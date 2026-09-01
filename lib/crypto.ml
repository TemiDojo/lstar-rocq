open Ciphersuite
open Utils
open Tls_types

(* -------------------------------------------------------------------------
   4. Cryptography — real HMAC/hash/AES-CBC/RSA via mirage-crypto & x509

   NOTE: this module is intentionally free of any reference to
   Engine_state (TLS.state). RecordProtection, which does need
   TLS.state, lives in engine_state.ml instead — keeping it here
   created a dependency cycle (Engine_state needs Crypto's hash/AES/RSA
   functions; Crypto needed Engine_state's TLS.state type for
   RecordProtection). Crypto must only ever be depended on, never
   depend back.
   ------------------------------------------------------------------------- *)
module Crypto = struct
  let bytes_to_hex b =
    let buf = Buffer.create (Bytes.length b * 2) in
    Bytes.iter
      (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c)))
      b ;
    Buffer.contents buf

  let generate_random len : bytes =
    Bytes.of_string (Mirage_crypto_rng.generate len)

  (* Hashing/HMAC now come from digestif, not mirage-crypto. *)
  let hmac_md5 (key : bytes) (data : bytes) : bytes =
    Bytes.of_string
      (Digestif.MD5.to_raw_string
         (Digestif.MD5.hmac_string ~key:(Bytes.to_string key)
            (Bytes.to_string data) ) )

  let hmac_sha1 (key : bytes) (data : bytes) : bytes =
    Bytes.of_string
      (Digestif.SHA1.to_raw_string
         (Digestif.SHA1.hmac_string ~key:(Bytes.to_string key)
            (Bytes.to_string data) ) )

  let hmac_sha256 (key : bytes) (data : bytes) : bytes =
    Bytes.of_string
      (Digestif.SHA256.to_raw_string
         (Digestif.SHA256.hmac_string ~key:(Bytes.to_string key)
            (Bytes.to_string data) ) )

  let sha256 (data : bytes) : bytes =
    Bytes.of_string
      (Digestif.SHA256.to_raw_string
         (Digestif.SHA256.digest_string (Bytes.to_string data)) )

  let compute_mac (algo : CipherParams.mac_algo) key data =
    match algo with
    | `MD5 ->
        hmac_md5 key data
    | `SHA1 ->
        hmac_sha1 key data
    | `SHA256 ->
        hmac_sha256 key data

  (* TLS 1.2 PRF is always HMAC-SHA256, independent of the record MAC. *)
  let prf_sha256 secret label seed output_len =
    let result = Buffer.create output_len in
    let label_seed = Bytes.cat (Bytes.of_string label) seed in
    let a = ref (hmac_sha256 secret label_seed) in
    while Buffer.length result < output_len do
      let output = hmac_sha256 secret (Bytes.cat !a label_seed) in
      Buffer.add_bytes result output ;
      a := hmac_sha256 secret !a
    done ;
    Bytes.sub (Buffer.to_bytes result) 0 output_len

  let compute_master_secret pms client_random server_random =
    prf_sha256 pms "master secret" (Bytes.cat client_random server_random) 48

  let compute_verify_data master_secret label handshake_hash =
    prf_sha256 master_secret label handshake_hash 12

  let compute_key_expansion master_secret server_random client_random len =
    prf_sha256 master_secret "key expansion"
      (Bytes.cat server_random client_random)
      len

  let rsa_encrypt_pre_master_secret (cert_der : bytes) (pms : bytes) : bytes =
    match X509.Certificate.decode_der (Bytes.to_string cert_der) with
    | Error (`Msg m) ->
        failwith ("Certificate parse failed: " ^ m)
    | Ok cert -> (
      match X509.Certificate.public_key cert with
      | `RSA pub ->
          Bytes.of_string
            (Mirage_crypto_pk.Rsa.PKCS1.encrypt ~key:pub (Bytes.to_string pms))
      | _ ->
          failwith "Server certificate does not carry an RSA public key" )

  (* mirage-crypto's Block.CBC is under Mirage_crypto.AES.CBC directly
     (no Cipher_block wrapper) and is keyed/typed over string, not Cstruct. *)
  let aes_cbc_encrypt (key : bytes) (iv : bytes) (data : bytes) : bytes =
    let k = Mirage_crypto.AES.CBC.of_secret (Bytes.to_string key) in
    Bytes.of_string
      (Mirage_crypto.AES.CBC.encrypt ~key:k ~iv:(Bytes.to_string iv)
         (Bytes.to_string data) )

  let aes_cbc_decrypt (key : bytes) (iv : bytes) (data : bytes) : bytes =
    let k = Mirage_crypto.AES.CBC.of_secret (Bytes.to_string key) in
    Bytes.of_string
      (Mirage_crypto.AES.CBC.decrypt ~key:k ~iv:(Bytes.to_string iv)
         (Bytes.to_string data) )
end
