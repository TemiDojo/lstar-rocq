[@@@warning "-26-27-32-33-34-35-37-69"]

open Tls_types
open Ciphersuite
open Crypto
open Record
open Handshake
open Utils

(* -------------------------------------------------------------------------
   7. TLS Engine & State Handler
   ------------------------------------------------------------------------- *)
module TLS = struct
  type state =
    { mutable version: ProtocolVersion.t
    ; mutable client_random: bytes
    ; mutable server_random: bytes
    ; mutable pre_master_secret: bytes
    ; mutable master_secret: bytes
    ; mutable transcript_buffer: Buffer.t
    ; mutable cipher_suite: CipherSuite.t option
    ; mutable cipher_params: CipherParams.t option
    ; (* write = client->server direction, read = server->client direction *)
      mutable is_write_encrypted: bool
    ; mutable is_read_encrypted: bool
    ; mutable client_seq_num: int64
    ; mutable server_seq_num: int64
    ; mutable client_mac_key: bytes
    ; mutable server_mac_key: bytes
    ; mutable client_enc_key: bytes
    ; mutable server_enc_key: bytes
    ; mutable server_certificate: bytes option }

  let create () =
    { version= ProtocolVersion.TLS12
    ; client_random= Bytes.create 32
    ; server_random= Bytes.create 32
    ; pre_master_secret= Bytes.create 48
    ; master_secret= Bytes.create 0
    ; transcript_buffer= Buffer.create 1024
    ; cipher_suite= None
    ; cipher_params= None
    ; is_write_encrypted= false
    ; is_read_encrypted= false
    ; client_seq_num= 0L
    ; server_seq_num= 0L
    ; client_mac_key= Bytes.create 0
    ; server_mac_key= Bytes.create 0
    ; client_enc_key= Bytes.create 0
    ; server_enc_key= Bytes.create 0
    ; server_certificate= None }

  let reset state =
    state.version <- ProtocolVersion.TLS12 ;
    state.client_random <- Crypto.generate_random 32 ;
    state.server_random <- Bytes.create 32 ;
    (* First two bytes of PMS must be client_version (0x03 0x03) — RFC 5246 7.4.7.1 *)
    let pms = Crypto.generate_random 48 in
    Bytes.set pms 0 '\x03' ;
    Bytes.set pms 1 '\x03' ;
    state.pre_master_secret <- pms ;
    state.master_secret <- Bytes.create 0 ;
    Buffer.clear state.transcript_buffer ;
    state.cipher_suite <- None ;
    state.cipher_params <- None ;
    state.is_write_encrypted <- false ;
    state.is_read_encrypted <- false ;
    state.client_seq_num <- 0L ;
    state.server_seq_num <- 0L ;
    state.client_mac_key <- Bytes.create 0 ;
    state.server_mac_key <- Bytes.create 0 ;
    state.client_enc_key <- Bytes.create 0 ;
    state.server_enc_key <- Bytes.create 0 ;
    state.server_certificate <- None

  let record_transcript state bytes =
    Buffer.add_bytes state.transcript_buffer bytes

  let get_transcript_hash state =
    Crypto.sha256 (Buffer.to_bytes state.transcript_buffer)

  let build_client_hello state =
    let ch : Messages.client_hello =
      { version= state.version
      ; random= state.client_random
      ; session_id= Bytes.create 0
      ; cipher_suites=
          [ CipherSuite.TLS_RSA_WITH_NULL_MD5
          ; CipherSuite.TLS_RSA_WITH_NULL_SHA
          ; CipherSuite.TLS_RSA_WITH_NULL_SHA256
          ; CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
          ; CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256 ]
      ; compression_methods= [0]
      ; extensions= Messages.default_client_hello_extensions () }
    in
    let payload = Messages.encode_client_hello ch in
    let hs_msg =
      Messages.encode_handshake_record HandshakeType.ClientHello payload
    in
    record_transcript state hs_msg ;
    Record.
      { content_type= ContentType.Handshake
      ; version= state.version
      ; fragment= hs_msg }

  (* Builds a ClientKeyExchange record and always produces something
     wire-valid, regardless of what state the connection is actually in --
     this must never fail, because for mapping the SERVER's state machine
     the client can't refuse to send a message just because it's missing
     the "correct" inputs (e.g. this arriving out of order, with no
     captured certificate yet). Single symbol, no separate "garbage"
     variant: the fallback behavior IS the behavior.
       - If a real server certificate is known: RSA-encrypt the real PMS
         under it, exactly as a legitimate client would (this is what
         happens on the normal, in-order path).
       - Otherwise: send `garbage_len` random bytes in place of the
         encrypted PMS. Still wire-format-valid (correct 2-byte length
         prefix), content the server cannot possibly decrypt correctly --
         itself a useful probe of out-of-order/malformed-input handling.
     Key-block derivation is attempted opportunistically whenever a
     cipher suite is already known (e.g. ServerHello arrived but
     Certificate didn't), but is committed to `state` only if every
     derivation step succeeds -- a partial failure can never leave
     `cipher_params` set while enc/mac keys are still empty, which would
     otherwise crash a LATER encrypted step (AES key of length 0). If
     nothing can be derived, cipher_params is simply left as-is;
     RecordProtection already treats `cipher_params = None` as
     "send/receive as plaintext", so nothing downstream can crash from
     this either. *)
  let build_client_key_exchange ?(garbage_len = 256) state =
    let encrypted_pms =
      match state.server_certificate with
      | Some cert -> (
        try Crypto.rsa_encrypt_pre_master_secret cert state.pre_master_secret
        with _ -> Crypto.generate_random garbage_len )
      | None ->
          Crypto.generate_random garbage_len
    in
    let cke : Messages.client_key_exchange =
      {encrypted_pre_master= encrypted_pms}
    in
    let payload = Messages.encode_client_key_exchange cke in
    let hs_msg =
      Messages.encode_handshake_record HandshakeType.ClientKeyExchange payload
    in
    record_transcript state hs_msg ;
    ( match state.cipher_suite with
    | Some cs -> (
      try
        let params = CipherParams.of_suite cs in
        let master_secret =
          Crypto.compute_master_secret state.pre_master_secret
            state.client_random state.server_random
        in
        let kb_len = CipherParams.key_block_len params in
        let key_block =
          Crypto.compute_key_expansion master_secret state.server_random
            state.client_random kb_len
        in
        let off = ref 0 in
        let take n =
          let b = Bytes.sub key_block !off n in
          off := !off + n ;
          b
        in
        let client_mac_key = take params.mac_key_len in
        let server_mac_key = take params.mac_key_len in
        let client_enc_key = take params.enc_key_len in
        let server_enc_key = take params.enc_key_len in
        (* only commit once every step above has succeeded *)
        state.master_secret <- master_secret ;
        state.cipher_params <- Some params ;
        state.client_mac_key <- client_mac_key ;
        state.server_mac_key <- server_mac_key ;
        state.client_enc_key <- client_enc_key ;
        state.server_enc_key <- server_enc_key
      with _ -> () (* leave state untouched; treated as unencrypted below *) )
    | None ->
        () ) ;
    Record.
      { content_type= ContentType.Handshake
      ; version= state.version
      ; fragment= hs_msg }

  let build_change_cipher_spec (state : state) =
    Record.
      { content_type= ContentType.ChangeCipherSpec
      ; version= state.version
      ; fragment= Bytes.of_string "\x01" }

  let build_finished state =
    let hash = get_transcript_hash state in
    let v_data =
      Crypto.compute_verify_data state.master_secret "client finished" hash
    in
    let payload = v_data in
    let hs_msg =
      Messages.encode_handshake_record HandshakeType.Finished payload
    in
    record_transcript state hs_msg ;
    Record.
      { content_type= ContentType.Handshake
      ; version= state.version
      ; fragment= hs_msg }
end

(* -------------------------------------------------------------------------
   8. Record protection (MAC + AES-CBC encryption/decryption)
   ------------------------------------------------------------------------- *)
module RecordProtection = struct
  let seq_bytes (seq : int64) : bytes =
    let buf = Buffer.create 8 in
    for i = 7 downto 0 do
      let shift = i * 8 in
      Buffer.add_char buf
        (Char.chr
           (Int64.to_int (Int64.shift_right_logical seq shift) land 0xFF) )
    done ;
    Buffer.to_bytes buf

  let mac_header seq content_type version plaintext_len =
    let buf = Buffer.create 13 in
    BinaryStream.write_bytes buf (seq_bytes seq) ;
    BinaryStream.write_byte buf (ContentType.to_int content_type) ;
    let maj, min = ProtocolVersion.to_bytes version in
    BinaryStream.write_byte buf maj ;
    BinaryStream.write_byte buf min ;
    BinaryStream.write_int16 buf plaintext_len ;
    Buffer.to_bytes buf

  (* Encrypt an outgoing (client -> server) record's fragment. *)
  let protect (state : TLS.state) (content_type : ContentType.t)
      (plaintext : bytes) : bytes =
    match state.cipher_params with
    | None ->
        plaintext
        (* not negotiated yet; shouldn't be called encrypted before this *)
    | Some params -> (
        let seq = state.client_seq_num in
        state.client_seq_num <- Int64.add seq 1L ;
        let hdr =
          mac_header seq content_type state.version (Bytes.length plaintext)
        in
        let mac_tag =
          Crypto.compute_mac params.mac_algo state.client_mac_key
            (Bytes.cat hdr plaintext)
        in
        match params.enc_algo with
        | `NULL ->
            Bytes.cat plaintext mac_tag
        | `AES128 | `AES256 ->
            let pre_pad = Bytes.cat plaintext mac_tag in
            let block = params.block_size in
            let r = (Bytes.length pre_pad + 1) mod block in
            let pad_len =
              if r = 0 then
                0
              else
                block - r
            in
            let padding = Bytes.make (pad_len + 1) (Char.chr pad_len) in
            let to_encrypt = Bytes.cat pre_pad padding in
            let iv = Crypto.generate_random block in
            let ciphertext =
              Crypto.aes_cbc_encrypt state.client_enc_key iv to_encrypt
            in
            Bytes.cat iv ciphertext )

  (* Decrypt an incoming (server -> client) record's fragment. Returns the
     plaintext content (MAC/padding already verified and stripped) or
     raises on MAC mismatch / malformed padding. *)
  let unprotect (state : TLS.state) (content_type : ContentType.t)
      (wire_fragment : bytes) : bytes =
    match state.cipher_params with
    | None ->
        wire_fragment
    | Some params -> (
        let seq = state.server_seq_num in
        state.server_seq_num <- Int64.add seq 1L ;
        match params.enc_algo with
        | `NULL ->
            let mac_len = params.mac_key_len in
            let total = Bytes.length wire_fragment in
            if total < mac_len then
              failwith "Record too short for MAC"
            else
              let content = Bytes.sub wire_fragment 0 (total - mac_len) in
              let received_mac =
                Bytes.sub wire_fragment (total - mac_len) mac_len
              in
              let hdr =
                mac_header seq content_type state.version (Bytes.length content)
              in
              let expected_mac =
                Crypto.compute_mac params.mac_algo state.server_mac_key
                  (Bytes.cat hdr content)
              in
              if not (Bytes.equal received_mac expected_mac) then
                failwith "bad record MAC (NULL cipher)"
              else
                content
        | `AES128 | `AES256 ->
            let block = params.block_size in
            if Bytes.length wire_fragment < block * 2 then
              failwith "Record too short for CBC"
            else
              let iv = Bytes.sub wire_fragment 0 block in
              let ciphertext =
                Bytes.sub wire_fragment block
                  (Bytes.length wire_fragment - block)
              in
              let plain =
                Crypto.aes_cbc_decrypt state.server_enc_key iv ciphertext
              in
              let plain_len = Bytes.length plain in
              let pad_len = Char.code (Bytes.get plain (plain_len - 1)) in
              if pad_len + 1 > plain_len then
                failwith "Invalid padding"
              else
                let mac_len = params.mac_key_len in
                let content_len = plain_len - pad_len - 1 - mac_len in
                if content_len < 0 then
                  failwith "Invalid padding/MAC length"
                else
                  let content = Bytes.sub plain 0 content_len in
                  let received_mac = Bytes.sub plain content_len mac_len in
                  let hdr =
                    mac_header seq content_type state.version content_len
                  in
                  let expected_mac =
                    Crypto.compute_mac params.mac_algo state.server_mac_key
                      (Bytes.cat hdr content)
                  in
                  if not (Bytes.equal received_mac expected_mac) then
                    failwith "bad record MAC (CBC)"
                  else
                    content )
end
