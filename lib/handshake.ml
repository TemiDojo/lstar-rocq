[@@@warning "-26-27-32-33-34-35-37-69"]

open Tls_types
open Utils
open Stdlib

module Messages = struct
  type client_hello =
    { version: ProtocolVersion.t
    ; random: bytes
    ; session_id: bytes
    ; cipher_suites: CipherSuite.t list
    ; compression_methods: int list
    ; extensions: bytes }

  let encode_extensions (exts : (int * bytes) list) : bytes =
    let buf = Buffer.create 64 in
    List.iter
      (fun (ext_type, ext_data) ->
        BinaryStream.write_int16 buf ext_type ;
        BinaryStream.write_int16 buf (Bytes.length ext_data) ;
        BinaryStream.write_bytes buf ext_data )
      exts ;
    Buffer.to_bytes buf

  let signature_algorithms_extension () : bytes =
    let algos =
      [ (0x04, 0x01)
      ; (* sha256, rsa *)
        (0x05, 0x01)
      ; (* sha384, rsa *)
        (0x06, 0x01)
      ; (* sha512, rsa *)
        (0x02, 0x01) (* sha1,   rsa *) ]
    in
    let buf = Buffer.create (2 + (List.length algos * 2)) in
    BinaryStream.write_int16 buf (List.length algos * 2) ;
    List.iter
      (fun (h, s) ->
        BinaryStream.write_byte buf h ;
        BinaryStream.write_byte buf s )
      algos ;
    Buffer.to_bytes buf

  let default_client_hello_extensions () : bytes =
    encode_extensions [(0x000d, signature_algorithms_extension ())]

  type server_hello =
    { version: ProtocolVersion.t
    ; random: bytes
    ; session_id: bytes
    ; cipher_suite: CipherSuite.t
    ; compression_method: int }

  type certificate = {certificates: bytes list}

  type client_key_exchange = {encrypted_pre_master: bytes}

  type finished = {verify_data: bytes}

  let encode_client_hello (ch : client_hello) =
    let buf = Buffer.create 128 in
    let maj, min = ProtocolVersion.to_bytes ch.version in
    BinaryStream.write_byte buf maj ;
    BinaryStream.write_byte buf min ;
    BinaryStream.write_bytes buf ch.random ;
    BinaryStream.write_byte buf (Bytes.length ch.session_id) ;
    BinaryStream.write_bytes buf ch.session_id ;
    BinaryStream.write_int16 buf (List.length ch.cipher_suites * 2) ;
    List.iter
      (fun cs -> BinaryStream.write_int16 buf (CipherSuite.to_int cs))
      ch.cipher_suites ;
    BinaryStream.write_byte buf (List.length ch.compression_methods) ;
    List.iter
      (fun comp -> BinaryStream.write_byte buf comp)
      ch.compression_methods ;
    (* Extensions block: 2-byte total length + concatenated extensions.
       Only emit it if non-empty, so an intentionally-bare ClientHello
       (e.g. for negative-testing the learner) is still possible by
       passing extensions = Bytes.create 0. *)
    if Bytes.length ch.extensions > 0 then begin
      BinaryStream.write_int16 buf (Bytes.length ch.extensions) ;
      BinaryStream.write_bytes buf ch.extensions
    end ;
    Buffer.to_bytes buf

  let decode_server_hello stream : server_hello =
    let maj = BinaryStream.read_byte stream in
    let min = BinaryStream.read_byte stream in
    let ver = ProtocolVersion.of_bytes maj min in
    let rand = BinaryStream.read_bytes stream 32 in
    let sess_id_len = BinaryStream.read_byte stream in
    let sess_id = BinaryStream.read_bytes stream sess_id_len in
    let cs = CipherSuite.of_int (BinaryStream.read_int16 stream) in
    let comp = BinaryStream.read_byte stream in
    { version= ver
    ; random= rand
    ; session_id= sess_id
    ; cipher_suite= cs
    ; compression_method= comp }

  let decode_certificate stream : certificate =
    let total_len = BinaryStream.read_int24 stream in
    let certs = ref [] in
    let read_len = ref 0 in
    while !read_len < total_len do
      let cert_len = BinaryStream.read_int24 stream in
      let cert_bytes = BinaryStream.read_bytes stream cert_len in
      certs := cert_bytes :: !certs ;
      read_len := !read_len + 3 + cert_len
    done ;
    {certificates= List.rev !certs}

  let encode_client_key_exchange (cke : client_key_exchange) =
    let buf = Buffer.create 128 in
    BinaryStream.write_int16 buf (Bytes.length cke.encrypted_pre_master) ;
    BinaryStream.write_bytes buf cke.encrypted_pre_master ;
    Buffer.to_bytes buf

  let encode_handshake_record ht payload_bytes =
    let buf = Buffer.create (4 + Bytes.length payload_bytes) in
    BinaryStream.write_byte buf (HandshakeType.to_int ht) ;
    BinaryStream.write_int24 buf (Bytes.length payload_bytes) ;
    BinaryStream.write_bytes buf payload_bytes ;
    Buffer.to_bytes buf
end
