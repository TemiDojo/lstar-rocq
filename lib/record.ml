open Tls_types
open Utils

(* 5. TLS Record Layer *)
module Record = struct
  type t =
    {content_type: ContentType.t; version: ProtocolVersion.t; fragment: bytes}

  let encode (rec_obj : t) =
    let buf = Buffer.create (5 + Bytes.length rec_obj.fragment) in
    BinaryStream.write_byte buf (ContentType.to_int rec_obj.content_type) ;
    let maj, min = ProtocolVersion.to_bytes rec_obj.version in
    BinaryStream.write_byte buf maj ;
    BinaryStream.write_byte buf min ;
    BinaryStream.write_int16 buf (Bytes.length rec_obj.fragment) ;
    BinaryStream.write_bytes buf rec_obj.fragment ;
    Cstruct.of_bytes (Buffer.to_bytes buf)

  let decode stream =
    if BinaryStream.length stream < 5 then
      None
    else
      let ct = ContentType.of_int (BinaryStream.read_byte stream) in
      let maj = BinaryStream.read_byte stream in
      let min = BinaryStream.read_byte stream in
      let ver = ProtocolVersion.of_bytes maj min in
      let len = BinaryStream.read_int16 stream in
      if BinaryStream.length stream < len then
        None
      else
        let frag = BinaryStream.read_bytes stream len in
        Some {content_type= ct; version= ver; fragment= frag}
end
