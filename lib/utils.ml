module BinaryStream = struct
  type t = {buffer: bytes; mutable pos: int}

  let create b = {buffer= b; pos= 0}

  let of_cstruct cs = {buffer= Cstruct.to_bytes cs; pos= 0}

  let length t = Bytes.length t.buffer - t.pos

  let read_byte t =
    if t.pos >= Bytes.length t.buffer then
      failwith "Unexpected EOF"
    else
      let b = Char.code (Bytes.get t.buffer t.pos) in
      t.pos <- t.pos + 1 ;
      b

  let read_int16 t =
    let b1 = read_byte t in
    let b2 = read_byte t in
    (b1 lsl 8) lor b2

  let read_int24 t =
    let b1 = read_byte t in
    let b2 = read_byte t in
    let b3 = read_byte t in
    (b1 lsl 16) lor (b2 lsl 8) lor b3

  let read_bytes t len =
    if t.pos + len > Bytes.length t.buffer then
      failwith "Buffer underflow"
    else
      let sub = Bytes.sub t.buffer t.pos len in
      t.pos <- t.pos + len ;
      sub

  let write_byte buf b = Buffer.add_char buf (Char.chr (b land 0xFF))

  let write_int16 buf v =
    write_byte buf ((v lsr 8) land 0xFF) ;
    write_byte buf (v land 0xFF)

  let write_int24 buf v =
    write_byte buf ((v lsr 16) land 0xFF) ;
    write_byte buf ((v lsr 8) land 0xFF) ;
    write_byte buf (v land 0xFF)

  let write_bytes buf b = Buffer.add_bytes buf b
end
