open Tls_types
open Ciphersuite
open Record
open Handshake
open Engine_state
open Utils
open Mirage_crypto_rng
open Unix
open String
open Stdlib

module TLSConfig = struct
  type t = {host: string; port: int; timeout_ms: float}

  let default = {host= "127.0.0.1"; port= 4433; timeout_ms= 2000.0}
end

module TLSSUL = struct
  type t =
    { config: TLSConfig.t
    ; tls_state: TLS.state
    ; mutable socket: Unix.file_descr option
    ; mutable read_buffer: bytes }

  let create config =
    {config; tls_state= TLS.create (); socket= None; read_buffer= Bytes.create 0}

  let connect t =
    let inet_addr = Unix.inet_addr_of_string t.config.host in
    let sockaddr = Unix.ADDR_INET (inet_addr, t.config.port) in
    let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
    try
      Unix.connect s sockaddr ;
      t.socket <- Some s
    with Unix.Unix_error (err, _, _) ->
      Unix.close s ;
      t.socket <- None ;
      Printf.eprintf "connect() failed: %s\n%!" (Unix.error_message err)

  let disconnect t =
    ( match t.socket with
    | Some s ->
        (try Unix.close s with _ -> ()) ;
        t.socket <- None
    | None ->
        () ) ;
    t.read_buffer <- Bytes.create 0

  let pre t = disconnect t ; TLS.reset t.tls_state ; connect t

  let post t = disconnect t

  let send_record t (rec_obj : Record.t) =
    match t.socket with
    | None ->
        ()
    | Some s ->
        let fragment =
          if t.tls_state.is_write_encrypted then
            RecordProtection.protect t.tls_state rec_obj.content_type
              rec_obj.fragment
          else
            rec_obj.fragment
        in
        let final_rec = Record.{rec_obj with fragment} in
        let raw_bytes = Cstruct.to_bytes (Record.encode final_rec) in
        let _ = Unix.send s raw_bytes 0 (Bytes.length raw_bytes) [] in
        ()

  let receive_responses t =
    match t.socket with
    | None ->
        "CLOSED"
    | Some s -> (
        let buf = Bytes.create 4096 in
        let closed = ref false in
        let rec drain acc first =
          let wait =
            if first then
              t.config.timeout_ms /. 1000.0
            else
              0.05
          in
          let read_fds, _, _ = Unix.select [s] [] [] wait in
          if read_fds = [] then
            acc
          else
            let len = Unix.recv s buf 0 4096 [] in
            if len = 0 then (
              closed := true ;
              acc
            ) else
              drain (Bytes.cat acc (Bytes.sub buf 0 len)) false
        in
        try
          let new_bytes = drain (Bytes.create 0) true in
          if
            !closed
            && Bytes.length new_bytes = 0
            && Bytes.length t.read_buffer = 0
          then
            "CLOSED"
          else
            let combined = Bytes.cat t.read_buffer new_bytes in
            if Bytes.length combined = 0 then
              "EMPTY"
            else
              let stream =
                BinaryStream.of_cstruct (Cstruct.of_bytes combined)
              in
              let responses = ref [] in
              let last_good_pos = ref 0 in
              let rec parse_records () =
                let before = stream.BinaryStream.pos in
                match Record.decode stream with
                | None ->
                    stream.BinaryStream.pos <- before
                | Some rec_item ->
                    last_good_pos := stream.BinaryStream.pos ;
                    let content_type = rec_item.Record.content_type in
                    let plaintext =
                      if
                        t.tls_state.is_read_encrypted
                        && content_type <> ContentType.ChangeCipherSpec
                      then (
                        try
                          RecordProtection.unprotect t.tls_state content_type
                            rec_item.Record.fragment
                        with Failure msg ->
                          responses :=
                            ("DECRYPT_ERROR(" ^ msg ^ ")") :: !responses ;
                          Bytes.create 0
                      ) else
                        rec_item.Record.fragment
                    in
                    ( match content_type with
                    | ContentType.Alert ->
                        if Bytes.length plaintext >= 2 then
                          let lvl =
                            Alert.level_of_int
                              (Char.code (Bytes.get plaintext 0))
                          in
                          let desc =
                            Alert.desc_of_int
                              (Char.code (Bytes.get plaintext 1))
                          in
                          responses :=
                            Alert.to_string Alert.{level= lvl; description= desc}
                            :: !responses
                        else
                          responses := "ALERT" :: !responses
                    | ContentType.ChangeCipherSpec ->
                        t.tls_state.is_read_encrypted <- true ;
                        responses := "CHANGE_CIPHER_SPEC" :: !responses
                    | ContentType.Handshake ->
                        if Bytes.length plaintext > 0 then begin
                          TLS.record_transcript t.tls_state plaintext ;
                          let ht =
                            HandshakeType.of_int
                              (Char.code (Bytes.get plaintext 0))
                          in
                          ( match ht with
                          | HandshakeType.ServerHello ->
                              if Bytes.length plaintext >= 38 then begin
                                let hs_stream =
                                  BinaryStream.create
                                    (Bytes.sub plaintext 4
                                       (Bytes.length plaintext - 4) )
                                in
                                let sh =
                                  Messages.decode_server_hello hs_stream
                                in
                                t.tls_state.server_random <- sh.random ;
                                t.tls_state.cipher_suite <- Some sh.cipher_suite
                              end
                          | HandshakeType.Certificate ->
                              if Bytes.length plaintext > 4 then begin
                                let hs_stream =
                                  BinaryStream.create
                                    (Bytes.sub plaintext 4
                                       (Bytes.length plaintext - 4) )
                                in
                                try
                                  let cert_msg =
                                    Messages.decode_certificate hs_stream
                                  in
                                  match cert_msg.Messages.certificates with
                                  | leaf :: _ ->
                                      t.tls_state.server_certificate <-
                                        Some leaf
                                  | [] ->
                                      ()
                                with _ -> ()
                              end
                          | _ ->
                              () ) ;
                          responses := HandshakeType.to_string ht :: !responses
                        end else
                          responses := "HANDSHAKE" :: !responses
                    | ContentType.Heartbeat ->
                        responses := "HEARTBEAT" :: !responses
                    | ContentType.ApplicationData ->
                        responses := "APPLICATION_DATA" :: !responses
                    | ContentType.Unknown _ ->
                        responses := "UNKNOWN_RECORD" :: !responses ) ;
                    parse_records ()
              in
              parse_records () ;
              t.read_buffer <-
                Bytes.sub combined !last_good_pos
                  (Bytes.length combined - !last_good_pos) ;
              if !responses = [] then
                "EMPTY_RESPONSE"
              else
                String.concat ", " (List.rev !responses)
        with _ -> "CONNECTION_ERROR" )

  let step t symbol =
    try
      match symbol with
      | "CLIENT_HELLO" ->
          let rec_obj = TLS.build_client_hello t.tls_state in
          send_record t rec_obj ; receive_responses t
      | "CLIENT_KEY_EXCHANGE" ->
          let rec_obj = TLS.build_client_key_exchange t.tls_state in
          send_record t rec_obj ; receive_responses t
      | "CHANGE_CIPHER_SPEC" ->
          let rec_obj = TLS.build_change_cipher_spec t.tls_state in
          send_record t rec_obj ;
          t.tls_state.is_write_encrypted <- true ;
          receive_responses t
      | "FINISHED" ->
          let rec_obj = TLS.build_finished t.tls_state in
          send_record t rec_obj ; receive_responses t
      | "EMPTY_APPLICATION_DATA" ->
          let rec_obj =
            Record.
              { content_type= ContentType.ApplicationData
              ; version= t.tls_state.version
              ; fragment= Bytes.create 0 }
          in
          send_record t rec_obj ; receive_responses t
      | "APPLICATION_DATA" ->
          let payload = Bytes.of_string "GET / HTTP/1.0\r\n\r\n" in
          let rec_obj =
            Record.
              { content_type= ContentType.ApplicationData
              ; version= t.tls_state.version
              ; fragment= payload }
          in
          send_record t rec_obj ; receive_responses t
      | "HEARTBEAT" ->
          let rec_obj =
            Record.
              { content_type= ContentType.Heartbeat
              ; version= t.tls_state.version
              ; fragment= Bytes.of_string "\x01"
              }
          in
          send_record t rec_obj ; receive_responses t
      | "CLOSE_NOTIFY" ->
          let rec_obj =
            Record.
              { content_type= ContentType.Alert
              ; version= t.tls_state.version
              ; fragment= Bytes.of_string "\x01\x00" (* warning, close_notify *)
              }
          in
          send_record t rec_obj ; receive_responses t
      | _ ->
          "UNKNOWN_SYMBOL"
    with
    | Failure msg ->
        (* Precondition not met in this state (missing cert, missing
           cipher suite, etc.) -- report it as a distinct output symbol
           rather than crashing, and importantly: nothing was sent, so
           the connection/state is left exactly as it was before this
           step, safe to try a different symbol next. *)
        "PRECONDITION_ERROR(" ^ msg ^ ")"
    | e ->
        (* Catch-all so no symbol can ever bring down the whole learner
           process, even from a bug we didn't anticipate. *)
        (*"INTERNAL_ERROR(" ^ Printexc.to_string e ^ ")"*)
        "CLOSED"
end

let init_and_seed_rng () =
  (* 1. Read 32 raw bytes from /dev/urandom *)
  let ic = open_in_bin "/dev/urandom" in
  let seed_bytes = Bytes.create 32 in
  really_input ic seed_bytes 0 32 ;
  close_in ic ;
  (* 2. Convert to Cstruct *)
  let seed_cstruct = Bytes.to_string seed_bytes in
  (* 3. Create generator with the initial seed *)
  let generator = create ~seed:seed_cstruct (module Fortuna) in
  (* 4. Set as default *)
  set_default_generator generator
