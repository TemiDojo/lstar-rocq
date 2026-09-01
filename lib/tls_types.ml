module ProtocolVersion = struct
  type t = SSL30 | TLS10 | TLS11 | TLS12 | Unknown of int * int

  let to_bytes = function
    | SSL30 ->
        (3, 0)
    | TLS10 ->
        (3, 1)
    | TLS11 ->
        (3, 2)
    | TLS12 ->
        (3, 3)
    | Unknown (maj, min) ->
        (maj, min)

  let of_bytes maj min =
    match (maj, min) with
    | 3, 0 ->
        SSL30
    | 3, 1 ->
        TLS10
    | 3, 2 ->
        TLS11
    | 3, 3 ->
        TLS12
    | _ ->
        Unknown (maj, min)

  let to_string v =
    let maj, min = to_bytes v in
    Printf.sprintf "%d.%d" maj min
end

module ContentType = struct
  type t =
    | ChangeCipherSpec
    | Alert
    | Handshake
    | ApplicationData
    | Heartbeat
    | Unknown of int

  let to_int = function
    | ChangeCipherSpec ->
        20
    | Alert ->
        21
    | Handshake ->
        22
    | ApplicationData ->
        23
    | Heartbeat ->
        24
    | Unknown v ->
        v

  let of_int = function
    | 20 ->
        ChangeCipherSpec
    | 21 ->
        Alert
    | 22 ->
        Handshake
    | 23 ->
        ApplicationData
    | 24 ->
        Heartbeat
    | v ->
        Unknown v

  let to_string = function
    | ChangeCipherSpec ->
        "CHANGE_CIPHER_SPEC"
    | Alert ->
        "ALERT"
    | Handshake ->
        "HANDSHAKE"
    | Heartbeat ->
        "HEARTBEAT"
    | ApplicationData ->
        "APPLICATION_DATA"
    | Unknown v ->
        Printf.sprintf "UNKNOWN_CONTENT_TYPE(%d)" v
end

module HandshakeType = struct
  type t =
    | HelloRequest
    | ClientHello
    | ServerHello
    | Certificate
    | ServerKeyExchange
    | CertificateRequest
    | ServerHelloDone
    | CertificateVerify
    | ClientKeyExchange
    | Finished
    | Unknown of int

  let to_int = function
    | HelloRequest ->
        0
    | ClientHello ->
        1
    | ServerHello ->
        2
    | Certificate ->
        11
    | ServerKeyExchange ->
        12
    | CertificateRequest ->
        13
    | ServerHelloDone ->
        14
    | CertificateVerify ->
        15
    | ClientKeyExchange ->
        16
    | Finished ->
        20
    | Unknown v ->
        v

  let of_int = function
    | 0 ->
        HelloRequest
    | 1 ->
        ClientHello
    | 2 ->
        ServerHello
    | 11 ->
        Certificate
    | 12 ->
        ServerKeyExchange
    | 13 ->
        CertificateRequest
    | 14 ->
        ServerHelloDone
    | 15 ->
        CertificateVerify
    | 16 ->
        ClientKeyExchange
    | 20 ->
        Finished
    | v ->
        Unknown v

  let to_string = function
    | HelloRequest ->
        "HELLO_REQUEST"
    | ClientHello ->
        "CLIENT_HELLO"
    | ServerHello ->
        "SERVER_HELLO"
    | Certificate ->
        "CERTIFICATE"
    | ServerKeyExchange ->
        "SERVER_KEY_EXCHANGE"
    | CertificateRequest ->
        "CERTIFICATE_REQUEST"
    | ServerHelloDone ->
        "SERVER_HELLO_DONE"
    | CertificateVerify ->
        "CERTIFICATE_VERIFY"
    | ClientKeyExchange ->
        "CLIENT_KEY_EXCHANGE"
    | Finished ->
        "FINISHED"
    | Unknown v ->
        Printf.sprintf "UNKNOWN_HANDSHAKE(%d)" v
end

module CipherSuite = struct
  type t =
    | TLS_RSA_WITH_NULL_MD5
    | TLS_RSA_WITH_NULL_SHA
    | TLS_RSA_WITH_NULL_SHA256
    | TLS_RSA_WITH_RC4_128_SHA
    | TLS_RSA_WITH_AES_128_CBC_SHA
    | TLS_RSA_WITH_AES_256_CBC_SHA
    | TLS_RSA_WITH_AES_128_CBC_SHA256
    | TLS_RSA_WITH_AES_256_CBC_SHA256
    | Unknown of int

  let to_int = function
    | TLS_RSA_WITH_NULL_MD5 ->
        0x0001
    | TLS_RSA_WITH_NULL_SHA ->
        0x0002
    | TLS_RSA_WITH_NULL_SHA256 ->
        0x003B
    | TLS_RSA_WITH_RC4_128_SHA ->
        0x0005
    | TLS_RSA_WITH_AES_128_CBC_SHA ->
        0x002F
    | TLS_RSA_WITH_AES_256_CBC_SHA ->
        0x0035
    | TLS_RSA_WITH_AES_128_CBC_SHA256 ->
        0x003C
    | TLS_RSA_WITH_AES_256_CBC_SHA256 ->
        0x003D
    | Unknown code ->
        code

  let of_int = function
    | 0x0001 ->
        TLS_RSA_WITH_NULL_MD5
    | 0x0002 ->
        TLS_RSA_WITH_NULL_SHA
    | 0x003B ->
        TLS_RSA_WITH_NULL_SHA256
    | 0x0005 ->
        TLS_RSA_WITH_RC4_128_SHA
    | 0x002F ->
        TLS_RSA_WITH_AES_128_CBC_SHA
    | 0x0035 ->
        TLS_RSA_WITH_AES_256_CBC_SHA
    | 0x003C ->
        TLS_RSA_WITH_AES_128_CBC_SHA256
    | 0x003D ->
        TLS_RSA_WITH_AES_256_CBC_SHA256
    | code ->
        Unknown code
end

module Alert = struct
  type level = Warning | Fatal | UnknownLevel of int

  type description =
    | CloseNotify
    | UnexpectedMessage
    | BadRecordMac
    | HandshakeFailure
    | BadCertificate
    | UnsupportedCertificate
    | CertificateRevoked
    | CertificateExpired
    | CertificateUnknown
    | IllegalParameter
    | UnknownDesc of int

  type t = {level: level; description: description}

  let level_of_int = function 1 -> Warning | 2 -> Fatal | n -> UnknownLevel n

  let desc_of_int = function
    | 0 ->
        CloseNotify
    | 10 ->
        UnexpectedMessage
    | 20 ->
        BadRecordMac
    | 40 ->
        HandshakeFailure
    | 42 ->
        BadCertificate
    | 43 ->
        UnsupportedCertificate
    | 44 ->
        CertificateRevoked
    | 45 ->
        CertificateExpired
    | 46 ->
        CertificateUnknown
    | 47 ->
        IllegalParameter
    | n ->
        UnknownDesc n

  let to_string t =
    let l_str =
      match t.level with
      | Warning ->
          "WARNING"
      | Fatal ->
          "FATAL"
      | UnknownLevel n ->
          string_of_int n
    in
    let d_str =
      match t.description with
      | CloseNotify ->
          "CLOSE_NOTIFY"
      | UnexpectedMessage ->
          "UNEXPECTED_MESSAGE"
      | BadRecordMac ->
          "BAD_RECORD_MAC"
      | HandshakeFailure ->
          "HANDSHAKE_FAILURE"
      | BadCertificate ->
          "BAD_CERTIFICATE"
      | UnsupportedCertificate ->
          "UNSUPPORTED_CERTIFICATE"
      | CertificateRevoked ->
          "CERTIFICATE_REVOKED"
      | CertificateExpired ->
          "CERTIFICATE_EXPIRED"
      | CertificateUnknown ->
          "CERTIFICATE_UNKNOWN"
      | IllegalParameter ->
          "ILLEGAL_PARAMETER"
      | UnknownDesc n ->
          string_of_int n
    in
    Printf.sprintf "ALERT(%s, %s)" l_str d_str
end
