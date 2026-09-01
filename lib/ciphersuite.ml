open Tls_types

module CipherParams = struct
  type mac_algo = [`MD5 | `SHA1 | `SHA256]

  type enc_algo = [`NULL | `AES128 | `AES256]

  type t =
    { mac_algo: mac_algo
    ; mac_key_len: int
    ; enc_algo: enc_algo
    ; enc_key_len: int
    ; block_size: int (* 0 for NULL, 16 for AES *) }

  let of_suite : CipherSuite.t -> t = function
    | CipherSuite.TLS_RSA_WITH_NULL_MD5 ->
        { mac_algo= `MD5
        ; mac_key_len= 16
        ; enc_algo= `NULL
        ; enc_key_len= 0
        ; block_size= 0 }
    | CipherSuite.TLS_RSA_WITH_NULL_SHA ->
        { mac_algo= `SHA1
        ; mac_key_len= 20
        ; enc_algo= `NULL
        ; enc_key_len= 0
        ; block_size= 0 }
    | CipherSuite.TLS_RSA_WITH_NULL_SHA256 ->
        { mac_algo= `SHA256
        ; mac_key_len= 32
        ; enc_algo= `NULL
        ; enc_key_len= 0
        ; block_size= 0 }
    | CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA ->
        { mac_algo= `SHA1
        ; mac_key_len= 20
        ; enc_algo= `AES128
        ; enc_key_len= 16
        ; block_size= 16 }
    | CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA ->
        { mac_algo= `SHA1
        ; mac_key_len= 20
        ; enc_algo= `AES256
        ; enc_key_len= 32
        ; block_size= 16 }
    | CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256 ->
        { mac_algo= `SHA256
        ; mac_key_len= 32
        ; enc_algo= `AES128
        ; enc_key_len= 16
        ; block_size= 16 }
    | CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256 ->
        { mac_algo= `SHA256
        ; mac_key_len= 32
        ; enc_algo= `AES256
        ; enc_key_len= 32
        ; block_size= 16 }
    | other ->
        failwith
          (Printf.sprintf
             "Unsupported cipher suite for record protection: 0x%04x"
             (CipherSuite.to_int other) )

  let key_block_len p = (2 * p.mac_key_len) + (2 * p.enc_key_len)
end
