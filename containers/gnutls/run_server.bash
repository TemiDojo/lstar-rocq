#!/bin/bash

set -euo pipefail

openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout whatever.crt.key -out whatever.crt -subj '/CN=whatever'
openssl s_server -accept 4433 -cert whatever.crt -key whatever.crt.key -tls1_2 -cipher RSA -msg -debug
