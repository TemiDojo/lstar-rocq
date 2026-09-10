#!/bin/bash

set -xmeuo pipefail

docker compose -f lstar_rocq_gnutls_3_3_8.yml build
docker compose -f lstar_rocq_gnutls_3_3_8.yml up
docker wait lstar-rocq_lstar-rocq_1
docker cp lstar-rocq_lstar-rocq_1:/tmp ./tmp
mv ./tmp/*.dot ./lstar_rocq_gnutls_3_3_8.dot
rm -rf ./tmp
docker compose -f lstar_rocq_gnutls_3_3_8.yml down

docker compose -f lstar_rocq_gnutls_3_3_12.yml build
docker compose -f lstar_rocq_gnutls_3_3_12.yml up
docker wait lstar-rocq_lstar-rocq_1
docker cp lstar-rocq_lstar-rocq_1:/tmp ./tmp
mv ./tmp/*.dot ./lstar_rocq_gnutls_3_3_12.dot
rm -rf ./tmp
docker compose -f lstar_rocq_gnutls_3_3_12.yml down

docker compose -f statelearner_gnutls_3_3_8.yml build
docker compose -f statelearner_gnutls_3_3_8.yml up
docker wait lstar-rocq_statelearner_1
docker cp lstar-rocq_statelearner_1:/app/statelearner/examples/openssl/output_server/learnedModel.dot ./statelearner_gnutls_3_3_8.dot
docker compose -f statelearner_gnutls_3_3_8.yml down

docker compose -f statelearner_gnutls_3_3_12.yml build
docker compose -f statelearner_gnutls_3_3_12.yml up
docker wait lstar-rocq_statelearner_1
docker cp lstar-rocq_statelearner_1:/app/statelearner/examples/openssl/output_server/learnedModel.dot ./statelearner_gnutls_3_3_12.dot
docker compose -f statelearner_gnutls_3_3_12.yml down
