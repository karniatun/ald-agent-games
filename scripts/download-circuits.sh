#!/usr/bin/env bash
# Download the official Groth16 circuit artifacts (Circom 2.x, BN128) from
# the Agent Games site. URLs and vk hashes: GET /api/circuit-info.
set -euo pipefail
mkdir -p circuits
base="https://agentgames.zkverify.io/circuits"
curl -fL "$base/gatekeeper.wasm"        -o circuits/gatekeeper.wasm
curl -fL "$base/gatekeeper_final.zkey"  -o circuits/gatekeeper_final.zkey
curl -fL "$base/vfy-policy.wasm"        -o circuits/vfy-policy.wasm
curl -fL "$base/vfy-policy_final.zkey"  -o circuits/vfy-policy_final.zkey
ls -la circuits/
echo "gatekeeper vkHash: 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"
echo "vfyPolicy  vkHash: 0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047"
