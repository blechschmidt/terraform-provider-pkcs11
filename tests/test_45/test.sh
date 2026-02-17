#!/usr/bin/env bash
# Two-phase unwrap test for YubiHSM
# YubiHSM's CKM_YUBICO_AES_CCM_WRAP preserves the original object ID in the
# wrapped blob. Unwrapping fails if an object with that ID already exists.
# So we must: wrap -> destroy original -> unwrap.
set -euo pipefail

WRAP_DIR="$(mktemp -d)"
ORIG_DIR="$(pwd)"

cleanup() {
  # Always clean up phase 1 (wrapping key) from HSM
  cd "${WRAP_DIR}" 2>/dev/null && terraform destroy -auto-approve -no-color 2>/dev/null || true
  cd "${ORIG_DIR}" 2>/dev/null || true
  rm -rf "${WRAP_DIR}"
}
trap cleanup EXIT

# Phase 1: wrap config in separate directory
cp provider.tf "${WRAP_DIR}/"
cp wrap.tf "${WRAP_DIR}/main.tf"
cp terraform.tfvars "${WRAP_DIR}/"

cd "${WRAP_DIR}"
terraform apply -auto-approve -no-color
WRAPPED_MATERIAL=$(terraform output -raw wrapped_key_material)

# Destroy only target key and wrapped_key, keeping wrapping key alive on HSM
terraform destroy -auto-approve -no-color \
  -target=pkcs11_wrapped_key.wrapped \
  -target=pkcs11_symmetric_key.original_key
cd "${ORIG_DIR}"


# Phase 2: unwrap using the captured material
# Remove wrap.tf so terraform only sees main.tf + provider.tf
rm -f wrap.tf
terraform apply -auto-approve -no-color -var="wrapped_key_material=${WRAPPED_MATERIAL}"

# Cleanup phase 2
terraform destroy -auto-approve -no-color -var="wrapped_key_material=${WRAPPED_MATERIAL}"
