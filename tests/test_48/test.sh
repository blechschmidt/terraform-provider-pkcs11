#!/usr/bin/env bash
# Two-phase unwrap test for YubiHSM — TWO wrapped materials
# YubiHSM's CKM_YUBICO_AES_CCM_WRAP preserves the original object ID in the
# wrapped blob. Unwrapping fails if an object with that ID already exists.
# So we must: wrap -> destroy originals -> unwrap.
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
WRAPPED_A=$(terraform output -raw wrapped_a)
WRAPPED_B=$(terraform output -raw wrapped_b)

# Destroy both target keys and both wrapped_keys, keeping wrapping key alive on HSM
terraform destroy -auto-approve -no-color \
  -target=pkcs11_wrapped_key.wrapped_a \
  -target=pkcs11_wrapped_key.wrapped_b \
  -target=pkcs11_symmetric_key.key_a \
  -target=pkcs11_symmetric_key.key_b
cd "${ORIG_DIR}"

# Allow YubiHSM sessions to be released before phase 2
sleep 5

# Phase 2: unwrap using the captured materials
# Remove wrap.tf so terraform only sees main.tf + provider.tf
rm -f wrap.tf
terraform apply -auto-approve -no-color \
  -var="wrapped_a=${WRAPPED_A}" \
  -var="wrapped_b=${WRAPPED_B}"

# Cleanup phase 2
terraform destroy -auto-approve -no-color \
  -var="wrapped_a=${WRAPPED_A}" \
  -var="wrapped_b=${WRAPPED_B}"
