#!/usr/bin/env bash
set -euo pipefail

# PKCS#11 Integration Test Runner for terraform-provider-pkcs11
#
# Usage:
#   ./tests/run_tests.sh                            # Run all tests with YubiHSM (default)
#   HSM=softhsm ./tests/run_tests.sh                # Run all tests with SoftHSM
#   HSM=softhsm ./tests/run_tests.sh test_31        # Run specific tests with SoftHSM
#   PKCS11_PIN=mypin ./tests/run_tests.sh            # Override PIN via env
#
# Environment variables:
#   HSM           - HSM backend: "yubihsm" (default) or "softhsm"
#   PKCS11_PIN    - PIN for the token (defaults per HSM)
#   PKCS11_MODULE - Override PKCS#11 module path
#   PKCS11_SLOT   - Override slot ID

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROVIDER_BINARY="${PROJECT_DIR}/terraform-provider-pkcs11"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
SKIPPED=0
FAILED_TESTS=()

# HSM backend selection
HSM="${HSM:-yubihsm}"

case "${HSM}" in
    yubihsm)
        PKCS11_PIN="${PKCS11_PIN:-0001password}"
        PKCS11_MODULE="${PKCS11_MODULE:-/usr/lib/pkcs11/yubihsm_pkcs11.so}"
        PKCS11_SLOT="${PKCS11_SLOT:-0}"
        PROVIDER_ENV='env = { "YUBIHSM_PKCS11_CONF" : "/etc/yubihsm_pkcs11.conf" }'
        ;;
    softhsm)
        PKCS11_PIN="${PKCS11_PIN:-1234}"
        PKCS11_MODULE="${PKCS11_MODULE:-/usr/lib/pkcs11/libsofthsm2.so}"
        # Auto-detect SoftHSM slot
        if [[ -z "${PKCS11_SLOT:-}" ]]; then
            PKCS11_SLOT=$(softhsm2-util --show-slots 2>/dev/null | grep -m1 "Slot " | awk '{print $2}' || echo "0")
        fi
        PROVIDER_ENV=""
        ;;
    *)
        echo "Unknown HSM backend: ${HSM}. Use 'yubihsm' or 'softhsm'."
        exit 1
        ;;
esac

cleanup() {
    if [[ -n "${TERRAFORMRC_FILE:-}" && -f "${TERRAFORMRC_FILE}" ]]; then
        rm -f "${TERRAFORMRC_FILE}"
    fi
    if [[ -n "${GENERATED_PROVIDER_TF:-}" && -f "${GENERATED_PROVIDER_TF}" ]]; then
        rm -f "${GENERATED_PROVIDER_TF}"
    fi
}
trap cleanup EXIT

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $*"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*"
}

# Build the provider
log_info "Building provider..."
cd "${PROJECT_DIR}"
if ! go build -o "${PROVIDER_BINARY}" .; then
    log_fail "Failed to build provider"
    exit 1
fi
log_info "Provider built: ${PROVIDER_BINARY}"
log_info "HSM backend: ${HSM} (module: ${PKCS11_MODULE}, slot: ${PKCS11_SLOT})"

# Create a temporary terraformrc with dev_overrides
TERRAFORMRC_FILE="$(mktemp)"
cat > "${TERRAFORMRC_FILE}" <<EOF
provider_installation {
  dev_overrides {
    "blechschmidt/pkcs11" = "${PROJECT_DIR}"
  }
  direct {}
}
EOF

export TF_CLI_CONFIG_FILE="${TERRAFORMRC_FILE}"

# Generate provider.tf
GENERATED_PROVIDER_TF="$(mktemp)"
cat > "${GENERATED_PROVIDER_TF}" <<EOF
terraform {
  required_providers {
    pkcs11 = {
      source = "blechschmidt/pkcs11"
    }
  }
}

variable "pkcs11_pin" {
  type      = string
  sensitive = true
}

provider "pkcs11" {
  module_path = "${PKCS11_MODULE}"
  slot_id     = ${PKCS11_SLOT}
  pin         = var.pkcs11_pin
  ${PROVIDER_ENV}
}
EOF

# Determine which tests to run
if [[ $# -gt 0 ]]; then
    TESTS=("$@")
else
    TESTS=()
    for dir in "${SCRIPT_DIR}"/test_*/; do
        if [[ -d "${dir}" ]]; then
            TESTS+=("$(basename "${dir}")")
        fi
    done
fi

# Sort tests
IFS=$'\n' TESTS=($(sort <<<"${TESTS[*]}")); unset IFS

log_info "Running ${#TESTS[@]} tests sequentially"
echo ""

for test_name in "${TESTS[@]}"; do
    test_dir="${SCRIPT_DIR}/${test_name}"

    if [[ ! -d "${test_dir}" ]]; then
        log_fail "${test_name}: directory not found"
        FAILED=$((FAILED + 1))
        FAILED_TESTS+=("${test_name}")
        continue
    fi

    if [[ ! -f "${test_dir}/main.tf" ]]; then
        log_fail "${test_name}: main.tf not found"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    echo -e "━━━ ${YELLOW}${test_name}${NC} ━━━"

    # Read the test description from the first comment line
    desc=$(head -1 "${test_dir}/main.tf" | sed 's/^# //')
    echo "    ${desc}"

    # Create a working directory for this test
    work_dir="$(mktemp -d)"

    # Copy generated provider config and test files
    cp "${GENERATED_PROVIDER_TF}" "${work_dir}/provider.tf"
    cp "${test_dir}"/*.tf "${work_dir}/"

    # Copy test.sh if present (for multi-phase tests)
    if [[ -f "${test_dir}/test.sh" ]]; then
        cp "${test_dir}/test.sh" "${work_dir}/"
    fi

    # Write tfvars
    cat > "${work_dir}/terraform.tfvars" <<EOF
pkcs11_pin = "${PKCS11_PIN}"
EOF

    cd "${work_dir}"

    if [[ -f "${work_dir}/test.sh" ]]; then
        # Custom test script
        test_output=""
        if ! test_output=$(bash "${work_dir}/test.sh" 2>&1); then
            log_fail "${test_name}: test.sh failed"
            echo "${test_output}" | tail -30
            FAILED=$((FAILED + 1))
            FAILED_TESTS+=("${test_name}")
            terraform destroy -auto-approve -no-color >/dev/null 2>&1 || true
        elif echo "${test_output}" | grep -q "Check block assertion failed"; then
            log_fail "${test_name}: check assertion(s) failed"
            echo "${test_output}" | grep -A2 "Check block assertion" | head -20
            FAILED=$((FAILED + 1))
            FAILED_TESTS+=("${test_name}")
        else
            log_pass "${test_name}"
            PASSED=$((PASSED + 1))
        fi
    else
        # Single-phase apply + destroy
        apply_output=""
        apply_ok=true

        if ! apply_output=$(terraform apply -auto-approve -no-color 2>&1); then
            apply_ok=false
        fi

        if ${apply_ok}; then
            if echo "${apply_output}" | grep -q "Check block assertion failed"; then
                log_fail "${test_name}: check assertion(s) failed"
                echo "${apply_output}" | grep -A2 "Check block assertion" | head -20
                FAILED=$((FAILED + 1))
                FAILED_TESTS+=("${test_name}")
                terraform destroy -auto-approve -no-color >/dev/null 2>&1 || true
            else
                destroy_output=""
                if ! destroy_output=$(terraform destroy -auto-approve -no-color 2>&1); then
                    log_fail "${test_name}: destroy failed"
                    echo "${destroy_output}" | tail -10
                    FAILED=$((FAILED + 1))
                    FAILED_TESTS+=("${test_name}")
                else
                    log_pass "${test_name}"
                    PASSED=$((PASSED + 1))
                fi
            fi
        else
            log_fail "${test_name}: apply failed"
            echo "${apply_output}" | tail -20
            FAILED=$((FAILED + 1))
            FAILED_TESTS+=("${test_name}")
            terraform destroy -auto-approve -no-color >/dev/null 2>&1 || true
        fi
    fi

    # Clean up working directory
    rm -rf "${work_dir}"
    echo ""

done

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "Results: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC}, ${YELLOW}${SKIPPED} skipped${NC}"

if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
    echo ""
    echo "Failed tests:"
    for t in "${FAILED_TESTS[@]}"; do
        echo -e "  ${RED}✗${NC} ${t}"
    done
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Exit with failure if any test failed
if [[ ${FAILED} -gt 0 ]]; then
    exit 1
fi
