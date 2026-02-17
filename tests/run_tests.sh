#!/usr/bin/env bash
set -euo pipefail

# YubiHSM Integration Test Runner for terraform-provider-pkcs11
#
# Usage:
#   ./tests/run_tests.sh                    # Run all tests
#   ./tests/run_tests.sh test_01 test_05    # Run specific tests
#   PKCS11_PIN=mypin ./tests/run_tests.sh   # Override PIN via env
#
# Prerequisites:
#   - YubiHSM2 connected and yubihsm-connector running
#   - /usr/lib/pkcs11/yubihsm_pkcs11.so installed
#   - /etc/yubihsm_pkcs11.conf configured
#   - Go toolchain installed
#   - Terraform installed

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROVIDER_BINARY="${PROJECT_DIR}/terraform-provider-pkcs11"
PROVIDER_TF="${SCRIPT_DIR}/provider.tf"

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

# Default PIN (can be overridden via env or terraform.tfvars)
PKCS11_PIN="${PKCS11_PIN:-0001password}"

cleanup() {
    # Remove terraformrc if we created it
    if [[ -n "${TERRAFORMRC_FILE:-}" && -f "${TERRAFORMRC_FILE}" ]]; then
        rm -f "${TERRAFORMRC_FILE}"
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

    # Copy provider config and test files
    cp "${PROVIDER_TF}" "${work_dir}/"
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
    elif [[ -f "${work_dir}/wrap.tf" ]]; then
        # Two-phase unwrap test: wrap -> destroy original -> unwrap
        # YubiHSM preserves the object ID in wrapped blobs, so the original
        # must be deleted before unwrapping.
        wrap_dir="$(mktemp -d)"
        cp "${work_dir}/provider.tf" "${wrap_dir}/"
        cp "${work_dir}/wrap.tf" "${wrap_dir}/main.tf"
        cp "${work_dir}/terraform.tfvars" "${wrap_dir}/"

        test_output=""
        test_ok=true

        # Phase 1: create keys and wrap
        if ! test_output=$(cd "${wrap_dir}" && terraform apply -auto-approve -no-color 2>&1); then
            log_fail "${test_name}: wrap phase apply failed"
            echo "${test_output}" | tail -20
            test_ok=false
        fi

        if ${test_ok}; then
            WRAPPED_MATERIAL=$(cd "${wrap_dir}" && terraform output -raw wrapped_key_material 2>&1) || true

            # Targeted destroy: remove original + wrapped, keep wrapping key
            phase1_targets=(-target=pkcs11_wrapped_key.wrapped -target=pkcs11_symmetric_key.original_key)
            if [[ -f "${test_dir}/phase1_targets" ]]; then
                phase1_targets=()
                while IFS= read -r target; do
                    [[ -n "${target}" ]] && phase1_targets+=(-target="${target}")
                done < "${test_dir}/phase1_targets"
            fi

            if ! test_output=$(cd "${wrap_dir}" && terraform destroy -auto-approve -no-color "${phase1_targets[@]}" 2>&1); then
                log_fail "${test_name}: wrap phase targeted destroy failed"
                echo "${test_output}" | tail -20
                test_ok=false
            fi
        fi

        # Phase 2: unwrap using the captured material
        if ${test_ok}; then
            cd "${work_dir}"
            rm -f wrap.tf
            if ! test_output=$(terraform apply -auto-approve -no-color -var="wrapped_key_material=${WRAPPED_MATERIAL}" 2>&1); then
                log_fail "${test_name}: unwrap phase apply failed"
                echo "${test_output}" | tail -20
                test_ok=false
            elif echo "${test_output}" | grep -q "Check block assertion failed"; then
                log_fail "${test_name}: check assertion(s) failed"
                echo "${test_output}" | grep -A2 "Check block assertion" | head -20
                test_ok=false
            fi
        fi

        if ${test_ok}; then
            cd "${work_dir}"
            if ! test_output=$(terraform destroy -auto-approve -no-color -var="wrapped_key_material=${WRAPPED_MATERIAL}" 2>&1); then
                log_fail "${test_name}: unwrap phase destroy failed"
                echo "${test_output}" | tail -10
                test_ok=false
            fi
        fi

        if ${test_ok}; then
            log_pass "${test_name}"
            PASSED=$((PASSED + 1))
        else
            FAILED=$((FAILED + 1))
            FAILED_TESTS+=("${test_name}")
        fi

        # Always clean up wrapping key from HSM
        cd "${wrap_dir}" 2>/dev/null && terraform destroy -auto-approve -no-color >/dev/null 2>&1 || true
        rm -rf "${wrap_dir}"
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
