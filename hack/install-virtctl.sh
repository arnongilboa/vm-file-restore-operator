#!/usr/bin/env bash
#
# Ensure virtctl is on PATH for e2e tests. The kubevirtci golang prow image does
# not ship virtctl; download the release binary matching KUBEVIRT_VERSION.

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"

if command -v virtctl >/dev/null 2>&1; then
	echo "virtctl already on PATH: $(command -v virtctl)" >&2
	return 0 2>/dev/null || exit 0
fi

install_dir="${REPO_ROOT}/.local/bin"
mkdir -p "${install_dir}"

# e2e runs on linux/amd64 (prow bare-metal and local kubevirtci).
url="https://github.com/kubevirt/kubevirt/releases/download/${KUBEVIRT_VERSION}/virtctl-${KUBEVIRT_VERSION}-linux-amd64"
echo "Installing virtctl ${KUBEVIRT_VERSION} to ${install_dir}" >&2
curl -fsSL -o "${install_dir}/virtctl" "${url}"
chmod +x "${install_dir}/virtctl"
export PATH="${install_dir}:${PATH}"
