#!/usr/bin/env bash
# Fills the Docker volume aegis-tf-mirror with every provider the Terraform
# fixtures need (needs network once). Then run the worker with
#   AEGIS_TF_MIRROR_VOLUME=aegis-tf-mirror
# and scans install providers only from the mirror, with no network at all.
set -euo pipefail
cd "$(dirname "$0")/.."
image="${AEGIS_TERRAFORM_IMAGE:-hashicorp/terraform:1.10.5}"
docker volume create aegis-tf-mirror >/dev/null
for dir in datasets/terraform-fixtures/*/; do
  [ -f "$dir/main.tf" ] || continue
  echo "mirroring providers for $dir"
  src="$(cd "$dir" && pwd -W 2>/dev/null || pwd)"
  MSYS_NO_PATHCONV=1 docker run --rm -v aegis-tf-mirror:/mirror -v "$src:/src:ro" -w /src "$image" providers mirror /mirror
done
echo "done: set AEGIS_TF_MIRROR_VOLUME=aegis-tf-mirror for the worker"
