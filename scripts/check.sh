#!/usr/bin/env bash
set -euo pipefail

project_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_directory"

for tool in go helm; do
  command -v "$tool" >/dev/null
done

(
  cd backend
  go build ./...
  go test -race ./...
  go vet ./...
)

for script in scripts/*.sh backend/deploy/*.sh postgres/*.sh; do
  bash -n "$script"
done

bash backend/deploy/infrastructure.sh lint
bash backend/deploy/application.sh lint
bash backend/deploy/application.sh template >/dev/null
bash backend/deploy/images.sh plan >/dev/null

# The runner template downloads the pinned official ARC charts, but does not
# access Kubernetes, register a runner, publish images or deploy anything.
bash backend/deploy/runner.sh template >/dev/null
