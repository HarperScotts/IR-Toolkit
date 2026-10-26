#!/bin/sh
set -eu

# Opt-in, synthetic data only. Can use about 1.1 GiB logical workspace and
# substantial Go heap in the dense JSON scenario; ordinary checks skip it.
task_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$task_root"
IR_PACKAGE_RESOURCE_PROFILE=1 go test ./internal/cli -run '^TestPackageResourceProfile$' -count=1 -v -timeout=10m
