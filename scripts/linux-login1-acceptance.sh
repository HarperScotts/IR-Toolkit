#!/bin/sh
# Capture ONLY the scoped diagnostic; never install, authenticate, start or alter
# a service. Reports are sensitive. This script is not an acceptance attestation.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
umask 077
if [ "$#" -ne 2 ]; then
  printf 'Usage: sh scripts/linux-login1-acceptance.sh /absolute/path/to/ir /new/private/report-directory\n' >&2
  exit 2
fi
task_ir_binary=$1
task_report_dir=$2
case "$task_ir_binary" in /*) ;; *) printf 'Binary path must be absolute\n' >&2; exit 2;; esac
case "$task_report_dir" in /*) ;; *) printf 'Report directory must be absolute and new\n' >&2; exit 2;; esac
if [ "$(uname -s)" != Linux ]; then
  printf 'This capture workflow requires an authorized Linux host\n' >&2
  exit 2
fi
if [ ! -f "$task_ir_binary" ] || [ ! -x "$task_ir_binary" ]; then
  printf 'IR binary must be an existing executable file\n' >&2
  exit 2
fi
if command -v sha256sum >/dev/null 2>&1; then
  task_hash_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  task_hash_tool=shasum
else
  printf 'sha256sum or shasum is required before capturing reports\n' >&2
  exit 2
fi
# mkdir (without -p) atomically refuses an existing leaf, including a symlink.
# Never overwrite an existing report/case or delete a failed capture.
mkdir -m 700 -- "$task_report_dir"
if [ "$task_hash_tool" = sha256sum ]; then
  sha256sum "$task_ir_binary" > "$task_report_dir/binary-before.sha256"
else
  shasum -a 256 "$task_ir_binary" > "$task_report_dir/binary-before.sha256"
fi
if "$task_ir_binary" diagnose-login1 > "$task_report_dir/diagnostic.json" 2> "$task_report_dir/diagnostic.stderr"; then
  task_exit_code=0
else
  task_exit_code=$?
fi
printf '%s\n' "$task_exit_code" > "$task_report_dir/exit-code.txt"
if [ "$task_hash_tool" = sha256sum ]; then
  sha256sum "$task_ir_binary" > "$task_report_dir/binary-after.sha256"
else
  shasum -a 256 "$task_ir_binary" > "$task_report_dir/binary-after.sha256"
fi
(
  cd -- "$task_report_dir"
  if [ "$task_hash_tool" = sha256sum ]; then
    sha256sum diagnostic.json diagnostic.stderr exit-code.txt binary-before.sha256 binary-after.sha256 > SHA256SUMS
  else
    shasum -a 256 diagnostic.json diagnostic.stderr exit-code.txt binary-before.sha256 binary-after.sha256 > SHA256SUMS
  fi
)
printf 'Saved private diagnostic report: %s\n' "$task_report_dir"
printf 'Diagnostic exit code: %s; real-host acceptance is NOT attested. Review JSON, stderr, hashes and manual checklist.\n' "$task_exit_code"
exit "$task_exit_code"
