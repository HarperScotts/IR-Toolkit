#!/bin/sh
set -eu

# Run from any directory. No existing executable or case evidence is overwritten;
# the native black-box smoke test builds its own executable in a test temp root.
task_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$task_root"

for task_tool in go gofmt node rg; do
  if ! command -v "$task_tool" >/dev/null 2>&1; then
    printf 'Required tool missing: %s\n' "$task_tool" >&2
    exit 1
  fi
done

printf 'Checking Go formatting...\n'
task_unformatted=$(rg --files -g '*.go' -g '!node_modules/**' | xargs gofmt -l)
if [ -n "$task_unformatted" ]; then
  printf 'Run gofmt on these files:\n%s\n' "$task_unformatted" >&2
  exit 1
fi

# rg status 1 means no match; status 2 is an execution error, not a passing check.
reject_matches() {
  task_label=$1
  task_pattern=$2
  task_dir=$3
  if rg -n --glob '*.go' "$task_pattern" "$task_dir"; then
    printf 'Boundary violation: %s\n' "$task_label" >&2
    exit 1
  else
    task_status=$?
    if [ "$task_status" -ne 1 ]; then
      printf 'Boundary check failed: %s\n' "$task_label" >&2
      exit "$task_status"
    fi
  fi
}

printf 'Checking Store/Web boundaries...\n'
reject_matches 'Store imports Web' '"ir-toolkit/internal/web"' internal/store
reject_matches 'Store contains Web DTO names' 'web[A-Z]|FileListItem|NetworkListItem|PersistenceListItem|InvestigationSearchResult' internal/store
reject_matches 'Model imports Store or Web' '"ir-toolkit/internal/(store|web)(/[^" ]*)?"' internal/model
reject_matches 'Web imports Central backend' '"ir-toolkit/internal/store/central"' internal/web
reject_matches 'Package parser imports investigation backends' '"ir-toolkit/internal/(web|store|analyzer|collector)(/[^" ]*)?"' internal/packageio
reject_matches 'Completion codec imports investigation backends or package parser' '"ir-toolkit/internal/(web|store|analyzer|collector|packageio)(/[^" ]*)?"' internal/analysiscommit
reject_matches 'Web redefines Store contracts' '^type (CaseStore|FileStore|PersistenceStore|ProcessStore|LoginStore|NetworkStore|TimelineStore|HistoricalProcessStore|PowerShellStore|WindowsEventStore|IOCStore|CorrelationStore|CaseMetadataStore|QueryStore|SearchStore) interface' internal/web
if ! rg -q 'network:%d:%s:%s:%d:%s:%d:%s' internal/store/local; then
  printf 'Network canonical ID format missing\n' >&2
  exit 1
fi

printf 'Running Go vet and tests...\n'
go run scripts/generate-central-snapshot.go -check internal/store/central/snapshot_methods.go
go vet ./...
go test ./...
go vet scripts/package-acceptance.go scripts/package-acceptance_test.go
go test scripts/package-acceptance.go scripts/package-acceptance_test.go
go vet scripts/utmp-abi-check.go scripts/utmp-abi-check_test.go
go test scripts/utmp-abi-check.go scripts/utmp-abi-check_test.go
go vet scripts/build-release.go scripts/build-release_test.go scripts/workflow_test.go
go test scripts/build-release.go scripts/build-release_test.go scripts/workflow_test.go

printf 'Checking frontend scripts and interactions...\n'
sh -n scripts/linux-login1-acceptance.sh
node --check internal/web/static/app.js
node --check internal/web/static/multi-host.js
node --check internal/web/static/linux-logins.js
node --check internal/web/static/linux-login1.js
node --test internal/web/frontend_tests/*.test.cjs

printf 'Cross-compiling Windows amd64 and arm64...\n'
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...
GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build ./...

printf 'Cross-compiling Linux amd64 and arm64...\n'
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...

printf 'All checks passed.\n'
