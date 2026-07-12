#!/bin/bash
# Integration-test driver for an `integration/cases/<name>/` directory.
#
# Reads from the case directory:
#   cmd                  shell pipeline executed via bash. May reference
#                        $NFL_LD_PRELOAD to apply the preload to a single
#                        pipeline stage. Setting LD_PRELOAD on the bash
#                        process itself would load the scripted module into
#                        the wrapper and trip its atexit hook.
#   scenario.txt         optional. Drives the scripted module's deliver/
#                        expect/tcp_accept directives. Empty/missing means
#                        "no scripted I/O contract", useful for tools that
#                        only query model state (ifconfig, ip).
#   stdout.expected      optional. Each non-blank/non-# line is an extended
#                        regex. The SUT's stdout must contain a match for
#                        every line. Order isn't enforced.
#
# Required env from the caller (CMake):
#   NFL_LD_PRELOAD       preload path, propagated into the shell as a
#                        plain variable (NOT named LD_PRELOAD).
#
# Exit codes:
#   0    cmd exited 0 and every stdout pattern matched.
#   1    cmd's exit code (when non-zero) or stdout-pattern mismatch.
#   2    case directory is malformed.

set -uo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <case-dir>" >&2
    exit 2
fi
case_dir="$1"
cmd_file="$case_dir/cmd"
scenario="$case_dir/scenario.txt"
patterns="$case_dir/stdout.expected"

if [[ ! -f "$cmd_file" ]]; then
    echo "$case_dir: missing 'cmd' file" >&2
    exit 2
fi
if [[ -z "${NFL_LD_PRELOAD:-}" ]]; then
    echo "$case_dir: NFL_LD_PRELOAD must be set by the caller" >&2
    exit 2
fi

# Prefer a real scenario. Fall back to /dev/null so the scripted module sees
# an empty directive list (ok when the SUT only queries state).
if [[ -f "$scenario" ]]; then
    export NFL_TEST_SCENARIO="$scenario"
else
    export NFL_TEST_SCENARIO=/dev/null
fi

cmd=$(<"$cmd_file")
actual=$(bash -c "$cmd")
rc=$?

if [[ -f "$patterns" ]]; then
    while IFS= read -r pat; do
        [[ -z "$pat" || "$pat" == \#* ]] && continue
        if ! grep -qE "$pat" <<< "$actual"; then
            echo "$case_dir: stdout missing pattern: $pat" >&2
            echo "--- actual stdout (rc=$rc) ---" >&2
            echo "$actual" >&2
            exit 1
        fi
    done < "$patterns"
fi

exit "$rc"
