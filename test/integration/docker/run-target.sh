#!/usr/bin/env bash
#
# Build the base image, build the per-target image, run the integration
# test. Used by both CTest and developers iterating locally.
#
# Args:
#   $1  target name (e.g. lightftp)
#   $2  build context dir (repo root)
#   $3  base Dockerfile path
#   $4  base image tag
#   $5  target Dockerfile path
#   $6  target image tag
#   $7  host lib dir (bind-mounted into container at /opt/nfl/lib)
#   $8+ optional KEY=VAL pairs, passed as `-e KEY=VAL` to docker run.
#       Used by the `programs` target to select the binary + scenario for
#       each ctest entry without needing a separate image per variant.
#
# A developer can re-run a failed CI test with the exact same command CTest
# uses by copying it from `ctest -R integration.docker.lightftp -V`.
#
# To debug interactively:
#   docker run --rm -it \
#       -v <repo>/cmake-build-debug/lib:/opt/nfl/lib:ro \
#       --entrypoint=/opt/nfl/bin/nfl-entrypoint \
#       netfuzzlib-test-<name> shell
#   docker run --rm \
#       -v <repo>/cmake-build-debug/lib:/opt/nfl/lib:ro \
#       --entrypoint=/opt/nfl/bin/nfl-entrypoint \
#       netfuzzlib-test-<name> daemon-only
# (in another terminal: `docker exec -it <id> bash` to poke).
#
# The libnfl + module .so files are NOT baked into the image.
# They're bind-mounted from the host's CMake build dir. Source-only
# edits don't trigger a Docker rebuild. Just `cmake --build` and re-run.

set -euo pipefail

TARGET_NAME="$1"
BUILD_CONTEXT="$2"
BASE_DOCKERFILE="$3"
BASE_TAG="$4"
TARGET_DOCKERFILE="$5"
TARGET_TAG="$6"
HOST_LIB_DIR="$7"
shift 7
ENV_ARGS=()
for kv in "$@"; do
    ENV_ARGS+=(-e "$kv")
done

if [[ ! -f "$HOST_LIB_DIR/libnfl.so" || \
      ! -f "$HOST_LIB_DIR/libmodule-bridge-kernel.so" ]]; then
    echo "[run-target] $HOST_LIB_DIR doesn't contain the libs." >&2
    echo "[run-target] Run \`cmake --build <build-dir>\` first to populate it." >&2
    exit 2
fi

# Translate a path that's valid in *this* mount namespace into the path
# the *outer* docker daemon would see. This matters when we're running
# inside a devcontainer/CI container that mounts `docker.sock` from the
# host: `docker run -v <p>:...` is interpreted by the host daemon, so
# <p> must be a host path. Without this, the bind silently lands at a
# non-existent host path and Docker creates an empty directory there,
# which is exactly the symptom that wasted an afternoon.
translate_to_host_path() {
    local container_path="$1"
    [[ -e /.dockerenv ]] || { echo "$container_path"; return 0; }
    # mountinfo line layout (whitespace-separated):
    #   id parent maj:min root mountpoint options ...
    # field 4 (root) = path inside source FS, field 5 (mountpoint) = where it lands here
    local best_mp="" best_root=""
    while read -r _ _ _ root mp _; do
        case "$container_path" in
            "$mp"|"$mp"/*)
                if (( ${#mp} > ${#best_mp} )); then
                    best_mp="$mp"
                    best_root="$root"
                fi
                ;;
        esac
    done < /proc/self/mountinfo
    if [[ -z "$best_mp" ]]; then
        echo "$container_path"
        return 0
    fi
    local suffix="${container_path#$best_mp}"
    echo "${best_root}${suffix}"
}

HOST_LIB_DIR_NATIVE="$(translate_to_host_path "$HOST_LIB_DIR")"
if [[ "$HOST_LIB_DIR_NATIVE" != "$HOST_LIB_DIR" ]]; then
    echo "[run-target] dev-container detected: translated $HOST_LIB_DIR -> $HOST_LIB_DIR_NATIVE" >&2
fi

echo "[run-target] building base image ${BASE_TAG} ..."
docker build -f "$BASE_DOCKERFILE" -t "$BASE_TAG" "$BUILD_CONTEXT" >&2

echo "[run-target] building target image ${TARGET_TAG} ..."
docker build -f "$TARGET_DOCKERFILE" -t "$TARGET_TAG" "$BUILD_CONTEXT" >&2

echo "[run-target] running ${TARGET_NAME} test ..."
# Per-target docker-args hook: if <target>/docker-args exists, its
# whitespace-separated contents are spliced into the `docker run`
# command line. Lets a target opt in to extra capabilities, mounts,
# limits etc. without polluting unrelated tests. Used today by
# pure-ftpd, which calls capset() during init (its hardening path)
# and aborts with "421 Unable to switch capabilities" because Docker
# drops CAP_SETPCAP from the default bounding set.
EXTRA_DOCKER_ARGS=()
TARGET_ARGS_FILE="$(dirname "$TARGET_DOCKERFILE")/docker-args"
if [[ -f "$TARGET_ARGS_FILE" ]]; then
    # shellcheck disable=SC2207
    EXTRA_DOCKER_ARGS=( $(cat "$TARGET_ARGS_FILE") )
    echo "[run-target] extra docker args from ${TARGET_ARGS_FILE}: ${EXTRA_DOCKER_ARGS[*]}" >&2
fi

# --init: PID 1 forwards signals so CTest's TIMEOUT actually kills the
# daemon. Without it, lightftp's worker threads ignore SIGTERM and the
# test wedges until the docker default 10s SIGKILL.
# --rm: clean up on exit. CTest captures stdout/stderr.
# -v ...:/opt/nfl/lib:ro: read-only mount of the host's CMake lib output.
# This is the optimization that lets source edits skip the Docker rebuild.
exec docker run --rm --init \
    -v "${HOST_LIB_DIR_NATIVE}:/opt/nfl/lib:ro" \
    "${EXTRA_DOCKER_ARGS[@]}" \
    "${ENV_ARGS[@]}" \
    "$TARGET_TAG" test
