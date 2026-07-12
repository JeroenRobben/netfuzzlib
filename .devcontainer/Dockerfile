FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

# Mirror the toolchain used by .github/workflows/ci.yml so a green local build
# is a reasonable proxy for green CI.
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake ninja-build pkg-config \
        gcc-13 g++-13 \
        clang-18 \
        libgtest-dev libgmock-dev \
        libevent-dev libev-dev libuv1-dev \
        netcat-openbsd net-tools inetutils-telnet iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Pre-create the mount point so the named volume in devcontainer.json
# inherits ownership from the vscode user instead of root.
RUN install -d -o vscode -g vscode /home/vscode/.claude
