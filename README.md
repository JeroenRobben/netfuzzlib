# netfuzzlib

[![CI](https://github.com/JeroenRobben/netfuzzlib/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/JeroenRobben/netfuzzlib/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](LICENSE-APACHE)

This framework intercepts libc network I/O related syscall wrappers like `accept()`/`recv()`/`send()`/`poll()` and routes them to the callbacks in [`callbacks.h`](include/netfuzzlib/callbacks.h). You can use this for efficient [fuzzing over network I/O](examples/afl), or any other case where you don't want network I/O to go through the kernel.
For the full rationale, see the [paper](http://papers.mathyvanhoef.com/esorics2024.pdf). The callback API has changed since, but the core design remains the same. 

## Usage

To use netfuzzlib, you need to implement the callbacks in [`callbacks.h`](include/netfuzzlib/callbacks.h) and link both your code and the core framework (`libnfl.so/a`) with the target, e.g., by using `LD_PRELOAD`. See [`examples/hello-world`](examples/hello-world) to get started.

Callback implementations for AFL++ are in [`examples/afl/`](examples/afl/).

> [!IMPORTANT]
> Always first check that the framework drives your target correctly. A possible smoke test is to replay a known-good trace and check that your target processes it as expected.

## Build

```sh
cmake -S . -B build && cmake --build build
```

Resulting libraries are put in `build/lib/`. `libnfl.so` is the core framework without any callback implementations, the examples (`libnfl-hello-world.so` and `libnfl-afl.so`) link in both the framework and corresponding callback implementations.

Test with netcat:

```sh
LD_PRELOAD=/path/to/libnfl-hello-world.so nc 1.2.3.4 5678
```

## Run tests

```sh
ctest --test-dir build -LE integration            # unit tests
ctest --test-dir build -L integration             # all
ctest --test-dir build -L integration -LE docker  # skip docker targets
ctest --test-dir build -L docker                  # only docker targets
```

## Limitations

### ! Multithreaded and multi-process targets

The framework is **not multi-process aware**: after fork(), each process has its own copy of the network environment state, including the (possible) internal state of your callbacks. Calling exit() from a callback only terminates the current process.

Targets that open sockets, then do an `execve()` and still operate on them afterwards likely won't work as expected. The framework lives in process memory, so any program that execs a fresh image while modelled sockets are open loses them, and the new image starts with an empty network environment.

### Missing syscalls

The framework does not implement [io_uring](https://man7.org/linux/man-pages/man7/io_uring.7.html). As a workaround, io_uring returns ENOSYS, as if it was run on an older kernel (<5.1). Some targets (e.g., based on libuv) fall back to epoll then.

### Signals

Since all I/O happens through callbacks, it does not support signal-driven async I/O (e.g., aio(7) or SIGIO). The framework does generate a SIGPIPE when writing to a closed TCP connection without the MSG_NOSIGNAL flag.

## Questions

If you have any questions or found a bug, feel free to create a GitHub issue or send an email to <jeroen@robben.io>.
