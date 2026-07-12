# afl

netfuzzlib callbacks for fuzzing Linux network daemons under [AFL++].

[AFL++]: https://github.com/AFLplusplus/AFLplusplus
[SnapFuzz]: https://doi.org/10.1145/3533767.3534376

## Usage

```sh
AFL_PRELOAD=/path/to/libnfl-afl.so NFL_PORT=5300
afl-fuzz -i in -o out -- <instrumented-daemon> <daemon args>
```

`NFL_PORT` is the port the target bind / listens on, or connects to.

## Delayed forkserver

We use the *latest safe point* snapshot mechanism described in [SnapFuzz].

**Without setting `AFL_DEFER_FORKSRV=1`**, the forkserver is inserted just before the SUT's `main` entry (afl-cc's default `__afl_auto_init`). This causes the daemon to re-run the full startup for every test case.

**With `AFL_DEFER_FORKSRV=1`**, the delayed forkserver is inserted on whichever happens first of:

1. **`nfl_receive` against the configured SUT endpoint**. The first
   time the daemon tries to read a packet on `NFL_PORT`.
2. **`fork()` from the SUT**.
3. **`pthread_create()` from the SUT**.

## Examples

#### Dnsmasq

# Fuzz dnsmasq with AFL++/

## 1. Build dnsmasq with afl-cc

```sh
wget -q https://thekelleys.org.uk/dnsmasq/dnsmasq-2.91.tar.gz
tar xzf dnsmasq-2.91.tar.gz
make -C dnsmasq-2.91 CC=afl-cc
```

## 2. Create seeds

```bash
mkdir -p in
printf '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x00\x00\x01\x00\x01' > in/q
```

## 3. Fuzz

```sh
AFL_PRELOAD=$NFL/libnfl-afl.so NFL_PORT=5300 \
afl-fuzz -i in -o out -m none -t 5000 -- \
   dnsmasq-2.91/src/dnsmasq --no-daemon --keep-in-foreground \
       --port=5300 --listen-address=127.0.0.1 \
       --no-resolv --no-hosts --cache-size=0 --user=root
```

### Redis

#### 1. Build redis with afl-cc

```sh
wget -q -O redis-7.4.5.tar.gz https://github.com/redis/redis/archive/refs/tags/7.4.5.tar.gz
tar xzf redis-7.4.5.tar.gz
make -C redis-7.4.5 CC=afl-cc MALLOC=libc OPT='-fno-omit-frame-pointer -g'
```

#### 2. Create seeds

```sh
mkdir -p in
printf 'PING\r\n'                  > in/ping
printf '*1\r\n$4\r\nPING\r\n'      > in/ping_resp
```

#### 3. Fuzz

```sh
AFL_PRELOAD=/path/to/libnfl-afl.so NFL_PORT=6379 \
afl-fuzz -i in -o out -m none -t 5000 -- \
   redis-7.4.5/src/redis-server \
      --port 6379 --bind 127.0.0.1 \
      --daemonize no --save '' --appendonly no \
      --logfile '' --protected-mode no
```
