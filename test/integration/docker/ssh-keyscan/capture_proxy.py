#!/usr/bin/env python3
# Minimal TCP proxy that records the server->client direction of one
# connection to a file. Usage: capture_proxy.py LISTEN_PORT UPSTREAM_PORT OUTFILE
import socket, sys, threading

listen_port, upstream_port, outfile = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]

ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", listen_port))
ls.listen(1)

client, _ = ls.accept()
upstream = socket.create_connection(("127.0.0.1", upstream_port))

captured = bytearray()

def c2u():
    try:
        while True:
            b = client.recv(65536)
            if not b:
                break
            upstream.sendall(b)
    except OSError:
        pass
    finally:
        try: upstream.shutdown(socket.SHUT_WR)
        except OSError: pass

def u2c():
    try:
        while True:
            b = upstream.recv(65536)
            if not b:
                break
            captured.extend(b)
            client.sendall(b)
    except OSError:
        pass
    finally:
        try: client.shutdown(socket.SHUT_WR)
        except OSError: pass

t1 = threading.Thread(target=c2u)
t2 = threading.Thread(target=u2c)
t1.start(); t2.start()
t1.join(); t2.join()

with open(outfile, "wb") as f:
    f.write(captured)
print(f"captured {len(captured)} server->client bytes to {outfile}")
