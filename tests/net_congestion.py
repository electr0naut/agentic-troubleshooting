"""Dummy process that simulates network congestion with a slow-consumer TCP pattern."""
import argparse
import os
import signal
import socket
import sys
import threading
import time


def server_thread(server_sock, delay):
    """Accept connections and read from them very slowly."""
    conns = []
    server_sock.settimeout(1.0)
    while not _shutdown.is_set():
        try:
            conn, _ = server_sock.accept()
            conns.append(conn)
        except socket.timeout:
            pass
        for c in list(conns):
            try:
                c.setblocking(False)
                try:
                    c.recv(1)
                except BlockingIOError:
                    pass
                c.setblocking(True)
            except OSError:
                conns.remove(c)
        time.sleep(delay)
    for c in conns:
        c.close()


def client_thread(port):
    """Connect and write data continuously to fill send buffers."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", port))
        _client_socks.append(sock)
        data = b"X" * 1024
        while not _shutdown.is_set():
            try:
                sock.sendall(data)
            except OSError:
                break
            time.sleep(0.1)
    except OSError:
        pass


_shutdown = threading.Event()
_client_socks = []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--connections", type=int, default=20, help="Number of client connections")
    parser.add_argument("--server-delay", type=float, default=5.0, help="Server read delay in seconds")
    args = parser.parse_args()

    pid = os.getpid()

    def shutdown(*_):
        _shutdown.set()
        time.sleep(0.5)
        for s in _client_socks:
            try:
                s.close()
            except OSError:
                pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", 0))
    port = server_sock.getsockname()[1]
    server_sock.listen(args.connections + 5)

    print(f"net_congestion started — PID {pid}, port {port}, {args.connections} clients", flush=True)

    srv = threading.Thread(target=server_thread, args=(server_sock, args.server_delay), daemon=True)
    srv.start()

    for _ in range(args.connections):
        t = threading.Thread(target=client_thread, args=(port,), daemon=True)
        t.start()
        time.sleep(0.05)

    print(f"net_congestion running — {args.connections} connections established", flush=True)
    while not _shutdown.is_set():
        time.sleep(1)


if __name__ == "__main__":
    main()
