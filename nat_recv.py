#!/usr/bin/env python3
"""
Receptor para testes manuais do NAT. Escuta portas UDP e TCP, mostra o que
chega e devolve os mesmos bytes (eco).

Exemplos (CLI do Mininet):
    h3 python3 nat_recv.py &                       UDP 9001, TCP 9002
    h3 python3 nat_recv.py --udp 9001 5000 --tcp 9002 80

Também pode rodar em H1/H2 (por exemplo, para testar conexões vindas de H3).
"""

import argparse
import socket
import sys
import threading
import time

print_lock = threading.Lock()


def log(text):
    now = time.time()
    stamp = time.strftime("%H:%M:%S", time.localtime(now)) + ".%03d" % (now % 1 * 1000)
    with print_lock:
        print("%s %s" % (stamp, text), flush=True)


def show(data, limit=64):
    text = repr(data[:limit])
    return text + ("..." if len(data) > limit else "")


def udp_loop(sock):
    port = sock.getsockname()[1]
    while True:
        data, addr = sock.recvfrom(65535)
        log("UDP :%d recvfrom %s:%d: %d bytes: %s"
            % (port, addr[0], addr[1], len(data), show(data)))
        try:
            n = sock.sendto(data, addr)
            log("UDP :%d sendto %s:%d: %d bytes" % (port, addr[0], addr[1], n))
        except OSError as exc:
            log("UDP :%d sendto %s:%d: %s" % (port, addr[0], addr[1], exc))


def tcp_conn(conn, addr, port):
    peer = "%s:%d" % addr
    with conn:
        conn.settimeout(10)
        while True:
            try:
                data = conn.recv(65535)
            except OSError as exc:
                log("TCP :%d recv %s: %s" % (port, peer, exc))
                return
            if not data:
                log("TCP :%d %s encerrou a conexão" % (port, peer))
                return
            log("TCP :%d recv %s: %d bytes: %s" % (port, peer, len(data), show(data)))
            try:
                conn.sendall(data)
                log("TCP :%d send %s: %d bytes" % (port, peer, len(data)))
            except OSError as exc:
                log("TCP :%d send %s: %s" % (port, peer, exc))
                return


def tcp_loop(lsock):
    port = lsock.getsockname()[1]
    while True:
        conn, addr = lsock.accept()
        log("TCP :%d accept %s:%d" % (port, addr[0], addr[1]))
        threading.Thread(target=tcp_conn, args=(conn, addr, port),
                         daemon=True).start()


def main():
    ap = argparse.ArgumentParser(
        description="Receptor UDP/TCP com eco.",
        epilog=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--udp", type=int, nargs="*", default=[9001],
                    help="portas UDP (padrão: 9001)")
    ap.add_argument("--tcp", type=int, nargs="*", default=[9002],
                    help="portas TCP (padrão: 9002)")
    args = ap.parse_args()

    threads = []
    for port in args.udp:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError as exc:
            log("UDP bind 0.0.0.0:%d: %s" % (port, exc))
            sys.exit(1)
        log("UDP escutando em 0.0.0.0:%d" % port)
        threads.append(threading.Thread(target=udp_loop, args=(sock,), daemon=True))

    for port in args.tcp:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
            sock.listen(20)
        except OSError as exc:
            log("TCP bind 0.0.0.0:%d: %s" % (port, exc))
            sys.exit(1)
        log("TCP escutando em 0.0.0.0:%d" % port)
        threads.append(threading.Thread(target=tcp_loop, args=(sock,), daemon=True))

    for t in threads:
        t.start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
