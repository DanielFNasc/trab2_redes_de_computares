#!/usr/bin/env python3
"""
Emissor para testes manuais do NAT. Envia uma mensagem UDP ou TCP e mostra
o resultado de cada chamada de socket, com as mensagens de erro do sistema.

Exemplos (CLI do Mininet; "h3" é trocado pelo IP de H3 automaticamente):
    h1 python3 nat_send.py udp h3 9001
    h1 python3 nat_send.py udp h3 9001 --sport 5000 --count 3
    h2 python3 nat_send.py tcp h3 9002 --sport 5000 --msg teste
"""

import argparse
import socket
import sys
import time


def log(text):
    now = time.time()
    stamp = time.strftime("%H:%M:%S", time.localtime(now)) + ".%03d" % (now % 1 * 1000)
    print("%s %s" % (stamp, text), flush=True)


def show(data, limit=64):
    text = repr(data[:limit])
    return text + ("..." if len(data) > limit else "")


def local_addr(sock):
    ip, port = sock.getsockname()[:2]
    return "%s:%d" % (ip, port)


def run_udp(args, payload):
    dst = (args.dst, args.dport)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    try:
        sock.bind(("0.0.0.0", args.sport))
    except OSError as exc:
        log("bind 0.0.0.0:%d: %s" % (args.sport, exc))
        return 1

    for i in range(args.count):
        if i:
            time.sleep(args.interval)
        try:
            n = sock.sendto(payload, dst)
            log("sendto %s:%d (local %s): %d bytes: %s"
                % (dst[0], dst[1], local_addr(sock), n, show(payload)))
        except OSError as exc:
            log("sendto %s:%d: %s" % (dst[0], dst[1], exc))
            continue
        try:
            data, addr = sock.recvfrom(65535)
            log("recvfrom %s:%d: %d bytes: %s" % (addr[0], addr[1], len(data), show(data)))
        except OSError as exc:
            log("recvfrom: %s" % exc)

    sock.close()
    return 0


def run_tcp(args, payload):
    dst = (args.dst, args.dport)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(args.timeout)
    try:
        sock.bind(("0.0.0.0", args.sport))
    except OSError as exc:
        log("bind 0.0.0.0:%d: %s" % (args.sport, exc))
        return 1

    try:
        sock.connect(dst)
        log("connect %s:%d (local %s): ok" % (dst[0], dst[1], local_addr(sock)))
    except OSError as exc:
        log("connect %s:%d: %s" % (dst[0], dst[1], exc))
        sock.close()
        return 1

    for i in range(args.count):
        if i:
            time.sleep(args.interval)
        try:
            sock.sendall(payload)
            log("send: %d bytes: %s" % (len(payload), show(payload)))
        except OSError as exc:
            log("send: %s" % exc)
            break
        try:
            data = sock.recv(65535)
        except OSError as exc:
            log("recv: %s" % exc)
            continue
        if not data:
            log("recv: conexão encerrada pelo outro lado")
            break
        log("recv: %d bytes: %s" % (len(data), show(data)))

    sock.close()
    log("close")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Emissor UDP/TCP para testes manuais.",
        epilog=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("proto", choices=("udp", "tcp"))
    ap.add_argument("dst", help="IP de destino")
    ap.add_argument("dport", type=int, help="porta de destino")
    ap.add_argument("--sport", type=int, default=0,
                    help="porta de origem (padrão: escolhida pelo sistema)")
    ap.add_argument("--msg", default="hello", help="conteúdo enviado")
    ap.add_argument("--count", type=int, default=1, help="número de envios")
    ap.add_argument("--interval", type=float, default=1.0,
                    help="intervalo entre envios, em segundos")
    ap.add_argument("--timeout", type=float, default=3.0,
                    help="tempo máximo de espera por resposta, em segundos")
    args = ap.parse_args()

    payload = args.msg.encode()
    if args.proto == "udp":
        sys.exit(run_udp(args, payload))
    sys.exit(run_tcp(args, payload))


if __name__ == "__main__":
    main()
