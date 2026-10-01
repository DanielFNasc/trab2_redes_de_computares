#!/usr/bin/env python3
"""
Servidor de testes do Trabalho 2 (NAT em P4). Executar em H3:

    mininet> h3 python3 server_NAT.py > /dev/null 2>&1 &

Cada inicialização começa uma sessão de correção nova: o diretório
nat_obs/ (ao lado deste script) é limpo. As observações do servidor e os
resultados dos clientes ficam nesse diretório; o log completo do servidor
fica em nat_obs/server.log.

Precisa de root para os raw sockets que inspecionam os pacotes que chegam
a H3 (no Mininet os hosts já rodam como root). Apenas biblioteca padrão.
"""

import argparse
import json
import os
import socket
import struct
import sys
import threading
import time

SERVER_IP = "200.0.0.2"
PUBLIC_NAT_IP = "200.0.0.1"

UDP_PORT = 9001
TCP_PORT = 9002

# Regras manuais do bônus: porta pública de S1 usada para alcançar cada host.
BONUS_PUBLIC_PORT = {"h1": 8080, "h2": 2222}

# Intervalo máximo (s) entre as mensagens de H1 e H2 no teste de colisão.
COLLISION_WINDOW = 15.0

DEFAULT_OBS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "nat_obs"
)

HOSTS = ("h1", "h2")
HEX_DIGITS = set("0123456789abcdef")


# ----------------------------------------------------------------------
# Utilitários
# ----------------------------------------------------------------------

def valid_nonce(nonce):
    return (
        isinstance(nonce, str)
        and 8 <= len(nonce) <= 32
        and set(nonce) <= HEX_DIGITS
    )


def encode(obj):
    return (json.dumps(obj) + "\n").encode()


def decode(data):
    try:
        obj = json.loads(data.decode().strip())
    except (UnicodeDecodeError, ValueError):
        return None
    return obj if isinstance(obj, dict) else None


def recv_json_line(sock, limit=65536):
    data = b""
    while not data.endswith(b"\n") and len(data) <= limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    obj = decode(data)
    if obj is None:
        raise ValueError("mensagem inválida ou conexão encerrada")
    return obj


def ones_complement_sum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def l4_checksum_status(src, dst, proto, segment, field):
    """Verifica o checksum TCP/UDP (com pseudo-cabeçalho) como chegou em H3."""
    if proto == socket.IPPROTO_UDP and field == 0:
        return "zero"
    pseudo = src + dst + struct.pack("!BBH", 0, proto, len(segment))
    if ones_complement_sum(pseudo + segment) == 0xFFFF:
        return "valid"
    return "invalid"


def parse_ipv4(pkt):
    """Retorna (src, dst, proto, segmento L4) ou None."""
    if len(pkt) < 20 or pkt[0] >> 4 != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    total_len = struct.unpack("!H", pkt[2:4])[0]
    frag_offset = struct.unpack("!H", pkt[6:8])[0] & 0x1FFF
    if ihl < 20 or total_len > len(pkt) or frag_offset:
        return None
    return pkt[12:16], pkt[16:20], pkt[9], pkt[ihl:total_len]


# ----------------------------------------------------------------------
# Servidor
# ----------------------------------------------------------------------

class Server:

    def __init__(self, obs_dir):
        self.obs_dir = obs_dir
        self.raw = {"udp": False, "tcp": False, "icmp": False}
        self.log_lock = threading.Lock()
        self.collision_lock = threading.Lock()
        self.collision_peers = {}
        self.collision_logged = set()
        self.bonus_lock = threading.Lock()
        self.bonus_results = {}

    # --- infraestrutura -------------------------------------------------

    def log(self, text):
        line = time.strftime("%H:%M:%S ") + text
        with self.log_lock:
            print(line, flush=True)
            try:
                with open(os.path.join(self.obs_dir, "server.log"), "a") as f:
                    f.write(line + "\n")
            except OSError:
                pass

    def write_obs(self, name, obj):
        final = os.path.join(self.obs_dir, name + ".json")
        tmp = "%s.%d.tmp" % (final, threading.get_ident())
        try:
            with open(tmp, "w") as f:
                json.dump(obj, f)
            os.replace(tmp, final)
        except OSError as exc:
            self.log("[ERRO] não foi possível gravar %s: %s" % (name, exc))

    def send(self, sock, obj, addr):
        try:
            sock.sendto(encode(obj), addr)
        except OSError as exc:
            self.log("[ERRO] envio para %s:%d falhou: %s" % (addr[0], addr[1], exc))

    # --- raw sockets: o que realmente chega em H3 ------------------------

    def open_raw(self, name, proto):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        except OSError as exc:
            self.log(
                "[AVISO] raw socket %s indisponível (%s). "
                "Execute como root." % (name.upper(), exc)
            )
            return None
        self.raw[name] = True
        return sock

    def sniff(self, sock, proto, handler):
        while True:
            try:
                pkt = sock.recv(65535)
            except OSError:
                continue
            parsed = parse_ipv4(pkt)
            if parsed is None or parsed[2] != proto:
                continue
            try:
                handler(*parsed)
            except Exception as exc:  # pacote malformado não derruba o sniffer
                self.log("[ERRO] sniffer: %s" % exc)

    def on_raw_udp(self, src, dst, proto, seg):
        if len(seg) < 8:
            return
        sport, dport, _, csum = struct.unpack("!HHHH", seg[:8])
        if dport != UDP_PORT:
            return
        msg = decode(seg[8:])
        if not msg or msg.get("test") != "udp-basic":
            return
        if not valid_nonce(msg.get("nonce")):
            return
        seen_ip = socket.inet_ntoa(src)
        status = l4_checksum_status(src, dst, proto, seg, csum)
        self.write_obs("udp_" + msg["nonce"], {
            "seen_ip": seen_ip,
            "seen_port": sport,
            "checksum": status,
            "time": time.time(),
        })
        self.log("[UDP] %s: chegou de %s:%d (checksum %s)"
                 % (msg.get("id"), seen_ip, sport, status))

    def on_raw_tcp(self, src, dst, proto, seg):
        if len(seg) < 20:
            return
        sport, dport = struct.unpack("!HH", seg[:4])
        flags = seg[13]
        if dport != TCP_PORT or not flags & 0x02 or flags & 0x10:
            return  # só SYN inicial
        csum = struct.unpack("!H", seg[16:18])[0]
        seen_ip = socket.inet_ntoa(src)
        status = l4_checksum_status(src, dst, proto, seg, csum)
        self.write_obs("tcpsyn_%d" % sport, {
            "seen_ip": seen_ip,
            "seen_port": sport,
            "checksum": status,
            "time": time.time(),
        })
        self.log("[TCP] SYN de %s:%d (checksum %s)" % (seen_ip, sport, status))

    def on_raw_icmp(self, src, dst, proto, seg):
        if len(seg) < 8 or seg[0] != 8:
            return  # só echo request
        seen_ip = socket.inet_ntoa(src)
        self.write_obs("icmp_%d" % time.time_ns(), {
            "seen_ip": seen_ip,
            "payload": seg[8:].hex(),
            "time": time.time(),
        })
        self.log("[ICMP] echo request de %s chegou em H3" % seen_ip)

    # --- serviço UDP -----------------------------------------------------

    def udp_loop(self, sock):
        while True:
            try:
                data, addr = sock.recvfrom(65535)
            except OSError:
                continue
            msg = decode(data)
            if not msg or msg.get("id") not in HOSTS:
                continue
            if not valid_nonce(msg.get("nonce")):
                continue
            test = msg.get("test")
            if test == "udp-basic":
                self.on_udp_basic(sock, msg, addr)
            elif test == "collision":
                self.on_collision(sock, msg, addr)
            elif test == "bonus-request":
                threading.Thread(
                    target=self.on_bonus,
                    args=(sock, msg, addr),
                    daemon=True,
                ).start()

    def on_udp_basic(self, sock, msg, addr):
        nonce = msg["nonce"]
        self.send(sock, {
            "test": "udp-basic",
            "id": msg["id"],
            "nonce": nonce,
            "seen_ip": addr[0],
            "seen_port": addr[1],
        }, addr)

        if not self.raw["udp"]:
            # Sem raw socket: registra o que o socket comum viu.
            self.write_obs("udp_" + nonce, {
                "seen_ip": addr[0],
                "seen_port": addr[1],
                "checksum": "unavailable",
                "time": time.time(),
            })
            self.log("[UDP] %s: chegou de %s:%d" % (msg["id"], addr[0], addr[1]))

    def on_collision(self, sock, msg, addr):
        cid = msg["id"]
        other = "h2" if cid == "h1" else "h1"
        now = time.time()

        with self.collision_lock:
            self.collision_peers[cid] = {
                "addr": addr,
                "nonce": msg["nonce"],
                "time": now,
            }
            peer = self.collision_peers.get(other)
            if peer is None or now - peer["time"] > COLLISION_WINDOW:
                return  # o outro host ainda não apareceu nesta rodada
            pair = {cid: dict(self.collision_peers[cid]), other: dict(peer)}
            key = (pair["h1"]["nonce"], pair["h2"]["nonce"])
            first_time = key not in self.collision_logged
            self.collision_logged.add(key)

        a1 = pair["h1"]["addr"]
        a2 = pair["h2"]["addr"]
        ok = (
            a1[0] == PUBLIC_NAT_IP
            and a2[0] == PUBLIC_NAT_IP
            and a1[1] != a2[1]
        )
        mappings = {
            h: {"ip": pair[h]["addr"][0], "port": pair[h]["addr"][1]}
            for h in HOSTS
        }
        for h in HOSTS:
            self.send(sock, {
                "test": "collision",
                "id": h,
                "nonce": pair[h]["nonce"],
                "ok": ok,
                "mappings": mappings,
            }, pair[h]["addr"])

        if first_time:
            self.log("[COLISÃO] H1 -> %s:%d | H2 -> %s:%d | %s"
                     % (a1[0], a1[1], a2[0], a2[1], "PASS" if ok else "FAIL"))

    def on_bonus(self, sock, msg, addr):
        cid = msg["id"]
        nonce = msg["nonce"]

        with self.bonus_lock:
            if nonce in self.bonus_results:
                done = self.bonus_results[nonce]
                if done is not None:  # retransmissão: reenvia o resultado
                    self.send(sock, done, addr)
                return
            self.bonus_results[nonce] = None

        port = BONUS_PUBLIC_PORT[cid]
        result = {
            "test": "bonus",
            "id": cid,
            "nonce": nonce,
            "public_port": port,
            "connected": False,
            "echo_ok": False,
            "error": "",
        }
        try:
            with socket.create_connection((PUBLIC_NAT_IP, port), timeout=4) as conn:
                result["connected"] = True
                conn.sendall(encode({"test": "bonus", "nonce": nonce}))
                echo = recv_json_line(conn)
                result["echo_ok"] = echo.get("nonce") == nonce
        except (OSError, ValueError) as exc:
            result["error"] = "%s: %s" % (type(exc).__name__, exc)

        with self.bonus_lock:
            self.bonus_results[nonce] = result
        self.send(sock, result, addr)
        self.log("[BÔNUS] %s: %s:%d conectou=%s eco=%s %s"
                 % (cid, PUBLIC_NAT_IP, port, result["connected"],
                    result["echo_ok"], result["error"]))

    # --- serviço TCP -----------------------------------------------------

    def tcp_loop(self, lsock):
        while True:
            try:
                conn, addr = lsock.accept()
            except OSError:
                continue
            threading.Thread(
                target=self.on_tcp_conn,
                args=(conn, addr),
                daemon=True,
            ).start()

    def on_tcp_conn(self, conn, addr):
        with conn:
            try:
                conn.settimeout(5)
                msg = recv_json_line(conn)
                nonce = msg.get("nonce")
                if valid_nonce(nonce):
                    self.write_obs("tcpconn_" + nonce, {
                        "seen_ip": addr[0],
                        "seen_port": addr[1],
                        "time": time.time(),
                    })
                conn.sendall(encode({
                    "test": msg.get("test"),
                    "id": msg.get("id"),
                    "nonce": nonce,
                    "seen_ip": addr[0],
                    "seen_port": addr[1],
                }))
                self.log("[TCP] %s: conexão de %s:%d"
                         % (msg.get("id"), addr[0], addr[1]))
            except (OSError, ValueError) as exc:
                self.log("[TCP] erro na conexão de %s:%d: %s"
                         % (addr[0], addr[1], exc))


def main():
    ap = argparse.ArgumentParser(
        description="Servidor de testes do NAT (executar em H3)."
    )
    ap.add_argument(
        "--obs-dir",
        default=DEFAULT_OBS_DIR,
        help="diretório compartilhado com client_NAT.py (padrão: %(default)s)",
    )
    args = ap.parse_args()

    obs_dir = os.path.abspath(args.obs_dir)
    os.makedirs(obs_dir, exist_ok=True)
    for name in os.listdir(obs_dir):  # nova sessão de correção
        if name.endswith((".json", ".tmp", ".log")):
            try:
                os.remove(os.path.join(obs_dir, name))
            except OSError:
                pass

    srv = Server(obs_dir)
    srv.log("=== Servidor de testes do NAT (H3) ===")

    try:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind((SERVER_IP, UDP_PORT))
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_sock.bind((SERVER_IP, TCP_PORT))
        tcp_sock.listen(20)
    except OSError as exc:
        srv.log("[ERRO] não foi possível abrir as portas em %s: %s" % (SERVER_IP, exc))
        srv.log("       Verifique se o script está rodando em H3.")
        sys.exit(1)

    sniffers = (
        ("udp", socket.IPPROTO_UDP, srv.on_raw_udp),
        ("tcp", socket.IPPROTO_TCP, srv.on_raw_tcp),
        ("icmp", socket.IPPROTO_ICMP, srv.on_raw_icmp),
    )
    for name, proto, handler in sniffers:
        raw = srv.open_raw(name, proto)
        if raw is not None:
            threading.Thread(
                target=srv.sniff,
                args=(raw, proto, handler),
                daemon=True,
            ).start()

    srv.write_obs("server_status", {
        "started": time.time(),
        "raw_sockets": srv.raw,
    })
    srv.log("UDP %s:%d | TCP %s:%d | observações em %s"
            % (SERVER_IP, UDP_PORT, SERVER_IP, TCP_PORT, obs_dir))

    threading.Thread(
        target=srv.udp_loop,
        args=(udp_sock,),
        daemon=True,
    ).start()

    try:
        srv.tcp_loop(tcp_sock)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
