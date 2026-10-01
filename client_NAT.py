#!/usr/bin/env python3
"""
Cliente de testes do Trabalho 2 (NAT em P4).

A nota tem 10 testes, 1 ponto cada (0 a 10). Cada teste só passa se
funcionar para H1 e para H2:

   1. UDP chegou em H3 (com checksum UDP válido e diferente de zero)
   2. IP UDP foi traduzido para 200.0.0.1
   3. Porta UDP foi preservada
   4. Resposta UDP retornou ao host correto
   5. TCP estabeleceu conexão (implica checksum TCP válido)
   6. IP TCP foi traduzido para 200.0.0.1
   7. Porta TCP foi preservada
   8. Resposta TCP retornou ao host correto
   9. ICMP foi bloqueado
  10. Colisão H1/H2 foi resolvida corretamente (mesma porta de origem ->
      portas públicas distintas, e cada host recebe a sua resposta)

Ponto extra (não entra nos 10): regras manuais 200.0.0.1:8080 -> 10.0.0.1:80
e 200.0.0.1:2222 -> 10.0.0.2:22, funcionando nos dois hosts.

Pré-requisito: server_NAT.py rodando em H3, iniciado a partir do mesmo
diretório deste script (os dois compartilham o diretório nat_obs/).

Uso no CLI do Mininet (o CLI troca "h1"/"h2" pelo IP; o script aceita os dois):

  h3 python3 server_NAT.py > /dev/null 2>&1 &     (uma vez por sessão)

  h1 python3 client_NAT.py h1                     testes 1-9 em H1
  h2 python3 client_NAT.py h2                     testes 1-9 em H2

  h1 python3 client_NAT.py h1 --collision > /tmp/col.txt 2>&1 &
  h2 python3 client_NAT.py h2 --collision         teste 10 (em até 15 s)

  h1 python3 client_NAT.py h1 --bonus             ponto extra
  h2 python3 client_NAT.py h2 --bonus

  h1 python3 client_NAT.py report                 nota final

Apenas biblioteca padrão.
"""

import argparse
import json
import os
import random
import socket
import subprocess
import sys
import threading
import time

SERVER_IP = "200.0.0.2"
PUBLIC_NAT_IP = "200.0.0.1"

UDP_PORT = 9001
TCP_PORT = 9002

HOSTS = ("h1", "h2")
HOST_IP = {"h1": "10.0.0.1", "h2": "10.0.0.2"}

# Faixas de portas disjuntas por host: um sorteio de H1 nunca coincide com
# um mapeamento ativo de H2, então uma troca de porta pelo NAT nos testes
# básicos indica que a porta não foi preservada sem necessidade.
PORT_RANGES = {
    "h1": {"udp": (30000, 32999), "tcp": (40000, 41999)},
    "h2": {"udp": (33000, 35999), "tcp": (42000, 43999)},
}

# Ambos os hosts usam exatamente esta porta no teste de colisão.
COLLISION_SRC_PORT = 45000
COLLISION_TIMEOUT = 20.0
COLLISION_WINDOW = 15.0  # igual ao do servidor

# Regras manuais do ponto extra.
BONUS_PRIVATE_PORT = {"h1": 80, "h2": 22}
BONUS_PUBLIC_PORT = {"h1": 8080, "h2": 2222}

# Os 10 testes da nota. Os 9 primeiros rodam em cada host; o último é a colisão.
TESTS = [
    ("udp_arrived", "UDP chegou em H3"),
    ("udp_ip", "IP UDP foi traduzido para %s" % PUBLIC_NAT_IP),
    ("udp_port", "Porta UDP foi preservada"),
    ("udp_return", "Resposta UDP retornou"),
    ("tcp_conn", "TCP estabeleceu conexão"),
    ("tcp_ip", "IP TCP foi traduzido para %s" % PUBLIC_NAT_IP),
    ("tcp_port", "Porta TCP foi preservada"),
    ("tcp_return", "Resposta TCP retornou"),
    ("icmp", "ICMP foi bloqueado"),
    ("collision", "Colisão H1/H2 foi resolvida corretamente"),
]
TEST_NAME = dict(TESTS)

DEFAULT_OBS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "nat_obs"
)

CHECKSUM_DETAIL = {
    "zero": "checksum UDP igual a zero: o campo não foi recalculado",
    "invalid": "checksum inválido no pacote que chegou em H3",
    "unavailable": "servidor sem raw sockets; execute server_NAT.py como root",
}


# ----------------------------------------------------------------------
# Utilitários
# ----------------------------------------------------------------------

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


def describe(exc):
    return "%s: %s" % (type(exc).__name__, exc)


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save_json(obs_dir, name, obj):
    final = os.path.join(obs_dir, name + ".json")
    tmp = "%s.%d.tmp" % (final, os.getpid())
    try:
        with open(tmp, "w") as f:
            json.dump(obj, f, indent=1)
        os.replace(tmp, final)
    except OSError as exc:
        print("[AVISO] não foi possível gravar %s: %s" % (final, exc))


def wait_obs(obs_dir, name, since, timeout):
    """Espera a observação gravada pelo servidor em H3."""
    path = os.path.join(obs_dir, name + ".json")
    deadline = time.time() + timeout
    while True:
        obj = load_json(path)
        if obj and obj.get("time", 0) >= since - 0.5:
            return obj
        if time.time() >= deadline:
            return None
        time.sleep(0.1)


def fmt_time(ts):
    return time.strftime("%H:%M:%S", time.localtime(ts))


class Checks:

    def __init__(self):
        self.items = []

    def add(self, test_id, name, ok, detail=""):
        ok = bool(ok)
        self.items.append({
            "id": test_id,
            "name": name,
            "ok": ok,
            "detail": "" if ok else detail,
        })

    def passed(self):
        return sum(c["ok"] for c in self.items), len(self.items)

    def show(self):
        for c in self.items:
            print("[%s] %s" % ("PASS" if c["ok"] else "FAIL", c["name"]))
            if c["detail"]:
                print("       -> %s" % c["detail"])


# ----------------------------------------------------------------------
# Testes 1-9 (executados em cada host)
# ----------------------------------------------------------------------

def test_udp(host, src_ip, obs_dir, checks):
    src_port = random.randint(*PORT_RANGES[host]["udp"])
    nonce = os.urandom(6).hex()
    start = time.time()

    reply = None
    error = ""

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((src_ip, src_port))
        msg = encode({"test": "udp-basic", "id": host, "nonce": nonce})
        sock.settimeout(1.0)
        for _ in range(3):
            sock.sendto(msg, (SERVER_IP, UDP_PORT))
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            obj = decode(data)
            if obj and obj.get("nonce") == nonce:
                reply = obj
                break
    except OSError as exc:
        error = describe(exc)
    finally:
        sock.close()

    obs = wait_obs(obs_dir, "udp_" + nonce, start, 0.5 if reply else 2.0)
    seen = "%s:%s" % (obs["seen_ip"], obs["seen_port"]) if obs else ""
    not_seen = error or "nenhum datagrama deste teste foi observado em H3"

    # "Chegou" exige um datagrama que H3 aceitaria: checksum UDP válido e
    # diferente de zero. Sem raw socket no servidor, vale a entrega à aplicação.
    status = obs.get("checksum") if obs else None
    if status == "unavailable":
        arrived, arr_detail = True, ""
    else:
        arrived = status == "valid"
        arr_detail = {
            "zero": "chegou com checksum UDP zerado (campo não foi recalculado)",
            "invalid": "chegou com checksum UDP inválido",
        }.get(status, not_seen)
    checks.add("udp_arrived", TEST_NAME["udp_arrived"], arrived, arr_detail)
    checks.add(
        "udp_ip", TEST_NAME["udp_ip"],
        obs and obs["seen_ip"] == PUBLIC_NAT_IP,
        "H3 observou a origem %s" % seen if obs else not_seen,
    )
    checks.add(
        "udp_port", "%s (%d)" % (TEST_NAME["udp_port"], src_port),
        obs and obs["seen_port"] == src_port,
        "H3 observou a origem %s" % seen if obs else not_seen,
    )
    if obs and reply is None:
        ret_detail = ("H3 recebeu o pacote e respondeu para %s, mas a resposta "
                      "não chegou a este host" % seen)
    else:
        ret_detail = error or "sem resposta de H3 em 3 s"
    checks.add("udp_return", TEST_NAME["udp_return"], reply is not None, ret_detail)

    return obs is not None


def test_tcp(host, src_ip, obs_dir, checks):
    src_port = random.randint(*PORT_RANGES[host]["tcp"])
    nonce = os.urandom(6).hex()
    start = time.time()

    established = False
    reply = None
    error = ""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((src_ip, src_port))
        sock.settimeout(4)
        sock.connect((SERVER_IP, TCP_PORT))
        established = True
        sock.sendall(encode({"test": "tcp-basic", "id": host, "nonce": nonce}))
        obj = recv_json_line(sock)
        if obj.get("nonce") == nonce:
            reply = obj
        else:
            error = "resposta com nonce diferente do enviado"
    except (OSError, ValueError) as exc:
        error = describe(exc)
    finally:
        sock.close()

    # O SYN é identificado pela porta de origem; a conexão, pelo nonce.
    syn = wait_obs(obs_dir, "tcpsyn_%d" % src_port, start,
                   0.5 if established else 1.5)
    conn = wait_obs(obs_dir, "tcpconn_" + nonce, start, 1.0) if established else None
    obs = conn or syn
    seen = "%s:%s" % (obs["seen_ip"], obs["seen_port"]) if obs else ""
    not_seen = (
        "nenhum SYN com porta de origem %d observado em H3 (se o NAT trocou "
        "a porta e o handshake não completou, o SYN não pode ser associado "
        "a este teste)%s" % (src_port, "; erro: " + error if error else ""))

    if established:
        conn_detail = ""
    elif syn and syn.get("checksum") == "invalid":
        conn_detail = "o SYN chegou em H3 com checksum TCP inválido"
    elif obs:
        conn_detail = ("H3 recebeu o SYN, mas o handshake não completou: "
                       "verifique a tradução no caminho de retorno")
    else:
        conn_detail = not_seen
    checks.add("tcp_conn", TEST_NAME["tcp_conn"], established, conn_detail)
    checks.add(
        "tcp_ip", TEST_NAME["tcp_ip"],
        obs and obs["seen_ip"] == PUBLIC_NAT_IP,
        "H3 observou a origem %s" % seen if obs else not_seen,
    )
    checks.add(
        "tcp_port", "%s (%d)" % (TEST_NAME["tcp_port"], src_port),
        obs and obs["seen_port"] == src_port,
        "H3 observou a origem %s" % seen if obs else not_seen,
    )
    checks.add(
        "tcp_return", TEST_NAME["tcp_return"],
        reply is not None,
        error or ("conexão não estabelecida" if not established else "sem resposta de H3"),
    )

    return obs is not None


def test_icmp(src_ip, obs_dir, functional, raw_ok, checks):
    if not functional:
        checks.add("icmp", TEST_NAME["icmp"], False,
                   "não avaliado: nenhum tráfego UDP/TCP chegou a H3 "
                   "(um NAT que descarta tudo não pontua aqui)")
        return

    nonce = os.urandom(6).hex()
    start = time.time()
    cmd = ["ping", "-I", src_ip, "-c", "2", "-i", "0.3", "-W", "1",
           "-p", nonce, SERVER_IP]
    try:
        replied = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=6,
        ).returncode == 0
    except subprocess.TimeoutExpired:
        replied = False
    except OSError as exc:
        checks.add("icmp", TEST_NAME["icmp"], False,
                   "não foi possível executar ping: %s" % describe(exc))
        return

    leaked = None
    if raw_ok:
        time.sleep(0.3)
        pattern = bytes.fromhex(nonce)
        for fname in sorted(os.listdir(obs_dir)):
            if not (fname.startswith("icmp_") and fname.endswith(".json")):
                continue
            obj = load_json(os.path.join(obs_dir, fname))
            if not obj or obj.get("time", 0) < start - 0.5:
                continue
            try:
                payload = bytes.fromhex(obj.get("payload", ""))
            except ValueError:
                continue
            if pattern in payload:
                leaked = obj.get("seen_ip")
                break

    if leaked:
        detail = "echo request chegou em H3 com origem %s" % leaked
    elif replied:
        detail = "ping recebeu resposta de H3"
    else:
        detail = ""
    if not raw_ok:
        print("[AVISO] servidor sem raw socket ICMP: avaliado só pela "
              "ausência de resposta do ping")
    checks.add("icmp", TEST_NAME["icmp"], not leaked and not replied, detail)


def run_basic(host, obs_dir, status):
    src_ip = HOST_IP[host]
    print("=== TESTES 1-9 DO NAT: %s (%s) ===\n" % (host.upper(), src_ip))

    raw = status.get("raw_sockets", {})
    if not all(raw.get(k) for k in ("udp", "tcp", "icmp")):
        print("[AVISO] servidor sem raw sockets (%s): checksums e ICMP são "
              "avaliados parcialmente. Execute server_NAT.py como root.\n" % raw)

    checks = Checks()
    udp_reached = test_udp(host, src_ip, obs_dir, checks)
    tcp_reached = test_tcp(host, src_ip, obs_dir, checks)
    test_icmp(src_ip, obs_dir, udp_reached or tcp_reached,
              raw.get("icmp", False), checks)

    checks.show()
    ok, total = checks.passed()
    print("\n%s: %d/%d testes aprovados neste host." % (host.upper(), ok, total))
    print("Cada teste só conta na nota se passar em H1 e em H2. "
          "Nota final: 'client_NAT.py report'.")

    save_json(obs_dir, "result_" + host, {
        "host": host,
        "time": time.time(),
        "checks": checks.items,
    })


# ----------------------------------------------------------------------
# Teste 10: colisão de portas
# ----------------------------------------------------------------------

def run_collision(host, obs_dir):
    src_ip = HOST_IP[host]
    print("=== TESTE 10 (COLISÃO): %s (%s:%d) ===" % (host.upper(), src_ip,
                                                       COLLISION_SRC_PORT))
    print("Aguardando o outro host (até %d s)...\n" % COLLISION_TIMEOUT)

    nonce = os.urandom(6).hex()
    result = None
    error = ""

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((src_ip, COLLISION_SRC_PORT))
        sock.settimeout(0.7)
        msg = encode({"test": "collision", "id": host, "nonce": nonce})
        deadline = time.time() + COLLISION_TIMEOUT
        while time.time() < deadline and result is None:
            sock.sendto(msg, (SERVER_IP, UDP_PORT))
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            obj = decode(data)
            if (obj and obj.get("test") == "collision"
                    and obj.get("id") == host
                    and obj.get("nonce") == nonce):
                result = obj
    except OSError as exc:
        error = describe(exc)
    finally:
        sock.close()

    mappings = result.get("mappings") if result else None
    if result is None:
        detail = error or (
            "sem resposta em %d s: o outro host não executou --collision a "
            "tempo, ou a resposta não retornou a este host" % COLLISION_TIMEOUT)
    elif not result.get("ok"):
        detail = "H3 observou H1 -> %s:%s e H2 -> %s:%s" % (
            mappings["h1"]["ip"], mappings["h1"]["port"],
            mappings["h2"]["ip"], mappings["h2"]["port"])
    else:
        detail = ""

    ok = bool(result and result.get("ok"))
    print("[%s] %s (parte de %s)" % ("PASS" if ok else "FAIL",
                                     TEST_NAME["collision"], host.upper()))
    if detail:
        print("       -> %s" % detail)
    if mappings:
        print("\nMapeamentos observados por H3:")
        for h in HOSTS:
            print("  %s %s:%d -> %s:%s" % (h.upper(), HOST_IP[h], COLLISION_SRC_PORT,
                                          mappings[h]["ip"], mappings[h]["port"]))

    save_json(obs_dir, "result_collision_" + host, {
        "host": host,
        "time": time.time(),
        "ok": ok,
        "mappings": mappings,
        "detail": detail,
    })


# ----------------------------------------------------------------------
# Ponto extra: regras manuais (conexões iniciadas pela rede pública)
# ----------------------------------------------------------------------

def bonus_accept(lsock, out):
    try:
        conn, peer = lsock.accept()
    except OSError as exc:
        out["error"] = describe(exc)
        return
    out["peer"] = peer
    with conn:
        try:
            conn.settimeout(4)
            msg = recv_json_line(conn)
            out["nonce"] = msg.get("nonce")
            conn.sendall(encode({"test": "bonus", "nonce": msg.get("nonce")}))
        except (OSError, ValueError) as exc:
            out["error"] = describe(exc)


def run_bonus(host, obs_dir):
    src_ip = HOST_IP[host]
    priv = BONUS_PRIVATE_PORT[host]
    pub = BONUS_PUBLIC_PORT[host]
    print("=== PONTO EXTRA: %s:%d -> %s:%d ===\n" % (PUBLIC_NAT_IP, pub, src_ip, priv))

    nonce = os.urandom(6).hex()
    accepted = {}
    server_result = None
    error = ""

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind((src_ip, priv))
        lsock.listen(1)
        lsock.settimeout(10)
        acceptor = threading.Thread(target=bonus_accept, args=(lsock, accepted),
                                    daemon=True)
        acceptor.start()

        # Pede a H3 (via NAT de saída) que abra a conexão para a porta pública.
        usock.bind((src_ip, 0))
        usock.settimeout(1.0)
        msg = encode({"test": "bonus-request", "id": host, "nonce": nonce})
        deadline = time.time() + 10
        while time.time() < deadline and server_result is None:
            usock.sendto(msg, (SERVER_IP, UDP_PORT))
            try:
                data, _ = usock.recvfrom(65535)
            except socket.timeout:
                continue
            obj = decode(data)
            if obj and obj.get("test") == "bonus" and obj.get("nonce") == nonce:
                server_result = obj
        acceptor.join(timeout=2)
    except OSError as exc:
        error = describe(exc)
    finally:
        lsock.close()
        usock.close()

    peer = accepted.get("peer")
    if server_result is None and not error:
        error = ("H3 não respondeu à requisição UDP (o ponto extra depende "
                 "do NAT de saída funcionando)")

    checks = Checks()
    checks.add(
        "bonus_in",
        "Conexão de H3 para %s:%d entregue em %s:%d" % (PUBLIC_NAT_IP, pub, src_ip, priv),
        peer and accepted.get("nonce") == nonce,
        accepted.get("error") or error
        or (server_result or {}).get("error") or "nenhuma conexão recebida",
    )
    checks.add(
        "bonus_src",
        "Origem da conexão preservada (%s)" % SERVER_IP,
        peer and peer[0] == SERVER_IP,
        "conexão chegou com origem %s:%d" % peer if peer else "nenhuma conexão recebida",
    )
    checks.add(
        "bonus_back",
        "Resposta retornou a H3 pela porta %d" % pub,
        server_result and server_result.get("echo_ok"),
        (server_result or {}).get("error") or error or "H3 não recebeu o eco",
    )
    checks.show()
    ok, total = checks.passed()
    print("\nPonto extra, parte de %s: %s" % (
        host.upper(), "OK" if ok == total else "incompleto (%d/%d)" % (ok, total)))

    save_json(obs_dir, "result_bonus_" + host, {
        "host": host,
        "time": time.time(),
        "ok": ok == total,
        "checks": checks.items,
    })


# ----------------------------------------------------------------------
# Relatório final
# ----------------------------------------------------------------------

def evaluate_collision(col):
    missing = [h.upper() for h in HOSTS if col[h] is None]
    if missing:
        return False, "--collision não executado em %s" % ", ".join(missing)
    if abs(col["h1"]["time"] - col["h2"]["time"]) > COLLISION_TIMEOUT + COLLISION_WINDOW:
        return False, "H1 e H2 executaram --collision em rodadas diferentes"
    failed = [h for h in HOSTS if not col[h]["ok"]]
    if failed:
        details = {col[h]["detail"] for h in failed}
        if len(details) == 1:
            return False, details.pop()
        return False, "; ".join("%s: %s" % (h.upper(), col[h]["detail"]) for h in failed)
    return True, ""


def evaluate_host_test(results, test_id):
    """Um teste de host só passa se passar em H1 e em H2."""
    reasons = []
    for h in HOSTS:
        r = results[h]
        if r is None:
            reasons.append("%s: testes básicos não executados" % h.upper())
            continue
        item = next((c for c in r["checks"] if c["id"] == test_id), None)
        if item is None:
            reasons.append("%s: resultado ausente" % h.upper())
        elif not item["ok"]:
            reasons.append("%s: %s" % (h.upper(), item["detail"]))
    return not reasons, reasons


def run_report(obs_dir):
    print("=== RELATÓRIO FINAL DO NAT ===\n")

    results = {h: load_json(os.path.join(obs_dir, "result_%s.json" % h))
               for h in HOSTS}
    for h in HOSTS:
        r = results[h]
        when = "executado às %s" % fmt_time(r["time"]) if r else "NÃO EXECUTADO"
        print("Testes 1-9 em %s: %s" % (h.upper(), when))
    col = {h: load_json(os.path.join(obs_dir, "result_collision_%s.json" % h))
           for h in HOSTS}
    print()

    grade = 0
    for number, (test_id, name) in enumerate(TESTS, start=1):
        if test_id == "collision":
            ok, detail = evaluate_collision(col)
            reasons = [detail] if detail else []
        else:
            ok, reasons = evaluate_host_test(results, test_id)
        grade += ok
        print("%2d. [%s] %s" % (number, "PASS" if ok else "FAIL", name))
        for reason in reasons:
            print("        -> %s" % reason)

    latest = max((c for c in col.values() if c and c.get("mappings")),
                 key=lambda c: c["time"], default=None)
    if latest:
        print("\n    Mapeamentos na colisão:")
        for h in HOSTS:
            m = latest["mappings"][h]
            print("      %s %s:%d -> %s:%s" % (h.upper(), HOST_IP[h],
                                              COLLISION_SRC_PORT, m["ip"], m["port"]))

    print("\nNOTA: %d / 10" % grade)

    bonus = {h: load_json(os.path.join(obs_dir, "result_bonus_%s.json" % h))
             for h in HOSTS}
    reasons = []
    for h in HOSTS:
        b = bonus[h]
        if b is None:
            reasons.append("%s: --bonus não executado" % h.upper())
        elif not b["ok"]:
            for c in b["checks"]:
                if not c["ok"]:
                    reasons.append("%s: %s -> %s" % (h.upper(), c["name"], c["detail"]))
    print("\nPONTO EXTRA (fora da nota, para trabalho futuro): %s"
          % ("+1.0" if not reasons else "0"))
    for reason in reasons:
        print("        -> %s" % reason)


# ----------------------------------------------------------------------

def parse_target(value):
    # O CLI do Mininet substitui nomes de hosts pelos IPs na linha de comando:
    # "h1 python3 client_NAT.py h1" chega aqui como "... client_NAT.py 10.0.0.1".
    aliases = {"report": "report"}
    for host, ip in HOST_IP.items():
        aliases[host] = host
        aliases[ip] = host
    target = aliases.get(value.strip().lower())
    if target is None:
        raise argparse.ArgumentTypeError(
            "'%s' inválido (use h1, h2, report ou o IP do host)" % value)
    return target


def main():
    ap = argparse.ArgumentParser(
        description="Cliente de testes do NAT.",
        epilog=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "target",
        type=parse_target,
        help="h1, h2 ou report (o IP do host também é aceito, pois o CLI "
             "do Mininet troca nomes de hosts pelos seus IPs)",
    )
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--collision", action="store_true",
                      help="teste 10 (executar em H1 e H2 em até 15 s)")
    mode.add_argument("--bonus", action="store_true",
                      help="ponto extra: regras manuais")
    ap.add_argument("--obs-dir", default=DEFAULT_OBS_DIR,
                    help="diretório compartilhado com server_NAT.py "
                         "(padrão: %(default)s)")
    args = ap.parse_args()
    obs_dir = os.path.abspath(args.obs_dir)

    if args.target == "report":
        if not os.path.isdir(obs_dir):
            print("[ERRO] diretório %s não encontrado." % obs_dir)
            sys.exit(2)
        run_report(obs_dir)
        return

    status = load_json(os.path.join(obs_dir, "server_status.json"))
    if status is None:
        print("[ERRO] %s/server_status.json não encontrado. Inicie "
              "server_NAT.py em H3 a partir do mesmo diretório deste script "
              "(ou use --obs-dir)." % obs_dir)
        sys.exit(2)

    if args.collision:
        run_collision(args.target, obs_dir)
    elif args.bonus:
        run_bonus(args.target, obs_dir)
    else:
        run_basic(args.target, obs_dir, status)


if __name__ == "__main__":
    main()
