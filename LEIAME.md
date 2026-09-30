# Testes de sanidade do NAT

Dois scripts para verificar manualmente o tráfego através do NAT. Eles não
avaliam a implementação: apenas mostram o resultado de cada chamada de socket
(`bind`, `connect`, `sendto`, `recvfrom`, `send`, `recv`, `accept`) e os erros
exatamente como o sistema os informa.

- `nat_recv.py`: escuta portas UDP e TCP, mostra o que chega e devolve os
  mesmos bytes (eco).
- `nat_send.py`: envia uma mensagem UDP ou TCP e mostra o que volta.

Copie os dois arquivos para o diretório do exercício (o mesmo onde se executa
`make run`).

## Execução

No CLI do Mininet, depois de `make run`:

```
h3 python3 nat_recv.py > /tmp/recv.txt 2>&1 &
h1 python3 nat_send.py udp h3 9001 --sport 5000
h2 python3 nat_send.py tcp h3 9002 --sport 5000 --msg teste
h3 cat /tmp/recv.txt
```

O CLI do Mininet substitui nomes de hosts (`h3`) pelos respectivos IPs.

A saída de comandos executados em segundo plano (`&`) não aparece no terminal
do Mininet. Por isso a saída do `nat_recv.py` é gravada em um arquivo; sem
isso, erros como `Address already in use` ficam invisíveis. Outra opção é
executar o receptor em um terminal próprio: `xterm h3`.

## Opções

`nat_send.py udp|tcp DESTINO PORTA [opções]`

| Opção | Significado | Padrão |
|---|---|---|
| `--sport N` | porta de origem | escolhida pelo sistema |
| `--msg TEXTO` | conteúdo enviado | `hello` |
| `--count N` | número de envios | 1 |
| `--interval S` | intervalo entre envios (s) | 1.0 |
| `--timeout S` | espera máxima por resposta (s) | 3.0 |

`nat_recv.py [--udp PORTA ...] [--tcp PORTA ...]`

Padrão: UDP 9001 e TCP 9002. Aceita várias portas, por exemplo
`--udp 9001 5000 --tcp 9002 80`. Escuta em `0.0.0.0`, então também pode ser
executado em H1 ou H2.

## Mensagens comuns

| Mensagem | Significado |
|---|---|
| `recvfrom: timed out` / `recv: timed out` | nenhuma resposta dentro do timeout |
| `connect ...: timed out` | o handshake TCP não completou |
| `[Errno 111] Connection refused` | o destino respondeu com RST (nenhum processo na porta) |
| `[Errno 98] Address already in use` | a porta local já está em uso por outro processo |
| `[Errno 99] Cannot assign requested address` | o endereço não existe neste host |

Em UDP, uma porta sem processo aparece como `timed out`, e não como
`Connection refused`.

Para encerrar um receptor em segundo plano: `h3 pkill -f nat_recv.py`.
