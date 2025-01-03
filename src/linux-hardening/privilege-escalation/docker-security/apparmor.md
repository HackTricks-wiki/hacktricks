# AppArmor

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

AppArmor एक **kernel enhancement है जिसे प्रोग्रामों के लिए उपलब्ध संसाधनों को प्रति-प्रोग्राम प्रोफाइल के माध्यम से प्रतिबंधित करने के लिए डिज़ाइन किया गया है**, प्रभावी रूप से Mandatory Access Control (MAC) को लागू करता है, जो पहुँच नियंत्रण विशेषताओं को सीधे प्रोग्रामों से जोड़ता है बजाय उपयोगकर्ताओं के। यह प्रणाली **kernel में प्रोफाइल लोड करके** काम करती है, आमतौर पर बूट के दौरान, और ये प्रोफाइल निर्धारित करते हैं कि एक प्रोग्राम किन संसाधनों तक पहुँच सकता है, जैसे नेटवर्क कनेक्शन, कच्चे सॉकेट तक पहुँच, और फ़ाइल अनुमतियाँ।

AppArmor प्रोफाइल के लिए दो संचालन मोड हैं:

- **Enforcement Mode**: यह मोड प्रोफाइल के भीतर परिभाषित नीतियों को सक्रिय रूप से लागू करता है, उन क्रियाओं को अवरुद्ध करता है जो इन नीतियों का उल्लंघन करती हैं और syslog या auditd जैसे सिस्टम के माध्यम से उल्लंघन के किसी भी प्रयास को लॉग करता है।
- **Complain Mode**: Enforcement mode के विपरीत, complain mode उन क्रियाओं को अवरुद्ध नहीं करता है जो प्रोफाइल की नीतियों के खिलाफ जाती हैं। इसके बजाय, यह इन प्रयासों को नीति उल्लंघनों के रूप में लॉग करता है बिना प्रतिबंध लागू किए।

### Components of AppArmor

- **Kernel Module**: नीतियों के प्रवर्तन के लिए जिम्मेदार।
- **Policies**: प्रोग्राम व्यवहार और संसाधन पहुँच के लिए नियम और प्रतिबंध निर्दिष्ट करते हैं।
- **Parser**: प्रवर्तन या रिपोर्टिंग के लिए नीतियों को kernel में लोड करता है।
- **Utilities**: ये उपयोगकर्ता-मोड प्रोग्राम हैं जो AppArmor के साथ इंटरैक्ट करने और प्रबंधित करने के लिए एक इंटरफ़ेस प्रदान करते हैं।

### Profiles path

Apparmor प्रोफाइल आमतौर पर _**/etc/apparmor.d/**_ में सहेजे जाते हैं।\
`sudo aa-status` के साथ आप उन बाइनरीज़ की सूची प्राप्त कर सकेंगे जो किसी प्रोफाइल द्वारा प्रतिबंधित हैं। यदि आप सूचीबद्ध प्रत्येक बाइनरी के पथ में "/" को बिंदु में बदल सकते हैं, तो आप उल्लेखित फ़ोल्डर के भीतर apparmor प्रोफाइल का नाम प्राप्त करेंगे।

उदाहरण के लिए, _/usr/bin/man_ के लिए एक **apparmor** प्रोफाइल _/etc/apparmor.d/usr.bin.man_ में स्थित होगा।

### Commands
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## एक प्रोफ़ाइल बनाना

- प्रभावित निष्पादन योग्य को इंगित करने के लिए, **पूर्ण पथ और वाइल्डकार्ड** फ़ाइलों को निर्दिष्ट करने के लिए अनुमति है (फ़ाइल ग्लोबिंग के लिए)।
- यह इंगित करने के लिए कि बाइनरी के पास **फाइलों** पर क्या पहुंच होगी, निम्नलिखित **एक्सेस नियंत्रण** का उपयोग किया जा सकता है:
- **r** (पढ़ें)
- **w** (लिखें)
- **m** (निष्पादन योग्य के रूप में मेमोरी मैप)
- **k** (फाइल लॉकिंग)
- **l** (हार्ड लिंक बनाना)
- **ix** (एक नए प्रोग्राम के साथ दूसरे प्रोग्राम को निष्पादित करने के लिए नीति विरासत में लेना)
- **Px** (एक अन्य प्रोफ़ाइल के तहत निष्पादित करें, पर्यावरण को साफ़ करने के बाद)
- **Cx** (एक बच्चे की प्रोफ़ाइल के तहत निष्पादित करें, पर्यावरण को साफ़ करने के बाद)
- **Ux** (बिना किसी प्रतिबंध के निष्पादित करें, पर्यावरण को साफ़ करने के बाद)
- **चर** प्रोफ़ाइल में परिभाषित किए जा सकते हैं और प्रोफ़ाइल के बाहर से हेरफेर किया जा सकता है। उदाहरण: @{PROC} और @{HOME} (प्रोफ़ाइल फ़ाइल में #include \<tunables/global> जोड़ें)
- **अनुमति नियमों को ओवरराइड करने के लिए अस्वीकृति नियमों का समर्थन किया जाता है**।

### aa-genprof

एक प्रोफ़ाइल बनाने की प्रक्रिया को सरल बनाने के लिए apparmor आपकी मदद कर सकता है। यह संभव है कि **apparmor एक बाइनरी द्वारा किए गए कार्यों का निरीक्षण करे और फिर आपको यह तय करने दे कि आप कौन से कार्यों की अनुमति देना या अस्वीकृत करना चाहते हैं**।\
आपको बस यह चलाना है:
```bash
sudo aa-genprof /path/to/binary
```
फिर, एक अलग कंसोल में सभी क्रियाएँ करें जो बाइनरी आमतौर पर करेगी:
```bash
/path/to/binary -a dosomething
```
फिर, पहले कंसोल में "**s**" दबाएं और फिर रिकॉर्ड की गई क्रियाओं में बताएं कि आप क्या अनदेखा, अनुमति या कुछ और करना चाहते हैं। जब आप समाप्त कर लें, तो "**f**" दबाएं और नया प्रोफ़ाइल _/etc/apparmor.d/path.to.binary_ में बनाया जाएगा।

> [!NOTE]
> तीर कुंजियों का उपयोग करके आप चुन सकते हैं कि आप क्या अनुमति/अस्वीकृत/कुछ और करना चाहते हैं।

### aa-easyprof

आप एक बाइनरी के apparmor प्रोफ़ाइल का टेम्पलेट भी बना सकते हैं:
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
> [!NOTE]
> ध्यान दें कि एक बनाए गए प्रोफ़ाइल में डिफ़ॉल्ट रूप से कुछ भी अनुमति नहीं है, इसलिए सब कुछ अस्वीकृत है। आपको उदाहरण के लिए बाइनरी को `/etc/passwd` पढ़ने की अनुमति देने के लिए `/etc/passwd r,` जैसी पंक्तियाँ जोड़ने की आवश्यकता होगी।

आप फिर **enforce** कर सकते हैं नया प्रोफ़ाइल के साथ
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### लॉग से प्रोफ़ाइल को संशोधित करना

निम्नलिखित उपकरण लॉग को पढ़ेगा और उपयोगकर्ता से पूछेगा कि क्या वह कुछ पहचानी गई प्रतिबंधित क्रियाओं की अनुमति देना चाहता है:
```bash
sudo aa-logprof
```
> [!NOTE]
> तीर कुंजियों का उपयोग करके आप चुन सकते हैं कि आप क्या अनुमति देना/अस्वीकृत करना/कुछ और करना चाहते हैं

### प्रोफ़ाइल प्रबंधित करना
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Logs

Example of **AUDIT** and **DENIED** logs from _/var/log/audit/audit.log_ of the executable **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
आप इस जानकारी को निम्नलिखित का उपयोग करके भी प्राप्त कर सकते हैं:
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Docker में Apparmor

ध्यान दें कि **docker-profile** का प्रोफ़ाइल डॉकर द्वारा डिफ़ॉल्ट रूप से लोड किया जाता है:
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
डिफ़ॉल्ट रूप से **Apparmor docker-default प्रोफ़ाइल** [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor) से उत्पन्न होती है।

**docker-default प्रोफ़ाइल सारांश**:

- सभी **नेटवर्किंग** तक **पहुँच**
- **कोई क्षमता** परिभाषित नहीं है (हालांकि, कुछ क्षमताएँ बुनियादी आधार नियमों को शामिल करने से आएँगी यानी #include \<abstractions/base>)
- किसी भी **/proc** फ़ाइल में **लिखना** **अनुमति नहीं है**
- /**proc** और /**sys** के अन्य **उपनिर्देशिकाएँ**/**फ़ाइलें** पढ़ने/लिखने/लॉक/लिंक/कार्य करने की पहुँच **अस्वीकृत** हैं
- **माउंट** **अनुमति नहीं है**
- **Ptrace** केवल उस प्रक्रिया पर चलाया जा सकता है जो **समान apparmor प्रोफ़ाइल** द्वारा सीमित है

एक बार जब आप **docker कंटेनर चलाते हैं** तो आपको निम्नलिखित आउटपुट देखना चाहिए:
```bash
1 processes are in enforce mode.
docker-default (825)
```
ध्यान दें कि **apparmor डिफ़ॉल्ट रूप से कंटेनर को दी गई क्षमताओं के विशेषाधिकारों को भी ब्लॉक करेगा**। उदाहरण के लिए, यह **/proc के अंदर लिखने की अनुमति को ब्लॉक करने में सक्षम होगा, भले ही SYS_ADMIN क्षमता दी गई हो** क्योंकि डिफ़ॉल्ट रूप से docker apparmor प्रोफ़ाइल इस एक्सेस को अस्वीकार करती है:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
आपको इसकी सीमाओं को बायपास करने के लिए **apparmor** को अक्षम करना होगा:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
ध्यान दें कि डिफ़ॉल्ट रूप से **AppArmor** भी **कंटेनर को अंदर से** फ़ोल्डर माउंट करने **से मना करेगा** भले ही SYS_ADMIN क्षमता हो।

ध्यान दें कि आप **docker** कंटेनर में **क्षमताएँ** **जोड़/हटा** सकते हैं (यह अभी भी **AppArmor** और **Seccomp** जैसी सुरक्षा विधियों द्वारा प्रतिबंधित रहेगा):

- `--cap-add=SYS_ADMIN` `SYS_ADMIN` क्षमता दें
- `--cap-add=ALL` सभी क्षमताएँ दें
- `--cap-drop=ALL --cap-add=SYS_PTRACE` सभी क्षमताएँ हटा दें और केवल `SYS_PTRACE` दें

> [!NOTE]
> आमतौर पर, जब आप **पाते** हैं कि आपके पास एक **विशिष्ट क्षमता** **docker** कंटेनर के **अंदर** उपलब्ध है **लेकिन** **शोषण का कुछ हिस्सा काम नहीं कर रहा है**, तो इसका कारण यह होगा कि docker **apparmor इसे रोक रहा होगा**।

### उदाहरण

(उदाहरण [**यहां**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/) से)

AppArmor कार्यक्षमता को स्पष्ट करने के लिए, मैंने निम्नलिखित पंक्ति के साथ एक नया Docker प्रोफ़ाइल "mydocker" बनाया:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
प्रोफ़ाइल को सक्रिय करने के लिए, हमें निम्नलिखित करना होगा:
```
sudo apparmor_parser -r -W mydocker
```
प्रोफाइल सूचीबद्ध करने के लिए, हम निम्नलिखित कमांड कर सकते हैं। नीचे दिया गया कमांड मेरे नए AppArmor प्रोफाइल को सूचीबद्ध कर रहा है।
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
जैसा कि नीचे दिखाया गया है, जब हम “/etc/” को बदलने की कोशिश करते हैं, तो हमें त्रुटि मिलती है क्योंकि AppArmor प्रोफ़ाइल “/etc” पर लिखने की अनुमति को रोक रही है।
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

आप यह पता लगा सकते हैं कि **कौन सा apparmor प्रोफ़ाइल एक कंटेनर चला रहा है**:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
फिर, आप निम्नलिखित पंक्ति चला सकते हैं **सटीक प्रोफ़ाइल खोजने के लिए**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
अजीब स्थिति में आप **apparmor docker प्रोफ़ाइल को संशोधित कर सकते हैं और इसे फिर से लोड कर सकते हैं।** आप प्रतिबंधों को हटा सकते हैं और "बायपास" कर सकते हैं।

### AppArmor Docker Bypass2

**AppArmor पथ आधारित है**, इसका मतलब है कि भले ही यह किसी निर्देशिका के अंदर फ़ाइलों की **सुरक्षा** कर रहा हो जैसे **`/proc`**, यदि आप **कॉन्फ़िगर कर सकते हैं कि कंटेनर कैसे चलाया जाएगा**, तो आप **होस्ट के proc निर्देशिका को** **`/host/proc`** के अंदर **माउंट** कर सकते हैं और यह **अब AppArmor द्वारा सुरक्षित नहीं होगा**।

### AppArmor Shebang Bypass

[**इस बग**](https://bugs.launchpad.net/apparmor/+bug/1911431) में आप देख सकते हैं कि कैसे **भले ही आप perl को कुछ संसाधनों के साथ चलाने से रोक रहे हों**, यदि आप बस एक शेल स्क्रिप्ट **बनाते हैं** **`#!/usr/bin/perl`** को पहले पंक्ति में **निर्दिष्ट करते हैं** और आप **फाइल को सीधे निष्पादित करते हैं**, तो आप जो चाहें उसे निष्पादित कर सकेंगे। उदाहरण:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
{{#include ../../../banners/hacktricks-training.md}}
